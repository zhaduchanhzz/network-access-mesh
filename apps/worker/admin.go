package main

// `meshguard-worker admin idp-bootstrap` — the host-only bootstrap of the keycloak IdP driver (P2-T05a, run at P2-T16):
// create or repair the provisioning identity of the master realm (client mg-provisioner: create-realm + the management
// roles of the realms it adopts, never impersonation — keycloak.Bootstrap) and store its secret in the SecretStore
// (platform_ops, kek-ops: worker only). The break-glass admin of the master realm (bootstrap-admin-* of keycloak.conf)
// is used for this ceremony only: its password is read from stdin — which must be a pipe, never a terminal or a file —
// stored as a platform_ops secret version for the duration of the call (Bootstrap reads it by reference) and destroyed
// right after, success or not. The driver never uses it.
//
// It runs INSIDE the running worker container (`docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin
// idp-bootstrap …`): the worker's static address on mg-edge is the only source the edge lets reach /admin/realms/* and
// /realms/master/* of auth.<domain> (§14.6, P2-T05a), so a second container (`compose run`) could not. Restart the
// worker afterwards so its keycloak driver picks up the provisioning identity (runner.idpDrivers).
//
// Output: the client id, the secret reference (mgsec://platform/…, not secret), what was created, rotated, adopted and
// changed. Exit status: 0 done, 1 failed, 2 usage or configuration error.

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

const adminUsage = `usage: meshguard-worker admin idp-bootstrap --admin-username <name> [--adopt-realm <realm>]...
  stdin: the break-glass admin password of the master realm (bootstrap-admin-password of keycloak.conf), piped
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin idp-bootstrap …
`

// breakGlassRef is the name of the transient platform_ops secret holding the break-glass password during a bootstrap.
const breakGlassRef = "idp.keycloak.break-glass"

// stdinFile is what the command needs from stdin: read it and check what it is (os.Stdin).
type stdinFile interface {
	io.Reader
	Stat() (fs.FileInfo, error)
}

var (
	realmRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	usernameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,255}$`)
)

type realmList []string

func (r *realmList) String() string { return strings.Join(*r, ",") }
func (r *realmList) Set(v string) error {
	*r = append(*r, v)
	return nil
}

// admin runs `meshguard-worker admin <command>`.
func admin(ctx context.Context, args []string, stdin stdinFile, stdout, stderr io.Writer, getenv func(string) string,
	environ []string,
) int {
	if len(args) > 0 && args[0] == "policy-apply" {
		return policyApply(ctx, args[1:], stdin, stdout, stderr, policyApplyEnv{getenv: getenv, environ: environ,
			open: openPolicyCore})
	}
	if len(args) == 0 || args[0] != "idp-bootstrap" {
		_, _ = io.WriteString(stderr, "meshguard-worker admin: unknown command\n"+adminUsage+policyApplyUsage)
		return 2
	}
	fset := flag.NewFlagSet("idp-bootstrap", flag.ContinueOnError)
	fset.SetOutput(io.Discard) // flag errors may quote a value
	username := fset.String("admin-username", "", "")
	var realms realmList
	fset.Var(&realms, "adopt-realm", "")
	if err := fset.Parse(args[1:]); err != nil || fset.NArg() != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-bootstrap: invalid flags\n"+adminUsage)
		return 2
	}
	if !usernameRE.MatchString(*username) {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-bootstrap: --admin-username is required\n"+adminUsage)
		return 2
	}
	for _, r := range realms {
		if !realmRE.MatchString(r) || r == "master" {
			_, _ = io.WriteString(stderr, "meshguard-worker admin idp-bootstrap: --adopt-realm takes realm names other than master\n")
			return 2
		}
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin idp-bootstrap: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	// The password first: refuse a terminal or a file before anything else happens.
	pw, err := readStdin(stdin)
	if err != nil {
		return fail(err)
	}
	defer clear(pw)
	value := bytes.TrimRight(pw, "\r\n") // a view of pw: cleared with it
	if len(value) == 0 || bytes.ContainsAny(value, "\r\n") {
		return fail(errors.New("stdin must hold exactly one password (one line)"))
	}
	cfg, err := config.Load("worker", getenv, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin idp-bootstrap: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-bootstrap: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	log := logx.New(stderr, cfg.LogLevel, "admin")
	ss, closeStore, err := openSecretStore(ctx, cfg, log)
	if err != nil {
		return fail(err)
	}
	defer closeStore()
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: cfg.IdPPlatformHost(), Address: cfg.IdPPlatformAddr})
	if err != nil {
		return fail(err)
	}
	pwRef, err := storeBreakGlass(ctx, ss, value)
	if err != nil {
		return fail(err)
	}
	defer func() { // the break-glass password never outlives the ceremony in the database
		if err := ss.Destroy(context.WithoutCancel(ctx), pwRef); err != nil {
			_, _ = fmt.Fprintf(stderr, "meshguard-worker admin idp-bootstrap: WARNING: destroy %s: %s\n", pwRef,
				logx.RedactString(err.Error()))
		}
	}()
	prov := keycloak.Credentials{ClientID: cfg.IdPProvisionerClientID}
	switch ref, err := ss.Latest(ctx, uuid.Nil, keycloak.ProvisionerRefName); {
	case err == nil:
		prov.Secret = ref
	case !errors.Is(err, secrets.ErrNotFound):
		return fail(err)
	}
	res, err := keycloak.Bootstrap(ctx, route, ss, keycloak.BootstrapConfig{AdminUsername: *username, AdminPassword: pwRef,
		Provisioner: prov, AdoptRealms: realms, Logger: log})
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	p("idp-bootstrap: platform IdP %s, provisioning identity %s", cfg.IdPPlatformHost(), res.Provisioner.ClientID)
	if res.Provisioner.Secret.Name != "" {
		p("  secret: %s (platform_ops — worker only)", res.Provisioner.Secret)
	}
	p("  created: %v, secret rotated: %v, realms adopted: %s", res.Created, res.Rotated, list(res.Adopted))
	for _, c := range res.Changes {
		p("  change: %s", c)
	}
	if err != nil {
		return fail(err)
	}
	p("  restart the worker so its keycloak driver uses this identity: docker compose -p mg-app restart worker")
	p("OK")
	return 0
}

func list(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

// storeBreakGlass stores the password as the next version of the transient platform_ops secret (version 1 the first
// time) and returns its reference.
func storeBreakGlass(ctx context.Context, ss *secrets.Store, value []byte) (secrets.Ref, error) {
	latest, err := ss.Latest(ctx, uuid.Nil, breakGlassRef)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		ref := secrets.PlatformRef(breakGlassRef, 1)
		return ref, ss.Put(ctx, ref, value, secrets.WithPlatformOps())
	case err != nil:
		return secrets.Ref{}, err
	}
	return ss.Rotate(ctx, latest, value, secrets.WithPlatformOps())
}

// openSecretStore opens the worker's pools and its SecretStore (kek-app + kek-ops).
func openSecretStore(ctx context.Context, cfg config.Config, log *slog.Logger) (*secrets.Store, func(), error) {
	app, err := secrets.LoadKeyring(secrets.KEKApp, cfg.KEKAppDir)
	if err != nil {
		return nil, nil, err
	}
	ops, err := secrets.LoadKeyring(secrets.KEKOps, cfg.KEKOpsDir)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(ctx, store.Config{URL: cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile}, MaxConns: 2})
	if err != nil {
		return nil, nil, err
	}
	ss, err := secrets.New(st, secrets.Options{App: app, Ops: ops})
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	log.Info("keyrings loaded", "kek_app", app.Active(), "kek_ops", ops.Active())
	return ss, st.Close, nil
}

const maxStdin = 4096

// readStdin reads one value from stdin, which must be a pipe: a terminal echoes what is typed and keeps it in the
// scrollback, a regular file means the value was written to disk. The caller clears the bytes.
func readStdin(in stdinFile) ([]byte, error) {
	if in == nil {
		return nil, errors.New("no stdin")
	}
	fi, err := in.Stat()
	if err != nil {
		return nil, errors.New("stdin cannot be inspected")
	}
	m := fi.Mode()
	switch {
	case m&os.ModeCharDevice != 0:
		return nil, errors.New("stdin is a terminal or a device: pipe the value into the command, never type or paste it")
	case m.IsRegular():
		return nil, errors.New("stdin is a file: the value must not be stored on disk — pipe it from where it is kept")
	case m&(os.ModeNamedPipe|os.ModeSocket) == 0:
		return nil, errors.New("stdin must be a pipe")
	}
	b, err := io.ReadAll(io.LimitReader(in, maxStdin+1))
	if err != nil {
		clear(b)
		return nil, errors.New("stdin could not be read")
	}
	if len(b) > maxStdin {
		clear(b)
		return nil, errors.New("stdin holds more than one value")
	}
	return b, nil
}
