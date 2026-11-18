package main

// `meshguard admin <command>` — host-only administration commands of the api binary (§4.4, §8.2):
//
//	adopt-instance         P2-T11: register a tenant built by hand in Phase 1 from its meta/instance.json and hand its
//	                       Headscale over with a NEW API key read from stdin (`headscale apikeys create -e <ttl> -o json`)
//	register-platform-idp  P2-T11: register the identity provider of the platform realm (MG_IDP_ID_PLATFORM)
//	set-idp-client-secret  P2-T11: store the client secret of an IdP (stdin) and record its reference
//	bootstrap-super-admin  P2-T11a: make (platform IdP, sub) a Super Admin while fewer than 2 active Super Admins exist
//	seed-membership        P2-T11a: make (the tenant's IdP, sub) Tenant Owner or Tenant Admin of a tenant
//	revoke-sessions        G2 round 2 (A-2): revoke every session of (IdP, sub) and disable the identity (offboarding)
//	enable-identity        G2 round 2 (A-2): undo of revoke-sessions
//	host-set               P3-T04: public entry (IPv4 from an environment variable), capacity or status of a registered
//	                       host — the change of PATCH /api/v1/platform/hosts/{hostId}, audited as actor_type system
//	maintenance            P3-T17: the persisted maintenance flag (on/off/status — admin_maintenance.go); the restore of
//	                       PostgreSQL to an older point and its reconcile (`meshguard-worker admin post-restore-reconcile`)
//
// They run on the host beside the api service (`docker compose -p mg-app run --rm --no-deps -T api admin …` — compose
// project mg-app, P2-T16), with the api's configuration (database roles mg_api_*, kek-app keyring, edge admin
// listener, the detached audit writer: their audit events go to audit_events — admin_audit.go): see
// infrastructure/host/RUNBOOK.md.
// A credential is read from stdin only, and stdin must be a pipe — never a terminal (echo, history), never a file
// (disk), never an argument or an environment variable. Nothing prints or logs a credential; the output names
// references (mgsec://…) and public key prefixes. bootstrap-super-admin and seed-membership take no credential: their
// inputs are identifiers (the `sub` of an IdP user, a tenant slug, a role key); so do revoke-sessions and
// enable-identity (an IdP id and a `sub`), and host-set (a host name; the public IPv4 comes from an environment variable
// named by --public-ipv4-env and is never printed).

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// stdinFile is what the admin commands need from stdin: read it and check what it is (os.Stdin).
type stdinFile interface {
	io.Reader
	Stat() (fs.FileInfo, error)
}

// adminIO is the environment of one admin command (the process's, or a test's).
type adminIO struct {
	stdin   stdinFile
	stdout  io.Writer
	stderr  io.Writer
	getenv  func(string) string
	environ []string
	// test hooks
	httpClient *http.Client     // nil: the adapter's default client (no proxy, no redirect)
	now        func() time.Time // nil: time.Now
	minKeyTTL  time.Duration    // 0: provisioning.DefaultMinKeyTTL
	audit      provisioning.Auditor
}

type adminCommand struct {
	usage string
	run   func(ctx context.Context, args []string, aio adminIO) int
}

// adminCommands is the table of `meshguard admin`. Filled in init because the commands print their own usage from it.
var adminCommands map[string]adminCommand

func init() {
	adminCommands = map[string]adminCommand{
		"adopt-instance": {run: runAdoptInstance, usage: "adopt-instance --host <name> [--host-region <region> " +
			"--run-uid-range <first>-<last> --tenant-net-pool <cidr>] [--name <display name>] <path of meta/instance.json>\n" +
			"      stdin: the NEW API key — `docker exec mg-hs-<slug> headscale apikeys create -e 2160h -o json | …`"},
		"register-platform-idp": {run: runRegisterPlatformIdP,
			usage: "register-platform-idp   (MG_IDP_ID_PLATFORM, MG_BASE_DOMAIN)"},
		"set-idp-client-secret": {run: runSetIdPClientSecret, usage: "set-idp-client-secret <idp id>\n" +
			"      stdin: the client secret of mg-portal in the realm of that IdP"},
		"bootstrap-super-admin": {run: runBootstrapSuperAdmin, usage: "bootstrap-super-admin --subject <sub> " +
			"[--display-name <name>]   (MG_IDP_ID_PLATFORM)\n" +
			"      only while fewer than 2 active Super Admins exist; <sub> = id of the user in the platform realm"},
		"seed-membership": {run: runSeedMembership, usage: "seed-membership --tenant <slug|id> " +
			"--role tenant_owner|tenant_admin --subject <sub> [--display-name <name>]\n" +
			"      <sub> = id of the user in the tenant's own realm (its active identity provider)"},
		"revoke-sessions": {run: runRevokeSessions, usage: "revoke-sessions --idp <idp id> --subject <sub> [--keep-enabled]\n" +
			"      revoke every session of that identity and disable it (offboarding); --keep-enabled: sessions only"},
		"enable-identity": {run: runEnableIdentity, usage: "enable-identity --idp <idp id> --subject <sub>\n" +
			"      undo of revoke-sessions: the identity may sign in again"},
		"maintenance": {run: runMaintenance, usage: "maintenance on [--reason <code>] | off [--force] | status\n" +
			"      persisted maintenance flag (system_settings): ON ⇒ api 503 except the platform sign-in, worker idle; " +
			"off refused while the post-restore reconcile is running or failed (--force overrides)"},
		"host-set": {run: runHostSet, usage: "host-set --name <host> [--public-ipv4-env <NAME>] [--mode direct|vps_gateway] " +
			"[--max-instances <n>] [--status active|draining|disabled]\n" +
			"      <NAME> = environment variable holding public_entry.ipv4 (MG_PUBLIC_IPV4) — the address is never an argument"},
	}
}

const adminTimeout = 3 * time.Minute

func admin(ctx context.Context, args []string, aio adminIO) int {
	if len(args) == 0 {
		adminUsage(aio.stderr)
		return 2
	}
	cmd, ok := adminCommands[args[0]]
	if !ok {
		_, _ = io.WriteString(aio.stderr, "meshguard admin: unknown command\n")
		adminUsage(aio.stderr)
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, adminTimeout)
	defer cancel()
	return cmd.run(ctx, args[1:], aio)
}

func adminUsage(w io.Writer) {
	names := make([]string, 0, len(adminCommands))
	for n := range adminCommands {
		names = append(names, n)
	}
	sort.Strings(names)
	_, _ = io.WriteString(w, "usage: meshguard admin <command> — host-only, see infrastructure/host/RUNBOOK.md\n")
	for _, n := range names {
		_, _ = fmt.Fprintf(w, "  %s\n", adminCommands[n].usage)
	}
}

// fail prints the error of a command (never a credential: errors of this binary and its packages name references,
// prefixes, files and fields only) and returns exit status 1.
func fail(aio adminIO, cmd string, err error) int {
	_, _ = fmt.Fprintf(aio.stderr, "meshguard admin %s: FAILED: %s\n", cmd, logx.RedactString(err.Error()))
	return 1
}

func usageError(aio adminIO, cmd, msg string) int {
	_, _ = fmt.Fprintf(aio.stderr, "meshguard admin %s: %s\nusage: meshguard admin %s\n", cmd, msg, adminCommands[cmd].usage)
	return 2
}

// parseFlags parses without letting the flag package print anything: its messages may quote a value.
func parseFlags(fset *flag.FlagSet, args []string) error {
	fset.SetOutput(io.Discard)
	fset.Usage = func() {}
	return fset.Parse(args)
}

// looksLikeCredential spots an argument that should have gone to stdin.
func looksLikeCredential(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "hskey-") {
			return true
		}
	}
	return false
}

const maxStdin = 4096

// readStdin reads one credential from stdin, which must be a pipe: a terminal echoes what is typed and keeps it in
// the scrollback, a regular file means the credential was written to disk. The caller clears the bytes.
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
		return nil, errors.New("stdin is a file: the value must not be stored on disk — pipe it from the command that creates it")
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

// parseAPIKey accepts what `headscale apikeys create -o json` prints — one JSON string (RT-15) — or the bare key.
func parseAPIKey(b []byte) (headscale.Secret, error) {
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, `"`) {
		var v string
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return headscale.Secret{}, errors.New("stdin is not the JSON string printed by `headscale apikeys create -o json`")
		}
		s = v
	}
	if !provisioning.ValidAPIKey(s) {
		return headscale.Secret{}, errors.New("stdin does not hold a Headscale API key (hskey-api-<prefix>-<secret>)")
	}
	return headscale.NewSecret(s), nil
}

// adminDeps are the services every command opens from the configuration.
type adminDeps struct {
	cfg     config.Admin
	log     *slog.Logger
	st      *store.Store
	secrets *secrets.Store
	tenants *tenants.Service
	writer  *store.AuditWriter // nil in dev without MG_DB_AUDIT_WRITER_PASSWORD_FILE
	audit   *audit.Logger
}

func openDeps(ctx context.Context, aio adminIO, needEdge bool) (*adminDeps, error) {
	cfg, err := config.LoadAdmin(aio.getenv, aio.environ, needEdge)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := logx.New(aio.stderr, cfg.LogLevel, "admin")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, cfg.KEKAppDir)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, store.Config{
		URL:      cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile},
		MaxConns: 4,
		Logger:   log,
	})
	if err != nil {
		return nil, err
	}
	ss, err := secrets.New(st, secrets.Options{App: kr, Logger: log, Now: aio.now})
	if err != nil {
		st.Close()
		return nil, err
	}
	d := &adminDeps{cfg: cfg, log: log, st: st, secrets: ss,
		tenants: tenants.New(st, tenants.Options{BaseDomain: cfg.BaseDomain})}
	if cfg.AuditWriterPasswordFile != "" { // P2-T16: the events go to audit_events (required outside dev)
		w, err := store.OpenAuditWriter(ctx, cfg.DB.URL, store.Credentials{User: store.AuditWriterRole,
			PasswordFile: cfg.AuditWriterPasswordFile})
		if err != nil {
			st.Close()
			return nil, err
		}
		d.writer = w
		if d.audit, err = audit.New(st, w, audit.Config{Log: log}); err != nil {
			d.close()
			return nil, err
		}
	}
	return d, nil
}

// close releases the pools of the command.
func (d *adminDeps) close() {
	if d.writer != nil {
		d.writer.Close()
	}
	d.st.Close()
}

// auditor is where the command records its audit events: audit_events through internal/audit when the detached
// writer is configured (always outside dev — P2-T16), the process log otherwise (dev).
func (d *adminDeps) auditor(aio adminIO) provisioning.Auditor {
	switch {
	case aio.audit != nil:
		return aio.audit
	case d.audit != nil:
		return newDBAuditor(d.audit)
	}
	return provisioning.LogAuditor{Logger: d.log}
}

// idpEnvName is MG_IDP_ID_<SLUG> (tenant-a ⇒ MG_IDP_ID_TENANT_A): the identity_providers.id allocated for the realm of
// that tenant in the environment file (P2-T05).
func idpEnvName(slug string) string {
	return "MG_IDP_ID_" + strings.ToUpper(strings.ReplaceAll(slug, "-", "_"))
}

func idpID(aio adminIO, name string) (uuid.UUID, error) {
	raw := strings.TrimSpace(aio.getenv(name))
	id, err := uuid.Parse(raw)
	if raw == "" || err != nil || id == uuid.Nil || id.String() != raw {
		return uuid.Nil, fmt.Errorf("%s must hold the canonical UUID of the identity provider (environment file, P2-T05)", name)
	}
	return id, nil
}

// ---------------------------------------------------------------- adopt-instance

func runAdoptInstance(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "adopt-instance"
	if looksLikeCredential(args) {
		return usageError(aio, cmd, "an API key is never an argument — pipe it into stdin")
	}
	fset := flag.NewFlagSet(cmd, flag.ContinueOnError)
	hostName := fset.String("host", "", "hosts.name of the host running the instance")
	region := fset.String("host-region", "", "region of the host (new host only)")
	uidRange := fset.String("run-uid-range", "", "UID range of the host, e.g. 30000-39999 (new host only)")
	pool := fset.String("tenant-net-pool", "", "tenant network pool of the host, e.g. 10.250.0.0/16 (new host only)")
	name := fset.String("name", "", "display name of a new tenant (default: the slug)")
	if err := parseFlags(fset, args); err != nil {
		return usageError(aio, cmd, "invalid flags")
	}
	if fset.NArg() != 1 {
		return usageError(aio, cmd, "exactly one argument: the path of meta/instance.json")
	}
	if *hostName == "" {
		return usageError(aio, cmd, "--host is required")
	}
	var newHost *platform.HostSpec
	if *region != "" || *uidRange != "" || *pool != "" {
		spec, err := hostSpec(*hostName, *region, *uidRange, *pool)
		if err != nil {
			return usageError(aio, cmd, err.Error())
		}
		newHost = &spec
	}

	// The key first: refuse a terminal or a file before anything else happens.
	raw, err := readStdin(aio.stdin)
	if err != nil {
		return fail(aio, cmd, err)
	}
	key, err := parseAPIKey(raw)
	clear(raw)
	if err != nil {
		return fail(aio, cmd, err)
	}

	meta, err := readMeta(fset.Arg(0))
	if err != nil {
		return fail(aio, cmd, err)
	}
	idp, err := idpID(aio, idpEnvName(meta.Slug))
	if err != nil {
		return fail(aio, cmd, err)
	}
	d, err := openDeps(ctx, aio, true)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.close()
	tenantID := meta.TenantID
	loc, err := locator.New(d.tenants, d.secrets, locator.Options{AdminURL: d.cfg.Edge.URL,
		EdgeTokenFile: d.cfg.Edge.TokenFile, Logger: d.log})
	if err != nil {
		return fail(aio, cmd, err)
	}
	ad := &provisioning.Adopter{
		Tenants: d.tenants, Platform: platform.New(d.st), Secrets: d.secrets, Locator: loc,
		Headscale: headscale.Options{HTTPClient: aio.httpClient, Logger: d.log, Now: aio.now},
		Audit:     d.auditor(aio), Log: d.log, Now: aio.now, MinKeyTTL: aio.minKeyTTL,
	}
	res, err := ad.Adopt(ctx, provisioning.AdoptRequest{
		Meta: meta, APIKey: key, HostName: *hostName, NewHost: newHost, TenantName: *name, BaseDomain: d.cfg.BaseDomain,
		IdP: provisioning.KeycloakRealmIdP(idp, &tenantID, meta.Slug, d.cfg.BaseDomain),
	})
	printAdopt(aio.stdout, meta, res)
	if err != nil {
		return fail(aio, cmd, err)
	}
	_, _ = io.WriteString(aio.stdout, "OK\n")
	return 0
}

// hostSpec parses the flags of a new host: all three are required together.
func hostSpec(name, region, uidRange, pool string) (platform.HostSpec, error) {
	if region == "" || uidRange == "" || pool == "" {
		return platform.HostSpec{}, errors.New("--host-region, --run-uid-range and --tenant-net-pool go together")
	}
	lo, hi, ok := strings.Cut(uidRange, "-")
	first, err1 := strconv.ParseInt(lo, 10, 32)
	last, err2 := strconv.ParseInt(hi, 10, 32)
	if !ok || err1 != nil || err2 != nil || first <= 0 || last < first {
		return platform.HostSpec{}, errors.New("--run-uid-range must be <first>-<last>, e.g. 30000-39999")
	}
	p, err := netip.ParsePrefix(pool)
	if err != nil || p != p.Masked() {
		return platform.HostSpec{}, errors.New("--tenant-net-pool must be a network in CIDR form, e.g. 10.250.0.0/16")
	}
	return platform.HostSpec{Name: name, Region: region, RunUIDFirst: int32(first), RunUIDLast: int32(last),
		TenantNetPool: p}, nil
}

func readMeta(path string) (provisioning.Meta, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's argument on the host (meta/instance.json)
	if err != nil {
		return provisioning.Meta{}, fmt.Errorf("open meta/instance.json: %w", err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return provisioning.Meta{}, errors.New("meta/instance.json must be a regular file")
	}
	return provisioning.ParseMeta(f)
}

func printAdopt(w io.Writer, m provisioning.Meta, r provisioning.AdoptResult) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	created := func(b bool) string {
		if b {
			return "created"
		}
		return "existing"
	}
	p("adopt-instance: tenant %s (%s), instance %s, host %s", r.Slug, r.TenantID, r.InstanceID, r.HostName)
	p("  meta: template_version %s, config_sha256 %s, image %s", m.TemplateVersion, m.ConfigSHA256, m.ImageDigest)
	if r.HeadscaleVersion != "" {
		p("  pre-flight: Headscale %s through the edge admin listener; new API key prefix %s, expires %s",
			r.HeadscaleVersion, r.KeyPrefix, r.KeyExpiresAt.Format(time.RFC3339))
	}
	if r.SecretRef == "" {
		return
	}
	p("  registry: host %s, tenant %s, instance %s, identity provider %s", created(r.HostCreated),
		created(r.TenantCreated), created(r.InstanceCreated), created(r.IdPCreated))
	prev := r.PreviousRef
	if prev == "" {
		prev = "none"
	}
	p("  secret: %s (previous: %s)", r.SecretRef, prev)
	if r.ValidKeys > 0 {
		p("  verified: ListAPIKeys through Registry.ForTenant (registry + SecretStore + edge)")
		p("  expired: %d other API key(s)%s; valid keys now: %d", len(r.ExpiredPrefixes), list(r.ExpiredPrefixes),
			r.ValidKeys)
	}
	if r.Activation.TenantFrom != "" || r.Activation.InstanceFrom != "" {
		p("  activated: tenant %s→active, instance %s→running", orDash(r.Activation.TenantFrom),
			orDash(r.Activation.InstanceFrom))
	}
	if len(r.DestroyedRefs) > 0 {
		p("  erased older secret versions: %s", strings.Join(r.DestroyedRefs, ", "))
	}
}

func list(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return " (" + strings.Join(s, ", ") + ")"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---------------------------------------------------------------- register-platform-idp

func runRegisterPlatformIdP(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "register-platform-idp"
	if len(args) != 0 {
		return usageError(aio, cmd, "no argument expected")
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.close()
	id, err := idpID(aio, "MG_IDP_ID_PLATFORM")
	if err != nil {
		return fail(aio, cmd, err)
	}
	ia := &provisioning.IdPAdmin{Tenants: d.tenants, Secrets: d.secrets, Audit: d.auditor(aio), Log: d.log}
	p, existed, err := ia.RegisterPlatformIdP(ctx, provisioning.KeycloakRealmIdP(id, nil, provisioning.PlatformRealm,
		d.cfg.BaseDomain))
	if err != nil {
		return fail(aio, cmd, err)
	}
	state := "created"
	if existed {
		state = "already registered"
	}
	_, _ = fmt.Fprintf(aio.stdout, "register-platform-idp: %s — %s, issuer %s, client %s, status %s\n"+
		"  client secret: %s\nOK\n", p.ID, state, p.Issuer, p.ClientID, p.Status,
		orText(p.ClientSecretRef, "not set — run set-idp-client-secret "+p.ID.String()))
	return 0
}

func orText(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// ---------------------------------------------------------------- set-idp-client-secret

func runSetIdPClientSecret(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "set-idp-client-secret"
	if len(args) != 1 {
		return usageError(aio, cmd, "exactly one argument: the identity provider id")
	}
	id, err := uuid.Parse(args[0])
	if err != nil || id == uuid.Nil || id.String() != args[0] {
		return usageError(aio, cmd, "the argument must be the canonical UUID of an identity provider")
	}
	raw, err := readStdin(aio.stdin)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer clear(raw)
	secret := []byte(strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r"))
	defer clear(secret)
	if !clientSecretOK(secret) {
		return fail(aio, cmd, errors.New("stdin must hold one client secret: 16–512 visible ASCII characters, no spaces"))
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.close()
	ia := &provisioning.IdPAdmin{Tenants: d.tenants, Secrets: d.secrets, Audit: d.auditor(aio), Log: d.log}
	res, err := ia.SetClientSecret(ctx, id, secret)
	if err != nil {
		return fail(aio, cmd, err)
	}
	_, _ = fmt.Fprintf(aio.stdout, "set-idp-client-secret: %s (%s, issuer %s, client %s)\n  secret: %s (previous: %s)\n",
		res.IdP.ID, res.IdP.Scope, res.IdP.Issuer, res.IdP.ClientID, res.Ref, orText(res.PreviousRef, "none"))
	if len(res.DestroyedRefs) > 0 {
		_, _ = fmt.Fprintf(aio.stdout, "  erased older versions: %s\n", strings.Join(res.DestroyedRefs, ", "))
	}
	_, _ = io.WriteString(aio.stdout, "OK\n")
	return 0
}

func clientSecretOK(b []byte) bool {
	if len(b) < 16 || len(b) > 512 {
		return false
	}
	for _, c := range b {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}
