package main

// `meshguard-worker admin idp-realm-smtp [--dry-run]` — G4b-E1: give every realm the keycloak driver created (tenant
// IdPs provisioned by the orchestrator, JSON driver_ref) the smtpServer of the worker's relay (MG_SMTP_*: mailrelay:587,
// STARTTLS, the relay's one sender — keycloak.SMTPFromConfig). Realms created before the driver carried it have no SMTP
// and Keycloak cannot e-mail the required-actions link of an invitation (job member.idp_invite ⇒ idp_email_failed).
// Realms created from now on get it at creation (EnsureIssuer). Idempotent: a realm that has it is left alone; the
// rendered realms (platform, tenant-a, tenant-b — bare driver_ref) are infrastructure/idp/realm-update.sh's and are
// skipped; deleted (disabled) IdPs are skipped. A failed invitation is then sent again from the Portal ("Gửi lại").
//
// It runs INSIDE the running worker container (`docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin
// idp-realm-smtp`): the worker's static address on mg-edge is the only source the edge lets reach /admin/realms/*.
// Output: one line per keycloak IdP (realm issuer, result updated | unchanged | would-update | skipped:<why> |
// failed:<code>). Exit status: 0 done, 1 some realm failed, 2 usage or configuration error (no relay: MG_SMTP_ADDR unset
// or authenticated).

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

const realmSMTPUsage = `usage: meshguard-worker admin idp-realm-smtp [--dry-run]
  sets the smtpServer (MG_SMTP_* relay) of every realm the keycloak driver created; runs inside the worker container:
  docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin idp-realm-smtp
`

// realmSMTPTarget is one keycloak IdP of the registry.
type realmSMTPTarget struct {
	Reg    idp.Registration
	Status string
}

// realmSMTPEnsurer is what the command needs from the keycloak driver (replaced in tests).
type realmSMTPEnsurer interface {
	EnsureSMTP(ctx context.Context, reg idp.Registration) (bool, error)
}

type realmSMTPEnv struct {
	getenv  func(string) string
	environ []string
	// open returns the keycloak IdPs of the registry and the driver configured with the relay; close releases them.
	open func(ctx context.Context, cfg config.Config, smtp keycloak.SMTPServer, w io.Writer) ([]realmSMTPTarget,
		realmSMTPEnsurer, func(), error)
}

func idpRealmSMTP(ctx context.Context, args []string, stdout, stderr io.Writer, env realmSMTPEnv) int {
	fset := flag.NewFlagSet("idp-realm-smtp", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	dry := fset.Bool("dry-run", false, "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-realm-smtp: invalid flags\n"+realmSMTPUsage)
		return 2
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin idp-realm-smtp: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-realm-smtp: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	smtp, ok, err := keycloak.SMTPFromConfig(cfg.SMTP.Addr, cfg.SMTP.TLS, cfg.SMTP.From, cfg.SMTP.Username, cfg.BaseDomain)
	if err != nil || !ok {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-realm-smtp: no realm relay — MG_SMTP_ADDR must be set "+
			"and unauthenticated (a realm's smtpServer never holds a password)\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	targets, drv, closeAll, err := env.open(ctx, cfg, smtp, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin idp-realm-smtp: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeAll()
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	var updated, unchanged, skipped, failed int
	for _, t := range targets {
		what := t.Reg.Issuer
		switch {
		case t.Status == "disabled":
			p("%s: skipped:disabled", what)
			skipped++
			continue
		case t.Reg.Scope == idp.ScopeTenant && t.Reg.DriverRef != "" && t.Reg.DriverRef[0] != '{':
			p("%s: skipped:rendered_realm (infrastructure/idp/realm-update.sh)", what)
			skipped++
			continue
		case t.Reg.DriverRef == "":
			p("%s: skipped:no_driver_ref", what)
			skipped++
			continue
		}
		if *dry {
			p("%s: would-update (if its smtpServer differs)", what)
			continue
		}
		changed, err := drv.EnsureSMTP(ctx, t.Reg)
		switch {
		case idp.CodeOf(err) == idp.CodeUnsupported:
			p("%s: skipped:rendered_realm", what)
			skipped++
		case err != nil:
			p("%s: failed:%s", what, idp.CodeOf(err))
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", what, logx.RedactString(err.Error()))
			failed++
		case changed:
			p("%s: updated", what)
			updated++
		default:
			p("%s: unchanged", what)
			unchanged++
		}
	}
	p("idp-realm-smtp: relay %s:%d, updated %d, unchanged %d, skipped %d, failed %d", smtp.Host, smtp.Port, updated,
		unchanged, skipped, failed)
	if failed > 0 {
		return 1
	}
	p("OK")
	return 0
}

// openRealmSMTP reads the keycloak IdPs of the registry (platform pool) and builds the keycloak driver with the
// provisioning identity (its latest secret version) and the relay.
func openRealmSMTP(ctx context.Context, cfg config.Config, smtp keycloak.SMTPServer, w io.Writer) ([]realmSMTPTarget,
	realmSMTPEnsurer, func(), error,
) {
	log := logx.New(w, cfg.LogLevel, "admin")
	ss, st, closeStore, err := openStores(ctx, cfg, log)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) ([]realmSMTPTarget, realmSMTPEnsurer, func(), error) {
		closeStore()
		return nil, nil, nil, err
	}
	var targets []realmSMTPTarget
	err = st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListKeycloakIdentityProviders(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			full, err := q.GetIdentityProvider(ctx, r.ID)
			if err != nil {
				return err
			}
			reg := idp.Registration{IdPID: full.ID, Scope: idp.Scope(full.Scope), Driver: full.Driver, Issuer: full.Issuer,
				ClientID: full.ClientID}
			if full.TenantID != nil {
				reg.TenantID = *full.TenantID
			}
			if full.DriverRef != nil {
				reg.DriverRef = *full.DriverRef
			}
			targets = append(targets, realmSMTPTarget{Reg: reg, Status: full.Status})
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: cfg.IdPPlatformHost(), Address: cfg.IdPPlatformAddr})
	if err != nil {
		return fail(err)
	}
	clientID := cfg.IdPProvisionerClientID
	if clientID == "" {
		clientID = keycloak.DefaultProvisionerClientID
	}
	ref, err := ss.Latest(ctx, uuid.Nil, keycloak.ProvisionerRefName)
	if errors.Is(err, secrets.ErrNotFound) {
		return fail(errors.New("the provisioning identity is not bootstrapped (admin idp-bootstrap)"))
	} else if err != nil {
		return fail(err)
	}
	kc, err := keycloak.New(keycloak.Config{Route: route, Secrets: ss, Provisioner: keycloak.Credentials{ClientID: clientID,
		Secret: ref}, AppHost: cfg.AppHost(), AdminHost: cfg.AdminHost(), Logger: log, SMTP: &smtp})
	if err != nil {
		return fail(err)
	}
	return targets, kc, closeStore, nil
}
