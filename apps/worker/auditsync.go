package main

// `meshguard-worker admin idp-audit-sync` — one pass of the job idp.audit_sync now (P3-T15): every realm of the
// platform-hosted Keycloak is read from its cursor and each new admin/login event imported (audit_events, security
// events, notifications), exactly as the job that runs every minute; an event already imported is never imported twice
// (internal/idp/auditsync), so running the command while the job runs is harmless. For the operator after a console
// session ("are the console's changes in the tenants' audit yet?") and for the E2E cases.
//
// It runs INSIDE the running worker container (`docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin
// idp-audit-sync`): the worker's static address on mg-edge is the only source the edge lets reach /admin/realms/* and
// /realms/master/* of auth.<domain>. It reads no input. Exit status: 0 every realm read, 3 some realm could not be read
// (each one raised a security event idp.audit_sync_failed), 4 skipped (the provisioning identity is not bootstrapped or
// the IdP is unreachable), 1 failure (database), 2 usage or configuration error.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/auditsync"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

const auditSyncUsage = `usage: meshguard-worker admin idp-audit-sync
  one pass of idp.audit_sync now; runs inside the worker container:
  docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin idp-audit-sync
`

func idpAuditSync(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, environ []string) int {
	if len(args) != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-audit-sync: takes no argument\n"+auditSyncUsage)
		return 2
	}
	cfg, err := config.Load("worker", getenv, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin idp-audit-sync: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin idp-audit-sync: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin idp-audit-sync: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	log := logx.New(stderr, cfg.LogLevel, "admin")
	ss, st, closeStore, err := openStores(ctx, cfg, log)
	if err != nil {
		return fail(err)
	}
	defer closeStore()
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: cfg.IdPPlatformHost(), Address: cfg.IdPPlatformAddr})
	if err != nil {
		return fail(err)
	}
	clientID := cfg.IdPProvisionerClientID
	if clientID == "" {
		clientID = keycloak.DefaultProvisionerClientID
	}
	ref, err := ss.Latest(ctx, uuid.Nil, keycloak.ProvisionerRefName)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		ref = secrets.PlatformRef(keycloak.ProvisionerRefName, 1) // not bootstrapped: the run is skipped
	case err != nil:
		return fail(err)
	}
	kc, err := keycloak.New(keycloak.Config{Route: route, Secrets: ss, Provisioner: keycloak.Credentials{ClientID: clientID,
		Secret: ref}, AppHost: cfg.AppHost(), AdminHost: cfg.AdminHost(), Logger: log})
	if err != nil {
		return fail(err)
	}
	syncer, err := auditsync.New(st, auditsync.Config{Source: kc, Logger: log})
	if err != nil {
		return fail(err)
	}
	sum, err := syncer.RunOnce(ctx)
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	if err != nil {
		p("idp-audit-sync: realms %d, imported %d before the failure", sum.Realms, sum.Imported)
		return fail(err)
	}
	switch {
	case sum.Skipped:
		p("idp-audit-sync: skipped — the provisioning identity is not usable or the IdP is unreachable (see the log)")
		return 4
	case len(sum.Failed) > 0:
		p("idp-audit-sync: realms %d, imported %d, NOT READ: %s (security event idp.audit_sync_failed)", sum.Realms,
			sum.Imported, strings.Join(sum.Failed, ", "))
		return 3
	}
	p("idp-audit-sync: realms %d, imported %d", sum.Realms, sum.Imported)
	p("OK")
	return 0
}
