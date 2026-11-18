package main

// `meshguard-worker admin post-restore-reconcile` — the reconcile after PostgreSQL was restored to an older point in
// time (P3-T17, §17.2; internal/provisioning/postrestore), run in the worker container while api and worker are in
// maintenance mode (docs/operations/backup-restore.md §6.3, infrastructure/host/RUNBOOK.md):
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile \
//	    --restore-point <started_at of the dump's manifest, RFC 3339> [--dry-run]
//
// It needs the worker's roles (sessions — migration 0020 —, invitations, policy applications), its SecretStore
// (kek-app: the instances' API keys), the edge admin listener (Headscale) and the Host Agent (MG_AGENT_* — the
// inventory of the host and BootstrapApiKey); without the agent the instance and key steps are reported incomplete.
//
// Output: the report (one JSON document, indented — ids, slugs, counts, key prefixes, hashes; never a key, a
// reference or a policy text). Exit status: 0 completed (the report may still list subjects to review), 3 incomplete
// (a step could not reach a subject — run it again once fixed), 1 failed, 2 usage or configuration error.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/postrestore"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

const postRestoreUsage = `usage: meshguard-worker admin post-restore-reconcile --restore-point <RFC 3339> [--dry-run]
  --restore-point: when the restored dump was taken (started_at of its manifest, mg-backup)
  runs inside the worker container (maintenance mode on): docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile …
`

// reconciler is the part of postrestore.Service the command uses (replaced in tests).
type reconciler interface {
	Run(ctx context.Context, req postrestore.Request) (postrestore.Report, error)
}

// postRestoreEnv is what the command needs from the process.
type postRestoreEnv struct {
	getenv  func(string) string
	environ []string
	open    func(ctx context.Context, cfg config.Config, log io.Writer) (reconciler, func(), error)
}

func postRestore(ctx context.Context, args []string, stdout, stderr io.Writer, env postRestoreEnv) int {
	fset := flag.NewFlagSet("post-restore-reconcile", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	point := fset.String("restore-point", "", "")
	dry := fset.Bool("dry-run", false, "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin post-restore-reconcile: invalid flags\n"+postRestoreUsage)
		return 2
	}
	at, err := time.Parse(time.RFC3339, *point)
	if err != nil {
		_, _ = io.WriteString(stderr, "meshguard-worker admin post-restore-reconcile: --restore-point takes an RFC 3339 time "+
			"(e.g. 2026-11-18T02:30:00Z — started_at of the dump's manifest)\n"+postRestoreUsage)
		return 2
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin post-restore-reconcile: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin post-restore-reconcile: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	rec, closeRec, err := env.open(ctx, cfg, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin post-restore-reconcile: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeRec()
	rep, err := rec.Run(ctx, postrestore.Request{RestorePoint: at, DryRun: *dry})
	b, _ := json.MarshalIndent(rep, "", "  ")
	_, _ = fmt.Fprintf(stdout, "%s\n", b)
	switch {
	case errors.Is(err, postrestore.ErrInvalidRequest):
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin post-restore-reconcile: %s\n", logx.RedactString(err.Error()))
		return 2
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin post-restore-reconcile: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	case rep.Status == postrestore.StatusIncomplete:
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin post-restore-reconcile: INCOMPLETE: %d item(s) — %v\n",
			len(rep.Incomplete), rep.Incomplete)
		return 3
	}
	_, _ = fmt.Fprintf(stderr, "meshguard-worker admin post-restore-reconcile: %s (dry run: %v) — %d subject(s) to review "+
		"before `meshguard admin maintenance off`\n", rep.Status, rep.DryRun, len(rep.ReviewRequired))
	return 0
}

// openPostRestore opens what the reconcile needs in the worker container: the worker's pools, its SecretStore (no
// logger: its lines name references), the Tenant Registry and a locator over them with apikey.TenantStatuses (edge
// admin listener), the Headscale registry, the Host Agent when MG_AGENT_* are set, the key rotation of P3-T10 and the
// policy core.
func openPostRestore(ctx context.Context, cfg config.Config, logw io.Writer) (reconciler, func(), error) {
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
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile}, MaxConns: 4})
	if err != nil {
		return nil, nil, err
	}
	closers := []func(){st.Close}
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	fail := func(err error) (reconciler, func(), error) { closeAll(); return nil, nil, err }
	log := logx.New(logw, cfg.LogLevel, "post-restore-reconcile")
	ss, err := secrets.New(st, secrets.Options{App: app, Ops: ops})
	if err != nil {
		return fail(err)
	}
	dir := tenants.New(st, tenants.Options{BaseDomain: cfg.BaseDomain})
	loc, err := locator.New(dir, ss, locator.Options{AdminURL: cfg.Edge.URL, EdgeTokenFile: cfg.Edge.TokenFile, Logger: log,
		TenantStatuses: apikey.TenantStatuses})
	if err != nil {
		return fail(err)
	}
	reg := headscale.NewRegistry(loc, headscale.Options{Logger: log})
	sec := commandSecurity{st: st}
	kc := apikey.Config{Locator: loc, Secrets: ss, Security: sec, Headscale: headscale.Options{Logger: log}, Logger: log,
		Invalidate: []apikey.Invalidator{reg}}
	pc := postrestore.Config{Headscale: reg, Security: sec, Logger: log}
	if cfg.Agent.Configured() {
		c, err := agentclient.New(agentclient.Config{Socket: cfg.Agent.Socket, TokenFile: cfg.Agent.TokenFile})
		if err != nil {
			return fail(err)
		}
		closers = append(closers, func() { _ = c.Close() })
		kc.Agent, pc.Agent = c, c
	} else {
		log.Warn("no Host Agent configured (MG_AGENT_SOCKET): the inventory of the host and the re-issue of API keys " +
			"cannot run — the report will be incomplete")
	}
	if pc.Keys, err = apikey.New(st, kc); err != nil {
		return fail(err)
	}
	if pc.Policies, err = policies.New(st, policies.Config{Registry: reg, Logger: log}); err != nil {
		return fail(err)
	}
	svc, err := postrestore.New(st, pc)
	if err != nil {
		return fail(err)
	}
	return svc, closeAll, nil
}
