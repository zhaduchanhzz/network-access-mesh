package main

// `meshguard-worker admin backfill-instance` — bring an instance built by hand and adopted (P2-T11: tenant-a/b of
// staging) under the orchestrator (P3-T14b, internal/provisioning/orchestrator Backfiller): record what tenant.provision
// records after step 3 — the configuration version (only when the agent's rendering of the orchestrator's parameters is
// byte-identical to config.yaml on the host), the Noise key fingerprint, the activation (meta/activated + edge_attach
// through the agent's EnsureEdgeAttachment, the edge already attached: no network change) and the relay rows — from
// the real state read through the Host Agent. Never a configuration write, never a restart, never a file of data/.
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin backfill-instance --tenant <uuid|slug> --dry-run
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin backfill-instance --tenant <uuid|slug>
//
// Output: one JSON object (the plan: items present / would_write / written, parameters, sha256 of config.yaml on the
// host and of the agent's rendering, fingerprint, the container's start time) — public values only. Exit status: 0 done,
// nothing to do, or a dry run that would succeed; 1 failed (after the audit operation was opened: .failed recorded);
// 2 usage or configuration error; 3 refused (nothing written — the plan says why).

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

const backfillUsage = `usage: meshguard-worker admin backfill-instance --tenant <uuid|slug> [--dry-run]
    [--node-expiry-days N] [--nameservers ip,ip] [--log-level info|warn|error] [--derp-region-id N]
    [--memory-mib N] [--cpu-millis N] [--pids N]
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin backfill-instance …
  needs the Host Agent (MG_AGENT_*); parameters default to tenant.provision's (MG_PROVISION_NAMESERVERS, 90 days,
  DERP 901, info, the plan's limits or 512 MiB / 1000 mCPU / 256 PIDs) — give the instance's Phase-1 values when they differ
`

// backfillEnv is what the command needs from the process: the configuration and an opener of the backfill (replaced in
// tests).
type backfillEnv struct {
	getenv  func(string) string
	environ []string
	open    func(ctx context.Context, cfg config.Config, log io.Writer) (backfiller, func(), error)
}

// backfiller is the registry's slug resolution and the orchestrator's Backfiller.
type backfiller interface {
	ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error)
	Backfill(ctx context.Context, req orchestrator.BackfillRequest) (orchestrator.BackfillPlan, error)
}

// u32Flag is an optional unsigned flag.
type u32Flag struct{ v *uint32 }

func (f *u32Flag) String() string {
	if f.v == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*f.v), 10)
}

func (f *u32Flag) Set(s string) error {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return errors.New("not a number")
	}
	v := uint32(n)
	f.v = &v
	return nil
}

func backfillInstance(ctx context.Context, args []string, stdout, stderr io.Writer, env backfillEnv) int {
	fset := flag.NewFlagSet("backfill-instance", flag.ContinueOnError)
	fset.SetOutput(io.Discard) // flag errors may quote a value
	tenant := fset.String("tenant", "", "")
	dry := fset.Bool("dry-run", false, "")
	nameservers := fset.String("nameservers", "", "")
	logLevel := fset.String("log-level", "", "")
	var expiry, derp, mem, cpu, pids u32Flag
	fset.Var(&expiry, "node-expiry-days", "")
	fset.Var(&derp, "derp-region-id", "")
	fset.Var(&mem, "memory-mib", "")
	fset.Var(&cpu, "cpu-millis", "")
	fset.Var(&pids, "pids", "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin backfill-instance: invalid flags\n"+backfillUsage)
		return 2
	}
	if _, err := uuid.Parse(*tenant); err != nil && !slugRE.MatchString(*tenant) {
		_, _ = io.WriteString(stderr, "meshguard-worker admin backfill-instance: --tenant takes a tenant UUID or slug\n"+backfillUsage)
		return 2
	}
	o := orchestrator.BackfillOverrides{NodeExpiryDays: expiry.v, LogLevel: *logLevel, DERPRegionID: derp.v,
		MemoryMiB: mem.v, CPUMillis: cpu.v, PIDs: pids.v}
	if *nameservers != "" {
		o.Nameservers = strings.Split(*nameservers, ",")
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin backfill-instance: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin backfill-instance: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	if !cfg.Agent.Configured() {
		_, _ = io.WriteString(stderr, "meshguard-worker admin backfill-instance: no Host Agent is configured (MG_AGENT_*)\n"+backfillUsage)
		return 2
	}
	if len(cfg.Provisioning.Nameservers) == 0 && len(o.Nameservers) == 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin backfill-instance: no nameservers (MG_PROVISION_NAMESERVERS or --nameservers)\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	b, closeB, err := env.open(ctx, cfg, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin backfill-instance: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeB()
	tenantID, err := b.ResolveTenant(ctx, *tenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin backfill-instance: tenant %q: %s\n", *tenant, logx.RedactString(err.Error()))
		return 2
	}
	plan, err := b.Backfill(ctx, orchestrator.BackfillRequest{TenantID: tenantID, Overrides: o, DryRun: *dry,
		Actor: "meshguard-worker admin backfill-instance"})
	code := 0
	var be *orchestrator.BackfillError
	switch {
	case errors.As(err, &be) && plan.OperationID == nil:
		plan.Refusal, plan.Error, code = be.Code, be.Msg, 3
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin backfill-instance: REFUSED (%s): %s — nothing written\n", be.Code,
			logx.RedactString(be.Msg))
	case err != nil:
		plan.Error, code = logx.RedactString(err.Error()), 1
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin backfill-instance: FAILED: %s\n", plan.Error)
	case !plan.Changed:
		_, _ = io.WriteString(stderr, "meshguard-worker admin backfill-instance: nothing to do — every item is recorded\n")
	}
	raw, _ := json.Marshal(plan)
	_, _ = fmt.Fprintf(stdout, "%s\n", raw)
	return code
}

// realBackfiller opens what the backfill needs in the worker container: the worker's pools (platform role), the Host
// Agent client, the registry for slugs, and the orchestrator's parameters of the configuration (MG_PROVISION_*).
type realBackfiller struct {
	tenants *tenants.Service
	b       *orchestrator.Backfiller
}

func openBackfiller(ctx context.Context, cfg config.Config, logw io.Writer) (backfiller, func(), error) {
	st, err := store.Open(ctx, store.Config{URL: cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile}, MaxConns: 2})
	if err != nil {
		return nil, nil, err
	}
	ac, err := agentclient.New(agentclient.Config{Socket: cfg.Agent.Socket, TokenFile: cfg.Agent.TokenFile})
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	b := &orchestrator.Backfiller{Store: orchestrator.NewDBStore(st, nil), Agent: ac,
		Defaults: orchestrator.BackfillDefaults{Nameservers: cfg.Provisioning.Nameservers},
		Logger:   logx.New(logw, cfg.LogLevel, "backfill-instance")}
	return &realBackfiller{tenants: tenants.New(st, tenants.Options{BaseDomain: cfg.BaseDomain}), b: b},
		func() { _ = ac.Close(); st.Close() }, nil
}

func (r *realBackfiller) ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error) {
	return (&realPolicyCore{tenants: r.tenants}).ResolveTenant(ctx, ref)
}

func (r *realBackfiller) Backfill(ctx context.Context, req orchestrator.BackfillRequest) (orchestrator.BackfillPlan, error) {
	return r.b.Backfill(ctx, req)
}
