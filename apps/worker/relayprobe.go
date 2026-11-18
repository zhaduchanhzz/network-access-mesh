package main

// `meshguard-worker admin relay-probe` — probe the relay regions of a tenant now (P3-T05c, §10.6): the probe of the job
// relay.probe (internal/relay), run in this process for every region the schedule would probe (embedded, active,
// served by a running instance), through the prober of the configuration (MG_PROBER_URL, towards
// MG_PROVISION_EDGE_ADDR), and recorded like the job records it — for the runbook and the coordinator (after deploying
// the prober, or to refresh a result before reading GET /tenants/{t}/relay):
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin relay-probe --tenant <uuid|slug>
//
// Output: one JSON object per region — region id, status (healthy | unhealthy), stable reason, the two checks (ok,
// HTTP status, error code, duration), checked_at, recorded, or the skip reason / error code. No address, no secret.
// Exit status: 0 every region recorded healthy (or the tenant has none to probe); 1 a probe could not run or be
// recorded; 2 usage or configuration error (no prober configured); 3 a region recorded unhealthy or skipped.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/apps/internal/runner"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

const relayProbeUsage = `usage: meshguard-worker admin relay-probe --tenant <uuid|slug>
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin relay-probe …
  needs the prober of the configuration (MG_PROBER_URL, MG_PROVISION_EDGE_ADDR)
`

// relayProbeOutput is one line of the command's output.
type relayProbeOutput struct {
	Tenant string `json:"tenant_id"`
	relay.ProbeOutcome
	ErrorCode string `json:"error_code,omitempty"`
}

// relayProbeEnv is what the command needs from the process: the configuration and an opener of the probe (replaced in
// tests).
type relayProbeEnv struct {
	getenv  func(string) string
	environ []string
	open    func(ctx context.Context, cfg config.Config, log io.Writer) (relayProber, func(), error)
}

// relayProber is the part of the registry and of the RelayService the command uses.
type relayProber interface {
	ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error)
	ProbeTenant(ctx context.Context, tenantID uuid.UUID) ([]relay.ProbeOutcome, []error, error)
}

func relayProbe(ctx context.Context, args []string, stdout, stderr io.Writer, env relayProbeEnv) int {
	fset := flag.NewFlagSet("relay-probe", flag.ContinueOnError)
	fset.SetOutput(io.Discard) // flag errors may quote a value
	tenant := fset.String("tenant", "", "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin relay-probe: invalid flags\n"+relayProbeUsage)
		return 2
	}
	if _, err := uuid.Parse(*tenant); err != nil && !slugRE.MatchString(*tenant) {
		_, _ = io.WriteString(stderr, "meshguard-worker admin relay-probe: --tenant takes a tenant UUID or slug\n"+relayProbeUsage)
		return 2
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin relay-probe: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin relay-probe: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	if cfg.Provisioning.ProberURL == "" {
		_, _ = io.WriteString(stderr, "meshguard-worker admin relay-probe: no prober is configured (MG_PROBER_URL)\n"+relayProbeUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	p, closeP, err := env.open(ctx, cfg, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin relay-probe: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeP()
	tenantID, err := p.ResolveTenant(ctx, *tenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin relay-probe: tenant %q: %s\n", *tenant, logx.RedactString(err.Error()))
		return 2
	}
	outs, errs, err := p.ProbeTenant(ctx, tenantID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin relay-probe: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	if len(outs) == 0 {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin relay-probe: tenant %s has no relay region to probe (embedded, "+
			"active, served by a running instance)\n", tenantID)
	}
	code := 0
	for i, o := range outs {
		line := relayProbeOutput{Tenant: tenantID.String(), ProbeOutcome: o}
		switch {
		case errs[i] != nil:
			line.ErrorCode, code = relay.CodeProbeRecordFailed, 1
			if errors.Is(errs[i], relay.ErrProbeNotRun) {
				line.ErrorCode = relay.CodeProberUnavailable
			}
			_, _ = fmt.Fprintf(stderr, "meshguard-worker admin relay-probe: region %s: %s\n", o.RegionID,
				logx.RedactString(errs[i].Error()))
		case (o.Skipped != "" || o.Status != relay.StatusHealthy) && code == 0:
			code = 3
		}
		b, _ := json.Marshal(line)
		_, _ = fmt.Fprintf(stdout, "%s\n", b)
	}
	return code
}

// realRelayProber opens what the probe needs in the worker container: the worker's pools, the Tenant Registry (slug ⇒
// id) and the RelayService over the prober of the configuration — the chain of the running worker
// (runner.NewRelayProbe), without its schedule.
type realRelayProber struct {
	tenants *tenants.Service
	svc     *relay.Service
}

func openRelayProber(ctx context.Context, cfg config.Config, logw io.Writer) (relayProber, func(), error) {
	st, err := store.Open(ctx, store.Config{URL: cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile}, MaxConns: 2})
	if err != nil {
		return nil, nil, err
	}
	svc, err := runner.NewRelayProbe(cfg, st, logx.New(logw, cfg.LogLevel, "relay-probe"), nil)
	if err != nil || svc == nil {
		st.Close()
		if err == nil {
			err = errors.New("no prober is configured (MG_PROBER_URL)")
		}
		return nil, nil, err
	}
	return &realRelayProber{tenants: tenants.New(st, tenants.Options{BaseDomain: cfg.BaseDomain}), svc: svc}, st.Close, nil
}

// ResolveTenant accepts a tenant UUID or slug (registry, platform scope).
func (r *realRelayProber) ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error) {
	return (&realPolicyCore{tenants: r.tenants}).ResolveTenant(ctx, ref)
}

func (r *realRelayProber) ProbeTenant(ctx context.Context, tenantID uuid.UUID) ([]relay.ProbeOutcome, []error, error) {
	return r.svc.ProbeTenant(ctx, tenantID)
}
