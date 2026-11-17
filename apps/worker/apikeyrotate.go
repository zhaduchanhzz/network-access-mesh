package main

// `meshguard-worker admin apikey-rotate` — rotate the API key of a tenant's Headscale instance now (P3-T10, §11.4): the
// rotation of the job apikey.rotate (internal/provisioning/apikey), run in this process under the instance's API key
// lock, for the coordinator (staging tenants A/B, adopted with keys) and the runbook:
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin apikey-rotate --tenant <uuid|slug> \
//	    [--force] [--allow-bootstrap]
//
// Without --force a key that is not due (it expires in more than 21 days) is left alone (skipped, not_due). A key that
// expired, or whose secret is lost, is re-issued through the Host Agent (MG_AGENT_*). --allow-bootstrap only after the
// instance was verified (§13.4): it lets the agent re-issue a key the instance refused although the registry holds it
// valid (a replaced database is suspected — the run fails without it).
//
// Output: one JSON object — tenant, instance, outcome (rotated | bootstrapped | skipped | failed), skip reason or error
// code, and the instance's key PREFIX and expiry after the run. Never the key, never its SecretStore reference. Exit
// status: 0 rotated, bootstrapped or skipped as not due; 1 failed; 2 usage or configuration error; 3 skipped for another
// reason (quarantined, not running, lifecycle job running, no key recorded…).

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

//nolint:gosec // G101: usage text, not a credential
const apikeyRotateUsage = `usage: meshguard-worker admin apikey-rotate --tenant <uuid|slug> [--force] [--allow-bootstrap]
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin apikey-rotate …
`

// apikeyRotateOutput is the command's JSON result: public identifiers, the outcome, the key prefix and its expiry.
type apikeyRotateOutput struct {
	Tenant     string `json:"tenant_id"`
	Instance   string `json:"instance_id,omitempty"`
	Outcome    string `json:"outcome"`
	SkipReason string `json:"skip_reason,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	KeyPrefix  string `json:"key_prefix,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// apikeyRotateEnv is what the command needs from the process: the configuration and an opener of the rotation
// (replaced in tests).
type apikeyRotateEnv struct {
	getenv  func(string) string
	environ []string
	open    func(ctx context.Context, cfg config.Config, log io.Writer) (keyRotator, func(), error)
}

// keyRotator is the part of the registry and of the rotation the command uses.
type keyRotator interface {
	ResolveInstance(ctx context.Context, ref string) (tenantID, instanceID uuid.UUID, err error)
	Rotate(ctx context.Context, req apikey.Request) (apikey.Result, error)
}

func apikeyRotate(ctx context.Context, args []string, stdout, stderr io.Writer, env apikeyRotateEnv) int {
	fset := flag.NewFlagSet("apikey-rotate", flag.ContinueOnError)
	fset.SetOutput(io.Discard) // flag errors may quote a value
	tenant := fset.String("tenant", "", "")
	force := fset.Bool("force", false, "")
	allowBootstrap := fset.Bool("allow-bootstrap", false, "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		_, _ = io.WriteString(stderr, "meshguard-worker admin apikey-rotate: invalid flags\n"+apikeyRotateUsage)
		return 2
	}
	if _, err := uuid.Parse(*tenant); err != nil && !slugRE.MatchString(*tenant) {
		_, _ = io.WriteString(stderr, "meshguard-worker admin apikey-rotate: --tenant takes a tenant UUID or slug\n"+apikeyRotateUsage)
		return 2
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin apikey-rotate: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin apikey-rotate: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	rot, closeRot, err := env.open(ctx, cfg, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin apikey-rotate: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeRot()
	tenantID, instanceID, err := rot.ResolveInstance(ctx, *tenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin apikey-rotate: tenant %q: %s\n", *tenant, logx.RedactString(err.Error()))
		return 2
	}
	res, err := rot.Rotate(ctx, apikey.Request{TenantID: tenantID, InstanceID: instanceID, Force: *force,
		AllowBootstrap: *allowBootstrap, Trigger: apikey.TriggerAdmin, Actor: "meshguard-worker admin apikey-rotate"})
	out := apikeyRotateOutput{Tenant: tenantID.String(), Instance: instanceID.String(), Outcome: res.Outcome,
		SkipReason: res.SkipReason, KeyPrefix: res.KeyPrefix}
	if res.ExpiresAt != nil {
		out.ExpiresAt = res.ExpiresAt.UTC().Format(time.RFC3339)
	}
	code := 0
	switch {
	case err != nil:
		out.Outcome, out.ErrorCode, code = "failed", jobs.CodeHandlerError, 1
		var je *jobs.Error
		if errors.As(err, &je) {
			out.ErrorCode = je.Code
		}
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin apikey-rotate: FAILED: %s\n", logx.RedactString(err.Error()))
	case res.Outcome == apikey.OutcomeSkipped && res.SkipReason != apikey.SkipNotDue:
		code = 3
	}
	b, _ := json.Marshal(out)
	_, _ = fmt.Fprintf(stdout, "%s\n", b)
	return code
}

// realKeyRotator opens what the rotation needs in the worker container: the worker's pools, the SecretStore (kek-app
// holds the tenants' instance API keys), the Tenant Registry, a locator over them with apikey.TenantStatuses (edge
// admin listener of the configuration) and the Host Agent when MG_AGENT_* are set — the chain of the running worker
// (runner.newAPIKeyRotation), without its schedule.
type realKeyRotator struct {
	tenants *tenants.Service
	svc     *apikey.Service
}

func openKeyRotator(ctx context.Context, cfg config.Config, logw io.Writer) (keyRotator, func(), error) {
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
	fail := func(err error) (keyRotator, func(), error) { closeAll(); return nil, nil, err }
	log := logx.New(logw, cfg.LogLevel, "apikey-rotate")
	// No logger for the SecretStore: its INFO lines name the secret references (mgsec://…), and this command's output —
	// stdout and stderr alike — carries the key prefix and expiry only (E2E-52 checks both).
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
	ac := apikey.Config{Locator: loc, Secrets: ss, Security: commandSecurity{st: st}, Headscale: headscale.Options{Logger: log},
		Logger: log}
	if cfg.Agent.Configured() {
		c, err := agentclient.New(agentclient.Config{Socket: cfg.Agent.Socket, TokenFile: cfg.Agent.TokenFile})
		if err != nil {
			return fail(err)
		}
		closers = append(closers, func() { _ = c.Close() })
		ac.Agent = c
	}
	svc, err := apikey.New(st, ac)
	if err != nil {
		return fail(err)
	}
	return &realKeyRotator{tenants: dir, svc: svc}, closeAll, nil
}

// ResolveInstance accepts a tenant UUID or slug (registry, platform scope) and returns its live instance.
func (r *realKeyRotator) ResolveInstance(ctx context.Context, ref string) (uuid.UUID, uuid.UUID, error) {
	tenantID, err := (&realPolicyCore{tenants: r.tenants}).ResolveTenant(ctx, ref)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	rec, err := r.tenants.LocateInstance(ctx, tenantID)
	if errors.Is(err, tenants.ErrNotFound) {
		return uuid.Nil, uuid.Nil, errors.New("the tenant has no live instance")
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return tenantID, rec.InstanceID, nil
}

func (r *realKeyRotator) Rotate(ctx context.Context, req apikey.Request) (apikey.Result, error) {
	return r.svc.Rotate(ctx, req)
}

// commandSecurity records the rotation's security events in a platform transaction of the command's store, as
// runner.platformSecurity does in the running worker.
type commandSecurity struct{ st *store.Store }

func (c commandSecurity) RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error) {
	var wrote bool
	err := c.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		wrote, err = audit.RecordSecurityEvent(ctx, q, ev)
		return err
	})
	return wrote, err
}
