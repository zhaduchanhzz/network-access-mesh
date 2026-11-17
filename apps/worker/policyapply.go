package main

// `meshguard-worker admin policy-apply` — the internal command of the policy core (P3-T08a): apply a HuJSON policy
// (the deny-all baseline, the suspension policy, a test fixture) read from stdin to a tenant's Headscale through the
// policy core (internal/policies: lint L1/L2, per-tenant advisory lock, CheckPolicy → SetPolicy → GetPolicy with the
// sha256 read-back, policy_versions + policy_applications + audit). It replaces infrastructure/host/tenant-policy.sh
// once the tenant's instance is in the registry and reachable through the edge admin listener:
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin policy-apply --tenant <uuid|slug> \
//	    [--kind baseline|suspension] [--trigger manual|bootstrap|suspend|resume|restore|drift_repair|rollback] \
//	    --file - < infrastructure/headscale/templates/test-allow-intra.hujson
//
// stdin is the policy (a pipe or a redirected file; never a terminal), at most 1 MiB. Output: one JSON object (tenant,
// instance, version, application, state, content/applied/read-back sha256, error code). Exit status: 0 applied,
// 1 failed (recorded failed, or not recorded), 2 usage or configuration error, 3 refused by the lint (nothing written
// but the audit event, Headscale never called).

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

const policyApplyUsage = `usage: meshguard-worker admin policy-apply --tenant <uuid|slug> [--kind baseline|suspension] [--trigger <trigger>] --file -
  stdin: the HuJSON policy (pipe or redirected file, at most 1 MiB)
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin policy-apply …
`

var slugRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)

// policyApplyOutput is the command's JSON result.
type policyApplyOutput struct {
	Tenant         string `json:"tenant_id"`
	Instance       string `json:"instance_id,omitempty"`
	VersionID      string `json:"version_id,omitempty"`
	Version        int    `json:"version,omitempty"`
	VersionCreated bool   `json:"version_created"`
	Application    string `json:"application_id,omitempty"`
	State          string `json:"state"`
	ContentSHA256  string `json:"content_sha256,omitempty"`
	AppliedSHA256  string `json:"applied_sha256,omitempty"`
	ReadbackSHA256 string `json:"readback_sha256,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	LintRule       string `json:"lint_rule,omitempty"`
	Reasserted     bool   `json:"reasserted,omitempty"`
}

// policyApplyEnv is what the command needs from the process: the configuration and an opener of the policy core
// (replaced in tests).
type policyApplyEnv struct {
	getenv  func(string) string
	environ []string
	open    func(ctx context.Context, cfg config.Config) (policyCore, func(), error)
}

// policyCore is the part of the policy core and registry the command uses.
type policyCore interface {
	ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error)
	Apply(ctx context.Context, req policies.ApplyRequest) (policies.Result, error)
}

func policyApply(ctx context.Context, args []string, stdin stdinFile, stdout, stderr io.Writer, env policyApplyEnv) int {
	fset := flag.NewFlagSet("policy-apply", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	tenant := fset.String("tenant", "", "")
	kind := fset.String("kind", policies.KindBaseline, "")
	trigger := fset.String("trigger", policies.TriggerManual, "")
	file := fset.String("file", "", "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || *file != "-" {
		_, _ = io.WriteString(stderr, "meshguard-worker admin policy-apply: invalid flags (the policy is read from stdin: --file -)\n"+policyApplyUsage)
		return 2
	}
	if _, err := uuid.Parse(*tenant); err != nil && !slugRE.MatchString(*tenant) {
		_, _ = io.WriteString(stderr, "meshguard-worker admin policy-apply: --tenant takes a tenant UUID or slug\n"+policyApplyUsage)
		return 2
	}
	if *kind != policies.KindBaseline && *kind != policies.KindSuspension {
		_, _ = io.WriteString(stderr, "meshguard-worker admin policy-apply: --kind is baseline or suspension\n")
		return 2
	}
	text, err := readPolicy(stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-apply: %v\n", err)
		return 2
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-apply: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin policy-apply: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	core, closeCore, err := env.open(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-apply: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeCore()
	tenantID, err := core.ResolveTenant(ctx, *tenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-apply: tenant %q: %s\n", *tenant, logx.RedactString(err.Error()))
		return 2
	}
	res, err := core.Apply(ctx, policies.ApplyRequest{TenantID: tenantID, Kind: *kind, HuJSON: text, Trigger: *trigger,
		Actor: "meshguard-worker admin policy-apply"})
	out := policyApplyOutput{Tenant: tenantID.String(), VersionCreated: res.VersionCreated, State: res.State,
		ContentSHA256: res.ContentSHA256, AppliedSHA256: res.AppliedSHA256, ReadbackSHA256: res.ReadbackSHA256,
		ErrorCode: res.ErrorCode, Reasserted: res.Reasserted, Version: res.Version}
	if res.InstanceID != uuid.Nil {
		out.Instance = res.InstanceID.String()
	}
	if res.VersionID != uuid.Nil {
		out.VersionID = res.VersionID.String()
	}
	if res.ApplicationID != uuid.Nil {
		out.Application = res.ApplicationID.String()
	}
	code := 0
	if le, ok := policies.IsLint(err); ok {
		out.State, out.ErrorCode, out.LintRule, code = "rejected", le.Code(), le.Rule, 3
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-apply: BLOCKED by lint %s: %s\n", le.Rule, le.Detail)
	} else if err != nil {
		if out.State == "" {
			out.State = "not_applied"
		}
		code = 1
		if errors.Is(err, policies.ErrInvalidRequest) {
			code = 2
		}
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-apply: FAILED: %s\n", logx.RedactString(err.Error()))
	}
	b, _ := json.Marshal(out)
	_, _ = fmt.Fprintf(stdout, "%s\n", b)
	return code
}

// readPolicy reads the policy from stdin: a pipe or a redirected file (a policy is not a secret), never a terminal.
func readPolicy(in stdinFile) (string, error) {
	if in == nil {
		return "", errors.New("no stdin")
	}
	fi, err := in.Stat()
	if err != nil {
		return "", errors.New("stdin cannot be inspected")
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		return "", errors.New("stdin is a terminal: pipe or redirect the policy file (--file -)")
	}
	b, err := io.ReadAll(io.LimitReader(in, policies.MaxPolicyBytes+1))
	if err != nil {
		return "", errors.New("stdin could not be read")
	}
	if len(b) > policies.MaxPolicyBytes {
		return "", fmt.Errorf("the policy is larger than %d bytes", policies.MaxPolicyBytes)
	}
	return string(b), nil
}

// realPolicyCore opens what the policy core needs in the worker container: the worker's pools, the SecretStore
// (kek-app holds the tenants' instance API keys), the Tenant Registry, the Locator (edge admin listener) and the
// Headscale registry — the same chain as the running worker (runner.openDeps), without the IdP clients.
type realPolicyCore struct {
	tenants *tenants.Service
	core    *policies.Service
}

func openPolicyCore(ctx context.Context, cfg config.Config) (policyCore, func(), error) {
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
	fail := func(err error) (policyCore, func(), error) { st.Close(); return nil, nil, err }
	ss, err := secrets.New(st, secrets.Options{App: app, Ops: ops})
	if err != nil {
		return fail(err)
	}
	dir := tenants.New(st, tenants.Options{BaseDomain: cfg.BaseDomain})
	log := logx.New(io.Discard, cfg.LogLevel, "policy-apply")
	loc, err := locator.New(dir, ss, locator.Options{AdminURL: cfg.Edge.URL, EdgeTokenFile: cfg.Edge.TokenFile, Logger: log})
	if err != nil {
		return fail(err)
	}
	core, err := policies.New(st, policies.Config{Registry: headscale.NewRegistry(loc, headscale.Options{Logger: log}),
		Logger: log})
	if err != nil {
		return fail(err)
	}
	return &realPolicyCore{tenants: dir, core: core}, st.Close, nil
}

// ResolveTenant accepts a tenant UUID or slug (the registry, platform scope).
func (r *realPolicyCore) ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error) {
	if id, err := uuid.Parse(ref); err == nil {
		t, err := r.tenants.GetRegistry(ctx, id)
		return t.ID, err
	}
	page, err := r.tenants.ListRegistry(ctx, tenants.RegistryFilter{Query: ref, Page: tenants.Page{Limit: 200}})
	if err != nil {
		return uuid.Nil, err
	}
	for _, t := range page.Items {
		if strings.EqualFold(t.Slug, ref) && t.Status != "deleted" {
			return t.ID, nil
		}
	}
	return uuid.Nil, errors.New("no tenant with this slug")
}

func (r *realPolicyCore) Apply(ctx context.Context, req policies.ApplyRequest) (policies.Result, error) {
	return r.core.Apply(ctx, req)
}
