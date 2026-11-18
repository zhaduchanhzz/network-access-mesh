package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
)

// fakeBackfiller stands for the registry and the orchestrator's Backfiller.
type fakeBackfiller struct {
	tenant uuid.UUID
	reqs   []orchestrator.BackfillRequest
	plan   orchestrator.BackfillPlan
	err    error
}

func (f *fakeBackfiller) ResolveTenant(_ context.Context, ref string) (uuid.UUID, error) {
	if ref == "tenant-a" || ref == f.tenant.String() {
		return f.tenant, nil
	}
	return uuid.Nil, errors.New("no tenant with this slug")
}

func (f *fakeBackfiller) Backfill(_ context.Context, req orchestrator.BackfillRequest) (orchestrator.BackfillPlan, error) {
	f.reqs = append(f.reqs, req)
	p := f.plan
	p.TenantID, p.DryRun = req.TenantID, req.DryRun
	return p, f.err
}

// TestBackfillInstanceCommand: flags (overrides passed through as typed values), configuration (the Host Agent and
// nameservers are required before anything is opened), exit codes (0 done / nothing to do / dry run, 1 failed after the
// operation was opened, 2 usage, 3 refused) and the JSON plan on stdout.
func TestBackfillInstanceCommand(t *testing.T) {
	fb := &fakeBackfiller{tenant: uuid.New()}
	opened := 0
	mkEnv := func(vars map[string]string) backfillEnv {
		env := backfillEnv{getenv: func(k string) string { return vars[k] },
			open: func(context.Context, config.Config, io.Writer) (backfiller, func(), error) {
				opened++
				return fb, func() {}, nil
			}}
		for k, v := range vars {
			env.environ = append(env.environ, k+"="+v)
		}
		return env
	}
	vars := wiredWorkerEnv(t)
	vars["MG_AGENT_SOCKET"], vars["MG_AGENT_TOKEN_FILE"] = "/run/meshguard/agent.sock", t.TempDir()+"/agent_token"
	env := mkEnv(vars)
	run := func(env backfillEnv, args ...string) (int, orchestrator.BackfillPlan, string) {
		var out, errb bytes.Buffer
		code := backfillInstance(context.Background(), args, &out, &errb, env)
		var p orchestrator.BackfillPlan
		if s := strings.TrimSpace(out.String()); s != "" {
			if err := json.Unmarshal([]byte(s), &p); err != nil {
				t.Fatalf("output %q: %v", s, err)
			}
		}
		return code, p, errb.String()
	}

	fb.plan = orchestrator.BackfillPlan{Changed: true, Items: []orchestrator.BackfillItem{{Name: "config_version", State: "would_write"}}}
	code, p, _ := run(env, "--tenant", "tenant-a", "--dry-run", "--nameservers", "1.1.1.1,9.9.9.9", "--node-expiry-days", "90",
		"--log-level", "warn", "--derp-region-id", "901", "--memory-mib", "512", "--cpu-millis", "1000", "--pids", "256")
	if code != 0 || !p.DryRun || p.TenantID != fb.tenant || len(fb.reqs) != 1 {
		t.Fatalf("dry run: exit %d %+v", code, p)
	}
	r := fb.reqs[0]
	o := r.Overrides
	if !r.DryRun || !slices.Equal(o.Nameservers, []string{"1.1.1.1", "9.9.9.9"}) || *o.NodeExpiryDays != 90 || o.LogLevel != "warn" ||
		*o.DERPRegionID != 901 || *o.MemoryMiB != 512 || *o.CPUMillis != 1000 || *o.PIDs != 256 || r.Actor == "" {
		t.Fatalf("request %+v", r)
	}
	fb.plan = orchestrator.BackfillPlan{}
	if code, _, stderr := run(env, "--tenant", fb.tenant.String(), "--nameservers", "1.1.1.1"); code != 0 ||
		!strings.Contains(stderr, "nothing to do") || fb.reqs[1].Overrides.NodeExpiryDays != nil {
		t.Fatalf("nothing to do: exit %d %q", code, stderr)
	}
	fb.err = &orchestrator.BackfillError{Code: orchestrator.BackfillConfigDiffers, Msg: "sha256 a ≠ b"}
	if code, p, stderr := run(env, "--tenant", "tenant-a", "--nameservers", "1.1.1.1"); code != 3 ||
		p.Refusal != orchestrator.BackfillConfigDiffers || !strings.Contains(stderr, "nothing written") {
		t.Fatalf("refused: exit %d %+v %q", code, p, stderr)
	}
	op := uuid.New()
	fb.plan.OperationID = &op
	fb.err = &orchestrator.BackfillError{Code: orchestrator.BackfillHostState, Msg: "restarted"}
	if code, p, _ := run(env, "--tenant", "tenant-a", "--nameservers", "1.1.1.1"); code != 1 || p.Error == "" {
		t.Fatalf("failed after the operation opened: exit %d %+v", code, p)
	}
	fb.err = nil
	for _, args := range [][]string{{}, {"--tenant", "Bad Slug!"}, {"--tenant", "tenant-a", "extra"}, {"--tenant", "tenant-a", "--pids", "x"},
		{"--tenant", "unknown-tenant", "--nameservers", "1.1.1.1"}} {
		if code, _, _ := run(env, args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	// no nameservers anywhere, or no Host Agent: a configuration error before anything is opened
	n := opened
	if code, _, stderr := run(env, "--tenant", "tenant-a"); code != 2 || opened != n || !strings.Contains(stderr, "nameservers") {
		t.Fatalf("no nameservers: exit %d %q", code, stderr)
	}
	if code, _, stderr := run(mkEnv(wiredWorkerEnv(t)), "--tenant", "tenant-a", "--nameservers", "1.1.1.1"); code != 2 || opened != n ||
		!strings.Contains(stderr, "MG_AGENT") {
		t.Fatalf("no agent: exit %d %q", code, stderr)
	}
	var errb bytes.Buffer
	if code := admin(context.Background(), []string{"backfill-instance", "--tenant", "Bad Slug!"}, nil, io.Discard, &errb,
		func(string) string { return "" }, nil); code != 2 || !strings.Contains(errb.String(), "backfill-instance") {
		t.Fatalf("admin dispatch: %d %q", code, errb.String())
	}
}
