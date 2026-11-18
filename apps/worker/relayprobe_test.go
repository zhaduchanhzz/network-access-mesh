package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
)

// fakeRelayProber stands for the registry and the RelayService.
type fakeRelayProber struct {
	tenant uuid.UUID
	asked  []uuid.UUID
	outs   []relay.ProbeOutcome
	errs   []error
	err    error
}

func (f *fakeRelayProber) ResolveTenant(_ context.Context, ref string) (uuid.UUID, error) {
	if ref == "tenant-a" || ref == f.tenant.String() {
		return f.tenant, nil
	}
	return uuid.Nil, errors.New("no tenant with this slug")
}

func (f *fakeRelayProber) ProbeTenant(_ context.Context, tenantID uuid.UUID) ([]relay.ProbeOutcome, []error, error) {
	f.asked = append(f.asked, tenantID)
	return f.outs, f.errs, f.err
}

// TestRelayProbeCommand: flags, configuration (a prober is required — exit 2 without MG_PROBER_URL, before anything is
// opened), exit codes (0 every region healthy or none to probe, 1 a probe could not run or be recorded, 3 a region
// unhealthy or skipped) and the JSON lines — region, verdict, checks, checked_at; never an address.
func TestRelayProbeCommand(t *testing.T) {
	fp := &fakeRelayProber{tenant: uuid.New()}
	opened := 0
	vars := wiredWorkerEnv(t)
	vars["MG_PROVISION_EDGE_ADDR"], vars["MG_PROBER_URL"] = "10.249.0.2:443", "http://prober:8080" // the prober alone
	mkEnv := func(vars map[string]string) relayProbeEnv {
		env := relayProbeEnv{getenv: func(k string) string { return vars[k] },
			open: func(context.Context, config.Config, io.Writer) (relayProber, func(), error) {
				opened++
				return fp, func() {}, nil
			}}
		for k, v := range vars {
			env.environ = append(env.environ, k+"="+v)
		}
		return env
	}
	env := mkEnv(vars)
	run := func(env relayProbeEnv, args ...string) (int, []relayProbeOutput, string, string) {
		var out, errb bytes.Buffer
		code := relayProbe(context.Background(), args, &out, &errb, env)
		var lines []relayProbeOutput
		for _, ln := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			if ln == "" {
				continue
			}
			var o relayProbeOutput
			if err := json.Unmarshal([]byte(ln), &o); err != nil {
				t.Fatalf("output line %q: %v", ln, err)
			}
			lines = append(lines, o)
		}
		return code, lines, out.String(), errb.String()
	}
	at := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	r1, r2 := uuid.New(), uuid.New()
	ok := relay.ProbeOutcome{RegionID: r1, Status: relay.StatusHealthy, Recorded: true, CheckedAt: &at,
		DERP: &relay.CheckView{OK: true, Status: 200, DurationMS: 9}, STUN: &relay.CheckView{OK: true, DurationMS: 1}}
	fp.outs, fp.errs = []relay.ProbeOutcome{ok}, []error{nil}
	code, lines, out, stderr := run(env, "--tenant", "tenant-a")
	if code != 0 || len(lines) != 1 || lines[0].Tenant != fp.tenant.String() || lines[0].RegionID != r1 || !lines[0].Recorded ||
		lines[0].Status != relay.StatusHealthy || lines[0].DERP == nil || lines[0].DERP.Status != 200 || lines[0].CheckedAt == nil ||
		!lines[0].CheckedAt.Equal(at) || fp.asked[0] != fp.tenant {
		t.Fatalf("healthy: exit %d %+v %q", code, lines, stderr)
	}
	if strings.Contains(out, "10.249.0.2") || strings.Contains(out, "prober:8080") {
		t.Fatalf("output names an address: %s", out)
	}
	bad := relay.ProbeOutcome{RegionID: r2, Status: relay.StatusUnhealthy, Reason: relay.ReasonSTUNProbeFailed, Recorded: true, CheckedAt: &at}
	fp.outs, fp.errs = []relay.ProbeOutcome{ok, bad}, []error{nil, nil}
	if code, lines, _, _ = run(env, "--tenant", fp.tenant.String()); code != 3 || len(lines) != 2 || lines[1].Reason != relay.ReasonSTUNProbeFailed {
		t.Fatalf("unhealthy: exit %d %+v", code, lines)
	}
	fp.outs, fp.errs = []relay.ProbeOutcome{{RegionID: r1, Skipped: relay.SkipRegionWithoutSTUN}}, []error{nil}
	if code, lines, _, _ = run(env, "--tenant", "tenant-a"); code != 3 || lines[0].Skipped != relay.SkipRegionWithoutSTUN {
		t.Fatalf("skipped: exit %d %+v", code, lines)
	}
	fp.outs, fp.errs = []relay.ProbeOutcome{bad, {RegionID: r1}}, []error{nil, errors.Join(relay.ErrProbeNotRun, errors.New("dial tcp: refused"))}
	code, lines, _, stderr = run(env, "--tenant", "tenant-a")
	if code != 1 || len(lines) != 2 || lines[1].ErrorCode != relay.CodeProberUnavailable || lines[1].Recorded || !strings.Contains(stderr, "refused") {
		t.Fatalf("could not run: exit %d %+v %q", code, lines, stderr)
	}
	fp.outs, fp.errs = nil, nil
	if code, lines, _, stderr = run(env, "--tenant", "tenant-a"); code != 0 || len(lines) != 0 || !strings.Contains(stderr, "no relay region") {
		t.Fatalf("nothing to probe: exit %d %+v %q", code, lines, stderr)
	}
	fp.err = errors.New("database unavailable")
	if code, _, _, _ = run(env, "--tenant", "tenant-a"); code != 1 {
		t.Fatalf("listing failed: exit %d", code)
	}
	fp.err = nil
	for _, args := range [][]string{{}, {"--tenant", "Bad Slug!"}, {"--tenant", "tenant-a", "extra"}, {"--tenant", "tenant-a", "--x"},
		{"--tenant", "unknown-tenant"}} {
		if code, _, _, _ := run(env, args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	// No prober configured: a usage/configuration error before anything is opened.
	noProber := wiredWorkerEnv(t)
	n := opened
	if code, _, _, stderr := run(mkEnv(noProber), "--tenant", "tenant-a"); code != 2 || opened != n || !strings.Contains(stderr, "MG_PROBER_URL") {
		t.Fatalf("no prober: exit %d (opened %d) %q", code, opened-n, stderr)
	}
	// the dispatch of `admin`
	var errb bytes.Buffer
	if code := admin(context.Background(), []string{"relay-probe", "--tenant", "Bad Slug!"}, nil, io.Discard, &errb,
		func(string) string { return "" }, nil); code != 2 || !strings.Contains(errb.String(), "relay-probe") {
		t.Fatalf("admin dispatch: %d %q", code, errb.String())
	}
}
