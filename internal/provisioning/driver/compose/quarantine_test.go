//go:build linux

package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// dataSums is sha256 of every file of data/ (the test reads them as root; the agent never does).
func dataSums(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, "data", e.Name())) //nolint:gosec // G304: test
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(s[:])
	}
	return out
}

func mapEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestQuarantineInstance — §11.4 Quarantine on the agent (P3-T18): the marker first, then flag cleared, edge detached,
// container stopped, data/ untouched; idempotent (the first quarantine stays the reference); the supervisor never
// attaches a marked instance and contains it again when something starts or attaches it behind the agent's back
// (Critical quarantine_breach); ReleaseInstance refuses another policy and a start-guard violation (still marked,
// stopped), refuses an instance never activated, and with the applied policy starts it, waits healthy and unmarks
// it — without attaching the edge.
func TestQuarantineInstance(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	rg.withEdge()
	rg.provision(t, rg.s)
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
	sums := dataSums(t, rg.idir)
	marker := filepath.Join(rg.idir, "meta", quarantineName)
	status := func() *agentv1.InstanceStatus {
		t.Helper()
		st, err := rg.d.InstanceStatus(ctx, rg.s.Ref, false)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	isolated := func(what string) {
		t.Helper()
		st := status()
		if !st.GetQuarantined() || st.GetEdgeAttachFlag() || st.GetNetwork().GetEdgeAttached() || rg.edgeOn("mg-t-acme") ||
			st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_EXITED {
			t.Fatalf("%s: not isolated: quarantined %v flag %v edge %v state %s", what, st.GetQuarantined(),
				st.GetEdgeAttachFlag(), st.GetNetwork().GetEdgeAttached(), st.GetContainerState())
		}
		if !mapEqual(dataSums(t, rg.idir), sums) {
			t.Fatalf("%s: data/ changed", what)
		}
	}
	if q, err := rg.d.Quarantined(ctx, rg.s.Ref); err != nil || q {
		t.Fatalf("Quarantined before: %v %v", q, err)
	}
	job := uuid.New()
	r, err := rg.d.QuarantineInstance(ctx, agentspec.Call{Ref: rg.s.Ref, JobID: job})
	if err != nil || !r.GetMarkedNow() || !r.GetEdgeWasAttached() || !r.GetContainerWasRunning() {
		t.Fatalf("QuarantineInstance: %+v %v", r, err)
	}
	isolated("quarantine")
	fi, err := os.Lstat(marker)
	if err != nil || fi.Mode().Perm() != 0o400 || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("marker: %v %v", fi, err)
	}
	raw, _ := os.ReadFile(marker) //nolint:gosec // G304: test
	var m map[string]string
	if json.Unmarshal(raw, &m) != nil || m["job_id"] != job.String() || m["quarantined_at"] == "" {
		t.Fatalf("marker content %s", raw)
	}
	if q, err := rg.d.Quarantined(ctx, rg.s.Ref); err != nil || !q {
		t.Fatalf("Quarantined: %v %v", q, err)
	}
	// again: nothing to do, the first quarantine kept
	if r, err := rg.d.QuarantineInstance(ctx, agentspec.Call{Ref: rg.s.Ref, JobID: uuid.New()}); err != nil || r.GetMarkedNow() ||
		r.GetEdgeWasAttached() || r.GetContainerWasRunning() {
		t.Fatalf("again: %+v %v", r, err)
	}
	if again, _ := os.ReadFile(marker); string(again) != string(raw) { //nolint:gosec // G304: test
		t.Fatal("the marker of the first quarantine was rewritten")
	}

	// ---- the supervisor: never attached; started and attached by hand ⇒ contained again, Critical
	cycle := func() EdgeReport {
		t.Helper()
		rep, err := rg.d.EdgeCycle(ctx, lockAll)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	for range 3 {
		if rep := cycle(); !slices.Equal(rep.Quarantined, []string{"acme"}) || len(rep.NewlyAttached) != 0 || len(rep.Contained) != 0 {
			t.Fatalf("quiet cycle: %+v", rep)
		}
	}
	isolated("three supervisor cycles")
	rg.e.mu.Lock()
	rg.e.ctrs["mg-hs-acme"].State = "running"
	rg.e.mu.Unlock()
	_ = rg.e.ConnectNetwork(ctx, "mg-t-acme", "mg-edge")
	if rep := cycle(); !slices.Equal(rep.Contained, []string{"acme"}) {
		t.Fatalf("bypass not contained: %+v", rep)
	}
	isolated("bypass contained")
	if ev := rg.logs.lines(t, "quarantine_breach"); len(ev) != 1 || ev[0]["severity"] != "critical" ||
		!strings.Contains(strings.Join(anyStrings(ev[0]["actions"]), ","), "container_stopped") {
		t.Fatalf("breach events %v", ev)
	}

	// ---- release: another policy ⇒ refused, still marked, stopped again
	baseline := sha256Hex([]byte(templates.BootstrapPolicy))
	_, err = rg.d.ReleaseInstance(ctx, agentspec.Release{Call: rg.call(), ExpectedPolicySHA256: strings.Repeat("0", 64)})
	if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE || !strings.Contains(err.Error(), "not released") {
		t.Fatalf("another policy: %v", err)
	}
	isolated("refused release (policy)")
	// the start guard: another Noise key ⇒ refused and contained, still marked
	key := filepath.Join(rg.idir, "data", "noise_private.key")
	saved, _ := os.ReadFile(key) //nolint:gosec // G304: test
	_ = os.Remove(key)
	_ = os.WriteFile(key, newNoiseKey(), 0o600)
	_, err = rg.d.ReleaseInstance(ctx, agentspec.Release{Call: rg.call(), ExpectedPolicySHA256: baseline})
	if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE || !strings.Contains(err.Error(), "start guard") {
		t.Fatalf("start guard: %v", err)
	}
	if st := status(); !st.GetQuarantined() || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_EXITED {
		t.Fatal("start guard: not still quarantined and stopped")
	}
	_ = os.Remove(key)
	_ = os.WriteFile(key, saved, 0o600)
	_ = os.Chown(key, int(rg.s.RunUID), int(rg.s.RunUID))
	// the applied policy: started through the guard, healthy, unmarked — never attached here
	rel, err := rg.d.ReleaseInstance(ctx, agentspec.Release{Call: rg.call(), ExpectedPolicySHA256: baseline})
	if err != nil || !rel.GetWasQuarantined() || rel.GetPolicySha256() != baseline {
		t.Fatalf("release: %+v %v", rel, err)
	}
	st := status()
	if st.GetQuarantined() || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING ||
		st.GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY || st.GetEdgeAttachFlag() || rg.edgeOn("mg-t-acme") {
		t.Fatalf("after the release: %+v", st)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("marker left")
	}
	if rep := cycle(); len(rep.Quarantined) != 0 || rg.edgeOn("mg-t-acme") {
		t.Fatalf("the supervisor attached without the flag: %+v", rep)
	}
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err != nil || !rg.edgeOn("mg-t-acme") {
		t.Fatalf("attachment after the release: %v", err)
	}
	// a release of an instance not quarantined: the checks again, nothing removed
	if rel, err := rg.d.ReleaseInstance(ctx, agentspec.Release{Call: rg.call(), ExpectedPolicySHA256: baseline}); err != nil || rel.GetWasQuarantined() {
		t.Fatalf("release again: %+v %v", rel, err)
	}
	if !mapEqual(dataSums(t, rg.idir), sums) {
		t.Fatal("data/ changed by quarantine and release")
	}

	// ---- an instance never activated: quarantined like any, never released
	b := rg.second("beta")
	rg.provision(t, b)
	if _, err := rg.d.QuarantineInstance(ctx, agentspec.Call{Ref: b.Ref, JobID: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	if _, err := rg.d.ReleaseInstance(ctx, agentspec.Release{Call: agentspec.Call{Ref: b.Ref, JobID: uuid.New()},
		ExpectedPolicySHA256: baseline}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE ||
		!strings.Contains(err.Error(), "never activated") {
		t.Fatalf("never activated: %v", err)
	}
	if q, _ := rg.d.Quarantined(ctx, b.Ref); !q {
		t.Fatal("the never-activated instance lost its marker")
	}
	// an unknown instance is not quarantined
	if q, err := rg.d.Quarantined(ctx, agentspec.Ref{InstanceID: uuid.New(), TenantID: uuid.New(), Slug: "nope"}); err != nil || q {
		t.Fatalf("unknown: %v %v", q, err)
	}
}

func anyStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
