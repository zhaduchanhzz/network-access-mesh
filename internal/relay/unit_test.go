package relay

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

func doc(t *testing.T, r record) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRecordOf: the verdict follows the two checks (healthy only when both pass; one reason per failing combination);
// a code that is not a stable one is not stored as text; an HTTP status outside 100–599 is not stored; a passed check
// carries no code. The stored document is understood back (valid) — and a forged one whose verdict contradicts its
// checks is not.
func TestRecordOf(t *testing.T) {
	for _, tc := range []struct {
		name           string
		in             ProbeResult
		status, reason string
	}{
		{"both pass", healthyResult, StatusHealthy, ""},
		{"derp 404", ProbeResult{DERP: Check{Status: 404, Code: "expectation_failed"}, STUN: Check{OK: true}}, StatusUnhealthy, ReasonDERPProbeFailed},
		{"stun refused", ProbeResult{DERP: Check{OK: true, Status: 200}, STUN: Check{Code: "refused"}}, StatusUnhealthy, ReasonSTUNProbeFailed},
		{"both fail", ProbeResult{DERP: Check{Code: "timeout"}, STUN: Check{Code: "timeout"}}, StatusUnhealthy, ReasonRelayUnreachable},
	} {
		r := recordOf(tc.in)
		if r.Status != tc.status || r.Reason != tc.reason || r.Schema != recordSchema || !r.valid() {
			t.Errorf("%s: %+v (valid %v), want %s/%q", tc.name, r, r.valid(), tc.status, tc.reason)
		}
	}
	r := recordOf(ProbeResult{DERP: Check{Status: 999, Code: "Upstream said: secret token=abc", Duration: -time.Second},
		STUN: Check{OK: true, Code: "ignored", Duration: 1500 * time.Microsecond}})
	if r.DERP.Status != 0 || r.DERP.Code != "check_failed" || r.DERP.DurationMS != 0 || r.STUN.Code != "" || r.STUN.DurationMS != 1 ||
		!r.valid() {
		t.Errorf("sanitised record %+v", r)
	}
	if b := doc(t, r); strings.Contains(string(b), "token") || strings.Contains(string(b), "Upstream") {
		t.Errorf("upstream text stored: %s", b)
	}
	forged := recordOf(healthyResult)
	forged.DERP.OK = false
	forged.DERP.Code = "timeout"
	for name, bad := range map[string]record{
		"verdict contradicts the checks": forged,
		"other schema":                   {Schema: 2, Status: StatusHealthy, DERP: checkRecord{OK: true}, STUN: checkRecord{OK: true}},
		"unknown status":                 {Schema: 1, Status: "fine", DERP: checkRecord{OK: true}, STUN: checkRecord{OK: true}},
		"free text code":                 {Schema: 1, Status: StatusUnhealthy, Reason: ReasonDERPProbeFailed, DERP: checkRecord{Code: "Bad Gateway"}, STUN: checkRecord{OK: true}},
		"passed check with a code":       {Schema: 1, Status: StatusHealthy, DERP: checkRecord{OK: true, Code: "timeout"}, STUN: checkRecord{OK: true}},
	} {
		if bad.valid() {
			t.Errorf("%s: accepted as a record of the module", name)
		}
	}
}

// TestHealthOf: the read-side rule, one case per branch — a verdict only from a valid record of a fresh probe of an
// active embedded region served by a running instance; otherwise unknown with the reason, the time of the last probe
// kept when there is one, and its checks kept when the record is understood.
func TestHealthOf(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	fresh, old := now.Add(-time.Minute), now.Add(-DefaultStaleAfter-time.Second)
	good, _ := json.Marshal(recordOf(healthyResult))
	bad, _ := json.Marshal(recordOf(ProbeResult{DERP: Check{OK: true, Status: 200}, STUN: Check{Code: "refused"}}))
	junk := []byte(`{"schema":1,"status":"healthy"}`)
	in := func(mod func(*HealthInput)) HealthInput {
		h := HealthInput{Kind: KindEmbedded, Active: true, Serving: true, LastProbe: good, LastProbeAt: &fresh, Now: now,
			StaleAfter: DefaultStaleAfter}
		if mod != nil {
			mod(&h)
		}
		return h
	}
	for _, tc := range []struct {
		name           string
		in             HealthInput
		status, reason string
		checkedAt      *time.Time
		checks         bool
	}{
		{"healthy", in(nil), StatusHealthy, "", &fresh, true},
		{"unhealthy", in(func(h *HealthInput) { h.LastProbe = bad }), StatusUnhealthy, ReasonSTUNProbeFailed, &fresh, true},
		{"stale", in(func(h *HealthInput) { h.LastProbeAt = &old }), StatusUnknown, ReasonStale, &old, true},
		{"never probed", in(func(h *HealthInput) { h.LastProbe, h.LastProbeAt = nil, nil }), StatusUnknown, ReasonNeverChecked, nil, false},
		{"never probed, not active", in(func(h *HealthInput) { h.LastProbe, h.LastProbeAt, h.Active = nil, nil, false }),
			StatusUnknown, ReasonNotActive, nil, false},
		{"never probed, instance down", in(func(h *HealthInput) { h.LastProbe, h.LastProbeAt, h.Serving = nil, nil, false }),
			StatusUnknown, ReasonInstanceNotRunning, nil, false},
		{"not active", in(func(h *HealthInput) { h.Active = false }), StatusUnknown, ReasonNotActive, &fresh, true},
		{"instance not running", in(func(h *HealthInput) { h.Serving = false }), StatusUnknown, ReasonInstanceNotRunning, &fresh, true},
		{"invalid record", in(func(h *HealthInput) { h.LastProbe = junk }), StatusUnknown, ReasonInvalidRecord, &fresh, false},
		{"not json", in(func(h *HealthInput) { h.LastProbe = []byte(`[1]`) }), StatusUnknown, ReasonInvalidRecord, &fresh, false},
		{"standalone region", in(func(h *HealthInput) { h.Kind = KindStandalone }), StatusUnknown, ReasonNoProbe, nil, false},
		{"shared region", in(func(h *HealthInput) { h.Kind = KindShared }), StatusUnknown, ReasonNoProbe, nil, false},
	} {
		h := HealthOf(tc.in)
		if h.Status != tc.status || h.Reason != tc.reason || (h.CheckedAt == nil) != (tc.checkedAt == nil) ||
			(h.CheckedAt != nil && !h.CheckedAt.Equal(*tc.checkedAt)) || (h.DERP != nil) != tc.checks || (h.STUN != nil) != tc.checks {
			t.Errorf("%s: %+v, want %s/%q at %v (checks %v)", tc.name, h, tc.status, tc.reason, tc.checkedAt, tc.checks)
		}
		if h.CheckedAt != nil && h.CheckedAt.Location() != time.UTC {
			t.Errorf("%s: checked_at not in UTC", tc.name)
		}
	}
	if h := HealthOf(in(func(h *HealthInput) { h.LastProbe = bad })); h.STUN.Code != "refused" || h.STUN.OK || !h.DERP.OK ||
		h.DERP.Status != 200 {
		t.Errorf("checks of an unhealthy probe: derp %+v stun %+v", h.DERP, h.STUN)
	}
}

// TestUnmeasured: the figures of §10.6 without a source are listed with a stable reason and a sentence — and a caller
// cannot change the module's list.
func TestUnmeasured(t *testing.T) {
	u := Unmeasured()
	var metrics []string
	for _, x := range u {
		metrics = append(metrics, x.Metric)
		if !codeRE.MatchString(x.Metric) || (x.Reason != ReasonUnsupported && x.Reason != ReasonNoSource) || x.Detail == "" {
			t.Errorf("unavailable %+v", x)
		}
	}
	if !slices.Equal(metrics, []string{"traffic_bytes", "throughput", "connections", "auth_failures", "client_latency"}) {
		t.Errorf("metrics %v", metrics)
	}
	u[0].Reason = "changed"
	if Unmeasured()[0].Reason == "changed" {
		t.Error("Unmeasured returns the module's own slice")
	}
}

// TestCursor: the cursor of the platform list round-trips and anything else is ErrInvalid.
func TestCursor(t *testing.T) {
	at, id := time.Date(2026, 11, 18, 1, 2, 3, 456789000, time.FixedZone("x", 7*3600)), uuid.New()
	gt, gid, err := decodeCursor(encodeCursor(at, id))
	if err != nil || !gt.Equal(at) || gid != id {
		t.Fatalf("round trip: %v %v %v", gt, gid, err)
	}
	for _, bad := range []string{"%%%", "bm90LWEtY3Vyc29y", encodeCursor(at, id)[:10], strings.Repeat("A", 600)} {
		if _, _, err := decodeCursor(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("cursor %q: %v", bad, err)
		}
	}
}

// TestKindRegistered: relay.probe is a tenant job of the registry (one attempt, dedupe per region and slot) and the
// defaults keep a probe below the job's timeout and a verdict alive for at least two missed periods.
func TestKindRegistered(t *testing.T) {
	if _, err := New(nil, Config{}); err == nil {
		t.Error("no store accepted")
	}
	k, ok := jobs.DefaultKinds()[KindProbe]
	if !ok || k.Scope != jobs.ScopeTenant || k.MaxAttempts != 1 || k.Dedupe != "relay:{object}:probe:{slot}" ||
		DefaultProbeTimeout >= k.Timeout || DefaultStaleAfter < 2*DefaultProbeInterval {
		t.Fatalf("relay.probe kind %+v (probe bound %v)", k, DefaultProbeTimeout)
	}
}
