package monitoring

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestHealthOf: the verdict shown for an instance — the recorded probe while fresh, otherwise unknown with the reason
// (never probed, not running, not a record of this module, stale) — at the boundary of StaleAfter.
func TestHealthOf(t *testing.T) {
	now := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	at := now.Add(-time.Minute)
	healthy := []byte(`{"schema":1,"status":"healthy","version":"v0.29.7","database":true,"breaker":"closed","duration_ms":4}`)
	down := []byte(`{"schema":1,"status":"unhealthy","reason":"instance_unavailable","breaker":"open","duration_ms":9}`)
	cases := []struct {
		name, status string
		raw          []byte
		at           *time.Time
		stale        time.Duration
		want         InstanceHealth
	}{
		{"healthy", "running", healthy, &at, time.Hour, InstanceHealth{StatusHealthy, "", &at, "v0.29.7"}},
		{"unhealthy", "running", down, &at, time.Hour, InstanceHealth{StatusUnhealthy, "instance_unavailable", &at, ""}},
		{"never probed", "running", nil, nil, time.Hour, InstanceHealth{StatusUnknown, ReasonNeverChecked, nil, ""}},
		{"time without record", "running", nil, &at, time.Hour, InstanceHealth{StatusUnknown, ReasonNeverChecked, nil, ""}},
		{"never probed, stopped", "stopped", nil, nil, time.Hour, InstanceHealth{StatusUnknown, ReasonInstanceNotRunning, nil, ""}},
		{"stopped", "stopped", healthy, &at, time.Hour, InstanceHealth{StatusUnknown, ReasonInstanceNotRunning, &at, "v0.29.7"}},
		{"quarantined", "quarantined", down, &at, time.Hour, InstanceHealth{StatusUnknown, ReasonInstanceNotRunning, &at, ""}},
		{"stale", "running", healthy, &at, 59 * time.Second, InstanceHealth{StatusUnknown, ReasonStale, &at, "v0.29.7"}},
		{"at the limit", "running", healthy, &at, time.Minute, InstanceHealth{StatusHealthy, "", &at, "v0.29.7"}},
		{"foreign", "running", []byte(`{"status":"healthy"}`), &at, time.Hour, InstanceHealth{StatusUnknown, ReasonInvalidRecord, &at, ""}},
		{"healthy with reason", "running", []byte(`{"schema":1,"status":"healthy","reason":"x"}`), &at, time.Hour,
			InstanceHealth{StatusUnknown, ReasonInvalidRecord, &at, ""}},
		{"unhealthy without reason", "running", []byte(`{"schema":1,"status":"unhealthy"}`), &at, time.Hour,
			InstanceHealth{StatusUnknown, ReasonInvalidRecord, &at, ""}},
		{"reason with text", "running", []byte(`{"schema":1,"status":"unhealthy","reason":"Headscale said: no"}`), &at, time.Hour,
			InstanceHealth{StatusUnknown, ReasonInvalidRecord, &at, ""}},
		{"not json", "running", []byte(`healthy`), &at, time.Hour, InstanceHealth{StatusUnknown, ReasonInvalidRecord, &at, ""}},
	}
	for _, c := range cases {
		got := HealthOf(c.status, c.raw, c.at, now, c.stale)
		if got.Status != c.want.Status || got.Reason != c.want.Reason || got.Version != c.want.Version ||
			(got.CheckedAt == nil) != (c.want.CheckedAt == nil) || (got.CheckedAt != nil && !got.CheckedAt.Equal(*c.want.CheckedAt)) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestRecordOf: what a probe stores — healthy only with no failure AND the database reachable; a reason, version or
// breaker that is not a stable value is never stored as text.
func TestRecordOf(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name  string
		probe InstanceProbe
		want  record
	}{
		{"healthy", InstanceProbe{Version: "v0.29.7", Database: &yes, Breaker: "closed", Duration: 12 * time.Millisecond},
			record{Schema: 1, Status: StatusHealthy, Version: "v0.29.7", Database: &yes, Breaker: "closed", DurationMS: 12}},
		{"database down", InstanceProbe{Version: "v0.29.7", Database: &no, Breaker: "closed", Reason: "database_unreachable"},
			record{Schema: 1, Status: StatusUnhealthy, Reason: "database_unreachable", Version: "v0.29.7", Database: &no, Breaker: "closed"}},
		{"no failure but no database", InstanceProbe{Version: "v0.29.7", Breaker: "closed"},
			record{Schema: 1, Status: StatusUnhealthy, Reason: ReasonIncompleteProbe, Version: "v0.29.7", Breaker: "closed"}},
		{"no failure, database false", InstanceProbe{Database: &no},
			record{Schema: 1, Status: StatusUnhealthy, Reason: ReasonIncompleteProbe, Database: &no}},
		{"text as reason", InstanceProbe{Reason: "upstream said hskey-" + "api-abc"},
			record{Schema: 1, Status: StatusUnhealthy, Reason: ReasonInvalidRecord}},
		{"odd version and breaker", InstanceProbe{Version: "v0.29.7 <script>", Breaker: "weird", Reason: "circuit_open"},
			record{Schema: 1, Status: StatusUnhealthy, Reason: "circuit_open"}},
	}
	for _, c := range cases {
		got := recordOf(c.probe)
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(c.want)
		if string(g) != string(w) {
			t.Errorf("%s: %s, want %s", c.name, g, w)
		}
		if !got.valid() {
			t.Errorf("%s: recordOf produced a record HealthOf would not read: %s", c.name, g)
		}
		if strings.Contains(string(g), "hskey") || strings.Contains(string(g), "script") {
			t.Errorf("%s: stored text %s", c.name, g)
		}
	}
}

// TestSchedulerSlots: offsets spread instances over the interval, and they differ from inventory.sync's (salted hash).
func TestSchedulerSlots(t *testing.T) {
	sc := (&Service{}).NewScheduler(SchedulerConfig{Interval: time.Minute})
	if sc.cfg.Tick != 15*time.Second {
		t.Errorf("default tick %v", sc.cfg.Tick)
	}
	if d := (&Service{}).NewScheduler(SchedulerConfig{}); d.cfg.Interval != DefaultProbeInterval || d.cfg.Tick != 15*time.Second {
		t.Errorf("defaults %+v", d.cfg)
	}
	now := time.Now()
	offsets := map[int64]bool{}
	for range 8 {
		id := uuid.New()
		s := sc.slot(id, now)
		if s != sc.slot(id, now) {
			t.Fatal("slot is not deterministic")
		}
		// the instant the slot changes, within one interval of now
		for d := time.Duration(0); d <= time.Minute; d += time.Second {
			if sc.slot(id, now.Add(d)) != s {
				offsets[int64(d/time.Second)] = true
				break
			}
		}
	}
	if len(offsets) < 3 {
		t.Errorf("8 instances start their period at only %d offsets", len(offsets))
	}
}

// TestNotYetSections: every section without a figure has a stable reason and a detail; the devices section is not
// in the static list (it depends on the tenant's sync).
func TestNotYetSections(t *testing.T) {
	seen := map[string]bool{}
	for _, u := range notYet {
		if !codeRE.MatchString(u.Section) || (u.Reason != ReasonNoSource && u.Reason != ReasonNotServed) || u.Detail == "" || seen[u.Section] {
			t.Errorf("section %+v", u)
		}
		seen[u.Section] = true
	}
	if seen[SectionDevices] || len(seen) != 4 {
		t.Errorf("sections %v", seen)
	}
}
