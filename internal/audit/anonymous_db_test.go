package audit

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestAnonymousDenialRows — G2 F2 on PostgreSQL: 150 anonymous denials of one key (IPv6 client, tenant A, action,
// reason) leave 3 rows — the 1st, 10th and 100th, each with the running count, the /64 and the window, in the event's
// tenant, on the detached path. A denial WITH an actor is never aggregated: one row each (§8.8). A new window starts
// counting again. The metric counts every anonymous denial.
func TestAnonymousDenialRows(t *testing.T) {
	var mu sync.Mutex
	now := time.Now().UTC()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	f := newFixture(t, Config{AnonymousWindow: time.Minute, Now: clock})
	ctx := t.Context()
	ev := func(i int) Event {
		return Event{TenantID: &f.a, Action: "auth.login", ResourceType: "session", Outcome: OutcomeDenied,
			ActorIP: netip.MustParseAddr(fmt.Sprintf("2001:db8:7::%x", i)), RequestID: fmt.Sprintf("req-anon-%d", i),
			Details: Details{"reason": "state_unknown_or_used"}}
	}
	for i := 1; i <= 150; i++ {
		if err := f.log.RecordAnonymousDenial(ctx, ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	got := f.events(t, "request_id LIKE 'req-anon-%'")
	if len(got) != 3 {
		t.Fatalf("%d rows for 150 anonymous denials, want 3 (1st, 10th, 100th)", len(got))
	}
	for i, want := range []int{1, 10, 100} {
		r := got[i]
		if r.RequestID != fmt.Sprintf("req-anon-%d", want) || r.Details["count"] != float64(want) || r.Tenant == nil ||
			*r.Tenant != f.a || r.Actor != nil || r.Outcome != OutcomeDenied || r.Details["client_prefix"] != "2001:db8:7::/64" ||
			r.Details["window_seconds"] != float64(60) || r.Details["reason"] != "state_unknown_or_used" {
			t.Errorf("row %d: %+v", i, r)
		}
	}
	actor := newID(t)
	for i := range 3 {
		e := ev(1000 + i)
		e.ActorIdentityID = &actor
		if err := f.log.RecordAnonymousDenial(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.events(t, "actor_identity_id = $1", actor)); n != 3 {
		t.Errorf("denials with an actor: %d rows, want 3 (one each)", n)
	}
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	if err := f.log.RecordAnonymousDenial(ctx, ev(2000)); err != nil {
		t.Fatal(err)
	}
	if got := f.events(t, "request_id = 'req-anon-2000'"); len(got) != 1 || got[0].Details["count"] != float64(1) {
		t.Errorf("first denial of a new window: %+v", got)
	}
	mfs, err := f.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var counted float64
	for _, mf := range mfs {
		if mf.GetName() == "meshguard_audit_anonymous_denials_total" {
			for _, m := range mf.GetMetric() {
				counted += m.GetCounter().GetValue()
			}
		}
	}
	if counted != 151 {
		t.Errorf("meshguard_audit_anonymous_denials_total = %v, want 151 (the denials with an actor are not anonymous)", counted)
	}
}
