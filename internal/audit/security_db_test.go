package audit

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// secRow is a security event as the superuser reads it.
type secRow struct {
	Tenant   *uuid.UUID
	Kind     string
	Severity string
	Source   string
	Details  map[string]any
}

func (f *fixture) securityEvents(t *testing.T, actor uuid.UUID) []secRow {
	t.Helper()
	rows, err := f.su.Query(t.Context(), `SELECT tenant_id, kind, severity, source, details FROM security_events
		WHERE details ->> 'actor_identity_id' = $1 ORDER BY occurred_at, id`, actor.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []secRow
	for rows.Next() {
		var (
			r   secRow
			raw []byte
		)
		if err := rows.Scan(&r.Tenant, &r.Kind, &r.Severity, &r.Source, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &r.Details); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCrossTenantRule — §8.8 "chuỗi từ chối chéo tenant bất thường sinh security_events", with the rule of P2-T08
// (threshold 3 in 10 minutes here): fewer denials or same-tenant denials raise nothing; the threshold raises exactly one
// platform-scope event per actor and window (high; critical from 3 distinct target tenants); platform staff count in
// the platform scope; denials outside the window do not count; concurrent denials still raise one event.
func TestCrossTenantRule(t *testing.T) {
	f := newFixture(t, Config{CrossTenantThreshold: 3, CrossTenantWindow: 10 * time.Minute})
	ctx := t.Context()
	deny := func(actor uuid.UUID, tenant *uuid.UUID, target uuid.UUID) error {
		return f.log.RecordDetached(ctx, Event{TenantID: tenant, TargetTenantID: &target, ActorIdentityID: &actor,
			Action: "device.list", ResourceType: "device", Outcome: OutcomeDenied, Details: Details{"reason": "not_a_member"}})
	}
	mustDeny := func(actor uuid.UUID, tenant *uuid.UUID, target uuid.UUID, n int) {
		t.Helper()
		for range n {
			if err := deny(actor, tenant, target); err != nil {
				t.Fatal(err)
			}
		}
	}

	// 1. a user of A probing B: 2 denials ⇒ nothing; the 3rd ⇒ one high event; more in the window ⇒ still one
	x := newID(t)
	mustDeny(x, &f.a, f.b, 2)
	if got := f.securityEvents(t, x); len(got) != 0 {
		t.Fatalf("below the threshold: %+v", got)
	}
	mustDeny(x, &f.a, f.b, 1)
	got := f.securityEvents(t, x)
	if len(got) != 1 || got[0].Tenant != nil || got[0].Kind != KindCrossTenantDenials || got[0].Severity != SeverityHigh ||
		got[0].Source != SourceAudit || got[0].Details["denials"] != float64(3) || got[0].Details["target_tenants"] != float64(1) ||
		got[0].Details["actor_tenant"] != f.a.String() || got[0].Details["dedupe_key"] != KindCrossTenantDenials+":"+x.String() {
		t.Fatalf("at the threshold: %+v", got)
	}
	mustDeny(x, &f.a, f.b, 2)
	if got := f.securityEvents(t, x); len(got) != 1 {
		t.Errorf("one event per actor and window, got %d", len(got))
	}

	// 2. denials in the actor's own tenant are not cross-tenant (no target, never counted)
	y := newID(t)
	mustDeny(y, &f.a, f.a, 5)
	if got := f.securityEvents(t, y); len(got) != 0 {
		t.Errorf("same-tenant denials raised %+v", got)
	}
	if n := f.count(t, "SELECT count(*) FROM audit_events WHERE actor_identity_id = $1 AND target_tenant_id IS NOT NULL", y); n != 0 {
		t.Errorf("same-tenant denials carry a target tenant (%d)", n)
	}
	mustDeny(y, &f.a, f.b, 1) // 5 same-tenant + 1 cross-tenant: only the cross-tenant one counts
	if got := f.securityEvents(t, y); len(got) != 0 {
		t.Errorf("same-tenant denials were counted with a cross-tenant one: %+v", got)
	}

	// 3. three distinct target tenants ⇒ critical
	z := newID(t)
	mustDeny(z, &f.a, f.b, 1)
	mustDeny(z, &f.a, newID(t), 1)
	mustDeny(z, &f.a, newID(t), 1)
	if got := f.securityEvents(t, z); len(got) != 1 || got[0].Severity != SeverityCritical || got[0].Details["target_tenants"] != float64(3) {
		t.Errorf("probing three tenants: %+v", got)
	}

	// 4. platform staff on tenant routes: counted in the platform scope
	s := newID(t)
	mustDeny(s, nil, f.a, 3)
	if got := f.securityEvents(t, s); len(got) != 1 || got[0].Details["actor_tenant"] != "platform" {
		t.Errorf("platform staff: %+v", got)
	}

	// 5. denials older than the window do not count
	w := newID(t)
	for range 2 {
		f.exec(t, `INSERT INTO audit_events (occurred_at, tenant_id, actor_type, actor_identity_id, action, resource_type,
				outcome, target_tenant_id) VALUES (now() - interval '20 minutes', $1, 'identity', $2, 'device.list', 'device',
				'denied', $3)`, f.a, w, f.b)
	}
	mustDeny(w, &f.a, f.b, 1)
	if got := f.securityEvents(t, w); len(got) != 0 {
		t.Errorf("denials outside the window counted: %+v", got)
	}
	mustDeny(w, &f.a, f.b, 2)
	if got := f.securityEvents(t, w); len(got) != 1 {
		t.Errorf("three denials in the window: %d events", len(got))
	}

	// 6. concurrent denials of one actor ⇒ still exactly one event (dedupe serialised by the advisory lock)
	v := newID(t)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := deny(v, &f.b, f.a); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatal(errors.Join(errs...))
	}
	if got := f.securityEvents(t, v); len(got) != 1 {
		t.Errorf("12 concurrent denials: %d security events, want 1", len(got))
	}
	if n := f.counter(t, "meshguard_security_events_total", map[string]string{"kind": KindCrossTenantDenials}); n < 1 {
		t.Errorf("meshguard_security_events_total = %v", n)
	}
}

// TestSecurityEventDedupeIsSerialised: while a transaction that wrote an event with a dedupe key is still open, a second
// writer of the same key waits for it (advisory lock of the key) and, once it commits, writes nothing. Without the
// lock the second writer would not see the uncommitted row and would write a duplicate.
func TestSecurityEventDedupeIsSerialised(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	ev := SecurityEvent{Kind: "test.serial", Severity: SeverityLow, Source: "test", DedupeKey: "test:serial",
		DedupeWindow: time.Minute}
	written, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- f.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			wrote, err := RecordSecurityEvent(ctx, q, ev)
			if err != nil || !wrote {
				close(written)
				return errors.Join(err, errors.New("the first writer did not write"))
			}
			close(written)
			<-release // keep the transaction — and the lock of the key — open
			return nil
		})
	}()
	<-written
	type result struct {
		wrote bool
		err   error
	}
	second := make(chan result, 1)
	go func() {
		wrote, err := f.log.RecordSecurityEvent(ctx, ev)
		second <- result{wrote, err}
	}()
	select {
	case r := <-second:
		close(release)
		t.Fatalf("the second writer did not wait for the open transaction of the first: %+v (first: %v)", r, <-first)
	case <-time.After(500 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if r := <-second; r.err != nil || r.wrote {
		t.Errorf("second writer after the first committed: wrote %v (%v), want nothing written", r.wrote, r.err)
	}
	if n := f.count(t, "SELECT count(*) FROM security_events WHERE kind = 'test.serial'"); n != 1 {
		t.Errorf("%d events, want 1", n)
	}
}

// TestSecurityEvents: the writer checks kind, severity and source (and the CHECKs of 0004 back it); a dedupe key
// collapses repeats within its window only; a tenant-scoped event is visible to that tenant and not to another.
func TestSecurityEvents(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	for _, ev := range []SecurityEvent{
		{Kind: "Bad Kind", Severity: SeverityLow, Source: "test"},
		{Kind: "test.kind", Severity: "urgent", Source: "test"},
		{Kind: "test.kind", Severity: SeverityLow, Source: "Test Source"},
		{Kind: "test.kind", Severity: SeverityLow, Source: "test", DedupeKey: "k"},
	} {
		if _, err := f.log.RecordSecurityEvent(ctx, ev); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%+v: %v, want ErrInvalidEvent", ev, err)
		}
	}
	for _, sql := range []string{
		"INSERT INTO security_events (kind, severity, source) VALUES ('test.kind', 'urgent', 'test')",
		"INSERT INTO security_events (kind, severity, source) VALUES ('Bad Kind', 'low', 'test')",
		"INSERT INTO security_events (kind, severity, source) VALUES ('test.kind', 'low', 'Bad Source')",
	} {
		if _, err := f.su.Exec(ctx, sql); sqlState(err) != "23514" {
			t.Errorf("%s: %v, want check_violation", sql, err)
		}
	}
	ev := SecurityEvent{Kind: "test.repeat", Severity: SeverityMedium, Source: "test", DedupeKey: "test:one", DedupeWindow: time.Minute}
	for i, want := range []bool{true, false, false} {
		if wrote, err := f.log.RecordSecurityEvent(ctx, ev); err != nil || wrote != want {
			t.Errorf("repeat %d: wrote %v (%v), want %v", i, wrote, err, want)
		}
	}
	other := ev
	other.DedupeKey = "test:two"
	if wrote, err := f.log.RecordSecurityEvent(ctx, other); err != nil || !wrote {
		t.Errorf("another key: wrote %v (%v)", wrote, err)
	}
	f.exec(t, "UPDATE security_events SET occurred_at = now() - interval '2 minutes' WHERE kind = 'test.repeat'")
	if wrote, err := f.log.RecordSecurityEvent(ctx, ev); err != nil || !wrote {
		t.Errorf("after the window: wrote %v (%v)", wrote, err)
	}

	tenantEv := SecurityEvent{TenantID: &f.a, Kind: "device.expiry_overridden", Severity: SeverityHigh, Source: "devices"}
	if wrote, err := f.log.RecordSecurityEvent(ctx, tenantEv); err != nil || !wrote {
		t.Fatalf("tenant event: %v %v", wrote, err)
	}
	for tenant, want := range map[uuid.UUID]int64{f.a: 1, f.b: 0} {
		c := f.connectAs(t, "mg_api_tenant")
		if _, err := c.Exec(ctx, "SELECT set_config('app.scope', 'tenant', false), set_config('app.tenant_id', $1, false)",
			tenant.String()); err != nil {
			t.Fatal(err)
		}
		var n int64
		if err := c.QueryRow(ctx, "SELECT count(*) FROM security_events").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("tenant %s sees %d security events, want %d", tenant, n, want)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM security_events WHERE kind = 'test.repeat'"); n != 3 {
		t.Errorf("test.repeat: %d rows, want 3 (key one twice — the window passed —, key two once)", n)
	}
}
