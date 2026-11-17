package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

const (
	privilegeErr   = "42501" // insufficient_privilege (also: a row refused by an RLS policy)
	restrictViolat = "23001" // restrict_violation: the append-only trigger of 0004
)

// TestAppendOnlyForEveryRole — §20 P2-T08 "UPDATE/DELETE bị từ chối", T-03 "test UPDATE/DELETE trên audit_events bị từ
// chối": no role of the system can change or erase an audit event. The application roles (in their own scope), the
// detached writer, the report role and the migrator lack the privilege (42501); the owner — the partition.maintain
// role — and the migrator acting as it, and even the superuser, are stopped by the trigger (23001); on the parent the
// owner's UPDATE/DELETE reach no row at all (FORCE ROW LEVEL SECURITY, no policy for it).
func TestAppendOnlyForEveryRole(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	if err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
		return Record(ctx, q, Event{TenantID: &f.a, Action: "tenant.read", ResourceType: "tenant"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		return Record(ctx, q, Event{Action: "platform.tenant.read", ResourceType: "tenant"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.log.RecordDetached(ctx, Event{TenantID: &f.b, Action: "device.rename", ResourceType: "device",
		Outcome: OutcomeDenied}); err != nil {
		t.Fatal(err)
	}
	const all = "SELECT count(*) FROM audit_events"
	before := f.count(t, all)
	var part string
	if err := f.su.QueryRow(ctx, "SELECT tableoid::regclass::text FROM audit_events LIMIT 1").Scan(&part); err != nil {
		t.Fatal(err)
	}
	// schema-qualified: mg_readonly has no USAGE on public (P2-T03), the name must not just fail to resolve
	modify := []string{"UPDATE public.audit_events SET outcome = 'failure'", "DELETE FROM public.audit_events",
		"TRUNCATE public.audit_events", "UPDATE public.audit_events SET details = '{}'"}

	for _, role := range []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform",
		store.AuditWriterRole, "mg_readonly", "mg_migrator"} {
		c := f.connectAs(t, role)
		// in their own scope, so that the refusal is the privilege and not an empty RLS view
		_, _ = c.Exec(ctx, "SELECT set_config('app.scope', 'tenant', false), set_config('app.tenant_id', $1, false)", f.a.String())
		for _, sql := range append(modify, "TRUNCATE "+part, "DELETE FROM "+part) {
			if _, err := c.Exec(ctx, sql); sqlState(err) != privilegeErr {
				t.Errorf("%s: %s ⇒ %v, want SQLSTATE %s", role, sql, err, privilegeErr)
			}
		}
	}

	owner := f.connectAs(t, "mg_partition_maint")
	mig := f.connectAs(t, "mg_migrator")
	if _, err := mig.Exec(ctx, "SET ROLE mg_partition_maint"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		who  string
		exec func(string) error
	}{
		{"mg_partition_maint (owner)", func(sql string) error { _, err := owner.Exec(ctx, sql); return err }},
		{"mg_migrator SET ROLE owner", func(sql string) error { _, err := mig.Exec(ctx, sql); return err }},
		{"superuser", func(sql string) error { _, err := f.su.Exec(ctx, sql); return err }},
	} {
		for _, sql := range []string{"UPDATE " + part + " SET outcome = 'failure'", "DELETE FROM " + part,
			"TRUNCATE audit_events", "TRUNCATE " + part} {
			if err := s.exec(sql); sqlState(err) != restrictViolat {
				t.Errorf("%s: %s ⇒ %v, want SQLSTATE %s (append-only trigger)", s.who, sql, err, restrictViolat)
			}
		}
	}
	for _, sql := range []string{"UPDATE audit_events SET outcome = 'failure'", "DELETE FROM audit_events"} {
		tag, err := owner.Exec(ctx, sql)
		if err != nil && sqlState(err) != restrictViolat || err == nil && tag.RowsAffected() != 0 {
			t.Errorf("owner: %s ⇒ %v rows, err %v — want no row changed", sql, tag.RowsAffected(), err)
		}
	}
	if after := f.count(t, all); after != before {
		t.Errorf("audit events: %d before, %d after the attempts", before, after)
	}
	if n := f.count(t, "SELECT count(*) FROM audit_events WHERE outcome = 'failure'"); n != 0 {
		t.Errorf("%d events were rewritten", n)
	}
}

// TestDeniedSurvivesRollback — §20 P2-T08 "sự kiện denied còn lại sau khi transaction nghiệp vụ rollback": inside a
// business transaction that then rolls back, the success event written in it disappears while the denied event of the
// detached path stays; the detached path also ignores the cancellation of the request and refuses success events.
func TestDeniedSurvivesRollback(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	actor, req := newID(t), newID(t).String()
	errBusiness := errors.New("business failure")
	err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
		if err := Record(ctx, q, Event{TenantID: &f.a, ActorIdentityID: &actor, Action: "device.rename",
			ResourceType: "device", ResourceID: "dev-1", RequestID: req}); err != nil {
			return err
		}
		if err := f.log.RecordDetached(ctx, Event{TenantID: &f.a, ActorIdentityID: &actor, Action: "device.rename",
			ResourceType: "device", ResourceID: "dev-1", RequestID: req, Outcome: OutcomeDenied,
			Details: Details{"reason": "not_own_resource"}}); err != nil {
			return err
		}
		return errBusiness
	})
	if !errors.Is(err, errBusiness) {
		t.Fatalf("business transaction: %v", err)
	}
	got := f.events(t, "request_id = $1", req)
	if len(got) != 1 || got[0].Outcome != OutcomeDenied || got[0].Tenant == nil || *got[0].Tenant != f.a ||
		got[0].Actor == nil || *got[0].Actor != actor || got[0].Details["reason"] != "not_own_resource" {
		t.Fatalf("after rollback: %+v, want only the denied event of the detached path", got)
	}

	// The client went away: the denial is still written (the write is detached from the request's cancellation).
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	req2 := newID(t).String()
	if err := f.log.RecordDetached(cctx, Event{TenantID: &f.a, Action: "device.expire", ResourceType: "device",
		RequestID: req2, Outcome: OutcomeFailure}); err != nil {
		t.Fatalf("detached write with a cancelled request context: %v", err)
	}
	if n := len(f.events(t, "request_id = $1", req2)); n != 1 {
		t.Errorf("events of the cancelled request: %d, want 1", n)
	}

	// Success events belong in the business transaction (§6.1): the detached path refuses them, counts and logs.
	err = f.log.RecordDetached(ctx, Event{TenantID: &f.a, Action: "device.rename", ResourceType: "device"})
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("detached success event: %v, want ErrInvalidEvent", err)
	}
	if f.counter(t, "meshguard_audit_write_failures_total", map[string]string{"path": pathDetached}) < 1 ||
		!f.logged("audit: write failed", "path", pathDetached) {
		t.Error("a refused detached write is neither counted nor logged")
	}
}

// TestOpenAuditWriterRefusesOtherRoles: the detached pool accepts only an insert-only role — an application role (it
// can read, and its RLS would refuse other tenants) or the owner (it can do everything) is refused at start-up.
func TestOpenAuditWriterRefusesOtherRoles(t *testing.T) {
	f := newFixture(t, Config{})
	for _, role := range []string{"mg_api_tenant", "mg_api_platform", "mg_worker_platform", "mg_partition_maint", "mg_readonly"} {
		w, err := store.OpenAuditWriter(t.Context(), f.env.URL(f.db), f.env.Creds(t, role))
		if err == nil {
			w.Close()
			t.Errorf("OpenAuditWriter accepted %s", role)
		}
	}
	if _, err := New(f.st, nil, Config{}); err == nil {
		t.Error("New without the detached writer succeeded")
	}
}

// TestRecordChecksTenant: an event written in the business transaction must belong to that transaction's scope — RLS
// refuses another tenant, a platform event in a tenant transaction and a tenant event in a platform transaction; with
// the request scope the tenant of the path, the action, the actor and the resource are the defaults.
func TestRecordChecksTenant(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	ev := func(tenant *uuid.UUID) Event {
		return Event{TenantID: tenant, Action: "device.rename", ResourceType: "device"}
	}
	for name, run := range map[string]func() error{
		"tenant B in a transaction of A": func() error {
			return f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error { return Record(ctx, q, ev(&f.b)) })
		},
		"platform event in a transaction of A": func() error {
			return f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error { return Record(ctx, q, ev(nil)) })
		},
		"tenant A in a platform transaction": func() error {
			return f.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error { return Record(ctx, q, ev(&f.a)) })
		},
	} {
		if err := run(); sqlState(err) != privilegeErr {
			t.Errorf("%s: %v, want RLS refusal (%s)", name, err, privilegeErr)
		}
	}

	actor := newID(t)
	rctx := WithRequest(ctx, &Request{TenantID: &f.a, Action: "device.rename", ResourceType: "device", ResourceID: "dev-7",
		RequestID: "req-defaults", ActorType: ActorIdentity, ActorIdentityID: &actor, ActorDisplay: "Alice"})
	if err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
		return Record(rctx, q, Event{Details: Details{"given_name": "laptop-2"}})
	}); err != nil {
		t.Fatal(err)
	}
	got := f.events(t, "request_id = 'req-defaults'")
	if len(got) != 1 || *got[0].Tenant != f.a || got[0].Action != "device.rename" || got[0].Resource != "device" ||
		got[0].ResourceID != "dev-7" || *got[0].Actor != actor || got[0].Details["given_name"] != "laptop-2" ||
		got[0].Outcome != OutcomeSuccess {
		t.Errorf("event with request defaults: %+v", got)
	}
}

// TestNoSecretInDetails — "never put secrets, tokens, cookies, codes or upstream bodies in details": a canary placed
// under credential-like keys and in credential-shaped values, through every write path, never reaches the database.
func TestNoSecretInDetails(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	canary := "canary" + strings.ReplaceAll(uuid.NewString(), "-", "")
	details := func() Details {
		return Details{
			"token": canary, "client_secret": canary, "Authorization": canary, "code": canary, "state": canary,
			"cookie": canary, "password": canary, "session_id": canary, "csrf_token": canary, "body": canary,
			"note": "hskey-api-" + canary, "jwt": "eyJhbGciOiJIUzI1NiJ9." + canary, "auth": "Bearer " + canary,
			"pem": "-----BEGIN PRIVATE KEY-----" + canary, "nested": map[string]any{"x": canary}, "blob": []byte(canary),
			"long": strings.Repeat("x", 300) + canary, "list": []string{"ok", "hskey-auth-" + canary},
			"reason": "kept", "status": 403,
		}
	}
	const dropped = 18
	req := newID(t).String()
	if err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
		if err := Record(ctx, q, Event{TenantID: &f.a, Action: "device.rename", ResourceType: "device", RequestID: req,
			Details: details()}); err != nil {
			return err
		}
		op, err := Requested(ctx, q, Event{TenantID: &f.a, Action: "device.expire", ResourceType: "device",
			RequestID: req, Details: details()})
		if err != nil {
			return err
		}
		return op.Succeeded(ctx, q, details())
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.log.RecordDetached(ctx, Event{TenantID: &f.a, Action: "device.rename", ResourceType: "device",
		RequestID: req, Outcome: OutcomeDenied, Details: details()}); err != nil {
		t.Fatal(err)
	}
	if err := f.log.RecordCommitted(ctx, Event{Action: "auth.login", ResourceType: "session", RequestID: req,
		Details: details()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.log.RecordSecurityEvent(ctx, SecurityEvent{Kind: "test.canary", Severity: SeverityLow,
		Source: "test", Details: details()}); err != nil {
		t.Fatal(err)
	}
	evs := f.events(t, "request_id = $1", req)
	if len(evs) != 5 {
		t.Fatalf("%d events, want 5", len(evs))
	}
	for _, e := range evs {
		if e.Details["reason"] != "kept" || e.Details["_redacted"] != float64(dropped) {
			t.Errorf("%s: details %v, want reason kept and _redacted %d", e.Action, e.Details, dropped)
		}
	}
	for _, table := range []string{"audit_events", "security_events"} {
		if n := f.count(t, "SELECT count(*) FROM "+table+" WHERE details::text LIKE '%' || $1 || '%'", canary); n != 0 {
			t.Errorf("%s: %d rows hold the canary", table, n)
		}
	}
	if strings.Contains(f.logs.String(), canary) {
		t.Error("the canary reached the log")
	}
}
