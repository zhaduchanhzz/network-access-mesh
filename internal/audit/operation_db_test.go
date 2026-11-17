package audit

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestPairing — §6.1, §20 P2-T08 "cặp sự kiện *.requested → *.succeeded/*.failed theo operation_id": the request is
// committed before the outcome; both events carry the same operation id, tenant, actor, resource and request id; the
// operation survives a JSON round trip (a job carries it); an operation without outcome is listed for reconcile.
func TestPairing(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	actor := newID(t)
	base := Event{TenantID: &f.a, ActorIdentityID: &actor, ActorDisplay: "Alice", Action: "device.expire",
		ResourceType: "device", ResourceID: "dev-1", RequestID: "req-pair"}
	request := func() Operation {
		t.Helper()
		var op Operation
		if err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
			var err error
			op, err = Requested(ctx, q, base)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return op
	}

	// 1. requested, then succeeded by "the job" from the JSON it carried
	op1 := request()
	raw, err := json.Marshal(op1)
	if err != nil {
		t.Fatal(err)
	}
	var carried Operation
	if err := json.Unmarshal(raw, &carried); err != nil || !reflect.DeepEqual(carried, op1) {
		t.Fatalf("operation JSON round trip: %v %+v", err, carried)
	}
	if err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
		return carried.Succeeded(ctx, q, Details{"expiry": "now"})
	}); err != nil {
		t.Fatal(err)
	}
	pair := f.events(t, "operation_id = $1", op1.ID)
	if len(pair) != 2 || pair[0].Action != "device.expire.requested" || pair[1].Action != "device.expire.succeeded" {
		t.Fatalf("pair of %s: %+v", op1.ID, pair)
	}
	for _, e := range pair {
		if e.Outcome != OutcomeSuccess || *e.Tenant != f.a || *e.Actor != actor || e.ResourceID != "dev-1" ||
			e.RequestID != "req-pair" || *e.OperationID != op1.ID {
			t.Errorf("event %s of the pair: %+v", e.Action, e)
		}
	}

	// 2. requested, then failed on the detached path (no transaction will commit)
	op2 := request()
	if err := op2.FailedDetached(ctx, f.log, "upstream_rejected", nil); err != nil {
		t.Fatal(err)
	}
	pair = f.events(t, "operation_id = $1", op2.ID)
	if len(pair) != 2 || pair[1].Action != "device.expire.failed" || pair[1].Outcome != OutcomeFailure ||
		pair[1].Details["reason"] != "upstream_rejected" || *pair[1].Tenant != f.a {
		t.Fatalf("failed pair: %+v", pair)
	}

	// 3. requested, never finished (the process died): listed for reconcile; the finished ones are not
	op3 := request()
	open, err := f.log.OpenOperations(ctx, &f.a, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].ID != op3.ID || open[0].Action != "device.expire" || open[0].ResourceID != "dev-1" {
		t.Fatalf("open operations: %+v, want only %s", open, op3.ID)
	}
	if open, err := f.log.OpenOperations(ctx, &f.b, 0, 100); err != nil || len(open) != 0 {
		t.Errorf("open operations of tenant B: %+v %v", open, err)
	}
	if open, err := f.log.OpenOperations(ctx, &f.a, time.Hour, 100); err != nil || len(open) != 0 {
		t.Errorf("open operations older than an hour: %+v %v", open, err)
	}

	// 4. the API refuses broken pairs before the database does
	if _, err := Requested(ctx, nil, Event{Action: "device.expire.requested"}); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("Requested with a suffixed action: %v", err)
	}
	if err := (Operation{}).Succeeded(ctx, nil, nil); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("Succeeded of a zero operation: %v", err)
	}
	err = f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
		return Record(ctx, q, Event{TenantID: &f.a, Action: "device.expire.succeeded", ResourceType: "device"})
	})
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("a *.succeeded event without operation id: %v", err)
	}
}

// TestPairingCheckInDatabase: the CHECK audit_events_operation_pair of 0004 refuses, even to the superuser, a paired
// suffix without operation id or with the wrong outcome, and an operation id on any other event.
func TestPairingCheckInDatabase(t *testing.T) {
	f := newFixture(t, Config{})
	op := newID(t)
	for _, c := range []struct {
		action, outcome string
		op              *uuid.UUID
	}{
		{"device.expire.succeeded", OutcomeSuccess, nil},
		{"device.expire.requested", OutcomeSuccess, nil},
		{"device.expire.failed", OutcomeSuccess, &op},
		{"device.expire.succeeded", OutcomeFailure, &op},
		{"device.expire", OutcomeSuccess, &op},
	} {
		_, err := f.su.Exec(t.Context(), `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome, operation_id)
			VALUES ($1, 'system', $2, 'device', $3, $4)`, f.a, c.action, c.outcome, c.op)
		if sqlState(err) != "23514" {
			t.Errorf("%s/%s with operation id %v: %v, want check_violation", c.action, c.outcome, c.op != nil, err)
		}
	}
	if _, err := f.su.Exec(t.Context(), `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome, operation_id)
		VALUES ($1, 'system', 'device.expire.failed', 'device', 'failure', $2)`, f.a, op); err != nil {
		t.Errorf("a well-formed *.failed: %v", err)
	}
}

// TestFinishClosesRequest — the request/outcome pairing of the HTTP middleware (Logger.Finish): a failed request fails
// the operations it left open (detached *.failed, same operation id) instead of writing its own failure; an operation
// whose *.requested rolled back never started; a successful request leaving an operation open or a write without any
// event is a reported gap; a handed-off operation is the job's; a failed read writes nothing.
func TestFinishClosesRequest(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	actor := newID(t)
	newRequest := func(action string, readOnly bool) *Request {
		return &Request{Operation: "Op", Action: action, ReadOnly: readOnly, ActorType: ActorIdentity, ActorIdentityID: &actor,
			ActorTenantID: &f.a, TenantID: &f.a, ResourceType: "device", ResourceID: "dev-9", RequestID: newID(t).String()}
	}
	requested := func(r *Request, commit bool) Operation {
		t.Helper()
		rctx := WithRequest(ctx, r)
		var op Operation
		errRollback := errors.New("rollback")
		err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error {
			var err error
			if op, err = Requested(rctx, q, Event{}); err != nil {
				return err
			}
			if !commit {
				return errRollback
			}
			return nil
		})
		if commit && err != nil || !commit && !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
		return op
	}
	failure := Result{Outcome: OutcomeFailure, Reason: "upstream_rejected", Status: 502}

	// 1. failed request with an open operation ⇒ <action>.failed with its operation id, no other failure event
	r1 := newRequest("device.sync", false)
	op1 := requested(r1, true)
	f.log.Finish(ctx, r1, failure)
	got := f.events(t, "request_id = $1", r1.RequestID)
	if len(got) != 2 || got[1].Action != "device.sync.failed" || *got[1].OperationID != op1.ID ||
		got[1].Details["reason"] != "upstream_rejected" || got[1].Details["status"] != float64(502) {
		t.Fatalf("failed request with an open operation: %+v", got)
	}

	// 2. the transaction of Requested rolled back ⇒ the operation never started: one plain failure event
	r2 := newRequest("device.sync", false)
	requested(r2, false)
	f.log.Finish(ctx, r2, failure)
	got = f.events(t, "request_id = $1", r2.RequestID)
	if len(got) != 1 || got[0].Action != "device.sync" || got[0].Outcome != OutcomeFailure || got[0].OperationID != nil ||
		*got[0].Tenant != f.a {
		t.Fatalf("failed request whose operation rolled back: %+v", got)
	}

	// 3. finished operation, successful request ⇒ nothing more, no gap
	r3 := newRequest("device.expire", false)
	op3 := requested(r3, true)
	if err := f.st.WithTenantTx(ctx, f.a, func(q *sqlcdb.Queries) error { return op3.Succeeded(ctx, q, nil) }); err != nil {
		t.Fatal(err)
	}
	f.log.Finish(ctx, r3, Result{})
	if n := len(f.events(t, "request_id = $1", r3.RequestID)); n != 2 {
		t.Errorf("finished pair: %d events, want 2", n)
	}

	// 4. successful request leaving its operation open ⇒ gap left_open; 5. a write without any event ⇒ gap no_event
	r4 := newRequest("device.expire", false)
	requested(r4, true)
	f.log.Finish(ctx, r4, Result{})
	f.log.Finish(ctx, newRequest("device.rename", false), Result{})
	if f.counter(t, "meshguard_audit_gaps_total", map[string]string{"reason": gapLeftOpen}) != 1 ||
		f.counter(t, "meshguard_audit_gaps_total", map[string]string{"reason": gapNoEvent}) != 1 ||
		!f.logged("audit: gap", "reason", gapLeftOpen) || !f.logged("audit: gap", "reason", gapNoEvent) {
		t.Error("gaps left_open / no_event not counted and logged once each")
	}

	// 6. handed off to a job ⇒ neither failed nor reported: the job finishes it
	r6 := newRequest("device.sync", false)
	op6 := requested(r6, true)
	HandOff(WithRequest(ctx, r6), op6)
	f.log.Finish(ctx, r6, Result{})
	if n := len(f.events(t, "operation_id = $1", op6.ID)); n != 1 {
		t.Errorf("handed-off operation: %d events, want only its request", n)
	}

	// 7. a failed read writes nothing (the access log has it); a read that succeeded is not audited
	r7 := newRequest("device.list", true)
	f.log.Finish(ctx, r7, failure)
	f.log.Finish(ctx, r7, Result{})
	if n := len(f.events(t, "request_id = $1", r7.RequestID)); n != 0 {
		t.Errorf("read: %d events", n)
	}
	if f.counter(t, "meshguard_audit_gaps_total", map[string]string{"reason": gapNoEvent}) != 1 {
		t.Error("a successful read counted as a gap")
	}

	// 8. a skipped result (501, anonymous 401) writes nothing
	r8 := newRequest("device.rename", false)
	f.log.Finish(ctx, r8, Result{Outcome: OutcomeDenied, Skip: true})
	if n := len(f.events(t, "request_id = $1", r8.RequestID)); n != 0 {
		t.Errorf("skipped request: %d events", n)
	}
}

// TestFinishDenials: a denial is written under the actor's tenant — with the tenant of the path as target when it is
// another one — so that the target tenant never lists it (§6.1); platform staff denied on a tenant route write a
// platform event. Same-tenant denials have no target.
func TestFinishDenials(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	userA, staff := newID(t), newID(t)
	denied := Result{Outcome: OutcomeDenied, Reason: "not_a_member", Status: 404}
	for _, c := range []struct {
		name           string
		r              *Request
		tenant, target *uuid.UUID
	}{
		{"user of A on tenant B", &Request{Action: "device.list", ReadOnly: true, ActorIdentityID: &userA,
			ActorTenantID: &f.a, TenantID: &f.b, ResourceType: "device"}, &f.a, &f.b},
		{"user of A on tenant A", &Request{Action: "audit.list", ReadOnly: true, ActorIdentityID: &userA,
			ActorTenantID: &f.a, TenantID: &f.a, ResourceType: "audit"}, &f.a, nil},
		{"staff on tenant B", &Request{Action: "device.list", ReadOnly: true, ActorIdentityID: &staff,
			TenantID: &f.b, ResourceType: "device"}, nil, &f.b},
		{"staff on a platform route", &Request{Action: "platform.audit.list", ReadOnly: true, ActorIdentityID: &staff,
			ResourceType: "audit"}, nil, nil},
	} {
		c.r.RequestID = newID(t).String()
		f.log.Finish(ctx, c.r, denied)
		got := f.events(t, "request_id = $1", c.r.RequestID)
		if len(got) != 1 || got[0].Outcome != OutcomeDenied || got[0].Details["reason"] != "not_a_member" ||
			!sameID(got[0].Tenant, c.tenant) || !sameID(got[0].Target, c.target) {
			t.Errorf("%s: %+v, want tenant %v target %v", c.name, got, c.tenant, c.target)
		}
	}
	r := NewReader(f.st)
	page, err := r.ListTenant(ctx, f.b, Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Errorf("tenant B lists %d events: the denials of other actors on B must not appear", len(page.Items))
	}
}

func sameID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
