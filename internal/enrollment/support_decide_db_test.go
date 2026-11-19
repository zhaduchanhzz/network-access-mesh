package enrollment

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// actor is the enrollment caller of s as enrollmentapi builds it from a support decision: no membership, the grant.
func (s supportStaff) actor() Actor {
	return Actor{IdentityID: s.identity, Display: "Support", SupportGrantID: s.grant}
}

// TestSupportActorDecides (C4 — the project owner's decision of 2026-11-19, migration 0028): platform staff with a live
// Support Access Grant into the tenant approve and reject an enrollment request like a tenant role (§8.6 cell G of
// tenant.enrollment:approve): the decider recorded is the grant (approver_support_grant_id, no membership), the audit
// event is in the tenant's trail as the support actor of the grant (details decided_by=support), the requester — and
// only them — is told, by_support; the requester then starts the approved request. Refused, with the request unchanged
// and nothing audited nor notified: a grant revoked, or expired while still approved (before grant.expire); a grant
// into another tenant (the transaction's own check); a request of another tenant (404); an actor that is not the
// support actor of the request context, or both a member and staff (no_decider); staff whose identity is the
// requester's (self_approval — impossible in practice: staff hold no membership); a decision racing a revocation waits
// for it (the grant locked FOR SHARE) and is refused once it commits.
func TestSupportActorDecides(t *testing.T) {
	f := newFixture(t)
	a, b := f.a, f.b
	for _, ten := range []*tenantFx{a, b} {
		f.setting(t, ten, "enrollment,self_enroll", "true")
		f.setting(t, ten, "enrollment,requires_approval", "true")
	}
	user := a.actor("user", uuid.New())
	n := 0
	pending := func(ten *tenantFx, who Actor, method string) uuid.UUID {
		t.Helper()
		n++
		label := fmt.Sprintf("dev-%d", n)
		out, err := f.api.Create(ctxOf(who, ten.id, ActionRequest), ten.id, who, NewRequest{Method: method, DeviceLabel: &label},
			idem(fmt.Sprintf("k-sd-%d", n), label))
		if err != nil || out.Request.Status != StatusPendingApproval {
			t.Fatalf("pending request: %+v %v", out.Request, err)
		}
		return out.Request.ID
	}
	type decision struct {
		status                string
		member, grant         *uuid.UUID
		approved              bool
		events, notifications int
	}
	state := func(id uuid.UUID) decision {
		t.Helper()
		var d decision
		f.scan(t, `SELECT status, approver_membership_id, approver_support_grant_id, approved_at IS NOT NULL,
				(SELECT count(*) FROM audit_events WHERE resource_id = $2 AND action IN ('enrollment.approve', 'enrollment.reject')),
				(SELECT count(*) FROM notification_outbox WHERE payload->>'request_id' = $2)
			FROM enrollment_requests WHERE id = $1`, []any{id, id.String()}, &d.status, &d.member, &d.grant, &d.approved, &d.events,
			&d.notifications)
		return d
	}
	unchanged := func(what string, id uuid.UUID) {
		t.Helper()
		if d := state(id); d.status != StatusPendingApproval || d.member != nil || d.grant != nil || d.approved || d.events != 0 ||
			d.notifications != 0 {
			t.Errorf("%s: the request changed: %+v", what, d)
		}
	}
	staff := f.supportGrant(t, a)

	// approve: the grant is the decider; the audit and the notification say it is the platform's support
	id := pending(a, user, MethodWebAuth)
	r, err := f.api.Approve(staff.ctx(a.id, ActionApprove), a.id, id, staff.actor())
	if err != nil || r.Status != StatusApproved || r.Approver != nil || r.ApproverGrant == nil || *r.ApproverGrant != staff.grant ||
		r.ApprovedAt == nil {
		t.Fatalf("approve by the support actor: %+v %v", r, err)
	}
	if d := state(id); d.status != StatusApproved || d.member != nil || d.grant == nil || *d.grant != staff.grant || !d.approved {
		t.Fatalf("row after the support approval: %+v", d)
	}
	auditAs := func(id uuid.UUID, action string) int {
		return f.count(t, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND tenant_id = $2 AND action = $3
			AND outcome = 'success' AND actor_type = 'support' AND support_grant_id = $4 AND actor_identity_id = $5
			AND details->>'decided_by' = 'support' AND details->>'requested_by' = $6`,
			id.String(), a.id, action, staff.grant, staff.identity, user.MembershipID.String())
	}
	if n := auditAs(id, ActionApprove); n != 1 {
		t.Errorf("approval events in A as the support actor: %d", n)
	}
	told := func(id uuid.UUID) []string {
		return f.list(t, `SELECT kind || '|' || recipient_membership_id || '|' || COALESCE(payload->>'decided_by', '') || '|' ||
				COALESCE(payload->>'by_support', '') FROM notification_outbox WHERE tenant_id = $1 AND payload->>'request_id' = $2
			ORDER BY created_at, id`, a.id, id.String())
	}
	if got := told(id); !slices.Equal(got, []string{"enrollment.approved|" + user.MembershipID.String() + "|Support|true"}) {
		t.Errorf("approval notification %v", got)
	}
	if iss, err := f.api.Start(ctxOf(user, a.id, ActionStart), a.id, id, user); err != nil || iss.Credential == nil ||
		iss.Request.ApproverGrant == nil || *iss.Request.ApproverGrant != staff.grant {
		t.Fatalf("start after the support approval: %+v %v", iss.Request, err)
	}
	if g := f.str(t, `SELECT approver_support_grant_id::text FROM enrollment_requests WHERE id = $1`, id); g != staff.grant.String() {
		t.Errorf("the decider after /start: %s", g)
	}
	if _, err := f.api.Approve(staff.ctx(a.id, ActionApprove), a.id, id, staff.actor()); reasonOf(err) != "not_pending_approval" {
		t.Errorf("approve twice: %v", err)
	}

	// reject
	rej := pending(a, user, MethodPreauthKey)
	if r, err := f.api.Reject(staff.ctx(a.id, ActionReject), a.id, rej, staff.actor()); err != nil || r.Status != StatusRejected ||
		r.Approver != nil || r.ApproverGrant == nil || *r.ApproverGrant != staff.grant || r.ApprovedAt != nil {
		t.Fatalf("reject by the support actor: %+v %v", r, err)
	}
	if n := auditAs(rej, ActionReject); n != 1 {
		t.Errorf("rejection events in A as the support actor: %d", n)
	}
	if got := told(rej); !slices.Equal(got, []string{"enrollment.rejected|" + user.MembershipID.String() + "|Support|true"}) {
		t.Errorf("rejection notification %v", got)
	}

	// another tenant: a request of B through A's grant is not found; a grant into B does not open A
	idB := pending(b, b.actor("user", uuid.New()), MethodWebAuth)
	if _, err := f.api.Approve(staff.ctx(a.id, ActionApprove), a.id, idB, staff.actor()); codeOf(err) != CodeNotFound {
		t.Errorf("B's request through A's grant: %v", err)
	}
	staffB := f.supportGrant(t, b)
	id2 := pending(a, user, MethodWebAuth)
	if _, err := f.api.Approve(staffB.ctx(a.id, ActionApprove), a.id, id2, staffB.actor()); !errors.Is(err, store.ErrSupportGrantNotLive) ||
		reasonOf(err) != ReasonSupportGrantNotLive || codeOf(err) != CodeForbidden {
		t.Errorf("A's request through a grant into B: %v", err)
	}
	unchanged("grant into another tenant", id2)
	unchanged("A's grant on B's request", idB)

	// actors that are not the support actor of the context — refused before any transaction
	member := a.actor("admin", uuid.New())
	both := staff.actor()
	both.MembershipID = member.MembershipID
	other := staff.actor()
	other.SupportGrantID = staffB.grant
	for name, c := range map[string]struct {
		ctx context.Context
		a   Actor
	}{
		"staff actor without the support context": {ctxOf(member, a.id, ActionApprove), staff.actor()},
		"member and staff":                        {staff.ctx(a.id, ActionApprove), both},
		"member inside a support context":         {staff.ctx(a.id, ActionApprove), member},
		"grant other than the context's":          {staff.ctx(a.id, ActionApprove), other},
	} {
		if _, err := f.api.Approve(c.ctx, a.id, id2, c.a); reasonOf(err) != ReasonNoDecider || codeOf(err) != CodeForbidden {
			t.Errorf("%s: %v, want forbidden %s", name, err, ReasonNoDecider)
		}
	}
	// the requester is never the decider, checked on the person
	self := staff.actor()
	self.IdentityID = a.people["user"].identity
	if _, err := f.api.Reject(staff.ctx(a.id, ActionReject), a.id, id2, self); reasonOf(err) != "self_approval" {
		t.Errorf("staff with the requester's identity: %v", err)
	}
	unchanged("refused actors", id2)

	// a decision racing a revocation of the grant: it waits for the revocation, then is refused
	revoker := f.env.Admin(t, f.db)
	tx, err := revoker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `UPDATE support_access_grants SET status = 'revoked', revoked_at = now() WHERE id = $1`,
		staff.grant); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.api.Approve(staff.ctx(a.id, ActionApprove), a.id, id2, staff.actor())
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the decision did not wait for the revocation in progress: %v", err)
	case <-time.After(700 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, store.ErrSupportGrantNotLive) || reasonOf(err) != ReasonSupportGrantNotLive {
		t.Errorf("decision after the revocation committed: %v", err)
	}
	unchanged("decision racing the revocation", id2)
	if _, err := f.api.Reject(staff.ctx(a.id, ActionReject), a.id, id2, staff.actor()); !errors.Is(err, store.ErrSupportGrantNotLive) {
		t.Errorf("reject through a revoked grant: %v", err)
	}
	unchanged("revoked grant", id2)

	// a grant still approved whose window is over (grant.expire has not run): refused by the window itself
	late := f.supportGrant(t, a)
	f.exec(t, `ALTER TABLE support_access_grants DISABLE TRIGGER support_access_grants_guard;
		UPDATE support_access_grants SET starts_at = now() - interval '2 hours', expires_at = now() - interval '1 second'
			WHERE id = '`+late.grant.String()+`';
		ALTER TABLE support_access_grants ENABLE TRIGGER support_access_grants_guard`)
	if st := f.str(t, `SELECT status FROM support_access_grants WHERE id = $1`, late.grant); st != "approved" {
		t.Fatalf("expired grant status %s", st)
	}
	if _, err := f.api.Approve(late.ctx(a.id, ActionApprove), a.id, id2, late.actor()); !errors.Is(err, store.ErrSupportGrantNotLive) ||
		reasonOf(err) != ReasonSupportGrantNotLive {
		t.Errorf("approve through an expired grant: %v", err)
	}
	unchanged("expired grant", id2)
	// a member still decides it
	if r, err := f.api.Approve(ctxOf(member, a.id, ActionApprove), a.id, id2, member); err != nil || r.Approver == nil ||
		*r.Approver != member.MembershipID || r.ApproverGrant != nil {
		t.Errorf("member approval after the refusals: %+v %v", r, err)
	}
	f.noKeyMaterial(t)
}
