//go:build mgtestfixture

package authzmatrix_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// supportStaff is a platform staff member holding a live Support Access Grant into tenant A.
type supportStaff struct {
	*actor
	grant uuid.UUID
}

// newSupportStaff creates a Platform Support member with a live grant into A of the support role role (§8.7):
// support_operator approved by A's Tenant Owner, support_admin through break-glass (asked and approved by two other
// Super Admins). Its session is on the admin origin, like every staff session.
func (m *matrix) newSupportStaff(t *testing.T, role string) supportStaff {
	t.Helper()
	fx := m.NewActor(t, authz.RolePlatformSupport, nil)
	requester := fx.PlatformUserID
	if role == authz.RoleSupportAdmin {
		requester = m.NewActor(t, authz.RoleSuperAdmin, nil).PlatformUserID
	}
	id := uuid.Must(uuid.NewV7())
	m.Exec(t, `INSERT INTO support_access_grants (id, tenant_id, grantee_platform_user_id, requested_by_platform_user_id,
			effective_role_key, reason, ticket_ref, starts_at, expires_at, grantee_display)
		VALUES ($1, $2, $3, $4, $5, 'matrix support', 'MATRIX-C4', now() - interval '1 minute', now() + interval '1 hour',
			'Matrix Support')`, id, m.A.ID, fx.PlatformUserID, requester, role)
	if role == authz.RoleSupportAdmin {
		m.Exec(t, `UPDATE support_access_grants SET status = 'approved', approval_kind = 'breakglass',
			approved_by_platform_user_id = $2, decided_at = now() WHERE id = $1`,
			id, m.NewActor(t, authz.RoleSuperAdmin, nil).PlatformUserID)
	} else {
		m.Exec(t, `UPDATE support_access_grants SET status = 'approved', approval_kind = 'tenant',
			approved_by_membership_id = $2, decided_at = now() WHERE id = $1`,
			id, m.Actor(t, authz.RoleTenantOwner, m.A).MembershipID)
	}
	a := &actor{name: role + "@grant-A", kind: kindPlatform, role: role, fx: fx, host: hostAdmin, session: m.Login(t, fx)}
	return supportStaff{actor: a, grant: id}
}

// freshRequest inserts one more request of tenant A waiting for approval, made by member (a write of the test acts on
// its own object, so the answers do not depend on the order of the requests).
func (m *matrix) freshRequest(t *testing.T, member uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	m.Exec(t, `INSERT INTO enrollment_requests (id, tenant_id, instance_id, requested_by_membership_id, method,
			target_membership_id, status) VALUES ($1, $2, $3, $4, 'web_auth', $4, 'pending_approval')`,
		id, m.A.ID, m.obj.instance["A"], member)
	return id
}

// liveKey inserts one more pre-auth key of tenant A that may still register a node (credential_issued, key id keyID —
// the same key in the fake Headscale of A, unused, of member's Headscale user), issued to member: its revoke takes the
// remote branch of the service (the key is expired at Headscale between two transactions).
func (m *matrix) liveKey(t *testing.T, member uuid.UUID, keyID int64) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	m.Exec(t, `INSERT INTO enrollment_requests (id, tenant_id, instance_id, requested_by_membership_id, method,
			target_membership_id, status, issued_at, credential_expires_at, headscale_preauthkey_id)
		VALUES ($1, $2, $3, $4, 'preauth_key', $4, 'credential_issued', now(), now() + interval '10 minutes', $5)`,
		id, m.A.ID, m.obj.instance["A"], member, keyID)
	m.hs["A"].PutKey(devicestest.Key{ID: uint64(keyID), UserID: uint64(keyID), UserName: "mg-" + member.String(), //nolint:gosec // small test ids
		Expiration: time.Now().Add(9 * time.Minute)})
	return id
}

// expectStaff derives the answer to a staff call from the Staff column of §8.6 (master_test.go): no grant into the
// tenant of the path ⇒ 403 no_support_grant; a cell — (or G (Admin) for support_operator) ⇒ 403 no_grant; a cell G ⇒
// the handler answers as for a tenant role of scope any — the decisions (tenant.enrollment:approve) included: the
// grant is recorded as their decider (approver_support_grant_id — 0028, the project owner's decision of 2026-11-19).
// A request of another tenant or a missing one is 404 (reason no_request); the revoke of a live key expires it at the
// fake Headscale of A: 200.
func (m *matrix) expectStaff(t *testing.T, c *call) expectation {
	t.Helper()
	refused := func(reason string) expectation {
		return expectation{status: http.StatusForbidden, code: gen.ProblemCodeForbidden, decision: decDeny,
			denyKind: authz.ErrForbidden, reason: reason}
	}
	if c.pathTenant != m.A.ID {
		return refused("no_support_grant")
	}
	row, ok := tenantMatrix[string(c.op.Permission)]
	if !ok {
		t.Fatalf("no row of §8.6 for %s", c.op.Permission)
	}
	switch cell := row[slices.Index(tenantColumns, "Staff")]; {
	case cell == G, cell == GA && c.actor.role == authz.RoleSupportAdmin:
	case cell == N, cell == GA:
		return refused("no_grant")
	default:
		t.Fatalf("staff cell %q of %s", cell, c.op.Permission)
	}
	if c.objectCase == "other-tenant" || c.objectCase == "missing" {
		return expectation{status: http.StatusNotFound, code: gen.ProblemCodeNotFound, decision: decGrant,
			reason: "no_request"}
	}
	return expectation{status: http.StatusOK, decision: decGrant}
}

// TestSupportGrantEnrollment — the Staff column of the tenant.enrollment:* rows of §8.6 through the composed API: two
// platform staff members hold a live Support Access Grant into tenant A (effective role support_operator, and
// support_admin) and send every enrollment operation of the spec (authz.Operations) on A with every object case, on B
// (no grant) and on a tenant that does not exist. Expected (expectStaff): on B and the missing tenant 403
// no_support_grant; on A the cells — refused by layer 1 (no_grant); the cells G of read and revoke answered as for a
// tenant role of scope any — the list shows every request of A and only those, an object of A (the End User's
// request, another member's) 200, an object of B or a missing one 404, a revoke ends the request (200 revoked); the
// revoke of a live pre-auth key takes the remote branch: the operation's requested event, the key expired at the fake
// Headscale of A (the matrix reaches it through the production Locator and adapter — A6), the operation closed
// succeeded and the request revoked (the refusal of a revoked grant: TestSupportActorRevokesLiveKey of
// internal/enrollment) —; approve and reject (cell G — migration 0028) decide the request (200 approved / rejected)
// with the grant recorded as the decider (approver_support_grant_id, no membership) and the requester notified
// (by_support), a request of B or a missing one 404 (the refusals of an ended grant: TestSupportActorDecides of
// internal/enrollment). Every answer of a granted call carries the decision of the grant (role, grant, platform user);
// every refusal leaves exactly one denied audit event — in A as the support actor when the grant decided (§8.7 step 3),
// with the reason of the refusal; in the platform's trail otherwise —, a revoke or a decision one success event in A as
// the support actor, the revoke of a live key the requested and succeeded events of its operation there.
func TestSupportGrantEnrollment(t *testing.T) {
	m := &matrix{matrixWorld: newMatrixWorld(t), byFixture: map[*sessionfixture.Actor]*actor{}}
	staff := []supportStaff{m.newSupportStaff(t, authz.RoleSupportOperator), m.newSupportStaff(t, authz.RoleSupportAdmin)}
	eu := m.Actor(t, authz.RoleEndUser, m.A).MembershipID
	members := map[string]uuid.UUID{"eu-own": eu, "other-member": m.obj.target["A"]}
	grantOf := map[*actor]uuid.UUID{}
	perms := map[authz.Permission]bool{}
	fresh := map[*call]uuid.UUID{} // writes on A: the request each one acts on
	keyID := int64(4000)           // the Headscale ids of the live keys
	for _, op := range authz.Operations() {
		if !strings.HasPrefix(string(op.Permission), "tenant.enrollment:") {
			continue
		}
		perms[op.Permission] = true
		_, hasObject := objectKindOf(op)
		rcp := recipes[op.ID]
		if op.ID == "listEnrollmentRequests" {
			rcp.query = func(*call) string { return "limit=200" } // every request of A on one page
		}
		for _, s := range staff {
			grantOf[s.actor] = s.grant
			for _, tc := range []string{"A", "B", "missing"} {
				objects := []string{""}
				switch {
				case hasObject && tc == "A" && op.ID == "revokeEnrollmentRequest":
					objects = []string{"eu-own", "other-member", "other-tenant", "missing", "live-key"}
				case hasObject && tc == "A":
					objects = []string{"eu-own", "other-member", "other-tenant", "missing"}
				case hasObject && tc == "B":
					objects = []string{"as-path"}
				case hasObject:
					objects = []string{"missing"}
				}
				for _, oc := range objects {
					c := &call{actor: s.actor, op: op, recipe: rcp, host: s.host, session: s.session, tenantCase: tc,
						objectCase: oc}
					m.place(t, c)
					switch member, ok := members[oc]; {
					case oc == "live-key":
						keyID++
						c.objectID = m.liveKey(t, eu, keyID)
						fresh[c] = c.objectID
					case ok && tc == "A" && op.Method != http.MethodGet:
						c.objectID = m.freshRequest(t, member)
						fresh[c] = c.objectID
					}
					c.exp = m.expectStaff(t, c)
					m.calls = append(m.calls, c)
				}
			}
		}
	}
	for _, p := range []authz.Permission{"tenant.enrollment:read", "tenant.enrollment:revoke", "tenant.enrollment:approve",
		"tenant.enrollment:request", "tenant.enrollment:issue_privileged"} {
		if !perms[p] {
			t.Fatalf("no operation of the spec needs %s", p)
		}
	}
	m.run(m.calls)

	var granted, refused, decided int
	for _, c := range m.calls {
		bad := m.check(t, c)
		add := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
		if d, ok := m.rec.get(c.reqs); ok && c.exp.decision == decGrant &&
			(d.decision.SupportGrantID != grantOf[c.actor] || d.decision.PlatformUserID != c.actor.fx.PlatformUserID) {
			add("decision grant %s platform user %s, want %s %s", d.decision.SupportGrantID, d.decision.PlatformUserID,
				grantOf[c.actor], c.actor.fx.PlatformUserID)
		}
		bad = append(bad, m.checkStaffAudit(t, c, grantOf[c.actor])...)
		if id, ok := fresh[c]; ok {
			want := "pending_approval"
			switch c.op.ID {
			case "revokeEnrollmentRequest":
				want = "revoked"
			case "approveEnrollmentRequest":
				want = "approved"
			case "rejectEnrollmentRequest":
				want = "rejected"
			}
			if c.op.Permission == "tenant.enrollment:approve" { // the grant is the decider; the requester is told
				var member, grant *uuid.UUID
				var told string
				m.Scan(t, `SELECT approver_membership_id, approver_support_grant_id, (SELECT coalesce(string_agg(n.kind || '|' ||
						n.recipient_membership_id || '|' || coalesce(n.payload->>'by_support', '-'), ','), '-')
						FROM notification_outbox n WHERE n.payload->>'request_id' = r.id::text)
					FROM enrollment_requests r WHERE r.id = $1`, []any{id}, &member, &grant, &told)
				kind := "enrollment.approved"
				if c.op.ID == "rejectEnrollmentRequest" {
					kind = "enrollment.rejected"
				}
				if member != nil || grant == nil || *grant != grantOf[c.actor] ||
					told != kind+"|"+members[c.objectCase].String()+"|true" {
					add("decider membership %v grant %v (want the grant %s), notifications %q", member, grant, grantOf[c.actor], told)
				}
			}
			if c.objectCase == "live-key" { // the key itself expired at Headscale
				var kid int64
				m.Scan(t, `SELECT headscale_preauthkey_id FROM enrollment_requests WHERE id = $1`, []any{id}, &kid)
				if k := m.hs["A"].Key(uint64(kid)); k.Expiration.After(time.Now()) { //nolint:gosec // small test ids
					add("the revoked key is still live at Headscale: %+v", k)
				}
			}
			var got string
			m.Scan(t, `SELECT status FROM enrollment_requests WHERE id = $1`, []any{id}, &got)
			if got != want {
				add("request status %s, want %s", got, want)
			}
		}
		if c.op.ID == "listEnrollmentRequests" && c.exp.decision == decGrant {
			var list gen.EnrollmentRequestList
			_ = json.Unmarshal(c.rec.Body.Bytes(), &list)
			ids := map[uuid.UUID]bool{}
			for _, r := range list.Items {
				ids[r.Id] = true
			}
			var ofA, listedOfA int // every request of A was written before the run
			m.Scan(t, `SELECT count(*), count(*) FILTER (WHERE id = ANY ($2)) FROM enrollment_requests WHERE tenant_id = $1`,
				[]any{m.A.ID, slices.Collect(maps.Keys(ids))}, &ofA, &listedOfA)
			if !ids[m.obj.enrEU["A"]] || !ids[m.obj.enrOther["A"]] || ids[m.obj.enrEU["B"]] || ids[m.obj.enrOther["B"]] ||
				len(list.Items) != len(ids) || listedOfA != len(ids) || ofA != len(ids) || list.NextCursor != nil {
				add("list of %d (%d distinct, %d of A — A holds %d): want every request of A (the End User's, another "+
					"member's) once and none of another tenant: %s", len(list.Items), len(ids), listedOfA, ofA, c.rec.Body)
			}
		}
		switch {
		case c.exp.decision == decDeny:
			refused++
		case c.exp.status == http.StatusOK && c.op.Permission == "tenant.enrollment:approve":
			decided++
		default:
			granted++
		}
		for _, b := range bad {
			t.Errorf("%s: %s", c, b)
		}
	}
	if granted == 0 || refused == 0 || decided == 0 {
		t.Fatalf("degenerate: %d granted, %d refused by layer 1, %d decisions", granted, refused, decided)
	}
	t.Logf("support staff × enrollment: %d requests — %d answered, %d refused by layer 1, %d decisions recorded "+
		"under the grant", len(m.calls), granted, refused, decided)
}

// checkStaffAudit checks the audit trail of one staff call: a refusal (layer 1 or the handler) leaves exactly one
// denied event — in A as the support actor of the grant when the grant decided, with the reason of the refusal; in the
// platform's trail (no tenant) when the staff member holds no grant into the tenant of the path —, a revoke a success
// event enrollment.revoke in A as the support actor, a decision a success event enrollment.approve / enrollment.reject
// there.
func (m *matrix) checkStaffAudit(t *testing.T, c *call, grant uuid.UUID) []string {
	t.Helper()
	var rows string
	m.Scan(t, `SELECT coalesce(json_agg(json_build_object('t', tenant_id, 'o', outcome, 'a', action, 'at', actor_type,
			'g', support_grant_id, 'why', details ->> 'reason')), '[]')::text
		FROM audit_events WHERE request_id = $1`, []any{c.reqs}, &rows)
	var events []struct {
		T   *uuid.UUID `json:"t"`
		O   string     `json:"o"`
		A   string     `json:"a"`
		At  string     `json:"at"`
		G   *uuid.UUID `json:"g"`
		Why string     `json:"why"`
	}
	if err := json.Unmarshal([]byte(rows), &events); err != nil {
		t.Fatal(err)
	}
	asSupport := func(i int) bool {
		e := events[i]
		return e.T != nil && *e.T == m.A.ID && e.At == audit.ActorSupport && e.G != nil && *e.G == grant
	}
	var denied []int
	revoked, requested, succeeded, decision := false, false, false, false
	for i, e := range events {
		if e.O == "denied" {
			denied = append(denied, i)
		}
		switch {
		case !asSupport(i):
		case e.O == "success" && e.A == "enrollment.revoke":
			revoked = true
		case e.O == "success" && e.A == c.op.AuditAction && c.op.Permission == "tenant.enrollment:approve":
			decision = true
		case e.O == "success" && e.A == "enrollment.revoke"+audit.SuffixRequested:
			requested = true
		case e.O == "success" && e.A == "enrollment.revoke"+audit.SuffixSucceeded:
			succeeded = true
		}
	}
	wantWhy := c.exp.reason
	switch {
	case c.objectCase == "live-key":
		if !requested || !succeeded || revoked || len(denied) != 0 || len(events) != 2 {
			return []string{fmt.Sprintf("audit %s: want the requested and succeeded events of the operation, in A as "+
				"the support actor, nothing else", rows)}
		}
	case c.exp.status == http.StatusOK && c.op.Permission == "tenant.enrollment:revoke":
		if !revoked || len(denied) != 0 {
			return []string{fmt.Sprintf("audit %s: want a success enrollment.revoke in A as the support actor", rows)}
		}
	case c.exp.status == http.StatusOK && c.op.Permission == "tenant.enrollment:approve":
		if !decision || len(denied) != 0 {
			return []string{fmt.Sprintf("audit %s: want a success %s in A as the support actor", rows, c.op.AuditAction)}
		}
	case c.exp.status == http.StatusOK:
		if len(denied) != 0 {
			return []string{fmt.Sprintf("audit %s: a granted read left a denial", rows)}
		}
	case c.pathTenant != m.A.ID:
		if len(denied) != 1 || events[denied[0]].T != nil || events[denied[0]].Why != wantWhy {
			return []string{fmt.Sprintf("audit %s: want one denied platform event (%s)", rows, wantWhy)}
		}
	default:
		if len(denied) != 1 || !asSupport(denied[0]) || events[denied[0]].Why != wantWhy {
			return []string{fmt.Sprintf("audit %s: want one denied event in A as the support actor (%s)", rows, wantWhy)}
		}
	}
	return nil
}
