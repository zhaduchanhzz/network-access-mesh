package tenants_test

// Integration tests of the Support Access Grant (P4-T13, §8.7) on a real PostgreSQL with the api roles (and the worker
// roles for grant.expire): request ⇒ pending + both trails + the deciders notified; the tenant decides (ceiling
// support_operator, step-up), revokes; break-glass needs a second Super Admin and raises a high security event + the
// Owners' notification; another tenant's grant is not found; grant.expire marks the grants past their window.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// staffUser inserts a platform identity (of the test's platform IdP) and its platform user of role; it returns the
// identity and platform user ids.
func (f *fixture) staffUser(name, role string) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	var idp uuid.UUID
	err := f.su.QueryRow(f.t.Context(), `SELECT id FROM identity_providers WHERE scope = 'platform' LIMIT 1`).Scan(&idp)
	if errors.Is(err, pgx.ErrNoRows) {
		idp = uuid.Must(uuid.NewV7())
		f.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
			VALUES ($1, 'platform', 'https://idp.test/platform', 'admin', 'external', 'active')`, idp)
	} else if err != nil {
		f.t.Fatal(err)
	}
	ident, pu := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO identities (id, idp_id, scope, subject, display_name) VALUES ($1, $2, 'platform', $3, $4)`,
		ident, idp, "sub-"+ident.String(), name)
	f.exec(`INSERT INTO platform_users (id, identity_id, role_id)
		SELECT $1, $2, id FROM roles WHERE scope = 'platform' AND key = $3`, pu, ident, role)
	return ident, pu
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.su.QueryRow(f.t.Context(), sql, args...).Scan(&n); err != nil {
		f.t.Fatalf("count: %v\n%s", err, sql)
	}
	return n
}

func staff(id uuid.UUID) tenants.StaffActor {
	return tenants.StaffActor{IdentityID: id, AuthTime: time.Now()}
}

func ask(tenant uuid.UUID, role string) tenants.SupportGrantCreate {
	return tenants.SupportGrantCreate{TenantID: tenant, Role: role, Reason: "customer ticket: devices offline",
		TicketRef: "SUP-1", DurationMinutes: 60}
}

func idem() *tenants.SupportIdempotency {
	return &tenants.SupportIdempotency{Key: "key-" + uuid.NewString(), Hash: make([]byte, 32)}
}

func TestSupportGrantLifecycle(t *testing.T) {
	f := newFixture(t)
	a, idpA := f.tenant("sup-a", "A", "active", false)
	b, idpB := f.tenant("sup-b", "B", "active", false)
	gone, _ := f.tenant("sup-gone", "Gone", "deprovisioning", false)
	ownerID, ownerM := f.member(a, idpA, "Owner A", "o@a.test", "tenant_owner", "active")
	adminID, adminM := f.member(a, idpA, "Admin A", "ad@a.test", "tenant_admin", "active")
	viewerID, viewerM := f.member(a, idpA, "Viewer A", "v@a.test", "tenant_viewer", "active")
	ownerB, ownerBM := f.member(b, idpB, "Owner B", "o@b.test", "tenant_owner", "active")
	sa1, _ := f.staffUser("Super One", "super_admin")
	sa2, _ := f.staffUser("Super Two", "super_admin")
	ps, _ := f.staffUser("Support Person", "platform_support")
	pctx := func(id uuid.UUID, action string) context.Context { return reqCtx(t.Context(), id, nil, action) }

	// request: validation, tenant state, pending + trails + notification
	for name, in := range map[string]tenants.SupportGrantCreate{
		"owner role":       {TenantID: a, Role: "tenant_owner", Reason: "x", TicketRef: "T", DurationMinutes: 60},
		"over 8 hours":     {TenantID: a, Role: tenants.SupportOperator, Reason: "x", TicketRef: "T", DurationMinutes: 481},
		"empty reason":     {TenantID: a, Role: tenants.SupportOperator, Reason: " ", TicketRef: "T", DurationMinutes: 60},
		"multiline ticket": {TenantID: a, Role: tenants.SupportOperator, Reason: "x", TicketRef: "T\n2", DurationMinutes: 60},
	} {
		if _, err := f.svc.RequestSupportGrant(pctx(ps, tenants.ActionPlatformSupportGrantRequest), staff(ps), in, nil); !errors.Is(err, tenants.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	if _, err := f.svc.RequestSupportGrant(pctx(ps, ""), tenants.StaffActor{IdentityID: ps, AuthTime: time.Now().Add(-time.Hour)},
		ask(a, tenants.SupportOperator), nil); !errors.Is(err, tenants.ErrReauthRequired) {
		t.Errorf("without step-up: %v", err)
	}
	if _, err := f.svc.RequestSupportGrant(pctx(ps, ""), staff(ps), ask(uuid.New(), tenants.SupportOperator), nil); !errors.Is(err, tenants.ErrNotFound) {
		t.Errorf("missing tenant: %v", err)
	}
	if _, err := f.svc.RequestSupportGrant(pctx(ps, ""), staff(ps), ask(gone, tenants.SupportOperator), nil); !errors.Is(err, tenants.ErrConflict) {
		t.Errorf("deprovisioning tenant: %v", err)
	}
	key := idem()
	g, err := f.svc.RequestSupportGrant(pctx(ps, tenants.ActionPlatformSupportGrantRequest), staff(ps), ask(a, tenants.SupportOperator), key)
	if err != nil || g.Status != tenants.GrantPending || g.Active || g.Grantee != "Support Person" || g.TenantSlug != "sup-a" ||
		g.ExpiresAt.Sub(g.StartsAt) != time.Hour {
		t.Fatalf("request: %+v, %v", g, err)
	}
	if again, err := f.svc.RequestSupportGrant(pctx(ps, ""), staff(ps), ask(a, tenants.SupportOperator), key); err != nil || again.ID != g.ID {
		t.Fatalf("replay of the same Idempotency-Key: %+v, %v", again, err)
	}
	if _, err := f.svc.RequestSupportGrant(pctx(ps, ""), staff(ps), ask(a, tenants.SupportOperator), idem()); !errors.Is(err, tenants.ErrConflict) {
		t.Errorf("a second open grant of the same person: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = $1 AND support_grant_id = $2`,
		tenants.ActionPlatformSupportGrantRequest, g.ID); n != 1 {
		t.Errorf("platform trail of the request: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2 AND support_grant_id = $3`,
		a, tenants.ActionSupportGrantRequest, g.ID); n != 1 {
		t.Errorf("tenant trail of the request: %d", n)
	}
	// the deciders (Owner, Admin — tenant.support_grant:decide), not the Viewer
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'support.grant_requested'
		AND recipient_membership_id IN ($2, $3)`, a, ownerM, adminM); n != 2 {
		t.Errorf("deciders notified: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE recipient_membership_id = $1`, viewerM); n != 0 {
		t.Errorf("viewer notified: %d", n)
	}

	// lists: the tenant sees its own grants only; the platform every grant
	tctx := reqCtx(t.Context(), viewerID, &a, tenants.ActionSupportGrantRequest)
	if p, err := f.svc.ListTenantSupportGrants(tctx, a, tenants.SupportGrantFilter{}); err != nil || len(p.Items) != 1 || p.Items[0].ID != g.ID {
		t.Fatalf("tenant list: %+v, %v", p, err)
	}
	if p, err := f.svc.ListTenantSupportGrants(tctx, b, tenants.SupportGrantFilter{}); err != nil || len(p.Items) != 0 {
		t.Fatalf("other tenant's list: %+v, %v", p, err)
	}
	if _, err := f.svc.ListTenantSupportGrants(tctx, a, tenants.SupportGrantFilter{Status: "bogus"}); !errors.Is(err, tenants.ErrInvalid) {
		t.Errorf("bad status filter: %v", err)
	}

	// tenant decisions: another tenant's Owner ⇒ not found; a viewer ⇒ the trigger refuses the decider
	bctx := reqCtx(t.Context(), ownerB, &b, tenants.ActionSupportGrantApprove)
	if _, err := f.svc.DecideTenantSupportGrant(bctx, fresh(ownerB, ownerBM), b, g.ID, true); !errors.Is(err, tenants.ErrNotFound) {
		t.Fatalf("approval from another tenant: %v", err)
	}
	actx := reqCtx(t.Context(), adminID, &a, tenants.ActionSupportGrantApprove)
	if _, err := f.svc.DecideTenantSupportGrant(actx, fresh(viewerID, viewerM), a, g.ID, true); !errors.Is(err, tenants.ErrForbidden) {
		t.Fatalf("approval by a viewer (layer 3 — trigger): %v", err)
	}
	if _, err := f.svc.DecideTenantSupportGrant(actx, tenants.Actor{IdentityID: adminID, MembershipID: adminM,
		AuthTime: time.Now().Add(-time.Hour)}, a, g.ID, true); !errors.Is(err, tenants.ErrReauthRequired) {
		t.Fatalf("approval without step-up: %v", err)
	}
	ok, err := f.svc.DecideTenantSupportGrant(actx, fresh(adminID, adminM), a, g.ID, true)
	if err != nil || ok.Status != tenants.GrantApproved || !ok.Active || ok.ApprovalKind != tenants.ApprovalTenant || ok.DecidedBy != "Admin A" {
		t.Fatalf("approval: %+v, %v", ok, err)
	}
	if _, err := f.svc.DecideTenantSupportGrant(actx, fresh(adminID, adminM), a, g.ID, false); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("reject after approval: %v", err)
	}
	rv, err := f.svc.RevokeTenantSupportGrant(reqCtx(t.Context(), ownerID, &a, tenants.ActionSupportGrantRevoke), fresh(ownerID, ownerM), a, g.ID)
	if err != nil || rv.Status != tenants.GrantRevoked || rv.Active || rv.RevokedAt == nil {
		t.Fatalf("revoke: %+v, %v", rv, err)
	}
	if _, err := f.svc.RevokeTenantSupportGrant(actx, fresh(ownerID, ownerM), a, g.ID); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("second revoke: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND support_grant_id = $2
		AND action IN ('support_grant.approve', 'support_grant.revoke')`, a, g.ID); n != 2 {
		t.Errorf("tenant trail of the decisions: %d", n)
	}

	// support_admin: never through the tenant ("Admin chỉ qua break-glass"); break-glass needs a SECOND Super Admin
	ga, err := f.svc.RequestSupportGrant(pctx(sa1, ""), staff(sa1), ask(a, tenants.SupportAdmin), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideTenantSupportGrant(actx, fresh(ownerID, ownerM), a, ga.ID, true); !errors.Is(err, tenants.ErrForbidden) {
		t.Fatalf("tenant approving support_admin: %v", err)
	}
	bg := pctx(sa1, tenants.ActionPlatformSupportGrantBreakGlass)
	if _, err := f.svc.ApproveBreakGlass(bg, staff(sa1), ga.ID); !errors.Is(err, tenants.ErrForbidden) {
		t.Fatalf("break-glass by the requester: %v", err)
	}
	if _, err := f.svc.ApproveBreakGlass(bg, tenants.StaffActor{IdentityID: sa2, AuthTime: time.Now().Add(-time.Hour)}, ga.ID); !errors.Is(err, tenants.ErrReauthRequired) {
		t.Fatalf("break-glass without step-up: %v", err)
	}
	done, err := f.svc.ApproveBreakGlass(pctx(sa2, tenants.ActionPlatformSupportGrantBreakGlass), staff(sa2), ga.ID)
	if err != nil || done.Status != tenants.GrantApproved || done.ApprovalKind != tenants.ApprovalBreakGlass || done.DecidedBy != "Super Two" || !done.Active {
		t.Fatalf("break-glass: %+v, %v", done, err)
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = 'support.break_glass' AND severity = 'high'`, a); n != 1 {
		t.Errorf("security event of the break-glass: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'support.break_glass'
		AND recipient_membership_id = $2`, a, ownerM); n != 1 {
		t.Errorf("Owner notified of the break-glass: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'support_grant.breakglass' AND support_grant_id = $2`, a, ga.ID); n != 1 {
		t.Errorf("tenant trail of the break-glass: %d", n)
	}
	// the tenant still revokes a break-glass grant; the tenant side never sees the platform approver's name
	tl, _ := f.svc.ListTenantSupportGrants(tctx, a, tenants.SupportGrantFilter{Status: tenants.GrantApproved})
	if len(tl.Items) != 1 || tl.Items[0].DecidedBy != "" || tl.Items[0].ApprovalKind != tenants.ApprovalBreakGlass {
		t.Fatalf("tenant view of the break-glass grant: %+v", tl.Items)
	}
	// a break-glass request by a non-Super Admin: the trigger refuses the requester
	gp, err := f.svc.RequestSupportGrant(pctx(ps, ""), staff(ps), ask(b, tenants.SupportOperator), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApproveBreakGlass(pctx(sa2, ""), staff(sa2), gp.ID); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("break-glass of a Platform Support request: %v", err)
	}
	if r, err := f.svc.RevokePlatformSupportGrant(pctx(sa1, tenants.ActionPlatformSupportGrantRevoke), staff(sa1), ga.ID); err != nil || r.Status != tenants.GrantRevoked {
		t.Fatalf("platform revoke: %+v, %v", r, err)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'support_grant.revoke' AND support_grant_id = $2
		AND details ->> 'revoked_by' = 'platform'`, a, ga.ID); n != 1 {
		t.Errorf("tenant trail of the platform revocation: %d", n)
	}
	if p, err := f.svc.ListPlatformSupportGrants(pctx(sa1, ""), tenants.SupportGrantFilter{Limit: 1}); err != nil || len(p.Items) != 1 || p.NextCursor == "" {
		t.Fatalf("platform list page 1: %+v, %v", p, err)
	} else if p2, err := f.svc.ListPlatformSupportGrants(pctx(sa1, ""), tenants.SupportGrantFilter{Limit: 10, Cursor: p.NextCursor}); err != nil ||
		len(p2.Items) != 2 || p2.Items[0].ID == p.Items[0].ID {
		t.Fatalf("platform list page 2: %+v, %v", p2, err)
	}
}

// TestSupportGrantExpire: grant.expire (worker roles) marks pending and approved grants past their window expired, on
// both trails; the lists already showed them expired; an expired grant cannot be approved.
func TestSupportGrantExpire(t *testing.T) {
	f := newFixture(t)
	a, idpA := f.tenant("exp-a", "A", "active", false)
	ownerID, ownerM := f.member(a, idpA, "Owner", "o@a.test", "tenant_owner", "active")
	_, pu := f.staffUser("Staff", "platform_support")
	ins := func(status string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		f.exec(`INSERT INTO support_access_grants (id, tenant_id, grantee_platform_user_id, requested_by_platform_user_id,
				effective_role_key, reason, ticket_ref, starts_at, expires_at)
			VALUES ($1, $2, $3, $3, 'support_operator', 'r', 'T', now() - interval '2 hours', now() - interval '1 hour')`, id, a, pu)
		if status == tenants.GrantApproved { // a decision recorded before the window ended (fixture: trigger bypassed)
			tx, err := f.su.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{`SET LOCAL session_replication_role = replica`,
				`UPDATE support_access_grants SET status = 'approved', approval_kind = 'tenant', approved_by_membership_id = '` +
					ownerM.String() + `', decided_at = now() - interval '90 minutes' WHERE id = '` + id.String() + `'`} {
				if _, err := tx.Exec(t.Context(), q); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	pending, approved := ins(tenants.GrantPending), ins(tenants.GrantApproved)
	ctx := reqCtx(t.Context(), ownerID, &a, tenants.ActionSupportGrantApprove)
	p, err := f.svc.ListTenantSupportGrants(ctx, a, tenants.SupportGrantFilter{Status: tenants.GrantExpired})
	if err != nil || len(p.Items) != 2 || p.Items[0].Active || p.Items[1].Active {
		t.Fatalf("effective status before the job: %+v, %v", p, err)
	}
	if _, err := f.svc.DecideTenantSupportGrant(ctx, fresh(ownerID, ownerM), a, pending, true); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("approving a grant past its window: %v", err)
	}
	pg := storetest.Require(t)
	worker := tenants.New(pg.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 4), tenants.Options{})
	n, err := worker.ExpireSupportGrants(audit.WithRequest(t.Context(), nil), nil)
	if err != nil || n != 2 {
		t.Fatalf("grant.expire: %d, %v", n, err)
	}
	for _, id := range []uuid.UUID{pending, approved} {
		if c := f.count(`SELECT count(*) FROM support_access_grants WHERE id = $1 AND status = 'expired'`, id); c != 1 {
			t.Errorf("%s not expired", id)
		}
		if c := f.count(`SELECT count(*) FROM audit_events WHERE support_grant_id = $1 AND actor_type = 'system'
			AND action IN ('support_grant.expire', 'platform.support_grant.expire')`, id); c != 2 {
			t.Errorf("%s: %d expiry events, want platform + tenant", id, c)
		}
	}
	if n, err := worker.ExpireSupportGrants(t.Context(), nil); err != nil || n != 0 {
		t.Fatalf("second run: %d, %v", n, err)
	}
}
