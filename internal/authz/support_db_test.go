package authz

// Support Access Grant on a real database (P4-T13, §8.7; IT-17 support case): staff reach a tenant route only through
// a live grant of their own on that tenant, with the permissions of its effective role; a revoked or expired grant
// stops at the next request (layer 1); and the support actor a granted request carries cannot open a tenant
// transaction once its grant is no longer live — nor ever for another tenant or another person (store.WithTenantTx).

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// grantFx inserts a support grant (pending), then — status approved — records a tenant decision with the trigger
// bypassed (fixture only); window "expired" puts the window in the past.
func grantFx(t *testing.T, su *pgx.Conn, tenant tenantFx, decider uuid.UUID, staffUser uuid.UUID, role, status string, expired bool) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	window := `now() - interval '1 minute', now() + interval '1 hour'`
	if expired {
		window = `now() - interval '2 hours', now() - interval '1 hour'`
	}
	exec(t, su, `INSERT INTO support_access_grants (id, tenant_id, grantee_platform_user_id, requested_by_platform_user_id,
			effective_role_key, reason, ticket_ref, starts_at, expires_at)
		VALUES ($1, $2, $3, $3, $4, 'r', 'T', `+window+`)`, id, tenant.id, staffUser, role)
	if status == "pending" {
		return id
	}
	tx, err := su.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	revoked := "NULL"
	st := "approved"
	if status == "revoked" {
		revoked, st = "now()", "revoked"
	}
	if _, err := tx.Exec(t.Context(), `UPDATE support_access_grants SET status = $2, approval_kind = 'tenant',
		approved_by_membership_id = $3, decided_at = starts_at, revoked_at = `+revoked+` WHERE id = $1`, id, st, decider); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return id
}

func platformUserOf(t *testing.T, su *pgx.Conn, identity uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := su.QueryRow(t.Context(), `SELECT id FROM platform_users WHERE identity_id = $1`, identity).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAuthorizerSupportAccess(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	st := e.openStore(t)
	az := New(st)
	ctx := t.Context()
	a, b := newTenant(t, su, "active"), newTenant(t, su, "active")
	suspended := newTenant(t, su, TenantSuspended)
	ownerA := a.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	ownerB := b.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	ownerS := suspended.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	op := platformIdentity(t, su, RolePlatformSupport, StatusActive)   // live support_operator grant on A
	adm := platformIdentity(t, su, RoleSuperAdmin, StatusActive)       // live support_admin grant on A
	late := platformIdentity(t, su, RolePlatformSupport, StatusActive) // expired, revoked and pending grants on A
	opPU, admPU, latePU := platformUserOf(t, su, op), platformUserOf(t, su, adm), platformUserOf(t, su, late)
	gOp := grantFx(t, su, a, ownerA.membership, opPU, RoleSupportOperator, "approved", false)
	gAdm := grantFx(t, su, a, ownerA.membership, admPU, RoleSupportAdmin, "approved", false)
	grantFx(t, su, a, ownerA.membership, latePU, RoleSupportOperator, "approved", true)
	grantFx(t, su, a, ownerA.membership, latePU, RoleSupportOperator, "revoked", false)
	grantFx(t, su, a, ownerA.membership, latePU, RoleSupportOperator, "pending", false)
	gS := grantFx(t, su, suspended, ownerS.membership, opPU, RoleSupportOperator, "approved", false)
	_ = ownerB

	read := func(p Permission) Requirement { return Requirement{Permission: p, ReadOnly: true} }
	cases := []struct {
		name   string
		who    uuid.UUID
		tenant uuid.UUID
		req    Requirement
		kind   error
		reason string
		grant  uuid.UUID // allowed: the grant of the decision
	}{
		{"operator reads devices (G)", op, a.id, read("tenant.device:read"), nil, "", gOp},
		{"operator syncs devices (G)", op, a.id, Need("tenant.device:sync"), nil, "", gOp},
		{"operator reads the audit (G)", op, a.id, read("tenant.audit:read"), nil, "", gOp},
		{"operator tags a device (G (Admin) only)", op, a.id, Need("tenant.device:tag"), ErrForbidden, "no_grant", uuid.Nil},
		{"operator applies a policy (G (Admin) only)", op, a.id, Need("tenant.policy:apply"), ErrForbidden, "no_grant", uuid.Nil},
		{"admin tags a device (G (Admin))", adm, a.id, Need("tenant.device:tag"), nil, "", gAdm},
		{"admin never edits a policy (Staff —)", adm, a.id, Need("tenant.policy:edit"), ErrForbidden, "no_grant", uuid.Nil},
		{"admin never manages members (Staff —)", adm, a.id, Need("tenant.membership:assign"), ErrForbidden, "no_grant", uuid.Nil},
		{"admin never decides grants (Staff —)", adm, a.id, Need("tenant.support_grant:decide"), ErrForbidden, "no_grant", uuid.Nil},
		{"operator on tenant B (no grant there)", op, b.id, read("tenant.device:read"), ErrForbidden, "no_support_grant", uuid.Nil},
		{"expired, revoked and pending grants only", late, a.id, read("tenant.device:read"), ErrForbidden, "no_support_grant", uuid.Nil},
		{"operator reads a suspended tenant", op, suspended.id, read("tenant.device:read"), nil, "", gS},
		{"operator writes in a suspended tenant", op, suspended.id, Need("tenant.device:sync"), ErrTenantSuspended, "tenant_suspended", uuid.Nil},
	}
	for _, c := range cases {
		d, err := az.Require(asStaff(ctx, c.who), c.tenant, c.req)
		if c.kind != nil {
			wantDenied(t, c.name, err, c.kind, c.reason)
			continue
		}
		if err != nil || d.SupportGrantID != c.grant || d.MembershipID != uuid.Nil || d.TenantID != c.tenant || !d.Support() {
			t.Errorf("%s: %+v, %v", c.name, d, err)
		}
	}

	// IT-17 (support case): the actor of a granted request opens tenant transactions while — and only while — its grant
	// is live, for its own tenant and person; the check runs inside the transaction, before the caller's statements.
	d, err := az.Require(asStaff(ctx, op), a.id, read("tenant.device:read"))
	if err != nil {
		t.Fatal(err)
	}
	sctx := SupportContext(ctx, d)
	ran := 0
	body := func(q *sqlcdb.Queries) error { ran++; return nil }
	if err := st.WithTenantTx(sctx, a.id, body); err != nil || ran != 1 {
		t.Fatalf("live grant: ran %d, %v", ran, err)
	}
	for name, c := range map[string]struct {
		ctx    context.Context
		tenant uuid.UUID
	}{
		"another tenant":  {sctx, b.id},
		"another person":  {store.WithSupportActor(ctx, store.SupportActor{GrantID: gOp, PlatformUserID: admPU}), a.id},
		"another's grant": {store.WithSupportActor(ctx, store.SupportActor{GrantID: gAdm, PlatformUserID: opPU}), a.id},
		"zero grant":      {store.WithSupportActor(ctx, store.SupportActor{PlatformUserID: opPU}), a.id},
	} {
		if err := st.WithTenantTx(c.ctx, c.tenant, body); !errors.Is(err, store.ErrSupportGrantNotLive) {
			t.Errorf("%s: %v, want ErrSupportGrantNotLive", name, err)
		}
	}
	exec(t, su, `UPDATE support_access_grants SET status = 'revoked', revoked_at = now() WHERE id = $1`, gOp)
	if err := st.WithTenantJobTx(sctx, a.id, func(*store.Tx) error { ran++; return nil }); !errors.Is(err, store.ErrSupportGrantNotLive) {
		t.Fatalf("revoked during the request (job tx): %v", err)
	}
	if err := st.WithTenantTx(store.WithoutSupportActor(sctx), a.id, body); err != nil {
		t.Fatalf("the audit trail's own write (support actor removed): %v", err)
	}
	if ran != 2 {
		t.Fatalf("a refused transaction ran its body: %d", ran)
	}
	_, err = az.Require(asStaff(ctx, op), a.id, read("tenant.device:read"))
	wantDenied(t, "next request after the revocation", err, ErrForbidden, "no_support_grant")
	if SupportContext(ctx, Decision{}) != ctx {
		t.Error("SupportContext of a non-support decision must leave ctx unchanged")
	}
}
