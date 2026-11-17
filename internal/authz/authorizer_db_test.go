package authz

// The Authorizer on a real database: memberships, roles and grants of the seed, RLS of the tenant pool, the
// outcomes of §8.4 (404 for a tenant the caller is not a member of, 403 without the grant, tenant_suspended for writes
// of a suspended tenant) and the per-request loading of §8.3 step 8.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAuthorizerTenantRoutes(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	az := New(e.openStore(t))
	ctx := t.Context()
	a, b := newTenant(t, su, "active"), newTenant(t, su, "active")
	suspended, deleted := newTenant(t, su, TenantSuspended), newTenant(t, su, TenantDeleted)
	viewer := a.member(t, su, RoleTenantViewer, StatusActive, StatusActive)
	eu := a.member(t, su, RoleEndUser, StatusActive, StatusActive)
	locked := a.member(t, su, RoleTenantAdmin, "locked", StatusActive)
	disabled := a.member(t, su, RoleTenantAdmin, StatusActive, "disabled")
	ownerB := b.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	adminS := suspended.member(t, su, RoleTenantAdmin, StatusActive, StatusActive)
	ownerD := deleted.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	staff := platformIdentity(t, su, RoleSuperAdmin, StatusActive)
	noMembership := a.identityOnly(t, su)

	readAudit := Requirement{Permission: "tenant.audit:read", ReadOnly: true}
	cases := []struct {
		name   string
		ctx    context.Context
		tenant uuid.UUID
		req    Requirement
		kind   error // nil = allowed
		reason string
	}{
		{"viewer reads the audit of its tenant", asTenant(ctx, viewer.identity), a.id, readAudit, nil, ""},
		{"viewer syncs devices (TV —)", asTenant(ctx, viewer.identity), a.id, Need("tenant.device:sync"), ErrForbidden, "no_grant"},
		{"owner of B on tenant A (cross-tenant ID ⇒ 404, invariant 6)", asTenant(ctx, ownerB.identity), a.id, readAudit, ErrNotFound, "not_a_member"},
		{"viewer of A on tenant B", asTenant(ctx, viewer.identity), b.id, readAudit, ErrNotFound, "not_a_member"},
		{"tenant that does not exist", asTenant(ctx, viewer.identity), uuid.Must(uuid.NewV7()), readAudit, ErrNotFound, "not_a_member"},
		{"identity of A without membership", asTenant(ctx, noMembership), a.id, readAudit, ErrNotFound, "not_a_member"},
		{"locked membership", asTenant(ctx, locked.identity), a.id, readAudit, ErrNotFound, "membership_inactive"},
		{"disabled identity", asTenant(ctx, disabled.identity), a.id, readAudit, ErrNotFound, "membership_inactive"},
		{"owner of a deleted tenant", asTenant(ctx, ownerD.identity), deleted.id, readAudit, ErrNotFound, "not_a_member"},
		{"admin writes while the tenant is suspended (invariant 5)", asTenant(ctx, adminS.identity), suspended.id, Need("tenant.device:sync"), ErrTenantSuspended, "tenant_suspended"},
		{"admin reads while the tenant is suspended", asTenant(ctx, adminS.identity), suspended.id, readAudit, nil, ""},
		{"end user: own scope on an operation without x-own-resource", asTenant(ctx, eu.identity), a.id, Requirement{Permission: "tenant.device:read", ReadOnly: true}, ErrForbidden, "own_scope_on_shared_operation"},
		{"end user requests enrolment, condition not enforced", asTenant(ctx, eu.identity), a.id, Need("tenant.enrollment:request"), ErrForbidden, "condition_not_enforced:self_enroll"},
		{"end user reads the audit (EU —)", asTenant(ctx, eu.identity), a.id, readAudit, ErrForbidden, "no_grant"},
		{"staff without Support Access Grant (invariant 2, AC-05a)", asStaff(ctx, staff), a.id, readAudit, ErrForbidden, "no_support_grant"},
		{"identity of A presented on the admin origin", WithPrincipal(ctx, Principal{IdentityID: viewer.identity, Scope: ScopeTenant, Origin: OriginAdmin}), a.id, readAudit, ErrForbidden, "origin_scope_mismatch"},
		{"no session", ctx, a.id, readAudit, ErrUnauthenticated, "no_principal"},
	}
	for _, c := range cases {
		d, err := az.Require(c.ctx, c.tenant, c.req)
		if c.kind != nil {
			wantDenied(t, c.name, err, c.kind, c.reason)
			continue
		}
		if err != nil || d.TenantID != c.tenant || d.MembershipID == uuid.Nil || d.RoleKey == "" {
			t.Errorf("%s: %+v, %v", c.name, d, err)
		}
	}

	// own-resource and conditional grants through the operations of the spec
	d, err := az.RequireOperation(asTenant(ctx, eu.identity), "getDevice", a.id)
	if err != nil || !d.OwnOnly || d.MembershipID != eu.membership {
		t.Fatalf("end user getDevice: %+v, %v", d, err)
	}
	if err := d.CheckOwner(&eu.membership, false); err != nil {
		t.Errorf("own device: %v", err)
	}
	wantDenied(t, "someone else's device", d.CheckOwner(&viewer.membership, false), ErrNotFound, "not_own_resource")
	if d, err := az.Require(asTenant(ctx, eu.identity), a.id, Requirement{Permission: "tenant.enrollment:request",
		Conditions: []string{CondSelfEnroll}}); err != nil || d.Condition != CondSelfEnroll {
		t.Errorf("end user requests enrolment, condition enforced by the operation: %+v, %v", d, err)
	}
	_, err = az.RequireOperation(asTenant(ctx, eu.identity), "syncDevices", a.id)
	wantDenied(t, "end user syncDevices", err, ErrForbidden, "no_grant")

	// the Owner may call every tenant operation of the spec — with a grant on every resource, except the notifications
	// that are own-only for every role (§8.6 ○: the Owner reads only its own); staff none of them (no grant yet)
	owner := a.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	for _, o := range Operations() {
		if !o.TenantScoped() {
			continue
		}
		ownOnly := o.Permission == "tenant.notification:read"
		if d, err := az.RequireOperation(asTenant(ctx, owner.identity), o.ID, a.id); err != nil || d.OwnOnly != ownOnly {
			t.Errorf("owner %s: %+v, %v", o.ID, d, err)
		}
		_, err := az.RequireOperation(asStaff(ctx, staff), o.ID, a.id)
		wantDenied(t, "staff "+o.ID, err, ErrForbidden, "no_support_grant")
	}
}

func TestAuthorizerPlatformRoutes(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	az := New(e.openStore(t))
	ctx := t.Context()
	sa := platformIdentity(t, su, RoleSuperAdmin, StatusActive)
	sa2 := platformIdentity(t, su, RoleSuperAdmin, StatusActive)
	po := platformIdentity(t, su, RolePlatformOperator, StatusActive)
	ps := platformIdentity(t, su, RolePlatformSupport, StatusActive)
	pv := platformIdentity(t, su, RolePlatformViewer, StatusActive)
	disabled := platformIdentity(t, su, RoleSuperAdmin, "disabled")
	notStaff := platformIdentity(t, su, "", "")
	a := newTenant(t, su, "active")
	tenantOwner := a.member(t, su, RoleTenantOwner, StatusActive, StatusActive)

	read := func(p Permission) Requirement { return Requirement{Permission: p, ReadOnly: true} }
	for _, c := range []struct {
		name     string
		identity uuid.UUID
		req      Requirement
		reason   string // "" = allowed
	}{
		{"viewer reads tenants", pv, read("platform.tenant:read"), ""},
		{"viewer reads the platform audit (PV ✔)", pv, read("platform.audit:read"), ""},
		{"viewer creates a tenant (PV —)", pv, Need("platform.tenant:create"), "no_grant"},
		{"support reads the platform audit (PS —)", ps, read("platform.audit:read"), "no_grant"},
		{"operator decides an approval, condition not enforced", po, Need("platform.approval:decide"), "condition_not_enforced:restore_only"},
		{"operator decides a restore approval", po, Requirement{Permission: "platform.approval:decide", Conditions: []string{CondRestoreOnly}}, ""},
		{"operator changes platform settings (PO —)", po, Need("platform.settings:update"), "no_grant"},
		{"disabled super admin", disabled, read("platform.tenant:read"), "platform_user_inactive"},
		{"platform identity that is not a platform user", notStaff, read("platform.tenant:read"), "not_platform_user"},
	} {
		d, err := az.Require(asStaff(ctx, c.identity), uuid.Nil, c.req)
		if c.reason != "" {
			wantDenied(t, c.name, err, ErrForbidden, c.reason)
			continue
		}
		if err != nil || d.PlatformUserID == uuid.Nil {
			t.Errorf("%s: %+v, %v", c.name, d, err)
		}
	}
	// a tenant identity never passes a platform route — not even a Tenant Owner
	_, err := az.RequireOperation(asTenant(ctx, tenantOwner.identity), "listPlatformTenants", uuid.Nil)
	wantDenied(t, "tenant owner on a platform route", err, ErrForbidden, "not_platform_principal")

	// every platform operation of the spec is open to the Super Admin
	for _, o := range Operations() {
		if !strings.HasPrefix(o.Path, "/platform/") {
			continue
		}
		if _, err := az.RequireOperation(asStaff(ctx, sa), o.ID, a.id); err != nil {
			t.Errorf("super admin %s: %v", o.ID, err)
		}
	}
	// 2P: the decision obliges an approval; the second person must be another Super Admin
	del := Requirement{Permission: "platform.tenant:delete", DualControl: true}
	d, err := az.Require(asStaff(ctx, sa), uuid.Nil, del)
	if err != nil || !d.NeedsApproval() {
		t.Fatalf("super admin deletes a tenant: %+v, %v", d, err)
	}
	_, err = az.RequireApprover(asStaff(ctx, sa), uuid.Nil, sa, del)
	wantDenied(t, "self approval", err, ErrForbidden, "self_approval")
	if d, err := az.RequireApprover(asStaff(ctx, sa2), uuid.Nil, sa, del); err != nil || d.NeedsApproval() {
		t.Errorf("second super admin approves: %+v, %v", d, err)
	}
	_, err = az.RequireApprover(asStaff(ctx, po), uuid.Nil, sa, del)
	wantDenied(t, "operator approving a tenant deletion (PO —)", err, ErrForbidden, "no_grant")
}

// TestAuthorizerLoadsEveryRequest is §8.3 step 8: the session carries no role, so a change of role, membership
// status or tenant status in the database decides the very next request — nothing is cached.
func TestAuthorizerLoadsEveryRequest(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	az := New(e.openStore(t))
	ctx := t.Context()
	a := newTenant(t, su, "active")
	m := a.member(t, su, RoleTenantViewer, StatusActive, StatusActive)
	who := asTenant(ctx, m.identity)
	readAudit := Requirement{Permission: "tenant.audit:read", ReadOnly: true}
	set := func(sql string, args ...any) { exec(t, su, sql, args...) }

	if _, err := az.Require(who, a.id, readAudit); err != nil {
		t.Fatalf("viewer: %v", err)
	}
	set(`UPDATE tenant_memberships SET role_id = $1 WHERE id = $2`, roleID(t, su, ScopeTenant, RoleEndUser), m.membership)
	_, err := az.Require(who, a.id, readAudit)
	wantDenied(t, "after demotion to end user", err, ErrForbidden, "no_grant")
	set(`UPDATE tenant_memberships SET role_id = $1, status = 'locked' WHERE id = $2`, roleID(t, su, ScopeTenant, RoleTenantAdmin), m.membership)
	_, err = az.Require(who, a.id, Need("tenant.device:sync"))
	wantDenied(t, "after lock", err, ErrNotFound, "membership_inactive")
	set(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, m.membership)
	if _, err := az.Require(who, a.id, Need("tenant.device:sync")); err != nil {
		t.Errorf("after unlock as admin: %v", err)
	}
	set(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, a.id)
	_, err = az.Require(who, a.id, Need("tenant.device:sync"))
	wantDenied(t, "after suspension", err, ErrTenantSuspended, "tenant_suspended")
	set(`UPDATE tenants SET status = 'active' WHERE id = $1`, a.id)
	if _, err := az.Require(who, a.id, Need("tenant.device:sync")); err != nil {
		t.Errorf("after resume: %v", err)
	}
	// a grant removed from the role (a new seed) applies at once as well
	set(`DELETE FROM role_permissions WHERE role_id = $1 AND permission_key = 'tenant.device:sync'`, roleID(t, su, ScopeTenant, RoleTenantAdmin))
	_, err = az.Require(who, a.id, Need("tenant.device:sync"))
	wantDenied(t, "after the grant is removed", err, ErrForbidden, "no_grant")
	set(`INSERT INTO role_permissions (role_id, role_scope, permission_key, permission_scope)
		VALUES ($1, 'tenant', 'tenant.device:sync', 'tenant')`, roleID(t, su, ScopeTenant, RoleTenantAdmin))
}
