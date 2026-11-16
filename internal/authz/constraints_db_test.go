package authz

// The verification of P2-T07 in §20: the database itself rejects a membership whose identity belongs to another
// tenant's IdP or whose role is of platform scope — issuer binding and role scope by composite foreign keys, no
// trigger (migration 0002). The same mechanism keeps platform users, identities and grants inside their scope.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

const (
	fkViolation    = "23503" // foreign_key_violation
	checkViolation = "23514" // check_violation
)

// TestDBRejectsCrossScopeMemberships inserts memberships through the application path (tenant pool, WithTenantTx of
// tenant A, sqlc) — RLS lets every row through (tenant_id = A), only the composite foreign keys stop them.
func TestDBRejectsCrossScopeMemberships(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	s := e.openStore(t)
	ctx := t.Context()
	a, b := newTenant(t, su, "active"), newTenant(t, su, "active")
	ownerRole := roleID(t, su, ScopeTenant, RoleTenantOwner)
	create := func(identity, role uuid.UUID) error {
		return s.WithTenantTx(ctx, a.id, func(q *sqlcdb.Queries) error {
			_, err := q.CreateTenantMembership(ctx, sqlcdb.CreateTenantMembershipParams{TenantID: a.id, IdentityID: identity, RoleID: role})
			return err
		})
	}
	for _, c := range []struct {
		name     string
		identity uuid.UUID
		role     uuid.UUID
	}{
		{"identity of tenant B's IdP in tenant A (issuer binding, §8.4 invariant 1)", b.identityOnly(t, su), ownerRole},
		{"identity of the platform IdP in a tenant (invariant 1)", platformIdentity(t, su, "", ""), ownerRole},
		{"role of platform scope (Super Admin) in a tenant", a.identityOnly(t, su), roleID(t, su, ScopePlatform, RoleSuperAdmin)},
		{"role of platform scope (Platform Viewer) in a tenant", a.identityOnly(t, su), roleID(t, su, ScopePlatform, RolePlatformViewer)},
		{"support role in a tenant (only the effective role of a grant, §8.6)", a.identityOnly(t, su), roleID(t, su, ScopeSupport, RoleSupportAdmin)},
	} {
		wantCode(t, c.name, create(c.identity, c.role), fkViolation)
	}
	if err := create(a.identityOnly(t, su), ownerRole); err != nil {
		t.Fatalf("control — own identity with a tenant role: %v", err)
	}

	// a role change into another scope is refused the same way
	m := a.member(t, su, RoleTenantViewer, StatusActive, StatusActive)
	for _, r := range []uuid.UUID{roleID(t, su, ScopePlatform, RoleSuperAdmin), roleID(t, su, ScopeSupport, RoleSupportOperator)} {
		err := s.WithTenantTx(ctx, a.id, func(q *sqlcdb.Queries) error {
			_, err := q.UpdateTenantMembershipRole(ctx, sqlcdb.UpdateTenantMembershipRoleParams{TenantID: a.id, ID: m.membership, RoleID: r})
			return err
		})
		wantCode(t, "role change to a role of another scope", err, fkViolation)
	}
	// nobody — not even the table owner or a superuser — can claim another role scope on the row itself
	_, err := su.Exec(ctx, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, role_scope) VALUES ($1, $2, $3, 'platform')`,
		a.id, a.identityOnly(t, su), roleID(t, su, ScopePlatform, RoleSuperAdmin))
	wantCode(t, "membership row claiming role_scope platform", err, checkViolation)
}

// TestDBRejectsCrossScopePlatformUsers: a platform user is a platform identity with a platform role.
func TestDBRejectsCrossScopePlatformUsers(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	ctx := t.Context()
	a := newTenant(t, su, "active")
	insert := func(identity, role uuid.UUID) error {
		_, err := su.Exec(ctx, `INSERT INTO platform_users (identity_id, role_id) VALUES ($1, $2)`, identity, role)
		return err
	}
	sa := roleID(t, su, ScopePlatform, RoleSuperAdmin)
	wantCode(t, "tenant identity as a platform user (IdP of a tenant gives no platform right — invariant 1)",
		insert(a.identityOnly(t, su), sa), fkViolation)
	wantCode(t, "platform user with a tenant role", insert(platformIdentity(t, su, "", ""), roleID(t, su, ScopeTenant, RoleTenantOwner)), fkViolation)
	wantCode(t, "platform user with a support role", insert(platformIdentity(t, su, "", ""), roleID(t, su, ScopeSupport, RoleSupportAdmin)), fkViolation)
	_, err := su.Exec(ctx, `INSERT INTO platform_users (identity_id, identity_scope, role_id) VALUES ($1, 'tenant', $2)`, a.identityOnly(t, su), sa)
	wantCode(t, "platform user row claiming identity_scope tenant", err, checkViolation)
	if err := insert(platformIdentity(t, su, "", ""), roleID(t, su, ScopePlatform, RolePlatformViewer)); err != nil {
		t.Fatalf("control — platform identity with a platform role: %v", err)
	}
}

// TestDBRejectsIdentityOutsideItsIdP: identities copy tenant_id and scope from their IdP; the copies are bound by
// composite foreign keys, so an identity cannot claim another tenant (or the platform) than its IdP's.
func TestDBRejectsIdentityOutsideItsIdP(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	ctx := t.Context()
	a, b := newTenant(t, su, "active"), newTenant(t, su, "active")
	platformIdP := uuid.Must(uuid.NewV7())
	exec(t, su, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver) VALUES ($1, 'platform', 'https://idp.test/p-'||$2, 'c', 'keycloak')`,
		platformIdP, randomHex(6))
	insert := func(idp uuid.UUID, tenant *uuid.UUID, scope string) error {
		_, err := su.Exec(ctx, `INSERT INTO identities (idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, $4)`, idp, tenant, scope, "s-"+randomHex(6))
		return err
	}
	wantCode(t, "identity of tenant A on tenant B's IdP", insert(b.idp, &a.id, "tenant"), fkViolation)
	wantCode(t, "platform identity on a tenant IdP", insert(a.idp, nil, "platform"), fkViolation)
	wantCode(t, "tenant identity on the platform IdP", insert(platformIdP, &a.id, "tenant"), fkViolation)
	wantCode(t, "scope platform with a tenant", insert(platformIdP, &a.id, "platform"), checkViolation)
	if err := insert(a.idp, &a.id, "tenant"); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// TestDBRejectsCrossScopeGrants: role_permissions copies the scope of the role and of the permission and binds both
// with composite foreign keys — a platform role never holds a tenant permission (invariant 2), a tenant or support
// role never a platform permission, and ○ exists only for tenant roles.
func TestDBRejectsCrossScopeGrants(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	ctx := t.Context()
	grant := func(role uuid.UUID, roleScope, perm, permScope, scope string) error {
		_, err := su.Exec(ctx, `INSERT INTO role_permissions (role_id, role_scope, permission_key, permission_scope, scope)
			VALUES ($1, $2, $3, $4, $5)`, role, roleScope, perm, permScope, scope)
		return err
	}
	sa := roleID(t, su, ScopePlatform, RoleSuperAdmin)
	pv := roleID(t, su, ScopePlatform, RolePlatformViewer)
	owner := roleID(t, su, ScopeTenant, RoleTenantOwner)
	support := roleID(t, su, ScopeSupport, RoleSupportOperator)
	for _, c := range []struct {
		name, code string
		err        error
	}{
		{"tenant permission for a platform role", checkViolation, grant(sa, "platform", "tenant.device:read", "tenant", "any")},
		{"…claiming the role is of tenant scope", fkViolation, grant(sa, "tenant", "tenant.device:read", "tenant", "any")},
		{"…claiming the permission is of platform scope", fkViolation, grant(sa, "platform", "tenant.device:read", "platform", "any")},
		{"platform permission for a tenant role", checkViolation, grant(owner, "tenant", "platform.tenant:read", "platform", "any")},
		{"platform permission for a support role", checkViolation, grant(support, "support", "platform.tenant:read", "platform", "any")},
		{"own scope on a platform role", checkViolation, grant(pv, "platform", "platform.tenant:create", "platform", "own")},
		{"own scope on a support role", checkViolation, grant(support, "support", "tenant.device:tag", "tenant", "own")},
	} {
		wantCode(t, c.name, c.err, c.code)
	}
	_, err := su.Exec(ctx, `INSERT INTO permissions (key, scope) VALUES ('platform.fixture_x:read', 'tenant')`)
	wantCode(t, "permission whose key prefix differs from its scope", err, checkViolation)
	_, err = su.Exec(ctx, `INSERT INTO roles (scope, key, name) VALUES ('global', 'x_`+randomHex(3)+`', 'x')`)
	wantCode(t, "role of an unknown scope", err, checkViolation)
}
