package store

import (
	"strings"
	"testing"
)

// TestSeedSyncsRBAC: Migrate applies database/seeds/rbac.sql after the migrations; every further run brings the
// seeded rows back to the committed content — a grant added to or removed from a system role is undone, a rank is
// restored, a permission that left the matrices goes away with its grants — while custom roles keep their grants; a
// system role missing from the seed stops the run without changing anything (memberships may reference it).
func TestSeedSyncsRBAC(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 0)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()

	type counts struct{ roles, perms, grants, systemGrants int }
	count := func() counts {
		var c counts
		if err := su.QueryRow(ctx, `SELECT (SELECT count(*) FROM roles WHERE is_system), (SELECT count(*) FROM permissions),
				(SELECT count(*) FROM role_permissions),
				(SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.is_system)`).
			Scan(&c.roles, &c.perms, &c.grants, &c.systemGrants); err != nil {
			t.Fatal(err)
		}
		return c
	}
	seeded := count()
	if seeded.roles != 11 || seeded.perms < 80 || seeded.systemGrants < 250 {
		t.Fatalf("after Migrate: %+v — the seed did not run", seeded)
	}
	if err := Seed(ctx, mig); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if got := count(); got != seeded {
		t.Fatalf("second seed changed the catalog: %+v → %+v", seeded, got)
	}

	// drift of every kind, then one seed run
	exec(t, su, `INSERT INTO role_permissions (role_id, role_scope, permission_key, permission_scope)
		SELECT id, scope, 'tenant.billing:read', 'tenant' FROM roles WHERE key = 'tenant_viewer'`)
	exec(t, su, `DELETE FROM role_permissions WHERE permission_key = 'tenant.audit:read'
		AND role_id = (SELECT id FROM roles WHERE key = 'tenant_owner')`)
	exec(t, su, `UPDATE roles SET rank = 0 WHERE key = 'tenant_admin'`)
	exec(t, su, `UPDATE role_permissions SET scope = 'any' WHERE permission_key = 'tenant.device:read'
		AND role_id = (SELECT id FROM roles WHERE key = 'end_user')`)
	exec(t, su, `INSERT INTO permissions (key, scope) VALUES ('tenant.obsolete_x:read', 'tenant')`)
	exec(t, su, `INSERT INTO roles (scope, key, name) VALUES ('tenant', 'custom_seed_test', 'Custom')`)
	exec(t, su, `INSERT INTO role_permissions (role_id, role_scope, permission_key, permission_scope)
		SELECT id, 'tenant', p, 'tenant' FROM roles, unnest(ARRAY['tenant.obsolete_x:read', 'tenant.audit:read']) p
		WHERE key = 'custom_seed_test'`)
	if err := Seed(ctx, mig); err != nil {
		t.Fatalf("seed after drift: %v", err)
	}
	var viewerBilling, ownerAudit, obsolete, customGrants, adminRank int
	var euScope string
	if err := su.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.key = 'tenant_viewer' AND rp.permission_key = 'tenant.billing:read'),
			(SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.key = 'tenant_owner' AND rp.permission_key = 'tenant.audit:read'),
			(SELECT count(*) FROM permissions WHERE key = 'tenant.obsolete_x:read'),
			(SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.key = 'custom_seed_test'),
			(SELECT rank FROM roles WHERE key = 'tenant_admin'),
			(SELECT rp.scope FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.key = 'end_user' AND rp.permission_key = 'tenant.device:read')`).
		Scan(&viewerBilling, &ownerAudit, &obsolete, &customGrants, &adminRank, &euScope); err != nil {
		t.Fatal(err)
	}
	if viewerBilling != 0 || ownerAudit != 1 || obsolete != 0 || customGrants != 1 || adminRank != 4 || euScope != "own" {
		t.Errorf("after re-seed: viewer billing %d (want 0), owner audit %d (1), obsolete permission %d (0), custom grants %d (1), "+
			"admin rank %d (4), end user device:read scope %q (own)", viewerBilling, ownerAudit, obsolete, customGrants, adminRank, euScope)
	}
	if got := count(); got.roles != seeded.roles || got.perms != seeded.perms || got.systemGrants != seeded.systemGrants {
		t.Errorf("catalog after re-seed %+v, want the seeded %+v (plus the custom role's grant)", got, seeded)
	}

	// a system role the seed does not know: the run fails and leaves everything as it was
	exec(t, su, `INSERT INTO roles (scope, key, name, is_system) VALUES ('tenant', 'retired_role', 'Retired', true)`)
	exec(t, su, `UPDATE roles SET rank = 0 WHERE key = 'tenant_admin'`)
	err = Seed(ctx, mig)
	if err == nil || !strings.Contains(err.Error(), "role hệ thống") {
		t.Fatalf("seed with an unknown system role: %v, want the seed's exception", err)
	}
	if err := su.QueryRow(ctx, `SELECT rank FROM roles WHERE key = 'tenant_admin'`).Scan(&adminRank); err != nil || adminRank != 0 {
		t.Errorf("a failed seed must roll back entirely: tenant_admin rank %d (err %v), want the drifted 0", adminRank, err)
	}
	exec(t, su, `DELETE FROM roles WHERE key = 'retired_role'`)
	if err := Seed(ctx, mig); err != nil {
		t.Fatalf("seed after removing the unknown role: %v", err)
	}
}
