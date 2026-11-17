package store

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestMigrationsUpWithData: every migration applies on a database that already holds data written after the previous
// ones (§6.1 "test up trên bản sao dữ liệu"), existing rows survive, a second run is a no-op, and the application reads
// the old rows through RLS afterwards.
func TestMigrationsUpWithData(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, -1) // bootstrapped, not migrated
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()

	f := newFixture()
	// The migrations create cluster-wide roles and the role passwords are set below: hold the same locks as
	// newDatabase (e.mu, then the cluster lock) until the passwords are set; released by defer even on t.Fatal.
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.lockCluster(t)()
	for v := int64(1); v <= latestMigration; v++ {
		if err := MigrateTo(ctx, mig, v); err != nil {
			t.Fatalf("migration %04d on a database with data: %v", v, err)
		}
		if got, err := SchemaVersion(ctx, mig); err != nil || got != v {
			t.Fatalf("schema version = %d (err %v), want %d", got, err, v)
		}
		fixtureSteps[v](f, t, su) // rows for the tables this migration created
	}
	counts := func() map[string]int64 {
		out := map[string]int64{}
		for _, r := range rlsTables {
			var n int64
			if err := su.QueryRow(ctx, "SELECT count(*) FROM "+q(r.name)).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[r.name] = n
		}
		return out
	}
	before := counts()
	for name, n := range before {
		if n == 0 {
			t.Errorf("%s: no fixture rows — the test would not prove anything for this table", name)
		}
	}
	if err := Migrate(ctx, mig); err != nil { // nothing pending
		t.Fatalf("second run: %v", err)
	}
	after := counts()
	for name, n := range before {
		if after[name] != n {
			t.Errorf("%s: %d rows before, %d after a no-op migrate", name, n, after[name])
		}
	}

	e.setAppPasswordsLocked(t, db) // e.mu and the cluster lock are held (above)
	s := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	if err := s.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
		devs, err := q.ListLiveDevices(ctx, f.a.id)
		if err != nil {
			return err
		}
		if len(devs) != 1 || devs[0].RevocationJobID == nil || *devs[0].RevocationJobID != f.a.job {
			t.Errorf("devices of A after migration = %+v, want the fixture device linked to its job", devs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestMigration0007ClientSecretRefOwner — G2 F3, migration 0007 (expand-only: one CHECK, no row rewritten, no query of
// the application changed): the owner segment of identity_providers.client_secret_ref must be the IdP's tenant, or
// "platform" when tenant_id IS NULL. Up on a database with data keeps the existing references (own owner, NULL). A
// database holding a foreign reference refuses 0007 as a whole — the migrations are forward-only (no Down section) and
// each runs in one transaction, so the schema stays at 0006 — and migrates once the row is repaired. Afterwards every
// write of a foreign owner is refused, by the application role and by the superuser alike; the name inside the owner's
// namespace is checked by the code (callback, IdP drivers), not here.
func TestMigration0007ClientSecretRefOwner(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 6)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	f := newFixture()
	for v := int64(1); v <= 6; v++ {
		fixtureSteps[v](f, t, su)
	}
	ref := func(owner, name string) string { return "mgsec://" + owner + "/" + name + "#1" }
	own := ref(f.a.id.String(), "idp."+f.a.idp.String()+".client")
	platformOwn := ref("platform", "idp-client-secret."+f.platformIdP.String())
	exec(t, su, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, own, f.a.idp)
	exec(t, su, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, platformOwn, f.platformIdP)
	exec(t, su, `UPDATE identity_providers SET client_secret_ref = NULL WHERE id = $1`, f.b.idp) // public client

	// 0006 checks the format only: tenant B's Headscale key is accepted as the client secret of A's IdP.
	foreign := ref(f.b.id.String(), "headscale-api-key")
	exec(t, su, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, foreign, f.a.idp)
	err = MigrateTo(ctx, mig, 7)
	if err == nil || (SQLState(err) != "23514" && !strings.Contains(err.Error(), "23514")) {
		t.Fatalf("0007 over a foreign reference: %v, want check_violation (23514)", err)
	}
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 6 {
		t.Fatalf("schema version after the refused 0007 = %d (%v), want 6", v, err)
	}
	exec(t, su, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, own, f.a.idp)
	if err := MigrateTo(ctx, mig, 7); err != nil {
		t.Fatalf("0007 on repaired data: %v", err)
	}
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 7 {
		t.Fatalf("schema version = %d (%v), want 7", v, err)
	}
	for id, want := range map[uuid.UUID]*string{f.a.idp: &own, f.platformIdP: &platformOwn, f.b.idp: nil} {
		var got *string
		if err := su.QueryRow(ctx, `SELECT client_secret_ref FROM identity_providers WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("IdP %s: reference %v after 0007, want %v", id, got, want)
		}
	}

	for name, c := range map[string]struct {
		idp uuid.UUID
		ref string
	}{
		"tenant IdP, another tenant's secret": {f.a.idp, foreign},
		"tenant IdP, a platform secret":       {f.a.idp, ref("platform", "idp."+f.a.idp.String()+".client")},
		"platform IdP, a tenant secret":       {f.platformIdP, ref(f.a.id.String(), "idp."+f.platformIdP.String()+".client")},
	} {
		_, err := su.Exec(ctx, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, c.ref, c.idp)
		wantSQLState(t, name+" (superuser)", err, "23514")
	}
	_, err = su.Exec(ctx, `INSERT INTO identity_providers (scope, tenant_id, issuer, client_id, client_secret_ref, driver)
		VALUES ('tenant', $1, 'https://idp.test/new-'||$2, 'portal', $3, 'external')`, f.b.id, f.sfx, foreign[:len(foreign)-2]+"#2")
	if err != nil {
		t.Errorf("insert with a reference of its own tenant: %v", err)
	}
	_, err = su.Exec(ctx, `INSERT INTO identity_providers (scope, tenant_id, issuer, client_id, client_secret_ref, driver)
		VALUES ('tenant', $1, 'https://idp.test/other-'||$2, 'portal', $3, 'external')`, f.a.id, f.sfx, foreign)
	wantSQLState(t, "insert with another tenant's reference", err, "23514")

	// The application role (the only one granted UPDATE of the column) is refused the same way.
	app := e.connectAs(t, db, "mg_api_platform") // passwords set by newDatabase
	if _, err := app.Exec(ctx, `SELECT set_config('app.scope', 'platform', false)`); err != nil {
		t.Fatal(err)
	}
	_, err = app.Exec(ctx, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, foreign, f.a.idp)
	wantSQLState(t, "mg_api_platform, another tenant's secret", err, "23514")
	tag, err := app.Exec(ctx, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, own[:len(own)-2]+"#2", f.a.idp)
	if err != nil || tag.RowsAffected() != 1 {
		t.Errorf("mg_api_platform, a new version of the IdP's own secret: %v (%d rows)", err, tag.RowsAffected())
	}
}

// TestMigrationsShareClusterRoles: a second database in the same cluster migrates while the cluster-wide roles
// already exist (idempotent role creation), and ends at the same version.
func TestMigrationsShareClusterRoles(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	first := e.sharedDB(t)
	second := e.newDatabase(t, 0)
	for _, db := range []string{first, second} {
		mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
		if err != nil {
			t.Fatal(err)
		}
		v, err := SchemaVersion(ctx, mig)
		_ = mig.Close()
		if err != nil || v != latestMigration {
			t.Errorf("%s: schema version %d (err %v), want %d", db, v, err, latestMigration)
		}
	}
}
