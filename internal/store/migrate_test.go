package store

import (
	"testing"

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
	unlock := e.clusterLock(t)
	defer unlock()
	for v := int64(1); v <= 6; v++ {
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
		if err != nil || v != 6 {
			t.Errorf("%s: schema version %d (err %v), want 6", db, v, err)
		}
	}
}
