package store

// Migration 0024 (P4-T09): tenant_memberships.status pinned to {active, locked, offboarded} and the index of
// provisioning_jobs by resource. Run on a database at schema 23 holding rows of every table (the state after P4-T05):
// a membership with another status makes 0024 fail as a whole (schema stays at 23); repaired, 0024 applies, every row
// survives, and the CHECK refuses any other value afterwards — through the api's own role as well.

import (
	"strings"
	"testing"
)

func TestMigration0024MembershipStatus(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 23)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	f := newFixture()
	for v := int64(1); v <= 23; v++ {
		fixtureSteps[v](f, t, su)
	}
	exec(t, su, `UPDATE tenant_memberships SET status = 'disabled' WHERE id = $1`, f.b.membership)
	err = MigrateTo(ctx, mig, 24)
	if err == nil || !strings.Contains(err.Error(), "tenant_memberships_status_check") {
		t.Fatalf("0024 over a membership 'disabled': err = %v, want the CHECK violation", err)
	}
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 23 {
		t.Fatalf("schema version after the refused 0024 = %d (%v), want 23", v, err)
	}
	exec(t, su, `UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, f.b.membership)
	before := publicRowCounts(t, su)
	if err := MigrateTo(ctx, mig, 24); err != nil {
		t.Fatalf("0024 on schema 23 with data: %v", err)
	}
	after := publicRowCounts(t, su)
	for n, c := range before {
		if n != "goose_db_version" && after[n] != c {
			t.Errorf("%s: %d rows at schema 23, %d at schema 24", n, c, after[n])
		}
	}
	var idx int
	if err := su.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'provisioning_jobs_resource_idx'`).Scan(&idx); err != nil || idx != 1 {
		t.Errorf("provisioning_jobs_resource_idx: %d (%v)", idx, err)
	}
	fixtureSteps[24](f, t, su) // locked + offboarded members

	for _, st := range []string{"active", "locked", "offboarded"} {
		if _, err := su.Exec(ctx, `UPDATE tenant_memberships SET status = $1 WHERE id = $2`, st, f.a.membership); err != nil {
			t.Errorf("status %s refused: %v", st, err)
		}
	}
	for _, st := range []string{"disabled", "suspended", "Active", ""} {
		_, err := su.Exec(ctx, `UPDATE tenant_memberships SET status = $1 WHERE id = $2`, st, f.a.membership)
		wantSQLState(t, "membership status "+st, err, "23514")
	}
}
