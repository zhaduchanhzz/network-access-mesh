package store

import (
	"os"
	"slices"
	"testing"
)

// TestBackupDrillSource prepares the source database of the backup restore drill (tests/backup/drill.sh, P2-T03a)
// and KEEPS it: a database bootstrapped and migrated like a deployment (goose + seeds + River), three fixtures (rows
// of every table of 0001–0006, both tenants and the platform), audit events in four partitions (this month, the next
// two and DEFAULT), River jobs and live sessions; mg_backup gets the password of the drill's secret file. The drill
// renames the database to `meshguard` and backs it up with the real pg-backup container.
//
//	MG_BACKUP_DRILL_OUT                  file that receives the database name (unset ⇒ the test is skipped, as in CI)
//	MG_BACKUP_DRILL_BACKUP_PASSWORD_FILE password file of mg_backup (the drill's pg_backup_password secret)
func TestBackupDrillSource(t *testing.T) {
	out, pwFile := os.Getenv("MG_BACKUP_DRILL_OUT"), os.Getenv("MG_BACKUP_DRILL_BACKUP_PASSWORD_FILE")
	if out == "" {
		t.Skip("MG_BACKUP_DRILL_OUT not set — only tests/backup/drill.sh runs this")
	}
	pw, err := ReadPasswordFile(pwFile)
	if err != nil {
		t.Fatal(err)
	}
	e := requireDB(t)
	db := e.newDatabase(t, 0)
	e.mu.Lock()
	e.created = slices.DeleteFunc(e.created, func(n string) bool { return n == db }) // keep it for the drill
	e.mu.Unlock()
	su := e.connectAdmin(t, db)
	for range 3 {
		newFixture().insertAll(t, su)
	}
	for _, at := range []string{"now()", "now() + interval '1 month'", "now() + interval '2 months'", "now() + interval '30 years'"} {
		exec(t, su, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome, occurred_at)
			SELECT NULL, 'system', 'drill.event', 'drill', 'success', `+at+` FROM generate_series(1, 4)`)
	}
	exec(t, su, `INSERT INTO river.river_job (args, kind, max_attempts) SELECT '{}', 'drill.job', 1 FROM generate_series(1, 5)`)
	var defaultRows, live int64
	if err := su.QueryRow(ctxT(t), `SELECT (SELECT count(*) FROM partitions.audit_events_default),
			(SELECT count(*) FROM sessions WHERE revoked_at IS NULL)`).Scan(&defaultRows, &live); err != nil {
		t.Fatal(err)
	}
	if defaultRows < 4 || live < 3 {
		t.Fatalf("drill data: %d rows in the DEFAULT partition, %d live sessions", defaultRows, live)
	}
	func() {
		defer e.lockCluster(t)()
		if err := SetRolePassword(ctxT(t), su, "mg_backup", pw); err != nil {
			t.Fatal(err)
		}
	}()
	if err := os.WriteFile(out, []byte(db+"\n"), 0o600); err != nil { //nolint:gosec // G703: path given by the drill
		t.Fatal(err)
	}
	t.Logf("drill source database %s: %d rows in audit_events_default, %d live sessions", db, defaultRows, live)
}
