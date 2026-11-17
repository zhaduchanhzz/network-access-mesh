package store

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestDeploySteps — the steps the `migrate` job runs (P2-T16), on an empty database like a first deployment:
// BootstrapDatabase as the superuser (twice: idempotent), the state before migrating (not current), MigrateAll,
// SetLoginPasswords as mg_migrator (every login role from its file; a missing file refused before anything is set),
// then the state is current and each application role logs in with the password set from its file. Role passwords
// follow the cluster rules of the test harnesses (pgcluster.RolePassword under the cluster lock).
func TestDeploySteps(t *testing.T) {
	e := requireDB(t)
	if len(e.secret) < 16 {
		t.Skip("the superuser password of the test cluster is shorter than a file secret (16 characters)")
	}
	ctx := ctxT(t)
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.lockCluster(t)()
	name := "mgt_" + randomHex(6)
	if _, err := e.connectAdmin(t, "postgres").Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	e.created = append(e.created, name)
	url := e.storeURL(name)
	su := filepath.Join(t.TempDir(), "superuser")
	if err := os.WriteFile(su, []byte(e.secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	superuser := Credentials{User: "postgres", PasswordFile: su}
	for range 2 {
		if err := BootstrapDatabase(ctx, url, superuser, e.passwordFile(t, MigratorRole), e.passwordFile(t, BackupRole)); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
	}
	migrator := e.creds(t, MigratorRole)
	st, err := ReadDeployState(ctx, url, migrator)
	if err != nil || st.Current() || st.SchemaVersion != 0 || st.LatestMigration < 6 {
		t.Fatalf("state before migrating: %+v, %v", st, err)
	}
	if err := MigrateAll(ctx, url, migrator); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, r := range LoginRoles {
		files[r] = e.passwordFile(t, r)
	}
	partial := map[string]string{}
	for k, v := range files {
		partial[k] = v
	}
	delete(partial, AuditWriterRole)
	if done, err := SetLoginPasswords(ctx, url, migrator, partial); err == nil || len(done) != 0 ||
		!strings.Contains(err.Error(), AuditWriterRole) {
		t.Fatalf("missing file: done %v, %v", done, err)
	}
	done, err := SetLoginPasswords(ctx, url, migrator, files)
	if err != nil || !slices.Equal(done, LoginRoles) {
		t.Fatalf("login passwords: %v, %v", done, err)
	}
	e.pwSet = true
	st, err = ReadDeployState(ctx, url, migrator)
	if err != nil || !st.Current() || st.SchemaVersion != st.LatestMigration || st.RiverMigrations == 0 ||
		st.SystemRoles == 0 || len(st.PartitionIssues) != 0 {
		t.Fatalf("state after migrating: %+v, %v", st, err)
	}
	for _, pair := range [][2]string{{"mg_api_tenant", "mg_api_platform"}, {"mg_worker_tenant", "mg_worker_platform"}} {
		s, err := Open(ctx, Config{URL: url, Tenant: e.creds(t, pair[0]), Platform: e.creds(t, pair[1]), MaxConns: 2})
		if err != nil {
			t.Fatalf("open %v: %v", pair, err)
		}
		err = s.Ping(ctx)
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	w, err := OpenAuditWriter(ctx, url, e.creds(t, AuditWriterRole))
	if err != nil {
		t.Fatalf("audit writer: %v", err)
	}
	w.Close()
	// a wrong superuser password file is refused without echoing it
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("wrong-password-CANARY-1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = BootstrapDatabase(ctx, url, Credentials{User: "postgres", PasswordFile: bad}, files[AuditWriterRole], files[AuditWriterRole])
	if err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("wrong superuser password: %v", err)
	}
}
