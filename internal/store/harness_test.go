package store

// Integration test harness: a real PostgreSQL of the pinned version (versions.lock [images.postgres]) — the CI
// service container of .github/workflows/go.yml or a `docker run` on the build VM.
//
//	MG_TEST_PG_ADMIN_URL  superuser URL of a THROWAWAY cluster, e.g. postgres://postgres:<pw>@pg:5432/postgres?sslmode=disable
//	MG_TEST_PG_REQUIRED=1 a missing URL fails the tests (CI) instead of skipping them
//
// Each test database is created by the superuser, bootstrapped (database/bootstrap/superuser.sql) and migrated as
// mg_migrator exactly like a deployment. Role passwords are derived from the superuser password (roles are
// cluster-wide), set as SCRAM verifiers with SetRolePassword and handed to the code under test as password files.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// loginRoles are every login role created by bootstrap and migrations (§6.1).
var loginRoles = []string{
	"mg_migrator", "mg_backup", "mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform",
	"mg_readonly", "mg_audit_writer", "mg_partition_maint",
}

// appRoles are the roles used by application processes and reporting — none may touch a partition.
var appRoles = []string{
	"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_audit_writer", "mg_readonly",
}

type pgEnv struct {
	admin    *url.URL // superuser URL (database part replaced per test)
	secret   string   // seed for the derived role passwords
	mu       sync.Mutex
	created  []string
	shared   string
	pwSet    bool
	pwDir    string
	setupErr error
}

var (
	envOnce sync.Once
	env     *pgEnv
)

func TestMain(m *testing.M) {
	code := m.Run()
	if env != nil {
		env.dropAll()
		if env.pwDir != "" {
			_ = os.RemoveAll(env.pwDir)
		}
	}
	os.Exit(code)
}

// requireDB returns the environment or skips (fails when MG_TEST_PG_REQUIRED=1).
func requireDB(t *testing.T) *pgEnv {
	t.Helper()
	raw := os.Getenv("MG_TEST_PG_ADMIN_URL")
	if raw == "" {
		if os.Getenv("MG_TEST_PG_REQUIRED") == "1" {
			t.Fatal("MG_TEST_PG_ADMIN_URL is not set but MG_TEST_PG_REQUIRED=1")
		}
		t.Skip("MG_TEST_PG_ADMIN_URL not set — PostgreSQL integration tests skipped")
	}
	envOnce.Do(func() {
		u, err := url.Parse(raw)
		if err != nil {
			env = &pgEnv{setupErr: err}
			return
		}
		pw, _ := u.User.Password()
		dir, err := os.MkdirTemp("", "mgtest-pw-")
		env = &pgEnv{admin: u, secret: pw, pwDir: dir, setupErr: err}
	})
	if env.setupErr != nil {
		t.Fatalf("test environment: %v", env.setupErr)
	}
	return env
}

func ctxT(t *testing.T) context.Context { return t.Context() }

// adminURL returns the superuser URL for database db.
func (e *pgEnv) adminURL(db string) string {
	u := *e.admin
	u.Path = "/" + db
	return u.String()
}

// storeURL returns the URL handed to the code under test: host, port, database and options, no credentials.
func (e *pgEnv) storeURL(db string) string {
	u := *e.admin
	u.User = nil
	u.Path = "/" + db
	return u.String()
}

func (e *pgEnv) password(role string) string {
	sum := sha256.Sum256([]byte("meshguard-test|" + e.secret + "|" + role))
	return hex.EncodeToString(sum[:])
}

// passwordFile writes the derived password of role to a 0600 file (with a trailing newline, like a file secret).
func (e *pgEnv) passwordFile(t *testing.T, role string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), role)
	if err := os.WriteFile(p, []byte(e.password(role)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *pgEnv) creds(t *testing.T, role string) Credentials {
	return Credentials{User: role, PasswordFile: e.passwordFile(t, role)}
}

// connectAdmin opens a superuser connection to db.
func (e *pgEnv) connectAdmin(t *testing.T, db string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(ctxT(t), e.adminURL(db))
	if err != nil {
		t.Fatalf("connect superuser to %s: %v", db, err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// connectAs opens a connection to db logged in as role with its derived password.
func (e *pgEnv) connectAs(t *testing.T, db, role string) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(e.storeURL(db))
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = role, e.password(role)
	c, err := pgx.ConnectConfig(ctxT(t), cfg)
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ClusterSetupLockKey is the advisory lock (taken in the "postgres" database) that serialises cluster-wide test setup
// — bootstrap, migrations creating roles, role passwords — across every test package sharing the PostgreSQL cluster
// (internal/store, internal/identity): roles belong to the cluster, two packages run in parallel under go test, and
// two concurrent ALTER ROLE of one role fail with "tuple concurrently updated".
const ClusterSetupLockKey int64 = 0x6d67746573740001

// clusterLock takes ClusterSetupLockKey on a dedicated superuser connection and returns its release. Lock order
// inside this package: e.mu first, then the cluster lock.
func (e *pgEnv) clusterLock(t *testing.T) func() {
	t.Helper()
	c := e.connectAdmin(t, "postgres")
	if _, err := c.Exec(ctxT(t), "SELECT pg_advisory_lock($1)", ClusterSetupLockKey); err != nil {
		t.Fatalf("cluster setup lock: %v", err)
	}
	return func() { _, _ = c.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", ClusterSetupLockKey) }
}

// newDatabase creates a bootstrapped database migrated to version (0 = latest, < 0 = bootstrap only) and returns
// its name. Database creation is serialised: roles are cluster-wide, and two migrations creating the same role at
// once would race (within this package by e.mu, across packages by ClusterSetupLockKey).
func (e *pgEnv) newDatabase(t *testing.T, version int64) string {
	t.Helper()
	ctx := ctxT(t)
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.clusterLock(t)()
	name := "mgt_" + randomHex(6)
	admin := e.connectAdmin(t, "postgres")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}
	e.created = append(e.created, name)

	su := e.connectAdmin(t, name)
	if err := Bootstrap(ctx, su); err != nil {
		t.Fatal(err)
	}
	if err := Bootstrap(ctx, su); err != nil { // idempotent
		t.Fatalf("second bootstrap: %v", err)
	}
	for _, r := range []string{"mg_migrator", "mg_backup"} { // created by the superuser bootstrap
		if err := SetRolePassword(ctx, su, r, e.password(r)); err != nil {
			t.Fatal(err)
		}
	}
	if version < 0 {
		return name
	}
	db, err := OpenMigrator(e.storeURL(name), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if version == 0 {
		err = Migrate(ctx, db)
	} else {
		err = MigrateTo(ctx, db, version)
	}
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	e.setAppPasswordsLocked(t, name)
	return name
}

// setAppPasswordsLocked sets the passwords of the roles created by the migrations, as mg_migrator (CREATEROLE with
// ADMIN on the roles it created) — the deployment path documented in database/README.md.
func (e *pgEnv) setAppPasswordsLocked(t *testing.T, db string) {
	t.Helper()
	if e.pwSet {
		return
	}
	ctx := ctxT(t)
	mig := e.connectAs(t, db, "mg_migrator")
	all := true
	for _, r := range loginRoles {
		if r == "mg_migrator" || r == "mg_backup" {
			continue
		}
		var exists bool
		if err := mig.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", r).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			all = false
			continue
		}
		if err := SetRolePassword(ctx, mig, r, e.password(r)); err != nil {
			t.Fatal(err)
		}
	}
	e.pwSet = all
}

// sharedDB returns a fully migrated database shared by the tests that create their own fixtures.
func (e *pgEnv) sharedDB(t *testing.T) string {
	t.Helper()
	e.mu.Lock()
	name := e.shared
	e.mu.Unlock()
	if name != "" {
		return name
	}
	name = e.newDatabase(t, 0)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shared == "" {
		e.shared = name
	}
	return e.shared
}

func (e *pgEnv) dropAll() {
	ctx := context.Background()
	c, err := pgx.Connect(ctx, e.adminURL("postgres"))
	if err != nil {
		return
	}
	defer func() { _ = c.Close(ctx) }()
	for _, n := range e.created {
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{n}.Sanitize()+" WITH (FORCE)")
	}
}

// openStore opens a Store on db with the given tenant and platform login roles.
func (e *pgEnv) openStore(t *testing.T, db, tenantRole, platformRole string, maxConns int32) *Store {
	t.Helper()
	s, err := Open(ctxT(t), Config{
		URL:      e.storeURL(db),
		Tenant:   e.creds(t, tenantRole),
		Platform: e.creds(t, platformRole),
		MaxConns: maxConns,
	})
	if err != nil {
		t.Fatalf("open store (%s, %s): %v", tenantRole, platformRole, err)
	}
	t.Cleanup(s.Close)
	return s
}

// wantSQLState asserts that err carries the given SQLSTATE.
func wantSQLState(t *testing.T, what string, err error, code string) {
	t.Helper()
	if got := SQLState(err); got != code {
		t.Errorf("%s: SQLSTATE = %q (err = %v), want %s", what, got, err, code)
	}
}

// anyContains reports whether some element of list contains s.
func anyContains(list []string, s string) bool {
	for _, x := range list {
		if strings.Contains(x, s) {
			return true
		}
	}
	return false
}
