// Package storetest is the PostgreSQL integration-test harness of the packages built on internal/store (internal/jobs
// first): a real PostgreSQL of the pinned version (versions.lock [images.postgres]), one throwaway database per call,
// bootstrapped and migrated like a deployment (store.Bootstrap, then store.MigrateAll as mg_migrator — goose and
// River's schema), with role passwords set as SCRAM verifiers and handed to the code under test as password files.
// Only test code imports it.
//
//	MG_TEST_PG_ADMIN_URL  superuser URL of a THROWAWAY cluster, e.g. postgres://postgres:<pw>@pg:5432/postgres?sslmode=disable
//	MG_TEST_PG_REQUIRED=1 a missing URL fails the tests (CI) instead of skipping them
//
// Role passwords are derived (pgcluster.RolePassword) and database creation holds the cluster-wide advisory lock
// (pgcluster.Lock) exactly like every other harness of the repository: roles are cluster-wide and `go test ./...` runs
// packages in parallel against the same cluster.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest/pgcluster"
)

// loginRoles are the login roles whose passwords the harness sets after migration (bootstrap roles excluded).
var loginRoles = []string{
	"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_readonly", "mg_audit_writer",
	"mg_partition_maint",
}

// Env is the test environment of one process.
type Env struct {
	admin   *url.URL
	secret  string
	mu      sync.Mutex
	created []string
	pwSet   bool
}

var (
	once   sync.Once
	env    *Env
	envErr error
)

// Require returns the environment, or skips the test when MG_TEST_PG_ADMIN_URL is not set (fails instead when
// MG_TEST_PG_REQUIRED=1).
func Require(t testing.TB) *Env {
	t.Helper()
	raw := os.Getenv("MG_TEST_PG_ADMIN_URL")
	if raw == "" {
		if os.Getenv("MG_TEST_PG_REQUIRED") == "1" {
			t.Fatal("MG_TEST_PG_ADMIN_URL is not set but MG_TEST_PG_REQUIRED=1")
		}
		t.Skip("MG_TEST_PG_ADMIN_URL not set — PostgreSQL integration tests skipped")
	}
	once.Do(func() {
		u, err := url.Parse(raw)
		if err != nil {
			envErr = err
			return
		}
		pw, _ := u.User.Password()
		env = &Env{admin: u, secret: pw}
	})
	if envErr != nil {
		t.Fatalf("test environment: %v", envErr)
	}
	return env
}

// Cleanup drops every database this process created; call it from TestMain after m.Run. It is bounded
// (pgcluster.DropDatabases: a few at a time, within a budget that ends before -test.timeout): a database it could not
// drop in time stays on the throwaway cluster and is named on stderr — the package's result is its tests'.
func Cleanup() {
	if env == nil {
		return
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	pgcluster.DropDatabases("storetest", env.adminURL("postgres"), env.created)
	env.created = nil
}

// DropDatabase drops a database the test created itself (a restore target…), bounded like Cleanup — for t.Cleanup.
func (e *Env) DropDatabase(name string) {
	pgcluster.DropDatabases("storetest", e.adminURL("postgres"), []string{name})
}

func (e *Env) adminURL(db string) string {
	u := *e.admin
	u.Path = "/" + db
	return u.String()
}

// URL returns the URL handed to the code under test: host, port, database and options, no credentials.
func (e *Env) URL(db string) string {
	u := *e.admin
	u.User = nil
	u.Path = "/" + db
	return u.String()
}

// Password returns the derived test password of role (pgcluster.RolePassword, shared by every harness).
func (e *Env) Password(role string) string { return pgcluster.RolePassword(e.secret, role) }

// Creds writes the password of role to a 0600 file (with a trailing newline, like a file secret) and returns the
// credentials naming it.
func (e *Env) Creds(t testing.TB, role string) store.Credentials {
	t.Helper()
	p := filepath.Join(t.TempDir(), role)
	if err := os.WriteFile(p, []byte(e.Password(role)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return store.Credentials{User: role, PasswordFile: p}
}

// Admin opens a superuser connection to db, closed when the test ends.
func (e *Env) Admin(t testing.TB, db string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(t.Context(), e.adminURL(db))
	if err != nil {
		t.Fatalf("connect superuser to %s: %v", db, err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// Exec runs sql as the superuser on db (fixtures bypass RLS).
func (e *Env) Exec(t testing.TB, db, sql string, args ...any) {
	t.Helper()
	c := e.Admin(t, db)
	if _, err := c.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

// NewDatabase creates a database, bootstraps it, migrates it to the latest version with store.MigrateAll (goose, then
// River's schema and privileges) and sets the role passwords; it returns the database name.
func (e *Env) NewDatabase(t testing.TB) string {
	t.Helper()
	ctx := t.Context()
	e.mu.Lock()
	defer e.mu.Unlock()
	release, err := pgcluster.Lock(ctx, e.adminURL("postgres"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	admin, err := pgx.Connect(ctx, e.adminURL("postgres"))
	if err != nil {
		t.Fatalf("connect superuser: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "mgj_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}
	e.created = append(e.created, name)

	su, err := pgx.Connect(ctx, e.adminURL(name))
	if err != nil {
		t.Fatalf("connect superuser to %s: %v", name, err)
	}
	defer func() { _ = su.Close(context.Background()) }()
	if err := store.Bootstrap(ctx, su); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"mg_migrator", "mg_backup"} {
		if err := store.SetRolePassword(ctx, su, r, e.Password(r)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MigrateAll(ctx, e.URL(name), e.Creds(t, "mg_migrator")); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !e.pwSet {
		cfg, err := pgx.ParseConfig(e.URL(name))
		if err != nil {
			t.Fatal(err)
		}
		cfg.User, cfg.Password = "mg_migrator", e.Password("mg_migrator")
		mig, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("connect as mg_migrator: %v", err)
		}
		defer func() { _ = mig.Close(context.Background()) }()
		for _, r := range loginRoles {
			if err := store.SetRolePassword(ctx, mig, r, e.Password(r)); err != nil {
				t.Fatal(err)
			}
		}
		e.pwSet = true
	}
	return name
}

// OpenStore opens a store.Store on db with the given tenant and platform login roles, closed when the test ends.
func (e *Env) OpenStore(t testing.TB, db, tenantRole, platformRole string, maxConns int32) *store.Store {
	t.Helper()
	s, err := store.Open(t.Context(), store.Config{
		URL:      e.URL(db),
		Tenant:   e.Creds(t, tenantRole),
		Platform: e.Creds(t, platformRole),
		MaxConns: maxConns,
	})
	if err != nil {
		t.Fatalf("open store (%s, %s): %v", tenantRole, platformRole, err)
	}
	t.Cleanup(s.Close)
	return s
}

// OpenAuditWriter opens the detached audit pool (mg_audit_writer, §6.1) on db, closed when the test ends.
func (e *Env) OpenAuditWriter(t testing.TB, db string) *store.AuditWriter {
	t.Helper()
	w, err := store.OpenAuditWriter(t.Context(), e.URL(db), e.Creds(t, store.AuditWriterRole))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}

// OpenPartitionMaintainer opens the partition.maintain pool (mg_partition_maint) on db, closed when the test ends.
func (e *Env) OpenPartitionMaintainer(t testing.TB, db string) *store.PartitionMaintainer {
	t.Helper()
	m, err := store.OpenPartitionMaintainer(t.Context(), e.URL(db), e.Creds(t, "mg_partition_maint"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}
