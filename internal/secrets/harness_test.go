package secrets

// Integration harness: a real PostgreSQL of the pinned version (versions.lock [images.postgres]), exactly like
// internal/store (P2-T03):
//
//	MG_TEST_PG_ADMIN_URL  superuser URL of a THROWAWAY cluster, e.g. postgres://postgres:<pw>@pg:5432/postgres?sslmode=disable
//	MG_TEST_PG_REQUIRED=1 a missing URL fails the tests (CI) instead of skipping them
//
// Every test gets its own database, bootstrapped and migrated as mg_migrator through internal/store like a deployment
// (the platform DEKs and the keyrings are per database, so tests cannot disturb each other). Only this harness and
// the tampering steps of the tests use a raw driver connection; the code under test reaches PostgreSQL through
// store.WithTenantTx / store.WithPlatformTx alone.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest/pgcluster"
)

// appRoles are the login roles of the application processes (migration 0001).
var appRoles = []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform"}

type pgEnv struct {
	admin  *url.URL
	secret string
	mu     sync.Mutex
	dbs    []string
	err    error
}

var (
	envOnce sync.Once
	env     *pgEnv
)

func TestMain(m *testing.M) {
	code := m.Run()
	if env != nil {
		env.dropAll()
	}
	os.Exit(code)
}

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
		env = &pgEnv{admin: u, err: err}
		if err == nil {
			env.secret, _ = u.User.Password()
		}
	})
	if env.err != nil {
		t.Fatalf("test environment: %v", env.err)
	}
	return env
}

func (e *pgEnv) adminURL(db string) string {
	u := *e.admin
	u.Path = "/" + db
	return u.String()
}

func (e *pgEnv) storeURL(db string) string {
	u := *e.admin
	u.User = nil
	u.Path = "/" + db
	return u.String()
}

// password derives a role password like every harness of the repository (pgcluster.RolePassword — roles are
// cluster-wide: all packages set the same value).
func (e *pgEnv) password(role string) string { return pgcluster.RolePassword(e.secret, role) }

func (e *pgEnv) creds(t *testing.T, role string) store.Credentials {
	t.Helper()
	p := filepath.Join(t.TempDir(), role)
	if err := os.WriteFile(p, []byte(e.password(role)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return store.Credentials{User: role, PasswordFile: p}
}

func (e *pgEnv) connectAdmin(t *testing.T, db string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(t.Context(), e.adminURL(db))
	if err != nil {
		t.Fatalf("connect superuser to %s: %v", db, err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// connectAs opens a raw connection as role (used to check what the role itself sees, whatever it sets in app.*).
func (e *pgEnv) connectAs(t *testing.T, db, role string) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(e.storeURL(db))
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = role, e.password(role)
	c, err := pgx.ConnectConfig(t.Context(), cfg)
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

// newDB creates a database, bootstraps and migrates it like a deployment, and sets the role passwords — under the
// cluster-wide lock shared by every test harness (pgcluster.Lock).
func (e *pgEnv) newDB(t *testing.T) string {
	t.Helper()
	ctx := t.Context()
	e.mu.Lock()
	defer e.mu.Unlock()
	release, err := pgcluster.Lock(ctx, e.adminURL("postgres"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	admin := e.connectAdmin(t, "postgres")

	name := "mgsec_" + randomHex(6)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}
	e.dbs = append(e.dbs, name)
	su := e.connectAdmin(t, name)
	if err := store.Bootstrap(ctx, su); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"mg_migrator", "mg_backup"} {
		if err := store.SetRolePassword(ctx, su, r, e.password(r)); err != nil {
			t.Fatal(err)
		}
	}
	mig, err := store.OpenMigrator(e.storeURL(name), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	if err := store.Migrate(ctx, mig); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mc := e.connectAs(t, name, "mg_migrator")
	for _, r := range appRoles {
		if err := store.SetRolePassword(ctx, mc, r, e.password(r)); err != nil {
			t.Fatal(err)
		}
	}
	return name
}

func (e *pgEnv) dropAll() {
	ctx := context.Background()
	c, err := pgx.Connect(ctx, e.adminURL("postgres"))
	if err != nil {
		return
	}
	defer func() { _ = c.Close(ctx) }()
	for _, n := range e.dbs {
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{n}.Sanitize()+" WITH (FORCE)")
	}
}

// syncBuffer collects log output from concurrent goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fixture is one migrated database with two tenants, the two keyrings and a SecretStore per process role set:
// worker (mg_worker_tenant + mg_worker_platform, kek-app + kek-ops) and api (mg_api_tenant + mg_api_platform,
// kek-app only — §7.6).
type fixture struct {
	e        *pgEnv
	db       string
	app, ops *testKeyring
	log      *syncBuffer
	logger   *slog.Logger
	workerDB *store.Store
	worker   *Store
	api      *Store
	su       *pgx.Conn
	a, b     uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	e := requireDB(t)
	f := &fixture{e: e, db: e.newDB(t), log: &syncBuffer{}}
	f.logger = logx.New(f.log, slog.LevelDebug, "test")
	f.app = newTestKeyring(t, KEKApp, "app-2026-11")
	f.ops = newTestKeyring(t, KEKOps, "ops-2026-11")
	f.workerDB = f.openDB(t, "mg_worker_tenant", "mg_worker_platform")
	f.worker = f.newStore(t, f.workerDB, Options{App: f.app.kr, Ops: f.ops.kr})
	f.api = f.newStore(t, f.openDB(t, "mg_api_tenant", "mg_api_platform"), Options{App: f.app.kr})
	f.su = e.connectAdmin(t, f.db)
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	return f
}

func (f *fixture) openDB(t *testing.T, tenantRole, platformRole string) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), store.Config{
		URL: f.e.storeURL(f.db), Tenant: f.e.creds(t, tenantRole), Platform: f.e.creds(t, platformRole), MaxConns: 8,
	})
	if err != nil {
		t.Fatalf("open store (%s, %s): %v", tenantRole, platformRole, err)
	}
	t.Cleanup(st.Close)
	return st
}

// newStore builds a SecretStore that logs into the fixture's buffer (unless o.Logger is set).
func (f *fixture) newStore(t *testing.T, db *store.Store, o Options) *Store {
	t.Helper()
	if o.Logger == nil {
		o.Logger = f.logger
	}
	s, err := New(db, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// storeWith opens a SecretStore on fresh pools of the given roles.
func (f *fixture) storeWith(t *testing.T, tenantRole, platformRole string, o Options) *Store {
	t.Helper()
	return f.newStore(t, f.openDB(t, tenantRole, platformRole), o)
}

// newTenant creates a tenant through the platform pool (sqlc CreateTenant).
func (f *fixture) newTenant(t *testing.T) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.workerDB.WithPlatformTx(t.Context(), func(q *sqlcdb.Queries) error {
		tn, err := q.CreateTenant(t.Context(), sqlcdb.CreateTenantParams{
			Slug: "t" + randomHex(5), Name: "Tenant", Status: "active", Settings: []byte(`{}`),
		})
		id = tn.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	tag, err := f.su.Exec(t.Context(), sql, args...)
	if err != nil {
		t.Fatalf("superuser: %v\n%s", err, sql)
	}
	return tag.RowsAffected()
}

// dekRow is what the superuser sees of one DEK.
type dekRow struct {
	id      uuid.UUID
	version int32
	state   string
	kekID   string
	wrapped []byte
	nonce   []byte
}

// deks lists the DEKs of one owner (superuser view, bypassing RLS), oldest first.
func (f *fixture) deks(t *testing.T, o Owner) []dekRow {
	t.Helper()
	rows, err := f.su.Query(t.Context(), `SELECT id, version, state, kek_id, wrapped_dek, wrap_nonce FROM tenant_keys
		WHERE scope = $1 AND tenant_id IS NOT DISTINCT FROM $2 ORDER BY version`, string(o.Scope), o.tenantPtr())
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (dekRow, error) {
		var d dekRow
		err := r.Scan(&d.id, &d.version, &d.state, &d.kekID, &d.wrapped, &d.nonce)
		return d, err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// secretDEK returns the dek_id of a secret version (superuser view).
func (f *fixture) secretDEK(t *testing.T, ref Ref) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.su.QueryRow(t.Context(), `SELECT dek_id FROM secrets WHERE tenant_id IS NOT DISTINCT FROM $1 AND name = $2
		AND version = $3`, tenantArg(ref), ref.Name, ref.Version).Scan(&id); err != nil {
		t.Fatalf("dek of %s: %v", ref, err)
	}
	return id
}

func tenantArg(r Ref) *uuid.UUID {
	if r.IsPlatform() {
		return nil
	}
	return &r.Tenant
}

// mustPut stores value under ref with s and fails the test otherwise.
func mustPut(t *testing.T, s *Store, ref Ref, value string, opts ...Option) {
	t.Helper()
	if err := s.Put(t.Context(), ref, []byte(value), opts...); err != nil {
		t.Fatalf("put %s: %v", ref, err)
	}
}

// wantValue asserts that s reads value under ref.
func wantValue(t *testing.T, s *Store, ref Ref, value string) {
	t.Helper()
	got, err := s.Get(t.Context(), ref)
	if err != nil || string(got) != value {
		t.Errorf("get %s: %q, %v; want %q", ref, string(got), err, value)
	}
}

// fixedClock is a settable clock for expiry tests.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
