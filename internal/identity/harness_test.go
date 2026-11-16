package identity

// PostgreSQL harness of the identity tests (same conventions as internal/store/harness_test.go):
//
//	MG_TEST_PG_ADMIN_URL  superuser URL of a THROWAWAY cluster, e.g. postgres://postgres:<pw>@pg:5432/postgres?sslmode=disable
//	MG_TEST_PG_REQUIRED=1 a missing URL fails the tests (CI) instead of skipping them
//
// One database per test binary is created by the superuser, bootstrapped and migrated as mg_migrator exactly like a
// deployment; tests isolate themselves with random tenants and IdPs. Role passwords are derived from the superuser
// password with the same formula as the store harness (roles are cluster-wide) and only written when the derived one
// does not work yet; the cluster-wide part of the setup holds the advisory lock shared with internal/store (both
// packages run in parallel under go test) and is retried on transient catalog conflicts. Identifiers are exported
// because the end-to-end tests live in the external package identity_test.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// clusterSetupLockKey must equal ClusterSetupLockKey of internal/store/harness_test.go.
const clusterSetupLockKey int64 = 0x6d67746573740001

// apiAndWorkerRoles are the login roles the tests use (created by the migrations).
var apiAndWorkerRoles = []string{"mg_api_tenant", "mg_api_platform", "mg_worker_tenant", "mg_worker_platform"}

// PGEnv is the migrated test database of this test binary.
type PGEnv struct {
	admin  *url.URL
	secret string
	pwDir  string
	DB     string
}

var (
	pgOnce sync.Once
	pgEnv  *PGEnv
	pgErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if pgEnv != nil {
		pgEnv.drop()
	}
	os.Exit(code)
}

// RequirePG returns the test database, or skips (fails when MG_TEST_PG_REQUIRED=1) without PostgreSQL.
func RequirePG(t testing.TB) *PGEnv {
	t.Helper()
	raw := os.Getenv("MG_TEST_PG_ADMIN_URL")
	if raw == "" {
		if os.Getenv("MG_TEST_PG_REQUIRED") == "1" {
			t.Fatal("MG_TEST_PG_ADMIN_URL is not set but MG_TEST_PG_REQUIRED=1")
		}
		t.Skip("MG_TEST_PG_ADMIN_URL not set — PostgreSQL tests skipped")
	}
	pgOnce.Do(func() { pgEnv, pgErr = setupPG(raw) })
	if pgErr != nil {
		t.Fatalf("test database: %v", pgErr)
	}
	return pgEnv
}

func setupPG(raw string) (*PGEnv, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("MG_TEST_PG_ADMIN_URL is not a URL")
	}
	pw, _ := u.User.Password()
	dir, err := os.MkdirTemp("", "mgtest-identity-")
	if err != nil {
		return nil, err
	}
	// Retry on catalog conflicts with a test package that does not (yet) take the cluster lock.
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		e := &PGEnv{admin: u, secret: pw, pwDir: dir, DB: "mgt_identity_" + randomHex(6)}
		if lastErr = e.setup(); lastErr == nil {
			return e, nil
		}
		e.dropDB()
		if !transientPG(lastErr) {
			break
		}
		time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
	}
	_ = os.RemoveAll(dir)
	return nil, lastErr
}

// transientPG reports the errors of concurrent cluster-wide DDL: "tuple concurrently updated" (XX000), duplicate
// role creation (23505), serialization failure, deadlock, lock not available.
func transientPG(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "40001", "40P01", "23505", "55P03":
		return true
	case "XX000":
		return strings.Contains(pgErr.Message, "concurrently")
	}
	return false
}

func (e *PGEnv) setup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lock, err := pgx.Connect(ctx, e.adminURL("postgres"))
	if err != nil {
		return fmt.Errorf("connect superuser: %w", err)
	}
	defer func() { _ = lock.Close(context.Background()) }()
	if _, err := lock.Exec(ctx, "SELECT pg_advisory_lock($1)", clusterSetupLockKey); err != nil {
		return fmt.Errorf("cluster setup lock: %w", err)
	}
	defer func() { _, _ = lock.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", clusterSetupLockKey) }()
	if _, err := lock.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{e.DB}.Sanitize()); err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	su, err := pgx.Connect(ctx, e.adminURL(e.DB))
	if err != nil {
		return err
	}
	defer func() { _ = su.Close(context.Background()) }()
	if err := store.Bootstrap(ctx, su); err != nil {
		return err
	}
	for _, r := range []string{"mg_migrator", "mg_backup"} {
		if err := e.ensurePassword(ctx, su, r); err != nil {
			return err
		}
	}
	mpw, err := e.passwordFile("mg_migrator")
	if err != nil {
		return err
	}
	db, err := store.OpenMigrator(e.storeURL(e.DB), store.Credentials{User: "mg_migrator", PasswordFile: mpw})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := store.Migrate(ctx, db); err != nil {
		return err
	}
	mig, err := e.connectAs(ctx, "mg_migrator")
	if err != nil {
		return err
	}
	defer func() { _ = mig.Close(context.Background()) }()
	for _, r := range apiAndWorkerRoles {
		if err := e.ensurePassword(ctx, mig, r); err != nil {
			return err
		}
		if _, err := e.passwordFile(r); err != nil { // written once here, only read by the tests
			return err
		}
	}
	return nil
}

func (e *PGEnv) connectAs(ctx context.Context, role string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(e.storeURL(e.DB))
	if err != nil {
		return nil, err
	}
	cfg.User, cfg.Password = role, e.password(role)
	return pgx.ConnectConfig(ctx, cfg)
}

// ensurePassword sets the derived password of a role unless it already works: no catalog write (ALTER ROLE) when
// another test package of the same cluster has set it already.
func (e *PGEnv) ensurePassword(ctx context.Context, admin store.Execer, role string) error {
	if c, err := e.connectAs(ctx, role); err == nil {
		_ = c.Close(context.Background())
		return nil
	}
	return store.SetRolePassword(ctx, admin, role, e.password(role))
}

func (e *PGEnv) dropDB() {
	ctx := context.Background()
	if c, err := pgx.Connect(ctx, e.adminURL("postgres")); err == nil {
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{e.DB}.Sanitize()+" WITH (FORCE)")
		_ = c.Close(ctx)
	}
}

func (e *PGEnv) adminURL(db string) string {
	u := *e.admin
	u.Path = "/" + db
	return u.String()
}

func (e *PGEnv) storeURL(db string) string {
	u := *e.admin
	u.User = nil
	u.Path = "/" + db
	return u.String()
}

// password must stay identical to pgEnv.password of internal/store/harness_test.go.
func (e *PGEnv) password(role string) string {
	sum := sha256.Sum256([]byte("meshguard-test|" + e.secret + "|" + role))
	return hex.EncodeToString(sum[:])
}

func (e *PGEnv) passwordFile(role string) (string, error) {
	p := filepath.Join(e.pwDir, role)
	if err := os.WriteFile(p, []byte(e.password(role)+"\n"), 0o600); err != nil {
		return "", err
	}
	return p, nil
}

func (e *PGEnv) drop() {
	e.dropDB()
	_ = os.RemoveAll(e.pwDir)
}

// Store opens a store as the api process does (mg_api_tenant / mg_api_platform).
func (e *PGEnv) Store(t testing.TB) *store.Store {
	return e.openStore(t, "mg_api_tenant", "mg_api_platform")
}

// WorkerStore opens a store as the worker does (mg_worker_tenant / mg_worker_platform) — session.gc.
func (e *PGEnv) WorkerStore(t testing.TB) *store.Store {
	return e.openStore(t, "mg_worker_tenant", "mg_worker_platform")
}

func (e *PGEnv) openStore(t testing.TB, tenantRole, platformRole string) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), store.Config{
		URL:      e.storeURL(e.DB),
		Tenant:   store.Credentials{User: tenantRole, PasswordFile: filepath.Join(e.pwDir, tenantRole)},
		Platform: store.Credentials{User: platformRole, PasswordFile: filepath.Join(e.pwDir, platformRole)},
		MaxConns: 4,
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// Admin opens a superuser connection to the test database (fixtures bypass RLS).
func (e *PGEnv) Admin(t testing.TB) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), e.adminURL(e.DB))
	if err != nil {
		t.Fatalf("connect superuser: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// Exec runs a fixture statement as superuser.
func Exec(t testing.TB, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RandomHex returns 2n random hex characters (fixture names).
func RandomHex(n int) string { return randomHex(n) }
