package authz

// Integration test harness: a real PostgreSQL of the pinned version (versions.lock [images.postgres]), as for
// internal/store (see internal/store/harness_test.go):
//
//	MG_TEST_PG_ADMIN_URL  superuser URL of a THROWAWAY cluster
//	MG_TEST_PG_REQUIRED=1 a missing URL fails the tests (CI) instead of skipping them
//
// The package gets one database, bootstrapped and migrated as mg_migrator with store.Migrate — which applies the
// RBAC seed — exactly like a deployment. Role passwords are derived from the superuser password with the same
// formula as internal/store's harness (roles are cluster-wide and both packages run in parallel under go test ./...),
// and the creation holds the same cluster-wide advisory lock.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// clusterLockKey is the advisory lock of internal/store/harness_test.go: held on database postgres while a test
// database is created, migrated and role passwords are set.
const clusterLockKey int64 = 0x6d67_7465_7374 // "mgtest"

var appLoginRoles = []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform"}

type pgEnv struct {
	admin   *url.URL
	secret  string
	pwDir   string
	once    sync.Once
	db      string
	err     error
	created []string
}

var (
	envOnce sync.Once
	env     *pgEnv
)

func TestMain(m *testing.M) {
	code := m.Run()
	if env != nil {
		env.cleanup()
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
		if err != nil {
			env = &pgEnv{err: err}
			return
		}
		pw, _ := u.User.Password()
		dir, err := os.MkdirTemp("", "mgtest-authz-")
		env = &pgEnv{admin: u, secret: pw, pwDir: dir, err: err}
	})
	if env.admin == nil {
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

// password is the formula of internal/store's harness: both packages must set identical passwords.
func (e *pgEnv) password(role string) string {
	sum := sha256.Sum256([]byte("meshguard-test|" + e.secret + "|" + role))
	return hex.EncodeToString(sum[:])
}

func (e *pgEnv) creds(role string) (store.Credentials, error) {
	p := filepath.Join(e.pwDir, role)
	if err := os.WriteFile(p, []byte(e.password(role)+"\n"), 0o600); err != nil {
		return store.Credentials{}, err
	}
	return store.Credentials{User: role, PasswordFile: p}, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// database returns the package's database, created on first use.
func (e *pgEnv) database(t *testing.T) string {
	t.Helper()
	e.once.Do(func() { e.db, e.err = e.create(context.Background()) })
	if e.err != nil {
		t.Fatalf("test database: %v", e.err)
	}
	return e.db
}

func (e *pgEnv) create(ctx context.Context) (string, error) {
	lock, err := pgx.Connect(ctx, e.adminURL("postgres"))
	if err != nil {
		return "", err
	}
	defer func() { _ = lock.Close(ctx) }() // closing the session releases the advisory lock
	if _, err := lock.Exec(ctx, "SELECT pg_advisory_lock($1)", clusterLockKey); err != nil {
		return "", err
	}
	name := "mga_" + randomHex(6)
	if _, err := lock.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		return "", err
	}
	e.created = append(e.created, name)
	su, err := pgx.Connect(ctx, e.adminURL(name))
	if err != nil {
		return "", err
	}
	defer func() { _ = su.Close(ctx) }()
	if err := store.Bootstrap(ctx, su); err != nil {
		return "", err
	}
	if err := store.SetRolePassword(ctx, su, "mg_migrator", e.password("mg_migrator")); err != nil {
		return "", err
	}
	cred, err := e.creds("mg_migrator")
	if err != nil {
		return "", err
	}
	mig, err := store.OpenMigrator(e.storeURL(name), cred)
	if err != nil {
		return "", err
	}
	defer func() { _ = mig.Close() }()
	if err := store.Migrate(ctx, mig); err != nil { // migrations + RBAC seed
		return "", err
	}
	for _, r := range appLoginRoles {
		if err := store.SetRolePassword(ctx, su, r, e.password(r)); err != nil {
			return "", fmt.Errorf("password of %s: %w", r, err)
		}
	}
	return name, nil
}

func (e *pgEnv) cleanup() {
	ctx := context.Background()
	if c, err := pgx.Connect(ctx, e.adminURL("postgres")); err == nil {
		for _, n := range e.created {
			_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{n}.Sanitize()+" WITH (FORCE)")
		}
		_ = c.Close(ctx)
	}
	if e.pwDir != "" {
		_ = os.RemoveAll(e.pwDir)
	}
}

// superuser opens a superuser connection to the package database (fixtures bypass RLS; constraints still apply).
func (e *pgEnv) superuser(t *testing.T) *pgx.Conn {
	t.Helper()
	db := e.database(t)
	c, err := pgx.Connect(t.Context(), e.adminURL(db))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// migrator opens the migration role on the package database (store.Seed).
func (e *pgEnv) migrator(t *testing.T) *sql.DB {
	t.Helper()
	db := e.database(t)
	cred, err := e.creds("mg_migrator")
	if err != nil {
		t.Fatal(err)
	}
	mig, err := store.OpenMigrator(e.storeURL(db), cred)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mig.Close() })
	return mig
}

// openStore opens the application pools (api roles) on the package database.
func (e *pgEnv) openStore(t *testing.T) *store.Store {
	t.Helper()
	db := e.database(t)
	tc, err := e.creds("mg_api_tenant")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := e.creds("mg_api_platform")
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(t.Context(), store.Config{URL: e.storeURL(db), Tenant: tc, Platform: pc, MaxConns: 4})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// ---------------------------------------------------------------- fixtures (inserted by the superuser)

func exec(t *testing.T, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

// roleID returns the ID of a seeded role.
func roleID(t *testing.T, su *pgx.Conn, scope Scope, key string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := su.QueryRow(t.Context(), "SELECT id FROM roles WHERE scope = $1 AND key = $2", string(scope), key).Scan(&id); err != nil {
		t.Fatalf("role %s/%s: %v", scope, key, err)
	}
	return id
}

type tenantFx struct {
	id, idp uuid.UUID
}

// newTenant inserts a tenant with the given status and its active IdP.
func newTenant(t *testing.T, su *pgx.Conn, status string) tenantFx {
	t.Helper()
	f := tenantFx{id: uuid.Must(uuid.NewV7()), idp: uuid.Must(uuid.NewV7())}
	slug := "t" + randomHex(5)
	exec(t, su, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, $4)`, f.id, slug, "Tenant "+slug, status)
	exec(t, su, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, 'https://idp.test/realms/'||$3, 'portal', 'keycloak', 'active')`, f.idp, f.id, slug)
	return f
}

type memberFx struct{ identity, membership uuid.UUID }

// member inserts an identity of the tenant's IdP and its membership with a seeded tenant role.
func (f tenantFx) member(t *testing.T, su *pgx.Conn, role, membershipStatus, identityStatus string) memberFx {
	t.Helper()
	m := memberFx{identity: uuid.Must(uuid.NewV7()), membership: uuid.Must(uuid.NewV7())}
	exec(t, su, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, status) VALUES ($1, $2, $3, 'tenant', $4, $5)`,
		m.identity, f.idp, f.id, "sub-"+randomHex(6), identityStatus)
	exec(t, su, `INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status) VALUES ($1, $2, $3, $4, $5)`,
		m.membership, f.id, m.identity, roleID(t, su, ScopeTenant, role), membershipStatus)
	return m
}

// identityOnly inserts an identity of the tenant's IdP without membership.
func (f tenantFx) identityOnly(t *testing.T, su *pgx.Conn) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	exec(t, su, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', $4)`,
		id, f.idp, f.id, "sub-"+randomHex(6))
	return id
}

// platformIdentity inserts an identity of a (new) platform IdP; with role != "" also its platform user.
func platformIdentity(t *testing.T, su *pgx.Conn, role, status string) uuid.UUID {
	t.Helper()
	idp, id := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(t, su, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.test/realms/platform-'||$2, 'console', 'keycloak', 'active')`, idp, randomHex(6))
	exec(t, su, `INSERT INTO identities (id, idp_id, scope, subject) VALUES ($1, $2, 'platform', $3)`, id, idp, "staff-"+randomHex(6))
	if role != "" {
		exec(t, su, `INSERT INTO platform_users (identity_id, role_id, status) VALUES ($1, $2, $3)`,
			id, roleID(t, su, ScopePlatform, role), status)
	}
	return id
}

func asTenant(ctx context.Context, identity uuid.UUID) context.Context {
	return WithPrincipal(ctx, Principal{IdentityID: identity, Scope: ScopeTenant, Origin: OriginApp})
}

func asStaff(ctx context.Context, identity uuid.UUID) context.Context {
	return WithPrincipal(ctx, Principal{IdentityID: identity, Scope: ScopePlatform, Origin: OriginAdmin})
}
