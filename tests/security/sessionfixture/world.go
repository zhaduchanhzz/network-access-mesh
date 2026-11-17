//go:build mgtestfixture

package sessionfixture

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// Tag is the build tag of the fixture and of every package that imports it.
const Tag = "mgtestfixture"

// Default host names of the two origins (§8.3). They are never resolved: the API is served in process.
const (
	AppHost   = "app.mg.test"
	AdminHost = "admin.mg.test"
)

// The roles of §8.4 (keys of database/seeds/rbac.sql).
var (
	PlatformRoles = []string{authz.RoleSuperAdmin, authz.RolePlatformOperator, authz.RolePlatformSupport, authz.RolePlatformViewer}
	TenantRoles   = []string{authz.RoleTenantOwner, authz.RoleTenantAdmin, authz.RoleTenantOperator, authz.RoleTenantViewer, authz.RoleEndUser}
)

// Roles returns the nine roles of §8.4, platform roles first.
func Roles() []string { return append(slices.Clone(PlatformRoles), TenantRoles...) }

// IsPlatformRole reports whether role is one of the four platform roles.
func IsPlatformRole(role string) bool { return slices.Contains(PlatformRoles, role) }

// Options configure New; the zero value is what the authorization matrix needs.
type Options struct {
	// AppHost and AdminHost are the host names of the two origins; "" ⇒ AppHost, AdminHost.
	AppHost, AdminHost string
	// HTTPClient is the IdP client of the identity module, for a test that also runs a real login (Keycloak);
	// nil ⇒ a client that refuses every connection — minted sessions need no IdP.
	HTTPClient *http.Client
	// ClientSecrets resolves client_secret_ref for such a login; nil ⇒ none.
	ClientSecrets identity.ClientSecretSource
	// Handlers mounts handler sets; a nil Auth set gets identityapi (the auth operations). Unmounted sets answer 501.
	Handlers httpapi.Handlers
	// RateLimits of the composed API; nil ⇒ limits no test reaches (rate limiting is tested by P2-T14, a matrix of
	// hundreds of requests from one address must not trip it).
	RateLimits httpapi.RateLimits
	// Now is the clock of the identity module and of Login; nil ⇒ time.Now.
	Now func() time.Time
	// MaxConns per pool of the api store; 0 ⇒ 8.
	MaxConns int32
}

// Tenant is one fixture tenant and its active IdP.
type Tenant struct {
	Name string // "A" or "B"
	ID   uuid.UUID
	Slug string
	IdP  uuid.UUID // identity_providers.id
}

// Actor is one identity holding one role: a tenant role in one tenant, or a platform role.
type Actor struct {
	Role       string
	Scope      identity.Scope
	Tenant     *Tenant // nil for platform staff
	IdentityID uuid.UUID
	IdPID      uuid.UUID
	Subject    string
	Email      string
	// MembershipID is the tenant_memberships.id of a tenant role, PlatformUserID the platform_users.id of a
	// platform role (the other one is uuid.Nil).
	MembershipID   uuid.UUID
	PlatformUserID uuid.UUID
}

// Origin is the origin of the actor's sessions: app for tenant identities, admin for platform staff (§8.3).
func (a *Actor) Origin() identity.Origin {
	if a.Scope == identity.ScopePlatform {
		return identity.OriginAdmin
	}
	return identity.OriginApp
}

// String names the actor in test output ("tenant_admin@A", "super_admin@platform").
func (a *Actor) String() string {
	if a.Tenant == nil {
		return a.Role + "@platform"
	}
	return a.Role + "@" + a.Tenant.Name
}

// World is a migrated database with two tenants, one actor per role and the composed API.
type World struct {
	DB          string       // name of the test database
	Store       *store.Store // the api process's store (mg_api_tenant / mg_api_platform)
	Identity    *identity.Service
	API         http.Handler // httpapi.New + identityapi + authzhook (identity session layer, authz decisions)
	A, B        *Tenant
	PlatformIdP uuid.UUID
	AppHost     string
	AdminHost   string

	now    func() time.Time
	logs   *logBuffer
	mu     sync.Mutex // guards su (a pgx.Conn is not safe for concurrent use)
	su     *pgx.Conn  // superuser of the test database: fixtures bypass RLS
	actors map[string]*Actor
}

// New builds a world for t: database, tenants A and B, the platform IdP, one actor per role (in A and in B for the
// tenant roles) and the composed API. Every resource lives as long as the test (the database until storetest.Cleanup).
func New(t testing.TB, opts Options) *World {
	t.Helper()
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	w := &World{
		DB: db, AppHost: opts.AppHost, AdminHost: opts.AdminHost, now: opts.Now,
		logs: &logBuffer{}, su: env.Admin(t, db), actors: map[string]*Actor{},
	}
	if w.AppHost == "" {
		w.AppHost = AppHost
	}
	if w.AdminHost == "" {
		w.AdminHost = AdminHost
	}
	if w.now == nil {
		w.now = time.Now
	}
	maxConns := opts.MaxConns
	if maxConns <= 0 {
		maxConns = 8
	}
	w.Store = env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", maxConns)

	w.A, w.B = w.newTenant(t, "A"), w.newTenant(t, "B")
	w.PlatformIdP = uuid.Must(uuid.NewV7())
	w.Exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.invalid/realms/platform', 'mg-portal', 'keycloak', 'active')`, w.PlatformIdP)
	for _, role := range PlatformRoles {
		w.actors[actorKey(role, nil)] = w.NewActor(t, role, nil)
	}
	for _, ten := range []*Tenant{w.A, w.B} {
		for _, role := range TenantRoles {
			w.actors[actorKey(role, ten)] = w.NewActor(t, role, ten)
		}
	}
	w.compose(t, opts)
	return w
}

// newTenant creates an active tenant and its active IdP (never contacted: issuer under .invalid, RFC 2606).
func (w *World) newTenant(t testing.TB, name string) *Tenant {
	t.Helper()
	ten := &Tenant{Name: name, ID: uuid.Must(uuid.NewV7()), Slug: "tenant-" + strings.ToLower(name), IdP: uuid.Must(uuid.NewV7())}
	w.Exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.ID, ten.Slug, "Tenant "+name)
	w.Exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, ten.IdP, ten.ID, "https://idp.invalid/realms/"+ten.Slug)
	return ten
}

// NewActor creates one more active identity holding role: a tenant role in tenant, or — tenant nil — a platform
// role. The database refuses a role of the wrong scope (composite foreign keys of 0002), so does the fixture.
func (w *World) NewActor(t testing.TB, role string, tenant *Tenant) *Actor {
	t.Helper()
	a := &Actor{Role: role, Tenant: tenant, IdentityID: uuid.Must(uuid.NewV7()), Subject: "fixture-" + role + "-" + randomHex(4)}
	a.Email = a.Subject + "@example.invalid"
	if tenant == nil {
		a.Scope, a.IdPID = identity.ScopePlatform, w.PlatformIdP
		w.Exec(t, `INSERT INTO identities (id, idp_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, 'platform', $3, $4, true, $5)`, a.IdentityID, a.IdPID, a.Subject, a.Email, "Fixture "+role)
		w.Scan(t, `INSERT INTO platform_users (identity_id, role_id, status)
			SELECT $1, id, 'active' FROM roles WHERE scope = 'platform' AND key = $2 RETURNING id`,
			[]any{a.IdentityID, role}, &a.PlatformUserID)
		return a
	}
	a.Scope, a.IdPID = identity.ScopeTenant, tenant.IdP
	w.Exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, a.IdentityID, a.IdPID, tenant.ID, a.Subject, a.Email, "Fixture "+role)
	w.Scan(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
		SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3 RETURNING id`,
		[]any{tenant.ID, a.IdentityID, role}, &a.MembershipID)
	return a
}

// Actor returns the actor of role created by New: in tenant for a tenant role, tenant nil for a platform role.
func (w *World) Actor(t testing.TB, role string, tenant *Tenant) *Actor {
	t.Helper()
	a, ok := w.actors[actorKey(role, tenant)]
	if !ok {
		t.Fatalf("sessionfixture: no actor %q in %v (tenant roles need a tenant, platform roles none)", role, tenant)
	}
	return a
}

func actorKey(role string, tenant *Tenant) string {
	if tenant == nil {
		return role + "@platform"
	}
	return role + "@" + tenant.Name
}

// Exec runs a fixture statement as the superuser of the test database (fixtures bypass RLS).
func (w *World) Exec(t testing.TB, sql string, args ...any) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.su.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("sessionfixture: %v\n%s", err, sql)
	}
}

// Scan runs a one-row query as superuser and scans it into dest; no row fails the test.
func (w *World) Scan(t testing.TB, sql string, args []any, dest ...any) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.su.QueryRow(context.Background(), sql, args...).Scan(dest...); err != nil {
		t.Fatalf("sessionfixture: %v\n%s", err, sql)
	}
}

// host returns the host name of an origin.
func (w *World) host(o identity.Origin) string {
	if o == identity.OriginAdmin {
		return w.AdminHost
	}
	return w.AppHost
}

// compose builds the identity module and the public API of the api process on the world's store.
func (w *World) compose(t testing.TB, opts Options) {
	t.Helper()
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Transport: noIdP{}}
	}
	log := logx.New(w.logs, slog.LevelInfo, "api")
	svc, err := identity.New(w.Store, identity.Config{
		AppHost: w.AppHost, AdminHost: w.AdminHost, HTTPClient: client, ClientSecrets: opts.ClientSecrets,
		Logger: log, Now: opts.Now,
		RequestID: authzhook.RequestID, ClientIP: authzhook.ClientIP, ProblemWriter: authzhook.WriteProblem,
	})
	if err != nil {
		t.Fatal(err)
	}
	handlers := opts.Handlers
	if handlers.Auth == nil {
		handlers.Auth = identityapi.New(svc)
	}
	limits := opts.RateLimits
	if limits == nil {
		limits = unlimited()
	}
	api, err := httpapi.New(httpapi.Options{
		Logger: log, Handlers: handlers, Hooks: authzhook.Hooks(svc, authz.New(w.Store)), RateLimits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.Identity, w.API = svc, api
}

// unlimited are rate limits no test reaches: a token every nanosecond, a bucket of a billion.
func unlimited() httpapi.RateLimits {
	l := ratelimit.Limit{Every: time.Nanosecond, Burst: 1_000_000_000}
	out := httpapi.RateLimits{}
	for _, c := range httpapi.Classes {
		out[c] = httpapi.ClassLimits{PerIP: l, PerIdentity: l}
	}
	return out
}

// noIdP is the IdP transport of a world without IdP: minted sessions never need one.
type noIdP struct{}

func (noIdP) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("sessionfixture: this world has no IdP (sessions are minted) — set Options.HTTPClient for a real login")
}

// AccessLine returns the access-log line (JSON) of the request whose X-Request-Id is requestID — fields "status",
// "operation", "identity", "problem" (§13.1; written by internal/httpapi, never with a secret).
func (w *World) AccessLine(t testing.TB, requestID string) map[string]any {
	t.Helper()
	lines := strings.Split(w.logs.String(), "\n")
	for i := len(lines) - 1; i >= 0; i-- { // the line asked for is almost always one of the last
		if !strings.Contains(lines[i], requestID) {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(lines[i]), &m) == nil && m["request_id"] == requestID && m["msg"] == "http request" {
			return m
		}
	}
	t.Fatalf("sessionfixture: no access-log line for request %q", requestID)
	return nil
}

// Logs returns everything the API and the identity module logged so far (JSON lines, redacted by logx).
func (w *World) Logs() string { return w.logs.String() }

// logBuffer collects the log lines written by concurrent requests.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
