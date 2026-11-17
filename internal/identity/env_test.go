package identity_test

// End-to-end test environment: the identity service on a real PostgreSQL (internal/identity harness), the generated
// router with the strict handlers of internal/httpapi/identityapi behind identity.Service.Middleware, fake OpenID
// Providers (httptest) and a minimal browser with a per-host cookie jar.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

const (
	appHost   = "app.mg.test"
	adminHost = "admin.mg.test"
)

// clock is the shared test clock of the service and the fake IdPs.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now().UTC().Truncate(time.Second)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// auditLog records the audit events of the service.
type auditLog struct {
	mu     sync.Mutex
	events []identity.AuditEvent
}

func (a *auditLog) Record(_ context.Context, ev identity.AuditEvent) {
	a.mu.Lock()
	a.events = append(a.events, ev)
	a.mu.Unlock()
}

// last returns the last event of an action.
func (a *auditLog) last(action string) identity.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.events) - 1; i >= 0; i-- {
		if a.events[i].Action == action {
			return a.events[i]
		}
	}
	return identity.AuditEvent{}
}

// unimplemented supplies the operations of other modules; the auth operations of identityapi.Handlers are promoted
// at a shallower depth and win.
type unimplemented struct{ gen.StrictServerInterface }

type apiServer struct {
	unimplemented
	*identityapi.Handlers
}

type env struct {
	t     *testing.T
	pg    *identity.PGEnv
	db    *pgx.Conn
	clock *clock
	audit *auditLog
	svc   *identity.Service
	h     http.Handler

	mu      sync.Mutex
	secrets map[string]string
}

// newEnv builds the environment; each option may change the configuration of the service (it gets the api store).
func newEnv(t *testing.T, opts ...func(e *env, st *store.Store, cfg *identity.Config)) *env {
	t.Helper()
	pg := identity.RequirePG(t)
	e := &env{t: t, pg: pg, db: pg.Admin(t), clock: newClock(), audit: &auditLog{}, secrets: map[string]string{}}
	st := pg.Store(t)
	cfg := identity.Config{
		AppHost: appHost, AdminHost: adminHost,
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(e.secret),
		Auditor:       e.audit,
		Logger:        slog.New(slog.DiscardHandler),
		Now:           e.clock.Now,
	}
	for _, o := range opts {
		o(e, st, &cfg)
	}
	svc, err := identity.New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	api := gen.HandlerWithOptions(gen.NewStrictHandler(apiServer{Handlers: identityapi.New(svc)}, nil),
		gen.StdHTTPServerOptions{BaseURL: "/api/v1"})
	e.h = svc.Middleware(api)
	return e
}

func (e *env) secret(_ context.Context, ref string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.secrets[ref]
	if !ok {
		return "", errors.New("unknown secret ref")
	}
	return s, nil
}

func (e *env) exec(sql string, args ...any) { e.t.Helper(); identity.Exec(e.t, e.db, sql, args...) }

func (e *env) fakeIdP() *identity.FakeIdP { return identity.NewFakeIdP(e.t, e.clock.Now) }

// idpOpts are the policy columns of an identity_providers fixture.
type idpOpts struct {
	requiredClaims       string // jsonb
	requireEmailVerified bool
	allowedDomains       []string
	clientID             string
	status               string
}

type idpOpt func(*idpOpts)

func withRequiredClaims(js string) idpOpt   { return func(o *idpOpts) { o.requiredClaims = js } }
func withAllowedDomains(d ...string) idpOpt { return func(o *idpOpts) { o.allowedDomains = d } }
func redirectURI(host string, idp uuid.UUID) string {
	return "https://" + host + "/api/v1/auth/callback/" + idp.String()
}

// tenantFix is a tenant with its IdP registration at a fake IdP.
type tenantFix struct {
	ID       uuid.UUID
	Slug     string
	IdP      uuid.UUID
	Fake     *identity.FakeIdP
	ClientID string
	Secret   string
	Role     uuid.UUID
	RoleKey  string
}

// newTenant creates an active tenant, a tenant role and an active IdP registered at fake.
func (e *env) newTenant(fake *identity.FakeIdP, opts ...idpOpt) *tenantFix {
	e.t.Helper()
	o := idpOpts{requiredClaims: "{}", requireEmailVerified: true, allowedDomains: []string{},
		clientID: "portal-" + identity.RandomHex(4), status: "active"}
	for _, fn := range opts {
		fn(&o)
	}
	f := &tenantFix{ID: uuid.Must(uuid.NewV7()), Slug: "t" + identity.RandomHex(5), IdP: uuid.Must(uuid.NewV7()),
		Fake: fake, ClientID: o.clientID, Role: uuid.Must(uuid.NewV7()), RoleKey: "tenant_admin_" + identity.RandomHex(3)}
	e.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, f.ID, f.Slug, "Tenant "+f.Slug)
	e.exec(`INSERT INTO roles (id, scope, key, name) VALUES ($1, 'tenant', $2, 'Tenant Admin')`, f.Role, f.RoleKey)
	ref := "mgsec://" + f.ID.String() + "/idp." + f.IdP.String() + ".client#1" // the IdP's own secret (G2 F3)
	secret := "secret-" + identity.RandomHex(8)
	f.Secret = secret
	e.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, required_claims,
			require_email_verified, allowed_email_domains, driver, status)
		VALUES ($1, 'tenant', $2, $3, $4, $5, $6::jsonb, $7, $8, 'external', $9)`,
		f.IdP, f.ID, fake.Issuer, o.clientID, ref, o.requiredClaims, o.requireEmailVerified, o.allowedDomains, o.status)
	e.mu.Lock()
	e.secrets[ref] = secret
	e.mu.Unlock()
	fake.AddClient(o.clientID, secret, redirectURI(appHost, f.IdP))
	return f
}

// platformMu serialises the tests that create the (single) active platform IdP.
var platformMu sync.Mutex

type platformFix struct {
	IdP      uuid.UUID
	Fake     *identity.FakeIdP
	Role     uuid.UUID
	RoleKey  string
	ClientID string
}

// newPlatform creates the active platform IdP (holding platformMu until the end of the test, when the IdP is
// disabled again) and a platform role.
func (e *env) newPlatform(fake *identity.FakeIdP) *platformFix {
	e.t.Helper()
	platformMu.Lock()
	f := &platformFix{IdP: uuid.Must(uuid.NewV7()), Fake: fake, Role: uuid.Must(uuid.NewV7()),
		RoleKey: "super_admin_" + identity.RandomHex(3), ClientID: "portal-admin-" + identity.RandomHex(4)}
	e.t.Cleanup(func() {
		_, _ = e.db.Exec(context.Background(), `UPDATE identity_providers SET status = 'disabled' WHERE id = $1`, f.IdP)
		platformMu.Unlock()
	})
	e.exec(`UPDATE identity_providers SET status = 'disabled' WHERE scope = 'platform' AND status = 'active'`)
	e.exec(`INSERT INTO roles (id, scope, key, name) VALUES ($1, 'platform', $2, 'Super Admin')`, f.Role, f.RoleKey)
	ref := "mgsec://platform/idp." + f.IdP.String() + ".client#1" // the IdP's own secret (G2 F3)
	secret := "secret-" + identity.RandomHex(8)
	e.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'platform', $2, $3, $4, 'keycloak', 'active')`, f.IdP, fake.Issuer, f.ClientID, ref)
	e.mu.Lock()
	e.secrets[ref] = secret
	e.mu.Unlock()
	fake.AddClient(f.ClientID, secret, redirectURI(adminHost, f.IdP))
	return f
}

// browser is a minimal user agent: host-only cookie jar, no redirect following.
type browser struct {
	e   *env
	jar map[string]map[string]string
}

func (e *env) browser() *browser { return &browser{e: e, jar: map[string]map[string]string{}} }

func (b *browser) cookie(host, name string) string { return b.jar[host][name] }

func (b *browser) setCookie(host, name, value string) {
	if b.jar[host] == nil {
		b.jar[host] = map[string]string{}
	}
	b.jar[host][name] = value
}

func (b *browser) store(host string, h http.Header) {
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			b.e.t.Fatalf("bad Set-Cookie %q: %v", line, err)
		}
		if c.MaxAge < 0 {
			delete(b.jar[host], c.Name)
			continue
		}
		b.setCookie(host, c.Name, c.Value)
	}
}

// do sends a request to the API handler as this browser would (cookies of the URL's host). For unsafe methods the
// caller passes the CSRF token and the Origin header it wants.
func (b *browser) do(method, rawURL string, hdr http.Header) *httptest.ResponseRecorder {
	b.e.t.Helper()
	req := httptest.NewRequestWithContext(b.e.t.Context(), method, rawURL, nil)
	req.Header.Set("User-Agent", "mg-test-browser/1.0")
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for name, value := range b.jar[req.Host] {
		req.Header.Add("Cookie", name+"="+value) // a request cookie carries no attributes
	}
	rec := httptest.NewRecorder()
	b.e.h.ServeHTTP(rec, req)
	b.store(req.Host, rec.Header())
	return rec
}

func (b *browser) get(rawURL string) *httptest.ResponseRecorder {
	return b.do(http.MethodGet, rawURL, nil)
}

// startLogin calls GET /auth/login and returns the response (302 to the IdP on success).
func (b *browser) startLogin(host, query string) *httptest.ResponseRecorder {
	return b.get("https://" + host + "/api/v1/auth/login?" + query)
}

// authorize follows the redirect to the fake IdP and returns its redirect back to the Portal (the callback URL).
func (b *browser) authorize(location string) *url.URL {
	b.e.t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(b.e.t.Context(), http.MethodGet, location, nil)
	resp, err := c.Do(req)
	if err != nil {
		b.e.t.Fatalf("authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		b.e.t.Fatalf("authorize: HTTP %d", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		b.e.t.Fatal(err)
	}
	return u
}

// login runs a full login: /auth/login → IdP → callback; it returns the callback response.
func (b *browser) login(host, query string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	start := b.startLogin(host, query)
	if start.Code != http.StatusFound {
		b.e.t.Fatalf("login start: HTTP %d %s", start.Code, start.Body.String())
	}
	return b.get(b.authorize(start.Header().Get("Location")).String())
}

// mustLogin runs a full login and fails unless it ends with a session cookie.
func (b *browser) mustLogin(host, query string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	rec := b.login(host, query)
	if rec.Code != http.StatusFound || b.cookie(host, identity.SessionCookieName) == "" {
		b.e.t.Fatalf("login: HTTP %d %s (audit: %+v)", rec.Code, rec.Body.String(), b.e.audit.last(identity.ActionLogin))
	}
	return rec
}

// session calls GET /auth/session.
func (b *browser) session(host string) (*httptest.ResponseRecorder, gen.Session) {
	b.e.t.Helper()
	rec := b.get("https://" + host + "/api/v1/auth/session")
	var s gen.Session
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			b.e.t.Fatal(err)
		}
	}
	return rec, s
}

// csrf computes the CSRF token of the browser's session independently of the module: HMAC-SHA256(session id,
// "csrf-v1"), base64url.
func (b *browser) csrf(host string) string {
	b.e.t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(b.cookie(host, identity.SessionCookieName))
	if err != nil {
		b.e.t.Fatal(err)
	}
	return hmacCSRF(raw)
}

// hmacCSRF is the CSRF derivation of §8.3 step 8, written out in the test.
func hmacCSRF(rawSessionID []byte) string {
	m := hmac.New(sha256.New, rawSessionID)
	_, _ = m.Write([]byte("csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// unsafeHeaders returns the headers of a same-origin state-changing request of the Portal.
func unsafeHeaders(host, csrf string) http.Header {
	return http.Header{"Origin": {"https://" + host}, "X-Csrf-Token": {csrf}}
}

// problemCode returns the code of a problem+json response.
func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("HTTP %d content type %q, want problem+json: %s", rec.Code, ct, rec.Body.String())
	}
	var p struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Status != rec.Code {
		t.Fatalf("problem status %d != HTTP %d", p.Status, rec.Code)
	}
	return p.Code
}

// count returns a count(*) as superuser.
func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%v\n%s", err, sql)
	}
	return n
}
