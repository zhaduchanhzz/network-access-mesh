//go:build mgtestfixture

package sessionfixture_test

// The fixture drives the composed API (as internal/httpapi/authzhook's TestComposedAPI does after a fake-IdP login)
// for every role of §8.4 with minted sessions — no browser, no IdP: the acceptance of P2-T15a ("ma trận authz chạy
// không cần trình duyệt"). The expected outcomes below are written from the matrices of §8.5/§8.6, independently of
// database/seeds/rbac.sql.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// problemOf decodes a problem+json answer and checks the headers every problem of the API carries.
func problemOf(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code gen.ProblemCode) gen.Problem {
	t.Helper()
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != status || p.Code != code ||
		rec.Header().Get("Content-Type") != "application/problem+json" ||
		rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%s: HTTP %d %v %s, want %d %s problem", what, rec.Code, rec.Header(), rec.Body.String(), status, code)
	}
	return p
}

// csrfOf is §8.3 step 8 written out here: HMAC-SHA256(key = raw session id, msg = "csrf-v1"), base64url.
func csrfOf(t *testing.T, cookie string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(raw) != 32 {
		t.Fatalf("cookie is not 32 bytes of base64url (%d bytes, %v)", len(raw), err)
	}
	m := hmac.New(sha256.New, raw)
	_, _ = m.Write([]byte("csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// TestMintedSessions — a minted session is stored like a login's (hash only, origin and timeouts of the scope), its
// CSRF token is the §8.3 derivation, and it never prints its secrets.
func TestMintedSessions(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	for _, role := range sessionfixture.Roles() {
		var ten *sessionfixture.Tenant
		if !sessionfixture.IsPlatformRole(role) {
			ten = w.A
		}
		a := w.Actor(t, role, ten)
		s := w.Login(t, a)
		raw, _ := base64.RawURLEncoding.DecodeString(s.CookieValue())
		sum := sha256.Sum256(raw)
		var (
			origin, row         string
			idle, absolute, age time.Duration
		)
		w.Scan(t, `SELECT origin, s::text, idle_expires_at - created_at, absolute_expires_at - created_at,
				created_at - auth_time
			FROM sessions s WHERE id_hash = $1 AND identity_id = $2 AND idp_id = $3 AND revoked_at IS NULL`,
			[]any{sum[:], a.IdentityID, a.IdPID}, &origin, &row, &idle, &absolute, &age)
		wantOrigin, want := "app", identity.DefaultTenantTimeouts
		if a.Scope == identity.ScopePlatform {
			wantOrigin, want = "admin", identity.DefaultPlatformTimeouts
		}
		if origin != wantOrigin || s.Origin != identity.Origin(wantOrigin) || idle != want.Idle || absolute != want.Absolute ||
			age < 0 || age > time.Second {
			t.Errorf("%s: origin %s, idle %v, absolute %v, created − auth_time %v", a, origin, idle, absolute, age)
		}
		for _, leak := range []string{s.CookieValue(), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw)} {
			if strings.Contains(row, leak) {
				t.Errorf("%s: the sessions row holds the raw session id", a)
			}
		}
		if s.CSRFToken() != csrfOf(t, s.CookieValue()) {
			t.Errorf("%s: CSRF token is not HMAC-SHA256(session id, csrf-v1)", a)
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "session", s, "value", *s)
		printed := fmt.Sprintf("%v %+v %#v %s %v", s, s, s, s, *s) + buf.String()
		if strings.Contains(printed, s.CookieValue()) || strings.Contains(printed, s.CSRFToken()) ||
			!strings.Contains(printed, s.PublicID.String()) {
			t.Errorf("%s: printed form %q", a, printed)
		}
	}
	// Step-up: a session minted with an old auth_time is valid but no longer a recent authentication (§8.3 step 7).
	old := w.Login(t, w.Actor(t, authz.RoleTenantOwner, w.A), sessionfixture.WithAuthTime(time.Now().Add(-20*time.Minute)))
	sess, err := w.Identity.Authenticate(t.Context(), old.CookieValue(), identity.OriginApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Identity.RequireRecentAuth(sess); err == nil || identity.AsError(err).Kind != identity.KindReauthRequired {
		t.Fatalf("RequireRecentAuth of a 20-minute-old auth_time: %v", err)
	}
	if rec := w.Do(t, old, http.MethodGet, "/auth/session", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("old auth_time session: HTTP %d", rec.Code)
	}
}

// op is one representative operation and the roles §8.5/§8.6 grant it to.
type op struct {
	goName   string
	method   string
	path     string // below /api/v1; {t} is replaced by the tenant
	platform bool
	granted  []string
}

var (
	tenantOps = []op{
		{"GetTenant", "GET", "/tenants/{t}", false, []string{"tenant_owner", "tenant_admin", "tenant_operator", "tenant_viewer", "end_user"}},
		{"GetTenantDashboard", "GET", "/tenants/{t}/dashboard", false, []string{"tenant_owner", "tenant_admin", "tenant_operator", "tenant_viewer"}},
		{"ListDevices", "GET", "/tenants/{t}/devices", false, []string{"tenant_owner", "tenant_admin", "tenant_operator", "tenant_viewer", "end_user"}}, // EU: ○ (x-own-resource)
		{"ListTenantUsers", "GET", "/tenants/{t}/users", false, []string{"tenant_owner", "tenant_admin", "tenant_operator", "tenant_viewer"}},
		{"ListTenantAuditEvents", "GET", "/tenants/{t}/audit", false, []string{"tenant_owner", "tenant_admin", "tenant_viewer"}},
		{"ListTenantJobs", "GET", "/tenants/{t}/jobs", false, []string{"tenant_owner", "tenant_admin", "tenant_operator", "tenant_viewer"}},
		{"SyncDevices", "POST", "/tenants/{t}/devices/sync", false, []string{"tenant_owner", "tenant_admin", "tenant_operator"}},
	}
	platformOps = []op{
		{"ListPlatformTenants", "GET", "/platform/tenants", true, []string{"super_admin", "platform_operator", "platform_support", "platform_viewer"}},
		{"GetPlatformHealth", "GET", "/platform/health", true, []string{"super_admin", "platform_operator", "platform_support", "platform_viewer"}},
		{"ListPlatformAuditEvents", "GET", "/platform/audit", true, []string{"super_admin", "platform_operator", "platform_viewer"}},
		{"ListPlatformJobs", "GET", "/platform/jobs", true, []string{"super_admin", "platform_operator", "platform_support", "platform_viewer"}},
		{"ListPlatformInstances", "GET", "/platform/instances", true, []string{"super_admin", "platform_operator", "platform_support", "platform_viewer"}},
	}
)

func (o op) grants(role string) bool {
	for _, r := range o.granted {
		if r == role {
			return true
		}
	}
	return false
}

// call sends the operation as s (tenant t substituted) and returns the answer.
func call(t *testing.T, w *sessionfixture.World, s *sessionfixture.Session, o op, tenant uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	var hdr http.Header
	if o.method != http.MethodGet {
		hdr = http.Header{"Idempotency-Key": {uuid.NewString()}}
	}
	return w.Do(t, s, o.method, strings.ReplaceAll(o.path, "{t}", tenant.String()), nil, hdr)
}

// expect checks status and code, the problem detail of a 501 (it names the operation) and the access-log line of the
// request (identity of the session, problem code).
func expect(t *testing.T, w *sessionfixture.World, s *sessionfixture.Session, what string, rec *httptest.ResponseRecorder,
	status int, code gen.ProblemCode, goName string) {
	t.Helper()
	p := problemOf(t, what, rec, status, code)
	if status == http.StatusNotImplemented && (p.Detail == nil || !strings.Contains(*p.Detail, goName)) {
		t.Errorf("%s: detail %v does not name %s", what, p.Detail, goName)
	}
	line := w.AccessLine(t, rec.Header().Get("X-Request-Id"))
	if line["problem"] != string(code) || line["identity"] != s.Actor.IdentityID.String() {
		t.Errorf("%s: access line %v", what, line)
	}
}

// TestEveryRoleThroughTheComposedAPI — the nine roles with minted sessions on representative operations of the
// composed API: granted ⇒ the authz hook lets the request through to the (not yet mounted) handler, 501 naming the
// operation; not granted ⇒ 403; another tenant or a tenant that does not exist ⇒ 404 (§8.4 invariant 6); a platform
// route from a tenant session ⇒ 403; a tenant route from a platform session (no Support Access Grant) ⇒ 403 (AC-05a);
// a session presented on the other origin ⇒ 401; GET /auth/session and /auth/sessions describe the actor.
func TestEveryRoleThroughTheComposedAPI(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	var mu sync.Mutex
	counts := map[int]int{}
	count := func(code int) { mu.Lock(); counts[code]++; mu.Unlock() }

	type actorCase struct {
		role   string
		tenant *sessionfixture.Tenant
		other  *sessionfixture.Tenant
	}
	var cases []actorCase
	for _, role := range sessionfixture.PlatformRoles {
		cases = append(cases, actorCase{role: role})
	}
	for _, pair := range [][2]*sessionfixture.Tenant{{w.A, w.B}, {w.B, w.A}} {
		for _, role := range sessionfixture.TenantRoles {
			cases = append(cases, actorCase{role: role, tenant: pair[0], other: pair[1]})
		}
	}
	for _, c := range cases {
		a := w.Actor(t, c.role, c.tenant)
		t.Run(a.String(), func(t *testing.T) {
			t.Parallel()
			s := w.Login(t, a)

			// GET /auth/session: principal, origin, CSRF token, role (display only — authz reloads it).
			rec := w.Do(t, s, http.MethodGet, "/auth/session", nil, nil)
			count(rec.Code)
			var view gen.Session
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil {
				t.Fatalf("GET /auth/session: HTTP %d %s", rec.Code, rec.Body.String())
			}
			if view.Principal.IdentityId != a.IdentityID || view.Principal.IdpId != a.IdPID ||
				string(view.Principal.Scope) != string(a.Scope) || string(view.Origin) != string(a.Origin()) ||
				view.CsrfToken != s.CSRFToken() || view.Principal.Email == nil || *view.Principal.Email != a.Email {
				t.Errorf("session view %+v", view.Principal)
			}
			if c.tenant == nil {
				if view.Principal.PlatformRole == nil || *view.Principal.PlatformRole != c.role || len(view.Memberships) != 0 {
					t.Errorf("platform session view: role %v, memberships %+v", view.Principal.PlatformRole, view.Memberships)
				}
			} else if view.Principal.PlatformRole != nil || len(view.Memberships) != 1 || view.Memberships[0].Role != c.role ||
				view.Memberships[0].TenantId != c.tenant.ID || view.Memberships[0].MembershipId != a.MembershipID {
				t.Errorf("tenant session view: role %v, memberships %+v", view.Principal.PlatformRole, view.Memberships)
			}
			// GET /auth/sessions: the minted session, current, with the fixture's user agent.
			rec = w.Do(t, s, http.MethodGet, "/auth/sessions", nil, nil)
			count(rec.Code)
			var list gen.ListAuthSessions200JSONResponse
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Items) != 1 ||
				list.Items[0].Id != s.PublicID || !list.Items[0].Current || list.Items[0].UserAgent == nil ||
				*list.Items[0].UserAgent != sessionfixture.UserAgent {
				t.Errorf("GET /auth/sessions: HTTP %d %s", rec.Code, rec.Body.String())
			}
			// GET /tenants (authenticated): every role reaches the handler.
			rec = w.Do(t, s, http.MethodGet, "/tenants", nil, nil)
			count(rec.Code)
			expect(t, w, s, "ListMyTenants", rec, http.StatusNotImplemented, gen.ProblemCodeNotImplemented, "ListMyTenants")

			if c.tenant == nil {
				for _, o := range platformOps {
					rec := call(t, w, s, o, uuid.Nil)
					count(rec.Code)
					if o.grants(c.role) {
						expect(t, w, s, o.goName, rec, http.StatusNotImplemented, gen.ProblemCodeNotImplemented, o.goName)
					} else {
						expect(t, w, s, o.goName, rec, http.StatusForbidden, gen.ProblemCodeForbidden, o.goName)
					}
				}
				for _, o := range tenantOps { // staff without Support Access Grant (§8.7, AC-05a)
					rec := call(t, w, s, o, w.A.ID)
					count(rec.Code)
					expect(t, w, s, o.goName+" on tenant A", rec, http.StatusForbidden, gen.ProblemCodeForbidden, o.goName)
				}
			} else {
				for _, o := range tenantOps {
					rec := call(t, w, s, o, c.tenant.ID)
					count(rec.Code)
					if o.grants(c.role) {
						expect(t, w, s, o.goName, rec, http.StatusNotImplemented, gen.ProblemCodeNotImplemented, o.goName)
					} else {
						expect(t, w, s, o.goName, rec, http.StatusForbidden, gen.ProblemCodeForbidden, o.goName)
					}
					for name, other := range map[string]uuid.UUID{"other tenant": c.other.ID, "missing tenant": uuid.New()} {
						rec := call(t, w, s, o, other)
						count(rec.Code)
						expect(t, w, s, o.goName+" in the "+name, rec, http.StatusNotFound, gen.ProblemCodeNotFound, o.goName)
					}
				}
				for _, o := range platformOps {
					rec := call(t, w, s, o, uuid.Nil)
					count(rec.Code)
					expect(t, w, s, o.goName+" from a tenant session", rec, http.StatusForbidden, gen.ProblemCodeForbidden, o.goName)
				}
			}

			// The same cookie on the other origin is no session at all (§8.3 step 8): 401.
			otherHost := w.AdminHost
			if a.Origin() == identity.OriginAdmin {
				otherHost = w.AppHost
			}
			rec = w.Do(t, s.OnHost(otherHost), http.MethodGet, "/auth/session", nil, nil)
			count(rec.Code)
			problemOf(t, "session on the other origin", rec, http.StatusUnauthorized, gen.ProblemCodeUnauthenticated)
		})
	}
	t.Cleanup(func() { t.Logf("answers by status: %v", counts) })
}

// TestSessionLayerThroughTheFixture — what the session layer refuses itself goes through authzhook.WriteProblem
// (nosniff + problem on the access line); CSRF and Origin are enforced on minted sessions as on real ones; logout and
// a suspended tenant behave as for a login.
func TestSessionLayerThroughTheFixture(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	owner := w.Actor(t, authz.RoleTenantOwner, w.A)
	s := w.Login(t, owner)
	other := w.Login(t, w.Actor(t, authz.RoleTenantAdmin, w.A))
	sync := "/tenants/" + w.A.ID.String() + "/devices/sync"
	idem := func() http.Header { return http.Header{"Idempotency-Key": {uuid.NewString()}} }

	// Unknown host: 404 written by the identity middleware, rendered by the chain.
	rec := w.Do(t, s.OnHost("evil.example"), http.MethodGet, "/auth/session", nil, nil)
	problemOf(t, "unknown host", rec, http.StatusNotFound, gen.ProblemCodeNotFound)
	if line := w.AccessLine(t, rec.Header().Get("X-Request-Id")); line["problem"] != string(gen.ProblemCodeNotFound) {
		t.Errorf("unknown host: access line %v", line)
	}
	// CSRF and Origin on a state-changing request (§8.3 step 5).
	for name, mutate := range map[string]func(r *http.Request){
		"no CSRF token":            func(r *http.Request) { r.Header.Del(identity.CSRFHeader) },
		"token of another session": func(r *http.Request) { r.Header.Set(identity.CSRFHeader, other.CSRFToken()) },
		"foreign Origin":           func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"Origin of the admin host": func(r *http.Request) { r.Header.Set("Origin", "https://"+w.AdminHost) },
		"no Origin, cross-site": func(r *http.Request) {
			r.Header.Del("Origin")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		},
	} {
		r := s.Request(t.Context(), http.MethodPost, sync, nil)
		r.Header.Set("Idempotency-Key", uuid.NewString())
		mutate(r)
		rec := httptest.NewRecorder()
		w.API.ServeHTTP(rec, r)
		problemOf(t, name, rec, http.StatusForbidden, gen.ProblemCodeForbidden)
		if line := w.AccessLine(t, rec.Header().Get("X-Request-Id")); line["problem"] != string(gen.ProblemCodeForbidden) {
			t.Errorf("%s: access line %v", name, line)
		}
	}
	rec = w.Do(t, s, http.MethodPost, sync, nil, idem())
	problemOf(t, "sync with the session's token", rec, http.StatusNotImplemented, gen.ProblemCodeNotImplemented)

	// A suspended tenant refuses writes of its roles and still serves reads (§8.4 invariant 5).
	w.Exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, w.A.ID)
	problemOf(t, "sync in a suspended tenant", w.Do(t, s, http.MethodPost, sync, nil, idem()), http.StatusForbidden,
		gen.ProblemCodeTenantSuspended)
	problemOf(t, "read in a suspended tenant", w.Do(t, s, http.MethodGet, "/tenants/"+w.A.ID.String()+"/devices", nil, nil),
		http.StatusNotImplemented, gen.ProblemCodeNotImplemented)
	w.Exec(t, `UPDATE tenants SET status = 'active' WHERE id = $1`, w.A.ID)

	// Anonymous: 401 on a tenant route and on /auth/session.
	anon := w.Anonymous(identity.OriginApp)
	problemOf(t, "anonymous tenant route", w.Do(t, anon, http.MethodGet, "/tenants/"+w.A.ID.String(), nil, nil),
		http.StatusUnauthorized, gen.ProblemCodeUnauthenticated)
	problemOf(t, "anonymous session", w.Do(t, anon, http.MethodGet, "/auth/session", nil, nil),
		http.StatusUnauthorized, gen.ProblemCodeUnauthenticated)

	// Logout revokes the minted session at once; the other session of the tenant is untouched.
	if rec := w.Do(t, s, http.MethodPost, "/auth/logout", nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: HTTP %d %s", rec.Code, rec.Body.String())
	}
	problemOf(t, "after logout", w.Do(t, s, http.MethodGet, "/auth/session", nil, nil), http.StatusUnauthorized,
		gen.ProblemCodeUnauthenticated)
	if rec := w.Do(t, other, http.MethodGet, "/auth/session", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("other session after logout: HTTP %d", rec.Code)
	}
	// A new identity of a role (NewActor) works like the predefined ones.
	extra := w.Login(t, w.NewActor(t, authz.RoleTenantViewer, w.B))
	problemOf(t, "new viewer reads audit of B", w.Do(t, extra, http.MethodGet, "/tenants/"+w.B.ID.String()+"/audit", nil, nil),
		http.StatusNotImplemented, gen.ProblemCodeNotImplemented)
	problemOf(t, "new viewer syncs B", w.Do(t, extra, http.MethodPost, "/tenants/"+w.B.ID.String()+"/devices/sync", nil, idem()),
		http.StatusForbidden, gen.ProblemCodeForbidden)
}
