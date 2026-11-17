//go:build mgtestfixture

// Package oidclogin_test holds the one real OpenID Connect login of P2-T15a: through the public API of MeshGuard as
// the api process composes it (httpapi.New + identityapi + authzhook, built by tests/security/sessionfixture) against
// the Keycloak of the dev/CI stack (tests/idp/run_dev.sh: image built from infrastructure/docker/idp, realms rendered
// from infrastructure/idp/realms by tools/render_idp.py), with the mandatory TOTP of the realm templates.
//
// Skipped unless MG_TEST_KEYCLOAK_URL is set — CI has no Keycloak — with the variables of the Keycloak tests of
// internal/identity:
//
//	MG_TEST_KEYCLOAK_URL         https://auth.<domain> (public base URL of the IdP; app.<domain> is the Portal)
//	MG_TEST_KEYCLOAK_CONNECT     host:port actually dialled for that host (the test TLS proxy)
//	MG_TEST_KEYCLOAK_CAFILE      CA certificate of the test proxy
//	MG_TEST_KEYCLOAK_ADMIN_CONF  keycloak.conf of the stack (bootstrap admin: client secret, test user)
//	MG_TEST_KEYCLOAK_IDP_ID      MG_IDP_ID_TENANT_A — the id the realm's redirect URI was rendered with
package oidclogin_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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

// apiBrowser is a minimal user agent of our API: host-only cookie jar, no redirect following.
type apiBrowser struct {
	t   *testing.T
	w   *sessionfixture.World
	jar map[string]map[string]string
}

func (b *apiBrowser) do(method, rawURL string, hdr http.Header) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), method, rawURL, nil)
	req.Header.Set("User-Agent", "p2t15a-oidc-test/1.0")
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v) // canonical key (X-CSRF-Token → X-Csrf-Token)
		}
	}
	for name, value := range b.jar[req.Host] {
		req.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // request cookie (attributes only exist in Set-Cookie)
	}
	rec := httptest.NewRecorder()
	b.w.API.ServeHTTP(rec, req)
	for _, line := range rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			b.t.Fatalf("bad Set-Cookie: %v", err)
		}
		if b.jar[req.Host] == nil {
			b.jar[req.Host] = map[string]string{}
		}
		if c.MaxAge < 0 {
			delete(b.jar[req.Host], c.Name)
		} else {
			b.jar[req.Host][c.Name] = c.Value
		}
	}
	return rec
}

// setCookie returns the parsed Set-Cookie of name in rec (fails when absent or repeated).
func setCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) (*http.Cookie, string) {
	t.Helper()
	var found *http.Cookie
	var raw string
	for _, line := range rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatal(err)
		}
		if c.Name == name {
			if found != nil {
				t.Fatalf("two Set-Cookie for %s", name)
			}
			found, raw = c, line
		}
	}
	if found == nil {
		t.Fatalf("no Set-Cookie for %s (HTTP %d)", name, rec.Code)
	}
	return found, raw
}

// hostCookie checks the attributes §8.3 step 4 gives Portal cookies: __Host- prefix rules (Secure, Path=/, no
// Domain), HttpOnly, SameSite=Lax.
func hostCookie(t *testing.T, what string, c *http.Cookie, raw string) {
	t.Helper()
	if !strings.HasPrefix(c.Name, "__Host-") || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode ||
		c.Path != "/" || c.Domain != "" || strings.Contains(strings.ToLower(raw), "domain=") {
		t.Errorf("%s: cookie attributes %+v (Secure %v, HttpOnly %v, SameSite %v, Path %q, Domain %q)", what, c.Name,
			c.Secure, c.HttpOnly, c.SameSite, c.Path, c.Domain)
	}
}

// TestKeycloakLoginThroughTheAPI — GET /api/v1/auth/login → Keycloak login form → mandatory TOTP enrolment → callback
// → __Host-mg_session → GET /api/v1/auth/session 200, through the composed API. Checks: the authorization request
// (issuer's endpoint, PKCE S256, exact redirect URI, max_age), the cookie flags, the issuer (discovery = stored issuer
// = RFC 9207 iss of the callback; the identity is the realm user's sub), the session's binding to the app origin
// (sessions.origin, 401 on admin), and that the real session goes through authz like a minted one.
func TestKeycloakLoginThroughTheAPI(t *testing.T) {
	kc := kcSetup(t)
	idpID, err := uuid.Parse(os.Getenv("MG_TEST_KEYCLOAK_IDP_ID"))
	if err != nil {
		t.Fatalf("MG_TEST_KEYCLOAK_IDP_ID: %v", err)
	}
	domain := strings.TrimPrefix(kc.base.Hostname(), "auth.")
	appHost, adminHost := "app."+domain, "admin."+domain
	const realm = "tenant-a"
	issuer := kc.base.String() + "/realms/" + realm

	// The issuer Keycloak publishes for the realm.
	var disc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	resp := kc.do(t, nil, http.MethodGet, "/realms/"+realm+"/.well-known/openid-configuration", nil, nil)
	err = json.NewDecoder(resp.Body).Decode(&disc)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || disc.Issuer != issuer ||
		!strings.HasPrefix(disc.AuthorizationEndpoint, issuer+"/") {
		t.Fatalf("discovery of %s: HTTP %d, issuer %q, authorization endpoint %q (%v)", realm, resp.StatusCode,
			disc.Issuer, disc.AuthorizationEndpoint, err)
	}
	secret, user := kc.kcRealm(t, realm)

	// Our API on a fresh database; the tenant's IdP row is the realm, with the id its redirect URI was rendered with.
	tenantID := uuid.Must(uuid.NewV7())
	slug := "kc-" + randomHex(4)
	ref := "mgsec://" + tenantID.String() + "/idp." + idpID.String() + ".client#1" // the IdP's own secret (G2 F3)
	w := sessionfixture.New(t, sessionfixture.Options{
		AppHost: appHost, AdminHost: adminHost,
		HTTPClient: &http.Client{Transport: kc.client.Transport, Timeout: 15 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, r string) (string, error) {
			if r != ref {
				return "", errors.New("unknown secret ref")
			}
			return secret, nil
		}),
	})
	w.Exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, 'Keycloak tenant-a', 'active')`, tenantID, slug)
	w.Exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', $4, 'keycloak', 'active')`, idpID, tenantID, issuer, ref)
	b := &apiBrowser{t: t, w: w, jar: map[string]map[string]string{}}
	api := "https://" + appHost + "/api/v1"

	// 1. GET /auth/login: 302 to the realm's authorization endpoint, browser-binding cookie.
	start := b.do(http.MethodGet, api+"/auth/login?scope=tenant&tenant="+slug+"&return_to=%2Fdevices", nil)
	if start.Code != http.StatusFound {
		t.Fatalf("GET /auth/login: HTTP %d %s", start.Code, start.Body.String())
	}
	authURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := authURL.Query()
	if !strings.HasPrefix(authURL.String(), disc.AuthorizationEndpoint+"?") || q.Get("response_type") != "code" ||
		q.Get("client_id") != "mg-portal" || q.Get("redirect_uri") != "https://"+appHost+"/api/v1/auth/callback/"+idpID.String() ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" ||
		q.Get("state") == "" || q.Get("max_age") != "43200" || !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		t.Fatalf("authorization request: endpoint %s, parameters %v", authURL.Path, keys(q))
	}
	c, raw := setCookie(t, start, identity.AuthRequestCookieName)
	hostCookie(t, "binding cookie", c, raw)
	if c.MaxAge != 600 {
		t.Errorf("binding cookie Max-Age %d, want 600", c.MaxAge)
	}

	// 2. Keycloak: password, then the mandatory TOTP enrolment of a new user (code computed here, RFC 6238).
	cb, steps := kc.browserLogin(t, authURL.String(), user, &totp{}, appHost)
	t.Logf("Keycloak steps: %v; callback parameters: %v", steps, keys(cb.Query()))
	if strings.Join(steps, ",") != "password,configure_totp" {
		t.Fatalf("Keycloak steps %v, want password then the TOTP enrolment", steps)
	}
	if cb.Path != "/api/v1/auth/callback/"+idpID.String() || cb.Query().Get("iss") != issuer ||
		cb.Query().Get("state") != q.Get("state") || cb.Query().Get("code") == "" {
		t.Fatalf("callback %s with parameters %v (iss = issuer: %v)", cb.Path, keys(cb.Query()), cb.Query().Get("iss") == issuer)
	}

	// 3. Callback through our API: 302 to return_to, __Host-mg_session set, binding cookie deleted.
	rec := b.do(http.MethodGet, cb.String(), nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/devices" {
		t.Fatalf("callback: HTTP %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("callback headers %v", rec.Header())
	}
	sc, raw := setCookie(t, rec, identity.SessionCookieName)
	hostCookie(t, "session cookie", sc, raw)
	if sc.MaxAge != 0 || !sc.Expires.IsZero() || strings.Contains(raw, "Max-Age") || strings.Contains(raw, "Expires") {
		t.Errorf("session cookie must be a browser-session cookie (no Max-Age/Expires): %v %v", sc.MaxAge, sc.Expires)
	}
	rawID, err := base64.RawURLEncoding.DecodeString(sc.Value)
	if err != nil || len(rawID) != 32 {
		t.Fatalf("session cookie value is not 256 bits of base64url (%d bytes)", len(rawID))
	}
	if del, _ := setCookie(t, rec, identity.AuthRequestCookieName); del.MaxAge >= 0 {
		t.Errorf("binding cookie not deleted (Max-Age %d)", del.MaxAge)
	}

	// 4. GET /auth/session: 200, the realm user, origin app, the CSRF token of §8.3 step 8.
	rec = b.do(http.MethodGet, api+"/auth/session", nil)
	var s gen.Session
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &s) != nil {
		t.Fatalf("GET /auth/session: HTTP %d %s", rec.Code, rec.Body.String())
	}
	mac := hmac.New(sha256.New, rawID)
	_, _ = mac.Write([]byte("csrf-v1"))
	if s.Origin != "app" || s.Principal.IdpId != idpID || s.Principal.Scope != "tenant" || s.Principal.Email == nil ||
		*s.Principal.Email != user.username+"@example.invalid" || s.Principal.DisplayName != "P2T15a Login" ||
		s.CsrfToken != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) || len(s.Memberships) != 0 ||
		time.Since(s.AuthTime) > 2*time.Minute {
		t.Fatalf("session: origin %s, principal %+v, %d memberships, auth_time %v", s.Origin, s.Principal, len(s.Memberships), s.AuthTime)
	}
	if line := w.AccessLine(t, rec.Header().Get("X-Request-Id")); line["identity"] != s.Principal.IdentityId.String() ||
		line["operation"] != "GetAuthSession" {
		t.Errorf("access line of GET /auth/session: %v", line)
	}

	// 5. Issuer and storage: the identity is (this IdP, the realm user's sub); the session row holds only the hash and
	// is bound to app.
	var subject, origin, idpIssuer string
	sum := sha256.Sum256(rawID)
	w.Scan(t, `SELECT i.subject, s.origin, p.issuer FROM sessions s
			JOIN identities i ON i.id = s.identity_id JOIN identity_providers p ON p.id = s.idp_id
		WHERE s.id_hash = $1 AND i.id = $2 AND s.revoked_at IS NULL`, []any{sum[:], s.Principal.IdentityId},
		&subject, &origin, &idpIssuer)
	if subject != user.id || origin != "app" || idpIssuer != issuer {
		t.Fatalf("stored session: subject is the realm user %v, origin %s, issuer is the realm %v", subject == user.id,
			origin, idpIssuer == issuer)
	}
	var row string
	w.Scan(t, `SELECT s::text FROM sessions s WHERE s.id_hash = $1`, []any{sum[:]}, &row)
	if strings.Contains(row, sc.Value) || strings.Contains(row, base64.StdEncoding.EncodeToString(rawID)) {
		t.Fatal("the sessions row holds the raw session id")
	}

	// 6. Origin binding: the same cookie on the admin origin is no session (§8.3 step 8).
	stolen := &apiBrowser{t: t, w: w, jar: map[string]map[string]string{adminHost: {identity.SessionCookieName: sc.Value}}}
	if rec := stolen.do(http.MethodGet, "https://"+adminHost+"/api/v1/auth/session", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("app session on admin: HTTP %d", rec.Code)
	}

	// 7. The real session through authz: Owner of its tenant ⇒ granted (501, no handler yet); tenant B of the world
	// ⇒ 404; a platform route ⇒ 403.
	w.Exec(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
		SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3`, tenantID, s.Principal.IdentityId,
		authz.RoleTenantOwner)
	for path, want := range map[string]int{
		"/tenants/" + tenantID.String(): http.StatusNotImplemented,
		"/tenants/" + w.B.ID.String():   http.StatusNotFound,
		"/platform/tenants":             http.StatusForbidden,
	} {
		if rec := b.do(http.MethodGet, api+path, nil); rec.Code != want {
			t.Errorf("GET %s: HTTP %d, want %d", path, rec.Code, want)
		}
	}

	// 8. Logout through the API (CSRF + Origin): the session is revoked at once — the old cookie replayed is refused.
	hdr := http.Header{"Origin": {"https://" + appHost}, identity.CSRFHeader: {s.CsrfToken}}
	// G2 round 2, A-1: 200 with the redirect that ends the Keycloak session too (end_session_endpoint + id_token_hint)
	if rec := b.do(http.MethodPost, api+"/auth/logout", hdr); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "/protocol/openid-connect/logout?") ||
		!strings.Contains(rec.Body.String(), "id_token_hint=") {
		t.Fatalf("logout: HTTP %d (redirect_to not the end_session_endpoint with a hint)", rec.Code)
	}
	replay := &apiBrowser{t: t, w: w, jar: map[string]map[string]string{appHost: {identity.SessionCookieName: sc.Value}}}
	if rec := replay.do(http.MethodGet, api+"/auth/session", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after logout: HTTP %d", rec.Code)
	}
	t.Logf("session: identity %s, origin %s, auth_time %s; same cookie on %s: 401", s.Principal.IdentityId, s.Origin,
		s.AuthTime.UTC().Format(time.RFC3339), adminHost)
}

func keys(v url.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	return out
}
