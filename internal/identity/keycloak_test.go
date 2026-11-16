package identity_test

// Integration with the real IdP of P2-T05 (Keycloak, realm tenant-a) — run on the dev/CI stack of
// tests/idp/run_dev.sh; skipped unless MG_TEST_KEYCLOAK_URL is set:
//
//	MG_TEST_KEYCLOAK_URL         https://auth.<domain> (public base URL of the IdP)
//	MG_TEST_KEYCLOAK_CONNECT     host:port actually dialled for that host (the test TLS proxy), e.g. 10.249.0.2:443
//	MG_TEST_KEYCLOAK_CAFILE      CA certificate of the test proxy
//	MG_TEST_KEYCLOAK_ADMIN_CONF  keycloak.conf of the stack (bootstrap admin, only to read the client secret and to
//	                             create/delete the test user)
//	MG_TEST_KEYCLOAK_IDP_ID      MG_IDP_ID_TENANT_A — the id the realm's redirect URI was rendered with
//
// The login goes through Keycloak's HTML forms exactly like a browser: password, mandatory TOTP enrolment (code
// computed here), then the callback of the module; a second login with the session asks prompt=login and must go
// through password + OTP again (step-up) and yield a fresh auth_time.

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is HMAC-SHA1 by definition
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

type kcEnv struct {
	base   *url.URL
	client *http.Client // TLS to the test proxy, no redirect following, no cookies
	admin  string       // bearer token of the bootstrap admin (master realm)
}

func kcSetup(t *testing.T) *kcEnv {
	t.Helper()
	raw := os.Getenv("MG_TEST_KEYCLOAK_URL")
	if raw == "" {
		t.Skip("MG_TEST_KEYCLOAK_URL not set — Keycloak integration skipped (tests/idp/run_dev.sh)")
	}
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" {
		t.Fatalf("MG_TEST_KEYCLOAK_URL %q", raw)
	}
	pem, err := os.ReadFile(os.Getenv("MG_TEST_KEYCLOAK_CAFILE")) //nolint:gosec // path given by the test operator
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no CA certificate")
	}
	connect := os.Getenv("MG_TEST_KEYCLOAK_CONNECT")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == base.Hostname()+":443" && connect != "" {
				addr = connect
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	e := &kcEnv{base: base, client: &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	conf := readKeycloakConf(t, os.Getenv("MG_TEST_KEYCLOAK_ADMIN_CONF"))
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	e.form(t, nil, "/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"},
		"client_id": {"admin-cli"}, "username": {conf["bootstrap-admin-username"]}, "password": {conf["bootstrap-admin-password"]}}, &tok)
	if tok.AccessToken == "" {
		t.Fatal("no admin token")
	}
	e.admin = tok.AccessToken
	return e
}

func readKeycloakConf(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test configuration
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && !strings.HasPrefix(strings.TrimSpace(k), "#") {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func (e *kcEnv) do(t *testing.T, jar http.CookieJar, method, target string, body io.Reader, hdr http.Header) *http.Response {
	t.Helper()
	u, err := e.base.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	// Not t.Context(): the user is deleted in a cleanup, after the test context is cancelled.
	req, err := http.NewRequestWithContext(context.Background(), method, u.String(), body)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	if jar != nil {
		for _, c := range jar.Cookies(u) {
			req.AddCookie(c) //nolint:gosec // request cookie (attributes only exist in Set-Cookie)
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u.Path, err)
	}
	if jar != nil {
		jar.SetCookies(u, resp.Cookies())
	}
	return resp
}

func (e *kcEnv) form(t *testing.T, jar http.CookieJar, target string, v url.Values, out any) {
	t.Helper()
	resp := e.do(t, jar, http.MethodPost, target, strings.NewReader(v.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: HTTP %d", target, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

// api calls the Admin REST API as the bootstrap admin and returns the response headers.
func (e *kcEnv) api(t *testing.T, method, path string, in, out any) http.Header {
	t.Helper()
	var body io.Reader
	hdr := http.Header{"Authorization": {"Bearer " + e.admin}, "Accept": {"application/json"}}
	if in != nil {
		b, _ := json.Marshal(in)
		body = strings.NewReader(string(b))
		hdr.Set("Content-Type", "application/json")
	}
	resp := e.do(t, nil, method, path, body, hdr)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.Header
}

// totp generates RFC 6238 codes (SHA-1, 6 digits, 30 s) strictly increasing in counter: Keycloak refuses a code
// twice (otpPolicyCodeReusable=false) and accepts the current or the next period.
type totp struct {
	key  []byte
	last int64
}

func (o *totp) code() string {
	for {
		now := time.Now().Unix() / 30
		for _, c := range []int64{now, now + 1} {
			if c > o.last {
				o.last = c
				m := hmac.New(sha1.New, o.key)
				_ = binary.Write(m, binary.BigEndian, c)
				sum := m.Sum(nil)
				off := sum[len(sum)-1] & 0x0f
				v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
				return fmt.Sprintf("%06d", v%1000000)
			}
		}
		time.Sleep(time.Until(time.Unix((now+1)*30, 0)) + 500*time.Millisecond)
	}
}

var (
	formRE  = regexp.MustCompile(`(?is)<form\b([^>]*)>|</form>|<input\b([^>]*)>`)
	attrRE  = regexp.MustCompile(`(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*"([^"]*)"`)
	checkRE = regexp.MustCompile(`(?i)\bchecked\b`)
)

type htmlForm struct {
	action string
	inputs map[string]string
}

// parseForms extracts the forms of a Keycloak page (action and named inputs).
func parseForms(page string) []htmlForm {
	var forms []htmlForm
	var cur *htmlForm
	for _, m := range formRE.FindAllStringSubmatch(page, -1) {
		switch {
		case strings.HasPrefix(strings.ToLower(m[0]), "<form"):
			a := attrs(m[1])
			forms = append(forms, htmlForm{action: a["action"], inputs: map[string]string{}})
			cur = &forms[len(forms)-1]
		case strings.HasPrefix(m[0], "</"):
			cur = nil
		case cur != nil:
			a := attrs(m[2])
			typ := strings.ToLower(a["type"])
			if a["name"] == "" || typ == "submit" || typ == "button" || typ == "image" || typ == "reset" ||
				((typ == "checkbox" || typ == "radio") && !checkRE.MatchString(m[2])) {
				continue
			}
			cur.inputs[a["name"]] = a["value"]
		}
	}
	return forms
}

func attrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRE.FindAllStringSubmatch(s, -1) {
		out[strings.ToLower(m[1])] = html.UnescapeString(m[2])
	}
	return out
}

func formWith(forms []htmlForm, names ...string) *htmlForm {
	for i := range forms {
		ok := true
		for _, n := range names {
			if _, has := forms[i].inputs[n]; !has {
				ok = false
			}
		}
		if ok {
			return &forms[i]
		}
	}
	return nil
}

// kcBrowserLogin drives Keycloak from the authorization URL to the redirect back to the Portal; it returns the
// redirect URL and the steps taken.
func (e *kcEnv) kcBrowserLogin(t *testing.T, jar http.CookieJar, authURL, user, password string, otp *totp, portal string) (*url.URL, []string) {
	t.Helper()
	var steps []string
	resp := e.do(t, jar, http.MethodGet, authURL, nil, nil)
	for range 12 {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if loc.Host == portal {
				return loc, steps
			}
			resp = e.do(t, jar, http.MethodGet, loc.String(), nil, nil)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Keycloak HTTP %d at step %v", resp.StatusCode, steps)
		}
		forms := parseForms(string(body))
		post := func(f *htmlForm, step string, set map[string]string) {
			v := url.Values{}
			for k, val := range f.inputs {
				v.Set(k, val)
			}
			for k, val := range set {
				v.Set(k, val)
			}
			steps = append(steps, step)
			resp = e.do(t, jar, http.MethodPost, f.action, strings.NewReader(v.Encode()), //nolint:bodyclose // closed at the top of the next iteration
				http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		}
		if f := formWith(forms, "password"); f != nil && formWith(forms, "totp") == nil {
			set := map[string]string{"password": password}
			if _, ok := f.inputs["username"]; ok {
				set["username"] = user
			}
			post(f, "password", set)
			continue
		}
		if f := formWith(forms, "totp", "totpSecret"); f != nil {
			otp.key = []byte(f.inputs["totpSecret"])
			post(f, "configure_totp", map[string]string{"totp": otp.code(), "userLabel": "p2t06-test"})
			continue
		}
		if f := formWith(forms, "otp"); f != nil {
			post(f, "otp", map[string]string{"otp": otp.code()})
			continue
		}
		t.Fatalf("unexpected Keycloak page after %v (%d forms)", steps, len(forms))
	}
	t.Fatalf("too many Keycloak steps: %v", steps)
	return nil, nil
}

// kcRealm prepares one realm of the stack: client secret of mg-portal (Keycloak generated it at import; production
// reads it from the SecretStore) and a test user (random password; CONFIGURE_TOTP is a default required action).
func (e *kcEnv) kcRealm(t *testing.T, realm string) (secret, username, password string) {
	t.Helper()
	var clients []struct {
		ID string `json:"id"`
	}
	e.api(t, http.MethodGet, "/admin/realms/"+realm+"/clients?clientId=mg-portal", nil, &clients)
	if len(clients) != 1 {
		t.Fatal("mg-portal not found")
	}
	var sec struct {
		Value string `json:"value"`
	}
	e.api(t, http.MethodGet, "/admin/realms/"+realm+"/clients/"+clients[0].ID+"/client-secret", nil, &sec)
	if sec.Value == "" {
		t.Fatal("no client secret")
	}
	username, password = "p2t06-"+identity.RandomHex(4), identity.RandomHex(16)
	hdr := e.api(t, http.MethodPost, "/admin/realms/"+realm+"/users", map[string]any{
		"username": username, "email": username + "@example.invalid", "emailVerified": true, "enabled": true,
		"firstName": "P2T06", "lastName": "Test",
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	}, nil)
	loc := hdr.Get("Location")
	userID := loc[strings.LastIndex(loc, "/")+1:]
	t.Cleanup(func() {
		r := e.do(t, nil, http.MethodDelete, "/admin/realms/"+realm+"/users/"+userID, nil,
			http.Header{"Authorization": {"Bearer " + e.admin}})
		_ = r.Body.Close()
	})
	return sec.Value, username, password
}

// kcService builds the module (real PostgreSQL, the IdP reached through the test proxy) for one client secret.
func (e *kcEnv) kcService(t *testing.T, pg *identity.PGEnv, ref, secret string) *env {
	t.Helper()
	domain := strings.TrimPrefix(e.base.Hostname(), "auth.")
	audit := &auditLog{}
	svc, err := identity.New(pg.Store(t), identity.Config{
		AppHost: "app." + domain, AdminHost: "admin." + domain,
		HTTPClient: &http.Client{Transport: e.client.Transport, Timeout: 15 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, r string) (string, error) {
			if r != ref {
				return "", fmt.Errorf("unknown ref")
			}
			return secret, nil
		}),
		Auditor: audit, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	en := &env{t: t, pg: pg, db: pg.Admin(t), clock: newClock(), audit: audit, svc: svc}
	en.h = svc.Middleware(gen.HandlerWithOptions(gen.NewStrictHandler(apiServer{Handlers: identityapi.New(svc)}, nil),
		gen.StdHTTPServerOptions{BaseURL: "/api/v1"}))
	return en
}

func idFromEnv(t *testing.T, name string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(os.Getenv(name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return id
}

// TestKeycloakTenantLoginEndToEnd — P2-T05 realm tenant-a: login through the forms with mandatory TOTP, callback of
// the module, session; then step-up with prompt=login (password + OTP again, fresh auth_time); logout.
func TestKeycloakTenantLoginEndToEnd(t *testing.T) {
	kc := kcSetup(t)
	idpID := idFromEnv(t, "MG_TEST_KEYCLOAK_IDP_ID")
	app := "app." + strings.TrimPrefix(kc.base.Hostname(), "auth.")
	realm := "tenant-a"
	issuer := kc.base.String() + "/realms/" + realm
	secret, username, password := kc.kcRealm(t, realm)

	// Database: tenant + IdP row with the id the realm's redirect URI was rendered with.
	pg := identity.RequirePG(t)
	db := pg.Admin(t)
	tenantID := uuid.Must(uuid.NewV7())
	slug := "kc" + identity.RandomHex(4)
	identity.Exec(t, db, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, 'Keycloak tenant-a', 'active')`, tenantID, slug)
	ref := "mgsec://" + tenantID.String() + "/idp-client#1"
	identity.Exec(t, db, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', $4, 'keycloak', 'active')`, idpID, tenantID, issuer, ref)
	e := kc.kcService(t, pg, ref, secret)
	svc, audit := e.svc, e.audit
	b := e.browser()
	kcJar, _ := cookiejar.New(nil)
	otp := &totp{}

	// Login 1: password + mandatory TOTP enrolment.
	start := b.startLogin(app, "scope=tenant&tenant="+slug+"&return_to=%2Fdashboard")
	wantStatus(t, "login", start.Code, http.StatusFound, start.Body.String())
	authURL, q := locationQuery(t, start.Header().Get("Location"))
	if !strings.HasPrefix(authURL.String(), issuer+"/protocol/openid-connect/auth?") || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != redirectURI(app, idpID) {
		t.Fatalf("authorization request %s", authURL)
	}
	cb, steps := kc.kcBrowserLogin(t, kcJar, authURL.String(), username, password, otp, app)
	t.Logf("login 1 steps: %v; callback params: %v", steps, keys(cb.Query()))
	if cb.Query().Get("iss") != issuer {
		t.Fatalf("Keycloak did not send iss = %s (RFC 9207)", issuer)
	}
	rec := b.get(cb.String())
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback: HTTP %d %s (audit %+v)", rec.Code, rec.Body.String(), audit.last(identity.ActionLogin))
	}
	r1, s1 := b.session(app)
	wantStatus(t, "session", r1.Code, http.StatusOK, r1.Body.String())
	if s1.Principal.IdpId != idpID || s1.Principal.Scope != "tenant" || s1.Principal.Email == nil ||
		*s1.Principal.Email != username+"@example.invalid" || s1.Principal.DisplayName != "P2T06 Test" || s1.CsrfToken != b.csrf(app) {
		t.Fatalf("session %+v", s1)
	}
	if time.Since(s1.AuthTime) > time.Minute {
		t.Fatalf("auth_time %v", s1.AuthTime)
	}
	sess1 := authenticate(t, e, b, app, identity.OriginApp)
	if err := svc.RequireRecentAuth(sess1); err != nil {
		t.Fatalf("fresh Keycloak login is not a recent authentication: %v", err)
	}
	t.Logf("session 1: identity %s auth_time %s acr %q", s1.Principal.IdentityId, s1.AuthTime.Format(time.RFC3339), sess1.ACR)

	// Login 2 with the session: prompt=login + max_age=0 — Keycloak must ask for the password and the OTP again
	// although its SSO session is alive, and return a newer auth_time.
	time.Sleep(1100 * time.Millisecond)
	start = b.startLogin(app, "scope=tenant&tenant="+slug)
	authURL, q = locationQuery(t, start.Header().Get("Location"))
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("step-up request %v", q)
	}
	cb, steps = kc.kcBrowserLogin(t, kcJar, authURL.String(), username, password, otp, app)
	t.Logf("step-up steps: %v", steps)
	if len(steps) < 2 || steps[0] != "password" || steps[len(steps)-1] != "otp" {
		t.Fatalf("Keycloak did not re-authenticate: %v", steps)
	}
	old := b.cookie(app, identity.SessionCookieName)
	rec = b.get(cb.String())
	wantStatus(t, "step-up callback", rec.Code, http.StatusFound, rec.Body.String())
	_, s2 := b.session(app)
	if !s2.AuthTime.After(s1.AuthTime) || s2.Principal.IdentityId != s1.Principal.IdentityId {
		t.Fatalf("step-up auth_time %v (before %v)", s2.AuthTime, s1.AuthTime)
	}
	if _, err := svc.Authenticate(context.Background(), old, identity.OriginApp); err == nil {
		t.Fatal("pre-step-up session still valid")
	}
	t.Logf("session 2: auth_time %s (was %s)", s2.AuthTime.Format(time.RFC3339), s1.AuthTime.Format(time.RFC3339))

	// Logout revokes the session server-side.
	rec = b.do(http.MethodPost, "https://"+app+"/api/v1/auth/logout", unsafeHeaders(app, b.csrf(app)))
	wantStatus(t, "logout", rec.Code, http.StatusNoContent, rec.Body.String())
	if r, _ := b.session(app); r.Code != http.StatusUnauthorized {
		t.Fatal("session alive after logout")
	}
}

// TestKeycloakPlatformLoginOriginBound — realm platform on the admin origin (MG_TEST_KEYCLOAK_PLATFORM_IDP_ID): a
// real platform session works on admin and is refused on app.
func TestKeycloakPlatformLoginOriginBound(t *testing.T) {
	kc := kcSetup(t)
	idpID := idFromEnv(t, "MG_TEST_KEYCLOAK_PLATFORM_IDP_ID")
	domain := strings.TrimPrefix(kc.base.Hostname(), "auth.")
	app, admin := "app."+domain, "admin."+domain
	issuer := kc.base.String() + "/realms/platform"
	secret, username, password := kc.kcRealm(t, "platform")

	pg := identity.RequirePG(t)
	platformMu.Lock()
	defer platformMu.Unlock()
	db := pg.Admin(t)
	identity.Exec(t, db, `UPDATE identity_providers SET status = 'disabled' WHERE scope = 'platform' AND status = 'active'`)
	ref := "mgsec://platform/idp-client-kc#1"
	identity.Exec(t, db, `INSERT INTO identity_providers (id, scope, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'platform', $2, 'mg-portal', $3, 'keycloak', 'active')`, idpID, issuer, ref)
	defer identity.Exec(t, db, `UPDATE identity_providers SET status = 'disabled' WHERE id = $1`, idpID)
	e := kc.kcService(t, pg, ref, secret)
	b := e.browser()
	kcJar, _ := cookiejar.New(nil)

	start := b.startLogin(admin, "scope=platform")
	wantStatus(t, "login", start.Code, http.StatusFound, start.Body.String())
	authURL, q := locationQuery(t, start.Header().Get("Location"))
	if q.Get("redirect_uri") != redirectURI(admin, idpID) || q.Get("max_age") != "28800" {
		t.Fatalf("authorization request %s", authURL)
	}
	cb, steps := kc.kcBrowserLogin(t, kcJar, authURL.String(), username, password, &totp{}, admin)
	t.Logf("platform login steps: %v", steps)
	rec := b.get(cb.String())
	wantStatus(t, "callback", rec.Code, http.StatusFound, rec.Body.String())
	r, s := b.session(admin)
	wantStatus(t, "session on admin", r.Code, http.StatusOK, r.Body.String())
	if s.Principal.Scope != "platform" || s.Origin != "admin" || s.Principal.IdpId != idpID {
		t.Fatalf("platform session %+v", s)
	}
	stolen := e.browser()
	stolen.setCookie(app, identity.SessionCookieName, b.cookie(admin, identity.SessionCookieName))
	if r, _ := stolen.session(app); r.Code != http.StatusUnauthorized {
		t.Fatalf("platform session accepted on app: HTTP %d", r.Code)
	}
	t.Logf("platform session: origin %s; same cookie on %s: HTTP 401", s.Origin, app)
}

func keys(v url.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	return out
}
