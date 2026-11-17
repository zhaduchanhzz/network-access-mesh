package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return b
}

func locationQuery(t *testing.T, loc string) (*url.URL, url.Values) {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u, u.Query()
}

// setCookies returns the parsed Set-Cookie headers of a response by name.
func setCookies(t *testing.T, h http.Header) map[string]*http.Cookie {
	t.Helper()
	out := map[string]*http.Cookie{}
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatalf("Set-Cookie %q: %v", line, err)
		}
		out[c.Name] = c
	}
	return out
}

func wantStatus(t *testing.T, what string, got, want int, body string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: HTTP %d, want %d: %s", what, got, want, body)
	}
}

// wantDenied checks a refused callback: status, problem code, the audited reason and that no session was set.
func wantDenied(t *testing.T, e *env, b *browser, host string, rec interface {
	Result() *http.Response
}, status int, code, reason string) {
	t.Helper()
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	var body bytes.Buffer
	_, _ = body.ReadFrom(res.Body)
	if res.StatusCode != status {
		t.Fatalf("HTTP %d, want %d: %s", res.StatusCode, status, body.String())
	}
	var p struct{ Code string }
	_ = json.Unmarshal(body.Bytes(), &p)
	if p.Code != code {
		t.Fatalf("problem code %q, want %q", p.Code, code)
	}
	if got := e.audit.last(identity.ActionLogin).Reason; reason != "" && got != reason {
		t.Fatalf("audited reason %q, want %q", got, reason)
	}
	if b.cookie(host, identity.SessionCookieName) != "" {
		t.Fatal("a session cookie was set")
	}
}

// TestLoginEndToEnd — §8.3 steps 1–4 on the tenant origin: authorization request (PKCE S256, state, nonce, max_age),
// auth_requests row, binding cookie, callback, session stored as a hash, GET /auth/session.
func TestLoginEndToEnd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	user := identity.FakeUser{Sub: "sub-" + identity.RandomHex(4), Email: "Alice@Example.test", EmailVerified: true, Name: "Alice"}
	fake.SetUser(user)
	// Pre-provisioned identity + membership (Phase 2 seed by (IdP, sub) — §8.2); the login matches it by (idp_id, sub).
	identID, membID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	e.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', $4)`,
		identID, ten.IdP, ten.ID, user.Sub)
	e.exec(`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id) VALUES ($1, $2, $3, $4)`,
		membID, ten.ID, identID, ten.Role)

	b := e.browser()
	start := b.startLogin(appHost, "scope=tenant&tenant="+ten.Slug+"&return_to="+url.QueryEscape("/devices?page=2"))
	wantStatus(t, "login", start.Code, http.StatusFound, start.Body.String())
	loc, q := locationQuery(t, start.Header().Get("Location"))
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != fake.Issuer+"/authorize" {
		t.Fatalf("redirect to %s", got)
	}
	for k, want := range map[string]string{
		"client_id": ten.ClientID, "redirect_uri": redirectURI(appHost, ten.IdP), "response_type": "code",
		"code_challenge_method": "S256", "max_age": "43200",
	} {
		if q.Get(k) != want {
			t.Errorf("authorization request %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("prompt") != "" {
		t.Errorf("prompt = %q on a first login", q.Get("prompt"))
	}
	if !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		t.Errorf("scope %q lacks openid", q.Get("scope"))
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if len(decodeB64(t, q.Get(k))) != 32 {
			t.Errorf("%s is not 256 bits", k)
		}
	}
	state := decodeB64(t, q.Get("state"))
	var (
		nonce, origin string
		sealed        []byte
		ttl           float64
	)
	if err := e.db.QueryRow(context.Background(), `SELECT nonce, origin, pkce_verifier_enc,
			EXTRACT(EPOCH FROM expires_at - created_at)::float8
		FROM auth_requests WHERE state_hash = $1 AND idp_id = $2 AND consumed_at IS NULL`, sha(state), ten.IdP).
		Scan(&nonce, &origin, &sealed, &ttl); err != nil {
		t.Fatalf("auth_requests row: %v", err)
	}
	if nonce != q.Get("nonce") || origin != "app" || ttl != 600 {
		t.Errorf("auth_requests nonce/origin/ttl = %q/%q/%v", nonce, origin, ttl)
	}
	binding := b.cookie(appHost, identity.AuthRequestCookieName)
	if len(decodeB64(t, binding)) != 32 {
		t.Fatal("binding cookie is not 256 bits")
	}
	if n := e.count(`SELECT count(*) FROM auth_requests WHERE browser_binding_hash = $1`, sha(decodeB64(t, binding))); n != 1 {
		t.Errorf("binding hash rows = %d", n)
	}

	cb := b.get(b.authorize(loc.String()).String())
	wantStatus(t, "callback", cb.Code, http.StatusFound, cb.Body.String())
	if got := cb.Header().Get("Location"); got != "/devices?page=2" {
		t.Errorf("callback redirects to %q", got)
	}
	if fake.TokenCalls.Load() != 1 {
		t.Errorf("token calls = %d", fake.TokenCalls.Load())
	}
	// PKCE S256: the verifier received by the token endpoint matches the challenge; the database never holds it.
	verifier := fake.LastVerifier()
	if c := sha([]byte(verifier)); base64.RawURLEncoding.EncodeToString(c) != q.Get("code_challenge") {
		t.Error("code_challenge is not S256(verifier)")
	}
	if bytes.Contains(sealed, []byte(verifier)) {
		t.Error("pkce_verifier_enc contains the plaintext verifier")
	}
	if n := e.count(`SELECT count(*) FROM auth_requests WHERE state_hash = $1 AND consumed_at IS NOT NULL`, sha(state)); n != 1 {
		t.Error("auth request not consumed")
	}
	raw := decodeB64(t, b.cookie(appHost, identity.SessionCookieName))
	if len(raw) != 32 {
		t.Fatal("session id is not 256 bits")
	}
	if b.cookie(appHost, identity.AuthRequestCookieName) != "" {
		t.Error("binding cookie not deleted")
	}
	// Only the hash of the session id is stored.
	if n := e.count(`SELECT count(*) FROM sessions WHERE id_hash = $1 AND identity_id = $2 AND origin = 'app'`, sha(raw), identID); n != 1 {
		t.Fatalf("session row by hash = %d", n)
	}

	rec, s := b.session(appHost)
	wantStatus(t, "GET /auth/session", rec.Code, http.StatusOK, rec.Body.String())
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("GET /auth/session is cacheable")
	}
	if s.Principal.IdentityId != identID || s.Principal.IdpId != ten.IdP || s.Principal.Scope != "tenant" ||
		s.Principal.DisplayName != "Alice" || s.Principal.Email == nil || *s.Principal.Email != user.Email || s.Origin != "app" {
		t.Errorf("principal = %+v origin %s", s.Principal, s.Origin)
	}
	if s.CsrfToken != b.csrf(appHost) {
		t.Error("csrf_token is not HMAC-SHA256(session id, \"csrf-v1\")")
	}
	if len(s.Memberships) != 1 || s.Memberships[0].MembershipId != membID || s.Memberships[0].TenantSlug != ten.Slug ||
		s.Memberships[0].Role != ten.RoleKey || s.SupportGrants == nil {
		t.Errorf("memberships = %+v", s.Memberships)
	}
	if !s.AuthTime.Equal(e.clock.Now()) || !s.IdleExpiresAt.Equal(e.clock.Now().Add(30*time.Minute)) ||
		!s.AbsoluteExpiresAt.Equal(e.clock.Now().Add(12*time.Hour)) {
		t.Errorf("times: auth %v idle %v absolute %v", s.AuthTime, s.IdleExpiresAt, s.AbsoluteExpiresAt)
	}
	if n := e.count(`SELECT count(*) FROM identities WHERE id = $1 AND email = $2 AND email_verified AND last_login_at IS NOT NULL`,
		identID, user.Email); n != 1 {
		t.Error("identity profile not updated at login")
	}
	if ev := e.audit.last(identity.ActionLogin); ev.Outcome != identity.OutcomeSuccess || ev.IdentityID != identID {
		t.Errorf("audit = %+v", ev)
	}
}

// TestCallbackSingleUseStateAndBinding — test nonce/state: replay, unknown/malformed state, expiry, binding cookie,
// IdP error responses; none of them reaches the token endpoint.
func TestCallbackSingleUseStateAndBinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	query := "scope=tenant&tenant=" + ten.Slug
	callbackURL := func(state string, extra url.Values) string {
		v := url.Values{"state": {state}}
		for k, vs := range extra {
			v[k] = vs
		}
		return "https://" + appHost + "/api/v1/auth/callback/" + ten.IdP.String() + "?" + v.Encode()
	}
	noTokenCall := func(t *testing.T, before int32) {
		t.Helper()
		if got := fake.TokenCalls.Load(); got != before {
			t.Fatalf("token endpoint called (%d → %d)", before, got)
		}
	}

	t.Run("replayed callback", func(t *testing.T) {
		b := e.browser()
		start := b.startLogin(appHost, query)
		binding := b.cookie(appHost, identity.AuthRequestCookieName)
		cb := b.authorize(start.Header().Get("Location"))
		wantStatus(t, "first callback", b.get(cb.String()).Code, http.StatusFound, "")
		before := fake.TokenCalls.Load()
		attacker := e.browser() // same URL and binding cookie, presented again
		attacker.setCookie(appHost, identity.AuthRequestCookieName, binding)
		wantDenied(t, e, attacker, appHost, attacker.get(cb.String()), http.StatusUnauthorized, "unauthenticated", "state_unknown_or_used")
		noTokenCall(t, before)
	})
	t.Run("unknown state", func(t *testing.T) {
		b := e.browser()
		b.startLogin(appHost, query)
		before := fake.TokenCalls.Load()
		state := base64.RawURLEncoding.EncodeToString(sha([]byte(identity.RandomHex(8))))
		wantDenied(t, e, b, appHost, b.get(callbackURL(state, url.Values{"code": {"x"}})), http.StatusUnauthorized, "unauthenticated", "state_unknown_or_used")
		noTokenCall(t, before)
	})
	t.Run("malformed state", func(t *testing.T) {
		b := e.browser()
		before := fake.TokenCalls.Load()
		wantDenied(t, e, b, appHost, b.get(callbackURL("not-a-state", url.Values{"code": {"x"}})), http.StatusUnauthorized, "unauthenticated", "state_malformed")
		noTokenCall(t, before)
	})
	t.Run("expired auth request", func(t *testing.T) {
		b := e.browser()
		start := b.startLogin(appHost, query)
		cb := b.authorize(start.Header().Get("Location"))
		e.clock.Advance(10*time.Minute + time.Second)
		before := fake.TokenCalls.Load()
		wantDenied(t, e, b, appHost, b.get(cb.String()), http.StatusUnauthorized, "unauthenticated", "auth_request_expired")
		noTokenCall(t, before)
	})
	t.Run("missing binding cookie", func(t *testing.T) {
		b := e.browser()
		start := b.startLogin(appHost, query)
		cb := b.authorize(start.Header().Get("Location"))
		delete(b.jar[appHost], identity.AuthRequestCookieName)
		before := fake.TokenCalls.Load()
		wantDenied(t, e, b, appHost, b.get(cb.String()), http.StatusUnauthorized, "unauthenticated", "browser_binding_mismatch")
		noTokenCall(t, before)
	})
	t.Run("binding cookie of another browser", func(t *testing.T) {
		victim, attacker := e.browser(), e.browser()
		start := victim.startLogin(appHost, query)
		attacker.startLogin(appHost, query) // the attacker has a binding cookie of its own login
		cb := victim.authorize(start.Header().Get("Location"))
		before := fake.TokenCalls.Load()
		wantDenied(t, e, attacker, appHost, attacker.get(cb.String()), http.StatusUnauthorized, "unauthenticated", "browser_binding_mismatch")
		noTokenCall(t, before)
	})
	t.Run("error response of the IdP", func(t *testing.T) {
		b := e.browser()
		_, q := locationQuery(t, b.startLogin(appHost, query).Header().Get("Location"))
		before := fake.TokenCalls.Load()
		rec := b.get(callbackURL(q.Get("state"), url.Values{"error": {"access_denied"}, "error_description": {"<script>"}}))
		wantDenied(t, e, b, appHost, rec, http.StatusUnauthorized, "unauthenticated", "idp_error")
		if strings.Contains(rec.Body.String(), "script") {
			t.Fatal("IdP text reflected in the problem")
		}
		noTokenCall(t, before)
	})
	t.Run("missing code", func(t *testing.T) {
		b := e.browser()
		_, q := locationQuery(t, b.startLogin(appHost, query).Header().Get("Location"))
		before := fake.TokenCalls.Load()
		wantDenied(t, e, b, appHost, b.get(callbackURL(q.Get("state"), nil)), http.StatusUnauthorized, "unauthenticated", "code_missing")
		noTokenCall(t, before)
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		fake.Mutate(func(c map[string]any) { c["nonce"] = "another-nonce" })
		defer fake.Mutate(nil)
		b := e.browser()
		wantDenied(t, e, b, appHost, b.login(appHost, query), http.StatusUnauthorized, "unauthenticated", "nonce_mismatch")
	})
	t.Run("nonce missing", func(t *testing.T) {
		fake.Mutate(func(c map[string]any) { delete(c, "nonce") })
		defer fake.Mutate(nil)
		b := e.browser()
		wantDenied(t, e, b, appHost, b.login(appHost, query), http.StatusUnauthorized, "unauthenticated", "nonce_mismatch")
	})
	t.Run("a later login of the same browser invalidates the earlier one", func(t *testing.T) {
		b := e.browser()
		first := b.startLogin(appHost, query)
		b.startLogin(appHost, query) // new binding cookie replaces the first
		cb := b.authorize(first.Header().Get("Location"))
		wantDenied(t, e, b, appHost, b.get(cb.String()), http.StatusUnauthorized, "unauthenticated", "browser_binding_mismatch")
	})
}

// TestIdPMixUpRejectedBeforeTokenCall — IT-01b (T-20): a response of IdP H delivered with the state of a login
// started at IdP M is refused on H's callback before any token request (no code ever reaches a token endpoint) and
// no session is created; RFC 9207 iss mismatch and missing iss are refused the same way.
func TestIdPMixUpRejectedBeforeTokenCall(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	honest, malicious := e.fakeIdP(), e.fakeIdP()
	honest.AdvertiseIss, malicious.AdvertiseIss = true, true
	victimTenant := e.newTenant(honest)
	attackerTenant := e.newTenant(malicious)
	sessionsBefore := e.count(`SELECT count(*) FROM sessions WHERE idp_id IN ($1, $2)`, victimTenant.IdP, attackerTenant.IdP)

	b := e.browser()
	// The victim starts a login at the tenant whose IdP the attacker controls…
	start := b.startLogin(appHost, "scope=tenant&tenant="+attackerTenant.Slug)
	_, mq := locationQuery(t, start.Header().Get("Location"))
	// …and the malicious authorization endpoint forwards the browser to the honest IdP for the honest client, which
	// authenticates the victim and answers on ITS OWN redirect URI with a code for the honest client.
	forwarded := honest.Issuer + "/authorize?" + url.Values{
		"client_id": {victimTenant.ClientID}, "redirect_uri": {redirectURI(appHost, victimTenant.IdP)},
		"response_type": {"code"}, "scope": {"openid"}, "state": {mq.Get("state")}, "nonce": {mq.Get("nonce")},
		"code_challenge": {mq.Get("code_challenge")}, "code_challenge_method": {"S256"},
	}.Encode()
	cb := b.authorize(forwarded)
	if !strings.HasSuffix(cb.Path, victimTenant.IdP.String()) || cb.Query().Get("iss") != honest.Issuer {
		t.Fatalf("unexpected honest response %s", cb)
	}
	wantDenied(t, e, b, appHost, b.get(cb.String()), http.StatusUnauthorized, "unauthenticated", "idp_mismatch")

	// The honest code replayed onto the malicious IdP's own callback carries the honest iss (RFC 9207).
	start2 := b.startLogin(appHost, "scope=tenant&tenant="+attackerTenant.Slug)
	_, mq2 := locationQuery(t, start2.Header().Get("Location"))
	onMalicious := "https://" + appHost + "/api/v1/auth/callback/" + attackerTenant.IdP.String() + "?" + url.Values{
		"state": {mq2.Get("state")}, "code": {cb.Query().Get("code")}, "iss": {honest.Issuer},
	}.Encode()
	wantDenied(t, e, b, appHost, b.get(onMalicious), http.StatusUnauthorized, "unauthenticated", "iss_mismatch")

	// An IdP that announces the iss parameter must send it.
	start3 := b.startLogin(appHost, "scope=tenant&tenant="+attackerTenant.Slug)
	_, mq3 := locationQuery(t, start3.Header().Get("Location"))
	noIss := "https://" + appHost + "/api/v1/auth/callback/" + attackerTenant.IdP.String() + "?" + url.Values{
		"state": {mq3.Get("state")}, "code": {"anything"},
	}.Encode()
	wantDenied(t, e, b, appHost, b.get(noIss), http.StatusUnauthorized, "unauthenticated", "iss_missing")

	if honest.TokenCalls.Load() != 0 || malicious.TokenCalls.Load() != 0 {
		t.Fatalf("token requests went out: honest %d, malicious %d", honest.TokenCalls.Load(), malicious.TokenCalls.Load())
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE idp_id IN ($1, $2)`, victimTenant.IdP, attackerTenant.IdP); n != sessionsBefore {
		t.Fatal("a session was created")
	}
}

// TestTenantIssuerIsolation — IT-01: an identity of tenant A's IdP gets a session and an identity bound to A only,
// cannot be given a membership of tenant B, and an ID token of issuer A is refused on tenant B's login flow.
func TestTenantIssuerIsolation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fakeA, fakeB := e.fakeIdP(), e.fakeIdP()
	tenA, tenB := e.newTenant(fakeA), e.newTenant(fakeB)
	user := identity.FakeUser{Sub: "shared-sub-" + identity.RandomHex(3), Email: "u@example.test", EmailVerified: true}
	fakeA.SetUser(user)
	fakeB.SetUser(user) // same subject string at both IdPs: still two unrelated identities

	b := e.browser()
	b.mustLogin(appHost, "scope=tenant&tenant="+tenA.Slug)
	_, s := b.session(appHost)
	var tenantOfIdentity uuid.UUID
	if err := e.db.QueryRow(context.Background(), `SELECT tenant_id FROM identities WHERE id = $1 AND idp_id = $2`,
		s.Principal.IdentityId, tenA.IdP).Scan(&tenantOfIdentity); err != nil || tenantOfIdentity != tenA.ID {
		t.Fatalf("identity of A bound to tenant %v (%v)", tenantOfIdentity, err)
	}
	if len(s.Memberships) != 0 {
		t.Fatalf("memberships %+v", s.Memberships)
	}
	// A membership of tenant B for A's identity is refused by the composite FK (tenant_id, identity_id).
	_, err := e.db.Exec(context.Background(), `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id) VALUES ($1, $2, $3)`,
		tenB.ID, s.Principal.IdentityId, tenB.Role)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("cross-tenant membership: %v", err)
	}

	cases := []struct {
		name     string
		override func(c map[string]any) string
	}{
		{"token of issuer A, signed by A", func(c map[string]any) string {
			c["iss"], c["aud"], c["azp"] = fakeA.Issuer, tenA.ClientID, tenA.ClientID
			return identity.SignRS256(fakeA.Key, fakeA.KID, c)
		}},
		{"token of issuer A with B's audience", func(c map[string]any) string {
			c["iss"] = fakeA.Issuer
			return identity.SignRS256(fakeA.Key, fakeA.KID, c)
		}},
		{"B's claims signed with A's key", func(c map[string]any) string {
			return identity.SignRS256(fakeA.Key, fakeB.KID, c)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeB.Override(tc.override)
			defer fakeB.Override(nil)
			bb := e.browser()
			wantDenied(t, e, bb, appHost, bb.login(appHost, "scope=tenant&tenant="+tenB.Slug), http.StatusUnauthorized, "unauthenticated", "id_token_invalid")
		})
	}
	if n := e.count(`SELECT count(*) FROM identities WHERE idp_id = $1`, tenB.IdP); n != 0 {
		t.Fatalf("%d identities created for tenant B from foreign tokens", n)
	}
	// The genuine flow of B gives a different identity bound to B.
	bb := e.browser()
	bb.mustLogin(appHost, "scope=tenant&tenant="+tenB.Slug)
	_, sb := bb.session(appHost)
	if sb.Principal.IdentityId == s.Principal.IdentityId || sb.Principal.IdpId != tenB.IdP {
		t.Fatal("identities of A and B are not distinct")
	}
}

// TestSharedIssuerOrganisationConstraint — IT-01c (§8.2 shared-issuer rule): two tenants on the same issuer with
// different clients; a user of another organisation is refused by required_claims before any identity is created;
// the allowed e-mail domains only trust a verified address.
func TestSharedIssuerOrganisationConstraint(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	shared := e.fakeIdP()
	tenX := e.newTenant(shared, withRequiredClaims(`{"org": "org-x"}`))
	tenY := e.newTenant(shared, withRequiredClaims(`{"org": ["org-y", "org-y2"]}`))
	tenZ := e.newTenant(shared, withAllowedDomains("x.example"))
	if tenX.ClientID == tenY.ClientID {
		t.Fatal("fixture: clients must differ")
	}
	login := func(ten *tenantFix, u identity.FakeUser) (*browser, int) {
		shared.SetUser(u)
		b := e.browser()
		rec := b.login(appHost, "scope=tenant&tenant="+ten.Slug)
		return b, rec.Code
	}
	userY := identity.FakeUser{Sub: "y-" + identity.RandomHex(3), Email: "bob@y.example", EmailVerified: true,
		Extra: map[string]any{"org": "org-y"}}

	cases := []struct {
		name   string
		ten    *tenantFix
		user   identity.FakeUser
		status int
		reason string
	}{
		{"organisation Y on X's registration", tenX, userY, http.StatusForbidden, "required_claim_mismatch"},
		{"organisation claim absent", tenX, identity.FakeUser{Sub: "n-" + identity.RandomHex(3), Email: "n@x.example", EmailVerified: true},
			http.StatusForbidden, "required_claim_missing"},
		{"organisation as an array containing X", tenX, identity.FakeUser{Sub: "a-" + identity.RandomHex(3), Email: "a@x.example",
			EmailVerified: true, Extra: map[string]any{"org": []any{"org-z", "org-x"}}}, http.StatusFound, ""},
		{"organisation Y on Y's registration", tenY, userY, http.StatusFound, ""},
		{"verified address outside the allowed domains", tenZ, identity.FakeUser{Sub: "d-" + identity.RandomHex(3),
			Email: "carol@y.example", EmailVerified: true}, http.StatusForbidden, "email_domain_not_allowed"},
		{"unverified address in the allowed domain", tenZ, identity.FakeUser{Sub: "u-" + identity.RandomHex(3),
			Email: "dave@x.example", EmailVerified: false}, http.StatusForbidden, "email_not_verified"},
		{"verified address in the allowed domain (case-insensitive)", tenZ, identity.FakeUser{Sub: "v-" + identity.RandomHex(3),
			Email: "erin@X.Example", EmailVerified: true}, http.StatusFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, code := login(tc.ten, tc.user)
			if code != tc.status {
				t.Fatalf("HTTP %d, want %d", code, tc.status)
			}
			n := e.count(`SELECT count(*) FROM identities WHERE idp_id = $1 AND subject = $2`, tc.ten.IdP, tc.user.Sub)
			if tc.status != http.StatusFound {
				if got := e.audit.last(identity.ActionLogin).Reason; got != tc.reason {
					t.Fatalf("reason %q, want %q", got, tc.reason)
				}
				if n != 0 || b.cookie(appHost, identity.SessionCookieName) != "" {
					t.Fatal("refused user got an identity or a session")
				}
			} else if n != 1 {
				t.Fatal("accepted user has no identity")
			}
		})
	}
}

// TestIDTokenValidation — wrong aud/azp, expiry, issuer, signature, alg none/HS256, iat freshness, auth_time.
func TestIDTokenValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	other := e.fakeIdP()
	ten := e.newTenant(fake)
	now := e.clock.Now
	cases := []struct {
		name     string
		mutate   func(c map[string]any)
		override func(c map[string]any) string
		status   int
		reason   string
	}{
		{name: "audience of another client", mutate: func(c map[string]any) { c["aud"], c["azp"] = "someone-else", "someone-else" },
			reason: "id_token_invalid"},
		{name: "several audiences without azp", mutate: func(c map[string]any) { c["aud"] = []any{ten.ClientID, "x"}; delete(c, "azp") },
			reason: "azp_mismatch"},
		{name: "azp of another client", mutate: func(c map[string]any) { c["azp"] = "other-client" }, reason: "azp_mismatch"},
		{name: "expired", mutate: func(c map[string]any) { c["exp"] = now().Add(-time.Second).Unix() }, reason: "id_token_invalid"},
		{name: "issuer of another IdP", mutate: func(c map[string]any) { c["iss"] = other.Issuer }, reason: "id_token_invalid"},
		{name: "signed with an unknown key", override: func(c map[string]any) string {
			return identity.SignRS256(other.Key, fake.KID, c)
		}, reason: "id_token_invalid"},
		{name: "alg none", override: identity.UnsignedJWT, reason: "id_token_invalid"},
		{name: "alg HS256 keyed with the client secret", override: func(c map[string]any) string {
			return identity.SignHS256([]byte(ten.Secret), c)
		}, reason: "id_token_invalid"},
		{name: "issued before the auth request", mutate: func(c map[string]any) { c["iat"] = now().Add(-time.Hour).Unix() },
			reason: "id_token_not_fresh"},
		{name: "issued in the future", mutate: func(c map[string]any) { c["iat"] = now().Add(10 * time.Minute).Unix() },
			reason: "id_token_not_fresh"},
		{name: "auth_time missing", mutate: func(c map[string]any) { delete(c, "auth_time") }, reason: "auth_time_missing"},
		{name: "auth_time in the future", mutate: func(c map[string]any) { c["auth_time"] = now().Add(10 * time.Minute).Unix() },
			reason: "auth_time_out_of_range"},
		{name: "auth_time older than max_age", mutate: func(c map[string]any) { c["auth_time"] = now().Add(-13 * time.Hour).Unix() },
			reason: "auth_time_out_of_range"},
		{name: "subject missing", mutate: func(c map[string]any) { delete(c, "sub") }, reason: "subject_invalid"},
		{name: "e-mail not verified", mutate: func(c map[string]any) { c["email_verified"] = false },
			status: http.StatusForbidden, reason: "email_not_verified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake.Mutate(tc.mutate)
			fake.Override(tc.override)
			defer func() { fake.Mutate(nil); fake.Override(nil) }()
			status, code := http.StatusUnauthorized, "unauthenticated"
			if tc.status != 0 {
				status, code = tc.status, "forbidden"
			}
			b := e.browser()
			wantDenied(t, e, b, appHost, b.login(appHost, "scope=tenant&tenant="+ten.Slug), status, code, tc.reason)
		})
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE idp_id = $1`, ten.IdP); n != 0 {
		t.Fatalf("%d sessions created from invalid tokens", n)
	}
	b := e.browser()
	b.mustLogin(appHost, "scope=tenant&tenant="+ten.Slug) // the untouched flow still works
}

// TestCookieFlags — __Host- cookies: Secure; HttpOnly; SameSite=Lax; Path=/; no Domain; the callback sets two
// cookies (session + deletion of the binding cookie); logout deletes the session cookie.
func TestCookieFlags(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	b := e.browser()
	check := func(t *testing.T, c *http.Cookie, maxAge int) {
		t.Helper()
		if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" ||
			c.MaxAge != maxAge || (maxAge == 0 && !c.Expires.IsZero()) {
			t.Fatalf("cookie %+v (want MaxAge %d)", c, maxAge)
		}
	}
	start := b.startLogin(appHost, "scope=tenant&tenant="+ten.Slug)
	sc := setCookies(t, start.Header())
	check(t, sc[identity.AuthRequestCookieName], 600)
	if len(start.Header().Values("Set-Cookie")) != 1 || start.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("login response headers")
	}
	cb := b.get(b.authorize(start.Header().Get("Location")).String())
	wantStatus(t, "callback", cb.Code, http.StatusFound, cb.Body.String())
	if n := len(cb.Header().Values("Set-Cookie")); n != 2 {
		t.Fatalf("callback sets %d cookies, want 2", n)
	}
	sc = setCookies(t, cb.Header())
	check(t, sc[identity.SessionCookieName], 0)
	check(t, sc[identity.AuthRequestCookieName], -1)
	if cb.Header().Get("Cache-Control") != "no-store" || cb.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("callback response headers")
	}
	rec := b.do(http.MethodPost, "https://"+appHost+"/api/v1/auth/logout", unsafeHeaders(appHost, b.csrf(appHost)))
	wantStatus(t, "logout", rec.Code, http.StatusNoContent, rec.Body.String())
	check(t, setCookies(t, rec.Header())[identity.SessionCookieName], -1)
}

// TestSessionOriginBinding — a session minted on app is refused on admin and vice versa, even when the cookie is
// presented there (the middleware does not rely on __Host- cookie scoping alone); logins are bound the same way.
func TestSessionOriginBinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tenantFake, platformFake := e.fakeIdP(), e.fakeIdP()
	ten := e.newTenant(tenantFake)
	e.newPlatform(platformFake)

	tb := e.browser()
	tb.mustLogin(appHost, "scope=tenant&tenant="+ten.Slug)
	pb := e.browser()
	pb.mustLogin(adminHost, "scope=platform")

	stolen := e.browser()
	stolen.setCookie(adminHost, identity.SessionCookieName, tb.cookie(appHost, identity.SessionCookieName))
	rec, _ := stolen.session(adminHost)
	wantStatus(t, "app session on admin", rec.Code, http.StatusUnauthorized, rec.Body.String())
	if ev := e.audit.last(identity.ActionSessionCheck); ev.Reason != "session_origin_mismatch" {
		t.Fatalf("audit %+v", ev)
	}
	stolen.setCookie(appHost, identity.SessionCookieName, pb.cookie(adminHost, identity.SessionCookieName))
	rec, _ = stolen.session(appHost)
	wantStatus(t, "admin session on app", rec.Code, http.StatusUnauthorized, rec.Body.String())
	// Unsafe request with a session of the other origin and its (valid) CSRF token: still no session.
	h := unsafeHeaders(appHost, pb.csrf(adminHost))
	rec = stolen.do(http.MethodPost, "https://"+appHost+"/api/v1/auth/logout", h)
	wantStatus(t, "logout with the admin session on app", rec.Code, http.StatusUnauthorized, rec.Body.String())

	for host, b := range map[string]*browser{appHost: tb, adminHost: pb} {
		if rec, s := b.session(host); rec.Code != http.StatusOK || string(s.Origin) != strings.SplitN(host, ".", 2)[0] {
			t.Fatalf("own origin %s: HTTP %d origin %s", host, rec.Code, s.Origin)
		}
	}
	// Defence in depth: even a row whose origin were rewritten to admin cannot carry a tenant identity there.
	tenantCookie := tb.cookie(appHost, identity.SessionCookieName)
	e.exec(`UPDATE sessions SET origin = 'admin' WHERE id_hash = $1`, sha(decodeB64(t, tenantCookie)))
	_, err := e.svc.Authenticate(context.Background(), tenantCookie, identity.OriginAdmin)
	var ie *identity.Error
	if !errors.As(err, &ie) || ie.Reason != "session_scope_origin_mismatch" {
		t.Fatalf("tenant identity accepted on admin: %v", err)
	}

	// Logins are bound to the origin of their scope.
	for _, c := range []struct{ host, query string }{
		{appHost, "scope=platform"}, {adminHost, "scope=tenant&tenant=" + ten.Slug},
	} {
		rec := e.browser().startLogin(c.host, c.query)
		if rec.Code != http.StatusUnprocessableEntity || problemCode(t, rec) != "validation_failed" {
			t.Fatalf("%s on %s: HTTP %d", c.query, c.host, rec.Code)
		}
	}
	// Any other host is not an origin of the Portal.
	rec = e.browser().get("https://evil.example/api/v1/auth/session")
	if rec.Code != http.StatusNotFound || problemCode(t, rec) != "not_found" {
		t.Fatalf("unknown host: HTTP %d", rec.Code)
	}
}

// TestCSRFAndOriginChecks — state-changing requests need X-CSRF-Token = HMAC-SHA256(session id, "csrf-v1") and a
// same-origin Origin (or Sec-Fetch-Site: same-origin); the token is never stored.
func TestCSRFAndOriginChecks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	b, other := e.browser(), e.browser()
	b.mustLogin(appHost, "scope=tenant&tenant="+ten.Slug)
	other.mustLogin(appHost, "scope=tenant&tenant="+ten.Slug)
	tok := b.csrf(appHost)
	logout := "https://" + appHost + "/api/v1/auth/logout"
	cases := []struct {
		name   string
		header http.Header
	}{
		{"no token", http.Header{"Origin": {"https://" + appHost}}},
		{"wrong token", unsafeHeaders(appHost, "AAAA"+tok[4:])},
		{"token of another session", unsafeHeaders(appHost, other.csrf(appHost))},
		{"Origin of the admin origin", http.Header{"Origin": {"https://" + adminHost}, "X-Csrf-Token": {tok}}},
		{"foreign Origin", http.Header{"Origin": {"https://evil.example"}, "X-Csrf-Token": {tok}}},
		{"Origin null", http.Header{"Origin": {"null"}, "X-Csrf-Token": {tok}}},
		{"cross-site fetch without Origin", http.Header{"Sec-Fetch-Site": {"cross-site"}, "X-Csrf-Token": {tok}}},
		{"same-site fetch without Origin", http.Header{"Sec-Fetch-Site": {"same-site"}, "X-Csrf-Token": {tok}}},
		{"neither Origin nor Sec-Fetch-Site", http.Header{"X-Csrf-Token": {tok}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := b.do(http.MethodPost, logout, tc.header)
			if rec.Code != http.StatusForbidden || problemCode(t, rec) != "forbidden" {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			if r, _ := b.session(appHost); r.Code != http.StatusOK {
				t.Fatal("session lost after a refused request")
			}
		})
	}
	// DELETE /auth/sessions/{id} is protected the same way.
	rec := b.do(http.MethodDelete, "https://"+appHost+"/api/v1/auth/sessions/"+uuid.NewString(), http.Header{"Origin": {"https://" + appHost}})
	wantStatus(t, "revoke without token", rec.Code, http.StatusForbidden, rec.Body.String())
	rec = b.do(http.MethodPost, logout, http.Header{"Sec-Fetch-Site": {"same-origin"}, "X-Csrf-Token": {tok}})
	wantStatus(t, "logout", rec.Code, http.StatusNoContent, rec.Body.String())
	if r, _ := b.session(appHost); r.Code != http.StatusUnauthorized {
		t.Fatal("session alive after logout")
	}
	if ev := e.audit.last(identity.ActionLogout); ev.Outcome != identity.OutcomeSuccess {
		t.Fatalf("audit %+v", ev)
	}
	if r, _ := other.session(appHost); r.Code != http.StatusOK {
		t.Fatal("logout revoked another session")
	}
}

// authenticate resolves the browser's session through the service (as the middleware does).
func authenticate(t *testing.T, e *env, b *browser, host string, o identity.Origin) *identity.Session {
	t.Helper()
	s, err := e.svc.Authenticate(context.Background(), b.cookie(host, identity.SessionCookieName), o)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return s
}

func wantReauth(t *testing.T, err error) {
	t.Helper()
	var ie *identity.Error
	if !errors.As(err, &ie) || ie.Kind != identity.KindReauthRequired || ie.Kind.Code() != "reauth_required" || ie.Kind.Status() != 401 {
		t.Fatalf("err = %v, want reauth_required", err)
	}
}

// TestStepUp — §8.3 step 7: auth_time older than 15 minutes needs a re-authentication; logging in again with a
// session asks for prompt=login and max_age=0; an ID token without auth_time is refused (no step-up recorded, the old
// session keeps its old auth_time); a stale auth_time from an IdP ignoring prompt=login does not satisfy step-up.
func TestStepUp(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	query := "scope=tenant&tenant=" + ten.Slug
	b := e.browser()
	b.mustLogin(appHost, query)
	if err := e.svc.RequireRecentAuth(authenticate(t, e, b, appHost, identity.OriginApp)); err != nil {
		t.Fatalf("fresh login: %v", err)
	}
	e.clock.Advance(15*time.Minute + time.Second)
	wantReauth(t, e.svc.RequireRecentAuth(authenticate(t, e, b, appHost, identity.OriginApp)))

	// Re-authentication request.
	start := b.startLogin(appHost, query)
	_, q := locationQuery(t, start.Header().Get("Location"))
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("step-up request prompt=%q max_age=%q", q.Get("prompt"), q.Get("max_age"))
	}

	// (1) The IdP returns no auth_time: refused, no new session, the old one is unchanged.
	old := b.cookie(appHost, identity.SessionCookieName)
	fake.Mutate(func(c map[string]any) { delete(c, "auth_time") })
	rec := b.get(b.authorize(start.Header().Get("Location")).String())
	fake.Mutate(nil)
	wantStatus(t, "step-up without auth_time", rec.Code, http.StatusUnauthorized, rec.Body.String())
	if e.audit.last(identity.ActionLogin).Reason != "auth_time_missing" || b.cookie(appHost, identity.SessionCookieName) != old {
		t.Fatal("step-up without auth_time was not refused cleanly")
	}
	wantReauth(t, e.svc.RequireRecentAuth(authenticate(t, e, b, appHost, identity.OriginApp)))

	// (2) The IdP ignores prompt=login and returns a 20-minute-old auth_time: logged in, but no step-up.
	fake.SetSSOTime(e.clock.Now().Add(-20*time.Minute), true)
	b.mustLogin(appHost, query)
	if b.cookie(appHost, identity.SessionCookieName) == old {
		t.Fatal("session id not rotated at login")
	}
	if _, err := e.svc.Authenticate(context.Background(), old, identity.OriginApp); err == nil {
		t.Fatal("previous session still valid after a new login")
	}
	wantReauth(t, e.svc.RequireRecentAuth(authenticate(t, e, b, appHost, identity.OriginApp)))

	// (3) A conforming IdP re-authenticates: fresh auth_time, step-up satisfied for 15 minutes.
	fake.SetSSOTime(time.Time{}, false)
	b.mustLogin(appHost, query)
	s := authenticate(t, e, b, appHost, identity.OriginApp)
	if err := e.svc.RequireRecentAuth(s); err != nil || !s.AuthTime.Equal(e.clock.Now()) {
		t.Fatalf("after re-authentication: %v (auth_time %v)", err, s.AuthTime)
	}
	if err := e.svc.RequireRecentAuthContext(context.Background()); err == nil {
		t.Fatal("RequireRecentAuthContext without a session must fail")
	}
	e.clock.Advance(15*time.Minute + time.Second)
	wantReauth(t, e.svc.RequireRecentAuth(authenticate(t, e, b, appHost, identity.OriginApp)))
}

// TestSessionsListAndRevoke — GET/DELETE /auth/sessions: only the caller's own live sessions, stable pagination,
// revocation effective on the next request, other identities' sessions answer 404.
func TestSessionsListAndRevoke(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	query := "scope=tenant&tenant=" + ten.Slug
	alice := identity.FakeUser{Sub: "alice-" + identity.RandomHex(3), Email: "alice@example.test", EmailVerified: true}
	bob := identity.FakeUser{Sub: "bob-" + identity.RandomHex(3), Email: "bob@example.test", EmailVerified: true}
	fake.SetUser(alice)
	b1, b2 := e.browser(), e.browser()
	b1.mustLogin(appHost, query)
	e.clock.Advance(time.Second)
	b2.mustLogin(appHost, query)
	fake.SetUser(bob)
	b3 := e.browser()
	b3.mustLogin(appHost, query)

	list := func(b *browser, q string) (int, gen.SessionList) {
		rec := b.get("https://" + appHost + "/api/v1/auth/sessions" + q)
		var l gen.SessionList
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, l
	}
	code, l := list(b1, "")
	if code != http.StatusOK || len(l.Items) != 2 || l.NextCursor != nil {
		t.Fatalf("list: HTTP %d %+v", code, l)
	}
	if !l.Items[0].Current || l.Items[1].Current || !l.Items[0].CreatedAt.Before(l.Items[1].CreatedAt) {
		t.Fatalf("order/current flags: %+v", l.Items)
	}
	if l.Items[0].UserAgent == nil || *l.Items[0].UserAgent != "mg-test-browser/1.0" || l.Items[0].Ip == nil {
		t.Fatalf("item %+v", l.Items[0])
	}
	_, l2 := list(b2, "")
	var b2ID uuid.UUID
	for _, it := range l2.Items {
		if it.Current {
			b2ID = it.Id
		}
	}
	// Pagination.
	code, p1 := list(b1, "?limit=1")
	if code != http.StatusOK || len(p1.Items) != 1 || p1.NextCursor == nil {
		t.Fatalf("page 1: %d %+v", code, p1)
	}
	code, p2 := list(b1, "?limit=1&cursor="+url.QueryEscape(*p1.NextCursor))
	if code != http.StatusOK || len(p2.Items) != 1 || p2.Items[0].Id != b2ID || p2.NextCursor != nil {
		t.Fatalf("page 2: %d %+v", code, p2)
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?cursor=bm90LWEtY3Vyc29y"} {
		rec := b1.get("https://" + appHost + "/api/v1/auth/sessions" + q)
		if rec.Code != http.StatusUnprocessableEntity || problemCode(t, rec) != "validation_failed" {
			t.Fatalf("%s: HTTP %d", q, rec.Code)
		}
	}
	_, l3 := list(b3, "")
	if len(l3.Items) != 1 {
		t.Fatalf("bob sees %d sessions", len(l3.Items))
	}
	bobID := l3.Items[0].Id

	revoke := func(b *browser, id uuid.UUID) int {
		return b.do(http.MethodDelete, "https://"+appHost+"/api/v1/auth/sessions/"+id.String(), unsafeHeaders(appHost, b.csrf(appHost))).Code
	}
	if c := revoke(b1, bobID); c != http.StatusNotFound {
		t.Fatalf("revoke another identity's session: HTTP %d", c)
	}
	if r, _ := b3.session(appHost); r.Code != http.StatusOK {
		t.Fatal("bob's session was revoked")
	}
	if c := revoke(b1, uuid.New()); c != http.StatusNotFound {
		t.Fatalf("revoke unknown: HTTP %d", c)
	}
	if c := revoke(b1, b2ID); c != http.StatusNoContent {
		t.Fatalf("revoke own other session: HTTP %d", c)
	}
	if r, _ := b2.session(appHost); r.Code != http.StatusUnauthorized {
		t.Fatal("revoked session still accepted")
	}
	if c := revoke(b1, b2ID); c != http.StatusNotFound {
		t.Fatalf("revoke twice: HTTP %d", c)
	}
	if _, l := list(b1, ""); len(l.Items) != 1 {
		t.Fatalf("after revoke: %+v", l.Items)
	}
	// RevokeIdentitySessions (lock/offboarding) ends every session of the identity at once.
	n, err := e.svc.RevokeIdentitySessions(context.Background(), authenticate(t, e, b1, appHost, identity.OriginApp).IdentityID)
	if err != nil || n != 1 {
		t.Fatalf("RevokeIdentitySessions = %d, %v", n, err)
	}
	if r, _ := b1.session(appHost); r.Code != http.StatusUnauthorized {
		t.Fatal("session alive after RevokeIdentitySessions")
	}
	if r, _ := b3.session(appHost); r.Code != http.StatusOK {
		t.Fatal("RevokeIdentitySessions touched another identity")
	}
}

// TestSessionTimeouts — §8.3 step 6: tenant idle 30 min / absolute 12 h; platform idle 15 min / absolute 8 h.
func TestSessionTimeouts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	query := "scope=tenant&tenant=" + ten.Slug

	idle := e.browser()
	idle.mustLogin(appHost, query)
	e.clock.Advance(29 * time.Minute)
	if r, _ := idle.session(appHost); r.Code != http.StatusOK {
		t.Fatal("expired before the idle timeout")
	}
	e.clock.Advance(29 * time.Minute) // activity extended the idle expiry
	if r, _ := idle.session(appHost); r.Code != http.StatusOK {
		t.Fatal("activity did not extend the idle expiry")
	}
	e.clock.Advance(30 * time.Minute)
	if r, _ := idle.session(appHost); r.Code != http.StatusUnauthorized {
		t.Fatal("alive after 30 idle minutes")
	}

	abs := e.browser()
	abs.mustLogin(appHost, query)
	started := e.clock.Now()
	for e.clock.Now().Sub(started) < 12*time.Hour-25*time.Minute {
		e.clock.Advance(25 * time.Minute)
		r, s := abs.session(appHost)
		if r.Code != http.StatusOK {
			t.Fatalf("expired after %v", e.clock.Now().Sub(started))
		}
		if s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
			t.Fatal("idle expiry beyond the absolute expiry")
		}
	}
	e.clock.Advance(started.Add(12 * time.Hour).Sub(e.clock.Now()))
	if r, _ := abs.session(appHost); r.Code != http.StatusUnauthorized {
		t.Fatal("alive after the absolute timeout")
	}

	// The absolute expiry is enforced on its own, even if a row had a later idle expiry.
	own := e.browser()
	own.mustLogin(appHost, query)
	hash := sha(decodeB64(t, own.cookie(appHost, identity.SessionCookieName)))
	e.exec(`UPDATE sessions SET idle_expires_at = $2, absolute_expires_at = $3 WHERE id_hash = $1`, hash,
		e.clock.Now().Add(24*time.Hour), e.clock.Now().Add(time.Minute))
	e.clock.Advance(time.Minute)
	_, err := e.svc.Authenticate(context.Background(), own.cookie(appHost, identity.SessionCookieName), identity.OriginApp)
	var ie *identity.Error
	if !errors.As(err, &ie) || ie.Reason != "session_expired" {
		t.Fatalf("absolute expiry not enforced: %v", err)
	}
}

// TestPlatformLogin — scope=platform on the admin origin: max_age of 8 h, idle 15 min, platform role in the view.
func TestPlatformLogin(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	pf := e.newPlatform(fake)
	staff := identity.FakeUser{Sub: "staff-" + identity.RandomHex(3), Email: "ops@example.test", EmailVerified: true, Name: "Ops"}
	fake.SetUser(staff)
	identID := uuid.Must(uuid.NewV7())
	e.exec(`INSERT INTO identities (id, idp_id, scope, subject) VALUES ($1, $2, 'platform', $3)`, identID, pf.IdP, staff.Sub)
	e.exec(`INSERT INTO platform_users (identity_id, role_id) VALUES ($1, $2)`, identID, pf.Role)

	if rec := e.browser().startLogin(adminHost, "scope=platform&tenant=x1x"); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("platform login with a tenant: HTTP %d", rec.Code)
	}
	b := e.browser()
	start := b.startLogin(adminHost, "scope=platform")
	_, q := locationQuery(t, start.Header().Get("Location"))
	if q.Get("max_age") != "28800" || q.Get("redirect_uri") != redirectURI(adminHost, pf.IdP) {
		t.Fatalf("platform authorization request %v", q)
	}
	cb := b.get(b.authorize(start.Header().Get("Location")).String())
	wantStatus(t, "callback", cb.Code, http.StatusFound, cb.Body.String())
	rec, s := b.session(adminHost)
	wantStatus(t, "session", rec.Code, http.StatusOK, rec.Body.String())
	if s.Principal.IdentityId != identID || s.Principal.Scope != "platform" || s.Principal.PlatformRole == nil ||
		*s.Principal.PlatformRole != pf.RoleKey || len(s.Memberships) != 0 || s.Origin != "admin" {
		t.Fatalf("platform session %+v", s)
	}
	if !s.IdleExpiresAt.Equal(e.clock.Now().Add(15*time.Minute)) || !s.AbsoluteExpiresAt.Equal(e.clock.Now().Add(8*time.Hour)) {
		t.Fatalf("platform timeouts %v %v", s.IdleExpiresAt, s.AbsoluteExpiresAt)
	}
	e.clock.Advance(15*time.Minute + time.Second)
	if r, _ := b.session(adminHost); r.Code != http.StatusUnauthorized {
		t.Fatal("platform session alive after 15 idle minutes")
	}
}

// TestDisabledIdentityAndIdP — a disabled identity or IdP ends its sessions and refuses new logins.
func TestDisabledIdentityAndIdP(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	query := "scope=tenant&tenant=" + ten.Slug
	b := e.browser()
	b.mustLogin(appHost, query)
	_, s := b.session(appHost)
	e.exec(`UPDATE identities SET status = 'disabled' WHERE id = $1`, s.Principal.IdentityId)
	if r, _ := b.session(appHost); r.Code != http.StatusUnauthorized {
		t.Fatal("session of a disabled identity accepted")
	}
	b2 := e.browser()
	wantDenied(t, e, b2, appHost, b2.login(appHost, query), http.StatusForbidden, "forbidden", "identity_disabled")
	if _, err := e.db.Exec(context.Background(), `UPDATE identities SET status = 'locked' WHERE id = $1`, s.Principal.IdentityId); err == nil {
		t.Fatal("identities.status accepts a value outside {active, disabled}")
	}

	fake2 := e.fakeIdP()
	ten2 := e.newTenant(fake2)
	b3 := e.browser()
	b3.mustLogin(appHost, "scope=tenant&tenant="+ten2.Slug)
	e.exec(`UPDATE identity_providers SET status = 'retiring' WHERE id = $1`, ten2.IdP)
	if r, _ := b3.session(appHost); r.Code != http.StatusOK {
		t.Fatal("session of a retiring IdP refused")
	}
	if r := e.browser().startLogin(appHost, "scope=tenant&tenant="+ten2.Slug); r.Code != http.StatusNotFound {
		t.Fatalf("login with only a retiring IdP: HTTP %d", r.Code)
	}
	e.exec(`UPDATE identity_providers SET status = 'disabled' WHERE id = $1`, ten2.IdP)
	if r, _ := b3.session(appHost); r.Code != http.StatusUnauthorized {
		t.Fatal("session of a disabled IdP accepted")
	}
}

// TestLoginRequestValidation — unknown tenants, invalid parameters and open redirects are refused before any auth
// request is stored.
func TestLoginRequestValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	deleted := e.newTenant(e.fakeIdP())
	e.exec(`UPDATE tenants SET status = 'deleted' WHERE id = $1`, deleted.ID)
	pending := e.newTenant(e.fakeIdP())
	e.exec(`UPDATE tenants SET status = 'pending' WHERE id = $1`, pending.ID)
	before := e.count(`SELECT count(*) FROM auth_requests WHERE idp_id = $1`, ten.IdP)
	cases := []struct {
		query  string
		status int
	}{
		{"scope=tenant&tenant=nosuchtenant" + identity.RandomHex(2), http.StatusNotFound},
		{"scope=tenant&tenant=" + deleted.Slug, http.StatusNotFound},
		{"scope=tenant&tenant=" + pending.Slug, http.StatusNotFound},
		{"scope=tenant", http.StatusUnprocessableEntity},
		{"scope=tenant&tenant=Not_A_Slug", http.StatusUnprocessableEntity},
		{"scope=nope&tenant=" + ten.Slug, http.StatusUnprocessableEntity},
	}
	for _, rt := range []string{"//evil.example/x", "/\\evil.example", "https://evil.example/", "javascript:alert(1)",
		"/a b", "/ok\x01", "devices", strings.Repeat("/a", 300)} {
		cases = append(cases, struct {
			query  string
			status int
		}{"scope=tenant&tenant=" + ten.Slug + "&return_to=" + url.QueryEscape(rt), http.StatusUnprocessableEntity})
	}
	for _, c := range cases {
		rec := e.browser().startLogin(appHost, c.query)
		if rec.Code != c.status {
			t.Errorf("%s: HTTP %d, want %d (%s)", c.query, rec.Code, c.status, rec.Body.String())
		}
	}
	if n := e.count(`SELECT count(*) FROM auth_requests WHERE idp_id = $1`, ten.IdP); n != before {
		t.Fatal("refused logins stored auth requests")
	}
	if rec := e.browser().startLogin(appHost, "scope=tenant&tenant="+ten.Slug+"&return_to="+url.QueryEscape("/a/b?c=d")); rec.Code != http.StatusFound {
		t.Fatalf("valid return_to refused: %d", rec.Code)
	}
}
