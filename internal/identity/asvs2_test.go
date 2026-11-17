package identity_test

// Tests of the fixes of the G2 review, round 2 (OWASP ASVS 5.0.0 L2 — docs/planning/evidence/G2-security-review.md):
// A-1 (RP-Initiated Logout: POST /auth/logout ends the IdP session too; platform logins always prompt=login) and A-6
// (platform logins need evidence of a second factor in the ID token). They drive the API over HTTP (router, middleware,
// handlers), so the same tests fail on the code before the fix.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// logoutAs posts POST /auth/logout with the browser's CSRF token and returns the response and its redirect_to.
func logoutAs(t *testing.T, b *browser, host string) (int, string, http.Header) {
	t.Helper()
	rec := b.do(http.MethodPost, "https://"+host+"/api/v1/auth/logout", unsafeHeaders(host, b.csrf(host)))
	var out struct {
		RedirectTo string `json:"redirect_to"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("logout body %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, out.RedirectTo, rec.Header()
}

// hintOf returns sessions.id_token_hint_enc of the browser's session (nil = NULL) and whether it is revoked.
func hintOf(t *testing.T, e *env, cookie string) ([]byte, bool) {
	t.Helper()
	var (
		enc     []byte
		revoked bool
	)
	if err := e.db.QueryRow(context.Background(),
		`SELECT id_token_hint_enc, revoked_at IS NOT NULL FROM sessions WHERE id_hash = $1`,
		sha(decodeB64(t, cookie))).Scan(&enc, &revoked); err != nil {
		t.Fatal(err)
	}
	return enc, revoked
}

// TestLogoutEndsTheIdPSession — A-1 (ASVS 7.6.1, 7.1.3): logout revokes the BFF session and answers the IdP's
// end_session_endpoint with client_id, the registered post_logout_redirect_uri (the origin's root) and the ID token of
// the login as id_token_hint. The hint is kept sealed (never the token itself in the database) and cleared with the
// revocation. Before the fix: 204 without any redirect — the IdP session outlived the logout (probe P1).
func TestLogoutEndsTheIdPSession(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	b := e.browser()
	b.mustLogin(appHost, "scope=tenant&tenant="+ten.Slug)
	idToken := fake.LastIDToken()
	cookie := b.cookie(appHost, identity.SessionCookieName)
	enc, _ := hintOf(t, e, cookie)
	if len(enc) == 0 || bytes.Contains(enc, []byte(idToken[strings.LastIndexByte(idToken, '.')+1:])) ||
		bytes.Contains(enc, []byte(strings.SplitN(idToken, ".", 3)[1])) {
		t.Fatalf("hint stored %d bytes, sealed: %v", len(enc), len(enc) > 0)
	}

	code, to, hdr := logoutAs(t, b, appHost)
	wantStatus(t, "logout", code, http.StatusOK, to)
	u, q := locationQuery(t, to)
	if u.Scheme+"://"+u.Host+u.Path != fake.EndSessionEndpoint() || len(q) != 3 || q.Get("client_id") != ten.ClientID ||
		q.Get("post_logout_redirect_uri") != "https://"+appHost+"/" || q.Get("id_token_hint") != idToken {
		t.Fatalf("redirect_to %s?%v", u.Scheme+"://"+u.Host+u.Path, q)
	}
	if hdr.Get("Cache-Control") != "no-store" || hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("logout headers %v", hdr)
	}
	if c := setCookies(t, hdr)[identity.SessionCookieName]; c == nil || c.MaxAge >= 0 {
		t.Fatal("logout does not delete the session cookie")
	}
	if enc, revoked := hintOf(t, e, cookie); !revoked || enc != nil {
		t.Fatalf("after logout: revoked %v, hint %d bytes", revoked, len(enc))
	}
	if ev := e.audit.last(identity.ActionLogout); ev.Outcome != identity.OutcomeSuccess {
		t.Fatalf("audit %+v", ev)
	}
	b.setCookie(appHost, identity.SessionCookieName, cookie)
	if rec, _ := b.session(appHost); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after logout: HTTP %d", rec.Code)
	}
}

// TestLogoutFallbacks — A-1: an IdP without end_session_endpoint (no hint kept at login; redirect to the post-logout
// page), a session without a hint (created before migration 0008: client_id only — Keycloak then asks to confirm),
// a hint moved from another session (does not open: no hint, the logout still happens), the platform origin.
func TestLogoutFallbacks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	noEnd := e.fakeIdP()
	noEnd.NoEndSession = true
	ten := e.newTenant(noEnd)
	b := e.browser()
	b.mustLogin(appHost, "scope=tenant&tenant="+ten.Slug)
	if enc, _ := hintOf(t, e, b.cookie(appHost, identity.SessionCookieName)); enc != nil {
		t.Fatal("hint kept although the IdP has no end_session_endpoint")
	}
	if code, to, _ := logoutAs(t, b, appHost); code != http.StatusOK || to != "https://"+appHost+"/" {
		t.Fatalf("no end_session_endpoint: HTTP %d redirect_to %q", code, to)
	}

	fake := e.fakeIdP()
	ten2 := e.newTenant(fake)
	q := "scope=tenant&tenant=" + ten2.Slug
	old, other := e.browser(), e.browser()
	old.mustLogin(appHost, q)
	other.mustLogin(appHost, q)
	oldCookie, otherCookie := old.cookie(appHost, identity.SessionCookieName), other.cookie(appHost, identity.SessionCookieName)
	e.exec(`UPDATE sessions SET id_token_hint_enc = NULL WHERE id_hash = $1`, sha(decodeB64(t, oldCookie)))
	code, to, _ := logoutAs(t, old, appHost)
	_, qv := locationQuery(t, to)
	if code != http.StatusOK || !strings.HasPrefix(to, fake.EndSessionEndpoint()+"?") || qv.Has("id_token_hint") ||
		qv.Get("client_id") != ten2.ClientID {
		t.Fatalf("session without a hint: HTTP %d %s", code, to)
	}
	third := e.browser()
	third.mustLogin(appHost, q)
	e.exec(`UPDATE sessions SET id_token_hint_enc = (SELECT id_token_hint_enc FROM sessions WHERE id_hash = $1)
		WHERE id_hash = $2`, sha(decodeB64(t, otherCookie)), sha(decodeB64(t, third.cookie(appHost, identity.SessionCookieName))))
	code, to, _ = logoutAs(t, third, appHost)
	if _, qv := locationQuery(t, to); code != http.StatusOK || qv.Has("id_token_hint") {
		t.Fatalf("moved hint: HTTP %d %s", code, to)
	}
	if rec, _ := third.session(appHost); rec.Code != http.StatusUnauthorized {
		t.Fatal("session alive after a logout whose hint did not open")
	}

	pfake := e.fakeIdP()
	pf := e.newPlatform(pfake)
	pb := e.browser()
	pb.mustLogin(adminHost, "scope=platform")
	code, to, _ = logoutAs(t, pb, adminHost)
	_, qv = locationQuery(t, to)
	if code != http.StatusOK || qv.Get("post_logout_redirect_uri") != "https://"+adminHost+"/" ||
		qv.Get("client_id") != pf.ClientID || qv.Get("id_token_hint") != pfake.LastIDToken() {
		t.Fatalf("platform logout: HTTP %d %v", code, qv)
	}
}

// TestLogoutKeepsCSRF — A-1: the logout stays a state-changing request: without the CSRF token or from another
// Origin it is refused and the session (and its hint) live on.
func TestLogoutKeepsCSRF(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	b := e.browser()
	b.mustLogin(appHost, "scope=tenant&tenant="+ten.Slug)
	logout := "https://" + appHost + "/api/v1/auth/logout"
	for name, h := range map[string]http.Header{
		"no CSRF token":   {"Origin": {"https://" + appHost}},
		"wrong token":     unsafeHeaders(appHost, strings.Repeat("A", 43)),
		"foreign Origin":  {"Origin": {"https://evil.example"}, "X-Csrf-Token": {b.csrf(appHost)}},
		"cross-site form": {"Sec-Fetch-Site": {"cross-site"}, "X-Csrf-Token": {b.csrf(appHost)}},
	} {
		if rec := b.do(http.MethodPost, logout, h); rec.Code != http.StatusForbidden {
			t.Errorf("%s: HTTP %d", name, rec.Code)
		}
	}
	if enc, revoked := hintOf(t, e, b.cookie(appHost, identity.SessionCookieName)); revoked || enc == nil {
		t.Fatalf("refused logouts changed the session: revoked %v, hint %v", revoked, enc != nil)
	}
	if rec, _ := b.session(appHost); rec.Code != http.StatusOK {
		t.Fatalf("session after refused logouts: HTTP %d", rec.Code)
	}
}

// TestRevocationsClearTheLogoutHint — A-1: every revocation path clears the sealed ID token with the session: the
// rotation of a re-login, DELETE /auth/sessions/{id}, the revocation of all sessions of an identity.
func TestRevocationsClearTheLogoutHint(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	q := "scope=tenant&tenant=" + ten.Slug
	b1, b2, b3 := e.browser(), e.browser(), e.browser()
	b1.mustLogin(appHost, q)
	first := b1.cookie(appHost, identity.SessionCookieName)
	b1.mustLogin(appHost, q+"&reauth=true") // rotation
	if enc, revoked := hintOf(t, e, first); !revoked || enc != nil {
		t.Fatalf("rotated session: revoked %v, hint %v", revoked, enc != nil)
	}
	b2.mustLogin(appHost, q)
	_, s2 := b2.session(appHost)
	rec := b1.do(http.MethodDelete, "https://"+appHost+"/api/v1/auth/sessions/"+currentPublicID(t, b2),
		unsafeHeaders(appHost, b1.csrf(appHost)))
	wantStatus(t, "revoke own other session", rec.Code, http.StatusNoContent, rec.Body.String())
	if enc, revoked := hintOf(t, e, b2.cookie(appHost, identity.SessionCookieName)); !revoked || enc != nil {
		t.Fatalf("revoked session: revoked %v, hint %v", revoked, enc != nil)
	}
	b3.mustLogin(appHost, q)
	if n, err := e.svc.RevokeIdentitySessions(context.Background(), s2.Principal.IdentityId); err != nil || n < 2 {
		t.Fatalf("revoke identity sessions: %d %v", n, err)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE identity_id = $1 AND id_token_hint_enc IS NOT NULL`,
		s2.Principal.IdentityId); n != 0 {
		t.Fatalf("%d hints left after revoking every session of the identity", n)
	}
}

// currentPublicID returns the public id of the browser's own session (GET /auth/sessions, current).
func currentPublicID(t *testing.T, b *browser) string {
	t.Helper()
	var other string
	var list struct {
		Items []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"items"`
	}
	rec := b.get("https://" + appHost + "/api/v1/auth/sessions")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, it := range list.Items {
		if it.Current {
			other = it.ID
		}
	}
	if other == "" {
		t.Fatal("no current session in the list")
	}
	return other
}

// TestPlatformLoginAlwaysPromptsLogin — A-1 defence in depth: every platform login asks the IdP for prompt=login (a
// staff session never starts from an IdP session left in the browser); tenant logins only on step-up.
func TestPlatformLoginAlwaysPromptsLogin(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tfake, pfake := e.fakeIdP(), e.fakeIdP()
	ten := e.newTenant(tfake)
	e.newPlatform(pfake)
	for _, c := range []struct {
		host, query, prompt, maxAge string
	}{
		{adminHost, "scope=platform", "login", "28800"},
		{adminHost, "scope=platform&reauth=true", "login", "0"},
		{appHost, "scope=tenant&tenant=" + ten.Slug, "", "43200"},
		{appHost, "scope=tenant&tenant=" + ten.Slug + "&reauth=true", "login", "0"},
	} {
		rec := e.browser().startLogin(c.host, c.query)
		_, q := locationQuery(t, rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || q.Get("prompt") != c.prompt || q.Get("max_age") != c.maxAge {
			t.Errorf("%s %s: HTTP %d prompt %q max_age %q", c.host, c.query, rec.Code, q.Get("prompt"), q.Get("max_age"))
		}
	}
}

// TestPlatformLoginRequiresMFAEvidence — A-6 (ASVS 6.8.4): the reversed probe TestProbeSingleFactorPlatformLoginAccepted.
// A platform login whose ID token shows no second factor in amr is refused (401 reauth_required — sign in again with the
// second factor; audited with reason mfa_evidence_missing) and creates nothing; otp / mfa / hwk / swk are accepted.
// Tenant IdPs: off by default, on through required_claims of the IdP.
func TestPlatformLoginRequiresMFAEvidence(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	pf := e.newPlatform(fake)
	for name, amr := range map[string]any{"pwd only, acr 0": []any{"pwd"}, "no amr": nil, "empty amr": []any{},
		"amr not a list": "otp", "unknown factor": []any{"pwd", "face2"}} {
		fake.Mutate(func(c map[string]any) {
			if amr == nil {
				delete(c, "amr")
			} else {
				c["amr"] = amr
			}
			c["acr"] = "0"
		})
		b := e.browser()
		wantDenied(t, e, b, adminHost, b.login(adminHost, "scope=platform"), http.StatusUnauthorized, "reauth_required",
			"mfa_evidence_missing")
		if ev := e.audit.last(identity.ActionLogin); ev.Outcome != identity.OutcomeDenied || ev.IdPID != pf.IdP {
			t.Fatalf("%s: audit %+v", name, ev)
		}
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE idp_id = $1`, pf.IdP) +
		e.count(`SELECT count(*) FROM identities WHERE idp_id = $1`, pf.IdP); n != 0 {
		t.Fatalf("%d rows created by refused platform logins", n)
	}
	for _, amr := range [][]any{{"pwd", "otp"}, {"mfa"}, {"hwk"}, {"swk", "pwd"}} {
		fake.Mutate(func(c map[string]any) { c["amr"] = amr })
		b := e.browser()
		b.mustLogin(adminHost, "scope=platform")
	}

	tfake := e.fakeIdP()
	tfake.Mutate(func(c map[string]any) { c["amr"] = []any{"pwd"} })
	ten := e.newTenant(tfake)
	e.browser().mustLogin(appHost, "scope=tenant&tenant="+ten.Slug) // tenant default: no MFA requirement
	strict := e.fakeIdP()
	strict.Mutate(func(c map[string]any) { c["amr"] = []any{"pwd"} })
	sten := e.newTenant(strict, withRequiredClaims(`{"amr": ["otp", "mfa", "hwk", "swk"]}`))
	b := e.browser()
	wantDenied(t, e, b, appHost, b.login(appHost, "scope=tenant&tenant="+sten.Slug), http.StatusForbidden, "forbidden",
		"required_claim_mismatch")
	strict.Mutate(nil)
	e.browser().mustLogin(appHost, "scope=tenant&tenant="+sten.Slug)
}
