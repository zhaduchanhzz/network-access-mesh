package identity_test

import (
	"net/http"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// TestLoginStartFetchMetadata — G2 F1 (login CSRF, first line of defence): a login start that the browser marks as
// coming from another site — Sec-Fetch-Site other than same-origin or none: a link, form, redirect or script of
// another page, a sibling subdomain included — is refused 403 before anything is stored: no auth_requests row, no
// binding cookie, no redirect, a denied auth.login_start event. A header that no browser sends (empty, repeated,
// unknown token) is refused too. No Sec-Fetch-Site at all is allowed: non-browser clients and browsers without Fetch
// Metadata send none, and the callback rule (TestCallbackKeepsSessionOfAnotherIdentity) does not depend on it.
func TestLoginStartFetchMetadata(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	query := "scope=tenant&tenant=" + ten.Slug
	login := "https://" + appHost + "/api/v1/auth/login?" + query
	rows := func() int { return e.count(`SELECT count(*) FROM auth_requests WHERE idp_id = $1`, ten.IdP) }
	before := rows()

	refused := []http.Header{
		{"Sec-Fetch-Site": {"cross-site"}},
		{"Sec-Fetch-Site": {"same-site"}}, // another subdomain of the platform (admin., a tenant page) is not this origin
		{"Sec-Fetch-Site": {"Same-Origin"}},
		{"Sec-Fetch-Site": {"nonsense"}},
		{"Sec-Fetch-Site": {""}},
		{"Sec-Fetch-Site": {"same-origin", "cross-site"}},
	}
	for _, h := range refused {
		b := e.browser()
		rec := b.do(http.MethodGet, login, h)
		if rec.Code != http.StatusForbidden || problemCode(t, rec) != "forbidden" {
			t.Fatalf("Sec-Fetch-Site %q: HTTP %d %s, want 403 forbidden", h.Values("Sec-Fetch-Site"), rec.Code, rec.Body.String())
		}
		if b.cookie(appHost, identity.AuthRequestCookieName) != "" || rec.Header().Get("Location") != "" {
			t.Fatalf("Sec-Fetch-Site %q: a binding cookie or a redirect was set", h.Values("Sec-Fetch-Site"))
		}
		if ev := e.audit.last(identity.ActionLoginStart); ev.Outcome != identity.OutcomeDenied ||
			ev.Reason != "sec_fetch_site_cross_origin" {
			t.Fatalf("Sec-Fetch-Site %q: audit %+v", h.Values("Sec-Fetch-Site"), ev)
		}
	}
	if n := rows(); n != before {
		t.Fatalf("refused login starts stored %d auth requests", n-before)
	}

	// The Portal's own page (same-origin), a typed address or bookmark (none) and a non-browser client (no header).
	for _, h := range []http.Header{{"Sec-Fetch-Site": {"same-origin"}}, {"Sec-Fetch-Site": {"none"}}, nil} {
		b := e.browser()
		rec := b.do(http.MethodGet, login, h)
		if rec.Code != http.StatusFound || b.cookie(appHost, identity.AuthRequestCookieName) == "" {
			t.Fatalf("Sec-Fetch-Site %q: HTTP %d %s, want 302 with a binding cookie", h.Values("Sec-Fetch-Site"), rec.Code,
				rec.Body.String())
		}
	}
	if n := rows(); n != before+3 {
		t.Fatalf("allowed login starts stored %d auth requests, want 3", n-before)
	}

	// A refused start leaves the session already open in the browser untouched.
	b := e.browser()
	b.mustLogin(appHost, query)
	cookie := b.cookie(appHost, identity.SessionCookieName)
	if rec := b.do(http.MethodGet, login, http.Header{"Sec-Fetch-Site": {"cross-site"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site re-login with a session: HTTP %d", rec.Code)
	}
	if r, _ := b.session(appHost); r.Code != http.StatusOK || b.cookie(appHost, identity.SessionCookieName) != cookie {
		t.Fatal("a refused login start changed the open session")
	}
}

// TestCallbackKeepsSessionOfAnotherIdentity — G2 F1 (login CSRF, second line of defence): a login that completes for
// an identity other than the one of the session already open on this origin is refused (403) and the open session is
// kept — never silently revoked and replaced by a session of someone else (an attacker's tenant, whose policy would
// then govern the victim's enrolments). The refusal is audited under the identity of the kept session; the other
// identity is not even created (the transaction rolls back). The explicit step — logging out first — then lets the
// other identity sign in; a new login of the same identity still rotates the session (TestStepUp).
func TestCallbackKeepsSessionOfAnotherIdentity(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	victimIdP, attackerIdP := e.fakeIdP(), e.fakeIdP()
	victimTen, attackerTen := e.newTenant(victimIdP), e.newTenant(attackerIdP)
	victimIdP.SetUser(identity.FakeUser{Sub: "victim-" + identity.RandomHex(3), Email: "victim@v.test", EmailVerified: true})
	attackerIdP.SetUser(identity.FakeUser{Sub: "attacker-" + identity.RandomHex(3), Email: "mallory@e.test", EmailVerified: true})

	b := e.browser()
	b.mustLogin(appHost, "scope=tenant&tenant="+victimTen.Slug)
	victimCookie := b.cookie(appHost, identity.SessionCookieName)
	victim := authenticate(t, e, b, appHost, identity.OriginApp)

	// The victim's browser is walked through a login at the attacker's tenant (the IdP approves it silently). No
	// Fetch Metadata here: the first line of defence is assumed absent (an old browser).
	rec := b.login(appHost, "scope=tenant&tenant="+attackerTen.Slug)
	if rec.Code != http.StatusForbidden || problemCode(t, rec) != "forbidden" {
		t.Fatalf("login of another identity over an open session: HTTP %d %s, want 403", rec.Code, rec.Body.String())
	}
	if b.cookie(appHost, identity.SessionCookieName) != victimCookie {
		t.Fatal("the open session was replaced")
	}
	if r, s := b.session(appHost); r.Code != http.StatusOK || s.Principal.IdentityId != victim.IdentityID {
		t.Fatalf("the open session was not kept: HTTP %d principal %v", r.Code, s.Principal.IdentityId)
	}
	if n := e.count(`SELECT count(*) FROM identities WHERE idp_id = $1`, attackerTen.IdP); n != 0 {
		t.Fatalf("%d identities of the attacker's IdP were created", n)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE idp_id = $1`, attackerTen.IdP); n != 0 {
		t.Fatalf("%d sessions of the attacker's IdP were created", n)
	}
	ev := e.audit.last(identity.ActionLogin)
	if ev.Outcome != identity.OutcomeDenied || ev.Reason != "session_identity_mismatch" || ev.IdentityID != victim.IdentityID ||
		ev.SessionID != victim.PublicID || ev.TenantID == nil || *ev.TenantID != victimTen.ID || ev.IdPID != attackerTen.IdP {
		t.Fatalf("audit %+v: want the refusal under the kept session's identity and tenant", ev)
	}
	if attackerIdP.TokenCalls.Load() != 1 {
		t.Fatalf("token calls at the attacker's IdP = %d", attackerIdP.TokenCalls.Load())
	}

	// The same rule inside one tenant: another user of the victim's own IdP.
	victimIdP.SetUser(identity.FakeUser{Sub: "colleague-" + identity.RandomHex(3), Email: "colleague@v.test", EmailVerified: true})
	if rec := b.login(appHost, "scope=tenant&tenant="+victimTen.Slug); rec.Code != http.StatusForbidden {
		t.Fatalf("login of a colleague over an open session: HTTP %d", rec.Code)
	}
	if b.cookie(appHost, identity.SessionCookieName) != victimCookie {
		t.Fatal("the open session was replaced by a colleague's")
	}

	// The explicit step: log out, then the other identity signs in.
	if rec := b.do(http.MethodPost, "https://"+appHost+"/api/v1/auth/logout", unsafeHeaders(appHost, b.csrf(appHost))); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: HTTP %d", rec.Code)
	}
	b.mustLogin(appHost, "scope=tenant&tenant="+attackerTen.Slug)
	if s := authenticate(t, e, b, appHost, identity.OriginApp); s.IdPID != attackerTen.IdP {
		t.Fatalf("after logout the login opened a session of IdP %s", s.IdPID)
	}
}
