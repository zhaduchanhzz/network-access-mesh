package identity_test

import (
	"net/http"
	"testing"
)

// TestExplicitReauth — reauth=true of GET /auth/login (added to api/openapi.yaml at the Phase 2 integration) asks
// the IdP for a re-authentication (prompt=login, max_age=0) even when the request carries no session; absent or
// false, a first login sends no prompt and max_age = the absolute session lifetime, as before.
func TestExplicitReauth(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ten := e.newTenant(e.fakeIdP())
	b := e.browser()
	for _, c := range []struct {
		query  string
		stepUp bool
	}{
		{"scope=tenant&tenant=" + ten.Slug, false},
		{"scope=tenant&tenant=" + ten.Slug + "&reauth=false", false},
		{"scope=tenant&tenant=" + ten.Slug + "&reauth=true", true},
	} {
		rec := b.startLogin(appHost, c.query)
		wantStatus(t, c.query, rec.Code, http.StatusFound, rec.Body.String())
		_, q := locationQuery(t, rec.Header().Get("Location"))
		want := [2]string{"", "43200"}
		if c.stepUp {
			want = [2]string{"login", "0"}
		}
		if got := [2]string{q.Get("prompt"), q.Get("max_age")}; got != want {
			t.Errorf("%s: prompt, max_age = %q, want %q", c.query, got, want)
		}
	}
	// The explicit re-authentication completes like any login.
	rec := b.login(appHost, "scope=tenant&tenant="+ten.Slug+"&reauth=true")
	wantStatus(t, "login with reauth=true", rec.Code, http.StatusFound, rec.Body.String())
}
