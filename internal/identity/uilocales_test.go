package identity_test

import (
	"net/http"
	"testing"
)

// TestLoginPassesUILocales — G4b-E14: the language of the Portal (ui_locales of GET /auth/login) reaches the IdP as the
// OIDC ui_locales parameter, on both origins; without it none is sent; a language the Portal does not have is refused
// (422) before anything is stored.
func TestLoginPassesUILocales(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ten := e.newTenant(e.fakeIdP())
	e.newPlatform(e.fakeIdP())
	for _, c := range []struct {
		host, query, want string
	}{
		{appHost, "scope=tenant&tenant=" + ten.Slug + "&ui_locales=vi", "vi"},
		{appHost, "scope=tenant&tenant=" + ten.Slug + "&ui_locales=en", "en"},
		{adminHost, "scope=platform&ui_locales=vi", "vi"},
		{appHost, "scope=tenant&tenant=" + ten.Slug, ""},
	} {
		rec := e.browser().startLogin(c.host, c.query)
		_, q := locationQuery(t, rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || q.Get("ui_locales") != c.want || (c.want == "" && q.Has("ui_locales")) {
			t.Errorf("%s %s: HTTP %d ui_locales %q, want %q", c.host, c.query, rec.Code, q.Get("ui_locales"), c.want)
		}
	}
	before := e.count(`SELECT count(*) FROM auth_requests WHERE idp_id = $1`, ten.IdP)
	if rec := e.browser().startLogin(appHost, "scope=tenant&tenant="+ten.Slug+"&ui_locales=fr"); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("ui_locales=fr: HTTP %d, want 422", rec.Code)
	}
	if n := e.count(`SELECT count(*) FROM auth_requests WHERE idp_id = $1`, ten.IdP); n != before {
		t.Error("a refused ui_locales stored an auth request")
	}
}
