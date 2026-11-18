package httpapi

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
)

// TestMaintenance (P3-T17): while the gate is on every request is answered 503 maintenance (problem+json, Retry-After)
// before the session hook runs — public operations, unknown paths and the internal routes of the edge alike — except
// the platform sign-in on the admin origin (login, callback, logout, session), which reaches the chain as usual; once
// the gate is off nothing is intercepted.
func TestMaintenance(t *testing.T) {
	var on atomic.Bool
	on.Store(true)
	var sessions atomic.Int32
	internal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	e := newEnv(t, Options{
		Hooks: Hooks{Session: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sessions.Add(1); next.ServeHTTP(w, r) })
		}},
		Internal:    map[string]http.Handler{"GET /internal/edge/idp-console": internal},
		Maintenance: Maintenance{On: on.Load, AdminHost: "admin.example.com"},
	})
	host := func(h string) func(*http.Request) { return func(r *http.Request) { r.Host = h } }
	refused := []struct {
		method, target, host string
	}{
		{"GET", "/api/v1/tenants", "app.example.com"},
		{"GET", "/api/v1/platform/tenants", "admin.example.com"},
		{"POST", "/api/v1/tenants/" + tenantID + "/devices/sync", "app.example.com"},
		{"GET", "/api/v1/auth/login?scope=tenant&tenant=a", "app.example.com"}, // tenant sign-in: app origin
		{"GET", "/api/v1/auth/callback/" + itemID, "app.example.com"},
		{"GET", "/api/v1/auth/sessions", "admin.example.com"}, // only the sign-in itself
		{"GET", "/api/v1/auth/callback/" + itemID + "/x", "admin.example.com"},
		{"GET", "/internal/edge/idp-console", "admin.example.com"}, // the Keycloak console gate
		{"GET", "/no/such/path", "admin.example.com"},
	}
	for _, c := range refused {
		w := e.do(c.method, c.target, "", host(c.host))
		p := problemOf(t, w)
		if w.Code != http.StatusServiceUnavailable || p.Code != gen.ProblemCodeMaintenance || w.Header().Get("Retry-After") != "60" {
			t.Errorf("%s %s (%s) in maintenance: %d %s Retry-After %q", c.method, c.target, c.host, w.Code, p.Code,
				w.Header().Get("Retry-After"))
		}
	}
	if n := sessions.Load(); n != 0 {
		t.Errorf("the session hook ran %d times for refused requests", n)
	}
	for _, c := range []struct{ method, target, host string }{
		{"GET", "/api/v1/auth/login?scope=platform", "admin.example.com"},
		{"GET", "/api/v1/auth/login?scope=platform", "ADMIN.example.com:443"},
		{"GET", "/api/v1/auth/callback/" + itemID + "?code=x&state=y", "admin.example.com"},
		{"POST", "/api/v1/auth/logout", "admin.example.com"},
		{"GET", "/api/v1/auth/session", "admin.example.com"},
	} {
		w := e.do(c.method, c.target, "", host(c.host))
		if w.Code == http.StatusServiceUnavailable {
			t.Errorf("%s %s (%s): the platform sign-in must be served in maintenance, got 503", c.method, c.target, c.host)
		}
	}
	on.Store(false)
	for _, c := range refused[:3] {
		if w := e.do(c.method, c.target, "", host(c.host)); w.Code == http.StatusServiceUnavailable {
			t.Errorf("%s %s after maintenance: 503", c.method, c.target)
		}
	}
	if w := e.do("GET", "/internal/edge/idp-console", "", host("admin.example.com")); w.Code != http.StatusNoContent {
		t.Errorf("internal route after maintenance: %d", w.Code)
	}
	// No gate configured (the zero value): never in maintenance.
	plain := newEnv(t, Options{})
	if w := plain.do("GET", "/api/v1/tenants", ""); w.Code == http.StatusServiceUnavailable {
		t.Errorf("zero Maintenance: 503")
	}
}
