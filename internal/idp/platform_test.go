package idp

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// routeFor returns a platform route for host example.com (the name of the test certificate) whose dialler records
// the address it was asked for and reaches srv.
func routeFor(t *testing.T, srv *httptest.Server, pool *x509.CertPool, cfg PlatformRouteConfig) (*PlatformRoute, *dialLog) {
	t.Helper()
	log := &dialLog{}
	if cfg.Host == "" {
		cfg.Host = "example.com"
	}
	cfg.RootCAs = pool
	cfg.Dial = log.dialer(srv.Listener.Addr().String())
	r, err := NewPlatformRoute(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r, log
}

// TestPlatformRoute: one host, https/443, the allowed paths only, the configured address only, TLS for the host.
func TestPlatformRoute(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	}))
	r, log := routeFor(t, srv, pool, PlatformRouteConfig{Address: "10.249.0.2:443"})
	if r.BaseURL() != "https://example.com" || r.Host() != "example.com" {
		t.Fatalf("base %q host %q", r.BaseURL(), r.Host())
	}
	for _, ok := range []string{"/realms/t1/.well-known/openid-configuration", "/realms/t1/protocol/openid-connect/token",
		"/admin/realms", "/admin/realms/t1/users", "/realms/t1/protocol/openid-connect/certs"} {
		resp, err := get(t.Context(), r.Client(), "https://example.com"+ok)
		if err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
		_ = resp.Body.Close()
	}
	for _, d := range log.list() {
		if d != "10.249.0.2:443" {
			t.Fatalf("dialled %q, want only the configured address", d)
		}
	}
	refusals := map[string]string{
		"https://other.example.com/realms/x":             "platform_host",
		"https://169.254.169.254/realms/x":               "platform_host",
		"http://example.com/realms/x":                    "scheme",
		"https://example.com:8443/realms/x":              "port",
		"https://example.com/admin/master/console/":      "platform_path",
		"https://example.com/admin/realmsX":              "platform_path",
		"https://example.com/metrics":                    "platform_path",
		"https://example.com/health/ready":               "platform_path",
		"https://example.com/realms/../admin/master":     "platform_path",
		"https://example.com/realms/%2e%2e/admin":        "platform_path",
		"https://example.com/realms/x%2F..%2F..%2Fadmin": "platform_path",
		"https://example.com/realms//x":                  "platform_path",
		"https://example.com/realms/x/./y":               "platform_path",
		"https://example.com/realms/x;y":                 "platform_path",
		"https://u:p@example.com/realms/x":               "userinfo",
	}
	before := len(log.list())
	for target, reason := range refusals {
		err := getErr(t.Context(), r.Client(), target)
		wantCode(t, target, err, CodeDestinationRefused, reason)
	}
	if len(log.list()) != before {
		t.Fatal("a refused request was dialled")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if strings.Contains(p, "..") || strings.HasPrefix(p, "/admin/master") {
			t.Fatalf("server saw %q", p)
		}
	}
}

// TestPlatformRouteTLS: the route verifies TLS for its host even though it dials an address — a server presenting
// another name's certificate is refused.
func TestPlatformRouteTLS(t *testing.T) {
	srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }))
	r, _ := routeFor(t, srv, pool, PlatformRouteConfig{Host: "auth.example.net", Address: "10.249.0.2:443"})
	err := getErr(t.Context(), r.Client(), "https://auth.example.net/realms/x")
	wantCode(t, "certificate of another name", Classify("t", err), CodeTLS, "")
	// default address: the host itself through the resolver (the edge alias on mg-edge)
	r2, err := NewPlatformRoute(PlatformRouteConfig{Host: "auth.example.net"})
	if err != nil || r2.address != "auth.example.net:443" {
		t.Fatalf("default address %q, %v", r2.address, err)
	}
	for _, bad := range []PlatformRouteConfig{{Host: "auth"}, {Host: "10.249.0.2"}, {Host: "auth.example.net", Address: "edge"},
		{Host: "auth.example.net", Paths: []string{"realms/"}}} {
		if _, err := NewPlatformRoute(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// TestIssuerClientRouting: the single client of the Relying Party sends the platform IdP host through the route —
// restricted to /realms/ — and everything else through the hardened client; the platform's domain is refused on the
// hardened side.
func TestIssuerClientRouting(t *testing.T) {
	srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }))
	route, rlog := routeFor(t, srv, pool, PlatformRouteConfig{Address: "10.249.0.2:443"})
	res := newResolver()
	res.set("idp.tenant.example.org", []netip.Addr{publicIP})
	hlog := &dialLog{}
	srv2, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }))
	h, err := NewHardened(HardenedConfig{Resolver: res, RootCAs: pool, Dial: hlog.dialer(srv2.Listener.Addr().String()),
		DenyDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewIssuerClient(h, route)
	resp, err := get(t.Context(), c, "https://example.com/realms/t1/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := rlog.list(); len(got) != 1 || got[0] != "10.249.0.2:443" {
		t.Fatalf("platform route dialled %v", got)
	}
	// the Admin API is not reachable through the Relying Party's client
	err = getErr(t.Context(), c, "https://example.com/admin/realms/t1/users")
	wantCode(t, "admin API via issuer client", err, CodeDestinationRefused, "platform_path")
	// a sub-domain of the platform's domain is not the platform IdP host: hardened side, refused
	err = getErr(t.Context(), c, "https://app.example.com/realms/x")
	wantCode(t, "platform sub-domain", err, CodeDestinationRefused, "host_platform_domain")
	// a tenant's issuer goes through the hardened client (TLS fails here: the test certificate is for example.com —
	// what matters is that the hardened dialler, not the route, was used)
	_ = getErr(t.Context(), c, "https://idp.tenant.example.org/.well-known/openid-configuration")
	if got := hlog.list(); len(got) != 1 || got[0] != publicIP.String()+":443" {
		t.Fatalf("hardened dialled %v", got)
	}
	if len(rlog.list()) != 1 {
		t.Fatal("a tenant issuer used the platform route")
	}
	// without a platform IdP, the platform host is just another (refused) name
	c2 := NewIssuerClient(h, nil)
	err = getErr(context.Background(), c2, "https://example.com/realms/t1/.well-known/openid-configuration")
	wantCode(t, "no platform route", err, CodeDestinationRefused, "host_platform_domain")
}
