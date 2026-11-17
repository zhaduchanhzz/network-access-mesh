package idp

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
}

// TestHardenedHappyPath: a public name is resolved once, the connection goes to exactly the checked IP on 443, and
// TLS is verified for the original name.
func TestHardenedHappyPath(t *testing.T) {
	srv, pool := tlsServer(t, okHandler(`{"ok":true}`))
	h, res, log := hardenedFor(t, srv, pool, HardenedConfig{})
	resp, err := get(t.Context(), h.Client(), "https://example.com/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != `{"ok":true}` {
		t.Fatalf("body %q", b)
	}
	if got := log.list(); len(got) != 1 || got[0] != "93.184.215.14:443" {
		t.Fatalf("dialled %v, want exactly the checked IP on 443", got)
	}
	if res.count("example.com") != 1 {
		t.Fatalf("resolved %d times, want once", res.count("example.com"))
	}
}

// TestHardenedStaticRefusals: scheme, port, user info, IP literals, invalid names and the platform's domain are
// refused before any resolution or connection.
func TestHardenedStaticRefusals(t *testing.T) {
	srv, pool := tlsServer(t, okHandler(`{}`))
	h, res, log := hardenedFor(t, srv, pool, HardenedConfig{DenyDomains: []string{"Example.NET"}})
	cases := map[string]string{
		"http://example.com/":                "scheme",
		"ftp://example.com/":                 "scheme",
		"https://example.com:8443/":          "port",
		"https://example.com:80/":            "port",
		"https://user:pw@example.com/":       "userinfo",
		"https://93.184.215.14/":             "host_ip_literal",
		"https://[2606:4700:4700::1111]/":    "host_ip_literal",
		"https://169.254.169.254/latest/":    "host_ip_literal",
		"https://[::ffff:169.254.169.254]/":  "host_ip_literal",
		"https://[::1]/":                     "host_ip_literal",
		"https://idp/":                       "host_invalid", // single label (Docker service name)
		"https://localhost/":                 "host_invalid",
		"https://1.2.3.4.5/":                 "host_invalid", // numeric last label
		"https://0x7f.1/":                    "host_invalid",
		"https://2130706433/":                "host_invalid",
		"https://ex_ample.com/":              "host_invalid",
		"https://auth.example.net/realms/x":  "host_platform_domain",
		"https://example.net/":               "host_platform_domain",
		"https://tenant-a.mesh.example.net/": "host_platform_domain",
	}
	for target, reason := range cases {
		err := getErr(t.Context(), h.Client(), target)
		wantCode(t, target, err, CodeDestinationRefused, reason)
	}
	if n := len(log.list()); n != 0 {
		t.Fatalf("%d connections made for refused URLs", n)
	}
	if res.count("example.com") != 0 {
		t.Fatal("a refused URL was resolved")
	}
	// a name that merely ends like the platform's domain is not under it
	res.set("notexample.net", []netip.Addr{publicIP})
	if err := h.CheckURL(mustURL("https://notexample.net/x")); err != nil {
		t.Fatalf("notexample.net refused: %v", err)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// TestHardenedDNSRebinding: a name that answers a public address first and an internal one afterwards. Each
// connection resolves exactly once and connects to exactly the address it checked; the internal answer is refused
// and never dialled.
func TestHardenedDNSRebinding(t *testing.T) {
	srv, pool := tlsServer(t, okHandler(`{}`))
	h, res, log := hardenedFor(t, srv, pool, HardenedConfig{})
	// example.com (the name of the test certificate) answers the public address, then the edge's admin listener
	res.set("example.com", addrs("93.184.215.14"), addrs("10.249.2.2"))
	resp, err := get(t.Context(), h.Client(), "https://example.com/first")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	h.Client().CloseIdleConnections() // force a new connection: a new (single) resolution
	err = getErr(t.Context(), h.Client(), "https://example.com/second")
	wantCode(t, "rebound answer", err, CodeDestinationRefused, "address_"+ReasonPrivate)
	if got := log.list(); len(got) != 1 || got[0] != "93.184.215.14:443" {
		t.Fatalf("dialled %v: the internal answer must never be dialled", got)
	}
	if res.count("example.com") != 2 {
		t.Fatalf("resolutions = %d, want one per connection (2)", res.count("example.com"))
	}
	// a mixed answer (public + internal) is refused as a whole
	res.set("example.com", addrs("93.184.215.14", "169.254.169.254"))
	h.Client().CloseIdleConnections()
	err = getErr(t.Context(), h.Client(), "https://example.com/third")
	wantCode(t, "mixed answer", err, CodeDestinationRefused, "address_"+ReasonLinkLocal)
	if n := len(log.list()); n != 1 {
		t.Fatalf("a mixed answer was dialled (%d dials)", n)
	}
}

// TestHardenedTLSNameVerified: the connection goes to the checked IP but the certificate must be valid for the
// requested name — a server holding another name's certificate is refused.
func TestHardenedTLSNameVerified(t *testing.T) {
	srv, pool := tlsServer(t, okHandler(`{}`))
	h, res, _ := hardenedFor(t, srv, pool, HardenedConfig{})
	res.set("other.example.org", []netip.Addr{publicIP})
	err := getErr(t.Context(), h.Client(), "https://other.example.org/")
	wantCode(t, "certificate of another name", Classify("t", err), CodeTLS, "")
	// and an untrusted CA
	h2, res2, _ := hardenedFor(t, srv, nil, HardenedConfig{})
	res2.set("example.com", []netip.Addr{publicIP})
	err = getErr(t.Context(), h2.Client(), "https://example.com/")
	wantCode(t, "unknown CA", Classify("t", err), CodeTLS, "")
}

// TestHardenedRedirectRefused: no redirect is followed — neither to an internal address nor to the same host.
func TestHardenedRedirectRefused(t *testing.T) {
	for _, loc := range []string{"https://169.254.169.254/latest/meta-data/", "https://10.249.2.2:8081/api/v1/node",
		"https://example.com/elsewhere", "http://example.com/"} {
		srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loc, http.StatusFound)
		}))
		h, _, log := hardenedFor(t, srv, pool, HardenedConfig{})
		err := getErr(t.Context(), h.Client(), "https://example.com/.well-known/openid-configuration")
		wantCode(t, loc, err, CodeRedirectRefused, "")
		if got := log.list(); len(got) != 1 {
			t.Fatalf("%s: dialled %v — the redirect target must never be contacted", loc, got)
		}
	}
	// even a copy of the client that follows redirects stays inside the policy: the transport re-checks every hop
	srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	h, _, log := hardenedFor(t, srv, pool, HardenedConfig{})
	follow := *h.Client()
	follow.CheckRedirect = nil
	err := getErr(t.Context(), &follow, "https://example.com/")
	wantCode(t, "redirect hop", err, CodeDestinationRefused, "host_ip_literal")
	if got := log.list(); len(got) != 1 {
		t.Fatalf("dialled %v", got)
	}
}

// TestHardenedResponseLimits: a declared or streamed body over the limit fails; the body is never truncated
// silently.
func TestHardenedResponseLimits(t *testing.T) {
	big := strings.Repeat("x", 2048)
	srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			for range 4 {
				_, _ = io.WriteString(w, big)
				w.(http.Flusher).Flush()
			}
			return
		}
		w.Header().Set("Content-Length", "8192")
		_, _ = io.WriteString(w, strings.Repeat(big, 4))
	}))
	h, _, _ := hardenedFor(t, srv, pool, HardenedConfig{MaxBody: 4096})
	err := getErr(t.Context(), h.Client(), "https://example.com/declared")
	wantCode(t, "Content-Length over the limit", err, CodeResponseTooLarge, "content_length")
	resp, err := get(t.Context(), h.Client(), "https://example.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	wantCode(t, "streamed body over the limit", err, CodeResponseTooLarge, "body")
}

// TestHardenedTimeout: a slow IdP ends in CodeTimeout within the configured time.
func TestHardenedTimeout(t *testing.T) {
	release := make(chan struct{})
	srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	h, _, _ := hardenedFor(t, srv, pool, HardenedConfig{Timeout: 300 * time.Millisecond})
	start := time.Now()
	err := getErr(context.Background(), h.Client(), "https://example.com/slow")
	wantCode(t, "slow IdP", Classify("t", err), CodeTimeout, "")
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %v", d)
	}
}

// TestHardenedIgnoresProxyEnvironment: HTTPS_PROXY would make a proxy resolve the name — the client ignores it. The
// transports are checked directly too: http.ProxyFromEnvironment reads the environment once per process, so a
// variable set by a test could go unnoticed.
func TestHardenedIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")
	srv, pool := tlsServer(t, okHandler(`{}`))
	h, _, log := hardenedFor(t, srv, pool, HardenedConfig{})
	resp, err := get(t.Context(), h.Client(), "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := log.list(); len(got) != 1 || got[0] != "93.184.215.14:443" {
		t.Fatalf("dialled %v", got)
	}
	route, err := NewPlatformRoute(PlatformRouteConfig{Host: "auth.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	for name, rt := range map[string]http.RoundTripper{"hardened": h.transport, "platform route": route.transport} {
		g, ok := rt.(*guardTransport)
		if !ok {
			t.Fatalf("%s: transport %T", name, rt)
		}
		if tr, ok := g.next.(*http.Transport); !ok || tr.Proxy != nil {
			t.Fatalf("%s: the transport uses a proxy", name)
		}
	}
}

// TestHardenedSocketGuard: the guard of the default dialer refuses an internal address or another port right before
// connect(2), whatever path led there.
func TestHardenedSocketGuard(t *testing.T) {
	h, err := NewHardened(HardenedConfig{Deny: []netip.Prefix{netip.MustParsePrefix("9.9.9.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	for addr, reason := range map[string]string{
		"127.0.0.1:443": "address_" + ReasonLoopback, "[::ffff:10.0.0.1]:443": "address_ipv4_mapped_" + ReasonPrivate,
		"169.254.169.254:443": "address_" + ReasonLinkLocal, "8.8.8.8:80": "port", "9.9.9.9:443": "address_" + ReasonConfigured,
		"[fe80::1]:443": "address_" + ReasonLinkLocal, "garbage": "address_unparsable",
	} {
		wantCode(t, addr, h.SocketGuard(addr), CodeDestinationRefused, reason)
	}
	if err := h.SocketGuard("8.8.8.8:443"); err != nil {
		t.Fatalf("public address refused: %v", err)
	}
	// default dialer + guard: an internal destination is refused by the dialler itself, even when called directly
	_, err = h.dialChecked(t.Context(), "tcp", "127.0.0.1:443")
	wantCode(t, "direct dial", err, CodeDestinationRefused, "address_"+ReasonLoopback)
	_, err = h.dialChecked(t.Context(), "udp", "8.8.8.8:443")
	wantCode(t, "udp", err, CodeDestinationRefused, "network")
}

// TestHardenedDNSFailure: an unresolvable name is CodeUnavailable/dns, never a fallback.
func TestHardenedDNSFailure(t *testing.T) {
	srv, pool := tlsServer(t, okHandler(`{}`))
	h, _, log := hardenedFor(t, srv, pool, HardenedConfig{})
	err := getErr(t.Context(), h.Client(), "https://missing.example.org/")
	wantCode(t, "nxdomain", err, CodeUnavailable, "dns")
	if len(log.list()) != 0 {
		t.Fatal("dialled without an answer")
	}
	err = h.CheckDestination(t.Context(), mustURL("https://example.com/token"))
	if err != nil {
		t.Fatalf("CheckDestination: %v", err)
	}
}
