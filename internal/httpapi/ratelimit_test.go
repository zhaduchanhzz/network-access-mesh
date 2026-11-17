package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

var generous = ratelimit.Limit{Every: time.Millisecond, Burst: 1000}

// tight limits one class; every other class keeps generous limits so that only the class under test can deny.
func tight(class Class, perIP, perIdentity ratelimit.Limit) RateLimits {
	rl := RateLimits{}
	for _, c := range Classes {
		rl[c] = ClassLimits{PerIP: generous, PerIdentity: generous}
	}
	rl[class] = ClassLimits{PerIP: perIP, PerIdentity: perIdentity}
	return rl
}

func rateHeaders(w *httptest.ResponseRecorder) [4]string {
	h := w.Header()
	return [4]string{h.Get("RateLimit-Limit"), h.Get("RateLimit-Remaining"), h.Get("RateLimit-Reset"), h.Get("Retry-After")}
}

// TestRateLimitPerIP walks a client through its bucket with the fake clock: exact headers, 429 problem, refill.
func TestRateLimitPerIP(t *testing.T) {
	e := newEnv(t, Options{RateLimits: tight(ClassDefault, ratelimit.Limit{Every: time.Second, Burst: 2}, generous)})
	a, b := from("198.51.100.7:4000"), from("198.51.100.8:4000")
	steps := []struct {
		advance time.Duration
		client  func(*http.Request)
		status  int
		headers [4]string
	}{
		{0, a, 501, [4]string{"2", "1", "1", ""}},
		{0, a, 501, [4]string{"2", "0", "2", ""}},
		{0, a, 429, [4]string{"2", "0", "2", "1"}},
		{0, b, 501, [4]string{"2", "1", "1", ""}}, // another client has its own bucket
		{500 * time.Millisecond, a, 429, [4]string{"2", "0", "2", "1"}},
		{500 * time.Millisecond, a, 501, [4]string{"2", "0", "2", ""}}, // one token refilled after 1 s
		{10 * time.Second, a, 501, [4]string{"2", "1", "1", ""}},
	}
	for i, s := range steps {
		e.clock.Advance(s.advance)
		w := e.do(http.MethodGet, "/api/v1/tenants", "", s.client)
		if w.Code != s.status || rateHeaders(w) != s.headers {
			t.Fatalf("step %d: status %d headers %v; want %d %v", i, w.Code, rateHeaders(w), s.status, s.headers)
		}
		if w.Code == http.StatusTooManyRequests {
			p := problemOf(t, w)
			line := e.accessLine(p.RequestId)
			if p.Code != gen.ProblemCodeRateLimited || line["level"] != "WARN" || line["rate_limited_by"] != "default/ip" {
				t.Fatalf("step %d: problem %+v, log %v", i, p, line)
			}
		}
	}
}

// TestRateLimitClasses: auth, enrollment and sync have their own (stricter) buckets; the class follows the path
// segments as the router sees them, so an encoded path cannot slip into a laxer class.
func TestRateLimitClasses(t *testing.T) {
	one := ratelimit.Limit{Every: time.Hour, Burst: 1}
	for _, c := range []struct {
		class        Class
		first, again struct{ method, target string }
	}{
		{ClassAuth, req(http.MethodGet, "/api/v1/auth/session"), req(http.MethodGet, "/api/v1/%61uth/login?scope=tenant")},
		{ClassEnrollment, req(http.MethodPost, "/api/v1/tenants/"+tenantID+"/enrollment/requests"), req(http.MethodGet, "/api/v1/tenants/"+tenantID+"/enrollment/instructions")},
		{ClassSync, req(http.MethodPost, "/api/v1/tenants/"+tenantID+"/devices/sync"), req(http.MethodGet, "/api/v1/tenants/"+tenantID+"/devices?fresh=true")},
	} {
		e := newEnv(t, Options{RateLimits: tight(c.class, one, one)})
		if w := e.do(c.first.method, c.first.target, "", idempotency); w.Code == http.StatusTooManyRequests {
			t.Fatalf("%s: first request limited", c.class)
		}
		w := e.do(c.again.method, c.again.target, "", idempotency)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("%s: %s %s shares the class bucket, got %d", c.class, c.again.method, c.again.target, w.Code)
		} else if line := e.accessLine(problemOf(t, w).RequestId); line["rate_limited_by"] != string(c.class)+"/ip" {
			t.Errorf("%s: log %v", c.class, line)
		}
		// The default class is untouched.
		for _, target := range []string{"/api/v1/tenants", "/api/v1/tenants/" + tenantID + "/devices", "/api/v1/tenants/" + tenantID + "/devices?fresh=false"} {
			if w := e.do(http.MethodGet, target, ""); w.Code == http.StatusTooManyRequests {
				t.Errorf("%s: %s was limited by another class", c.class, target)
			}
		}
	}
}

func req(method, target string) struct{ method, target string } {
	return struct{ method, target string }{method, target}
}

// TestRateLimitPerIdentity: once the session hook has called SetIdentity, the identity has its own bucket whatever
// its address; the headers show the bucket closest to exhaustion.
func TestRateLimitPerIdentity(t *testing.T) {
	session := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id := r.Header.Get("X-Test-Identity"); id != "" {
				SetIdentity(r.Context(), id)
			}
			next.ServeHTTP(w, r)
		})
	}
	e := newEnv(t, Options{
		Hooks:      Hooks{Session: session},
		RateLimits: tight(ClassDefault, ratelimit.Limit{Every: time.Second, Burst: 10}, ratelimit.Limit{Every: time.Second, Burst: 2}),
	})
	alice := header("X-Test-Identity", "identity-alice")
	ipA, ipB := from("198.51.100.7:1"), from("203.0.113.9:1")
	steps := []struct {
		mods      []func(*http.Request)
		status    int
		remaining string
		deniedBy  string
	}{
		{[]func(*http.Request){alice, ipA}, 501, "1", ""}, // identity bucket (1 left) is tighter than IP (9 left)
		{[]func(*http.Request){alice, ipB}, 501, "0", ""}, // same identity from another address: same bucket
		{[]func(*http.Request){alice, ipA}, 429, "0", "default/identity"},
		{[]func(*http.Request){header("X-Test-Identity", "identity-bob"), ipA}, 501, "1", ""},
		{[]func(*http.Request){ipA}, 501, "6", ""}, // anonymous: IP bucket only (4 taken from 198.51.100.7, this is the 5th)
	}
	for i, s := range steps {
		w := e.do(http.MethodGet, "/api/v1/tenants", "", s.mods...)
		if w.Code != s.status || w.Header().Get("RateLimit-Remaining") != s.remaining {
			t.Fatalf("step %d: status %d remaining %q; want %d %q", i, w.Code, w.Header().Get("RateLimit-Remaining"), s.status, s.remaining)
		}
		line := e.accessLine(w.Header().Get(requestid.Header))
		if denied, _ := line["rate_limited_by"].(string); denied != s.deniedBy {
			t.Fatalf("step %d: rate_limited_by %q, want %q", i, denied, s.deniedBy)
		}
	}
}

// TestRateLimitBehindEdge: with the edge as trusted proxy, each client behind it has its own bucket; a client that
// is not the edge cannot choose its bucket with X-Forwarded-For.
func TestRateLimitBehindEdge(t *testing.T) {
	e := newEnv(t, Options{
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.249.0.2/32")},
		RateLimits:     tight(ClassDefault, ratelimit.Limit{Every: time.Hour, Burst: 1}, generous),
	})
	edge := from("10.249.0.2:41000")
	xff := func(v string) func(*http.Request) { return header("X-Forwarded-For", v) }
	steps := []struct {
		mods   []func(*http.Request)
		status int
	}{
		{[]func(*http.Request){edge, xff("198.51.100.7")}, 501},
		{[]func(*http.Request){edge, xff("198.51.100.8")}, 501},              // another client behind the edge
		{[]func(*http.Request){edge, xff("1.2.3.4, 198.51.100.7")}, 429},     // spoofed left entry ignored
		{[]func(*http.Request){from("198.51.100.9:1"), xff("1.1.1.1")}, 501}, // direct peer: its own address
		{[]func(*http.Request){from("198.51.100.9:2"), xff("2.2.2.2")}, 429}, // …whatever X-Forwarded-For says
	}
	for i, s := range steps {
		if w := e.do(http.MethodGet, "/api/v1/tenants", "", s.mods...); w.Code != s.status {
			t.Fatalf("step %d: status %d, want %d", i, w.Code, s.status)
		}
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.249.0.2/32"), netip.MustParsePrefix("10.248.0.0/24")}
	for _, c := range []struct {
		peer string
		xff  []string
		want string
	}{
		{"198.51.100.7:1234", nil, "198.51.100.7"},
		{"198.51.100.7:1234", []string{"1.2.3.4"}, "198.51.100.7"}, // untrusted peer: header ignored
		{"10.249.0.2:1234", nil, "10.249.0.2"},
		{"10.249.0.2:1234", []string{"203.0.113.5"}, "203.0.113.5"},
		{"10.249.0.2:1234", []string{"6.6.6.6, 203.0.113.5"}, "203.0.113.5"},
		{"10.249.0.2:1234", []string{"6.6.6.6", "203.0.113.5, 10.248.0.1"}, "203.0.113.5"}, // two header lines, proxy chain
		{"10.249.0.2:1234", []string{"203.0.113.5, not-an-ip"}, "10.249.0.2"},
		{"10.249.0.2:1234", []string{"10.248.0.1"}, "10.249.0.2"}, // only proxies: the peer
		{"10.249.0.2:1234", []string{"[2001:db8::1]:443"}, "2001:db8::1"},
		{"[::ffff:198.51.100.7]:1234", nil, "198.51.100.7"},
		{"[fe80::1%eth0]:1234", nil, "fe80::1"},
		{"garbage", nil, "invalid IP"},
	} {
		r := request(http.MethodGet, "/", "", from(c.peer))
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r, trusted).String(); got != c.want {
			t.Errorf("peer %s xff %v: %s, want %s", c.peer, c.xff, got, c.want)
		}
	}
}

func TestIPKey(t *testing.T) {
	for addr, want := range map[string]string{
		"198.51.100.7":           "ip:198.51.100.7",
		"2001:db8:1:2:3:4:5:6":   "ip6:2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9":   "ip6:2001:db8:1:2::/64", // same /64, same bucket
		"::ffff:198.51.100.7":    "ip6:::/64",             // only reached if never unmapped; parseAddr unmaps
		"invalid (zero) address": "ip:unknown",
	} {
		a, _ := netip.ParseAddr(addr)
		if got := ipKey(a); got != want {
			t.Errorf("ipKey(%s) = %s, want %s", addr, got, want)
		}
	}
}
