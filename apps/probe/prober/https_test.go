package prober

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/stub"
)

const mesh = "mesh.example.test"

func newEdge(t *testing.T) *stub.Edge {
	t.Helper()
	e, err := stub.NewEdge("127.0.0.1:0", mesh, "tenant-a", "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestHTTPSAllowedPath(t *testing.T) {
	e := newEdge(t)
	p := New(Options{Allow: loopback, RootCAs: e.CA})
	host := e.Host("tenant-a")
	res, err := p.HTTPS(t.Context(), HTTPSRequest{Address: e.Addr().String(), SNI: host, Path: "/key?v=113",
		Headers: []string{"content-type"}, Expect: Expect{Status: []int{200}, JSONPresent: []string{"publicKey"},
			Headers: map[string]string{"Content-Type": "application/json"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Status != 200 || res.Class != ClassOK || res.JSON["publicKey"] != e.PublicKeys[host] ||
		res.Headers["Content-Type"] != "application/json" || res.Host != host || res.Path != "/key?v=113" {
		t.Fatalf("result %+v", res)
	}
	if res.TLS == nil || res.TLS.Version != "TLS 1.3" || !slices.Equal(res.TLS.DNSNames, []string{"*." + mesh}) ||
		res.TLS.NotAfter.IsZero() || res.TLS.Issuer != "MeshGuard prober stub CA" {
		t.Fatalf("tls %+v", res.TLS)
	}
	if res.Timing.ConnectMS <= 0 || res.Timing.TLSMS <= 0 || res.Timing.FirstByteMS <= 0 || res.Timing.TotalMS <
		res.Timing.TLSMS || res.BodySize == 0 || len(res.BodySHA256) != 64 {
		t.Fatalf("timing/body %+v", res)
	}
	// the request is exactly what was asked for: SNI, Host and the raw request target
	got := e.Requests()
	if len(got) != 1 || got[0] != (stub.Request{SNI: host, Host: host, Target: "/key?v=113"}) {
		t.Fatalf("edge received %+v", got)
	}
}

// A forbidden path ⇒ 404, classified not_found; the expectation decides whether that is OK.
func TestHTTPSForbiddenPathIs404(t *testing.T) {
	e := newEdge(t)
	p := New(Options{Allow: loopback, RootCAs: e.CA})
	req := HTTPSRequest{Address: e.Addr().String(), SNI: e.Host("tenant-a"), Path: "/api/v1/apikey", Expect: Expect{Status: []int{404}}}
	res, err := p.HTTPS(t.Context(), req)
	if err != nil || !res.OK || res.Status != 404 || res.Class != ClassNotFound || res.Error != nil {
		t.Fatalf("%+v %v", res, err)
	}
	req.Expect.Status = []int{200}
	res, _ = p.HTTPS(t.Context(), req)
	if res.OK || len(res.Failures) != 1 || res.Failures[0] != (Failure{Check: "status", Want: "200", Got: "404"}) {
		t.Fatalf("%+v", res)
	}
	// the raw target is sent byte for byte (no normalisation of %2e or ..)
	req.Path, req.Expect = "/derp/%2e%2e/api/v1/apikey", Expect{}
	if _, err := p.HTTPS(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if r := e.Requests(); r[len(r)-1].Target != "/derp/%2e%2e/api/v1/apikey" {
		t.Fatalf("target sent %q", r[len(r)-1].Target)
	}
}

// SNI and Host are independent: SNI tenant-a + Host tenant-b ⇒ the edge answers 421 (misdirected); a SNI without a
// certificate ⇒ tls_handshake; a certificate that does not cover the SNI ⇒ tls_verify; roots without the CA ⇒
// tls_verify (verification is on by default).
func TestSNIAndHost(t *testing.T) {
	e := newEdge(t)
	p := New(Options{Allow: loopback, RootCAs: e.CA})
	addr, a, b := e.Addr().String(), e.Host("tenant-a"), e.Host("tenant-b")
	res, err := p.HTTPS(t.Context(), HTTPSRequest{Address: addr, SNI: a, Host: b, Path: "/key?v=113", Expect: Expect{Status: []int{421}}})
	if err != nil || !res.OK || res.Class != ClassMisdirected || res.SNI != a || res.Host != b {
		t.Fatalf("SNI≠Host: %+v %v", res, err)
	}
	if r := e.Requests(); r[len(r)-1].SNI != a || r[len(r)-1].Host != b {
		t.Fatalf("edge saw %+v", r[len(r)-1])
	}
	res, _ = p.HTTPS(t.Context(), HTTPSRequest{Address: addr, SNI: "foreign.example", Path: "/"})
	if res.OK || res.Error == nil || res.Error.Code != CodeTLSHandshake || res.Status != 0 {
		t.Fatalf("foreign SNI: %+v", res)
	}
	e.SetLenient(true)
	res, _ = p.HTTPS(t.Context(), HTTPSRequest{Address: addr, SNI: "foreign.example", Path: "/"})
	if res.OK || res.Error == nil || res.Error.Code != CodeTLSVerify || !strings.Contains(res.Error.Message, "not valid for the SNI") {
		t.Fatalf("certificate for another name: %+v", res)
	}
	e.SetLenient(false)
	res, _ = New(Options{Allow: loopback}).HTTPS(t.Context(), HTTPSRequest{Address: addr, SNI: a, Path: "/key?v=113"})
	if res.OK || res.Error == nil || res.Error.Code != CodeTLSVerify || !strings.Contains(res.Error.Message, "unknown authority") {
		t.Fatalf("system roots against the stub CA: %+v", res)
	}
	// an unknown tenant under the mesh domain gets the edge's uniform 404
	res, _ = p.HTTPS(t.Context(), HTTPSRequest{Address: addr, SNI: e.Host("nope"), Path: "/key?v=113"})
	if res.Status != 404 || res.Class != ClassNotFound {
		t.Fatalf("unknown tenant: %+v", res)
	}
}

func TestHTTPSTransportErrors(t *testing.T) {
	p := New(Options{Allow: loopback})
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() { // accepts and never answers
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	start := time.Now()
	res, err := p.HTTPS(t.Context(), HTTPSRequest{Address: ln.Addr().String(), SNI: "x.example", TimeoutMS: 700})
	if err != nil || res.Error == nil || res.Error.Code != CodeTimeout || time.Since(start) > 3*time.Second {
		t.Fatalf("silent server: %+v %v", res, err)
	}
	closed, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.Addr().String()
	_ = closed.Close()
	res, _ = p.HTTPS(t.Context(), HTTPSRequest{Address: addr, SNI: "x.example"})
	if res.Error == nil || res.Error.Code != CodeRefused {
		t.Fatalf("closed port: %+v", res)
	}
}

func TestHTTPSChecks(t *testing.T) {
	e := newEdge(t)
	p := New(Options{Allow: loopback, RootCAs: e.CA})
	host := e.Host("tenant-a")
	ok, _ := p.HTTPS(t.Context(), HTTPSRequest{Address: e.Addr().String(), SNI: host, Path: "/derp/probe"})
	empty := sha256.Sum256(nil)
	if !ok.OK || ok.BodySize != 0 || ok.BodySHA256 != hex.EncodeToString(empty[:]) {
		t.Fatalf("%+v", ok)
	}
	size := int64(3)
	res, _ := p.HTTPS(t.Context(), HTTPSRequest{Address: e.Addr().String(), SNI: host, Path: "/key?v=113",
		Expect: Expect{Status: []int{200}, BodySHA256: strings.Repeat("0", 64), BodySize: &size,
			Headers: map[string]string{"X-Missing": "1"}, JSONEquals: map[string]string{"publicKey": "mkey:other"},
			JSONPresent: []string{"absent"}}})
	var checks []string
	for _, f := range res.Failures {
		checks = append(checks, f.Check)
	}
	slices.Sort(checks)
	want := []string{"body_sha256", "body_size", "header:x-missing", "json:absent", "json:publicKey"}
	if res.OK || !slices.Equal(checks, want) {
		t.Fatalf("failures %v, want %v (%+v)", checks, want, res.Failures)
	}
	// a body that is not JSON fails the JSON checks; a body over the limit is reported truncated
	small := New(Options{Allow: loopback, RootCAs: e.CA, MaxBody: 10})
	res, _ = small.HTTPS(t.Context(), HTTPSRequest{Address: e.Addr().String(), SNI: host, Path: "/key?v=113",
		Expect: Expect{JSONPresent: []string{"publicKey"}}})
	if res.OK || !res.BodyTruncated || res.BodySize != 10 || len(res.Failures) != 1 || res.Failures[0].Check != "body" {
		t.Fatalf("truncated: %+v", res)
	}
	res, _ = p.HTTPS(t.Context(), HTTPSRequest{Address: e.Addr().String(), SNI: host, Path: "/register/x",
		Expect: Expect{JSONPresent: []string{"publicKey"}}})
	if res.OK || len(res.Failures) != 1 || res.Failures[0].Check != "json" {
		t.Fatalf("not JSON: %+v", res)
	}
}

// Malformed requests and targets outside the allow-list are refused before any connection is made.
func TestHTTPSRefusesBeforeConnecting(t *testing.T) {
	e := newEdge(t)
	p := New(Options{Allow: loopback, RootCAs: e.CA})
	addr, host := e.Addr().String(), e.Host("tenant-a")
	size := int64(-1)
	for name, req := range map[string]HTTPSRequest{
		"host name address":    {Address: "edge.example:443", SNI: host},
		"no port":              {Address: "127.0.0.1", SNI: host},
		"sni is an IP":         {Address: addr, SNI: "127.0.0.1"},
		"sni empty":            {Address: addr},
		"sni with space":       {Address: addr, SNI: "a b.example"},
		"host with path":       {Address: addr, SNI: host, Host: "x.example/evil"},
		"host with CRLF":       {Address: addr, SNI: host, Host: "x.example\r\nX-Evil: 1"},
		"relative path":        {Address: addr, SNI: host, Path: "key"},
		"absolute URL path":    {Address: addr, SNI: host, Path: "https://other.example/"},
		"scheme-relative path": {Address: addr, SNI: host, Path: "//other.example/"},
		"path with CRLF":       {Address: addr, SNI: host, Path: "/key\r\nX-Evil: 1"},
		"path with space":      {Address: addr, SNI: host, Path: "/a b"},
		"path with fragment":   {Address: addr, SNI: host, Path: "/a#b"},
		"credential header":    {Address: addr, SNI: host, Headers: []string{"Set-Cookie"}},
		"token header":         {Address: addr, SNI: host, Headers: []string{"X-Auth-Token"}},
		"expect credential":    {Address: addr, SNI: host, Expect: Expect{Headers: map[string]string{"Authorization": "x"}}},
		"bad status":           {Address: addr, SNI: host, Expect: Expect{Status: []int{999}}},
		"bad sha":              {Address: addr, SNI: host, Expect: Expect{BodySHA256: "ABC"}},
		"negative size":        {Address: addr, SNI: host, Expect: Expect{BodySize: &size}},
		"json secret key":      {Address: addr, SNI: host, Expect: Expect{JSONPresent: []string{"api_token"}}},
		"timeout too long":     {Address: addr, SNI: host, TimeoutMS: 60000},
	} {
		if _, err := p.HTTPS(t.Context(), req); CodeOf(err) != CodeInvalidRequest {
			t.Errorf("%s: %v, want invalid_request", name, err)
		}
	}
	other := New(Options{Allow: []netip.Prefix{netip.MustParsePrefix("10.249.0.2/32")}, RootCAs: e.CA})
	if _, err := other.HTTPS(t.Context(), HTTPSRequest{Address: addr, SNI: host}); CodeOf(err) != CodeTargetNotAllowed {
		t.Errorf("outside the allow-list: %v", err)
	}
	if _, err := other.Edge(t.Context(), EdgeRequest{Address: addr, Host: host}); CodeOf(err) != CodeTargetNotAllowed {
		t.Errorf("edge outside the allow-list: %v", err)
	}
	if n := e.Conns(); n != 0 {
		t.Fatalf("%d connections reached the edge from refused probes", n)
	}
}

// The edge check (step 18): /key + every forbidden path ⇒ 404; one leaking path is pinpointed; a wrong expected
// key fails the key check.
func TestEdgeCheck(t *testing.T) {
	e := newEdge(t)
	p := New(Options{Allow: loopback, RootCAs: e.CA})
	host := e.Host("tenant-b")
	res, err := p.Edge(t.Context(), EdgeRequest{Address: e.Addr().String(), Host: host, PublicKey: e.PublicKeys[host]})
	if err != nil || !res.OK || res.Blocked != len(DefaultForbidden) || len(res.Forbidden) != len(DefaultForbidden) ||
		!res.Key.OK || res.Key.Path != "/key?v=113" {
		t.Fatalf("%+v %v", res, err)
	}
	for i, f := range res.Forbidden {
		if f.Path != DefaultForbidden[i] || f.Class != ClassNotFound {
			t.Fatalf("forbidden[%d] = %+v", i, f)
		}
	}
	e.Leak("/version")
	res, _ = p.Edge(t.Context(), EdgeRequest{Address: e.Addr().String(), Host: host,
		PublicKey: e.PublicKeys[e.Host("tenant-a")]})
	var leaked []string
	for _, f := range res.Forbidden {
		if !f.OK {
			leaked = append(leaked, f.Path)
		}
	}
	if res.OK || res.Key.OK || res.Blocked != len(DefaultForbidden)-1 || !slices.Equal(leaked, []string{"/version"}) {
		t.Fatalf("leak not pinpointed: ok %v key %v blocked %d leaked %v", res.OK, res.Key.OK, res.Blocked, leaked)
	}
	for name, req := range map[string]EdgeRequest{
		"bad key":   {Address: e.Addr().String(), Host: host, PublicKey: "nodekey:00"},
		"capver":    {Address: e.Addr().String(), Host: host, CapVer: -1},
		"empty":     {Address: e.Addr().String(), Host: host, Forbidden: []string{}},
		"bad path":  {Address: e.Addr().String(), Host: host, Forbidden: []string{"relative"}},
		"no host":   {Address: e.Addr().String()},
		"too many":  {Address: e.Addr().String(), Host: host, Forbidden: slices.Repeat([]string{"/x"}, 65)},
		"stun host": {Address: e.Addr().String(), Host: "127.0.0.1"},
	} {
		if _, err := p.Edge(t.Context(), req); CodeOf(err) != CodeInvalidRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRelayCheck(t *testing.T) {
	e, s := newEdge(t), newSTUN(t)
	p := New(Options{Allow: loopback, RootCAs: e.CA})
	res, err := p.Relay(t.Context(), RelayRequest{Address: e.Addr().String(), Host: e.Host("tenant-a"), STUN: s.Addr().String()})
	if err != nil || !res.OK || res.DERP.Status != 200 || !res.STUN.OK || res.STUN.Mapped != s.Seen()[0].String() {
		t.Fatalf("%+v %v", res, err)
	}
	s.SetSilent(true)
	res, _ = p.Relay(t.Context(), RelayRequest{Address: e.Addr().String(), Host: e.Host("tenant-a"), STUN: s.Addr().String(), TimeoutMS: 600})
	if res.OK || !res.DERP.OK || res.STUN.Error == nil || res.STUN.Error.Code != CodeTimeout {
		t.Fatalf("silent STUN: %+v", res)
	}
	if _, err := p.Relay(t.Context(), RelayRequest{Address: e.Addr().String(), Host: e.Host("tenant-a"), STUN: "192.0.2.1:3478"}); CodeOf(err) != CodeTargetNotAllowed {
		t.Fatalf("stun outside the allow-list: %v", err)
	}
}

// DefaultForbidden covers FORBIDDEN_PUBLIC of tests/security/edge/conformance.py (the edge conformance suite of
// P1-T10a) and the paths of §11.3 step 18.
func TestDefaultForbiddenMatchesConformance(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "security", "edge", "conformance.py"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)FORBIDDEN_PUBLIC = \[(.*?)\]`).FindSubmatch(src)
	if m == nil {
		t.Fatal("FORBIDDEN_PUBLIC not found in conformance.py")
	}
	var py []string
	for _, q := range regexp.MustCompile(`"([^"]*)"`).FindAllSubmatch(m[1], -1) {
		py = append(py, string(q[1]))
	}
	if len(py) < 15 {
		t.Fatalf("parsed only %d paths: %v", len(py), py)
	}
	for _, path := range append(py, "/api/v1/health", "/swagger", "/verify", "/version", "/health", "/metrics", "/debug/pprof/") {
		if !slices.Contains(DefaultForbidden, path) {
			t.Errorf("DefaultForbidden lacks %q", path)
		}
	}
	for _, path := range DefaultForbidden {
		if _, _, err := splitPath(path); err != nil {
			t.Errorf("%q: %v", path, err)
		}
	}
}
