package idp

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

// publicIP is the address the fake resolver gives the test server's names: a public address that passes the
// policy; the test dialer then connects to the local httptest server instead.
var publicIP = netip.MustParseAddr("93.184.215.14")

// fakeResolver answers from a script: per host, the successive answers of each lookup (the last one repeats).
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
}

func newResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}}
}

func (r *fakeResolver) set(host string, answers ...[]netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = answers
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.calls[host]
	r.calls[host]++
	a := r.answers[host]
	if len(a) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if n >= len(a) {
		n = len(a) - 1
	}
	return a[n], nil
}

func (r *fakeResolver) count(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, x := range s {
		out[i] = netip.MustParseAddr(x)
	}
	return out
}

// dialLog records every address the client dialled; the connection always goes to the test server.
type dialLog struct {
	mu      sync.Mutex
	targets []string
}

func (l *dialLog) dialer(server string) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		l.mu.Lock()
		l.targets = append(l.targets, addr)
		l.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, "tcp", server)
	}
}

func (l *dialLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.targets...)
}

// tlsServer starts an httptest TLS server (certificate valid for example.com, 127.0.0.1, ::1) and returns it with
// the pool that trusts it.
func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

// hardenedFor returns a hardened client whose resolver maps example.com (and the extra names) to publicIP and whose
// dialer reaches srv.
func hardenedFor(t *testing.T, srv *httptest.Server, pool *x509.CertPool, cfg HardenedConfig) (*Hardened, *fakeResolver, *dialLog) {
	t.Helper()
	res := newResolver()
	res.set("example.com", []netip.Addr{publicIP})
	log := &dialLog{}
	cfg.Resolver, cfg.RootCAs, cfg.Dial = res, pool, log.dialer(srv.Listener.Addr().String())
	h, err := NewHardened(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h, res, log
}

// wantCode asserts err is an *Error of code (and, if reason is not empty, of that reason).
func wantCode(t *testing.T, what string, err error, code Code, reason string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("%s: error %v (%T), want an *idp.Error %s", what, err, err, code)
	}
	if e.Code != code || (reason != "" && e.Reason != reason) {
		t.Fatalf("%s: got %s/%s, want %s/%s", what, e.Code, e.Reason, code, reason)
	}
}

func get(ctx context.Context, c *http.Client, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// getErr performs a GET whose response does not matter (refusal tests): the body, if any, is closed.
func getErr(ctx context.Context, c *http.Client, target string) error {
	resp, err := get(ctx, c, target)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}
