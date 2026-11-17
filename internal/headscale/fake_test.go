package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	testTenant   = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	testInstance = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
)

// Credentials are assembled at run time so no literal matches the secret-scanner rules (.gitleaks.toml).
func testAPIKey(prefix string) string {
	return "hskey-" + "api-" + prefix + "-" + strings.Repeat("s", 64)
}

var testEdgeToken = strings.Repeat("T", 40)

type recorded struct {
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Body     []byte
}

// fakeEdge plays the edge admin listener (§14.6) in front of a scripted Headscale.
type fakeEdge struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	slug    string
	token   string
	apiKey  string
	version string
	delay   time.Duration
	reqs    []recorded
	routes  map[string]func(w http.ResponseWriter, r *http.Request, body []byte)
}

func newFakeEdge(t *testing.T) *fakeEdge {
	t.Helper()
	f := &fakeEdge{t: t, slug: "tenant-a", token: testEdgeToken, apiKey: testAPIKey("goodprefix12"), version: "v0.29.7",
		routes: map[string]func(http.ResponseWriter, *http.Request, []byte){}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEdge) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{Method: r.Method, Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
	route := f.routes[r.Method+" "+r.URL.Path]
	slug, token, key, version, delay := f.slug, f.token, f.apiKey, f.version, f.delay
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	// The edge (§14.6): token first (403), then the instance header and the path allow-list (bare 404).
	if r.Header.Get(HeaderEdgeToken) != token {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Header.Get(HeaderInstance) != slug {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/version" {
		writeJSON(w, 200, map[string]any{"version": version, "commit": "c9cf210b8bc84d13177e18b91f555788a44b47b6"})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Headscale's auth middleware.
	if r.Header.Get("Authorization") != "Bearer "+key {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
		return
	}
	if route == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(gw(5, "Not Found")))
		return
	}
	route(w, r, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// on registers a static answer.
func (f *fakeEdge) on(method, path string, status int, body string) {
	f.onFunc(method, path, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func (f *fakeEdge) onFunc(method, path string, h func(w http.ResponseWriter, r *http.Request, body []byte)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = h
}

func (f *fakeEdge) set(fn func(f *fakeEdge)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeEdge) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

// apiRequests drops the version probe(s).
func (f *fakeEdge) apiRequests() []recorded {
	var out []recorded
	for _, r := range f.requests() {
		if r.Path != "/version" {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeEdge) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = nil
}

// mutableLocator lets a test rotate credentials and count lookups.
type mutableLocator struct {
	mu    sync.Mutex
	t     Target
	calls int
	err   error
}

func (m *mutableLocator) Locate(context.Context, uuid.UUID) (Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.t, m.err
}

func (m *mutableLocator) setKey(k string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.APIKey = NewSecret(k)
}

func (m *mutableLocator) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type harness struct {
	edge   *fakeEdge
	loc    *mutableLocator
	reg    *CachingRegistry
	clk    *fakeClock
	sleeps []time.Duration
	logBuf *bytes.Buffer
}

func newHarness(t *testing.T, opts Options) *harness {
	t.Helper()
	h := &harness{edge: newFakeEdge(t), clk: &fakeClock{t: time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)}, logBuf: &bytes.Buffer{}}
	h.loc = &mutableLocator{t: Target{InstanceID: testInstance, Slug: "tenant-a", AdminURL: h.edge.srv.URL,
		APIKey: NewSecret(h.edge.apiKey), EdgeToken: NewSecret(testEdgeToken)}}
	if opts.Now == nil {
		opts.Now = h.clk.now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(h.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	h.reg = NewRegistry(h.loc, opts)
	h.reg.sleep = func(_ context.Context, d time.Duration) bool { h.sleeps = append(h.sleeps, d); return true }
	return h
}

func (h *harness) instance(t *testing.T) Instance {
	t.Helper()
	inst, err := h.reg.ForTenant(context.Background(), testTenant)
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	return inst
}
