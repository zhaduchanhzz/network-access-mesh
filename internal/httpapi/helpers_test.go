package httpapi

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

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

const (
	tenantID = "0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f50"
	itemID   = "0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f51"
	// canary is a secret-shaped value no log line may ever contain (§25.1 rule 9).
	canary = "mgcanary7Q2xW9kP4vZ8"
)

// syncBuffer is a log sink safe for the server goroutines of httptest.Server.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// passAuthz is an explicit "allow everything" Authz hook for tests that mount handler sets.
func passAuthz(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }

// newLogger is the production logger (logx: JSON, redaction, request_id from the context) at debug level.
func newLogger(w io.Writer) *slog.Logger { return logx.New(w, slog.LevelDebug, "api") }

func discardLogger() *slog.Logger { return newLogger(io.Discard) }

type env struct {
	t     *testing.T
	h     http.Handler
	log   *slog.Logger
	logs  *syncBuffer
	clock *fakeClock
}

// newEnv builds the API with a debug-level logx logger writing to a buffer and a fake clock.
func newEnv(t *testing.T, opts Options) *env {
	t.Helper()
	e := &env{t: t, logs: &syncBuffer{}, clock: &fakeClock{now: time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)}}
	e.log = newLogger(e.logs)
	if opts.Logger == nil {
		opts.Logger = e.log
	}
	if opts.Now == nil {
		opts.Now = e.clock.Now
	}
	h, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.h = h
	return e
}

// request builds a request from 192.0.2.1 (httptest's default peer); mods adjust it.
func request(method, target, body string, mods ...func(*http.Request)) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(context.Background(), method, target, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, m := range mods {
		m(r)
	}
	return r
}

func header(k, v string) func(*http.Request) { return func(r *http.Request) { r.Header.Set(k, v) } }

func from(addr string) func(*http.Request) { return func(r *http.Request) { r.RemoteAddr = addr } }

var idempotency = header("Idempotency-Key", "test-key-0001")

func (e *env) serve(r *http.Request) *httptest.ResponseRecorder {
	e.t.Helper()
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *env) do(method, target, body string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.serve(request(method, target, body, mods...))
}

// problemOf decodes a problem response and checks the invariants every problem must hold.
func problemOf(t *testing.T, w *httptest.ResponseRecorder) gen.Problem {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != problem.ContentType {
		t.Fatalf("Content-Type %q (status %d): %s", ct, w.Code, w.Body.String())
	}
	var p gen.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body: %v\n%s", err, w.Body.String())
	}
	if p.Status != w.Code || p.Type != problem.TypePrefix+string(p.Code) || p.Title == "" {
		t.Errorf("problem %+v does not match status %d", p, w.Code)
	}
	if id := w.Header().Get(requestid.Header); id == "" || p.RequestId != id {
		t.Errorf("request_id %q, header %q", p.RequestId, id)
	}
	return p
}

// lines returns the JSON log records written so far.
func (e *env) lines() []map[string]any {
	e.t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		if ln == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			e.t.Fatalf("log line is not JSON: %v\n%s", err, ln)
		}
		out = append(out, rec)
	}
	return out
}

// accessLine returns the access log record of the request id.
func (e *env) accessLine(id string) map[string]any {
	e.t.Helper()
	for _, rec := range e.lines() {
		if rec["msg"] == "http request" && rec["request_id"] == id {
			return rec
		}
	}
	e.t.Fatalf("no access log line for request %s:\n%s", id, e.logs.String())
	return nil
}
