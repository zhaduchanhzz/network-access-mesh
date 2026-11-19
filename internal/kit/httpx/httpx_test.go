package httpx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx/httpxtest"
)

func TestInternalEndpoints(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "mg_test_total", Help: "test"})
	reg.MustRegister(c)
	c.Inc()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ok := InternalMux(map[string]Probe{"db": func(context.Context) error { return nil }}, reg, log)
	bad := InternalMux(map[string]Probe{
		"db":  func(context.Context) error { return errors.New("dial tcp 10.0.0.5:5432: secret-dsn") },
		"idp": func(context.Context) error { return nil },
	}, reg, log)

	cases := []struct {
		h        http.Handler
		method   string
		path     string
		code     int
		contains string
		absent   string
	}{
		{ok, "GET", "/healthz", 200, "ok", ""},
		{ok, "GET", "/readyz", 200, `"ready":true`, ""},
		{bad, "GET", "/readyz", 503, `"failing":["db"]`, "secret-dsn"},
		{ok, "GET", "/metrics", 200, "mg_test_total 1", ""},
		{ok, "POST", "/healthz", 405, "", ""},
		{ok, "GET", "/debug/pprof/", 404, "", ""},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		tc.h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil))
		body := rec.Body.String()
		if rec.Code != tc.code || !strings.Contains(body, tc.contains) || (tc.absent != "" && strings.Contains(body, tc.absent)) {
			t.Errorf("%s %s = %d %q; want %d containing %q", tc.method, tc.path, rec.Code, body, tc.code, tc.contains)
		}
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer("127.0.0.1:0", http.NotFoundHandler(), log)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Serve(ctx, log, srv); err != nil {
		t.Fatalf("Serve after cancel: %v", err)
	}
}

// spyListener records that the server's listener was closed.
type spyListener struct {
	net.Listener
	closed atomic.Bool
}

func (l *spyListener) Close() error {
	l.closed.Store(true)
	return l.Listener.Close()
}

// TestServeWithHeldListeners: ServeWith serves on the listeners handed over by listen (httpxtest — no port of its own,
// none picked "free"), binds every Addr before serving — a bind failure is returned at once and closes the listeners
// already opened — and closes every listener when it returns.
func TestServeWithHeldListeners(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var ports httpxtest.Listeners
	var spies []*spyListener
	listen := func(ctx context.Context, network, address string) (net.Listener, error) {
		l, err := ports.Listen(ctx, network, address)
		if err != nil {
			return nil, err
		}
		s := &spyListener{Listener: l}
		spies = append(spies, s)
		return s, nil
	}

	addr := ports.Addr(t)
	err := ServeWith(t.Context(), log, listen, NewServer(addr, http.NotFoundHandler(), log),
		NewServer("127.0.0.1:1", http.NotFoundHandler(), log))
	if err == nil || !strings.Contains(err.Error(), "no listener held for tcp 127.0.0.1:1") || len(spies) != 1 || !spies[0].closed.Load() {
		t.Fatalf("second bind refused: %v, %d listeners, first closed %v", err, len(spies), len(spies) == 1 && spies[0].closed.Load())
	}

	spies, addr = nil, ports.Addr(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ServeWith(ctx, log, listen, NewServer(addr, http.NotFoundHandler(), log)) }()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/nothing", nil)
	resp, err := http.DefaultClient.Do(req) // the listener is bound before ServeWith runs: no retry needed
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET on the held listener: %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil || len(spies) != 1 || !spies[0].closed.Load() {
			t.Fatalf("after cancel: %v, listener closed %v", err, len(spies) == 1 && spies[0].closed.Load())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("ServeWith did not stop")
	}
	if _, err := ports.Listen(t.Context(), "tcp", addr); err == nil {
		t.Fatal("a held listener was handed over twice")
	}
}
