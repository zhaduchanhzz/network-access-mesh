package httpx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
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
