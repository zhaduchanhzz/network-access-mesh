package identity

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// TestMiddlewareProblemWriter — the refusals of the middleware itself (unknown host, Origin/Sec-Fetch-Site) go through
// Config.ProblemWriter when it is set (authzhook.WriteProblem behind httpapi — P2-T15a), and the default writer sends
// the same problem+json with X-Content-Type-Options: nosniff. No session is involved, so no database is touched.
func TestMiddlewareProblemWriter(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("the request reached the next handler") })
	cases := []struct {
		name, method, url string
		header            http.Header
		kind              Kind
		reason            string
	}{
		{"unknown host", http.MethodGet, "https://evil.example/api/v1/auth/session", nil, KindNotFound, "unknown_host"},
		{"foreign Origin", http.MethodPost, "https://app.mg.test/api/v1/auth/logout",
			http.Header{"Origin": {"https://evil.example"}}, KindForbidden, "origin_header_mismatch"},
		{"cross-site fetch", http.MethodPost, "https://admin.mg.test/api/v1/auth/logout",
			http.Header{"Sec-Fetch-Site": {"cross-site"}}, KindForbidden, "sec_fetch_site_cross_origin"},
		{"neither Origin nor Sec-Fetch-Site", http.MethodDelete, "https://app.mg.test/api/v1/auth/sessions/x",
			nil, KindForbidden, "origin_header_missing"},
	}
	request := func(method, url string, h http.Header) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), method, url, nil)
		r.Header.Set("X-Request-Id", "req-pw-1")
		for k, vs := range h {
			r.Header[k] = vs
		}
		return r
	}
	cfg := Config{AppHost: "app.mg.test", AdminHost: "admin.mg.test", HTTPClient: http.DefaultClient,
		Logger: slog.New(slog.DiscardHandler)}

	// Default writer: the module's problem, with nosniff.
	def, err := New(&store.Store{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		def.Middleware(next).ServeHTTP(rec, request(tc.method, tc.url, tc.header))
		var p Problem
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if rec.Code != tc.kind.Status() || p.Code != tc.kind.Code() || p.RequestID != "req-pw-1" ||
			rec.Header().Get("Content-Type") != "application/problem+json" ||
			rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s (default writer): HTTP %d %v %+v", tc.name, rec.Code, rec.Header(), p)
		}
	}

	// Injected writer: called once with the module's error, and its answer is the response.
	var got []*Error
	cfg.ProblemWriter = func(w http.ResponseWriter, r *http.Request, err error) {
		var e *Error
		if !errors.As(err, &e) || r.Header.Get("X-Request-Id") != "req-pw-1" {
			t.Errorf("writer called with %v", err)
		}
		got = append(got, e)
		w.WriteHeader(http.StatusTeapot)
	}
	inj, err := New(&store.Store{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		got = nil
		rec := httptest.NewRecorder()
		inj.Middleware(next).ServeHTTP(rec, request(tc.method, tc.url, tc.header))
		if rec.Code != http.StatusTeapot || rec.Body.Len() != 0 || len(got) != 1 || got[0] == nil ||
			got[0].Kind != tc.kind || got[0].Reason != tc.reason {
			t.Errorf("%s (injected writer): HTTP %d, writer calls %+v, want one %s/%s", tc.name, rec.Code, got,
				tc.kind.Code(), tc.reason)
		}
	}
}
