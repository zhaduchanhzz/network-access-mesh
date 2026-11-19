package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx/httpxtest"
)

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

// ports holds the listeners of the processes under test: run() binds through listenTCP, which only hands these over.
var ports httpxtest.Listeners

func init() { listenTCP = ports.Listen }

// heldAddr returns the loopback address of a listener held for run() (no "free port" picked by listening and closing:
// another test or process could take it before run() binds it).
func heldAddr(t *testing.T) string {
	t.Helper()
	return ports.Addr(t)
}

func environment(m map[string]string) (func(string) string, []string) {
	var list []string
	for k, v := range m {
		list = append(list, k+"="+v)
	}
	return func(k string) string { return m[k] }, list
}

type response struct {
	status int
	header http.Header
	body   string
}

func get(t *testing.T, url string) (response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return response{resp.StatusCode, resp.Header, string(body)}, err
}

// TestRunServesPublicAndInternalListeners starts the api process wiring on two real listeners: the public one serves
// the generated API under /api/v1 behind the middleware chain (501 problem for every operation until handlers are
// mounted) and nothing else; the internal one still serves /healthz, /readyz and /metrics and no API.
func TestRunServesPublicAndInternalListeners(t *testing.T) {
	public, internal := heldAddr(t), heldAddr(t)
	getenv, environ := environment(map[string]string{"MG_HTTP_ADDR": public, "MG_INTERNAL_ADDR": internal})
	var stdout, stderr syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- run(ctx, "api", getenv, environ, &stdout, &stderr) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		_, errInternal := get(t, "http://"+internal+"/healthz")
		_, errPublic := get(t, "http://"+public+"/api/v1/tenants")
		if errInternal == nil && errPublic == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listeners not up: %v / %v\nstderr: %s\nstdout: %s", errInternal, errPublic, stderr.String(), stdout.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	cases := []struct {
		url         string
		status      int
		contentType string
		contains    string
	}{
		{"http://" + public + "/api/v1/tenants", 501, "application/problem+json", `"code":"not_implemented"`},
		{"http://" + public + "/api/v1/tenants/0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f50/devices", 501, "application/problem+json", "ListDevices"},
		{"http://" + public + "/api/v1/tenants/not-a-uuid/devices", 422, "application/problem+json", `"field":"tenantId"`},
		{"http://" + public + "/healthz", 404, "application/problem+json", `"code":"not_found"`},
		{"http://" + public + "/metrics", 404, "application/problem+json", `"code":"not_found"`},
		{"http://" + internal + "/healthz", 200, "text/plain; charset=utf-8", "ok"},
		{"http://" + internal + "/readyz", 200, "application/json", `"ready":true`},
		{"http://" + internal + "/metrics", 200, "", "meshguard_build_info{"},
		{"http://" + internal + "/api/v1/tenants", 404, "", ""},
	}
	for _, c := range cases {
		r, err := get(t, c.url)
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if r.status != c.status || (c.contentType != "" && r.header.Get("Content-Type") != c.contentType) || !strings.Contains(r.body, c.contains) {
			t.Errorf("%s: %d %q %q; want %d %q containing %q", c.url, r.status, r.header.Get("Content-Type"), r.body, c.status, c.contentType, c.contains)
		}
		if strings.HasPrefix(c.url, "http://"+public) {
			var p struct {
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal([]byte(r.body), &p); err != nil || p.RequestID == "" || p.RequestID != r.header.Get("X-Request-Id") {
				t.Errorf("%s: request_id %q vs header %q (%v)", c.url, p.RequestID, r.header.Get("X-Request-Id"), err)
			}
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d\nstderr: %s", code, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not stop after cancel")
	}
	out := stdout.String()
	for _, want := range []string{`"msg":"starting"`, `"msg":"http request"`, `"route":"GET /api/v1/tenants/{tenantId}/devices"`, `"operation":"ListDevices"`, `"msg":"stopped"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	getenv, environ := environment(map[string]string{"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com"})
	var stdout, stderr syncBuffer
	if code := run(context.Background(), "api", getenv, environ, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "MG_TRUSTED_PROXIES is required") || stdout.String() != "" {
		t.Fatalf("stderr %q, stdout %q", stderr.String(), stdout.String())
	}
}
