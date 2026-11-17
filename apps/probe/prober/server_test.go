package prober

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

func rpc(t *testing.T, p Prober, o HandlerOptions) *Client {
	t.Helper()
	srv := httptest.NewServer(Handler(p, o))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Every kind through Handler + Client gives the same typed result as the in-process prober; refusals come back as
// the service's *Error.
func TestRPCRoundTrip(t *testing.T) {
	e, s := newEdge(t), newSTUN(t)
	reg := prometheus.NewRegistry()
	c := rpc(t, New(Options{Allow: loopback, RootCAs: e.CA}), HandlerOptions{Callers: loopback, Registerer: reg})
	ctx := t.Context()
	st, err := c.STUN(ctx, STUNRequest{Target: s.Addr().String()})
	if err != nil || !st.OK || st.Mapped != s.Seen()[0].String() || st.CheckedAt.IsZero() {
		t.Fatalf("stun %+v %v", st, err)
	}
	h, err := c.HTTPS(ctx, HTTPSRequest{Address: e.Addr().String(), SNI: e.Host("tenant-a"), Path: "/verify",
		Expect: Expect{Status: []int{404}}})
	if err != nil || !h.OK || h.Class != ClassNotFound || h.TLS == nil || h.Timing.TotalMS <= 0 {
		t.Fatalf("https %+v %v", h, err)
	}
	ed, err := c.Edge(ctx, EdgeRequest{Address: e.Addr().String(), Host: e.Host("tenant-a")})
	if err != nil || !ed.OK || ed.Blocked != len(DefaultForbidden) || ed.Key.JSON["publicKey"] != e.PublicKeys[e.Host("tenant-a")] {
		t.Fatalf("edge %+v %v", ed, err)
	}
	rl, err := c.Relay(ctx, RelayRequest{Address: e.Addr().String(), Host: e.Host("tenant-b"), STUN: s.Addr().String()})
	if err != nil || !rl.OK {
		t.Fatalf("relay %+v %v", rl, err)
	}
	// a probe that failed is a 200 with OK=false, not an error
	h, err = c.HTTPS(ctx, HTTPSRequest{Address: e.Addr().String(), SNI: "foreign.example"})
	if err != nil || h.OK || h.Error == nil || h.Error.Code != CodeTLSHandshake {
		t.Fatalf("failed probe %+v %v", h, err)
	}
	if _, err := c.STUN(ctx, STUNRequest{Target: "192.0.2.1:3478"}); CodeOf(err) != CodeTargetNotAllowed {
		t.Fatalf("target outside the allow-list: %v", err)
	}
	if _, err := c.HTTPS(ctx, HTTPSRequest{Address: "edge.example:443", SNI: "a.example"}); CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("invalid request: %v", err)
	}
	for kind, n := range map[string]float64{"stun": 1, "https": 1, "edge": 1, "relay": 1} {
		if got := counter(reg, kind, "ok"); got != n {
			t.Errorf("rpc_total{%s,ok} = %v, want %v", kind, got, n)
		}
	}
	for _, c := range [][2]string{{"https", "failed"}, {"stun", CodeTargetNotAllowed}, {"https", CodeInvalidRequest}} {
		if got := counter(reg, c[0], c[1]); got != 1 {
			t.Errorf("rpc_total{%s,%s} = %v, want 1", c[0], c[1], got)
		}
	}
}

// counter reads meshguard_probe_rpc_total{kind, outcome}.
func counter(reg *prometheus.Registry, kind, outcome string) float64 {
	mfs, _ := reg.Gather()
	v := 0.0
	for _, mf := range mfs {
		if mf.GetName() != "meshguard_probe_rpc_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["kind"] == kind && labels["outcome"] == outcome {
				v = m.GetCounter().GetValue()
			}
		}
	}
	return v
}

func post(h http.Handler, remote, path, ctype, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	r.RemoteAddr = remote
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error *Error `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error == nil {
		t.Fatalf("not an error envelope: %d %s", w.Code, w.Body.String())
	}
	return e.Error.Code
}

// The RPC refuses callers outside the allow-list (before routing), wrong methods, content types, unknown fields,
// trailing data and oversized bodies.
func TestRPCRefusals(t *testing.T) {
	s := newSTUN(t)
	h := Handler(New(Options{Allow: loopback}), HandlerOptions{Callers: []netip.Prefix{netip.MustParsePrefix("10.249.2.0/24")}})
	ok := `{"target":"` + s.Addr().String() + `"}`
	cases := []struct {
		name, remote, method, path, ctype, body string
		status                                  int
		code                                    string
	}{
		{"caller outside", "10.249.0.4:4000", http.MethodPost, RouteSTUN, "application/json", ok, 403, CodeCallerNotAllowed},
		{"caller outside, unknown route", "192.0.2.1:1", http.MethodGet, "/debug/pprof/", "", "", 403, CodeCallerNotAllowed},
		{"unknown route", "10.249.2.5:1", http.MethodGet, "/v1/other", "", "", 404, CodeNotFound},
		{"GET on a route", "10.249.2.5:1", http.MethodGet, RouteSTUN, "", "", 405, CodeInvalidRequest},
		{"text/plain", "10.249.2.5:1", http.MethodPost, RouteSTUN, "text/plain", ok, 415, CodeInvalidRequest},
		{"unknown field", "10.249.2.5:1", http.MethodPost, RouteSTUN, "application/json", `{"target":"127.0.0.1:1","x":1}`, 400, CodeInvalidRequest},
		{"two objects", "10.249.2.5:1", http.MethodPost, RouteSTUN, "application/json", ok + ok, 400, CodeInvalidRequest},
		{"too large", "10.249.2.5:1", http.MethodPost, RouteHTTPS, "application/json", `{"path":"` + strings.Repeat("a", 70000) + `"}`, 413, CodeInvalidRequest},
		{"target outside", "10.249.2.5:1", http.MethodPost, RouteSTUN, "application/json; charset=utf-8", `{"target":"192.0.2.1:3478"}`, 403, CodeTargetNotAllowed},
	}
	for _, c := range cases {
		r := httptest.NewRequestWithContext(context.Background(), c.method, c.path, strings.NewReader(c.body))
		r.RemoteAddr = c.remote
		if c.ctype != "" {
			r.Header.Set("Content-Type", c.ctype)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.status || errorCode(t, w) != c.code {
			t.Errorf("%s: %d %s, want %d %s", c.name, w.Code, w.Body.String(), c.status, c.code)
		}
	}
	if n := len(s.Seen()) + s.Ignored(); n != 0 {
		t.Fatalf("refused requests reached the responder (%d datagrams)", n)
	}
	// the allowed caller is served: the probe runs (nothing listens on port 1 ⇒ a failed result, still HTTP 200)
	w := post(h, "10.249.2.5:1", RouteSTUN, "application/json", `{"target":"127.0.0.1:1","timeout_ms":1000}`)
	var res STUNResult
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &res) != nil || res.OK || res.Error == nil || res.Attempts == 0 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := post(Handler(New(Options{Allow: loopback}), HandlerOptions{}), "127.0.0.1:1", RouteSTUN, "application/json", ok); w.Code != 403 {
		t.Fatalf("empty caller allow-list must refuse everyone: %d", w.Code)
	}
}

// blocking is a Prober whose STUN waits until released (to fill the in-flight slots).
type blocking struct {
	Prober
	started chan struct{}
	release chan struct{}
}

func (b *blocking) STUN(ctx context.Context, _ STUNRequest) (STUNResult, error) {
	b.started <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return STUNResult{OK: true}, nil
}

func TestRPCBusy(t *testing.T) {
	b := &blocking{started: make(chan struct{}, 1), release: make(chan struct{})}
	h := Handler(b, HandlerOptions{Callers: loopback, MaxInFlight: 1})
	var wg sync.WaitGroup
	wg.Go(func() { post(h, "127.0.0.1:1", RouteSTUN, "application/json", `{"target":"127.0.0.1:3478"}`) })
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first probe did not start")
	}
	w := post(h, "127.0.0.1:2", RouteSTUN, "application/json", `{"target":"127.0.0.1:3478"}`)
	close(b.release)
	wg.Wait()
	if w.Code != http.StatusTooManyRequests || errorCode(t, w) != CodeBusy {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// Nothing the prober logs or returns carries a credential: a path with a token or a Headscale key is redacted in the
// result and in the log line, credential headers cannot be asked for, and a refused request does not echo its input.
func TestNoCredentialInLogsOrResults(t *testing.T) {
	e := newEdge(t)
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, "probe")
	token := "tok" + strings.Repeat("Z9", 16)
	hskey := strings.Join([]string{"hskey", "auth", strings.Repeat("Ab", 6), "Zz" + strings.Repeat("9", 20)}, "-")
	c := rpc(t, New(Options{Allow: loopback, RootCAs: e.CA, Logger: log}), HandlerOptions{Callers: loopback, Logger: log})
	ctx := t.Context()
	res, err := c.HTTPS(ctx, HTTPSRequest{Address: e.Addr().String(), SNI: e.Host("tenant-a"),
		Path: "/register/" + hskey + "?token=" + token + "&v=113", Headers: []string{"Content-Type"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Path, token) || strings.Contains(res.Path, hskey) || !strings.Contains(res.Path, "[REDACTED]") ||
		!strings.Contains(res.Path, "v=113") {
		t.Fatalf("result path not redacted: %q", res.Path)
	}
	// the edge did receive the real target: redaction is only for what the prober reports
	if r := e.Requests(); !strings.Contains(r[len(r)-1].Target, token) {
		t.Fatal("the request sent was altered")
	}
	_, err = c.HTTPS(ctx, HTTPSRequest{Address: e.Addr().String(), SNI: e.Host("tenant-a"), Headers: []string{"Authorization"}})
	if CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("credential header: %v", err)
	}
	_, err = c.STUN(ctx, STUNRequest{Target: "bearer " + token})
	if CodeOf(err) != CodeInvalidRequest || strings.Contains(err.Error(), token) {
		t.Fatalf("invalid target echoed: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, token) || strings.Contains(out, hskey) || !strings.Contains(out, `"kind":"https"`) ||
		!strings.Contains(out, "prober rpc: request refused") {
		t.Fatalf("log line holds a credential or misses the probe:\n%s", out)
	}
}

func TestNewClientRefusesBadURLs(t *testing.T) {
	for _, u := range []string{"", "prober:8080", "ftp://prober", "http://user:pw@prober:8080", "http://prober:8080/v1",
		"http://prober:8080?x=1"} {
		if _, err := NewClient(u, nil); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := NewClient("http://10.249.2.9:8080/", nil); err != nil {
		t.Fatal(err)
	}
	// an answer that is not the service's
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", http.StatusBadGateway) }))
	t.Cleanup(srv.Close)
	c, _ := NewClient(srv.URL, nil)
	if _, err := c.STUN(t.Context(), STUNRequest{Target: "127.0.0.1:1"}); CodeOf(err) != CodeRPC {
		t.Fatalf("502: %v", err)
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes(" 10.249.2.0/24, 116.118.3.46 ::ffff:10.0.0.0/104\n2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.249.2.0/24", "116.118.3.46/32", "10.0.0.0/8", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("%v, want %v", got, want)
		}
	}
	if !allowed(got, netip.MustParseAddr("::ffff:10.1.2.3")) || allowed(got, netip.MustParseAddr("11.249.3.1")) {
		t.Fatal("membership")
	}
	for _, bad := range []string{"", " , ", "10.0.0.0/33", "host.example", "fe80::1%eth0", "10.0.0.1/24/8"} {
		if _, err := ParsePrefixes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
