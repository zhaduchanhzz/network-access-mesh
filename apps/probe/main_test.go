package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/stub"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func run(t *testing.T, getenv func(string) string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := dispatch(t.Context(), args, getenv, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestDispatchUsage(t *testing.T) {
	none := env(nil)
	if code, out, _ := run(t, none, "", "version"); code != 0 || !strings.HasPrefix(out, "meshguard-probe ") {
		t.Fatalf("version: %d %q", code, out)
	}
	for _, args := range [][]string{{"nope"}, {"version", "x"}, {"run"}, {"run", "dns"}, {"call", "stun", "extra"},
		{"selftest", "x"}, {"serve", "x"}} {
		if code, _, stderr := run(t, none, "", args...); code != 2 || !strings.Contains(stderr, "usage:") {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	// the service refuses to start without its two allow-lists (fail closed), and says which variables
	code, _, stderr := run(t, none, "", "serve")
	if code != 2 || !strings.Contains(stderr, "MG_PROBE_ALLOW_CALLERS") || !strings.Contains(stderr, "MG_PROBE_ALLOW_TARGETS") {
		t.Fatalf("serve without allow-lists: %d %s", code, stderr)
	}
	code, _, stderr = run(t, env(map[string]string{"MG_PROBE_ALLOW_CALLERS": "10.249.2.0/24", "MG_PROBE_ALLOW_TARGETS": "10.249.0.2",
		"MG_PROBE_CA_FILE": filepath.Join(t.TempDir(), "missing.pem")}), "", "serve")
	if code != 2 || !strings.Contains(stderr, "MG_PROBE_CA_FILE") {
		t.Fatalf("missing CA file: %d %s", code, stderr)
	}
	if code, _, _ := run(t, none, "", "call", "--url", "not a url", "stun"); code != 2 {
		t.Fatalf("call with a bad URL: %d", code)
	}
	// P3-T16: optional scrape allow-list and capver are validated too
	code, _, stderr = run(t, env(map[string]string{"MG_PROBE_ALLOW_CALLERS": "10.249.2.0/24", "MG_PROBE_ALLOW_TARGETS": "10.249.0.2",
		"MG_PROBE_ALLOW_SCRAPERS": "prometheus", "MG_PROBE_CAPVER": "0"}), "", "serve")
	if code != 2 || !strings.Contains(stderr, "MG_PROBE_ALLOW_SCRAPERS") || !strings.Contains(stderr, "MG_PROBE_CAPVER") {
		t.Fatalf("bad scrapers/capver: %d %s", code, stderr)
	}
	// the alert sink refuses to start without its allow-list (fail closed)
	if code, _, stderr := run(t, none, "", "alertsink"); code != 2 || !strings.Contains(stderr, "MG_ALERTSINK_ALLOW_CALLERS") {
		t.Fatalf("alertsink without allow-list: %d %s", code, stderr)
	}
	if code, _, _ := run(t, none, "", "alertsink", "x"); code != 2 {
		t.Fatalf("alertsink with an argument: %d", code)
	}
}

// httpGet is a GET on loopback (no proxy) returning status and body.
func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestSelftest(t *testing.T) {
	code, out, _ := run(t, env(nil), "", "selftest")
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "selftest: 10/10 cases passed") {
		t.Fatalf("selftest exit %d:\n%s", code, out)
	}
}

// `run` probes in-process with exactly the targets of its request allowed and the CA of MG_PROBE_CA_FILE.
func TestRunSubcommand(t *testing.T) {
	s, err := stub.NewSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	code, out, _ := run(t, env(nil), `{"target":"`+s.Addr().String()+`"}`, "run", "stun")
	var res prober.STUNResult
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || !res.OK || res.Mapped != s.Seen()[0].String() {
		t.Fatalf("run stun: %d %s", code, out)
	}
	e, err := stub.NewEdge("127.0.0.1:0", "mesh.example.test", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, e.CAPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	req := `{"address":"` + e.Addr().String() + `","host":"` + e.Host("tenant-a") + `"}`
	code, out, _ = run(t, env(map[string]string{"MG_PROBE_CA_FILE": ca}), req, "run", "edge")
	if code != 0 || !strings.Contains(out, `"ok": true`) {
		t.Fatalf("run edge with the CA: %d %s", code, out)
	}
	code, out, _ = run(t, env(nil), req, "run", "edge")
	if code != 1 || !strings.Contains(out, `"code": "tls_verify"`) {
		t.Fatalf("run edge with the system roots: %d %s", code, out)
	}
	code, out, _ = run(t, env(nil), `{"target":"localhost:3478"}`, "run", "stun")
	if code != 3 || !strings.Contains(out, `"code": "invalid_request"`) {
		t.Fatalf("invalid request: %d %s", code, out)
	}
	code, out, _ = run(t, env(nil), `{"target":"127.0.0.1:3478","extra":1}`, "run", "stun")
	if code != 3 || !strings.Contains(out, `"code": "invalid_request"`) {
		t.Fatalf("unknown field: %d %s", code, out)
	}
}

// serve starts both listeners, answers the healthcheck and the RPC, and stops on cancel.
func TestServe(t *testing.T) {
	rpcAddr, internalAddr := freeTCP(t), freeTCP(t)
	getenv := env(map[string]string{"MG_PROBE_LISTEN": rpcAddr, "MG_INTERNAL_ADDR": internalAddr,
		"MG_PROBE_ALLOW_CALLERS": "127.0.0.1", "MG_PROBE_ALLOW_TARGETS": "127.0.0.0/8", "MG_PROBE_ALLOW_SCRAPERS": "127.0.0.1",
		"MG_LOG_LEVEL": "debug"})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	var logs bytes.Buffer
	go func() { done <- dispatch(ctx, []string{"serve"}, getenv, strings.NewReader(""), &logs, &logs) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var out bytes.Buffer
		if healthcheck(getenv, &out) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("healthcheck never passed: %s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	s, err := stub.NewSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	code, out, _ := run(t, env(map[string]string{"MG_PROBER_URL": "http://" + rpcAddr}), `{"target":"`+s.Addr().String()+`"}`, "call", "stun")
	if code != 0 || !strings.Contains(out, `"mapped": "`+s.Seen()[0].String()+`"`) {
		t.Fatalf("call stun: %d %s", code, out)
	}
	code, out, _ = run(t, env(nil), `{"target":"192.0.2.1:3478"}`, "call", "--url", "http://"+rpcAddr, "stun")
	if code != 3 || !strings.Contains(out, prober.CodeTargetNotAllowed) {
		t.Fatalf("call outside the allow-list: %d %s", code, out)
	}
	// P3-T16: GET /probe on the internal listener (the stub's CA is not trusted ⇒ a failed probe, reported as metrics)
	e, err := stub.NewEdge("127.0.0.1:0", "mesh.example.test", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	status, body := httpGet(t, "http://"+internalAddr+prober.RouteScrape+"?module=tls&target="+e.Addr().String()+
		"&host="+e.Host("tenant-a"))
	if status != 200 || !strings.Contains(body, "probe_success 0") || !strings.Contains(body, `probe_failure_info{code="tls_verify"} 1`) {
		t.Fatalf("scrape: %d\n%s", status, body)
	}
	if status, body = httpGet(t, "http://"+internalAddr+"/metrics"); status != 200 ||
		!strings.Contains(body, `meshguard_probe_scrapes_total{module="tls",outcome="failed"} 1`) {
		t.Fatalf("metrics: %d\n%s", status, body)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d:\n%s", code, logs.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop")
	}
	if !strings.Contains(logs.String(), `"msg":"starting"`) || !strings.Contains(logs.String(), `"kind":"stun"`) ||
		!strings.Contains(logs.String(), `"msg":"probe failed"`) || strings.Contains(logs.String(), `"kind":"tls"`) {
		t.Fatalf("logs (a scrape probe logs its failure once, not its info line):\n%s", logs.String())
	}
}

// alertsink serves the webhook route and the internal listener, and stops on cancel.
func TestAlertsink(t *testing.T) {
	apiAddr, internalAddr := freeTCP(t), freeTCP(t)
	getenv := env(map[string]string{"MG_ALERTSINK_LISTEN": apiAddr, "MG_INTERNAL_ADDR": internalAddr,
		"MG_ALERTSINK_ALLOW_CALLERS": "127.0.0.1"})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	var logs bytes.Buffer
	go func() { done <- dispatch(ctx, []string{"alertsink"}, getenv, strings.NewReader(""), &logs, &logs) }()
	deadline := time.Now().Add(10 * time.Second)
	for healthcheck(getenv, io.Discard) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("healthcheck never passed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	body := `{"version":"4","status":"firing","receiver":"meshguard","groupKey":"k","alerts":[{"status":"firing",` +
		`"labels":{"alertname":"Drill","severity":"high"},"annotations":{"summary":"drill"},"startsAt":"2026-11-18T03:00:00Z"}]}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+apiAddr+"/v1/alerts", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
	if status, out := httpGet(t, "http://"+apiAddr+"/v1/notifications?alertname=Drill"); status != 200 ||
		!strings.Contains(out, `"alertname":"Drill"`) {
		t.Fatalf("list: %d %s", status, out)
	}
	if status, out := httpGet(t, "http://"+internalAddr+"/metrics"); status != 200 ||
		!strings.Contains(out, `meshguard_alertsink_notifications_total{receiver="meshguard",status="firing"} 1`) {
		t.Fatalf("metrics: %d %s", status, out)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("alertsink exit %d:\n%s", code, logs.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("alertsink did not stop")
	}
	if !strings.Contains(logs.String(), `"msg":"alert notification"`) {
		t.Fatalf("logs:\n%s", logs.String())
	}
}

func freeTCP(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
