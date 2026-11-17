package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
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
		"MG_PROBE_ALLOW_CALLERS": "127.0.0.1", "MG_PROBE_ALLOW_TARGETS": "127.0.0.0/8", "MG_LOG_LEVEL": "debug"})
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
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d:\n%s", code, logs.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop")
	}
	if !strings.Contains(logs.String(), `"msg":"starting"`) || !strings.Contains(logs.String(), `"kind":"stun"`) {
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
