package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx/httpxtest"
)

// TestMailRelayCommand: usage and configuration errors exit 2 without starting anything; a valid configuration serves
// SMTP and the internal listener (/readyz with the relay's probes) until the context ends, then exits 0.
func TestMailRelayCommand(t *testing.T) {
	none := func() ([]net.Addr, error) { return nil, nil }
	var stderr bytes.Buffer
	if code := mailRelay(t.Context(), []string{"extra"}, io.Discard, &stderr, func(string) string { return "" }, nil, none); code != 2 ||
		!strings.Contains(stderr.String(), "usage: meshguard-worker mailrelay") {
		t.Fatalf("argument: exit %d, %q", code, stderr.String())
	}
	stderr.Reset()
	bad := map[string]string{"MG_ENV": "staging", "MG_MAILRELAY_URL": "http://x.example/v1/send"}
	if code := mailRelay(t.Context(), nil, io.Discard, &stderr, func(k string) string { return bad[k] }, []string{"MG_ENV=staging"},
		none); code != 2 || !strings.Contains(stderr.String(), "invalid configuration") || strings.Contains(stderr.String(), "x.example") {
		t.Fatalf("configuration: exit %d, %q", code, stderr.String())
	}

	key := filepath.Join(t.TempDir(), "relay_hmac_key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	smtpPort, internalPort := heldPort(t), heldPort(t)
	env := map[string]string{"MG_ENV": "ci", "MG_MAILRELAY_URL": "http://127.0.0.1:9/v1/send", "MG_MAILRELAY_HMAC_KEY_FILE": key,
		"MG_MAILRELAY_ALLOWED_FROM": "no-reply@example.com", "MG_MAILRELAY_SMTP_ADDR": "127.0.0.1:" + smtpPort,
		"MG_INTERNAL_ADDR": "127.0.0.1:" + internalPort}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	var out bytes.Buffer
	go func() {
		done <- mailRelay(ctx, nil, &out, io.Discard, func(k string) string { return env[k] }, nil, none)
	}()
	var line string
	for range 100 {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", "127.0.0.1:"+smtpPort)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			line, _ = bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.HasPrefix(line, "220 mailrelay ESMTP") {
		t.Fatalf("greeting: %q", line)
	}
	var ready int
	for range 100 {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:"+internalPort+"/readyz", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			ready = resp.StatusCode
			_ = resp.Body.Close()
			if ready == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ready != http.StatusOK {
		t.Fatalf("/readyz = %d", ready)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("mailrelay did not stop")
	}
	if strings.Contains(out.String(), strings.Repeat("k", 40)) || !strings.Contains(out.String(), "plain-text SMTP") {
		t.Fatalf("log: %s", out.String())
	}
}

// ports holds the listeners of mailRelay: it binds through listenTCP, which only hands these over.
var ports httpxtest.Listeners

func init() { listenTCP = ports.Listen }

// heldPort returns the port of a loopback listener held for mailRelay (no "free port" picked by listening and closing:
// another test or process could take it before mailRelay binds it).
func heldPort(t *testing.T) string {
	t.Helper()
	_, p, _ := net.SplitHostPort(ports.Addr(t))
	return p
}
