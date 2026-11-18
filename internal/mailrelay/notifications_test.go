package mailrelay

import (
	"context"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
)

// TestNotificationsClientThroughTheBridge is the SMTP conversation of the deployment: the worker's real notification
// client (internal/notifications, MG_SMTP_TLS=starttls + MG_SMTP_CA_FILE = the internal CA) → the bridge (STARTTLS
// required) → the HTTP forwarder → a fake Worker that verifies the HMAC. The client's error classes follow the Worker's
// answers, so the notification.send job retries exactly when it should.
func TestNotificationsClientThroughTheBridge(t *testing.T) {
	ca := newTestCA(t)
	w := &fakeWorker{t: t, key: []byte(testKey)}
	worker := httptest.NewServer(w)
	defer worker.Close()
	fwd := newForwarder(t, worker.URL+"/v1/send", keyFile(t, testKey), nil)
	addr, _ := startServer(t, Config{Forwarder: fwd, TLS: ca.serverTLS, Timeout: 5 * time.Second})
	_, port, _ := net.SplitHostPort(addr)

	mailer := func(tlsMode string) *notifications.SMTPMailer {
		m, err := notifications.NewSMTPMailer(notifications.SMTPConfig{Addr: "127.0.0.1:" + port, TLS: tlsMode,
			ServerName: "mailrelay", From: "MeshGuard <no-reply@example.com>", RootCAs: ca.pool, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ctx := context.Background()
	msg := notifications.Message{To: "owner@example.org", Subject: "[MeshGuard] Chính sách đã áp dụng",
		Body: "Xin chào\n.leading dot\n", MessageID: "<0190abcd@example.com>"}
	if err := mailer(notifications.TLSStartTLS).Send(ctx, msg); err != nil {
		t.Fatalf("send through the bridge: %v", err)
	}
	reqs := w.requests()
	if len(reqs) != 1 || reqs[0].From != "no-reply@example.com" || len(reqs[0].To) != 1 || reqs[0].To[0] != "owner@example.org" {
		t.Fatalf("Worker request: %+v", reqs)
	}
	raw, _ := base64.StdEncoding.DecodeString(reqs[0].RawB64)
	for _, want := range []string{"From: \"MeshGuard\" <no-reply@example.com>\r\n", "Message-ID: <0190abcd@example.com>\r\n",
		"Subject: =?utf-8?q?", "\r\n.leading dot\r\n"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("raw message lacks %q:\n%s", want, raw)
		}
	}
	if strings.Count(string(raw), "Message-ID:") != 1 {
		t.Error("the client's Message-ID must be kept, not doubled")
	}

	// the Worker's answers become the client's error classes (notification.send: retry on temporary, stop on permanent)
	w.mu.Lock()
	w.answers = []fakeAnswer{{422, `{"ok":false,"code":"send_failed"}`}, {503, `{}`}, {503, `{}`}, {503, `{}`}}
	w.mu.Unlock()
	if err := mailer(notifications.TLSStartTLS).Send(ctx, msg); err == nil || !notifications.IsPermanent(err) ||
		!strings.Contains(err.Error(), "554") {
		t.Fatalf("Worker 422 ⇒ permanent 554, got %v", err)
	}
	if err := mailer(notifications.TLSStartTLS).Send(ctx, msg); err == nil || notifications.IsPermanent(err) ||
		!strings.Contains(err.Error(), "451") {
		t.Fatalf("Worker 503 (after the retries) ⇒ temporary 451, got %v", err)
	}
	// a plain-text client is refused before anything is relayed (STARTTLS required once a certificate is configured)
	before := len(w.requests())
	if err := mailer(notifications.TLSNone).Send(ctx, msg); err == nil || !strings.Contains(err.Error(), "530") {
		t.Fatalf("plain text: %v", err)
	}
	// a sender the relay does not allow
	m, _ := notifications.NewSMTPMailer(notifications.SMTPConfig{Addr: "127.0.0.1:" + port, ServerName: "mailrelay",
		From: "Other <other@example.com>", RootCAs: ca.pool})
	if err := m.Send(ctx, msg); err == nil || !notifications.IsPermanent(err) || !strings.Contains(err.Error(), "550") {
		t.Fatalf("foreign sender: %v", err)
	}
	if len(w.requests()) != before {
		t.Fatal("refused messages reached the Worker")
	}
}
