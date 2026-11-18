package mailrelay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const msgHead = "From: MeshGuard <no-reply@example.com>\r\nTo: a@example.org\r\nSubject: test\r\nMessage-ID: <1@example.com>\r\n\r\n"

func TestConversationPlainText(t *testing.T) {
	fwd := &fakeForwarder{}
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := startServer(t, Config{Forwarder: fwd, Metrics: m})
	c := dial(t, addr)
	c.cmd(503, "MAIL FROM:<no-reply@example.com>") // EHLO first
	ehlo := c.cmd(250, "EHLO client.example")
	if !strings.Contains(ehlo, "SIZE 1048576") || !strings.Contains(ehlo, "ENHANCEDSTATUSCODES") || strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("EHLO without TLS: %q", ehlo)
	}
	c.cmd(503, "RCPT TO:<a@example.org>")                              // MAIL first
	c.cmd(550, "MAIL FROM:<someone@example.com>")                      // not an allowed sender
	c.cmd(501, "MAIL FROM:<>")                                         // null path
	c.cmd(501, "MAIL FROM:no-reply@example.com")                       // no angle brackets
	c.cmd(555, "MAIL FROM:<no-reply@example.com> AUTH=<>")             // unknown parameter
	c.cmd(552, "MAIL FROM:<no-reply@example.com> SIZE=2000000")        // over the limit
	c.cmd(250, "MAIL FROM: <No-Reply@Example.COM> SIZE=100 BODY=7BIT") // case-insensitive, space after the colon
	c.cmd(503, "MAIL FROM:<no-reply@example.com>")                     // nested
	c.cmd(501, "RCPT TO:<a@b@example.org>")
	c.cmd(501, "RCPT TO:<\"quoted\"@example.org>")
	c.cmd(501, "RCPT TO:<a@localhost>")
	c.cmd(555, "RCPT TO:<a@example.org> NOTIFY=NEVER")
	for i := range MaxRecipients {
		c.cmd(250, "RCPT TO:<r"+string(rune('a'+i))+"@example.org>")
	}
	c.cmd(250, "RCPT TO:<RA@example.org>") // duplicate (case-insensitive): accepted, not counted
	c.cmd(452, "RCPT TO:<z@example.org>")  // the 11th
	c.cmd(354, "DATA")
	body := "From: MeshGuard <no-reply@example.com>\r\nSubject: dots\r\n\r\nline 1\r\n..starts with a dot\nbare LF\r\n...\r\n.\r\n"
	if _, err := io.WriteString(c.conn, body); err != nil {
		t.Fatal(err)
	}
	c.expect(250)
	got := fwd.all()
	if len(got) != 1 || got[0].from != "no-reply@example.com" || len(got[0].to) != MaxRecipients || got[0].to[0] != "ra@example.org" {
		t.Fatalf("forwarded envelope: %+v", got)
	}
	raw := got[0].raw
	if !strings.HasPrefix(raw, "Message-ID: <") || !strings.Contains(raw, "@example.com>\r\nFrom: MeshGuard") {
		t.Fatalf("a Message-ID is added when missing: %q", raw[:min(len(raw), 120)])
	}
	if !strings.HasSuffix(raw, "\r\n\r\nline 1\r\n.starts with a dot\r\nbare LF\r\n..\r\n") {
		t.Fatalf("dot-unstuffing / CRLF: %q", raw)
	}
	// the transaction is over: DATA needs MAIL again; RSET, NOOP, VRFY, HELP, unknown, AUTH
	c.cmd(503, "DATA")
	c.cmd(250, "RSET")
	c.cmd(250, "NOOP")
	c.cmd(252, "VRFY a@example.org")
	c.cmd(214, "HELP")
	c.cmd(502, "AUTH PLAIN")
	c.cmd(502, "STARTTLS") // no certificate: not offered
	// From header that is not an allowed sender ⇒ refused, nothing forwarded
	c.cmd(250, "MAIL FROM:<no-reply@example.com>")
	c.cmd(250, "RCPT TO:<a@example.org>")
	c.cmd(354, "DATA")
	_, _ = io.WriteString(c.conn, "From: attacker@example.net\r\nSubject: x\r\n\r\nhi\r\n.\r\n")
	c.expect(550)
	c.cmd(250, "MAIL FROM:<no-reply@example.com>")
	c.cmd(250, "RCPT TO:<a@example.org>")
	c.cmd(354, "DATA")
	_, _ = io.WriteString(c.conn, "From: no-reply@example.com\r\nFrom: no-reply@example.com\r\n\r\nhi\r\n.\r\n")
	c.expect(550) // two From headers
	c.cmd(221, "QUIT")
	if len(fwd.all()) != 1 {
		t.Fatalf("refused messages were forwarded: %d", len(fwd.all()))
	}
	for reason, want := range map[string]float64{ReasonSender: 1, ReasonSize: 1, ReasonTooManyRecipients: 1, ReasonHeader: 2,
		ReasonRecipient: 0, ReasonSyntax: 6} {
		if got := val(t, m.rejected.WithLabelValues(reason)); got != want {
			t.Errorf("rejected{reason=%q} = %v, want %v", reason, got, want)
		}
	}
	if got := val(t, m.messages.WithLabelValues("delivered")); got != 1 {
		t.Errorf("messages{delivered} = %v", got)
	}
	if got := val(t, m.recipients.WithLabelValues("sent")); got != MaxRecipients {
		t.Errorf("recipients{sent} = %v", got)
	}
}

func TestStartTLSRequired(t *testing.T) {
	ca := newTestCA(t)
	fwd := &fakeForwarder{}
	reg := prometheus.NewRegistry()
	m, _ := NewMetrics(reg)
	addr, _ := startServer(t, Config{Forwarder: fwd, TLS: ca.serverTLS, Metrics: m})
	c := dial(t, addr)
	if ehlo := c.cmd(250, "EHLO client"); !strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("STARTTLS not offered: %q", ehlo)
	}
	c.cmd(530, "MAIL FROM:<no-reply@example.com>") // plain text refused
	c.cmd(501, "STARTTLS now")
	c.starttls(ca.pool)
	c.cmd(503, "MAIL FROM:<no-reply@example.com>") // RFC 3207: EHLO again after TLS
	if ehlo := c.cmd(250, "EHLO client"); strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("STARTTLS offered again inside TLS: %q", ehlo)
	}
	c.cmd(503, "STARTTLS")
	c.cmd(250, "MAIL FROM:<no-reply@example.com>")
	c.cmd(250, "RCPT TO:<a@example.org>")
	c.cmd(354, "DATA")
	_, _ = io.WriteString(c.tp.W, msgHead+"hello\r\n.\r\n")
	_ = c.tp.W.Flush()
	c.expect(250)
	c.cmd(221, "QUIT")
	if n := len(fwd.all()); n != 1 {
		t.Fatalf("forwarded %d", n)
	}
	if val(t, m.starttls.WithLabelValues("ok")) != 1 || val(t, m.rejected.WithLabelValues(ReasonTLSRequired)) != 1 {
		t.Fatal("metrics: starttls ok / tls_required")
	}

	// a client that does not trust the internal CA cannot complete the handshake
	c2 := dial(t, addr)
	c2.cmd(250, "EHLO client")
	c2.cmd(220, "STARTTLS")
	bad := tlsClient(c2.conn, nil)
	if err := bad.HandshakeContext(context.Background()); err == nil {
		t.Fatal("handshake without the CA succeeded")
	}
}

func TestStartTLSPipelinedCommandsRefused(t *testing.T) {
	ca := newTestCA(t)
	addr, _ := startServer(t, Config{Forwarder: &fakeForwarder{}, TLS: ca.serverTLS})
	c := dial(t, addr)
	c.cmd(250, "EHLO client")
	// STARTTLS and a command in one segment: the second would be read as if it came over TLS (CVE-2011-0411 class)
	if _, err := io.WriteString(c.conn, "STARTTLS\r\nMAIL FROM:<no-reply@example.com>\r\n"); err != nil {
		t.Fatal(err)
	}
	c.expect(554)
	if !c.closed() {
		t.Fatal("connection kept open after pipelined STARTTLS")
	}
}

func TestOutcomesAndLimits(t *testing.T) {
	fwd := &fakeForwarder{next: []Outcome{
		{Class: Temporary, Code: "timeout"}, {Class: Permanent, Code: "send_failed", Status: 422},
		{Class: Partial, Code: "partial", Status: 200, Sent: 1, Failed: 1},
	}}
	addr, _ := startServer(t, Config{Forwarder: fwd, Rate: 4})
	c := dial(t, addr)
	c.cmd(250, "EHLO client")
	send := func(code int) string {
		c.cmd(250, "MAIL FROM:<no-reply@example.com>")
		c.cmd(250, "RCPT TO:<a@example.org>")
		c.cmd(354, "DATA")
		_, _ = io.WriteString(c.conn, msgHead+"x\r\n.\r\n")
		return c.expect(code)
	}
	if msg := send(451); !strings.Contains(msg, "timeout") {
		t.Fatalf("temporary: %q", msg)
	}
	if msg := send(554); !strings.Contains(msg, "send_failed") {
		t.Fatalf("permanent: %q", msg)
	}
	send(250) // partial: accepted (a retry would duplicate the recipients already sent)
	// too large: the data is read to the end, refused, and the session goes on
	c.cmd(250, "MAIL FROM:<no-reply@example.com>")
	c.cmd(250, "RCPT TO:<a@example.org>")
	c.cmd(354, "DATA")
	big := strings.Repeat(strings.Repeat("x", 998)+"\r\n", MaxMessageBytes/1000+10)
	_, _ = io.WriteString(c.conn, msgHead+big+".\r\n")
	c.expect(552)
	c.cmd(250, "NOOP")
	// rate: 4 per minute ⇒ the 5th MAIL is refused with 451
	c.cmd(451, "MAIL FROM:<no-reply@example.com>")
	if n := len(fwd.all()); n != 3 {
		t.Fatalf("forwarded %d, want 3", n)
	}
}

func TestBusyLongLineAndShutdown(t *testing.T) {
	addr, stop := startServer(t, Config{Forwarder: &fakeForwarder{}, MaxConnections: 1})
	c := dial(t, addr)
	c.cmd(250, "EHLO client")
	// a second session while the only slot is taken ⇒ 421
	d, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.SetDeadline(time.Now().Add(10 * time.Second))
	line, _ := bufio.NewReader(d).ReadString('\n')
	_ = d.Close()
	if !strings.HasPrefix(line, "421 ") {
		t.Fatalf("busy: %q", line)
	}
	// a command line over the limit ⇒ 500 and the connection is closed
	if _, err := io.WriteString(c.conn, strings.Repeat("N", 5000)+"\r\n"); err != nil {
		t.Fatal(err)
	}
	c.expect(500)
	if !c.closed() {
		t.Fatal("connection kept open after a too long line")
	}
	// shutdown: an idle session is told 421 (or closed) and Serve returns
	c3 := dialRetry(t, addr)
	c3.cmd(250, "EHLO client")
	stop()
	if !c3.closed() {
		t.Fatal("idle session survives the shutdown")
	}
}

func TestReadData(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\r\n.\r\n", "a\r\n"},
		{"..x\r\n...\r\n.\r\n", ".x\r\n..\r\n"},
		{"bare\nlf\n.\n", "bare\r\nlf\r\n"},
		{strings.Repeat("y", 40) + "\r\n.\r\n", strings.Repeat("y", 40) + "\r\n"}, // longer than the reader's buffer
		{"cr split" + strings.Repeat("z", 7) + "\r\n.\r\n", "cr split" + strings.Repeat("z", 7) + "\r\n"},
		{".\r\n", ""},
	}
	for _, tc := range cases {
		br := bufio.NewReaderSize(strings.NewReader(tc.in+"NEXT\r\n"), 16)
		raw, tooLarge, err := readData(br, 1000)
		if err != nil || tooLarge || string(raw) != tc.want {
			t.Errorf("readData(%q) = %q, %v, %v; want %q", tc.in, raw, tooLarge, err, tc.want)
		}
		if rest, _ := br.ReadString('\n'); rest != "NEXT\r\n" {
			t.Errorf("readData(%q) consumed past the terminator: %q", tc.in, rest)
		}
	}
	raw, tooLarge, err := readData(bufio.NewReader(strings.NewReader(strings.Repeat("abcdefghi\r\n", 20)+".\r\n")), 100)
	if err != nil || !tooLarge || len(raw) != 0 {
		t.Fatalf("too large: %q %v %v", raw, tooLarge, err)
	}
	if _, _, err := readData(bufio.NewReader(strings.NewReader("no terminator\r\n")), 100); err == nil {
		t.Fatal("EOF before the terminator is an error")
	}
}

func TestAddressesAndMask(t *testing.T) {
	for a, want := range map[string]bool{"a@example.org": true, "first.last+tag@sub.example.co": true, "a@b@example.org": false,
		"a@localhost": false, ".a@example.org": false, "a..b@example.org": false, "a.@example.org": false, "@example.org": false,
		"\"q\"@example.org": false, "a@[192.0.2.1]": false, "a b@example.org": false, "ä@example.org": false,
		strings.Repeat("l", 65) + "@example.org": false} {
		if ValidAddress(a) != want {
			t.Errorf("ValidAddress(%q) != %v", a, want)
		}
	}
	for a, want := range map[string]string{"alice@example.com": "a***@example.com", "x": "***", "@d": "***"} {
		if got := Mask(a); got != want {
			t.Errorf("Mask(%q) = %q", a, got)
		}
	}
	if a, p, ok := parsePath("from:<A@example.org> SIZE=10", "FROM:"); !ok || a != "A@example.org" || len(p) != 1 {
		t.Errorf("parsePath = %q %v %v", a, p, ok)
	}
	for _, bad := range []string{"FROM:", "FROM:<>", "TO:<a@example.org>", "FROM:<a@example.org", "FROM:<<a@example.org>>"} {
		if _, _, ok := parsePath(bad, "FROM:"); ok {
			t.Errorf("parsePath(%q) accepted", bad)
		}
	}
}

func TestListenAddr(t *testing.T) {
	local := func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("10.249.8.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("10.249.5.7"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	if got, err := ListenAddr(":587", netip.MustParsePrefix("10.249.8.0/24"), local); err != nil || got != "10.249.8.5:587" {
		t.Fatalf("ListenAddr = %q, %v", got, err)
	}
	if got, err := ListenAddr(":587", netip.Prefix{}, local); err != nil || got != ":587" {
		t.Fatalf("without a network = %q, %v", got, err)
	}
	if _, err := ListenAddr(":587", netip.MustParsePrefix("10.249.9.0/24"), local); err == nil {
		t.Fatal("no address in the network must fail")
	}
}

func TestCertFilesReload(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls_cert"), filepath.Join(dir, "tls_key")
	write := func(c, k []byte) {
		if err := os.WriteFile(certFile, c, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, k, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(ca.certPEM, ca.keyPEM)
	cf, err := NewCertFiles(certFile, keyFile)
	if err != nil || cf.Check() != nil {
		t.Fatalf("NewCertFiles: %v", err)
	}
	first, _ := cf.get()
	c2, k2 := ca.leaf(t, 7)
	write(c2, k2)
	later := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certFile, later, later)
	second, _ := cf.get()
	if second.Leaf == nil || second.Leaf.SerialNumber.Int64() != 7 || first == second {
		t.Fatal("the renewed certificate is not served")
	}
	write([]byte("garbage"), k2) // a half-written renewal keeps the previous pair
	_ = os.Chtimes(certFile, later.Add(time.Second), later.Add(time.Second))
	if third, err := cf.get(); err != nil || third != second {
		t.Fatalf("broken renewal: %v", err)
	}
	if _, err := NewCertFiles(certFile, keyFile); err == nil {
		t.Fatal("a broken pair must stop the start")
	}
	if _, err := NewCertFiles(filepath.Join(dir, "missing"), keyFile); err == nil {
		t.Fatal("a missing file must stop the start")
	}
}

func TestLogsHoldNoAddressOrContent(t *testing.T) {
	var logs bytes.Buffer
	fwd := &fakeForwarder{next: []Outcome{{Class: Temporary, Code: "network"}}}
	addr, _ := startServer(t, Config{Forwarder: fwd, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	c := dial(t, addr)
	c.cmd(250, "EHLO client")
	c.cmd(550, "MAIL FROM:<intruder@example.net>")
	c.cmd(250, "MAIL FROM:<no-reply@example.com>")
	c.cmd(250, "RCPT TO:<bob.secret@example.org>")
	c.cmd(354, "DATA")
	_, _ = io.WriteString(c.conn, "From: no-reply@example.com\r\nSubject: confidential-subject\r\n\r\nconfidential-body\r\n.\r\n")
	c.expect(451)
	c.cmd(221, "QUIT")
	time.Sleep(50 * time.Millisecond)
	out := logs.String()
	for _, leak := range []string{"intruder@", "bob.secret", "confidential-subject", "confidential-body", "no-reply@example.com"} {
		if strings.Contains(out, leak) {
			t.Errorf("log holds %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "i***@example.net") || !strings.Contains(out, `"code":"network"`) {
		t.Errorf("log lacks the masked sender or the code: %s", out)
	}
}
