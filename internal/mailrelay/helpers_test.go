package mailrelay

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// val reads a counter or gauge series.
func val(t testing.TB, c prometheus.Metric) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	if m.Counter != nil {
		return m.GetCounter().GetValue()
	}
	return m.GetGauge().GetValue()
}

// testCA is a throw-away CA (name constraint DNS:mailrelay, like infrastructure/host/mail-secrets.sh) and a leaf for
// "mailrelay" signed by it.
type testCA struct {
	pool            *x509.CertPool
	caPEM           []byte
	certPEM, keyPEM []byte
	serverTLS       *tls.Config
	caKey           *ecdsa.PrivateKey
	caCert          *x509.Certificate
}

func newTestCA(t testing.TB) *testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MeshGuard mail relay test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"mailrelay"}}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	ca := &testCA{pool: x509.NewCertPool(), caKey: caKey, caCert: caCert,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	ca.pool.AddCert(caCert)
	ca.certPEM, ca.keyPEM = ca.leaf(t, 2)
	pair, err := tls.X509KeyPair(ca.certPEM, ca.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca.serverTLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	return ca
}

// leaf issues a certificate for "mailrelay" with the given serial; PEM of the certificate and of its key.
func (ca *testCA) leaf(t testing.TB, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "mailrelay"},
		DNSNames: []string{"mailrelay"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// fakeForwarder records the messages it is handed and answers a scripted outcome.
type fakeForwarder struct {
	mu   sync.Mutex
	msgs []forwarded
	next []Outcome
}

type forwarded struct {
	from string
	to   []string
	raw  string
}

func (f *fakeForwarder) Forward(_ context.Context, from string, to []string, raw []byte) Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, forwarded{from: from, to: append([]string(nil), to...), raw: string(raw)})
	if len(f.next) > 0 {
		o := f.next[0]
		f.next = f.next[1:]
		return o
	}
	return Outcome{Class: Delivered, Code: "sent", Status: 200, Attempts: 1, Sent: len(to)}
}

func (f *fakeForwarder) all() []forwarded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]forwarded(nil), f.msgs...)
}

// startServer runs a Server on 127.0.0.1 until the test ends; it returns the address and the stop function.
func startServer(t testing.TB, cfg Config) (string, func()) {
	t.Helper()
	if cfg.Hostname == "" {
		cfg.Hostname = "mailrelay"
	}
	if cfg.AllowedFrom == nil {
		cfg.AllowedFrom = []string{"no-reply@example.com"}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(40 * time.Second):
			t.Error("Serve did not return")
		}
	}
	var once sync.Once
	t.Cleanup(func() { once.Do(stop) })
	return ln.Addr().String(), func() { once.Do(stop) }
}

// client is a raw SMTP conversation.
type client struct {
	t    testing.TB
	conn net.Conn
	tp   *textproto.Conn
}

func dial(t testing.TB, addr string) *client {
	t.Helper()
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	cl := &client{t: t, conn: c, tp: textproto.NewConn(c)}
	t.Cleanup(func() { _ = c.Close() })
	cl.expect(220)
	return cl
}

// dialRetry is dial once the server has a free slot again (a closed session releases it just after closing).
func dialRetry(t testing.TB, addr string) *client {
	t.Helper()
	for range 100 {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		tp := textproto.NewConn(c)
		if code, _, err := tp.ReadResponse(220); err == nil && code == 220 {
			t.Cleanup(func() { _ = c.Close() })
			return &client{t: t, conn: c, tp: tp}
		}
		_ = c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no free session slot")
	return nil
}

func tlsClient(c net.Conn, pool *x509.CertPool) *tls.Conn {
	return tls.Client(c, &tls.Config{ServerName: "mailrelay", RootCAs: pool, MinVersion: tls.VersionTLS12})
}

// expect reads one (possibly multi-line) answer and checks its code; it returns the text.
func (c *client) expect(code int) string {
	c.t.Helper()
	got, msg, err := c.tp.ReadResponse(0)
	if err != nil && got == 0 {
		c.t.Fatalf("read answer (want %d): %v", code, err)
	}
	if got != code {
		c.t.Fatalf("answer %d %q, want %d", got, msg, code)
	}
	return msg
}

func (c *client) cmd(code int, line string) string {
	c.t.Helper()
	if err := c.tp.PrintfLine("%s", line); err != nil {
		c.t.Fatalf("send %q: %v", line, err)
	}
	return c.expect(code)
}

// starttls upgrades the conversation, trusting pool for "mailrelay".
func (c *client) starttls(pool *x509.CertPool) {
	c.t.Helper()
	c.cmd(220, "STARTTLS")
	tc := tls.Client(c.conn, &tls.Config{ServerName: "mailrelay", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(context.Background()); err != nil {
		c.t.Fatalf("TLS handshake: %v", err)
	}
	c.conn, c.tp = tc, textproto.NewConn(tc)
}

// closed reports whether the server closed the connection.
func (c *client) closed() bool {
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := bufio.NewReader(c.conn).ReadByte()
	return err != nil && !strings.Contains(err.Error(), "timeout")
}
