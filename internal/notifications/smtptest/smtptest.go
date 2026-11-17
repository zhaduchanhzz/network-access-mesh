// Package smtptest is a fake SMTP relay for tests of internal/notifications (P3-T05b): it speaks enough of RFC 5321
// for net/smtp — EHLO/HELO, STARTTLS (with a throw-away self-signed certificate), AUTH PLAIN, MAIL, RCPT, DATA, RSET,
// NOOP, QUIT — records every accepted message, and can answer a temporary (4xx) or permanent (5xx) error at DATA.
// Only test code imports it.
package smtptest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

// Message is one accepted message.
type Message struct {
	From     string
	To       []string
	Data     string // raw message (headers + body), dot-unstuffed, CRLF line endings
	TLS      bool   // the session was encrypted when DATA ended
	AuthUser string // the AUTH PLAIN identity ("" without authentication)
}

// Header returns the value of a header of the message ("" if absent), decoded per RFC 2047.
func (m Message) Header(name string) string {
	msg, err := mail.ReadMessage(strings.NewReader(m.Data))
	if err != nil {
		return ""
	}
	v := msg.Header.Get(name)
	if dec, err := new(mime.WordDecoder).DecodeHeader(v); err == nil {
		return dec
	}
	return v
}

// Options of a server.
type Options struct {
	StartTLS bool              // offer STARTTLS
	Implicit bool              // TLS from the first byte (port 465 style); exclusive with StartTLS
	Users    map[string]string // AUTH PLAIN accounts; nil = no AUTH offered
}

// Server is a running fake relay.
type Server struct {
	t     testing.TB
	ln    net.Listener
	opts  Options
	tls   *tls.Config
	Roots *x509.CertPool // trust this pool to verify the server's certificate (server name "localhost")

	mu       sync.Mutex
	msgs     []Message
	failures []int // answers to give at the end of DATA for the next messages (0 = accept)
	conns    int
}

// New starts a server on 127.0.0.1 and stops it when the test ends.
func New(t testing.TB, opts Options) *Server {
	t.Helper()
	s := &Server{t: t, opts: opts}
	if opts.StartTLS || opts.Implicit {
		s.tls, s.Roots = selfSigned(t)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// Addr is host:port of the server ("localhost:<port>", matching the certificate).
func (s *Server) Addr() string {
	_, port, _ := net.SplitHostPort(s.ln.Addr().String())
	return "localhost:" + port
}

// Messages returns the accepted messages.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.msgs...)
}

// Connections returns how many sessions were opened.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// FailNext makes the end of DATA answer the given codes for the next messages (e.g. 451, 451, 550); 0 accepts.
func (s *Server) FailNext(codes ...int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, codes...)
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.session(c)
	}
}

func (s *Server) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	encrypted := false
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if s.opts.Implicit {
		tc := tls.Server(c, s.tls)
		if err := tc.HandshakeContext(ctx); err != nil {
			return
		}
		c, encrypted = tc, true
	}
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(line string) { _, _ = w.WriteString(line + "\r\n"); _ = w.Flush() }
	say("220 localhost fake ESMTP")
	var cur Message
	authUser := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			lines := []string{"250-localhost"}
			if s.opts.StartTLS && !encrypted {
				lines = append(lines, "250-STARTTLS")
			}
			if s.opts.Users != nil {
				lines = append(lines, "250-AUTH PLAIN")
			}
			lines = append(lines, "250 8BITMIME")
			for _, l := range lines {
				_, _ = w.WriteString(l + "\r\n")
			}
			_ = w.Flush()
		case "HELO":
			say("250 localhost")
		case "STARTTLS":
			if !s.opts.StartTLS || encrypted {
				say("502 not offered")
				continue
			}
			say("220 go ahead")
			tc := tls.Server(c, s.tls)
			if err := tc.HandshakeContext(ctx); err != nil {
				return
			}
			c, encrypted = tc, true
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
			say = func(line string) { _, _ = w.WriteString(line + "\r\n"); _ = w.Flush() }
		case "AUTH":
			mech, initial, _ := strings.Cut(arg, " ")
			if s.opts.Users == nil || !strings.EqualFold(mech, "PLAIN") {
				say("504 unsupported")
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(initial)
			parts := strings.Split(string(raw), "\x00")
			if err != nil || len(parts) != 3 || s.opts.Users[parts[1]] == "" || s.opts.Users[parts[1]] != parts[2] {
				say("535 authentication failed")
				continue
			}
			authUser = parts[1]
			say("235 ok")
		case "MAIL":
			cur = Message{From: addrOf(arg), AuthUser: authUser}
			say("250 ok")
		case "RCPT":
			cur.To = append(cur.To, addrOf(arg))
			say("250 ok")
		case "DATA":
			say("354 end with .")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				l = strings.TrimPrefix(l, ".")
				b.WriteString(l)
			}
			cur.Data, cur.TLS = b.String(), encrypted
			s.mu.Lock()
			code := 0
			if len(s.failures) > 0 {
				code, s.failures = s.failures[0], s.failures[1:]
			}
			if code == 0 {
				s.msgs = append(s.msgs, cur)
			}
			s.mu.Unlock()
			if code != 0 {
				say(fmt.Sprintf("%d injected failure", code))
				continue
			}
			say("250 queued")
		case "RSET":
			cur = Message{AuthUser: authUser}
			say("250 ok")
		case "NOOP":
			say("250 ok")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("500 unknown command")
		}
	}
}

func addrOf(arg string) string {
	_, v, _ := strings.Cut(arg, ":")
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = v[:i]
	}
	return strings.Trim(v, "<>")
}

// selfSigned returns a TLS config with a throw-away certificate for "localhost" and the pool that trusts it.
func selfSigned(t testing.TB) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion: tls.VersionTLS12}, pool
}
