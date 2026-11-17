package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"time"
)

// Message is one e-mail to one recipient.
type Message struct {
	To        string // bare address
	Subject   string // one line, UTF-8 (encoded as RFC 2047 when needed)
	Body      string // plain text, UTF-8
	MessageID string // <id@domain>: the outbox row — a retried send carries the same Message-ID
}

// Mailer delivers one message. Errors are classified by IsPermanent.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// TLS modes of the SMTP relay.
const (
	TLSStartTLS = "starttls" // plain connection upgraded with STARTTLS — refused if the server does not offer it
	TLSImplicit = "implicit" // TLS from the first byte (port 465)
	TLSNone     = "none"     // no TLS: only for the dev/CI test sink, never with authentication (config refuses it outside dev/ci)
)

// SMTPConfig is the relay of the worker (MG_SMTP_* — internal/config). The password is a file secret read at every
// send (rotation without restart), never configuration.
type SMTPConfig struct {
	Addr         string // host:port
	TLS          string // TLSStartTLS (default), TLSImplicit, TLSNone
	ServerName   string // TLS server name; default the host of Addr
	Username     string // "" = no authentication
	PasswordFile string // required with Username
	From         string // RFC 5322 address of the sender, e.g. "MeshGuard <no-reply@example.com>"
	HeloName     string // EHLO name; default "meshguard"
	RootCAs      *x509.CertPool
	Timeout      time.Duration // whole conversation; default 30 s
}

// SMTPMailer sends through one relay with net/smtp (AUTH PLAIN only over TLS — net/smtp refuses it otherwise).
type SMTPMailer struct {
	cfg  SMTPConfig
	host string
	from *mail.Address
}

// NewSMTPMailer checks cfg and returns the mailer.
func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("notifications: SMTP address must be host:port")
	}
	if cfg.TLS == "" {
		cfg.TLS = TLSStartTLS
	}
	switch cfg.TLS {
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		return nil, fmt.Errorf("notifications: SMTP TLS mode %q (starttls, implicit, none)", cfg.TLS)
	}
	if cfg.Username != "" && cfg.PasswordFile == "" {
		return nil, errors.New("notifications: SMTP username without a password file")
	}
	if cfg.Username != "" && cfg.TLS == TLSNone {
		return nil, errors.New("notifications: SMTP authentication requires TLS")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, errors.New("notifications: SMTP From must be an RFC 5322 address")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if cfg.HeloName == "" {
		cfg.HeloName = "meshguard"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &SMTPMailer{cfg: cfg, host: host, from: from}, nil
}

// FromDomain is the domain of the sender address (Message-ID right-hand side).
func (s *SMTPMailer) FromDomain() string {
	_, d, _ := strings.Cut(s.from.Address, "@")
	return d
}

// smtpError is a failed SMTP conversation; Permanent for a 5xx answer (no retry can fix it).
type smtpError struct {
	stage     string
	permanent bool
	err       error
}

func (e *smtpError) Error() string { return "smtp " + e.stage + ": " + e.err.Error() }
func (e *smtpError) Unwrap() error { return e.err }

// IsPermanent reports an error no retry can fix: a 5xx answer of the relay, a refused STARTTLS, a bad address.
func IsPermanent(err error) bool {
	var se *smtpError
	return errors.As(err, &se) && se.permanent
}

func classify(stage string, err error) error {
	if err == nil {
		return nil
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		return &smtpError{stage: stage, permanent: te.Code >= 500, err: fmt.Errorf("%d %s", te.Code, clean(te.Msg))}
	}
	return &smtpError{stage: stage, err: errors.New(clean(err.Error()))}
}

// clean bounds a server message (it never holds our credentials: AUTH PLAIN is never echoed).
func clean(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// Send delivers m: connect (bounded by ctx and Timeout), TLS as configured, EHLO, AUTH PLAIN when configured, MAIL,
// RCPT, DATA, QUIT.
func (s *SMTPMailer) Send(ctx context.Context, m Message) (err error) {
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return &smtpError{stage: "address", permanent: true, err: errors.New("invalid recipient address")}
	}
	data, err := s.compose(to, m)
	if err != nil {
		return &smtpError{stage: "compose", permanent: true, err: err}
	}
	deadline := time.Now().Add(s.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := &net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return classify("connect", err)
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	tlsCfg := &tls.Config{ServerName: s.cfg.ServerName, RootCAs: s.cfg.RootCAs, MinVersion: tls.VersionTLS12}
	if s.cfg.TLS == TLSImplicit {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return classify("tls", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return classify("greeting", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(s.cfg.HeloName); err != nil {
		return classify("ehlo", err)
	}
	if s.cfg.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return &smtpError{stage: "starttls", permanent: true, err: errors.New("the relay does not offer STARTTLS (no downgrade to plain text)")}
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return classify("starttls", err)
		}
	}
	if s.cfg.Username != "" {
		pw, err := readSecretFile(s.cfg.PasswordFile)
		if err != nil {
			return &smtpError{stage: "auth", permanent: true, err: err}
		}
		auth := smtp.PlainAuth("", s.cfg.Username, pw, s.host) // net/smtp checks it against the dialled host
		if err := c.Auth(auth); err != nil {
			return classify("auth", err)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return classify("mail", err)
	}
	if err := c.Rcpt(to.Address); err != nil {
		return classify("rcpt", err)
	}
	w, err := c.Data()
	if err != nil {
		return classify("data", err)
	}
	if _, err := w.Write(data); err != nil {
		return classify("data", err)
	}
	if err := w.Close(); err != nil {
		return classify("data", err)
	}
	_ = c.Quit() // the message is accepted once DATA ends with 250; a failed QUIT changes nothing
	return nil
}

// compose builds the RFC 5322 message: UTF-8 text in quoted-printable, an RFC 2047 subject, no header taken from
// user data without encoding (CR/LF cannot reach a header).
func (s *SMTPMailer) compose(to *mail.Address, m Message) ([]byte, error) {
	if strings.ContainsAny(m.MessageID, "\r\n") || strings.ContainsAny(m.To, "\r\n") {
		return nil, errors.New("header value with a line break")
	}
	subject := strings.Join(strings.Fields(m.Subject), " ")
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", s.from.String())
	h("To", to.String())
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	if m.MessageID != "" {
		h("Message-ID", m.MessageID)
	}
	h("MIME-Version", "1.0")
	h("Content-Type", `text/plain; charset="utf-8"`)
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

// readSecretFile reads a file secret (one value, trailing newline removed).
func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: deployment configuration (MG_SMTP_PASSWORD_FILE)
	if err != nil {
		return "", fmt.Errorf("read the SMTP password file: %w", errors.Unwrap(err))
	}
	v := strings.TrimRight(string(b), "\r\n")
	clear(b)
	if v == "" {
		return "", errors.New("the SMTP password file is empty")
	}
	return v, nil
}
