package mailrelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the relay — the Worker's contract (infrastructure/mail/cf-worker): at most MaxRecipients recipients and
// MaxMessageBytes of raw message per request.
const (
	MaxRecipients   = 10
	MaxMessageBytes = 1 << 20
	maxCommandLine  = 2048
	maxBadCommands  = 20
)

// Config of a Server.
type Config struct {
	Hostname    string      // greeting, EHLO answer, name in the certificate
	AllowedFrom []string    // sender addresses accepted in MAIL FROM and in the From header (lower case)
	TLS         *tls.Config // STARTTLS; nil = plain text only (dev/ci). Set ⇒ STARTTLS required before MAIL
	Forwarder   Forwarder
	Timeout     time.Duration // forwarding budget of one message (default 8 s)
	Rate        int           // messages per minute, 0 = no limit
	Logger      *slog.Logger
	Metrics     *Metrics
	// MaxConnections bounds concurrent sessions (default 32); one more is answered 421.
	MaxConnections int
	// ReadTimeout bounds each command (default 2 min), SessionTimeout a whole session (default 10 min).
	ReadTimeout    time.Duration
	SessionTimeout time.Duration
}

// Server is the SMTP side of the relay.
type Server struct {
	cfg     Config
	allowed map[string]bool
	sem     chan struct{}
	limit   *limiter
	ready   atomic.Bool
	wg      sync.WaitGroup
}

// NewServer checks cfg and returns the server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Hostname == "" || len(cfg.AllowedFrom) == 0 || cfg.Forwarder == nil || cfg.Logger == nil {
		return nil, errors.New("mailrelay: hostname, allowed senders, forwarder and logger are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 2 * time.Minute
	}
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = 10 * time.Minute
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 32
	}
	s := &Server{cfg: cfg, allowed: map[string]bool{}, sem: make(chan struct{}, cfg.MaxConnections), limit: newLimiter(cfg.Rate)}
	for _, a := range cfg.AllowedFrom {
		s.allowed[strings.ToLower(a)] = true
	}
	return s, nil
}

// Ready reports whether the server is accepting connections (readiness probe).
func (s *Server) Ready() bool { return s.ready.Load() }

// Serve accepts connections on ln until ctx ends, then closes ln and waits up to 30 s for the sessions in progress (a
// message being forwarded is finished, no new command is read).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.ready.Store(true)
	defer s.ready.Store(false)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var err error
	for {
		c, aerr := ln.Accept()
		if aerr != nil {
			if ctx.Err() == nil {
				err = aerr
			}
			break
		}
		select {
		case s.sem <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.sem }()
				s.session(ctx, c)
			}()
		default:
			s.cfg.Metrics.reject(ReasonBusy)
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(c, "421 4.3.2 too many connections, try again later\r\n")
			_ = c.Close()
		}
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	return err
}

type session struct {
	s     *Server
	conn  net.Conn
	br    *bufio.Reader
	bw    *bufio.Writer
	tls   bool
	helo  bool
	from  string
	rcpts []string
	bad   int
	log   *slog.Logger
}

var errLineTooLong = errors.New("line too long")

func (s *Server) session(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	defer s.cfg.Metrics.session()()
	end := time.Now().Add(s.cfg.SessionTimeout)
	ss := &session{s: s, conn: c, br: bufio.NewReaderSize(c, 4096), bw: bufio.NewWriter(c), log: s.cfg.Logger}
	stop := context.AfterFunc(ctx, func() { _ = ss.conn.SetReadDeadline(time.Now()) })
	defer stop()
	ss.reply(220, s.cfg.Hostname+" ESMTP MeshGuard mail relay")
	for {
		if ctx.Err() != nil {
			ss.reply(421, "4.3.2 service shutting down")
			return
		}
		rd := time.Now().Add(s.cfg.ReadTimeout)
		if rd.After(end) {
			rd = end
		}
		_ = ss.conn.SetReadDeadline(rd)
		line, err := ss.readLine()
		if err != nil {
			var ne net.Error
			switch {
			case errors.Is(err, errLineTooLong):
				s.cfg.Metrics.reject(ReasonSyntax)
				ss.reply(500, "5.5.6 command line too long")
			case errors.As(err, &ne) && ne.Timeout() && ctx.Err() == nil:
				ss.reply(421, "4.4.2 idle timeout, closing connection")
			}
			return
		}
		if ss.command(ctx, line) {
			return
		}
		if ss.bad >= maxBadCommands {
			ss.reply(421, "4.7.0 too many errors, closing connection")
			return
		}
	}
}

func (ss *session) readLine() (string, error) {
	line, err := ss.br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxCommandLine {
		return "", errLineTooLong
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

func (ss *session) reply(code int, text string) {
	_ = ss.conn.SetWriteDeadline(time.Now().Add(time.Minute))
	_, _ = fmt.Fprintf(ss.bw, "%d %s\r\n", code, text)
	_ = ss.bw.Flush()
}

func (ss *session) replyLines(code int, lines []string) {
	_ = ss.conn.SetWriteDeadline(time.Now().Add(time.Minute))
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		_, _ = fmt.Fprintf(ss.bw, "%d%s%s\r\n", code, sep, l)
	}
	_ = ss.bw.Flush()
}

// fail answers an error caused by the client's command (counted towards maxBadCommands).
func (ss *session) fail(code int, text string) {
	ss.bad++
	ss.reply(code, text)
}

func (ss *session) reset() {
	ss.from, ss.rcpts = "", nil
}

// command runs one command line; true ends the session.
func (ss *session) command(ctx context.Context, line string) bool {
	verb, arg, _ := strings.Cut(line, " ")
	arg = strings.TrimSpace(arg)
	s := ss.s
	switch strings.ToUpper(verb) {
	case "EHLO", "HELO":
		if arg == "" {
			ss.fail(501, "5.5.4 a domain or address literal is required")
			return false
		}
		ss.helo = true
		ss.reset()
		if strings.EqualFold(verb, "HELO") {
			ss.reply(250, s.cfg.Hostname)
			return false
		}
		lines := []string{s.cfg.Hostname, "SIZE " + strconv.Itoa(MaxMessageBytes), "ENHANCEDSTATUSCODES"}
		if s.cfg.TLS != nil && !ss.tls {
			lines = append(lines, "STARTTLS")
		}
		ss.replyLines(250, lines)
	case "STARTTLS":
		return ss.startTLS(ctx, arg)
	case "MAIL":
		ss.mail(arg)
	case "RCPT":
		ss.rcpt(arg)
	case "DATA":
		return ss.data(ctx, arg)
	case "RSET":
		ss.reset()
		ss.reply(250, "2.0.0 reset")
	case "NOOP":
		ss.reply(250, "2.0.0 OK")
	case "QUIT":
		ss.reply(221, "2.0.0 closing connection")
		return true
	case "VRFY":
		ss.reply(252, "2.5.2 cannot verify the address")
	case "HELP":
		ss.reply(214, "2.0.0 EHLO STARTTLS MAIL RCPT DATA RSET NOOP QUIT")
	default:
		// AUTH included: the relay listens on the internal network only and accepts only its own sender addresses
		s.cfg.Metrics.reject(ReasonSyntax)
		ss.fail(502, "5.5.1 command not implemented")
	}
	return false
}

func (ss *session) startTLS(ctx context.Context, arg string) bool {
	s := ss.s
	switch {
	case s.cfg.TLS == nil:
		ss.fail(502, "5.5.1 STARTTLS not available")
		return false
	case ss.tls:
		ss.fail(503, "5.5.1 TLS already active")
		return false
	case arg != "":
		ss.fail(501, "5.5.4 STARTTLS takes no parameter")
		return false
	case ss.br.Buffered() > 0:
		// data pipelined after STARTTLS would be read as if it came over TLS (command injection) — refuse and close
		s.cfg.Metrics.tls(false)
		ss.reply(554, "5.5.1 data sent after STARTTLS before the TLS handshake")
		return true
	}
	ss.reply(220, "2.0.0 ready to start TLS")
	tc := tls.Server(ss.conn, s.cfg.TLS)
	_ = ss.conn.SetDeadline(time.Now().Add(30 * time.Second))
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		s.cfg.Metrics.tls(false)
		ss.log.Info("mailrelay: STARTTLS handshake failed", "reason", tlsReason(err))
		return true
	}
	_ = ss.conn.SetDeadline(time.Time{})
	ss.conn, ss.br, ss.bw = tc, bufio.NewReaderSize(tc, 4096), bufio.NewWriter(tc)
	ss.tls, ss.helo = true, false // RFC 3207: forget everything, the client says EHLO again
	ss.reset()
	s.cfg.Metrics.tls(true)
	return false
}

func tlsReason(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, io.EOF):
		return "closed"
	default:
		return "handshake"
	}
}

func (ss *session) mail(arg string) {
	s := ss.s
	switch {
	case !ss.helo:
		ss.fail(503, "5.5.1 say EHLO first")
		return
	case s.cfg.TLS != nil && !ss.tls:
		s.cfg.Metrics.reject(ReasonTLSRequired)
		ss.fail(530, "5.7.0 must issue a STARTTLS command first")
		return
	case ss.from != "":
		ss.fail(503, "5.5.1 nested MAIL command")
		return
	}
	addr, params, ok := parsePath(arg, "FROM:")
	if !ok {
		s.cfg.Metrics.reject(ReasonSyntax)
		ss.fail(501, "5.5.4 syntax: MAIL FROM:<address>")
		return
	}
	for _, p := range params {
		k, v, _ := strings.Cut(p, "=")
		switch strings.ToUpper(k) {
		case "SIZE":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				ss.fail(501, "5.5.4 invalid SIZE")
				return
			}
			if n > MaxMessageBytes {
				s.cfg.Metrics.reject(ReasonSize)
				ss.fail(552, "5.3.4 message size exceeds the limit of "+strconv.Itoa(MaxMessageBytes)+" bytes")
				return
			}
		case "BODY":
			if u := strings.ToUpper(v); u != "7BIT" && u != "8BITMIME" {
				ss.fail(501, "5.5.4 invalid BODY")
				return
			}
		default:
			ss.fail(555, "5.5.4 MAIL parameter not supported")
			return
		}
	}
	addr = strings.ToLower(addr)
	if !s.allowed[addr] {
		s.cfg.Metrics.reject(ReasonSender)
		ss.log.Info("mailrelay: sender refused", "from", Mask(addr))
		ss.fail(550, "5.7.1 sender address not allowed")
		return
	}
	if !s.limit.allow(time.Now()) {
		s.cfg.Metrics.reject(ReasonRate)
		ss.reply(451, "4.7.0 rate limit reached, try again later")
		return
	}
	ss.from = addr
	ss.reply(250, "2.1.0 sender OK")
}

func (ss *session) rcpt(arg string) {
	s := ss.s
	if ss.from == "" {
		ss.fail(503, "5.5.1 MAIL first")
		return
	}
	addr, params, ok := parsePath(arg, "TO:")
	switch {
	case !ok:
		s.cfg.Metrics.reject(ReasonSyntax)
		ss.fail(501, "5.5.4 syntax: RCPT TO:<address>")
		return
	case len(params) > 0:
		ss.fail(555, "5.5.4 RCPT parameters not supported")
		return
	case !ValidAddress(addr):
		s.cfg.Metrics.reject(ReasonRecipient)
		ss.fail(501, "5.1.3 bad recipient address syntax")
		return
	}
	addr = strings.ToLower(addr)
	for _, r := range ss.rcpts {
		if r == addr {
			ss.reply(250, "2.1.5 recipient OK")
			return
		}
	}
	if len(ss.rcpts) >= MaxRecipients {
		s.cfg.Metrics.reject(ReasonTooManyRecipients)
		ss.reply(452, "4.5.3 too many recipients ("+strconv.Itoa(MaxRecipients)+" per message)")
		return
	}
	ss.rcpts = append(ss.rcpts, addr)
	ss.reply(250, "2.1.5 recipient OK")
}

func (ss *session) data(ctx context.Context, arg string) bool {
	s := ss.s
	switch {
	case arg != "":
		ss.fail(501, "5.5.4 DATA takes no parameter")
		return false
	case ss.from == "":
		ss.fail(503, "5.5.1 MAIL first")
		return false
	case len(ss.rcpts) == 0:
		ss.fail(554, "5.5.1 no valid recipients")
		return false
	}
	ss.reply(354, "end data with <CR><LF>.<CR><LF>")
	_ = ss.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	raw, tooLarge, err := readData(ss.br, MaxMessageBytes)
	if err != nil {
		return true // connection lost or timed out in the middle of the message
	}
	from, rcpts := ss.from, ss.rcpts
	ss.reset()
	if tooLarge {
		s.cfg.Metrics.reject(ReasonSize)
		ss.reply(552, "5.3.4 message size exceeds the limit of "+strconv.Itoa(MaxMessageBytes)+" bytes")
		return false
	}
	raw, err = s.prepare(raw, from)
	if err != nil {
		s.cfg.Metrics.reject(ReasonHeader)
		ss.log.Info("mailrelay: message refused", "from", Mask(from), "rcpt", len(rcpts), "reason", err.Error())
		ss.reply(550, "5.7.1 "+err.Error())
		return false
	}
	t0 := time.Now()
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.Timeout)
	out := s.cfg.Forwarder.Forward(fctx, from, rcpts, raw)
	cancel()
	took := time.Since(t0)
	s.cfg.Metrics.message(out, took)
	attrs := []any{"from", Mask(from), "rcpt", len(rcpts), "bytes", len(raw), "result", out.Class.String(), "code", out.Code,
		"status", out.Status, "attempts", out.Attempts, "sent", out.Sent, "failed", out.Failed, "duration_ms", took.Milliseconds()}
	switch out.Class {
	case Delivered:
		ss.log.Info("mailrelay: message relayed", attrs...)
		ss.reply(250, "2.0.0 message accepted for delivery")
	case Partial:
		ss.log.Warn("mailrelay: message relayed to some recipients only", attrs...)
		ss.reply(250, "2.0.0 message accepted for delivery (some recipients failed)")
	case Temporary:
		ss.log.Warn("mailrelay: message not relayed (temporary)", attrs...)
		ss.reply(451, "4.3.0 temporary relay failure ("+out.Code+"), try again later")
	default:
		ss.log.Warn("mailrelay: message refused by the Worker", attrs...)
		ss.reply(554, "5.6.0 message refused by the relay ("+out.Code+")")
	}
	return false
}

// prepare checks the header block (the From header must be one allowed sender) and adds a Message-ID when missing
// (Email Service refuses a raw message without one — E_FIELD_MISSING).
func (s *Server) prepare(raw []byte, from string) ([]byte, error) {
	head := raw
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head = raw[:i+2]
	}
	h, err := textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(head), strings.NewReader("\r\n")))).ReadMIMEHeader()
	if err != nil {
		return nil, errors.New("malformed header section")
	}
	vals := h.Values("From")
	if len(vals) != 1 {
		return nil, errors.New("exactly one From header is required")
	}
	list, err := mail.ParseAddressList(vals[0])
	if err != nil || len(list) != 1 || !s.allowed[strings.ToLower(list[0].Address)] {
		return nil, errors.New("the From header must be an allowed sender address")
	}
	if strings.TrimSpace(h.Get("Message-Id")) != "" {
		return raw, nil
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	_, domain, _ := strings.Cut(from, "@")
	out := make([]byte, 0, len(raw)+64)
	out = append(out, "Message-ID: <"+hex.EncodeToString(id[:])+"@"+domain+">\r\n"...)
	return append(out, raw...), nil
}

// readData reads a DATA section up to the terminating "." line: dot-unstuffing, bare LF → CRLF. Past limit bytes the
// rest is read and dropped (tooLarge). err only for a broken connection.
func readData(br *bufio.Reader, limit int) (raw []byte, tooLarge bool, err error) {
	var buf bytes.Buffer
	atStart, last := true, byte('\n')
	for {
		chunk, rerr := br.ReadSlice('\n')
		if rerr != nil && !errors.Is(rerr, bufio.ErrBufferFull) {
			return nil, false, rerr
		}
		if atStart && (string(chunk) == ".\r\n" || string(chunk) == ".\n") {
			return buf.Bytes(), tooLarge, nil
		}
		if atStart && len(chunk) > 0 && chunk[0] == '.' {
			chunk = chunk[1:]
		}
		if n := len(chunk); n > 0 && chunk[n-1] == '\n' {
			crlf := (n >= 2 && chunk[n-2] == '\r') || (n == 1 && last == '\r') // CR may end the previous chunk
			if !crlf {
				chunk = append(chunk[:n-1:n-1], '\r', '\n') // bare LF ⇒ CRLF (a copy: chunk is the reader's buffer)
			}
		}
		if !tooLarge {
			if buf.Len()+len(chunk) > limit {
				tooLarge = true
				buf.Reset()
			} else {
				buf.Write(chunk)
			}
		}
		if len(chunk) > 0 {
			last = chunk[len(chunk)-1]
		}
		atStart = len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
	}
}

// parsePath parses `FROM:<address> [params]` / `TO:<address> [params]` (prefix case-insensitive, optional space after
// the colon). The null path <> is refused: the relay only sends from its own addresses.
func parsePath(arg, prefix string) (string, []string, bool) {
	if len(arg) < len(prefix) || !strings.EqualFold(arg[:len(prefix)], prefix) {
		return "", nil, false
	}
	rest := strings.TrimLeft(arg[len(prefix):], " ")
	if !strings.HasPrefix(rest, "<") {
		return "", nil, false
	}
	end := strings.IndexByte(rest, '>')
	if end < 2 {
		return "", nil, false
	}
	addr := rest[1:end]
	if !ValidAddress(addr) {
		return "", nil, false
	}
	return addr, strings.Fields(rest[end+1:]), true
}

var addrRE = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@" +
	`[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

// ValidAddress accepts a plain ASCII address local@domain (dot-atom local part, a domain with at least one dot; no
// quoted local part, address literal, source route or SMTPUTF8).
func ValidAddress(a string) bool {
	return len(a) <= 254 && addrRE.MatchString(a) && !strings.HasPrefix(a, ".") && !strings.Contains(a, "..") &&
		!strings.Contains(a, ".@")
}

// Mask hides an address in logs: first character of the local part + "***@" + domain.
func Mask(a string) string {
	local, domain, ok := strings.Cut(a, "@")
	if !ok || local == "" || domain == "" {
		return "***"
	}
	return local[:1] + "***@" + domain
}

// limiter is a token bucket of rate messages per minute (burst = rate); nil allows everything.
type limiter struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	at     time.Time
}

func newLimiter(perMinute int) *limiter {
	if perMinute <= 0 {
		return nil
	}
	return &limiter{rate: float64(perMinute), tokens: float64(perMinute)}
}

func (l *limiter) allow(now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.at.IsZero() {
		l.tokens = min(l.rate, l.tokens+now.Sub(l.at).Minutes()*l.rate)
	}
	l.at = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
