package prober

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

var (
	hostnameRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)
	jsonKeyRE  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// credentialHeader reports header names whose value is (or may be) a credential: they can be neither reported nor
// expected, so no answer of the prober ever carries one.
func credentialHeader(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"authorization", "cookie", "token", "secret", "password", "api-key", "apikey", "credential", "x-mg-"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// httpsPlan is a validated HTTPS request.
type httpsPlan struct {
	addr    netip.AddrPort
	sni     string
	host    string
	path    string // escaped path part, sent as is
	query   string // raw query, sent as is
	headers []string
	expect  Expect
	limit   time.Duration
}

func validHostname(s string) bool { return len(s) <= 253 && hostnameRE.MatchString(s) }

// planHTTPS validates a request (nothing is sent for an invalid one).
func planHTTPS(req HTTPSRequest) (httpsPlan, error) {
	addr, err := parseTarget("address", req.Address)
	if err != nil {
		return httpsPlan{}, err
	}
	p := httpsPlan{addr: addr, sni: strings.ToLower(strings.TrimSpace(req.SNI)), expect: req.Expect}
	if !validHostname(p.sni) || net.ParseIP(p.sni) != nil {
		return httpsPlan{}, newError(CodeInvalidRequest, "sni must be a DNS host name")
	}
	p.host = strings.TrimSpace(req.Host)
	if p.host == "" {
		p.host = p.sni
	}
	if h, port, err := net.SplitHostPort(p.host); err == nil {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || !validHostname(h) {
			return httpsPlan{}, newError(CodeInvalidRequest, "host must be a host name with an optional port")
		}
	} else if !validHostname(p.host) {
		return httpsPlan{}, newError(CodeInvalidRequest, "host must be a host name with an optional port")
	}
	if p.path, p.query, err = splitPath(req.Path); err != nil {
		return httpsPlan{}, err
	}
	if p.limit, err = timeout(req.TimeoutMS, DefaultHTTPSTimeout); err != nil {
		return httpsPlan{}, err
	}
	if len(req.Headers) > 16 {
		return httpsPlan{}, newError(CodeInvalidRequest, "at most 16 response headers can be reported")
	}
	for _, h := range req.Headers {
		if err := checkHeaderName(h); err != nil {
			return httpsPlan{}, err
		}
		p.headers = append(p.headers, textproto.CanonicalMIMEHeaderKey(h))
	}
	for h := range req.Expect.Headers {
		if err := checkHeaderName(h); err != nil {
			return httpsPlan{}, err
		}
	}
	for _, s := range req.Expect.Status {
		if s < 100 || s > 599 {
			return httpsPlan{}, newError(CodeInvalidRequest, "expect.status must be HTTP statuses")
		}
	}
	if req.Expect.BodySHA256 != "" && !sha256RE.MatchString(req.Expect.BodySHA256) {
		return httpsPlan{}, newError(CodeInvalidRequest, "expect.body_sha256 must be 64 lower-case hex digits")
	}
	if req.Expect.BodySize != nil && *req.Expect.BodySize < 0 {
		return httpsPlan{}, newError(CodeInvalidRequest, "expect.body_size must not be negative")
	}
	keys := append(slices.Clone(req.Expect.JSONPresent), slices.Collect(maps.Keys(req.Expect.JSONEquals))...)
	if len(keys) > 8 {
		return httpsPlan{}, newError(CodeInvalidRequest, "at most 8 JSON keys can be checked")
	}
	for _, k := range keys {
		if !jsonKeyRE.MatchString(k) || credentialHeader(k) {
			return httpsPlan{}, newError(CodeInvalidRequest, "invalid JSON key in expect")
		}
	}
	return p, nil
}

func checkHeaderName(h string) error {
	if h == "" || len(h) > 64 || strings.ContainsFunc(h, func(r rune) bool {
		return r <= ' ' || r >= 0x7f || strings.ContainsRune(`()<>@,;:\"/[]?={}`, r)
	}) {
		return newError(CodeInvalidRequest, "invalid header name")
	}
	if credentialHeader(h) {
		return newError(CodeInvalidRequest, "headers that carry credentials cannot be reported or expected")
	}
	return nil
}

// splitPath checks an origin-form request target ("/a/b?c") and splits it; the bytes are kept as given.
func splitPath(target string) (path, query string, err error) {
	if target == "" {
		return "/", "", nil
	}
	if len(target) > 2048 || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") ||
		strings.ContainsFunc(target, func(r rune) bool { return r <= ' ' || r >= 0x7f || r == '#' }) {
		return "", "", newError(CodeInvalidRequest, "path must be an origin-form target: /…, printable ASCII, no fragment")
	}
	path, query, _ = strings.Cut(target, "?")
	return path, query, nil
}

// HTTPS sends one GET to req.Address with the given SNI and Host, then evaluates the expectations.
func (l *Local) HTTPS(ctx context.Context, req HTTPSRequest) (HTTPSResult, error) {
	p, err := planHTTPS(req)
	if err != nil {
		return HTTPSResult{}, err
	}
	if err := checkTarget(l.allow, "address", p.addr); err != nil {
		return HTTPSResult{}, err
	}
	res := l.https(ctx, p)
	l.log.InfoContext(ctx, "probe", "kind", "https", "address", res.Address, "sni", res.SNI, "host", res.Host,
		"path", res.Path, "ok", res.OK, "status", res.Status, "class", res.Class, "code", code(res.Error),
		"failures", len(res.Failures), "total_ms", res.Timing.TotalMS)
	return res, nil
}

func (l *Local) https(ctx context.Context, p httpsPlan) (res HTTPSResult) {
	target := p.path
	if p.query != "" {
		target += "?" + p.query
	}
	res = HTTPSResult{Address: p.addr.String(), SNI: p.sni, Host: p.host, Path: logx.RedactString(target),
		CheckedAt: l.now().UTC()}
	start := time.Now()
	defer func() { res.Timing.TotalMS = ms(time.Since(start)) }()
	ctx, cancel := context.WithTimeout(ctx, p.limit)
	defer cancel()

	tc, cleanup, e := l.handshake(ctx, p.addr, p.sni, start, &res.Timing, &res.TLS)
	defer cleanup()
	if e != nil {
		res.Error = e
		return res
	}

	hreq := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: p.sni, Opaque: p.path, RawQuery: p.query},
		Host: p.host, Header: http.Header{"User-Agent": {l.ua}, "Accept": {"*/*"}}, Close: true, Proto: "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1}
	t1 := time.Now()
	if err := hreq.Write(tc); err != nil {
		res.Error = classify(ctx, err)
		return res
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), hreq)
	if err != nil {
		res.Error = classifyRead(ctx, err)
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	res.Timing.FirstByteMS = ms(time.Since(t1))
	res.Status, res.Class = resp.StatusCode, ClassOf(resp.StatusCode)
	for _, h := range p.headers {
		if v := resp.Header.Values(h); len(v) > 0 {
			if res.Headers == nil {
				res.Headers = map[string]string{}
			}
			res.Headers[h] = bounded(strings.Join(v, ", "), 512)
		}
	}
	var body bytes.Buffer
	n, err := io.Copy(&body, io.LimitReader(resp.Body, int64(l.maxBody)+1))
	if err != nil {
		res.Error = classifyRead(ctx, err)
	}
	if n > int64(l.maxBody) {
		res.BodyTruncated = true
		body.Truncate(l.maxBody)
	}
	sum := sha256.Sum256(body.Bytes())
	res.BodySize, res.BodySHA256 = int64(body.Len()), hex.EncodeToString(sum[:])
	l.check(&res, resp.Header, body.Bytes(), p.expect)
	res.OK = res.Error == nil && len(res.Failures) == 0
	return res
}

// handshake dials addr and runs a verified TLS handshake with sni (ALPN http/1.1). It fills the connect and TLS timings
// and the session's TLSInfo; cleanup closes the connection and must always be called. ctx bounds the whole exchange:
// its deadline becomes the socket deadline and its end aborts a blocked read or write.
func (l *Local) handshake(ctx context.Context, addr netip.AddrPort, sni string, start time.Time, timing *Timing,
	info **TLSInfo) (tc *tls.Conn, cleanup func(), failure *Error) {
	cleanup = func() {}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, cleanup, classify(ctx, err)
	}
	timing.ConnectMS = ms(time.Since(start))
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })
	cleanup = func() { stop(); _ = raw.Close() }

	t0 := time.Now()
	tc = tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: l.roots, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, cleanup, classifyTLS(ctx, err)
	}
	timing.TLSMS = ms(time.Since(t0))
	cs := tc.ConnectionState()
	*info = &TLSInfo{Version: tls.VersionName(cs.Version)}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		(*info).Issuer, (*info).DNSNames, (*info).NotAfter = leaf.Issuer.CommonName, leaf.DNSNames, leaf.NotAfter.UTC()
	}
	return tc, cleanup, nil
}

// TLS runs a verified TLS handshake with req.SNI against req.Address and reports the certificate the server presented
// (P3-T16: certificate expiry of every site of the edge — a site whose HTTP layer refuses the prober, such as
// admin.<domain>, still presents its certificate). Nothing is sent after the handshake.
func (l *Local) TLS(ctx context.Context, req TLSRequest) (TLSResult, error) {
	addr, err := parseTarget("address", req.Address)
	if err != nil {
		return TLSResult{}, err
	}
	sni := strings.ToLower(strings.TrimSpace(req.SNI))
	if !validHostname(sni) || net.ParseIP(sni) != nil {
		return TLSResult{}, newError(CodeInvalidRequest, "sni must be a DNS host name")
	}
	limit, err := timeout(req.TimeoutMS, DefaultHTTPSTimeout)
	if err != nil {
		return TLSResult{}, err
	}
	if err := checkTarget(l.allow, "address", addr); err != nil {
		return TLSResult{}, err
	}
	res := TLSResult{Address: addr.String(), SNI: sni, CheckedAt: l.now().UTC()}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	_, cleanup, e := l.handshake(ctx, addr, sni, start, &res.Timing, &res.TLS)
	cleanup()
	res.Error, res.OK = e, e == nil
	res.Timing.TotalMS = ms(time.Since(start))
	l.log.InfoContext(ctx, "probe", "kind", "tls", "address", res.Address, "sni", sni, "ok", res.OK, "code", code(e),
		"total_ms", res.Timing.TotalMS)
	return res, nil
}

// check evaluates the expectations of an answer.
func (l *Local) check(res *HTTPSResult, h http.Header, body []byte, e Expect) {
	fail := func(check, want, got string) {
		res.Failures = append(res.Failures, Failure{Check: check, Want: want, Got: bounded(got, 256)})
	}
	if len(e.Status) > 0 && !slices.Contains(e.Status, res.Status) {
		want := make([]string, len(e.Status))
		for i, s := range e.Status {
			want[i] = strconv.Itoa(s)
		}
		fail("status", strings.Join(want, "|"), strconv.Itoa(res.Status))
	}
	for _, name := range slices.Sorted(maps.Keys(e.Headers)) {
		if got := strings.Join(h.Values(name), ", "); got != e.Headers[name] {
			fail("header:"+strings.ToLower(name), e.Headers[name], got)
		}
	}
	if res.BodyTruncated && (e.BodySHA256 != "" || e.BodySize != nil || len(e.JSONPresent)+len(e.JSONEquals) > 0) {
		fail("body", fmt.Sprintf("at most %d bytes", l.maxBody), "larger")
		return
	}
	if e.BodySHA256 != "" && e.BodySHA256 != res.BodySHA256 {
		fail("body_sha256", e.BodySHA256, res.BodySHA256)
	}
	if e.BodySize != nil && *e.BodySize != res.BodySize {
		fail("body_size", strconv.FormatInt(*e.BodySize, 10), strconv.FormatInt(res.BodySize, 10))
	}
	if len(e.JSONPresent)+len(e.JSONEquals) == 0 {
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		fail("json", "a JSON object", "not a JSON object")
		return
	}
	value := func(k string) (string, bool) {
		s, ok := doc[k].(string)
		if ok {
			if res.JSON == nil {
				res.JSON = map[string]string{}
			}
			res.JSON[k] = bounded(s, 256)
		}
		return s, ok
	}
	for _, k := range e.JSONPresent {
		if s, ok := value(k); !ok || s == "" {
			fail("json:"+k, "a non-empty string", jsonKind(doc[k]))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(e.JSONEquals)) {
		if s, ok := value(k); !ok || s != e.JSONEquals[k] {
			got := jsonKind(doc[k])
			if ok {
				got = s
			}
			fail("json:"+k, e.JSONEquals[k], got)
		}
	}
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "missing"
	case string:
		return "empty string"
	case float64:
		return "a number"
	case bool:
		return "a boolean"
	case []any:
		return "an array"
	}
	return "an object"
}

// bounded redacts s and cuts it to n bytes.
func bounded(s string, n int) string {
	s = logx.RedactString(s)
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// classifyTLS maps a handshake error: certificate problems are tls_verify, everything else tls_handshake (alert, no
// certificate for the SNI, protocol) unless it is a socket error.
func classifyTLS(ctx context.Context, err error) *Error {
	var (
		verr *tls.CertificateVerificationError
		unk  x509.UnknownAuthorityError
		host x509.HostnameError
		inv  x509.CertificateInvalidError
		alrt tls.AlertError
		rec  tls.RecordHeaderError
	)
	switch {
	case errors.As(err, &unk):
		return newError(CodeTLSVerify, "certificate signed by an unknown authority")
	case errors.As(err, &host):
		return newError(CodeTLSVerify, "certificate is not valid for the SNI")
	case errors.As(err, &inv):
		return newError(CodeTLSVerify, "certificate is invalid ("+message(inv)+")")
	case errors.As(err, &verr):
		return newError(CodeTLSVerify, message(err))
	case errors.As(err, &alrt), errors.As(err, &rec):
		return newError(CodeTLSHandshake, message(err))
	}
	if e := classify(ctx, err); e.Code != CodeNetwork {
		return e
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return newError(CodeTLSHandshake, "connection closed during the handshake")
	}
	return newError(CodeTLSHandshake, message(err))
}

// classifyRead maps an error while reading the answer.
func classifyRead(ctx context.Context, err error) *Error {
	if e := classify(ctx, err); e.Code != CodeNetwork {
		return e
	}
	return newError(CodeHTTP, message(err))
}
