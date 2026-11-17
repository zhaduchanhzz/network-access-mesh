package idp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Defaults of the clients of this module.
const (
	DefaultTimeout     = 10 * time.Second // one request, body included
	DefaultMaxBody     = 1 << 20          // bytes of one response body
	dialTimeout        = 5 * time.Second
	resolveTimeout     = 5 * time.Second
	tlsTimeout         = 5 * time.Second
	maxResponseHeaders = 32 << 10
)

// Resolver resolves a host name to IP addresses; *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc dials a network address; in the hardened client it always receives an IP literal that passed the policy.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// HardenedConfig configures the client for every URL a tenant can influence (issuer, jwks_uri, token and userinfo
// endpoints of driver=external — T-21).
type HardenedConfig struct {
	// Deny lists the destinations refused on top of the built-in special-purpose ranges (MG_EGRESS_DENY_CIDRS): every
	// Docker address pool of the platform, the LAN, the tunnel, the public entry of the environment.
	Deny []netip.Prefix
	// DenyDomains are DNS names refused with all their subdomains: the platform's base domain (MG_BASE_DOMAIN), so
	// that no tenant-supplied URL reaches a platform name (auth., app., admin., *.mesh.) through this client — the
	// platform-hosted IdP has its own narrow path (PlatformRoute).
	DenyDomains []string
	// RootCAs verifies server certificates; nil = system roots.
	RootCAs *x509.CertPool
	// Timeout bounds one request including its body (DefaultTimeout when 0); MaxBody bounds one response body
	// (DefaultMaxBody when 0).
	Timeout time.Duration
	MaxBody int64
	// Resolver resolves host names once per connection (net.DefaultResolver when nil).
	Resolver Resolver
	// Dial connects to the checked ip:443 (tests only; default: net.Dialer whose socket guard re-checks the address).
	Dial DialFunc
}

// Hardened is the SSRF-hardened HTTP client of §8.2 / T-21:
//
//   - https on port 443 only; no user info in the URL; host names only (an IP literal is refused: an OIDC issuer has a
//     DNS name and a certificate for it); names under DenyDomains refused;
//   - no redirect is followed (CheckRedirect refuses every redirect, and the transport re-checks scheme, port and host
//     of every request it sends, so even a copy of the client with another CheckRedirect cannot leave the policy);
//   - the host is resolved ONCE per connection, every resolved address must pass the EgressPolicy (one refused
//     address refuses the whole answer), and the connection is made to exactly that checked IP while TLS verifies the
//     certificate against the original host name — a DNS-rebinding answer between check and connect has nowhere to
//     go; the socket guard of the dialer checks the address again right before connect(2);
//   - environment proxies are ignored (a proxy would resolve the name itself);
//   - response size and time are bounded; errors are *Error values without upstream content.
type Hardened struct {
	policy      *EgressPolicy
	denyDomains []string
	resolver    Resolver
	dial        DialFunc
	maxBody     int64
	timeout     time.Duration
	transport   http.RoundTripper
	client      *http.Client
}

// NewHardened builds the hardened client.
func NewHardened(cfg HardenedConfig) (*Hardened, error) {
	pol, err := NewEgressPolicy(cfg.Deny)
	if err != nil {
		return nil, err
	}
	h := &Hardened{policy: pol, resolver: cfg.Resolver, dial: cfg.Dial, maxBody: cfg.MaxBody, timeout: cfg.Timeout}
	for _, d := range cfg.DenyDomains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if !hostRE.MatchString(d) {
			return nil, errors.New("idp: DenyDomains holds an invalid domain")
		}
		h.denyDomains = append(h.denyDomains, d)
	}
	if h.resolver == nil {
		h.resolver = net.DefaultResolver
	}
	if h.maxBody <= 0 {
		h.maxBody = DefaultMaxBody
	}
	if h.timeout <= 0 {
		h.timeout = DefaultTimeout
	}
	if h.dial == nil {
		d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second, Control: h.socketGuard}
		h.dial = d.DialContext
	}
	base := &http.Transport{
		Proxy:                  nil, // never HTTP(S)_PROXY: a proxy would resolve and connect on its own
		DialContext:            h.dialChecked,
		TLSClientConfig:        &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    tlsTimeout,
		ResponseHeaderTimeout:  h.timeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    2,
		MaxResponseHeaderBytes: maxResponseHeaders,
	}
	h.transport = &guardTransport{check: h.checkRequest, next: base, maxBody: h.maxBody}
	h.client = &http.Client{Transport: h.transport, CheckRedirect: refuseRedirect, Timeout: h.timeout}
	return h, nil
}

// Client returns the hardened *http.Client.
func (h *Hardened) Client() *http.Client { return h.client }

// Policy returns the address policy of the client.
func (h *Hardened) Policy() *EgressPolicy { return h.policy }

// CheckURL applies the static rules of the client to u (scheme, port, user info, host syntax, denied domains)
// without any network access.
func (h *Hardened) CheckURL(u *url.URL) error {
	if err := checkStaticURL(u); err != nil {
		return err
	}
	host := strings.ToLower(u.Hostname())
	if _, err := netip.ParseAddr(host); err == nil {
		return refused("host_ip_literal")
	}
	if !hostRE.MatchString(host) || numericTLD(host) {
		return refused("host_invalid")
	}
	for _, d := range h.denyDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return refused("host_platform_domain")
		}
	}
	return nil
}

// CheckDestination applies CheckURL and then resolves the host once and checks every address — for endpoints the
// backend will call later (token, userinfo) and that are not fetched now.
func (h *Hardened) CheckDestination(ctx context.Context, u *url.URL) error {
	if err := h.CheckURL(u); err != nil {
		return err
	}
	_, err := h.resolveChecked(ctx, strings.ToLower(u.Hostname()))
	return err
}

func (h *Hardened) checkRequest(r *http.Request) error {
	if err := h.CheckURL(r.URL); err != nil {
		return err
	}
	if r.Host != "" && !strings.EqualFold(r.Host, r.URL.Host) {
		return refused("host_header")
	}
	return nil
}

// resolveChecked resolves host once and checks every address against the policy.
func (h *Hardened) resolveChecked(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := h.policy.Check(ip); err != nil {
			return nil, err
		}
		return []netip.Addr{ip}, nil
	}
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	ips, err := h.resolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable, Op: "egress", Reason: "dns", err: err}
	}
	if len(ips) == 0 {
		return nil, &Error{Code: CodeUnavailable, Op: "egress", Reason: "dns_no_address"}
	}
	for _, ip := range ips {
		if err := h.policy.Check(ip); err != nil {
			return nil, err // one refused address refuses the whole answer (no mixed public/internal answers)
		}
	}
	return ips, nil
}

// dialChecked is the DialContext of the transport: resolve once, check, connect to the checked IP.
func (h *Hardened) dialChecked(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, refused("network")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "443" {
		return nil, refused("port")
	}
	ips, err := h.resolveChecked(ctx, strings.ToLower(host))
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		conn, err := h.dial(ctx, "tcp", netip.AddrPortFrom(ip.Unmap(), 443).String())
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

// socketGuard runs right before connect(2) on every socket of the default dialer: the address must still pass the
// policy and be port 443 (defence in depth — the dial target is already a checked IP literal).
func (h *Hardened) socketGuard(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return refused("address_unparsable")
	}
	if ap.Port() != 443 {
		return refused("port")
	}
	return h.policy.Check(ap.Addr())
}

// SocketGuard exposes the socket guard (tests).
func (h *Hardened) SocketGuard(address string) error { return h.socketGuard("tcp", address, nil) }

func refused(reason string) *Error {
	return &Error{Code: CodeDestinationRefused, Op: "egress", Reason: reason}
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return &Error{Code: CodeRedirectRefused, Op: "egress", Reason: "redirect"}
}

var (
	hostLabel = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`
	// hostRE: lower-case LDH name of at least two labels, no trailing dot.
	hostRE = regexp.MustCompile(`^(` + hostLabel + `\.)+` + hostLabel + `$`)
)

// numericTLD reports a name whose last label is all digits (no TLD is): "1.2.3.4.5", "0x7f.1" — forms some resolvers
// read as an IPv4 address.
func numericTLD(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	for _, c := range last {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// checkStaticURL: https, port 443 or none, no user info, no fragment, non-empty host.
func checkStaticURL(u *url.URL) error {
	switch {
	case u == nil:
		return refused("url_missing")
	case u.Scheme != "https":
		return refused("scheme")
	case u.User != nil:
		return refused("userinfo")
	case u.Port() != "" && u.Port() != "443":
		return refused("port")
	case u.Hostname() == "":
		return refused("host_missing")
	case u.Fragment != "" || u.RawFragment != "":
		return refused("fragment")
	case u.Opaque != "":
		return refused("opaque")
	}
	return nil
}

// guardTransport checks every request before sending it and bounds every response body.
type guardTransport struct {
	check   func(*http.Request) error
	next    http.RoundTripper
	maxBody int64
}

func (t *guardTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.check(r); err != nil {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, err
	}
	resp, err := t.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > t.maxBody {
		_ = resp.Body.Close()
		return nil, &Error{Code: CodeResponseTooLarge, Op: "egress", Reason: "content_length"}
	}
	resp.Body = &limitedBody{rc: resp.Body, left: t.maxBody}
	return resp, nil
}

// CloseIdleConnections forwards http.Client.CloseIdleConnections to the pooled transport.
func (t *guardTransport) CloseIdleConnections() { closeIdle(t.next) }

func closeIdle(rt http.RoundTripper) {
	if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// limitedBody fails a read that goes past the limit instead of truncating silently.
type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var one [1]byte
		n, err := b.rc.Read(one[:])
		if n > 0 {
			return 0, &Error{Code: CodeResponseTooLarge, Op: "egress", Reason: "body"}
		}
		if err == nil {
			err = io.EOF
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }
