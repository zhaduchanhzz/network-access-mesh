package idp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
)

// Path prefixes of the platform route.
var (
	// PlatformOIDCPaths are the public OIDC endpoints of the platform-hosted IdP (discovery, JWKS, token, userinfo):
	// all a Relying Party (internal/identity) needs.
	PlatformOIDCPaths = []string{"/realms/"}
	// PlatformDriverPaths add the Admin REST API the keycloak driver uses (never the admin console).
	PlatformDriverPaths = []string{"/realms/", "/admin/realms"}
)

// PlatformRouteConfig configures the narrow path to the platform-hosted IdP.
type PlatformRouteConfig struct {
	// Host is the host name of the platform-hosted IdP: "auth." + MG_BASE_DOMAIN (§15.4). The only host the route
	// serves; TLS is verified for it.
	Host string
	// Address is the host:port actually dialled for Host — e.g. the edge's static address on mg-edge
	// (MG_IDP_PLATFORM_ADDR). Empty: Host:443 through the system resolver, which inside the api/worker containers
	// answers with the edge alias auth.<domain> on mg-edge (§14.3).
	Address string
	// Paths are the path prefixes the route accepts (PlatformDriverPaths when nil).
	Paths []string
	// RootCAs verifies the IdP certificate (nil = system roots: the public ACME certificate of the edge).
	RootCAs *x509.CertPool
	Timeout time.Duration // DefaultTimeout when 0
	MaxBody int64         // DefaultMaxBody when 0
	// Dial connects to Address (tests only; default net.Dialer).
	Dial DialFunc
}

// PlatformRoute is the explicit, narrow path from api/worker to the IdP the platform hosts itself (driver=keycloak).
// In staging auth.<domain> resolves to a private LAN address and, inside Docker, to the edge alias on mg-edge — both
// refused by the Hardened client by design. The route accepts exactly one host (Host, https, port 443), only the
// configured path prefixes (clean paths, no encoded separators), dials only the configured address and verifies TLS
// for Host. Tenant-supplied (driver=external) URLs never use it: the external driver only holds a *Hardened, the
// keycloak driver only a *PlatformRoute, and the Hardened client refuses every name under the platform's domain.
type PlatformRoute struct {
	host      string
	address   string
	paths     []string
	timeout   time.Duration
	transport http.RoundTripper
	client    *http.Client
}

// NewPlatformRoute builds the route.
func NewPlatformRoute(cfg PlatformRouteConfig) (*PlatformRoute, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Host)), ".")
	if !hostRE.MatchString(host) || numericTLD(host) {
		return nil, errors.New("idp: PlatformRouteConfig.Host must be a DNS host name (auth.<domain>)")
	}
	addr := strings.TrimSpace(cfg.Address)
	if addr == "" {
		addr = net.JoinHostPort(host, "443")
	}
	if h, p, err := net.SplitHostPort(addr); err != nil || h == "" || p == "" {
		return nil, errors.New("idp: PlatformRouteConfig.Address must be host:port")
	}
	r := &PlatformRoute{host: host, address: addr, paths: cfg.Paths, timeout: cfg.Timeout}
	if r.paths == nil {
		r.paths = PlatformDriverPaths
	}
	for _, p := range r.paths {
		if !strings.HasPrefix(p, "/") {
			return nil, errors.New("idp: platform route paths must start with /")
		}
	}
	if r.timeout <= 0 {
		r.timeout = DefaultTimeout
	}
	maxBody := cfg.MaxBody
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	base := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, r.address) // whatever the URL says, only the configured address
		},
		TLSClientConfig:        &tls.Config{RootCAs: cfg.RootCAs, ServerName: host, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    tlsTimeout,
		ResponseHeaderTimeout:  r.timeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    4,
		MaxResponseHeaderBytes: maxResponseHeaders,
	}
	r.transport = &guardTransport{check: func(req *http.Request) error { return r.checkRequest(req, r.paths) },
		next: base, maxBody: maxBody}
	r.client = &http.Client{Transport: r.transport, CheckRedirect: refuseRedirect, Timeout: r.timeout}
	return r, nil
}

// Client returns the route's *http.Client.
func (r *PlatformRoute) Client() *http.Client { return r.client }

// Host returns the platform IdP host name.
func (r *PlatformRoute) Host() string { return r.host }

// BaseURL returns https://<host> — the base of every issuer of the platform-hosted IdP (issuer = BaseURL +
// "/realms/<realm>").
func (r *PlatformRoute) BaseURL() string { return "https://" + r.host }

// checkRequest: https, the configured host, port 443, an allowed clean path.
func (r *PlatformRoute) checkRequest(req *http.Request, paths []string) error {
	if err := checkStaticURL(req.URL); err != nil {
		return err
	}
	if !strings.EqualFold(req.URL.Hostname(), r.host) {
		return refused("platform_host")
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return refused("host_header")
	}
	if !allowedPath(req.URL.EscapedPath(), paths) {
		return refused("platform_path")
	}
	return nil
}

// allowedPath accepts a path equal to a prefix (without its trailing slash) or below it, that is already clean (no "."
// or ".." segment, no empty segment) and has no encoded separator, encoded dot, backslash or ";" — the edge or the IdP
// could otherwise normalise /realms/../admin/… or /realms/%2e%2e/admin/… into a path the route does not allow.
func allowedPath(escaped string, prefixes []string) bool {
	low := strings.ToLower(escaped)
	if !strings.HasPrefix(escaped, "/") || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") ||
		strings.Contains(low, "%2e") || strings.ContainsAny(escaped, "\\;") || strings.Contains(escaped, "//") {
		return false
	}
	for _, seg := range strings.Split(escaped[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	if path.Clean(escaped) != strings.TrimSuffix(escaped, "/") && escaped != "/" {
		return false
	}
	for _, p := range prefixes {
		base := strings.TrimSuffix(p, "/")
		if escaped == base || strings.HasPrefix(escaped, base+"/") {
			return true
		}
	}
	return false
}

// NewIssuerClient returns the single client a Relying Party that serves every IdP (internal/identity:
// identity.Config.HTTPClient) uses: requests for the platform IdP host go through the platform route restricted to
// the public OIDC endpoints (PlatformOIDCPaths), every other request through the hardened client. platform may be nil
// (no platform-hosted IdP). Redirects are refused and every request is checked by the transport it is routed to.
func NewIssuerClient(h *Hardened, platform *PlatformRoute) *http.Client {
	rt := &issuerRouter{hardened: h.transport, platform: platform}
	timeout := h.timeout
	if platform != nil && platform.timeout > timeout {
		timeout = platform.timeout
	}
	return &http.Client{Transport: rt, CheckRedirect: refuseRedirect, Timeout: timeout}
}

type issuerRouter struct {
	hardened http.RoundTripper
	platform *PlatformRoute
}

func (t *issuerRouter) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.platform != nil && r.URL != nil && strings.EqualFold(r.URL.Hostname(), t.platform.host) {
		if !allowedPath(r.URL.EscapedPath(), PlatformOIDCPaths) {
			if r.Body != nil {
				_ = r.Body.Close()
			}
			return nil, refused("platform_path")
		}
		return t.platform.transport.RoundTrip(r)
	}
	return t.hardened.RoundTrip(r)
}

// CloseIdleConnections forwards http.Client.CloseIdleConnections to both transports.
func (t *issuerRouter) CloseIdleConnections() {
	closeIdle(t.hardened)
	if t.platform != nil {
		closeIdle(t.platform.transport)
	}
}
