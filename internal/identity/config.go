package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// Defaults from §8.3 (steps 2, 6, 7) and §6.4.
const (
	DefaultAuthRequestTTL = 10 * time.Minute // auth_requests.expires_at ≤ created_at + 10 min (CHECK of 0002)
	DefaultStepUpWindow   = 15 * time.Minute
	DefaultProviderTTL    = time.Hour        // discovery document cache per IdP
	DefaultTouchInterval  = 30 * time.Second // minimum gap between two last_seen_at writes of one session
	DefaultClockSkew      = 2 * time.Minute  // tolerated skew for iat/auth_time against the IdP clock
)

// Timeouts are the idle and absolute lifetimes of a session.
type Timeouts struct {
	Idle     time.Duration
	Absolute time.Duration
}

// Session timeouts of §8.3 step 6.
var (
	DefaultTenantTimeouts   = Timeouts{Idle: 30 * time.Minute, Absolute: 12 * time.Hour}
	DefaultPlatformTimeouts = Timeouts{Idle: 15 * time.Minute, Absolute: 8 * time.Hour}
)

// ClientSecretSource resolves identity_providers.client_secret_ref (mgsec://<tenant_id|platform>/<name>#<version>)
// to the OIDC client secret. Production: the SecretStore (P2-T04). The value is used for the token request only and
// is never logged.
type ClientSecretSource interface {
	ClientSecret(ctx context.Context, ref string) (string, error)
}

// ClientSecretFunc adapts a function to ClientSecretSource.
type ClientSecretFunc func(ctx context.Context, ref string) (string, error)

// ClientSecret implements ClientSecretSource.
func (f ClientSecretFunc) ClientSecret(ctx context.Context, ref string) (string, error) {
	return f(ctx, ref)
}

// Config configures the Service. AppHost, AdminHost and HTTPClient are required.
type Config struct {
	// AppHost and AdminHost are the public host names of the Tenant Portal and the Platform Console, e.g.
	// "app."+MG_BASE_DOMAIN and "admin."+MG_BASE_DOMAIN (never hard-coded). The middleware maps the request Host to
	// an origin; the redirect URI of an IdP is https://<host of its origin>/api/v1/auth/callback/<idpId>.
	AppHost, AdminHost string

	// HTTPClient makes every call to an IdP (discovery, JWKS, token). Production: the SSRF-hardened client of
	// internal/idp (P2-T05a, T-21: https/443 only, resolve once, internal ranges refused). The module adds its own
	// limits on top: no redirects, 1 MiB per response, a 10 s timeout when the client has none.
	HTTPClient *http.Client

	// ClientSecrets resolves client_secret_ref; required as soon as one IdP has a client secret.
	ClientSecrets ClientSecretSource

	// Auditor receives the audit events of the module (P2-T08 wires audit_events); nil logs them.
	Auditor Auditor

	// Logger; nil uses slog.Default().
	Logger *slog.Logger

	// Now is the clock; nil uses time.Now.
	Now func() time.Time

	// ClientIP returns the client address of a request (sessions.ip). Behind the edge this must be the trusted
	// X-Forwarded-For handling of the HTTP chain (P2-T14); nil uses the host of RemoteAddr.
	ClientIP func(*http.Request) string

	// RequestID returns the request id copied into problems and audit events; nil reads the X-Request-Id header
	// (the request-id middleware runs first and sets it on the request).
	RequestID func(*http.Request) string

	// Zero values take the defaults above.
	TenantTimeouts   Timeouts
	PlatformTimeouts Timeouts
	StepUpWindow     time.Duration
	AuthRequestTTL   time.Duration
	ProviderTTL      time.Duration
	TouchInterval    time.Duration
	ClockSkew        time.Duration
}

var hostRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Service is the identity module: OIDC login, sessions, CSRF, step-up, session middleware.
type Service struct {
	store     *store.Store
	cfg       Config
	hosts     hosts
	log       *slog.Logger
	audit     Auditor
	now       func() time.Time
	providers *providerCache
}

// New validates cfg and returns the Service. st is the api process store (tenant pool mg_api_tenant, platform pool
// mg_api_platform): sessions and auth_requests are only granted to the platform role.
func New(st *store.Store, cfg Config) (*Service, error) {
	var errs []error
	if st == nil {
		errs = append(errs, errors.New("a store is required"))
	}
	app, admin := normalizeHost(cfg.AppHost), normalizeHost(cfg.AdminHost)
	if !hostRE.MatchString(app) || !hostRE.MatchString(admin) || net.ParseIP(app) != nil || net.ParseIP(admin) != nil {
		errs = append(errs, fmt.Errorf("AppHost and AdminHost must be DNS host names (got %q, %q)", cfg.AppHost, cfg.AdminHost))
	} else if app == admin {
		errs = append(errs, errors.New("AppHost and AdminHost must differ (two origins, §8.3)"))
	}
	if cfg.HTTPClient == nil {
		errs = append(errs, errors.New("HTTPClient is required (the hardened IdP client)"))
	}
	setDefault(&cfg.TenantTimeouts.Idle, DefaultTenantTimeouts.Idle)
	setDefault(&cfg.TenantTimeouts.Absolute, DefaultTenantTimeouts.Absolute)
	setDefault(&cfg.PlatformTimeouts.Idle, DefaultPlatformTimeouts.Idle)
	setDefault(&cfg.PlatformTimeouts.Absolute, DefaultPlatformTimeouts.Absolute)
	setDefault(&cfg.StepUpWindow, DefaultStepUpWindow)
	setDefault(&cfg.AuthRequestTTL, DefaultAuthRequestTTL)
	setDefault(&cfg.ProviderTTL, DefaultProviderTTL)
	setDefault(&cfg.TouchInterval, DefaultTouchInterval)
	setDefault(&cfg.ClockSkew, DefaultClockSkew)
	if cfg.AuthRequestTTL > DefaultAuthRequestTTL {
		errs = append(errs, errors.New("AuthRequestTTL must not exceed 10 minutes (§8.3 step 2)"))
	}
	for _, t := range []Timeouts{cfg.TenantTimeouts, cfg.PlatformTimeouts} {
		if t.Idle > t.Absolute {
			errs = append(errs, errors.New("an idle timeout must not exceed the absolute timeout"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("identity: invalid configuration: %w", err)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = remoteAddrIP
	}
	if cfg.RequestID == nil {
		cfg.RequestID = func(r *http.Request) string { return r.Header.Get("X-Request-Id") }
	}
	s := &Service{
		store: st, cfg: cfg, hosts: hosts{app: app, admin: admin},
		log: cfg.Logger.With("module", "identity"), now: cfg.Now,
	}
	s.audit = cfg.Auditor
	if s.audit == nil {
		s.audit = logAuditor{log: s.log}
	}
	s.providers = newProviderCache(limitClient(cfg.HTTPClient), cfg.ProviderTTL, cfg.Now)
	return s, nil
}

func setDefault(d *time.Duration, def time.Duration) {
	if *d <= 0 {
		*d = def
	}
}

// timeouts returns the session timeouts of an identity scope.
func (s *Service) timeouts(sc Scope) Timeouts {
	if sc == ScopePlatform {
		return s.cfg.PlatformTimeouts
	}
	return s.cfg.TenantTimeouts
}

// maxAge is the max_age sent with a normal login: the absolute session lifetime of the scope. The IdP must then
// re-authenticate when its own session is older, and must return auth_time (OIDC Core §3.1.2.1).
func (s *Service) maxAge(sc Scope) time.Duration { return s.timeouts(sc).Absolute }

// redirectURI is the callback registered at the IdP: one per IdP (§8.3 step 3).
func (s *Service) redirectURI(sc Scope, idpID fmt.Stringer) string {
	return s.hosts.baseURL(originForScope(sc)) + "/api/v1/auth/callback/" + idpID.String()
}

// remoteAddrIP is the default ClientIP: the host part of RemoteAddr.
func remoteAddrIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}
