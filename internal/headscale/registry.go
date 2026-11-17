package headscale

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Target is where and how the adapter reaches the Headscale instance of one tenant. It is produced only by a
// Locator from the platform's own records (tenant_instances + SecretStore + platform configuration) — never from
// request input (§13.4 rule 1).
type Target struct {
	InstanceID uuid.UUID     // tenant_instances.id: keys the circuit breaker and appears in logs
	Slug       string        // tenant slug: X-MG-Instance; the edge routes it to hs-<slug>:8080
	AdminURL   string        // base URL of the edge admin listener, e.g. http://10.249.2.2:8081 (no path)
	APIKey     Secret        // the instance API key (Authorization: Bearer)
	EdgeToken  Secret        // the admin listener's own token (X-MG-Token, 40 characters [A-Za-z0-9])
	Timeout    time.Duration // per-call timeout for this instance; 0 = Options.Timeout
}

// Locator resolves a tenant to its instance. The production implementation (P2-T11) reads tenant_instances and
// the SecretStore; it must return an error wrapping ErrNoInstance when the tenant has no running instance.
// Locate is called on a cache miss, after Options.CacheTTL, and again (bypassing the cache) when the edge or the
// instance rejects the credentials, so a rotated API key is picked up without a restart.
type Locator interface {
	Locate(ctx context.Context, tenantID uuid.UUID) (Target, error)
}

// ErrNoInstance is returned (wrapped) by a Locator when the tenant has no instance that can be called.
var ErrNoInstance = errors.New("headscale: tenant has no running instance")

// StaticLocator is a fixed tenant → target table, for tests and local development.
type StaticLocator map[uuid.UUID]Target

// Locate implements Locator.
func (s StaticLocator) Locate(_ context.Context, tenantID uuid.UUID) (Target, error) {
	t, ok := s[tenantID]
	if !ok {
		return Target{}, fmt.Errorf("tenant %s: %w", tenantID, ErrNoInstance)
	}
	return t, nil
}

// Options configures a CachingRegistry. Zero values select the defaults.
type Options struct {
	Timeout    time.Duration // per HTTP attempt (default 10s); Target.Timeout overrides it per instance
	CacheTTL   time.Duration // lifetime of a located target and its checked version (default 60s)
	Breaker    BreakerConfig
	Retry      RetryPolicy
	HTTPClient *http.Client // default: no proxy from the environment, no redirects
	Logger     *slog.Logger // default: discard; build it with logx.New so attributes are redacted
	Now        func() time.Time
}

// CachingRegistry implements Registry over a Locator with a short-lived cache, a circuit breaker per instance and a
// version check before an implementation is chosen.
type CachingRegistry struct {
	loc     Locator
	timeout time.Duration
	ttl     time.Duration
	brCfg   BreakerConfig
	retry   RetryPolicy
	client  *http.Client
	log     *slog.Logger
	now     func() time.Time
	sleep   func(context.Context, time.Duration) bool
	jitter  func(int64) int64

	mu       sync.Mutex
	entries  map[uuid.UUID]*entry
	breakers map[uuid.UUID]*Breaker
}

type entry struct {
	target  Target
	base    string
	impl    apiImpl
	version Version
	at      time.Time
}

// NewRegistry returns a registry backed by loc.
func NewRegistry(loc Locator, o Options) *CachingRegistry {
	r := &CachingRegistry{
		loc: loc, timeout: o.Timeout, ttl: o.CacheTTL, brCfg: o.Breaker.withDefaults(), retry: o.Retry.withDefaults(),
		client: o.HTTPClient, log: o.Logger, now: o.Now, sleep: sleepCtx, jitter: defaultJitter,
		entries: map[uuid.UUID]*entry{}, breakers: map[uuid.UUID]*Breaker{},
	}
	if r.timeout <= 0 {
		r.timeout = 10 * time.Second
	}
	if r.ttl <= 0 {
		r.ttl = time.Minute
	}
	if r.client == nil {
		r.client = DefaultHTTPClient()
	}
	if r.log == nil {
		r.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r
}

// DefaultHTTPClient never takes a proxy from the environment (credentials must only go to the edge) and never
// follows a redirect (X-MG-Token is a custom header that Go would forward to another host).
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// OpForTenant labels errors raised while resolving a tenant.
const OpForTenant Op = "ForTenant"

// ForTenant returns the Instance of a tenant: the only way to obtain one (§13.4).
func (r *CachingRegistry) ForTenant(ctx context.Context, tenantID uuid.UUID) (Instance, error) {
	if tenantID == uuid.Nil {
		return nil, localError(OpForTenant, KindInternal, "nil tenant id")
	}
	r.mu.Lock()
	e := r.entries[tenantID]
	if e != nil && r.now().Sub(e.at) >= r.ttl {
		e = nil
	}
	r.mu.Unlock()
	if e != nil {
		return e.impl.construct(r.newConn(tenantID, e.target, e.base)), nil
	}

	target, base, err := r.locate(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	c := r.newConn(tenantID, target, base)
	raw, err := c.version(ctx)
	if err != nil {
		return nil, err
	}
	v, err := ParseVersion(raw)
	if err != nil {
		return nil, localError(OpVersion, KindUnsupportedVersion, err.Error())
	}
	impl, ok := implFor(v)
	if !ok {
		return nil, localError(OpVersion, KindUnsupportedVersion,
			fmt.Sprintf("instance reports %s; supported: %s", v.Raw, SupportedVersions()))
	}
	r.mu.Lock()
	r.entries[tenantID] = &entry{target: target, base: base, impl: impl, version: v, at: r.now()}
	r.mu.Unlock()
	return impl.construct(c), nil
}

// Invalidate drops the cached target of a tenant (after an upgrade, a restore or a key rotation).
func (r *CachingRegistry) Invalidate(tenantID uuid.UUID) {
	r.mu.Lock()
	delete(r.entries, tenantID)
	r.mu.Unlock()
}

// CachedVersion returns the version checked for a tenant's instance while its cache entry is fresh.
func (r *CachingRegistry) CachedVersion(tenantID uuid.UUID) (Version, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entries[tenantID]
	if e == nil || r.now().Sub(e.at) >= r.ttl {
		return Version{}, false
	}
	return e.version, true
}

// BreakerState returns the breaker state of an instance (closed when the instance was never called).
func (r *CachingRegistry) BreakerState(instanceID uuid.UUID) BreakerState {
	r.mu.Lock()
	b := r.breakers[instanceID]
	r.mu.Unlock()
	if b == nil {
		return BreakerClosed
	}
	return b.State()
}

func (r *CachingRegistry) newConn(tenantID uuid.UUID, t Target, base string) *conn {
	return &conn{reg: r, tenantID: tenantID, breaker: r.breakerFor(t.InstanceID), target: t, base: base}
}

func (r *CachingRegistry) breakerFor(instanceID uuid.UUID) *Breaker {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.breakers[instanceID]
	if b == nil {
		b = NewBreaker(r.brCfg, r.now)
		r.breakers[instanceID] = b
	}
	return b
}

func (r *CachingRegistry) locate(ctx context.Context, tenantID uuid.UUID) (Target, string, error) {
	t, err := r.loc.Locate(ctx, tenantID)
	if err != nil {
		kind := KindInternal
		if errors.Is(err, ErrNoInstance) {
			kind = KindUnavailable
		}
		return Target{}, "", &Error{Op: OpForTenant, Kind: kind, Code: -1, Err: err}
	}
	base, err := validateTarget(t)
	if err != nil {
		return Target{}, "", localError(OpForTenant, KindInternal, "invalid target from locator: "+err.Error())
	}
	return t, base, nil
}

// reload locates the tenant again, bypassing the cache, and refreshes the cached target (the checked version is
// kept: the instance is the same).
func (r *CachingRegistry) reload(ctx context.Context, tenantID uuid.UUID) (Target, string, error) {
	t, base, err := r.locate(ctx, tenantID)
	if err != nil {
		return Target{}, "", err
	}
	r.mu.Lock()
	if e := r.entries[tenantID]; e != nil && e.target.InstanceID == t.InstanceID && e.base == base {
		e.target = t
	} else {
		delete(r.entries, tenantID)
	}
	r.mu.Unlock()
	return t, base, nil
}

// validateTarget checks a located target and returns the normalised base URL (scheme://host[:port]).
func validateTarget(t Target) (string, error) {
	if t.InstanceID == uuid.Nil {
		return "", errors.New("instance id is nil")
	}
	if !slugPattern.MatchString(t.Slug) {
		return "", errors.New("slug does not match the slug rule (§14.5)")
	}
	if t.APIKey.IsZero() {
		return "", errors.New("API key is empty")
	}
	if !edgeTokenPattern.MatchString(t.EdgeToken.Reveal()) {
		return "", errors.New("edge token must be 40 characters [A-Za-z0-9] (§14.6)")
	}
	u, err := url.Parse(t.AdminURL)
	if err != nil {
		return "", errors.New("admin URL does not parse")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("admin URL must be http(s)://host[:port] without path, query or user info")
	}
	return u.Scheme + "://" + u.Host, nil
}
