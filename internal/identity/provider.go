package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

const (
	// maxIdPResponse bounds every body read from an IdP (discovery, JWKS, token).
	maxIdPResponse = 1 << 20
	// idpTimeout bounds one call to an IdP when the configured client has no timeout.
	idpTimeout = 10 * time.Second
)

// IdP statuses (identity_providers.status). A login starts only with an active IdP; a retiring IdP still completes
// logins and keeps its sessions (migration window, §8.2); pending and disabled IdPs do neither.
const (
	idpActive   = "active"
	idpRetiring = "retiring"
)

func idpUsable(status string) bool { return status == idpActive || status == idpRetiring }

// idp is the part of an identity_providers row the login flow uses. An IdP registration is the triple (issuer,
// client_id, organisation constraint) — §8.2 shared-issuer rule.
type idp struct {
	ID                   uuid.UUID
	Scope                Scope
	TenantID             *uuid.UUID
	Issuer               string
	ClientID             string
	ClientSecretRef      *string
	RequiredClaims       map[string]any
	RequireEmailVerified bool
	AllowedEmailDomains  []string
	ClaimMapping         map[string]string
	Status               string
}

func idpFromRow(r sqlcdb.IdentityProvider) (*idp, error) {
	p := &idp{
		ID: r.ID, Scope: Scope(r.Scope), TenantID: r.TenantID, Issuer: r.Issuer, ClientID: r.ClientID,
		ClientSecretRef: r.ClientSecretRef, RequireEmailVerified: r.RequireEmailVerified, Status: r.Status,
	}
	for _, d := range r.AllowedEmailDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			p.AllowedEmailDomains = append(p.AllowedEmailDomains, d)
		}
	}
	if len(r.RequiredClaims) > 0 {
		if err := json.Unmarshal(r.RequiredClaims, &p.RequiredClaims); err != nil {
			return nil, newErr(KindInternal, "idp_required_claims_invalid", err)
		}
	}
	if len(r.ClaimMapping) > 0 {
		var m map[string]any
		if err := json.Unmarshal(r.ClaimMapping, &m); err != nil {
			return nil, newErr(KindInternal, "idp_claim_mapping_invalid", err)
		}
		p.ClaimMapping = map[string]string{}
		for k, v := range m {
			s, ok := v.(string)
			if !ok || s == "" {
				return nil, newErr(KindInternal, "idp_claim_mapping_invalid", errors.New("claim_mapping values must be claim names"))
			}
			p.ClaimMapping[k] = s
		}
	}
	if p.Scope != ScopePlatform && p.Scope != ScopeTenant {
		return nil, newErr(KindInternal, "idp_scope_invalid", nil)
	}
	return p, nil
}

// discoveryMeta holds the discovery fields that go-oidc does not expose.
type discoveryMeta struct {
	IssParameterSupported    bool     `json:"authorization_response_iss_parameter_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
}

// providerEntry is one discovered IdP.
type providerEntry struct {
	issuer  string
	op      *oidc.Provider
	meta    discoveryMeta
	fetched time.Time
}

// providerCache keeps one discovered provider per IdP row (two IdPs may share an issuer but never a client).
type providerCache struct {
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	entries map[uuid.UUID]*providerEntry
}

func newProviderCache(client *http.Client, ttl time.Duration, now func() time.Time) *providerCache {
	return &providerCache{client: client, ttl: ttl, now: now, entries: map[uuid.UUID]*providerEntry{}}
}

// get returns the discovered provider of p, refreshing it after the TTL. go-oidc checks that the issuer of the
// discovery document is exactly the stored issuer (an IdP cannot announce another issuer).
func (c *providerCache) get(ctx context.Context, p *idp) (*providerEntry, error) {
	c.mu.Lock()
	e := c.entries[p.ID]
	c.mu.Unlock()
	if e != nil && e.issuer == p.Issuer && c.now().Sub(e.fetched) < c.ttl {
		return e, nil
	}
	dctx, cancel := context.WithTimeout(ctx, idpTimeout)
	defer cancel()
	op, err := oidc.NewProvider(oidc.ClientContext(dctx, c.client), p.Issuer)
	if err != nil {
		return nil, newErr(KindUpstream, "discovery_failed", err)
	}
	var meta discoveryMeta
	if err := op.Claims(&meta); err != nil {
		return nil, newErr(KindUpstream, "discovery_invalid", err)
	}
	if len(meta.CodeChallengeMethods) > 0 && !slices.Contains(meta.CodeChallengeMethods, "S256") {
		return nil, newErr(KindUpstream, "pkce_s256_unsupported", nil)
	}
	e = &providerEntry{issuer: p.Issuer, op: op, meta: meta, fetched: c.now()}
	c.mu.Lock()
	c.entries[p.ID] = e
	c.mu.Unlock()
	return e, nil
}

// authStyle chooses how the client authenticates at the token endpoint from the advertised methods (RFC 8414:
// client_secret_basic when the list is absent). A public client (no secret) sends only client_id.
func authStyle(meta discoveryMeta, hasSecret bool) (oauth2.AuthStyle, error) {
	switch {
	case !hasSecret:
		return oauth2.AuthStyleInParams, nil
	case len(meta.TokenEndpointAuthMethods) == 0 || slices.Contains(meta.TokenEndpointAuthMethods, "client_secret_basic"):
		return oauth2.AuthStyleInHeader, nil
	case slices.Contains(meta.TokenEndpointAuthMethods, "client_secret_post"):
		return oauth2.AuthStyleInParams, nil
	}
	return 0, newErr(KindUpstream, "token_auth_method_unsupported", nil)
}

// oauthConfig is the OAuth 2.0 client of one IdP; secret is empty for a public client or when only building the
// authorization URL.
func (s *Service) oauthConfig(p *idp, e *providerEntry, secret string, style oauth2.AuthStyle) *oauth2.Config {
	ep := e.op.Endpoint()
	ep.AuthStyle = style
	return &oauth2.Config{
		ClientID: p.ClientID, ClientSecret: secret, Endpoint: ep,
		RedirectURL: s.redirectURI(p.Scope, p.ID),
		Scopes:      []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
	}
}

// limitClient copies the configured client and adds the module's own limits: no redirect is followed (§8.2 SSRF
// rule), every response body is capped and a timeout applies when the client has none.
func limitClient(c *http.Client) *http.Client {
	cp := *c
	base := cp.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cp.Transport = limitTransport{base: base, max: maxIdPResponse}
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if cp.Timeout == 0 {
		cp.Timeout = idpTimeout
	}
	return &cp
}

type limitTransport struct {
	base http.RoundTripper
	max  int64
}

func (t limitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{rc: resp.Body, left: t.max}
	return resp, nil
}

var errResponseTooLarge = errors.New("identity: IdP response exceeds the size limit")

type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var one [1]byte
		n, err := b.rc.Read(one[:])
		if n > 0 {
			return 0, errResponseTooLarge
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
