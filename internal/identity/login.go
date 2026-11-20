package identity

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// LoginRequest is the input of BeginLogin (GET /auth/login, §8.3 steps 1–2).
type LoginRequest struct {
	Scope      Scope  // tenant on the app origin, platform on the admin origin
	TenantSlug string // required for ScopeTenant: routes the login only (§13.1), never an API tenant context
	ReturnTo   string // relative Portal path to land on after the callback; "" = "/"
	Origin     Origin // origin of the request (from the middleware)
	// Current is the valid session already attached to the request on this origin, if any: logging in again is a
	// re-authentication (step-up, §8.3 step 7) and asks the IdP for prompt=login and max_age=0.
	Current *Session
	// Reauth asks for that re-authentication explicitly (reauth=true of GET /auth/login), with or without a session.
	Reauth bool
	// FetchSite is RequestInfo.FetchSite (Sec-Fetch-Site of the request): a login start is refused unless it is
	// same-origin (the Portal's own page), none (typed address, bookmark) or absent (G2 F1, see BeginLogin).
	FetchSite string
	// UILocales is the language of the Portal (ui_locales of GET /auth/login — G4b-E14): passed to the IdP as the OIDC
	// ui_locales parameter so that its pages speak the same language; only the languages of the Portal, "" = none.
	UILocales string
	ClientIP  string
	RequestID string
}

// uiLocales are the ui_locales values a login start passes on (the languages of the Portal and of the realms' i18n).
var uiLocales = map[string]bool{"vi": true, "en": true}

// LoginRedirect is the answer of BeginLogin: a 302 to Location setting Cookie (the browser binding).
type LoginRedirect struct {
	Location string
	Cookie   *http.Cookie
	IdPID    uuid.UUID
	StepUp   bool
}

var (
	slugRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	returnToRE = regexp.MustCompile(`^/([^/\\\s][^\s]*)?$`)
)

const maxReturnTo = 512

// Sec-Fetch-Site values a login start accepts (BeginLogin): a request of the Portal's own pages, and a navigation the
// user started (address bar, bookmark).
const (
	fetchSiteSameOrigin = "same-origin"
	fetchSiteNone       = "none"
)

// loginTenantStatuses are the tenant states in which members can sign in (a suspended tenant still lets its Owner
// read billing and audit — §8.4 invariant 5).
var loginTenantStatuses = map[string]bool{"provisioning": true, "active": true, "suspended": true}

// BeginLogin selects the IdP from the database (never from the client), records the auth request and returns the
// redirect to the IdP's authorization endpoint (Authorization Code + PKCE S256).
//
// Login CSRF (G2 F1): a login started by another site — Sec-Fetch-Site cross-site, or same-site (a sibling subdomain:
// another origin of the platform, a tenant's page) — is refused 403 before anything is stored, so that no page can walk
// a browser into a login of the attacker's choosing (an attacker-run external IdP would sign the victim in as the
// attacker). A request without Sec-Fetch-Site is allowed: non-browser clients and browsers without Fetch Metadata send
// none, and the login CSRF it leaves open is closed in the callback, which never replaces the open session of another
// identity (CompleteLogin).
func (s *Service) BeginLogin(ctx context.Context, in LoginRequest) (*LoginRedirect, error) {
	ev := AuditEvent{Action: ActionLoginStart, Origin: in.Origin, ClientIP: in.ClientIP, RequestID: in.RequestID}
	out, err := s.beginLogin(ctx, in, &ev)
	if err != nil {
		e := AsError(err)
		ev.Outcome, ev.Reason = outcomeOf(e), e.Reason
		s.audit.Record(ctx, ev)
		if e.Kind == KindInternal || e.Kind == KindUpstream {
			s.log.ErrorContext(ctx, "login start failed", "reason", e.Reason, "error", errString(e))
		}
		return nil, e
	}
	return out, nil
}

func (s *Service) beginLogin(ctx context.Context, in LoginRequest, ev *AuditEvent) (*LoginRedirect, error) {
	if in.Origin != OriginApp && in.Origin != OriginAdmin {
		return nil, newErr(KindInternal, "origin_unknown", errors.New("no origin in the request (middleware missing?)"))
	}
	switch in.FetchSite {
	case "", fetchSiteSameOrigin, fetchSiteNone:
	default: // cross-site, same-site, or a form no browser sends
		return nil, forbidden("sec_fetch_site_cross_origin")
	}
	switch in.Scope {
	case ScopeTenant:
		if in.TenantSlug == "" {
			return nil, invalid("tenant", "required")
		}
		if !slugRE.MatchString(in.TenantSlug) {
			return nil, invalid("tenant", "pattern")
		}
	case ScopePlatform:
		if in.TenantSlug != "" {
			return nil, invalid("tenant", "not_allowed")
		}
	default:
		return nil, invalid("scope", "enum")
	}
	if originForScope(in.Scope) != in.Origin {
		return nil, invalid("scope", "origin_mismatch")
	}
	returnTo, ok := cleanReturnTo(in.ReturnTo)
	if !ok {
		return nil, invalid("return_to", "pattern")
	}
	if in.UILocales != "" && !uiLocales[in.UILocales] {
		return nil, invalid("ui_locales", "enum")
	}
	p, err := s.loginIdP(ctx, in.Scope, in.TenantSlug)
	if err != nil {
		return nil, err
	}
	ev.IdPID, ev.TenantID = p.ID, p.TenantID
	e, err := s.providers.get(ctx, p)
	if err != nil {
		return nil, err
	}

	now := s.now()
	state, nonce, binding, verifier := newSecret(), newSecret(), newSecret(), encodeSecret(newSecret())
	stateHash := hashSecret(state)
	sealed, err := sealVerifier(state, binding, authRequestAAD(stateHash, p.ID, in.Origin), verifier)
	if err != nil {
		return nil, newErr(KindInternal, "seal_failed", err)
	}
	ttl := s.cfg.AuthRequestTTL
	err = s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		return q.InsertAuthRequest(ctx, sqlcdb.InsertAuthRequestParams{
			StateHash: stateHash, IdpID: p.ID, TenantID: p.TenantID, Scope: string(p.Scope), Origin: string(in.Origin),
			Nonce: encodeSecret(nonce), PkceVerifierEnc: sealed, ReturnTo: &returnTo,
			BrowserBindingHash: hashSecret(binding), CreatedAt: now, ExpiresAt: now.Add(ttl),
		})
	})
	if err != nil {
		return nil, newErr(KindInternal, "auth_request_insert_failed", err)
	}

	stepUp := in.Reauth || (in.Current != nil && in.Current.Origin == in.Origin)
	maxAge := int(s.maxAge(p.Scope).Seconds())
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(encodeSecret(nonce))}
	if stepUp {
		maxAge = 0
	}
	// prompt=login on every platform login (G2 round 2, A-1, defence in depth): a staff session never starts from an
	// IdP session left in the browser — e.g. after a logout whose redirect to the IdP never happened (tab closed, IdP
	// unreachable). The platform realm serves only this client, so SSO buys staff nothing. Tenant logins keep the SSO
	// session (external IdPs, other apps of a tenant's realm); the logout ends it (Logout → end_session_endpoint).
	if stepUp || p.Scope == ScopePlatform {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	}
	opts = append(opts, oauth2.SetAuthURLParam("max_age", strconv.Itoa(maxAge)))
	if in.UILocales != "" { // OIDC Core 3.1.2.1: the IdP's pages in the Portal's language (G4b-E14)
		opts = append(opts, oauth2.SetAuthURLParam("ui_locales", in.UILocales))
	}
	location := s.oauthConfig(p, e, "", oauth2.AuthStyleInParams).AuthCodeURL(encodeSecret(state), opts...)
	return &LoginRedirect{
		Location: location, Cookie: AuthRequestCookie(encodeSecret(binding), ttl), IdPID: p.ID, StepUp: stepUp,
	}, nil
}

// loginIdP returns the active IdP of a tenant (by slug) or of the platform.
func (s *Service) loginIdP(ctx context.Context, sc Scope, slug string) (*idp, error) {
	var (
		rows   []sqlcdb.IdentityProvider
		status []string
	)
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if sc == ScopePlatform {
			r, err := q.ListActivePlatformIdPs(ctx)
			rows = r
			return err
		}
		r, err := q.ListLoginIdPsForTenant(ctx, slug)
		for _, x := range r {
			rows = append(rows, x.IdentityProvider)
			status = append(status, x.TenantStatus)
		}
		return err
	})
	switch {
	case err != nil:
		return nil, newErr(KindInternal, "idp_lookup_failed", err)
	case len(rows) == 0:
		return nil, newErr(KindNotFound, "idp_not_found", nil)
	case len(rows) > 1:
		return nil, newErr(KindInternal, "idp_ambiguous", errors.New("more than one active IdP for the login scope"))
	case sc == ScopeTenant && !loginTenantStatuses[status[0]]:
		return nil, newErr(KindNotFound, "tenant_not_loginable", nil)
	}
	return idpFromRow(rows[0])
}

// authRequestAAD binds the sealed PKCE verifier to its auth request (state hash, IdP and origin).
func authRequestAAD(stateHash []byte, idpID uuid.UUID, o Origin) []byte {
	aad := make([]byte, 0, len(stateHash)+16+len(o))
	aad = append(aad, stateHash...)
	aad = append(aad, idpID[:]...)
	return append(aad, o...)
}

// cleanReturnTo accepts only a same-origin relative path (no scheme, host, "//" or "/\" prefix, whitespace or
// control character) — the open-redirect rule of the return_to parameter.
func cleanReturnTo(s string) (string, bool) {
	if s == "" {
		return "/", true
	}
	if len(s) > maxReturnTo || !returnToRE.MatchString(s) {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") ||
		strings.HasPrefix(u.Path, "//") {
		return "", false
	}
	return s, true
}

func outcomeOf(e *Error) string {
	switch e.Kind {
	case KindInternal, KindUpstream:
		return OutcomeFailure
	}
	return OutcomeDenied
}

// errString is the cause of an error for the internal log, truncated (an IdP error may echo a large body).
func errString(e *Error) string {
	if e.cause == nil {
		return ""
	}
	return truncateUTF8(e.cause.Error(), 300)
}
