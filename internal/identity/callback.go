package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"regexp"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	idpkg "github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// CallbackRequest is the input of CompleteLogin (GET /auth/callback/{idpId}, §8.3 steps 3–4).
type CallbackRequest struct {
	IdPID         uuid.UUID // {idpId} of the path — the redirect URI the IdP answered on
	State         string
	Code          string
	Iss           string // RFC 9207 iss parameter; "" when absent
	IdPError      string // error parameter of an error response; "" on success
	BindingCookie string // value of __Host-mg_authreq; "" when absent
	Origin        Origin
	// Current is the valid session already attached on this origin. A login of the same identity revokes it when the
	// new session is created (session id rotation at login, §8.3 step 6); a login of ANOTHER identity is refused and
	// Current is kept — logging out first is the explicit step to switch identity (login CSRF, G2 F1).
	Current   *Session
	ClientIP  string
	UserAgent string
	RequestID string
}

// LoginResult is the answer of CompleteLogin: a 302 to ReturnTo that sets Cookie and deletes the binding cookie.
type LoginResult struct {
	Session  *Session
	Cookie   *http.Cookie
	ReturnTo string
}

const maxUserAgent = 512

var oauthErrorRE = regexp.MustCompile(`^[a-z_]{1,64}$`)

// Reasons of the callback refusals added after the G2 review (rounds 1 and 2).
const (
	reasonSessionIdentityMismatch = "session_identity_mismatch"   // F1: login of another identity over an open session
	reasonClientSecretRefNotOwned = "client_secret_ref_not_owned" // F3: the IdP's client_secret_ref is not its own
	reasonMFAEvidenceMissing      = "mfa_evidence_missing"        // A-6: platform login whose ID token shows no 2nd factor
)

// CompleteLogin finishes a login. Every check that binds the response to this browser and this IdP runs BEFORE the
// token endpoint is called (IdP mix-up, T-20); the ID token and the IdP's claim policy are checked before the
// identity is upserted (§8.2, §8.3 step 3).
func (s *Service) CompleteLogin(ctx context.Context, in CallbackRequest) (*LoginResult, error) {
	ev := AuditEvent{Action: ActionLogin, Origin: in.Origin, ClientIP: in.ClientIP, RequestID: in.RequestID, IdPID: in.IdPID}
	res, err := s.completeLogin(ctx, in, &ev)
	if err != nil {
		e := AsError(err)
		ev.Outcome, ev.Reason = outcomeOf(e), e.Reason
		s.audit.Record(ctx, ev)
		attrs := []any{"reason", e.Reason, "idp_id", in.IdPID.String()}
		if c := errString(e); c != "" {
			attrs = append(attrs, "error", c)
		}
		if e.Kind == KindInternal || e.Kind == KindUpstream {
			s.log.ErrorContext(ctx, "login callback failed", attrs...)
		} else {
			s.log.WarnContext(ctx, "login callback rejected", attrs...)
		}
		return nil, e
	}
	ev.Outcome, ev.IdentityID, ev.SessionID = OutcomeSuccess, res.Session.IdentityID, res.Session.PublicID
	s.audit.Record(ctx, ev)
	return res, nil
}

func (s *Service) completeLogin(ctx context.Context, in CallbackRequest, ev *AuditEvent) (*LoginResult, error) {
	if in.Origin != OriginApp && in.Origin != OriginAdmin {
		return nil, newErr(KindInternal, "origin_unknown", errors.New("no origin in the request (middleware missing?)"))
	}
	state, ok := decodeSecret(in.State)
	if !ok {
		return nil, unauthenticated("state_malformed")
	}
	stateHash := hashSecret(state)
	now := s.now()

	// 1. Consume the auth request — single use: a replayed state finds no row — and load its IdP.
	var (
		ar  sqlcdb.AuthRequest
		row sqlcdb.IdentityProvider
	)
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if ar, err = q.ConsumeAuthRequest(ctx, sqlcdb.ConsumeAuthRequestParams{Now: now, StateHash: stateHash}); err != nil {
			return err
		}
		row, err = q.GetIdentityProvider(ctx, ar.IdpID)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return nil, unauthenticated("state_unknown_or_used")
	case err != nil:
		return nil, newErr(KindInternal, "auth_request_lookup_failed", err)
	}
	ev.TenantID = ar.TenantID

	// 2. Bind the response to the auth request, this IdP, this origin and this browser — no network call yet.
	switch {
	case !now.Before(ar.ExpiresAt):
		return nil, unauthenticated("auth_request_expired")
	case ar.IdpID != in.IdPID:
		return nil, unauthenticated("idp_mismatch") // response of another IdP on this IdP's callback (IT-01b)
	case Origin(ar.Origin) != in.Origin:
		return nil, unauthenticated("origin_mismatch")
	}
	binding, ok := decodeSecret(in.BindingCookie)
	if !ok || !equalHash(hashSecret(binding), ar.BrowserBindingHash) {
		return nil, unauthenticated("browser_binding_mismatch")
	}
	if in.IdPError != "" {
		code := "invalid"
		if oauthErrorRE.MatchString(in.IdPError) {
			code = in.IdPError
		}
		return nil, newErr(KindUnauthenticated, "idp_error", errors.New("authorization error "+code))
	}
	p, err := idpFromRow(row)
	if err != nil {
		return nil, err
	}
	switch {
	case !idpUsable(p.Status):
		return nil, unauthenticated("idp_not_usable")
	case p.Scope != Scope(ar.Scope) || !sameTenant(p.TenantID, ar.TenantID) || originForScope(p.Scope) != in.Origin:
		return nil, newErr(KindInternal, "auth_request_inconsistent", nil)
	case in.Iss != "" && in.Iss != p.Issuer:
		return nil, unauthenticated("iss_mismatch") // RFC 9207
	}
	e, err := s.providers.get(ctx, p)
	if err != nil {
		return nil, err
	}
	if in.Iss == "" && e.meta.IssParameterSupported {
		return nil, unauthenticated("iss_missing") // RFC 9207 §2.4: the IdP announces iss, so it must be present
	}
	if in.Code == "" {
		return nil, unauthenticated("code_missing")
	}
	verifier, err := openVerifier(state, binding, authRequestAAD(stateHash, ar.IdpID, Origin(ar.Origin)), ar.PkceVerifierEnc)
	if err != nil {
		return nil, newErr(KindUnauthenticated, "pkce_verifier_unavailable", err)
	}

	// 3. Token endpoint of the stored issuer (the only place the code is sent), PKCE verifier. The client secret is only
	// read through a reference that names this IdP's own client secret (G2 F3): any other reference — another tenant's
	// Headscale API key, a platform credential — fails closed here, before the SecretStore is read and before the
	// token request, and raises a security event.
	secret := ""
	if p.ClientSecretRef != nil && *p.ClientSecretRef != "" {
		if err := p.checkClientSecretRef(); err != nil {
			ev.Security = idpkg.KindClientSecretRefNotOwned
			return nil, newErr(KindInternal, reasonClientSecretRefNotOwned, err)
		}
		if s.cfg.ClientSecrets == nil {
			return nil, newErr(KindInternal, "client_secret_source_missing", nil)
		}
		if secret, err = s.cfg.ClientSecrets.ClientSecret(ctx, *p.ClientSecretRef); err != nil || secret == "" {
			return nil, newErr(KindInternal, "client_secret_unavailable", err)
		}
	}
	style, err := authStyle(e.meta, secret != "")
	if err != nil {
		return nil, err
	}
	tctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, s.providers.client), idpTimeout)
	defer cancel()
	tok, err := s.oauthConfig(p, e, secret, style).Exchange(tctx, in.Code, oauth2.VerifierOption(verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			code := "invalid"
			if oauthErrorRE.MatchString(re.ErrorCode) {
				code = re.ErrorCode
			}
			return nil, newErr(KindUnauthenticated, "token_rejected", errors.New("token endpoint error "+code))
		}
		return nil, newErr(KindUpstream, "token_request_failed", err)
	}
	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, unauthenticated("id_token_missing")
	}

	// 4. ID token: signature against the JWKS of the stored issuer, iss, aud, exp (go-oidc), then nonce, azp, iat
	// freshness and auth_time (OIDC Core §3.1.3.7).
	idt, err := e.op.Verifier(&oidc.Config{ClientID: p.ClientID, Now: s.now}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, newErr(KindUnauthenticated, "id_token_invalid", err)
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, newErr(KindUnauthenticated, "id_token_claims_invalid", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(ar.Nonce)) != 1 {
		return nil, unauthenticated("nonce_mismatch")
	}
	if azp := claimString(claims, "azp"); (azp != "" && azp != p.ClientID) || (len(idt.Audience) > 1 && azp == "") {
		return nil, unauthenticated("azp_mismatch")
	}
	skew := s.cfg.ClockSkew
	if idt.IssuedAt.IsZero() || idt.IssuedAt.Before(ar.CreatedAt.Add(-skew)) || idt.IssuedAt.After(now.Add(skew)) {
		return nil, unauthenticated("id_token_not_fresh")
	}
	authTime, ok := claimTime(claims, "auth_time")
	if !ok {
		// max_age was sent, so a conforming IdP must return auth_time; without it no step-up could ever be recorded.
		return nil, unauthenticated("auth_time_missing")
	}
	if authTime.After(now.Add(skew)) || now.Sub(authTime) > s.maxAge(p.Scope)+skew {
		return nil, unauthenticated("auth_time_out_of_range")
	}
	prof, perr := profileFromClaims(p, claims)
	if perr != nil {
		return nil, perr
	}
	// Platform staff: the ID token must show the second factor (amr — G2 round 2, A-6, ASVS 6.8.4). The platform realm
	// requires OTP in its browser flow, but a realm changed through break-glass (OTP made conditional) would still sign
	// a password-only login; the BFF does not take the realm's word for it. The refusal is 401 reauth_required (no
	// session, audited with reason mfa_evidence_missing): Keycloak 26.8 also leaves OTP out of amr on the login that
	// ENROLS it (CONFIGURE_TOTP runs as a required action, not as the OTP step) — a new staff member signs in once more,
	// now with password + OTP (the Portal's reauth=true; platform logins always prompt=login). Not a security event for
	// that reason: an enrolment and a downgraded realm look alike here; the realm itself is held by check_realm, the
	// driver and realm-update.sh. Tenant IdPs: required_claims of the IdP row (e.g. {"amr": ["otp", "mfa", "hwk",
	// "swk"]}) — off by default, an external IdP may not send amr at all (§8.2).
	if p.Scope == ScopePlatform && !hasMFAEvidence(prof.AMR) {
		return nil, newErr(KindReauthRequired, reasonMFAEvidenceMissing, nil)
	}

	// 5. Identity (idp_id, sub) and session, in one transaction. The session presented on this origin is revoked when it
	// is the same identity's (rotation); a session of another identity is kept and the login refused (G2 F1): a login
	// CSRF — a page walking the victim's browser through a login at an IdP of the attacker's — must not silently swap
	// the victim's session for one of the attacker's identity. The rollback also drops a newly created identity.
	raw := newSecret()
	// The ID token is kept — sealed with a key only this session's cookie yields — as the id_token_hint of the logout
	// (RP-Initiated Logout, G2 round 2, A-1): without it Keycloak asks the user to confirm and a closed tab leaves the
	// IdP session alive. Never kept in a cookie, never logged; cleared when the session is revoked.
	var hint []byte
	if e.meta.EndSessionEndpoint != "" {
		if hint, err = sealHint(raw, hintAAD(hashSecret(raw), p.ID), rawIDToken); err != nil {
			s.log.WarnContext(ctx, "login: id token not kept as a logout hint", "idp_id", p.ID.String(), "reason", err.Error())
			hint = nil
		}
	}
	t := s.timeouts(p.Scope)
	absolute := now.Add(t.Absolute)
	idle := minTime(now.Add(t.Idle), absolute)
	amr := prof.AMR
	if amr == nil {
		amr = []string{}
	}
	var (
		ident sqlcdb.Identity
		srow  sqlcdb.Session
	)
	err = s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		ident, err = q.UpsertLoginIdentity(ctx, sqlcdb.UpsertLoginIdentityParams{
			IdpID: p.ID, TenantID: p.TenantID, Scope: string(p.Scope), Subject: prof.Subject,
			Email: nilIfEmpty(prof.Email), EmailVerified: prof.EmailVerified, DisplayName: nilIfEmpty(prof.DisplayName),
			Now: now,
		})
		if errors.Is(err, store.ErrNoRows) {
			return forbidden("identity_disabled")
		}
		if err != nil {
			return err
		}
		if in.Current != nil && in.Current.Origin == in.Origin {
			if in.Current.IdentityID != ident.ID {
				return forbidden(reasonSessionIdentityMismatch)
			}
			if _, err := q.RevokeSessionByHash(ctx, sqlcdb.RevokeSessionByHashParams{Now: now, IDHash: in.Current.idHash}); err != nil {
				return err
			}
		}
		srow, err = q.InsertSession(ctx, sqlcdb.InsertSessionParams{
			IDHash: hashSecret(raw), IdentityID: ident.ID, IdpID: p.ID, Origin: string(in.Origin), Now: now,
			AuthTime: authTime, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute, Ip: parseAddr(in.ClientIP),
			UserAgent: nilIfEmpty(truncateUTF8(in.UserAgent, maxUserAgent)), Acr: nilIfEmpty(prof.ACR), Amr: amr,
			IDTokenHintEnc: hint,
		})
		return err
	})
	if err != nil {
		var ie *Error
		if errors.As(err, &ie) {
			ev.IdentityID = ident.ID
			if ie.Reason == reasonSessionIdentityMismatch {
				// audited under the kept session — its identity and tenant — never under the other identity, which was
				// not created, nor in the other IdP's tenant (that tenant must not learn who was walked through its IdP)
				ev.IdentityID, ev.TenantID, ev.SessionID = in.Current.IdentityID, in.Current.TenantID, in.Current.PublicID
			}
			return nil, ie
		}
		return nil, newErr(KindInternal, "session_create_failed", err)
	}
	sess := sessionFromRow(srow, raw, sessionIdentity{
		scope: Scope(ident.Scope), tenantID: ident.TenantID, subject: ident.Subject,
		email: ident.Email, displayName: ident.DisplayName,
	})
	returnTo := "/"
	if ar.ReturnTo != nil && *ar.ReturnTo != "" {
		returnTo = *ar.ReturnTo
	}
	return &LoginResult{Session: sess, Cookie: SessionCookie(encodeSecret(raw)), ReturnTo: returnTo}, nil
}

func sameTenant(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func parseAddr(s string) *netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	a = a.Unmap().WithZone("")
	return &a
}
