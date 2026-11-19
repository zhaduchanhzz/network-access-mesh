package identity

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Identity statuses (identities.status — set fixed by P2-T06, CHECK in 0002).
const (
	IdentityActive   = "active"
	IdentityDisabled = "disabled"
)

// Session is an authenticated Portal session. It carries identity only — never roles, memberships or grants:
// authorization reloads those from the database on every request (§8.3 step 8).
type Session struct {
	PublicID          uuid.UUID // sessions.public_id — the only id ever shown (GET/DELETE /auth/sessions)
	IdentityID        uuid.UUID
	IdPID             uuid.UUID
	Scope             Scope
	TenantID          *uuid.UUID // tenant of the identity; nil for platform staff
	Subject           string
	Email             string
	DisplayName       string
	Origin            Origin
	CreatedAt         time.Time
	LastSeenAt        time.Time
	AuthTime          time.Time // auth_time of the fresh ID token that created the session — basis of step-up
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	ACR               string
	AMR               []string

	raw    []byte // raw session id: the CSRF key; never logged, printed or serialised
	idHash []byte
}

// CSRFToken returns the CSRF token of the session (HMAC-SHA256(key = session id, msg = "csrf-v1")).
func (s Session) CSRFToken() string { return csrfToken(s.raw) }

// String, GoString and LogValue keep the raw session id out of fmt and slog output.
func (s Session) String() string   { return "identity.Session{public_id=" + s.PublicID.String() + "}" }
func (s Session) GoString() string { return s.String() }

// LogValue implements slog.LogValuer.
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(slog.String("public_id", s.PublicID.String()), slog.String("identity_id", s.IdentityID.String()),
		slog.String("origin", string(s.Origin)))
}

// sessionIdentity is the identity part of a session row.
type sessionIdentity struct {
	scope       Scope
	tenantID    *uuid.UUID
	subject     string
	email       *string
	displayName *string
}

func sessionFromRow(r sqlcdb.Session, raw []byte, id sessionIdentity) *Session {
	s := &Session{
		PublicID: r.PublicID, IdentityID: r.IdentityID, IdPID: r.IdpID, Scope: id.scope, TenantID: id.tenantID,
		Subject: id.subject, Origin: Origin(r.Origin), CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt,
		AuthTime: r.AuthTime, IdleExpiresAt: r.IdleExpiresAt, AbsoluteExpiresAt: r.AbsoluteExpiresAt, AMR: r.Amr,
		raw: raw, idHash: r.IDHash,
	}
	if id.email != nil {
		s.Email = *id.email
	}
	if id.displayName != nil {
		s.DisplayName = *id.displayName
	}
	if r.Acr != nil {
		s.ACR = *r.Acr
	}
	return s
}

// Authenticate resolves the value of the session cookie on a request of the given origin. Unknown, revoked, idle- or
// absolutely-expired sessions, sessions created on the other origin, and sessions of a disabled identity or IdP are
// rejected with KindUnauthenticated (the reason tells which); a database failure is KindInternal. An accepted session
// has its idle expiry extended (at most once per TouchInterval, never beyond the absolute expiry).
func (s *Service) Authenticate(ctx context.Context, cookieValue string, origin Origin) (*Session, error) {
	raw, ok := decodeSecret(cookieValue)
	if !ok {
		return nil, unauthenticated("session_malformed")
	}
	now := s.now()
	var sess *Session
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetSessionForRequest(ctx, hashSecret(raw))
		if errors.Is(err, store.ErrNoRows) {
			return unauthenticated("session_unknown")
		}
		if err != nil {
			return err
		}
		r := row.Session
		switch {
		case r.RevokedAt != nil:
			return unauthenticated("session_revoked")
		case !now.Before(r.AbsoluteExpiresAt):
			return unauthenticated("session_expired")
		case !now.Before(r.IdleExpiresAt):
			return unauthenticated("session_idle_expired")
		case Origin(r.Origin) != origin:
			// §8.3 step 8: a session of app is refused on admin and vice versa, whatever the cookie scoping.
			return unauthenticated("session_origin_mismatch")
		case originForScope(Scope(row.IdentityScope)) != origin:
			// Invariant kept by the login (tenant identities on app, platform staff on admin), re-checked here.
			return unauthenticated("session_scope_origin_mismatch")
		case row.IdentityStatus != IdentityActive:
			return unauthenticated("identity_disabled")
		case !idpUsable(row.IdpStatus):
			return unauthenticated("idp_not_usable")
		}
		if now.Sub(r.LastSeenAt) >= s.cfg.TouchInterval {
			idle := minTime(now.Add(s.timeouts(Scope(row.IdentityScope)).Idle), r.AbsoluteExpiresAt)
			if err := q.TouchSession(ctx, sqlcdb.TouchSessionParams{Now: now, IdleExpiresAt: idle, IDHash: r.IDHash}); err != nil {
				return err
			}
			r.LastSeenAt, r.IdleExpiresAt = now, idle
		}
		sess = sessionFromRow(r, raw, sessionIdentity{
			scope: Scope(row.IdentityScope), tenantID: row.IdentityTenantID, subject: row.IdentitySubject,
			email: row.IdentityEmail, displayName: row.IdentityDisplayName,
		})
		return nil
	})
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, e
		}
		return nil, newErr(KindInternal, "session_lookup_failed", err)
	}
	return sess, nil
}

// RequireRecentAuth is the step-up check of sensitive actions (§8.3 step 7): the session's auth_time must be within
// StepUpWindow, otherwise ErrReauthRequired (401 reauth_required — the Portal then logs in again, which sends
// prompt=login and max_age=0).
func (s *Service) RequireRecentAuth(sess *Session) error {
	if sess == nil {
		return ErrUnauthenticated
	}
	now := s.now()
	if now.Sub(sess.AuthTime) > s.cfg.StepUpWindow || sess.AuthTime.After(now.Add(s.cfg.ClockSkew)) {
		return ErrReauthRequired
	}
	return nil
}

// RequireRecentAuthContext applies RequireRecentAuth to the session of the request context.
func (s *Service) RequireRecentAuthContext(ctx context.Context) error {
	sess, _ := SessionFromContext(ctx)
	return s.RequireRecentAuth(sess)
}

// Membership is one active tenant membership shown by GET /auth/session.
type Membership struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	TenantSlug string
	TenantName string
	Role       string
	Status     string
}

// SessionView is the content of GET /auth/session: the session plus, for display only, the platform role or the
// active memberships (authorization never trusts this view — it reloads on every request).
type SessionView struct {
	Session      *Session
	PlatformRole string // "" when the identity has no active platform role
	Memberships  []Membership
	// SupportGrants: the live Support Access Grants of platform staff (§8.7, P4-T13) — display only.
	SupportGrants []SupportGrantSummary
}

// SupportGrantSummary is one live Support Access Grant of the session's platform user.
type SupportGrantSummary struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Role      string // support_operator, support_admin
	ExpiresAt time.Time
}

// View loads the display data of a session.
func (s *Service) View(ctx context.Context, sess *Session) (*SessionView, error) {
	if sess == nil {
		return nil, ErrUnauthenticated
	}
	v := &SessionView{Session: sess, Memberships: []Membership{}, SupportGrants: []SupportGrantSummary{}}
	var err error
	switch sess.Scope {
	case ScopePlatform:
		err = s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			key, err := q.GetPlatformRoleKeyForIdentity(ctx, sess.IdentityID)
			if errors.Is(err, store.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			v.PlatformRole = key
			grants, err := q.ListSessionSupportGrants(ctx, sess.IdentityID)
			for _, g := range grants {
				v.SupportGrants = append(v.SupportGrants, SupportGrantSummary{ID: g.ID, TenantID: g.TenantID,
					Role: g.EffectiveRoleKey, ExpiresAt: g.ExpiresAt.UTC()})
			}
			return err
		})
	case ScopeTenant:
		if sess.TenantID == nil {
			return nil, newErr(KindInternal, "tenant_identity_without_tenant", nil)
		}
		err = s.store.WithTenantTx(ctx, *sess.TenantID, func(q *sqlcdb.Queries) error {
			rows, err := q.ListActiveMembershipsForIdentity(ctx, sess.IdentityID)
			for _, r := range rows {
				v.Memberships = append(v.Memberships, Membership{
					ID: r.ID, TenantID: r.TenantID, TenantSlug: r.Slug, TenantName: r.Name, Role: r.RoleKey, Status: r.Status,
				})
			}
			return err
		})
	}
	if err != nil {
		return nil, newErr(KindInternal, "session_view_failed", err)
	}
	return v, nil
}

// SessionSummary is one entry of GET /auth/sessions.
type SessionSummary struct {
	PublicID          uuid.UUID
	Origin            Origin
	CreatedAt         time.Time
	LastSeenAt        time.Time
	AuthTime          time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	IP                string
	UserAgent         string
	Current           bool
}

// SessionPage is one page of GET /auth/sessions; NextCursor is "" on the last page.
type SessionPage struct {
	Items      []SessionSummary
	NextCursor string
}

// Page size of GET /auth/sessions (§13.1).
const (
	DefaultPageLimit = 50
	MaxPageLimit     = 200
)

// ListSessions lists the live sessions of the caller's own identity in a stable (created_at, public_id) order.
func (s *Service) ListSessions(ctx context.Context, sess *Session, limit int, cursor string) (*SessionPage, error) {
	if sess == nil {
		return nil, ErrUnauthenticated
	}
	if limit == 0 {
		limit = DefaultPageLimit
	}
	if limit < 1 || limit > MaxPageLimit {
		return nil, invalid("limit", "range")
	}
	afterTime, afterID := time.Unix(0, 0).UTC(), uuid.Nil
	if cursor != "" {
		var ok bool
		if afterTime, afterID, ok = decodeCursor(cursor); !ok {
			return nil, invalid("cursor", "invalid")
		}
	}
	var rows []sqlcdb.Session
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListLiveSessionsForIdentity(ctx, sqlcdb.ListLiveSessionsForIdentityParams{
			IdentityID: sess.IdentityID, Now: s.now(), AfterCreatedAt: afterTime, AfterPublicID: afterID,
			PageLimit: int32(limit + 1), //nolint:gosec // limit ≤ MaxPageLimit
		})
		return err
	})
	if err != nil {
		return nil, newErr(KindInternal, "session_list_failed", err)
	}
	page := &SessionPage{Items: []SessionSummary{}}
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[limit-1]
		page.NextCursor = encodeCursor(last.CreatedAt, last.PublicID)
	}
	for _, r := range rows {
		item := SessionSummary{
			PublicID: r.PublicID, Origin: Origin(r.Origin), CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt,
			AuthTime: r.AuthTime, IdleExpiresAt: r.IdleExpiresAt, AbsoluteExpiresAt: r.AbsoluteExpiresAt,
			Current: r.PublicID == sess.PublicID,
		}
		if r.Ip != nil {
			item.IP = r.Ip.String()
		}
		if r.UserAgent != nil {
			item.UserAgent = *r.UserAgent
		}
		page.Items = append(page.Items, item)
	}
	return page, nil
}

// cursorVersion prefixes the opaque cursor of GET /auth/sessions: version | created_at (µs) | public_id.
const cursorVersion = 1

func encodeCursor(t time.Time, id uuid.UUID) string {
	b := make([]byte, 0, 1+8+16)
	b = append(b, cursorVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(t.UnixMicro())) //nolint:gosec // timestamps after 1970
	b = append(b, id[:]...)
	return b64.EncodeToString(b)
}

func decodeCursor(s string) (time.Time, uuid.UUID, bool) {
	b, err := b64.Strict().DecodeString(s)
	if err != nil || len(b) != 1+8+16 || b[0] != cursorVersion {
		return time.Time{}, uuid.Nil, false
	}
	micros := binary.BigEndian.Uint64(b[1:9])
	if micros > 1<<62 {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.FromBytes(b[9:])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.UnixMicro(int64(micros)).UTC(), id, true
}

// LogoutResult is the answer of Logout: where the browser goes next.
type LogoutResult struct {
	// RedirectTo is the end_session_endpoint of the session's IdP (OIDC RP-Initiated Logout 1.0) with client_id, the
	// registered post_logout_redirect_uri (https://<origin host>/) and, when the session kept it, id_token_hint — or,
	// when the IdP announces no end_session_endpoint or cannot be reached, the post-logout page itself.
	RedirectTo string
	// IdPLogout tells whether RedirectTo ends the IdP session; HintSent whether it carries id_token_hint (without it
	// Keycloak shows a confirmation page first).
	IdPLogout, HintSent bool
}

// Logout revokes the session (POST /auth/logout, §8.3 step 6) — effective on the next request — and returns the
// redirect that ends the IdP's session too (G2 round 2, A-1, ASVS 7.6.1): without it the next login on the same browser
// gets a code from the IdP's SSO session without password or OTP. The BFF session is revoked first, in its own
// transaction, together with the sealed hint (read and cleared under a row lock); building the redirect afterwards
// needs the IdP's discovery and never undoes the revocation: a failure there falls back to the post-logout page.
func (s *Service) Logout(ctx context.Context, sess *Session, info RequestInfo) (*LogoutResult, error) {
	if sess == nil {
		return nil, ErrUnauthenticated
	}
	var (
		sealed []byte
		row    sqlcdb.IdentityProvider
	)
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		h, err := q.GetSessionLogoutHint(ctx, sess.idHash)
		switch {
		case errors.Is(err, store.ErrNoRows): // revoked meanwhile: logging out again is harmless
		case err != nil:
			return err
		default:
			sealed = h
		}
		if _, err := q.RevokeSessionByHash(ctx, sqlcdb.RevokeSessionByHashParams{Now: s.now(), IDHash: sess.idHash}); err != nil {
			return err
		}
		row, err = q.GetIdentityProvider(ctx, sess.IdPID)
		return err
	})
	ev := s.sessionEvent(ActionLogout, sess, info)
	if err != nil {
		ev.Outcome, ev.Reason = OutcomeFailure, "revoke_failed"
		s.audit.Record(ctx, ev)
		return nil, newErr(KindInternal, "logout_failed", err)
	}
	ev.Outcome = OutcomeSuccess
	s.audit.Record(ctx, ev)
	return s.endSession(ctx, sess, row, sealed), nil
}

// endSession builds the RP-Initiated Logout redirect of a revoked session (best effort, see Logout).
func (s *Service) endSession(ctx context.Context, sess *Session, row sqlcdb.IdentityProvider, sealed []byte) *LogoutResult {
	plr := s.postLogoutRedirectURI(sess.Origin)
	res := &LogoutResult{RedirectTo: plr}
	p, err := idpFromRow(row)
	if err != nil {
		s.log.WarnContext(ctx, "logout: identity provider unusable, no IdP logout", "idp_id", sess.IdPID.String())
		return res
	}
	e, err := s.providers.get(ctx, p)
	if err != nil {
		s.log.WarnContext(ctx, "logout: discovery failed, no IdP logout", "idp_id", p.ID.String(), "reason", AsError(err).Reason)
		return res
	}
	if e.meta.EndSessionEndpoint == "" {
		return res
	}
	// An absolute URL of the issuer's own scheme (https: the IdP client refuses anything else), no credentials, no
	// fragment — the discovery document is the issuer's word, but a malformed value never reaches the browser.
	iss, _ := url.Parse(p.Issuer)
	u, err := url.Parse(e.meta.EndSessionEndpoint)
	if err != nil || iss == nil || u.Scheme != iss.Scheme || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.Fragment != "" {
		s.log.WarnContext(ctx, "logout: end_session_endpoint is not a usable URL, no IdP logout", "idp_id", p.ID.String())
		return res
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("post_logout_redirect_uri", plr)
	if sealed != nil {
		hint, err := openHint(sess.raw, hintAAD(sess.idHash, sess.IdPID), sealed)
		if err != nil {
			s.log.WarnContext(ctx, "logout: logout hint not usable", "idp_id", p.ID.String(), "reason", err.Error())
		} else {
			q.Set("id_token_hint", hint)
			res.HintSent = true
		}
	}
	u.RawQuery = q.Encode()
	res.RedirectTo, res.IdPLogout = u.String(), true
	return res
}

// postLogoutRedirectURI is the page an IdP sends the browser back to after the logout: the root of the session's
// origin, registered exactly as post.logout.redirect.uris of mg-portal (infrastructure/idp/realms, check_realm).
func (s *Service) postLogoutRedirectURI(o Origin) string { return s.hosts.baseURL(o) + "/" }

// RevokeSession revokes one live session of the caller's own identity (DELETE /auth/sessions/{id}); the session of
// another identity, an unknown or an already ended one answers not_found (§8.4 invariant 6).
func (s *Service) RevokeSession(ctx context.Context, sess *Session, publicID uuid.UUID, info RequestInfo) error {
	if sess == nil {
		return ErrUnauthenticated
	}
	var n int64
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.RevokeOwnSession(ctx, sqlcdb.RevokeOwnSessionParams{Now: s.now(), PublicID: publicID, IdentityID: sess.IdentityID})
		return err
	})
	ev := s.sessionEvent(ActionSessionRevoke, sess, info)
	switch {
	case err != nil:
		ev.Outcome, ev.Reason = OutcomeFailure, "revoke_failed"
		s.audit.Record(ctx, ev)
		return newErr(KindInternal, "session_revoke_failed", err)
	case n == 0:
		ev.Outcome, ev.Reason = OutcomeDenied, "session_not_found"
		s.audit.Record(ctx, ev)
		return newErr(KindNotFound, "session_not_found", nil)
	}
	ev.Outcome, ev.SessionID = OutcomeSuccess, publicID
	s.audit.Record(ctx, ev)
	return nil
}

// RevokeIdentitySessions revokes every session of an identity (lock, offboarding, role change — §8.3 step 8) and
// returns how many were live. Callers record their own audit event for the business action.
func (s *Service) RevokeIdentitySessions(ctx context.Context, identityID uuid.UUID) (int64, error) {
	var n int64
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.RevokeIdentitySessions(ctx, sqlcdb.RevokeIdentitySessionsParams{Now: s.now(), IdentityID: identityID})
		return err
	})
	if err != nil {
		return 0, newErr(KindInternal, "identity_sessions_revoke_failed", err)
	}
	return n, nil
}

func (s *Service) sessionEvent(action string, sess *Session, info RequestInfo) AuditEvent {
	return AuditEvent{
		Action: action, IdentityID: sess.IdentityID, TenantID: sess.TenantID, IdPID: sess.IdPID, SessionID: sess.PublicID,
		Origin: sess.Origin, ClientIP: info.ClientIP, RequestID: info.RequestID,
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
