// Package identityapi serves the auth operations of api/openapi.yaml (tag auth, P2-T06) for the generated strict
// server (internal/httpapi/gen): authLogin, authCallback, authLogout, getAuthSession, listAuthSessions and
// revokeAuthSession. It only translates between the generated types and internal/identity, which takes every
// decision.
//
// Wiring (P2-T14): embed *Handlers in the type that implements gen.StrictServerInterface (its six methods are then
// promoted), and run identity.Service.Middleware in front of the router — the handlers read the origin, the request
// id and the session from the request context and answer 500 when the middleware is missing.
package identityapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// Handlers implements the auth operations of gen.StrictServerInterface.
type Handlers struct {
	svc *identity.Service
}

// New returns the handlers of the auth operations.
func New(svc *identity.Service) *Handlers { return &Handlers{svc: svc} }

// AuthOperations is the subset of gen.StrictServerInterface implemented by Handlers.
type AuthOperations interface {
	AuthLogin(ctx context.Context, request gen.AuthLoginRequestObject) (gen.AuthLoginResponseObject, error)
	AuthCallback(ctx context.Context, request gen.AuthCallbackRequestObject) (gen.AuthCallbackResponseObject, error)
	AuthLogout(ctx context.Context, request gen.AuthLogoutRequestObject) (gen.AuthLogoutResponseObject, error)
	GetAuthSession(ctx context.Context, request gen.GetAuthSessionRequestObject) (gen.GetAuthSessionResponseObject, error)
	ListAuthSessions(ctx context.Context, request gen.ListAuthSessionsRequestObject) (gen.ListAuthSessionsResponseObject, error)
	RevokeAuthSession(ctx context.Context, request gen.RevokeAuthSessionRequestObject) (gen.RevokeAuthSessionResponseObject, error)
}

var _ AuthOperations = (*Handlers)(nil)

var errNoMiddleware = errors.New("identityapi: identity.Service.Middleware is not in the handler chain")

// requestInfo returns the information set by the middleware, or a problem when it is missing.
func requestInfo(ctx context.Context) (identity.RequestInfo, *problemResponse) {
	info, ok := identity.RequestInfoFromContext(ctx)
	if !ok {
		p := problemFor(identity.AsError(errNoMiddleware), identity.RequestInfo{})
		return info, &p
	}
	return info, nil
}

func problemFor(err error, info identity.RequestInfo, cookies ...*http.Cookie) problemResponse {
	return problemResponse{problem: identity.NewProblem(err, info.RequestID, info.Path), cookies: cookies}
}

// AuthLogin implements GET /auth/login (§8.3 steps 1–2).
func (h *Handlers) AuthLogin(ctx context.Context, req gen.AuthLoginRequestObject) (gen.AuthLoginResponseObject, error) {
	info, perr := requestInfo(ctx)
	if perr != nil {
		return *perr, nil
	}
	in := identity.LoginRequest{
		Scope: identity.Scope(req.Params.Scope), Origin: info.Origin, ClientIP: info.ClientIP, RequestID: info.RequestID,
		FetchSite: info.FetchSite,
	}
	if req.Params.Tenant != nil {
		in.TenantSlug = *req.Params.Tenant
	}
	if req.Params.ReturnTo != nil {
		in.ReturnTo = *req.Params.ReturnTo
	}
	in.Reauth = req.Params.Reauth != nil && *req.Params.Reauth
	in.Current, _ = identity.SessionFromContext(ctx)
	out, err := h.svc.BeginLogin(ctx, in)
	if err != nil {
		return problemFor(err, info), nil
	}
	return redirectResponse{location: out.Location, cookies: []*http.Cookie{out.Cookie}}, nil
}

// AuthCallback implements GET /auth/callback/{idpId} (§8.3 steps 3–4). Success sets the session cookie and deletes
// the binding cookie; a failure also deletes the binding cookie (the auth request is single use anyway).
func (h *Handlers) AuthCallback(ctx context.Context, req gen.AuthCallbackRequestObject) (gen.AuthCallbackResponseObject, error) {
	info, perr := requestInfo(ctx)
	if perr != nil {
		return *perr, nil
	}
	in := identity.CallbackRequest{
		IdPID: req.IdpId, State: req.Params.State, Origin: info.Origin,
		ClientIP: info.ClientIP, UserAgent: info.UserAgent, RequestID: info.RequestID,
	}
	in.Code = deref(req.Params.Code)
	in.Iss = deref(req.Params.Iss)
	in.IdPError = deref(req.Params.Error)
	in.BindingCookie = deref(req.Params.AuthRequestCookie)
	in.Current, _ = identity.SessionFromContext(ctx)
	clearBinding := identity.ExpiredCookie(identity.AuthRequestCookieName)
	res, err := h.svc.CompleteLogin(ctx, in)
	if err != nil {
		return problemFor(err, info, clearBinding), nil
	}
	return redirectResponse{location: res.ReturnTo, cookies: []*http.Cookie{res.Cookie, clearBinding}}, nil
}

// AuthLogout implements POST /auth/logout: server-side revocation, effective immediately (§8.3 step 6).
func (h *Handlers) AuthLogout(ctx context.Context, _ gen.AuthLogoutRequestObject) (gen.AuthLogoutResponseObject, error) {
	info, perr := requestInfo(ctx)
	if perr != nil {
		return *perr, nil
	}
	sess, ok := identity.SessionFromContext(ctx)
	if !ok {
		return problemFor(identity.ErrUnauthenticated, info), nil
	}
	if err := h.svc.Logout(ctx, sess, info); err != nil {
		return problemFor(err, info), nil
	}
	return logoutResponse{}, nil
}

// GetAuthSession implements GET /auth/session: principal, memberships, grants and the CSRF token.
func (h *Handlers) GetAuthSession(ctx context.Context, _ gen.GetAuthSessionRequestObject) (gen.GetAuthSessionResponseObject, error) {
	info, perr := requestInfo(ctx)
	if perr != nil {
		return *perr, nil
	}
	sess, ok := identity.SessionFromContext(ctx)
	if !ok {
		return problemFor(identity.ErrUnauthenticated, info), nil
	}
	v, err := h.svc.View(ctx, sess)
	if err != nil {
		return problemFor(err, info), nil
	}
	return sessionResponse(toSession(v)), nil
}

// ListAuthSessions implements GET /auth/sessions: live sessions of the caller's own identity.
func (h *Handlers) ListAuthSessions(ctx context.Context, req gen.ListAuthSessionsRequestObject) (gen.ListAuthSessionsResponseObject, error) {
	info, perr := requestInfo(ctx)
	if perr != nil {
		return *perr, nil
	}
	sess, ok := identity.SessionFromContext(ctx)
	if !ok {
		return problemFor(identity.ErrUnauthenticated, info), nil
	}
	limit := 0
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
		if limit == 0 {
			limit = -1 // explicit 0 is out of range, not "default"
		}
	}
	page, err := h.svc.ListSessions(ctx, sess, limit, deref(req.Params.Cursor))
	if err != nil {
		return problemFor(err, info), nil
	}
	out := gen.ListAuthSessions200JSONResponse{Items: make([]gen.SessionSummary, 0, len(page.Items))}
	for _, it := range page.Items {
		s := gen.SessionSummary{
			Id: it.PublicID, Origin: gen.SessionOrigin(it.Origin), CreatedAt: utc(it.CreatedAt),
			LastSeenAt: utc(it.LastSeenAt), AuthTime: utc(it.AuthTime), IdleExpiresAt: utc(it.IdleExpiresAt),
			AbsoluteExpiresAt: utc(it.AbsoluteExpiresAt), Current: it.Current,
		}
		if it.IP != "" {
			ip := it.IP
			s.Ip = &ip
		}
		if it.UserAgent != "" {
			ua := it.UserAgent
			s.UserAgent = &ua
		}
		out.Items = append(out.Items, s)
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return out, nil
}

// RevokeAuthSession implements DELETE /auth/sessions/{sessionId}: only a session of the caller's own identity;
// any other id answers 404.
func (h *Handlers) RevokeAuthSession(ctx context.Context, req gen.RevokeAuthSessionRequestObject) (gen.RevokeAuthSessionResponseObject, error) {
	info, perr := requestInfo(ctx)
	if perr != nil {
		return *perr, nil
	}
	sess, ok := identity.SessionFromContext(ctx)
	if !ok {
		return problemFor(identity.ErrUnauthenticated, info), nil
	}
	if err := h.svc.RevokeSession(ctx, sess, req.SessionId, info); err != nil {
		return problemFor(err, info), nil
	}
	return gen.RevokeAuthSession204Response{}, nil
}

// toSession maps the session view to the API schema.
func toSession(v *identity.SessionView) gen.Session {
	s := v.Session
	p := gen.Principal{
		IdentityId: s.IdentityID, IdpId: s.IdPID, Scope: gen.PrincipalScope(s.Scope), DisplayName: s.DisplayName,
	}
	if p.DisplayName == "" {
		p.DisplayName = s.Email
	}
	if p.DisplayName == "" {
		p.DisplayName = s.Subject
	}
	if s.Email != "" {
		email := s.Email
		p.Email = &email
	}
	if v.PlatformRole != "" {
		role := v.PlatformRole
		p.PlatformRole = &role
	}
	ms := make([]gen.SessionMembership, 0, len(v.Memberships))
	for _, m := range v.Memberships {
		ms = append(ms, gen.SessionMembership{
			MembershipId: m.ID, TenantId: m.TenantID, TenantSlug: m.TenantSlug, TenantName: m.TenantName,
			Role: m.Role, Status: m.Status,
		})
	}
	return gen.Session{
		Principal: p, Origin: gen.SessionOrigin(s.Origin), CsrfToken: s.CSRFToken(), AuthTime: utc(s.AuthTime),
		IdleExpiresAt: utc(s.IdleExpiresAt), AbsoluteExpiresAt: utc(s.AbsoluteExpiresAt), Memberships: ms,
		SupportGrants: []gen.SupportGrantSummary{}, // Support Access Grants arrive with P4-T13
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func utc(t time.Time) time.Time { return t.UTC() }
