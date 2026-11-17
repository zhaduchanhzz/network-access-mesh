// Package authzhook fills the security slots of the public API (httpapi.Hooks — P2-T14) with the session layer of the
// identity module (P2-T06) and the decisions of the authorization module (P2-T07): layer 1 of §8.8. It lives under
// internal/httpapi because neither identity nor authz may import httpapi (§13.6, internal/archtest), and it takes an
// already built authorizer because httpapi may not import internal/store.
//
// Wiring (P2-T16, apps/internal/runner):
//
//	svc, _ := identity.New(apiStore, identity.Config{…, RequestID: authzhook.RequestID, ClientIP: authzhook.ClientIP,
//		ProblemWriter: authzhook.WriteProblem})
//	api, _ := httpapi.New(httpapi.Options{
//		Logger:   log,
//		Handlers: httpapi.Handlers{Auth: identityapi.New(svc) /* , … */},
//		Hooks:    authzhook.Hooks(svc, authz.New(apiStore)),
//	})
package authzhook

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// Authorizer is the part of *authz.Authorizer the hook needs.
type Authorizer interface {
	RequireOperation(ctx context.Context, operation string, tenantID uuid.UUID) (authz.Decision, error)
}

var _ Authorizer = (*authz.Authorizer)(nil)

// Hooks returns the three security hooks of httpapi.New:
//   - Session: identity.Service.Middleware — Host → origin (unknown host ⇒ 404), Origin/Sec-Fetch-Site and
//     X-CSRF-Token on unsafe methods (⇒ 403), the session cookie resolved on every request — then
//     httpapi.SetIdentity(identities.id) for the per-identity rate limit and the access log;
//   - CSRF: nil — the identity middleware already enforces it where the session is resolved (§8.3 step 5);
//   - Authz: Authz(a).
func Hooks(svc *identity.Service, a Authorizer) httpapi.Hooks {
	return httpapi.Hooks{Session: Session(svc), Authz: Authz(a)}
}

// Session returns the session hook: identity.Service.Middleware followed by httpapi.SetIdentity.
func Session(svc *identity.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s, ok := identity.SessionFromContext(r.Context()); ok {
				httpapi.SetIdentity(r.Context(), s.IdentityID.String()) // a stable id, never the session id
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// Authz returns the strict middleware that decides every operation before its handler runs: the principal comes from
// the session (identity.SessionFromContext), the tenant from the {tenantId} of the path (already bound as a UUID by
// the generated router; ignored by authz for platform operations), the permission from the operation's x-permission
// (authz.RequireOperation with the Go operation name). A granted request reaches the handler with the decision in
// its context (DecisionFrom); a refused one never does.
func Authz(a Authorizer) gen.StrictMiddlewareFunc {
	return func(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			if s, ok := identity.SessionFromContext(ctx); ok {
				ctx = authz.WithPrincipal(ctx, PrincipalOf(s))
			}
			tenantID := uuid.Nil
			if raw := r.PathValue("tenantId"); raw != "" {
				id, err := uuid.Parse(raw)
				if err != nil { // the generated binding refused it already; never decide on an unparsed tenant
					return nil, problem.New(gen.ProblemCodeNotFound, "The resource does not exist.")
				}
				tenantID = id
			}
			d, err := a.RequireOperation(ctx, operationID, tenantID)
			if err != nil {
				return nil, Problem(err)
			}
			return f(context.WithValue(ctx, decisionKey{}, d), w, r, request)
		}
	}
}

// PrincipalOf is the authz principal of a session: the identity, its scope and the origin the session is bound to
// (the values of identity.Scope/Origin and authz.Scope/Origin are the same strings — TestPrincipalValues).
func PrincipalOf(s *identity.Session) authz.Principal {
	return authz.Principal{IdentityID: s.IdentityID, Scope: authz.Scope(s.Scope), Origin: authz.Origin(s.Origin)}
}

type decisionKey struct{}

// DecisionFrom returns the decision of the request — the obligations a handler must honour (own-resource filter,
// dual control, condition).
func DecisionFrom(ctx context.Context) (authz.Decision, bool) {
	d, ok := ctx.Value(decisionKey{}).(authz.Decision)
	return d, ok
}

// details are the client-facing texts of the refusals: generic, the same for every reason of one code (a non-member
// cannot tell a missing tenant from someone else's — §8.4 invariant 6); authz.Denial.Reason stays in the log.
var details = map[gen.ProblemCode]string{
	gen.ProblemCodeUnauthenticated:  "The session is missing, expired or revoked.",
	gen.ProblemCodeNotFound:         "The resource does not exist.",
	gen.ProblemCodeForbidden:        "The request is not allowed.",
	gen.ProblemCodeTenantSuspended:  "The tenant is suspended: changes are not allowed.",
	gen.ProblemCodeValidationFailed: "The request is invalid.",
}

// Problem maps an error of internal/authz to the problem of §13.1 (authz.Status): a refusal keeps its code with a
// generic detail, anything else is 500 internal_error. The error is kept as Cause (internal log only).
func Problem(err error) *problem.Error {
	_, code := authz.Status(err)
	c := gen.ProblemCode(code)
	var denial *authz.Denial
	if detail, ok := details[c]; ok && errors.As(err, &denial) {
		return &problem.Error{Code: c, Detail: detail, Cause: err}
	}
	return problem.Internal(err)
}

// WriteProblem gives identity.Config the problem writer of the httpapi chain: what the session middleware refuses
// itself (unknown host ⇒ 404, Origin/Sec-Fetch-Site or X-CSRF-Token ⇒ 403, session lookup failure ⇒ 500) is answered
// by httpapi.WriteProblem like every other problem — the code, status, generic detail and field errors of the
// identity module's own problem, plus X-Content-Type-Options: nosniff and the code on the access-log line. The
// identity error stays the internal cause (logged for a 5xx only, never sent).
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
	p := identity.NewProblem(err, "", "")
	e := &problem.Error{Code: gen.ProblemCode(p.Code), Detail: p.Detail, Cause: err}
	for _, f := range p.Errors {
		e.Fields = append(e.Fields, problem.Field(f.Field, f.Code, f.Message))
	}
	httpapi.WriteProblem(w, r, e)
}

// RequestID gives identity.Config the request id of the httpapi chain (generated when the client sent none), so the
// problems, sessions and audit events of the identity module carry the id of the access log.
func RequestID(r *http.Request) string { return requestid.From(r.Context()) }

// ClientIP gives identity.Config the client address of the httpapi chain (X-Forwarded-For only from
// MG_TRUSTED_PROXIES, P2-T14); outside the chain, the peer address.
func ClientIP(r *http.Request) string {
	if a := httpapi.ClientIP(r.Context()); a.IsValid() {
		return a.String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
