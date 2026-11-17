package auditapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// Finisher is the part of *audit.Logger the middleware needs.
type Finisher interface {
	Finish(ctx context.Context, r *audit.Request, res audit.Result)
}

var _ Finisher = (*audit.Logger)(nil)

// unknownAction is the action of an operation missing from the authorization table (authz refuses it anyway).
const unknownAction = "api.unknown_operation"

// Middleware returns the strict middleware of httpapi.Hooks.Audit. It runs outside Hooks.Authz, so it sees the
// refusals of authorization as well as the errors of the handler. For every operation except those of /auth/* (the
// identity module audits its own operations through IdentityAuditor) it:
//
//  1. builds the audit scope of the request (audit.Request) — the operation's x-audit-action, the actor and its tenant
//     from the session, the tenant of the path, the resource of the path, the request id and the client address — and
//     puts it in the context: handlers and services write their events with audit.Record / audit.Requested;
//  2. once the handler returned (or panicked), classifies the outcome and calls Finisher.Finish: a refusal (401 with a
//     principal, 403, 404) is denied, any other error a failure, success nothing; 501 and anonymous 401 are skipped.
//
// Handlers report failures by returning an error (httpapi convention): a response object with an error status is not
// seen here.
func Middleware(f Finisher) gen.StrictMiddlewareFunc {
	return func(next gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
		op, known := authz.OperationByID(operationID)
		if known && strings.HasPrefix(op.Path, "/auth/") {
			return next
		}
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (resp any, err error) {
			req := newRequest(ctx, r, operationID, op, known)
			ctx = audit.WithRequest(ctx, req)
			defer func() {
				if v := recover(); v != nil {
					f.Finish(ctx, req, audit.Result{Outcome: audit.OutcomeFailure, Reason: "panic", Status: http.StatusInternalServerError})
					panic(v)
				}
			}()
			resp, err = next(ctx, w, r, request)
			f.Finish(ctx, req, resultOf(err, req))
			return resp, err
		}
	}
}

// newRequest builds the audit scope of a request.
func newRequest(ctx context.Context, r *http.Request, name string, op authz.Operation, known bool) *audit.Request {
	req := &audit.Request{
		Operation: name, Action: op.AuditAction, ReadOnly: r.Method == http.MethodGet || r.Method == http.MethodHead,
		ActorType: audit.ActorIdentity, RequestID: requestid.From(ctx), ClientIP: httpapi.ClientIP(ctx),
	}
	if !known || req.Action == "" {
		req.Action = unknownAction
	}
	req.ResourceType = resourceType(req.Action)
	if s, ok := identity.SessionFromContext(ctx); ok {
		id := s.IdentityID
		req.ActorIdentityID = &id
		if s.TenantID != nil {
			t := *s.TenantID
			req.ActorTenantID = &t
		}
		req.ActorDisplay = displayName(s)
	}
	if known && op.TenantScoped() {
		if t, err := uuid.Parse(r.PathValue("tenantId")); err == nil {
			req.TenantID = &t
		}
	}
	if known {
		req.ResourceID = resourceID(op, r)
	}
	return req
}

// resultOf classifies how the handler (or authorization) ended.
func resultOf(err error, req *audit.Request) audit.Result {
	if err == nil {
		return audit.Result{}
	}
	code, status := gen.ProblemCodeInternalError, http.StatusInternalServerError
	var p *problem.Error
	if errors.As(err, &p) {
		code, status = p.Code, p.Status()
	}
	reason := string(code)
	var d *authz.Denial
	if errors.As(err, &d) && d.Reason != "" {
		reason = d.Reason // the cause of an authorization refusal — never shown to the client (authzhook)
	}
	res := audit.Result{Reason: reason, Status: status}
	switch code {
	case gen.ProblemCodeNotImplemented:
		res.Skip = true // no handler yet: nothing happened
	case gen.ProblemCodeUnauthenticated:
		// no actor to attribute: an anonymous request is in the access log, not in the append-only audit trail
		res.Skip, res.Outcome = req.ActorIdentityID == nil, audit.OutcomeDenied
	case gen.ProblemCodeReauthRequired, gen.ProblemCodeForbidden, gen.ProblemCodeTenantSuspended,
		gen.ProblemCodeQuotaExceeded, gen.ProblemCodeNotFound:
		res.Outcome = audit.OutcomeDenied
	default:
		res.Outcome = audit.OutcomeFailure
	}
	return res
}

// resourceType is the resource noun of an action: "device.rename" → device, "platform.tenant.read" → tenant.
func resourceType(action string) string {
	a := strings.TrimPrefix(action, "platform.")
	if i := strings.IndexByte(a, '.'); i > 0 {
		return a[:i]
	}
	return "api"
}

// resourceID is the value of the last path parameter of the operation — the resource it acts on — except the
// {tenantId} of a tenant route below the tenant itself (the tenant is the context there, not the resource).
func resourceID(op authz.Operation, r *http.Request) string {
	segs := strings.Split(op.Path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
			continue
		}
		name := s[1 : len(s)-1]
		if name == "tenantId" && op.TenantScoped() && op.Path != "/tenants/{tenantId}" {
			return ""
		}
		return r.PathValue(name) // bound and type-checked (UUIDs) by the generated router
	}
	return ""
}

// displayName is the actor_display snapshot of a session.
func displayName(s *identity.Session) string {
	switch {
	case s.DisplayName != "":
		return s.DisplayName
	case s.Email != "":
		return s.Email
	}
	return s.Subject
}
