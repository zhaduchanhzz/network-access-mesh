// Package idpconsoleapi serves the Keycloak administration console session of P3-T15 (§8.2 (3)):
//
//   - the operations of api/openapi.yaml (httpapi.IdPConsoleHandlers): requestIdpConsoleSession — POST
//     /platform/idp-console/sessions, always dual control: a request of action platform.idp.console_session
//     (internal/idp/console) through internal/authz/approvals, 202 + Location of /platform/approvals/{id} — and
//     listIdpConsoleSessions — GET /platform/idp-console/sessions, those requests as console sessions;
//   - the gate (Gate) the edge calls as forward_auth for every request of the console on admin.<domain> (GET
//     /internal/edge/idp-console, outside /api/v1 and the public contract): it lets a request through (204) only when
//     the caller has a Platform Console session of the admin origin, still holds platform.idp:console and holds an
//     approved console session in its window from its source CIDR; it refuses impersonation whatever the session.
//
// Wiring (apps/internal/runner — api process): httpapi.Handlers{…, IdPConsole: idpconsoleapi.New(approvalsSvc)} and
// httpapi.Options.Internal{"GET /internal/edge/idp-console": idpconsoleapi.NewGate(…)}.
package idpconsoleapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// Approvals is the part of *approvals.Service the handlers use.
type Approvals interface {
	RequestIdempotent(ctx context.Context, actor approvals.Actor, in approvals.NewRequest, idem approvals.Idempotency) (approvals.Request, error)
	List(ctx context.Context, ref approvals.Ref, f approvals.Filter) (approvals.Page, error)
}

var _ Approvals = (*approvals.Service)(nil)

// Handlers implements httpapi.IdPConsoleHandlers.
type Handlers struct {
	appr Approvals
	now  func() time.Time
}

var _ httpapi.IdPConsoleHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T15.
func New(appr Approvals) *Handlers { return &Handlers{appr: appr, now: time.Now} }

// requestOperation is the operationId whose Idempotency-Key RequestIdpConsoleSession stores (§13.1).
const requestOperation = "requestIdpConsoleSession"

var errNoSession = errors.New("idpconsoleapi: no session or decision in the request context (hooks missing)")

// RequestIdpConsoleSession implements POST /platform/idp-console/sessions: the caller asks for a console session for
// themselves; the payload binds their identity, the source CIDR (by default their own address) and the duration.
func (h *Handlers) RequestIdpConsoleSession(ctx context.Context, req gen.RequestIdpConsoleSessionRequestObject) (gen.RequestIdpConsoleSessionResponseObject, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return nil, problem.Internal(errNoSession)
	}
	if !d.NeedsApproval() { // x-dual-control: the decision must carry the 2P obligation (§8.6) — never run it directly
		return nil, problem.Internal(errors.New("idpconsoleapi: the decision does not require a second approver"))
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	if r := strings.TrimSpace(req.Body.Reason); r == "" || utf8.RuneCountInString(r) > 1000 {
		return nil, problem.Validation("The request is invalid.",
			problem.Field("reason", "required", "a reason (1–1000 characters) is required: the approver reads it"))
	}
	minutes := int(console.DefaultDuration.Minutes())
	if req.Body.DurationMinutes != nil {
		minutes = *req.Body.DurationMinutes
	}
	cidr := ""
	if req.Body.SourceCidr != nil {
		cidr = *req.Body.SourceCidr
	} else {
		c, err := console.DefaultCIDR(httpapi.ClientIP(ctx))
		if err != nil {
			return nil, problem.Validation("The request is invalid.",
				problem.Field("source_cidr", "required", "the client address is unknown: name the source network"))
		}
		cidr = c
	}
	p := console.Payload{IdentityID: s.IdentityID, SourceCIDR: cidr, DurationMinutes: minutes}
	if _, err := console.ParseCIDR(cidr); err != nil {
		return nil, problem.Validation("The request is invalid.", problem.Field("source_cidr", "invalid_format", err.Error()))
	}
	if err := p.Validate(); err != nil {
		return nil, problem.Validation("The request is invalid.", problem.Field("duration_minutes", "out_of_range", err.Error()))
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	r, err := h.appr.RequestIdempotent(ctx, approvals.Actor{IdentityID: s.IdentityID, Scope: authz.ScopePlatform,
		AuthTime: s.AuthTime}, approvals.NewRequest{Action: console.Action, ResourceID: s.IdentityID.String(), Payload: p,
		Reason: req.Body.Reason}, approvals.Idempotency{Operation: requestOperation, Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/platform/idp-console/sessions", body)})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.RequestIdpConsoleSession202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.RequestIdpConsoleSession202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

// ListIdpConsoleSessions implements GET /platform/idp-console/sessions: the requests of action
// platform.idp.console_session, newest first, as console sessions.
func (h *Handlers) ListIdpConsoleSessions(ctx context.Context, req gen.ListIdpConsoleSessionsRequestObject) (gen.ListIdpConsoleSessionsResponseObject, error) {
	f := approvals.Filter{Action: console.Action}
	if req.Params.Limit != nil {
		f.Limit = *req.Params.Limit
		if f.Limit == 0 {
			f.Limit = -1 // an explicit 0 is out of range, not "the default"
		}
	}
	if req.Params.Cursor != nil {
		f.Cursor = *req.Params.Cursor
	}
	page, err := h.appr.List(ctx, approvals.Ref{Scope: authz.ScopePlatform}, f)
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	now := h.now()
	out := gen.IdpConsoleSessionList{Items: make([]gen.IdpConsoleSession, 0, len(page.Items))}
	for _, r := range page.Items {
		sess, ok := console.SessionOf(r.Status, r.Payload, r.DecidedAt, now)
		if !ok {
			continue // a payload that no longer decodes is no session (the approval itself stays readable)
		}
		item := gen.IdpConsoleSession{Id: r.ID, Status: gen.IdpConsoleSessionStatus(sess.Status),
			RequestedBy: gen.IdentityRef{IdentityId: r.RequestedBy.IdentityID, DisplayName: r.RequestedBy.Display},
			SourceCidr:  sess.Payload.SourceCIDR, DurationMinutes: sess.Payload.DurationMinutes, CreatedAt: r.CreatedAt,
			StartsAt: sess.StartsAt, EndsAt: sess.EndsAt}
		if r.DecidedBy != nil && (r.Status == approvals.StatusExecuted || r.Status == approvals.StatusApproved) {
			item.ApprovedBy = &gen.IdentityRef{IdentityId: r.DecidedBy.IdentityID, DisplayName: r.DecidedBy.Display}
		}
		if r.Reason != "" {
			reason := r.Reason
			item.Reason = &reason
		}
		out.Items = append(out.Items, item)
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListIdpConsoleSessions200JSONResponse(out), nil
}
