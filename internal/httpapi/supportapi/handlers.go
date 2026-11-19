// Package supportapi serves the Support Access Grant operations of api/openapi.yaml built by P4-T13 (§8.7,
// httpapi.SupportHandlers): the tenant side (listTenantSupportGrants, approveTenantSupportGrant,
// rejectTenantSupportGrant, revokeTenantSupportGrant) and the platform side (listPlatformSupportGrants,
// createSupportGrant, approveSupportGrantBreakglass, revokePlatformSupportGrant). It only translates between the
// generated types and internal/tenants, which takes every decision; layer 1 (authzhook) decided the route.
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Support: supportapi.New(tenantsService)}
package supportapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Service is the part of *tenants.Service the handlers use.
type Service interface {
	ListTenantSupportGrants(ctx context.Context, tenantID uuid.UUID, f tenants.SupportGrantFilter) (tenants.SupportGrantPage, error)
	ListPlatformSupportGrants(ctx context.Context, f tenants.SupportGrantFilter) (tenants.SupportGrantPage, error)
	RequestSupportGrant(ctx context.Context, a tenants.StaffActor, in tenants.SupportGrantCreate, idem *tenants.SupportIdempotency) (tenants.SupportGrant, error)
	DecideTenantSupportGrant(ctx context.Context, a tenants.Actor, tenantID, id uuid.UUID, approve bool) (tenants.SupportGrant, error)
	RevokeTenantSupportGrant(ctx context.Context, a tenants.Actor, tenantID, id uuid.UUID) (tenants.SupportGrant, error)
	ApproveBreakGlass(ctx context.Context, a tenants.StaffActor, id uuid.UUID) (tenants.SupportGrant, error)
	RevokePlatformSupportGrant(ctx context.Context, a tenants.StaffActor, id uuid.UUID) (tenants.SupportGrant, error)
}

var _ Service = (*tenants.Service)(nil)

// Handlers implements httpapi.SupportHandlers.
type Handlers struct{ svc Service }

var _ httpapi.SupportHandlers = (*Handlers)(nil)

// New returns the handler set of P4-T13.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

var errNoDecision = errors.New("supportapi: no session or decision in the request context (hooks missing)")

func session(ctx context.Context) (*identity.Session, authz.Decision, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s == nil || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return nil, authz.Decision{}, problem.Internal(errNoDecision)
	}
	return s, d, nil
}

// staff is the caller of a platform operation (never decided with a tenant).
func staff(ctx context.Context) (tenants.StaffActor, error) {
	s, d, err := session(ctx)
	if err != nil {
		return tenants.StaffActor{}, err
	}
	if d.TenantID != uuid.Nil || d.PlatformUserID == uuid.Nil {
		return tenants.StaffActor{}, problem.Internal(errNoDecision)
	}
	return tenants.StaffActor{IdentityID: s.IdentityID, AuthTime: s.AuthTime}, nil
}

// member is the caller of a tenant decision: a membership of the tenant of the path (a support actor never decides —
// tenant.support_grant:decide is no cell of the Staff column).
func member(ctx context.Context, tenantID uuid.UUID) (tenants.Actor, error) {
	s, d, err := session(ctx)
	if err != nil {
		return tenants.Actor{}, err
	}
	if d.MembershipID == uuid.Nil || d.TenantID != tenantID || d.Support() {
		return tenants.Actor{}, problem.Internal(errNoDecision)
	}
	display := s.DisplayName
	if display == "" {
		display = s.Email
	}
	return tenants.Actor{IdentityID: s.IdentityID, MembershipID: d.MembershipID, AuthTime: s.AuthTime, Display: display}, nil
}

// details are the client texts of the refusals (by reason) — never a submitted value.
var details = map[string]string{
	tenants.ReasonGrantClosed:         "The grant was already decided, ended or its window is over.",
	tenants.ReasonGrantOpen:           "You already hold an open support access grant on this tenant.",
	tenants.ReasonGrantTenantClosed:   "The tenant is not open to support access (provisioning, being deprovisioned or failed).",
	tenants.ReasonAdminBreakGlassOnly: "The Support Admin role is granted only through break-glass by two Super Admins.",
	tenants.ReasonBreakGlassSelf:      "Break-glass needs a second Super Admin: not the requester, not the grantee.",
	tenants.ReasonBreakGlassRequester: "Break-glass needs a request made by an active Super Admin.",
	tenants.ReasonDeciderNotAllowed:   "You may not decide this grant.",
	tenants.ReasonNotPlatformUser:     "You are not an active platform user.",
}

// failure maps an error of the service to its problem; the reason travels as the cause (an authz.Denial — the audit
// middleware records it, the client never sees it).
func failure(err error) error {
	var ae *tenants.AdminError
	kind, reason, field := err, "", ""
	if errors.As(err, &ae) {
		kind, reason, field = ae.Kind, ae.Reason, ae.Field
	}
	cause := &authz.Denial{Kind: err, Reason: reason}
	p := func(code gen.ProblemCode, def string) error {
		detail, ok := details[reason]
		if !ok {
			detail = def
		}
		return &problem.Error{Code: code, Detail: detail, Cause: cause}
	}
	switch {
	case errors.Is(kind, tenants.ErrNotFound):
		return p(gen.ProblemCodeNotFound, "The resource does not exist.")
	case errors.Is(kind, tenants.ErrInvalid):
		if field == "" {
			field = "body"
		}
		v := problem.Validation("The request is invalid.", problem.Field(field, reason, "has an invalid value"))
		v.Cause = cause
		return v
	case errors.Is(kind, tenants.ErrForbidden):
		return p(gen.ProblemCodeForbidden, "The request is not allowed.")
	case errors.Is(kind, tenants.ErrReauthRequired):
		return p(gen.ProblemCodeReauthRequired, "This operation needs a recent sign-in: sign in again.")
	case errors.Is(kind, tenants.ErrIdempotencyKeyReuse):
		return p(gen.ProblemCodeIdempotencyKeyReuse, "The Idempotency-Key was used for another request.")
	case errors.Is(kind, tenants.ErrIdempotencyInProgress):
		return p(gen.ProblemCodeConflict, "A request with this Idempotency-Key is still in progress.")
	case errors.Is(kind, tenants.ErrConflict):
		return p(gen.ProblemCodeConflict, "The request conflicts with the current state.")
	}
	return problem.Internal(err)
}

func filter(limit *gen.Limit, cursor *gen.Cursor, status *gen.SupportGrantStatusFilter) tenants.SupportGrantFilter {
	f := tenants.SupportGrantFilter{}
	if limit != nil {
		f.Limit = *limit
		if f.Limit == 0 {
			f.Limit = -1 // an explicit 0 is out of range, not "the default"
		}
	}
	if cursor != nil {
		f.Cursor = *cursor
	}
	if status != nil {
		f.Status = string(*status)
	}
	return f
}

// toGrant maps a grant; DecidedBy only when the caller's side may see a name.
func toGrant(g tenants.SupportGrant) gen.SupportGrant {
	out := gen.SupportGrant{Id: g.ID, TenantId: g.TenantID, TenantSlug: g.TenantSlug,
		EffectiveRole: gen.SupportGrantRole(g.Role), Reason: g.Reason, TicketRef: g.TicketRef,
		Status: gen.SupportGrantStatus(g.Status), Active: g.Active, Grantee: gen.SupportGrantPerson{DisplayName: g.Grantee},
		DecidedAt: g.DecidedAt, StartsAt: g.StartsAt, ExpiresAt: g.ExpiresAt, RevokedAt: g.RevokedAt, CreatedAt: g.CreatedAt}
	if g.ApprovalKind != "" {
		k := gen.SupportGrantApprovalKind(g.ApprovalKind)
		out.ApprovalKind = &k
	}
	if g.DecidedBy != "" {
		out.DecidedBy = &gen.SupportGrantPerson{DisplayName: g.DecidedBy}
	}
	return out
}

func toList(p tenants.SupportGrantPage) gen.SupportGrantList {
	out := gen.SupportGrantList{Items: make([]gen.SupportGrant, 0, len(p.Items))}
	for _, g := range p.Items {
		out.Items = append(out.Items, toGrant(g))
	}
	if p.NextCursor != "" {
		c := p.NextCursor
		out.NextCursor = &c
	}
	return out
}

// ListTenantSupportGrants implements GET /tenants/{tenantId}/support-grants.
func (h *Handlers) ListTenantSupportGrants(ctx context.Context, req gen.ListTenantSupportGrantsRequestObject) (gen.ListTenantSupportGrantsResponseObject, error) {
	p, err := h.svc.ListTenantSupportGrants(ctx, req.TenantId, filter(req.Params.Limit, req.Params.Cursor, req.Params.Status))
	if err != nil {
		return nil, failure(err)
	}
	return gen.ListTenantSupportGrants200JSONResponse(toList(p)), nil
}

// ApproveTenantSupportGrant implements POST /tenants/{tenantId}/support-grants/{grantId}/approve.
func (h *Handlers) ApproveTenantSupportGrant(ctx context.Context, req gen.ApproveTenantSupportGrantRequestObject) (gen.ApproveTenantSupportGrantResponseObject, error) {
	a, err := member(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.DecideTenantSupportGrant(ctx, a, req.TenantId, req.GrantId, true)
	if err != nil {
		return nil, failure(err)
	}
	return gen.ApproveTenantSupportGrant200JSONResponse(toGrant(g)), nil
}

// RejectTenantSupportGrant implements POST /tenants/{tenantId}/support-grants/{grantId}/reject.
func (h *Handlers) RejectTenantSupportGrant(ctx context.Context, req gen.RejectTenantSupportGrantRequestObject) (gen.RejectTenantSupportGrantResponseObject, error) {
	a, err := member(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.DecideTenantSupportGrant(ctx, a, req.TenantId, req.GrantId, false)
	if err != nil {
		return nil, failure(err)
	}
	return gen.RejectTenantSupportGrant200JSONResponse(toGrant(g)), nil
}

// RevokeTenantSupportGrant implements POST /tenants/{tenantId}/support-grants/{grantId}/revoke.
func (h *Handlers) RevokeTenantSupportGrant(ctx context.Context, req gen.RevokeTenantSupportGrantRequestObject) (gen.RevokeTenantSupportGrantResponseObject, error) {
	a, err := member(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.RevokeTenantSupportGrant(ctx, a, req.TenantId, req.GrantId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.RevokeTenantSupportGrant200JSONResponse(toGrant(g)), nil
}

// ListPlatformSupportGrants implements GET /platform/support-grants.
func (h *Handlers) ListPlatformSupportGrants(ctx context.Context, req gen.ListPlatformSupportGrantsRequestObject) (gen.ListPlatformSupportGrantsResponseObject, error) {
	p, err := h.svc.ListPlatformSupportGrants(ctx, filter(req.Params.Limit, req.Params.Cursor, req.Params.Status))
	if err != nil {
		return nil, failure(err)
	}
	return gen.ListPlatformSupportGrants200JSONResponse(toList(p)), nil
}

// CreateSupportGrant implements POST /platform/support-grants (Idempotency-Key over method, path and body).
func (h *Handlers) CreateSupportGrant(ctx context.Context, req gen.CreateSupportGrantRequestObject) (gen.CreateSupportGrantResponseObject, error) {
	a, err := staff(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	g, err := h.svc.RequestSupportGrant(ctx, a, tenants.SupportGrantCreate{TenantID: req.Body.TenantId,
		Role: string(req.Body.EffectiveRole), Reason: req.Body.Reason, TicketRef: req.Body.TicketRef,
		DurationMinutes: req.Body.DurationMinutes}, &tenants.SupportIdempotency{Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/platform/support-grants", raw)})
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreateSupportGrant201JSONResponse(toGrant(g)), nil
}

// ApproveSupportGrantBreakglass implements POST /platform/support-grants/{grantId}/approve-breakglass: the dual control
// of the 2P cell is the grant itself (requester Super Admin + this second Super Admin) — the decision's DualControl
// obligation is honoured by the service refusing the requester and the grantee.
func (h *Handlers) ApproveSupportGrantBreakglass(ctx context.Context, req gen.ApproveSupportGrantBreakglassRequestObject) (gen.ApproveSupportGrantBreakglassResponseObject, error) {
	a, err := staff(ctx)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.ApproveBreakGlass(ctx, a, req.GrantId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.ApproveSupportGrantBreakglass200JSONResponse(toGrant(g)), nil
}

// RevokePlatformSupportGrant implements POST /platform/support-grants/{grantId}/revoke.
func (h *Handlers) RevokePlatformSupportGrant(ctx context.Context, req gen.RevokePlatformSupportGrantRequestObject) (gen.RevokePlatformSupportGrantResponseObject, error) {
	a, err := staff(ctx)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.RevokePlatformSupportGrant(ctx, a, req.GrantId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.RevokePlatformSupportGrant200JSONResponse(toGrant(g)), nil
}
