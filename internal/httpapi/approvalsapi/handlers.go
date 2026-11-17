// Package approvalsapi serves the dual-control operations of api/openapi.yaml built by P3-T04a
// (httpapi.ApprovalHandlers): listPlatformApprovals, getPlatformApproval, approvePlatformApproval,
// rejectPlatformApproval (platform scope, /platform/approvals) and listTenantApprovals, getTenantApproval,
// approveTenantApproval, rejectTenantApproval (tenant scope, /tenants/{tenantId}/approvals). It only translates between
// the generated types and internal/authz/approvals, which takes every decision.
//
// Layer 1 (authzhook) decided the route — :read or :decide in the scope of the path; for approvePlatformApproval and
// rejectPlatformApproval the operation declares x-conditions [restore_only], so a Platform Operator gets through with
// a conditional decision that the service enforces (restore requests only). The actor of the service comes from the
// session (identity and auth_time — the step-up of §8.3 step 7) and the decision (the grant's condition).
//
// Wiring (apps/internal/runner — api process):
//
//	svc, _ := approvals.New(apiStore, approvals.Config{Approvers: authz.New(apiStore), Registry: <registry>,
//		Security: auditLogger, Logger: log})
//	httpapi.Handlers{…, Approvals: approvalsapi.New(svc)}
package approvalsapi

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// Service is the part of *approvals.Service the handlers use.
type Service interface {
	List(ctx context.Context, ref approvals.Ref, f approvals.Filter) (approvals.Page, error)
	Get(ctx context.Context, ref approvals.Ref) (approvals.Request, error)
	Approve(ctx context.Context, actor approvals.Actor, ref approvals.Ref, reviewedSHA256 string) (approvals.Request, error)
	Reject(ctx context.Context, actor approvals.Actor, ref approvals.Ref) (approvals.Request, error)
}

var _ Service = (*approvals.Service)(nil)

// Handlers implements httpapi.ApprovalHandlers.
type Handlers struct{ svc Service }

var _ httpapi.ApprovalHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T04a.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

var errNoSession = errors.New("approvalsapi: no session or decision in the request context (hooks missing)")

// actor is the person deciding: the session's identity and auth_time, the condition of the layer-1 decision.
func actor(ctx context.Context) (approvals.Actor, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return approvals.Actor{}, problem.Internal(errNoSession)
	}
	return approvals.Actor{IdentityID: s.IdentityID, Scope: authz.Scope(s.Scope), AuthTime: s.AuthTime,
		Condition: d.Condition}, nil
}

func platformRef(id uuid.UUID) approvals.Ref {
	return approvals.Ref{Scope: authz.ScopePlatform, ID: id}
}

func tenantRef(tenantID, id uuid.UUID) approvals.Ref {
	return approvals.Ref{Scope: authz.ScopeTenant, TenantID: tenantID, ID: id}
}

// details are the client-facing texts of the refusals of the service — written here, never the reason.
var details = map[string]string{
	approvals.ReasonExpired:               "The approval request has expired; nothing was executed.",
	approvals.ReasonNotPending:            "The approval request is no longer pending.",
	approvals.ReasonExecuted:              "The approval request was already executed; it cannot be used again.",
	approvals.ReasonOtherApprover:         "The approval request was approved by another person.",
	approvals.ReasonActionUnavailable:     "This action cannot be executed by this version of the platform.",
	approvals.ReasonPayloadIntegrity:      "The stored parameters no longer match their hash; nothing was executed.",
	approvals.ReasonOpenRequest:           "An open approval request already exists for this action and resource.",
	approvals.ReasonInvalidPayload:        "The parameters of the request are not valid for its action.",
	approvals.ReasonPayloadChanged:        "The parameters differ from the ones you reviewed (payload_sha256); review the request again.",
	approvals.ReasonSelfDecision:          "A request cannot be decided by the person who made it.",
	approvals.ReasonDecideCondition:       "Your role cannot decide this kind of request.",
	approvals.ReasonIdempotencyInProgress: "A request with this Idempotency-Key is still in progress.",
}

// Failure maps an error of the approvals service to its problem — for the handler sets of the 2P operations that
// create requests (P3-T15 requestIdpConsoleSession…), with the same codes and texts as the approvals operations.
func Failure(err error) error { return failure(err) }

// View is schema ApprovalRequest of a request (the body of the 202 of a 2P operation).
func View(r approvals.Request) gen.ApprovalRequest { return toAPI(r) }

// failure maps an error of the service to its problem: the kind fixes the code, the reason picks a fixed detail and
// travels as an authz.Denial cause — the audit middleware records it as the reason, the client never sees it.
func failure(err error) error {
	var d *authz.Denial
	if errors.As(err, &d) {
		return authzhook.Problem(err)
	}
	var e *approvals.Error
	if !errors.As(err, &e) {
		return problem.Internal(err)
	}
	cause := &authz.Denial{Kind: e.Kind, Reason: e.Reason}
	var code gen.ProblemCode
	switch {
	case errors.Is(e.Kind, approvals.ErrNotFound):
		code = gen.ProblemCodeNotFound
	case errors.Is(e.Kind, approvals.ErrForbidden):
		code = gen.ProblemCodeForbidden
	case errors.Is(e.Kind, approvals.ErrReauthRequired):
		return &problem.Error{Code: gen.ProblemCodeReauthRequired, Cause: cause,
			Detail: "This action requires a recent sign-in; sign in again and retry."}
	case errors.Is(e.Kind, approvals.ErrPayloadChanged):
		code = gen.ProblemCodePreconditionFailed
	case errors.Is(e.Kind, approvals.ErrConflict), errors.Is(e.Kind, approvals.ErrUnavailable):
		code = gen.ProblemCodeConflict
	case errors.Is(e.Kind, approvals.ErrInvalid) && e.Reason == approvals.ReasonIdempotencyKeyReuse:
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(e.Kind, approvals.ErrInvalid):
		return &problem.Error{Code: gen.ProblemCodeValidationFailed, Cause: cause, Detail: "The request is invalid.",
			Fields: []gen.FieldError{problem.Field("request", e.Reason, "the request parameters are invalid")}}
	default:
		return problem.Internal(err)
	}
	detail, ok := details[e.Reason]
	if !ok {
		detail = map[gen.ProblemCode]string{gen.ProblemCodeNotFound: "The resource does not exist.",
			gen.ProblemCodeForbidden: "The request is not allowed."}[code]
	}
	return &problem.Error{Code: code, Detail: detail, Cause: cause, RetryAfter: e.RetryAfter}
}

func filterOf(limit *gen.Limit, cursor *gen.Cursor, status *gen.ApprovalStatusFilter, action *gen.ApprovalActionFilter) approvals.Filter {
	var f approvals.Filter
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
	if action != nil {
		f.Action = *action
	}
	return f
}

func list(p approvals.Page) gen.ApprovalList {
	out := gen.ApprovalList{Items: make([]gen.ApprovalRequest, 0, len(p.Items))}
	for _, r := range p.Items {
		out.Items = append(out.Items, toAPI(r))
	}
	if p.NextCursor != "" {
		c := p.NextCursor
		out.NextCursor = &c
	}
	return out
}

// toAPI is schema ApprovalRequest: the payload in canonical form — exactly what will be executed — and its hash.
func toAPI(r approvals.Request) gen.ApprovalRequest {
	out := gen.ApprovalRequest{
		Id: r.ID, Scope: gen.ApprovalRequestScope(r.Scope), Action: r.Action, ResourceType: r.ResourceType,
		Payload: r.Payload, PayloadSha256: r.PayloadSHA256, Status: gen.ApprovalStatus(r.Status),
		RequestedBy: gen.IdentityRef{IdentityId: r.RequestedBy.IdentityID, DisplayName: r.RequestedBy.Display},
		DecidedAt:   r.DecidedAt, ExpiresAt: r.ExpiresAt, JobId: r.JobID, CreatedAt: r.CreatedAt,
	}
	if r.ResourceID != "" {
		id := r.ResourceID
		out.ResourceId = &id
	}
	if r.Reason != "" {
		reason := r.Reason
		out.Reason = &reason
	}
	if r.DecidedBy != nil {
		out.DecidedBy = &gen.IdentityRef{IdentityId: r.DecidedBy.IdentityID, DisplayName: r.DecidedBy.Display}
	}
	return out
}

func reviewed(body *gen.ApprovalDecision) (string, error) {
	if body == nil || !approvals.ValidHash(body.PayloadSha256) {
		return "", problem.Validation("The request body is invalid.",
			problem.Field("payload_sha256", "invalid_format", "must be the 64 hex digits of the reviewed payload hash"))
	}
	return body.PayloadSha256, nil
}

// ListPlatformApprovals implements GET /platform/approvals.
func (h *Handlers) ListPlatformApprovals(ctx context.Context, req gen.ListPlatformApprovalsRequestObject) (gen.ListPlatformApprovalsResponseObject, error) {
	p := req.Params
	page, err := h.svc.List(ctx, platformRef(uuid.Nil), filterOf(p.Limit, p.Cursor, p.Status, p.Action))
	if err != nil {
		return nil, failure(err)
	}
	return gen.ListPlatformApprovals200JSONResponse(list(page)), nil
}

// GetPlatformApproval implements GET /platform/approvals/{approvalId}.
func (h *Handlers) GetPlatformApproval(ctx context.Context, req gen.GetPlatformApprovalRequestObject) (gen.GetPlatformApprovalResponseObject, error) {
	r, err := h.svc.Get(ctx, platformRef(req.ApprovalId))
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetPlatformApproval200JSONResponse(toAPI(r)), nil
}

// ApprovePlatformApproval implements POST /platform/approvals/{approvalId}/approve.
func (h *Handlers) ApprovePlatformApproval(ctx context.Context, req gen.ApprovePlatformApprovalRequestObject) (gen.ApprovePlatformApprovalResponseObject, error) {
	a, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	sum, err := reviewed(req.Body)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Approve(ctx, a, platformRef(req.ApprovalId), sum)
	if err != nil {
		return nil, failure(err)
	}
	return gen.ApprovePlatformApproval200JSONResponse(toAPI(r)), nil
}

// RejectPlatformApproval implements POST /platform/approvals/{approvalId}/reject.
func (h *Handlers) RejectPlatformApproval(ctx context.Context, req gen.RejectPlatformApprovalRequestObject) (gen.RejectPlatformApprovalResponseObject, error) {
	a, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Reject(ctx, a, platformRef(req.ApprovalId))
	if err != nil {
		return nil, failure(err)
	}
	return gen.RejectPlatformApproval200JSONResponse(toAPI(r)), nil
}

// ListTenantApprovals implements GET /tenants/{tenantId}/approvals.
func (h *Handlers) ListTenantApprovals(ctx context.Context, req gen.ListTenantApprovalsRequestObject) (gen.ListTenantApprovalsResponseObject, error) {
	p := req.Params
	page, err := h.svc.List(ctx, tenantRef(req.TenantId, uuid.Nil), filterOf(p.Limit, p.Cursor, p.Status, p.Action))
	if err != nil {
		return nil, failure(err)
	}
	return gen.ListTenantApprovals200JSONResponse(list(page)), nil
}

// GetTenantApproval implements GET /tenants/{tenantId}/approvals/{approvalId}.
func (h *Handlers) GetTenantApproval(ctx context.Context, req gen.GetTenantApprovalRequestObject) (gen.GetTenantApprovalResponseObject, error) {
	r, err := h.svc.Get(ctx, tenantRef(req.TenantId, req.ApprovalId))
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetTenantApproval200JSONResponse(toAPI(r)), nil
}

// ApproveTenantApproval implements POST /tenants/{tenantId}/approvals/{approvalId}/approve.
func (h *Handlers) ApproveTenantApproval(ctx context.Context, req gen.ApproveTenantApprovalRequestObject) (gen.ApproveTenantApprovalResponseObject, error) {
	a, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	sum, err := reviewed(req.Body)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Approve(ctx, a, tenantRef(req.TenantId, req.ApprovalId), sum)
	if err != nil {
		return nil, failure(err)
	}
	return gen.ApproveTenantApproval200JSONResponse(toAPI(r)), nil
}

// RejectTenantApproval implements POST /tenants/{tenantId}/approvals/{approvalId}/reject.
func (h *Handlers) RejectTenantApproval(ctx context.Context, req gen.RejectTenantApprovalRequestObject) (gen.RejectTenantApprovalResponseObject, error) {
	a, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Reject(ctx, a, tenantRef(req.TenantId, req.ApprovalId))
	if err != nil {
		return nil, failure(err)
	}
	return gen.RejectTenantApproval200JSONResponse(toAPI(r)), nil
}
