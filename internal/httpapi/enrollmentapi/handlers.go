// Package enrollmentapi serves the operations of api/openapi.yaml built by P4-T06 (httpapi.EnrollmentHandlers):
// listEnrollmentRequests, getEnrollmentRequest, getEnrollmentInstructions (`tenant.enrollment:read` — End User: own),
// createEnrollmentRequest, startEnrollmentRequest, claimEnrollmentWebAuth (`tenant.enrollment:request` — End User only
// when the tenant allows self-enrolment: condition self_enroll), approveEnrollmentRequest, rejectEnrollmentRequest
// (`tenant.enrollment:approve`), revokeEnrollmentRequest (`tenant.enrollment:revoke` — End User: own),
// createEnrollmentKey (`tenant.enrollment:issue_privileged`). It translates between the generated types and
// internal/enrollment, which takes every decision; the only fact it adds is whether the caller may approve (its request
// then skips the approval — §7.4), asked to the authorizer.
//
// Wiring (apps/internal/runner — api process):
//
//	svc, _ := enrollment.New(apiStore, enrollment.Config{Registry: reg, Vault: vault, Tags: policies.RequireTags})
//	httpapi.Handlers{…, Enrollment: enrollmentapi.New(svc, authorizer)}
package enrollmentapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/enrollment"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// Service is the part of *enrollment.Service the handlers use.
type Service interface {
	Create(ctx context.Context, tenantID uuid.UUID, a enrollment.Actor, in enrollment.NewRequest, idem *enrollment.Idempotency) (enrollment.Issue, error)
	CreateKey(ctx context.Context, tenantID uuid.UUID, a enrollment.Actor, in enrollment.NewKey, idem *enrollment.Idempotency) (enrollment.Issue, error)
	Get(ctx context.Context, tenantID, id uuid.UUID, a enrollment.Actor) (enrollment.Request, error)
	List(ctx context.Context, tenantID uuid.UUID, a enrollment.Actor, limit int, cursor, status string) (enrollment.Page, error)
	Approve(ctx context.Context, tenantID, id uuid.UUID, a enrollment.Actor) (enrollment.Request, error)
	Reject(ctx context.Context, tenantID, id uuid.UUID, a enrollment.Actor) (enrollment.Request, error)
	Start(ctx context.Context, tenantID, id uuid.UUID, a enrollment.Actor) (enrollment.Issue, error)
	Revoke(ctx context.Context, tenantID, id uuid.UUID, a enrollment.Actor) (enrollment.Request, error)
	Claim(ctx context.Context, tenantID uuid.UUID, a enrollment.Actor, in enrollment.Claim) (enrollment.Request, error)
	Instructions(ctx context.Context, tenantID uuid.UUID, os string) (enrollment.Instructions, error)
}

var _ Service = (*enrollment.Service)(nil)

// Authorizer answers whether the caller holds a permission in the tenant (*authz.Authorizer).
type Authorizer interface {
	Require(ctx context.Context, tenantID uuid.UUID, req authz.Requirement) (authz.Decision, error)
}

// PermApprove is the permission whose holders' own requests skip the approval (§7.4).
const PermApprove authz.Permission = "tenant.enrollment:approve"

// Handlers implements httpapi.EnrollmentHandlers.
type Handlers struct {
	svc  Service
	auth Authorizer
}

var _ httpapi.EnrollmentHandlers = (*Handlers)(nil)

// New returns the handler set of P4-T06; auth answers "may the caller approve" (nil: nobody skips the approval).
func New(svc Service, auth Authorizer) *Handlers { return &Handlers{svc: svc, auth: auth} }

var errNoDecision = errors.New("enrollmentapi: no session or decision in the request context (hooks missing)")

// actorOf is the caller: identity, Portal session, membership and the obligations of the decision.
func actorOf(ctx context.Context) (enrollment.Actor, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s == nil || d.MembershipID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return enrollment.Actor{}, problem.Internal(errNoDecision)
	}
	display := s.DisplayName
	if display == "" {
		display = s.Email
	}
	return enrollment.Actor{IdentityID: s.IdentityID, MembershipID: d.MembershipID, Display: display,
		ClientIP: httpapi.ClientIP(ctx), SessionID: s.PublicID, OwnOnly: d.OwnOnly,
		SelfEnrollOnly: d.Condition == authz.CondSelfEnroll}, nil
}

// canApprove asks the authorizer whether the caller holds tenant.enrollment:approve (a read-only requirement: the
// caller's own write was already decided).
func (h *Handlers) canApprove(ctx context.Context, tenantID uuid.UUID) bool {
	if h.auth == nil {
		return false
	}
	_, err := h.auth.Require(ctx, tenantID, authz.Requirement{Permission: PermApprove, ReadOnly: true})
	return err == nil
}

// failure maps an error of the module to its Problem (the reason reaches the audit through the cause).
func failure(err error) error {
	if p, ok := problem.FromQuota(err); ok {
		p.Cause = err
		return p
	}
	e, ok := enrollment.AsError(err)
	if !ok {
		return problem.Internal(err)
	}
	cause := &authz.Denial{Kind: err, Reason: e.Reason}
	code := gen.ProblemCode(e.Code)
	if problem.Status(code) == http.StatusInternalServerError {
		return problem.Internal(err)
	}
	p := &problem.Error{Code: code, Detail: e.Detail, Cause: cause, RetryAfter: e.RetryAfter}
	if code == gen.ProblemCodeValidationFailed {
		field := e.Field
		if field == "" {
			field = "body"
		}
		p.Fields = []gen.FieldError{problem.Field(field, e.Reason, e.Detail)}
	}
	if p.Detail == "" {
		p.Detail = "The request could not be completed."
	}
	return p
}

func toRequest(r enrollment.Request) gen.EnrollmentRequest {
	out := gen.EnrollmentRequest{Id: r.ID, Method: gen.EnrollmentMethod(r.Method), Status: gen.EnrollmentRequestStatus(r.Status),
		DeviceLabel: r.DeviceLabel, Tags: r.Tags, Ephemeral: r.Ephemeral, Reusable: r.Reusable,
		RequestedByMembershipId: r.RequestedBy, TargetMembershipId: r.Target, ApproverMembershipId: r.Approver,
		ApprovedAt: r.ApprovedAt, IssuedAt: r.IssuedAt, CredentialExpiresAt: r.CredentialExpiresAt, ClaimedAt: r.ClaimedAt,
		FailureCode: r.FailureCode, LoginServer: r.LoginServer, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		Version: r.Version}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	if r.NodeID != nil {
		s := strconv.FormatInt(*r.NodeID, 10)
		out.NodeId = &s
	}
	return out
}

func toIssue(i enrollment.Issue) gen.EnrollmentIssue {
	out := gen.EnrollmentIssue{Request: toRequest(i.Request)}
	if c := i.Credential; c != nil {
		gc := &gen.EnrollmentCredential{Kind: gen.EnrollmentCredentialKind(c.Kind), Command: c.Command, ExpiresAt: c.ExpiresAt}
		if c.Hostname != "" {
			h := c.Hostname
			gc.Hostname = &h
		}
		if !c.PreauthKey.IsZero() { // x-secret-once: the only place the key leaves the process
			k := c.PreauthKey.Reveal()
			gc.PreauthKey = &k
		}
		if !c.EnrollCode.IsZero() {
			k := c.EnrollCode.Reveal()
			gc.EnrollCode = &k
		}
		out.Credential = gc
	}
	return out
}

func idempotencyOf(method, path, key string, body any) (*enrollment.Idempotency, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	return &enrollment.Idempotency{Key: key, Hash: jobs.RequestHash(method, path, raw)}, nil
}

func noBody() error {
	return problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
}

// ListEnrollmentRequests implements GET /tenants/{tenantId}/enrollment/requests.
func (h *Handlers) ListEnrollmentRequests(ctx context.Context, req gen.ListEnrollmentRequestsRequestObject) (gen.ListEnrollmentRequestsResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	limit, cursor, status := 0, "", ""
	if p := req.Params.Limit; p != nil {
		limit = *p
		if limit == 0 {
			limit = -1
		}
	}
	if c := req.Params.Cursor; c != nil {
		cursor = *c
	}
	if s := req.Params.Status; s != nil {
		status = string(*s)
	}
	page, err := h.svc.List(ctx, req.TenantId, a, limit, cursor, status)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.EnrollmentRequestList{Items: make([]gen.EnrollmentRequest, 0, len(page.Items))}
	for _, r := range page.Items {
		out.Items = append(out.Items, toRequest(r))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListEnrollmentRequests200JSONResponse(out), nil
}

// CreateEnrollmentRequest implements POST /tenants/{tenantId}/enrollment/requests.
func (h *Handlers) CreateEnrollmentRequest(ctx context.Context, req gen.CreateEnrollmentRequestRequestObject) (gen.CreateEnrollmentRequestResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	idem, err := idempotencyOf("POST", "/tenants/"+req.TenantId.String()+"/enrollment/requests", req.Params.IdempotencyKey, req.Body)
	if err != nil {
		return nil, err
	}
	a.CanApprove = h.canApprove(ctx, req.TenantId)
	in := enrollment.NewRequest{Method: string(req.Body.Method), DeviceLabel: req.Body.DeviceLabel}
	if req.Body.TtlMinutes != nil {
		in.TTLMinutes = *req.Body.TtlMinutes
		if in.TTLMinutes == 0 {
			in.TTLMinutes = -1
		}
	}
	out, err := h.svc.Create(ctx, req.TenantId, a, in, idem)
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreateEnrollmentRequest201JSONResponse(toIssue(out)), nil
}

// GetEnrollmentRequest implements GET /tenants/{tenantId}/enrollment/requests/{enrollmentRequestId}.
func (h *Handlers) GetEnrollmentRequest(ctx context.Context, req gen.GetEnrollmentRequestRequestObject) (gen.GetEnrollmentRequestResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Get(ctx, req.TenantId, req.EnrollmentRequestId, a)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetEnrollmentRequest200JSONResponse(toRequest(r)), nil
}

// ApproveEnrollmentRequest implements POST …/enrollment/requests/{enrollmentRequestId}/approve.
func (h *Handlers) ApproveEnrollmentRequest(ctx context.Context, req gen.ApproveEnrollmentRequestRequestObject) (gen.ApproveEnrollmentRequestResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Approve(ctx, req.TenantId, req.EnrollmentRequestId, a)
	if err != nil {
		return nil, failure(err)
	}
	return gen.ApproveEnrollmentRequest200JSONResponse(toRequest(r)), nil
}

// RejectEnrollmentRequest implements POST …/enrollment/requests/{enrollmentRequestId}/reject.
func (h *Handlers) RejectEnrollmentRequest(ctx context.Context, req gen.RejectEnrollmentRequestRequestObject) (gen.RejectEnrollmentRequestResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Reject(ctx, req.TenantId, req.EnrollmentRequestId, a)
	if err != nil {
		return nil, failure(err)
	}
	return gen.RejectEnrollmentRequest200JSONResponse(toRequest(r)), nil
}

// StartEnrollmentRequest implements POST …/enrollment/requests/{enrollmentRequestId}/start.
func (h *Handlers) StartEnrollmentRequest(ctx context.Context, req gen.StartEnrollmentRequestRequestObject) (gen.StartEnrollmentRequestResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.svc.Start(ctx, req.TenantId, req.EnrollmentRequestId, a)
	if err != nil {
		return nil, failure(err)
	}
	return gen.StartEnrollmentRequest200JSONResponse(toIssue(out)), nil
}

// RevokeEnrollmentRequest implements POST …/enrollment/requests/{enrollmentRequestId}/revoke.
func (h *Handlers) RevokeEnrollmentRequest(ctx context.Context, req gen.RevokeEnrollmentRequestRequestObject) (gen.RevokeEnrollmentRequestResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Revoke(ctx, req.TenantId, req.EnrollmentRequestId, a)
	if err != nil {
		return nil, failure(err)
	}
	return gen.RevokeEnrollmentRequest200JSONResponse(toRequest(r)), nil
}

// CreateEnrollmentKey implements POST /tenants/{tenantId}/enrollment/keys.
func (h *Handlers) CreateEnrollmentKey(ctx context.Context, req gen.CreateEnrollmentKeyRequestObject) (gen.CreateEnrollmentKeyResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	idem, err := idempotencyOf("POST", "/tenants/"+req.TenantId.String()+"/enrollment/keys", req.Params.IdempotencyKey, req.Body)
	if err != nil {
		return nil, err
	}
	b := req.Body
	in := enrollment.NewKey{Target: b.TargetMembershipId, DeviceLabel: b.DeviceLabel}
	if b.Tags != nil {
		in.Tags = *b.Tags
	}
	if b.Reusable != nil {
		in.Reusable = *b.Reusable
	}
	if b.Ephemeral != nil {
		in.Ephemeral = *b.Ephemeral
	}
	if b.TtlMinutes != nil {
		in.TTLMinutes = *b.TtlMinutes
		if in.TTLMinutes == 0 {
			in.TTLMinutes = -1
		}
	}
	out, err := h.svc.CreateKey(ctx, req.TenantId, a, in, idem)
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreateEnrollmentKey201JSONResponse(toIssue(out)), nil
}

// ClaimEnrollmentWebAuth implements POST /tenants/{tenantId}/enrollment/web-auth/claim.
func (h *Handlers) ClaimEnrollmentWebAuth(ctx context.Context, req gen.ClaimEnrollmentWebAuthRequestObject) (gen.ClaimEnrollmentWebAuthResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	r, err := h.svc.Claim(ctx, req.TenantId, a, enrollment.Claim{AuthID: req.Body.AuthId, RequestID: req.Body.RequestId})
	if err != nil {
		return nil, failure(err)
	}
	return gen.ClaimEnrollmentWebAuth200JSONResponse(toRequest(r)), nil
}

// GetEnrollmentInstructions implements GET /tenants/{tenantId}/enrollment/instructions.
func (h *Handlers) GetEnrollmentInstructions(ctx context.Context, req gen.GetEnrollmentInstructionsRequestObject) (gen.GetEnrollmentInstructionsResponseObject, error) {
	in, err := h.svc.Instructions(ctx, req.TenantId, string(req.Params.Os))
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetEnrollmentInstructions200JSONResponse(gen.EnrollmentInstructions{Os: gen.EnrollmentOS(in.OS),
		LoginServer: in.LoginServer, Steps: in.Steps, WebAuthCommand: in.WebAuthCommand,
		PreauthKeyCommand: in.PreauthKeyCommand, PrivacyNotice: in.PrivacyNotice, ManagedEnv: in.ManagedEnv}), nil
}
