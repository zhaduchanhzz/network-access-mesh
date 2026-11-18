// Package deprovisionapi serves the deletion of a tenant built by P3-T09 (httpapi.DeprovisionHandlers):
// deletePlatformTenant — DELETE /platform/tenants/{tenantId} (platform.tenant:delete, always dual control — §8.5,
// §13.2). The request is checked by internal/provisioning/deprovision (the tenant can be deprovisioned, the typed slug
// is its slug) and turned into an approval request of action platform.tenant.delete through
// internal/authz/approvals: 202 + Location of /platform/approvals/{id}. The approved payload ({tenant_id, slug,
// skip_final_backup}) is the only input of the tenant.deprovision job, enqueued when a second Super Admin approves
// (the action apps/internal/runner registers). It never imports internal/store (§13.6).
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Deprovision: deprovisionapi.New(deprovision.NewRequester(store), approvalsService)}
package deprovisionapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/deprovision"
)

// Requester is the part of *deprovision.Requester the handler uses.
type Requester interface {
	Check(ctx context.Context, tenantID uuid.UUID, confirmSlug string, skipFinalBackup bool) (deprovision.Payload, error)
}

// Approvals is the part of *approvals.Service the request uses.
type Approvals interface {
	RequestIdempotent(ctx context.Context, actor approvals.Actor, in approvals.NewRequest, idem approvals.Idempotency) (approvals.Request, error)
}

var (
	_ Requester = (*deprovision.Requester)(nil)
	_ Approvals = (*approvals.Service)(nil)
)

// Handlers implements httpapi.DeprovisionHandlers.
type Handlers struct {
	req  Requester
	appr Approvals
}

var _ httpapi.DeprovisionHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T09.
func New(req Requester, appr Approvals) *Handlers { return &Handlers{req: req, appr: appr} }

var errNoSession = errors.New("deprovisionapi: no session or platform decision in the request context (hooks missing)")

// DeletePlatformTenant implements DELETE /platform/tenants/{tenantId}: always a 2P request.
func (h *Handlers) DeletePlatformTenant(ctx context.Context, req gen.DeletePlatformTenantRequestObject) (gen.DeletePlatformTenantResponseObject, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID || d.TenantID != uuid.Nil {
		return nil, problem.Internal(errNoSession)
	}
	if !d.NeedsApproval() { // x-dual-control: never run directly (§8.5)
		return nil, problem.Internal(errors.New("deprovisionapi: the decision does not require a second approver"))
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	if r := strings.TrimSpace(req.Body.Reason); r == "" || utf8.RuneCountInString(r) > 1000 {
		return nil, problem.Validation("The request is invalid.",
			problem.Field("reason", "required", "a reason (1–1000 characters) is required: the approver reads it"))
	}
	skip := req.Body.SkipFinalBackup != nil && *req.Body.SkipFinalBackup
	p, err := h.req.Check(ctx, req.TenantId, strings.TrimSpace(req.Body.ConfirmSlug), skip)
	if err != nil {
		return nil, failure(err)
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	r, err := h.appr.RequestIdempotent(ctx, approvals.Actor{IdentityID: s.IdentityID, Scope: authz.ScopePlatform, AuthTime: s.AuthTime},
		approvals.NewRequest{Action: deprovision.Action, ResourceID: req.TenantId.String(), Payload: p, Reason: req.Body.Reason},
		approvals.Idempotency{Operation: deprovision.Operation, Key: req.Params.IdempotencyKey,
			Hash: jobs.RequestHash("DELETE", "/platform/tenants/"+req.TenantId.String(), body)})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.DeletePlatformTenant202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.DeletePlatformTenant202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

// failure maps a refusal of the deprovision check to a problem (the Cause carries a stable reason for the audit).
func failure(err error) error {
	var re *deprovision.RequestError
	if !errors.As(err, &re) {
		return problem.Internal(err)
	}
	cause := &authz.Denial{Kind: err, Reason: re.Reason}
	switch {
	case errors.Is(err, deprovision.ErrNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, deprovision.ErrInvalid):
		return problem.Validation("The request is invalid.", problem.Field("confirm_slug", re.Reason,
			"must be the slug of the tenant to delete"))
	}
	detail := map[string]string{
		deprovision.ReasonDeleted:          "The tenant is already deleted.",
		deprovision.ReasonInProgress:       "The tenant is already being deprovisioned.",
		deprovision.ReasonNotDeprovisioned: "The tenant is not active, suspended or failed: finish or roll back its provisioning first.",
		deprovision.ReasonLifecycleJob:     "Another lifecycle job of the tenant is unfinished.",
		deprovision.ReasonQuarantined:      "The instance is quarantined: no final backup can be taken (release it, or skip the final backup).",
	}[re.Reason]
	if detail == "" {
		detail = "The tenant's state does not allow a deprovision."
	}
	return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
}
