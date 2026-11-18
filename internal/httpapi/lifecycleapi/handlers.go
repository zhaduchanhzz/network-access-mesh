// Package lifecycleapi serves the suspension of a tenant built by P3-T08 (httpapi.LifecycleHandlers):
// suspendPlatformTenant and resumePlatformTenant (POST /platform/tenants/{tenantId}/suspend, /resume —
// platform.tenant:suspend, §8.5). It translates between the generated types and internal/provisioning/lifecycle, which
// checks the tenant's state and enqueues tenant.suspend / tenant.resume in the api's platform transaction with the
// audit event platform.tenant.<suspend|resume>.requested. It never imports internal/store (§13.6).
//
// The refusal of the tenant's own writes while it is suspended (§8.4 invariant 5) is not here: it is the decision of
// layer 1 (internal/authz, through the Authz hook of every operation), driven by the operation table generated from
// the spec — no handler has to remember it.
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Lifecycle: lifecycleapi.New(lifecycle.NewRequester(store))}
package lifecycleapi

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
)

// Requester is the part of *lifecycle.Requester the handlers use.
type Requester interface {
	Suspend(ctx context.Context, actor, tenantID uuid.UUID, idem *lifecycle.Idempotency) (lifecycle.Requested, error)
	Resume(ctx context.Context, actor, tenantID uuid.UUID, idem *lifecycle.Idempotency) (lifecycle.Requested, error)
}

var _ Requester = (*lifecycle.Requester)(nil)

// Handlers implements httpapi.LifecycleHandlers.
type Handlers struct {
	req Requester
}

var _ httpapi.LifecycleHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T08.
func New(req Requester) *Handlers { return &Handlers{req: req} }

var (
	errNoDecision    = errors.New("lifecycleapi: no session or authorization decision in the request context (hooks missing)")
	errWrongDecision = errors.New("lifecycleapi: the authorization decision does not cover a platform route")
)

// actor is the platform staff member calling: the identity of the session, under a platform decision.
func actor(ctx context.Context) (uuid.UUID, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	switch {
	case !ok || !okd || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID:
		return uuid.Nil, problem.Internal(errNoDecision)
	case d.TenantID != uuid.Nil:
		return uuid.Nil, problem.Internal(errWrongDecision)
	}
	return s.IdentityID, nil
}

// JobLocation is the Location of a job for a caller of platform scope (§13.1 "Thao tác dài").
func JobLocation(id uuid.UUID) string { return "/api/v1/platform/jobs/" + id.String() }

// SuspendPlatformTenant implements POST /platform/tenants/{tenantId}/suspend: 202 + the tenant.suspend job.
func (h *Handlers) SuspendPlatformTenant(ctx context.Context, req gen.SuspendPlatformTenantRequestObject) (gen.SuspendPlatformTenantResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.req.Suspend(ctx, who, req.TenantId, idem("suspend", req.TenantId, req.Params.IdempotencyKey))
	if err != nil {
		return nil, failure(err)
	}
	if !out.Changed {
		markNoChange(ctx)
	}
	return gen.SuspendPlatformTenant202JSONResponse{Body: jobsapi.ToAPI(out.Job),
		Headers: gen.SuspendPlatformTenant202ResponseHeaders{Location: JobLocation(out.Job.ID)}}, nil
}

// ResumePlatformTenant implements POST /platform/tenants/{tenantId}/resume: 202 + the tenant.resume job.
func (h *Handlers) ResumePlatformTenant(ctx context.Context, req gen.ResumePlatformTenantRequestObject) (gen.ResumePlatformTenantResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.req.Resume(ctx, who, req.TenantId, idem("resume", req.TenantId, req.Params.IdempotencyKey))
	if err != nil {
		return nil, failure(err)
	}
	if !out.Changed {
		markNoChange(ctx)
	}
	return gen.ResumePlatformTenant202JSONResponse{Body: jobsapi.ToAPI(out.Job),
		Headers: gen.ResumePlatformTenant202ResponseHeaders{Location: JobLocation(out.Job.ID)}}, nil
}

// idem is the Idempotency-Key of a request: no body, the path names the tenant and the action.
func idem(action string, tenant uuid.UUID, key string) *lifecycle.Idempotency {
	return &lifecycle.Idempotency{Key: key, Hash: jobs.RequestHash("POST", "/platform/tenants/"+tenant.String()+"/"+action, nil)}
}

// markNoChange: a replayed request, or the job already in flight, writes no event — tell the audit middleware it is
// not a gap (a write that succeeded without an event).
func markNoChange(ctx context.Context) {
	if r := audit.RequestFrom(ctx); r != nil {
		r.ReadOnly = true
	}
}

// conflictDetail is the client-facing text of each conflict reason.
var conflictDetail = map[string]string{
	lifecycle.ReasonAlreadySuspended:   "The tenant is already suspended.",
	lifecycle.ReasonNotSuspended:       "The tenant is not suspended.",
	lifecycle.ReasonNotActive:          "Only an active tenant can be suspended.",
	lifecycle.ReasonNotSuspendable:     "Only a suspended tenant can be resumed.",
	lifecycle.ReasonNoPolicy:           "The tenant has no desired policy version to restore on resume.",
	lifecycle.ReasonLifecycleJobActive: "Another lifecycle job of the tenant is not finished.",
}

// failure maps an error of the lifecycle module to a problem (the Cause carries a stable reason for the audit).
func failure(err error) error {
	reason := "conflict"
	var re *lifecycle.RequestError
	if errors.As(err, &re) {
		reason = re.Reason
	}
	cause := &authz.Denial{Kind: err, Reason: reason}
	switch {
	case errors.Is(err, lifecycle.ErrNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, lifecycle.ErrIdempotencyInProgress):
		p := &problem.Error{Code: gen.ProblemCodeConflict, Cause: cause,
			Detail: "A request with this Idempotency-Key is still in progress."}
		if re != nil {
			p.RetryAfter = re.RetryAfter
		}
		return p
	case errors.Is(err, lifecycle.ErrIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, lifecycle.ErrConflict):
		detail := conflictDetail[reason]
		if detail == "" {
			detail = "The request conflicts with the tenant's state."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	}
	return problem.Internal(err)
}
