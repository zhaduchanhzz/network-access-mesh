// Package provisioningapi serves the operations of the Tenant Orchestrator built by P3-T05
// (httpapi.ProvisioningHandlers): createPlatformTenant (POST /platform/tenants — platform.tenant:create) and
// retryPlatformJob, cancelPlatformJob, rollbackPlatformJob (POST /platform/jobs/{jobId}/<action> —
// platform.job:control). It translates between the generated types and internal/provisioning/orchestrator, which runs
// steps 1–2 of tenant.provision and the job controls in the api's platform transactions; every write records its audit
// event there (platform.tenant.create.requested, platform.job.<action>). It never imports internal/store (§13.6).
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Provisioning: provisioningapi.New(creator, control)}
package provisioningapi

import (
	"context"
	"encoding/json"
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
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
)

// Creator is the part of *orchestrator.Creator the handlers use.
type Creator interface {
	Create(ctx context.Context, actor uuid.UUID, req orchestrator.CreateRequest, idem *orchestrator.Idempotency) (orchestrator.Created, error)
}

// Control is the part of *orchestrator.Control the handlers use.
type Control interface {
	Retry(ctx context.Context, actor, jobID uuid.UUID, idem *orchestrator.Idempotency) (orchestrator.ControlResult, error)
	Cancel(ctx context.Context, actor, jobID uuid.UUID, idem *orchestrator.Idempotency) (orchestrator.ControlResult, error)
	Rollback(ctx context.Context, actor, jobID uuid.UUID, idem *orchestrator.Idempotency) (orchestrator.ControlResult, error)
}

var (
	_ Creator = (*orchestrator.Creator)(nil)
	_ Control = (*orchestrator.Control)(nil)
)

// Handlers implements httpapi.ProvisioningHandlers.
type Handlers struct {
	creator Creator
	control Control
}

var _ httpapi.ProvisioningHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T05.
func New(creator Creator, control Control) *Handlers {
	return &Handlers{creator: creator, control: control}
}

var (
	errNoDecision    = errors.New("provisioningapi: no session or authorization decision in the request context (hooks missing)")
	errWrongDecision = errors.New("provisioningapi: the authorization decision does not cover a platform route")
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

// CreatePlatformTenant implements POST /platform/tenants: 202 + the job (steps 1–2 done, 3–19 queued).
func (h *Handlers) CreatePlatformTenant(ctx context.Context, req gen.CreatePlatformTenantRequestObject) (gen.CreatePlatformTenantResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	b := req.Body
	cr := orchestrator.CreateRequest{Slug: b.Slug, Name: b.Name, PlanKey: b.PlanKey, OwnerEmail: string(b.OwnerEmail),
		IdP: orchestrator.IdPRequest{Driver: string(b.IdentityProvider.Driver)}}
	if b.DeploymentRegion != nil {
		cr.DeploymentRegion = *b.DeploymentRegion
	}
	if b.Settings != nil {
		if cr.Settings, err = json.Marshal(*b.Settings); err != nil {
			return nil, problem.Internal(err)
		}
	}
	p := b.IdentityProvider
	if p.Issuer != nil {
		cr.IdP.Issuer = *p.Issuer
	}
	if p.ClientId != nil {
		cr.IdP.ClientID = *p.ClientId
	}
	if p.ClientSecret != nil {
		cr.IdP.ClientSecret = []byte(*p.ClientSecret)
		defer clear(cr.IdP.ClientSecret)
	}
	if p.RequiredClaims != nil {
		cr.IdP.RequiredClaims = *p.RequiredClaims
	}
	if p.AllowedEmailDomains != nil {
		cr.IdP.AllowedEmailDomains = *p.AllowedEmailDomains
	}
	hash, err := requestHash(b)
	if err != nil {
		return nil, problem.Internal(err)
	}
	out, err := h.creator.Create(ctx, who, cr, &orchestrator.Idempotency{Key: req.Params.IdempotencyKey, Hash: hash})
	if err != nil {
		return nil, failure(err)
	}
	if out.Replayed {
		markNoChange(ctx) // the stored answer of the first request: nothing written now
	}
	return gen.CreatePlatformTenant202JSONResponse{Body: jobsapi.ToAPI(out.Job),
		Headers: gen.CreatePlatformTenant202ResponseHeaders{Location: JobLocation(out.Job.ID)}}, nil
}

// requestHash is the Idempotency-Key hash of POST /platform/tenants: method, path and the canonical body WITHOUT the
// write-only client secret (orchestrator.RequestBodyForHash) — no secret, not even its hash, is kept.
func requestHash(b *gen.CreatePlatformTenantJSONRequestBody) ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	body, err := json.Marshal(orchestrator.RequestBodyForHash(m))
	if err != nil {
		return nil, err
	}
	return jobs.RequestHash("POST", "/platform/tenants", body), nil
}

// RetryPlatformJob implements POST /platform/jobs/{jobId}/retry.
func (h *Handlers) RetryPlatformJob(ctx context.Context, req gen.RetryPlatformJobRequestObject) (gen.RetryPlatformJobResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.control.Retry(ctx, who, req.JobId, controlIdem("retry", req.JobId, req.Params.IdempotencyKey))
	if err != nil {
		return nil, failure(err)
	}
	if !r.Changed {
		markNoChange(ctx)
	}
	return gen.RetryPlatformJob202JSONResponse{Body: jobsapi.ToAPI(r.Job),
		Headers: gen.RetryPlatformJob202ResponseHeaders{Location: JobLocation(r.Job.ID)}}, nil
}

// CancelPlatformJob implements POST /platform/jobs/{jobId}/cancel.
func (h *Handlers) CancelPlatformJob(ctx context.Context, req gen.CancelPlatformJobRequestObject) (gen.CancelPlatformJobResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.control.Cancel(ctx, who, req.JobId, controlIdem("cancel", req.JobId, req.Params.IdempotencyKey))
	if err != nil {
		return nil, failure(err)
	}
	if !r.Changed {
		markNoChange(ctx)
	}
	return gen.CancelPlatformJob202JSONResponse{Body: jobsapi.ToAPI(r.Job),
		Headers: gen.CancelPlatformJob202ResponseHeaders{Location: JobLocation(r.Job.ID)}}, nil
}

// RollbackPlatformJob implements POST /platform/jobs/{jobId}/rollback.
func (h *Handlers) RollbackPlatformJob(ctx context.Context, req gen.RollbackPlatformJobRequestObject) (gen.RollbackPlatformJobResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.control.Rollback(ctx, who, req.JobId, controlIdem("rollback", req.JobId, req.Params.IdempotencyKey))
	if err != nil {
		return nil, failure(err)
	}
	if !r.Changed {
		markNoChange(ctx)
	}
	return gen.RollbackPlatformJob202JSONResponse{Body: jobsapi.ToAPI(r.Job),
		Headers: gen.RollbackPlatformJob202ResponseHeaders{Location: JobLocation(r.Job.ID)}}, nil
}

// controlIdem is the Idempotency-Key of a control: the request has no body, the path names the job and the action.
func controlIdem(action string, job uuid.UUID, key string) *orchestrator.Idempotency {
	return &orchestrator.Idempotency{Key: key, Hash: jobs.RequestHash("POST", "/platform/jobs/"+job.String()+"/"+action, nil)}
}

// markNoChange: a repeated /cancel or a replayed request changes nothing and writes no event — tell the audit
// middleware it is not a gap (a write that succeeded without an event).
func markNoChange(ctx context.Context) {
	if r := audit.RequestFrom(ctx); r != nil {
		r.ReadOnly = true
	}
}

// failure maps an error of the orchestrator to a problem (the Cause carries a stable reason for the audit).
func failure(err error) error {
	if p, ok := problem.FromQuota(err); ok {
		return p
	}
	reason := "conflict"
	field := "body"
	var ce *orchestrator.CreateError
	if errors.As(err, &ce) {
		reason = ce.Reason
		if ce.Field != "" {
			field = ce.Field
		}
	}
	var se *jobs.StateError
	if errors.As(err, &se) {
		reason = se.Reason
	}
	cause := &authz.Denial{Kind: err, Reason: reason}
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, orchestrator.ErrIdempotencyInProgress):
		p := &problem.Error{Code: gen.ProblemCodeConflict, Cause: cause,
			Detail: "A request with this Idempotency-Key is still in progress."}
		if ce != nil {
			p.RetryAfter = ce.RetryAfter
		}
		return p
	case errors.Is(err, orchestrator.ErrIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, orchestrator.ErrInvalid):
		return problem.Validation("The request is invalid.", problem.Field(field, reason, "has an invalid value"))
	case errors.Is(err, orchestrator.ErrConflict):
		detail := map[string]string{
			"slug_taken":        "A tenant with this slug already exists.",
			"slug_not_reusable": "The slug belonged to a deleted tenant whose objects are not purged yet.",
			"hostname_in_use":   "The control hostname of this slug is still held by an instance.",
		}[reason]
		if detail == "" {
			detail = "The request conflicts with the registry."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	case errors.Is(err, jobs.ErrJobState):
		detail := map[string]string{
			"status_not_allowed":   "The job's status does not allow this action.",
			"status_changed":       "The job changed status meanwhile; read it again.",
			"kind_not_lifecycle":   "Only lifecycle jobs can be controlled.",
			"kind_not_compensable": "This kind of job cannot be rolled back.",
			"point_of_no_return":   "The job passed its point of no return: it cannot be rolled back, only retried.",
			"tenant_not_failed":    "The tenant is not in status failed.",
		}[reason]
		if detail == "" {
			detail = "The job cannot take this action."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	}
	return problem.Internal(err)
}
