// Package instanceopsapi serves the operations of P3-T13a (httpapi.InstanceOpsHandlers): restartPlatformInstance
// (POST /platform/instances/{instanceId}/restart — platform.instance:operate, §8.5) and upgradePlatformInstance
// (POST /platform/instances/{instanceId}/upgrade — platform.instance:upgrade). orchestrator.InstanceOpsService checks
// the instance and enqueues the job instance.restart / instance.upgrade in one platform transaction of the api, with
// the audit event platform.instance.restart.requested / platform.instance.upgrade.requested (the worker closes it). It
// never imports internal/store (§13.6).
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, InstanceOps: instanceopsapi.New(orchestrator.NewInstanceOpsService(st))}
package instanceopsapi

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

// Service is the part of *orchestrator.InstanceOpsService the handlers use.
type Service interface {
	Restart(ctx context.Context, actor, instanceID uuid.UUID, idem *orchestrator.Idempotency) (orchestrator.Reconfigured, error)
	Upgrade(ctx context.Context, actor, instanceID uuid.UUID, digest string, idem *orchestrator.Idempotency) (orchestrator.Reconfigured, error)
}

var _ Service = (*orchestrator.InstanceOpsService)(nil)

// Handlers implements httpapi.InstanceOpsHandlers.
type Handlers struct {
	svc Service
}

var _ httpapi.InstanceOpsHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T13a.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

var (
	errNoDecision    = errors.New("instanceopsapi: no session or authorization decision in the request context (hooks missing)")
	errWrongDecision = errors.New("instanceopsapi: the authorization decision does not cover a platform route")
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

// RestartPlatformInstance implements POST /platform/instances/{instanceId}/restart: 202 + the job.
func (h *Handlers) RestartPlatformInstance(ctx context.Context, req gen.RestartPlatformInstanceRequestObject) (gen.RestartPlatformInstanceResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	hash := jobs.RequestHash("POST", "/platform/instances/"+req.InstanceId.String()+"/restart", nil)
	out, err := h.svc.Restart(ctx, who, req.InstanceId, &orchestrator.Idempotency{Key: req.Params.IdempotencyKey, Hash: hash})
	if err != nil {
		return nil, failure(err)
	}
	if out.Replayed || !out.Created {
		markNoChange(ctx)
	}
	return gen.RestartPlatformInstance202JSONResponse{Body: jobsapi.ToAPI(out.Job),
		Headers: gen.RestartPlatformInstance202ResponseHeaders{Location: JobLocation(out.Job.ID)}}, nil
}

// UpgradePlatformInstance implements POST /platform/instances/{instanceId}/upgrade: 202 + the job.
func (h *Handlers) UpgradePlatformInstance(ctx context.Context, req gen.UpgradePlatformInstanceRequestObject) (gen.UpgradePlatformInstanceResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	hash, err := requestHash(req.InstanceId, req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	out, err := h.svc.Upgrade(ctx, who, req.InstanceId, req.Body.ImageDigest,
		&orchestrator.Idempotency{Key: req.Params.IdempotencyKey, Hash: hash})
	if err != nil {
		return nil, failure(err)
	}
	if out.Replayed || !out.Created {
		markNoChange(ctx)
	}
	return gen.UpgradePlatformInstance202JSONResponse{Body: jobsapi.ToAPI(out.Job),
		Headers: gen.UpgradePlatformInstance202ResponseHeaders{Location: JobLocation(out.Job.ID)}}, nil
}

// requestHash is the Idempotency-Key hash of an upgrade: method, path (with the instance) and the canonical body.
func requestHash(instance uuid.UUID, b *gen.InstanceUpgrade) ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return jobs.RequestHash("POST", "/platform/instances/"+instance.String()+"/upgrade", raw), nil
}

// markNoChange: a replayed request (or the unfinished job returned again) writes no event — not an audit gap.
func markNoChange(ctx context.Context) {
	if r := audit.RequestFrom(ctx); r != nil {
		r.ReadOnly = true
	}
}

// conflictText is the detail of each 409 reason.
var conflictText = map[string]string{
	"instance_quarantined":  "The instance is quarantined: it is not restarted or upgraded until it is released.",
	"instance_not_running":  "The instance is not running.",
	"no_config_version":     "The instance has no configuration version recorded by the orchestrator.",
	"tenant_not_active":     "The tenant is neither active nor suspended.",
	"already_on_target":     "The instance already runs this image.",
	"upgrade_in_progress":   "Another upgrade of this instance (to another image) is not finished yet.",
	"operation_in_progress": "Another request for this instance was enqueued at the same time; retry.",
}

// failure maps an error of the orchestrator to a problem (the Cause carries a stable reason for the audit).
func failure(err error) error {
	reason, field := "conflict", "body"
	var ce *orchestrator.CreateError
	if errors.As(err, &ce) {
		reason = ce.Reason
		if ce.Field != "" {
			field = ce.Field
		}
	}
	cause := &authz.Denial{Kind: err, Reason: reason}
	switch {
	case errors.Is(err, orchestrator.ErrNotFound):
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
		detail := conflictText[reason]
		if detail == "" {
			detail = "The request conflicts with the registry."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	}
	return problem.Internal(err)
}
