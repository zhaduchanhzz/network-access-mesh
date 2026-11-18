// Package reconfigureapi serves the operation of P3-T13 (httpapi.ReconfigureHandlers): reconfigurePlatformInstance
// (POST /platform/instances/{instanceId}/reconfigure — platform.instance:operate, §8.5). It translates the generated
// body into an orchestrator.ConfigChange; orchestrator.ReconfigureService checks the instance and enqueues the job
// instance.reconfigure in one platform transaction of the api, with the audit event
// platform.instance.reconfigure.requested (the worker closes it). It never imports internal/store (§13.6).
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Reconfigure: reconfigureapi.New(orchestrator.NewReconfigureService(st))}
package reconfigureapi

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

// Service is the part of *orchestrator.ReconfigureService the handler uses.
type Service interface {
	Request(ctx context.Context, actor, instanceID uuid.UUID, change orchestrator.ConfigChange,
		idem *orchestrator.Idempotency) (orchestrator.Reconfigured, error)
}

var _ Service = (*orchestrator.ReconfigureService)(nil)

// Handlers implements httpapi.ReconfigureHandlers.
type Handlers struct {
	svc Service
}

var _ httpapi.ReconfigureHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T13.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

var (
	errNoDecision    = errors.New("reconfigureapi: no session or authorization decision in the request context (hooks missing)")
	errWrongDecision = errors.New("reconfigureapi: the authorization decision does not cover a platform route")
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

// ReconfigurePlatformInstance implements POST /platform/instances/{instanceId}/reconfigure: 202 + the job.
func (h *Handlers) ReconfigurePlatformInstance(ctx context.Context, req gen.ReconfigurePlatformInstanceRequestObject) (gen.ReconfigurePlatformInstanceResponseObject, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	change, err := Change(*req.Body)
	if err != nil {
		return nil, failure(err)
	}
	hash, err := requestHash(req.InstanceId, req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	out, err := h.svc.Request(ctx, who, req.InstanceId, change, &orchestrator.Idempotency{Key: req.Params.IdempotencyKey, Hash: hash})
	if err != nil {
		return nil, failure(err)
	}
	if out.Replayed || !out.Created {
		markNoChange(ctx) // the stored answer, or the unfinished job asking for the same change: nothing written now
	}
	return gen.ReconfigurePlatformInstance202JSONResponse{Body: jobsapi.ToAPI(out.Job),
		Headers: gen.ReconfigurePlatformInstance202ResponseHeaders{Location: JobLocation(out.Job.ID)}}, nil
}

// Change maps the generated body to the orchestrator's change; a value out of its bounds is a *CreateError
// (ErrInvalid) naming the field — Normalize checks the rest.
func Change(b gen.InstanceReconfigure) (orchestrator.ConfigChange, error) {
	var c orchestrator.ConfigChange
	if b.LogLevel != nil {
		c.LogLevel = string(*b.LogLevel)
		if c.LogLevel == "" {
			return c, &orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "invalid_log_level", Field: "log_level"}
		}
	}
	u32 := func(field string, v *int, lo, hi int) (*uint32, error) {
		if v == nil {
			return nil, nil
		}
		if *v < lo || *v > hi {
			return nil, &orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "out_of_range", Field: field}
		}
		x := uint32(*v) //nolint:gosec // bounded above
		return &x, nil
	}
	var err error
	if c.NodeExpiryDays, err = u32("node_expiry_days", b.NodeExpiryDays, 1, 3650); err != nil {
		return c, err
	}
	if c.DERPRegionID, err = u32("derp_region_id", b.DerpRegionId, 900, 999); err != nil {
		return c, err
	}
	if b.Nameservers != nil {
		c.Nameservers = append([]string{}, *b.Nameservers...)
		if len(c.Nameservers) == 0 {
			return c, &orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "invalid_count", Field: "nameservers"}
		}
	}
	return c, c.Normalize()
}

// requestHash is the Idempotency-Key hash: method, path (with the instance) and the canonical body.
func requestHash(instance uuid.UUID, b *gen.InstanceReconfigure) ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return jobs.RequestHash("POST", "/platform/instances/"+instance.String()+"/reconfigure", raw), nil
}

// markNoChange: a replayed request changes nothing and writes no event — tell the audit middleware it is not a gap.
func markNoChange(ctx context.Context) {
	if r := audit.RequestFrom(ctx); r != nil {
		r.ReadOnly = true
	}
}

// conflictText is the detail of each 409 reason.
var conflictText = map[string]string{
	"instance_quarantined":    "The instance is quarantined: it is not reconfigured until it is released.",
	"instance_not_running":    "The instance is not running.",
	"no_config_version":       "The instance has no configuration version recorded by the orchestrator.",
	"tenant_not_active":       "The tenant is neither active nor suspended.",
	"reconfigure_in_progress": "Another reconfiguration of this instance is not finished yet.",
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
