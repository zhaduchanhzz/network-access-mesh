// Package quarantineapi serves the quarantine of an instance built by P3-T18 (httpapi.QuarantineHandlers, §11.4):
//
//   - quarantinePlatformInstance — POST /platform/instances/{instanceId}/quarantine (platform.instance:quarantine, no
//     2P: the isolation must be immediate): internal/provisioning/quarantine moves the instance to quarantined and
//     enqueues instance.quarantine in the api's platform transaction; 202 + the job;
//   - releasePlatformInstance — POST /platform/instances/{instanceId}/release (platform.instance:release, always 2P):
//     the request becomes an approval request of action platform.instance.release (internal/authz/approvals); the
//     instance.release job exists only once a second person approved it (the executor is wired in apps/internal/runner);
//     202 + Location of /platform/approvals/{id}.
//
// It translates between the generated types and the quarantine module and never imports internal/store (§13.6).
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Quarantine: quarantineapi.New(quarantine.NewRequester(store), approvalsSvc)}
package quarantineapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/quarantine"
)

// Requester is the part of *quarantine.Requester the handlers use.
type Requester interface {
	Quarantine(ctx context.Context, actor, instanceID uuid.UUID, reason string, idem *quarantine.Idempotency) (quarantine.Requested, error)
	ReleasePayload(ctx context.Context, instanceID uuid.UUID) (quarantine.ReleasePayload, error)
}

var _ Requester = (*quarantine.Requester)(nil)

// Approvals is the part of *approvals.Service the release uses.
type Approvals interface {
	RequestIdempotent(ctx context.Context, actor approvals.Actor, in approvals.NewRequest, idem approvals.Idempotency) (approvals.Request, error)
}

var _ Approvals = (*approvals.Service)(nil)

// Handlers implements httpapi.QuarantineHandlers.
type Handlers struct {
	req  Requester
	appr Approvals
}

var _ httpapi.QuarantineHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T18.
func New(req Requester, appr Approvals) *Handlers { return &Handlers{req: req, appr: appr} }

var (
	errNoDecision    = errors.New("quarantineapi: no session or authorization decision in the request context (hooks missing)")
	errWrongDecision = errors.New("quarantineapi: the authorization decision does not cover a platform route")
	errNotDual       = errors.New("quarantineapi: the release decision does not require a second approver")
)

// session returns the caller's session under a platform decision.
func session(ctx context.Context) (*identity.Session, authz.Decision, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	switch {
	case !ok || !okd || s == nil || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID:
		return nil, d, problem.Internal(errNoDecision)
	case d.TenantID != uuid.Nil:
		return nil, d, problem.Internal(errWrongDecision)
	}
	return s, d, nil
}

// JobLocation is the Location of a job for a caller of platform scope (§13.1 "Thao tác dài").
func JobLocation(id uuid.UUID) string { return "/api/v1/platform/jobs/" + id.String() }

// QuarantinePlatformInstance implements POST /platform/instances/{instanceId}/quarantine: 202 + instance.quarantine.
func (h *Handlers) QuarantinePlatformInstance(ctx context.Context, req gen.QuarantinePlatformInstanceRequestObject) (gen.QuarantinePlatformInstanceResponseObject, error) {
	s, _, err := session(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	idem := &quarantine.Idempotency{Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/platform/instances/"+req.InstanceId.String()+"/quarantine", body)}
	out, err := h.req.Quarantine(ctx, s.IdentityID, req.InstanceId, req.Body.Reason, idem)
	if err != nil {
		return nil, failure(err)
	}
	if !out.Changed {
		markNoChange(ctx)
	}
	return gen.QuarantinePlatformInstance202JSONResponse{Body: jobsapi.ToAPI(out.Job),
		Headers: gen.QuarantinePlatformInstance202ResponseHeaders{Location: JobLocation(out.Job.ID)}}, nil
}

// ReleasePlatformInstance implements POST /platform/instances/{instanceId}/release: the instance must be quarantined
// with its isolation finished; the request becomes an approval request (202 + Location) — nothing runs until a
// second person approves it.
func (h *Handlers) ReleasePlatformInstance(ctx context.Context, req gen.ReleasePlatformInstanceRequestObject) (gen.ReleasePlatformInstanceResponseObject, error) {
	s, d, err := session(ctx)
	if err != nil {
		return nil, err
	}
	if !d.NeedsApproval() { // x-dual-control: the decision must carry the 2P obligation (§8.6) — never run it directly
		return nil, problem.Internal(errNotDual)
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	p, err := h.req.ReleasePayload(ctx, req.InstanceId) // 404 / 409 before the body is judged
	if err != nil {
		return nil, failure(err)
	}
	reason, err := quarantine.CleanReason(req.Body.Reason)
	if err != nil {
		return nil, failure(err)
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	r, err := h.appr.RequestIdempotent(ctx, approvals.Actor{IdentityID: s.IdentityID, Scope: authz.ScopePlatform,
		AuthTime: s.AuthTime}, approvals.NewRequest{Action: quarantine.ReleaseApprovalAction,
		ResourceID: req.InstanceId.String(), Payload: p, Reason: reason}, approvals.Idempotency{
		Operation: quarantine.ReleaseOperation, Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/platform/instances/"+req.InstanceId.String()+"/release", body)})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.ReleasePlatformInstance202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.ReleasePlatformInstance202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

// markNoChange: a replayed request, or the quarantine already in flight, writes no event — tell the audit middleware
// it is not a gap.
func markNoChange(ctx context.Context) {
	if r := audit.RequestFrom(ctx); r != nil {
		r.ReadOnly = true
	}
}

// conflictDetail is the client-facing text of each refusal reason.
var conflictDetail = map[string]string{
	quarantine.ReasonRemoved:          "The instance was removed.",
	quarantine.ReasonNotQuarantined:   "The instance is not quarantined.",
	quarantine.ReasonQuarantineActive: "The quarantine of the instance is still in progress.",
}

// failure maps an error of the quarantine module to a problem (the Cause carries a stable reason for the audit).
func failure(err error) error {
	reason := "conflict"
	var re *quarantine.RequestError
	if errors.As(err, &re) {
		reason = re.Reason
	}
	cause := &authz.Denial{Kind: err, Reason: reason}
	switch {
	case errors.Is(err, quarantine.ErrNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, quarantine.ErrInvalid):
		return problem.Validation("The request is invalid.",
			problem.Field("reason", "required", "a reason (1–1000 characters) is required"))
	case errors.Is(err, quarantine.ErrIdempotencyInProgress):
		p := &problem.Error{Code: gen.ProblemCodeConflict, Cause: cause,
			Detail: "A request with this Idempotency-Key is still in progress."}
		if re != nil {
			p.RetryAfter = re.RetryAfter
		}
		return p
	case errors.Is(err, quarantine.ErrIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, quarantine.ErrConflict):
		detail := conflictDetail[reason]
		if detail == "" {
			detail = "The request conflicts with the instance's state."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	}
	return problem.Internal(err)
}
