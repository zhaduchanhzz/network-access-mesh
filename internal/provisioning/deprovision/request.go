package deprovision

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// RequestError is a refused request: Kind is ErrNotFound (404), ErrConflict (409) or ErrInvalid (422); Reason a
// stable code.
type RequestError struct {
	Kind   error
	Reason string
}

func (e *RequestError) Error() string { return e.Kind.Error() + " (" + e.Reason + ")" }
func (e *RequestError) Unwrap() error { return e.Kind }

// Refusal kinds of the API side.
var (
	ErrNotFound = errors.New("deprovision: no such tenant")
	ErrConflict = errors.New("deprovision: the tenant's state does not allow a deprovision")
	ErrInvalid  = errors.New("deprovision: invalid request")
)

// Refusal reasons (RequestError.Reason).
const (
	ReasonDeleted          = "tenant_deleted"             // already deleted
	ReasonInProgress       = "deprovision_in_progress"    // already being deprovisioned
	ReasonNotDeprovisioned = "tenant_not_deprovisionable" // provisioning/pending: finish or roll back the provisioning first
	ReasonLifecycleJob     = "lifecycle_job_in_progress"  // another lifecycle job of the tenant is unfinished
	ReasonQuarantined      = "instance_quarantined"       // the instance is quarantined: no final backup is possible
	ReasonSlugMismatch     = "slug_mismatch"              // the typed slug is not the tenant's
	ReasonPayloadMismatch  = "payload_mismatch"           // the approved payload names another tenant than the request
)

func refuse(kind error, reason string) error { return &RequestError{Kind: kind, Reason: reason} }

// Requester is the API side of the deprovision (the api process's store).
type Requester struct {
	st *store.Store
}

// NewRequester returns the API side of the deprovision.
func NewRequester(st *store.Store) *Requester { return &Requester{st: st} }

// Check validates a deprovision request before its approval request exists (DELETE /platform/tenants/{tenantId}): the
// tenant exists, can be deprovisioned now, and confirmSlug — typed by the requester — is its slug. It returns the
// payload of the approval request.
func (r *Requester) Check(ctx context.Context, tenantID uuid.UUID, confirmSlug string, skipFinalBackup bool) (Payload, error) {
	var p Payload
	err := r.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		t, _, err := check(ctx, q, tenantID, skipFinalBackup)
		if err != nil {
			return err
		}
		if confirmSlug != t.Slug {
			return refuse(ErrInvalid, ReasonSlugMismatch)
		}
		p = Payload{TenantID: t.ID, Slug: t.Slug, SkipFinalBackup: skipFinalBackup}
		return nil
	})
	return p, err
}

// check is the state rule of a deprovision (§11.4): a tenant active, suspended or failed, no unfinished lifecycle job
// of the tenant, and — unless the final backup is skipped — an instance that can be backed up.
func check(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, skipFinalBackup bool) (sqlcdb.Tenant, *sqlcdb.GetLiveInstanceOfTenantRow, error) {
	t, err := q.GetTenant(ctx, tenantID)
	if errors.Is(err, store.ErrNoRows) {
		return t, nil, refuse(ErrNotFound, "not_found")
	}
	if err != nil {
		return t, nil, err
	}
	switch {
	case t.Status == tenants.StatusDeleted:
		return t, nil, refuse(ErrConflict, ReasonDeleted)
	case t.Status == tenants.StatusDeprovisioning:
		return t, nil, refuse(ErrConflict, ReasonInProgress)
	case !slices.Contains(FromStatuses, t.Status):
		return t, nil, refuse(ErrConflict, ReasonNotDeprovisioned)
	}
	if _, err := q.GetActiveJobByDedupeKey(ctx, jobs.LockKey(tenantID)); err == nil {
		return t, nil, refuse(ErrConflict, ReasonLifecycleJob)
	} else if !errors.Is(err, store.ErrNoRows) {
		return t, nil, err
	}
	inst, err := q.GetLiveInstanceOfTenant(ctx, tenantID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return t, nil, nil
	case err != nil:
		return t, nil, err
	case inst.Status == tenants.InstanceQuarantined && !skipFinalBackup:
		return t, nil, refuse(ErrConflict, ReasonQuarantined)
	}
	return t, &inst, nil
}

// EnqueueApproved is the execution of an approved platform.tenant.delete (apps/internal/runner registers the approval
// action — authz does not import provisioning): in the approval's transaction the request is checked again, the
// operation audited (platform.tenant.delete.requested, both persons in the details) and the lifecycle job
// tenant.deprovision enqueued with its step 1 `validate`. The job's id is returned (approval_requests.job_id).
func (r *Requester) EnqueueApproved(ctx context.Context, tx *store.Tx, requestedBy, approvalID uuid.UUID, p Payload) (*uuid.UUID, error) {
	if err := p.Validate(); err != nil {
		return nil, refuse(ErrInvalid, "invalid_payload")
	}
	q := tx.Q
	t, inst, err := check(ctx, q, p.TenantID, p.SkipFinalBackup)
	if err != nil {
		return nil, err
	}
	if t.Slug != p.Slug {
		return nil, refuse(ErrConflict, ReasonPayloadMismatch)
	}
	in := Input{TenantID: t.ID, Slug: t.Slug, FromStatus: t.Status, RestoreVersionID: t.DesiredPolicyVersionID,
		SkipFinalBackup: p.SkipFinalBackup, ApprovalID: approvalID, RequestedBy: requestedBy}
	details := audit.Details{"tenant_id": t.ID, "slug": t.Slug, "status": t.Status, "approval_id": approvalID,
		"requested_by_identity_id": requestedBy, "skip_final_backup": p.SkipFinalBackup}
	if inst != nil {
		id := inst.ID
		in.InstanceID = &id
		details["instance_id"] = inst.ID
		details["instance_status"] = inst.Status
	}
	opn, err := audit.Requested(ctx, q, audit.Event{Action: Action, ResourceType: "tenant", ResourceID: t.ID.String(),
		Details: details})
	if err != nil {
		return nil, err
	}
	in.Operation = opn
	tid, requester := t.ID, requestedBy
	enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: Kind, TenantID: &tid, Input: in, RequestedBy: &requester,
		Resource: &jobs.Resource{Type: "tenant", ID: t.ID.String()}})
	switch {
	case errors.Is(err, jobs.ErrDedupeConflict):
		return nil, refuse(ErrConflict, ReasonLifecycleJob)
	case err != nil:
		return nil, err
	case !enq.Created:
		return nil, refuse(ErrConflict, ReasonInProgress)
	}
	if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, StepValidate, jobs.StepSucceeded, map[string]any{
		"status": t.Status, "instance_id": in.InstanceID, "approval_id": approvalID,
		"skip_final_backup": p.SkipFinalBackup}); err != nil {
		return nil, err
	}
	audit.HandOff(ctx, opn)
	id := enq.Job.ID
	return &id, nil
}
