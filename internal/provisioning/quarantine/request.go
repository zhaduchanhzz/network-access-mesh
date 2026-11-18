package quarantine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Idempotency is the Idempotency-Key of a request and the SHA-256 of the request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// Requested is the outcome of a quarantine request.
type Requested struct {
	Job jobs.Job
	// Changed is false when nothing was written: the stored answer of the same request (Idempotency-Key replay) or the
	// unfinished quarantine job of the instance.
	Changed bool
}

// RequestError is a refused request: Kind is ErrNotFound (404), ErrConflict (409), ErrInvalid (422) or an idempotency
// error; Reason a stable code.
type RequestError struct {
	Kind       error
	Reason     string
	RetryAfter time.Duration // ErrIdempotencyInProgress
}

func (e *RequestError) Error() string { return e.Kind.Error() + " (" + e.Reason + ")" }
func (e *RequestError) Unwrap() error { return e.Kind }

// Refusal kinds of the API side.
var (
	ErrNotFound              = errors.New("quarantine: no such instance")
	ErrConflict              = errors.New("quarantine: the instance's state does not allow this request")
	ErrInvalid               = errors.New("quarantine: invalid request")
	ErrIdempotencyInProgress = errors.New("quarantine: a request with this Idempotency-Key is in progress")
	ErrIdempotencyKeyReuse   = errors.New("quarantine: Idempotency-Key used for another request")
)

// Conflict reasons (RequestError.Reason of ErrConflict / ErrInvalid).
const (
	ReasonRemoved          = "instance_removed" // quarantine or release of a removed instance
	ReasonNotQuarantined   = "instance_not_quarantined"
	ReasonQuarantineActive = "quarantine_in_progress" // release while the isolation is not finished
	ReasonReasonRequired   = "reason_required"
	ReasonTenantMismatch   = "tenant_mismatch" // the approved payload names another tenant than the registry
)

func conflict(reason string) error { return &RequestError{Kind: ErrConflict, Reason: reason} }

const idempotencyLock = 30 * time.Second

// Requester serves POST /platform/instances/{instanceId}/quarantine and prepares /release in the api process.
type Requester struct {
	st *store.Store
}

// NewRequester returns the API side of quarantine/release on the api's store.
func NewRequester(st *store.Store) *Requester { return &Requester{st: st} }

// CleanReason trims a reason and checks it: 1–MaxReason characters of valid UTF-8 ("" ⇒ ErrInvalid).
func CleanReason(reason string) (string, error) {
	r := strings.TrimSpace(reason)
	if r == "" || !utf8.ValidString(r) || utf8.RuneCountInString(r) > MaxReason {
		return "", &RequestError{Kind: ErrInvalid, Reason: ReasonReasonRequired}
	}
	return r, nil
}

// Quarantine asks for instance.quarantine (§11.4): in ONE platform transaction the instance moves to quarantined (the
// step gate, the Headscale locator and the schedules see it at once), the Critical security event, the audit
// .requested and the job whose worker isolates the instance on its host. 202 + the job. A quarantined instance can be
// quarantined again (the isolation is re-asserted by a new job — useful after an incomplete one); an unfinished
// quarantine job of the instance is returned as is.
func (r *Requester) Quarantine(ctx context.Context, actor, instanceID uuid.UUID, reason string, idem *Idempotency) (Requested, error) {
	if actor == uuid.Nil {
		return Requested{}, errors.New("quarantine: no actor")
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: actor, OperationID: QuarantineOperation, Key: idem.Key}
		replay, err := r.beginIdempotent(ctx, *key, idem.Hash)
		if err != nil {
			return Requested{}, err
		}
		if replay != nil {
			return Requested{Job: *replay}, nil
		}
	}
	var out Requested
	err := r.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		var err error
		if out, err = enqueueQuarantine(ctx, tx, actor, instanceID, reason, idem); err != nil || key == nil {
			return err
		}
		body, err := json.Marshal(out.Job)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, tx.Q, *key, idem.Hash, jobs.StoredResponse{Status: 202, Body: body,
			Resource: &jobs.Resource{Type: "job", ID: out.Job.ID.String()}})
	})
	if err != nil && key != nil {
		_ = r.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
			return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
		})
	}
	return out, err
}

// enqueueQuarantine is steps 1–2 and the job, in the caller's platform transaction. The instance is looked up before
// the reason is checked: an unknown instance is 404 whatever the body (§8.4 invariant 6).
func enqueueQuarantine(ctx context.Context, tx *store.Tx, actor, instanceID uuid.UUID, reason string, idem *Idempotency) (Requested, error) {
	q := tx.Q
	inst, err := q.LockInstanceForQuarantine(ctx, instanceID)
	if errors.Is(err, store.ErrNoRows) {
		return Requested{}, &RequestError{Kind: ErrNotFound, Reason: "not_found"}
	}
	if err != nil {
		return Requested{}, err
	}
	if reason, err = CleanReason(reason); err != nil {
		return Requested{}, err
	}
	if inst.Status == tenants.InstanceRemoved {
		return Requested{}, conflict(ReasonRemoved)
	}
	tid, iid := inst.TenantID, inst.ID
	if active, err := q.GetActiveJobByDedupeKey(ctx, dedupe(iid)); err == nil {
		j, err := jobs.ProjectTx(ctx, q, active.ID)
		return Requested{Job: j}, err
	} else if !errors.Is(err, store.ErrNoRows) {
		return Requested{}, err
	}
	from := inst.Status
	if from != tenants.InstanceQuarantined {
		if _, err := q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{
			Status: tenants.InstanceQuarantined, ID: iid, TenantID: tid, FromStatus: from}); err != nil {
			return Requested{}, err
		}
	}
	details := audit.Details{"instance_id": iid, "tenant_id": tid, "slug": inst.Slug, "from": from, "reason": reason}
	opn, err := audit.Requested(ctx, q, audit.Event{Action: ActionQuarantine, ActorIdentityID: &actor,
		ResourceType: "instance", ResourceID: iid.String(), Details: details})
	if err != nil {
		return Requested{}, err
	}
	in := Input{TenantID: tid, InstanceID: iid, Slug: inst.Slug, From: from, Reason: reason, Operation: opn}
	spec := jobs.Spec{Kind: KindQuarantine, TenantID: &tid, InstanceID: &iid, Input: in, RequestedBy: &actor,
		Resource: &jobs.Resource{Type: "instance", ID: iid.String()}}
	if idem != nil {
		spec.RequestKey = idem.Key
	}
	enq, err := jobs.Enqueue(ctx, tx, spec)
	switch {
	case errors.Is(err, jobs.ErrRequestKeyReuse):
		return Requested{}, &RequestError{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
	case err != nil:
		return Requested{}, err
	case !enq.Created:
		// a concurrent quarantine of the same instance enqueued it meanwhile: that job isolates it
		j, err := jobs.ProjectTx(ctx, q, enq.Job.ID)
		return Requested{Job: j}, err
	}
	if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, StepValidate, jobs.StepSucceeded, map[string]any{
		"status": from}); err != nil {
		return Requested{}, err
	}
	if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, StepRegistry, jobs.StepSucceeded, map[string]any{
		"from": from, "to": tenants.InstanceQuarantined, "changed": from != tenants.InstanceQuarantined}); err != nil {
		return Requested{}, err
	}
	// §11.4 "audit + cảnh báo Critical": platform scope (the tenant does not see an incident investigation)
	if _, err := audit.RecordSecurityEvent(ctx, q, audit.SecurityEvent{Kind: EventQuarantined, Severity: audit.SeverityCritical,
		Source: Source, Details: audit.Details{"instance_id": iid, "tenant_id": tid, "slug": inst.Slug, "from": from,
			"job_id": enq.Job.ID, "requested_by": actor, "reason": reason}}); err != nil {
		return Requested{}, err
	}
	audit.HandOff(ctx, opn)
	j, err := jobs.ProjectTx(ctx, q, enq.Job.ID)
	return Requested{Job: j, Changed: true}, err
}

func dedupe(instanceID uuid.UUID) string { return "instance:" + instanceID.String() + ":quarantine" }

func releaseDedupe(instanceID uuid.UUID) string {
	return "instance:" + instanceID.String() + ":release"
}

// ReleasePayload checks a release request before it becomes an approval request (§8.6): the instance exists (404), is
// quarantined and its isolation finished (409) — and returns the payload the approver will see.
func (r *Requester) ReleasePayload(ctx context.Context, instanceID uuid.UUID) (ReleasePayload, error) {
	var p ReleasePayload
	err := r.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.GetInstanceForQuarantine(ctx, instanceID)
		if errors.Is(err, store.ErrNoRows) {
			return &RequestError{Kind: ErrNotFound, Reason: "not_found"}
		}
		if err != nil {
			return err
		}
		if err := releasable(ctx, q, inst.ID, inst.Status); err != nil {
			return err
		}
		p = ReleasePayload{InstanceID: inst.ID, TenantID: inst.TenantID}
		return nil
	})
	return p, err
}

// releasable: a quarantined instance whose quarantine job (if any) has finished.
func releasable(ctx context.Context, q *sqlcdb.Queries, instanceID uuid.UUID, status string) error {
	switch status {
	case tenants.InstanceQuarantined:
	case tenants.InstanceRemoved:
		return conflict(ReasonRemoved)
	default:
		return conflict(ReasonNotQuarantined)
	}
	if _, err := q.GetActiveJobByDedupeKey(ctx, dedupe(instanceID)); err == nil {
		return conflict(ReasonQuarantineActive)
	} else if !errors.Is(err, store.ErrNoRows) {
		return err
	}
	return nil
}

// ReleaseExecution is an approved release request (approvals.Execution, decoded).
type ReleaseExecution struct {
	ApprovalID  uuid.UUID
	RequestedBy uuid.UUID
	ApprovedBy  uuid.UUID
	Payload     ReleasePayload
}

// ExecuteRelease is the action of an approved release request (P3-T04a executor), run in the transaction that marks
// the request executed: the instance must still be quarantined with no quarantine in progress (otherwise the request
// stays approved and nothing runs), then audit platform.instance.release.requested and instance.release (the
// unfinished release job of the instance is returned as is). It returns the job.
func ExecuteRelease(ctx context.Context, tx *store.Tx, e ReleaseExecution) (uuid.UUID, error) {
	if err := e.Payload.Validate(); err != nil || e.ApprovalID == uuid.Nil || e.ApprovedBy == uuid.Nil {
		return uuid.Nil, &RequestError{Kind: ErrInvalid, Reason: "invalid_payload"}
	}
	q := tx.Q
	inst, err := q.LockInstanceForQuarantine(ctx, e.Payload.InstanceID)
	if errors.Is(err, store.ErrNoRows) {
		return uuid.Nil, &RequestError{Kind: ErrNotFound, Reason: "not_found"}
	}
	if err != nil {
		return uuid.Nil, err
	}
	if inst.TenantID != e.Payload.TenantID {
		return uuid.Nil, &RequestError{Kind: ErrInvalid, Reason: ReasonTenantMismatch}
	}
	if active, err := q.GetActiveJobByDedupeKey(ctx, releaseDedupe(inst.ID)); err == nil {
		return active.ID, nil // the release of this instance already runs
	} else if !errors.Is(err, store.ErrNoRows) {
		return uuid.Nil, err
	}
	if err := releasable(ctx, q, inst.ID, inst.Status); err != nil {
		return uuid.Nil, err
	}
	tid, iid, approver := inst.TenantID, inst.ID, e.ApprovedBy
	opn, err := audit.Requested(ctx, q, audit.Event{Action: ActionRelease, ActorIdentityID: &approver,
		ResourceType: "instance", ResourceID: iid.String(), Details: audit.Details{"instance_id": iid, "tenant_id": tid,
			"slug": inst.Slug, "approval_id": e.ApprovalID, "requested_by_identity_id": e.RequestedBy,
			"decided_by_identity_id": e.ApprovedBy}})
	if err != nil {
		return uuid.Nil, err
	}
	in := ReleaseInput{TenantID: tid, InstanceID: iid, Slug: inst.Slug, ApprovalID: e.ApprovalID, Operation: opn}
	enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindRelease, TenantID: &tid, InstanceID: &iid, Input: in,
		RequestedBy: &approver, Resource: &jobs.Resource{Type: "instance", ID: iid.String()}})
	if err != nil {
		return uuid.Nil, fmt.Errorf("quarantine: enqueue the release: %w", err)
	}
	if !enq.Created {
		return enq.Job.ID, nil
	}
	if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, StepValidate, jobs.StepSucceeded, map[string]any{
		"approval_id": e.ApprovalID, "status": inst.Status}); err != nil {
		return uuid.Nil, err
	}
	audit.HandOff(ctx, opn)
	return enq.Job.ID, nil
}

// beginIdempotent takes the Idempotency-Key of the request in a transaction of its own: nil = proceed; a job = the
// stored answer of the same request (replay).
func (r *Requester) beginIdempotent(ctx context.Context, key jobs.IdempotencyKey, hash []byte) (*jobs.Job, error) {
	var replay *jobs.Job
	err := r.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		d, err := jobs.BeginIdempotent(ctx, q, key, hash, idempotencyLock)
		if err != nil {
			return err
		}
		switch d.Outcome {
		case jobs.IdempotencyReplay:
			var j jobs.Job
			if d.Response == nil || json.Unmarshal(d.Response.Body, &j) != nil || j.ID == uuid.Nil {
				return fmt.Errorf("quarantine: stored response of %s unreadable", key.OperationID)
			}
			replay = &j
		case jobs.IdempotencyInProgress:
			return &RequestError{Kind: ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
		case jobs.IdempotencyKeyReuse:
			return &RequestError{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
		}
		return nil
	})
	return replay, err
}
