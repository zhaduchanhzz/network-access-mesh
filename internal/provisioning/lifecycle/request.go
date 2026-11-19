package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Job kinds (§13.5) — lifecycle group: dedupe and lock key tenant:<id>:lifecycle.
const (
	KindSuspend = "tenant.suspend"
	KindResume  = "tenant.resume"
)

// Steps of the two jobs, in order (provisioning_job_steps.name).
const (
	StepValidate        = "validate"
	StepPolicySuspend   = "policy.suspend"
	StepRegistrySuspend = "registry.suspend"
	StepPreAuthExpire   = "preauthkeys.expire"
	StepNotify          = "notify"
	StepPolicyResume    = "policy.resume"
	StepRegistryResume  = "registry.resume"
)

// SuspendSteps and ResumeSteps list the steps of each kind in order (step 1 runs in the API).
var (
	SuspendSteps = []string{StepValidate, StepPolicySuspend, StepRegistrySuspend, StepPreAuthExpire, StepNotify}
	ResumeSteps  = []string{StepValidate, StepPolicyResume, StepRegistryResume, StepNotify}
)

// Audit actions (x-audit-action of the operations): paired .requested (API) → .succeeded (step notify) / .failed
// (rolled back or cancelled before it ran).
const (
	ActionSuspend = "platform.tenant.suspend"
	ActionResume  = "platform.tenant.resume"
)

// Operation ids of the API (Idempotency-Key scope — §13.1).
const (
	SuspendOperation = "suspendPlatformTenant"
	ResumeOperation  = "resumePlatformTenant"
)

// Input is the input of a tenant.suspend / tenant.resume job: identifiers only.
type Input struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Slug     string    `json:"slug"`
	// RestoreVersionID is the tenant's desired policy version when the job was requested — the version a resume
	// applies again (§11.4: tenants.desired_policy_version_id is kept during the suspension).
	RestoreVersionID uuid.UUID `json:"restore_version_id"`
	// Operation is the audit operation platform.tenant.<suspend|resume> opened by the API; the job closes it.
	Operation audit.Operation `json:"operation"`
}

func (in Input) validate() error {
	switch {
	case in.TenantID == uuid.Nil || in.RestoreVersionID == uuid.Nil:
		return errors.New("tenant or restore version missing")
	case in.Operation.ID == uuid.Nil:
		return errors.New("audit operation missing")
	}
	return nil
}

// Idempotency is the Idempotency-Key of a request and the SHA-256 of the request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// Requested is the outcome of a suspend or resume request.
type Requested struct {
	Job jobs.Job
	// Changed is false when nothing was written: the stored answer of the same request (Idempotency-Key replay), or
	// the unfinished job of the same kind already queued or running for the tenant.
	Changed bool
}

// RequestError is a refused request: Kind is ErrNotFound (404), ErrConflict (409) or an idempotency error; Reason a
// stable code.
type RequestError struct {
	Kind       error
	Reason     string
	RetryAfter time.Duration // ErrIdempotencyInProgress
}

func (e *RequestError) Error() string { return e.Kind.Error() + " (" + e.Reason + ")" }
func (e *RequestError) Unwrap() error { return e.Kind }

// Refusal kinds of the API side.
var (
	ErrNotFound              = errors.New("lifecycle: no such tenant")
	ErrConflict              = errors.New("lifecycle: the tenant's state does not allow this request")
	ErrIdempotencyInProgress = errors.New("lifecycle: a request with this Idempotency-Key is in progress")
	ErrIdempotencyKeyReuse   = errors.New("lifecycle: Idempotency-Key used for another request")
)

// Conflict reasons (RequestError.Reason of ErrConflict).
const (
	ReasonAlreadySuspended   = "already_suspended"         // suspend of a suspended tenant
	ReasonNotSuspended       = "not_suspended"             // resume of an active tenant
	ReasonNotActive          = "tenant_not_active"         // suspend of a tenant neither active nor suspended
	ReasonNotSuspendable     = "tenant_not_suspended"      // resume of a tenant neither suspended nor active
	ReasonNoPolicy           = "no_policy_to_restore"      // no desired policy version: resume would have nothing to apply
	ReasonLifecycleJobActive = "lifecycle_job_in_progress" // another lifecycle job of the tenant is unfinished
)

func conflict(reason string) error { return &RequestError{Kind: ErrConflict, Reason: reason} }

const idempotencyLock = 30 * time.Second

// Requester serves POST /platform/tenants/{tenantId}/suspend and /resume in the api process.
type Requester struct {
	st *store.Store
}

// NewRequester returns the API side of suspend/resume on the api's store.
func NewRequester(st *store.Store) *Requester { return &Requester{st: st} }

// Suspend asks for tenant.suspend (§11.4): 202 + the job.
func (r *Requester) Suspend(ctx context.Context, actor, tenantID uuid.UUID, idem *Idempotency) (Requested, error) {
	return r.request(ctx, KindSuspend, actor, tenantID, idem)
}

// Resume asks for tenant.resume (§11.4): 202 + the job.
func (r *Requester) Resume(ctx context.Context, actor, tenantID uuid.UUID, idem *Idempotency) (Requested, error) {
	return r.request(ctx, KindResume, actor, tenantID, idem)
}

func (r *Requester) request(ctx context.Context, kind string, actor, tenantID uuid.UUID, idem *Idempotency) (Requested, error) {
	if actor == uuid.Nil {
		return Requested{}, errors.New("lifecycle: no actor")
	}
	op := SuspendOperation
	if kind == KindResume {
		op = ResumeOperation
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: actor, OperationID: op, Key: idem.Key}
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
		if out, err = enqueue(ctx, tx, kind, actor, tenantID, idem); err != nil || key == nil {
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

// enqueue is step 1 `validate` and the job, in the caller's platform transaction.
func enqueue(ctx context.Context, tx *store.Tx, kind string, actor, tenantID uuid.UUID, idem *Idempotency) (Requested, error) {
	q := tx.Q
	t, err := q.GetTenant(ctx, tenantID)
	if errors.Is(err, store.ErrNoRows) {
		return Requested{}, &RequestError{Kind: ErrNotFound, Reason: "not_found"}
	}
	if err != nil {
		return Requested{}, err
	}
	// One lifecycle job per tenant (§13.5): the same request in flight is answered with its job, another kind waits.
	if active, err := q.GetActiveJobByDedupeKey(ctx, jobs.LockKey(tenantID)); err == nil {
		if active.Kind != kind {
			return Requested{}, conflict(ReasonLifecycleJobActive)
		}
		j, err := jobs.ProjectTx(ctx, q, active.ID)
		return Requested{Job: j}, err
	} else if !errors.Is(err, store.ErrNoRows) {
		return Requested{}, err
	}
	if err := checkStatus(kind, t.Status); err != nil {
		return Requested{}, err
	}
	if t.DesiredPolicyVersionID == nil {
		return Requested{}, conflict(ReasonNoPolicy)
	}
	action := ActionSuspend
	if kind == KindResume {
		action = ActionResume
	}
	opn, err := audit.Requested(ctx, q, audit.Event{Action: action, ActorIdentityID: &actor, ResourceType: "tenant",
		ResourceID: t.ID.String(), Details: audit.Details{"tenant_id": t.ID, "slug": t.Slug, "status": t.Status,
			"restore_version_id": *t.DesiredPolicyVersionID}})
	if err != nil {
		return Requested{}, err
	}
	in := Input{TenantID: t.ID, Slug: t.Slug, RestoreVersionID: *t.DesiredPolicyVersionID, Operation: opn}
	spec := jobs.Spec{Kind: kind, TenantID: &t.ID, Input: in, RequestedBy: &actor,
		Resource: &jobs.Resource{Type: "tenant", ID: t.ID.String()}}
	if idem != nil {
		spec.RequestKey = idem.Key
	}
	enq, err := jobs.Enqueue(ctx, tx, spec)
	switch {
	case errors.Is(err, jobs.ErrDedupeConflict):
		return Requested{}, conflict(ReasonLifecycleJobActive)
	case errors.Is(err, jobs.ErrRequestKeyReuse):
		return Requested{}, &RequestError{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
	case err != nil:
		return Requested{}, err
	case !enq.Created:
		// a concurrent request of the same kind enqueued it between the read above and this insert: this request
		// writes nothing (its audit event rolls back) — the client reads the tenant's job and sends again if needed
		return Requested{}, conflict(ReasonLifecycleJobActive)
	}
	tid := t.ID
	detail := map[string]any{"status": t.Status, "restore_version_id": *t.DesiredPolicyVersionID}
	if kind == KindSuspend {
		// P4-T10 (§11.4, §13.5): the deny-all policy is its own policy.apply job (dedupe tenant:<id>:policy.apply), in
		// this transaction — it does not wait for the lifecycle lock (an instance.upgrade in progress); the job reads
		// the unfinished tenant.suspend and applies the suspension policy. Step policy.suspend asserts it again.
		pa, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: policies.KindApply, TenantID: &tid,
			Input: policies.ApplyJobInput{Trigger: policies.TriggerSuspend}, RequestedBy: &actor})
		if err != nil {
			return Requested{}, err
		}
		detail["policy_apply_job_id"] = pa.Job.ID
	}
	if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, StepValidate, jobs.StepSucceeded, detail); err != nil {
		return Requested{}, err
	}
	audit.HandOff(ctx, opn)
	j, err := jobs.ProjectTx(ctx, q, enq.Job.ID)
	return Requested{Job: j, Changed: true}, err
}

// checkStatus is the state rule of the request: suspend from active, resume from suspended (§11.4).
func checkStatus(kind, status string) error {
	switch {
	case kind == KindSuspend && status == tenants.StatusActive, kind == KindResume && status == tenants.StatusSuspended:
		return nil
	case kind == KindSuspend && status == tenants.StatusSuspended:
		return conflict(ReasonAlreadySuspended)
	case kind == KindSuspend:
		return conflict(ReasonNotActive)
	case status == tenants.StatusActive:
		return conflict(ReasonNotSuspended)
	}
	return conflict(ReasonNotSuspendable)
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
				return fmt.Errorf("lifecycle: stored response of %s unreadable", key.OperationID)
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
