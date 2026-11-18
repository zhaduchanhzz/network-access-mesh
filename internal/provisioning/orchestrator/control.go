package orchestrator

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Control serves POST /platform/jobs/{jobId}/retry, /cancel and /rollback (§13.2, platform.job:control — §8.5) in
// the api process: the transitions of jobs.Transitions in one platform transaction with their audit event, plus what
// tenant.provision adds — /retry of a rolled_back job creates a NEW job from step 3 (§11.3), /cancel of a job that
// never started ends the tenant `failed`.
type Control struct {
	st *store.Store
}

// NewControl returns the job controls on the api's store.
func NewControl(st *store.Store) *Control { return &Control{st: st} }

// ControlResult is the outcome of a control action.
type ControlResult struct {
	Job     jobs.Job // the job to follow: the controlled one, or the new job of a retry after rollback
	From    string   // status before
	NewJob  bool     // /retry created a new job (rolled_back tenant.provision)
	Changed bool     // false: nothing to do (a repeated /cancel)
}

// Operation ids of the controls (Idempotency-Key scope — §13.1).
const (
	RetryOperation    = "retryPlatformJob"
	CancelOperation   = "cancelPlatformJob"
	RollbackOperation = "rollbackPlatformJob"
)

// Retry is /retry.
func (c *Control) Retry(ctx context.Context, actor, jobID uuid.UUID, idem *Idempotency) (ControlResult, error) {
	return c.idempotent(ctx, actor, RetryOperation, idem, func(tx *store.Tx) (ControlResult, error) {
		rec, err := jobs.LoadForControl(ctx, tx, jobID)
		if err != nil {
			return ControlResult{}, err
		}
		if rec.Kind == JobKind && rec.Status == jobs.StatusRolledBack {
			return c.retryProvision(ctx, tx, actor, rec)
		}
		r, err := jobs.Retry(ctx, tx, jobID)
		if err != nil {
			return ControlResult{}, err
		}
		return ControlResult{Job: r.Job, From: r.From, Changed: true}, recordControl(ctx, tx, rec, ActionJobRetry, r.Event, nil)
	})
}

// idempotent runs a control in one platform transaction under the request's Idempotency-Key: a replay of the same
// request returns the job it answered first, without acting again.
func (c *Control) idempotent(ctx context.Context, actor uuid.UUID, op string, idem *Idempotency,
	fn func(tx *store.Tx) (ControlResult, error)) (ControlResult, error) {
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: actor, OperationID: op, Key: idem.Key}
		replay, err := beginIdempotent(ctx, c.st, *key, idem.Hash)
		if err != nil {
			return ControlResult{}, err
		}
		if replay != nil {
			return ControlResult{Job: *replay, Changed: false}, nil
		}
	}
	var out ControlResult
	err := c.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		var err error
		if out, err = fn(tx); err != nil || key == nil {
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
		_ = c.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
			return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
		})
	}
	return out, err
}

// retryProvision: a rolled_back tenant.provision is not resumed (its resources were undone): the tenant goes back from
// `failed` to `provisioning` and a NEW job runs from step 3 — new instance id, new audit operation — in this
// transaction (§11.3).
func (c *Control) retryProvision(ctx context.Context, tx *store.Tx, actor uuid.UUID, rec sqlcdb.ProvisioningJob) (ControlResult, error) {
	var in Input
	if err := json.Unmarshal(rec.Input, &in); err != nil || in.validate() != nil {
		return ControlResult{}, &jobs.StateError{Action: jobs.ActionRetry, Kind: rec.Kind, Status: rec.Status, Reason: "input_unreadable"}
	}
	if _, err := tx.Q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: tenants.StatusProvisioning,
		ID: in.TenantID, FromStatus: tenants.StatusFailed}); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return ControlResult{}, &jobs.StateError{Action: jobs.ActionRetry, Kind: rec.Kind, Status: rec.Status,
				Reason: "tenant_not_failed"}
		}
		return ControlResult{}, err
	}
	op, err := audit.Requested(ctx, tx.Q, audit.Event{Action: ActionTenantCreate, ResourceType: "tenant",
		ResourceID: in.TenantID.String(), Details: audit.Details{"tenant_id": in.TenantID, "slug": in.Slug,
			"retry_of": rec.ID}})
	if err != nil {
		return ControlResult{}, err
	}
	old := rec.ID
	in.Operation, in.RetryOf = op, &old
	in.IdP.PendingSecretRef = "" // moved under the tenant (or expired) during the first job
	enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: JobKind, TenantID: &in.TenantID, Input: in, RequestedBy: &actor,
		Resource: &jobs.Resource{Type: "tenant", ID: in.TenantID.String()}})
	if err != nil {
		return ControlResult{}, err
	}
	tid := in.TenantID
	for _, name := range []string{StepValidate, StepRegistryCreate} {
		if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, name, jobs.StepSkipped,
			map[string]any{"retry_of": rec.ID}); err != nil {
			return ControlResult{}, err
		}
	}
	audit.HandOff(ctx, op)
	j, err := jobs.ProjectTx(ctx, tx.Q, enq.Job.ID)
	if err != nil {
		return ControlResult{}, err
	}
	return ControlResult{Job: j, From: rec.Status, NewJob: true, Changed: true},
		recordControl(ctx, tx, rec, ActionJobRetry, jobs.EventRetryNewJob, audit.Details{"new_job_id": enq.Job.ID})
}

// Cancel is /cancel.
func (c *Control) Cancel(ctx context.Context, actor, jobID uuid.UUID, idem *Idempotency) (ControlResult, error) {
	return c.idempotent(ctx, actor, CancelOperation, idem, func(tx *store.Tx) (ControlResult, error) {
		rec, err := jobs.LoadForControl(ctx, tx, jobID)
		if err != nil {
			return ControlResult{}, err
		}
		r, err := jobs.Cancel(ctx, tx, jobID)
		if err != nil {
			return ControlResult{}, err
		}
		out := ControlResult{Job: r.Job, From: r.From, Changed: r.Event != ""}
		switch {
		case r.Event == jobs.EventCancelQueued && rec.Kind == JobKind:
			// Nothing of the tenant was created beyond the registry rows of step 2: it ends failed, like a rollback.
			if err := failCancelled(ctx, tx, rec); err != nil {
				return out, err
			}
		case r.Event == jobs.EventCancelQueued:
			// Another job requested through the API (tenant.suspend, tenant.resume — P3-T08) never ran: its audit
			// operation closes with .failed (cancelled), nothing else changed.
			if err := closeCancelledOperation(ctx, tx, rec); err != nil {
				return out, err
			}
		}
		if !out.Changed {
			return out, nil
		}
		return out, recordControl(ctx, tx, rec, ActionJobCancel, r.Event, nil)
	})
}

func failCancelled(ctx context.Context, tx *store.Tx, rec sqlcdb.ProvisioningJob) error {
	var in Input
	if err := json.Unmarshal(rec.Input, &in); err != nil || in.validate() != nil {
		return nil //nolint:nilerr // an unreadable input has no tenant to fail
	}
	if _, err := tx.Q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: tenants.StatusFailed,
		ID: in.TenantID, FromStatus: tenants.StatusProvisioning}); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		return err
	}
	return in.Operation.Failed(ctx, tx.Q, jobs.CodeCancelled, audit.Details{"job_id": rec.ID, "cancelled": true})
}

// closeCancelledOperation closes the audit operation a cancelled job carries in its input ({"operation": …} — the
// lifecycle jobs requested through the API) with .failed (cancelled), once; a job without one has nothing to close.
func closeCancelledOperation(ctx context.Context, tx *store.Tx, rec sqlcdb.ProvisioningJob) error {
	var in struct {
		Operation audit.Operation `json:"operation"`
	}
	if err := json.Unmarshal(rec.Input, &in); err != nil || in.Operation.ID == uuid.Nil || in.Operation.Action == "" {
		return nil //nolint:nilerr // no operation in the input: nothing to close
	}
	st, err := tx.Q.OperationState(ctx, in.Operation.ID)
	if err != nil || !st.Requested || st.Finished {
		return err
	}
	return in.Operation.Failed(ctx, tx.Q, jobs.CodeCancelled, audit.Details{"job_id": rec.ID, "cancelled": true})
}

// Rollback is /rollback.
func (c *Control) Rollback(ctx context.Context, actor, jobID uuid.UUID, idem *Idempotency) (ControlResult, error) {
	return c.idempotent(ctx, actor, RollbackOperation, idem, func(tx *store.Tx) (ControlResult, error) {
		rec, err := jobs.LoadForControl(ctx, tx, jobID)
		if err != nil {
			return ControlResult{}, err
		}
		r, err := jobs.Rollback(ctx, tx, jobID)
		if err != nil {
			return ControlResult{}, err
		}
		return ControlResult{Job: r.Job, From: r.From, Changed: true}, recordControl(ctx, tx, rec, ActionJobRollback, r.Event, nil)
	})
}

// recordControl writes the audit event of a control action (x-audit-action of the operation, platform scope) in the
// transaction of the change.
func recordControl(ctx context.Context, tx *store.Tx, rec sqlcdb.ProvisioningJob, action, event string, extra audit.Details) error {
	d := audit.Details{"job_id": rec.ID, "kind": rec.Kind, "from": rec.Status, "event": event}
	if rec.TenantID != nil {
		d["tenant_id"] = *rec.TenantID
	}
	for k, v := range extra {
		d[k] = v
	}
	return audit.Record(ctx, tx.Q, audit.Event{Action: action, ResourceType: "job", ResourceID: rec.ID.String(), Details: d})
}
