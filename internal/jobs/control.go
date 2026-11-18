package jobs

// The lifecycle state machine of a job (§11.3) and the operator's controls POST /platform/jobs/{id}/retry, /cancel,
// /rollback (§13.2, permission platform.job:control — §8.5). The transitions are listed once, in Transitions; the
// controls consult it, the worker's own transitions (worker.go, maintenance.go) are tested against it row by row.

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Events of the lifecycle state machine.
const (
	EventAcquire          = "acquire"           // a worker takes the job; queued → running takes the tenant's lock
	EventSucceed          = "succeed"           // the handler returned nil
	EventTransientRetry   = "transient_retry"   // transient error with attempts left: River retries with backoff
	EventInterrupt        = "interrupt"         // the worker stopped mid-attempt: not counted, resumes after restart
	EventRetriesExhausted = "retries_exhausted" // transient error on the last attempt, or a Resumable error
	EventTimeout          = "timeout"           // timeout_at passed (10 min for the lifecycle group)
	EventPanic            = "panic"             // the handler panicked: never retried
	EventPermanent        = "permanent"         // unrecoverable error: compensation in reverse order (Compensator)
	EventCompensated      = "compensated"       // every completed step undone
	EventCompensationFail = "compensation_failed"
	EventReaped           = "reaped"           // job.reaper: running/compensating past timeout_at (worker lost)
	EventCancelQueued     = "cancel"           // /cancel on a job that never started
	EventCancelRequested  = "cancel_requested" // /cancel on a running job: it stops after its current step
	EventCancelObserved   = "cancel_observed"  // the handler saw the request before its next step
	EventRetry            = "retry"            // /retry on failed_resumable: resumes from the failed step
	EventRollback         = "rollback"         // /rollback on failed_resumable: compensation in reverse order
	EventRetryNewJob      = "retry_new_job"    // /retry on rolled_back (tenant.provision): a NEW job from step 3
)

// Transition is one edge of the lifecycle state machine of the lifecycle group (LockHold kinds).
type Transition struct {
	From, Event, To string
	Note            string
}

// Transitions is the state machine of a lifecycle job (§11.3). The lifecycle lock (lock_key) is held in running,
// compensating and failed_resumable; queued and every finished status hold none.
var Transitions = []Transition{
	{StatusQueued, EventAcquire, StatusRunning, "takes the tenant's lifecycle lock; a held lock ⇒ snooze, no attempt used"},
	{StatusQueued, EventCancelQueued, StatusCancelled, "/cancel before the first run"},
	{StatusRunning, EventSucceed, StatusSucceeded, "releases the lock"},
	{StatusRunning, EventTransientRetry, StatusRunning, "keeps the lock; backoff 2 s → 60 s ± 20 %"},
	{StatusRunning, EventInterrupt, StatusRunning, "attempt not counted"},
	{StatusRunning, EventRetriesExhausted, StatusFailedResumable, "no compensation; resources kept; edge not attached unless step 14 ran"},
	{StatusRunning, EventTimeout, StatusFailedResumable, "the 10-minute job deadline"},
	{StatusRunning, EventPanic, StatusFailedResumable, "never retried"},
	{StatusRunning, EventPermanent, StatusCompensating, "kinds with a Compensator; others end failed_resumable"},
	{StatusRunning, EventReaped, StatusFailedResumable, "job.reaper: worker_lost / queue_lost"},
	{StatusRunning, EventCancelRequested, StatusRunning, "cancel_requested_at set"},
	{StatusRunning, EventCancelObserved, StatusFailedResumable, "code cancelled; no compensation"},
	{StatusCompensating, EventCompensated, StatusRolledBack, "releases the lock; tenant.provision: tenant failed"},
	{StatusCompensating, EventCompensationFail, StatusFailedResumable, "code compensation_failed; /rollback resumes it"},
	{StatusCompensating, EventInterrupt, StatusCompensating, "delivered again; compensation resumes"},
	{StatusCompensating, EventReaped, StatusFailedResumable, "job.reaper: worker_lost"},
	{StatusFailedResumable, EventRetry, StatusRunning, "never through queued: the lock never leaves the job"},
	{StatusFailedResumable, EventRollback, StatusCompensating, "compensable kinds only"},
	{StatusRolledBack, EventRetryNewJob, StatusQueued, "the rolled_back job stays; a new job of the same kind is queued"},
}

// NextStatus returns the status a lifecycle job in from reaches on event (ok = false: no such transition).
func NextStatus(from, event string) (string, bool) {
	for _, t := range Transitions {
		if t.From == from && t.Event == event {
			return t.To, true
		}
	}
	return "", false
}

// Control actions (the path segment of POST /platform/jobs/{jobId}/<action>).
const (
	ActionRetry    = "retry"
	ActionCancel   = "cancel"
	ActionRollback = "rollback"
)

// ErrJobState: the job's kind or status does not allow the action ⇒ 409 conflict.
var ErrJobState = errors.New("jobs: the job's status does not allow this action")

// StateError is a refused control action (errors.Is(err, ErrJobState)).
type StateError struct {
	Action, Kind, Status string
	Reason               string // stable code: status_not_allowed, kind_not_lifecycle, kind_not_compensable, point_of_no_return
}

func (e *StateError) Error() string {
	return fmt.Sprintf("jobs: %s refused for a %s job in status %s (%s)", e.Action, e.Kind, e.Status, e.Reason)
}

// Is makes errors.Is(err, ErrJobState) true.
func (e *StateError) Is(target error) bool { return target == ErrJobState }

// Controlled is the outcome of a control action.
type Controlled struct {
	Job    Job
	From   string // status before
	Event  string // the transition applied ("" = nothing changed: a repeated /cancel)
	Record sqlcdb.ProvisioningJob
}

// LoadForControl reads a job in the caller's platform transaction (ErrNotFound when absent).
func LoadForControl(ctx context.Context, tx *store.Tx, id uuid.UUID) (sqlcdb.ProvisioningJob, error) {
	rec, err := tx.Q.GetJob(ctx, id)
	if errors.Is(err, store.ErrNoRows) {
		return rec, ErrNotFound
	}
	return rec, err
}

// Retry is /retry of a failed_resumable lifecycle job (§11.3): straight back to running — never through queued, so the
// tenant's lifecycle lock never leaves the job — with a new River job, fresh attempts and a fresh timeout_at; the job
// resumes from the step that failed (succeeded steps are skipped). A rolled_back job is not resumed: its kind decides
// (tenant.provision creates a new job — provisioning.Control); here it is a StateError.
func Retry(ctx context.Context, tx *store.Tx, id uuid.UUID) (Controlled, error) {
	rec, k, err := controllable(ctx, tx, id, ActionRetry)
	if err != nil {
		return Controlled{}, err
	}
	if _, ok := NextStatus(rec.Status, EventRetry); !ok {
		return Controlled{}, &StateError{Action: ActionRetry, Kind: rec.Kind, Status: rec.Status, Reason: "status_not_allowed"}
	}
	qid, err := tx.InsertQueueJob(ctx, queueArgs{JobID: rec.ID, JobKind: k.Name},
		&river.InsertOpts{Queue: k.Queue, MaxAttempts: k.MaxAttempts + queueSlack})
	if err != nil {
		return Controlled{}, err
	}
	row, err := tx.Q.ResumeJob(ctx, sqlcdb.ResumeJobParams{Attempts: int32(k.MaxAttempts), QueueJobID: qid, ID: rec.ID}) //nolint:gosec // small registry value
	if err != nil {
		return Controlled{}, controlRace(err, ActionRetry, rec)
	}
	return controlled(ctx, tx, row, rec.Status, EventRetry)
}

// Rollback is /rollback of a failed_resumable lifecycle job whose kind can compensate: compensating with a new River
// job; the worker undoes the completed steps in reverse order and ends rolled_back (or failed_resumable when the
// compensation itself fails — /rollback again resumes it).
func Rollback(ctx context.Context, tx *store.Tx, id uuid.UUID) (Controlled, error) {
	rec, k, err := controllable(ctx, tx, id, ActionRollback)
	if err != nil {
		return Controlled{}, err
	}
	if !k.Compensable {
		return Controlled{}, &StateError{Action: ActionRollback, Kind: rec.Kind, Status: rec.Status, Reason: "kind_not_compensable"}
	}
	if _, ok := NextStatus(rec.Status, EventRollback); !ok {
		return Controlled{}, &StateError{Action: ActionRollback, Kind: rec.Kind, Status: rec.Status, Reason: "status_not_allowed"}
	}
	if passed, err := PastPointOfNoReturn(ctx, tx.Q, k, rec.ID); err != nil {
		return Controlled{}, err
	} else if passed {
		return Controlled{}, &StateError{Action: ActionRollback, Kind: rec.Kind, Status: rec.Status, Reason: ReasonPointOfNoReturn}
	}
	qid, err := tx.InsertQueueJob(ctx, queueArgs{JobID: rec.ID, JobKind: k.Name},
		&river.InsertOpts{Queue: k.Queue, MaxAttempts: k.MaxAttempts + queueSlack})
	if err != nil {
		return Controlled{}, err
	}
	row, err := tx.Q.RollbackJob(ctx, sqlcdb.RollbackJobParams{QueueJobID: qid, TimeoutSecs: k.Timeout.Seconds(), ID: rec.ID})
	if err != nil {
		return Controlled{}, controlRace(err, ActionRollback, rec)
	}
	return controlled(ctx, tx, row, rec.Status, EventRollback)
}

// ReasonPointOfNoReturn: /rollback of a job past its kind's point of no return (Kind.PointOfNoReturn).
const ReasonPointOfNoReturn = "point_of_no_return"

// PastPointOfNoReturn reports whether job id of kind k has passed the kind's point of no return: the step
// Kind.PointOfNoReturn exists and recorded its created_resources (the step records them just before its first
// irreversible action). Kinds without one never pass it. Used by /rollback and by the compensation itself (defence in
// depth: a compensation that finds the job past it refuses).
func PastPointOfNoReturn(ctx context.Context, q *sqlcdb.Queries, k Kind, id uuid.UUID) (bool, error) {
	if k.PointOfNoReturn == "" {
		return false, nil
	}
	row, err := q.GetJobStep(ctx, sqlcdb.GetJobStepParams{JobID: id, Name: k.PointOfNoReturn})
	if errors.Is(err, store.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(row.CreatedResources) > 0 && string(row.CreatedResources) != "null", nil
}

// KindOf returns the kind of the §13.5 registry named name (ok = false: unknown).
func KindOf(name string) (Kind, bool) {
	k, ok := registry[name]
	return k, ok
}

// Cancel is /cancel: a queued job ends cancelled at once; a running lifecycle job is asked to stop after its current
// step (it then ends failed_resumable, without compensation — §11.3). Asking again is a no-op.
func Cancel(ctx context.Context, tx *store.Tx, id uuid.UUID) (Controlled, error) {
	rec, err := LoadForControl(ctx, tx, id)
	if err != nil {
		return Controlled{}, err
	}
	k, known := registry[rec.Kind]
	switch {
	case rec.Status == StatusQueued:
		row, err := tx.Q.CancelQueuedJob(ctx, sqlcdb.CancelQueuedJobParams{
			Error: jobError(CodeCancelled, "cancelled by an operator before it started"), ID: rec.ID})
		if err != nil {
			return Controlled{}, controlRace(err, ActionCancel, rec)
		}
		return controlled(ctx, tx, row, rec.Status, EventCancelQueued)
	case !known || k.Lock != LockHold:
		return Controlled{}, &StateError{Action: ActionCancel, Kind: rec.Kind, Status: rec.Status, Reason: "kind_not_lifecycle"}
	case rec.Status == StatusRunning:
		row, err := tx.Q.RequestJobCancel(ctx, rec.ID)
		if err != nil {
			return Controlled{}, controlRace(err, ActionCancel, rec)
		}
		ev := EventCancelRequested
		if rec.CancelRequestedAt != nil {
			ev = "" // already requested
		}
		return controlled(ctx, tx, row, rec.Status, ev)
	}
	return Controlled{}, &StateError{Action: ActionCancel, Kind: rec.Kind, Status: rec.Status, Reason: "status_not_allowed"}
}

// controllable loads a job of a lifecycle kind (retry and rollback apply to the lifecycle group only).
func controllable(ctx context.Context, tx *store.Tx, id uuid.UUID, action string) (sqlcdb.ProvisioningJob, Kind, error) {
	rec, err := LoadForControl(ctx, tx, id)
	if err != nil {
		return rec, Kind{}, err
	}
	k, ok := registry[rec.Kind]
	if !ok || k.Lock != LockHold {
		return rec, k, &StateError{Action: action, Kind: rec.Kind, Status: rec.Status, Reason: "kind_not_lifecycle"}
	}
	return rec, k, nil
}

// controlRace: the conditional update found the job in another status (a worker or the reaper moved it meanwhile).
func controlRace(err error, action string, rec sqlcdb.ProvisioningJob) error {
	if errors.Is(err, store.ErrNoRows) {
		return &StateError{Action: action, Kind: rec.Kind, Status: rec.Status, Reason: "status_changed"}
	}
	return err
}

func controlled(ctx context.Context, tx *store.Tx, row sqlcdb.ProvisioningJob, from, event string) (Controlled, error) {
	steps, err := tx.Q.ListJobSteps(ctx, []uuid.UUID{row.ID})
	if err != nil {
		return Controlled{}, err
	}
	return Controlled{Job: project(row, steps), From: from, Event: event, Record: row}, nil
}

// EnqueueFinishedStep records, in the caller's transaction, a step that ran outside the worker (steps 1–2 of
// tenant.provision run in the API, inside the transaction that enqueues the job) or that a new job skips (the job
// created by /retry of a rolled_back tenant.provision starts at step 3).
func EnqueueFinishedStep(ctx context.Context, tx *store.Tx, jobID uuid.UUID, tenantID *uuid.UUID, name, status string,
	detail any,
) error {
	if !stepNameRE.MatchString(name) || (status != StepSucceeded && status != StepSkipped) {
		return fmt.Errorf("%w: finished step %q (%s)", ErrInvalidSpec, name, status)
	}
	var d []byte
	if detail != nil {
		b, err := marshalObject(detail)
		if err != nil {
			return err
		}
		d = b
	}
	attempt := int32(1)
	if status == StepSkipped {
		attempt = 0
	}
	return tx.Q.InsertFinishedJobStep(ctx, sqlcdb.InsertFinishedJobStepParams{TenantID: tenantID, JobID: jobID, Name: name,
		Status: status, Attempt: attempt, Detail: d})
}
