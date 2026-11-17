package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/riverqueue/river"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// queueKind is the River kind of every MeshGuard job: River carries only the provisioning_jobs ID and the business kind
// (§6.3), the business kind selects the handler.
const queueKind = "meshguard.job"

// queueArgs are the args of every River job.
type queueArgs struct {
	JobID   uuid.UUID `json:"job_id,omitzero"` // provisioning_jobs.id; zero for a periodic run (row created at start)
	JobKind string    `json:"kind"`
	Slot    string    `json:"slot,omitempty"` // periodic runs: the schedule slot of the dedupe key
}

func (queueArgs) Kind() string { return queueKind }

const (
	uniqueViolation = "23505"
	lockIndex       = "provisioning_jobs_lock_key" // partial unique index of 0006
)

// Handler runs the jobs of one kind. Modules register theirs on the Worker in apps/worker (§13.6: jobs imports no
// business module). A handler must be idempotent — a job runs again after a retry, an interrupted attempt or a /retry —,
// must honour ctx (its deadline is the job's timeout_at), must not hold a transaction across calls to the Agent or
// Headscale, and must never put a secret in its errors, output or step detail (§11.3).
type Handler interface {
	Run(ctx context.Context, run *Run) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, run *Run) error

// Run calls f.
func (f HandlerFunc) Run(ctx context.Context, run *Run) error { return f(ctx, run) }

// Compensator is implemented by lifecycle handlers that can undo, in reverse order, the steps they completed (§11.3).
// It is called in the same attempt after a permanent error, with a fresh deadline: success ends the job rolled_back,
// failure failed_resumable (the operator decides).
type Compensator interface {
	Compensate(ctx context.Context, run *Run, cause error) error
}

// Options are the optional collaborators of a Worker.
type Options struct {
	Logger     *slog.Logger
	Registerer prometheus.Registerer      // nil ⇒ metrics are kept but not exported
	Alerter    Alerter                    // receives every alert after it is counted and logged
	Partitions *store.PartitionMaintainer // nil ⇒ partition.maintain is not scheduled in this process
}

// Worker runs jobs: the River client of the process (store.QueueClient) and the registered handlers. job.reaper and
// retention.sweep are built in, and partition.maintain when Options.Partitions is set.
type Worker struct {
	st         *store.Store
	cfg        Config
	log        *slog.Logger
	alerter    Alerter
	metrics    *metrics
	partitions *store.PartitionMaintainer

	mu        sync.Mutex
	handlers  map[string]Handler
	periodics []periodic // RegisterPeriodic
	client    *store.QueueClient
	started   bool
}

// NewWorker validates cfg and returns a worker with the built-in handlers registered.
func NewWorker(st *store.Store, cfg Config, opts Options) (*Worker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	w := &Worker{st: st, cfg: cfg, log: log, alerter: opts.Alerter, metrics: newMetrics(opts.Registerer),
		partitions: opts.Partitions, handlers: map[string]Handler{}}
	w.handlers["job.reaper"] = HandlerFunc(w.runReaper)
	w.handlers["retention.sweep"] = HandlerFunc(w.runSweep)
	if w.partitions != nil {
		w.handlers["partition.maintain"] = HandlerFunc(w.runPartitionMaintain)
	}
	return w, nil
}

// Register sets the handler of a kind; call it before Start.
func (w *Worker) Register(kind string, h Handler) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return errorf("register %s: the worker has started", kind)
	}
	if _, ok := w.cfg.Kinds[kind]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	if _, dup := w.handlers[kind]; dup {
		return errorf("a handler for %s is already registered", kind)
	}
	w.handlers[kind] = h
	return nil
}

// Start creates the River client (its own pool, mg_worker_platform) and starts working the queues. Cancelling ctx
// starts a graceful stop.
func (w *Worker) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return errorf("the worker has already started")
	}
	client, err := w.st.NewQueueClient(ctx, w.riverConfig(), w.cfg.QueuePoolConns)
	if err != nil {
		return err
	}
	if err := client.Start(ctx); err != nil {
		client.Close()
		return err
	}
	w.client, w.started = client, true
	return nil
}

// Stop stops fetching jobs, gives running ones SoftStopTimeout, then cancels them (they resume after restart).
func (w *Worker) Stop(ctx context.Context) error {
	w.mu.Lock()
	c := w.client
	w.client = nil
	w.mu.Unlock()
	if c == nil {
		return nil
	}
	err := c.Stop(ctx)
	c.Close()
	return err
}

// riverConfig is the River client configuration — every timeout explicit (§11.3).
func (w *Worker) riverConfig() *river.Config {
	workers := river.NewWorkers()
	river.AddWorker[queueArgs](workers, &queueWorker{w: w})
	queues := make(map[string]river.QueueConfig, len(w.cfg.Queues))
	for name, n := range w.cfg.Queues {
		queues[name] = river.QueueConfig{MaxWorkers: n}
	}
	return &river.Config{
		Workers:                     workers,
		Queues:                      queues,
		PeriodicJobs:                w.periodicJobs(),
		JobTimeout:                  w.cfg.JobTimeout,
		RescueStuckJobsAfter:        w.cfg.RescueStuckJobsAfter,
		SoftStopTimeout:             w.cfg.SoftStopTimeout,
		JobStuckThreshold:           w.cfg.JobStuckThreshold,
		FetchCooldown:               w.cfg.FetchCooldown,
		FetchPollInterval:           w.cfg.FetchPollInterval,
		CompletedJobRetentionPeriod: w.cfg.CompletedRetention,
		CancelledJobRetentionPeriod: w.cfg.CancelledRetention,
		DiscardedJobRetentionPeriod: w.cfg.DiscardedRetention,
		MaxAttempts:                 1 + queueSlack, // every insert sets its own; this only covers a forgotten one
		// River's reindexer needs ownership (or MAINTAIN) of its tables, which mg_worker_platform does not have:
		// autovacuum keeps the small queue tables in shape; REINDEX, if ever needed, runs as mg_migrator.
		ReindexerSchedule: river.NeverSchedule(),
		Logger:            w.log,
		TestOnly:          w.cfg.testOnly,
	}
}

// queueWorker is the single River worker: per-kind timeout and backoff, then Worker.work.
type queueWorker struct {
	river.WorkerDefaults[queueArgs]
	w *Worker
}

// Timeout is River's attempt timeout: the kind's WorkerTimeout (the lifecycle group: = RescueStuckJobsAfter).
func (q *queueWorker) Timeout(job *river.Job[queueArgs]) time.Duration {
	if k, ok := q.w.cfg.Kinds[job.Args.JobKind]; ok {
		return k.WorkerTimeout
	}
	return q.w.cfg.JobTimeout
}

// NextRetry is the exponential backoff with jitter of §11.3.
func (q *queueWorker) NextRetry(job *river.Job[queueArgs]) time.Time {
	return time.Now().Add(backoff(job.Attempt, q.w.cfg.RetryBase, q.w.cfg.RetryMax))
}

func (q *queueWorker) Work(ctx context.Context, job *river.Job[queueArgs]) error {
	return q.w.work(ctx, job.ID, job.Args)
}

// work is one delivery of a River job: take the business job (and the lifecycle lock), run the handler, record the
// outcome.
func (w *Worker) work(ctx context.Context, queueJobID int64, args queueArgs) error {
	k, known := w.cfg.Kinds[args.JobKind]
	h := w.handlers[args.JobKind]
	if !known || h == nil {
		w.log.Warn("no handler for this job kind in this worker; snoozing", "kind", args.JobKind, "job_id", args.JobID)
		return river.JobSnooze(w.cfg.NoHandlerSnooze)
	}
	var (
		rec sqlcdb.ProvisioningJob
		err error
	)
	if args.JobID == uuid.Nil {
		rec, err = w.startPeriodic(ctx, k, args, queueJobID)
	} else {
		rec, err = w.acquire(ctx, k, args.JobID, queueJobID)
	}
	switch {
	case err == nil:
	case store.SQLState(err) == uniqueViolation && store.SQLConstraint(err) == lockIndex:
		// Another lifecycle job of the tenant holds the lock: wait without using an attempt (§13.5 (d)).
		w.metrics.lockWaits.WithLabelValues(k.Name).Inc()
		return river.JobSnooze(w.lockSnooze(ctx, args.JobID))
	case errors.Is(err, store.ErrNoRows):
		// Nothing to run: the job finished, waits in failed_resumable or compensating, was cancelled, or is carried by
		// another River job (a stale delivery, the rescue of a reaped job, a periodic slot already running).
		w.log.Info("job not runnable; delivery ignored", "kind", k.Name, "job_id", args.JobID, "queue_job_id", queueJobID)
		return nil
	default:
		w.log.Error("job bookkeeping failed", "kind", k.Name, "job_id", args.JobID, "error", scrub(err.Error()))
		return errorf("bookkeeping failed (sqlstate %q)", store.SQLState(err))
	}
	return w.execute(ctx, k, h, rec)
}

// acquire moves the job to running (queued → running takes the lifecycle lock; running → running is the next attempt
// of the same River job) and sets timeout_at at the first start.
func (w *Worker) acquire(ctx context.Context, k Kind, id uuid.UUID, queueJobID int64) (sqlcdb.ProvisioningJob, error) {
	var rec sqlcdb.ProvisioningJob
	err := w.bookkeep(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		rec, err = acquireJob(ctx, tx.Q, id, queueJobID, k.Timeout.Seconds())
		return err
	})
	return rec, err
}

// acquireJob is AcquireJob followed by MarkJobStarted in the caller's transaction. The first statement may wait for the
// previous holder of the tenant's lock to commit (unique index on lock_key), so a timestamp computed inside it can be
// older than that holder's finished_at; the second runs only once the lock is held, so started_at never precedes it.
// ErrNoRows / 23505 come from the first statement, as before.
func acquireJob(ctx context.Context, q *sqlcdb.Queries, id uuid.UUID, queueJobID int64, timeoutSecs float64) (sqlcdb.ProvisioningJob, error) {
	if _, err := q.AcquireJob(ctx, sqlcdb.AcquireJobParams{ID: id, QueueJobID: queueJobID}); err != nil {
		return sqlcdb.ProvisioningJob{}, err
	}
	return q.MarkJobStarted(ctx, sqlcdb.MarkJobStartedParams{ID: id, TimeoutSecs: timeoutSecs})
}

// startPeriodic records a periodic run (River periodic jobs have no business row yet) directly as running, or resumes
// the run of this same River job after a failed attempt. A run of the same slot carried by another River job ⇒
// ErrNoRows.
func (w *Worker) startPeriodic(ctx context.Context, k Kind, args queueArgs, queueJobID int64) (sqlcdb.ProvisioningJob, error) {
	dedupe, err := k.dedupeKey(Spec{Slot: args.Slot})
	if err != nil {
		return sqlcdb.ProvisioningJob{}, err
	}
	var rec sqlcdb.ProvisioningJob
	err = w.bookkeep(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		rec, err = tx.Q.InsertRunningJob(ctx, sqlcdb.InsertRunningJobParams{Kind: k.Name, DedupeKey: dedupe,
			MaxAttempts: int32(k.MaxAttempts), QueueJobID: queueJobID, TimeoutSecs: k.Timeout.Seconds()}) //nolint:gosec // registry value
		if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		active, err := tx.Q.GetActiveJobByDedupeKey(ctx, dedupe)
		if err != nil {
			return err
		}
		rec, err = acquireJob(ctx, tx.Q, active.ID, queueJobID, k.Timeout.Seconds())
		return err
	})
	return rec, err
}

// lockSnooze is how long a lifecycle job waits for its tenant's lock: longer while the holder sits in failed_resumable.
func (w *Worker) lockSnooze(ctx context.Context, id uuid.UUID) time.Duration {
	d := w.cfg.LockBusySnooze
	_ = w.bookkeep(ctx, func(ctx context.Context, tx *store.Tx) error {
		rec, err := tx.Q.GetJob(ctx, id)
		if err != nil || rec.LockKey == nil {
			return err
		}
		if holder, err := tx.Q.GetLockHolder(ctx, *rec.LockKey); err == nil && holder.Status == StatusFailedResumable {
			d = w.cfg.LockHeldSnooze
		}
		return nil
	})
	return jitter(d, 0.2)
}

// bookkeep runs one framework write in its own short platform transaction, on a context detached from the job's
// (a cancelled or timed-out job is still recorded) and bounded by BookkeepingTimeout.
func (w *Worker) bookkeep(ctx context.Context, fn func(ctx context.Context, tx *store.Tx) error) error {
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.cfg.BookkeepingTimeout)
	defer cancel()
	return w.st.WithPlatformJobTx(bctx, func(tx *store.Tx) error { return fn(bctx, tx) })
}

// execute runs one attempt and records its outcome (§11.3):
//
//	success                                       → succeeded
//	transient error, attempts left                → stays running (keeps the lock), River retries with backoff
//	transient error on the last attempt, timeout  → failed_resumable (lifecycle group) / failed
//	permanent error                               → compensating → rolled_back (lifecycle group with a Compensator);
//	                                                failed_resumable (lifecycle group) / failed otherwise
//	worker stopping                               → attempt not counted, resumes after restart
func (w *Worker) execute(ctx context.Context, k Kind, h Handler, rec sqlcdb.ProvisioningJob) error {
	if rec.Attempt > rec.MaxAttempts {
		return w.fail(ctx, k, rec, CodeRetriesExhausted,
			fmt.Sprintf("delivered again after its last attempt (%d of %d)", rec.Attempt, rec.MaxAttempts))
	}
	deadline := time.Now().Add(k.Timeout)
	if rec.TimeoutAt != nil {
		deadline = *rec.TimeoutAt
	}
	if !time.Now().Before(deadline) {
		return w.fail(ctx, k, rec, CodeTimeout, "timeout_at had passed when the attempt started")
	}
	run := w.newRun(rec, deadline)
	hctx, cancel := context.WithDeadline(ctx, deadline)
	start := time.Now()
	herr := call(hctx, h.Run, run)
	cancel()
	w.metrics.duration.WithLabelValues(k.Name).Observe(time.Since(start).Seconds())
	if herr == nil {
		return w.finish(ctx, k, rec, StatusRunning, StatusSucceeded, nil, run, "")
	}
	code, permanent, msg := classify(herr)
	var pe *panicError
	switch {
	case errors.As(herr, &pe):
		return w.fail(ctx, k, rec, CodeHandlerPanic, msg)
	case !time.Now().Before(deadline):
		return w.fail(ctx, k, rec, CodeTimeout, msg)
	case ctx.Err() != nil:
		return w.interrupt(ctx, k, rec, msg)
	case permanent:
		if c, ok := h.(Compensator); ok && k.Lock == LockHold {
			return w.compensate(ctx, k, rec, run, c, herr, code, msg)
		}
		return w.fail(ctx, k, rec, code, msg)
	case rec.Attempt >= rec.MaxAttempts:
		return w.fail(ctx, k, rec, code, fmt.Sprintf("%s (attempt %d of %d)", msg, rec.Attempt, rec.MaxAttempts))
	}
	_ = w.bookkeep(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.Q.RecordJobError(ctx, sqlcdb.RecordJobErrorParams{Error: jobError(code, msg), ID: rec.ID, Attempt: rec.Attempt})
	})
	// River records this message in river_job.errors: the code only, never the handler's text.
	return errorf("%s attempt %d of %d failed: %s", k.Name, rec.Attempt, rec.MaxAttempts, code)
}

// fail ends the job for good: failed_resumable for the lifecycle group — no compensation, resources kept, the lock
// held until /retry or /rollback (§11.3) —, failed otherwise.
func (w *Worker) fail(ctx context.Context, k Kind, rec sqlcdb.ProvisioningJob, code, msg string) error {
	to := StatusFailed
	if k.Lock == LockHold {
		to = StatusFailedResumable
	}
	return w.finish(ctx, k, rec, rec.Status, to, jobError(code, msg), nil, code)
}

// interrupt records an attempt cut short by the worker stopping: the attempt is not counted and the job stays running
// (it keeps the lifecycle lock). The returned error wraps context.Canceled, so River makes the job available again
// without using an attempt; if the worker never comes back, job.reaper settles it after timeout_at.
func (w *Worker) interrupt(ctx context.Context, k Kind, rec sqlcdb.ProvisioningJob, msg string) error {
	_ = w.bookkeep(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.Q.InterruptJob(ctx, sqlcdb.InterruptJobParams{Error: jobError(CodeInterrupted, msg), ID: rec.ID, Attempt: rec.Attempt})
	})
	w.log.Info("job attempt interrupted; it resumes after restart", "kind", k.Name, "job_id", rec.ID)
	return fmt.Errorf("jobs: %s interrupted: %w", k.Name, context.Canceled)
}

// compensate undoes a lifecycle job after a permanent error (§11.3): compensating (lock kept) → rolled_back, or
// failed_resumable when the compensation itself fails.
func (w *Worker) compensate(ctx context.Context, k Kind, rec sqlcdb.ProvisioningJob, run *Run, c Compensator, cause error,
	code, msg string,
) error {
	var comp sqlcdb.ProvisioningJob
	err := w.bookkeep(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		comp, err = tx.Q.BeginCompensation(ctx, sqlcdb.BeginCompensationParams{Error: jobError(code, msg),
			TimeoutSecs: k.Timeout.Seconds(), ID: rec.ID, Attempt: rec.Attempt})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		w.log.Warn("job changed while running; compensation skipped", "kind", k.Name, "job_id", rec.ID)
		return nil
	case err != nil:
		return errorf("bookkeeping failed (sqlstate %q)", store.SQLState(err))
	}
	deadline := time.Now().Add(k.Timeout)
	if comp.TimeoutAt != nil {
		deadline = *comp.TimeoutAt
	}
	cctx, cancel := context.WithDeadline(ctx, deadline)
	cerr := call(cctx, func(ctx context.Context, run *Run) error { return c.Compensate(ctx, run, cause) }, run)
	cancel()
	if cerr != nil {
		ccode, _, cmsg := classify(cerr)
		return w.finish(ctx, k, comp, StatusCompensating, StatusFailedResumable,
			jobError(CodeCompensationFailed, ccode+": "+cmsg), nil, CodeCompensationFailed)
	}
	return w.finish(ctx, k, comp, StatusCompensating, StatusRolledBack, jobError(code, msg), nil, code)
}

// finish records the outcome of this worker's attempt, conditioned on the status and attempt it observed: when
// job.reaper (or a cancellation) changed the job meanwhile nothing is written. A failure outcome raises an alert and
// cancels the River job so the queue stops retrying it.
func (w *Worker) finish(ctx context.Context, k Kind, rec sqlcdb.ProvisioningJob, from, to string, errJSON []byte, run *Run,
	code string,
) error {
	p := sqlcdb.TransitionJobParams{ToStatus: to, Error: errJSON, ID: rec.ID, FromStatus: from, Attempt: rec.Attempt}
	if run != nil {
		p.Output = run.output
		if run.resource != nil {
			p.ResourceType, p.ResourceID = &run.resource.Type, &run.resource.ID
		}
	}
	var updated sqlcdb.ProvisioningJob
	err := w.bookkeep(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		updated, err = tx.Q.TransitionJob(ctx, p)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		w.log.Warn("job changed while running (reaped or cancelled); outcome not recorded", "kind", k.Name,
			"job_id", rec.ID, "outcome", to)
		return nil
	case err != nil:
		w.log.Error("recording a job outcome failed", "kind", k.Name, "job_id", rec.ID, "outcome", to, "error", scrub(err.Error()))
		return errorf("recording %s failed (sqlstate %q)", to, store.SQLState(err))
	}
	w.metrics.finished.WithLabelValues(k.Name, to).Inc()
	if reason := alertReason(to); reason != "" {
		w.alert(ctx, Alert{Reason: reason, JobID: rec.ID, TenantID: updated.TenantID, Kind: k.Name, Status: to, Code: code})
	}
	if to == StatusSucceeded {
		return nil
	}
	return river.JobCancel(errorf("%s %s: %s", k.Name, to, code))
}

func alertReason(status string) string {
	switch status {
	case StatusFailed:
		return AlertFailed
	case StatusFailedResumable:
		return AlertFailedResumable
	case StatusRolledBack:
		return AlertRolledBack
	}
	return ""
}

// panicError is a recovered handler panic: never retried.
type panicError struct{ v any }

func (p *panicError) Error() string { return fmt.Sprintf("handler panic: %v", p.v) }

func call(ctx context.Context, f func(context.Context, *Run) error, run *Run) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &panicError{v: v}
		}
	}()
	return f(ctx, run)
}

// Run is one attempt of a job, handed to its handler.
type Run struct {
	ID          uuid.UUID
	Kind        string
	TenantID    *uuid.UUID
	InstanceID  *uuid.UUID
	Input       json.RawMessage // the job's parameters (a JSON object)
	Attempt     int             // 1 for the first run
	MaxAttempts int
	Deadline    time.Time    // timeout_at: the deadline of the whole job, across attempts
	Store       *store.Store // for the handler's own transactions

	w        *Worker
	output   []byte
	resource *Resource
}

func (w *Worker) newRun(rec sqlcdb.ProvisioningJob, deadline time.Time) *Run {
	return &Run{ID: rec.ID, Kind: rec.Kind, TenantID: rec.TenantID, InstanceID: rec.InstanceID, Input: rec.Input,
		Attempt: int(rec.Attempt), MaxAttempts: int(rec.MaxAttempts), Deadline: deadline, Store: w.st, w: w}
}

// DecodeInput unmarshals the job's input into v.
func (r *Run) DecodeInput(v any) error { return json.Unmarshal(r.Input, v) }

// SetOutput sets the output stored when the job succeeds (a JSON object, no secret).
func (r *Run) SetOutput(v any) error {
	b, err := marshalObject(v)
	if err != nil {
		return err
	}
	r.output = b
	return nil
}

// SetResource sets the resource the job created (Job.resource), stored when the job succeeds.
func (r *Run) SetResource(typ, id string) { r.resource = &Resource{Type: typ, ID: id} }

var stepNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// Step runs one named step of the job and records it in provisioning_job_steps (§11.3): a step that succeeded in an
// earlier attempt is skipped — the job resumes from the step that failed —, attempts are counted, and a failure stores
// its code (the tenant's message is built from it) and its redacted message in the raw detail. Steps of a job run one
// at a time.
func (r *Run) Step(ctx context.Context, name string, fn func(ctx context.Context, s *StepRun) error) error {
	if !stepNameRE.MatchString(name) {
		return Permanent("invalid_step", errorf("invalid step name %q", name))
	}
	var started bool
	err := r.w.bookkeep(ctx, func(bctx context.Context, tx *store.Tx) error {
		_, err := tx.Q.StartJobStep(bctx, sqlcdb.StartJobStepParams{TenantID: r.TenantID, JobID: r.ID, Name: name})
		if errors.Is(err, store.ErrNoRows) {
			return nil // succeeded in an earlier attempt
		}
		if err != nil {
			return err
		}
		started = true
		return tx.Q.SetJobCurrentStep(bctx, sqlcdb.SetJobCurrentStepParams{CurrentStep: name, ID: r.ID, Attempt: int32(r.Attempt)}) //nolint:gosec // attempt count
	})
	if err != nil {
		return Transient("step_bookkeeping", errorf("step %s: sqlstate %q", name, store.SQLState(err)))
	}
	if !started {
		return nil
	}
	s := &StepRun{run: r, name: name}
	ferr := call(ctx, func(ctx context.Context, _ *Run) error { return fn(ctx, s) }, r)
	status, code, detail := StepSucceeded, (*string)(nil), s.detail
	if ferr != nil {
		c, _, msg := classify(ferr)
		status, code, detail = StepFailed, &c, withError(detail, msg)
	}
	if err := r.w.bookkeep(ctx, func(bctx context.Context, tx *store.Tx) error {
		return tx.Q.FinishJobStep(bctx, sqlcdb.FinishJobStepParams{Status: status, ErrorCode: code, Detail: detail,
			JobID: r.ID, Name: name})
	}); err != nil {
		return errors.Join(ferr, Transient("step_bookkeeping", errorf("step %s: sqlstate %q", name, store.SQLState(err))))
	}
	return ferr
}

// StepRun is the running step handed to a Step function.
type StepRun struct {
	run    *Run
	name   string
	detail []byte
}

// RecordCreated stores what the step is about to create — BEFORE creating it — so a compensation removes exactly what
// this job made, even when the worker died in between (§11.3). Identifiers only, never a secret.
func (s *StepRun) RecordCreated(ctx context.Context, resources any) error {
	b, err := json.Marshal(resources)
	if err != nil {
		return Permanent("invalid_step", err)
	}
	return s.run.w.bookkeep(ctx, func(bctx context.Context, tx *store.Tx) error {
		return tx.Q.SetJobStepResources(bctx, sqlcdb.SetJobStepResourcesParams{CreatedResources: b, JobID: s.run.ID, Name: s.name})
	})
}

// SetDetail sets the raw detail of the step (a JSON object, redacted, no secret), stored when the step ends and shown
// only by GET /platform/jobs/{id} (§13.3).
func (s *StepRun) SetDetail(v any) error {
	b, err := marshalObject(v)
	if err != nil {
		return err
	}
	s.detail = b
	return nil
}

// withError adds the redacted error message to a step's raw detail.
func withError(detail []byte, msg string) []byte {
	m := map[string]any{}
	if len(detail) > 0 {
		_ = json.Unmarshal(detail, &m)
	}
	m["error"] = scrub(msg)
	b, _ := json.Marshal(m)
	return b
}

// periodicJobs are the River periodic jobs of this worker. River's OSS periodic schedule is not durable (ST-01, R-14):
// it restarts with every leader, so the long-period jobs also run on start (RunOnStart), delayed by a random
// 0–StartJitter (§13.5). Each run records its own provisioning_jobs row with dedupe key <kind>:<slot>.
func (w *Worker) periodicJobs() []*river.PeriodicJob {
	if w.cfg.periodicOff {
		return nil
	}
	type schedule struct {
		kind    string
		every   time.Duration
		onStart bool
	}
	list := []schedule{{"job.reaper", w.cfg.ReaperInterval, false}, {"retention.sweep", w.cfg.SweepInterval, true}}
	if w.partitions != nil {
		list = append(list, schedule{"partition.maintain", w.cfg.PartitionInterval, true})
	}
	for _, p := range w.periodics {
		list = append(list, schedule{p.kind, p.every, true})
	}
	out := make([]*river.PeriodicJob, 0, len(list))
	for _, s := range list {
		k, ok := w.cfg.Kinds[s.kind]
		if !ok {
			continue
		}
		var first atomic.Bool
		jitterFirst := s.onStart && w.cfg.StartJitter > 0
		out = append(out, river.NewPeriodicJob(river.PeriodicInterval(s.every), func() (river.JobArgs, *river.InsertOpts) {
			now := time.Now().UTC()
			opts := &river.InsertOpts{Queue: k.Queue, MaxAttempts: k.MaxAttempts + queueSlack,
				UniqueOpts: river.UniqueOpts{ByArgs: true}}
			if jitterFirst && first.CompareAndSwap(false, true) {
				opts.ScheduledAt = now.Add(randUpTo(w.cfg.StartJitter))
			}
			return queueArgs{JobKind: k.Name, Slot: slotOf(now, s.every)}, opts
		}, &river.PeriodicJobOpts{ID: k.Name, RunOnStart: s.onStart}))
	}
	return out
}

// slotOf is the schedule slot of a periodic run: the start of its period (UTC).
func slotOf(t time.Time, every time.Duration) string {
	return t.UTC().Truncate(every).Format("20060102T150405Z")
}
