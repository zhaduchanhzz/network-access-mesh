package jobs

import (
	"errors"
	"fmt"
	"time"
)

// Config is the worker configuration. Every timeout and threshold that River would otherwise default is set here
// explicitly (§11.3: worker timeout and stuck-job rescue threshold of the lifecycle queue set to match, ≈ 15 min, never
// the library's defaults — checked by Validate and TestDefaultConfigExplicit).
type Config struct {
	Kinds  map[string]Kind // registry with worker timeouts (DefaultKinds)
	Queues map[string]int  // River queue → worker slots in this process

	// JobTimeout is River's client-level attempt timeout. Every kind sets its own WorkerTimeout, so this only applies to
	// a job of a kind this worker does not know (it then snoozes).
	JobTimeout time.Duration
	// RescueStuckJobsAfter is River's stuck-job threshold: a River job still running this long after its attempt
	// started (and past its worker timeout) is rescued — retried or discarded. It must exceed every kind's
	// Timeout + ReaperInterval so that job.reaper settles a dead worker's job first; the rescued delivery then finds a
	// finished business job and does nothing.
	RescueStuckJobsAfter time.Duration
	// SoftStopTimeout bounds a graceful stop: running jobs get this long, then their contexts are cancelled and they
	// resume after restart (River marks them available without using an attempt).
	SoftStopTimeout time.Duration
	// JobStuckThreshold is River's grace after a worker timeout before an attempt that ignores its context is reported
	// stuck (logged).
	JobStuckThreshold time.Duration
	FetchCooldown     time.Duration
	FetchPollInterval time.Duration
	// River keeps its own finished rows only for diagnosis — provisioning_jobs is the record (retention 180 days).
	CompletedRetention time.Duration
	CancelledRetention time.Duration
	DiscardedRetention time.Duration
	// Retry backoff (§11.3: exponential 2 s → 60 s + jitter).
	RetryBase time.Duration
	RetryMax  time.Duration
	// Snooze of a lifecycle job that finds its tenant's lock taken: LockBusySnooze while the holder runs, LockHeldSnooze
	// while the holder is failed_resumable (it keeps the lock until /retry or /rollback — §11.3). NoHandlerSnooze: a
	// job of a kind without a handler in this process (another release of the worker will run it).
	LockBusySnooze  time.Duration
	LockHeldSnooze  time.Duration
	NoHandlerSnooze time.Duration
	// StartJitter delays the RunOnStart run of a periodic job by a random 0–StartJitter after the worker starts
	// (§13.5: 0–10 min), so a restart does not fire everything at once.
	StartJitter time.Duration
	// ReaperInterval is the period of job.reaper (§13.5: every minute); ReaperMinAge the age from which an unfinished
	// job is checked against its River job.
	ReaperInterval time.Duration
	ReaperMinAge   time.Duration
	// SweepInterval is the period of retention.sweep, PartitionInterval of partition.maintain (daily).
	SweepInterval     time.Duration
	PartitionInterval time.Duration
	Retention         Retention
	// QueuePoolConns is the size of the River client's own pool (one connection stays on LISTEN).
	QueuePoolConns int32
	// BookkeepingTimeout bounds each write of the framework itself (status, steps), done on a context detached from the
	// job's, so a cancelled or timed-out job is still recorded.
	BookkeepingTimeout time.Duration

	testOnly    bool // River TestOnly: no start stagger of River's maintenance services (tests only)
	periodicOff bool // no periodic jobs (tests that count jobs)
}

// Retention holds the retention periods applied by retention.sweep (§6.4). audit_events is never swept: its retention
// is the drop of whole partitions (§6.1).
type Retention struct {
	Jobs           time.Duration // finished provisioning_jobs (+ steps by cascade): 180 days
	SecurityEvents time.Duration // ≥ 400 days, like audit
	RemovedDevices time.Duration // device_inventory_cache rows 90 days after removed_at
	Notifications  time.Duration // notification_outbox rows 90 days after sent_at (failed/cancelled: after created_at)
	// idempotency_keys: deleted once expires_at has passed (IdempotencyTTL = 24 hours after the key was taken).
	BatchSize int32
}

// DefaultConfig returns the production settings.
func DefaultConfig() Config {
	return Config{
		Kinds:                DefaultKinds(),
		Queues:               map[string]int{QueueLifecycle: 4, QueueDefault: 8, QueueMaintenance: 2},
		JobTimeout:           5 * time.Minute,
		RescueStuckJobsAfter: LifecycleWorkerTimeout,
		SoftStopTimeout:      30 * time.Second,
		JobStuckThreshold:    30 * time.Second,
		FetchCooldown:        100 * time.Millisecond,
		FetchPollInterval:    time.Second,
		CompletedRetention:   24 * time.Hour,
		CancelledRetention:   7 * 24 * time.Hour,
		DiscardedRetention:   7 * 24 * time.Hour,
		RetryBase:            2 * time.Second,
		RetryMax:             time.Minute,
		LockBusySnooze:       10 * time.Second,
		LockHeldSnooze:       time.Minute,
		NoHandlerSnooze:      5 * time.Minute,
		StartJitter:          10 * time.Minute,
		ReaperInterval:       time.Minute,
		ReaperMinAge:         30 * time.Second,
		SweepInterval:        time.Hour,
		PartitionInterval:    24 * time.Hour,
		Retention: Retention{
			Jobs:           180 * 24 * time.Hour,
			SecurityEvents: 400 * 24 * time.Hour,
			RemovedDevices: 90 * 24 * time.Hour,
			Notifications:  90 * 24 * time.Hour,
			BatchSize:      1000,
		},
		QueuePoolConns:     10,
		BookkeepingTimeout: 10 * time.Second,
	}
}

// Validate checks that nothing is left to a library default and that the timeouts fit together (§11.3).
func (c Config) Validate() error {
	var errs []error
	positive := map[string]time.Duration{
		"JobTimeout": c.JobTimeout, "RescueStuckJobsAfter": c.RescueStuckJobsAfter, "SoftStopTimeout": c.SoftStopTimeout,
		"JobStuckThreshold": c.JobStuckThreshold, "FetchCooldown": c.FetchCooldown, "FetchPollInterval": c.FetchPollInterval,
		"CompletedRetention": c.CompletedRetention, "CancelledRetention": c.CancelledRetention,
		"DiscardedRetention": c.DiscardedRetention, "RetryBase": c.RetryBase, "RetryMax": c.RetryMax,
		"LockBusySnooze": c.LockBusySnooze, "LockHeldSnooze": c.LockHeldSnooze, "NoHandlerSnooze": c.NoHandlerSnooze,
		"ReaperInterval": c.ReaperInterval, "ReaperMinAge": c.ReaperMinAge, "SweepInterval": c.SweepInterval,
		"PartitionInterval": c.PartitionInterval, "BookkeepingTimeout": c.BookkeepingTimeout,
		"Retention.Jobs": c.Retention.Jobs, "Retention.SecurityEvents": c.Retention.SecurityEvents,
		"Retention.RemovedDevices": c.Retention.RemovedDevices, "Retention.Notifications": c.Retention.Notifications,
	}
	for name, d := range positive {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be set (> 0)", name))
		}
	}
	if c.StartJitter < 0 {
		errs = append(errs, errors.New("StartJitter must not be negative"))
	}
	if c.RetryMax < c.RetryBase {
		errs = append(errs, errors.New("RetryMax must be ≥ RetryBase"))
	}
	if c.FetchPollInterval < c.FetchCooldown {
		errs = append(errs, errors.New("FetchPollInterval must be ≥ FetchCooldown"))
	}
	if c.RescueStuckJobsAfter < c.JobTimeout {
		errs = append(errs, errors.New("RescueStuckJobsAfter must be ≥ JobTimeout"))
	}
	if c.QueuePoolConns < 2 || c.Retention.BatchSize < 1 {
		errs = append(errs, errors.New("QueuePoolConns must be ≥ 2 and Retention.BatchSize ≥ 1"))
	}
	if len(c.Kinds) == 0 {
		errs = append(errs, errors.New("the kind registry is empty"))
	}
	for name, k := range c.Kinds {
		switch {
		case k.Name != name:
			errs = append(errs, fmt.Errorf("kind %s: name mismatch", name))
		case k.Timeout <= 0 || k.WorkerTimeout < k.Timeout:
			errs = append(errs, fmt.Errorf("kind %s: need 0 < Timeout ≤ WorkerTimeout", name))
		case k.WorkerTimeout > c.RescueStuckJobsAfter:
			errs = append(errs, fmt.Errorf("kind %s: WorkerTimeout above RescueStuckJobsAfter", name))
		case k.Timeout+c.ReaperInterval >= c.RescueStuckJobsAfter:
			errs = append(errs, fmt.Errorf("kind %s: Timeout + ReaperInterval must stay below RescueStuckJobsAfter", name))
		case k.MaxAttempts < 1:
			errs = append(errs, fmt.Errorf("kind %s: MaxAttempts must be ≥ 1", name))
		case c.Queues[k.Queue] < 1:
			errs = append(errs, fmt.Errorf("kind %s: queue %q has no worker slot", name, k.Queue))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("jobs: invalid config: %w", err)
	}
	return nil
}
