package jobs

// Built-in maintenance jobs: job.reaper (every minute), retention.sweep (hourly) and partition.maintain (daily) —
// §13.5, §6.1, §6.4.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

const reapBatch = 500

// ReapReport is the outcome of one job.reaper run (stored as its output).
type ReapReport struct {
	WorkerLost int `json:"worker_lost"`
	QueueLost  int `json:"queue_lost"`
}

func (w *Worker) runReaper(ctx context.Context, run *Run) error {
	rep, err := w.reap(ctx)
	if err != nil {
		return Transient("reaper_failed", err)
	}
	return run.SetOutput(rep)
}

// reap settles the unfinished jobs nobody runs any more (§11.3, §13.5):
//
//   - running or compensating past timeout_at — the worker died or hung (River would only rescue the River job after
//     RescueStuckJobsAfter): code worker_lost;
//   - queued or running whose River job is gone, finished, cancelled or discarded — the queue dropped it: queue_lost.
//
// A started job of the lifecycle group ends failed_resumable and keeps the lock until /retry or /rollback; a job that
// never started, and every other kind, ends failed. Every reaped job raises an alert. The transition is conditioned on
// the status and attempt read here, so a worker that finishes the job meanwhile wins. The gauge of unfinished jobs is
// refreshed at the end.
func (w *Worker) reap(ctx context.Context) (ReapReport, error) {
	var (
		cands  []sqlcdb.ProvisioningJob
		states map[int64]string
	)
	err := w.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		var err error
		cands, err = tx.Q.ListJobsToReap(ctx, sqlcdb.ListJobsToReapParams{MinAgeSecs: w.cfg.ReaperMinAge.Seconds(), RowLimit: reapBatch})
		if err != nil {
			return err
		}
		ids := make([]int64, 0, len(cands))
		for _, c := range cands {
			if c.QueueJobID != nil {
				ids = append(ids, *c.QueueJobID)
			}
		}
		states, err = tx.QueueJobStates(ctx, ids)
		return err
	})
	if err != nil {
		return ReapReport{}, fmt.Errorf("jobs: reaper: %w", err)
	}
	var rep ReapReport
	now := time.Now()
	for _, c := range cands {
		code := reapCode(c, states, now)
		if code == "" {
			continue
		}
		k := w.cfg.Kinds[c.Kind]
		to := StatusFailed
		if k.Lock == LockHold && c.Status != StatusQueued {
			to = StatusFailedResumable
		}
		msg := "job.reaper: running past timeout_at without a worker finishing it"
		if code == CodeQueueLost {
			msg = "job.reaper: the job queue no longer carries this job"
		}
		var reaped sqlcdb.ProvisioningJob
		err := w.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
			var err error
			reaped, err = tx.Q.TransitionJob(ctx, sqlcdb.TransitionJobParams{ToStatus: to, Error: jobError(code, msg),
				ID: c.ID, FromStatus: c.Status, Attempt: c.Attempt})
			return err
		})
		if errors.Is(err, store.ErrNoRows) {
			continue // its worker settled it meanwhile
		}
		if err != nil {
			return rep, fmt.Errorf("jobs: reaper: %w", err)
		}
		if code == CodeWorkerLost {
			rep.WorkerLost++
		} else {
			rep.QueueLost++
		}
		w.metrics.finished.WithLabelValues(c.Kind, to).Inc()
		w.alert(ctx, Alert{Reason: AlertReaped, JobID: c.ID, TenantID: reaped.TenantID, Kind: c.Kind, Status: to, Code: code})
	}
	w.refreshGauge(ctx)
	return rep, nil
}

// reapCode decides whether a candidate is reaped, and why ("" = leave it).
func reapCode(c sqlcdb.ProvisioningJob, states map[int64]string, now time.Time) string {
	if (c.Status == StatusRunning || c.Status == StatusCompensating) && c.TimeoutAt != nil && c.TimeoutAt.Before(now) {
		return CodeWorkerLost
	}
	if c.Status != StatusQueued && c.Status != StatusRunning {
		return ""
	}
	if c.QueueJobID == nil {
		return CodeQueueLost
	}
	switch states[*c.QueueJobID] {
	case "", "completed", "cancelled", "discarded":
		return CodeQueueLost
	}
	return ""
}

func (w *Worker) refreshGauge(ctx context.Context) {
	var rows []sqlcdb.CountUnfinishedJobsRow
	if err := w.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.CountUnfinishedJobs(ctx)
		return err
	}); err != nil {
		return
	}
	for _, s := range Statuses[:4] {
		w.metrics.unfinished.WithLabelValues(s).Set(0)
	}
	for _, r := range rows {
		w.metrics.unfinished.WithLabelValues(r.Status).Set(float64(r.Jobs))
	}
}

// SweepReport counts the rows deleted by one retention.sweep run (stored as its output).
type SweepReport struct {
	Jobs            int64 `json:"jobs"`
	IdempotencyKeys int64 `json:"idempotency_keys"`
	SecurityEvents  int64 `json:"security_events"`
	RemovedDevices  int64 `json:"removed_devices"`
	Notifications   int64 `json:"notifications"`
}

func (w *Worker) runSweep(ctx context.Context, run *Run) error {
	rep, err := w.sweep(ctx)
	if err != nil {
		return Transient("sweep_failed", err)
	}
	return run.SetOutput(rep)
}

// sweep applies the retention of §6.4 in batches: finished jobs (+ steps) after Retention.Jobs, expired Idempotency-Keys,
// security_events after Retention.SecurityEvents, notification_outbox after Retention.Notifications (as
// mg_worker_platform), and per tenant the device_inventory_cache rows
// removed more than Retention.RemovedDevices ago (tenant-internal table, mg_worker_tenant). audit_events is NOT a target:
// its retention is the drop of whole partitions (§6.1), and no worker role may delete from it.
func (w *Worker) sweep(ctx context.Context) (SweepReport, error) {
	now := time.Now()
	batch := w.cfg.Retention.BatchSize
	drain := func(fn func(q *sqlcdb.Queries) (int64, error)) (int64, error) {
		var total int64
		for {
			var n int64
			if err := w.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
				var err error
				n, err = fn(q)
				return err
			}); err != nil {
				return total, err
			}
			total += n
			if n < int64(batch) {
				return total, nil
			}
		}
	}
	var (
		rep SweepReport
		err error
	)
	if rep.Jobs, err = drain(func(q *sqlcdb.Queries) (int64, error) {
		return q.DeleteFinishedJobs(ctx, sqlcdb.DeleteFinishedJobsParams{FinishedBefore: now.Add(-w.cfg.Retention.Jobs), RowLimit: batch})
	}); err != nil {
		return rep, fmt.Errorf("jobs: retention.sweep: jobs: %w", err)
	}
	if rep.IdempotencyKeys, err = drain(func(q *sqlcdb.Queries) (int64, error) {
		return q.DeleteExpiredIdempotencyKeys(ctx, sqlcdb.DeleteExpiredIdempotencyKeysParams{ExpiredBefore: now, RowLimit: batch})
	}); err != nil {
		return rep, fmt.Errorf("jobs: retention.sweep: idempotency_keys: %w", err)
	}
	if rep.SecurityEvents, err = drain(func(q *sqlcdb.Queries) (int64, error) {
		return q.DeleteOldSecurityEvents(ctx, sqlcdb.DeleteOldSecurityEventsParams{
			OccurredBefore: now.Add(-w.cfg.Retention.SecurityEvents), RowLimit: batch})
	}); err != nil {
		return rep, fmt.Errorf("jobs: retention.sweep: security_events: %w", err)
	}
	if rep.Notifications, err = drain(func(q *sqlcdb.Queries) (int64, error) {
		return q.DeleteOldNotifications(ctx, sqlcdb.DeleteOldNotificationsParams{
			Before: now.Add(-w.cfg.Retention.Notifications), RowLimit: batch})
	}); err != nil {
		return rep, fmt.Errorf("jobs: retention.sweep: notification_outbox: %w", err)
	}
	var tenants []uuid.UUID
	if err := w.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		tenants, err = q.ListTenantIDs(ctx)
		return err
	}); err != nil {
		return rep, fmt.Errorf("jobs: retention.sweep: tenants: %w", err)
	}
	for _, t := range tenants {
		for {
			var n int64
			if err := w.st.WithTenantTx(ctx, t, func(q *sqlcdb.Queries) error {
				var err error
				n, err = q.DeleteRemovedDevices(ctx, sqlcdb.DeleteRemovedDevicesParams{TenantID: t,
					RemovedBefore: now.Add(-w.cfg.Retention.RemovedDevices), RowLimit: batch})
				return err
			}); err != nil {
				return rep, fmt.Errorf("jobs: retention.sweep: device_inventory_cache of %s: %w", t, err)
			}
			rep.RemovedDevices += n
			if n < int64(batch) {
				break
			}
		}
	}
	return rep, nil
}

// runPartitionMaintain is the daily partition.maintain job (§6.1): monthly partitions for the current month and
// store.PartitionMonthsAhead months after it, on the separate mg_partition_maint pool. Rows in a DEFAULT partition raise
// an alert. Export + drop of partitions past retention is not implemented yet (first due ≥ 400 days after go-live).
func (w *Worker) runPartitionMaintain(ctx context.Context, run *Run) error {
	reports, err := w.partitions.Maintain(ctx, store.PartitionMonthsAhead)
	if err != nil {
		return Transient("partition_maintain_failed", err)
	}
	type table struct {
		Table       string   `json:"table"`
		Created     []string `json:"created"`
		DefaultRows int64    `json:"default_rows"`
	}
	out := struct {
		Tables []table `json:"tables"`
	}{Tables: []table{}}
	for _, r := range reports {
		created := r.Created
		if created == nil {
			created = []string{}
		}
		out.Tables = append(out.Tables, table{Table: r.Table, Created: created, DefaultRows: r.DefaultRows})
		if r.DefaultRows > 0 {
			w.alert(ctx, Alert{Reason: AlertPartitionDefaultRows, JobID: run.ID, Kind: run.Kind, Status: StatusRunning, Code: r.Table})
		}
	}
	return run.SetOutput(out)
}
