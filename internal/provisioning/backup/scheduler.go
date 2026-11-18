package backup

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Scheduler enqueues instance.backup for every instance running or stopped (not quarantined or removed) of a tenant
// still served, every period — the plan's PlanLimits.backup_interval_minutes (§17.1 "theo plan": 60 for the standard
// plan, 15 when hardened; clamped to 15 min…24 h), MG_BACKUP_INTERVAL when the tenant has no live subscription — each
// instance at an offset of its own within its period (a hash of its id — §13.5 "Giãn tải"); the dedupe key
// instance:<id>:backup:<minutes>m-<period> keeps at most one scheduled job per instance and period. An instance is
// due when its last backup (any status) started before the beginning of its current period.
type Scheduler struct {
	svc  *Service
	tick time.Duration
}

// NewScheduler returns the schedule of instance.backup (tick: how often the registry is read — default 5 min).
func (s *Service) NewScheduler(tick time.Duration) *Scheduler {
	if tick <= 0 {
		tick = 5 * time.Minute
	}
	return &Scheduler{svc: s, tick: tick}
}

// Run ticks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, sc.svc.cfg.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "backup: schedule failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Period bounds of a plan's backup interval (an out-of-range value is clamped, never trusted to be sane).
const (
	minPeriod = 15 * time.Minute
	maxPeriod = 24 * time.Hour
)

// offset is the instance's offset within its period.
func offset(id uuid.UUID, period time.Duration) time.Duration {
	sum := sha256.Sum256(append([]byte(KindBackup+":"), id[:]...))
	return time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(period)) //nolint:gosec // period > 0
}

// period is the backup period of an instance: its plan's, or the worker's default.
func (sc *Scheduler) period(minutes int32) time.Duration {
	return periodOf(minutes, sc.svc.cfg.Interval)
}

// periodOf is the backup period of a plan's backup_interval_minutes (clamped to minPeriod…maxPeriod), def when the
// tenant has none — shared by the schedule and the freshness gauges (P3-T16).
func periodOf(minutes int32, def time.Duration) time.Duration {
	if minutes <= 0 {
		return def
	}
	return min(max(time.Duration(minutes)*time.Minute, minPeriod), maxPeriod)
}

// Tick enqueues the due backups; it returns how many jobs it enqueued.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	var rows []sqlcdb.ListBackupScheduleRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListBackupSchedule(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		period := sc.period(r.IntervalMinutes)
		off := offset(r.ID, period)
		p := (now.UnixNano() - int64(off)) / int64(period)
		start := time.Unix(0, p*int64(period)+int64(off))
		if !r.LastStartedAt.Before(start) {
			continue // already backed up in this period
		}
		tenant, inst := r.TenantID, r.ID
		slot := strconv.FormatInt(int64(period/time.Minute), 10) + "m-" + strconv.FormatInt(p, 10)
		created := false
		err := sc.svc.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindBackup, TenantID: &tenant, InstanceID: &inst, Slot: slot,
				Input: BackupInput{Trigger: TriggerSchedule}})
			created = enq.Created
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "backup: enqueue instance.backup failed", "tenant_id", tenant.String(),
				"instance_id", inst.String(), "error", err.Error())
			continue
		}
		if created {
			n++
		}
	}
	return n, nil
}
