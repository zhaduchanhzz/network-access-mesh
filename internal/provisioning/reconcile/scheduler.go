package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"sync"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// SchedulerConfig configures the schedule of the reconcile jobs.
type SchedulerConfig struct {
	// Interval between two reconciles of one instance, and of the host; default DefaultInterval.
	Interval time.Duration
	// Tick is how often the schedule looks at the instances; default 30 s (≤ Interval).
	Tick time.Duration
}

// Scheduler enqueues instance.reconcile for every targeted instance and host.reconcile once per Interval, each at its
// own offset within the interval (a hash of the kind and the instance id — the jitter: a restart of the worker does
// not fire every reconcile at once, §13.5 "Giãn tải"). The first time an instance (or the host) is seen only its
// current period is noted, so its first run comes at its own offset. The dedupe keys instance:<id>:reconcile:<slot>
// and host.reconcile:<slot> keep one job per slot while it is unfinished.
type Scheduler struct {
	svc *Service
	cfg SchedulerConfig

	mu   sync.Mutex
	last map[string]int64 // subject (instance id, "host") → last slot seen
}

// NewScheduler returns the schedule of the reconcile jobs on the service's store (worker).
func (s *Service) NewScheduler(cfg SchedulerConfig) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Interval {
		cfg.Tick = min(30*time.Second, cfg.Interval)
	}
	return &Scheduler{svc: s, cfg: cfg, last: map[string]int64{}}
}

// Run ticks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.cfg.Tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "reconcile: schedule failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// slot is the number of the subject's period that contains now.
func (sc *Scheduler) slot(kind string, subject []byte, now time.Time) int64 {
	sum := sha256.Sum256(append([]byte(kind+":"), subject...))
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Interval)) //nolint:gosec // interval > 0, offset < interval
	return (now.UnixNano() - offset) / int64(sc.cfg.Interval)
}

// due notes the subject's slot and reports whether a new period started since the previous tick.
func (sc *Scheduler) due(subject string, slot int64) bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	prev, known := sc.last[subject]
	sc.last[subject] = slot
	return known && slot > prev
}

// Tick enqueues the reconciles whose period started since the previous tick and returns how many it enqueued.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	n := 0
	if slot := sc.slot(KindHost, nil, now); sc.due(ScopeHost, slot) {
		err := sc.svc.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
			_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindHost, Slot: strconv.FormatInt(slot, 10)})
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "reconcile: enqueue host.reconcile failed", "error", err)
		} else {
			sc.svc.m.scheduled.WithLabelValues(ScopeHost).Inc()
			n++
		}
	}
	var targets []sqlcdb.ListReconcileTargetsRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		targets, err = q.ListReconcileTargets(ctx)
		return err
	}); err != nil {
		return n, err
	}
	keep := make(map[string]bool, len(targets))
	for _, in := range targets {
		keep[in.ID.String()] = true
		slot := sc.slot(KindInstance, in.ID[:], now)
		if !sc.due(in.ID.String(), slot) {
			continue
		}
		tenant, instance := in.TenantID, in.ID
		err := sc.svc.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindInstance, TenantID: &tenant, InstanceID: &instance,
				Slot: strconv.FormatInt(slot, 10)})
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "reconcile: enqueue instance.reconcile failed", "tenant_id", tenant,
				"instance_id", instance, "error", err)
			continue
		}
		sc.svc.m.scheduled.WithLabelValues(ScopeInstance).Inc()
		n++
	}
	sc.forgetMissing(keep)
	return n, nil
}

// forgetMissing drops the subjects that are no longer targeted (schedule and gauge).
func (sc *Scheduler) forgetMissing(keep map[string]bool) {
	sc.mu.Lock()
	for sub := range sc.last {
		if sub != ScopeHost && !keep[sub] {
			delete(sc.last, sub)
		}
	}
	sc.mu.Unlock()
	sc.svc.retain(keep)
}
