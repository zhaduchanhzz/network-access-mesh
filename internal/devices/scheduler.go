package devices

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// SchedulerConfig configures the schedule of inventory.sync.
type SchedulerConfig struct {
	// Interval between two syncs of one instance; default 5 minutes.
	Interval time.Duration
	// Tick is how often the schedule looks at the instances; default 30 s (≤ Interval).
	Tick time.Duration
}

// Scheduler enqueues inventory.sync for every running instance once per Interval, each instance at its own offset
// within the interval (a hash of instance_id), so the syncs of many instances are spread instead of firing together
// after a restart (§13.5 "Giãn tải"). It runs in the worker process. The dedupe key instance:<id>:sync:<slot> keeps
// one job per instance and slot while it is unfinished; with several worker processes a slot can still be synced
// twice — harmless, the sync is level-triggered and a stale snapshot is skipped.
type Scheduler struct {
	svc *Service
	cfg SchedulerConfig

	mu   sync.Mutex
	last map[uuid.UUID]int64 // instance → last slot seen
}

// NewScheduler returns the schedule of inventory.sync on the service's store (worker: mg_worker_*).
func (s *Service) NewScheduler(cfg SchedulerConfig) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Interval {
		cfg.Tick = min(30*time.Second, cfg.Interval)
	}
	return &Scheduler{svc: s, cfg: cfg, last: map[uuid.UUID]int64{}}
}

// Run ticks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.cfg.Tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "devices: inventory.sync schedule failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// slot is the number of the instance's sync period that contains now.
func (sc *Scheduler) slot(instance uuid.UUID, now time.Time) int64 {
	sum := sha256.Sum256(instance[:])
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Interval)) //nolint:gosec // interval > 0, offset < interval
	return (now.UnixNano() - offset) / int64(sc.cfg.Interval)
}

// Tick enqueues the syncs whose period started since the previous tick and returns how many it enqueued. The first
// time an instance is seen only its current period is noted: its first sync comes at its own offset.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	var instances []sqlcdb.ListRunningInstancesRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		instances, err = q.ListRunningInstances(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, in := range instances {
		slot := sc.slot(in.ID, now)
		sc.mu.Lock()
		prev, known := sc.last[in.ID]
		sc.last[in.ID] = slot
		sc.mu.Unlock()
		if !known || slot <= prev {
			continue
		}
		tenant, instance := in.TenantID, in.ID
		err := sc.svc.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindSync, TenantID: &tenant, InstanceID: &instance,
				Slot: strconv.FormatInt(slot, 10)})
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "devices: enqueue inventory.sync failed", "tenant_id", tenant, "instance_id", instance,
				"error", err)
			continue
		}
		sc.svc.m.scheduled.Inc()
		n++
	}
	return n, nil
}
