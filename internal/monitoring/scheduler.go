package monitoring

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

// SchedulerConfig configures the schedule of health.probe.
type SchedulerConfig struct {
	// Interval between two probes of one instance; default DefaultProbeInterval.
	Interval time.Duration
	// Tick is how often the schedule looks at the instances; default 15 s (≤ Interval).
	Tick time.Duration
}

// Scheduler enqueues health.probe for every running instance once per Interval, each instance at its own offset within
// the interval (a hash of the job kind and the instance id), so the probes of many instances are spread rather than
// fired together after a restart (§13.5 "Giãn tải"; every authenticated call costs Headscale a bcrypt — RT-15). It
// runs in the worker process. The dedupe key instance:<id>:health:<slot> keeps one job per instance and slot while it
// is unfinished; with several worker processes a slot can still be probed twice — harmless: the later-started probe
// wins and an older result never overwrites it.
type Scheduler struct {
	svc *Service
	cfg SchedulerConfig

	mu   sync.Mutex
	last map[uuid.UUID]int64 // instance → last slot seen
}

// NewScheduler returns the schedule of health.probe on the service's store (worker: mg_worker_*).
func (s *Service) NewScheduler(cfg SchedulerConfig) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultProbeInterval
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Interval {
		cfg.Tick = min(15*time.Second, cfg.Interval)
	}
	return &Scheduler{svc: s, cfg: cfg, last: map[uuid.UUID]int64{}}
}

// Run ticks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.cfg.Tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "monitoring: health.probe schedule failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// slot is the number of the instance's probe period that contains now.
func (sc *Scheduler) slot(instance uuid.UUID, now time.Time) int64 {
	sum := sha256.Sum256(append([]byte(KindProbe+":"), instance[:]...))
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Interval)) //nolint:gosec // interval > 0, offset < interval
	return (now.UnixNano() - offset) / int64(sc.cfg.Interval)
}

// Tick enqueues the probes whose period started since the previous tick and returns how many it enqueued. The first
// time an instance is seen only its current period is noted: its first probe comes at its own offset.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	var instances []sqlcdb.ListHealthProbeTargetsRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		instances, err = q.ListHealthProbeTargets(ctx)
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
			_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindProbe, TenantID: &tenant, InstanceID: &instance,
				Slot: strconv.FormatInt(slot, 10)})
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "monitoring: enqueue health.probe failed", "tenant_id", tenant, "instance_id", instance,
				"error", err)
			continue
		}
		sc.svc.m.scheduled.Inc()
		n++
	}
	return n, nil
}
