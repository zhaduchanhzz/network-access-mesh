package relay

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

// SchedulerConfig configures the schedule of relay.probe.
type SchedulerConfig struct {
	// Interval between two probes of one region; default DefaultProbeInterval.
	Interval time.Duration
	// Tick is how often the schedule looks at the regions; default 15 s (≤ Interval).
	Tick time.Duration
}

// Scheduler enqueues relay.probe for every probed region (embedded, active, served by a running instance) once per
// Interval, each region at its own offset within the interval (a hash of the job kind and the region id — §13.5
// "Giãn tải"). A region seen for the first time is probed at that tick when it was never probed (a new tenant), and
// otherwise first at its own offset. The dedupe key relay:<region>:probe:<slot> keeps one job per region and slot
// while it is unfinished; with several worker processes a slot can still be probed twice — harmless: the later-started
// probe wins and an older result never overwrites it. It runs in the worker process.
type Scheduler struct {
	svc *Service
	cfg SchedulerConfig

	mu   sync.Mutex
	last map[uuid.UUID]int64 // region → last slot seen
}

// NewScheduler returns the schedule of relay.probe on the service's store (worker: mg_worker_*).
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
			sc.svc.log.ErrorContext(ctx, "relay: relay.probe schedule failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// slot is the number of the region's probe period that contains now.
func (sc *Scheduler) slot(region uuid.UUID, now time.Time) int64 {
	sum := sha256.Sum256(append([]byte(KindProbe+":"), region[:]...))
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Interval)) //nolint:gosec // interval > 0, offset < interval
	return (now.UnixNano() - offset) / int64(sc.cfg.Interval)
}

// Tick enqueues the probes whose period started since the previous tick — and the first probe of a region never
// probed — and returns how many it enqueued.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	var targets []sqlcdb.ListRelayProbeTargetsRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		targets, err = q.ListRelayProbeTargets(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, tg := range targets {
		slot := sc.slot(tg.ID, now)
		sc.mu.Lock()
		prev, known := sc.last[tg.ID]
		sc.last[tg.ID] = slot
		sc.mu.Unlock()
		due := known && slot > prev
		if !known && tg.LastProbeAt == nil {
			due = true // never probed: a result now, not at the region's offset
		}
		if !due {
			continue
		}
		tenant, region := tg.TenantID, tg.ID
		err := sc.svc.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindProbe, TenantID: &tenant, Object: region.String(),
				Slot: strconv.FormatInt(slot, 10), Input: probeInput{RegionID: region},
				Resource: &jobs.Resource{Type: ResourceType, ID: region.String()}})
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "relay: enqueue relay.probe failed", "tenant_id", tenant, "region_id", region,
				"error", err)
			continue
		}
		sc.svc.m.scheduled.Inc()
		n++
	}
	return n, nil
}
