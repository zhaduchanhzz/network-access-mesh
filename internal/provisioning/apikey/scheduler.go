package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// Input is the input of an apikey.rotate job (identifiers and flags only — never a secret).
type Input struct {
	Trigger string `json:"trigger,omitempty"` // TriggerSchedule, TriggerJob ("" = TriggerJob)
	Force   bool   `json:"force,omitempty"`
}

// run is the handler of apikey.rotate: one instance per job (the job's tenant and instance).
func (s *Service) run(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil || run.InstanceID == nil {
		return jobs.Permanent(CodeInvalid, errors.New("apikey.rotate needs a tenant and an instance"))
	}
	var in Input
	if err := run.DecodeInput(&in); err != nil {
		return jobs.Permanent(CodeInvalid, errors.New("apikey.rotate: the input is not an object of trigger/force"))
	}
	if in.Trigger != TriggerSchedule {
		in.Trigger = TriggerJob
	}
	res, err := s.Rotate(ctx, Request{TenantID: *run.TenantID, InstanceID: *run.InstanceID, Force: in.Force,
		Trigger: in.Trigger, JobID: run.ID, Actor: Kind})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := run.SetOutput(res); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	return nil
}

// Register sets the handler of apikey.rotate on the worker (apps/worker).
func (s *Service) Register(w *jobs.Worker) error {
	return w.Register(Kind, jobs.HandlerFunc(s.run))
}

// SchedulerConfig configures the schedule of apikey.rotate.
type SchedulerConfig struct {
	// Period is the rotation period of the dedupe key instance:<id>:apikey:<period>: at most one scheduled job per
	// instance and period, each instance at its own offset within the period (a hash of its id — §13.5 "Giãn tải").
	// Default 24 h: a due key gets one job a day until it is rotated (a week before the alert of §16.3).
	Period time.Duration
	// Tick is how often the registry is read — the expiry gauge is refreshed and due keys are looked for; default
	// 5 min (≤ Period).
	Tick time.Duration
}

// Scheduler enqueues apikey.rotate for every instance whose recorded key is due (expires within RotateBefore, or has
// no recorded expiry), once per period: when an instance is first seen due (also after a restart — the job is
// idempotent: a key already rotated is skipped as not_due) and then at each new period while it stays due. It also
// refreshes the expiry gauge from the registry at every tick.
type Scheduler struct {
	svc *Service
	cfg SchedulerConfig

	mu   sync.Mutex
	last map[uuid.UUID]int64 // instance → period of its last scheduled job
}

// NewScheduler returns the schedule of apikey.rotate on the service's store (worker).
func (s *Service) NewScheduler(cfg SchedulerConfig) *Scheduler {
	if cfg.Period <= 0 {
		cfg.Period = 24 * time.Hour
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Period {
		cfg.Tick = min(5*time.Minute, cfg.Period)
	}
	return &Scheduler{svc: s, cfg: cfg, last: map[uuid.UUID]int64{}}
}

// Run ticks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.cfg.Tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, sc.svc.cfg.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "apikey: schedule failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// period is the number of the instance's period that contains now.
func (sc *Scheduler) period(instanceID uuid.UUID, now time.Time) int64 {
	sum := sha256.Sum256(append([]byte(Kind+":"), instanceID[:]...))
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Period)) //nolint:gosec // period > 0, offset < period
	return (now.UnixNano() - offset) / int64(sc.cfg.Period)
}

// Tick refreshes the expiry gauge and enqueues the due rotations; it returns how many jobs it enqueued.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	rows, err := sc.svc.db.expiries(ctx)
	if err != nil {
		return 0, err
	}
	sc.svc.m.replace(rows)
	n := 0
	seen := make(map[uuid.UUID]bool, len(rows))
	for _, r := range rows {
		seen[r.InstanceID] = true
		if r.ExpiresAt != nil && r.ExpiresAt.Sub(now) > sc.svc.cfg.RotateBefore {
			continue
		}
		p := sc.period(r.InstanceID, now)
		sc.mu.Lock()
		prev, known := sc.last[r.InstanceID]
		sc.mu.Unlock()
		if known && prev >= p {
			continue
		}
		created, err := sc.svc.db.enqueue(ctx, r.TenantID, r.InstanceID, p, Input{Trigger: TriggerSchedule})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "apikey: enqueue apikey.rotate failed", "tenant_id", r.TenantID.String(),
				"instance_id", r.InstanceID.String(), "error", err.Error())
			continue
		}
		sc.mu.Lock()
		sc.last[r.InstanceID] = p
		sc.mu.Unlock()
		if created {
			sc.svc.m.scheduled.Inc()
			n++
		}
	}
	sc.mu.Lock()
	for id := range sc.last {
		if !seen[id] {
			delete(sc.last, id)
		}
	}
	sc.mu.Unlock()
	return n, nil
}
