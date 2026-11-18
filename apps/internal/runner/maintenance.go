package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// Maintenance mode of the processes (P3-T17, §17.2; internal/platform/maintenance.go): the gate is MG_MAINTENANCE OR
// the persisted flag system_settings `maintenance`, read at start-up (which must succeed) and every
// platform.DefaultMaintenancePoll after. The api answers 503 maintenance through httpapi.Options.Maintenance; the worker
// runs its job worker and its schedules only while the gate is off (workControl).

// newMaintenanceGate builds the gate of the process, reads the flag once and exports meshguard_maintenance_mode.
func newMaintenanceGate(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger,
	reg prometheus.Registerer,
) (*platform.MaintenanceGate, error) {
	g := platform.NewMaintenanceGate(st, platform.MaintenanceGateOptions{Forced: cfg.Maintenance, Logger: log})
	on, err := g.Refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("maintenance flag: %w", err)
	}
	if on {
		m, _ := g.State()
		log.Warn("maintenance mode ON at start-up", "startup_switch", cfg.Maintenance, "persisted", m.Enabled,
			"reason", m.Reason)
	}
	if reg != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "meshguard_maintenance_mode",
			Help: "1 while the process is in maintenance mode (MG_MAINTENANCE or system_settings maintenance — P3-T17).",
		}, func() float64 {
			if g.On() {
				return 1
			}
			return 0
		}))
	}
	return g, nil
}

// background runs fn in a goroutine until stop is called.
type background struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func startBackground(fn func(ctx context.Context)) *background {
	ctx, cancel := context.WithCancel(context.Background())
	b := &background{cancel: cancel}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		fn(ctx)
	}()
	return b
}

func (b *background) stop() {
	b.cancel()
	b.wg.Wait()
}

// worker is what workControl starts and stops: the job worker of the process (jobs.Worker — River).
type worker interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// workControl runs the job worker and the schedules of the worker process while maintenance is off: started when the
// gate opens, stopped (gracefully — running jobs get SoftStopTimeout, then resume after) when it closes. In maintenance
// no job of the queue runs and no schedule enqueues anything.
type workControl struct {
	gate      interface{ On() bool }
	w         worker
	schedules map[string]func(context.Context) error
	log       *slog.Logger
	check     time.Duration // how often the gate is looked at (an atomic read)
	stopWait  time.Duration

	mu      sync.Mutex
	running bool
	sched   context.CancelFunc
	wg      sync.WaitGroup
}

// run follows the gate until ctx is cancelled, then stops what runs.
func (c *workControl) run(ctx context.Context) {
	t := time.NewTicker(c.check)
	defer t.Stop()
	c.apply(ctx)
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), c.stopWait)
			c.stopWork(sctx)
			cancel()
			return
		case <-t.C:
			c.apply(ctx)
		}
	}
}

// apply starts or stops the work so that it runs iff the gate is off. A start that fails is retried at the next tick.
func (c *workControl) apply(ctx context.Context) {
	on := c.gate.On()
	c.mu.Lock()
	running := c.running
	c.mu.Unlock()
	switch {
	case !on && !running:
		if err := c.startWork(ctx); err != nil && ctx.Err() == nil {
			c.log.Error("cannot start the job worker — retried", "error", err.Error())
		}
	case on && running:
		c.log.Warn("maintenance mode: stopping the job worker and the schedules (no job runs until it is turned off)")
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.stopWait)
		c.stopWork(sctx)
		cancel()
	}
}

func (c *workControl) startWork(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return nil
	}
	if err := c.w.Start(context.WithoutCancel(ctx)); err != nil {
		return err
	}
	sched, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c.sched, c.running = cancel, true
	for name, run := range c.schedules {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if err := run(sched); err != nil && !errors.Is(err, context.Canceled) {
				c.log.Error("schedule stopped", "schedule", name, "error", err.Error())
			}
		}()
	}
	c.log.Info("job worker and schedules started", "schedules", len(c.schedules))
	return nil
}

func (c *workControl) stopWork(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return
	}
	c.sched()
	c.wg.Wait()
	if err := c.w.Stop(ctx); err != nil {
		c.log.Warn("job worker stop", "error", err.Error())
	}
	c.running = false
}

// Running reports whether the job worker runs (tests).
func (c *workControl) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}
