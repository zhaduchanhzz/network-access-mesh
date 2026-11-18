package main

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)

// edgeSupervisor is a driver that supervises the edge attachments (§11.4): the compose driver.
type edgeSupervisor interface {
	EdgeCycle(ctx context.Context, tryLock func(uuid.UUID) (func(), bool)) (compose.EdgeReport, error)
	EdgeStarts(ctx context.Context) <-chan struct{}
}

// cycleTimeout bounds one supervisor cycle (a helper container per changed key file, a few Engine calls per instance).
const cycleTimeout = 5 * time.Minute

// superviseEdge is the edge supervisor of §11.4, a loop inside the agent: a cycle when the agent starts, every
// interval (30 s), and at once when the edge container starts (recreated by an upgrade, a reboot…). Each cycle runs the
// start guard of every activated instance and attaches the edge to the networks of the instances flagged
// edge_attach — only those, never a quarantined one, which is contained again instead (compose.Driver.EdgeCycle). It needs Docker and the local files only: it keeps working
// while PostgreSQL and the worker are down. An instance whose lock is held by an operation is left to the next cycle.
func (s *server) superviseEdge(ctx context.Context, sup edgeSupervisor, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var (
		starts      <-chan struct{}
		subscribeAt time.Time
		last        *compose.EdgeReport
		seen        string // ID of the last edge seen present: a recreation seen through an absent cycle is still one
	)
	for {
		if starts == nil && !time.Now().Before(subscribeAt) {
			starts = sup.EdgeStarts(ctx)
		}
		last = s.edgeCycle(ctx, sup, last, &seen)
		for due := false; !due; {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				due = true
			case _, ok := <-starts:
				if !ok { // the event stream ended: the ticker goes on, subscribe again after an interval
					starts, subscribeAt = nil, time.Now().Add(interval)
					continue
				}
				s.log.Info("edge_started", "edge", s.edge)
				due = true
			}
		}
	}
}

// edgeCycle runs one cycle and logs it: at info when something happened or changed (the edge recreated, an
// attachment, a detachment, a containment, other counts), at debug otherwise.
func (s *server) edgeCycle(ctx context.Context, sup edgeSupervisor, last *compose.EdgeReport, seen *string) *compose.EdgeReport {
	cctx, cancel := context.WithTimeout(ctx, cycleTimeout)
	defer cancel()
	start := time.Now()
	rep, err := sup.EdgeCycle(cctx, s.locks.tryLock)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("edge_supervisor_cycle_failed", "error", err)
		}
		return last
	}
	if rep.EdgeID != "" { // compared with the last edge seen, not the last cycle: a cycle may fall between the removal
		// of the old container and the start of the new one (edge absent), and the recreation is still logged
		if *seen != "" && *seen != rep.EdgeID {
			s.log.Info("edge_recreated", "edge", s.edge, "previous_id", short(*seen), "id", short(rep.EdgeID))
		}
		*seen = rep.EdgeID
	}
	level := slog.LevelDebug
	if last == nil || len(rep.NewlyAttached)+len(rep.Detached)+len(rep.Contained) > 0 || rep.EdgeID != last.EdgeID ||
		rep.Instances != last.Instances || rep.Flagged != last.Flagged || rep.Attached != last.Attached ||
		!slices.Equal(rep.Unflagged, last.Unflagged) || !slices.Equal(rep.Failed, last.Failed) ||
		!slices.Equal(rep.Quarantined, last.Quarantined) {
		level = slog.LevelInfo
	}
	s.log.Log(ctx, level, "edge_supervisor_cycle", "edge", s.edge, "edge_id", short(rep.EdgeID), "edge_present", rep.EdgeID != "",
		"instances", rep.Instances, "flagged", rep.Flagged, "attached", rep.Attached, "newly_attached", rep.NewlyAttached,
		"detached", rep.Detached, "contained", rep.Contained, "busy", rep.Busy, "attached_unflagged", rep.Unflagged,
		"failed", rep.Failed, "quarantined", rep.Quarantined, "gateway_drift", rep.GatewayDrift, "duration_ms", time.Since(start).Milliseconds())
	return &rep
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
