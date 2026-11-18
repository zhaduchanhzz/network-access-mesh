package runner

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	probe "github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// NewRelayProbe builds the RelayService of the worker (P3-T05c): relay.probe over the prober's RPC client
// (MG_PROBER_URL, apps/probe — P3-T03a) towards the edge's public listener as the prober reaches it
// (MG_PROVISION_EDGE_ADDR — the address step 17 probes). nil (and a warning) without a prober: the relay read models
// then report every region never_checked or stale — no figure is invented. Exported for `meshguard-worker admin
// relay-probe`, which runs the same chain once.
func NewRelayProbe(cfg config.Config, st *store.Store, log *slog.Logger, reg prometheus.Registerer) (*relay.Service, error) {
	pc := cfg.Provisioning
	if pc.ProberURL == "" {
		log.Warn("relay.probe is not run by this worker: no prober is configured (MG_PROBER_URL) — the relay read " +
			"models report every region never_checked or stale")
		return nil, nil
	}
	c, err := probe.NewClient(pc.ProberURL, nil)
	if err != nil {
		return nil, err
	}
	return relay.New(st, relay.Config{Prober: RelayProber(c), EdgeAddress: pc.EdgeAddr, Logger: log, Registerer: reg})
}

// RelayProber maps the prober's RPC client (apps/probe) onto relay.Prober (relay does not import apps/* — §13.6): the
// DERP check is GET /derp/probe ⇒ 200, the STUN check a binding with a mapped address; a check that failed carries the
// prober's error code, or expectation_failed when an answer came but not the expected one.
func RelayProber(c probe.Prober) relay.Prober {
	return relay.ProberFunc(func(ctx context.Context, p relay.ProbeRequest) (relay.ProbeResult, error) {
		r, err := c.Relay(ctx, probe.RelayRequest{Address: p.Address, Host: p.Host, STUN: p.STUN})
		if err != nil {
			return relay.ProbeResult{}, err
		}
		derp := relay.Check{OK: r.DERP.OK, Status: r.DERP.Status, Duration: millis(r.DERP.Timing.TotalMS)}
		switch {
		case r.DERP.Error != nil:
			derp.Code = r.DERP.Error.Code
		case !r.DERP.OK:
			derp.Code = "expectation_failed"
		}
		stun := relay.Check{OK: r.STUN.OK, Duration: millis(r.STUN.TotalMS)}
		switch {
		case r.STUN.Error != nil:
			stun.Code = r.STUN.Error.Code
		case !r.STUN.OK:
			stun.Code = "expectation_failed"
		}
		return relay.ProbeResult{DERP: derp, STUN: stun}, nil
	})
}

// relaySchedule is the schedule of relay.probe, or nothing to run when the worker has no prober.
func relaySchedule(s *relay.Service) func(context.Context) error {
	if s == nil {
		return func(context.Context) error { return nil }
	}
	return s.NewScheduler(relay.SchedulerConfig{}).Run
}

func millis(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }
