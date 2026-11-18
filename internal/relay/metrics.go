package relay

import "github.com/prometheus/client_golang/prometheus"

// metrics of the module (§16.1). Labels are bounded sets (statuses and stable reason codes) — never a tenant, a region
// or an address. Alertmanager rules: P3-T16 / P6-T01.
type metrics struct {
	probes    *prometheus.CounterVec // status: healthy, unhealthy, skipped, failed; reason: stable code ("" when healthy)
	scheduled prometheus.Counter     // relay.probe jobs enqueued by the schedule
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_relay_probes_total",
			Help: "Relay probes by outcome (healthy, unhealthy recorded; skipped; failed: the probe could not run) and stable reason.",
		}, []string{"status", "reason"}),
		scheduled: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshguard_relay_probe_jobs_scheduled_total", Help: "relay.probe jobs enqueued by the schedule.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.probes, m.scheduled)
	}
	return m
}
