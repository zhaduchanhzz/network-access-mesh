package monitoring

import "github.com/prometheus/client_golang/prometheus"

// metrics of the module (§16.1). Labels are bounded sets (statuses and stable reason codes) — never a tenant or an
// instance id. Alertmanager rules: P3-T16 / P6-T01.
type metrics struct {
	probes    *prometheus.CounterVec // status: healthy, unhealthy, skipped; reason: stable code ("" when healthy)
	scheduled prometheus.Counter     // health.probe jobs enqueued by the schedule
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_instance_health_probes_total",
			Help: "Health probes of tenant instances by recorded status (healthy, unhealthy, skipped) and stable reason.",
		}, []string{"status", "reason"}),
		scheduled: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshguard_health_probe_jobs_scheduled_total", Help: "health.probe jobs enqueued by the schedule.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.probes, m.scheduled)
	}
	return m
}
