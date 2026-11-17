package devices

import "github.com/prometheus/client_golang/prometheus"

// metrics of the module (§16.1). A failed revocation is also logged at ERROR with alert=true; the job framework counts
// the failed job itself (meshguard_job_alerts_total{kind="device.revoke"}). Alertmanager rules: P6-T01.
type metrics struct {
	syncs       *prometheus.CounterVec // result: applied, stale, failed
	clamps      *prometheus.CounterVec // result: clamped, failed
	revocations *prometheus.CounterVec // kind, state: applied, failed
	scheduled   prometheus.Counter     // inventory.sync jobs enqueued by the schedule
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		syncs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_device_syncs_total", Help: "Inventory syncs by result (applied, stale snapshot skipped, failed).",
		}, []string{"result"}),
		clamps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_device_expiry_clamps_total",
			Help: "Node expiries beyond the tenant's node_expiry that a sync clamped (or failed to clamp).",
		}, []string{"result"}),
		revocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_device_revocations_total", Help: "Device revocations settled, by kind and final state.",
		}, []string{"kind", "state"}),
		scheduled: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshguard_device_sync_jobs_scheduled_total", Help: "inventory.sync jobs enqueued by the schedule.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.syncs, m.clamps, m.revocations, m.scheduled)
	}
	return m
}
