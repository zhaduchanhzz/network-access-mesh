package reconcile

import "github.com/prometheus/client_golang/prometheus"

// metrics of the reconcile jobs (§16.1 "API / Worker"; alert rules: P6-T01 — §16.3 "reconcile phát hiện network tenant
// ≠ 2 thành viên" is meshguard_reconcile_drift{kind="network_extra_member"} > 0).
type metrics struct {
	runs          *prometheus.CounterVec // scope, result: clean | drift | incomplete | skipped
	drift         *prometheus.GaugeVec   // kind: findings in the latest report of every subject
	scheduled     *prometheus.CounterVec // scope
	events        *prometheus.CounterVec // kind, severity: security events written (not deduplicated)
	eventFailures prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_reconcile_runs_total",
			Help: "Reconcile runs by scope (instance, host) and result (clean, drift, incomplete, skipped)."}, []string{"scope", "result"}),
		drift: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "meshguard_reconcile_drift",
			Help: "Drift findings by kind in the latest reconcile report of every instance and of the host."}, []string{"kind"}),
		scheduled: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_reconcile_scheduled_total",
			Help: "Reconcile jobs enqueued by the schedule, by scope."}, []string{"scope"}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_reconcile_security_events_total",
			Help: "Security events written by reconcile (after dedupe), by kind and severity."}, []string{"kind", "severity"}),
		eventFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "meshguard_reconcile_security_event_failures_total",
			Help: "Security events of reconcile that could not be recorded."}),
	}
	for _, k := range DriftKinds {
		m.drift.WithLabelValues(k).Set(0)
	}
	if reg != nil {
		reg.MustRegister(m.runs, m.drift, m.scheduled, m.events, m.eventFailures)
	}
	return m
}
