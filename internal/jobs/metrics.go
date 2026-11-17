package jobs

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// Alert reasons (§16.3 group Orchestrator: job failed or failed_resumable; job that rolled back by itself; job reaped by
// job.reaper — and §6.1: rows in a DEFAULT partition).
const (
	AlertFailed               = "failed"
	AlertFailedResumable      = "failed_resumable"
	AlertRolledBack           = "rolled_back"
	AlertReaped               = "reaped"
	AlertPartitionDefaultRows = "partition_default_rows"
)

// Alert describes one job that ended badly, or a maintenance finding. It never carries an error message — only the
// stable code — so it can be forwarded anywhere.
type Alert struct {
	Reason   string
	JobID    uuid.UUID
	TenantID *uuid.UUID
	Kind     string
	Status   string // the status the job ended in
	Code     string // error code (or table name for partition_default_rows)
}

// Alerter receives every alert after the worker has counted it (meshguard_job_alerts_total) and logged it at ERROR with
// alert=true. The Alertmanager rules on that counter come with P6-T01 (§16.3); an Alerter may forward alerts elsewhere.
type Alerter interface {
	JobAlert(ctx context.Context, a Alert)
}

// metrics of the worker (§16.1 "job: độ sâu hàng đợi, lỗi, thời lượng").
type metrics struct {
	finished   *prometheus.CounterVec   // kind, status
	alerts     *prometheus.CounterVec   // kind, reason
	duration   *prometheus.HistogramVec // kind
	lockWaits  *prometheus.CounterVec   // kind
	unfinished *prometheus.GaugeVec     // status
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		finished: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_jobs_finished_total", Help: "Jobs that reached a final or failure status, by kind and status.",
		}, []string{"kind", "status"}),
		alerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_job_alerts_total",
			Help: "Job alerts (failed, failed_resumable, rolled_back, reaped by job.reaper, partition_default_rows).",
		}, []string{"kind", "reason"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "meshguard_job_attempt_duration_seconds", Help: "Duration of one handler attempt, by kind.",
			Buckets: []float64{0.05, 0.25, 1, 5, 15, 60, 180, 600},
		}, []string{"kind"}),
		lockWaits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_job_lock_waits_total",
			Help: "Lifecycle jobs that found their tenant's lock taken and snoozed, by kind.",
		}, []string{"kind"}),
		unfinished: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "meshguard_jobs_unfinished", Help: "Unfinished jobs by status (refreshed by job.reaper every run).",
		}, []string{"status"}),
	}
	if reg != nil {
		reg.MustRegister(m.finished, m.alerts, m.duration, m.lockWaits, m.unfinished)
	}
	return m
}

// alert counts, logs and forwards one alert.
func (w *Worker) alert(ctx context.Context, a Alert) {
	w.metrics.alerts.WithLabelValues(a.Kind, a.Reason).Inc()
	attrs := []any{"alert", true, "reason", a.Reason, "job_id", a.JobID, "kind", a.Kind, "status", a.Status, "code", a.Code}
	if a.TenantID != nil {
		attrs = append(attrs, "tenant_id", *a.TenantID)
	}
	w.log.Log(ctx, slog.LevelError, "job alert", attrs...)
	if w.alerter != nil {
		w.alerter.JobAlert(ctx, a)
	}
}
