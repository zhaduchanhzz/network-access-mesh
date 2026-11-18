package backup

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Metric names of the backup freshness (P3-T16 — the alert of §16.3 "Quá hạn lịch backup của tenant", rule
// TenantBackupOverdue of infrastructure/monitoring):
//
//	meshguard_instance_backup_age_seconds > meshguard_instance_backup_max_age_seconds
const (
	MetricBackupAge         = "meshguard_instance_backup_age_seconds"
	MetricBackupMaxAge      = "meshguard_instance_backup_max_age_seconds"
	MetricBackupLastSuccess = "meshguard_instance_backup_last_success_timestamp_seconds"
)

// Freshness exports how old the newest succeeded backup of every instance the schedule covers is (running or stopped,
// tenant still served — the instances of ListBackupSchedule):
//
//	meshguard_instance_backup_age_seconds{tenant_id,instance_id}  now − finished_at of the newest succeeded (or purged)
//	    backup, computed at scrape time; an instance that never had one counts from its creation — a new instance
//	    becomes overdue one max age after it was created, never silently
//	meshguard_instance_backup_max_age_seconds{…}                   2 × the instance's backup period (plan's
//	    backup_interval_minutes clamped to 15 min…24 h, else MG_BACKUP_INTERVAL): one scheduled backup may fail, the
//	    second missed one is overdue
//	meshguard_instance_backup_last_success_timestamp_seconds{…}    finished_at of that backup (instances with one only)
//
// The rows are read from PostgreSQL every tick (default 1 min) by every worker, whether or not it schedules backups:
// a worker without the Host Agent or the manifest key never backs anything up, and its instances become overdue
// instead of absent.
type Freshness struct {
	svc  *Service
	tick time.Duration
	now  func() time.Time

	age, maxAge, last *prometheus.Desc

	mu   sync.Mutex
	rows []freshRow
}

type freshRow struct {
	tenant, instance uuid.UUID
	since            time.Time // finished_at of the newest succeeded backup, or the instance's created_at
	succeeded        bool
	maxAge           time.Duration
}

// NewFreshness returns the freshness gauges of the schedule's instances, registered on reg (nil: not registered).
func (s *Service) NewFreshness(reg prometheus.Registerer, tick time.Duration) (*Freshness, error) {
	if tick <= 0 {
		tick = time.Minute
	}
	labels := []string{"tenant_id", "instance_id"}
	f := &Freshness{svc: s, tick: tick, now: s.cfg.Now,
		age: prometheus.NewDesc(MetricBackupAge, "Seconds since the newest succeeded backup of the instance finished "+
			"(since the instance was created when it never had one), computed at scrape time.", labels, nil),
		maxAge: prometheus.NewDesc(MetricBackupMaxAge, "Age past which the instance's backup is overdue: twice its backup period.",
			labels, nil),
		last: prometheus.NewDesc(MetricBackupLastSuccess, "End of the newest succeeded backup of the instance (Unix seconds).",
			labels, nil)}
	if reg != nil {
		if err := reg.Register(f); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// Run refreshes the rows every tick until ctx is cancelled (a failed read keeps the previous rows and is logged).
func (f *Freshness) Run(ctx context.Context) error {
	t := time.NewTicker(f.tick)
	defer t.Stop()
	for {
		if err := f.Refresh(ctx); err != nil && ctx.Err() == nil {
			f.svc.log.ErrorContext(ctx, "backup: freshness refresh failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Refresh reads the instances of the schedule and their newest succeeded backup.
func (f *Freshness) Refresh(ctx context.Context) error {
	var rows []sqlcdb.ListBackupFreshnessRow
	if err := f.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListBackupFreshness(ctx)
		return err
	}); err != nil {
		return err
	}
	out := make([]freshRow, 0, len(rows))
	for _, r := range rows {
		fr := freshRow{tenant: r.TenantID, instance: r.ID, since: r.CreatedAt,
			maxAge: 2 * periodOf(r.IntervalMinutes, f.svc.cfg.Interval)}
		if r.LastSuccessAt.Unix() > 0 {
			fr.since, fr.succeeded = r.LastSuccessAt, true
		}
		out = append(out, fr)
	}
	f.mu.Lock()
	f.rows = out
	f.mu.Unlock()
	return nil
}

// Describe implements prometheus.Collector.
func (f *Freshness) Describe(ch chan<- *prometheus.Desc) {
	ch <- f.age
	ch <- f.maxAge
	ch <- f.last
}

// Collect implements prometheus.Collector.
func (f *Freshness) Collect(ch chan<- prometheus.Metric) {
	f.mu.Lock()
	rows := f.rows
	f.mu.Unlock()
	now := f.now()
	for _, r := range rows {
		lv := []string{r.tenant.String(), r.instance.String()}
		ch <- prometheus.MustNewConstMetric(f.age, prometheus.GaugeValue, now.Sub(r.since).Seconds(), lv...)
		ch <- prometheus.MustNewConstMetric(f.maxAge, prometheus.GaugeValue, r.maxAge.Seconds(), lv...)
		if r.succeeded {
			ch <- prometheus.MustNewConstMetric(f.last, prometheus.GaugeValue, float64(r.since.Unix()), lv...)
		}
	}
}
