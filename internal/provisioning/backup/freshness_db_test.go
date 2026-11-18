package backup_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
)

// gauge returns the value of name{instance_id} in reg (-1 when absent) and whether tenant_id was the expected one.
func gauge(t *testing.T, reg *prometheus.Registry, name, tenant, instance string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			l := map[string]string{}
			for _, lp := range m.GetLabel() {
				l[lp.GetName()] = lp.GetValue()
			}
			if l["instance_id"] == instance {
				if l["tenant_id"] != tenant || len(l) != 2 {
					t.Fatalf("%s labels %v", name, l)
				}
				return m.GetGauge().GetValue()
			}
		}
	}
	return -1
}

// TestBackupFreshness — P3-T16, §16.3 "quá hạn lịch backup của tenant": the age of the newest succeeded backup of
// every scheduled instance, against twice its period. An instance that never had a backup counts from its creation; a
// failed backup does not refresh the age; an instance the schedule no longer covers has no series.
func TestBackupFreshness(t *testing.T) {
	f := newFix(t)
	f.worker()
	ctx := context.Background()
	reg := prometheus.NewRegistry()
	fr, err := f.svc.NewFreshness(reg, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ten, inst := f.tenant.String(), f.instance.String()
	refresh := func() {
		t.Helper()
		if err := fr.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	near := func(got, want, tol float64) bool { return math.Abs(got-want) <= tol }

	// a new instance: its age counts from created_at, max age = 2 × MG_BACKUP_INTERVAL (1 h here)
	refresh()
	if age, maxAge := gauge(t, reg, backup.MetricBackupAge, ten, inst), gauge(t, reg, backup.MetricBackupMaxAge, ten, inst); age < 0 ||
		age > 120 || maxAge != 7200 || gauge(t, reg, backup.MetricBackupLastSuccess, ten, inst) != -1 {
		t.Fatalf("new instance: age %v max %v", age, maxAge)
	}
	// created 3 h ago and never backed up ⇒ overdue (age > max age)
	f.exec(`UPDATE tenant_instances SET created_at = now() - interval '3 hours' WHERE id = $1`, f.instance)
	refresh()
	if age := gauge(t, reg, backup.MetricBackupAge, ten, inst); !near(age, 3*3600, 120) {
		t.Fatalf("never backed up, created 3 h ago: age %v", age)
	}
	// a real backup through the job ⇒ fresh again, last success = its finished_at
	id := f.backupNow()
	refresh()
	finished := float64(time.Now().Unix())
	if age, last := gauge(t, reg, backup.MetricBackupAge, ten, inst), gauge(t, reg, backup.MetricBackupLastSuccess, ten, inst); age < 0 ||
		age > 120 || !near(last, finished, 120) {
		t.Fatalf("after a backup: age %v last %v", age, last)
	}
	// the newest succeeded backup finished 4 h ago ⇒ overdue
	f.exec(`UPDATE backups SET started_at = now() - interval '4 hours 5 minutes', finished_at = now() - interval '4 hours' WHERE id = $1`, id)
	refresh()
	if age := gauge(t, reg, backup.MetricBackupAge, ten, inst); !near(age, 4*3600, 120) || age <= gauge(t, reg, backup.MetricBackupMaxAge, ten, inst) {
		t.Fatalf("backup 4 h old: age %v", age)
	}
	// purged (archive past retention) still counts as the last success
	f.exec(`UPDATE backups SET status = 'purged' WHERE id = $1`, id)
	refresh()
	if age := gauge(t, reg, backup.MetricBackupAge, ten, inst); !near(age, 4*3600, 120) {
		t.Fatalf("purged: age %v", age)
	}
	// a failed backup does not count: back to the creation time
	f.exec(`UPDATE backups SET status = 'failed' WHERE id = $1`, id)
	refresh()
	if age := gauge(t, reg, backup.MetricBackupAge, ten, inst); !near(age, 3*3600, 120) ||
		gauge(t, reg, backup.MetricBackupLastSuccess, ten, inst) != -1 {
		t.Fatalf("failed backup counted: age %v", age)
	}
	// the plan's period (clamped to 15 min) sets the max age
	plan := f.str(`SELECT id::text FROM subscription_plans ORDER BY created_at LIMIT 1`)
	f.exec(`INSERT INTO subscriptions (tenant_id, plan_id, status, overrides) VALUES ($1, $2, 'active', '{"backup_interval_minutes": 5}')`,
		f.tenant, plan)
	refresh()
	if maxAge := gauge(t, reg, backup.MetricBackupMaxAge, ten, inst); maxAge != 2*15*60 {
		t.Fatalf("plan period 5 min (clamped to 15): max age %v", maxAge)
	}
	// an instance the schedule no longer covers (removed) has no series
	f.exec(`UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, f.instance)
	refresh()
	if age := gauge(t, reg, backup.MetricBackupAge, ten, inst); age != -1 {
		t.Fatalf("removed instance still exported: %v", age)
	}
	// a second registration on the same registry is refused
	if _, err := f.svc.NewFreshness(reg, time.Minute); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}
