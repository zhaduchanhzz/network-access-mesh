package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// sections returns section → reason of a dashboard's unavailable list.
func sections(d TenantDashboard) map[string]string {
	out := map[string]string{}
	for _, u := range d.Unavailable {
		out[u.Section] = u.Reason
	}
	return out
}

// TestTenantDashboardIsolation (IT-12b, service level): two tenants with different devices and instance health; each
// dashboard holds exactly its own tenant's figures — device totals/online of its own register with the synced_at of
// its own instance's last sync, the health of its own instance with that instance's checked_at — and the sections
// without a source are reported unavailable with their reason, never as numbers.
func TestTenantDashboardIsolation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.a.hs.PutNode(node(1, true))
	f.a.hs.PutNode(node(2, false))
	for i := uint64(1); i <= 3; i++ {
		f.b.hs.PutNode(node(i, true))
	}
	for _, ten := range []*tenantFx{f.a, f.b} {
		if _, err := f.devWrk.Sync(ctx, ten.id, ten.instance); err != nil {
			t.Fatal(err)
		}
	}
	f.b.hs.SetDown(true)
	for _, ten := range []*tenantFx{f.a, f.b} {
		if _, err := f.wrk.Probe(ctx, ten.id, ten.instance); err != nil {
			t.Fatal(err)
		}
	}
	want := map[*tenantFx]struct {
		total, online int
		status        string
		reason        string
	}{f.a: {2, 1, StatusHealthy, ""}, f.b: {3, 3, StatusUnhealthy, headscale.ProbeInstanceUnavailable}}
	for ten, w := range want {
		d, err := f.api.TenantDashboard(ctx, ten.id)
		if err != nil {
			t.Fatal(err)
		}
		var syncedAt time.Time
		f.scan(t, `SELECT synced_at FROM device_inventory_sync_state WHERE tenant_id = $1 AND instance_id = $2`,
			[]any{ten.id, ten.instance}, &syncedAt)
		row := f.instanceRow(t, ten.instance)
		if d.Devices.Total != w.total || d.Devices.Online != w.online || d.Devices.SyncedAt == nil || !d.Devices.SyncedAt.Equal(syncedAt) {
			t.Errorf("%s devices %+v, want %d/%d synced at %v (its own register)", ten.slug, d.Devices, w.total, w.online, syncedAt)
		}
		if d.Instance.Status != w.status || d.Instance.Reason != w.reason || d.Instance.CheckedAt == nil ||
			!d.Instance.CheckedAt.Equal(*row.healthAt) {
			t.Errorf("%s instance %+v, want %s/%q checked at %v (its own instance)", ten.slug, d.Instance, w.status, w.reason, row.healthAt)
		}
		got := sections(d)
		if len(got) != 4 || got[SectionPolicies] != ReasonNoSource || got[SectionRelay] != ReasonNoSource ||
			got[SectionRoutes] != ReasonNotServed || got[SectionSecurityEvents] != ReasonNotServed {
			t.Errorf("%s unavailable sections %v", ten.slug, got)
		}
		for _, u := range d.Unavailable {
			if u.Detail == "" {
				t.Errorf("%s: section %s without a detail", ten.slug, u.Section)
			}
		}
	}
	if _, err := f.api.TenantDashboard(ctx, uuid.Nil); err == nil {
		t.Error("dashboard without a tenant")
	}
}

// TestTenantDashboardWithoutFigures: honest answers when a source has nothing to say — a register never synced
// (counts 0 with synced_at null AND the devices section reported never_synced), an instance never probed, no
// instance at all (or only a removed one), a stale probe (checked_at kept), an instance that is not running, a record
// this module did not write.
func TestTenantDashboardWithoutFigures(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	d, err := f.api.TenantDashboard(ctx, f.a.id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Devices.Total != 0 || d.Devices.SyncedAt != nil || sections(d)[SectionDevices] != ReasonNeverSynced || len(d.Unavailable) != 5 {
		t.Errorf("never synced: %+v %v", d.Devices, sections(d))
	}
	if d.Instance.Status != StatusUnknown || d.Instance.Reason != ReasonNeverChecked || d.Instance.CheckedAt != nil {
		t.Errorf("never probed: %+v", d.Instance)
	}
	if _, err := f.wrk.Probe(ctx, f.a.id, f.a.instance); err != nil {
		t.Fatal(err)
	}
	at := f.instanceRow(t, f.a.instance).healthAt
	cases := []struct {
		name, sql, reason string
		keepsTime         bool
	}{
		{"stale", `UPDATE tenant_instances SET last_health_at = last_health_at - interval '1 hour' WHERE id = $1`, ReasonStale, true},
		{"not running", `UPDATE tenant_instances SET status = 'stopped' WHERE id = $1`, ReasonInstanceNotRunning, true},
		{"foreign record", `UPDATE tenant_instances SET status = 'running', last_health = '{"status":"ok"}' WHERE id = $1`,
			ReasonInvalidRecord, true},
		{"removed", `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, ReasonNoInstance, false},
	}
	for _, c := range cases {
		f.exec(t, c.sql, f.a.instance)
		d, err := f.api.TenantDashboard(ctx, f.a.id)
		if err != nil {
			t.Fatal(err)
		}
		if d.Instance.Status != StatusUnknown || d.Instance.Reason != c.reason || (d.Instance.CheckedAt != nil) != c.keepsTime {
			t.Errorf("%s: %+v (probed at %v)", c.name, d.Instance, at)
		}
	}
	noInstance := uuid.New()
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'bare', 'Bare', 'pending')`, noInstance)
	if d, err := f.api.TenantDashboard(ctx, noInstance); err != nil || d.Instance.Reason != ReasonNoInstance ||
		sections(d)[SectionDevices] != ReasonNeverSynced {
		t.Errorf("tenant without an instance: %+v %v", d, err)
	}
}

// TestPlatformHealth: one snapshot of the platform — tenants by status (zeros included), instances not removed by
// status / health / reported version with the unhealthy count, the job queue (unfinished by status, failed or rolled
// back in the last 24 hours), the worker's heartbeat from the last job.reaper (none, fresh, failed, stale), postgres
// healthy at the aggregation time, and the components without a probe reported unknown with their reason.
func TestPlatformHealth(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, d := f.newTenant(t, "suspended"), f.newTenant(t, "failed")
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'gone', 'Gone', 'deleted')`, uuid.New())
	f.exec(t, `UPDATE tenant_instances SET status = 'stopped' WHERE id = $1`, c.instance)
	f.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, d.instance)
	f.b.hs.SetDown(true)
	for _, ten := range []*tenantFx{f.a, f.b} {
		if _, err := f.wrk.Probe(ctx, ten.id, ten.instance); err != nil {
			t.Fatal(err)
		}
	}
	e := f.newTenant(t, "active")
	e.hs.SetVersion("v0.30.0")
	reg := headscale.NewRegistry(headscale.StaticLocator{e.id: e.hs.Target(e.instance)}, headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1}})
	if _, err := f.service(t, f.wrkSt, f.devWrk, adapterProber(reg)).Probe(ctx, e.id, e.instance); err != nil {
		t.Fatal(err)
	}
	// Job queue.
	for i, j := range []struct {
		kind, status string
		finished     string
	}{
		{"tenant.provision", "queued", ""}, {"tenant.resume", "running", ""}, {"tenant.suspend", "failed_resumable", ""},
		{"instance.backup", "failed", "1 hour"}, {"instance.restart", "rolled_back", "2 hours"}, {"policy.apply", "failed", "30 hours"},
		{"inventory.sync", "succeeded", "5 minutes"},
	} {
		fin := any(nil)
		if j.finished != "" {
			fin = j.finished
		}
		f.exec(t, `INSERT INTO provisioning_jobs (tenant_id, kind, status, dedupe_key, finished_at)
			VALUES ($1, $2, $3, $4, now() - $5::interval)`, f.a.id, j.kind, j.status, "test:"+j.kind+":"+string(rune('a'+i)), fin)
	}
	ph, err := f.api.PlatformHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var dbNow time.Time
	f.scan(t, `SELECT now()`, nil, &dbNow)
	if ph.CheckedAt.IsZero() || ph.CheckedAt.After(dbNow) || dbNow.Sub(ph.CheckedAt) > time.Minute || !ph.Jobs.CheckedAt.Equal(ph.CheckedAt) {
		t.Errorf("checked_at %v (db now %v), jobs %v", ph.CheckedAt, dbNow, ph.Jobs.CheckedAt)
	}
	wantTenants := map[string]int{"pending": 0, "provisioning": 0, "active": 3, "suspended": 1, "deprovisioning": 0, "deleted": 1, "failed": 1}
	if ph.Tenants.Total != 6 || !sameCounts(ph.Tenants.ByStatus, wantTenants) {
		t.Errorf("tenants %+v, want 6 %v", ph.Tenants, wantTenants)
	}
	in := ph.Instances
	if in.Total != 4 || !sameCounts(in.ByStatus, map[string]int{"allocated": 0, "starting": 0, "running": 3, "stopped": 1, "failed": 0, "quarantined": 0}) ||
		!sameCounts(in.ByHealth, map[string]int{StatusHealthy: 1, StatusUnhealthy: 2, StatusUnknown: 1}) || in.Unhealthy != 2 ||
		!sameCounts(in.ByVersion, map[string]int{"v0.29.7": 1, "v0.30.0": 1}) {
		t.Errorf("instances %+v", in)
	}
	if !sameCounts(ph.Jobs.Unfinished, map[string]int{"queued": 1, "running": 1, "compensating": 0, "failed_resumable": 1}) ||
		ph.Jobs.FailedLast24h != 2 {
		t.Errorf("jobs %+v, want 1/1/0/1 unfinished and 2 failed in 24 h", ph.Jobs)
	}
	comp := map[string]Component{}
	for _, c := range ph.Components {
		comp[c.Name] = c
	}
	if p := comp[ComponentPostgres]; p.Status != StatusHealthy || p.CheckedAt == nil || !p.CheckedAt.Equal(ph.CheckedAt) {
		t.Errorf("postgres %+v", p)
	}
	for name, reason := range map[string]string{ComponentEdge: ReasonNoProbe, ComponentIdP: ReasonNoProbe, ComponentAgent: ReasonNotDeployed,
		ComponentWorker: ReasonNoHeartbeat} {
		if c := comp[name]; c.Status != StatusUnknown || c.Reason != reason || c.CheckedAt != nil {
			t.Errorf("%s %+v, want unknown/%s without checked_at", name, c, reason)
		}
	}
	if len(ph.Components) != 5 {
		t.Errorf("%d components", len(ph.Components))
	}

	// Worker heartbeat: the last job.reaper.
	heartbeat := func(status, age string) Component {
		t.Helper()
		f.exec(t, `INSERT INTO provisioning_jobs (kind, status, dedupe_key, finished_at) VALUES ('job.reaper', $1, $2, now() - $3::interval)`,
			status, "job.reaper:"+uuid.NewString(), age)
		ph, err := f.api.PlatformHealth(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range ph.Components {
			if c.Name == ComponentWorker {
				return c
			}
		}
		t.Fatal("no worker component")
		return Component{}
	}
	if w := heartbeat("succeeded", "20 seconds"); w.Status != StatusHealthy || w.Reason != "" || w.CheckedAt == nil {
		t.Errorf("fresh heartbeat: %+v", w)
	}
	if w := heartbeat("failed", "5 seconds"); w.Status != StatusUnhealthy || w.Reason != ReasonHeartbeatFailed || w.CheckedAt == nil {
		t.Errorf("failed heartbeat: %+v", w)
	}
	f.exec(t, `UPDATE provisioning_jobs SET finished_at = finished_at - interval '10 minutes', status = 'succeeded' WHERE kind = 'job.reaper'`)
	if w := heartbeat("succeeded", "4 minutes"); w.Status != StatusUnhealthy || w.Reason != ReasonHeartbeatStale {
		t.Errorf("stale heartbeat: %+v", w)
	}
}

func sameCounts(got, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			return false
		}
	}
	return true
}
