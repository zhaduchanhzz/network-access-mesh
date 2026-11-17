package contract

// Phase 9 (P2-T13a): the health probe of internal/monitoring against the real Headscale of the contract run, through
// the real admin listener of the edge, with the register database of the device phases. Runs after the device test of
// the same phase (the runner needs no step of its own: every failure mode is produced through the target):
//
//   - healthy: job health.probe run by the real job framework (River) — GET /version reports the pinned version and
//     GET /api/v1/health database connectivity; tenant_instances.last_health holds them with checked_at; the tenant
//     dashboard shows the instance healthy at that checked_at and the devices of the last sync with their synced_at;
//   - not reachable (an instance the edge does not know ⇒ the edge cannot route) ⇒ instance_unavailable, then the
//     adapter's breaker opens ⇒ circuit_open without a call;
//   - a wrong API key ⇒ api_key_rejected (after the adapter's one reload); a wrong edge token ⇒ edge_rejected;
//   - finally healthy again (the last record is the real state of the instance).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// healthProber is the Prober of apps/* (monitoring imports neither headscale nor devices — §13.6).
func healthProber(reg *headscale.CachingRegistry) monitoring.Prober {
	return monitoring.ProberFunc(func(ctx context.Context, t uuid.UUID) monitoring.InstanceProbe {
		p := reg.Probe(ctx, t)
		return monitoring.InstanceProbe{InstanceID: p.InstanceID, Version: p.Version, Database: p.Database,
			Breaker: string(p.Breaker), Reason: p.Reason(), Duration: p.Duration}
	})
}

func healthDevices(svc *devices.Service) monitoring.DeviceCounter {
	return monitoring.DeviceCounterFunc(func(ctx context.Context, t uuid.UUID) (monitoring.DeviceCounts, error) {
		s, err := svc.Summary(ctx, t)
		return monitoring.DeviceCounts(s), err
	})
}

type healthRecord struct {
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	Version  string `json:"version"`
	Database *bool  `json:"database"`
	Breaker  string `json:"breaker"`
}

// lastHealth reads tenant_instances.last_health / last_health_at of the run's instance (superuser).
func (d *devEnv) lastHealth(t *testing.T) (healthRecord, time.Time) {
	t.Helper()
	var (
		raw []byte
		at  *time.Time
	)
	if err := d.su.QueryRow(context.Background(), `SELECT last_health, last_health_at FROM tenant_instances WHERE id = $1`,
		instanceID).Scan(&raw, &at); err != nil {
		t.Fatal(err)
	}
	var h healthRecord
	if raw == nil || at == nil || json.Unmarshal(raw, &h) != nil {
		t.Fatalf("last_health %s at %v", raw, at)
	}
	return h, *at
}

func TestP9_HealthProbe(t *testing.T) {
	d := devSetup(t)
	c := ctx(t)
	lf, err := os.OpenFile(filepath.Join(d.stateDir, "adapter.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304/G703: run.sh's state directory
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lf.Close() })
	log := logx.New(lf, slog.LevelDebug, "monitoring")
	newService := func(st *store.Store, p monitoring.Prober) *monitoring.Service {
		t.Helper()
		dev, err := devices.New(st, devices.Config{Registry: d.reg, Logger: log})
		if err != nil {
			t.Fatal(err)
		}
		svc, err := monitoring.New(st, monitoring.Config{Devices: healthDevices(dev), Prober: p, Logger: log,
			Registerer: prometheus.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		return svc
	}
	wrk := newService(d.wrkSt, healthProber(d.reg))
	apiSt := d.pg.OpenStore(t, d.db, "mg_api_tenant", "mg_api_platform", 4)
	api := newService(apiSt, nil)

	// Healthy, through the real job framework: the schedule enqueues health.probe, the worker runs it.
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	w, err := jobs.NewWorker(d.wrkSt, cfg, jobs.Options{Registerer: prometheus.NewRegistry(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrk.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(sc)
	})
	sched := wrk.NewScheduler(monitoring.SchedulerConfig{Interval: time.Minute, Tick: time.Second})
	t0 := time.Now()
	if _, err := sched.Tick(c, t0); err != nil {
		t.Fatal(err)
	}
	if n, err := sched.Tick(c, t0.Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("schedule: %d %v, want one health.probe", n, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	var status, output string
	for {
		if err := d.su.QueryRow(context.Background(), `SELECT status, coalesce(output::text, '') FROM provisioning_jobs
				WHERE kind = 'health.probe' AND instance_id = $1 ORDER BY created_at DESC LIMIT 1`, instanceID).Scan(&status, &output); err != nil {
			t.Fatal(err)
		}
		if status == jobs.StatusSucceeded || status == jobs.StatusFailed || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	h, at := d.lastHealth(t)
	if status != jobs.StatusSucceeded || h.Status != monitoring.StatusHealthy || h.Version != "v0.29.7" || h.Database == nil ||
		!*h.Database || h.Breaker != "closed" {
		t.Fatalf("health.probe job %s (%s); last_health %+v", status, output, h)
	}
	dash, err := api.TenantDashboard(c, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var syncedAt time.Time
	if err := d.su.QueryRow(context.Background(), `SELECT synced_at FROM device_inventory_sync_state WHERE instance_id = $1`,
		instanceID).Scan(&syncedAt); err != nil {
		t.Fatal(err)
	}
	live := d.count(t, `SELECT count(*) FROM device_inventory_cache WHERE instance_id = $1 AND removed_at IS NULL`, instanceID)
	if dash.Instance.Status != monitoring.StatusHealthy || dash.Instance.CheckedAt == nil || !dash.Instance.CheckedAt.Equal(at) ||
		dash.Devices.Total != live || dash.Devices.SyncedAt == nil || !dash.Devices.SyncedAt.Equal(syncedAt) {
		t.Fatalf("dashboard %+v; want healthy at %v, %d devices synced at %v", dash, at, live, syncedAt)
	}
	d.record(t, "P2-T13a", "health.probe — instance chạy (job thật, Headscale thật qua edge)",
		fmt.Sprintf("job %s; last_health status=%s version=%s database=%v breaker=%s; last_health_at=%s; dashboard: instance %s (checked_at = last_health_at), %d thiết bị synced_at=%s",
			status, h.Status, h.Version, *h.Database, h.Breaker, at.UTC().Format(time.RFC3339Nano), dash.Instance.Status, dash.Devices.Total,
			dash.Devices.SyncedAt.UTC().Format(time.RFC3339Nano)), "job output: "+output)

	// Failure modes through the target (the real edge answers them).
	probeWith := func(cas string, mutate func(*headscale.Target), breaker headscale.BreakerConfig, times int) []monitoring.ProbeResult {
		t.Helper()
		tg := d.target()
		mutate(&tg)
		reg := headscale.NewRegistry(headscale.StaticLocator{tenantID: tg}, headscale.Options{Logger: log, Timeout: 10 * time.Second,
			Retry: headscale.RetryPolicy{Attempts: 1}, Breaker: breaker})
		svc := newService(d.wrkSt, healthProber(reg))
		var out []monitoring.ProbeResult
		var parts []string
		for range times {
			res, err := svc.Probe(c, tenantID, instanceID)
			if err != nil {
				t.Fatalf("%s: %v", cas, err)
			}
			rec, _ := d.lastHealth(t)
			if !res.Recorded || rec.Status != res.Status || rec.Reason != res.Reason {
				t.Fatalf("%s: result %+v, recorded %+v", cas, res, rec)
			}
			out = append(out, res)
			parts = append(parts, fmt.Sprintf("%s/%s breaker=%s", res.Status, res.Reason, res.Breaker))
		}
		d.record(t, "P2-T13a", "health.probe — "+cas, strings.Join(parts, "; "), "")
		return out
	}
	unknownSlug := func(tg *headscale.Target) { tg.Slug = "hsct-unknown" }
	r := probeWith("edge không định tuyến được (instance không tồn tại sau edge)", unknownSlug,
		headscale.BreakerConfig{FailureThreshold: 2, OpenFor: time.Hour}, 3)
	if r[0].Reason != headscale.ProbeInstanceUnavailable || r[1].Reason != headscale.ProbeInstanceUnavailable || r[1].Breaker != "open" ||
		r[2].Reason != headscale.ProbeCircuitOpen || r[2].Breaker != "open" {
		t.Errorf("unreachable instance: %+v", r)
	}
	r = probeWith("API key sai", func(tg *headscale.Target) {
		tg.APIKey = headscale.NewSecret("hskey-" + "api-" + "wrongprefix1" + "-" + strings.Repeat("x", 40))
	}, headscale.BreakerConfig{}, 1)
	if r[0].Reason != headscale.ProbeAPIKeyRejected || r[0].Version != "v0.29.7" {
		t.Errorf("wrong API key: %+v", r)
	}
	r = probeWith("token edge sai", func(tg *headscale.Target) { tg.EdgeToken = headscale.NewSecret(strings.Repeat("Z", 40)) },
		headscale.BreakerConfig{}, 1)
	if r[0].Reason != headscale.ProbeEdgeRejected {
		t.Errorf("wrong edge token: %+v", r)
	}
	r = probeWith("trở lại target đúng", func(*headscale.Target) {}, headscale.BreakerConfig{}, 1)
	if r[0].Status != monitoring.StatusHealthy {
		t.Errorf("back to the real target: %+v", r)
	}
	if dash, err := api.TenantDashboard(c, tenantID); err != nil || dash.Instance.Status != monitoring.StatusHealthy {
		t.Errorf("dashboard at the end: %+v %v", dash.Instance, err)
	}

	// Canary of §25.1 rule 9: no credential in the logs or the observations.
	logs, err := os.ReadFile(filepath.Join(d.stateDir, "adapter.log"))
	if err != nil {
		t.Fatal(err)
	}
	obs, _ := os.ReadFile(d.obsFile)
	for name, text := range map[string]string{"adapter.log": string(logs), "observations": string(obs)} {
		if strings.Contains(text, d.apiKey) || strings.Contains(text, d.edgeToken) {
			t.Errorf("%s contains a credential of the run", name)
		}
	}
}
