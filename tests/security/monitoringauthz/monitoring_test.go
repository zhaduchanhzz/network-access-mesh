//go:build mgtestfixture

// Package monitoringauthz drives the monitoring operations of P2-T13a through the composed API — identity session
// layer, authorization (authz), audit middleware, monitoringapi — with sessions minted by the fixture of P2-T15a for
// every role of §8.5/§8.6, a fake Headscale per tenant behind the real adapter, the device register synced and the
// instances probed by the worker-side services: the permission matrix of both operations, IT-12b (a tenant's dashboard
// never holds another tenant's figures; the tenant is forced server-side — a tenant in the query or a header is
// ignored), the timestamps of every figure, and the audit trail (reads are not audited, refusals are).
package monitoringauthz

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/monitoringapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

func unlimited() httpapi.RateLimits {
	l := ratelimit.Limit{Every: time.Nanosecond, Burst: 1_000_000_000}
	out := httpapi.RateLimits{}
	for _, c := range httpapi.Classes {
		out[c] = httpapi.ClassLimits{PerIP: l, PerIdentity: l}
	}
	return out
}

// The glue of apps/* (§13.6: monitoring imports neither headscale nor devices).
func prober(reg *headscale.CachingRegistry) monitoring.Prober {
	return monitoring.ProberFunc(func(ctx context.Context, t uuid.UUID) monitoring.InstanceProbe {
		p := reg.Probe(ctx, t)
		return monitoring.InstanceProbe{InstanceID: p.InstanceID, Version: p.Version, Database: p.Database,
			Breaker: string(p.Breaker), Reason: p.Reason(), Duration: p.Duration}
	})
}

func deviceCounter(svc *devices.Service) monitoring.DeviceCounter {
	return monitoring.DeviceCounterFunc(func(ctx context.Context, t uuid.UUID) (monitoring.DeviceCounts, error) {
		s, err := svc.Summary(ctx, t)
		return monitoring.DeviceCounts(s), err
	})
}

func monitoringService(t *testing.T, st *store.Store, reg *headscale.CachingRegistry, withProber bool) (*devices.Service, *monitoring.Service) {
	t.Helper()
	dev, err := devices.New(st, devices.Config{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	cfg := monitoring.Config{Devices: deviceCounter(dev), Registerer: prometheus.NewRegistry()}
	if withProber {
		cfg.Prober = prober(reg)
	}
	mon, err := monitoring.New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return dev, mon
}

func get(t *testing.T, api http.Handler, s *sessionfixture.Session, path string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := s.Request(context.Background(), http.MethodGet, path, nil)
	for k, v := range hdr {
		r.Header[k] = v
	}
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, r)
	return rec
}

// TestMonitoringThroughTheComposedAPI: §8.6 tenant.dashboard:read (TO TA TP TV ✔, EU —, staff without a Support
// Access Grant 403 — AC-05a) and §8.5 platform.health:read (SA PO PS PV ✔, tenant roles 403), with IT-12b: every
// granted dashboard of A holds exactly A's figures with their synced_at/checked_at, whatever tenant a query parameter
// or header names; B's members get 404 on A's dashboard; B's dashboard holds B's figures; the platform health holds
// no device figure; reads leave no audit event, refusals do.
func TestMonitoringThroughTheComposedAPI(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	pg := storetest.Require(t)
	ctx := context.Background()
	host := uuid.New()
	w.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	instances := map[*sessionfixture.Tenant]uuid.UUID{w.A: uuid.New(), w.B: uuid.New()}
	fakes := map[*sessionfixture.Tenant]*devicestest.Fake{}
	targets := map[uuid.UUID]headscale.Target{}
	i := 0
	for _, ten := range []*sessionfixture.Tenant{w.A, w.B} {
		i++
		inst := instances[ten]
		w.Exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
			inst, ten.ID, host, ten.Slug+".mesh.test", ten.Slug+".ts.test", "hs-"+ten.Slug+":8080", 30000+i,
			fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+inst.String())
		fakes[ten] = devicestest.New(t, ten.Slug)
		targets[ten.ID] = fakes[ten].Target(inst)
	}
	reg := devicestest.Registry(targets)
	now := time.Now().UTC()
	put := func(f *devicestest.Fake, n int, online int) {
		for id := 1; id <= n; id++ {
			exp := now.Add(24 * time.Hour)
			f.PutNode(devicestest.Node{ID: uint64(id), MachineKey: fmt.Sprintf("mkey:%064x", id), NodeKey: fmt.Sprintf("nodekey:%064x", id), //nolint:gosec // small test ids
				Hostname: fmt.Sprintf("host-%d", id), GivenName: fmt.Sprintf("host-%d", id), UserID: 9, UserName: "someone",
				IPs: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", id))}, Method: "cli", Online: id <= online,
				CreatedAt: now.Add(-time.Hour), Expiry: &exp})
		}
	}
	put(fakes[w.A], 2, 1)
	put(fakes[w.B], 4, 3)

	// The worker side: sync both registers, probe both instances (B down at probe time).
	wrkStore := pg.OpenStore(t, w.DB, "mg_worker_tenant", "mg_worker_platform", 4)
	devWrk, monWrk := monitoringService(t, wrkStore, reg, true)
	for ten, inst := range instances {
		if _, err := devWrk.Sync(ctx, ten.ID, inst); err != nil {
			t.Fatal(err)
		}
	}
	fakes[w.B].SetDown(true)
	for ten, inst := range instances {
		if _, err := monWrk.Probe(ctx, ten.ID, inst); err != nil {
			t.Fatal(err)
		}
	}
	type figures struct {
		total, online int
		syncedAt      time.Time
		status        gen.HealthStatus
		reason        string
		checkedAt     time.Time
	}
	want := map[*sessionfixture.Tenant]*figures{w.A: {total: 2, online: 1, status: gen.HealthStatusHealthy},
		w.B: {total: 4, online: 3, status: gen.HealthStatusUnhealthy, reason: headscale.ProbeInstanceUnavailable}}
	for ten, f := range want {
		w.Scan(t, `SELECT synced_at FROM device_inventory_sync_state WHERE tenant_id = $1`, []any{ten.ID}, &f.syncedAt)
		w.Scan(t, `SELECT last_health_at FROM tenant_instances WHERE id = $1`, []any{instances[ten]}, &f.checkedAt)
	}

	// The api side: the composed API with the monitoring handlers and the audit middleware.
	_, monAPI := monitoringService(t, w.Store, reg, false)
	logger, err := audit.New(w.Store, pg.OpenAuditWriter(t, w.DB), audit.Config{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	hooks := authzhook.Hooks(w.Identity, authz.New(w.Store))
	hooks.Audit = auditapi.Middleware(logger)
	api, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"), Hooks: hooks, RateLimits: unlimited(),
		Handlers: httpapi.Handlers{Auth: identityapi.New(w.Identity), Monitoring: monitoringapi.New(monAPI)}})
	if err != nil {
		t.Fatal(err)
	}

	dashOf := func(ten *sessionfixture.Tenant) string { return "/tenants/" + ten.ID.String() + "/dashboard" }
	checkDashboard := func(who string, rec *httptest.ResponseRecorder, ten *sessionfixture.Tenant) {
		t.Helper()
		f := want[ten]
		var d gen.TenantDashboard
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &d) != nil {
			t.Errorf("%s: dashboard of %s: HTTP %d %s", who, ten.Name, rec.Code, rec.Body.String())
			return
		}
		reason := ""
		if d.Instance.Reason != nil {
			reason = *d.Instance.Reason
		}
		if d.Devices.Total != f.total || d.Devices.Online != f.online || d.Devices.SyncedAt == nil || !d.Devices.SyncedAt.Equal(f.syncedAt) ||
			d.Instance.Status != f.status || reason != f.reason || d.Instance.CheckedAt == nil || !d.Instance.CheckedAt.Equal(f.checkedAt) {
			t.Errorf("%s: dashboard of %s = devices %d/%d at %v, instance %s/%q at %v; want %d/%d at %v, %s/%q at %v", who, ten.Name,
				d.Devices.Total, d.Devices.Online, d.Devices.SyncedAt, d.Instance.Status, reason, d.Instance.CheckedAt,
				f.total, f.online, f.syncedAt, f.status, f.reason, f.checkedAt)
		}
		other := w.B
		if ten == w.B {
			other = w.A
		}
		if body := rec.Body.String(); strings.Contains(body, other.ID.String()) || strings.Contains(body, instances[other].String()) ||
			strings.Contains(body, other.Slug) {
			t.Errorf("%s: dashboard of %s names tenant %s: %s", who, ten.Name, other.Name, body)
		}
		got := map[string]string{}
		for _, u := range d.Unavailable {
			got[u.Section] = u.Reason
		}
		if len(got) != 4 || got["policies"] != "no_source" || got["relay"] != "not_served" || got["routes"] != "not_served" ||
			got["security_events"] != "not_served" {
			t.Errorf("%s: unavailable sections %v", who, got)
		}
	}
	inject := http.Header{"X-Tenant-Id": {w.B.ID.String()}, "X-Mg-Tenant": {w.B.ID.String()}}
	injectQuery := "?tenant_id=" + w.B.ID.String() + "&tenant=" + w.B.Slug + "&tenantId=" + w.B.ID.String()

	// Tenant roles of A (expectations written from §8.6, independently of the seed).
	allowed := map[string]bool{authz.RoleTenantOwner: true, authz.RoleTenantAdmin: true, authz.RoleTenantOperator: true,
		authz.RoleTenantViewer: true, authz.RoleEndUser: false}
	for _, role := range sessionfixture.TenantRoles {
		a := w.Actor(t, role, w.A)
		s := w.Login(t, a)
		for _, path := range []string{dashOf(w.A), dashOf(w.A) + injectQuery} {
			rec := get(t, api, s, path, inject)
			if allowed[role] {
				checkDashboard(a.String()+" "+path, rec, w.A)
			} else if rec.Code != http.StatusForbidden {
				t.Errorf("%s on %s: HTTP %d, want 403", a, path, rec.Code)
			}
		}
		if rec := get(t, api, s, dashOf(w.B), nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s on B's dashboard: HTTP %d, want 404 (not a member)", a, rec.Code)
		}
		if rec := get(t, api, s, "/platform/health", nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s on /platform/health: HTTP %d, want 403", a, rec.Code)
		}
	}
	// B's members see B's figures; B's members on A's dashboard: 404.
	sB := w.Login(t, w.Actor(t, authz.RoleTenantAdmin, w.B))
	checkDashboard("tenant_admin@B", get(t, api, sB, dashOf(w.B), nil), w.B)
	if rec := get(t, api, sB, dashOf(w.A)+injectQuery, inject); rec.Code != http.StatusNotFound {
		t.Errorf("admin of B on A's dashboard: HTTP %d, want 404", rec.Code)
	}

	// Platform roles: platform health ✔ (§8.5); a tenant dashboard without a Support Access Grant: 403 (AC-05a).
	for _, role := range sessionfixture.PlatformRoles {
		a := w.Actor(t, role, nil)
		s := w.Login(t, a)
		if rec := get(t, api, s, dashOf(w.A), nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s on A's dashboard: HTTP %d, want 403 (no support grant)", a, rec.Code)
		}
		rec := get(t, api, s, "/platform/health", nil)
		var ph gen.PlatformHealth
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ph) != nil {
			t.Errorf("%s on /platform/health: HTTP %d %s", a, rec.Code, rec.Body.String())
			continue
		}
		if ph.Tenants.Total != 2 || ph.Tenants.ByStatus["active"] != 2 || ph.Instances.Total != 2 || ph.Instances.Unhealthy != 1 ||
			ph.Instances.ByHealth["healthy"] != 1 || ph.Instances.ByVersion["v0.29.7"] != 1 || ph.CheckedAt.IsZero() || len(ph.Components) != 5 {
			t.Errorf("%s: platform health %s", a, rec.Body.String())
		}
		var raw map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &raw)
		if _, ok := raw["devices"]; ok || strings.Contains(rec.Body.String(), "synced_at") {
			t.Errorf("%s: the platform health carries device figures: %s", a, rec.Body.String())
		}
	}

	// Audit: reads leave no event; the refusals are recorded under the read actions.
	n := func(sql string, args ...any) int {
		var v int
		w.Scan(t, sql, args, &v)
		return v
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE action IN ('dashboard.read', 'platform.health.read') AND outcome <> 'denied'`); v != 0 {
		t.Errorf("%d audit events for successful reads (reads are not audited — P2-T08)", v)
	}
	eu := w.Actor(t, authz.RoleEndUser, w.A)
	if v := n(`SELECT count(*) FROM audit_events WHERE action = 'dashboard.read' AND outcome = 'denied' AND actor_identity_id = $1`,
		eu.IdentityID); v < 2 {
		t.Errorf("denials of the End User on the dashboard: %d, want ≥ 2", v)
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE action = 'platform.health.read' AND outcome = 'denied'`); v < len(sessionfixture.TenantRoles) {
		t.Errorf("denials of tenant roles on the platform health: %d, want ≥ %d", v, len(sessionfixture.TenantRoles))
	}
}
