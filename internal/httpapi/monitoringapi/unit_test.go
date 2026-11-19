package monitoringapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
)

// fakeService records the tenant it was asked for and answers what the test sets.
type fakeService struct {
	tenants  []uuid.UUID
	dash     monitoring.TenantDashboard
	health   monitoring.PlatformHealth
	err      error
	platform int
}

func (f *fakeService) TenantDashboard(_ context.Context, tenantID uuid.UUID) (monitoring.TenantDashboard, error) {
	f.tenants = append(f.tenants, tenantID)
	return f.dash, f.err
}

func (f *fakeService) PlatformHealth(context.Context) (monitoring.PlatformHealth, error) {
	f.platform++
	return f.health, f.err
}

// fakeAuthorizer answers every operation with a fixed decision, completed the way authz completes it (the tenant of
// the path on tenant routes). The authorization itself is tested by P2-T07; the composed test with real sessions is
// tests/security/monitoringauthz.
type fakeAuthorizer struct {
	d           authz.Decision
	wrongTenant bool
}

func (a fakeAuthorizer) RequireOperation(_ context.Context, _ string, tenantID uuid.UUID) (authz.Decision, error) {
	d := a.d
	if tenantID != uuid.Nil { // a tenant route: authz decides for the tenant of the path
		d.TenantID = tenantID
		if a.wrongTenant {
			d.TenantID = uuid.New()
		}
	}
	return d, nil
}

func serve(t *testing.T, svc *fakeService, authorizer gen.StrictMiddlewareFunc, path string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Monitoring: New(svc)}, Hooks: httpapi.Hooks{Authz: authorizer, Session: noSession, Audit: noAudit}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.mg.test/api/v1"+path, nil)
	for k, v := range hdr {
		r.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestDashboardMapping: the figures, times and reasons of the service reach the schema TenantDashboard unchanged (UTC);
// the tenant is the one of the path — a tenant in the query or a header is ignored (IT-12b: tenant forced server-side,
// no free-form query); the instance's version stays internal.
func TestDashboardMapping(t *testing.T) {
	tenant, other := uuid.New(), uuid.New()
	synced := time.Date(2026, 11, 17, 8, 0, 0, 0, time.FixedZone("x", 7*3600))
	checked := synced.Add(time.Minute)
	svc := &fakeService{dash: monitoring.TenantDashboard{
		Devices:  monitoring.DeviceCounts{Total: 5, Online: 2, SyncedAt: &synced},
		Instance: monitoring.InstanceHealth{Status: monitoring.StatusUnhealthy, Reason: "instance_unavailable", CheckedAt: &checked, Version: "v0.29.7"},
		Unavailable: []monitoring.Unavailable{{Section: "relay", Reason: "no_source", Detail: "Relay probes are not deployed yet."},
			{Section: "routes", Reason: "not_served"}},
	}}
	authorizer := authzhook.Authz(fakeAuthorizer{})
	rec := serve(t, svc, authorizer, "/tenants/"+tenant.String()+"/dashboard?tenant_id="+other.String()+"&tenant="+other.String(),
		http.Header{"X-Tenant-Id": {other.String()}})
	var got gen.TenantDashboard
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("dashboard: %d %s", rec.Code, rec.Body.String())
	}
	if len(svc.tenants) != 1 || svc.tenants[0] != tenant {
		t.Fatalf("service asked for %v, want only the tenant of the path %s", svc.tenants, tenant)
	}
	if got.Devices.Total != 5 || got.Devices.Online != 2 || got.Devices.SyncedAt == nil || !got.Devices.SyncedAt.Equal(synced) ||
		got.Instance.Status != gen.HealthStatusUnhealthy || got.Instance.Reason == nil || *got.Instance.Reason != "instance_unavailable" ||
		got.Instance.CheckedAt == nil || !got.Instance.CheckedAt.Equal(checked) || len(got.Unavailable) != 2 ||
		got.Unavailable[0].Section != "relay" || got.Unavailable[0].Detail == nil || got.Unavailable[1].Detail != nil {
		t.Errorf("dashboard %+v", got)
	}
	if body := rec.Body.String(); strings.Contains(body, "v0.29.7") || !strings.Contains(body, `"synced_at":"2026-11-17T01:00:00Z"`) {
		t.Errorf("body %s (version must stay internal, times in UTC)", body)
	}
	// Never synced, never probed: nulls, not zeros pretending to be figures.
	svc.dash = monitoring.TenantDashboard{Instance: monitoring.InstanceHealth{Status: monitoring.StatusUnknown, Reason: "never_checked"},
		Unavailable: []monitoring.Unavailable{{Section: "devices", Reason: "never_synced"}}}
	rec = serve(t, svc, authorizer, "/tenants/"+tenant.String()+"/dashboard", nil)
	if body := rec.Body.String(); rec.Code != 200 || !strings.Contains(body, `"synced_at":null`) || !strings.Contains(body, `"checked_at":null`) ||
		!strings.Contains(body, `"reason":"never_synced"`) {
		t.Errorf("empty dashboard: %d %s", rec.Code, body)
	}
}

// TestPlatformHealthMapping: every count, time, component and reason of the service reaches the schema.
func TestPlatformHealthMapping(t *testing.T) {
	now := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	hb := now.Add(-30 * time.Second)
	svc := &fakeService{health: monitoring.PlatformHealth{
		CheckedAt: now,
		Components: []monitoring.Component{{Name: "postgres", Status: "healthy", CheckedAt: &now}, {Name: "worker", Status: "healthy", CheckedAt: &hb},
			{Name: "agent", Status: "unknown", Reason: "not_deployed"}},
		Tenants: monitoring.TenantCounts{Total: 3, ByStatus: map[string]int{"active": 2, "suspended": 1, "pending": 0}},
		Instances: monitoring.InstanceCounts{Total: 2, ByStatus: map[string]int{"running": 2}, ByHealth: map[string]int{"healthy": 1, "unhealthy": 1, "unknown": 0},
			ByVersion: map[string]int{"v0.29.7": 1}, Unhealthy: 1},
		Jobs: monitoring.JobQueue{CheckedAt: now, Unfinished: map[string]int{"queued": 4}, FailedLast24h: 2},
	}}
	rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{}), "/platform/health", nil)
	var got gen.PlatformHealth
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || svc.platform != 1 {
		t.Fatalf("platform health: %d %s", rec.Code, rec.Body.String())
	}
	if !got.CheckedAt.Equal(now) || got.Tenants.Total != 3 || got.Tenants.ByStatus["suspended"] != 1 || got.Tenants.ByStatus["pending"] != 0 ||
		got.Instances.Unhealthy != 1 || got.Instances.ByHealth["healthy"] != 1 || got.Instances.ByVersion["v0.29.7"] != 1 ||
		got.Jobs.FailedLast24h != 2 || got.Jobs.Unfinished["queued"] != 4 || !got.Jobs.CheckedAt.Equal(now) || len(got.Components) != 3 ||
		got.Components[2].Reason == nil || *got.Components[2].Reason != "not_deployed" || got.Components[2].CheckedAt != nil ||
		got.Components[0].Reason != nil || got.Components[1].CheckedAt == nil || !got.Components[1].CheckedAt.Equal(hb) {
		t.Errorf("platform health %+v", got)
	}
}

// TestHandlersFailClosed: without the authorization decision, with a decision about another tenant, or with an
// own-only grant, the dashboard is never served and the service is never called; a service error is 500 without its
// text.
func TestHandlersFailClosed(t *testing.T) {
	tenant := uuid.New()
	path := "/tenants/" + tenant.String() + "/dashboard"
	noDecision := gen.StrictMiddlewareFunc(func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f })
	cases := []struct {
		name       string
		authorizer gen.StrictMiddlewareFunc
		path       string
		status     int
	}{
		{"dashboard without decision", noDecision, path, 500},
		{"platform without decision", noDecision, "/platform/health", 500},
		{"decision about another tenant", authzhook.Authz(fakeAuthorizer{wrongTenant: true}), path, 500},
		{"own-only grant", authzhook.Authz(fakeAuthorizer{d: authz.Decision{OwnOnly: true}}), path, 403},
		{"platform route with a tenant decision", authzhook.Authz(fakeAuthorizer{d: authz.Decision{TenantID: uuid.New()}}), "/platform/health", 500},
	}
	for _, c := range cases {
		svc := &fakeService{}
		rec := serve(t, svc, c.authorizer, c.path, nil)
		if rec.Code != c.status || len(svc.tenants) != 0 || svc.platform != 0 {
			t.Errorf("%s: %d (%d dashboard, %d platform calls), want %d and no call", c.name, rec.Code, len(svc.tenants), svc.platform, c.status)
		}
	}
	// Every leak marker holds a character outside [0-9a-f-]: a UUID (tenant id of the path, request_id) can never
	// contain one — a bare "4242" matched a random UUID about once in a thousand runs.
	leak := []string{"database said", "relation tenant_instances", "locked by pid", "pid 4242"}
	svc := &fakeService{err: errors.New("database said: relation tenant_instances is locked by pid 4242")}
	for _, p := range []string{path, "/platform/health"} {
		rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{}), p, nil)
		if rec.Code != 500 || slices.ContainsFunc(leak, func(m string) bool { return strings.Contains(rec.Body.String(), m) }) {
			t.Errorf("%s with a service error: %d %s", p, rec.Code, rec.Body.String())
		}
	}
}

// noSession and noAudit are explicit pass-through hooks: httpapi.New requires Session and Audit once handlers are
// mounted (P2-T16); this test exercises the handlers behind the authorization hook only.
func noSession(next http.Handler) http.Handler { return next }

func noAudit(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }
