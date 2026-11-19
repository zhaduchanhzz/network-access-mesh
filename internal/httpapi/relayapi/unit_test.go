package relayapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
)

// fakeService records what it was asked and answers what the test sets.
type fakeService struct {
	tenants []uuid.UUID
	filters []relay.RegionFilter
	tr      relay.TenantRelay
	page    relay.RegionPage
	err     error
}

func (f *fakeService) TenantRelay(_ context.Context, tenantID uuid.UUID) (relay.TenantRelay, error) {
	f.tenants = append(f.tenants, tenantID)
	return f.tr, f.err
}

func (f *fakeService) PlatformRegions(_ context.Context, rf relay.RegionFilter) (relay.RegionPage, error) {
	f.filters = append(f.filters, rf)
	return f.page, f.err
}

// fakeAuthorizer answers every operation with a fixed decision, completed the way authz completes it (the tenant of
// the path on tenant routes). The authorization itself is tested by P2-T07; the composed test with real sessions is the
// isolation suite (tests/isolation, IT-12b relay part) and the authorization matrix.
type fakeAuthorizer struct {
	d           authz.Decision
	wrongTenant bool
}

func (a fakeAuthorizer) RequireOperation(_ context.Context, _ string, tenantID uuid.UUID) (authz.Decision, error) {
	d := a.d
	if tenantID != uuid.Nil {
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
		Handlers: httpapi.Handlers{Relay: New(svc)}, Hooks: httpapi.Hooks{Authz: authorizer, Session: noSession, Audit: noAudit}})
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

func sample(checked *time.Time) relay.TenantRelay {
	return relay.TenantRelay{
		Assignments: []relay.Assignment{{ID: uuid.New(), Priority: 0, Status: "active",
			Region: relay.Region{ID: uuid.New(), Code: "mg-acme", Name: "MeshGuard acme", Kind: "embedded", DERPRegionID: 901,
				Hostname: "acme.mesh.example", IPv4: netip.MustParseAddr("203.0.113.10"), STUNPort: 3478, DERPPort: 443,
				VerifyMode: "in_process", Status: "active"},
			Health: relay.Health{Status: "unhealthy", Reason: "stun_probe_failed", CheckedAt: checked,
				DERP: &relay.CheckView{OK: true, Status: 200, DurationMS: 14}, STUN: &relay.CheckView{Code: "timeout", DurationMS: 3000}}}},
		Unavailable: relay.Unmeasured(),
	}
}

// TestTenantRelayMapping: the region, the health and its checks reach the schema TenantRelay unchanged, the time in
// UTC; the tenant is the one of the path — a tenant in the query or a header is ignored (IT-12b: tenant forced
// server-side, no free-form query); absent addresses, ports and checks are omitted, a never-probed region has
// checked_at null; the unmeasured figures are listed with their reasons.
func TestTenantRelayMapping(t *testing.T) {
	tenant, other := uuid.New(), uuid.New()
	checked := time.Date(2026, 11, 18, 9, 0, 0, 0, time.FixedZone("x", 7*3600))
	svc := &fakeService{tr: sample(&checked)}
	authorizer := authzhook.Authz(fakeAuthorizer{})
	rec := serve(t, svc, authorizer, "/tenants/"+tenant.String()+"/relay?tenant_id="+other.String()+"&tenantId="+other.String(),
		http.Header{"X-Tenant-Id": {other.String()}})
	var got gen.TenantRelay
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("relay: %d %s", rec.Code, rec.Body.String())
	}
	if len(svc.tenants) != 1 || svc.tenants[0] != tenant {
		t.Fatalf("service asked for %v, want only the tenant of the path %s", svc.tenants, tenant)
	}
	a := got.Assignments[0]
	if len(got.Assignments) != 1 || a.Status != gen.RelayAdminStatusActive || a.Region.Code != "mg-acme" ||
		a.Region.Kind != gen.RelayRegionKindEmbedded || a.Region.DerpRegionId != 901 || a.Region.Ipv4 == nil ||
		*a.Region.Ipv4 != "203.0.113.10" || a.Region.Ipv6 != nil || a.Region.StunPort == nil || *a.Region.StunPort != 3478 ||
		a.Region.DerpPort != 443 || a.Region.VerifyMode != gen.RelayRegionVerifyModeInProcess || a.Health.Status != gen.HealthStatusUnhealthy ||
		a.Health.Reason == nil || *a.Health.Reason != "stun_probe_failed" || a.Health.CheckedAt == nil || !a.Health.CheckedAt.Equal(checked) ||
		a.Health.Derp == nil || !a.Health.Derp.Ok || a.Health.Derp.Status == nil || *a.Health.Derp.Status != 200 || a.Health.Derp.Code != nil ||
		a.Health.Stun == nil || a.Health.Stun.Ok || a.Health.Stun.Code == nil || *a.Health.Stun.Code != "timeout" || a.Health.Stun.Status != nil ||
		a.Health.Stun.DurationMs != 3000 {
		t.Errorf("assignment %+v", a)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"checked_at":"2026-11-18T02:00:00Z"`) || strings.Contains(body, other.String()) {
		t.Errorf("body %s (time in UTC, nothing of the injected tenant)", body)
	}
	reasons := map[string]string{}
	for _, u := range got.Unavailable {
		reasons[u.Metric] = u.Reason
		if u.Detail == nil || *u.Detail == "" {
			t.Errorf("unavailable %s without detail", u.Metric)
		}
	}
	if len(reasons) != 5 || reasons["traffic_bytes"] != "unsupported" || reasons["connections"] != "no_source" ||
		reasons["client_latency"] != "no_source" {
		t.Errorf("unavailable %v", reasons)
	}
	// Never probed, no STUN address: nulls and omissions, not zeros pretending to be figures.
	tr := sample(nil)
	tr.Assignments[0].Region.IPv4, tr.Assignments[0].Region.STUNPort = netip.Addr{}, 0
	tr.Assignments[0].Health = relay.Health{Status: "unknown", Reason: "never_checked"}
	svc.tr = tr
	rec = serve(t, svc, authorizer, "/tenants/"+tenant.String()+"/relay", nil)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `"checked_at":null`) || !strings.Contains(body, `"reason":"never_checked"`) ||
		strings.Contains(body, `"derp"`) || strings.Contains(body, `"ipv4"`) || strings.Contains(body, `"stun_port"`) {
		t.Errorf("never probed: %d %s", rec.Code, body)
	}
	// No relay registered: an empty list, not an error.
	svc.tr = relay.TenantRelay{Assignments: []relay.Assignment{}, Unavailable: relay.Unmeasured()}
	if rec = serve(t, svc, authorizer, "/tenants/"+tenant.String()+"/relay", nil); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"assignments":[]`) {
		t.Errorf("no relay: %d %s", rec.Code, rec.Body.String())
	}
}

// TestPlatformRegionsMapping: the page, the owner (null for a shared region), the assignments with their instance
// status, the health and the cursor reach the schema RelayRegionList; limit and cursor reach the service; a limit out
// of range or an empty cursor is 422 before the service is called, a cursor the service refuses is 422.
func TestPlatformRegionsMapping(t *testing.T) {
	tenant, inst, host := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	tr := sample(&now)
	svc := &fakeService{page: relay.RegionPage{NextCursor: "next-1", Unavailable: relay.Unmeasured(), Items: []relay.PlatformRegion{
		{Region: tr.Assignments[0].Region, HostID: &host, TenantID: &tenant, Health: tr.Assignments[0].Health,
			Assignments: []relay.PlatformAssignment{{ID: uuid.New(), TenantID: tenant, InstanceID: inst, Status: "active", InstanceStatus: "running"}},
			CreatedAt:   now, UpdatedAt: now, Version: 3},
		{Region: relay.Region{ID: uuid.New(), Code: "shared-eu", Name: "Shared EU", Kind: "shared", DERPRegionID: 950, Hostname: "derp-eu.relay.test",
			DERPPort: 443, VerifyMode: "verify_url", Status: "pending"}, Assignments: []relay.PlatformAssignment{},
			Health: relay.Health{Status: "unknown", Reason: "no_probe"}, CreatedAt: now, UpdatedAt: now, Version: 1},
	}}}
	rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{}), "/platform/relay-regions?limit=2&cursor=abc", nil)
	var got gen.RelayRegionList
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("regions: %d %s", rec.Code, rec.Body.String())
	}
	if len(svc.filters) != 1 || svc.filters[0] != (relay.RegionFilter{Limit: 2, Cursor: "abc"}) {
		t.Errorf("filters %+v", svc.filters)
	}
	if len(got.Items) != 2 || got.NextCursor == nil || *got.NextCursor != "next-1" || len(got.Unavailable) != 5 {
		t.Fatalf("list %+v", got)
	}
	a, s := got.Items[0], got.Items[1]
	if a.TenantId == nil || *a.TenantId != tenant || a.HostId == nil || *a.HostId != host || len(a.Assignments) != 1 ||
		a.Assignments[0].InstanceId != inst || a.Assignments[0].InstanceStatus != gen.InstanceStatusRunning || a.Version != 3 ||
		a.Health.Reason == nil || *a.Health.Reason != "stun_probe_failed" || a.Region.Code != "mg-acme" {
		t.Errorf("tenant region %+v", a)
	}
	if s.TenantId != nil || s.HostId != nil || len(s.Assignments) != 0 || s.Region.Kind != gen.RelayRegionKindShared ||
		s.Health.Status != gen.HealthStatusUnknown || s.Health.CheckedAt != nil {
		t.Errorf("shared region %+v", s)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"tenant_id":null`) || !strings.Contains(body, `"assignments":[]`) {
		t.Errorf("body %s", body)
	}
	for _, q := range []string{"limit=0", "limit=201", "limit=-1", "cursor="} {
		svc.filters = nil
		rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{}), "/platform/relay-regions?"+q, nil)
		if rec.Code != http.StatusUnprocessableEntity || len(svc.filters) != 0 {
			t.Errorf("%s: %d %s (service called %d times)", q, rec.Code, rec.Body.String(), len(svc.filters))
		}
	}
	svc.err = relay.ErrInvalid
	if rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{}), "/platform/relay-regions?cursor=zzz", nil); rec.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(rec.Body.String(), `"field":"cursor"`) {
		t.Errorf("refused cursor: %d %s", rec.Code, rec.Body.String())
	}
}

// TestHandlersFailClosed: without the authorization decision, with a decision about another tenant, with an own-only
// grant, or with a tenant decision on the platform route, nothing is served and the service is never called; a service
// error is 500 without its text.
func TestHandlersFailClosed(t *testing.T) {
	tenant := uuid.New()
	path := "/tenants/" + tenant.String() + "/relay"
	noDecision := gen.StrictMiddlewareFunc(func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f })
	for _, c := range []struct {
		name       string
		authorizer gen.StrictMiddlewareFunc
		path       string
		status     int
	}{
		{"tenant relay without decision", noDecision, path, 500},
		{"platform list without decision", noDecision, "/platform/relay-regions", 500},
		{"decision about another tenant", authzhook.Authz(fakeAuthorizer{wrongTenant: true}), path, 500},
		{"own-only grant", authzhook.Authz(fakeAuthorizer{d: authz.Decision{OwnOnly: true}}), path, 403},
		{"platform route with a tenant decision", authzhook.Authz(fakeAuthorizer{d: authz.Decision{TenantID: uuid.New()}}), "/platform/relay-regions", 500},
	} {
		svc := &fakeService{}
		rec := serve(t, svc, c.authorizer, c.path, nil)
		if rec.Code != c.status || len(svc.tenants) != 0 || len(svc.filters) != 0 {
			t.Errorf("%s: %d (%d tenant, %d platform calls), want %d and no call", c.name, rec.Code, len(svc.tenants), len(svc.filters), c.status)
		}
	}
	svc := &fakeService{err: errors.New("database said: relation relay_regions is locked by pid 4242")}
	for _, p := range []string{path, "/platform/relay-regions"} {
		rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{}), p, nil)
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "4242") || strings.Contains(rec.Body.String(), "database said") {
			t.Errorf("%s with a service error: %d %s", p, rec.Code, rec.Body.String())
		}
	}
}

// noSession and noAudit are explicit pass-through hooks: httpapi.New requires Session and Audit once handlers are
// mounted (P2-T16); this test exercises the handlers behind the authorization hook only.
func noSession(next http.Handler) http.Handler { return next }

func noAudit(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }

// platformAuthorizer answers like authz on a platform route: granted, no tenant in the decision even when the path
// carries a {tenantId} (the tenant of /platform/tenants/{tenantId}/… filters the registry, it is not a tenant context).
type platformAuthorizer struct{}

func (platformAuthorizer) RequireOperation(context.Context, string, uuid.UUID) (authz.Decision, error) {
	return authz.Decision{}, nil
}

// TestPlatformTenantRegions (P4-T02): GET /platform/tenants/{tenantId}/relay-regions asks the service for the regions of
// the tenant of the path only; the page is mapped like the platform list; an unknown tenant is 404; a region of
// another tenant (or a shared one) returned by a lower layer is never sent (500); without a platform decision nothing
// reaches the service.
func TestPlatformTenantRegions(t *testing.T) {
	tenant, other, host := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	tr := sample(&now)
	own := relay.PlatformRegion{Region: tr.Assignments[0].Region, HostID: &host, TenantID: &tenant, Health: tr.Assignments[0].Health,
		Assignments: []relay.PlatformAssignment{}, CreatedAt: now, UpdatedAt: now, Version: 2}
	mount := func(svc *fakeService, a gen.StrictMiddlewareFunc, path string) *httptest.ResponseRecorder {
		t.Helper()
		h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
			Handlers: httpapi.Handlers{TenantView: httpapi.PlatformTenantView{Relay: New(svc)}},
			Hooks:    httpapi.Hooks{Authz: a, Session: noSession, Audit: noAudit}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://admin.mg.test/api/v1"+path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	base := "/platform/tenants/" + tenant.String() + "/relay-regions"
	svc := &fakeService{page: relay.RegionPage{Items: []relay.PlatformRegion{own}, Unavailable: relay.Unmeasured()}}
	rec := mount(svc, authzhook.Authz(platformAuthorizer{}), base+"?limit=5&cursor=abc")
	var got gen.RelayRegionList
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("regions: %d %s", rec.Code, rec.Body.String())
	}
	if len(svc.filters) != 1 || svc.filters[0] != (relay.RegionFilter{Limit: 5, Cursor: "abc", TenantID: tenant}) {
		t.Errorf("filters %+v", svc.filters)
	}
	if len(got.Items) != 1 || *got.Items[0].TenantId != tenant || got.Items[0].Region.Code != "mg-acme" || got.NextCursor != nil ||
		len(got.Unavailable) == 0 || got.Items[0].Health.CheckedAt == nil {
		t.Errorf("page %+v", got)
	}
	if rec := mount(&fakeService{err: relay.ErrNotFound}, authzhook.Authz(platformAuthorizer{}), base); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), `"not_found"`) {
		t.Errorf("unknown tenant: %d %s", rec.Code, rec.Body.String())
	}
	foreign := own
	foreign.TenantID = &other
	shared := own
	shared.TenantID = nil
	for name, item := range map[string]relay.PlatformRegion{"region of another tenant": foreign, "shared region": shared} {
		s := &fakeService{page: relay.RegionPage{Items: []relay.PlatformRegion{own, item}, Unavailable: relay.Unmeasured()}}
		if rec := mount(s, authzhook.Authz(platformAuthorizer{}), base); rec.Code != http.StatusInternalServerError ||
			strings.Contains(rec.Body.String(), "mg-acme") || strings.Contains(rec.Body.String(), other.String()) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	noDecision := gen.StrictMiddlewareFunc(func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f })
	for name, a := range map[string]gen.StrictMiddlewareFunc{
		"no decision": noDecision, "tenant decision": authzhook.Authz(fakeAuthorizer{}),
	} {
		s := &fakeService{}
		if rec := mount(s, a, base); rec.Code != http.StatusInternalServerError || len(s.filters) != 0 {
			t.Errorf("%s: %d, %d calls", name, rec.Code, len(s.filters))
		}
	}
	if rec := mount(&fakeService{}, authzhook.Authz(platformAuthorizer{}), base+"?limit=201"); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("limit 201: %d", rec.Code)
	}
	if rec := mount(&fakeService{err: errors.New("boom")}, authzhook.Authz(platformAuthorizer{}), base); rec.Code != http.StatusInternalServerError ||
		strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("service failure: %d %s", rec.Code, rec.Body.String())
	}
}
