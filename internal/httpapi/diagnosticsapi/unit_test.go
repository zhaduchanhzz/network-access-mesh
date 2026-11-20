package diagnosticsapi

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
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/network"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
)

// fakeService records the questions and answers what the test sets.
type fakeService struct {
	tenants []uuid.UUID
	scopes  []monitoring.DeviceScope
	reqs    []monitoring.ConnectivityRequest
	inst    monitoring.InstanceDiagnostics
	rep     monitoring.ConnectivityReport
	err     error
}

func (f *fakeService) InstanceDiagnostics(_ context.Context, tenantID uuid.UUID) (monitoring.InstanceDiagnostics, error) {
	f.tenants = append(f.tenants, tenantID)
	return f.inst, f.err
}

func (f *fakeService) Connectivity(_ context.Context, tenantID uuid.UUID, scope monitoring.DeviceScope, req monitoring.ConnectivityRequest) (monitoring.ConnectivityReport, error) {
	f.tenants, f.scopes, f.reqs = append(f.tenants, tenantID), append(f.scopes, scope), append(f.reqs, req)
	return f.rep, f.err
}

// fakeAuthorizer answers every operation with a fixed decision about the tenant of the path.
type fakeAuthorizer struct {
	d           authz.Decision
	wrongTenant bool
}

func (a fakeAuthorizer) RequireOperation(_ context.Context, _ string, tenantID uuid.UUID) (authz.Decision, error) {
	d := a.d
	d.TenantID = tenantID
	if a.wrongTenant {
		d.TenantID = uuid.New()
	}
	return d, nil
}

func noSession(next http.Handler) http.Handler { return next }

func noAudit(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }

func serve(t *testing.T, svc Service, authorizer gen.StrictMiddlewareFunc, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Diagnostics: New(svc)}, Hooks: httpapi.Hooks{Authz: authorizer, Session: noSession, Audit: noAudit}})
	if err != nil {
		t.Fatal(err)
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(t.Context(), method, "https://app.mg.test/api/v1"+path, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) (gen.Problem, string) {
	t.Helper()
	var p gen.Problem
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return p, string(p.Code)
}

// TestInstanceMapping: the control-plane state reaches the schema with times in UTC, the tenant is the one of the
// path (query and headers ignored), absent parts are omitted, nothing secret exists in the type to be sent.
func TestInstanceMapping(t *testing.T) {
	tenant := uuid.New()
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.FixedZone("x", 7*3600))
	exp := at.Add(5 * 24 * time.Hour)
	svc := &fakeService{inst: monitoring.InstanceDiagnostics{CheckedAt: at, TenantStatus: "active",
		Instance: monitoring.InstanceDiag{Status: "running", Health: monitoring.InstanceHealth{Status: "healthy", CheckedAt: &at},
			APIKey: monitoring.APIKeyState{Status: "expiring", ExpiresAt: &exp}},
		Edge:        monitoring.EdgeState{Status: "reachable", CheckedAt: &at},
		Relays:      []monitoring.DiagRelay{{Code: "mg-acme", Name: "acme", Hostname: "acme.mesh.test", Status: "active", Health: "unhealthy", Reason: "stun_probe_failed", CheckedAt: &at, DERP: &monitoring.DiagCheck{OK: true}, STUN: &monitoring.DiagCheck{Code: "timeout"}}},
		Policy:      monitoring.DiagPolicy{Applied: true, Version: 4, SHA256: strings.Repeat("a", 64), AppliedAt: &at, Trigger: "manual", DesiredVersion: 4},
		Devices:     monitoring.DeviceDiag{Total: 5, Online: 3, Offline: 2, Expired: 1, SyncedAt: &at},
		Unavailable: []monitoring.Unavailable{{Section: "p2p_path", Reason: "not_observable", Detail: "x"}}}}
	rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{}), http.MethodGet, "/tenants/"+tenant.String()+"/diagnostics/instance?tenant_id="+uuid.NewString(), "")
	var got gen.TenantDiagnostics
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(svc.tenants) != 1 || svc.tenants[0] != tenant {
		t.Fatalf("asked for %v", svc.tenants)
	}
	if got.CheckedAt.Location() != time.UTC || got.Instance.Status == nil || *got.Instance.Status != gen.InstanceStatusRunning ||
		got.Instance.ApiKey.Status != gen.DiagnosticsAPIKeyStatusExpiring || got.Instance.ApiKey.ExpiresAt == nil ||
		got.Edge.Status != gen.DiagnosticsEdgeStatusReachable || got.Edge.Reason != nil || len(got.Relays) != 1 ||
		got.Relays[0].DerpOk == nil || !*got.Relays[0].DerpOk || got.Relays[0].StunOk == nil || *got.Relays[0].StunOk ||
		got.Policy.Version == nil || *got.Policy.Version != 4 || got.Policy.Access != nil || got.Devices.Expired != 1 ||
		got.Devices.Offline != 2 || len(got.Unavailable) != 1 || got.Unavailable[0].Detail == nil {
		t.Errorf("mapping %s", rec.Body)
	}
	// no instance: status omitted, never an empty string
	svc.inst.Instance = monitoring.InstanceDiag{Health: monitoring.InstanceHealth{Status: "unknown", Reason: "no_instance"},
		APIKey: monitoring.APIKeyState{Status: "unknown"}}
	rec = serve(t, svc, authzhook.Authz(fakeAuthorizer{}), http.MethodGet, "/tenants/"+tenant.String()+"/diagnostics/instance", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"status":""`) || !strings.Contains(rec.Body.String(), `"expires_at":null`) {
		t.Errorf("no instance: %s", rec.Body)
	}
}

// TestHandlersFailClosed: no decision, a decision about another tenant ⇒ 500 (never data); the instance state to an
// own-only grant ⇒ 403; an unknown tenant ⇒ 404; the service's errors map to 404/422/500.
func TestHandlersFailClosed(t *testing.T) {
	tenant := uuid.New()
	path := "/tenants/" + tenant.String() + "/diagnostics/"
	body := `{"source_device_id":"` + uuid.NewString() + `","target_device_id":"` + uuid.NewString() + `"}`
	none := func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }
	for name, c := range map[string]struct {
		authorizer gen.StrictMiddlewareFunc
		method     string
		path, body string
		svcErr     error
		status     int
		code       string
	}{
		"no decision (get)":  {none, http.MethodGet, path + "instance", "", nil, 500, "internal_error"},
		"no decision (post)": {none, http.MethodPost, path + "connectivity", body, nil, 500, "internal_error"},
		"wrong tenant":       {authzhook.Authz(fakeAuthorizer{wrongTenant: true}), http.MethodGet, path + "instance", "", nil, 500, "internal_error"},
		"own-only instance":  {authzhook.Authz(fakeAuthorizer{d: authz.Decision{OwnOnly: true}}), http.MethodGet, path + "instance", "", nil, 403, "forbidden"},
		"unknown tenant":     {authzhook.Authz(fakeAuthorizer{}), http.MethodGet, path + "instance", "", monitoring.ErrDiagNotFound, 404, "not_found"},
		"device not found":   {authzhook.Authz(fakeAuthorizer{}), http.MethodPost, path + "connectivity", body, monitoring.NotFound(monitoring.ReasonNotOwnResource), 404, "not_found"},
		"invalid request":    {authzhook.Authz(fakeAuthorizer{}), http.MethodPost, path + "connectivity", body, &monitoring.DiagnosticsError{Field: "target_device_id", Reason: "same_device"}, 422, "validation_failed"},
		"service failure":    {authzhook.Authz(fakeAuthorizer{}), http.MethodPost, path + "connectivity", body, errors.New("boom"), 500, "internal_error"},
		"port out of range":  {authzhook.Authz(fakeAuthorizer{}), http.MethodPost, path + "connectivity", `{"source_device_id":"` + uuid.NewString() + `","target_device_id":"` + uuid.NewString() + `","port":0}`, nil, 422, "validation_failed"},
	} {
		svc := &fakeService{err: c.svcErr}
		rec := serve(t, svc, c.authorizer, c.method, c.path, c.body)
		p, code := problemCode(t, rec)
		if rec.Code != c.status || code != c.code {
			t.Errorf("%s: %d %s (%s)", name, rec.Code, code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "boom") || (p.Detail != nil && strings.Contains(*p.Detail, "not_own_resource")) {
			t.Errorf("%s: internal detail leaked: %s", name, rec.Body)
		}
	}
}

// TestConnectivityMapping: the request reaches the service with the caller's own-only scope; the report reaches the
// schema — path_observable false, the target kind, checks and commands in order.
func TestConnectivityMapping(t *testing.T) {
	tenant, src, dst, member := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	dev := monitoring.DiagDevice{ID: dst, Name: "srv", GivenName: "srv", Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		Tags: []string{"tag:server"}, Online: true, SyncedAt: at}
	svc := &fakeService{rep: monitoring.ConnectivityReport{CheckedAt: at, Port: 443, Verdict: "allowed",
		Source: monitoring.DiagDevice{ID: src, Owner: member, Revocation: "none", SyncedAt: at}, Target: monitoring.Target{Device: &dev},
		Checks:   []monitoring.Check{{ID: "tenant_active", Status: "pass"}, {ID: "policy_grant", Status: "pass"}},
		Policy:   monitoring.DiagPolicy{Applied: true, Access: &monitoring.AccessVerdict{Decision: "allowed", Grants: []int{2}, Allowed: []string{"tcp:443"}}},
		Commands: []monitoring.Command{{ID: "status", OS: "linux", RunOn: "source", Command: "tailscale status"}}}}
	a := authzhook.Authz(fakeAuthorizer{d: authz.Decision{OwnOnly: true, MembershipID: member}})
	rec := serve(t, svc, a, http.MethodPost, "/tenants/"+tenant.String()+"/diagnostics/connectivity",
		`{"source_device_id":"`+src.String()+`","target_device_id":"`+dst.String()+`","port":443}`)
	var got gen.ConnectivityDiagnosis
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(svc.scopes) != 1 || !svc.scopes[0].OwnOnly || svc.scopes[0].MembershipID != member || svc.reqs[0].Source != src ||
		svc.reqs[0].TargetDevice == nil || *svc.reqs[0].TargetDevice != dst || svc.reqs[0].Port != 443 || svc.tenants[0] != tenant {
		t.Errorf("asked %+v %+v", svc.scopes, svc.reqs)
	}
	if got.PathObservable || !strings.Contains(rec.Body.String(), `"path_observable":false`) || got.Verdict != gen.ConnectivityDiagnosisVerdictAllowed ||
		got.Target.Kind != gen.DiagnosticsTargetKindDevice || got.Target.Device == nil || got.Target.Device.OwnerMembershipId != nil ||
		got.Source.OwnerMembershipId == nil || *got.Source.OwnerMembershipId != member || got.Source.RevocationState != "none" ||
		len(got.Checks) != 2 || got.Checks[1].Id != gen.DiagnosticsCheckIdPolicyGrant || got.Policy.Access == nil ||
		got.Policy.Access.Grants[0] != 2 || len(got.Commands) != 1 || got.Port == nil || *got.Port != 443 || got.Target.Routers == nil {
		t.Errorf("mapping %s", rec.Body)
	}
}

// ----------------------------------------------------------------------------------------------- Source

type fakeDevices struct{ items map[uuid.UUID]devices.Device }

func (f fakeDevices) Get(_ context.Context, _ uuid.UUID, id uuid.UUID, a devices.Access) (devices.Device, error) {
	d, ok := f.items[id]
	if !ok {
		return devices.Device{}, &devices.Error{Code: devices.CodeNotFound, Reason: "device_not_found"}
	}
	if a.OwnOnly && (d.Owner == nil || d.Owner.MembershipID != a.MembershipID || len(d.Tags) > 0) {
		return devices.Device{}, &devices.Error{Code: devices.CodeNotFound, Reason: devices.ReasonNotOwnResource}
	}
	return d, nil
}

type fakeNetwork struct {
	res    map[uuid.UUID]network.Resource
	routes []network.RouteDevice
}

func (f fakeNetwork) GetResource(_ context.Context, _ uuid.UUID, id uuid.UUID) (network.Resource, error) {
	r, ok := f.res[id]
	if !ok {
		return network.Resource{}, &network.Error{Code: network.CodeNotFound, Reason: "resource_not_found"}
	}
	return r, nil
}

func (f fakeNetwork) ListRoutes(context.Context, uuid.UUID) ([]network.RouteDevice, error) {
	return f.routes, nil
}

type fakeRelay struct{ tr relay.TenantRelay }

func (f fakeRelay) TenantRelay(context.Context, uuid.UUID) (relay.TenantRelay, error) {
	return f.tr, nil
}

type fakePolicy struct{ st policies.PolicyState }

func (f fakePolicy) State(context.Context, uuid.UUID) (policies.PolicyState, error) { return f.st, nil }

// TestSource: the adapter of the api process — devices' own-only refusal becomes not_own_resource, a missing resource
// not found; the relay's assignment and region status (a region not active ⇒ not active); the applied document is
// evaluated by internal/policies with the identities of the devices and the tags of the covering routers; without an
// applied policy the answer is unknown/no_applied_policy, never a denial.
func TestSource(t *testing.T) {
	alice := uuid.New()
	laptop := devices.Device{ID: uuid.New(), Name: "laptop", IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Owner: &devices.Owner{MembershipID: alice}, Tags: []string{}, Online: true, Revocation: devices.Revocation{State: "none"}}
	server := devices.Device{ID: uuid.New(), Name: "server", IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		Tags: []string{"tag:server"}, Online: true}
	router := devices.Device{ID: uuid.New(), Name: "router", IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.20")},
		Tags: []string{"tag:router"}, Online: true}
	db := network.Resource{ID: uuid.New(), Name: "db", Address: netip.MustParsePrefix("10.77.0.5/32"), Protocol: "tcp"}
	doc := `{"grants": [
		{"src": ["mg-` + alice.String() + `@"], "dst": ["tag:server"], "ip": ["tcp:443"]},
		{"src": ["autogroup:member"], "dst": ["db"], "ip": ["tcp:5432"], "via": ["tag:router"]}], "ssh": []}`
	finished := time.Now().UTC()
	pol := policies.PolicyState{Applied: &policies.AppliedPolicy{Application: policies.Application{PolicyVersionID: uuid.New(),
		Trigger: "manual", State: "applied", AppliedSHA256: strings.Repeat("b", 64), FinishedAt: &finished}, Version: 2, Document: doc},
		Latest: &policies.Application{State: "failed", ErrorCode: ptr("headscale_rejected"), CreatedAt: finished}, DesiredVersion: 3}
	s := NewSource(fakeDevices{items: map[uuid.UUID]devices.Device{laptop.ID: laptop, server.ID: server, router.ID: router}},
		fakeNetwork{res: map[uuid.UUID]network.Resource{db.ID: db}, routes: []network.RouteDevice{
			{DeviceID: router.ID, Name: "router", Tags: []string{"tag:router"}, Online: true, Approved: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}},
			{DeviceID: uuid.New(), Name: "advertises only", Advertised: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}}}},
		fakeRelay{tr: relay.TenantRelay{Assignments: []relay.Assignment{{Status: "active", Region: relay.Region{Code: "mg-a", Status: "disabled"},
			Health: relay.Health{Status: "unknown", Reason: "relay_not_active"}}}}},
		fakePolicy{st: pol})
	ctx := context.Background()
	tenant := uuid.New()

	if _, err := s.Device(ctx, tenant, server.ID, monitoring.DeviceScope{OwnOnly: true, MembershipID: alice}); monitoring.NotFoundReason(err) != monitoring.ReasonNotOwnResource {
		t.Errorf("own-only tagged device: %v", err)
	}
	if _, err := s.Device(ctx, tenant, uuid.New(), monitoring.DeviceScope{}); !errors.Is(err, monitoring.ErrDiagNotFound) {
		t.Errorf("missing device: %v", err)
	}
	if _, err := s.Resource(ctx, tenant, uuid.New()); !errors.Is(err, monitoring.ErrDiagNotFound) {
		t.Errorf("missing resource: %v", err)
	}
	d, err := s.Device(ctx, tenant, laptop.ID, monitoring.DeviceScope{OwnOnly: true, MembershipID: alice})
	if err != nil || d.Owner != alice || d.Revocation != "none" {
		t.Errorf("own device: %+v %v", d, err)
	}
	rs, err := s.Relays(ctx, tenant)
	if err != nil || len(rs) != 1 || rs[0].Status != "disabled" || rs[0].Code != "mg-a" {
		t.Errorf("relays %+v %v", rs, err)
	}
	routers, err := s.Routers(ctx, tenant)
	if err != nil || len(routers) != 1 || routers[0].DeviceID != router.ID || len(routers[0].Addresses) != 1 {
		t.Errorf("routers %+v %v", routers, err)
	}
	p, err := s.Policy(ctx, tenant, nil)
	if err != nil || !p.Applied || p.Version != 2 || p.DesiredVersion != 3 || p.LatestState != "failed" ||
		p.LatestErrorCode != "headscale_rejected" || p.Access != nil || p.AppliedAt == nil {
		t.Errorf("policy %+v %v", p, err)
	}
	peer := func(d devices.Device) monitoring.AccessPeer {
		out := monitoring.AccessPeer{Tags: d.Tags, Addresses: d.IPAddresses}
		if d.Owner != nil && len(d.Tags) == 0 {
			out.Owner = d.Owner.MembershipID
		}
		return out
	}
	srv := peer(server)
	for name, c := range map[string]struct {
		check    monitoring.AccessCheck
		decision string
	}{
		"alice → server 443":  {monitoring.AccessCheck{Src: peer(laptop), Dst: &srv, Port: 443}, policies.AccessAllowed},
		"alice → server 22":   {monitoring.AccessCheck{Src: peer(laptop), Dst: &srv, Port: 22}, policies.AccessDenied},
		"alice → db via tag":  {monitoring.AccessCheck{Src: peer(laptop), TargetResource: true, ResourceName: "db", ResourceAddr: db.Address, RouterTags: [][]string{{"tag:router"}}, Port: 5432}, policies.AccessAllowed},
		"router without tag":  {monitoring.AccessCheck{Src: peer(laptop), TargetResource: true, ResourceName: "db", ResourceAddr: db.Address, RouterTags: [][]string{{}}, Port: 5432}, policies.AccessDenied},
		"server → alice (no)": {monitoring.AccessCheck{Src: srv, Dst: &monitoring.AccessPeer{Owner: alice, Addresses: laptop.IPAddresses}, Port: 443}, policies.AccessDenied},
	} {
		chk := c.check
		p, err := s.Policy(ctx, tenant, &chk)
		if err != nil || p.Access == nil || p.Access.Decision != c.decision {
			t.Errorf("%s: %+v %v", name, p.Access, err)
		}
	}
	none := NewSource(fakeDevices{}, fakeNetwork{}, fakeRelay{}, fakePolicy{})
	if p, err := none.Policy(ctx, tenant, &monitoring.AccessCheck{Src: peer(laptop), Dst: &srv}); err != nil || p.Applied ||
		p.Access == nil || p.Access.Decision != policies.AccessUnknown || p.Access.Reason != policies.AccessReasonNoPolicy {
		t.Errorf("no applied policy: %+v %v", p.Access, err)
	}
}

func ptr[T any](v T) *T { return &v }
