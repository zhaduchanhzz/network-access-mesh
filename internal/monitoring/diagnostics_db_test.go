package monitoring

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
)

// testSource is the DiagnosticsSource of the DB tests: the REAL device register of the api process (devices.Service —
// own-only scope through devices.Access, as diagnosticsapi.Source does) and fixed answers for the other modules (their
// adapter is tested in internal/httpapi/diagnosticsapi). It records the policy questions it is asked.
type testSource struct {
	dev     *devices.Service
	relays  []DiagRelay
	policy  DiagPolicy
	routers []DiagRouter
	asked   []AccessCheck
}

func (s *testSource) Device(ctx context.Context, tenantID, deviceID uuid.UUID, scope DeviceScope) (DiagDevice, error) {
	d, err := s.dev.Get(ctx, tenantID, deviceID, devices.Access{OwnOnly: scope.OwnOnly, MembershipID: scope.MembershipID})
	if e, ok := devices.AsError(err); ok && e.Code == devices.CodeNotFound {
		if e.Reason == devices.ReasonNotOwnResource {
			return DiagDevice{}, NotFound(ReasonNotOwnResource)
		}
		return DiagDevice{}, NotFound(e.Reason)
	}
	if err != nil {
		return DiagDevice{}, err
	}
	out := DiagDevice{ID: d.ID, Name: d.Name, GivenName: d.GivenName, Addresses: d.IPAddresses, Tags: d.Tags,
		Online: d.Online, LastSeen: d.LastSeen, Expiry: d.Expiry, Revocation: d.Revocation.State, SyncedAt: d.SyncedAt}
	if d.Owner != nil {
		out.Owner = d.Owner.MembershipID
	}
	return out, nil
}

func (s *testSource) Resource(context.Context, uuid.UUID, uuid.UUID) (DiagResource, error) {
	return DiagResource{}, NotFound("resource_not_found")
}

func (s *testSource) Routers(context.Context, uuid.UUID) ([]DiagRouter, error) { return s.routers, nil }

func (s *testSource) Relays(context.Context, uuid.UUID) ([]DiagRelay, error) { return s.relays, nil }

func (s *testSource) Policy(_ context.Context, _ uuid.UUID, check *AccessCheck) (DiagPolicy, error) {
	p := s.policy
	if check != nil {
		s.asked = append(s.asked, *check)
		p.Access = &AccessVerdict{Decision: "allowed", Grants: []int{0}, Allowed: []string{"tcp:443"}}
	}
	return p, nil
}

// member inserts an End User of the tenant (its IdP, identity and membership) and returns the membership.
func (f *fixture) member(t *testing.T, ten *tenantFx, name string) uuid.UUID {
	t.Helper()
	idp, ident, m := uuid.New(), uuid.New(), uuid.Nil
	f.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active') ON CONFLICT DO NOTHING`, idp, ten.id,
		"https://idp.invalid/realms/"+ten.slug)
	f.scan(t, `SELECT id FROM identity_providers WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 1`, []any{ten.id}, &idp)
	f.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, ident, idp, ten.id, name+"-"+ten.slug, name+"@"+ten.slug+".test", name)
	f.scan(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
		SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'end_user' RETURNING id`, []any{ten.id, ident}, &m)
	return m
}

func (f *fixture) deviceID(t *testing.T, ten *tenantFx, node uint64) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	f.scan(t, `SELECT id FROM device_inventory_cache WHERE tenant_id = $1 AND headscale_node_id = $2 AND removed_at IS NULL`,
		[]any{ten.id, int64(node)}, &id) //nolint:gosec // small test ids
	return id
}

// TestInstanceDiagnostics (P5-T08, service level with PostgreSQL): the control-plane state of each tenant holds its
// own figures only — instance health with the checked_at of its own probe, API key expiry as a status and a time (no
// secret), device counts online/offline/expired with the synced_at of its own register —, the relays and policy of
// the source, and the parts without a source in `unavailable` (noise, p2p_path always; devices never synced, policy
// never applied, no relay when so). A suspended tenant is still readable; a tenant without an instance answers
// unknown/no_instance, not an error.
func TestInstanceDiagnostics(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	n1, n2, n3 := node(1, true), node(2, false), node(3, true)
	past := time.Now().Add(-time.Hour).UTC()
	n3.Expiry = &past
	f.a.hs.PutNode(n1)
	f.a.hs.PutNode(n2)
	f.a.hs.PutNode(n3)
	f.b.hs.PutNode(node(1, true))
	if _, err := f.devWrk.Sync(ctx, f.a.id, f.a.instance); err != nil {
		t.Fatal(err)
	}
	if _, err := f.wrk.Probe(ctx, f.a.id, f.a.instance); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE tenant_instances SET api_key_expires_at = now() + interval '5 days' WHERE id = $1`, f.a.instance)
	f.exec(t, `UPDATE tenant_instances SET api_key_expires_at = now() + interval '80 days' WHERE id = $1`, f.b.instance)
	checked := time.Now().Add(-time.Minute).UTC()
	src := &testSource{dev: f.devAPI,
		relays: []DiagRelay{{Code: "mg-" + f.a.slug, Status: "active", Health: StatusHealthy, CheckedAt: &checked, DERP: &DiagCheck{OK: true}}},
		policy: DiagPolicy{Applied: true, Version: 3, SHA256: "ab", AppliedAt: &checked}}
	svc, err := New(f.apiSt, Config{Devices: deviceCounter(f.devAPI), Diagnostics: src, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.InstanceDiagnostics(ctx, f.a.id)
	if err != nil {
		t.Fatal(err)
	}
	row := f.instanceRow(t, f.a.instance)
	if d.TenantStatus != "active" || d.Instance.Status != "running" || d.Instance.Health.Status != StatusHealthy ||
		d.Instance.Health.CheckedAt == nil || !d.Instance.Health.CheckedAt.Equal(*row.healthAt) {
		t.Errorf("instance %+v (probe at %v)", d.Instance, row.healthAt)
	}
	if d.Instance.APIKey.Status != APIKeyExpiring || d.Instance.APIKey.ExpiresAt == nil {
		t.Errorf("api key %+v", d.Instance.APIKey)
	}
	if d.Devices.Total != 3 || d.Devices.Online != 2 || d.Devices.Offline != 1 || d.Devices.Expired != 1 || d.Devices.SyncedAt == nil {
		t.Errorf("devices %+v", d.Devices)
	}
	if d.Edge.Status != DiagReachable || d.Edge.CheckedAt == nil || len(d.Relays) != 1 || !d.Policy.Applied || d.Policy.Version != 3 ||
		d.Policy.Access != nil || d.CheckedAt.IsZero() {
		t.Errorf("edge %+v relays %+v policy %+v", d.Edge, d.Relays, d.Policy)
	}
	if got := unavailableOf(d); len(got) != 2 || got[SectionNoise] != ReasonNoProbe || got[SectionP2PPath] != ReasonNotObservable {
		t.Errorf("unavailable %v", got)
	}

	// B: never synced, never probed, no relay, no policy — and suspended: still readable
	f.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, f.b.id)
	src.relays, src.policy = nil, DiagPolicy{}
	d, err = svc.InstanceDiagnostics(ctx, f.b.id)
	if err != nil {
		t.Fatal(err)
	}
	if d.TenantStatus != "suspended" || d.Instance.Health.Status != StatusUnknown || d.Instance.Health.Reason != ReasonNeverChecked ||
		d.Instance.APIKey.Status != APIKeyValid || d.Devices.Total != 0 || d.Devices.SyncedAt != nil || d.Edge.Status != StatusUnknown {
		t.Errorf("B: %+v", d)
	}
	if got := unavailableOf(d); got[SectionDevices] != ReasonNeverSynced || got[SectionPolicy] != ReasonNeverApplied ||
		got[SectionRelay] != ReasonNoRelay || len(got) != 5 {
		t.Errorf("B unavailable %v", got)
	}

	// a tenant whose only instance is removed: no instance, unknown — and a tenant that does not exist: not found
	c := f.newTenant(t, "active")
	f.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, c.instance)
	d, err = svc.InstanceDiagnostics(ctx, c.id)
	if err != nil || d.Instance.Status != "" || d.Instance.Health.Reason != ReasonNoInstance || d.Instance.APIKey.Status != APIKeyUnknown {
		t.Errorf("no instance: %+v %v", d.Instance, err)
	}
	if _, err := svc.InstanceDiagnostics(ctx, uuid.New()); !errors.Is(err, ErrDiagNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	// built without a source: an error, never an empty answer
	bare := f.api
	if _, err := bare.InstanceDiagnostics(ctx, f.a.id); err == nil {
		t.Error("diagnostics without a source")
	}
}

func unavailableOf(d InstanceDiagnostics) map[string]string {
	out := map[string]string{}
	for _, u := range d.Unavailable {
		out[u.Section] = u.Reason
	}
	return out
}

// TestConnectivityDiagnosis (P5-T08, service level with PostgreSQL): two devices of the tenant ⇒ a diagnosis with
// the checks of the register and the policy question asked with their identities; a device of another tenant ⇒ not
// found (the register is read on the tenant's pool only); the End User (own-only) gets its own untagged devices only —
// another member's device, a tagged one or a resource ⇒ not found with reason not_own_resource; invalid requests ⇒
// a DiagnosticsError on the field.
func TestConnectivityDiagnosis(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := uint64(1); i <= 4; i++ {
		f.a.hs.PutNode(node(i, i != 3))
	}
	f.b.hs.PutNode(node(1, true))
	for _, ten := range []*tenantFx{f.a, f.b} {
		if _, err := f.devWrk.Sync(ctx, ten.id, ten.instance); err != nil {
			t.Fatal(err)
		}
	}
	alice, bob := f.member(t, f.a, "alice"), f.member(t, f.a, "bob")
	d1, d2, d3, d4 := f.deviceID(t, f.a, 1), f.deviceID(t, f.a, 2), f.deviceID(t, f.a, 3), f.deviceID(t, f.a, 4)
	f.exec(t, `UPDATE device_inventory_cache SET owner_membership_id = $2 WHERE id = ANY ($1)`, []uuid.UUID{d1, d2}, alice)
	f.exec(t, `UPDATE device_inventory_cache SET owner_membership_id = $2 WHERE id = $1`, d3, bob)
	f.exec(t, `UPDATE device_inventory_cache SET tags = '{tag:server}', owner_membership_id = NULL WHERE id = $1`, d4)
	b1 := f.deviceID(t, f.b, 1)
	src := &testSource{dev: f.devAPI, relays: []DiagRelay{{Code: "mg-a", Status: "active", Health: StatusHealthy}},
		policy: DiagPolicy{Applied: true, Version: 1}}
	svc, err := New(f.apiSt, Config{Devices: deviceCounter(f.devAPI), Diagnostics: src, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.wrk.Probe(ctx, f.a.id, f.a.instance); err != nil {
		t.Fatal(err)
	}
	all := DeviceScope{}
	r, err := svc.Connectivity(ctx, f.a.id, all, ConnectivityRequest{Source: d1, TargetDevice: &d4, Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if r.Source.ID != d1 || r.Target.Device == nil || r.Target.Device.ID != d4 || r.Verdict != VerdictAllowed || r.Port != 443 ||
		r.RelayCode != "mg-a" || len(r.Commands) == 0 || r.CheckedAt.IsZero() {
		t.Errorf("diagnosis %+v", r)
	}
	q := src.asked[len(src.asked)-1]
	if q.Src.Owner != alice || q.Dst == nil || !slices.Equal(q.Dst.Tags, []string{"tag:server"}) || q.Dst.Owner != uuid.Nil ||
		q.Port != 443 || len(q.Src.Addresses) != 1 {
		t.Errorf("policy asked %+v", q)
	}
	// target offline (bob's device) ⇒ blocked by the register, whatever the policy says
	if r, err := svc.Connectivity(ctx, f.a.id, all, ConnectivityRequest{Source: d1, TargetDevice: &d3}); err != nil ||
		r.Verdict != VerdictBlocked || checkMap(r.Checks)[CheckTargetOnline].Status != CheckFail {
		t.Errorf("offline target: %+v %v", r.Checks, err)
	}
	// cross-tenant: B's device on A's path, A's device on B's path
	if _, err := svc.Connectivity(ctx, f.a.id, all, ConnectivityRequest{Source: d1, TargetDevice: &b1}); !errors.Is(err, ErrDiagNotFound) {
		t.Errorf("B's device on A: %v", err)
	}
	if _, err := svc.Connectivity(ctx, f.b.id, all, ConnectivityRequest{Source: b1, TargetDevice: &d1}); !errors.Is(err, ErrDiagNotFound) {
		t.Errorf("A's device on B: %v", err)
	}
	// own-only: alice's two devices ⇒ answered; bob's, a tagged one, a resource ⇒ not found (not_own_resource)
	own := DeviceScope{OwnOnly: true, MembershipID: alice}
	if r, err := svc.Connectivity(ctx, f.a.id, own, ConnectivityRequest{Source: d1, TargetDevice: &d2, Port: 22}); err != nil ||
		r.Target.Device.ID != d2 {
		t.Errorf("own devices: %v", err)
	}
	res := uuid.New()
	for name, req := range map[string]ConnectivityRequest{
		"another member's target": {Source: d1, TargetDevice: &d3},
		"tagged target":           {Source: d1, TargetDevice: &d4},
		"another member's source": {Source: d3, TargetDevice: &d1},
		"resource":                {Source: d1, TargetResource: &res},
	} {
		if _, err := svc.Connectivity(ctx, f.a.id, own, req); !errors.Is(err, ErrDiagNotFound) || NotFoundReason(err) != ReasonNotOwnResource {
			t.Errorf("own-only, %s: %v", name, err)
		}
	}
	// invalid requests
	for name, c := range map[string]struct {
		req   ConnectivityRequest
		field string
	}{
		"no source":    {ConnectivityRequest{TargetDevice: &d2}, "source_device_id"},
		"no target":    {ConnectivityRequest{Source: d1}, "target_device_id"},
		"two targets":  {ConnectivityRequest{Source: d1, TargetDevice: &d2, TargetResource: &res}, "target_device_id"},
		"same device":  {ConnectivityRequest{Source: d1, TargetDevice: &d1}, "target_device_id"},
		"port too big": {ConnectivityRequest{Source: d1, TargetDevice: &d2, Port: 70000}, "port"},
	} {
		var de *DiagnosticsError
		if _, err := svc.Connectivity(ctx, f.a.id, all, c.req); !errors.As(err, &de) || de.Field != c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
}
