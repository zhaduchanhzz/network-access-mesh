package relay

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
)

// TestTenantRelayReadsOwnRowsOnly (IT-12b, relay part, at the module): on the api's tenant pool, each tenant reads
// exactly its own assignment and region — with the health its probe recorded and checked_at = last_probe_at — never
// the other tenant's, whatever the other tenant's rows hold; the RLS of 0010 shows nothing of B under A even when the
// query names B. The figures of §10.6 without a source are listed, not invented.
func TestTenantRelayReadsOwnRowsOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.prober.set(f.b.host, ProbeResult{DERP: Check{OK: true, Status: 200}, STUN: Check{Code: "timeout", Duration: 3 * time.Second}})
	for _, ten := range []*tenantFx{f.a, f.b} {
		if _, err := f.wrk.Probe(ctx, ten.id, ten.region); err != nil {
			t.Fatal(err)
		}
	}
	want := map[*tenantFx]struct{ status, reason string }{f.a: {StatusHealthy, ""}, f.b: {StatusUnhealthy, ReasonSTUNProbeFailed}}
	for ten, w := range want {
		r, err := f.api.TenantRelay(ctx, ten.id)
		if err != nil {
			t.Fatal(err)
		}
		row := f.regionRow(t, ten.region)
		if len(r.Assignments) != 1 {
			t.Fatalf("%s: %d assignments, want its own 1", ten.slug, len(r.Assignments))
		}
		a := r.Assignments[0]
		if a.ID != ten.assignment || a.Status != AdminActive || a.Region.ID != ten.region || a.Region.Code != "mg-"+ten.slug ||
			a.Region.Hostname != ten.host || a.Region.Kind != KindEmbedded || a.Region.DERPRegionID != 901 ||
			a.Region.IPv4 != netip.MustParseAddr(entryIPv4) || a.Region.STUNPort != 3478 || a.Region.DERPPort != 443 ||
			a.Region.VerifyMode != "in_process" || a.Region.Status != AdminActive || a.Region.IPv6.IsValid() {
			t.Errorf("%s: assignment %+v", ten.slug, a)
		}
		if a.Health.Status != w.status || a.Health.Reason != w.reason || a.Health.CheckedAt == nil ||
			!a.Health.CheckedAt.Equal(*row.probeAt) || a.Health.DERP == nil || a.Health.STUN == nil {
			t.Errorf("%s: health %+v, want %s/%q checked at %v", ten.slug, a.Health, w.status, w.reason, row.probeAt)
		}
		if len(r.Unavailable) != len(unmeasured) {
			t.Errorf("%s: unavailable %v", ten.slug, r.Unavailable)
		}
	}
	// The tenant pool under A never sees B's rows, even when the query names B (RLS of 0010).
	r, err := f.api.TenantRelay(ctx, f.a.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Assignments {
		if a.ID == f.b.assignment || a.Region.ID == f.b.region || a.Region.Hostname == f.b.host {
			t.Errorf("A reads B's relay: %+v", a)
		}
	}
	if _, err := f.api.TenantRelay(ctx, uuid.Nil); err == nil {
		t.Error("a relay read without a tenant was accepted")
	}
	// A tenant without relay rows (an adopted tenant before backfill): no assignment, not an error.
	f.exec(t, `DELETE FROM relay_assignments WHERE tenant_id = $1`, f.b.id)
	if r, err := f.api.TenantRelay(ctx, f.b.id); err != nil || len(r.Assignments) != 0 || len(r.Unavailable) != len(unmeasured) {
		t.Errorf("tenant without relay rows: %+v %v", r, err)
	}
}

// TestTenantRelayHealthRules: the health shown follows the region's and the instance's state at read time — a stale
// probe, a stopped instance, a disabled region or assignment give unknown with the reason and keep checked_at; an
// instance removed drops its assignments from the tenant's view; a never-probed region says never_checked with a null
// checked_at; a record the module does not understand is invalid_record, never a figure.
func TestTenantRelayHealthRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	health := func(step string) Health {
		t.Helper()
		r, err := f.api.TenantRelay(ctx, f.a.id)
		if err != nil || len(r.Assignments) != 1 {
			t.Fatalf("%s: %+v %v", step, r, err)
		}
		return r.Assignments[0].Health
	}
	if h := health("never probed"); h.Status != StatusUnknown || h.Reason != ReasonNeverChecked || h.CheckedAt != nil || h.DERP != nil {
		t.Errorf("never probed: %+v", h)
	}
	if _, err := f.wrk.Probe(ctx, f.a.id, f.a.region); err != nil {
		t.Fatal(err)
	}
	at := *f.regionRow(t, f.a.region).probeAt
	for _, tc := range []struct {
		step, set, reset, reason string
	}{
		{"stale", `UPDATE relay_regions SET last_probe_at = now() - interval '1 hour' WHERE id = $1`,
			`UPDATE relay_regions SET last_probe_at = $2 WHERE id = $1`, ReasonStale},
		{"instance stopped", `UPDATE tenant_instances SET status = 'stopped' WHERE id = (SELECT instance_id FROM relay_assignments WHERE relay_region_id = $1)`,
			`UPDATE tenant_instances SET status = 'running' WHERE id = (SELECT instance_id FROM relay_assignments WHERE relay_region_id = $1)`, ReasonInstanceNotRunning},
		{"region disabled", `UPDATE relay_regions SET status = 'disabled' WHERE id = $1`,
			`UPDATE relay_regions SET status = 'active' WHERE id = $1`, ReasonNotActive},
		{"assignment disabled", `UPDATE relay_assignments SET status = 'disabled' WHERE relay_region_id = $1`,
			`UPDATE relay_assignments SET status = 'active' WHERE relay_region_id = $1`, ReasonNotActive},
		{"record not understood", `UPDATE relay_regions SET last_probe = '{"schema":7,"status":"healthy"}' WHERE id = $1`,
			`UPDATE relay_regions SET last_probe = NULL, last_probe_at = NULL WHERE id = $1`, ReasonInvalidRecord},
	} {
		f.exec(t, tc.set, f.a.region)
		h := health(tc.step)
		if h.Status != StatusUnknown || h.Reason != tc.reason || h.CheckedAt == nil {
			t.Errorf("%s: %+v, want unknown/%s with checked_at", tc.step, h, tc.reason)
		}
		if tc.reset == `UPDATE relay_regions SET last_probe_at = $2 WHERE id = $1` {
			f.exec(t, tc.reset, f.a.region, at)
		} else {
			f.exec(t, tc.reset, f.a.region)
		}
	}
	if h := health("record cleared"); h.Reason != ReasonNeverChecked {
		t.Errorf("after clearing the record: %+v", h)
	}
	f.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, f.a.instance)
	if r, err := f.api.TenantRelay(ctx, f.a.id); err != nil || len(r.Assignments) != 0 {
		t.Errorf("removed instance: %+v %v, want no assignment", r, err)
	}
}

// TestStepSeventeenRowsAreRead: the rows the Tenant Orchestrator writes at step 17 (orchestrator.DBStore.AssignRelay,
// the worker's platform pool — the only writer of relay rows) are what the read model returns, and the probe finds
// them; the compensation of step 17 removes them from both views.
func TestStepSeventeenRowsAreRead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := &tenantFx{id: uuid.New(), instance: uuid.New(), slug: "acme"}
	c.host = "acme.mesh.test"
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'acme', 'Acme', 'provisioning')`, c.id)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
			server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, 'acme.ts.test',
			'hs-acme:8080', 30050, '10.250.50.0/29', $5)`, c.instance, c.id, f.host, c.host, "/opt/meshguard/tenants/"+c.instance.String())
	db := orchestrator.NewDBStore(f.wrkSt, nil)
	if err := db.AssignRelay(ctx, orchestrator.RelayRequest{TenantID: c.id, InstanceID: c.instance, HostID: f.host, Code: "mg-acme",
		Name: "MeshGuard acme", Hostname: c.host, DERPRegionID: 901, IPv4: netip.MustParseAddr(entryIPv4), STUNPort: 3478}); err != nil {
		t.Fatal(err)
	}
	r, err := f.api.TenantRelay(ctx, c.id)
	if err != nil || len(r.Assignments) != 1 || r.Assignments[0].Region.Code != "mg-acme" || r.Assignments[0].Region.STUNPort != 3478 ||
		r.Assignments[0].Health.Reason != ReasonNeverChecked {
		t.Fatalf("relay of the provisioned tenant: %+v %v", r, err)
	}
	outs, errs, err := f.wrk.ProbeTenant(ctx, c.id)
	if err != nil || len(outs) != 1 || errs[0] != nil || !outs[0].Recorded || outs[0].Status != StatusHealthy {
		t.Fatalf("probe of the provisioned tenant: %+v %v %v", outs, errs, err)
	}
	if reqs := f.prober.requests(); reqs[len(reqs)-1] != (ProbeRequest{Address: edgeAddr, Host: c.host, STUN: entryIPv4 + ":3478"}) {
		t.Errorf("probe request %+v", reqs[len(reqs)-1])
	}
	if err := db.RemoveRelay(ctx, c.id, c.instance, "mg-acme"); err != nil {
		t.Fatal(err)
	}
	if r, err := f.api.TenantRelay(ctx, c.id); err != nil || len(r.Assignments) != 0 {
		t.Errorf("after compensation: %+v %v", r, err)
	}
	page, err := f.api.PlatformRegions(ctx, RegionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range page.Items {
		if it.Code == "mg-acme" {
			t.Errorf("compensated region still listed: %+v", it)
		}
	}
}

// TestPlatformRegions: the platform list (api's platform pool) holds every region — both tenants' and a shared one of
// the platform scope — ordered by (created_at, id), each with its assignments, owner and health (a shared region is
// not probed: no_probe); pages chain through next_cursor with no duplicate and no gap; limit and cursor out of range ⇒
// ErrInvalid.
func TestPlatformRegions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.wrk.Probe(ctx, f.a.id, f.a.region); err != nil {
		t.Fatal(err)
	}
	shared := uuid.New()
	f.exec(t, `INSERT INTO relay_regions (id, code, name, kind, derp_region_id, hostname, verify_mode, status)
		VALUES ($1, 'shared-eu', 'Shared EU', 'shared', 950, 'derp-eu.relay.test', 'verify_url', 'pending')`, shared)
	page, err := f.api.PlatformRegions(ctx, RegionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor != "" || len(page.Items) != 3 || len(page.Unavailable) != len(unmeasured) {
		t.Fatalf("page %+v", page)
	}
	byID := map[uuid.UUID]PlatformRegion{}
	for _, it := range page.Items {
		byID[it.ID] = it
	}
	a, b, s := byID[f.a.region], byID[f.b.region], byID[shared]
	if a.TenantID == nil || *a.TenantID != f.a.id || len(a.Assignments) != 1 || a.Assignments[0].InstanceID != f.a.instance ||
		a.Assignments[0].TenantID != f.a.id || a.Assignments[0].InstanceStatus != "running" || a.HostID == nil || *a.HostID != f.host ||
		a.Health.Status != StatusHealthy || a.Health.CheckedAt == nil || a.Version != 1 {
		t.Errorf("A's region %+v", a)
	}
	if b.TenantID == nil || *b.TenantID != f.b.id || b.Health.Reason != ReasonNeverChecked || b.Health.CheckedAt != nil {
		t.Errorf("B's region %+v", b)
	}
	if s.TenantID != nil || len(s.Assignments) != 0 || s.Kind != KindShared || s.Health.Status != StatusUnknown || s.Health.Reason != ReasonNoProbe {
		t.Errorf("shared region %+v", s)
	}
	var seen []uuid.UUID
	cursor := ""
	for range 10 {
		p, err := f.api.PlatformRegions(ctx, RegionFilter{Limit: 1, Cursor: cursor})
		if err != nil || len(p.Items) != 1 {
			t.Fatalf("page after %q: %+v %v", cursor, p, err)
		}
		seen = append(seen, p.Items[0].ID)
		if cursor = p.NextCursor; cursor == "" {
			break
		}
	}
	all := []uuid.UUID{page.Items[0].ID, page.Items[1].ID, page.Items[2].ID}
	if !slices.Equal(seen, all) {
		t.Errorf("paged %v, want %v", seen, all)
	}
	for _, bad := range []RegionFilter{{Limit: -1}, {Limit: MaxLimit + 1}, {Cursor: "not-a-cursor"}} {
		if _, err := f.api.PlatformRegions(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("filter %+v: %v, want ErrInvalid", bad, err)
		}
	}
	// P4-T02: the regions of one tenant (GET /platform/tenants/{t}/relay-regions) — not the shared one, not the other
	// tenant's; an unknown tenant is ErrNotFound
	ofA, err := f.api.PlatformRegions(ctx, RegionFilter{TenantID: f.a.id})
	if err != nil || len(ofA.Items) != 1 || ofA.Items[0].ID != f.a.region || ofA.NextCursor != "" || len(ofA.Unavailable) != len(unmeasured) ||
		ofA.Items[0].Health.Status != StatusHealthy || len(ofA.Items[0].Assignments) != 1 {
		t.Errorf("regions of A: %+v %v", ofA, err)
	}
	if _, err := f.api.PlatformRegions(ctx, RegionFilter{TenantID: uuid.New()}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown tenant: %v, want ErrNotFound", err)
	}
}
