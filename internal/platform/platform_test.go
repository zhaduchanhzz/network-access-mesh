package platform_test

// Integration tests of the platform registry (P2-T11): hosts registered idempotently, instances listed for platform
// staff without any secret reference — real PostgreSQL migrated like a deployment (storetest), api roles.

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

func TestHostsAndInstances(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	su := pg.Admin(t, db)
	svc := platform.New(pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 4))
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := su.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, sql)
		}
	}

	spec := platform.HostSpec{Name: "mg-staging", Region: "lab", RunUIDFirst: 30000, RunUIDLast: 39999,
		TenantNetPool: netip.MustParsePrefix("10.250.0.0/16")}
	if _, exists, err := svc.CheckHost(ctx, spec); err != nil || exists {
		t.Fatalf("CheckHost before: %v %v", exists, err)
	}
	h, existed, err := svc.EnsureHost(ctx, spec)
	if err != nil || existed || h.ID == uuid.Nil || h.RunUIDFirst != 30000 || h.RunUIDLast != 39999 ||
		h.TenantNetPool != spec.TenantNetPool || h.Region != "lab" {
		t.Fatalf("EnsureHost = %+v, %v, %v", h, existed, err)
	}
	h2, existed, err := svc.EnsureHost(ctx, spec)
	if err != nil || !existed || h2.ID != h.ID {
		t.Fatalf("second EnsureHost = %+v, %v, %v", h2, existed, err)
	}
	for name, s := range map[string]platform.HostSpec{
		"region": {Name: spec.Name, Region: "dc1", RunUIDFirst: 30000, RunUIDLast: 39999, TenantNetPool: spec.TenantNetPool},
		"range":  {Name: spec.Name, Region: "lab", RunUIDFirst: 30000, RunUIDLast: 30999, TenantNetPool: spec.TenantNetPool},
		"pool": {Name: spec.Name, Region: "lab", RunUIDFirst: 30000, RunUIDLast: 39999,
			TenantNetPool: netip.MustParsePrefix("10.251.0.0/16")},
	} {
		if _, _, err := svc.EnsureHost(ctx, s); !errors.Is(err, platform.ErrConflict) {
			t.Errorf("host with another %s: %v", name, err)
		}
	}
	for name, s := range map[string]platform.HostSpec{
		"name":   {Name: "Bad Host", Region: "lab", RunUIDFirst: 1, RunUIDLast: 2, TenantNetPool: spec.TenantNetPool},
		"region": {Name: "h2", Region: "", RunUIDFirst: 1, RunUIDLast: 2, TenantNetPool: spec.TenantNetPool},
		"range":  {Name: "h2", Region: "lab", RunUIDFirst: 5, RunUIDLast: 4, TenantNetPool: spec.TenantNetPool},
		"pool":   {Name: "h2", Region: "lab", RunUIDFirst: 1, RunUIDLast: 2, TenantNetPool: netip.MustParsePrefix("10.250.0.1/16")},
	} {
		if _, _, err := svc.EnsureHost(ctx, s); !errors.Is(err, platform.ErrInvalid) {
			t.Errorf("invalid %s: %v", name, err)
		}
	}
	if !h.Contains(30001, netip.MustParsePrefix("10.250.0.8/29")) || h.Contains(40000, netip.MustParsePrefix("10.250.0.8/29")) ||
		h.Contains(30001, netip.MustParsePrefix("10.251.0.8/29")) || h.Contains(30001, netip.MustParsePrefix("10.0.0.0/8")) {
		t.Error("Host.Contains")
	}

	// instances of two tenants; the API key reference never leaves the service
	var insts, tids []uuid.UUID
	for i, slug := range []string{"tenant-a", "tenant-b"} {
		tid, iid := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		insts, tids = append(insts, iid), append(tids, tid)
		exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2::text, $2::text, 'active')`, tid, slug)
		exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, derp_region_id, run_uid, net_cidr, data_path,
				api_key_secret_ref, api_key_prefix, last_health_at, last_health)
			VALUES ($1, $2, $3, $4, 'v0.29.7', 'sha256:'||repeat('a', 64), $5||'.mesh.mg.test', 'https://'||$5||'.mesh.mg.test',
				$5||'.tail.mg.test', 'hs-'||$5||':8080', 901, $6, $7::cidr, '/data', 'mgsec://'||$8||'/headscale-api-key#1',
				'pfx', CASE WHEN $4 = 'running' THEN now() END, CASE WHEN $4 = 'running' THEN '{"status":"healthy"}'::jsonb END)`,
			iid, tid, h.ID, []string{"running", "stopped"}[i], slug, 30001+i, "10.250.0."+[]string{"0", "8"}[i]+"/29",
			tid.String())
	}
	page, err := svc.ListInstances(ctx, platform.InstanceFilter{})
	if err != nil || len(page.Items) != 2 || page.Items[0].ID != insts[0] || page.NextCursor != "" {
		t.Fatalf("ListInstances = %+v, %v", page, err)
	}
	a := page.Items[0]
	if string(a.LastHealth) != `{"status": "healthy"}` || a.HealthCheckedAt == nil || a.HealthCheckedAt.After(a.ReadAt) ||
		a.ReadAt.IsZero() || *a.DerpRegionID != 901 || a.NetCIDR.String() != "10.250.0.0/29" ||
		page.Items[1].LastHealth != nil || page.Items[1].HealthCheckedAt != nil || !page.Items[1].ReadAt.Equal(a.ReadAt) {
		t.Errorf("instance view %+v / %+v", a, page.Items[1])
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), "mgsec://") || strings.Contains(string(raw), "pfx") {
		t.Errorf("the instance view carries the key reference or prefix: %s", raw)
	}
	if reflect.ValueOf(platform.Instance{}).FieldByName("APIKeyRef").IsValid() {
		t.Error("platform.Instance has an APIKeyRef field")
	}
	if p, err := svc.ListInstances(ctx, platform.InstanceFilter{Status: "stopped"}); err != nil || len(p.Items) != 1 ||
		p.Items[0].ID != insts[1] {
		t.Errorf("status filter: %+v %v", p, err)
	}
	if p, err := svc.ListInstances(ctx, platform.InstanceFilter{HostID: uuid.New()}); err != nil || len(p.Items) != 0 {
		t.Errorf("host filter: %+v %v", p, err)
	}
	// P4-T02: the instances of one tenant (GET /platform/tenants/{t}/instances); an unknown tenant is ErrNotFound
	if p, err := svc.ListInstances(ctx, platform.InstanceFilter{TenantID: tids[1]}); err != nil || len(p.Items) != 1 ||
		p.Items[0].ID != insts[1] || p.Items[0].TenantID != tids[1] {
		t.Errorf("tenant filter: %+v %v", p, err)
	}
	if p, err := svc.ListInstances(ctx, platform.InstanceFilter{TenantID: tids[0], Status: "stopped"}); err != nil || len(p.Items) != 0 {
		t.Errorf("tenant + status filter: %+v %v", p, err)
	}
	if _, err := svc.ListInstances(ctx, platform.InstanceFilter{TenantID: uuid.New()}); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown tenant: %v, want ErrNotFound", err)
	}
	p1, err := svc.ListInstances(ctx, platform.InstanceFilter{Limit: 1})
	if err != nil || len(p1.Items) != 1 || p1.NextCursor == "" {
		t.Fatalf("page 1: %+v %v", p1, err)
	}
	p2, err := svc.ListInstances(ctx, platform.InstanceFilter{Limit: 1, Cursor: p1.NextCursor})
	if err != nil || len(p2.Items) != 1 || p2.Items[0].ID != insts[1] || p2.NextCursor != "" {
		t.Fatalf("page 2: %+v %v", p2, err)
	}
	for name, f := range map[string]platform.InstanceFilter{"status": {Status: "asleep"}, "limit": {Limit: 500},
		"cursor": {Cursor: "!!"}} {
		if _, err := svc.ListInstances(ctx, f); !errors.Is(err, platform.ErrInvalid) {
			t.Errorf("invalid %s: %v", name, err)
		}
	}
	if got, err := svc.GetInstance(ctx, insts[1]); err != nil || got.Status != "stopped" {
		t.Fatalf("GetInstance = %+v, %v", got, err)
	}
	if _, err := svc.GetInstance(ctx, uuid.New()); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("unknown instance: %v", err)
	}
}
