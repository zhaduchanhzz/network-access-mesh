//go:build mgtestfixture

package isolation_test

// IT-07 (DNS) and IT-08 (routing) at the level of the API's network module (P4-T12; §5.2 boundaries 7 and 8 — the
// network-verified halves with real clients are P5-T05a). Tenants A and B each have a running instance, a router with an
// approved route and an extra DNS record, with the api's store (mg_api_tenant — RLS) and a Headscale registry that
// records which tenant each call is for:
//
//	IT-07  A lists only A's records; A cannot delete B's record (404); the records job of A hands the Host Agent only
//	       A's set for A's instance — B's names are never in A's file; a record of A cannot point at B's tailnet address
//	       (T-09 lint over A's register only) nor sit in B's MagicDNS domain.
//	IT-08  A's routes view holds only A's routers; approving or revoking B's device under A's path is 404 before any
//	       Headscale call — the registry is never asked for an instance on behalf of the other tenant.

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/network"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// countingRegistry answers no instance (nothing may reach Headscale here) and records the tenants it was asked for.
type countingRegistry struct {
	mu   sync.Mutex
	seen []uuid.UUID
}

func (r *countingRegistry) ForTenant(_ context.Context, t uuid.UUID) (headscale.Instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, t)
	return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable}
}

type capturingWriter struct {
	refs []network.InstanceRef
	recs [][]network.DNSRecord
}

func (w *capturingWriter) WriteRecords(_ context.Context, ref network.InstanceRef, _ uuid.UUID, recs []network.DNSRecord) (string, error) {
	w.refs, w.recs = append(w.refs, ref), append(w.recs, recs)
	return "0000000000000000000000000000000000000000000000000000000000000000", nil
}

func TestIT07IT08NetworkIsolation(t *testing.T) {
	ctx := context.Background()
	w := sessionfixture.New(t, sessionfixture.Options{})
	host := uuid.New()
	w.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-it07', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	inst := map[uuid.UUID]uuid.UUID{}
	dev := map[uuid.UUID]uuid.UUID{}
	rec := map[uuid.UUID]uuid.UUID{}
	for i, ten := range []*sessionfixture.Tenant{w.A, w.B} {
		inst[ten.ID], dev[ten.ID], rec[ten.ID] = uuid.New(), uuid.New(), uuid.New()
		w.Exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
			inst[ten.ID], ten.ID, host, ten.Slug+".mesh.mg.test", ten.Slug+".tail.mg.test", "hs-"+ten.Slug+":8080", 30001+i,
			[]string{"10.250.0.0/29", "10.250.0.8/29"}[i], "/opt/meshguard/tenants/"+inst[ten.ID].String())
		ip := []string{"100.64.0.1", "100.64.0.2"}[i]
		w.Exec(t, `INSERT INTO device_inventory_cache (id, tenant_id, instance_id, headscale_node_id, machine_key, name,
				given_name, ip_addresses, tags, available_routes, approved_routes)
			VALUES ($1, $2, $3, 1, $4, 'router', 'router', ARRAY[$5::inet], '{tag:server}', '{10.60.0.0/24}', '{10.60.0.0/24}')`,
			dev[ten.ID], ten.ID, inst[ten.ID], "mkey:"+ten.Slug, ip)
		w.Exec(t, `INSERT INTO dns_records (id, tenant_id, name, type, value) VALUES ($1, $2, $3, 'A', $4)`,
			rec[ten.ID], ten.ID, "db."+ten.Slug+".tail.mg.test", ip)
	}
	reg := &countingRegistry{}
	svc, err := network.New(w.Store, network.Config{Registry: reg, Devices: devices.RouteRegister{}, Tags: policies.RequireTags,
		BaseDomain: "mg.test"})
	if err != nil {
		t.Fatal(err)
	}
	a := network.Actor{IdentityID: uuid.New()}
	code := func(err error) string {
		if e, ok := network.AsError(err); ok {
			return e.Code
		}
		if err == nil {
			return "ok"
		}
		return err.Error()
	}

	// IT-08: routes
	routes, err := svc.ListRoutes(ctx, w.A.ID)
	if err != nil || len(routes) != 1 || routes[0].DeviceID != dev[w.A.ID] {
		t.Fatalf("A's routes: %+v %v", routes, err)
	}
	etag := network.RoutesETag([]netip.Prefix{netip.MustParsePrefix("10.60.0.0/24")})
	in := network.RouteChangeInput{DeviceID: dev[w.B.ID], Prefixes: []string{"10.60.0.0/24"}}
	if _, err := svc.ApproveRoutes(ctx, w.A.ID, a, etag, in, nil); code(err) != network.CodeNotFound {
		t.Errorf("approve B's device under A: %s", code(err))
	}
	if _, err := svc.RevokeRoutes(ctx, w.A.ID, a, etag, in); code(err) != network.CodeNotFound {
		t.Errorf("revoke B's device under A: %s", code(err))
	}
	if slices.Contains(reg.seen, w.B.ID) || len(reg.seen) != 0 {
		t.Errorf("Headscale registry asked for %v", reg.seen)
	}

	// IT-07: DNS
	recs, err := svc.ListDNSRecords(ctx, w.A.ID)
	if err != nil || len(recs) != 1 || recs[0].ID != rec[w.A.ID] {
		t.Fatalf("A's records: %+v %v", recs, err)
	}
	if _, err := svc.DeleteDNSRecord(ctx, w.A.ID, rec[w.B.ID], a, `"x"`); code(err) != network.CodeNotFound {
		t.Errorf("delete B's record under A: %s", code(err))
	}
	for _, bad := range []network.DNSRecordInput{
		{Name: "x.corp.example", Type: "A", Value: "100.64.0.2"},                  // B's tailnet address
		{Name: "x." + w.B.Slug + ".tail.mg.test", Type: "A", Value: "100.64.0.1"}, // B's MagicDNS domain
	} {
		if _, err := svc.CreateDNSRecord(ctx, w.A.ID, a, bad, nil); code(err) != network.CodeValidationFailed {
			t.Errorf("record %+v under A: %s", bad, code(err))
		}
	}
	wr := &capturingWriter{}
	if err := svc.RecordsHandler(wr).Run(ctx, &jobs.Run{ID: uuid.New(), TenantID: &w.A.ID, Store: w.Store}); err != nil {
		t.Fatal(err)
	}
	if len(wr.refs) != 1 || wr.refs[0].InstanceID != inst[w.A.ID] || wr.refs[0].TenantID != w.A.ID || len(wr.recs[0]) != 1 ||
		wr.recs[0][0].Name != "db."+w.A.Slug+".tail.mg.test" {
		t.Fatalf("A's records job wrote %+v %+v", wr.refs, wr.recs)
	}
}
