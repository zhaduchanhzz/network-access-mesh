package orphans

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
)

// inventoryAgent answers ListInstances with a fixed host inventory.
type inventoryAgent struct {
	resp *agentv1.ListInstancesResponse
}

func (a inventoryAgent) ListInstances(context.Context, *agentv1.ListInstancesRequest, ...grpc.CallOption) (*agentv1.ListInstancesResponse, error) {
	return a.resp, nil
}

func (a inventoryAgent) GetInstanceStatus(context.Context, *agentv1.GetInstanceStatusRequest, ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	return &agentv1.GetInstanceStatusResponse{}, nil
}

// TestHostReconcileKnowsTenantsOutsideTheScope is the staging case of P3-T14b: the tenants directory holds the
// instances of tenant-a/b (adopted, registered, outside the g3-* scope of a G3 run) beside the run's own. The host check
// must know them (as the worker's host.reconcile does) — before the fix it compared the inventory with the scope's
// instances only and reported both as unknown_instance. A directory of an instance the registry does not have is still
// unknown; a registered instance outside the scope that is absent from the host is not the run's to report.
func TestHostReconcileKnowsTenantsOutsideTheScope(t *testing.T) {
	ta, tb, tg, tgone := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ia, ib, ig, igone, stray := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	inv := Inventory{
		Scope: Scope{SlugPrefix: "g3-", TenantsDir: "/opt/meshguard/tenants"},
		Registry: Registry{
			Tenants: []Tenant{{ID: ta, Slug: "tenant-a", Status: "active"}, {ID: tb, Slug: "tenant-b", Status: "active"},
				{ID: tg, Slug: "g3-ab12-01", Status: "active"}, {ID: tgone, Slug: "zz-elsewhere", Status: "active"}},
			Instances: []Instance{{ID: ia, TenantID: ta, Slug: "tenant-a", Status: StatusRunning},
				{ID: ib, TenantID: tb, Slug: "tenant-b", Status: StatusRunning},
				{ID: ig, TenantID: tg, Slug: "g3-ab12-01", Status: StatusRunning},
				{ID: igone, TenantID: tgone, Slug: "zz-elsewhere", Status: StatusRunning}},
		},
	}
	all := func(id uuid.UUID, slug string) *agentv1.InventoryEntry {
		return &agentv1.InventoryEntry{InstanceId: id.String(), Slug: slug, HasDirectory: true, HasContainer: true, HasNetwork: true}
	}
	host := &agentv1.ListInstancesResponse{Instances: []*agentv1.InventoryEntry{all(ia, "tenant-a"), all(ib, "tenant-b"),
		all(ig, "g3-ab12-01"), {InstanceId: stray.String(), HasDirectory: true}}}
	inScope := scopeInstances(inv)
	if len(inScope) != 1 {
		t.Fatalf("scope: %v", inScope)
	}
	src := Sources{Timeout: time.Second, Now: time.Now}
	agent := scopedAgent{next: inventoryAgent{host}, scope: inv.Scope, ids: inScope}
	got := hostReconcile(t.Context(), agent, src, inv, inScope)
	want := []HostFinding{{Kind: reconcile.DriftUnknownInstance, Subject: stray.String()}}
	if !slices.Equal(got, want) {
		t.Fatalf("findings %v, want %v (tenant-a/b known, zz-elsewhere absent but out of scope)", got, want)
	}

	// the registry of the scope alone — the detector before P3-T14b — reports tenant-a and tenant-b as unknown
	rep, _ := (&reconcile.Inspector{Agent: agent, AgentTimeout: time.Second, Now: time.Now}).Host(t.Context(), registered(inScope))
	var unknown []string
	for _, f := range rep.Findings {
		if f.Kind == reconcile.DriftUnknownInstance {
			unknown = append(unknown, f.Subject)
		}
	}
	slices.Sort(unknown)
	before := []string{ia.String(), ib.String(), stray.String()}
	slices.Sort(before)
	if !slices.Equal(unknown, before) {
		t.Fatalf("scope-only registry: unknown %v, want %v", unknown, before)
	}

	// a registered instance of the scope missing from the host is still reported
	host.Instances = host.Instances[:2]
	got = hostReconcile(t.Context(), agent, src, inv, inScope)
	want = []HostFinding{{Kind: reconcile.DriftRegisteredMissing, Subject: ig.String()}}
	if !slices.Equal(got, want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
}
