package compose

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
)

// rigAgent answers the two reads of reconcile from this driver and its guard, like apps/agent's handlers do.
type rigAgent struct{ rg *rig }

func (a rigAgent) GetInstanceStatus(ctx context.Context, _ *agentv1.GetInstanceStatusRequest, _ ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	st, err := a.rg.d.InstanceStatus(ctx, a.rg.s.Ref, false)
	return &agentv1.GetInstanceStatusResponse{Status: st}, err
}

func (a rigAgent) ListInstances(ctx context.Context, _ *agentv1.ListInstancesRequest, _ ...grpc.CallOption) (*agentv1.ListInstancesResponse, error) {
	list, err := a.rg.d.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	aliases, err := a.rg.g.EdgeAliases(ctx)
	return &agentv1.ListInstancesResponse{Instances: list, EdgeAliases: aliases}, err
}

// TestReconcileParity: the expectations of reconcile (P3-T12) — names, network, owner/mode of every path (§14.2) —
// are what this driver builds. An instance run to the container phase with the edge attached reconciles without a
// finding on every agent check, and so does the host (inventory, hs-<slug> on the edge's networks); then a path
// chmod'ed, a stranger on the tenant network and a second hs-<slug> on another network of the edge are reported.
func TestReconcileParity(t *testing.T) {
	rg := newRig(t)
	ctx := context.Background()
	resp := rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	rg.e.addContainer(Container{Name: "mg-edge", State: "running", Labels: map[string]string{}, Networks: map[string][]string{"mg-edge": {"mg-edge"}}})
	if err := rg.e.ConnectNetwork(ctx, "mg-t-acme", "mg-edge"); err != nil {
		t.Fatal(err)
	}
	in := &reconcile.Inspector{Agent: rigAgent{rg}, AgentUID: uint32(os.Geteuid()), AgentGID: uint32(os.Getegid())} //nolint:gosec // ids
	d := reconcile.Desired{InstanceID: rg.s.Ref.InstanceID, TenantID: rg.s.Ref.TenantID, Slug: rg.s.Ref.Slug, Status: "running",
		ImageDigest: rg.s.Image.Digest, NetCIDR: rg.s.NetCIDR, RunUID: rg.s.RunUID, ConfigSHA256: resp.GetConfigSha256()}
	rep, evs := in.Instance(ctx, d)
	if len(rep.Findings) != 0 || len(evs) != 0 {
		t.Fatalf("fresh instance: findings %+v events %d", rep.Findings, len(evs))
	}
	ok := map[string]bool{}
	for _, c := range rep.Checks {
		ok[c.Name] = c.Outcome == reconcile.OutcomeOK
	}
	for _, c := range []string{reconcile.CheckAgent, reconcile.CheckContainer, reconcile.CheckImage, reconcile.CheckConfig,
		reconcile.CheckNetwork, reconcile.CheckPaths} {
		if !ok[c] {
			t.Errorf("check %s not ok: %+v", c, rep.Checks)
		}
	}
	regs := []reconcile.Registered{{InstanceID: d.InstanceID, TenantID: d.TenantID, Slug: d.Slug, Status: "running"}}
	host, hevs := in.Host(ctx, regs)
	if host.Status != reconcile.StatusClean || len(hevs) != 0 {
		t.Fatalf("host: %+v (%d events)", host, len(hevs))
	}

	// drift: data/ opened up, a stranger on mg-t-acme, hs-acme also held on another network of the edge
	if err := os.Chmod(filepath.Join(rg.idir, "data"), 0o755); err != nil { //nolint:gosec // G302: test
		t.Fatal(err)
	}
	rg.e.addContainer(Container{Name: "stranger", State: "running", Labels: map[string]string{}, Networks: map[string][]string{"mg-t-acme": {"stranger"}}})
	rg.e.addNetwork(Network{Name: "mg-t-evil", Internal: true, Labels: map[string]string{}})
	rg.e.addContainer(Container{Name: "rogue", State: "running", Labels: map[string]string{}, Networks: map[string][]string{"mg-t-evil": {"rogue", "hs-acme"}}})
	if err := rg.e.ConnectNetwork(ctx, "mg-t-evil", "mg-edge"); err != nil {
		t.Fatal(err)
	}
	before := rg.snapshot(t)
	rep, _ = in.Instance(ctx, d)
	kinds := rep.Kinds()
	if kinds[reconcile.DriftPathPermissions] != 1 || kinds[reconcile.DriftNetworkExtraMember] != 1 || len(rep.Findings) != 2 {
		t.Fatalf("drift: %+v", rep.Findings)
	}
	for _, f := range rep.Findings {
		if f.Kind == reconcile.DriftPathPermissions && !slices.Equal(f.Items, []string{"data_dir:mode=0755,want=0700"}) {
			t.Errorf("path items %v", f.Items)
		}
	}
	host, _ = in.Host(ctx, regs)
	if k := host.Kinds(); k[reconcile.DriftAliasCollision] != 1 || len(host.Findings) != 1 {
		t.Fatalf("host drift: %+v", host.Findings)
	}
	if after := rg.snapshot(t); after != before {
		t.Fatalf("reconcile changed the host:\n%s\n---\n%s", before, after)
	}
}
