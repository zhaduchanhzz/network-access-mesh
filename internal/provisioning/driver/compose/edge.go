package compose

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Edge attachment (§11.3 step 14, §11.4, §14.3, §14.6; ADR-08). The shared edge (mg-edge) is attached at run time to
// the internal network mg-t-<slug> of every activated tenant — adding a tenant never reloads Caddy; the tenant name
// hs-<slug> resolves through Docker's DNS on that network. The network must have exactly two members (the tenant's
// Headscale and the edge), and the alias hs-<slug> must exist on no other network the edge is attached to, or the
// edge would route one tenant's hostname to another tenant's control plane.

const (
	execTimeout = 30 * time.Second
	// headscaleBin is the Headscale CLI inside the tenant container (in PATH of the official and patched images).
	headscaleBin = "headscale"
)

func (d *Driver) runningContainer(ctx context.Context, n agentspec.Names, ref agentspec.Ref) (*Container, error) {
	c, err := d.cfg.Engine.Container(ctx, n.Container)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, state("instance", "container %s does not exist (EnsureInstance with TARGET_PHASE_CONTAINER)", n.Container)
	}
	if err := ownContainer(c, n, ref); err != nil {
		return nil, err
	}
	if c.State != "running" {
		return nil, state("instance", "container %s is not running", n.Container)
	}
	return c, nil
}

// tenantNetwork returns the instance's network after checking it is its own (labels, internal).
func (d *Driver) tenantNetwork(ctx context.Context, n agentspec.Names, ref agentspec.Ref) (*Network, error) {
	nw, err := d.cfg.Engine.Network(ctx, n.Network)
	if err != nil {
		return nil, err
	}
	if nw == nil {
		return nil, state("instance", "network %s does not exist (EnsureInstance with TARGET_PHASE_NETWORK)", n.Network)
	}
	if nw.Labels[agentspec.LabelInstanceID] != ref.InstanceID.String() || nw.Labels[agentspec.LabelRole] != agentspec.RoleTenant || !nw.Internal {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, Field: "instance.slug",
			Msg: fmt.Sprintf("network %s is not this instance's internal network (never adopted)", n.Network)}
	}
	return nw, nil
}

// foreignMembers lists the members of the tenant network other than the instance's container and the edge.
func (d *Driver) foreignMembers(nw *Network, n agentspec.Names) []string {
	var out []string
	for _, m := range nw.Members {
		if m != n.Container && m != d.cfg.Edge {
			out = append(out, m)
		}
	}
	return out
}

// policyPresent: the instance has a policy (`headscale policy get` succeeds). An instance without one runs the
// allow-all default of Headscale (PL-02): it never gets an edge before BootstrapPolicy (§11.3 step 12 → 14).
func (d *Driver) policyPresent(ctx context.Context, n agentspec.Names) error {
	res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "policy", "get", "-o", "json"}, execTimeout)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 || len(res.Stdout) == 0 {
		return state("instance", "the instance has no policy (allow-all window, PL-02): BootstrapPolicy first (§11.3 step 12)")
	}
	return nil
}

// EnsureEdgeAttachment — §11.3 step 14. The guard checked (before this call) that hs-<slug> exists on no other network
// of the edge and that the tenant network holds nothing but the instance (and the edge). Here: the edge exists, the
// instance runs, has a policy and passes the start guard — on the first activation its Noise key fingerprint is
// recorded; then meta/activated and the edge_attach flag are written BEFORE the edge is connected (a crash in
// between leaves the attachment to the supervisor), and the network must end with exactly two members. Idempotent.
func (d *Driver) EnsureEdgeAttachment(ctx context.Context, c agentspec.Call) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	n := d.cfg.Host.Names(c.Ref)
	l := newLayout(c.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, err := d.readState(t, l, c.Ref.InstanceID)
	if err != nil {
		return nil, err
	}
	edge, err := d.cfg.Engine.Container(ctx, d.cfg.Edge)
	if err != nil {
		return nil, err
	}
	if edge == nil || edge.State != "running" {
		return nil, state("instance", "the edge container %s does not exist or is not running", d.cfg.Edge)
	}
	if _, err := d.runningContainer(ctx, n, c.Ref); err != nil {
		return nil, err
	}
	nw, err := d.tenantNetwork(ctx, n, c.Ref)
	if err != nil {
		return nil, err
	}
	if f := d.foreignMembers(nw, n); len(f) > 0 {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, Field: "instance.slug",
			Msg: fmt.Sprintf("network %s has a member other than %s and the edge", n.Network, n.Container)}
	}
	wasAttached := slices.Contains(nw.Members, d.cfg.Edge)
	if err := d.policyPresent(ctx, n); err != nil {
		return nil, err
	}
	// the start guard; on the first activation the fingerprint is recorded instead of compared
	recorded, _ := st.meta[metaFingerprint].(string)
	var g guardCheck
	if st.activated || recorded != "" {
		g = d.startGuard(ctx, t, l, n, c.Ref, st.runUID, st.meta)
	} else {
		g = d.checkData(ctx, t, l, n, c.Ref, st.runUID)
	}
	switch {
	case g.err != nil:
		return nil, status.Errorf(codes.Unavailable, "start guard (§11.4) could not verify data/ of this instance: %v", g.err)
	case g.violation != "" && st.activated:
		actions := d.contain(ctx, t, l, n, c.Ref, st.meta, g, "edge_attach")
		return nil, state("instance", "start guard (§11.4): %s — not attached; actions: %v", g.describe(), actions)
	case g.violation != "":
		return nil, state("instance", "data/ of the instance is not complete (%s): not activated, not attached", g.describe())
	}
	// meta/activated first, then the flag (the flag never exists without the activation, whose guard it relies on)
	before := clone(st.meta)
	createdActivation := false
	if !st.activated {
		if err := writeActivation(t, l, c.JobID, time.Now()); err != nil {
			return nil, err
		}
		createdActivation = true
	}
	st.meta[metaFingerprint] = g.fingerprint
	st.meta[metaEdgeAttach] = true
	if err := writeMetaMap(t, l, st.meta); err != nil {
		return nil, err
	}
	rollback := func(cause error) error {
		if !wasAttached {
			_ = d.cfg.Engine.DisconnectNetwork(context.WithoutCancel(ctx), n.Network, d.cfg.Edge)
		}
		_ = writeMetaMap(t, l, before)
		if createdActivation {
			_ = t.removeFile(l.activatedFile)
		}
		return cause
	}
	if !wasAttached {
		if err := d.cfg.Engine.ConnectNetwork(ctx, n.Network, d.cfg.Edge); err != nil {
			return nil, rollback(err)
		}
	}
	// exactly two members: the instance and the edge (§14.3 — a member that appeared meanwhile is refused)
	if nw, err = d.cfg.Engine.Network(ctx, n.Network); err != nil {
		return nil, rollback(err)
	}
	if nw == nil || !slices.Equal(nw.Members, sorted(n.Container, d.cfg.Edge)) {
		return nil, rollback(&agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, Field: "instance.slug",
			Msg: fmt.Sprintf("network %s does not hold exactly %s and the edge after the attachment — detached", n.Network, n.Container)})
	}
	if !wasAttached || createdActivation {
		d.cfg.Log.Info("edge_attached", "instance_id", l.id, "network", n.Network, "edge", d.cfg.Edge, "trigger", "rpc",
			"activated_now", createdActivation, "noise_key_fingerprint", g.fingerprint)
	}
	return &agentv1.EnsureEdgeAttachmentResponse{Attached: true, AlreadyAttached: wasAttached, NetworkMembers: uint32(len(nw.Members))}, nil //nolint:gosec // G115: 2
}

// RemoveEdgeAttachment — §11.4 (quarantine, deprovision, restore, post-start gate) and the compensation of §11.3 step
// 14: the edge_attach flag is cleared FIRST (the supervisor never re-attaches), then the edge is detached. With
// EDGE_DETACH_REASON_COMPENSATION, meta/activated (and the fingerprint recorded with it) is removed too — only when it
// was written by the same job. Idempotent.
func (d *Driver) RemoveEdgeAttachment(ctx context.Context, r agentspec.EdgeDetach) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	n := d.cfg.Host.Names(r.Ref)
	l := newLayout(r.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, err := d.readState(t, l, r.Ref.InstanceID)
	if err != nil {
		return nil, err
	}
	changed := false
	if flag, _ := st.meta[metaEdgeAttach].(bool); flag {
		delete(st.meta, metaEdgeAttach)
		changed = true
	}
	compensated := false
	if r.Reason == agentv1.EdgeDetachReason_EDGE_DETACH_REASON_COMPENSATION {
		exists, job, err := readActivation(t, l)
		if err != nil {
			return nil, err
		}
		if exists && job == r.JobID.String() {
			delete(st.meta, metaFingerprint)
			changed, compensated = true, true
		}
	}
	if changed {
		if err := writeMetaMap(t, l, st.meta); err != nil {
			return nil, err
		}
	}
	wasAttached, err := d.edgeAttached(ctx, n)
	if err != nil {
		return nil, err
	}
	if wasAttached {
		if err := d.cfg.Engine.DisconnectNetwork(ctx, n.Network, d.cfg.Edge); err != nil {
			return nil, err
		}
	}
	if compensated {
		if err := t.removeFile(l.activatedFile); err != nil {
			return nil, err
		}
		d.fps.forget(r.Ref.InstanceID)
	}
	if changed || wasAttached {
		d.cfg.Log.Info("edge_detached", "instance_id", l.id, "network", n.Network, "edge", d.cfg.Edge, "reason", r.Reason.String(),
			"was_attached", wasAttached, "activation_removed", compensated)
	}
	return &agentv1.RemoveEdgeAttachmentResponse{Detached: true, WasAttached: wasAttached}, nil
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sorted(s ...string) []string {
	sort.Strings(s)
	return s
}

// ---------------------------------------------------------------------------------------------------- supervisor

// EdgeReport is the outcome of one supervisor cycle (logged by apps/agent when it changes).
type EdgeReport struct {
	// EdgeID is the ID of the edge container ("" when it does not exist): a new ID means the edge was recreated.
	EdgeID string
	// Instances looked at; Flagged: with edge_attach; Attached: flagged and attached at the end of the cycle.
	Instances, Flagged, Attached int
	// Slugs: attached this cycle, detached (indeterminate guard or foreign member), contained (guard violation),
	// skipped because an operation held their lock, attached without the flag (left alone — e.g. instances deployed
	// by hand before the agent, P3-T14b), and the instances the cycle could not handle.
	NewlyAttached, Detached, Contained, Busy, Unflagged, Failed []string
	// Quarantined: instances under meta/quarantined (P3-T18) — never attached, contained again at every cycle (a
	// containment that had to act is in Contained too).
	Quarantined []string
	// GatewayDrift: the edge's default gateway is no longer on the edge network (gw_priority — §14.3).
	GatewayDrift bool
}

// EdgeCycle is one cycle of the edge supervisor (§11.4): for every instance directory, the start guard of an
// activated instance (a violation is contained), then the edge attached to the network of every instance whose
// meta/instance.json has edge_attach — and only those. It relies on Docker and the local files only: it works while
// PostgreSQL and the worker are down. tryLock takes an instance's lock without waiting; an instance whose lock is
// held by an operation is skipped until the next cycle.
func (d *Driver) EdgeCycle(ctx context.Context, tryLock func(uuid.UUID) (func(), bool)) (EdgeReport, error) {
	var rep EdgeReport
	edge, err := d.cfg.Engine.Container(ctx, d.cfg.Edge)
	if err != nil {
		return rep, err
	}
	if edge != nil {
		rep.EdgeID = edge.ID
		rep.GatewayDrift = d.gatewayDrift(edge)
	}
	ids, err := d.instanceIDs()
	if err != nil {
		return rep, err
	}
	t, err := d.open()
	if err != nil {
		return rep, err
	}
	defer func() { _ = t.Close() }()
	for _, id := range ids {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		rep.Instances++
		unlock, ok := tryLock(id)
		if !ok {
			rep.Busy = append(rep.Busy, id.String())
			continue
		}
		d.superviseInstance(ctx, t, id, edge, &rep)
		unlock()
	}
	return rep, nil
}

func (d *Driver) superviseInstance(ctx context.Context, t *tree, id uuid.UUID, edge *Container, rep *EdgeReport) {
	gm, err := d.cfg.Guard.ReadMeta(id)
	if err != nil || gm == nil {
		d.cfg.Log.Warn("edge_supervisor_skip", "instance_id", id.String(), "error", err)
		rep.Failed = append(rep.Failed, id.String())
		return
	}
	ref, n, l := gm.Ref, d.cfg.Host.Names(gm.Ref), newLayout(id.String())
	fail := func(step string, err error) {
		d.cfg.Log.Warn("edge_supervisor_error", "instance_id", l.id, "step", step, "error", err)
		rep.Failed = append(rep.Failed, ref.Slug)
	}
	m, err := readMetaMap(t, l)
	if err != nil {
		fail("meta", err)
		return
	}
	act, err := t.lstat(l.activatedFile)
	if err != nil {
		fail("meta", err)
		return
	}
	// quarantined (§11.4, P3-T18): never attached, whatever the flag — contained again instead
	if q, err := isQuarantined(t, l); err != nil {
		fail("meta", err)
		return
	} else if q {
		d.superviseQuarantined(ctx, t, l, n, ref, m, rep)
		return
	}
	flag, _ := m[metaEdgeAttach].(bool)
	if flag {
		rep.Flagged++
	}
	nw, err := d.cfg.Engine.Network(ctx, n.Network)
	if err != nil {
		fail("network", err)
		return
	}
	// members of a network are its active endpoints: a stopped edge is never "attached" here
	attached := edge != nil && nw != nil && slices.Contains(nw.Members, d.cfg.Edge)
	detach := func(why string) {
		if err := d.cfg.Engine.DisconnectNetwork(ctx, n.Network, d.cfg.Edge); err != nil {
			fail("detach", err)
			return
		}
		attached = false
		rep.Detached = append(rep.Detached, ref.Slug)
		d.cfg.Log.Warn("edge_detached", "instance_id", l.id, "network", n.Network, "edge", d.cfg.Edge, "trigger", "edge_supervisor", "reason", why)
	}
	if act != nil {
		g := d.startGuard(ctx, t, l, n, ref, gm.RunUID, m)
		switch {
		case g.violation != "":
			d.contain(ctx, t, l, n, ref, m, g, "edge_supervisor")
			rep.Contained = append(rep.Contained, ref.Slug)
			return
		case g.err != nil:
			// fail closed for this cycle without clearing the flag: the next cycle that concludes re-attaches
			d.cfg.Log.Error("start_guard_indeterminate", "instance_id", l.id, "trigger", "edge_supervisor", "error", g.err)
			if attached {
				detach("start_guard_indeterminate")
			}
			rep.Failed = append(rep.Failed, ref.Slug)
			return
		}
	}
	switch {
	case !flag:
		if attached {
			rep.Unflagged = append(rep.Unflagged, ref.Slug) // never touched: not the supervisor's to decide (reconcile reports it)
		}
		return
	case act == nil:
		// a flag without the activation it relies on (the agent writes meta/activated first): never attached
		d.cfg.Log.Warn("edge_attach_without_activation", "instance_id", l.id)
		rep.Failed = append(rep.Failed, ref.Slug)
		return
	case edge == nil || edge.State != "running" || nw == nil:
		return // nothing to attach to (yet): a stopped edge is handled when it starts again
	}
	if f := d.foreignMembers(nw, n); len(f) > 0 {
		d.cfg.Log.Error("tenant_network_foreign_member", "severity", "critical", "alert", "MeshGuardTenantNetworkMembers",
			"instance_id", l.id, "network", n.Network, "members", nw.Members)
		if attached {
			detach("foreign_member")
		}
		rep.Failed = append(rep.Failed, ref.Slug)
		return
	}
	if attached {
		rep.Attached++
		return
	}
	if err := d.cfg.Guard.CheckEdgeAttach(ctx, ref); err != nil {
		if r, ok := agentspec.AsRefusal(err); ok && r.Reason == agentv1.RefusalReason_REFUSAL_REASON_CONFLICT {
			d.cfg.Log.Error("edge_alias_conflict", "severity", "critical", "alert", "MeshGuardEdgeAliasConflict",
				"instance_id", l.id, "network", n.Network, "error", err)
			rep.Failed = append(rep.Failed, ref.Slug)
			return
		}
		fail("check_edge_attach", err)
		return
	}
	if err := d.cfg.Engine.ConnectNetwork(ctx, n.Network, d.cfg.Edge); err != nil {
		fail("attach", err)
		return
	}
	rep.Attached++
	rep.NewlyAttached = append(rep.NewlyAttached, ref.Slug)
	d.cfg.Log.Info("edge_attached", "instance_id", l.id, "network", n.Network, "edge", d.cfg.Edge, "trigger", "edge_supervisor")
}

// EdgeStarts signals the starts of the edge container (a recreated edge is re-attached at once — §11.4).
func (d *Driver) EdgeStarts(ctx context.Context) <-chan struct{} {
	return d.cfg.Engine.ContainerStarts(ctx, d.cfg.Edge)
}

// gatewayDrift: the edge's default gateway (and the DNAT target of its published ports) must stay on the edge network
// — its endpoint there has the highest gw_priority, strictly (§14.3, §11.4). A drift is a Critical event.
func (d *Driver) gatewayDrift(edge *Container) bool {
	want, ok := edge.GwPriority[d.cfg.EdgeNetwork]
	drift := !ok
	for nw, p := range edge.GwPriority {
		if nw != d.cfg.EdgeNetwork && p >= want {
			drift = true
		}
	}
	if drift {
		d.cfg.Log.Error("edge_gateway_drift", "severity", "critical", "alert", "MeshGuardEdgeGatewayDrift",
			"edge", d.cfg.Edge, "network", d.cfg.EdgeNetwork, "gw_priority", edge.GwPriority)
	}
	return drift
}

// instanceIDs lists the instance directories (canonical UUID names) of the tenants directory.
func (d *Driver) instanceIDs() ([]uuid.UUID, error) {
	root, err := os.OpenRoot(d.cfg.Host.TenantsDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []uuid.UUID
	for _, name := range names {
		if id, err := agentspec.UUID("", name); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
}
