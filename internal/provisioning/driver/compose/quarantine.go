package compose

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Quarantine (§11.4, P3-T18). An instance suspected of compromise is isolated on the host by one marker file,
// meta/quarantined (root:root 0400, JSON {job_id, quarantined_at}), written FIRST by QuarantineInstance, then the
// edge_attach flag is cleared, the container stopped and the edge detached (enforceQuarantine: stop before detach). data/ and the container (its logs) are kept
// for the investigation. While the marker exists:
//
//   - apps/agent refuses (STATE) every call that could make the instance serve or change it — start, restart,
//     EnsureInstance, configtest, upgrade, DNS records, policy/API key bootstrap, restore, edge attachment, a
//     compensation that would remove meta/activated, a removal that deletes data; StopInstance, RemoveEdgeAttachment,
//     RemoveInstance keeping data, Backup and the reads still pass;
//   - the edge supervisor never attaches the instance and contains it again at every cycle (flag cleared, container
//     stopped, edge detached) — a Critical quarantine_breach line when it had to act (a container started by
//     hand, an edge connected by hand). Because the marker is written before anything else, an agent that dies in the
//     middle of QuarantineInstance leaves the containment to its next cycle.
//
// Only ReleaseInstance lifts it, and only after the instance passed the start guard, became healthy and serves the
// expected policy; it never attaches the edge (EnsureEdgeAttachment does, afterwards).

// quarantineName is the marker file under meta/.
const quarantineName = "quarantined"

// quarantineStopGrace: a quarantined container is stopped without grace period (enforceQuarantine).
const quarantineStopGrace = 0 * time.Second

// Bounds of ReleaseInstance: the health gate of §11.3 step 11 (vars: shortened by the unit tests).
var (
	releaseHealthTimeout = 90 * time.Second
	releasePoll          = time.Second
)

func quarantineFile(l layout) string { return filepath.Join(l.meta, quarantineName) }

// isQuarantined reports whether meta/quarantined exists. Whatever sits at that path counts (a directory, a symlink):
// fail closed — only the agent writes under meta/.
func isQuarantined(t *tree, l layout) (bool, error) {
	fi, err := t.lstat(quarantineFile(l))
	return fi != nil, err
}

// Quarantined reports whether the instance carries meta/quarantined (false when it has no directory): the check of
// apps/agent before every call a quarantined instance refuses.
func (d *Driver) Quarantined(_ context.Context, ref agentspec.Ref) (bool, error) {
	t, err := d.open()
	if err != nil {
		return false, err
	}
	defer func() { _ = t.Close() }()
	return isQuarantined(t, newLayout(ref.InstanceID.String()))
}

// containment is what enforceQuarantine undid.
type containment struct{ flag, edge, stopped bool }

func (c containment) actions() []string {
	out := []string{}
	if c.flag {
		out = append(out, "edge_attach_cleared")
	}
	if c.edge {
		out = append(out, "edge_detached")
	}
	if c.stopped {
		out = append(out, "container_stopped")
	}
	return out
}

// enforceQuarantine makes the host state of a quarantined instance true: no edge_attach flag, the container not running,
// the edge not attached to the tenant network (a stopped edge's configuration included). The container is stopped at
// once — no grace period (SIGKILL): a process suspected of compromise must not be able to delay its own stop, and the
// database stays a consistent crash image (SQLite WAL) — and BEFORE the edge is detached: the kernel then closes the
// instance's connections with the edge (FIN/RST over a route that still exists), so the edge keeps no pooled connection
// to an address without a route — a request to the tenant's hostname gets the uniform 404 of §14.6 at once instead of
// hanging on a dead connection, and the clients' long-lived streams through the edge end with it. Every step is
// attempted; the failures are returned together.
func (d *Driver) enforceQuarantine(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref, meta map[string]any) (containment, error) {
	var (
		c    containment
		errs []error
	)
	if flag, _ := meta[metaEdgeAttach].(bool); flag {
		delete(meta, metaEdgeAttach)
		if err := writeMetaMap(t, l, meta); err != nil {
			errs = append(errs, fmt.Errorf("clear edge_attach: %w", err))
		} else {
			c.flag = true
		}
	}
	ctr, err := d.cfg.Engine.Container(ctx, n.Container)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("inspect the container: %w", err))
	case ctr != nil && ownContainer(ctr, n, ref) == nil && (ctr.State == "running" || ctr.State == "restarting" || ctr.State == "paused"):
		sctx, cancel := context.WithTimeout(ctx, stopTimeout)
		err := d.cfg.Engine.StopContainer(sctx, n.Container, quarantineStopGrace)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("stop the container: %w", err))
		} else {
			c.stopped = true
		}
	}
	if attached, err := d.edgeAttached(ctx, n); err != nil {
		errs = append(errs, fmt.Errorf("inspect the edge attachment: %w", err))
	} else if attached {
		if err := d.cfg.Engine.DisconnectNetwork(ctx, n.Network, d.cfg.Edge); err != nil {
			errs = append(errs, fmt.Errorf("detach the edge: %w", err))
		} else {
			c.edge = true
		}
	}
	return c, errors.Join(errs...)
}

// QuarantineInstance — §11.4 Quarantine: meta/quarantined first (kept as it is when it exists: the first quarantine
// stays the reference), then the containment (flag, container, edge). Idempotent; data/ is never touched.
func (d *Driver) QuarantineInstance(ctx context.Context, c agentspec.Call) (*agentv1.QuarantineInstanceResponse, error) {
	n, l := d.cfg.Host.Names(c.Ref), newLayout(c.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, err := d.readState(t, l, c.Ref.InstanceID)
	if err != nil {
		return nil, err
	}
	out := &agentv1.QuarantineInstanceResponse{}
	marked, err := isQuarantined(t, l)
	if err != nil {
		return nil, err
	}
	if !marked {
		raw, err := encodeMeta(map[string]any{"job_id": c.JobID.String(), "quarantined_at": time.Now().UTC().Format(time.RFC3339)})
		if err != nil {
			return nil, err
		}
		if _, err := t.writeFile(quarantineFile(l), raw, owner{t.agentUID, t.agentGID, modeMeta}); err != nil {
			return nil, err
		}
		out.MarkedNow = true
	}
	done, err := d.enforceQuarantine(ctx, t, l, n, c.Ref, st.meta)
	out.EdgeWasAttached, out.ContainerWasRunning = done.flag || done.edge, done.stopped
	d.cfg.Log.Warn("instance_quarantined", "instance_id", l.id, "tenant_id", c.Ref.TenantID.String(), "slug", c.Ref.Slug,
		"job_id", c.JobID.String(), "marked_now", out.MarkedNow, "actions", done.actions(), "complete", err == nil)
	if err != nil {
		// the marker is written: the supervisor finishes the containment at its next cycle; the worker retries
		return nil, err
	}
	if out.Status, err = d.status(ctx, t, l, n, c.Ref); err != nil {
		return nil, err
	}
	return out, nil
}

// ReleaseInstance — §11.4 Quarantine, the agent side of an approved release: the container is started through the
// start guard (a violation is contained like any start — §11.4 Start guard), must become healthy within
// releaseHealthTimeout and must serve a policy whose sha256 (CLI in the container, one newline removed — RT-15) is the
// expected one; only then is meta/quarantined removed. Any failure stops the container again and keeps the marker. A
// call on an instance that is not (or no longer) quarantined runs the same checks and removes nothing (a retried
// release). An instance that was never activated has nothing to release (re-provisioning, not a release).
func (d *Driver) ReleaseInstance(ctx context.Context, r agentspec.Release) (*agentv1.ReleaseInstanceResponse, error) {
	n, l := d.cfg.Host.Names(r.Ref), newLayout(r.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, err := d.readState(t, l, r.Ref.InstanceID)
	if err != nil {
		return nil, err
	}
	marked, err := isQuarantined(t, l)
	if err != nil {
		return nil, err
	}
	if !st.activated {
		return nil, state("instance", "the instance was never activated (meta/activated): nothing to release")
	}
	fail := func(cause error) error {
		if marked { // still quarantined: never left running
			if _, cerr := d.enforceQuarantine(context.WithoutCancel(ctx), t, l, n, r.Ref, st.meta); cerr != nil {
				d.cfg.Log.Error("quarantine_containment_failed", "instance_id", l.id, "trigger", "release", "error", cerr)
			}
		}
		d.cfg.Log.Warn("instance_release_refused", "instance_id", l.id, "job_id", r.JobID.String(), "error", cause)
		return cause
	}
	ctr, err := d.cfg.Engine.Container(ctx, n.Container)
	switch {
	case err != nil:
		return nil, err
	case ctr == nil:
		return nil, state("instance", "container %s does not exist: nothing to release", n.Container)
	}
	if err := ownContainer(ctr, n, r.Ref); err != nil {
		return nil, err
	}
	if ctr.State == "running" {
		// started by an earlier attempt of this release: the guard again, nothing started on a guess
		if err := d.enforceStartGuard(ctx, t, l, n, r.Ref, "release"); err != nil {
			return nil, fail(err)
		}
	} else if _, err := d.lifecycle(ctx, r.Call, stopTimeout, "start"); err != nil { // start guard, then compose start
		return nil, fail(err)
	}
	if err := d.waitReleaseHealthy(ctx, n); err != nil {
		return nil, fail(err)
	}
	res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "policy", "get", "-o", "json"}, execTimeout)
	if err != nil {
		return nil, fail(err)
	}
	if res.ExitCode != 0 || len(res.Stdout) == 0 {
		return nil, fail(state("instance", "the instance serves no policy (allow-all — PL-02): not released"))
	}
	got := sha256Hex(readBack(res.Stdout))
	if got != r.ExpectedPolicySHA256 {
		return nil, fail(state("instance", "the instance serves the policy sha256 %s, not the applied policy %s: not released",
			got, r.ExpectedPolicySHA256))
	}
	if marked {
		if err := t.removeFile(quarantineFile(l)); err != nil {
			return nil, fail(err)
		}
	}
	d.cfg.Log.Warn("instance_released", "instance_id", l.id, "tenant_id", r.Ref.TenantID.String(), "slug", r.Ref.Slug,
		"job_id", r.JobID.String(), "was_quarantined", marked, "policy_sha256", got)
	out := &agentv1.ReleaseInstanceResponse{WasQuarantined: marked, PolicySha256: got}
	if out.Status, err = d.status(ctx, t, l, n, r.Ref); err != nil {
		return nil, err
	}
	return out, nil
}

// waitReleaseHealthy waits until the container runs and its healthcheck reports healthy (§11.3 step 11).
func (d *Driver) waitReleaseHealthy(ctx context.Context, n agentspec.Names) error {
	deadline := time.Now().Add(releaseHealthTimeout)
	for {
		c, err := d.cfg.Engine.Container(ctx, n.Container)
		switch {
		case err != nil:
			return err
		case c == nil:
			return state("instance", "container %s disappeared while starting", n.Container)
		case c.State == "running" && c.Health == "healthy":
			return nil
		case c.State == "exited" || c.State == "dead":
			return state("instance", "container %s stopped while starting", n.Container)
		case c.Health == "unhealthy":
			return state("instance", "container %s is unhealthy", n.Container)
		case !time.Now().Before(deadline):
			return state("instance", "container %s not healthy after %s", n.Container, releaseHealthTimeout)
		}
		t := time.NewTimer(releasePoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// superviseQuarantined is the edge supervisor's cycle for a quarantined instance: never attached, contained again;
// having to act is a Critical event (something started or attached the instance behind the agent's back).
func (d *Driver) superviseQuarantined(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref, m map[string]any, rep *EdgeReport) {
	rep.Quarantined = append(rep.Quarantined, ref.Slug)
	done, err := d.enforceQuarantine(ctx, t, l, n, ref, m)
	if err != nil {
		d.cfg.Log.Error("quarantine_containment_failed", "instance_id", l.id, "trigger", "edge_supervisor", "error", err)
		rep.Failed = append(rep.Failed, ref.Slug)
	}
	if acts := done.actions(); len(acts) > 0 {
		rep.Contained = append(rep.Contained, ref.Slug)
		d.cfg.Log.Error("quarantine_breach", "severity", "critical", "alert", "MeshGuardQuarantineBreach",
			"instance_id", l.id, "tenant_id", ref.TenantID.String(), "slug", ref.Slug, "trigger", "edge_supervisor",
			"actions", acts)
	}
}
