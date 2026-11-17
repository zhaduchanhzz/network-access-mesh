package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Start guard (§11.4, RT-06). Headscale silently creates a new Noise key and an empty database — an empty, allow-all
// control plane on the tenant's hostname — when data/ lost its files. An instance that was ever activated
// (meta/activated) is therefore started, given an API key or attached to the edge only while data/db.sqlite,
// data/noise_private.key and data/derp_server_private.key exist (lstat by the agent, nothing read) and the
// fingerprint of the Noise key — computed by the one-shot helper container, never by the agent — equals the one
// recorded at activation in meta/instance.json (noise_key_fingerprint; the registry has a copy, but the guard must
// work while PostgreSQL and the worker are down). A violation is contained at once: the edge_attach flag is cleared,
// the edge detached from the tenant network, the container stopped, and a Critical event logged.

// Keys of meta/instance.json written by P3-T03 (§14.2).
const (
	metaEdgeAttach  = "edge_attach"
	metaFingerprint = "noise_key_fingerprint"
)

// dataFiles are the files of data/ an activated instance cannot run without (§11.6).
var dataFiles = []string{"db.sqlite", "noise_private.key", "derp_server_private.key"}

// Violation reasons (log field "reason", refusal message).
const (
	reasonDataMissing       = "data_dir_missing"
	reasonDataNotDir        = "data_dir_not_a_directory"
	reasonFileMissing       = "data_file_missing"
	reasonFileNotRegular    = "data_file_not_regular"
	reasonNoiseKeyInvalid   = "noise_key_invalid"
	reasonNotRecorded       = "fingerprint_not_recorded"
	reasonFingerprintDiffer = "fingerprint_mismatch"
)

// guardCheck is the outcome of the start guard for one instance.
type guardCheck struct {
	// violation is empty when the check passed; otherwise one of the reason* values, detail names the file.
	violation, detail string
	// fingerprint is the fingerprint of the Noise key as the helper computed it (empty on violation or error).
	fingerprint string
	// err: the check could not conclude (helper failed, Docker unavailable) — fail closed, but not a violation.
	err error
}

func (g guardCheck) ok() bool { return g.violation == "" && g.err == nil }

func (g guardCheck) describe() string {
	if g.detail == "" {
		return g.violation
	}
	return g.violation + " (" + g.detail + ")"
}

// checkData checks data/ of an instance — the files exist and are regular (lstat only) — and computes the Noise key
// fingerprint through the helper. It does not compare it to anything.
func (d *Driver) checkData(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref, runUID uint32) guardCheck {
	fi, err := t.lstat(l.data)
	switch {
	case err != nil:
		return guardCheck{err: err}
	case fi == nil:
		return guardCheck{violation: reasonDataMissing}
	case !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0:
		return guardCheck{violation: reasonDataNotDir}
	}
	var keyID fileID
	for _, name := range dataFiles {
		fi, err := t.lstat(filepath.Join(l.data, name))
		switch {
		case err != nil:
			return guardCheck{err: err}
		case fi == nil:
			return guardCheck{violation: reasonFileMissing, detail: name}
		case !fi.Mode().IsRegular():
			return guardCheck{violation: reasonFileNotRegular, detail: name}
		}
		if name == "noise_private.key" {
			keyID = identity(fi)
		}
	}
	fp, err := d.fingerprint(ctx, n, ref, runUID, keyID)
	switch {
	case errors.Is(err, ErrNoiseKeyAbsent):
		return guardCheck{violation: reasonFileMissing, detail: "noise_private.key"}
	case errors.Is(err, ErrNoiseKeyInvalid):
		return guardCheck{violation: reasonNoiseKeyInvalid}
	case err != nil:
		return guardCheck{err: err}
	}
	return guardCheck{fingerprint: fp}
}

// startGuard is the full check of an activated instance: data/ as checkData, and the fingerprint equal to the one
// recorded at activation.
func (d *Driver) startGuard(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref, runUID uint32, meta map[string]any) guardCheck {
	g := d.checkData(ctx, t, l, n, ref, runUID)
	if !g.ok() {
		return g
	}
	recorded, _ := meta[metaFingerprint].(string)
	switch {
	case !fingerprintRE.MatchString(recorded):
		return guardCheck{violation: reasonNotRecorded}
	case recorded != g.fingerprint:
		return guardCheck{violation: reasonFingerprintDiffer}
	}
	return g
}

// instanceState is what the guard paths read about one instance.
type instanceState struct {
	meta      map[string]any
	activated bool
	runUID    uint32
}

func (d *Driver) readState(t *tree, l layout, id uuid.UUID) (instanceState, error) {
	gm, err := d.cfg.Guard.ReadMeta(id)
	if err != nil {
		return instanceState{}, err
	}
	if gm == nil {
		return instanceState{}, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, Field: "instance.instance_id",
			Msg: "no instance directory with meta/instance.json"}
	}
	m, err := readMetaMap(t, l)
	if err != nil {
		return instanceState{}, err
	}
	fi, err := t.lstat(l.activatedFile)
	if err != nil {
		return instanceState{}, err
	}
	return instanceState{meta: m, activated: fi != nil, runUID: gm.RunUID}, nil
}

// enforceStartGuard runs before anything that would make an activated instance serve (start, restart, compose up,
// API key, policy bootstrap, edge attachment). A violation is contained and refused (STATE); an indeterminate check
// is refused UNAVAILABLE (the worker retries) — the instance is never started on a guess.
func (d *Driver) enforceStartGuard(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref, trigger string) error {
	st, err := d.readState(t, l, ref.InstanceID)
	if err != nil {
		return err
	}
	if !st.activated {
		return nil
	}
	g := d.startGuard(ctx, t, l, n, ref, st.runUID, st.meta)
	switch {
	case g.err != nil:
		d.cfg.Log.Error("start_guard_indeterminate", "instance_id", l.id, "trigger", trigger, "error", g.err)
		return status.Errorf(codes.Unavailable, "start guard (§11.4) could not verify data/ of this activated instance: %v", g.err)
	case g.violation != "":
		actions := d.contain(ctx, t, l, n, ref, st.meta, g, trigger)
		return state("instance", "start guard (§11.4): %s — the instance was not started; actions: %v; data/ must be restored (§17.2) before it can serve again",
			g.describe(), actions)
	}
	return nil
}

// contain is the reaction to a start-guard violation (§11.4): clear the edge_attach flag, detach the edge from the
// tenant network, stop the container, log a Critical event. Every step is attempted; a failing step is logged and the
// next one still runs. It returns the actions taken.
func (d *Driver) contain(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref, meta map[string]any, g guardCheck, trigger string) []string {
	actions := []string{}
	if flag, _ := meta[metaEdgeAttach].(bool); flag {
		delete(meta, metaEdgeAttach)
		if err := writeMetaMap(t, l, meta); err != nil {
			d.cfg.Log.Error("start_guard_containment_failed", "instance_id", l.id, "step", "clear_edge_attach", "error", err)
		} else {
			actions = append(actions, "edge_attach_cleared")
		}
	}
	if attached, err := d.edgeAttached(ctx, n); err != nil {
		d.cfg.Log.Error("start_guard_containment_failed", "instance_id", l.id, "step", "detach_edge", "error", err)
	} else if attached {
		if err := d.cfg.Engine.DisconnectNetwork(ctx, n.Network, d.cfg.Edge); err != nil {
			d.cfg.Log.Error("start_guard_containment_failed", "instance_id", l.id, "step", "detach_edge", "error", err)
		} else {
			actions = append(actions, "edge_detached")
		}
	}
	if c, err := d.cfg.Engine.Container(ctx, n.Container); err != nil {
		d.cfg.Log.Error("start_guard_containment_failed", "instance_id", l.id, "step", "stop_container", "error", err)
	} else if c != nil && ownContainer(c, n, ref) == nil && (c.State == "running" || c.State == "restarting" || c.State == "paused") {
		sctx, cancel := context.WithTimeout(ctx, stopTimeout)
		err := d.cfg.Engine.StopContainer(sctx, n.Container, stopGrace)
		cancel()
		if err != nil {
			d.cfg.Log.Error("start_guard_containment_failed", "instance_id", l.id, "step", "stop_container", "error", err)
		} else {
			actions = append(actions, "container_stopped")
		}
	}
	d.fps.forget(ref.InstanceID)
	// The Critical event monitoring alerts on (§16.3 "fingerprint Noise key khác giá trị đã ghi nhận"): one JSON line
	// on the agent's stdout, msg start_guard_failed, severity critical — see the evidence of P3-T03 for how it
	// surfaces until the alerting of P3-T16 exists.
	d.cfg.Log.Error("start_guard_failed", "severity", "critical", "alert", "MeshGuardStartGuardFailed",
		"instance_id", l.id, "tenant_id", ref.TenantID.String(), "slug", ref.Slug, "reason", g.violation, "detail", g.detail,
		"trigger", trigger, "actions", actions)
	return actions
}

// edgeAttached reports whether the edge is a member of the tenant network (false when the network does not exist).
func (d *Driver) edgeAttached(ctx context.Context, n agentspec.Names) (bool, error) {
	nw, err := d.cfg.Engine.Network(ctx, n.Network)
	if err != nil || nw == nil {
		return false, err
	}
	for _, m := range nw.Members {
		if m == d.cfg.Edge {
			return true, nil
		}
	}
	// a stopped edge has no active endpoint: look at the edge's own configuration too
	e, err := d.cfg.Engine.Container(ctx, d.cfg.Edge)
	if err != nil || e == nil {
		return false, err
	}
	_, ok := e.Networks[n.Network]
	return ok, nil
}

// ---------------------------------------------------------------------------------------------------- meta files

// readMetaMap reads meta/instance.json keeping every key (the guard read and checked its identity keys already).
func readMetaMap(t *tree, l layout) (map[string]any, error) {
	raw, err := t.readFile(l.metaFile, maxMetaBytes)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("%s: %w", filepath.ToSlash(l.metaFile), errMissing)
	}
	m, err := decodeMeta(raw)
	if err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, Field: "instance", Msg: err.Error()}
	}
	return m, nil
}

// writeMetaMap writes meta/instance.json atomically (root:root 0400); nothing is written when it is unchanged.
func writeMetaMap(t *tree, l layout, m map[string]any) error {
	raw, err := encodeMeta(m)
	if err != nil {
		return err
	}
	_, err = t.writeFile(l.metaFile, raw, owner{t.agentUID, t.agentGID, modeMeta})
	return err
}

// activation is the content of meta/activated: the job that activated the instance (the compensation of §11.3 step
// 14 removes the file only when it was written by the same job).
type activation struct {
	JobID       string `json:"job_id"`
	ActivatedAt string `json:"activated_at"`
}

// readActivation returns the job recorded in meta/activated ("" when the file is absent or its content unknown — a
// file of another origin is never removed by a compensation).
func readActivation(t *tree, l layout) (exists bool, jobID string, err error) {
	raw, err := t.readFile(l.activatedFile, maxMetaBytes)
	if err != nil || raw == nil {
		return false, "", err
	}
	var a activation
	if json.Unmarshal(raw, &a) == nil {
		if _, err := agentspec.UUID("", a.JobID); err == nil {
			return true, a.JobID, nil
		}
	}
	return true, "", nil
}

func writeActivation(t *tree, l layout, jobID uuid.UUID, now time.Time) error {
	raw, err := encodeMeta(map[string]any{"job_id": jobID.String(), "activated_at": now.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	_, err = t.writeFile(l.activatedFile, raw, owner{t.agentUID, t.agentGID, modeMeta})
	return err
}
