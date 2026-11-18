package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Timeouts of the compose commands (the worker's own deadline still applies). stop_grace_period of the tenant
// service is 60 s (§14.5): stop/restart/down wait for it.
const (
	upTimeout      = 5 * time.Minute // includes pulling the pinned image on first start
	stopTimeout    = 90 * time.Second
	restartTimeout = 150 * time.Second
	downTimeout    = 2 * time.Minute
	stopGrace      = 60 * time.Second
	maxMetaBytes   = 64 << 10
	maxRecords     = 8 << 20
)

// Config wires the driver to one host.
type Config struct {
	// Host is the validated host configuration (paths, ranges, allowlist, OwnerUID = the agent's euid).
	Host *agentspec.Host
	// Guard is the ownership guard of apps/agent: the driver re-checks uniqueness with it under its creation lock and
	// reads meta/instance.json through it.
	Guard *agentspec.Guard
	// AgentGID is the group of the agent's own paths (its egid: 0 in production).
	AgentGID int
	Engine   Engine
	Compose  Runner
	// Edge is the container name of the shared edge (mg-edge): a tenant network with the edge attached is not removed
	// here (RemoveEdgeAttachment first — §11.4); the edge supervisor attaches it to the networks of the activated
	// instances.
	Edge string
	// EdgeNetwork is the platform network that must carry the edge's default gateway (mg-edge, gw_priority — §14.3).
	EdgeNetwork string
	// HelperImage is the image of the fingerprint helper (§11.5): the agent's own image, pinned by digest
	// (MG_AGENT_HELPER_IMAGE); it runs `meshguard-agent noise-fingerprint` as the tenant's run_uid. Empty: every
	// fingerprint is indeterminate — the start guard then fails closed.
	HelperImage string
	// Backup enables Backup and Restore (P3-T11); nil: both are refused.
	Backup *BackupConfig
	// MaxDBBytes bounds data/db.sqlite for the start guard (0: DefaultMaxDBBytes) — a larger (sparse) file is a
	// violation (IT-15).
	MaxDBBytes int64
	Log        *slog.Logger
}

// Driver is the compose driver: it implements the infrastructure operations of apps/agent's Driver interface up to
// §11.3 step 11 (EnsureInstance storage → config → network → container; status; start/stop/restart; remove). Every
// call arrives validated (agentspec), under the instance's lock (mutations) and after the guard.
type Driver struct {
	cfg Config
	// createMu serialises the creation of instance directories host-wide: uniqueness of slug, run_uid and subnet is
	// re-checked under it (the per-instance lock does not exclude two instances racing for the same values).
	createMu sync.Mutex
	// fps caches the fingerprint helper's answers per key-file identity (fileid.go).
	fps fpCache
}

// New returns a driver; every field of c but Log is required.
func New(c Config) (*Driver, error) {
	if c.Host == nil || c.Guard == nil || c.Engine == nil || c.Compose == nil || c.Edge == "" {
		return nil, errors.New("compose driver: host, guard, engine, compose runner and edge name are required")
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.EdgeNetwork == "" {
		c.EdgeNetwork = "mg-edge"
	}
	return &Driver{cfg: c}, nil
}

// Name is reported by Health.
func (d *Driver) Name() string { return "compose" }

func (d *Driver) open() (*tree, error) {
	return openTree(d.cfg.Host.TenantsDir, d.cfg.Host.OwnerUID, d.cfg.AgentGID)
}

func state(field, format string, args ...any) error {
	return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_STATE, Field: field, Msg: fmt.Sprintf(format, args...)}
}

func project(n agentspec.Names) Project {
	return Project{Name: n.Project, File: n.ComposeFile, Dir: n.Dir}
}

// ---------------------------------------------------------------------------------------------------- EnsureInstance

// EnsureInstance runs the instance up to e.Phase — storage → config → network → container (§11.3 steps 7–10), each
// phase idempotent and re-run by every later one — and returns the actual status.
func (d *Driver) EnsureInstance(ctx context.Context, e agentspec.Ensure) (*agentv1.EnsureInstanceResponse, error) {
	s := e.Spec
	n := d.cfg.Host.Names(s.Ref)
	l := newLayout(s.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	if err := d.ensureStorage(ctx, t, l, s); err != nil {
		return nil, err
	}
	resp := &agentv1.EnsureInstanceResponse{TemplateVersion: agentspec.TemplateVersion}
	var r *Rendered
	if e.Phase >= agentv1.TargetPhase_TARGET_PHASE_CONFIG {
		if r, err = d.ensureConfig(t, l, s); err != nil {
			return nil, err
		}
		resp.ConfigSha256 = r.ConfigSHA256
	}
	if e.Phase >= agentv1.TargetPhase_TARGET_PHASE_NETWORK {
		if err := d.ensureNetwork(ctx, n, s); err != nil {
			return nil, err
		}
	}
	if e.Phase >= agentv1.TargetPhase_TARGET_PHASE_CONTAINER {
		if err := d.ensureContainer(ctx, t, l, n, s, r); err != nil {
			return nil, err
		}
	}
	if resp.Status, err = d.status(ctx, t, l, n, s.Ref); err != nil {
		return nil, err
	}
	return resp, nil
}

// ensureStorage — §11.3 step 7. A new instance directory appears complete (meta first) through one rename; an
// existing one has its owners and modes corrected and missing config/, records/ re-created. data/ is created only
// with the instance: an activated instance (meta/activated) whose data/ is missing is refused, never given an empty
// data/ (a fresh Noise key and an empty, allow-all control plane on the tenant's hostname — RT-06).
func (d *Driver) ensureStorage(ctx context.Context, t *tree, l layout, s agentspec.InstanceSpec) error {
	fi, err := t.lstat(l.dir)
	if err != nil {
		return err
	}
	runUID := int(s.RunUID)
	if fi == nil {
		d.createMu.Lock()
		defer d.createMu.Unlock()
		if err := d.cfg.Guard.CheckSpec(ctx, s); err != nil {
			return err
		}
		meta, err := encodeMeta(identityMeta(s))
		if err != nil {
			return err
		}
		if err := t.createInstance(l, runUID, meta); err != nil {
			return err
		}
		d.cfg.Log.Info("instance_storage_created", "instance_id", l.id, "run_uid", runUID)
		return nil
	}
	activated, err := t.lstat(l.activatedFile)
	if err != nil {
		return err
	}
	o := t.owners(runUID)
	for _, p := range []struct {
		rel    string
		o      owner
		create bool
	}{
		{l.dir, o["dir"], false}, {l.meta, o["meta"], false},
		{l.config, o["config"], true}, {l.records, o["records"], true},
		{l.data, o["data"], activated == nil},
	} {
		changed, err := t.ensureDir(p.rel, p.o, p.create)
		if errors.Is(err, errMissing) && p.rel == l.data {
			// an activated instance lost data/: never re-created empty — a start-guard violation (§11.4)
			if m, merr := readMetaMap(t, l); merr == nil {
				d.contain(ctx, t, l, d.cfg.Host.Names(s.Ref), s.Ref, m, guardCheck{violation: reasonDataMissing}, "ensure_storage")
			}
			return state("spec.instance", "data of an activated instance is missing — never re-created empty (start guard, §11.4)")
		}
		if errors.Is(err, errMissing) {
			return state("spec.instance", "%s of an activated instance is missing — never re-created empty (start guard, §11.4)", filepath.Base(p.rel))
		}
		if err != nil {
			return err
		}
		if changed {
			d.cfg.Log.Info("instance_storage_corrected", "instance_id", l.id, "path", filepath.ToSlash(p.rel))
		}
	}
	return t.ensureFileOwner(l.metaFile, o["metaf"])
}

// ensureConfig — §11.3 step 8 without configtest (ValidateConfig runs it before): render, check the invariants, write
// atomically the files that differ, then record template_version, config_sha256 and image in meta/instance.json.
// records/extra-records.json is written ([]) only when absent: WriteDnsRecords owns it afterwards. The image of an
// existing instance is not changed here (UpgradeInstance — compare-and-swap, §11.4).
func (d *Driver) ensureConfig(t *tree, l layout, s agentspec.InstanceSpec) (*Rendered, error) {
	r, err := Render(d.cfg.Host, s)
	if err != nil {
		return nil, err
	}
	raw, err := t.readFile(l.metaFile, maxMetaBytes)
	if err != nil {
		return nil, err
	}
	m, err := decodeMeta(raw)
	if err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, Field: "spec.instance", Msg: err.Error()}
	}
	if img, ok := m["image"].(string); ok && img != r.Image {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, Field: "spec.image_digest",
			Msg: "differs from the instance's image — an image changes only through UpgradeInstance (§11.4)"}
	}
	o := t.owners(int(s.RunUID))
	var written []string
	for _, f := range []struct {
		rel     string
		content []byte
		o       owner
	}{
		{l.configFile, r.Config, o["tenant"]},
		{l.policyFile, r.Policy, o["tenant"]},
		{l.composeFile, r.Compose, o["compose"]},
	} {
		changed, err := t.writeFile(f.rel, f.content, f.o)
		if err != nil {
			return nil, err
		}
		if changed {
			written = append(written, filepath.ToSlash(f.rel))
		}
	}
	if fi, err := t.lstat(l.recordsFile); err != nil {
		return nil, err
	} else if fi == nil {
		if _, err := t.writeFile(l.recordsFile, []byte(InitialRecords), o["tenant"]); err != nil {
			return nil, err
		}
		written = append(written, filepath.ToSlash(l.recordsFile))
	} else if err := t.ensureFileOwner(l.recordsFile, o["tenant"]); err != nil {
		return nil, err
	}
	configMeta(m, r)
	meta, err := encodeMeta(m)
	if err != nil {
		return nil, err
	}
	changed, err := t.writeFile(l.metaFile, meta, o["metaf"])
	if err != nil {
		return nil, err
	}
	if changed {
		written = append(written, filepath.ToSlash(l.metaFile))
	}
	if len(written) > 0 {
		d.cfg.Log.Info("instance_config_written", "instance_id", l.id, "files", written, "config_sha256", r.ConfigSHA256,
			"template_version", agentspec.TemplateVersion)
	}
	return r, nil
}

// ensureNetwork — §11.3 step 9: mg-t-<slug>, internal, subnet net_cidr, labels meshguard.instance_id and
// meshguard.role=tenant (infrastructure/host/tenant-deploy.sh). An existing network was checked by the guard; it is
// checked again here (a network created between the guard and this call is never adopted).
func (d *Driver) ensureNetwork(ctx context.Context, n agentspec.Names, s agentspec.InstanceSpec) error {
	nw, err := d.cfg.Engine.Network(ctx, n.Network)
	if err != nil {
		return err
	}
	if nw == nil {
		labels := map[string]string{agentspec.LabelInstanceID: s.Ref.InstanceID.String(), agentspec.LabelRole: agentspec.RoleTenant}
		cerr := d.cfg.Engine.CreateNetwork(ctx, NetworkSpec{Name: n.Network, Subnet: s.NetCIDR, Labels: labels})
		if cerr == nil {
			d.cfg.Log.Info("instance_network_created", "instance_id", s.Ref.InstanceID.String(), "network", n.Network, "subnet", s.NetCIDR.String())
			return nil
		}
		// created concurrently? look again — and check it like any existing network
		if nw, err = d.cfg.Engine.Network(ctx, n.Network); err != nil || nw == nil {
			return errors.Join(cerr, err)
		}
	}
	return ownNetwork(nw, s)
}

func ownNetwork(nw *Network, s agentspec.InstanceSpec) error {
	switch {
	case nw.Labels[agentspec.LabelInstanceID] != s.Ref.InstanceID.String() || nw.Labels[agentspec.LabelRole] != agentspec.RoleTenant:
		return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, Field: "spec.instance.slug",
			Msg: fmt.Sprintf("network %s exists and is not labelled for this instance (never adopted)", nw.Name)}
	case !nw.Internal || len(nw.Subnets) != 1 || nw.Subnets[0] != s.NetCIDR:
		return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, Field: "spec.net_cidr",
			Msg: fmt.Sprintf("network %s is not internal with exactly the subnet net_cidr", nw.Name)}
	}
	return nil
}

// ensureContainer — §11.3 step 10: records/extra-records.json must be a regular file holding a JSON array, the network
// must exist, an activated instance must pass the start guard; then `compose up -d` (the image is pinned by digest in
// compose.yaml; pulled by the daemon when missing) and the container must carry this instance's labels and run
// exactly that image.
func (d *Driver) ensureContainer(ctx context.Context, t *tree, l layout, n agentspec.Names, s agentspec.InstanceSpec, r *Rendered) error {
	raw, err := t.readFile(l.recordsFile, maxRecords)
	if err != nil {
		return err
	}
	var recs []json.RawMessage
	if raw == nil || json.Unmarshal(raw, &recs) != nil || recs == nil {
		return state("spec.instance", "records/extra-records.json must be a regular file holding a JSON array (§11.3 step 10)")
	}
	nw, err := d.cfg.Engine.Network(ctx, n.Network)
	if err != nil {
		return err
	}
	if nw == nil {
		return state("spec.instance", "network %s does not exist (TARGET_PHASE_NETWORK first)", n.Network)
	}
	if err := ownNetwork(nw, s); err != nil {
		return err
	}
	// an activated instance starts only on its own data (start guard, §11.4)
	if err := d.enforceStartGuard(ctx, t, l, n, s.Ref, "compose_up"); err != nil {
		return err
	}
	uctx, cancel := context.WithTimeout(ctx, upTimeout)
	defer cancel()
	if err := d.cfg.Compose.Compose(uctx, project(n), "up", "--detach", "--no-build", "--pull", "missing", "--quiet-pull"); err != nil {
		return err
	}
	c, err := d.cfg.Engine.Container(ctx, n.Container)
	if err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("container %s does not exist after compose up", n.Container)
	}
	if err := ownContainer(c, n, s.Ref); err != nil {
		return err
	}
	if c.Image != r.Image {
		return fmt.Errorf("container %s runs another image than compose.yaml", n.Container)
	}
	d.cfg.Log.Info("instance_compose_up", "instance_id", l.id, "project", n.Project, "container_state", c.State)
	return nil
}

func ownContainer(c *Container, n agentspec.Names, ref agentspec.Ref) error {
	if c.Labels[agentspec.LabelInstanceID] != ref.InstanceID.String() || c.Labels[agentspec.LabelTenantID] != ref.TenantID.String() ||
		c.Labels[agentspec.LabelComposeProject] != n.Project {
		return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, Field: "instance.slug",
			Msg: fmt.Sprintf("container %s is not labelled for this instance (never adopted)", c.Name)}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- lifecycle

// lifecycle runs one compose command on an existing container of the instance.
func (d *Driver) lifecycle(ctx context.Context, c agentspec.Call, timeout time.Duration, args ...string) (*agentv1.InstanceStatus, error) {
	n := d.cfg.Host.Names(c.Ref)
	l := newLayout(c.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	ctr, err := d.cfg.Engine.Container(ctx, n.Container)
	if err != nil {
		return nil, err
	}
	switch {
	case ctr == nil && args[0] == "stop":
		// nothing to stop: idempotent
	case ctr == nil:
		return nil, state("instance", "container %s does not exist (EnsureInstance with TARGET_PHASE_CONTAINER)", n.Container)
	default:
		if err := ownContainer(ctr, n, c.Ref); err != nil {
			return nil, err
		}
		if fi, err := t.lstat(l.composeFile); err != nil {
			return nil, err
		} else if fi == nil {
			return nil, state("instance", "compose.yaml does not exist (EnsureInstance with TARGET_PHASE_CONFIG)")
		}
		if args[0] != "stop" {
			if nw, err := d.cfg.Engine.Network(ctx, n.Network); err != nil {
				return nil, err
			} else if nw == nil {
				return nil, state("instance", "network %s does not exist (EnsureInstance with TARGET_PHASE_NETWORK)", n.Network)
			}
			// an activated instance starts only on its own data (start guard, §11.4)
			if err := d.enforceStartGuard(ctx, t, l, n, c.Ref, args[0]); err != nil {
				return nil, err
			}
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := d.cfg.Compose.Compose(cctx, project(n), args...); err != nil {
			return nil, err
		}
		d.cfg.Log.Info("instance_"+args[0], "instance_id", l.id, "project", n.Project)
	}
	return d.status(ctx, t, l, n, c.Ref)
}

// StartInstance starts the existing container (`compose start`; already running ⇒ nothing changes). An activated
// instance passes the start guard first (data/ files and Noise key fingerprint — §11.4): a violation is refused and
// contained (edge_attach cleared, edge detached, container stopped, Critical event).
func (d *Driver) StartInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error) {
	return d.lifecycle(ctx, c, stopTimeout, "start")
}

// StopInstance stops the container within its stop_grace_period (`compose stop`); absent or stopped ⇒ nothing changes.
func (d *Driver) StopInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error) {
	return d.lifecycle(ctx, c, stopTimeout, "stop")
}

// RestartInstance restarts the existing container (`compose restart`; a stopped container is started) — after the
// start guard, like StartInstance.
func (d *Driver) RestartInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error) {
	return d.lifecycle(ctx, c, restartTimeout, "restart")
}

// RemoveInstance — compensation of §11.3 steps 7/9/10 and the last steps of Deprovision (§11.4): compose down (then
// any leftover container of the project labelled for this instance), remove the network, and per r.Data the
// directory. Nothing is touched when the request cannot complete: the edge still attached (RemoveEdgeAttachment
// first — the order of §11.4), a foreign member on the network, an activated instance with
// DELETE_IF_NEVER_ACTIVATED. DELETE_ARCHIVED removes the directory of an activated instance only when the final backup
// named by ArchiveSequence exists with a valid signed manifest of this very instance (P3-T11) — checked before anything
// is touched.
func (d *Driver) RemoveInstance(ctx context.Context, r agentspec.Remove) (*agentv1.RemoveInstanceResponse, error) {
	if r.Data == agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED {
		if err := d.checkFinalBackup(r); err != nil {
			return nil, err
		}
	}
	n := d.cfg.Host.Names(r.Ref)
	l := newLayout(r.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	activated, err := t.lstat(l.activatedFile)
	if err != nil {
		return nil, err
	}
	if activated != nil && r.Data == agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED {
		return nil, state("data", "the instance was activated (meta/activated): its directory is never deleted by compensation")
	}
	nw, err := d.cfg.Engine.Network(ctx, n.Network)
	if err != nil {
		return nil, err
	}
	if nw != nil {
		for _, m := range nw.Members {
			switch m {
			case n.Container:
			case d.cfg.Edge:
				return nil, state("instance", "the edge is attached to %s — RemoveEdgeAttachment first (§11.4)", n.Network)
			default:
				return nil, state("instance", "network %s has a member other than %s and the edge", n.Network, n.Container)
			}
		}
	}
	out := &agentv1.RemoveInstanceResponse{}
	before, err := d.projectContainers(ctx, n, r.Ref)
	if err != nil {
		return nil, err
	}
	out.ContainerRemoved = len(before) > 0
	if fi, err := t.lstat(l.composeFile); err != nil {
		return nil, err
	} else if fi != nil && fi.Mode().IsRegular() {
		dctx, cancel := context.WithTimeout(ctx, downTimeout)
		err := d.cfg.Compose.Compose(dctx, project(n), "down", "--remove-orphans")
		cancel()
		if err != nil {
			return nil, err
		}
	}
	// leftovers (compose.yaml missing, an interrupted down): containers of the project, labelled for this instance
	left, err := d.projectContainers(ctx, n, r.Ref)
	if err != nil {
		return nil, err
	}
	for _, c := range left {
		if err := d.cfg.Engine.RemoveContainer(ctx, c.Name, stopGrace); err != nil {
			return nil, err
		}
	}
	if left, err = d.projectContainers(ctx, n, r.Ref); err != nil {
		return nil, err
	} else if len(left) > 0 {
		return nil, fmt.Errorf("%d container(s) of project %s still exist after compose down", len(left), n.Project)
	}
	if nw != nil {
		if err := d.cfg.Engine.RemoveNetwork(ctx, n.Network); err != nil {
			return nil, err
		}
		out.NetworkRemoved = true
	}
	if r.Data == agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED || r.Data == agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED {
		if out.DirectoryRemoved, err = t.removeInstance(l); err != nil {
			return nil, err
		}
	}
	d.cfg.Log.Info("instance_removed", "instance_id", l.id, "data", r.Data.String(), "container_removed", out.ContainerRemoved,
		"network_removed", out.NetworkRemoved, "directory_removed", out.DirectoryRemoved)
	return out, nil
}

// projectContainers lists the containers named mg-hs-<slug> or belonging to project mg-t-<slug>; every one must carry
// this instance's labels (the guard checked them before the call; a container appearing since is refused too).
func (d *Driver) projectContainers(ctx context.Context, n agentspec.Names, ref agentspec.Ref) ([]Container, error) {
	ctrs, err := d.cfg.Engine.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var out []Container
	for _, c := range ctrs {
		if c.Name == n.Container || c.Labels[agentspec.LabelComposeProject] == n.Project {
			if err := ownContainer(&c, n, ref); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}
