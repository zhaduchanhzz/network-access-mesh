package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

var containerStates = map[string]agentv1.ContainerState{
	"created":    agentv1.ContainerState_CONTAINER_STATE_CREATED,
	"running":    agentv1.ContainerState_CONTAINER_STATE_RUNNING,
	"paused":     agentv1.ContainerState_CONTAINER_STATE_PAUSED,
	"restarting": agentv1.ContainerState_CONTAINER_STATE_RESTARTING,
	"removing":   agentv1.ContainerState_CONTAINER_STATE_EXITED,
	"exited":     agentv1.ContainerState_CONTAINER_STATE_EXITED,
	"dead":       agentv1.ContainerState_CONTAINER_STATE_DEAD,
}

var healthStates = map[string]agentv1.HealthState{
	"":          agentv1.HealthState_HEALTH_STATE_NONE,
	"starting":  agentv1.HealthState_HEALTH_STATE_STARTING,
	"healthy":   agentv1.HealthState_HEALTH_STATE_HEALTHY,
	"unhealthy": agentv1.HealthState_HEALTH_STATE_UNHEALTHY,
}

// InstanceStatus reports the actual state (§11.3 step 11 health gate, §11.4 reconcile and start guard): container,
// health, image digest, config hash and template version, network and its members, owner/mode of every managed
// path, meta/activated and the edge_attach flag. The API keys (a CLI call inside the container) and the Noise key
// fingerprint (a one-shot helper container) arrive with P3-T03.
func (d *Driver) InstanceStatus(ctx context.Context, ref agentspec.Ref, includeAPIKeys bool) (*agentv1.InstanceStatus, error) {
	if includeAPIKeys {
		return nil, status.Error(codes.Unimplemented, "include_api_keys needs the CLI inside the container (P3-T03)")
	}
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	return d.status(ctx, t, newLayout(ref.InstanceID.String()), d.cfg.Host.Names(ref), ref)
}

func (d *Driver) status(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref) (*agentv1.InstanceStatus, error) {
	st := &agentv1.InstanceStatus{
		Instance:       &agentv1.InstanceRef{InstanceId: ref.InstanceID.String(), TenantId: ref.TenantID.String(), Slug: ref.Slug},
		ContainerState: agentv1.ContainerState_CONTAINER_STATE_ABSENT,
		Health:         agentv1.HealthState_HEALTH_STATE_NONE,
		Network:        &agentv1.NetworkState{},
	}
	c, err := d.cfg.Engine.Container(ctx, n.Container)
	if err != nil {
		return nil, err
	}
	if c != nil {
		st.ContainerId = c.ID
		if s, ok := containerStates[c.State]; ok {
			st.ContainerState = s
		} else {
			st.ContainerState = agentv1.ContainerState_CONTAINER_STATE_UNSPECIFIED
		}
		st.Health = healthStates[c.Health]
		if !c.StartedAt.IsZero() {
			st.StartedAt = timestamppb.New(c.StartedAt)
		}
		if _, digest, ok := strings.Cut(c.Image, "@"); ok {
			st.ImageDigest = digest
		}
	}
	nw, err := d.cfg.Engine.Network(ctx, n.Network)
	if err != nil {
		return nil, err
	}
	if nw != nil {
		st.Network.Exists, st.Network.Internal, st.Network.Members = true, nw.Internal, nw.Members
		if len(nw.Subnets) == 1 {
			st.Network.Subnet = nw.Subnets[0].String()
		}
		for _, m := range nw.Members {
			if m == d.cfg.Edge {
				st.Network.EdgeAttached = true
			}
		}
	}
	if cfg, err := t.readFile(l.configFile, maxRecords); err == nil && cfg != nil {
		sum := sha256.Sum256(cfg)
		st.ConfigSha256 = hex.EncodeToString(sum[:])
	}
	if raw, err := t.readFile(l.metaFile, maxMetaBytes); err == nil && raw != nil {
		if m, err := decodeMeta(raw); err == nil {
			if v, ok := m["template_version"].(string); ok {
				if tv, err := strconv.ParseUint(v, 10, 32); err == nil {
					st.TemplateVersion = uint32(tv)
				}
			}
			st.EdgeAttachFlag, _ = m["edge_attach"].(bool)
		}
	}
	if fi, err := t.lstat(l.activatedFile); err == nil && fi != nil {
		st.Activated = true
	}
	for _, p := range []struct {
		kind agentv1.PathKind
		rel  string
	}{
		{agentv1.PathKind_PATH_KIND_INSTANCE_DIR, l.dir}, {agentv1.PathKind_PATH_KIND_CONFIG_DIR, l.config},
		{agentv1.PathKind_PATH_KIND_RECORDS_DIR, l.records}, {agentv1.PathKind_PATH_KIND_DATA_DIR, l.data},
		{agentv1.PathKind_PATH_KIND_META_DIR, l.meta}, {agentv1.PathKind_PATH_KIND_COMPOSE_FILE, l.composeFile},
		{agentv1.PathKind_PATH_KIND_CONFIG_FILE, l.configFile}, {agentv1.PathKind_PATH_KIND_POLICY_FILE, l.policyFile},
		{agentv1.PathKind_PATH_KIND_RECORDS_FILE, l.recordsFile}, {agentv1.PathKind_PATH_KIND_META_FILE, l.metaFile},
	} {
		ps := &agentv1.PathState{Kind: p.kind}
		fi, err := t.lstat(p.rel)
		if err != nil {
			return nil, err
		}
		if fi != nil {
			ps.Exists = true
			if uid, gid, ok := fileOwner(fi); ok {
				ps.Uid, ps.Gid = uint32(uid), uint32(gid) //nolint:gosec // G115: owners of files are non-negative 32-bit ids
			}
			ps.Mode = uint32(fi.Mode().Perm() | fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky|fs.ModeSymlink))
		}
		st.Paths = append(st.Paths, ps)
	}
	return st, nil
}

// ListInstances is the inventory of the host (reconcile, §17.2): every instance directory (UUID name), every
// container and network labelled meshguard.instance_id. Orphans are reported — a directory whose meta cannot be read
// with its id only — never adopted.
func (d *Driver) ListInstances(ctx context.Context) ([]*agentv1.InventoryEntry, error) {
	byID := map[string]*agentv1.InventoryEntry{}
	entry := func(id string) *agentv1.InventoryEntry {
		if e, ok := byID[id]; ok {
			return e
		}
		e := &agentv1.InventoryEntry{InstanceId: id}
		byID[id] = e
		return e
	}
	dir, err := os.OpenRoot(d.cfg.Host.TenantsDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		id, err := agentspec.UUID("", name)
		if err != nil {
			continue
		}
		e := entry(name)
		e.HasDirectory = true
		if m, err := d.cfg.Guard.ReadMeta(id); err == nil && m != nil {
			e.TenantId, e.Slug = m.Ref.TenantID.String(), m.Ref.Slug
		}
	}
	ctrs, err := d.cfg.Engine.Containers(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range ctrs {
		id := c.Labels[agentspec.LabelInstanceID]
		if agentspecUUID(id) != nil {
			continue
		}
		e := entry(id)
		e.HasContainer = true
		if e.TenantId == "" && agentspecUUID(c.Labels[agentspec.LabelTenantID]) == nil {
			e.TenantId = c.Labels[agentspec.LabelTenantID]
		}
		if e.Slug == "" {
			e.Slug = strings.TrimPrefix(c.Labels[agentspec.LabelComposeProject], "mg-t-")
		}
	}
	nets, err := d.cfg.Engine.Networks(ctx)
	if err != nil {
		return nil, err
	}
	for _, nw := range nets {
		id := nw.Labels[agentspec.LabelInstanceID]
		if agentspecUUID(id) != nil {
			continue
		}
		e := entry(id)
		e.HasNetwork = true
		if e.Slug == "" {
			e.Slug = strings.TrimPrefix(nw.Name, "mg-t-")
		}
	}
	out := make([]*agentv1.InventoryEntry, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].InstanceId < out[b].InstanceId })
	return out, nil
}

// agentspecUUID: nil when s is a canonical lower-case UUID (labels are written by the agent; anything else is skipped).
func agentspecUUID(s string) error {
	_, err := agentspec.UUID("label", s)
	return err
}
