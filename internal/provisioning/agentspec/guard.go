package agentspec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// NetworkInfo is what the guard needs to know about one Docker network.
type NetworkInfo struct {
	Name     string
	Labels   map[string]string
	Subnets  []netip.Prefix
	Internal bool
	Members  []Member
}

// Member is one container attached to a network, with its network-scoped aliases (DNS names).
type Member struct {
	Container string
	Aliases   []string
}

// ContainerInfo is what the guard needs to know about one container (running or not).
type ContainerInfo struct {
	Name   string
	Labels map[string]string
}

// Inventory is the read-only view of Docker the guard checks against. The compose driver (P3-T02,
// internal/provisioning/driver/compose: NewInventory) implements it with the Docker Engine API; tests use a fake. Every container and network of the host is listed, not only labelled
// ones: an unlabelled object with a derived name must be refused, not missed.
type Inventory interface {
	Networks(ctx context.Context) ([]NetworkInfo, error)
	Containers(ctx context.Context) ([]ContainerInfo, error)
}

// Meta is the identity part of meta/instance.json — the file the agent itself writes (root:root 0400 in meta/,
// root:root 0700; same keys as tools/render_instance.py, other keys are allowed for later versions).
type Meta struct {
	Ref     Ref
	RunUID  uint32
	NetCIDR netip.Prefix
}

// Guard checks, before anything is touched, that the objects an operation would touch belong to the instance it
// names (§11.1: "FAIL, không adopt").
type Guard struct {
	Host *Host
	// Inventory is the Docker view; nil only with MG_AGENT_DRIVER=none (no Docker access): then only the filesystem is
	// checked.
	Inventory Inventory
	// Edge is the container name of the shared edge (mg-edge).
	Edge string
}

const (
	maxMetaBytes = 64 << 10
	maxInstances = 4096
)

// ---------------------------------------------------------------------------------------------------- filesystem

// ReadMeta returns the identity recorded in <tenants>/<id>/meta/instance.json, or nil when the instance directory
// does not exist. Every path is resolved inside the tenants directory (os.Root: no escape through "..", absolute
// symlinks or symlinks pointing outside), and symlinks are refused outright.
func (g *Guard) ReadMeta(id uuid.UUID) (*Meta, error) {
	root, err := os.OpenRoot(g.Host.TenantsDir)
	if err != nil {
		return nil, fmt.Errorf("tenants directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	return g.readMeta(root, id.String())
}

func (g *Guard) readMeta(root *os.Root, name string) (*Meta, error) {
	unsafe := func(what string) error {
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, "instance", "%s of instance %s: %s", what, name, "symlink, wrong type, owner or mode")
	}
	fi, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("instance directory %s: %w", name, err)
	}
	if !fi.IsDir() || !g.agentOwned(fi) {
		return nil, unsafe("instance directory")
	}
	metaDir := filepath.Join(name, "meta")
	fi, err = root.Lstat(metaDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, refuse(agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "instance",
			"instance directory %s has no meta/ — not created by the agent (never adopted)", name)
	}
	if err != nil {
		return nil, fmt.Errorf("meta directory of %s: %w", name, err)
	}
	if !fi.IsDir() || !g.agentOwned(fi) {
		return nil, unsafe("meta/")
	}
	file := filepath.Join(metaDir, "instance.json")
	fi, err = root.Lstat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, refuse(agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "instance",
			"instance directory %s has no meta/instance.json — not created by the agent (never adopted)", name)
	}
	if err != nil {
		return nil, fmt.Errorf("meta of %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() || !g.agentOwned(fi) || fi.Size() > maxMetaBytes {
		return nil, unsafe("meta/instance.json")
	}
	f, err := root.Open(file)
	if err != nil {
		return nil, fmt.Errorf("meta of %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxMetaBytes+1))
	if err != nil {
		return nil, fmt.Errorf("meta of %s: %w", name, err)
	}
	m, err := parseMeta(raw)
	if err != nil {
		return nil, refuse(agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, "instance", "meta/instance.json of %s: %v", name, err)
	}
	if m.Ref.InstanceID.String() != name {
		return nil, refuse(agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, "instance",
			"meta/instance.json of directory %s names another instance", name)
	}
	return m, nil
}

// agentOwned: owned by the agent's UID and not writable by group or others — a tenant process (run_uid) can never
// have written it.
func (g *Guard) agentOwned(fi fs.FileInfo) bool {
	uid, ok := fileOwner(fi)
	return ok && uid == g.Host.OwnerUID && fi.Mode().Perm()&0o022 == 0
}

func parseMeta(raw []byte) (*Meta, error) {
	if len(raw) > maxMetaBytes {
		return nil, errors.New("too large")
	}
	var f struct {
		InstanceID *string `json:"instance_id"`
		TenantID   *string `json:"tenant_id"`
		Slug       *string `json:"slug"`
		RunUID     *int64  `json:"run_uid"`
		NetCIDR    *string `json:"net_cidr"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, errors.New("not a JSON object with the expected key types")
	}
	if f.InstanceID == nil || f.TenantID == nil || f.Slug == nil || f.RunUID == nil || f.NetCIDR == nil {
		return nil, errors.New("missing instance_id, tenant_id, slug, run_uid or net_cidr")
	}
	var m Meta
	var err error
	if m.Ref.InstanceID, err = UUID("instance_id", *f.InstanceID); err != nil {
		return nil, errors.New("instance_id")
	}
	if m.Ref.TenantID, err = UUID("tenant_id", *f.TenantID); err != nil {
		return nil, errors.New("tenant_id")
	}
	if !slugRE.MatchString(*f.Slug) {
		return nil, errors.New("slug")
	}
	m.Ref.Slug = *f.Slug
	if *f.RunUID <= 0 || *f.RunUID > 1<<31-1 {
		return nil, errors.New("run_uid")
	}
	m.RunUID = uint32(*f.RunUID)
	if m.NetCIDR, err = netip.ParsePrefix(*f.NetCIDR); err != nil || !m.NetCIDR.Addr().Is4() || m.NetCIDR != m.NetCIDR.Masked() {
		return nil, errors.New("net_cidr")
	}
	return &m, nil
}

// Instances reads the meta of every instance directory (canonical UUID names; other entries are ignored). One
// unreadable or foreign instance directory fails the whole scan: uniqueness of run_uid, slug and subnet cannot be
// proven without it (fail closed).
func (g *Guard) Instances() ([]Meta, error) {
	root, err := os.OpenRoot(g.Host.TenantsDir)
	if err != nil {
		return nil, fmt.Errorf("tenants directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	d, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("tenants directory: %w", err)
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return nil, fmt.Errorf("tenants directory: %w", err)
	}
	if len(entries) > maxInstances {
		return nil, fmt.Errorf("tenants directory: more than %d entries", maxInstances)
	}
	var out []Meta
	for _, e := range entries {
		if _, err := UUID("", e.Name()); err != nil {
			continue
		}
		m, err := g.readMeta(root, e.Name())
		if r, ok := AsRefusal(err); ok {
			return nil, refuse(r.Reason, "inventory", "%s", r.Msg)
		}
		if err != nil {
			return nil, err
		}
		if m != nil {
			out = append(out, *m)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------- checks

// CheckSpec runs before ValidateConfig and EnsureInstance: the directory, if any, must be this instance's and keep
// its immutable run_uid and net_cidr; no other instance may use the slug, the run_uid or an overlapping subnet; the
// Docker objects with the derived names must carry this instance's labels and the network its subnet.
func (g *Guard) CheckSpec(ctx context.Context, s InstanceSpec) error {
	metas, err := g.Instances()
	if err != nil {
		return err
	}
	for _, m := range metas {
		if m.Ref.InstanceID == s.Ref.InstanceID {
			if err := sameIdentity("spec.instance", m, s.Ref); err != nil {
				return err
			}
			if m.RunUID != s.RunUID {
				return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "spec.run_uid", "differs from the instance's run_uid (immutable)")
			}
			if m.NetCIDR != s.NetCIDR {
				return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "spec.net_cidr", "differs from the instance's net_cidr (immutable)")
			}
			continue
		}
		switch {
		case m.Ref.Slug == s.Ref.Slug:
			return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "spec.instance.slug", "used by instance %s", m.Ref.InstanceID)
		case m.RunUID == s.RunUID:
			return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "spec.run_uid", "used by instance %s", m.Ref.InstanceID)
		case m.NetCIDR.Overlaps(s.NetCIDR):
			return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "spec.net_cidr", "overlaps the subnet of instance %s", m.Ref.InstanceID)
		}
	}
	return g.checkDocker(ctx, "spec.instance", "spec.net_cidr", s.Ref, s.NetCIDR)
}

// CheckRef runs before every call on an existing instance. With mustExist, the instance directory must exist
// (otherwise NOT_FOUND); whenever it exists its meta must match ref. Docker objects with the derived names must
// carry this instance's labels.
func (g *Guard) CheckRef(ctx context.Context, ref Ref, mustExist bool) (*Meta, error) {
	m, err := g.ReadMeta(ref.InstanceID)
	if err != nil {
		return nil, err
	}
	var cidr netip.Prefix
	switch {
	case m == nil && mustExist:
		return nil, refuse(agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, "instance.instance_id", "no instance directory with meta/instance.json")
	case m != nil:
		if err := sameIdentity("instance", *m, ref); err != nil {
			return nil, err
		}
		cidr = m.NetCIDR
	}
	return m, g.checkDocker(ctx, "instance", "instance", ref, cidr)
}

func sameIdentity(field string, m Meta, ref Ref) error {
	switch {
	case m.Ref.TenantID != ref.TenantID:
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, join(field, "tenant_id"), "differs from meta/instance.json")
	case m.Ref.Slug != ref.Slug:
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, join(field, "slug"), "differs from meta/instance.json")
	}
	return nil
}

func (g *Guard) checkDocker(ctx context.Context, field, cidrField string, ref Ref, cidr netip.Prefix) error {
	if g.Inventory == nil {
		return nil
	}
	n := g.Host.Names(ref)
	id, tenant := ref.InstanceID.String(), ref.TenantID.String()
	nets, err := g.Inventory.Networks(ctx)
	if err != nil {
		return fmt.Errorf("inventory of networks: %w", err)
	}
	for _, nw := range nets {
		switch {
		case nw.Name == n.Network:
			if nw.Labels[LabelInstanceID] != id || nw.Labels[LabelRole] != RoleTenant {
				return refuse(agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, join(field, "slug"),
					"network %s exists and is not labelled for this instance (never adopted)", n.Network)
			}
			if !nw.Internal {
				return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, join(field, "slug"), "network %s is not internal", n.Network)
			}
			if cidr.IsValid() && (len(nw.Subnets) != 1 || nw.Subnets[0] != cidr) {
				return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, cidrField, "network %s has another subnet", n.Network)
			}
		case nw.Labels[LabelInstanceID] == id:
			return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, join(field, "instance_id"),
				"network %s carries this instance's label under another name", nw.Name)
		case cidr.IsValid():
			for _, sn := range nw.Subnets {
				if sn.Overlaps(cidr) {
					return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, cidrField, "overlaps network %s", nw.Name)
				}
			}
		}
	}
	ctrs, err := g.Inventory.Containers(ctx)
	if err != nil {
		return fmt.Errorf("inventory of containers: %w", err)
	}
	for _, c := range ctrs {
		switch {
		case c.Name == n.Container, c.Labels[LabelComposeProject] == n.Project:
			if c.Labels[LabelInstanceID] != id || c.Labels[LabelTenantID] != tenant || c.Labels[LabelComposeProject] != n.Project {
				return refuse(agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, join(field, "slug"),
					"container %s exists and is not labelled for this instance (never adopted)", c.Name)
			}
		case c.Labels[LabelInstanceID] == id:
			return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, join(field, "instance_id"),
				"container %s carries this instance's label under another name", c.Name)
		}
	}
	return nil
}

// CheckEdgeAttach runs before the edge is attached to a tenant network (§11.3 step 14, §11.4 edge supervisor): the
// alias hs-<slug> must not exist on any other network the edge is attached to, and the tenant network may hold only
// the instance's container and the edge.
func (g *Guard) CheckEdgeAttach(ctx context.Context, ref Ref) error {
	if g.Inventory == nil {
		return nil
	}
	n := g.Host.Names(ref)
	nets, err := g.Inventory.Networks(ctx)
	if err != nil {
		return fmt.Errorf("inventory of networks: %w", err)
	}
	var own *NetworkInfo
	for i, nw := range nets {
		if nw.Name == n.Network {
			own = &nets[i]
			continue
		}
		if !slices.ContainsFunc(nw.Members, func(m Member) bool { return m.Container == g.Edge }) {
			continue
		}
		for _, m := range nw.Members {
			if m.Container == n.Alias || slices.Contains(m.Aliases, n.Alias) {
				return refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "instance.slug",
					"alias %s already exists on network %s of the edge", n.Alias, nw.Name)
			}
		}
	}
	if own == nil {
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_STATE, "instance.slug", "network %s does not exist", n.Network)
	}
	if own.Labels[LabelInstanceID] != ref.InstanceID.String() {
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "instance.slug", "network %s is not labelled for this instance", n.Network)
	}
	hasInstance := false
	for _, m := range own.Members {
		switch m.Container {
		case n.Container:
			hasInstance = true
		case g.Edge:
		default:
			return refuse(agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "instance.slug",
				"network %s has a member other than %s and the edge", n.Network, n.Container)
		}
	}
	if !hasInstance {
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_STATE, "instance.slug", "container %s is not attached to %s", n.Container, n.Network)
	}
	return nil
}
