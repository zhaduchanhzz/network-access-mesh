package agentspec

import (
	"fmt"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// Plan lists, for a dry run of EnsureInstance, the actions the compose driver (internal/provisioning/driver/compose)
// performs up to phase (§11.3 steps 7–10, §14.2, §14.5) — owners, modes and names exactly as
// infrastructure/host/tenant-deploy.sh applies them. It is static: it does not look at what already exists (an ensure
// skips what is already in place and corrects owners and modes).
func (h *Host) Plan(s InstanceSpec, phase agentv1.TargetPhase) []*agentv1.PlannedAction {
	n := h.Names(s.Ref)
	root, uid := uint32(h.OwnerUID), s.RunUID //nolint:gosec // G115: OwnerUID is the agent's euid (≥ 0, checked)
	var out []*agentv1.PlannedAction
	add := func(p agentv1.TargetPhase, k agentv1.PlannedActionKind, target string, u, g, mode uint32, detail string) {
		if p <= phase {
			out = append(out, &agentv1.PlannedAction{Kind: k, Phase: p, Target: target, Uid: u, Gid: g, Mode: mode, Detail: detail})
		}
	}
	const (
		storage   = agentv1.TargetPhase_TARGET_PHASE_STORAGE
		config    = agentv1.TargetPhase_TARGET_PHASE_CONFIG
		network   = agentv1.TargetPhase_TARGET_PHASE_NETWORK
		container = agentv1.TargetPhase_TARGET_PHASE_CONTAINER
		dir       = agentv1.PlannedActionKind_PLANNED_ACTION_KIND_ENSURE_DIRECTORY
		file      = agentv1.PlannedActionKind_PLANNED_ACTION_KIND_WRITE_FILE
	)
	// storage: a new directory is assembled under a hidden name, meta/instance.json first, then renamed into place — the
	// guard never sees an instance directory without its meta
	add(storage, dir, n.Dir, root, uid, 0o750, "new: assembled under a hidden name and renamed into place (meta first)")
	add(storage, dir, n.MetaDir, root, root, 0o700, "")
	add(storage, file, n.MetaFile, root, root, 0o400, "identity: tenant_id, instance_id, slug, run_uid, net_cidr")
	add(storage, dir, n.ConfigDir, root, uid, 0o750, "")
	add(storage, dir, n.RecordsDir, root, uid, 0o750, "")
	add(storage, dir, n.DataDir, uid, uid, 0o700, "created empty with the instance only — never re-created for an activated instance (meta/activated)")
	// config: render from the agent's embedded templates, check the isolation invariants on the rendered bytes, then
	// atomic writes (tmp + fsync + rename) of what differs; headscale configtest is the ValidateConfig RPC (P3-T03)
	add(config, agentv1.PlannedActionKind_PLANNED_ACTION_KIND_VALIDATE_CONFIG, n.ConfigDir, 0, 0, 0,
		fmt.Sprintf("template v%d rendered and checked against the isolation invariants (§11.1, §11.3 step 8) before any write", TemplateVersion))
	add(config, file, n.ConfigFile, root, uid, 0o440, fmt.Sprintf("template v%d, trusted_proxies %s", TemplateVersion, s.NetCIDR))
	add(config, file, n.PolicyFile, root, uid, 0o440, "baseline deny-all")
	add(config, file, n.RecordsFile, root, uid, 0o440, "[] only when absent (WriteDnsRecords owns it afterwards)")
	add(config, file, n.ComposeFile, root, root, 0o440, fmt.Sprintf("project %s, image %s", n.Project, s.Image.Reference()))
	add(config, file, n.MetaFile, root, root, 0o400, "config_sha256, image, template_version (an image change is refused: UpgradeInstance)")
	// network: internal, explicit subnet, labelled; the edge is NOT attached here (§11.3 step 14)
	add(network, agentv1.PlannedActionKind_PLANNED_ACTION_KIND_ENSURE_NETWORK, n.Network, 0, 0, 0,
		fmt.Sprintf("--internal --subnet %s, labels %s=%s %s=%s", s.NetCIDR, LabelInstanceID, s.Ref.InstanceID, LabelRole, RoleTenant))
	// container
	add(container, agentv1.PlannedActionKind_PLANNED_ACTION_KIND_COMPOSE_UP, n.Project, uid, uid, 0,
		fmt.Sprintf("records/extra-records.json checked, then docker compose up -d: container %s, alias %s on %s, no published port, cap_drop ALL, read-only",
			n.Container, n.Alias, n.Network))
	return out
}
