package orchestrator

import (
	"errors"
	"math"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// Bounds the agent enforces on the resource limits (agentspec, P3-T01): out-of-range plan values are clamped to them
// rather than refused by the agent at step 7.
const (
	minMemoryMiB, maxMemoryMiB = 64, 16384
	minCPUMillis, maxCPUMillis = 100, 16000
	minPIDs, maxPIDs           = 32, 4096
)

// instanceSpec is the typed InstanceSpec of steps 7–10 (§11.1): identifiers, the pinned image, run_uid, net_cidr,
// limits and HeadscaleParams — no YAML, no path, no name: the agent renders and names everything itself.
func (p *Provisioner) instanceSpec(a *attempt, inst InstanceRecord) (*agentv1.InstanceSpec, error) {
	if !inst.PublicEntryIPv4.IsValid() || !inst.NetCIDR.IsValid() || inst.RunUID <= 0 {
		return nil, jobs.Permanent("registry_state", errors.New("the instance has no public entry, subnet or run_uid"))
	}
	derp := p.derpRegion(inst)
	ns := make([]string, 0, len(p.cfg.Nameservers))
	for _, a := range p.cfg.Nameservers {
		ns = append(ns, a.String())
	}
	hs := &agentv1.HeadscaleParams{NodeExpiryDays: p.cfg.NodeExpiryDays, Nameservers: ns, DerpRegionId: uint32(derp), //nolint:gosec // 900–999
		PublicEntryIpv4: inst.PublicEntryIPv4.String(), LogLevel: p.cfg.LogLevel}
	if inst.STUNPort > 0 {
		sp := uint32(inst.STUNPort) //nolint:gosec // a port
		hs.StunPort = &sp
	}
	return &agentv1.InstanceSpec{
		Instance:    &agentv1.InstanceRef{InstanceId: inst.ID.String(), TenantId: inst.TenantID.String(), Slug: a.in.Slug},
		ImageDigest: inst.ImageDigest,
		RunUid:      uint32(inst.RunUID), //nolint:gosec // > 0, checked above
		NetCidr:     inst.NetCIDR.String(),
		Limits:      p.limits(a.tenant.Instance),
		Headscale:   hs,
	}, nil
}

func (p *Provisioner) derpRegion(inst InstanceRecord) int32 {
	if inst.DERPRegionID > 0 {
		return inst.DERPRegionID
	}
	return int32(p.cfg.DERPRegionID) //nolint:gosec // 900–999
}

// limits are the plan's instance limits (PlanLimits.instance) or the defaults, within the agent's bounds.
func (p *Provisioner) limits(l InstanceLimits) *agentv1.ResourceLimits {
	return specLimits(p.cfg.MemoryMiB, p.cfg.CPUMillis, p.cfg.PIDs, l)
}

// specLimits are the plan's instance limits over the defaults mem/cpu/pids, within the agent's bounds (tenant.provision
// and the backfill of an adopted instance — P3-T14b).
func specLimits(mem, cpu, pids uint32, l InstanceLimits) *agentv1.ResourceLimits {
	if l.MemoryMB > 0 {
		mem = clamp(uint32(min(l.MemoryMB, math.MaxUint32)), minMemoryMiB, maxMemoryMiB) //nolint:gosec // bounded
	}
	if l.CPUs > 0 {
		cpu = clamp(uint32(math.Round(min(l.CPUs, 1000)*1000)), minCPUMillis, maxCPUMillis)
	}
	if l.PIDs > 0 {
		pids = clamp(uint32(min(l.PIDs, math.MaxUint32)), minPIDs, maxPIDs) //nolint:gosec // bounded
	}
	return &agentv1.ResourceLimits{MemoryMib: mem, CpuMillis: cpu, Pids: pids}
}

func clamp(v, lo, hi uint32) uint32 { return max(lo, min(v, hi)) }

// specParams is the no-secret summary of a spec stored with the configuration version (instance_config_versions.params).
func specParams(spec *agentv1.InstanceSpec) map[string]any {
	h := spec.GetHeadscale()
	out := map[string]any{
		"image_digest": spec.GetImageDigest(), "run_uid": spec.GetRunUid(), "net_cidr": spec.GetNetCidr(),
		"memory_mib": spec.GetLimits().GetMemoryMib(), "cpu_millis": spec.GetLimits().GetCpuMillis(),
		"pids": spec.GetLimits().GetPids(), "node_expiry_days": h.GetNodeExpiryDays(), "nameservers": h.GetNameservers(),
		"derp_region_id": h.GetDerpRegionId(), "public_entry_ipv4": h.GetPublicEntryIpv4(),
		"log_level": h.GetLogLevel().String(),
	}
	if h.StunPort != nil {
		out["stun_port"] = h.GetStunPort()
	}
	return out
}
