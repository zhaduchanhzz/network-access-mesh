package runner

import (
	probe "github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
)

// reachableRegistry is a Headscale registry whose locator reaches the instance of a SUSPENDED tenant
// (lifecycle.ReachableStatuses — the registry every other job and the api use refuses it, G2 L1, and must keep doing
// so). Only the jobs that must reach it get one: tenant.suspend / tenant.resume (P3-T08) and the post-start gate of
// instance.release (P3-T18 — the instance of a suspended tenant can be quarantined and released).
// TestWiringKeepsDefaults allows TenantStatuses in this file only, exactly once, with exactly that list.
func reachableRegistry(cfg config.Config, d *deps) (*headscale.CachingRegistry, error) {
	loc, err := locator.New(d.tenants, d.secrets, locator.Options{AdminURL: cfg.Edge.URL, EdgeTokenFile: cfg.Edge.TokenFile,
		TenantStatuses: lifecycle.ReachableStatuses, Logger: d.log})
	if err != nil {
		return nil, err
	}
	return headscale.NewRegistry(loc, headscale.Options{Logger: d.log}), nil
}

// newLifecycle builds tenant.suspend and tenant.resume (P3-T08, §11.4) for the worker: a registry of their own that
// reaches a suspended tenant's instance (reachableRegistry), the policy core over that registry, and the handler.
func newLifecycle(cfg config.Config, d *deps) (*lifecycle.Handler, error) {
	reg, err := reachableRegistry(cfg, d)
	if err != nil {
		return nil, err
	}
	core, err := policies.New(d.st, policies.Config{Registry: reg, Logger: d.log})
	if err != nil {
		return nil, err
	}
	return lifecycle.New(lifecycle.Config{Store: d.st, Policies: core, Headscale: reg, Logger: d.log})
}

// reachable is the reachable registry (reachableRegistry — a suspended tenant's instance too) and the policy core over
// it, for instance.restart and instance.upgrade (P3-T13a).
func reachable(cfg config.Config, d *deps) (*headscale.CachingRegistry, *policies.Service, error) {
	reg, err := reachableRegistry(cfg, d)
	if err != nil {
		return nil, nil, err
	}
	core, err := policies.New(d.st, policies.Config{Registry: reg, Logger: d.log})
	if err != nil {
		return nil, nil, err
	}
	return reg, core, nil
}

// newInstanceOps builds instance.restart and instance.upgrade (P3-T13a, §11.4) for the worker: the Host Agent client
// shared with the other jobs (typed RPCs), a registry of their own that reaches suspended tenants too (the instance of a
// suspended tenant keeps running and is restarted or upgraded like any other; its post-start gate re-applies the
// suspension policy), the policy core over it (drift_repair), the backup subsystem (cold backup, rollback by restore)
// and, when MG_PROBER_URL is set, the prober of the short edge.verify. nil (and a warning) without a Host Agent: the
// jobs then stay queued.
func newInstanceOps(cfg config.Config, d *deps, agent *agentclient.Client, bk *backup.Service) (*orchestrator.InstanceRestarter,
	*orchestrator.InstanceUpgrader, error) {
	if agent == nil {
		d.log.Warn("instance.restart and instance.upgrade are not run by this worker: the Host Agent (MG_AGENT_*) is not " +
			"configured — their jobs stay queued until a configured worker takes them")
		return nil, nil, nil
	}
	reg, core, err := reachable(cfg, d)
	if err != nil {
		return nil, nil, err
	}
	pc := cfg.Provisioning
	oc := orchestrator.InstanceOpsConfig{Store: orchestrator.NewDBStore(d.st, nil), Agent: agent, Headscale: reg, Policies: core,
		Backups: bk, Security: platformSecurity{st: d.st}, Logger: d.log, EdgeAddress: pc.EdgeAddr}
	if pc.ProberURL != "" {
		c, err := probe.NewClient(pc.ProberURL, nil)
		if err != nil {
			return nil, nil, err
		}
		oc.Prober = probeAdapter{c}
	}
	rs, err := orchestrator.NewRestarter(oc)
	if err != nil {
		return nil, nil, err
	}
	up, err := orchestrator.NewUpgrader(oc)
	if err != nil {
		return nil, nil, err
	}
	d.log.Info("instance restart and upgrade configured", "prober", oc.Prober != nil, "backups", cfg.Backup.Enabled())
	return rs, up, nil
}
