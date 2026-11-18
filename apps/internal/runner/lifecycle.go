package runner

import (
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
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
