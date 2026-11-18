package runner

import (
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
)

// newLifecycle builds tenant.suspend and tenant.resume (P3-T08, §11.4) for the worker: a Headscale registry of their own
// whose locator reaches the instance of a SUSPENDED tenant (lifecycle.ReachableStatuses — the registry every other job
// and the api use refuses it, G2 L1, and must keep doing so), the policy core over that registry, and the handler. Only
// these two jobs get it: TestWiringKeepsDefaults allows TenantStatuses in this file only, with exactly that list.
func newLifecycle(cfg config.Config, d *deps) (*lifecycle.Handler, error) {
	loc, err := locator.New(d.tenants, d.secrets, locator.Options{AdminURL: cfg.Edge.URL, EdgeTokenFile: cfg.Edge.TokenFile,
		TenantStatuses: lifecycle.ReachableStatuses, Logger: d.log})
	if err != nil {
		return nil, err
	}
	reg := headscale.NewRegistry(loc, headscale.Options{Logger: d.log})
	core, err := policies.New(d.st, policies.Config{Registry: reg, Logger: d.log})
	if err != nil {
		return nil, err
	}
	return lifecycle.New(lifecycle.Config{Store: d.st, Policies: core, Headscale: reg, Logger: d.log})
}
