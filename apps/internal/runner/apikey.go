package runner

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
)

// newAPIKeyRotation builds apikey.rotate (P3-T10, §11.4) and its schedule: a locator of its own over the worker's
// Tenant Registry and SecretStore with apikey.TenantStatuses (an instance of a suspended tenant keeps running — its key
// must not expire), the Host Agent for the fallback when MG_AGENT_SOCKET/MG_AGENT_TOKEN_FILE are set (its own client,
// like reconcile's; without it an expired or lost key fails with agent_not_configured), the worker's shared Headscale
// registry invalidated after each rotation, and the security events in platform transactions of the worker's store.
func newAPIKeyRotation(cfg config.Config, d *deps, reg prometheus.Registerer) (*apikey.Service, error) {
	loc, err := locator.New(d.tenants, d.secrets, locator.Options{AdminURL: cfg.Edge.URL, EdgeTokenFile: cfg.Edge.TokenFile,
		Logger: d.log, TenantStatuses: apikey.TenantStatuses})
	if err != nil {
		return nil, err
	}
	ac := apikey.Config{Locator: loc, Secrets: d.secrets, Security: platformSecurity{st: d.st},
		Headscale: headscale.Options{Logger: d.log}, Logger: d.log, Registerer: reg}
	if d.headscale != nil {
		ac.Invalidate = []apikey.Invalidator{d.headscale}
	}
	if cfg.Agent.Configured() {
		c, err := agentclient.New(agentclient.Config{Socket: cfg.Agent.Socket, TokenFile: cfg.Agent.TokenFile})
		if err != nil {
			return nil, err
		}
		d.closers = append(d.closers, func() { _ = c.Close() })
		ac.Agent = c
	} else {
		d.log.Warn("apikey.rotate: no Host Agent configured (MG_AGENT_SOCKET, MG_AGENT_TOKEN_FILE) — an expired or lost " +
			"instance API key cannot be re-issued (agent_not_configured); keys still valid rotate through the adapter")
	}
	return apikey.New(d.st, ac)
}
