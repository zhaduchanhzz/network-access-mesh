package runner

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
)

// newReconcile builds the report-only reconcile of the worker (P3-T12, §11.4): the Host Agent through agentclient when
// MG_AGENT_SOCKET/MG_AGENT_TOKEN_FILE are set (the token is read once here: a missing or malformed token file fails
// the start like every other secret file), the worker's Headscale registry for the API key lists, and the security
// events written in platform transactions of the worker's store (platformSecurity). Without an agent the jobs still
// run and report agent_unavailable.
func newReconcile(cfg config.Config, d *deps, reg prometheus.Registerer) (*reconcile.Service, error) {
	rc := reconcile.Config{Security: platformSecurity{st: d.st}, Logger: d.log, Registerer: reg}
	if d.headscale != nil {
		rc.Headscale = d.headscale
	}
	if cfg.Agent.Configured() {
		c, err := agentclient.New(agentclient.Config{Socket: cfg.Agent.Socket, TokenFile: cfg.Agent.TokenFile})
		if err != nil {
			return nil, err
		}
		d.closers = append(d.closers, func() { _ = c.Close() })
		rc.Agent = c
	} else {
		d.log.Warn("reconcile: no Host Agent configured (MG_AGENT_SOCKET, MG_AGENT_TOKEN_FILE) — the agent checks of " +
			"instance.reconcile and host.reconcile report agent_unavailable")
	}
	return reconcile.New(d.st, rc)
}
