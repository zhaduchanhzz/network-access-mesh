package runner

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
)

// newReconcile builds the report-only reconcile of the worker (P3-T12, §11.4): the Host Agent client the worker opened
// once (newAgent — shared with the Tenant Orchestrator), the worker's Headscale registry for the API key lists, and the security
// events written in platform transactions of the worker's store (platformSecurity). Without an agent the jobs still
// run and report agent_unavailable.
func newReconcile(d *deps, agent *agentclient.Client, reg prometheus.Registerer) (*reconcile.Service, error) {
	rc := reconcile.Config{Security: platformSecurity{st: d.st}, Logger: d.log, Registerer: reg}
	if d.headscale != nil {
		rc.Headscale = d.headscale
	}
	if agent != nil {
		rc.Agent = agent
	} else {
		d.log.Warn("reconcile: no Host Agent configured (MG_AGENT_SOCKET, MG_AGENT_TOKEN_FILE) — the agent checks of " +
			"instance.reconcile and host.reconcile report agent_unavailable")
	}
	return reconcile.New(d.st, rc)
}
