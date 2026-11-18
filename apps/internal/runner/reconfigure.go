package runner

import (
	probe "github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
)

// newReconfigurer builds instance.reconfigure (P3-T13, §11.4) over the worker's dependencies: the registry (DBStore),
// the Host Agent client shared with reconcile and the orchestrator (typed RPCs only), the Headscale registry (CheckPolicy,
// GET /api/v1/health, the post-start gate) and — when MG_PROBER_URL is set — the prober of the short edge.verify (without
// it the step is recorded skipped). nil (and a warning) without a Host Agent: the jobs then stay queued.
func newReconfigurer(cfg config.Config, d *deps, agent *agentclient.Client) (*orchestrator.InstanceReconfigurer, error) {
	if agent == nil {
		d.log.Warn("instance.reconfigure is not run by this worker: the Host Agent (MG_AGENT_*) is not configured — " +
			"POST /platform/instances/{id}/reconfigure jobs stay queued until a configured worker takes them")
		return nil, nil
	}
	pc := cfg.Provisioning
	rc := orchestrator.ReconfigureConfig{Store: orchestrator.NewDBStore(d.st, nil), Agent: agent, Headscale: d.headscale,
		Security: platformSecurity{st: d.st}, Logger: d.log, EdgeAddress: pc.EdgeAddr}
	if pc.ProberURL != "" {
		c, err := probe.NewClient(pc.ProberURL, nil)
		if err != nil {
			return nil, err
		}
		rc.Prober = probeAdapter{c}
	}
	r, err := orchestrator.NewReconfigurer(rc)
	if err != nil {
		return nil, err
	}
	d.log.Info("instance reconfiguration configured", "prober", rc.Prober != nil, "edge", pc.EdgeAddr)
	return r, nil
}
