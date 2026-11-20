package runner

import (
	"context"

	probe "github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/members"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
)

// newAgent opens the worker's client of the Host Agent once — reconcile (P3-T12) and the Tenant Orchestrator (P3-T05)
// share it — from the shared configuration (config.AgentClient: MG_AGENT_SOCKET, MG_AGENT_TOKEN_FILE). The token is
// read here: a missing or malformed token file fails the start like every other secret file. nil without an agent.
func newAgent(cfg config.Config, d *deps) (*agentclient.Client, error) {
	if !cfg.Agent.Configured() {
		return nil, nil
	}
	c, err := agentclient.New(agentclient.Config{Socket: cfg.Agent.Socket, TokenFile: cfg.Agent.TokenFile})
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, func() { _ = c.Close() })
	return c, nil
}

// newProvisioner builds tenant.provision (P3-T05, §11.3) over the worker's dependencies: the registry (DBStore,
// platform.Placer), the SecretStore, the IdP drivers, the Headscale registry, the Host Agent (typed RPCs only), the DNS
// check of step 4 (net resolver, or skipped on the dev/ci stack) and the prober of steps 17/18 (MG_PROBER_URL — without
// it the job stops failed_resumable at step 17). nil (and a warning) when the orchestrator is not configured.
func newProvisioner(cfg config.Config, d *deps, agent *agentclient.Client, idps *idp.Registry) (*orchestrator.Provisioner, error) {
	pc := cfg.Provisioning
	if !pc.Enabled() || agent == nil {
		d.log.Warn("tenant.provision is not run by this worker: MG_PROVISION_* or the Host Agent (MG_AGENT_*) is not " +
			"configured — POST /platform/tenants jobs stay queued until a configured worker takes them")
		return nil, nil
	}
	placer, err := platform.NewPlacer(d.st, platform.PlacerOptions{BaseDomain: cfg.BaseDomain})
	if err != nil {
		return nil, err
	}
	// G4b-E1: the Owner invitation of step 16 also creates the Owner's account at a platform-hosted IdP (member.idp_invite)
	dbs := orchestrator.NewDBStore(d.st, nil).WithOwnerInvite(members.IdPInviteNotifier{})
	oc := orchestrator.Config{Store: dbs, Agent: agent, Placer: placer, Secrets: d.secrets,
		IdP: idps, Headscale: d.headscale, Security: platformSecurity{st: d.st}, Logger: d.log,
		HeadscaleDigest: pc.HeadscaleDigest, HeadscaleVersion: pc.HeadscaleVersion, Nameservers: pc.Nameservers,
		EdgeAddress: pc.EdgeAddr}
	if pc.DNSCheck == "resolve" {
		oc.DNS = orchestrator.Resolver{Server: pc.DNSServer}
	}
	if pc.ProberURL != "" {
		c, err := probe.NewClient(pc.ProberURL, nil)
		if err != nil {
			return nil, err
		}
		oc.Prober = probeAdapter{c}
	}
	p, err := orchestrator.New(oc)
	if err != nil {
		return nil, err
	}
	d.log.Info("tenant orchestrator configured", "headscale_version", pc.HeadscaleVersion, "dns_check", pc.DNSCheck,
		"prober", pc.ProberURL != "", "edge", pc.EdgeAddr)
	return p, nil
}

// probeAdapter maps the prober's RPC client (apps/probe, P3-T03a) onto the orchestrator's Prober (orchestrator does
// not import apps/*).
type probeAdapter struct{ c probe.Prober }

func check(name string, r probe.HTTPSResult) orchestrator.ProbeCheck {
	out := orchestrator.ProbeCheck{Name: name, OK: r.OK, Status: r.Status}
	if r.Error != nil {
		out.Code = r.Error.Code
	} else if !r.OK && len(r.Failures) > 0 {
		out.Code = "expectation_failed"
	}
	return out
}

func (a probeAdapter) Relay(ctx context.Context, p orchestrator.RelayProbe) (orchestrator.ProbeResult, error) {
	r, err := a.c.Relay(ctx, probe.RelayRequest{Address: p.Address, Host: p.Host, STUN: p.STUN})
	if err != nil {
		return orchestrator.ProbeResult{}, err
	}
	stun := orchestrator.ProbeCheck{Name: "stun", OK: r.STUN.OK}
	if r.STUN.Error != nil {
		stun.Code = r.STUN.Error.Code
	}
	return orchestrator.ProbeResult{OK: r.OK, Checks: []orchestrator.ProbeCheck{check("/derp/probe", r.DERP), stun}}, nil
}

func (a probeAdapter) Edge(ctx context.Context, p orchestrator.EdgeProbe) (orchestrator.ProbeResult, error) {
	r, err := a.c.Edge(ctx, probe.EdgeRequest{Address: p.Address, Host: p.Host, PublicKey: p.PublicKey})
	if err != nil {
		return orchestrator.ProbeResult{}, err
	}
	out := orchestrator.ProbeResult{OK: r.OK, Checks: []orchestrator.ProbeCheck{check("/key", r.Key)}}
	if k, ok := r.Key.JSON["publicKey"]; ok && r.Key.Status == 200 && k != p.PublicKey {
		out.KeyMismatch = true
	}
	for _, f := range r.Forbidden {
		out.Checks = append(out.Checks, check(f.Path, f))
		// An answer that is not 404 is the edge publishing a path it must hide (§14.6); no answer at all (timeout,
		// refused) is a probe failure, retried.
		if f.Error == nil && f.Status != 0 && f.Status != 404 && f.Status != 421 {
			out.Exposed = append(out.Exposed, f.Path)
		}
	}
	return out, nil
}
