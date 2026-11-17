package runner

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	probe "github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// TestNewReconcile — the wiring of P3-T12 and P3-T05: without MG_AGENT_* the worker still gets the reconcile jobs
// (agent checks report agent_unavailable, a warning is logged) and no orchestrator; with them ONE agent client is built
// (connection on first call), shared by reconcile and the orchestrator and closed with the process; an unreadable token
// file fails the start, naming the file, never a value.
func TestNewReconcile(t *testing.T) {
	pg := storetest.Require(t)
	st := pg.OpenStore(t, pg.NewDatabase(t), "mg_worker_tenant", "mg_worker_platform", 2)
	var logs syncBuffer
	d := &deps{st: st, log: newTestLogger(&logs)}
	defer d.close()
	agent, err := newAgent(config.Config{}, d)
	if err != nil || agent != nil {
		t.Fatalf("without agent: %v %v", agent, err)
	}
	svc, err := newReconcile(d, agent, nil)
	if err != nil || svc.AgentConfigured() || len(d.closers) != 0 || !strings.Contains(logs.String(), "no Host Agent configured") {
		t.Fatalf("without agent: %v %v closers=%d\n%s", svc, err, len(d.closers), logs.String())
	}
	reg, err := idp.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	prov := config.Provisioning{HeadscaleDigest: "sha256:" + strings.Repeat("d", 64), HeadscaleVersion: "v0.29.7",
		Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, EdgeAddr: "10.249.0.2:443", DNSCheck: "resolve"}
	if p, err := newProvisioner(config.Config{BaseDomain: "example.test", Provisioning: prov}, d, agent, reg); p != nil || err != nil ||
		!strings.Contains(logs.String(), "tenant.provision is not run by this worker") {
		t.Fatalf("orchestrator without agent: %v %v", p, err)
	}
	dir := t.TempDir()
	tok := writeFile(t, dir, "agent_token", strings.Repeat("A", 40)+"\n")
	cfg := config.Config{BaseDomain: "example.test", Agent: config.AgentClient{Socket: dir + "/agent.sock", TokenFile: tok},
		Provisioning: prov}
	if agent, err = newAgent(cfg, d); err != nil || agent == nil || len(d.closers) != 1 {
		t.Fatalf("with agent: %v closers=%d", err, len(d.closers))
	}
	if svc, err = newReconcile(d, agent, nil); err != nil || !svc.AgentConfigured() || len(d.closers) != 1 {
		t.Fatalf("reconcile with agent: %v closers=%d", err, len(d.closers))
	}
	if p, err := newProvisioner(cfg, d, agent, reg); err != nil || p == nil || !strings.Contains(logs.String(), "tenant orchestrator configured") {
		t.Fatalf("orchestrator with agent and MG_PROVISION_*: %v %v", p, err)
	}
	short := writeFile(t, dir, "short_token", "tooshort-secret-value\n")
	if _, err := newAgent(config.Config{Agent: config.AgentClient{Socket: dir + "/agent.sock", TokenFile: short}}, d); err == nil ||
		!strings.Contains(err.Error(), "short_token") || strings.Contains(err.Error(), "tooshort-secret-value") {
		t.Fatalf("bad token: %v", err)
	}
}

// fakeProbe answers the prober RPCs with fixed results.
type fakeProbe struct {
	probe.Prober
	edge  probe.EdgeResult
	relay probe.RelayResult
}

func (f fakeProbe) Edge(context.Context, probe.EdgeRequest) (probe.EdgeResult, error) {
	return f.edge, nil
}
func (f fakeProbe) Relay(context.Context, probe.RelayRequest) (probe.RelayResult, error) {
	return f.relay, nil
}

// TestProbeAdapter: the prober's results map onto the orchestrator's — a forbidden path answered with anything but 404
// (or 421) is an exposure, no answer is a probe failure, /key with another key a mismatch.
func TestProbeAdapter(t *testing.T) {
	key := "mkey:" + strings.Repeat("a", 64)
	a := probeAdapter{fakeProbe{edge: probe.EdgeResult{OK: false,
		Key: probe.HTTPSResult{OK: false, Status: 200, JSON: map[string]string{"publicKey": "mkey:" + strings.Repeat("b", 64)}},
		Forbidden: []probe.HTTPSResult{{Path: "/api/v1/node", Status: 404, OK: true}, {Path: "/metrics", Status: 200},
			{Path: "/version", Error: &probe.Error{Code: probe.CodeTimeout}}, {Path: "/", Status: 421}}}}}
	r, err := a.Edge(t.Context(), orchestrator.EdgeProbe{Address: "10.249.0.2:443", Host: "acme.mesh.example.test", PublicKey: key})
	if err != nil || r.OK || !r.KeyMismatch || len(r.Exposed) != 1 || r.Exposed[0] != "/metrics" || len(r.Checks) != 5 ||
		r.Checks[3].Code != probe.CodeTimeout {
		t.Fatalf("edge %+v %v", r, err)
	}
	a = probeAdapter{fakeProbe{relay: probe.RelayResult{OK: false, DERP: probe.HTTPSResult{OK: true, Status: 200},
		STUN: probe.STUNResult{Error: &probe.Error{Code: probe.CodeRefused}}}}}
	rr, err := a.Relay(t.Context(), orchestrator.RelayProbe{})
	if err != nil || rr.OK || len(rr.Checks) != 2 || rr.Checks[1].Code != probe.CodeRefused || !rr.Checks[0].OK {
		t.Fatalf("relay %+v %v", rr, err)
	}
}
