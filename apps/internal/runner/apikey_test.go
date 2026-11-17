package runner

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// TestNewAPIKeyRotation — the wiring of P3-T10: without MG_AGENT_* the rotation is built (a warning names the
// consequence: an expired or lost key cannot be re-issued), with them the agent client is built and closed with the
// process; an unreadable agent token fails the start without the value; the metrics of the rotation are exported.
func TestNewAPIKeyRotation(t *testing.T) {
	pg := storetest.Require(t)
	st := pg.OpenStore(t, pg.NewDatabase(t), "mg_worker_tenant", "mg_worker_platform", 2)
	dir := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	writeFile(t, dir, "kek-1", hex.EncodeToString(k)+"\n")
	writeFile(t, dir, secrets.ActiveFile, "kek-1\n")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := secrets.New(st, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	d := &deps{st: st, log: newTestLogger(&logs), secrets: ss, tenants: tenants.New(st, tenants.Options{BaseDomain: "mg.test"})}
	d.headscale = headscale.NewRegistry(headscale.StaticLocator{}, headscale.Options{})
	defer d.close()
	tokens := t.TempDir()
	cfg := config.Config{Edge: config.EdgeAdmin{URL: "http://10.249.0.2:8081", TokenFile: writeFile(t, tokens, "edge_admin_token",
		randomToken()+"\n")}}
	reg := prometheus.NewRegistry()
	svc, err := newAPIKeyRotation(cfg, d, reg)
	if err != nil || svc.AgentConfigured() || len(d.closers) != 0 || !strings.Contains(logs.String(), "agent_not_configured") {
		t.Fatalf("without agent: %v closers=%d\n%s", err, len(d.closers), logs.String())
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names[apikey.MetricEvents] {
		t.Fatalf("metrics: %v", names)
	}
	cfg.Agent = config.AgentClient{Socket: dir + "/agent.sock", TokenFile: writeFile(t, dir, "agent_token", strings.Repeat("A", 40)+"\n")}
	if svc, err = newAPIKeyRotation(cfg, d, nil); err != nil || !svc.AgentConfigured() || len(d.closers) != 1 {
		t.Fatalf("with agent: %v closers=%d", err, len(d.closers))
	}
	cfg.Agent.TokenFile = writeFile(t, dir, "short_token", "tooshort-secret-value\n")
	if _, err := newAPIKeyRotation(cfg, d, nil); err == nil || !strings.Contains(err.Error(), "short_token") ||
		strings.Contains(err.Error(), "tooshort-secret-value") {
		t.Fatalf("bad token: %v", err)
	}
}
