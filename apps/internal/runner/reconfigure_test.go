package runner

import (
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
)

// TestNewReconfigurer — the wiring of P3-T13: without MG_AGENT_* the worker runs no instance.reconfigure (a warning,
// the jobs stay queued); with the agent it does, with the shared client; the prober is optional (MG_PROBER_URL).
func TestNewReconfigurer(t *testing.T) {
	var logs syncBuffer
	d := &deps{log: newTestLogger(&logs)}
	defer d.close()
	if r, err := newReconfigurer(config.Config{}, d, nil); r != nil || err != nil ||
		!strings.Contains(logs.String(), "instance.reconfigure is not run by this worker") {
		t.Fatalf("without agent: %v %v\n%s", r, err, logs.String())
	}
	dir := t.TempDir()
	tok := writeFile(t, dir, "agent_token", strings.Repeat("A", 40)+"\n")
	cfg := config.Config{Agent: config.AgentClient{Socket: dir + "/agent.sock", TokenFile: tok}}
	agent, err := newAgent(cfg, d)
	if err != nil || agent == nil {
		t.Fatal(err)
	}
	if r, err := newReconfigurer(cfg, d, agent); r == nil || err != nil ||
		!strings.Contains(logs.String(), `"msg":"instance reconfiguration configured","service":"test","prober":false`) {
		t.Fatalf("with agent: %v %v\n%s", r, err, logs.String())
	}
	cfg.Provisioning = config.Provisioning{ProberURL: "http://10.249.0.9:8080", EdgeAddr: "10.249.0.2:443"}
	if r, err := newReconfigurer(cfg, d, agent); r == nil || err != nil ||
		!strings.Contains(logs.String(), `"prober":true,"edge":"10.249.0.2:443"`) {
		t.Fatalf("with prober: %v %v\n%s", r, err, logs.String())
	}
}
