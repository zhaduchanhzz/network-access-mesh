package runner

import (
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// TestNewReconcile — the wiring of P3-T12: without MG_AGENT_* the worker still gets the reconcile jobs (agent checks
// report agent_unavailable, a warning is logged); with them the agent client is built (connection on first call) and
// closed with the process; an unreadable token file fails the start, naming the file, never a value.
func TestNewReconcile(t *testing.T) {
	pg := storetest.Require(t)
	st := pg.OpenStore(t, pg.NewDatabase(t), "mg_worker_tenant", "mg_worker_platform", 2)
	var logs syncBuffer
	d := &deps{st: st, log: newTestLogger(&logs)}
	defer d.close()
	svc, err := newReconcile(config.Config{}, d, nil)
	if err != nil || svc.AgentConfigured() || len(d.closers) != 0 || !strings.Contains(logs.String(), "no Host Agent configured") {
		t.Fatalf("without agent: %v %v closers=%d\n%s", svc, err, len(d.closers), logs.String())
	}
	dir := t.TempDir()
	tok := writeFile(t, dir, "agent_token", strings.Repeat("A", 40)+"\n")
	svc, err = newReconcile(config.Config{Agent: config.AgentClient{Socket: dir + "/agent.sock", TokenFile: tok}}, d, nil)
	if err != nil || !svc.AgentConfigured() || len(d.closers) != 1 {
		t.Fatalf("with agent: %v closers=%d", err, len(d.closers))
	}
	short := writeFile(t, dir, "short_token", "tooshort-secret-value\n")
	if _, err := newReconcile(config.Config{Agent: config.AgentClient{Socket: dir + "/agent.sock", TokenFile: short}}, d, nil); err == nil ||
		!strings.Contains(err.Error(), "short_token") || strings.Contains(err.Error(), "tooshort-secret-value") {
		t.Fatalf("bad token: %v", err)
	}
}
