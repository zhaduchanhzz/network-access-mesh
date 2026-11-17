package config

import (
	"strings"
	"testing"
)

// TestAgentClient: the agent of the worker is optional (both variables or neither, absolute paths); the api may not
// have one; a value never appears in an error.
func TestAgentClient(t *testing.T) {
	get, list := env(map[string]string{})
	cfg, err := Load("worker", get, list)
	if err != nil || cfg.Agent.Configured() {
		t.Fatalf("no agent in dev: %+v %v", cfg.Agent, err)
	}
	ok := map[string]string{"MG_AGENT_SOCKET": "/run/meshguard/agent.sock", "MG_AGENT_TOKEN_FILE": "/run/secrets/agent_token"}
	get, list = env(ok)
	if cfg, err = Load("worker", get, list); err != nil || !cfg.Agent.Configured() ||
		cfg.Agent != (AgentClient{Socket: "/run/meshguard/agent.sock", TokenFile: "/run/secrets/agent_token"}) {
		t.Fatalf("worker with an agent: %+v %v", cfg.Agent, err)
	}
	for name, c := range map[string]struct {
		service string
		env     map[string]string
		want    string
	}{
		"api":            {"api", ok, "worker only"},
		"socket only":    {"worker", map[string]string{"MG_AGENT_SOCKET": "/run/meshguard/agent.sock"}, "both be absolute"},
		"token only":     {"worker", map[string]string{"MG_AGENT_TOKEN_FILE": "/run/secrets/agent_token"}, "both be absolute"},
		"relative token": {"worker", map[string]string{"MG_AGENT_SOCKET": "/s", "MG_AGENT_TOKEN_FILE": "rel-secret-path"}, "both be absolute"},
	} {
		get, list := env(c.env)
		_, err := Load(c.service, get, list)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "rel-secret-path") {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
