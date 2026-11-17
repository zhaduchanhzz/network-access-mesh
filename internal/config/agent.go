package config

import (
	"errors"
	"path/filepath"
	"strings"
)

// AgentClient locates the Host Agent of the worker's host (§11.1): its Unix socket (MG_AGENT_SOCKET — in the worker
// container /run/meshguard/agent.sock, host /opt/meshguard/run/agent.sock) and the agent token file
// (MG_AGENT_TOKEN_FILE — host secrets/worker/agent_token, root:mg-sec-worker 0440). Both or neither: the worker runs
// without an agent until its compose mounts the socket (P3-T05); reconcile (P3-T12) then reports agent_unavailable.
type AgentClient struct {
	Socket    string
	TokenFile string
}

// Configured reports whether the worker has an agent.
func (a AgentClient) Configured() bool { return a.Socket != "" }

// LoadAgentClient reads MG_AGENT_SOCKET and MG_AGENT_TOKEN_FILE of a process; only the worker may have them (§11.1:
// the socket is mounted into the worker only). Errors name variables, never values.
func LoadAgentClient(service string, getenv func(string) string) (AgentClient, []error) {
	a := AgentClient{Socket: strings.TrimSpace(getenv("MG_AGENT_SOCKET")), TokenFile: strings.TrimSpace(getenv("MG_AGENT_TOKEN_FILE"))}
	if a.Socket == "" && a.TokenFile == "" {
		return a, nil
	}
	var errs []error
	if service != "worker" {
		errs = append(errs, errors.New("MG_AGENT_SOCKET, MG_AGENT_TOKEN_FILE: the agent socket is mounted into the worker only (§11.1)"))
	}
	if !filepath.IsAbs(a.Socket) || !filepath.IsAbs(a.TokenFile) {
		errs = append(errs, errors.New("MG_AGENT_SOCKET and MG_AGENT_TOKEN_FILE must both be absolute paths (or both unset)"))
	}
	return a, errs
}
