// Command meshguard-agent is the Host Agent (P3-T01; master plan §11.1, §11.5, §14.4, ADR-05): one per host, the
// ONLY component with the Docker socket, `/opt/meshguard/tenants` and `/opt/meshguard/backups/tenants`. It is
// equivalent to root (R-15), so it serves only the closed, typed protocol of api/agent/v1/agent.proto:
//
//   - one listener, a Unix socket (MG_AGENT_SOCKET, 0660, group mg-sec-worker) — no TCP, network_mode: none;
//   - every call: SO_PEERCRED (worker UID allowlist) + agent token (file secret), then the closed parameter sets of
//     internal/provisioning/agentspec, then the ownership guard — before any driver is reached;
//   - every refusal: a typed gRPC status (Refusal detail: reason + field) and one audit line (agent_call).
//
// P3-T01 wires no infrastructure driver: Health and GetHostInfo answer, EnsureInstance can dry-run, every other
// operation is validated, guarded and then answered UNIMPLEMENTED. The compose driver arrives in P3-T02.
//
// Subcommands (exit status 0 = ok, 1 = failure, 2 = configuration or usage error):
//
//	meshguard-agent              run the agent
//	meshguard-agent healthcheck  container healthcheck: Health over the socket, with the token
//	meshguard-agent version
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := dispatch(ctx, os.Args[1:], os.Getenv, os.Environ(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// dispatch runs one subcommand. Arguments are never echoed back (a secret could have been passed by mistake).
func dispatch(ctx context.Context, args []string, getenv func(string) string, environ []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 0:
		return run(ctx, getenv, environ, stdout, stderr)
	case len(args) == 1 && args[0] == "healthcheck":
		return healthcheck(ctx, getenv, stdout, stderr)
	case len(args) == 1 && args[0] == "version":
		_, _ = fmt.Fprintf(stdout, "meshguard-agent %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return 0
	}
	_, _ = fmt.Fprint(stderr, "meshguard-agent: unknown subcommand\nusage: meshguard-agent | meshguard-agent healthcheck | meshguard-agent version\n")
	return 2
}

func run(ctx context.Context, getenv func(string) string, environ []string, stdout, stderr io.Writer) int {
	cfg, err := LoadConfig(getenv, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-agent: configuration:\n%v\n", err)
		return 2
	}
	token, err := cfg.Prepare()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-agent: %v\n", err)
		return 2
	}
	log := logx.New(stdout, cfg.LogLevel, "agent")
	srv := newServer(cfg, token, noDriver{}, nil, log)
	l, err := listenUnix(ctx, cfg.Socket, cfg.SocketGID)
	if err != nil {
		log.Error("agent_listen_failed", "error", err)
		return 1
	}
	gs := srv.grpcServer(cfg)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(l) }()
	log.Info("agent_started", "socket", cfg.Socket, "socket_gid", cfg.SocketGID, "peer_uids", cfg.PeerUIDs,
		"driver", srv.drv.Name(), "allowed_images", cfg.Host.Images.Len(), "run_uid_range", cfg.Host.RunUIDs.String(),
		"tenant_net_pool", cfg.Host.TenantPool.String(), "version", buildinfo.Version, "commit", buildinfo.Commit)
	select {
	case err := <-served:
		log.Error("agent_serve_failed", "error", err)
		return 1
	case <-ctx.Done():
	}
	done := make(chan struct{})
	go func() { gs.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		gs.Stop()
	}
	log.Info("agent_stopped")
	return 0
}

// healthcheck calls Health over the socket like the worker would (same token file), as the agent's own UID — the
// only method that UID may call.
func healthcheck(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) int {
	sock := getenv("MG_AGENT_SOCKET")
	if sock == "" {
		sock = agentclient.DefaultSocket
	}
	c, err := agentclient.New(agentclient.Config{Socket: sock, TokenFile: getenv("MG_AGENT_TOKEN_FILE")})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 2
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	h, err := c.Health(ctx, &agentv1.HealthRequest{})
	if err != nil || h.GetStatus() != agentv1.ServingStatus_SERVING_STATUS_SERVING {
		_, _ = fmt.Fprintf(stderr, "healthcheck: not serving: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "agent %s: %s, driver %s, %d allowed images\n", h.GetVersion(), h.GetStatus(), h.GetDriver(), h.GetAllowedImages())
	return 0
}
