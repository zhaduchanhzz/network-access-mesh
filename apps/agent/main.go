// Command meshguard-agent is the Host Agent (P3-T01; master plan §11.1, §11.5, §14.4, ADR-05): one per host, the
// ONLY component with the Docker socket, `/opt/meshguard/tenants` and `/opt/meshguard/backups/tenants`. It is
// equivalent to root (R-15), so it serves only the closed, typed protocol of api/agent/v1/agent.proto:
//
//   - one listener, a Unix socket (MG_AGENT_SOCKET, 0660, group mg-sec-worker) — no TCP, network_mode: none;
//   - every call: SO_PEERCRED (worker UID allowlist) + agent token (file secret), then the closed parameter sets of
//     internal/provisioning/agentspec, then the ownership guard — before any driver is reached;
//   - every refusal: a typed gRPC status (Refusal detail: reason + field) and one audit line (agent_call).
//
// The compose driver (P3-T02, internal/provisioning/driver/compose) performs EnsureInstance (storage → config →
// network → container), GetInstanceStatus, ListInstances, Start/Stop/Restart and RemoveInstance; ValidateConfig,
// BootstrapPolicy, BootstrapApiKey and the edge attachment (P3-T03); a loop inside the agent is the edge supervisor and
// start guard of §11.4 (supervisor.go); Backup, Restore and PostRestoreReconcile (P3-T11). The other operations are
// validated, guarded and answered UNIMPLEMENTED until their task (P3-T13a). MG_AGENT_DRIVER=none keeps the P3-T01 behaviour (no Docker access).
//
// Subcommands (exit status 0 = ok, 1 = failure, 2 = configuration or usage error):
//
//	meshguard-agent                    run the agent
//	meshguard-agent healthcheck        container healthcheck: Health over the socket, with the token
//	meshguard-agent version
//	meshguard-agent noise-fingerprint  the one-shot helper of the start guard, run by the agent itself (§11.5)
//	meshguard-agent backup-snapshot    the backup helpers (P3-T11, §17.1–§17.2): one-shot containers run by the agent
//	meshguard-agent restore-unpack
//	meshguard-agent data-check
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
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
	case len(args) == 1 && args[0] == compose.FingerprintCommand:
		return noiseFingerprint(compose.NoiseKeyPath, stdout, stderr)
	case len(args) == 1 && (args[0] == compose.BackupSnapshotCommand || args[0] == compose.RestoreUnpackCommand || args[0] == compose.DataCheckCommand):
		// the backup helpers (P3-T11, §17.1–§17.2): run by the agent in a one-shot container of its own image, as the
		// tenant's run_uid — request on stdin, result on stdout
		return compose.RunHelper(args[0], os.Stdin, stdout)
	}
	_, _ = fmt.Fprint(stderr, "meshguard-agent: unknown subcommand\nusage: meshguard-agent | meshguard-agent healthcheck | meshguard-agent version\n")
	return 2
}

// noiseFingerprint is the one-shot helper of the start guard (§11.5), run by the agent in a container of its own image
// as the tenant's run_uid, network none, read-only, data/ mounted read-only: it prints the fingerprint of the Noise
// key (64 hex) — nothing of the key itself. Exit status: 0 ok, 3 key file absent, 4 not a valid key file, 1 error.
// The path is fixed: the subcommand takes no argument.
func noiseFingerprint(path string, stdout, stderr io.Writer) int {
	fp, err := compose.FingerprintNoiseKeyFile(path)
	switch {
	case errors.Is(err, compose.ErrNoiseKeyAbsent):
		_, _ = fmt.Fprintln(stderr, "noise-fingerprint: key file absent")
		return compose.FingerprintExitAbsent
	case errors.Is(err, compose.ErrNoiseKeyInvalid):
		_, _ = fmt.Fprintln(stderr, "noise-fingerprint: not a valid key file")
		return compose.FingerprintExitInvalid
	case err != nil:
		_, _ = fmt.Fprintln(stderr, "noise-fingerprint: cannot read the key file")
		return 1
	}
	_, _ = fmt.Fprintln(stdout, fp)
	return 0
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
	drv, inv, err := buildDriver(ctx, cfg, log)
	if err != nil {
		log.Error("agent_driver_failed", "error", err)
		return 2
	}
	srv := newServer(cfg, token, drv, inv, log)
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
	if sup, ok := drv.(edgeSupervisor); ok {
		log.Info("edge_supervisor_started", "edge", cfg.Edge, "edge_network", cfg.EdgeNetwork, "interval", cfg.SupervisorInterval.String())
		go srv.superviseEdge(ctx, sup, cfg.SupervisorInterval)
	}
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

// buildDriver wires the driver of cfg.Driver. The compose driver talks to the Docker Engine through DOCKER_HOST (a
// Unix socket) and runs the compose binary of the image; an unreachable engine at start is logged, not fatal (the
// agent still answers Health; operations fail UNAVAILABLE until the engine is back).
func buildDriver(ctx context.Context, cfg *Config, log *slog.Logger) (Driver, agentspec.Inventory, error) {
	if cfg.Driver == "none" {
		return noDriver{}, nil, nil
	}
	fi, err := os.Lstat(cfg.ComposeBin)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 || fi.Mode().Perm()&0o111 == 0 {
		return nil, nil, fmt.Errorf("MG_AGENT_COMPOSE_BIN must be an executable regular file not writable by group or others")
	}
	eng, err := compose.NewEngine(cfg.DockerHost)
	if err != nil {
		return nil, nil, err
	}
	inv := compose.NewInventory(eng)
	c, err := compose.New(compose.Config{
		Host: &cfg.Host, Guard: &agentspec.Guard{Host: &cfg.Host, Inventory: inv, Edge: cfg.Edge}, AgentGID: os.Getegid(),
		Engine: eng, Compose: &compose.CLI{Command: []string{cfg.ComposeBin}, DockerHost: cfg.DockerHost, ConfigDir: cfg.DockerConfig},
		Edge: cfg.Edge, EdgeNetwork: cfg.EdgeNetwork, HelperImage: cfg.HelperImage, Backup: cfg.Backup, MaxDBBytes: cfg.MaxDBBytes, Log: log,
	})
	if err != nil {
		return nil, nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := eng.Ping(pctx); err != nil {
		log.Warn("agent_docker_unreachable", "docker_host", cfg.DockerHost, "error", err)
	}
	return composeDriver{c: c}, inv, nil
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
