// Package runner is the shared entry point of the api and worker processes (one codebase, several run modes —
// §4.2): load and validate configuration, build the logger and metrics registry, serve the internal endpoints
// (and the public API listener for api), and shut down gracefully on SIGINT/SIGTERM.
package runner

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Main runs one service and returns the process exit code.
func Main(service string) int {
	cfg, err := config.Load(service, os.Getenv, os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshguard %s: invalid configuration:\n%v\n", service, err)
		return 2
	}
	log := logx.New(os.Stdout, cfg.LogLevel, service)
	log.Info("starting", "version", buildinfo.Version, "commit", buildinfo.Commit, "env", cfg.Env)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "meshguard_build_info",
			Help:        "Build information of the running MeshGuard process.",
			ConstLabels: prometheus.Labels{"service": service, "version": buildinfo.Version, "commit": buildinfo.Commit},
		}, func() float64 { return 1 }),
	)

	// Readiness probes are registered here as dependencies arrive (PostgreSQL in P2-T03, Agent in P3-T01).
	probes := map[string]httpx.Probe{}

	servers := []*http.Server{httpx.NewServer(cfg.InternalAddr, httpx.InternalMux(probes, reg, log), log)}
	if service == "api" {
		// The public REST API (/api/v1, contract-first from api/openapi.yaml) is mounted here in P2-T02.
		servers = append(servers, httpx.NewServer(cfg.HTTPAddr, http.NotFoundHandler(), log))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := httpx.Serve(ctx, log, servers...); err != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}
