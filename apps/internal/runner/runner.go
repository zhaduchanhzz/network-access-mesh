// Package runner is the shared entry point of the api and worker processes (one codebase, several run modes —
// §4.2): load and validate configuration, build the logger and metrics registry, serve the internal endpoints
// (and the public API listener for api), and shut down gracefully on SIGINT/SIGTERM.
package runner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Main runs one service and returns the process exit code.
func Main(service string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return run(ctx, service, os.Getenv, os.Environ(), os.Stdout, os.Stderr)
}

// run is Main with the process inputs passed in; it serves until ctx is cancelled.
func run(ctx context.Context, service string, getenv func(string) string, environ []string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(service, getenv, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard %s: invalid configuration:\n%v\n", service, err)
		return 2
	}
	log := logx.New(stdout, cfg.LogLevel, service)
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
		// The public REST API (/api/v1, §13): the strict server generated from api/openapi.yaml behind the middleware
		// chain of P2-T14 (internal/httpapi). Handler sets (httpapi.Handlers) and the session/CSRF/authz hooks
		// (httpapi.Hooks) are wired here as P2-T06, P2-T07 and the domain tasks land; until then every operation
		// answers 501 not_implemented.
		api, err := httpapi.New(httpapi.Options{Logger: log, TrustedProxies: cfg.TrustedProxies})
		if err != nil {
			log.Error("cannot build the public API", "error", err.Error())
			return 1
		}
		servers = append(servers, httpx.NewServer(cfg.HTTPAddr, api, log))
	}

	if err := httpx.Serve(ctx, log, servers...); err != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}
