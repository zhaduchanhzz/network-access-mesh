// Package runner is the shared entry point of the api and worker processes (one codebase, several run modes —
// §4.2): load and validate configuration, build the logger and metrics registry, wire the modules (P2-T16 — api.go,
// worker.go), serve the internal endpoints (and the public API listener for api), and shut down gracefully on
// SIGINT/SIGTERM.
//
// A process is wired (config.Config.Wired) outside dev, and in dev once MG_DB_URL is set: it opens its PostgreSQL pools,
// its SecretStore and the edge admin listener and refuses to start when one of them is missing. A dev process without
// MG_DB_URL stays bare — internal endpoints and a public API answering 501 — which is what the smoke test of the
// `images` workflow runs (no database there).
package runner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// Main runs one service and returns the process exit code.
func Main(service string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return run(ctx, service, os.Getenv, os.Environ(), os.Stdout, os.Stderr)
}

// component is what wiring a process produced: its readiness probes, the public API (api only), the background work
// to start once the listeners are up (worker only) and how to release everything.
type component struct {
	probes map[string]httpx.Probe
	public http.Handler
	start  func(ctx context.Context) error
	stop   func(ctx context.Context)
	close  func()
}

// stopTimeout bounds the graceful stop of the background work (the job worker's SoftStopTimeout is 30 s).
const stopTimeout = 45 * time.Second

// run is Main with the process inputs passed in; it serves until ctx is cancelled.
func run(ctx context.Context, service string, getenv func(string) string, environ []string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(service, getenv, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard %s: invalid configuration:\n%v\n", service, err)
		return 2
	}
	log := logx.New(stdout, cfg.LogLevel, service)
	log.Info("starting", "version", buildinfo.Version, "commit", buildinfo.Commit, "env", cfg.Env, "wired", cfg.Wired)

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

	c, err := build(ctx, cfg, log, reg)
	if err != nil {
		log.Error("cannot start", "error", err.Error())
		return 1
	}
	defer c.close()

	servers := []*http.Server{httpx.NewServer(cfg.InternalAddr, httpx.InternalMux(c.probes, reg, log), log)}
	if c.public != nil {
		servers = append(servers, httpx.NewServer(cfg.HTTPAddr, c.public, log))
	}
	if c.start != nil {
		if err := c.start(ctx); err != nil {
			log.Error("cannot start the background work", "error", err.Error())
			return 1
		}
	}
	serveErr := httpx.Serve(ctx, log, servers...)
	if c.stop != nil {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopTimeout)
		c.stop(sctx)
		cancel()
	}
	if serveErr != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}

// build wires the process: api.go / worker.go when wired, the bare dev process otherwise.
func build(ctx context.Context, cfg config.Config, log *slog.Logger, reg *prometheus.Registry) (*component, error) {
	if cfg.Wired {
		// Start-up must not hang forever on an unreachable dependency: the orchestrator restarts the container.
		bctx, cancel := context.WithTimeout(requestid.With(ctx, "startup-"+cfg.Service), startupTimeout)
		defer cancel()
		if cfg.Service == "api" {
			return buildAPI(bctx, cfg, log, reg)
		}
		return buildWorker(bctx, cfg, log, reg)
	}
	log.Warn("dev process without MG_DB_URL: not wired — internal endpoints only, every API operation answers 501")
	c := &component{probes: map[string]httpx.Probe{}, close: func() {}}
	if cfg.Service == "api" {
		api, err := httpapi.New(httpapi.Options{Logger: log, TrustedProxies: cfg.TrustedProxies})
		if err != nil {
			return nil, fmt.Errorf("public API: %w", err)
		}
		c.public = api
	}
	return c, nil
}

// startupTimeout bounds the wiring (pools, keyrings, the IdP driver's lookup).
const startupTimeout = 60 * time.Second
