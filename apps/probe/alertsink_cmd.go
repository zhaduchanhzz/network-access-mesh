package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/alertsink"
	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// alertsinkCmd runs the internal alert sink (P3-T16): the receiver of Alertmanager's webhook on MG_ALERTSINK_LISTEN
// (default :8080) for the callers of MG_ALERTSINK_ALLOW_CALLERS (required — fail closed), and the internal listener
// MG_INTERNAL_ADDR (default :9090: /healthz, /readyz, /metrics) for the healthcheck and Prometheus.
func alertsinkCmd(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) int {
	listen, internalAddr := getenv("MG_ALERTSINK_LISTEN"), getenv("MG_INTERNAL_ADDR")
	if listen == "" {
		listen = ":8080"
	}
	if internalAddr == "" {
		internalAddr = ":9090"
	}
	var errs []error
	for _, a := range []struct{ name, value string }{{"MG_ALERTSINK_LISTEN", listen}, {"MG_INTERNAL_ADDR", internalAddr}} {
		if _, _, err := net.SplitHostPort(a.value); err != nil {
			errs = append(errs, fmt.Errorf("%s must be host:port", a.name))
		}
	}
	callers, err := prober.ParsePrefixes(getenv("MG_ALERTSINK_ALLOW_CALLERS"))
	if err != nil {
		errs = append(errs, fmt.Errorf("MG_ALERTSINK_ALLOW_CALLERS (Alertmanager and the drill reader): %w", err))
	}
	lvl := getenv("MG_LOG_LEVEL")
	if lvl == "" {
		lvl = "info"
	}
	level, err := logx.ParseLevel(lvl)
	if err != nil {
		errs = append(errs, errors.New("MG_LOG_LEVEL must be debug, info, warn or error"))
	}
	if err := errors.Join(errs...); err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-probe alertsink: invalid configuration:\n%v\n", err)
		return 2
	}
	log := logx.New(stdout, level, "alertsink")
	log.Info("starting", "version", buildinfo.Version, "commit", buildinfo.Commit, "listen", listen,
		"internal", internalAddr, "callers", prefixList(callers))
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "meshguard_build_info", Help: "Build information of the running MeshGuard process.",
			ConstLabels: prometheus.Labels{"service": "alertsink", "version": buildinfo.Version, "commit": buildinfo.Commit}},
			func() float64 { return 1 }))
	sink := alertsink.New(alertsink.Options{Callers: callers, Logger: log, Registerer: reg})
	api := &http.Server{Addr: listen, Handler: sink.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	internal := httpx.NewServer(internalAddr, httpx.InternalMux(map[string]httpx.Probe{}, reg, log), log)
	if err := httpx.ServeWith(ctx, log, listenTCP, api, internal); err != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}
