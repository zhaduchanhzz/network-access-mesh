package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// config is the configuration of `serve` (environment variables; none is a secret).
type config struct {
	listen      string
	internal    string
	callers     []netip.Prefix
	targets     []netip.Prefix
	scrapers    []netip.Prefix // P3-T16: callers of GET /probe on the internal listener (Prometheus); empty = none
	capver      int            // P3-T16: capability version of the key module (MG_PROBE_CAPVER, default 113)
	roots       *x509.CertPool
	caFile      string
	maxInFlight int
	level       slog.Level
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{listen: getenv("MG_PROBE_LISTEN"), internal: getenv("MG_INTERNAL_ADDR"), maxInFlight: 8}
	if c.listen == "" {
		c.listen = ":8080"
	}
	if c.internal == "" {
		c.internal = ":9090"
	}
	var errs []error
	for _, a := range []struct{ name, value string }{{"MG_PROBE_LISTEN", c.listen}, {"MG_INTERNAL_ADDR", c.internal}} {
		if _, _, err := net.SplitHostPort(a.value); err != nil {
			errs = append(errs, fmt.Errorf("%s must be host:port", a.name))
		}
	}
	var err error
	if c.callers, err = prober.ParsePrefixes(getenv("MG_PROBE_ALLOW_CALLERS")); err != nil {
		errs = append(errs, fmt.Errorf("MG_PROBE_ALLOW_CALLERS (RPC clients — the worker's network): %w", err))
	}
	if c.targets, err = prober.ParsePrefixes(getenv("MG_PROBE_ALLOW_TARGETS")); err != nil {
		errs = append(errs, fmt.Errorf("MG_PROBE_ALLOW_TARGETS (probe targets — edge, public entry): %w", err))
	}
	if v := getenv("MG_PROBE_ALLOW_SCRAPERS"); v != "" {
		if c.scrapers, err = prober.ParsePrefixes(v); err != nil {
			errs = append(errs, fmt.Errorf("MG_PROBE_ALLOW_SCRAPERS (callers of /probe — Prometheus): %w", err))
		}
	}
	c.capver = prober.DefaultCapVer
	if v := getenv("MG_PROBE_CAPVER"); v != "" {
		if c.capver, err = strconv.Atoi(v); err != nil || c.capver < 1 || c.capver > 10000 {
			errs = append(errs, errors.New("MG_PROBE_CAPVER must be 1-10000"))
		}
	}
	if c.caFile = getenv("MG_PROBE_CA_FILE"); c.caFile != "" {
		if c.roots, err = loadRoots(c.caFile); err != nil {
			errs = append(errs, err)
		}
	}
	if v := getenv("MG_PROBE_MAX_INFLIGHT"); v != "" {
		if c.maxInFlight, err = strconv.Atoi(v); err != nil || c.maxInFlight < 1 || c.maxInFlight > 256 {
			errs = append(errs, errors.New("MG_PROBE_MAX_INFLIGHT must be 1-256"))
		}
	}
	lvl := getenv("MG_LOG_LEVEL")
	if lvl == "" {
		lvl = "info"
	}
	if c.level, err = logx.ParseLevel(lvl); err != nil {
		errs = append(errs, errors.New("MG_LOG_LEVEL must be debug, info, warn or error"))
	}
	return c, errors.Join(errs...)
}

// loadRoots reads the PEM roots of MG_PROBE_CA_FILE: they replace the system roots (the dev/CI CA).
func loadRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) //nolint:gosec // G304: the CA file named by the process configuration
	if err != nil {
		return nil, errors.New("MG_PROBE_CA_FILE cannot be read")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("MG_PROBE_CA_FILE holds no PEM certificate")
	}
	return pool, nil
}

func serveCmd(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) int {
	cfg, err := loadConfig(getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-probe serve: invalid configuration:\n%v\n", err)
		return 2
	}
	log := logx.New(stdout, cfg.level, "probe")
	log.Info("starting", "version", buildinfo.Version, "commit", buildinfo.Commit, "listen", cfg.listen,
		"internal", cfg.internal, "callers", prefixList(cfg.callers), "targets", prefixList(cfg.targets),
		"scrapers", prefixList(cfg.scrapers), "capver", cfg.capver, "ca_file", cfg.caFile != "")
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "meshguard_build_info", Help: "Build information of the running MeshGuard process.",
			ConstLabels: prometheus.Labels{"service": "probe", "version": buildinfo.Version, "commit": buildinfo.Commit}},
			func() float64 { return 1 }))
	p := prober.New(prober.Options{Allow: cfg.targets, RootCAs: cfg.roots, Logger: log})
	rpc := &http.Server{Addr: cfg.listen,
		Handler: prober.Handler(p, prober.HandlerOptions{Callers: cfg.callers, MaxInFlight: cfg.maxInFlight, Logger: log,
			Registerer: reg}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 90 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	// GET /probe (P3-T16): the probes Prometheus scrapes, on their own Local — same allow-list and roots, but only the
	// failures are logged (a scrape every interval per target would otherwise flood the log).
	quiet := logx.New(stdout, max(cfg.level, slog.LevelWarn), "probe")
	mux := http.NewServeMux()
	mux.Handle(prober.RouteScrape, prober.ScrapeHandler(prober.New(prober.Options{Allow: cfg.targets, RootCAs: cfg.roots,
		Logger: quiet}), prober.ScrapeOptions{Scrapers: cfg.scrapers, CapVer: cfg.capver, Logger: log, Registerer: reg}))
	mux.Handle("/", httpx.InternalMux(map[string]httpx.Probe{}, reg, log))
	internal := httpx.NewServer(cfg.internal, mux, log)
	if err := httpx.Serve(ctx, log, rpc, internal); err != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}

func prefixList(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ",")
}

// runCmd runs one probe in this process; its allow-list is exactly the targets named in the request.
func runCmd(ctx context.Context, kind string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	var roots *x509.CertPool
	if f := getenv("MG_PROBE_CA_FILE"); f != "" {
		var err error
		if roots, err = loadRoots(f); err != nil {
			_, _ = fmt.Fprintf(stderr, "meshguard-probe run: %v\n", err)
			return 2
		}
	}
	local := func(targets ...string) prober.Prober {
		var allow []netip.Prefix
		for _, t := range targets {
			if ap, err := netip.ParseAddrPort(strings.TrimSpace(t)); err == nil {
				a := ap.Addr().Unmap()
				allow = append(allow, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		return prober.New(prober.Options{Allow: allow, RootCAs: roots})
	}
	switch kind {
	case "stun":
		return do(ctx, stdin, stdout, func(ctx context.Context, r prober.STUNRequest) (prober.STUNResult, error) {
			return local(r.Target).STUN(ctx, r)
		}, func(r prober.STUNResult) bool { return r.OK })
	case "https":
		return do(ctx, stdin, stdout, func(ctx context.Context, r prober.HTTPSRequest) (prober.HTTPSResult, error) {
			return local(r.Address).HTTPS(ctx, r)
		}, func(r prober.HTTPSResult) bool { return r.OK })
	case "edge":
		return do(ctx, stdin, stdout, func(ctx context.Context, r prober.EdgeRequest) (prober.EdgeResult, error) {
			return local(r.Address).Edge(ctx, r)
		}, func(r prober.EdgeResult) bool { return r.OK })
	default:
		return do(ctx, stdin, stdout, func(ctx context.Context, r prober.RelayRequest) (prober.RelayResult, error) {
			return local(r.Address, r.STUN).Relay(ctx, r)
		}, func(r prober.RelayResult) bool { return r.OK })
	}
}

// callCmd sends one probe to the RPC API of a running service (the worker's path).
func callCmd(ctx context.Context, url, kind string, stdin io.Reader, stdout, stderr io.Writer) int {
	c, err := prober.NewClient(url, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-probe call: --url (or MG_PROBER_URL): %v\n", err)
		return 2
	}
	return runKind(ctx, c, kind, stdin, stdout)
}

// runKind decodes the request of kind from stdin and runs it on p.
func runKind(ctx context.Context, p prober.Prober, kind string, stdin io.Reader, stdout io.Writer) int {
	switch kind {
	case "stun":
		return do(ctx, stdin, stdout, p.STUN, func(r prober.STUNResult) bool { return r.OK })
	case "https":
		return do(ctx, stdin, stdout, p.HTTPS, func(r prober.HTTPSResult) bool { return r.OK })
	case "edge":
		return do(ctx, stdin, stdout, p.Edge, func(r prober.EdgeResult) bool { return r.OK })
	default:
		return do(ctx, stdin, stdout, p.Relay, func(r prober.RelayResult) bool { return r.OK })
	}
}

// do reads one request (a JSON object of known fields) from stdin, runs it and prints the result (exit 0/1) or the
// refusal (exit 3).
func do[Req, Res any](ctx context.Context, stdin io.Reader, stdout io.Writer, run func(context.Context, Req) (Res, error),
	passed func(Res) bool) int {
	var req Req
	dec := json.NewDecoder(io.LimitReader(stdin, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return printJSON(stdout, map[string]any{"error": &prober.Error{Code: prober.CodeInvalidRequest,
			Message: "the request on stdin must be one JSON object of known fields"}}, 3)
	}
	res, err := run(ctx, req)
	if err != nil {
		e := &prober.Error{Code: prober.CodeRPC, Message: logx.RedactString(err.Error())}
		_ = errors.As(err, &e)
		return printJSON(stdout, map[string]any{"error": e}, 3)
	}
	if passed(res) {
		return printJSON(stdout, res, 0)
	}
	return printJSON(stdout, res, 1)
}

func printJSON(stdout io.Writer, v any, status int) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return status
}

// healthcheck is the container healthcheck (distroless: no shell, no curl): GET /readyz of the internal listener.
func healthcheck(getenv func(string) string, stdout io.Writer) int {
	addr := getenv("MG_INTERNAL_ADDR")
	if addr == "" {
		addr = ":9090"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "healthcheck: MG_INTERNAL_ADDR is not host:port")
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/readyz", nil)
	if err != nil {
		return 1
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}).Do(req)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "healthcheck: internal listener unreachable")
		return 1
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	_, _ = fmt.Fprintf(stdout, "healthcheck: HTTP %d %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
