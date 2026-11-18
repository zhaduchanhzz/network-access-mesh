package prober

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RouteScrape is the Prometheus endpoint of the prober (P3-T16; §16.1 "blackbox_exporter (trong service prober)"):
// GET /probe?module=<module>&target=<ip:port>&host=<name> runs ONE probe and answers its result in the Prometheus
// text format — the contract of blackbox_exporter (probe_success, probe_duration_seconds, probe_http_status_code,
// probe_ssl_earliest_cert_expiry) on the prober's own checks: IP-literal targets inside the allow-list, explicit
// SNI/Host, no name resolution. The official blackbox_exporter resolves the target name and fixes the TLS server name
// per module, so it cannot probe every tenant hostname at the edge's address without one module per tenant.
const RouteScrape = "/probe"

// Scrape modules.
const (
	ModuleKey = "key" // GET /key?v=<capver> of a tenant hostname (§16.1, §16.3 "probe /key?v=<capver> fail")
	ModuleTLS = "tls" // TLS handshake only: the certificate a site presents (§16.3 "chứng chỉ còn < 21 ngày")
)

// ScrapeOptions configures the scrape endpoint.
type ScrapeOptions struct {
	// Scrapers is the allow-list of callers (MG_PROBE_ALLOW_SCRAPERS — Prometheus). Empty: every scrape is refused.
	Scrapers []netip.Prefix
	// MaxInFlight bounds the scrape probes run at once (default 16); a scrape waits for a slot until its deadline.
	MaxInFlight int
	// CapVer is the capability version of the key module when the scrape names none (default DefaultCapVer).
	CapVer int
	// Logger receives one WARN line per failed probe and per refused scrape; nil = discard.
	Logger *slog.Logger
	// Registerer receives meshguard_probe_scrapes_total{module,outcome}; nil = none.
	Registerer prometheus.Registerer
}

type scraper struct {
	l       *Local
	allow   []netip.Prefix
	slots   chan struct{}
	capver  int
	log     *slog.Logger
	scrapes *prometheus.CounterVec
}

// ScrapeHandler serves RouteScrape over l (its target allow-list applies). Answers: 200 + metrics when the probe ran
// (probe_success 0 when it failed); 400 for an invalid scrape, 403 for a caller outside Scrapers or a target outside
// the allow-list, 503 when no slot freed up before the scrape's deadline — Prometheus records each of them as a failed
// scrape (up 0), never as a failed probe.
func ScrapeHandler(l *Local, o ScrapeOptions) http.Handler {
	s := &scraper{l: l, allow: slices.Clone(o.Scrapers), capver: o.CapVer, log: o.Logger}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if s.capver == 0 {
		s.capver = DefaultCapVer
	}
	n := o.MaxInFlight
	if n <= 0 {
		n = 16
	}
	s.slots = make(chan struct{}, n)
	s.scrapes = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_probe_scrapes_total",
		Help: "Scrapes of /probe by module and outcome (ok, failed, or why the probe did not run)."}, []string{"module", "outcome"})
	if o.Registerer != nil {
		o.Registerer.MustRegister(s.scrapes)
	}
	return s
}

func (s *scraper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	a, perr := netip.ParseAddr(host)
	if err != nil || perr != nil || !allowed(s.allow, a) {
		s.refuse(w, r, "-", http.StatusForbidden, newError(CodeCallerNotAllowed, "caller outside the scrape allow-list"))
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		s.refuse(w, r, "-", http.StatusMethodNotAllowed, newError(CodeInvalidRequest, "method not allowed"))
		return
	}
	q := r.URL.Query()
	module := q.Get("module")
	run, perr2 := s.plan(module, q)
	if perr2 != nil {
		status := http.StatusBadRequest
		if perr2.Code == CodeTargetNotAllowed {
			status = http.StatusForbidden
		}
		s.refuse(w, r, module, status, perr2)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), scrapeBudget(r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds")))
	defer cancel()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		s.refuse(w, r, module, http.StatusServiceUnavailable, newError(CodeBusy, "no probe slot before the scrape deadline"))
		return
	}

	reg := prometheus.NewRegistry()
	g := func(name, help string) prometheus.Gauge {
		m := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
		reg.MustRegister(m)
		return m
	}
	success := g("probe_success", "Whether the probe succeeded (1) or failed (0).")
	duration := g("probe_duration_seconds", "Duration of the probe in seconds.")
	start := time.Now()
	o := run(ctx)
	duration.Set(time.Since(start).Seconds())
	if o.ok {
		success.Set(1)
	}
	if o.status != 0 {
		g("probe_http_status_code", "HTTP status of the answer (0 = no answer).").Set(float64(o.status))
	}
	if o.tls != nil && !o.tls.NotAfter.IsZero() {
		g("probe_ssl_earliest_cert_expiry", "NotAfter of the certificate the server presented, Unix seconds.").
			Set(float64(o.tls.NotAfter.Unix()))
	}
	outcome := "ok"
	if !o.ok {
		outcome = "failed"
		fi := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_failure_info",
			Help: "Why the probe failed: the prober's stable error code, or expectation_failed."}, []string{"code"})
		reg.MustRegister(fi)
		fi.WithLabelValues(o.code).Set(1)
		s.log.WarnContext(r.Context(), "probe failed", "module", module, "target", q.Get("target"), "host", q.Get("host"),
			"code", o.code, "status", o.status, "duration_ms", ms(time.Since(start)))
	}
	s.scrapes.WithLabelValues(module, outcome).Inc()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// outcome is the summary of one scrape probe.
type outcome struct {
	ok     bool
	status int
	tls    *TLSInfo
	code   string // stable error code, expectation_failed, or "" when ok
}

// plan validates a scrape (nothing is sent for an invalid one) and returns the probe to run.
func (s *scraper) plan(module string, q map[string][]string) (func(context.Context) outcome, *Error) {
	get := func(k string) string {
		if v := q[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	for k, v := range q {
		if len(v) != 1 || !slices.Contains([]string{"module", "target", "host", "capver"}, k) {
			return nil, newError(CodeInvalidRequest, "parameters are module, target, host and capver, each at most once")
		}
	}
	target, host := get("target"), strings.ToLower(get("host"))
	switch module {
	case ModuleKey:
		capver := s.capver
		if v := get("capver"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return nil, newError(CodeInvalidRequest, "capver must be 1-10000")
			}
			capver = n
		}
		req, err := keyRequest(target, host, capver, "", 0)
		if err != nil {
			return nil, asError(err)
		}
		p, err := planHTTPS(req)
		if err != nil {
			return nil, asError(err)
		}
		if err := checkTarget(s.l.allow, "target", p.addr); err != nil {
			return nil, asError(err)
		}
		return func(ctx context.Context) outcome {
			p.limit = budgetOf(ctx)
			res := s.l.https(ctx, p)
			checkKey(&res)
			return outcome{ok: res.OK, status: res.Status, tls: res.TLS, code: failureCode(res.Error, res.OK)}
		}, nil
	case ModuleTLS:
		if get("capver") != "" {
			return nil, newError(CodeInvalidRequest, "capver applies to the key module only")
		}
		addr, err := parseTarget("target", target)
		if err != nil {
			return nil, asError(err)
		}
		if !validHostname(host) || net.ParseIP(host) != nil {
			return nil, newError(CodeInvalidRequest, "host must be a DNS host name")
		}
		if err := checkTarget(s.l.allow, "target", addr); err != nil {
			return nil, asError(err)
		}
		return func(ctx context.Context) outcome {
			res, err := s.l.TLS(ctx, TLSRequest{Address: addr.String(), SNI: host,
				TimeoutMS: int(budgetOf(ctx) / time.Millisecond)})
			if err != nil {
				return outcome{code: CodeOf(err)}
			}
			return outcome{ok: res.OK, tls: res.TLS, code: failureCode(res.Error, res.OK)}
		}, nil
	}
	return nil, newError(CodeInvalidRequest, "module must be key or tls")
}

func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return newError(CodeInvalidRequest, message(err))
}

func failureCode(e *Error, ok bool) string {
	switch {
	case ok:
		return ""
	case e != nil:
		return e.Code
	}
	return "expectation_failed"
}

// scrapeBudget is the time a scrape may take: Prometheus's scrape timeout less half a second, within [1 s, MaxTimeout];
// DefaultHTTPSTimeout when the header is missing.
func scrapeBudget(header string) time.Duration {
	f, err := strconv.ParseFloat(header, 64)
	if err != nil || f <= 0 {
		return DefaultHTTPSTimeout
	}
	d := time.Duration(f*float64(time.Second)) - 500*time.Millisecond
	return min(max(d, time.Second), MaxTimeout)
}

// budgetOf is what is left of ctx for the probe itself (the slot wait came out of it).
func budgetOf(ctx context.Context) time.Duration {
	d := MaxTimeout
	if dl, ok := ctx.Deadline(); ok {
		d = time.Until(dl)
	}
	return min(max(d, 100*time.Millisecond), MaxTimeout)
}

func (s *scraper) refuse(w http.ResponseWriter, r *http.Request, module string, status int, e *Error) {
	if module == "" {
		module = "-"
	}
	if !slices.Contains([]string{ModuleKey, ModuleTLS, "-"}, module) {
		module = "invalid"
	}
	s.scrapes.WithLabelValues(module, e.Code).Inc()
	s.log.WarnContext(r.Context(), "probe scrape refused", "module", module, "status", status, "code", e.Code,
		"error", e.Message)
	writeError(w, status, e) // {"error": {"code", "message"}} — the RPC API's shape
}
