package prober

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// RPC routes of the service (internal API for the worker — §11.3 steps 17–18, P3-T05c).
const (
	RouteSTUN  = "/v1/stun"
	RouteHTTPS = "/v1/https"
	RouteEdge  = "/v1/edge"
	RouteRelay = "/v1/relay"
)

const maxRequestBody = 64 << 10

// HandlerOptions configures the RPC handler.
type HandlerOptions struct {
	// Callers is the allow-list of RPC clients (MG_PROBE_ALLOW_CALLERS — the worker's network). Empty: every caller
	// is refused (fail closed).
	Callers []netip.Prefix
	// MaxInFlight bounds the probes run at once; a request beyond it is answered 429 busy. 0 = 8.
	MaxInFlight int
	// Logger receives refused requests (the probes log themselves); nil = discard.
	Logger *slog.Logger
	// Registerer receives the RPC metrics; nil = none.
	Registerer prometheus.Registerer
}

type handler struct {
	p       Prober
	callers []netip.Prefix
	slots   chan struct{}
	log     *slog.Logger
	total   *prometheus.CounterVec
	dur     *prometheus.HistogramVec
}

// Handler serves the RPC API over p: POST <route> with the request as JSON (application/json, at most 64 KiB, unknown
// fields refused) ⇒ 200 + the result; 400 invalid_request, 403 target_not_allowed / caller_not_allowed, 404, 405,
// 413, 415, 429 busy ⇒ {"error": {"code", "message"}}.
func Handler(p Prober, o HandlerOptions) http.Handler {
	h := &handler{p: p, callers: slices.Clone(o.Callers), log: o.Logger}
	if h.log == nil {
		h.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	n := o.MaxInFlight
	if n <= 0 {
		n = 8
	}
	h.slots = make(chan struct{}, n)
	h.total = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_probe_rpc_total",
		Help: "Prober RPC requests by kind and outcome (ok, failed, or why the probe did not run)."}, []string{"kind", "outcome"})
	h.dur = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "meshguard_probe_rpc_duration_seconds",
		Help: "Duration of the probes run through the RPC API.", Buckets: prometheus.ExponentialBuckets(0.005, 2, 12)},
		[]string{"kind"})
	if o.Registerer != nil {
		o.Registerer.MustRegister(h.total, h.dur)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+RouteSTUN, serve(h, "stun", p.STUN))
	mux.HandleFunc("POST "+RouteHTTPS, serve(h, "https", p.HTTPS))
	mux.HandleFunc("POST "+RouteEdge, serve(h, "edge", p.Edge))
	mux.HandleFunc("POST "+RouteRelay, serve(h, "relay", p.Relay))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for _, route := range []string{RouteSTUN, RouteHTTPS, RouteEdge, RouteRelay} {
			if r.URL.Path == route {
				w.Header().Set("Allow", http.MethodPost)
				writeError(w, http.StatusMethodNotAllowed, newError(CodeInvalidRequest, "method not allowed"))
				return
			}
		}
		writeError(w, http.StatusNotFound, newError(CodeNotFound, "unknown route"))
	})
	return h.guard(mux)
}

// guard refuses every caller outside the allow-list, before routing.
func (h *handler) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		a, perr := netip.ParseAddr(host)
		if err != nil || perr != nil || !allowed(h.callers, a) {
			h.total.WithLabelValues("-", CodeCallerNotAllowed).Inc()
			h.log.WarnContext(r.Context(), "prober rpc: caller refused", "remote", host, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, newError(CodeCallerNotAllowed, "caller outside the prober's allow-list"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// result is what every probe kind returns: a result whose OK field tells whether the probe passed.
type result interface {
	STUNResult | HTTPSResult | EdgeResult | RelayResult
}

func ok(v any) bool {
	switch r := v.(type) {
	case STUNResult:
		return r.OK
	case HTTPSResult:
		return r.OK
	case EdgeResult:
		return r.OK
	case RelayResult:
		return r.OK
	}
	return false
}

func serve[Req any, Res result](h *handler, kind string, run func(context.Context, Req) (Res, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			h.refuse(w, r, kind, http.StatusUnsupportedMediaType, newError(CodeInvalidRequest, "content type must be application/json"))
			return
		}
		var req Req
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
		if err != nil {
			var mbe *http.MaxBytesError
			status := http.StatusBadRequest
			if errors.As(err, &mbe) {
				status = http.StatusRequestEntityTooLarge
			}
			h.refuse(w, r, kind, status, newError(CodeInvalidRequest, "request body unreadable or larger than 64 KiB"))
			return
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || dec.More() {
			h.refuse(w, r, kind, http.StatusBadRequest, newError(CodeInvalidRequest, "request must be one JSON object of known fields"))
			return
		}
		select {
		case h.slots <- struct{}{}:
			defer func() { <-h.slots }()
		default:
			h.refuse(w, r, kind, http.StatusTooManyRequests, newError(CodeBusy, "too many probes in flight"))
			return
		}
		start := time.Now()
		res, err := run(r.Context(), req)
		if err != nil {
			e := &Error{Code: CodeInvalidRequest, Message: message(err)}
			_ = errors.As(err, &e)
			status := http.StatusBadRequest
			if e.Code == CodeTargetNotAllowed {
				status = http.StatusForbidden
			}
			h.refuse(w, r, kind, status, e)
			return
		}
		h.dur.WithLabelValues(kind).Observe(time.Since(start).Seconds())
		outcome := "failed"
		if ok(res) {
			outcome = "ok"
		}
		h.total.WithLabelValues(kind, outcome).Inc()
		writeJSON(w, http.StatusOK, res)
	}
}

func (h *handler) refuse(w http.ResponseWriter, r *http.Request, kind string, status int, e *Error) {
	h.total.WithLabelValues(kind, e.Code).Inc()
	h.log.WarnContext(r.Context(), "prober rpc: request refused", "kind", kind, "status", status, "code", e.Code,
		"error", e.Message)
	writeError(w, status, e)
}

func writeError(w http.ResponseWriter, status int, e *Error) {
	writeJSON(w, status, struct {
		Error *Error `json:"error"`
	}{e})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
