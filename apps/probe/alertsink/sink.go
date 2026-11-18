// Package alertsink is the internal alert channel of staging and of the dev/CI stack (P3-T16; master plan §16.3): a
// receiver of Alertmanager's webhook (payload version 4) that keeps the last notifications in memory, logs one line
// per alert and serves them back for the alert drills. It is NOT a delivery channel to people — e-mail, Telegram or an
// external webhook are configured next to it in Alertmanager when the owner provides them (docs/planning/evidence/
// P3-T16.md); the sink is what proves the pipeline Prometheus → Alertmanager → receiver works until then.
//
//	POST /v1/alerts         Alertmanager webhook (application/json, at most 1 MiB, version "4") ⇒ 200
//	GET  /v1/notifications  the notifications kept, oldest first (JSON) — ?alertname=<name> filters by alert name
//
// Only callers inside the allow-list (MG_ALERTSINK_ALLOW_CALLERS — the monitoring network) are served; every other
// caller gets 403 before routing. Notifications hold labels and annotations of alerts — no secret: the alert rules of
// infrastructure/monitoring never put a credential in a label or annotation, and every value goes through
// logx.RedactString before it is kept or logged.
package alertsink

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Routes of the sink.
const (
	RouteAlerts        = "/v1/alerts"
	RouteNotifications = "/v1/notifications"
)

// Limits.
const (
	maxBody     = 1 << 20 // Alertmanager caps a webhook body far below this (max_alerts)
	maxAlerts   = 200     // alerts kept per notification
	maxValue    = 1024    // bytes kept of one label or annotation value
	maxPairs    = 64      // labels or annotations kept per alert
	DefaultKeep = 1000    // notifications kept
)

// Alert is one alert of a notification.
type Alert struct {
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations,omitempty"`
	StartsAt    time.Time         `json:"starts_at"`
	EndsAt      time.Time         `json:"ends_at,omitzero"`
	Fingerprint string            `json:"fingerprint,omitempty"`
}

// Notification is one webhook call of Alertmanager as the sink keeps it.
type Notification struct {
	Seq        int64             `json:"seq"`
	ReceivedAt time.Time         `json:"received_at"`
	Receiver   string            `json:"receiver"`
	Status     string            `json:"status"`
	GroupKey   string            `json:"group_key"`
	GroupLabel map[string]string `json:"group_labels,omitempty"`
	Truncated  int               `json:"truncated_alerts,omitempty"`
	Alerts     []Alert           `json:"alerts"`
}

// Options configures the sink.
type Options struct {
	// Callers is the allow-list of callers (Alertmanager and the drill reader). Empty: every caller is refused.
	Callers []netip.Prefix
	// Keep bounds the notifications kept (default DefaultKeep); the oldest is dropped first.
	Keep int
	// Logger receives one INFO line per alert received and one WARN line per refused request; nil = discard.
	Logger *slog.Logger
	// Registerer receives meshguard_alertsink_notifications_total{receiver,status} and
	// meshguard_alertsink_last_notification_timestamp_seconds; nil = none.
	Registerer prometheus.Registerer
	// Now is the clock of ReceivedAt; nil = time.Now.
	Now func() time.Time
}

// Sink keeps the notifications received.
type Sink struct {
	callers []netip.Prefix
	keep    int
	log     *slog.Logger
	now     func() time.Time
	total   *prometheus.CounterVec
	last    prometheus.Gauge

	mu    sync.Mutex
	seq   int64
	notes []Notification
}

// New returns a sink.
func New(o Options) *Sink {
	s := &Sink{callers: slices.Clone(o.Callers), keep: o.Keep, log: o.Logger, now: o.Now}
	if s.keep <= 0 {
		s.keep = DefaultKeep
	}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.total = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_alertsink_notifications_total",
		Help: "Alertmanager notifications received by the internal alert sink, by receiver and status."},
		[]string{"receiver", "status"})
	s.last = prometheus.NewGauge(prometheus.GaugeOpts{Name: "meshguard_alertsink_last_notification_timestamp_seconds",
		Help: "Unix time of the last notification the internal alert sink accepted (0 = none yet)."})
	if o.Registerer != nil {
		o.Registerer.MustRegister(s.total, s.last)
	}
	return s
}

// Notifications returns a copy of the notifications kept, oldest first.
func (s *Sink) Notifications() []Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.notes)
}

// Handler serves the routes of the sink.
func (s *Sink) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+RouteAlerts, s.receive)
	mux.HandleFunc("GET "+RouteNotifications, s.list)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == RouteAlerts || r.URL.Path == RouteNotifications {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "unknown route")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		a, perr := netip.ParseAddr(host)
		if err != nil || perr != nil || !allowed(s.callers, a.Unmap()) {
			s.log.WarnContext(r.Context(), "alertsink: caller refused", "remote", host, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, "caller outside the alert sink's allow-list")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func allowed(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// payload is the webhook body of Alertmanager (version 4).
type payload struct {
	Version         string            `json:"version"`
	GroupKey        string            `json:"groupKey"`
	TruncatedAlerts int               `json:"truncatedAlerts"`
	Status          string            `json:"status"`
	Receiver        string            `json:"receiver"`
	GroupLabels     map[string]string `json:"groupLabels"`
	Alerts          []struct {
		Status      string            `json:"status"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    time.Time         `json:"startsAt"`
		EndsAt      time.Time         `json:"endsAt"`
		Fingerprint string            `json:"fingerprint"`
	} `json:"alerts"`
}

func (s *Sink) receive(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		s.refuse(w, r, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.refuse(w, r, http.StatusRequestEntityTooLarge, "body larger than 1 MiB")
			return
		}
		s.refuse(w, r, http.StatusBadRequest, "body unreadable")
		return
	}
	var p payload
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&p); err != nil || dec.More() {
		s.refuse(w, r, http.StatusBadRequest, "body must be one JSON object (Alertmanager webhook)")
		return
	}
	if p.Version != "4" || (p.Status != "firing" && p.Status != "resolved") || len(p.Alerts) == 0 {
		s.refuse(w, r, http.StatusBadRequest, "not an Alertmanager webhook notification (version 4, firing|resolved, alerts)")
		return
	}
	n := Notification{ReceivedAt: s.now().UTC(), Receiver: clean(p.Receiver), Status: p.Status,
		GroupKey: clean(p.GroupKey), GroupLabel: cleanMap(p.GroupLabels), Truncated: p.TruncatedAlerts}
	for i, a := range p.Alerts {
		if i == maxAlerts {
			n.Truncated += len(p.Alerts) - maxAlerts
			break
		}
		st := a.Status
		if st != "firing" && st != "resolved" {
			st = "unknown"
		}
		n.Alerts = append(n.Alerts, Alert{Status: st, Labels: cleanMap(a.Labels), Annotations: cleanMap(a.Annotations),
			StartsAt: a.StartsAt.UTC(), EndsAt: a.EndsAt.UTC(), Fingerprint: clean(a.Fingerprint)})
	}
	s.mu.Lock()
	s.seq++
	n.Seq = s.seq
	s.notes = append(s.notes, n)
	if over := len(s.notes) - s.keep; over > 0 {
		s.notes = slices.Delete(s.notes, 0, over)
	}
	s.mu.Unlock()
	s.total.WithLabelValues(n.Receiver, n.Status).Inc()
	s.last.Set(float64(n.ReceivedAt.Unix()))
	for _, a := range n.Alerts {
		s.log.InfoContext(r.Context(), "alert notification", "seq", n.Seq, "receiver", n.Receiver,
			"notification_status", n.Status, "status", a.Status, "alertname", a.Labels["alertname"],
			"severity", a.Labels["severity"], "labels", a.Labels, "summary", a.Annotations["summary"])
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{\"ok\":true}\n")
}

func (s *Sink) list(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("alertname")
	out := []Notification{}
	for _, n := range s.Notifications() {
		if name == "" || slices.ContainsFunc(n.Alerts, func(a Alert) bool { return a.Labels["alertname"] == name }) {
			out = append(out, n)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"notifications": out})
}

func (s *Sink) refuse(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.log.WarnContext(r.Context(), "alertsink: request refused", "status", status, "error", msg)
	writeError(w, status, msg)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// clean redacts a value and bounds it to maxValue bytes (on a rune boundary).
func clean(v string) string {
	v = logx.RedactString(v)
	if len(v) <= maxValue {
		return v
	}
	cut := maxValue
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "…"
}

func cleanMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, min(len(keys), maxPairs))
	for i, k := range keys {
		if i == maxPairs {
			break
		}
		out[clean(k)] = clean(m[k])
	}
	return out
}
