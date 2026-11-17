package apikey

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// Metric names (§16.1 "API / Worker"; the alert of §16.3 "API key của instance còn < 14 ngày" — P3-T16/P6-T01):
//
//	meshguard_instance_api_key_expires_in_seconds < 14 * 86400
//
// or, from the timestamp, (meshguard_instance_api_key_expiration_timestamp_seconds - time()) < 14 * 86400.
const (
	MetricExpiresIn  = "meshguard_instance_api_key_expires_in_seconds"
	MetricExpiration = "meshguard_instance_api_key_expiration_timestamp_seconds"
	MetricRotations  = "meshguard_api_key_rotations_total"
	MetricScheduled  = "meshguard_api_key_rotation_jobs_scheduled_total"
	MetricEvents     = "meshguard_api_key_security_events_total"
)

// Results of meshguard_api_key_rotations_total.
const (
	ResultRotated      = "rotated"
	ResultBootstrapped = "bootstrapped"
	ResultSkipped      = "skipped"
	ResultFailed       = "failed"
)

type metrics struct {
	rotations *prometheus.CounterVec // result, code ("" unless failed; the skip reason when skipped)
	scheduled prometheus.Counter
	events    *prometheus.CounterVec // kind
	expiry    *expiryCollector
}

func newMetrics(reg prometheus.Registerer, now func() time.Time) *metrics {
	m := &metrics{
		rotations: prometheus.NewCounterVec(prometheus.CounterOpts{Name: MetricRotations,
			Help: "API key rotations of the instances by result (rotated, bootstrapped, skipped, failed) and code (skip reason or error code)."},
			[]string{"result", "code"}),
		scheduled: prometheus.NewCounter(prometheus.CounterOpts{Name: MetricScheduled,
			Help: "apikey.rotate jobs enqueued by the schedule."}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{Name: MetricEvents,
			Help: "Security events raised by the API key rotation, by kind (before dedupe)."}, []string{"kind"}),
		expiry: &expiryCollector{now: now, entries: map[uuid.UUID]expiryEntry{},
			in: prometheus.NewDesc(MetricExpiresIn,
				"Seconds until the recorded API key of the instance expires (negative: expired), computed at scrape time.",
				[]string{"tenant_id", "instance_id"}, nil),
			at: prometheus.NewDesc(MetricExpiration, "Recorded expiration time of the instance's API key (Unix seconds).",
				[]string{"tenant_id", "instance_id"}, nil)},
	}
	for _, k := range []string{EventRejected, EventStray, EventLeftover} {
		m.events.WithLabelValues(k)
	}
	if reg != nil {
		reg.MustRegister(m.rotations, m.scheduled, m.events, m.expiry)
	}
	return m
}

// result counts the outcome of one rotation.
func (m *metrics) result(res Result, err error) {
	switch {
	case err != nil:
		code := jobs.CodeHandlerError
		var je *jobs.Error
		if errors.As(err, &je) {
			code = je.Code
		}
		m.rotations.WithLabelValues(ResultFailed, code).Inc()
	case res.Outcome == OutcomeRotated:
		m.rotations.WithLabelValues(ResultRotated, "").Inc()
	case res.Outcome == OutcomeBootstrapped:
		m.rotations.WithLabelValues(ResultBootstrapped, res.BootstrapReason).Inc()
	default:
		m.rotations.WithLabelValues(ResultSkipped, res.SkipReason).Inc()
	}
}

// observe records the expiry of an instance's key (nil: no expiry recorded — the instance is not exported).
func (m *metrics) observe(tenantID, instanceID uuid.UUID, at *time.Time) {
	m.expiry.mu.Lock()
	defer m.expiry.mu.Unlock()
	if at == nil {
		delete(m.expiry.entries, instanceID)
		return
	}
	m.expiry.entries[instanceID] = expiryEntry{tenant: tenantID, at: *at}
}

func (m *metrics) forget(instanceID uuid.UUID) {
	m.expiry.mu.Lock()
	delete(m.expiry.entries, instanceID)
	m.expiry.mu.Unlock()
}

// replace sets the whole gauge from the registry (the schedule's tick).
func (m *metrics) replace(rows []expiry) {
	next := make(map[uuid.UUID]expiryEntry, len(rows))
	for _, r := range rows {
		if r.ExpiresAt != nil {
			next[r.InstanceID] = expiryEntry{tenant: r.TenantID, at: *r.ExpiresAt}
		}
	}
	m.expiry.mu.Lock()
	m.expiry.entries = next
	m.expiry.mu.Unlock()
}

type expiryEntry struct {
	tenant uuid.UUID
	at     time.Time
}

// expiryCollector exports the recorded expiry of every scheduled instance's key; the remaining time is computed at
// scrape time, so it never goes stale between two reads of the registry.
type expiryCollector struct {
	now     func() time.Time
	in, at  *prometheus.Desc
	mu      sync.Mutex
	entries map[uuid.UUID]expiryEntry
}

func (c *expiryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.in
	ch <- c.at
}

func (c *expiryCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for id, e := range c.entries {
		t, i := e.tenant.String(), id.String()
		ch <- prometheus.MustNewConstMetric(c.in, prometheus.GaugeValue, e.at.Sub(now).Seconds(), t, i)
		ch <- prometheus.MustNewConstMetric(c.at, prometheus.GaugeValue, float64(e.at.UnixNano())/1e9, t, i)
	}
}

// Expiries returns the exported expiries (instance → time) — for tests and the admin command.
func (s *Service) Expiries() map[uuid.UUID]time.Time {
	s.m.expiry.mu.Lock()
	defer s.m.expiry.mu.Unlock()
	out := make(map[uuid.UUID]time.Time, len(s.m.expiry.entries))
	for id, e := range s.m.expiry.entries {
		out[id] = e.at
	}
	return out
}
