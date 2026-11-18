package mailrelay

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics of the relay (meshguard_mailrelay_*). Every method is a no-op on a nil *Metrics. No label carries an address
// or anything taken from a message.
type Metrics struct {
	sessions   prometheus.Counter
	active     prometheus.Gauge
	starttls   *prometheus.CounterVec
	rejected   *prometheus.CounterVec
	messages   *prometheus.CounterVec
	recipients *prometheus.CounterVec
	attempts   *prometheus.CounterVec
	duration   prometheus.Histogram
}

// Rejection reasons (label `reason` of meshguard_mailrelay_rejected_total).
const (
	ReasonBusy              = "busy"
	ReasonTLSRequired       = "tls_required"
	ReasonSender            = "sender"
	ReasonRecipient         = "recipient"
	ReasonTooManyRecipients = "too_many_recipients"
	ReasonSize              = "size"
	ReasonHeader            = "header"
	ReasonRate              = "rate"
	ReasonSyntax            = "syntax"
)

// NewMetrics registers the relay's metrics on reg.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		sessions: prometheus.NewCounter(prometheus.CounterOpts{Name: "meshguard_mailrelay_sessions_total",
			Help: "SMTP sessions accepted by the mail relay."}),
		active: prometheus.NewGauge(prometheus.GaugeOpts{Name: "meshguard_mailrelay_sessions_active",
			Help: "SMTP sessions in progress."}),
		starttls: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_mailrelay_starttls_total",
			Help: "STARTTLS upgrades by result (ok, failed)."}, []string{"result"}),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_mailrelay_rejected_total",
			Help: "SMTP commands or messages refused by the relay itself, by reason."}, []string{"reason"}),
		messages: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_mailrelay_messages_total",
			Help: "Messages handed to the Worker, by outcome (delivered, partial, temporary, permanent)."}, []string{"result"}),
		recipients: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_mailrelay_recipients_total",
			Help: "Recipients the Worker reported, by result (sent, failed)."}, []string{"result"}),
		attempts: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_mailrelay_forward_attempts_total",
			Help: "HTTPS requests to the Worker, by status class (2xx, 4xx, 429, 5xx, error)."}, []string{"status"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "meshguard_mailrelay_forward_duration_seconds",
			Help:    "Time to hand one message to the Worker, all attempts included.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 4, 8, 16}}),
	}
	for _, c := range []prometheus.Collector{m.sessions, m.active, m.starttls, m.rejected, m.messages, m.recipients,
		m.attempts, m.duration} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	for _, r := range []string{"ok", "failed"} {
		m.starttls.WithLabelValues(r)
	}
	for _, r := range []string{ReasonBusy, ReasonTLSRequired, ReasonSender, ReasonRecipient, ReasonTooManyRecipients,
		ReasonSize, ReasonHeader, ReasonRate, ReasonSyntax} {
		m.rejected.WithLabelValues(r)
	}
	for _, c := range []Class{Delivered, Partial, Temporary, Permanent} {
		m.messages.WithLabelValues(c.String())
	}
	for _, r := range []string{"sent", "failed"} {
		m.recipients.WithLabelValues(r)
	}
	for _, s := range []string{"2xx", "4xx", "429", "5xx", "error"} {
		m.attempts.WithLabelValues(s)
	}
	return m, nil
}

func (m *Metrics) session() func() {
	if m == nil {
		return func() {}
	}
	m.sessions.Inc()
	m.active.Inc()
	return m.active.Dec
}

func (m *Metrics) tls(ok bool) {
	if m == nil {
		return
	}
	if ok {
		m.starttls.WithLabelValues("ok").Inc()
	} else {
		m.starttls.WithLabelValues("failed").Inc()
	}
}

func (m *Metrics) reject(reason string) {
	if m != nil {
		m.rejected.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) message(o Outcome, d time.Duration) {
	if m == nil {
		return
	}
	m.messages.WithLabelValues(o.Class.String()).Inc()
	m.recipients.WithLabelValues("sent").Add(float64(o.Sent))
	m.recipients.WithLabelValues("failed").Add(float64(o.Failed))
	m.duration.Observe(d.Seconds())
}

func (m *Metrics) attempt(status int) {
	if m == nil {
		return
	}
	class := "error"
	switch {
	case status == 429:
		class = "429"
	case status >= 500:
		class = "5xx"
	case status >= 400:
		class = "4xx"
	case status >= 200 && status < 300:
		class = "2xx"
	}
	m.attempts.WithLabelValues(class).Inc()
}
