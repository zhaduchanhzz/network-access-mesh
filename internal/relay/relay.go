package relay

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// KindProbe is the job kind of the relay probe (§13.5).
const KindProbe = "relay.probe"

// ResourceType is the type of the job's resource (Job.resource): the probed region.
const ResourceType = "relay_region"

// Defaults of the probe schedule and of the read side.
const (
	// DefaultProbeInterval is the period of relay.probe per region.
	DefaultProbeInterval = 5 * time.Minute
	// DefaultStaleAfter is the age after which a recorded probe no longer gives a verdict (3 missed periods).
	DefaultStaleAfter = 3 * DefaultProbeInterval
	// DefaultProbeTimeout bounds the Prober call of one probe, below the 1-minute timeout of relay.probe (jobs
	// registry): the prober's own checks time out after 5 s (HTTPS) and 3 s (STUN).
	DefaultProbeTimeout = 40 * time.Second
)

// Region kinds (relay_regions.kind) and administrative statuses (relay_regions.status, relay_assignments.status).
const (
	KindEmbedded   = "embedded"
	KindStandalone = "standalone"
	KindShared     = "shared"

	AdminPending  = "pending"
	AdminActive   = "active"
	AdminDisabled = "disabled"
)

// Health statuses (schema HealthStatus of the API).
const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusUnknown   = "unknown"
)

// Reasons of a health that is not healthy (schema RelayHealth.reason). The verdicts of a probe:
const (
	ReasonDERPProbeFailed  = "derp_probe_failed" // GET /derp/probe through the edge did not answer 200
	ReasonSTUNProbeFailed  = "stun_probe_failed" // the STUN binding to the region's STUN address got no valid answer
	ReasonRelayUnreachable = "relay_unreachable" // both checks failed
)

// …and the reasons there is no verdict:
const (
	ReasonNeverChecked       = "never_checked"        // the region was never probed
	ReasonStale              = "stale"                // the last probe is older than StaleAfter
	ReasonInvalidRecord      = "invalid_record"       // last_probe does not hold a record of this module
	ReasonInstanceNotRunning = "instance_not_running" // no running instance serves the region (its DERP is down with it)
	ReasonNotActive          = "relay_not_active"     // the region or the assignment is not active (administrative state)
	ReasonNoProbe            = "no_probe"             // regions of this kind are not probed in this release (Phase 7)
)

// Reasons of a figure that is not available (schema UnavailableSection.reason).
const (
	// ReasonUnsupported: the component cannot provide the figure (the embedded DERP exports no relay metric — §10.6).
	ReasonUnsupported = "unsupported"
	// ReasonNoSource: the platform has no source for the figure yet.
	ReasonNoSource = "no_source"
)

// Unavailable is a relay figure the platform does not report, with the reason (§10.6, §12.4: "không khả dụng" kèm lý
// do — never a fake number).
type Unavailable struct {
	Metric string
	Reason string
	Detail string // short English sentence for people; the reason is the stable part
}

// unmeasured are the figures of §10.6 without a source for the embedded DERP of the MVP. A figure leaves this list in
// the task that builds its source (edge counters per hostname, V-25; log-derived authentication failures; a canary
// client — P6-T01).
var unmeasured = []Unavailable{
	{"traffic_bytes", ReasonUnsupported, "The embedded DERP of Headscale exports no relay byte counters; no estimate from the edge is collected yet."},
	{"throughput", ReasonUnsupported, "Relay throughput derives from byte counters, which the embedded DERP does not export."},
	{"connections", ReasonNoSource, "Concurrent relay connections per hostname at the edge are not measured yet."},
	{"auth_failures", ReasonNoSource, "Relay authentication failures are not derived from the Headscale log yet."},
	{"client_latency", ReasonNoSource, "Latency as clients see it needs a canary client running netcheck; none is deployed."},
}

// Unmeasured returns the relay figures of §10.6 the platform does not report, with their reasons (a fresh copy).
func Unmeasured() []Unavailable { return append([]Unavailable(nil), unmeasured...) }

// ProbeRequest is one relay probe as the prober runs it (apps/probe, P3-T03a — POST /v1/relay).
type ProbeRequest struct {
	Address string // the edge's public listener, ip:port (the DERP of an embedded region is behind it)
	Host    string // the region's hostname: SNI and Host of GET /derp/probe
	STUN    string // the region's STUN address, ip:port (the shared responder of the public entry)
}

// Check is the outcome of one check of a probe.
type Check struct {
	OK       bool
	Status   int    // HTTP status when one was received (derp)
	Code     string // the prober's error code (timeout, refused, tls_verify…) or expectation_failed; "" when OK
	Duration time.Duration
}

// ProbeResult is the outcome of a relay probe that ran.
type ProbeResult struct {
	DERP Check // GET /derp/probe ⇒ 200
	STUN Check // STUN binding ⇒ mapped address
}

// Prober runs a relay probe. In apps/* it wraps the prober's RPC client (relay does not import apps/*):
//
//	relay.ProberFunc(func(ctx context.Context, p relay.ProbeRequest) (relay.ProbeResult, error) {
//		r, err := client.Relay(ctx, prober.RelayRequest{Address: p.Address, Host: p.Host, STUN: p.STUN})
//		… map r.DERP / r.STUN …
//	})
//
// An error means the probe could not run (prober unreachable, target outside its allow-list) — nothing is said about
// the relay; a probe that ran and failed is a result with failed checks.
type Prober interface {
	Relay(ctx context.Context, p ProbeRequest) (ProbeResult, error)
}

// ProberFunc adapts a function to Prober.
type ProberFunc func(ctx context.Context, p ProbeRequest) (ProbeResult, error)

// Relay calls f.
func (f ProberFunc) Relay(ctx context.Context, p ProbeRequest) (ProbeResult, error) { return f(ctx, p) }

// Config are the collaborators and settings of a Service.
type Config struct {
	// Prober is required to run relay.probe (Register, worker process); the api process reads only.
	Prober Prober
	// EdgeAddress (ip:port) is the edge's public listener as the prober reaches it — MG_PROVISION_EDGE_ADDR, the address
	// step 17 probes. Required with Prober.
	EdgeAddress string
	// StaleAfter: a recorded probe older than this gives no verdict (unknown, reason stale); default DefaultStaleAfter.
	// Keep it a few periods of the worker's SchedulerConfig.Interval.
	StaleAfter time.Duration
	// ProbeTimeout bounds the Prober call of one probe; default DefaultProbeTimeout (below relay.probe's job timeout).
	ProbeTimeout time.Duration
	Logger       *slog.Logger
	// Registerer exports the module's metrics; nil keeps them unexported.
	Registerer prometheus.Registerer
}

// Service is the RelayService of §4.2: the read models of GET /tenants/{t}/relay and GET /platform/relay-regions, the
// relay.probe handler (Register) and its schedule (NewScheduler).
type Service struct {
	st         *store.Store
	prober     Prober
	edge       string
	staleAfter time.Duration
	probeLimit time.Duration
	log        *slog.Logger
	m          *metrics
}

// New returns the service of the process whose store is st (api: mg_api_*, worker: mg_worker_*).
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil {
		return nil, errors.New("relay: a store is required")
	}
	if cfg.Prober != nil {
		if _, err := netip.ParseAddrPort(cfg.EdgeAddress); err != nil {
			return nil, errors.New("relay: a Prober needs EdgeAddress (ip:port of the edge's public listener)")
		}
	}
	s := &Service{st: st, prober: cfg.Prober, edge: cfg.EdgeAddress, staleAfter: cfg.StaleAfter, probeLimit: cfg.ProbeTimeout,
		log: cfg.Logger, m: newMetrics(cfg.Registerer)}
	if s.staleAfter <= 0 {
		s.staleAfter = DefaultStaleAfter
	}
	if s.probeLimit <= 0 {
		s.probeLimit = DefaultProbeTimeout
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}
