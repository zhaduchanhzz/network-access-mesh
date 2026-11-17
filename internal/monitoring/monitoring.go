package monitoring

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// KindProbe is the job kind of the instance health probe (§13.5).
const KindProbe = "health.probe"

// Defaults of the probe schedule and of the read side.
const (
	// DefaultProbeInterval is the period of health.probe per instance.
	DefaultProbeInterval = 2 * time.Minute
	// DefaultStaleAfter is the age after which a recorded probe no longer gives a verdict (3 missed periods).
	DefaultStaleAfter = 3 * DefaultProbeInterval
	// DefaultHeartbeatMaxAge is the age after which the worker's heartbeat (job.reaper, every minute) is stale.
	DefaultHeartbeatMaxAge = 3 * time.Minute
	// DefaultProbeTimeout bounds one probe, below the 1-minute timeout of health.probe (registry of P2-T12): an instance
	// that does not answer in time is recorded unhealthy instead of failing the job.
	DefaultProbeTimeout = 40 * time.Second
)

// Health statuses (schema HealthStatus of the API).
const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusUnknown   = "unknown"
)

// Reasons of the read side (the probe's own reasons come from the Prober: headscale.Probe*).
const (
	ReasonNoInstance         = "no_instance"          // the tenant has no instance that is not removed
	ReasonNeverChecked       = "never_checked"        // the instance was never probed
	ReasonStale              = "stale"                // the last probe is older than StaleAfter
	ReasonInstanceNotRunning = "instance_not_running" // only running instances are probed: no verdict
	ReasonInvalidRecord      = "invalid_record"       // last_health does not hold a record of this module
	ReasonIncompleteProbe    = "incomplete_probe"     // the Prober reported no failure but no database connectivity either
)

// InstanceProbe is the outcome of one probe of a tenant's instance through the Headscale adapter.
type InstanceProbe struct {
	InstanceID uuid.UUID     // the instance the adapter resolved; uuid.Nil when it could not resolve one
	Version    string        // version the instance reported ("" when not reached)
	Database   *bool         // database connectivity the instance reported (nil when not reached)
	Breaker    string        // state of the adapter's circuit breaker for the instance after the probe
	Reason     string        // "" when healthy, else a stable code — never upstream text
	Duration   time.Duration // wall time of the probe
}

// Prober probes the instance of a tenant. In apps/* it wraps headscale.CachingRegistry.Probe (monitoring does not
// import internal/headscale — §13.6):
//
//	monitoring.ProberFunc(func(ctx context.Context, t uuid.UUID) monitoring.InstanceProbe {
//		p := reg.Probe(ctx, t)
//		return monitoring.InstanceProbe{InstanceID: p.InstanceID, Version: p.Version, Database: p.Database,
//			Breaker: string(p.Breaker), Reason: p.Reason(), Duration: p.Duration}
//	})
type Prober interface {
	ProbeInstance(ctx context.Context, tenantID uuid.UUID) InstanceProbe
}

// ProberFunc adapts a function to Prober.
type ProberFunc func(ctx context.Context, tenantID uuid.UUID) InstanceProbe

// ProbeInstance calls f.
func (f ProberFunc) ProbeInstance(ctx context.Context, tenantID uuid.UUID) InstanceProbe {
	return f(ctx, tenantID)
}

// DeviceCounts are the device figures of a tenant dashboard and the time of the sync they come from (nil: never
// synced — the counts then hold no figure).
type DeviceCounts struct {
	Total    int
	Online   int
	SyncedAt *time.Time
}

// DeviceCounter reads the device figures of a tenant through the devices module (§13.6: monitoring never reads the
// devices' tables). In apps/* (devices.Summary has the same fields, so the conversion is checked by the compiler):
//
//	monitoring.DeviceCounterFunc(func(ctx context.Context, t uuid.UUID) (monitoring.DeviceCounts, error) {
//		s, err := devicesSvc.Summary(ctx, t)
//		return monitoring.DeviceCounts(s), err
//	})
type DeviceCounter interface {
	DeviceCounts(ctx context.Context, tenantID uuid.UUID) (DeviceCounts, error)
}

// DeviceCounterFunc adapts a function to DeviceCounter.
type DeviceCounterFunc func(ctx context.Context, tenantID uuid.UUID) (DeviceCounts, error)

// DeviceCounts calls f.
func (f DeviceCounterFunc) DeviceCounts(ctx context.Context, tenantID uuid.UUID) (DeviceCounts, error) {
	return f(ctx, tenantID)
}

// Config are the collaborators and settings of a Service.
type Config struct {
	// Devices is required: the device figures of the tenant dashboard.
	Devices DeviceCounter
	// Prober is required to run health.probe (Register, worker process).
	Prober Prober
	// StaleAfter: a recorded probe older than this gives no verdict (unknown, reason stale); default DefaultStaleAfter.
	// Keep it a few periods of the worker's SchedulerConfig.Interval.
	StaleAfter time.Duration
	// HeartbeatMaxAge: the worker is unhealthy when job.reaper last finished longer ago; default DefaultHeartbeatMaxAge.
	HeartbeatMaxAge time.Duration
	// ProbeTimeout bounds the Prober call of one probe; default DefaultProbeTimeout. Keep it below the job timeout of
	// health.probe (jobs.Config.Kinds) — with the adapter's defaults a probe of a hung instance takes about 31 s.
	ProbeTimeout time.Duration
	Logger       *slog.Logger
	// Registerer exports the module's metrics; nil keeps them unexported.
	Registerer prometheus.Registerer
}

// Service is the HealthService of §4.2 and the read models of the dashboards: Probe and the health.probe handler
// (Register), the schedule of health.probe (NewScheduler), TenantDashboard and PlatformHealth.
type Service struct {
	st         *store.Store
	devices    DeviceCounter
	prober     Prober
	staleAfter time.Duration
	heartbeat  time.Duration
	probeLimit time.Duration
	log        *slog.Logger
	m          *metrics
}

// New returns the service of the process whose store is st (api: mg_api_*, worker: mg_worker_*).
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Devices == nil {
		return nil, errors.New("monitoring: a store and a device counter are required")
	}
	s := &Service{st: st, devices: cfg.Devices, prober: cfg.Prober, staleAfter: cfg.StaleAfter, heartbeat: cfg.HeartbeatMaxAge,
		probeLimit: cfg.ProbeTimeout, log: cfg.Logger, m: newMetrics(cfg.Registerer)}
	if s.staleAfter <= 0 {
		s.staleAfter = DefaultStaleAfter
	}
	if s.heartbeat <= 0 {
		s.heartbeat = DefaultHeartbeatMaxAge
	}
	if s.probeLimit <= 0 {
		s.probeLimit = DefaultProbeTimeout
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}
