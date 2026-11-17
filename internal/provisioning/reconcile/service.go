package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Defaults.
const (
	// DefaultInterval is the period of instance.reconcile per instance and of host.reconcile.
	DefaultInterval = 10 * time.Minute
	// DefaultRotationGrace: the key rotation of §11.4 runs in one apikey.rotate job (whole-job timeout 5 min, §13.5).
	DefaultRotationGrace = 15 * time.Minute
	// DefaultEventWindow: one security event per subject (instance + key prefix, alias…) and day while the drift lasts.
	DefaultEventWindow = 24 * time.Hour
	// DefaultAgentTimeout bounds one call to the agent, below the 5-minute job timeout of the reconcile kinds.
	DefaultAgentTimeout = time.Minute
	// DefaultKeyLockWait bounds the wait of the API key check for the instance's API key lock (a rotation holds it for
	// a few seconds); past it the check reports api_key_rotation_in_progress (unavailable, no finding).
	DefaultKeyLockWait = 30 * time.Second
)

// SecurityRecorder writes a security event (dedupe per DedupeKey): in apps/worker a platform transaction of the
// worker's store (audit.RecordSecurityEvent), like the integrity reporter of the SecretStore.
type SecurityRecorder interface {
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

// Config are the collaborators and settings of a Service.
type Config struct {
	// Agent of the host; nil = no agent configured (dev): the agent checks report agent_unavailable.
	Agent Agent
	// Headscale reaches a tenant's instance for its API key list; nil = the key check is unavailable.
	Headscale headscale.Registry
	// Security records the security events; required.
	Security SecurityRecorder
	// AgentUID/AgentGID own the agent's paths (0 in production).
	AgentUID, AgentGID uint32
	// RotationGrace, EventWindow, AgentTimeout, KeyLockWait: zero = the defaults above.
	RotationGrace time.Duration
	EventWindow   time.Duration
	AgentTimeout  time.Duration
	KeyLockWait   time.Duration
	Logger        *slog.Logger
	// Registerer exports the metrics; nil keeps them unexported.
	Registerer prometheus.Registerer
}

// Service runs the two reconcile jobs on the worker's store (mg_worker_*: platform transactions only — reads).
type Service struct {
	st  *store.Store
	in  *Inspector
	sec SecurityRecorder
	log *slog.Logger
	m   *metrics

	mu    sync.Mutex
	drift map[string]map[string]int // subject (instance id, "host") → kind → findings of its latest report
}

// New returns the reconcile service of the worker.
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Security == nil {
		return nil, errors.New("reconcile: a store and a security recorder are required")
	}
	in := &Inspector{Agent: cfg.Agent, Headscale: cfg.Headscale, AgentUID: cfg.AgentUID, AgentGID: cfg.AgentGID,
		RotationGrace: cfg.RotationGrace, EventWindow: cfg.EventWindow, AgentTimeout: cfg.AgentTimeout}
	if in.RotationGrace <= 0 {
		in.RotationGrace = DefaultRotationGrace
	}
	if in.EventWindow <= 0 {
		in.EventWindow = DefaultEventWindow
	}
	if in.AgentTimeout <= 0 {
		in.AgentTimeout = DefaultAgentTimeout
	}
	wait := cfg.KeyLockWait
	if wait <= 0 {
		wait = DefaultKeyLockWait
	}
	in.KeyGuard = keyGuard{st: st, wait: wait}
	s := &Service{st: st, in: in, sec: cfg.Security, log: cfg.Logger, m: newMetrics(cfg.Registerer),
		drift: map[string]map[string]int{}}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// AgentConfigured reports whether the service has an agent.
func (s *Service) AgentConfigured() bool { return s.in.Agent != nil }

// ReconcileInstance compares one instance and records its security events. The report is returned, never written
// anywhere but the job's output: reconcile changes nothing. A skipped run returns its reason.
func (s *Service) ReconcileInstance(ctx context.Context, tenantID, instanceID uuid.UUID) (Report, string, error) {
	var row sqlcdb.GetInstanceForReconcileRow
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.GetInstanceForReconcile(ctx, sqlcdb.GetInstanceForReconcileParams{ID: instanceID, TenantID: tenantID})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		s.forget(instanceID.String())
		return Report{}, s.skip(ScopeInstance, SkipInstanceNotFound), nil
	case err != nil:
		return Report{}, "", fmt.Errorf("reconcile: read instance: %w", err)
	case !targeted(row.Status):
		s.forget(instanceID.String())
		return Report{}, s.skip(ScopeInstance, SkipNotReconciled), nil
	case row.LifecycleBusy:
		return Report{}, s.skip(ScopeInstance, SkipLifecycleBusy), nil
	}
	d := Desired{InstanceID: row.ID, TenantID: row.TenantID, Slug: row.Slug, Status: row.Status, ImageDigest: row.ImageDigest,
		NetCIDR: row.NetCidr, RunUID: uint32(row.RunUid), APIKeyPrefix: deref(row.ApiKeyPrefix), //nolint:gosec // CHECK run_uid > 0
		NoiseKeyFingerprint: deref(row.NoiseKeyFingerprint), ConfigSHA256: deref(row.DesiredConfigSha256)}
	in := *s.in
	checked := row.CheckedAt
	in.Now = func() time.Time { return checked }
	rep, evs := in.Instance(ctx, d)
	if err := s.raise(ctx, evs); err != nil {
		return Report{}, "", err
	}
	s.observe(instanceID.String(), rep)
	return rep, "", nil
}

// ReconcileHost compares the host's inventory with the registry.
func (s *Service) ReconcileHost(ctx context.Context) (Report, error) {
	var rows []sqlcdb.ListInstancesForHostReconcileRow
	var now time.Time
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if rows, err = q.ListInstancesForHostReconcile(ctx); err != nil {
			return err
		}
		now, err = q.MonitoringNow(ctx)
		return err
	})
	if err != nil {
		return Report{}, fmt.Errorf("reconcile: read registry: %w", err)
	}
	regs := make([]Registered, 0, len(rows))
	for _, r := range rows {
		regs = append(regs, Registered{InstanceID: r.ID, TenantID: r.TenantID, Slug: r.Slug, Status: r.Status})
	}
	in := *s.in
	in.Now = func() time.Time { return now }
	rep, evs := in.Host(ctx, regs)
	if err := s.raise(ctx, evs); err != nil {
		return Report{}, err
	}
	s.observe(ScopeHost, rep)
	return rep, nil
}

// raise records the security events (each deduplicated per subject for EventWindow). A failure fails the job, which
// is retried: dedupe makes the retry write each event once.
func (s *Service) raise(ctx context.Context, evs []audit.SecurityEvent) error {
	var errs []error
	for _, ev := range evs {
		wrote, err := s.sec.RecordSecurityEvent(ctx, ev)
		if err != nil {
			s.m.eventFailures.Inc()
			s.log.ErrorContext(ctx, "reconcile: security event NOT recorded", "kind", ev.Kind, "error", err.Error())
			errs = append(errs, err)
			continue
		}
		if wrote {
			s.m.events.WithLabelValues(ev.Kind, ev.Severity).Inc()
			s.log.WarnContext(ctx, "reconcile: security event", "kind", ev.Kind, "severity", ev.Severity,
				"dedupe_key", ev.DedupeKey)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("reconcile: security events: %w", err)
	}
	return nil
}

// observe updates the metrics and logs the outcome of a run.
func (s *Service) observe(subject string, rep Report) {
	s.m.runs.WithLabelValues(rep.Scope, rep.Status).Inc()
	kinds := rep.Kinds()
	s.mu.Lock()
	s.drift[subject] = kinds
	s.publishLocked()
	s.mu.Unlock()
	if rep.Status == StatusDrift {
		attrs := []any{"scope", rep.Scope, "subject", subject, "findings", len(rep.Findings), "kinds", kinds}
		if rep.TenantID != nil {
			attrs = append(attrs, "tenant_id", rep.TenantID.String())
		}
		s.log.Warn("reconcile: drift", attrs...)
	}
}

// forget drops a subject from the gauge (an instance no longer reconciled).
func (s *Service) forget(subjects ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range subjects {
		delete(s.drift, sub)
	}
	s.publishLocked()
}

// retain keeps the gauge's instance subjects to the targeted instances (the host subject stays).
func (s *Service) retain(keep map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sub := range s.drift {
		if sub != ScopeHost && !keep[sub] {
			delete(s.drift, sub)
		}
	}
	s.publishLocked()
}

func (s *Service) publishLocked() {
	total := map[string]int{}
	for _, kinds := range s.drift {
		for k, n := range kinds {
			total[k] += n
		}
	}
	for _, k := range DriftKinds {
		s.m.drift.WithLabelValues(k).Set(float64(total[k]))
	}
}

func (s *Service) skip(scope, reason string) string {
	s.m.runs.WithLabelValues(scope, "skipped").Inc()
	return reason
}

// runInstance is the handler of instance.reconcile.
func (s *Service) runInstance(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil || run.InstanceID == nil {
		return jobs.Permanent("invalid_input", errors.New("instance.reconcile needs a tenant and an instance"))
	}
	rep, skipped, err := s.ReconcileInstance(ctx, *run.TenantID, *run.InstanceID)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return jobs.Transient("reconcile_failed", err)
	}
	var out any = rep
	if skipped != "" {
		out = Skipped{Skipped: skipped}
	}
	if err := run.SetOutput(out); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	return nil
}

// runHost is the handler of host.reconcile.
func (s *Service) runHost(ctx context.Context, run *jobs.Run) error {
	rep, err := s.ReconcileHost(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return jobs.Transient("reconcile_failed", err)
	}
	if err := run.SetOutput(rep); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	return nil
}

// Register sets the handlers of instance.reconcile and host.reconcile on the worker (apps/worker).
func (s *Service) Register(w *jobs.Worker) error {
	if err := w.Register(KindInstance, jobs.HandlerFunc(s.runInstance)); err != nil {
		return err
	}
	return w.Register(KindHost, jobs.HandlerFunc(s.runHost))
}

// StoredReport is a report as monitoring reads it: the output of the latest successful reconcile job.
type StoredReport struct {
	Report     Report
	FinishedAt time.Time
}

// LatestReports returns the latest report of every instance reconciled since `since` (platform scope).
func (s *Service) LatestReports(ctx context.Context, since time.Time) ([]StoredReport, error) {
	var rows []sqlcdb.LatestInstanceReconcileReportsRow
	if err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.LatestInstanceReconcileReports(ctx, since)
		return err
	}); err != nil {
		return nil, err
	}
	out := make([]StoredReport, 0, len(rows))
	for _, r := range rows {
		var rep Report
		if err := json.Unmarshal(r.Output, &rep); err != nil || rep.Schema != ReportSchema {
			continue
		}
		out = append(out, StoredReport{Report: rep, FinishedAt: r.FinishedAt})
	}
	return out, nil
}

// LatestHostReport returns the latest host report, or nil when none was recorded.
func (s *Service) LatestHostReport(ctx context.Context) (*StoredReport, error) {
	var row sqlcdb.LatestHostReconcileReportRow
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.LatestHostReconcileReport(ctx)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(row.Output, &rep); err != nil {
		return nil, fmt.Errorf("reconcile: host report: %w", err)
	}
	return &StoredReport{Report: rep, FinishedAt: row.FinishedAt}, nil
}

// keyGuard is the KeyGuard of the worker (P3-T10): the instance's API key lock of apikey.rotate (store.WithTenantLock
// with apikey.LockName — a dedicated connection, a rolled-back transaction: nothing is written), under which the
// recorded prefix and the database clock are read again.
type keyGuard struct {
	st   *store.Store
	wait time.Duration
}

func (g keyGuard) WithKeyLock(ctx context.Context, tenantID, instanceID uuid.UUID, fn func(context.Context, CurrentKey) error) error {
	return g.st.WithTenantLock(ctx, tenantID, apikey.LockName, g.wait, func(ctx context.Context) error {
		var row sqlcdb.GetInstanceForReconcileRow
		if err := g.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			var err error
			row, err = q.GetInstanceForReconcile(ctx, sqlcdb.GetInstanceForReconcileParams{ID: instanceID, TenantID: tenantID})
			return err
		}); err != nil {
			return err
		}
		return fn(ctx, CurrentKey{Prefix: deref(row.ApiKeyPrefix), Now: row.CheckedAt})
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
