package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// recordSchema is the version of the document stored in tenant_instances.last_health.
const recordSchema = 1

// record is the document of tenant_instances.last_health: what one probe observed — no secret, no upstream text.
type record struct {
	Schema     int    `json:"schema"`
	Status     string `json:"status"`             // healthy | unhealthy
	Reason     string `json:"reason,omitempty"`   // stable code when unhealthy
	Version    string `json:"version,omitempty"`  // GET /version of the probe
	Database   *bool  `json:"database,omitempty"` // GET /api/v1/health database connectivity
	Breaker    string `json:"breaker,omitempty"`  // the adapter's breaker for the instance after the probe
	DurationMS int64  `json:"duration_ms"`
}

var (
	codeRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	versionRE = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)
	breakers  = map[string]bool{"closed": true, "open": true, "half_open": true}
)

// valid reports whether a decoded document is a record of this module.
func (r record) valid() bool {
	switch {
	case r.Schema != recordSchema:
		return false
	case r.Status == StatusHealthy:
		return r.Reason == ""
	case r.Status == StatusUnhealthy:
		return codeRE.MatchString(r.Reason)
	}
	return false
}

// recordOf turns a probe into the stored document. A healthy verdict needs no failure AND the database reachable; a
// reason or version that is not a stable code is not stored as text.
func recordOf(p InstanceProbe) record {
	r := record{Schema: recordSchema, Database: p.Database, DurationMS: p.Duration.Milliseconds()}
	if versionRE.MatchString(p.Version) {
		r.Version = p.Version
	}
	if breakers[p.Breaker] {
		r.Breaker = p.Breaker
	}
	switch {
	case p.Reason == "" && p.Database != nil && *p.Database:
		r.Status = StatusHealthy
	case p.Reason == "":
		r.Status, r.Reason = StatusUnhealthy, ReasonIncompleteProbe
	case codeRE.MatchString(p.Reason):
		r.Status, r.Reason = StatusUnhealthy, p.Reason
	default:
		r.Status, r.Reason = StatusUnhealthy, ReasonInvalidRecord
	}
	return r
}

// Reasons a probe job records nothing.
const (
	SkipInstanceNotFound   = "instance_not_found"   // no instance with this id for this tenant
	SkipInstanceNotRunning = "instance_not_running" // only running instances are probed
	SkipInstanceChanged    = "instance_changed"     // the adapter resolved another instance for the tenant
)

// ProbeResult describes one run of health.probe (the job's output — no secret).
type ProbeResult struct {
	Status    string     `json:"status,omitempty"` // healthy | unhealthy; "" when skipped
	Reason    string     `json:"reason,omitempty"`
	Version   string     `json:"version,omitempty"`
	Breaker   string     `json:"breaker,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Recorded is false when the probe was skipped, or when a probe that started later had already been recorded.
	Recorded bool   `json:"recorded"`
	Skipped  string `json:"skipped,omitempty"`
}

var errNoProber = errors.New("monitoring: no Prober configured (Config.Prober)")

// Probe checks the instance of a tenant through the Prober — bounded by ProbeTimeout — and records the result in
// tenant_instances.last_health, with last_health_at = the database clock when the probe started (see the package
// documentation). An unhealthy instance is a result, not an error; the error is for a probe that could not be recorded,
// or that ctx cut short (then nothing is said about the instance).
func (s *Service) Probe(ctx context.Context, tenantID, instanceID uuid.UUID) (ProbeResult, error) {
	if s.prober == nil {
		return ProbeResult{}, errNoProber
	}
	var row sqlcdb.GetInstanceForProbeRow
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.GetInstanceForProbe(ctx, sqlcdb.GetInstanceForProbeParams{ID: instanceID, TenantID: tenantID})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return s.skip(SkipInstanceNotFound), nil
	case err != nil:
		return ProbeResult{}, fmt.Errorf("monitoring: probe: read instance: %w", err)
	case row.Status != "running":
		return s.skip(SkipInstanceNotRunning), nil
	}
	pctx, cancel := context.WithTimeout(ctx, s.probeLimit) // a slow instance is a result (unhealthy), not a failed job
	p := s.prober.ProbeInstance(pctx, tenantID)
	cancel()
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, fmt.Errorf("monitoring: probe interrupted: %w", err)
	}
	if p.InstanceID != uuid.Nil && p.InstanceID != instanceID {
		return s.skip(SkipInstanceChanged), nil
	}
	rec := recordOf(p)
	doc, err := json.Marshal(rec)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("monitoring: probe: encode: %w", err)
	}
	checked := row.CheckedAt.UTC()
	var n int64
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.RecordInstanceHealth(ctx, sqlcdb.RecordInstanceHealthParams{Health: doc, CheckedAt: &checked,
			ID: instanceID, TenantID: tenantID})
		return err
	})
	if err != nil {
		return ProbeResult{}, fmt.Errorf("monitoring: probe: record (sqlstate %q): %w", store.SQLState(err), err)
	}
	s.m.probes.WithLabelValues(rec.Status, rec.Reason).Inc()
	if rec.Status != StatusHealthy {
		s.log.WarnContext(ctx, "monitoring: tenant instance unhealthy", "tenant_id", tenantID, "instance_id", instanceID,
			"reason", rec.Reason, "breaker", rec.Breaker, "version", rec.Version, "recorded", n == 1)
	}
	return ProbeResult{Status: rec.Status, Reason: rec.Reason, Version: rec.Version, Breaker: rec.Breaker, CheckedAt: &checked,
		Recorded: n == 1}, nil
}

func (s *Service) skip(reason string) ProbeResult {
	s.m.probes.WithLabelValues("skipped", reason).Inc()
	return ProbeResult{Skipped: reason}
}

// runProbe is the handler of health.probe: one attempt (registry of P2-T12), idempotent — a replay probes again and
// records only if no later probe was recorded.
func (s *Service) runProbe(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil || run.InstanceID == nil {
		return jobs.Permanent("invalid_input", errors.New("health.probe needs a tenant and an instance"))
	}
	res, err := s.Probe(ctx, *run.TenantID, *run.InstanceID)
	if err != nil {
		if ctx.Err() != nil {
			return err // the framework records the timeout or the interruption
		}
		return jobs.Transient("health_record_failed", err)
	}
	if err := run.SetOutput(res); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	return nil
}

// Register sets the handler of health.probe on the worker (apps/worker); a Prober is required.
func (s *Service) Register(w *jobs.Worker) error {
	if s.prober == nil {
		return errNoProber
	}
	return w.Register(KindProbe, jobs.HandlerFunc(s.runProbe))
}
