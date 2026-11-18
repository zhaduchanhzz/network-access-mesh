package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// recordSchema is the version of the document stored in relay_regions.last_probe.
const recordSchema = 1

// checkRecord is one check of a stored probe: what the prober observed — no address, no upstream text.
type checkRecord struct {
	OK         bool   `json:"ok"`
	Status     int    `json:"status,omitempty"` // HTTP status (derp)
	Code       string `json:"code,omitempty"`   // the prober's error code when the check failed
	DurationMS int64  `json:"duration_ms"`
}

// record is the document of relay_regions.last_probe.
type record struct {
	Schema int         `json:"schema"`
	Status string      `json:"status"`           // healthy | unhealthy
	Reason string      `json:"reason,omitempty"` // stable code when unhealthy
	DERP   checkRecord `json:"derp"`
	STUN   checkRecord `json:"stun"`
}

var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (c checkRecord) valid() bool {
	return c.DurationMS >= 0 && c.Status >= 0 && c.Status <= 599 && (c.Code == "" || codeRE.MatchString(c.Code)) &&
		(!c.OK || c.Code == "")
}

// valid reports whether a decoded document is a record of this module whose verdict matches its checks.
func (r record) valid() bool {
	if r.Schema != recordSchema || !r.DERP.valid() || !r.STUN.valid() {
		return false
	}
	status, reason := verdict(r.DERP.OK, r.STUN.OK)
	return r.Status == status && r.Reason == reason
}

// verdict is the health of a probe from its two checks.
func verdict(derp, stun bool) (status, reason string) {
	switch {
	case derp && stun:
		return StatusHealthy, ""
	case !derp && !stun:
		return StatusUnhealthy, ReasonRelayUnreachable
	case !derp:
		return StatusUnhealthy, ReasonDERPProbeFailed
	}
	return StatusUnhealthy, ReasonSTUNProbeFailed
}

func checkOf(c Check) checkRecord {
	out := checkRecord{OK: c.OK, DurationMS: max(c.Duration.Milliseconds(), 0)}
	if c.Status >= 100 && c.Status <= 599 {
		out.Status = c.Status
	}
	switch {
	case c.OK:
	case codeRE.MatchString(c.Code):
		out.Code = c.Code
	default:
		out.Code = "check_failed" // a code that is not a stable one is not stored as text
	}
	return out
}

// recordOf turns a probe result into the stored document.
func recordOf(p ProbeResult) record {
	r := record{Schema: recordSchema, DERP: checkOf(p.DERP), STUN: checkOf(p.STUN)}
	r.Status, r.Reason = verdict(r.DERP.OK, r.STUN.OK)
	return r
}

// Reasons a probe job records nothing.
const (
	SkipRegionNotFound      = "region_not_found"     // no region with this id for this tenant
	SkipKindNotProbed       = "kind_not_probed"      // only embedded regions are probed in this release
	SkipRegionNotActive     = "region_not_active"    // the region is pending or disabled
	SkipInstanceNotRunning  = "instance_not_running" // no running instance serves the region
	SkipRegionWithoutSTUN   = "region_incomplete"    // the region has no STUN address (ipv4 + stun_port)
	CodeProberUnavailable   = "prober_unavailable"   // job error: the probe could not run
	CodeProbeRecordFailed   = "relay_record_failed"  // job error: the result could not be recorded
	codeInvalidProbeRequest = "invalid_input"
)

// ProbeOutcome describes one run of relay.probe (the job's output — no secret, no address).
type ProbeOutcome struct {
	RegionID  uuid.UUID  `json:"region_id"`
	Status    string     `json:"status,omitempty"` // healthy | unhealthy; "" when skipped
	Reason    string     `json:"reason,omitempty"`
	DERP      *CheckView `json:"derp,omitempty"`
	STUN      *CheckView `json:"stun,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Recorded is false when the probe was skipped, or when a probe that started later had already been recorded.
	Recorded bool   `json:"recorded"`
	Skipped  string `json:"skipped,omitempty"`
}

// ErrProbeNotRun wraps the error of a probe that could not run (prober unreachable, target outside its allow-list):
// nothing was recorded and nothing is said about the relay.
var ErrProbeNotRun = errors.New("relay: the probe could not run")

var errNoProber = errors.New("relay: no Prober configured (Config.Prober)")

// Probe probes one region of a tenant through the Prober — bounded by ProbeTimeout — and records the result in
// relay_regions.last_probe, with last_probe_at = the database clock when the probe started (see the package
// documentation). An unhealthy relay is a result, not an error; the error is for a probe that could not run
// (ErrProbeNotRun), could not be recorded, or that ctx cut short.
func (s *Service) Probe(ctx context.Context, tenantID, regionID uuid.UUID) (ProbeOutcome, error) {
	if s.prober == nil {
		return ProbeOutcome{}, errNoProber
	}
	out := ProbeOutcome{RegionID: regionID}
	var row sqlcdb.GetRelayRegionForProbeRow
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.GetRelayRegionForProbe(ctx, sqlcdb.GetRelayRegionForProbeParams{ID: regionID, TenantID: tenantID})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return s.skip(out, SkipRegionNotFound), nil
	case err != nil:
		return ProbeOutcome{}, fmt.Errorf("relay: probe: read region: %w", err)
	case row.Kind != KindEmbedded:
		return s.skip(out, SkipKindNotProbed), nil
	case row.Status != AdminActive:
		return s.skip(out, SkipRegionNotActive), nil
	case !row.Serving:
		return s.skip(out, SkipInstanceNotRunning), nil
	case row.Ipv4 == nil || !row.Ipv4.Is4() || row.StunPort == nil || *row.StunPort < 1 || *row.StunPort > 65535:
		s.log.WarnContext(ctx, "relay: region without a STUN address is not probed", "tenant_id", tenantID, "region_id", regionID)
		return s.skip(out, SkipRegionWithoutSTUN), nil
	}
	req := ProbeRequest{Address: s.edge, Host: row.Hostname,
		STUN: netip.AddrPortFrom(*row.Ipv4, uint16(*row.StunPort)).String()} //nolint:gosec // 1–65535 checked above
	pctx, cancel := context.WithTimeout(ctx, s.probeLimit)
	res, perr := s.prober.Relay(pctx, req)
	cancel()
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{}, fmt.Errorf("relay: probe interrupted: %w", err)
	}
	if perr != nil {
		s.m.probes.WithLabelValues("failed", CodeProberUnavailable).Inc()
		return ProbeOutcome{}, fmt.Errorf("%w: %w", ErrProbeNotRun, perr)
	}
	rec := recordOf(res)
	doc, err := json.Marshal(rec)
	if err != nil {
		return ProbeOutcome{}, fmt.Errorf("relay: probe: encode: %w", err)
	}
	checked := row.CheckedAt.UTC()
	var n int64
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.RecordRelayProbe(ctx, sqlcdb.RecordRelayProbeParams{Probe: doc, CheckedAt: &checked, ID: regionID,
			TenantID: tenantID})
		return err
	})
	if err != nil {
		return ProbeOutcome{}, fmt.Errorf("relay: probe: record (sqlstate %q): %w", store.SQLState(err), err)
	}
	s.m.probes.WithLabelValues(rec.Status, rec.Reason).Inc()
	if rec.Status != StatusHealthy {
		s.log.WarnContext(ctx, "relay: region unhealthy", "tenant_id", tenantID, "region_id", regionID, "reason", rec.Reason,
			"derp_status", rec.DERP.Status, "derp_code", rec.DERP.Code, "stun_code", rec.STUN.Code, "recorded", n == 1)
	}
	derp, stun := viewOf(rec.DERP), viewOf(rec.STUN)
	out.Status, out.Reason, out.DERP, out.STUN, out.CheckedAt, out.Recorded = rec.Status, rec.Reason, &derp, &stun, &checked, n == 1
	return out, nil
}

func (s *Service) skip(out ProbeOutcome, reason string) ProbeOutcome {
	s.m.probes.WithLabelValues("skipped", reason).Inc()
	out.Skipped = reason
	return out
}

// ProbeTenant probes now every region of the tenant the schedule would probe (`meshguard-worker admin relay-probe`).
// A region whose probe could not run is reported with the error; the others are probed anyway.
func (s *Service) ProbeTenant(ctx context.Context, tenantID uuid.UUID) ([]ProbeOutcome, []error, error) {
	if s.prober == nil {
		return nil, nil, errNoProber
	}
	var targets []sqlcdb.ListRelayProbeTargetsRow
	if err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		targets, err = q.ListRelayProbeTargets(ctx)
		return err
	}); err != nil {
		return nil, nil, fmt.Errorf("relay: list probe targets: %w", err)
	}
	var outs []ProbeOutcome
	var errs []error
	for _, t := range targets {
		if t.TenantID != tenantID {
			continue
		}
		o, err := s.Probe(ctx, tenantID, t.ID)
		if err != nil {
			if ctx.Err() != nil {
				return outs, errs, err
			}
			o = ProbeOutcome{RegionID: t.ID}
		}
		outs = append(outs, o)
		errs = append(errs, err)
	}
	return outs, errs, nil
}

// probeInput is the input of a relay.probe job.
type probeInput struct {
	RegionID uuid.UUID `json:"region_id"`
}

// runProbe is the handler of relay.probe: one attempt (jobs registry), idempotent — a replay probes again and records
// only if no later probe was recorded.
func (s *Service) runProbe(ctx context.Context, run *jobs.Run) error {
	var in probeInput
	if run.TenantID == nil || run.DecodeInput(&in) != nil || in.RegionID == uuid.Nil {
		return jobs.Permanent(codeInvalidProbeRequest, errors.New("relay.probe needs a tenant and a region_id"))
	}
	run.SetResource(ResourceType, in.RegionID.String())
	res, err := s.Probe(ctx, *run.TenantID, in.RegionID)
	switch {
	case err != nil && ctx.Err() != nil:
		return err // the framework records the timeout or the interruption
	case errors.Is(err, ErrProbeNotRun):
		return jobs.Transient(CodeProberUnavailable, err)
	case err != nil:
		return jobs.Transient(CodeProbeRecordFailed, err)
	}
	if err := run.SetOutput(res); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	return nil
}

// Register sets the handler of relay.probe on the worker (apps/worker); a Prober is required.
func (s *Service) Register(w *jobs.Worker) error {
	if s.prober == nil {
		return errNoProber
	}
	return w.Register(KindProbe, jobs.HandlerFunc(s.runProbe))
}
