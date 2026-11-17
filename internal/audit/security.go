package audit

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Severities of security_events (CHECK of 0004 — the scale of §16.3 and §18).
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Kinds and sources written by this package.
const (
	// KindCrossTenantDenials: an actor denied repeatedly on tenants other than its own (§8.8, Config.CrossTenantThreshold).
	KindCrossTenantDenials = "authz.cross_tenant_denials"
	SourceAudit            = "audit"
)

var (
	kindRE   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	sourceRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// SecurityEvent is one row of security_events (§6.3): what platform staff — and, for a tenant-scoped event, the tenant
// — must look at.
type SecurityEvent struct {
	TenantID *uuid.UUID // nil = platform scope: visible to platform staff only
	Kind     string     // dotted lowercase, e.g. authz.cross_tenant_denials
	Severity string     // SeverityLow … SeverityCritical
	Source   string     // module or system that raised it (audit, secrets, crowdsec…)
	Details  Details    // filtered like audit details
	// DedupeKey makes the event unique per key within DedupeWindow (stored as details.dedupe_key): the check and the
	// insert are serialised by a transaction-scoped advisory lock on the key, so concurrent raisers write one event.
	DedupeKey    string
	DedupeWindow time.Duration
}

func (ev *SecurityEvent) check() error {
	switch {
	case len(ev.Kind) > 100 || !kindRE.MatchString(ev.Kind):
		return fmt.Errorf("%w: security event kind %q", ErrInvalidEvent, ev.Kind)
	case ev.Severity != SeverityLow && ev.Severity != SeverityMedium && ev.Severity != SeverityHigh &&
		ev.Severity != SeverityCritical:
		return fmt.Errorf("%w: severity %q", ErrInvalidEvent, ev.Severity)
	case !sourceRE.MatchString(ev.Source):
		return fmt.Errorf("%w: source %q", ErrInvalidEvent, ev.Source)
	case ev.DedupeKey != "" && (len(ev.DedupeKey) > maxDetailText || ev.DedupeWindow <= 0):
		return fmt.Errorf("%w: a dedupe key needs 1–%d bytes and a positive window", ErrInvalidEvent, maxDetailText)
	}
	return nil
}

// RecordSecurityEvent writes ev in transaction q — the business transaction when the event belongs to a change, or a
// transaction of its own (Logger.RecordSecurityEvent). It reports whether a row was written (false: deduplicated).
func RecordSecurityEvent(ctx context.Context, q *sqlcdb.Queries, ev SecurityEvent) (bool, error) {
	if err := ev.check(); err != nil {
		return false, err
	}
	details := ev.Details
	if ev.DedupeKey != "" {
		details = make(Details, len(ev.Details)+1)
		for k, v := range ev.Details {
			details[k] = v
		}
		details["dedupe_key"] = ev.DedupeKey
		if err := q.LockSecurityEventKey(ctx, ev.DedupeKey); err != nil {
			return false, fmt.Errorf("audit: security event lock: %w", err)
		}
		found, err := q.SecurityEventExists(ctx, sqlcdb.SecurityEventExistsParams{
			TenantID: ev.TenantID, Kind: ev.Kind, DedupeKey: ev.DedupeKey, WindowSeconds: ev.DedupeWindow.Seconds(),
		})
		if err != nil {
			return false, fmt.Errorf("audit: security event dedupe: %w", err)
		}
		if found {
			return false, nil
		}
	}
	raw, _, err := encodeDetails(details)
	if err != nil {
		return false, err
	}
	if _, err := q.InsertSecurityEvent(ctx, sqlcdb.InsertSecurityEventParams{
		TenantID: ev.TenantID, Kind: ev.Kind, Severity: ev.Severity, Source: ev.Source, Details: raw,
	}); err != nil {
		return false, fmt.Errorf("audit: security event %s: %w", ev.Kind, err)
	}
	return true, nil
}

// RecordSecurityEvent writes ev in a transaction of its own on the application pools (tenant scope, or platform when
// TenantID is nil), detached from the request's cancellation; a failure is logged and counted besides being returned.
func (l *Logger) RecordSecurityEvent(ctx context.Context, ev SecurityEvent) (bool, error) {
	wctx, cancel := l.writeContext(ctx)
	defer cancel()
	var wrote bool
	err := l.inScope(wctx, ev.TenantID, func(q *sqlcdb.Queries) error {
		var err error
		wrote, err = RecordSecurityEvent(wctx, q, ev)
		return err
	})
	if err != nil {
		l.failed(ctx, pathSecurity, Event{Action: ev.Kind}, err)
		return false, err
	}
	if wrote {
		l.m.security.WithLabelValues(ev.Kind, ev.Severity).Inc()
		l.log.WarnContext(ctx, "audit: security event", "kind", ev.Kind, "severity", ev.Severity, "source", ev.Source)
	}
	return wrote, nil
}
