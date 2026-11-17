package provisioning

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// Audit outcomes and action suffixes (audit_events, §6.1): an operation that calls Headscale writes
// "<action>.requested" BEFORE the first change, then exactly one "<action>.succeeded" or "<action>.failed" with the same
// OperationID — a process that dies halfway leaves the request for reconcile.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"

	SuffixRequested = ".requested"
	SuffixSucceeded = ".succeeded"
	SuffixFailed    = ".failed"
)

// Audit actions of the admin commands (actor_type = system).
const (
	ActionAdoptInstance      = "platform.instance.adopt"           // paired: .requested → .succeeded / .failed
	ActionRegisterIdP        = "platform.idp.register"             // single event
	ActionSetIdPClientSecret = "platform.idp.client_secret.update" //nolint:gosec // G101: an audit action name
)

// AuditEvent is one audit event of an admin command — the fields of audit.Event (P2-T08) it needs, so that wiring is a
// field-by-field copy with ActorType = system.
type AuditEvent struct {
	Action       string     // with its suffix for paired events
	OperationID  *uuid.UUID // pairs *.requested with *.succeeded / *.failed; nil for single events
	Outcome      string     // OutcomeSuccess or OutcomeFailure
	TenantID     *uuid.UUID // the tenant whose audit lists it; nil = a platform event
	ResourceType string     // "instance", "identity_provider"
	ResourceID   string
	Details      map[string]any // ids, prefixes, counts, stable codes — never a credential or a raw upstream message
}

// Auditor records the audit events of the admin commands. A failure to record "<action>.requested" aborts the command
// before any change (§6.1). Until P2-T16 wires internal/audit (P2-T08) — Record for .requested/.succeeded and single
// success events through audit.Logger.RecordCommitted, .failed through RecordDetached, both with
// ActorType = audit.ActorSystem — LogAuditor writes the events to the process log.
type Auditor interface {
	Record(ctx context.Context, ev AuditEvent) error
}

// LogAuditor writes audit events to a logger (built with logx.New, so attributes are redacted anyway).
type LogAuditor struct {
	Logger *slog.Logger
}

// Record implements Auditor.
func (a LogAuditor) Record(ctx context.Context, ev AuditEvent) error {
	if a.Logger == nil {
		return nil
	}
	attrs := []any{"action", ev.Action, "outcome", ev.Outcome, "actor_type", "system", "resource_type", ev.ResourceType,
		"resource_id", ev.ResourceID}
	if ev.OperationID != nil {
		attrs = append(attrs, "operation_id", ev.OperationID.String())
	}
	if ev.TenantID != nil {
		attrs = append(attrs, "tenant_id", ev.TenantID.String())
	}
	if len(ev.Details) > 0 {
		group := make([]any, 0, 2*len(ev.Details))
		for k, v := range ev.Details {
			group = append(group, k, v)
		}
		attrs = append(attrs, slog.Group("details", group...))
	}
	a.Logger.InfoContext(ctx, "audit", attrs...)
	return nil
}
