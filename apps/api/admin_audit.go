package main

import (
	"context"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
)

// dbAuditor writes the audit events of the admin commands (adopt-instance, register-platform-idp,
// set-idp-client-secret — P2-T11) to audit_events through internal/audit (P2-T08), as provisioning.Auditor asks
// (P2-T16): "<action>.requested", "<action>.succeeded" and single success events in a transaction of their own on the
// application pools (Logger.RecordCommitted — RLS checks the tenant of a tenant event), "<action>.failed" on the
// detached path of mg_audit_writer (Logger.RecordDetached — it survives whatever the command rolled back). Every event
// is actor_type system and carries the request id of the command run (admin-<uuid>), so the events of one run can be
// found together. A failure to record "<action>.requested" aborts the command before any change (the Adopter's rule).
// bootstrap-super-admin and seed-membership write their events in their own business transaction (P2-T11a).
type dbAuditor struct {
	l         *audit.Logger
	requestID string
}

func newDBAuditor(l *audit.Logger) dbAuditor {
	return dbAuditor{l: l, requestID: "admin-" + uuid.Must(uuid.NewV7()).String()}
}

// Record implements provisioning.Auditor.
func (a dbAuditor) Record(ctx context.Context, ev provisioning.AuditEvent) error {
	e := audit.Event{
		TenantID: ev.TenantID, ActorType: audit.ActorSystem, Action: ev.Action, ResourceType: ev.ResourceType,
		ResourceID: ev.ResourceID, RequestID: a.requestID, OperationID: ev.OperationID, Outcome: ev.Outcome,
		Details: audit.Details(ev.Details),
	}
	if ev.Outcome == provisioning.OutcomeFailure {
		return a.l.RecordDetached(ctx, e)
	}
	return a.l.RecordCommitted(ctx, e)
}
