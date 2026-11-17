package auditapi

import (
	"context"
	"net/netip"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// IdentityRecorder is the part of *audit.Logger the identity adapter needs.
type IdentityRecorder interface {
	RecordDetached(ctx context.Context, ev audit.Event) error
	RecordCommitted(ctx context.Context, ev audit.Event) error
}

var _ IdentityRecorder = (*audit.Logger)(nil)

// IdentityAuditor is the identity.Auditor of the api process (identity.Config.Auditor): it maps the events of the
// identity module (login, logout, session revocation, session checks — P2-T06) to audit_events. Denied and failed
// events go through the detached path (their transaction rolled back or never opened); successful ones are reported
// by the identity module after its transaction committed and are written with the application role in a transaction
// of their own. The event belongs to the identity's tenant (nil: platform staff, or a login that failed before its
// IdP was known — a platform event). Only stable codes and ids reach details: the identity module never puts a
// secret, token, code or cookie in an AuditEvent, and the audit filter drops any that would slip in. A write failure
// is logged and counted by the Logger; it never fails the request.
func IdentityAuditor(l IdentityRecorder) identity.Auditor {
	return identity.AuditorFunc(func(ctx context.Context, ev identity.AuditEvent) {
		e := identityEvent(ev)
		if e.Outcome == audit.OutcomeSuccess {
			_ = l.RecordCommitted(ctx, e)
			return
		}
		_ = l.RecordDetached(ctx, e)
	})
}

// identityEvent maps one identity event.
func identityEvent(ev identity.AuditEvent) audit.Event {
	e := audit.Event{
		ActorType: audit.ActorIdentity, Action: ev.Action, ResourceType: "session", RequestID: ev.RequestID,
		Outcome: ev.Outcome, Details: audit.Details{},
	}
	switch ev.Outcome {
	case identity.OutcomeSuccess, identity.OutcomeDenied, identity.OutcomeFailure:
	default:
		e.Outcome = audit.OutcomeFailure // unknown outcome: never lost, never a success
	}
	if ev.TenantID != nil {
		t := *ev.TenantID
		e.TenantID = &t
	}
	if ev.IdentityID != uuid.Nil {
		id := ev.IdentityID
		e.ActorIdentityID = &id
	}
	if ev.SessionID != uuid.Nil {
		e.ResourceID = ev.SessionID.String() // sessions.public_id — never the session id itself
	}
	if a, err := netip.ParseAddr(ev.ClientIP); err == nil {
		e.ActorIP = a
	}
	if ev.Reason != "" {
		e.Details["reason"] = ev.Reason
	}
	if ev.IdPID != uuid.Nil {
		e.Details["idp_id"] = ev.IdPID
	}
	if ev.Origin != "" {
		e.Details["origin"] = string(ev.Origin)
	}
	return e
}
