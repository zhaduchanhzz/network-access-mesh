package auditapi

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// IdentityRecorder is the part of *audit.Logger the identity adapter needs.
type IdentityRecorder interface {
	RecordDetached(ctx context.Context, ev audit.Event) error
	RecordCommitted(ctx context.Context, ev audit.Event) error
	RecordAnonymousDenial(ctx context.Context, ev audit.Event) error
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

var _ IdentityRecorder = (*audit.Logger)(nil)

// securityDedupeWindow deduplicates the security events the identity module asks for (AuditEvent.Security) per kind
// and IdP.
const securityDedupeWindow = time.Hour

// IdentityAuditor is the identity.Auditor of the api process (identity.Config.Auditor): it maps the events of the
// identity module (login, logout, session revocation, session checks — P2-T06) to audit_events. Denied and failed
// events go through the detached path (their transaction rolled back or never opened); successful ones are reported
// by the identity module after its transaction committed and are written with the application role in a transaction
// of their own. A refusal without an identity — before any session or login exists: foreign Origin, cross-site or
// invalid login start, broken callback — is an anonymous denial, aggregated per client prefix, action, reason and
// window instead of one append-only row each (audit.Logger.RecordAnonymousDenial, G2 F2), as the HTTP audit middleware
// leaves anonymous 401s to the access log; once an identity is known every denial is one row (§8.8). An event with
// AuditEvent.Security also raises that security event (platform scope, severity high, one per IdP and hour). The event
// belongs to the identity's tenant (nil: platform staff, or a login that failed before its IdP was known — a platform
// event). Only stable codes and ids reach details: the identity module never puts a secret, token, code or cookie in
// an AuditEvent, and the audit filter drops any that would slip in. A write failure is logged and counted by the
// Logger; it never fails the request.
func IdentityAuditor(l IdentityRecorder) identity.Auditor {
	return identity.AuditorFunc(func(ctx context.Context, ev identity.AuditEvent) {
		e := identityEvent(ev)
		switch {
		case e.Outcome == audit.OutcomeSuccess:
			_ = l.RecordCommitted(ctx, e)
		case e.ActorIdentityID == nil:
			_ = l.RecordAnonymousDenial(ctx, e)
		default:
			_ = l.RecordDetached(ctx, e)
		}
		if ev.Security != "" {
			_, _ = l.RecordSecurityEvent(ctx, securityEvent(ev))
		}
	})
}

// securityEvent is the security event an identity event asks for (AuditEvent.Security).
func securityEvent(ev identity.AuditEvent) audit.SecurityEvent {
	d := audit.Details{"action": ev.Action, "reason": ev.Reason}
	if ev.IdPID != uuid.Nil {
		d["idp_id"] = ev.IdPID
	}
	if ev.TenantID != nil {
		d["idp_tenant_id"] = *ev.TenantID
	}
	if ev.Origin != "" {
		d["origin"] = string(ev.Origin)
	}
	if ev.RequestID != "" {
		d["request_id"] = ev.RequestID
	}
	return audit.SecurityEvent{
		Kind: ev.Security, Severity: audit.SeverityHigh, Source: "identity", Details: d,
		DedupeKey: ev.Security + ":" + ev.IdPID.String(), DedupeWindow: securityDedupeWindow,
	}
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
