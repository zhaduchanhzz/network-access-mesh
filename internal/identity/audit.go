package identity

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// Audit actions (x-audit-action of api/openapi.yaml) and outcomes (audit_events.outcome).
const (
	ActionLoginStart    = "auth.login_start"
	ActionLogin         = "auth.login"
	ActionLogout        = "auth.logout"
	ActionSessionRead   = "auth.session.read"
	ActionSessionList   = "auth.session.list"
	ActionSessionRevoke = "auth.session.revoke"
	// ActionSessionCheck is recorded by the middleware when a presented session or a state-changing request is
	// refused for a security reason (origin binding, CSRF, Origin/Sec-Fetch-Site).
	ActionSessionCheck = "auth.session.check"

	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeFailure = "failure"
)

// AuditEvent is one event for audit_events (P2-T08 maps it: denied/failure through the detached writer). Reason is a
// stable code (e.g. "idp_mismatch"); no secret, token, code or cookie is ever placed in an event.
type AuditEvent struct {
	Action     string
	Outcome    string
	Reason     string
	IdentityID uuid.UUID  // zero when unknown (failed login)
	TenantID   *uuid.UUID // tenant of the identity / IdP; nil for platform
	IdPID      uuid.UUID  // zero when unknown
	SessionID  uuid.UUID  // sessions.public_id; zero when none
	Origin     Origin
	ClientIP   string
	RequestID  string
	// Security, when set, is the kind of a security event (security_events, severity high) the Auditor raises besides
	// the audit event: a refusal that reveals a broken invariant of the platform's own records rather than a mistake
	// of the user — a client_secret_ref that is not the IdP's own (idp.KindClientSecretRefNotOwned, G2 F3).
	Security string
}

// Auditor receives the module's audit events. Record must not block for long and must not fail the request.
type Auditor interface {
	Record(ctx context.Context, ev AuditEvent)
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(ctx context.Context, ev AuditEvent)

// Record implements Auditor.
func (f AuditorFunc) Record(ctx context.Context, ev AuditEvent) { f(ctx, ev) }

// logAuditor is the default Auditor until audit_events is wired (P2-T08): one structured log line per event.
type logAuditor struct{ log *slog.Logger }

func (a logAuditor) Record(ctx context.Context, ev AuditEvent) {
	level := slog.LevelInfo
	if ev.Outcome != OutcomeSuccess {
		level = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("action", ev.Action), slog.String("outcome", ev.Outcome), slog.String("origin", string(ev.Origin)),
		slog.String("client_ip", ev.ClientIP), slog.String("request_id", ev.RequestID),
	}
	if ev.Reason != "" {
		attrs = append(attrs, slog.String("reason", ev.Reason))
	}
	if ev.IdentityID != uuid.Nil {
		attrs = append(attrs, slog.String("identity_id", ev.IdentityID.String()))
	}
	if ev.TenantID != nil {
		attrs = append(attrs, slog.String("tenant_id", ev.TenantID.String()))
	}
	if ev.IdPID != uuid.Nil {
		attrs = append(attrs, slog.String("idp_id", ev.IdPID.String()))
	}
	if ev.SessionID != uuid.Nil {
		attrs = append(attrs, slog.String("session_public_id", ev.SessionID.String()))
	}
	if ev.Security != "" {
		level = slog.LevelError
		attrs = append(attrs, slog.String("security_event", ev.Security))
	}
	a.log.LogAttrs(ctx, level, "audit", attrs...)
}
