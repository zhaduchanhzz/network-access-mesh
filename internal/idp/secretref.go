package idp

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// ClientSecretName is the SecretStore name under which the drivers store the client secret of IdP id
// (Registration.ClientSecretOwner): idp.<id>.client.
func ClientSecretName(id uuid.UUID) string { return "idp." + id.String() + ".client" }

// AdminClientSecretName is the name `meshguard admin set-idp-client-secret` stores it under (P2-T11,
// provisioning.ClientSecretName): idp-client-secret.<id>.
func AdminClientSecretName(id uuid.UUID) string { return "idp-client-secret." + id.String() }

// OwnClientSecretRef parses r.ClientSecretRef and returns it only when it names the IdP's own client secret: the owner
// segment is the IdP's tenant (platform for the platform IdP — the owner of identity_providers.tenant_id, the CHECK of
// migration 0007) and the name is ClientSecretName or AdminClientSecretName of r.IdPID. Any other reference is refused
// with CodeSecretRefNotOwned (reason "malformed", "owner" or "name") before anything reads or destroys it (G2 F3):
// otherwise a row pointing at another secret — another tenant's Headscale API key, a platform credential, the tenant's
// own Headscale key — would have that secret decrypted and sent to the IdP as client_secret at the token request, or
// destroyed by RemoveIssuer(purge).
func (r Registration) OwnClientSecretRef(op string) (secrets.Ref, error) {
	ref, err := secrets.ParseRef(r.ClientSecretRef)
	if err != nil {
		return secrets.Ref{}, NewError(CodeSecretRefNotOwned, op, "malformed", nil)
	}
	switch {
	case r.IdPID == uuid.Nil,
		r.Scope == ScopePlatform && !ref.IsPlatform(),
		r.Scope == ScopeTenant && (r.TenantID == uuid.Nil || ref.Tenant != r.TenantID),
		r.Scope != ScopePlatform && r.Scope != ScopeTenant:
		return secrets.Ref{}, NewError(CodeSecretRefNotOwned, op, "owner", nil)
	case ref.Name != ClientSecretName(r.IdPID) && ref.Name != AdminClientSecretName(r.IdPID):
		return secrets.Ref{}, NewError(CodeSecretRefNotOwned, op, "name", nil)
	}
	return ref, nil
}

// KindClientSecretRefNotOwned is the security event (security_events.kind) of a refused client_secret_ref: the
// registry holds a reference the IdP does not own — a corrupted row, an operator mistake or an attempt to reach
// another owner's secret. Raised by the callback of internal/identity and by the drivers.
const KindClientSecretRefNotOwned = "idp.client_secret_ref_not_owned" //nolint:gosec // G101: a security event kind, not a credential

// SecretRefEventWindow deduplicates KindClientSecretRefNotOwned per IdP: one event per IdP and hour, however many
// logins or driver runs hit the broken row.
const SecretRefEventWindow = time.Hour

// SecurityRecorder receives the security events of the drivers (*audit.Logger implements it). nil: the refusal stands
// but no event is written.
type SecurityRecorder interface {
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

var _ SecurityRecorder = (*audit.Logger)(nil)

// SecretRefEvent is the security event of a refused client_secret_ref of r (platform scope, severity high, no
// reference value — only which check failed).
func SecretRefEvent(r Registration, source string, err error) audit.SecurityEvent {
	reason := ""
	var e *Error
	if errors.As(err, &e) {
		reason = e.Reason
	}
	d := audit.Details{"idp_id": r.IdPID, "idp_scope": string(r.Scope), "driver": r.Driver, "check": reason}
	if r.TenantID != uuid.Nil {
		d["idp_tenant_id"] = r.TenantID
	}
	if e != nil {
		d["op"] = e.Op
	}
	return audit.SecurityEvent{
		Kind: KindClientSecretRefNotOwned, Severity: audit.SeverityHigh, Source: source, Details: d,
		DedupeKey: KindClientSecretRefNotOwned + ":" + r.IdPID.String(), DedupeWindow: SecretRefEventWindow,
	}
}

// DriverClientSecretRef is the check the drivers run before they read (EnsureClient) or destroy (RemoveIssuer purge)
// the client secret of a registration: OwnClientSecretRef, plus the security event through rec on a refusal (a write
// failure is logged and counted by the recorder; the refusal stands either way).
func DriverClientSecretRef(ctx context.Context, rec SecurityRecorder, r Registration, op string) (secrets.Ref, error) {
	ref, err := r.OwnClientSecretRef(op)
	if err != nil && rec != nil {
		_, _ = rec.RecordSecurityEvent(context.WithoutCancel(ctx), SecretRefEvent(r, "idp", err))
	}
	return ref, err
}
