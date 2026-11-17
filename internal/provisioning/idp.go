package provisioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// PortalClientID is the client of the Portal in every realm rendered by tools/render_idp.py (P2-T05: mg-portal,
// confidential, Authorization Code + PKCE S256 only).
const PortalClientID = "mg-portal"

// PlatformRealm is the realm of the platform staff (tools/render_idp.py REALMS).
const PlatformRealm = "platform"

// KeycloakIssuer is the issuer of a realm of the platform-hosted Keycloak: https://auth.<base domain>/realms/<realm>
// (tools/render_idp.py issuers(); KC_HOSTNAME of compose.idp.yaml.tmpl). Tenant realms are named by the tenant slug.
func KeycloakIssuer(baseDomain, realm string) string {
	return "https://auth." + baseDomain + "/realms/" + realm
}

// KeycloakRealmIdP is the registration of a realm of the platform-hosted Keycloak (§8.2 realm-per-tenant): issuer of
// the realm, client mg-portal, driver keycloak with the realm as driver_ref. tenantID nil ⇒ the platform realm.
func KeycloakRealmIdP(id uuid.UUID, tenantID *uuid.UUID, realm, baseDomain string) tenants.IdPSpec {
	scope := tenants.IdPScopeTenant
	if tenantID == nil {
		scope = tenants.IdPScopePlatform
	}
	return tenants.IdPSpec{ID: id, Scope: scope, TenantID: tenantID, Issuer: KeycloakIssuer(baseDomain, realm),
		ClientID: PortalClientID, Driver: tenants.IdPDriverKeycloak, DriverRef: realm}
}

// IdPAdmin runs `meshguard admin register-platform-idp` and `meshguard admin set-idp-client-secret`.
type IdPAdmin struct {
	Tenants *tenants.Service
	Secrets SecretStore
	Audit   Auditor      // nil: LogAuditor{Log}
	Log     *slog.Logger // nil discards
}

func (a *IdPAdmin) defaults() {
	if a.Log == nil {
		a.Log = slog.New(slog.DiscardHandler)
	}
	if a.Audit == nil {
		a.Audit = LogAuditor{Logger: a.Log}
	}
}

// RegisterPlatformIdP registers the identity provider of the platform realm (idempotent; issuer and client of an
// existing row are immutable — a different value is refused). It returns the row and whether it existed.
func (a *IdPAdmin) RegisterPlatformIdP(ctx context.Context, spec tenants.IdPSpec) (tenants.IdP, bool, error) {
	a.defaults()
	if spec.Scope != tenants.IdPScopePlatform {
		return tenants.IdP{}, false, fmt.Errorf("%w: not a platform identity provider", ErrRefused)
	}
	p, existed, err := a.Tenants.RegisterIdP(ctx, spec)
	if err != nil {
		return p, existed, refusal(err)
	}
	if !existed {
		if err := a.Audit.Record(ctx, AuditEvent{Action: ActionRegisterIdP, Outcome: OutcomeSuccess,
			ResourceType: "identity_provider", ResourceID: p.ID.String(),
			Details: map[string]any{"scope": p.Scope, "issuer": p.Issuer, "client_id": p.ClientID}}); err != nil {
			a.Log.Error("register-platform-idp: audit event not recorded", "error", err.Error())
		}
	}
	return p, existed, nil
}

// ClientSecretResult describes a stored client secret — references only.
type ClientSecretResult struct {
	IdP           tenants.IdP
	Ref           string   // new reference
	PreviousRef   string   // "" = none
	DestroyedRefs []string // older versions erased
}

// ClientSecretName is the SecretStore name of an IdP client secret: idp-client-secret.<idp id>, owned by the tenant of
// the IdP (tenant DEK) or by the platform (DEK platform — the api reads it at the token endpoint, P2-T06).
func ClientSecretName(idpID uuid.UUID) string { return "idp-client-secret." + idpID.String() }

// SetClientSecret stores the client secret of an IdP (read from stdin by the command — P2-T05: Keycloak generates it
// at realm import) and records its reference in identity_providers.client_secret_ref; older versions are erased.
func (a *IdPAdmin) SetClientSecret(ctx context.Context, idpID uuid.UUID, secret []byte) (ClientSecretResult, error) {
	a.defaults()
	var res ClientSecretResult
	p, err := a.Tenants.GetIdP(ctx, idpID)
	if errors.Is(err, tenants.ErrNotFound) {
		return res, fmt.Errorf("%w: identity provider %s is not registered", ErrRefused, idpID)
	}
	if err != nil {
		return res, err
	}
	res.IdP = p
	owner := uuid.Nil // platform secret
	var tenantID *uuid.UUID
	if p.Scope == tenants.IdPScopeTenant {
		if p.TenantID == nil {
			return res, fmt.Errorf("%w: identity provider %s of scope tenant without tenant", ErrRefused, idpID)
		}
		owner, tenantID = *p.TenantID, p.TenantID
	}
	name := ClientSecretName(idpID)
	var ref secrets.Ref
	latest, err := a.Secrets.Latest(ctx, owner, name)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		ref = secrets.Ref{Tenant: owner, Name: name, Version: 1}
		err = a.Secrets.Put(ctx, ref, secret)
	case err == nil:
		ref, err = a.Secrets.Rotate(ctx, latest, secret)
	}
	if err != nil {
		return res, fmt.Errorf("store the client secret in the SecretStore: %w", err)
	}
	res.Ref = ref.String()
	prev, err := a.Tenants.SetIdPClientSecretRef(ctx, idpID, ref.String())
	if err != nil {
		if derr := a.Secrets.Destroy(context.WithoutCancel(ctx), ref); derr != nil {
			a.Log.Error("set-idp-client-secret: could not destroy the unrecorded version", "ref", ref.String())
		}
		return res, fmt.Errorf("record the client secret reference: %w", err)
	}
	res.PreviousRef = prev
	res.DestroyedRefs = destroyOlder(ctx, a.Secrets, a.Log, ref, prev)
	if err := a.Audit.Record(ctx, AuditEvent{Action: ActionSetIdPClientSecret, Outcome: OutcomeSuccess,
		TenantID: tenantID, ResourceType: "identity_provider", ResourceID: idpID.String(),
		Details: map[string]any{"ref_version": ref.Version}}); err != nil {
		a.Log.Error("set-idp-client-secret: audit event not recorded", "error", err.Error())
	}
	return res, nil
}
