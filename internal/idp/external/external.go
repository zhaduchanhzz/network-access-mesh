// Package external is the IdP driver for an IdP the tenant brings (Entra ID, Google Workspace, Okta, its own
// Keycloak… — §8.2, driver=external). The platform does not administer that IdP: the driver only records the
// tenant-supplied issuer and client — the client secret goes to the SecretStore — and checks the issuer's discovery
// document and JWKS through the SSRF-hardened client (T-21). It never receives the platform route, so a
// tenant-supplied URL cannot reach the platform-hosted IdP or any internal address.
package external

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"strings"
	"unicode"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// Config configures the driver.
type Config struct {
	// Client is the hardened client every call goes through (required).
	Client *idp.Hardened
	// Secrets stores the tenant-supplied client secret (required for confidential clients).
	Secrets secrets.SecretStore
	// Security receives the security event of a registration whose client_secret_ref is not the IdP's own (G2 F3,
	// idp.KindClientSecretRefNotOwned); production: the audit.Logger of the process. nil: the refusal stands, no event.
	Security idp.SecurityRecorder
}

// Driver is the external IdP driver.
type Driver struct {
	h        *idp.Hardened
	secrets  secrets.SecretStore
	security idp.SecurityRecorder
}

var _ idp.IdPDriver = (*Driver)(nil)

// New returns the driver.
func New(cfg Config) (*Driver, error) {
	if cfg.Client == nil {
		return nil, errors.New("external: a hardened client is required")
	}
	return &Driver{h: cfg.Client, secrets: cfg.Secrets, security: cfg.Security}, nil
}

// Name implements idp.IdPDriver.
func (d *Driver) Name() string { return idp.DriverExternal }

// rule: every endpoint passes the static rules of the hardened client (https, 443, DNS name outside the platform's
// domain); endpoints the backend calls must also resolve to allowed addresses now (they are re-checked at every
// connection anyway). Browser-only endpoints are not resolved: the backend never calls them.
func (d *Driver) rule(ctx context.Context, u *url.URL, kind idp.EndpointKind) error {
	if kind == idp.EndpointBackend {
		return d.h.CheckDestination(ctx, u)
	}
	return d.h.CheckURL(u)
}

// checkIssuer validates the shape of a tenant-supplied issuer: https URL without query, fragment or user info, on
// port 443, host passing the hardened client's static rules.
func (d *Driver) checkIssuer(op, issuer string) error {
	if issuer == "" || len(issuer) > 2048 || strings.TrimSpace(issuer) != issuer {
		return idp.NewError(idp.CodeInvalidArgument, op, "issuer_invalid", nil)
	}
	u, err := url.Parse(issuer)
	if err != nil || u.RawQuery != "" || u.ForceQuery {
		return idp.NewError(idp.CodeInvalidArgument, op, "issuer_invalid", nil)
	}
	return d.h.CheckURL(u)
}

// EnsureIssuer checks the tenant-supplied issuer (shape, then discovery + JWKS through the hardened client). Nothing
// is created at the IdP; the issuer is recorded by the caller in identity_providers.
func (d *Driver) EnsureIssuer(ctx context.Context, spec idp.IssuerSpec) (idp.IssuerResult, error) {
	const op = "external.EnsureIssuer"
	if err := spec.Validate(op); err != nil {
		return idp.IssuerResult{}, err
	}
	if err := d.checkIssuer(op, spec.Issuer); err != nil {
		return idp.IssuerResult{}, err
	}
	if _, err := idp.FetchDiscovery(ctx, d.h.Client(), spec.Issuer, d.rule); err != nil {
		return idp.IssuerResult{}, err
	}
	return idp.IssuerResult{Issuer: spec.Issuer}, nil
}

// CheckDiscovery re-checks the stored issuer (at every refresh: §8.2 — the issuer of the document must still equal
// the stored issuer and every endpoint must pass the rules).
func (d *Driver) CheckDiscovery(ctx context.Context, reg idp.Registration) (idp.Discovery, error) {
	const op = "external.CheckDiscovery"
	if err := d.checkIssuer(op, reg.Issuer); err != nil {
		return idp.Discovery{}, err
	}
	return idp.FetchDiscovery(ctx, d.h.Client(), reg.Issuer, d.rule)
}

// validClientID: 1–255 printable characters without spaces (stored as identity_providers.client_id).
func validClientID(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// EnsureClient records the tenant-supplied client: the client id is returned for the row; the client secret (if
// any) is stored as a new version of idp.<idpId>.client in the tenant's SecretStore unless the stored version already
// holds the same value. A stored reference that is not the IdP's own client secret is refused before anything is read
// (CodeSecretRefNotOwned, G2 F3).
func (d *Driver) EnsureClient(ctx context.Context, spec idp.ClientSpec) (idp.ClientResult, error) {
	const op = "external.EnsureClient"
	if err := spec.Validate(op); err != nil {
		return idp.ClientResult{}, err
	}
	if !validClientID(spec.ClientID) {
		return idp.ClientResult{}, idp.NewError(idp.CodeInvalidArgument, op, "client_id_invalid", nil)
	}
	var ref secrets.Ref
	if spec.ClientSecretRef != "" {
		var err error
		if ref, err = idp.DriverClientSecretRef(ctx, d.security, spec.Registration, op); err != nil {
			return idp.ClientResult{}, err
		}
	}
	res := idp.ClientResult{ClientID: spec.ClientID, ClientSecretRef: spec.ClientSecretRef}
	if len(spec.ClientSecret) == 0 {
		return res, nil // public client, or keep the stored secret
	}
	if len(spec.ClientSecret) > 4096 {
		return idp.ClientResult{}, idp.NewError(idp.CodeInvalidArgument, op, "client_secret_too_long", nil)
	}
	if d.secrets == nil {
		return idp.ClientResult{}, idp.NewError(idp.CodeCredentials, op, "no_secret_store", nil)
	}
	if spec.ClientSecretRef != "" {
		if cur, err := d.secrets.Get(ctx, ref); err == nil {
			same := subtle.ConstantTimeCompare(cur.Bytes(), spec.ClientSecret.Bytes()) == 1
			cur.Wipe()
			if same {
				return res, nil
			}
		}
	}
	ref, err := idp.StoreNewVersion(ctx, d.secrets, spec.ClientSecretOwner(1), spec.ClientSecret.Bytes())
	if err != nil {
		return idp.ClientResult{}, idp.NewError(idp.CodeCredentials, op, "secret_store_write", err)
	}
	res.ClientSecretRef, res.SecretRotated = ref.String(), true
	return res, nil
}

// InviteUser is not offered: the tenant administers its own IdP.
func (d *Driver) InviteUser(context.Context, idp.Registration, idp.Invite) (idp.InviteResult, error) {
	return idp.InviteResult{}, idp.NewError(idp.CodeUnsupported, "external.InviteUser", "tenant_managed_idp", nil)
}

// DisableUser is not offered: offboarding on the platform side (memberships, sessions, nodes) does not depend on it.
func (d *Driver) DisableUser(context.Context, idp.Registration, string) (idp.DisableResult, error) {
	return idp.DisableResult{}, idp.NewError(idp.CodeUnsupported, "external.DisableUser", "tenant_managed_idp", nil)
}

// RemoveIssuer touches nothing at the tenant's IdP. Purge destroys the stored client secret (idempotent) — only when
// the reference names the IdP's own client secret (CodeSecretRefNotOwned otherwise, nothing destroyed — G2 F3).
func (d *Driver) RemoveIssuer(ctx context.Context, reg idp.Registration, mode idp.RemoveMode) (idp.RemoveResult, error) {
	const op = "external.RemoveIssuer"
	if mode != idp.RemoveDisable && mode != idp.RemovePurge {
		return idp.RemoveResult{}, idp.NewError(idp.CodeInvalidArgument, op, "mode", nil)
	}
	res := idp.RemoveResult{Mode: mode}
	if mode == idp.RemovePurge && reg.ClientSecretRef != "" && d.secrets != nil {
		ref, err := idp.DriverClientSecretRef(ctx, d.security, reg, op)
		if err != nil {
			return res, err
		}
		for v := int32(1); v <= ref.Version; v++ {
			r := ref
			r.Version = v
			if err := d.secrets.Destroy(ctx, r); err != nil && !errors.Is(err, secrets.ErrNotFound) {
				return res, idp.NewError(idp.CodeCredentials, op, "secret_store_destroy", err)
			}
		}
		res.Changed = true
	}
	return res, nil
}
