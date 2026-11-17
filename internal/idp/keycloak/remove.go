package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// RemoveIssuer disables the realm (RemoveDisable: every login and token request is refused, users are kept) or
// deletes it (RemovePurge) and then destroys every version of the secrets the IdP used: the mg-idp-driver secret and
// the Portal client secret. Both modes are idempotent: a realm already disabled or already deleted is a success.
func (d *Driver) RemoveIssuer(ctx context.Context, reg idp.Registration, mode idp.RemoveMode) (idp.RemoveResult, error) {
	const op = "keycloak.RemoveIssuer"
	if err := reg.Validate(op); err != nil {
		return idp.RemoveResult{}, err
	}
	ref, sref, err := ParseDriverRef(reg.DriverRef)
	if err != nil {
		return idp.RemoveResult{}, err
	}
	res := idp.RemoveResult{Mode: mode}
	ts := d.provisioner()
	switch mode {
	case idp.RemoveDisable:
		var live map[string]any
		st, _, err := d.call(ctx, op, ts, http.MethodGet, realmPath(ref.Realm), nil, &live, http.StatusNotFound)
		if err != nil {
			return res, err
		}
		if st == http.StatusNotFound {
			res.AlreadyAbsent = true
			return res, nil
		}
		if str(live["id"]) == "" {
			return res, idp.NewError(idp.CodeForbidden, op, "realm_not_managed", nil)
		}
		if str(asMap(live["attributes"])["meshguard.idp_id"]) != reg.IdPID.String() {
			return res, idp.NewError(idp.CodeConflict, op, "realm_of_another_idp", nil)
		}
		if live["enabled"] == true {
			if _, _, err := d.call(ctx, op, ts, http.MethodPut, realmPath(ref.Realm), map[string]any{"enabled": false}, nil); err != nil {
				return res, err
			}
			res.Changed = true
		}
	case idp.RemovePurge:
		var live map[string]any
		st, _, err := d.call(ctx, op, ts, http.MethodGet, realmPath(ref.Realm), nil, &live, http.StatusNotFound)
		if err != nil {
			return res, err
		}
		if st == http.StatusNotFound {
			res.AlreadyAbsent = true
		} else {
			if str(live["id"]) == "" {
				return res, idp.NewError(idp.CodeForbidden, op, "realm_not_managed", nil)
			}
			if str(asMap(live["attributes"])["meshguard.idp_id"]) != reg.IdPID.String() {
				return res, idp.NewError(idp.CodeConflict, op, "realm_of_another_idp", nil)
			}
			st, _, err := d.call(ctx, op, ts, http.MethodDelete, realmPath(ref.Realm), nil, nil, http.StatusNotFound)
			if err != nil {
				return res, err
			}
			res.AlreadyAbsent = st == http.StatusNotFound
			res.Changed = st != http.StatusNotFound
		}
		refs := []secrets.Ref{sref}
		if reg.ClientSecretRef != "" {
			if cr, err := secrets.ParseRef(reg.ClientSecretRef); err == nil {
				refs = append(refs, cr)
			}
		}
		for _, r := range refs {
			if err := destroyAll(ctx, d.secrets, r); err != nil {
				return res, idp.NewError(idp.CodeCredentials, op, "secret_store_destroy", err)
			}
		}
	default:
		return res, idp.NewError(idp.CodeInvalidArgument, op, "mode", nil)
	}
	d.invalidateRealm(ref.Realm)
	d.log.Info("keycloak: realm removed", "realm", ref.Realm, "mode", string(mode), "changed", res.Changed)
	return res, nil
}

// destroyAll destroys versions 1…ref.Version (idempotent).
func destroyAll(ctx context.Context, st secrets.SecretStore, ref secrets.Ref) error {
	for v := int32(1); v <= ref.Version; v++ {
		r := ref
		r.Version = v
		if err := st.Destroy(ctx, r); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return err
		}
	}
	return nil
}

// CheckDiscovery fetches the discovery document and the JWKS of the realm through the platform route: the issuer
// must be the stored one (= the realm's issuer) and every endpoint must be an https URL of the platform IdP host under
// /realms/<realm>/.
func (d *Driver) CheckDiscovery(ctx context.Context, reg idp.Registration) (idp.Discovery, error) {
	const op = "keycloak.CheckDiscovery"
	ref, _, err := ParseDriverRef(reg.DriverRef)
	if err != nil {
		return idp.Discovery{}, err
	}
	if reg.Issuer != d.Issuer(ref.Realm) {
		return idp.Discovery{}, idp.NewError(idp.CodeIssuerMismatch, op, "issuer_not_realm", nil)
	}
	prefix := "/realms/" + ref.Realm + "/"
	rule := func(_ context.Context, u *url.URL, _ idp.EndpointKind) error {
		if u.Scheme != "https" || !strings.EqualFold(u.Hostname(), d.hostOf()) || (u.Port() != "" && u.Port() != "443") ||
			u.User != nil {
			return idp.NewError(idp.CodeDiscoveryInvalid, op, "endpoint_not_platform_idp", nil)
		}
		if u.Path != strings.TrimSuffix(prefix, "/") && !strings.HasPrefix(u.Path, prefix) {
			return idp.NewError(idp.CodeDiscoveryInvalid, op, "endpoint_outside_realm", nil)
		}
		return nil
	}
	return idp.FetchDiscovery(ctx, d.http, reg.Issuer, rule)
}

func (a *admin) hostOf() string { return strings.TrimPrefix(a.base, "https://") }
