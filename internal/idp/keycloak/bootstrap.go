package keycloak

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// impersonationRole is the one role of a realm's management client Keycloak never grants a realm creator, and that
// Bootstrap never grants either (§8.2 (2); the feature is also disabled at the server).
const impersonationRole = "impersonation"

// ViewEventsRole is the role of a realm's management client that reads its login and admin events — the only role the
// provisioning identity holds on master-realm and on the realms it audits without managing them (P3-T15,
// idp.audit_sync).
const ViewEventsRole = "view-events"

// BootstrapConfig configures Bootstrap.
type BootstrapConfig struct {
	// AdminUsername and AdminPassword: the break-glass admin of the master realm (bootstrap-admin-* of keycloak.conf).
	// The operator puts the password into the SecretStore (platform_ops) first; Bootstrap reads it by reference and
	// uses it for this ceremony only — the driver never does.
	AdminUsername string
	AdminPassword secrets.Ref
	// Provisioner is the client to create or repair (ClientID; default mg-provisioner) and the reference of its secret:
	// the latest stored version, or version 1 for a first bootstrap.
	Provisioner Credentials
	// AdoptRealms are existing realms (imported at Keycloak start, e.g. tenant-a, tenant-b) the provisioning identity
	// must manage: it gets the same roles of their management client Keycloak gives a realm creator — all except
	// impersonation.
	AdoptRealms []string
	// AuditRealms are realms the provisioning identity only reads the events of (P3-T15, idp.audit_sync): it gets exactly
	// view-events of their management client — the platform realm, which it never manages. The master realm is always
	// audited the same way (console logins: view-events of master-realm). A realm both adopted and audited is managed.
	AuditRealms []string
	Logger      *slog.Logger
	Now         func() time.Time
}

// BootstrapResult is the outcome of Bootstrap.
type BootstrapResult struct {
	Provisioner Credentials // the working client id and secret reference (store it in the worker's configuration)
	Created     bool
	Rotated     bool
	Adopted     []string
	Audited     []string // realms read for idp.audit_sync only (view-events), master first
	Changes     []string
}

// provisionerClient is the master-realm client of the provisioning identity: confidential, client credentials only,
// no refresh token, audience of the Admin API only (scopes basic + kc-admin-api). fullScopeAllowed stays true: the
// roles of the realms it creates are granted to it at creation time and must be usable without a scope mapping.
func provisionerClient(clientID string) map[string]any {
	return map[string]any{
		"clientId": clientID, "name": "MeshGuard provisioning identity",
		"description":               "IdP driver (P2-T05a): create-realm only; manages the realms it creates or adopts. Secret in the SecretStore (platform_ops).",
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"bearerOnly":                false,
		"clientAuthenticatorType":   "client-secret",
		"standardFlowEnabled":       false,
		"implicitFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    true,
		"consentRequired":           false,
		"frontchannelLogout":        false,
		"fullScopeAllowed":          true,
		"redirectUris":              []any{},
		"webOrigins":                []any{},
		"attributes": map[string]any{
			"use.refresh.tokens":                        "false",
			"client_credentials.use_refresh_token":      "false",
			"oauth2.device.authorization.grant.enabled": "false",
			"oidc.ciba.grant.enabled":                   "false",
			"standard.token.exchange.enabled":           "false",
		},
		"defaultClientScopes":  []any{"basic", "kc-admin-api"},
		"optionalClientScopes": []any{},
	}
}

// Bootstrap creates — or repairs — the provisioning identity in the master realm, with the break-glass admin read from
// the SecretStore: client provisionerClient, service-account roles exactly {create-realm} in the master realm plus,
// per realm it manages, the roles of that realm's management client except impersonation, plus view-events of
// master-realm and of every realm it only audits (P3-T15) — no admin role, no other master-realm role is ever kept. A
// realm counts as managed when the identity holds a role of its management client besides view-events (Keycloak
// granted them at creation, or an earlier adoption) or it is adopted now; a realm whose mapping is view-events alone
// stays audit-only (never promoted to managed). Its secret is generated, stored first (DEK platform_ops), then set; an
// existing secret that still works is kept. Idempotent.
func Bootstrap(ctx context.Context, route *idp.PlatformRoute, st secrets.SecretStore, cfg BootstrapConfig) (BootstrapResult, error) {
	const op = "keycloak.Bootstrap"
	if route == nil || st == nil || cfg.AdminUsername == "" || cfg.AdminPassword.Validate() != nil || !cfg.AdminPassword.IsPlatform() {
		return BootstrapResult{}, idp.NewError(idp.CodeInvalidArgument, op, "config", nil)
	}
	if cfg.Provisioner.ClientID == "" {
		cfg.Provisioner.ClientID = DefaultProvisionerClientID
	}
	if cfg.Provisioner.Secret.Name == "" {
		cfg.Provisioner.Secret = secrets.PlatformRef(ProvisionerRefName, 1)
	}
	if cfg.Provisioner.Secret.Validate() != nil || !cfg.Provisioner.Secret.IsPlatform() {
		return BootstrapResult{}, idp.NewError(idp.CodeInvalidArgument, op, "provisioner_secret_ref", nil)
	}
	for _, r := range cfg.AdoptRealms {
		if !validRealm(r) {
			return BootstrapResult{}, idp.NewError(idp.CodeInvalidArgument, op, "adopt_realm", nil)
		}
	}
	for _, r := range cfg.AuditRealms {
		if !validRealm(r) {
			return BootstrapResult{}, idp.NewError(idp.CodeInvalidArgument, op, "audit_realm", nil)
		}
	}
	a := newAdmin(route, st, cfg.Logger, cfg.Now)
	adm := tokenSource{realm: masterRealm, clientID: "admin-cli", username: cfg.AdminUsername, secret: cfg.AdminPassword}
	cid := cfg.Provisioner.ClientID
	want := provisionerClient(cid)
	res := BootstrapResult{Provisioner: cfg.Provisioner}
	live, err := a.findClient(ctx, op, adm, masterRealm, cid)
	if err != nil {
		return res, err
	}
	if live == nil {
		secret, sref, err := a.newSecret(ctx, op, cfg.Provisioner.Secret, secrets.WithPlatformOps())
		if err != nil {
			return res, err
		}
		c := deepCopy(want)
		c["secret"] = string(secret.Bytes())
		secret.Wipe()
		if _, err := a.createClient(ctx, op, adm, masterRealm, c); err != nil {
			return res, err
		}
		res.Created, res.Provisioner.Secret = true, sref
		res.Changes = append(res.Changes, joinChange("client", cid, "created"))
		if live, err = a.findClient(ctx, op, adm, masterRealm, cid); err != nil || live == nil {
			return res, idp.NewError(idp.CodeUpstream, op, "client_not_found_after_create", err)
		}
	}
	id := str(live["id"])
	ch, err := a.reconcileClient(ctx, op, adm, masterRealm, want, live)
	res.Changes = append(res.Changes, ch...)
	if err != nil {
		return res, err
	}
	// service-account roles: create-realm in master; per managed realm, its management-client roles minus
	// impersonation; nothing else (no admin, no master-realm role, no default roles).
	var sa map[string]any
	if _, _, err := a.call(ctx, op, adm, http.MethodGet, realmSub(masterRealm, "clients", id, "service-account-user"), nil, &sa); err != nil {
		return res, err
	}
	base := realmSub(masterRealm, "users", str(sa["id"]), "role-mappings")
	var live2 mappings
	if _, _, err := a.call(ctx, op, adm, http.MethodGet, base, nil, &live2); err != nil {
		return res, err
	}
	wantClients := map[string][]string{masterRealm + "-realm": {ViewEventsRole}}
	managed := map[string]bool{}
	audited := map[string]bool{}
	for c, m := range live2.ClientMappings {
		r, ok := strings.CutSuffix(c, "-realm")
		if !ok || r == masterRealm {
			continue
		}
		if len(m.Mappings) == 1 && str(m.Mappings[0]["name"]) == ViewEventsRole {
			audited[r] = true // audit-only realm of an earlier bootstrap: never promoted to managed
			continue
		}
		managed[r] = true // a realm this identity created (Keycloak granted the roles) or adopted earlier
	}
	for _, r := range cfg.AdoptRealms {
		if !managed[r] {
			res.Adopted = append(res.Adopted, r)
		}
		managed[r] = true
	}
	for _, r := range cfg.AuditRealms {
		audited[r] = true
	}
	res.Audited = append(res.Audited, masterRealm)
	auditOnly := make([]string, 0, len(audited))
	for r := range audited {
		if !managed[r] {
			auditOnly = append(auditOnly, r)
		}
	}
	sort.Strings(auditOnly)
	for _, r := range auditOnly {
		mgmt, err := a.findClient(ctx, op, adm, masterRealm, r+"-realm")
		if err != nil {
			return res, err
		}
		if mgmt == nil {
			if slices.Contains(cfg.AuditRealms, r) {
				return res, idp.NewError(idp.CodeNotFound, op, "audit_realm_missing", nil)
			}
			continue // the realm was deleted: its mapping is gone with it
		}
		wantClients[r+"-realm"] = []string{ViewEventsRole}
		res.Audited = append(res.Audited, r)
	}
	realms := make([]string, 0, len(managed))
	for r := range managed {
		realms = append(realms, r)
	}
	sort.Strings(realms)
	for _, r := range realms {
		mgmt, err := a.findClient(ctx, op, adm, masterRealm, r+"-realm")
		if err != nil {
			return res, err
		}
		if mgmt == nil {
			if slices.Contains(cfg.AdoptRealms, r) {
				return res, idp.NewError(idp.CodeNotFound, op, "adopt_realm_missing", nil)
			}
			continue
		}
		var roles []map[string]any
		if _, _, err := a.call(ctx, op, adm, http.MethodGet, realmSub(masterRealm, "clients", str(mgmt["id"]), "roles"), nil, &roles); err != nil {
			return res, err
		}
		for _, role := range roles {
			if n := str(role["name"]); n != impersonationRole {
				wantClients[r+"-realm"] = append(wantClients[r+"-realm"], n)
			}
		}
	}
	ch, err = a.reconcileMappings(ctx, op, adm, masterRealm, base, joinChange("serviceaccount", cid), []string{"create-realm"}, wantClients)
	res.Changes = append(res.Changes, ch...)
	if err != nil {
		return res, err
	}
	// secret: keep a stored secret that works, otherwise store a new version first and set it
	prov := tokenSource{realm: masterRealm, clientID: cid, secret: res.Provisioner.Secret}
	if !res.Created {
		err := a.checkToken(ctx, op, prov)
		if c := idp.CodeOf(err); err != nil && c != idp.CodeUnauthenticated && c != idp.CodeCredentials {
			return res, err
		}
		if err != nil {
			secret, sref, err := a.newSecret(ctx, op, cfg.Provisioner.Secret, secrets.WithPlatformOps())
			if err != nil {
				return res, err
			}
			err = a.setClientSecret(ctx, op, adm, masterRealm, id, secret)
			secret.Wipe()
			if err != nil {
				return res, err
			}
			res.Rotated, res.Provisioner.Secret = true, sref
			res.Changes = append(res.Changes, joinChange("client", cid, "secret"))
			prov.secret = sref
		}
	}
	if err := a.checkToken(ctx, op, prov); err != nil {
		return res, err
	}
	if err := idp.DestroyOlder(ctx, st, res.Provisioner.Secret); err != nil {
		return res, idp.NewError(idp.CodeCredentials, op, "secret_store_destroy", err)
	}
	a.log.Info("keycloak: provisioning identity ready", "client", cid, "created", res.Created, "rotated", res.Rotated,
		"adopted", strings.Join(res.Adopted, ","), "audited", strings.Join(res.Audited, ","), "changes", len(res.Changes))
	return res, nil
}
