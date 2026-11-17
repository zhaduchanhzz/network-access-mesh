package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// builtinClients are created by Keycloak in every realm; anything else outside the template is reported as unmanaged.
var builtinClients = []string{"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}

// realmSkip: template keys reconciled through their own endpoints (or identity: realm). authenticatorConfig (the amr
// references of the browser flow — G2 round 2, A-6) is created with the realm and not reconciled: a missing one
// shows as a platform login refused for lack of MFA evidence; infrastructure/idp/realm-update.sh repairs it.
var realmSkip = map[string]bool{"realm": true, "clients": true, "users": true, "authenticationFlows": true,
	"requiredActions": true, "clientScopeMappings": true, "scopeMappings": true, "attributes": true,
	"authenticatorConfig": true}

func (d *Driver) params(reg idp.Registration, realm, display string) realmParams {
	return realmParams{Realm: realm, DisplayName: display, Scope: reg.Scope, IdPID: reg.IdPID, RedirectURI: d.redirectURI(reg)}
}

// EnsureIssuer creates the realm from the template when it does not exist — with a fresh mg-idp-driver secret, stored
// first in the SecretStore (DEK platform_ops) — or, when it exists, checks that it belongs to this IdP
// (attributes meshguard.idp_id / meshguard.scope) and repairs drift: realm settings (enabled included), the MFA
// browser flow, required actions, the template's clients other than the Portal (EnsureClient owns it), their
// service-account roles and scope mappings, and a mg-idp-driver secret that no longer works. Calling it twice yields
// the same realm and no duplicate. The issuer is derived from the realm and never changes (§8.2 (1)).
func (d *Driver) EnsureIssuer(ctx context.Context, spec idp.IssuerSpec) (idp.IssuerResult, error) {
	const op = "keycloak.EnsureIssuer"
	if err := spec.Validate(op); err != nil {
		return idp.IssuerResult{}, err
	}
	realm := spec.Realm
	var known secrets.Ref
	if spec.DriverRef != "" {
		ref, sref, err := ParseDriverRef(spec.DriverRef)
		if err != nil {
			return idp.IssuerResult{}, err
		}
		if realm != "" && realm != ref.Realm {
			return idp.IssuerResult{}, idp.NewError(idp.CodeInvalidArgument, op, "realm_mismatch", nil)
		}
		realm, known = ref.Realm, sref
	}
	if !validRealm(realm) {
		return idp.IssuerResult{}, idp.NewError(idp.CodeInvalidArgument, op, "realm_name", nil)
	}
	if spec.Issuer != "" && spec.Issuer != d.Issuer(realm) {
		return idp.IssuerResult{}, idp.NewError(idp.CodeInvalidArgument, op, "issuer_is_derived", nil)
	}
	rep, err := realmRep(d.params(spec.Registration, realm, spec.DisplayName))
	if err != nil {
		return idp.IssuerResult{}, idp.NewError(idp.CodeInternal, op, "template", err)
	}
	ts := d.provisioner()
	res := idp.IssuerResult{Issuer: d.Issuer(realm)}
	var live map[string]any
	st, _, err := d.call(ctx, op, ts, http.MethodGet, realmPath(realm), nil, &live, http.StatusNotFound)
	if err != nil {
		return res, err
	}
	if st == http.StatusNotFound {
		created, sref, err := d.createRealm(ctx, op, ts, spec.IdPID, realm, rep)
		if err != nil {
			return res, err
		}
		if created {
			res.Created = true
			res.DriverRef = DriverRef{Realm: realm, DriverSecret: sref.String()}.Encode()
			res.Changes = []string{"realm.created"}
			return res, nil
		}
		known = sref // created concurrently by another worker: reconcile it (its driver secret is not ours)
		if _, _, err := d.call(ctx, op, ts, http.MethodGet, realmPath(realm), nil, &live); err != nil {
			return res, err
		}
	}
	sref, changes, unmanaged, err := d.reconcileRealm(ctx, op, ts, spec.Registration, realm, rep, live, known)
	res.Changes, res.Unmanaged = changes, unmanaged
	if err != nil {
		return res, err
	}
	res.DriverRef = DriverRef{Realm: realm, DriverSecret: sref.String()}.Encode()
	if len(changes) > 0 {
		d.log.Info("keycloak: realm drift repaired", "realm", realm, "changes", len(changes))
	}
	return res, nil
}

// createRealm posts the realm with a new mg-idp-driver secret (stored first). created=false: the realm appeared
// meanwhile (409).
func (d *Driver) createRealm(ctx context.Context, op string, ts tokenSource, idpID uuid.UUID, realm string,
	rep map[string]any,
) (bool, secrets.Ref, error) {
	secret, sref, err := d.newSecret(ctx, op, driverSecretRef(idpID), secrets.WithPlatformOps())
	if err != nil {
		return false, secrets.Ref{}, err
	}
	defer secret.Wipe()
	r := deepCopy(rep)
	drv := clientsOf(r)[DriverClientID]
	if drv == nil {
		return false, sref, idp.NewError(idp.CodeInternal, op, "template_driver_client", nil)
	}
	drv["secret"] = string(secret.Bytes())
	st, _, err := d.call(ctx, op, ts, http.MethodPost, "/admin/realms", r, nil, http.StatusConflict)
	if err != nil {
		return false, sref, err
	}
	if st == http.StatusConflict {
		return false, sref, nil
	}
	if err := d.checkToken(ctx, op, realmToken(realm, sref)); err != nil {
		return true, sref, err
	}
	if err := idp.DestroyOlder(ctx, d.secrets, sref); err != nil {
		d.log.Warn("keycloak: older driver secret versions not destroyed", "ref", sref.String(), "error", err.Error())
	}
	d.log.Info("keycloak: realm created", "realm", realm, "idp_id", idpID.String())
	return true, sref, nil
}

// checkToken obtains a fresh token for ts (credentials work).
func (a *admin) checkToken(ctx context.Context, op string, ts tokenSource) error {
	a.invalidate(ts)
	_, err := a.token(ctx, op, ts)
	return err
}

// reconcileRealm repairs an existing realm; it returns the reference of the working mg-idp-driver secret.
func (d *Driver) reconcileRealm(ctx context.Context, op string, ts tokenSource, reg idp.Registration, realm string,
	rep, live map[string]any, known secrets.Ref,
) (secrets.Ref, []string, []string, error) {
	if str(live["id"]) == "" {
		// a master-realm identity that does not manage the realm only gets its name list entry
		return known, nil, nil, idp.NewError(idp.CodeForbidden, op, "realm_not_managed", nil)
	}
	la := asMap(live["attributes"])
	switch got := str(la["meshguard.idp_id"]); {
	case got == "":
		return known, nil, nil, idp.NewError(idp.CodeConflict, op, "realm_not_meshguard", nil)
	case got != reg.IdPID.String():
		return known, nil, nil, idp.NewError(idp.CodeConflict, op, "realm_of_another_idp", nil)
	case str(la["meshguard.scope"]) != string(reg.Scope):
		return known, nil, nil, idp.NewError(idp.CodeConflict, op, "realm_scope_mismatch", nil)
	}
	var changes, unmanaged []string
	// 1. realm settings and attributes
	upd := map[string]any{}
	for _, k := range diffKeys(rep, live, realmSkip) {
		upd[k] = rep[k]
		changes = append(changes, joinChange("realm", k))
	}
	if merged, ch := mergeAttributes(asMap(rep["attributes"]), la); len(ch) > 0 {
		upd["attributes"] = merged
		for _, k := range ch {
			changes = append(changes, joinChange("realm", "attributes", k))
		}
	}
	if len(upd) > 0 {
		if _, _, err := d.call(ctx, op, ts, http.MethodPut, realmPath(realm), upd, nil); err != nil {
			return known, changes, nil, err
		}
	}
	// 2. MFA browser flow, 3. required actions
	ch, err := d.reconcileFlow(ctx, op, ts, realm, rep)
	changes = append(changes, ch...)
	if err != nil {
		return known, changes, nil, err
	}
	ch, err = d.reconcileRequiredActions(ctx, op, ts, realm, rep)
	changes = append(changes, ch...)
	if err != nil {
		return known, changes, nil, err
	}
	// 4. clients of the template (the Portal client belongs to EnsureClient)
	var driverID string
	for _, cid := range clientIDs(rep) {
		if cid == PortalClientID {
			continue
		}
		id, ch, err := d.reconcileTemplateClient(ctx, op, ts, realm, rep, cid)
		changes = append(changes, ch...)
		if err != nil {
			return known, changes, nil, err
		}
		if cid == DriverClientID {
			driverID = id
		}
	}
	// 5. clients nobody declared: reported, never modified (a change to a tenant's IdP needs approval — §8.2 (1))
	var all []map[string]any
	if _, _, err := d.call(ctx, op, ts, http.MethodGet, realmSub(realm, "clients"), nil, &all); err != nil {
		return known, changes, nil, err
	}
	declared := clientsOf(rep)
	for _, c := range all {
		cid := str(c["clientId"])
		if _, ok := declared[cid]; !ok && !slices.Contains(builtinClients, cid) {
			unmanaged = append(unmanaged, joinChange("client", cid))
		}
	}
	sort.Strings(unmanaged)
	// 6. the mg-idp-driver secret must work
	sref, ch, err := d.ensureDriverSecret(ctx, op, ts, reg.IdPID, realm, driverID, known)
	changes = append(changes, ch...)
	return sref, changes, unmanaged, err
}

// reconcileTemplateClient makes client cid of the template exist and conform, with its scope mappings (when
// fullScopeAllowed is false) and its service-account roles. It returns the client's id.
func (d *Driver) reconcileTemplateClient(ctx context.Context, op string, ts tokenSource, realm string, rep map[string]any,
	cid string,
) (string, []string, error) {
	want := clientsOf(rep)[cid]
	var changes []string
	live, err := d.findClient(ctx, op, ts, realm, cid)
	if err != nil {
		return "", nil, err
	}
	if live == nil {
		if _, err := d.createClient(ctx, op, ts, realm, deepCopy(want)); err != nil {
			return "", nil, err
		}
		changes = append(changes, joinChange("client", cid, "created"))
		if live, err = d.findClient(ctx, op, ts, realm, cid); err != nil || live == nil {
			return "", changes, idp.NewError(idp.CodeUpstream, op, "client_not_found_after_create", err)
		}
	}
	id := str(live["id"])
	ch, err := d.reconcileClient(ctx, op, ts, realm, want, live)
	changes = append(changes, ch...)
	if err != nil {
		return id, changes, err
	}
	if want["fullScopeAllowed"] == false {
		wr, wc := scopeMappingsOf(rep, cid)
		ch, err := d.reconcileMappings(ctx, op, ts, realm, realmSub(realm, "clients", id, "scope-mappings"),
			joinChange("client", cid, "scope"), wr, wc)
		changes = append(changes, ch...)
		if err != nil {
			return id, changes, err
		}
	}
	if want["serviceAccountsEnabled"] == true {
		var sa map[string]any
		if _, _, err := d.call(ctx, op, ts, http.MethodGet, realmSub(realm, "clients", id, "service-account-user"), nil, &sa); err != nil {
			return id, changes, err
		}
		wr, wc := serviceAccountRoles(rep, cid)
		ch, err := d.reconcileMappings(ctx, op, ts, realm, realmSub(realm, "users", str(sa["id"]), "role-mappings"),
			joinChange("serviceaccount", cid), wr, wc)
		changes = append(changes, ch...)
		if err != nil {
			return id, changes, err
		}
	}
	return id, changes, nil
}

// reconcileFlow checks the browser flow of the template execution by execution: a different structure is drift the
// driver does not repair (CodeDrift); a different requirement (e.g. OTP no longer REQUIRED) is set back.
func (d *Driver) reconcileFlow(ctx context.Context, op string, ts tokenSource, realm string, rep map[string]any) ([]string, error) {
	alias := str(rep["browserFlow"])
	want, err := flowExecutions(rep, alias)
	if err != nil {
		return nil, idp.NewError(idp.CodeInternal, op, "template_flow", err)
	}
	var live []map[string]any
	st, _, err := d.call(ctx, op, ts, http.MethodGet, realmSub(realm, "authentication", "flows", alias, "executions"),
		nil, &live, http.StatusNotFound)
	if err != nil {
		return nil, err
	}
	if st == http.StatusNotFound {
		return nil, idp.NewError(idp.CodeDrift, op, "flow_missing", nil)
	}
	if len(live) != len(want) {
		return nil, idp.NewError(idp.CodeDrift, op, "flow_structure", nil)
	}
	for i, w := range want {
		l := live[i]
		key := str(l["providerId"])
		if l["authenticationFlow"] == true {
			key = str(l["displayName"])
		}
		lvl, _ := l["level"].(json.Number).Int64()
		if int(lvl) != w.Level || key != w.Key {
			return nil, idp.NewError(idp.CodeDrift, op, "flow_structure", nil)
		}
	}
	var changes []string
	for i, w := range want {
		if str(live[i]["requirement"]) == w.Requirement {
			continue
		}
		upd := deepCopy(live[i])
		upd["requirement"] = w.Requirement
		if _, _, err := d.call(ctx, op, ts, http.MethodPut, realmSub(realm, "authentication", "flows", alias, "executions"), upd, nil); err != nil {
			return changes, err
		}
		changes = append(changes, joinChange("flow", alias, w.Key, "requirement"))
	}
	return changes, nil
}

// reconcileRequiredActions sets enabled/defaultAction of the template's required actions back (CONFIGURE_TOTP must stay
// enabled and a default action) and their configuration (max_auth_age = 0: changing a password or a second factor
// from the account console always re-authenticates — G2 round 2, A-4); a missing action is drift.
func (d *Driver) reconcileRequiredActions(ctx context.Context, op string, ts tokenSource, realm string, rep map[string]any) ([]string, error) {
	var live []map[string]any
	if _, _, err := d.call(ctx, op, ts, http.MethodGet, realmSub(realm, "authentication", "required-actions"), nil, &live); err != nil {
		return nil, err
	}
	byAlias := map[string]map[string]any{}
	for _, l := range live {
		byAlias[str(l["alias"])] = l
	}
	wantList, _ := rep["requiredActions"].([]any)
	var changes []string
	for _, w := range wantList {
		wm := asMap(w)
		alias := str(wm["alias"])
		l := byAlias[alias]
		if l == nil {
			return changes, idp.NewError(idp.CodeDrift, op, "required_action_missing", nil)
		}
		if l["enabled"] != wm["enabled"] || l["defaultAction"] != wm["defaultAction"] {
			upd := deepCopy(l)
			upd["enabled"], upd["defaultAction"] = wm["enabled"], wm["defaultAction"]
			if _, _, err := d.call(ctx, op, ts, http.MethodPut, realmSub(realm, "authentication", "required-actions", alias), upd, nil); err != nil {
				return changes, err
			}
			changes = append(changes, joinChange("requiredAction", alias))
		}
		if want := asMap(wm["config"]); len(want) > 0 {
			path := realmSub(realm, "authentication", "required-actions", alias, "config")
			var cfg map[string]any
			if _, _, err := d.call(ctx, op, ts, http.MethodGet, path, nil, &cfg); err != nil {
				return changes, err
			}
			have := asMap(cfg["config"])
			if merged, ch := mergeAttributes(want, have); len(ch) > 0 {
				if _, _, err := d.call(ctx, op, ts, http.MethodPut, path, map[string]any{"config": merged}, nil); err != nil {
					return changes, err
				}
				changes = append(changes, joinChange("requiredAction", alias, "config"))
			}
		}
	}
	return changes, nil
}

// ensureDriverSecret keeps the known mg-idp-driver secret when it still works; when the IdP refuses it (or the store
// no longer holds it) a new secret is stored first, set at Keycloak, checked, and older versions destroyed. A transient
// failure (network, 5xx) is returned without rotating.
func (d *Driver) ensureDriverSecret(ctx context.Context, op string, ts tokenSource, idpID uuid.UUID, realm, driverID string,
	known secrets.Ref,
) (secrets.Ref, []string, error) {
	if known.Name != "" {
		err := d.checkToken(ctx, op, realmToken(realm, known))
		if err == nil {
			return known, nil, nil
		}
		if c := idp.CodeOf(err); c != idp.CodeUnauthenticated && c != idp.CodeCredentials {
			return known, nil, err
		}
	}
	if driverID == "" {
		return known, nil, idp.NewError(idp.CodeInternal, op, "driver_client_unknown", nil)
	}
	secret, sref, err := d.newSecret(ctx, op, driverSecretRef(idpID), secrets.WithPlatformOps())
	if err != nil {
		return known, nil, err
	}
	defer secret.Wipe()
	if err := d.setClientSecret(ctx, op, ts, realm, driverID, secret); err != nil {
		return known, nil, err
	}
	if known.Name != "" {
		d.invalidate(realmToken(realm, known))
	}
	changes := []string{joinChange("client", DriverClientID, "secret")}
	if err := d.checkToken(ctx, op, realmToken(realm, sref)); err != nil {
		return sref, changes, err
	}
	if err := idp.DestroyOlder(ctx, d.secrets, sref); err != nil {
		d.log.Warn("keycloak: older driver secret versions not destroyed", "ref", sref.String(), "error", err.Error())
	}
	return sref, changes, nil
}
