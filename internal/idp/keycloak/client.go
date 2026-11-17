package keycloak

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"slices"
	"sort"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// clientSkip: client fields not compared one by one (identity, secret, read-only fields, lists reconciled through
// their own endpoints, attributes merged key by key).
var clientSkip = map[string]bool{"clientId": true, "id": true, "secret": true, "defaultClientScopes": true,
	"optionalClientScopes": true, "attributes": true, "protocolMappers": true, "access": true}

// findClient returns the live representation of clientID in realm (nil when absent).
func (a *admin) findClient(ctx context.Context, op string, ts tokenSource, realm, clientID string) (map[string]any, error) {
	var list []map[string]any
	if _, _, err := a.call(ctx, op, ts, http.MethodGet,
		realmSub(realm, "clients")+"?clientId="+url.QueryEscape(clientID), nil, &list); err != nil {
		return nil, err
	}
	for _, c := range list {
		if str(c["clientId"]) == clientID {
			return c, nil
		}
	}
	return nil, nil
}

// createClient creates a client from rep and returns its id.
func (a *admin) createClient(ctx context.Context, op string, ts tokenSource, realm string, rep map[string]any) (string, error) {
	_, h, err := a.call(ctx, op, ts, http.MethodPost, realmSub(realm, "clients"), rep, nil)
	if err != nil {
		return "", err
	}
	return createdID(op, h)
}

// reconcileClient makes the settings, attributes and client scopes of live match want; it returns the corrections.
func (a *admin) reconcileClient(ctx context.Context, op string, ts tokenSource, realm string, want, live map[string]any,
) ([]string, error) {
	cid, id := str(want["clientId"]), str(live["id"])
	var changes []string
	upd := map[string]any{}
	for _, k := range diffKeys(want, live, clientSkip) {
		upd[k] = want[k]
		changes = append(changes, joinChange("client", cid, k))
	}
	if wa := asMap(want["attributes"]); wa != nil {
		merged, ch := mergeAttributes(wa, asMap(live["attributes"]))
		if len(ch) > 0 {
			upd["attributes"] = merged
			for _, k := range ch {
				changes = append(changes, joinChange("client", cid, "attributes", k))
			}
		}
	}
	if len(upd) > 0 {
		if err := a.putClient(ctx, op, ts, realm, id, func(c map[string]any) {
			for k, v := range upd {
				c[k] = v
			}
		}); err != nil {
			return changes, err
		}
	}
	for _, kind := range []string{"default", "optional"} {
		w, ok := want[kind+"ClientScopes"]
		if !ok {
			continue
		}
		ch, err := a.reconcileClientScopes(ctx, op, ts, realm, id, cid, kind, stringList(w))
		changes = append(changes, ch...)
		if err != nil {
			return changes, err
		}
	}
	return changes, nil
}

// reconcileClientScopes makes the default or optional client scopes of a client exactly want.
func (a *admin) reconcileClientScopes(ctx context.Context, op string, ts tokenSource, realm, id, cid, kind string,
	want []string,
) ([]string, error) {
	var live []map[string]any
	if _, _, err := a.call(ctx, op, ts, http.MethodGet, realmSub(realm, "clients", id, kind+"-client-scopes"), nil, &live); err != nil {
		return nil, err
	}
	have := map[string]string{}
	for _, s := range live {
		have[str(s["name"])] = str(s["id"])
	}
	var changes []string
	var missing []string
	for _, w := range want {
		if _, ok := have[w]; !ok {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		var all []map[string]any
		if _, _, err := a.call(ctx, op, ts, http.MethodGet, realmSub(realm, "client-scopes"), nil, &all); err != nil {
			return nil, err
		}
		ids := map[string]string{}
		for _, s := range all {
			ids[str(s["name"])] = str(s["id"])
		}
		sort.Strings(missing)
		for _, m := range missing {
			sid := ids[m]
			if sid == "" {
				return changes, idp.NewError(idp.CodeDrift, op, "client_scope_missing", nil)
			}
			if _, _, err := a.call(ctx, op, ts, http.MethodPut, realmSub(realm, "clients", id, kind+"-client-scopes", sid), nil, nil); err != nil {
				return changes, err
			}
			changes = append(changes, joinChange("client", cid, kind+"ClientScopes", "+"+m))
		}
	}
	var extra []string
	for name := range have {
		if !slices.Contains(want, name) {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, e := range extra {
		if _, _, err := a.call(ctx, op, ts, http.MethodDelete, realmSub(realm, "clients", id, kind+"-client-scopes", have[e]), nil, nil); err != nil {
			return changes, err
		}
		changes = append(changes, joinChange("client", cid, kind+"ClientScopes", "-"+e))
	}
	return changes, nil
}

// mappings is a MappingsRepresentation (role mappings of a user, scope mappings of a client).
type mappings struct {
	RealmMappings  []map[string]any `json:"realmMappings"`
	ClientMappings map[string]struct {
		ID       string           `json:"id"`
		Client   string           `json:"client"`
		Mappings []map[string]any `json:"mappings"`
	} `json:"clientMappings"`
}

// reconcileMappings makes the role mappings at base (".../users/<id>/role-mappings" or
// ".../clients/<id>/scope-mappings") exactly wantRealm + wantClients (role names per role-container clientId). what
// names the object in the change entries.
func (a *admin) reconcileMappings(ctx context.Context, op string, ts tokenSource, realm, base, what string,
	wantRealm []string, wantClients map[string][]string,
) ([]string, error) {
	var live mappings
	if _, _, err := a.call(ctx, op, ts, http.MethodGet, base, nil, &live); err != nil {
		return nil, err
	}
	var changes []string
	// realm roles
	var extra []map[string]any
	haveRealm := map[string]bool{}
	for _, r := range live.RealmMappings {
		haveRealm[str(r["name"])] = true
		if !slices.Contains(wantRealm, str(r["name"])) {
			extra = append(extra, r)
			changes = append(changes, joinChange(what, "realmRoles", "-"+str(r["name"])))
		}
	}
	if len(extra) > 0 {
		if err := a.changeMapping(ctx, op, ts, http.MethodDelete, base+"/realm", extra); err != nil {
			return changes, err
		}
	}
	var add []map[string]any
	for _, name := range wantRealm {
		if haveRealm[name] {
			continue
		}
		var role map[string]any
		if _, _, err := a.call(ctx, op, ts, http.MethodGet, realmSub(realm, "roles", name), nil, &role); err != nil {
			return changes, err
		}
		add = append(add, role)
		changes = append(changes, joinChange(what, "realmRoles", "+"+name))
	}
	if len(add) > 0 {
		if err := a.changeMapping(ctx, op, ts, http.MethodPost, base+"/realm", add); err != nil {
			return changes, err
		}
	}
	// client roles: remove what is not wanted
	containers := make([]string, 0, len(live.ClientMappings))
	for c := range live.ClientMappings {
		containers = append(containers, c)
	}
	sort.Strings(containers)
	for _, c := range containers {
		m := live.ClientMappings[c]
		var rm []map[string]any
		for _, r := range m.Mappings {
			if !slices.Contains(wantClients[c], str(r["name"])) {
				rm = append(rm, r)
				changes = append(changes, joinChange(what, c, "-"+str(r["name"])))
			}
		}
		if len(rm) > 0 {
			if err := a.changeMapping(ctx, op, ts, http.MethodDelete, base+"/clients/"+url.PathEscape(m.ID), rm); err != nil {
				return changes, err
			}
		}
	}
	// client roles: add what is missing
	wanted := make([]string, 0, len(wantClients))
	for c := range wantClients {
		wanted = append(wanted, c)
	}
	sort.Strings(wanted)
	for _, c := range wanted {
		have := map[string]bool{}
		for _, r := range live.ClientMappings[c].Mappings {
			have[str(r["name"])] = true
		}
		var missing []string
		for _, name := range wantClients[c] {
			if !have[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) == 0 {
			continue
		}
		container, err := a.findClient(ctx, op, ts, realm, c)
		if err != nil {
			return changes, err
		}
		if container == nil {
			return changes, idp.NewError(idp.CodeDrift, op, "role_container_missing", nil)
		}
		var roles []map[string]any
		if _, _, err := a.call(ctx, op, ts, http.MethodGet, realmSub(realm, "clients", str(container["id"]), "roles"), nil, &roles); err != nil {
			return changes, err
		}
		var reps []map[string]any
		for _, name := range missing {
			i := slices.IndexFunc(roles, func(r map[string]any) bool { return str(r["name"]) == name })
			if i < 0 {
				return changes, idp.NewError(idp.CodeDrift, op, "role_missing", nil)
			}
			reps = append(reps, roles[i])
			changes = append(changes, joinChange(what, c, "+"+name))
		}
		if err := a.changeMapping(ctx, op, ts, http.MethodPost, base+"/clients/"+url.PathEscape(str(container["id"])), reps); err != nil {
			return changes, err
		}
	}
	return changes, nil
}

// changeMapping adds or removes role mappings. Keycloak refuses (403) to map or unmap a role the caller does not hold
// itself — e.g. realm-admin, a composite that contains impersonation, which no identity of the driver holds: such a
// mapping is drift only the break-glass admin can repair (CodeDrift), never silently accepted.
func (a *admin) changeMapping(ctx context.Context, op string, ts tokenSource, method, p string, roles []map[string]any) error {
	_, _, err := a.call(ctx, op, ts, method, p, roles, nil)
	if idp.CodeOf(err) == idp.CodeForbidden {
		return idp.NewError(idp.CodeDrift, op, "role_mapping_not_repairable", err)
	}
	return err
}

// clientSecret reads the current secret of a confidential client.
func (a *admin) clientSecret(ctx context.Context, op string, ts tokenSource, realm, id string) (secrets.Plaintext, error) {
	var cred struct {
		Value string `json:"value"`
	}
	if _, _, err := a.call(ctx, op, ts, http.MethodGet, realmSub(realm, "clients", id, "client-secret"), nil, &cred); err != nil {
		return nil, err
	}
	return secrets.Plaintext(cred.Value), nil
}

// setClientSecret sets the secret of a confidential client (the value was stored in the SecretStore first).
func (a *admin) setClientSecret(ctx context.Context, op string, ts tokenSource, realm, id string,
	secret secrets.Plaintext,
) error {
	return a.putClient(ctx, op, ts, realm, id, func(c map[string]any) { c["secret"] = string(secret.Bytes()) })
}

// putClient updates a client with its FULL current representation, changed by mutate. Two behaviours of Keycloak
// 26.8 found by the integration test of P2-T05a shape the body: (1) an update that omits webOrigins makes Keycloak
// derive them from the redirect URIs — silently opening a CORS origin the template forbids (BFF: webOrigins = []), so
// the body is never partial; (2) an update carrying serviceAccountsEnabled=true re-attaches the service_account
// default scope, so that field is sent only when mutate sets it (a deliberate repair).
func (a *admin) putClient(ctx context.Context, op string, ts tokenSource, realm, id string, mutate func(map[string]any)) error {
	var full map[string]any
	if _, _, err := a.call(ctx, op, ts, http.MethodGet, realmSub(realm, "clients", id), nil, &full); err != nil {
		return err
	}
	if full["webOrigins"] == nil {
		full["webOrigins"] = []any{}
	}
	for _, k := range []string{"serviceAccountsEnabled", "access", "protocolMappers", "authorizationSettings"} {
		delete(full, k)
	}
	mutate(full)
	_, _, err := a.call(ctx, op, ts, http.MethodPut, realmSub(realm, "clients", id), full, nil)
	return err
}

// EnsureClient makes the Portal client of the realm conform to the template (exact redirect URI of the IdP, PKCE
// S256, Authorization Code only, no refresh token) and its secret equal to the SecretStore version the registration
// names. A missing, unreadable or different secret is replaced: a new version is stored first, then set at Keycloak
// (SecretRotated: the caller must write ClientSecretRef into the row). Older versions are kept for the api until the
// row is updated.
func (d *Driver) EnsureClient(ctx context.Context, spec idp.ClientSpec) (idp.ClientResult, error) {
	const op = "keycloak.EnsureClient"
	if err := spec.Validate(op); err != nil {
		return idp.ClientResult{}, err
	}
	ref, _, err := ParseDriverRef(spec.DriverRef)
	if err != nil {
		return idp.ClientResult{}, err
	}
	if spec.ClientID != "" && spec.ClientID != PortalClientID {
		return idp.ClientResult{}, idp.NewError(idp.CodeInvalidArgument, op, "client_id_is_fixed", nil)
	}
	rep, err := realmRep(d.params(spec.Registration, ref.Realm, ""))
	if err != nil {
		return idp.ClientResult{}, idp.NewError(idp.CodeInternal, op, "template", err)
	}
	want := clientsOf(rep)[PortalClientID]
	ts := d.provisioner()
	res := idp.ClientResult{ClientID: PortalClientID, ClientSecretRef: spec.ClientSecretRef}
	live, err := d.findClient(ctx, op, ts, ref.Realm, PortalClientID)
	if err != nil {
		return idp.ClientResult{}, err
	}
	if live == nil {
		secret, sref, err := d.newSecret(ctx, op, spec.ClientSecretOwner(1))
		if err != nil {
			return idp.ClientResult{}, err
		}
		defer secret.Wipe()
		c := deepCopy(want)
		c["secret"] = string(secret.Bytes())
		if _, err := d.createClient(ctx, op, ts, ref.Realm, c); err != nil {
			return idp.ClientResult{}, err
		}
		res.Created, res.SecretRotated, res.ClientSecretRef = true, true, sref.String()
		res.Changes = []string{joinChange("client", PortalClientID, "created")}
		return res, nil
	}
	res.Changes, err = d.reconcileClient(ctx, op, ts, ref.Realm, want, live)
	if err != nil {
		return res, err
	}
	wantRealm, wantClients := scopeMappingsOf(rep, PortalClientID)
	ch, err := d.reconcileMappings(ctx, op, ts, ref.Realm, realmSub(ref.Realm, "clients", str(live["id"]), "scope-mappings"),
		joinChange("client", PortalClientID, "scope"), wantRealm, wantClients)
	res.Changes = append(res.Changes, ch...)
	if err != nil {
		return res, err
	}
	// secret: keep it when Keycloak holds exactly the stored version
	if spec.ClientSecretRef != "" {
		if sr, perr := secrets.ParseRef(spec.ClientSecretRef); perr == nil {
			if stored, gerr := d.secrets.Get(ctx, sr); gerr == nil {
				cur, cerr := d.clientSecret(ctx, op, ts, ref.Realm, str(live["id"]))
				same := cerr == nil && subtle.ConstantTimeCompare(stored.Bytes(), cur.Bytes()) == 1
				stored.Wipe()
				cur.Wipe()
				if cerr != nil {
					return res, cerr
				}
				if same {
					return res, nil
				}
			}
		}
	}
	secret, sref, err := d.newSecret(ctx, op, spec.ClientSecretOwner(1))
	if err != nil {
		return res, err
	}
	defer secret.Wipe()
	if err := d.setClientSecret(ctx, op, ts, ref.Realm, str(live["id"]), secret); err != nil {
		return res, err
	}
	res.SecretRotated, res.ClientSecretRef = true, sref.String()
	res.Changes = append(res.Changes, joinChange("client", PortalClientID, "secret"))
	return res, nil
}

// newSecret generates a client secret and stores it as the newest version of base (platform_ops for platform
// references of the driver's own credentials, see opts).
func (a *admin) newSecret(ctx context.Context, op string, base secrets.Ref, opts ...secrets.Option) (secrets.Plaintext, secrets.Ref, error) {
	v, err := idp.NewSecretValue()
	if err != nil {
		return nil, secrets.Ref{}, idp.NewError(idp.CodeInternal, op, "random", err)
	}
	ref, err := idp.StoreNewVersion(ctx, a.secrets, base, v.Bytes(), opts...)
	if err != nil {
		v.Wipe()
		return nil, secrets.Ref{}, idp.NewError(idp.CodeCredentials, op, "secret_store_write", err)
	}
	return v, ref, nil
}
