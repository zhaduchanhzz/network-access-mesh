package auditsync

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
)

// RealmKind is what a realm is to the platform.
type RealmKind int

const (
	RealmTenant   RealmKind = iota // the realm of a tenant's IdP: events go to that tenant's audit
	RealmPlatform                  // the realm of the platform IdP (platform staff): platform audit
	RealmMaster                    // Keycloak's administration realm: console logins, platform audit
)

// Actor kinds (details.idp_actor_kind): who acted at the IdP, as far as the event tells.
const (
	ActorDriver      = "idp_driver"      // the realm's own mg-idp-driver service account (platform automation, P2-T05a)
	ActorProvisioner = "idp_provisioner" // the platform's provisioning identity (master realm, platform automation)
	ActorAdmin       = "idp_admin"       // any other identity of the master realm: the console, kcadm, the break-glass admin
	ActorRealmUser   = "realm_user"      // an identity of the event's own realm (not the driver)
)

// actorDisplay is audit_events.actor_display of each actor kind.
var actorDisplay = map[string]string{
	ActorDriver:      "IdP driver (service account of the realm)",
	ActorProvisioner: "IdP provisioning identity (platform)",
	ActorAdmin:       "Keycloak administrator (master realm)",
	ActorRealmUser:   "user of the realm",
}

// Security event kinds raised by the job (security_events.kind) and by the console gate.
const (
	KindImpersonation      = "idp.impersonation"            // critical: impersonation done or attempted (§8.2 (2))
	KindCredentialReset    = "idp.credential_reset"         //nolint:gosec // event kind, not a credential. high: a credential reset/removed by a non-tenant actor
	KindIdentityProvider   = "idp.identity_provider_change" // high: identity brokering changed in a realm (a way in)
	KindAuthFlow           = "idp.auth_flow_change"         // medium: the login flow / required actions changed (MFA)
	KindMasterPrivilege    = "idp.master_privilege_change"  // high: a role mapping changed in the master realm
	KindMasterClient       = "idp.master_client_change"     // medium: a client of the master realm changed
	KindConsoleLogin       = "idp.console_login"            // high: a sign-in to the Keycloak administration
	KindConsoleLoginFailed = "idp.console_login_failed"     // medium: a failed sign-in to it
	KindAuditDisabled      = "idp.audit_events_disabled"    // high: events or admin events of an audited realm are off
	KindAuditSyncFailed    = "idp.audit_sync_failed"        // medium: a realm could not be read (no view-events…)
)

// Security is the security event an IdP event raises.
type Security struct {
	Kind     string
	Severity string
}

// Record is what one Keycloak event becomes: one audit_events row (always), maybe a security event and a
// notification. Details never hold the representation of an admin event nor any field outside the allow-lists.
type Record struct {
	EventID      string
	At           time.Time
	Action       string // idp.user.credential_reset …
	Outcome      string
	ResourceType string // idp.user, idp.client, idp.realm …
	ResourceID   string
	ActorKind    string
	ActorDisplay string
	ActorIP      netip.Addr
	UserSub      string // the affected user of the realm (Keycloak id = OIDC sub), when the event names one
	Details      audit.Details
	Security     *Security
	// Notify: tell the Tenant Owners (tenant realms) or the platform staff (console logins).
	Notify bool
	// ConsoleLogin: a successful sign-in to the Keycloak administration (master realm).
	ConsoleLogin bool
	Client       string // the client of a user event (security-admin-console, admin-cli…)
	Username     string // the account of a user event (details.username)
}

// Actors identifies the platform's own identities in the events of one realm.
type Actors struct {
	ProvisionerUserID string // sub of the provisioning identity's token
	DriverClientUUID  string // internal id of mg-idp-driver in the realm ("" when unknown)
}

// ActorOf classifies who acted in an admin event of a realm of kind k.
func (a Actors) ActorOf(ev keycloak.AdminEvent, k RealmKind) string {
	ad := ev.AuthDetails
	switch {
	case ad.UserID != "" && ad.UserID == a.ProvisionerUserID:
		return ActorProvisioner
	case k == RealmMaster:
		return ActorAdmin
	case ad.RealmID != "" && ad.RealmID == ev.RealmID && a.DriverClientUUID != "" && ad.ClientID == a.DriverClientUUID:
		return ActorDriver
	case ad.RealmID != "" && ad.RealmID == ev.RealmID:
		return ActorRealmUser
	}
	return ActorAdmin // another realm: only the master realm administers other realms in Keycloak
}

var (
	uuidRE  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9._@:+-]{1,128}$`)
)

// rule is one admin event class.
type rule struct {
	action       string
	resourceType string
	sensitive    bool // notify the Owners even when the platform's own automation did it
	security     func(actor string, k RealmKind, op string) *Security
}

func sec(kind, severity string) *Security { return &Security{Kind: kind, Severity: severity} }

// credential: a credential reset or removed by anyone but a user of the realm (in a tenant realm, only the platform
// side reaches the Admin API: this is the "non-tenant actor" of P3-T15).
func credential(actor string, _ RealmKind, _ string) *Security {
	if actor == ActorRealmUser {
		return nil
	}
	return sec(KindCredentialReset, audit.SeverityHigh)
}

// classifyAdmin turns an admin event into its record (actor already classified). Unknown resource types are still
// imported as idp.admin.change — every admin event reaches the audit trail.
func classifyAdmin(ev keycloak.AdminEvent, k RealmKind, actor string) Record {
	path := strings.Trim(ev.ResourcePath, "/")
	segs := strings.Split(path, "/")
	op := strings.ToUpper(ev.OperationType)
	seg := func(i int) string {
		if i < len(segs) {
			return segs[i]
		}
		return ""
	}
	r := Record{EventID: ev.ID, At: time.UnixMilli(ev.Time).UTC(), Outcome: audit.OutcomeSuccess, ActorKind: actor,
		ActorDisplay: actorDisplay[actor]}
	if ev.Error != "" {
		r.Outcome = audit.OutcomeFailure
	}
	var ru rule
	switch ev.ResourceType {
	case "USER":
		ru = userRule(op, seg(2), len(segs))
		if seg(0) == "users" {
			r.UserSub = seg(1)
		}
	case "REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING":
		verb := map[string]string{"CREATE": "role_grant", "DELETE": "role_revoke"}[op]
		if verb == "" {
			verb = "role_change"
		}
		owner := "user"
		if seg(0) == "groups" {
			owner = "group"
		} else if seg(0) == "users" {
			r.UserSub = seg(1)
		}
		ru = rule{action: "idp." + owner + "." + verb, resourceType: "idp." + owner, sensitive: true,
			security: func(actor string, k RealmKind, _ string) *Security {
				if k == RealmMaster && actor != ActorProvisioner {
					return sec(KindMasterPrivilege, audit.SeverityHigh)
				}
				return nil
			}}
	case "GROUP_MEMBERSHIP":
		verb := map[string]string{"CREATE": "group_join", "DELETE": "group_leave"}[op]
		if verb == "" {
			verb = "group_change"
		}
		if seg(0) == "users" {
			r.UserSub = seg(1)
		}
		ru = rule{action: "idp.user." + verb, resourceType: "idp.user", sensitive: true}
	case "CLIENT":
		switch {
		case seg(2) == "client-secret":
			ru = rule{action: "idp.client.secret_rotate", resourceType: "idp.client", sensitive: true}
		case len(segs) <= 2:
			ru = rule{action: "idp.client." + opVerb(op, "change"), resourceType: "idp.client", sensitive: true}
		default:
			ru = rule{action: "idp.client.change", resourceType: "idp.client", sensitive: true}
		}
		ru.security = func(actor string, k RealmKind, _ string) *Security {
			if k == RealmMaster && actor != ActorProvisioner {
				return sec(KindMasterClient, audit.SeverityMedium)
			}
			return nil
		}
	case "CLIENT_SCOPE", "CLIENT_SCOPE_MAPPING", "CLIENT_SCOPE_CLIENT_MAPPING", "PROTOCOL_MAPPER", "CLIENT_INITIAL_ACCESS_MODEL",
		"CLUSTER_NODE":
		ru = rule{action: "idp.client.config_change", resourceType: "idp.client", sensitive: true}
	case "REALM_ROLE", "CLIENT_ROLE", "REALM_SCOPE_MAPPING":
		ru = rule{action: "idp.realm.role_change", resourceType: "idp.realm", sensitive: true}
	case "GROUP":
		ru = rule{action: "idp.group." + opVerb(op, "change"), resourceType: "idp.group", sensitive: true}
	case "REALM":
		ru = rule{action: "idp.realm.update", resourceType: "idp.realm", sensitive: true}
	case "AUTH_FLOW", "AUTH_EXECUTION", "AUTH_EXECUTION_FLOW", "AUTHENTICATOR_CONFIG", "REQUIRED_ACTION",
		"REQUIRED_ACTION_CONFIG":
		ru = rule{action: "idp.realm.auth_change", resourceType: "idp.realm", sensitive: true,
			security: func(string, RealmKind, string) *Security { return sec(KindAuthFlow, audit.SeverityMedium) }}
	case "IDENTITY_PROVIDER", "IDENTITY_PROVIDER_MAPPER":
		ru = rule{action: "idp.realm.identity_provider_change", resourceType: "idp.realm", sensitive: true,
			security: func(string, RealmKind, string) *Security { return sec(KindIdentityProvider, audit.SeverityHigh) }}
	case "COMPONENT", "USER_FEDERATION_PROVIDER", "USER_FEDERATION_MAPPER", "USER_PROFILE":
		ru = rule{action: "idp.realm.component_change", resourceType: "idp.realm", sensitive: true}
	case "USER_SESSION", "USER_LOGIN_FAILURE":
		ru = rule{action: "idp.user.session_change", resourceType: "idp.user"}
		if seg(0) == "attack-detection" && seg(3) != "" {
			r.UserSub = seg(3)
		}
	case "ORGANIZATION", "ORGANIZATION_MEMBERSHIP":
		ru = rule{action: "idp.realm.organization_change", resourceType: "idp.realm", sensitive: true}
	default:
		ru = rule{action: "idp.admin.change", resourceType: "idp.realm", sensitive: true}
	}
	r.Action, r.ResourceType = ru.action, ru.resourceType
	r.ResourceID = resourceID(segs)
	if ru.security != nil {
		r.Security = ru.security(actor, k, op)
	}
	if r.UserSub != "" && !uuidRE.MatchString(r.UserSub) {
		r.UserSub = ""
	}
	// Notify the Owners of a tenant realm: always for a change the platform's automation never makes on its own
	// (credentials, roles, clients, the realm itself), and for anything a person did (the console, kcadm).
	r.Notify = k == RealmTenant && (ru.sensitive || (actor != ActorDriver && actor != ActorProvisioner))
	r.Details = audit.Details{
		"idp_event_id": ev.ID, "idp_operation": op, "idp_resource_type": ev.ResourceType,
		"idp_resource_path": clipPath(path), "idp_actor_kind": actor, "idp_actor_user_id": idOrEmpty(ev.AuthDetails.UserID),
		"idp_actor_client": idOrEmpty(ev.AuthDetails.ClientID), "idp_actor_realm": actorRealm(ev),
	}
	if r.UserSub != "" {
		r.Details["idp_user_id"] = r.UserSub
	}
	if ev.Error != "" {
		r.Details["idp_error"] = token(ev.Error)
	}
	for key, v := range representationDetails(ev.ResourceType, ev.Representation) {
		r.Details[key] = v
	}
	if ip, err := netip.ParseAddr(ev.AuthDetails.IPAddress); err == nil {
		r.ActorIP = ip.Unmap()
	}
	return r
}

// userRule classifies an admin event on users/{id}[/sub].
func userRule(op, sub string, n int) rule {
	switch {
	case n <= 2:
		return rule{action: "idp.user." + opVerb(op, "update"), resourceType: "idp.user", sensitive: op == "DELETE"}
	case sub == "reset-password":
		return rule{action: "idp.user.credential_reset", resourceType: "idp.user", sensitive: true, security: credential}
	case sub == "reset-password-email":
		return rule{action: "idp.user.credential_reset_email", resourceType: "idp.user", sensitive: true, security: credential}
	case sub == "credentials" || sub == "disable-credential-types":
		return rule{action: "idp.user.credential_remove", resourceType: "idp.user", sensitive: true, security: credential}
	case sub == "impersonation":
		return rule{action: "idp.user.impersonate", resourceType: "idp.user", sensitive: true,
			security: func(string, RealmKind, string) *Security { return sec(KindImpersonation, audit.SeverityCritical) }}
	case sub == "execute-actions-email":
		return rule{action: "idp.user.actions_email", resourceType: "idp.user"}
	case sub == "send-verify-email":
		return rule{action: "idp.user.verify_email", resourceType: "idp.user"}
	case sub == "logout":
		return rule{action: "idp.user.logout", resourceType: "idp.user"}
	case sub == "federated-identity":
		return rule{action: "idp.user.federated_identity_change", resourceType: "idp.user", sensitive: true}
	}
	return rule{action: "idp.user.change", resourceType: "idp.user", sensitive: true}
}

// opVerb maps CREATE/UPDATE/DELETE to create/update/delete, anything else to def.
func opVerb(op, def string) string {
	switch op {
	case "CREATE":
		return "create"
	case "UPDATE":
		return "update"
	case "DELETE":
		return "delete"
	}
	return def
}

// resourceID is the id the path names (users/<id>…, clients/<id>…): the second segment when it is an id or a plain
// name, else "".
func resourceID(segs []string) string {
	if len(segs) >= 2 && tokenRE.MatchString(segs[1]) {
		return segs[1]
	}
	return ""
}

// actorRealm says where the actor comes from: the event's own realm ("self") or another one (in practice master).
func actorRealm(ev keycloak.AdminEvent) string {
	if ev.AuthDetails.RealmID != "" && ev.AuthDetails.RealmID == ev.RealmID {
		return "self"
	}
	return "other"
}

func idOrEmpty(s string) string {
	if tokenRE.MatchString(s) {
		return s
	}
	return ""
}

// token keeps a short machine value (an event error code) and drops anything else.
func token(s string) string {
	if tokenRE.MatchString(s) {
		return s
	}
	return "other"
}

// clipPath keeps the resource path (ids and names only in Keycloak's paths) bounded.
func clipPath(p string) string {
	if len(p) > 200 {
		return p[:200]
	}
	return p
}

// maxRepresentation bounds the representation the job parses (a larger one is skipped, never stored).
const maxRepresentation = 256 << 10

// representationDetails extracts the allow-listed fields of an admin event's representation — the representation
// itself (which may hold a client secret or, for some operations, a credential) is never stored, logged or forwarded.
// Each resource type has its own allow-list of non-secret attributes; everything else is dropped.
func representationDetails(resourceType, rep string) audit.Details {
	out := audit.Details{}
	rep = strings.TrimSpace(rep)
	if rep == "" || len(rep) > maxRepresentation {
		return out
	}
	out["idp_representation"] = "redacted"
	switch resourceType {
	case "USER":
		var u struct {
			Username        string   `json:"username"`
			Enabled         *bool    `json:"enabled"`
			EmailVerified   *bool    `json:"emailVerified"`
			RequiredActions []string `json:"requiredActions"`
		}
		if json.Unmarshal([]byte(rep), &u) != nil {
			return out
		}
		if u.Username != "" && len(u.Username) <= 128 {
			out["username"] = u.Username
		}
		boolDetail(out, "user_enabled", u.Enabled)
		boolDetail(out, "email_verified", u.EmailVerified)
		if acts := tokens(u.RequiredActions); len(acts) > 0 {
			out["required_actions"] = acts
		}
	case "REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING", "REALM_ROLE", "CLIENT_ROLE":
		var roles []struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(rep), &roles) != nil {
			var one struct {
				Name string `json:"name"`
			}
			if json.Unmarshal([]byte(rep), &one) != nil || one.Name == "" {
				return out
			}
			roles = append(roles, one)
		}
		names := make([]string, 0, len(roles))
		for _, r := range roles {
			names = append(names, r.Name)
		}
		if n := tokens(names); len(n) > 0 {
			out["roles"] = n
		}
	case "GROUP_MEMBERSHIP", "GROUP":
		var g struct {
			Name string `json:"name"`
			Path string `json:"path"`
		}
		if json.Unmarshal([]byte(rep), &g) == nil {
			if v := g.Path; v != "" && len(v) <= 200 {
				out["group"] = v
			} else if v := g.Name; v != "" && len(v) <= 200 {
				out["group"] = v
			}
		}
	case "CLIENT":
		var c struct {
			ClientID                  string   `json:"clientId"`
			Enabled                   *bool    `json:"enabled"`
			PublicClient              *bool    `json:"publicClient"`
			StandardFlowEnabled       *bool    `json:"standardFlowEnabled"`
			ImplicitFlowEnabled       *bool    `json:"implicitFlowEnabled"`
			DirectAccessGrantsEnabled *bool    `json:"directAccessGrantsEnabled"`
			ServiceAccountsEnabled    *bool    `json:"serviceAccountsEnabled"`
			RedirectURIs              []string `json:"redirectUris"`
			WebOrigins                []string `json:"webOrigins"`
		}
		if json.Unmarshal([]byte(rep), &c) != nil {
			return out
		}
		if tokenRE.MatchString(c.ClientID) {
			out["client_id"] = c.ClientID
		}
		boolDetail(out, "client_enabled", c.Enabled)
		boolDetail(out, "public_client", c.PublicClient)
		boolDetail(out, "standard_flow", c.StandardFlowEnabled)
		boolDetail(out, "implicit_flow", c.ImplicitFlowEnabled)
		boolDetail(out, "direct_access_grants", c.DirectAccessGrantsEnabled)
		boolDetail(out, "service_accounts", c.ServiceAccountsEnabled)
		if c.RedirectURIs != nil {
			out["redirect_uri_count"] = len(c.RedirectURIs)
		}
		if c.WebOrigins != nil {
			out["web_origin_count"] = len(c.WebOrigins)
		}
	case "REALM":
		var rl struct {
			Enabled             *bool `json:"enabled"`
			RegistrationAllowed *bool `json:"registrationAllowed"`
			BruteForceProtected *bool `json:"bruteForceProtected"`
			EventsEnabled       *bool `json:"eventsEnabled"`
			AdminEventsEnabled  *bool `json:"adminEventsEnabled"`
		}
		if json.Unmarshal([]byte(rep), &rl) != nil {
			return out
		}
		boolDetail(out, "realm_enabled", rl.Enabled)
		boolDetail(out, "registration_allowed", rl.RegistrationAllowed)
		boolDetail(out, "brute_force_protected", rl.BruteForceProtected)
		boolDetail(out, "events_enabled", rl.EventsEnabled)
		boolDetail(out, "admin_events_enabled", rl.AdminEventsEnabled)
	}
	return out
}

func boolDetail(d audit.Details, key string, v *bool) {
	if v != nil {
		d[key] = *v
	}
}

// tokens keeps the short machine values of a list (role names, required actions), at most 16.
func tokens(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if tokenRE.MatchString(s) && len(out) < 16 {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Login event types read from the master realm (console and admin CLI sign-ins) and from the other realms
// (impersonation, which the feature switch disables at the server — P2-T05).
var (
	masterEventTypes = []string{"LOGIN", "LOGIN_ERROR", "CLIENT_LOGIN", "CLIENT_LOGIN_ERROR", "IMPERSONATE", "IMPERSONATE_ERROR"}
	realmEventTypes  = []string{"IMPERSONATE", "IMPERSONATE_ERROR"}
)

// classifyUser turns a login/user event into its record; ok is false for an event that is not imported (the
// provisioning identity's own client logins, every few minutes).
func classifyUser(ev keycloak.UserEvent, k RealmKind, provisionerClient string) (Record, bool) {
	r := Record{EventID: ev.ID, At: time.UnixMilli(ev.Time).UTC(), Outcome: audit.OutcomeSuccess, Client: token(ev.ClientID)}
	if ev.Error != "" || strings.HasSuffix(ev.Type, "_ERROR") {
		r.Outcome = audit.OutcomeFailure
	}
	if ip, err := netip.ParseAddr(ev.IPAddress); err == nil {
		r.ActorIP = ip.Unmap()
	}
	username := ev.Details["username"]
	if username != "" && len(username) <= 128 && !strings.ContainsAny(username, "\r\n") {
		r.Username = username
	}
	r.Details = audit.Details{"idp_event_id": ev.ID, "idp_event_type": token(ev.Type), "idp_client": r.Client,
		"idp_user_id": idOrEmpty(ev.UserID)}
	if r.Username != "" {
		r.Details["username"] = r.Username
	}
	for _, k := range []string{"auth_method", "grant_type", "auth_type"} {
		if v := ev.Details[k]; v != "" {
			r.Details[k] = token(v)
		}
	}
	if ev.Error != "" {
		r.Details["idp_error"] = token(ev.Error)
	}
	switch ev.Type {
	case "IMPERSONATE", "IMPERSONATE_ERROR":
		r.Action, r.ResourceType, r.ResourceID = "idp.user.impersonate", "idp.user", idOrEmpty(ev.UserID)
		r.UserSub = r.ResourceID
		r.Security = sec(KindImpersonation, audit.SeverityCritical)
		r.Notify = k == RealmTenant
		r.ActorKind, r.ActorDisplay = ActorAdmin, actorDisplay[ActorAdmin]
		for _, key := range []string{"impersonator", "impersonator_realm"} {
			if v := ev.Details[key]; v != "" {
				r.Details[key] = token(v)
			}
		}
		if r.UserSub != "" && !uuidRE.MatchString(r.UserSub) {
			r.UserSub = ""
		}
		return r, true
	case "LOGIN", "CLIENT_LOGIN", "LOGIN_ERROR", "CLIENT_LOGIN_ERROR":
		if k != RealmMaster {
			return Record{}, false
		}
		if ev.ClientID == provisionerClient && provisionerClient != "" && r.Outcome == audit.OutcomeSuccess {
			return Record{}, false // the driver's own token requests
		}
		r.Action, r.ResourceType, r.ResourceID = "idp.console.login", "idp.user", idOrEmpty(ev.UserID)
		r.ActorKind, r.ActorDisplay = ActorAdmin, "Keycloak administrator (master realm)"
		if r.Username != "" {
			r.ActorDisplay = "Keycloak master: " + r.Username
		}
		if r.Outcome == audit.OutcomeSuccess {
			r.Security = sec(KindConsoleLogin, audit.SeverityHigh)
			r.ConsoleLogin, r.Notify = true, true
		} else {
			r.Security = sec(KindConsoleLoginFailed, audit.SeverityMedium)
		}
		return r, true
	}
	return Record{}, false
}
