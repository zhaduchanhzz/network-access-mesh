package auditsync

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
)

const (
	realmID  = "2965b163-a88c-45c4-a36e-783bd6a94025"
	masterID = "863f7984-ff68-4a4f-93dc-a151bb2a1397"
	userID   = "2809355a-a2aa-4862-874b-26f46b5456ad"
	adminUID = "c90191fe-350b-4912-aa14-e95f87c2e6d8"
	provUID  = "4ece649d-8602-45da-9b32-356788887546"
	drvUUID  = "8369b9ce-3822-41f5-9aad-35b3b8db28f2"
	canary   = "mg-canary-secret-7f3a9c" //nolint:gosec // G101: a test canary, not a credential
)

var actors = Actors{ProvisionerUserID: provUID, DriverClientUUID: drvUUID}

func adminEvent(op, typ, path, rep string, by keycloak.AuthDetails) keycloak.AdminEvent {
	return keycloak.AdminEvent{ID: "ev-" + strings.ReplaceAll(path, "/", "-"), Time: 1794944457252, RealmID: realmID,
		AuthDetails: by, OperationType: op, ResourceType: typ, ResourcePath: path, Representation: rep}
}

var (
	byMaster   = keycloak.AuthDetails{RealmID: masterID, ClientID: "admin-cli-uuid", UserID: adminUID, IPAddress: "10.0.0.7"}
	byProv     = keycloak.AuthDetails{RealmID: masterID, ClientID: "prov-uuid", UserID: provUID, IPAddress: "10.249.0.4"}
	byDriver   = keycloak.AuthDetails{RealmID: realmID, ClientID: drvUUID, UserID: "sa-of-driver", IPAddress: "10.249.0.4"}
	byRealmUsr = keycloak.AuthDetails{RealmID: realmID, ClientID: "other-client", UserID: "u2", IPAddress: "198.51.100.4"}
)

// TestActorOf: who acted, from the authDetails of an admin event.
func TestActorOf(t *testing.T) {
	for _, c := range []struct {
		by   keycloak.AuthDetails
		kind RealmKind
		want string
	}{
		{byMaster, RealmTenant, ActorAdmin},
		{byProv, RealmTenant, ActorProvisioner},
		{byDriver, RealmTenant, ActorDriver},
		{byRealmUsr, RealmTenant, ActorRealmUser},
		{keycloak.AuthDetails{}, RealmTenant, ActorAdmin}, // nothing known ⇒ treated as an administrator (notified)
		{byRealmUsr, RealmMaster, ActorAdmin},
		{byProv, RealmMaster, ActorProvisioner},
	} {
		ev := adminEvent("UPDATE", "USER", "users/"+userID, "", c.by)
		if got := actors.ActorOf(ev, c.kind); got != c.want {
			t.Errorf("%+v in kind %d: %s, want %s", c.by, c.kind, got, c.want)
		}
	}
	// the driver's client id is unknown (realm the identity cannot list clients of): a user of the realm
	if got := (Actors{ProvisionerUserID: provUID}).ActorOf(adminEvent("UPDATE", "USER", "users/x", "", byDriver), RealmTenant); got != ActorRealmUser {
		t.Errorf("unknown driver: %s", got)
	}
}

// TestClassifyAdmin: every class of P3-T15 — action, the affected user, notification and security event.
func TestClassifyAdmin(t *testing.T) {
	cases := []struct {
		name               string
		ev                 keycloak.AdminEvent
		kind               RealmKind
		action, user       string
		notify             bool
		security, severity string
	}{
		{"credential reset by a Keycloak admin", adminEvent("ACTION", "USER", "users/"+userID+"/reset-password", "", byMaster),
			RealmTenant, "idp.user.credential_reset", userID, true, KindCredentialReset, audit.SeverityHigh},
		{"credential reset by the driver", adminEvent("ACTION", "USER", "users/"+userID+"/reset-password", "", byDriver),
			RealmTenant, "idp.user.credential_reset", userID, true, KindCredentialReset, audit.SeverityHigh},
		{"credential reset by a user of the realm", adminEvent("ACTION", "USER", "users/"+userID+"/reset-password", "", byRealmUsr),
			RealmTenant, "idp.user.credential_reset", userID, true, "", ""},
		{"credential removed", adminEvent("ACTION", "USER", "users/"+userID+"/credentials/c1", "", byMaster),
			RealmTenant, "idp.user.credential_remove", userID, true, KindCredentialReset, audit.SeverityHigh},
		{"reset e-mail", adminEvent("ACTION", "USER", "users/"+userID+"/reset-password-email", "", byMaster),
			RealmTenant, "idp.user.credential_reset_email", userID, true, KindCredentialReset, audit.SeverityHigh},
		{"impersonation", adminEvent("ACTION", "USER", "users/"+userID+"/impersonation", "", byMaster),
			RealmTenant, "idp.user.impersonate", userID, true, KindImpersonation, audit.SeverityCritical},
		{"user update by an admin", adminEvent("UPDATE", "USER", "users/"+userID, `{"username":"a"}`, byMaster),
			RealmTenant, "idp.user.update", userID, true, "", ""},
		{"user created by the driver (invitation)", adminEvent("CREATE", "USER", "users/"+userID, `{"username":"a"}`, byDriver),
			RealmTenant, "idp.user.create", userID, false, "", ""},
		{"user disabled by the driver (offboarding)", adminEvent("UPDATE", "USER", "users/"+userID, `{"enabled":false}`, byDriver),
			RealmTenant, "idp.user.update", userID, false, "", ""},
		{"logout by the driver", adminEvent("ACTION", "USER", "users/"+userID+"/logout", "", byDriver),
			RealmTenant, "idp.user.logout", userID, false, "", ""},
		{"user deleted by the driver", adminEvent("DELETE", "USER", "users/"+userID, "", byDriver),
			RealmTenant, "idp.user.delete", userID, true, "", ""},
		{"role granted", adminEvent("CREATE", "CLIENT_ROLE_MAPPING", "users/"+userID+"/role-mappings/clients/x", `[{"name":"manage-users"}]`, byMaster),
			RealmTenant, "idp.user.role_grant", userID, true, "", ""},
		{"role revoked by the provisioner", adminEvent("DELETE", "REALM_ROLE_MAPPING", "users/"+userID+"/role-mappings/realm", `[{"name":"x"}]`, byProv),
			RealmTenant, "idp.user.role_revoke", userID, true, "", ""},
		{"client update", adminEvent("UPDATE", "CLIENT", "clients/"+drvUUID, `{"clientId":"mg-portal","secret":"`+canary+`"}`, byProv),
			RealmTenant, "idp.client.update", "", true, "", ""},
		{"client secret rotated", adminEvent("ACTION", "CLIENT", "clients/"+drvUUID+"/client-secret", "", byMaster),
			RealmTenant, "idp.client.secret_rotate", "", true, "", ""},
		{"identity brokering added", adminEvent("CREATE", "IDENTITY_PROVIDER", "identity-provider/instances/evil", "", byMaster),
			RealmTenant, "idp.realm.identity_provider_change", "", true, KindIdentityProvider, audit.SeverityHigh},
		{"login flow changed", adminEvent("UPDATE", "AUTH_EXECUTION", "authentication/flows/mg-browser-forms/executions", "", byMaster),
			RealmTenant, "idp.realm.auth_change", "", true, KindAuthFlow, audit.SeverityMedium},
		{"realm update", adminEvent("UPDATE", "REALM", "", `{"eventsEnabled":false}`, byMaster),
			RealmTenant, "idp.realm.update", "", true, "", ""},
		{"unknown resource type", adminEvent("CREATE", "SOMETHING_NEW", "things/1", "", byMaster),
			RealmTenant, "idp.admin.change", "", true, "", ""},
		{"platform realm: credential reset", adminEvent("ACTION", "USER", "users/"+userID+"/reset-password", "", byMaster),
			RealmPlatform, "idp.user.credential_reset", userID, false, KindCredentialReset, audit.SeverityHigh},
		{"master: role granted to an admin", adminEvent("CREATE", "CLIENT_ROLE_MAPPING", "users/"+userID+"/role-mappings/clients/x", "[]", byMaster),
			RealmMaster, "idp.user.role_grant", userID, false, KindMasterPrivilege, audit.SeverityHigh},
		{"master: the provisioner's own role mapping", adminEvent("CREATE", "CLIENT_ROLE_MAPPING", "users/"+userID+"/role-mappings/clients/x", "[]", byProv),
			RealmMaster, "idp.user.role_grant", userID, false, "", ""},
		{"master: client created", adminEvent("CREATE", "CLIENT", "clients/"+drvUUID, `{"clientId":"rogue"}`, byMaster),
			RealmMaster, "idp.client.create", "", false, KindMasterClient, audit.SeverityMedium},
	}
	for _, c := range cases {
		r := classifyAdmin(c.ev, c.kind, actors.ActorOf(c.ev, c.kind))
		var kind, sev string
		if r.Security != nil {
			kind, sev = r.Security.Kind, r.Security.Severity
		}
		if r.Action != c.action || r.UserSub != c.user || r.Notify != c.notify || kind != c.security || sev != c.severity {
			t.Errorf("%s: action %s user %q notify %v security %s/%s; want %s %q %v %s/%s", c.name, r.Action, r.UserSub,
				r.Notify, kind, sev, c.action, c.user, c.notify, c.security, c.severity)
		}
		if r.EventID != c.ev.ID || r.At.UnixMilli() != c.ev.Time || r.Details["idp_event_id"] != c.ev.ID {
			t.Errorf("%s: event id/time not carried: %+v", c.name, r)
		}
	}
}

// TestRepresentationRedacted: the representation is never stored — only allow-listed, non-secret fields — whatever it
// holds (a client secret, a credential value, a token), and the audit encoding keeps it that way.
func TestRepresentationRedacted(t *testing.T) {
	reps := map[string]string{
		"CLIENT": `{"clientId":"mg-portal","secret":"` + canary + `","enabled":true,"redirectUris":["https://app.x/cb"],` +
			`"attributes":{"client.secret.creation.time":"1","x":"` + canary + `"},"protocolMappers":[{"config":{"s":"` + canary + `"}}]}`,
		"USER": `{"username":"alice","enabled":true,"credentials":[{"type":"password","value":"` + canary + `"}],` +
			`"attributes":{"note":"` + canary + `"},"requiredActions":["UPDATE_PASSWORD","CONFIGURE_TOTP"]}`,
		"REALM_ROLE_MAPPING": `[{"name":"offline_access","description":"` + canary + `"}]`,
		"REALM":              `{"enabled":true,"smtpServer":{"password":"` + canary + `"},"eventsEnabled":false}`,
		"GROUP_MEMBERSHIP":   `{"name":"g","path":"/g","attributes":{"k":["` + canary + `"]}}`,
		"IDENTITY_PROVIDER":  `{"alias":"evil","config":{"clientSecret":"` + canary + `"}}`,
		"COMPONENT":          `{"config":{"bindCredential":["` + canary + `"]}}`,
	}
	for typ, rep := range reps {
		ev := adminEvent("UPDATE", typ, "users/"+userID, rep, byMaster)
		r := classifyAdmin(ev, RealmTenant, ActorAdmin)
		raw, err := json.Marshal(r.Details)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), canary) {
			t.Errorf("%s: the representation leaked into the details: %s", typ, raw)
		}
		if r.Details["idp_representation"] != "redacted" {
			t.Errorf("%s: representation not marked redacted: %v", typ, r.Details)
		}
	}
	r := classifyAdmin(adminEvent("UPDATE", "CLIENT", "clients/x", reps["CLIENT"], byMaster), RealmTenant, ActorAdmin)
	if r.Details["client_id"] != "mg-portal" || r.Details["client_enabled"] != true || r.Details["redirect_uri_count"] != 1 {
		t.Errorf("client allow-list: %v", r.Details)
	}
	r = classifyAdmin(adminEvent("UPDATE", "USER", "users/"+userID, reps["USER"], byMaster), RealmTenant, ActorAdmin)
	if r.Details["username"] != "alice" || r.Details["user_enabled"] != true ||
		strings.Join(r.Details["required_actions"].([]string), ",") != "CONFIGURE_TOTP,UPDATE_PASSWORD" {
		t.Errorf("user allow-list: %v", r.Details)
	}
	// an oversized or malformed representation is dropped whole
	if d := representationDetails("CLIENT", "{"+strings.Repeat(" ", maxRepresentation)+"}"); len(d) != 0 {
		t.Errorf("oversized representation kept: %v", d)
	}
	if d := representationDetails("CLIENT", `{"secret":`); d["client_id"] != nil {
		t.Errorf("malformed representation: %v", d)
	}
}

// TestClassifyUser: login events — console sign-ins of the master realm (success ⇒ alert + notification, failure ⇒
// medium), impersonation everywhere, the provisioning identity's own logins skipped.
func TestClassifyUser(t *testing.T) {
	login := func(typ, client, errText string) keycloak.UserEvent {
		return keycloak.UserEvent{ID: "u-" + typ + "-" + client, Time: 1794944621332, Type: typ, RealmID: masterID,
			ClientID: client, UserID: adminUID, IPAddress: "10.230.0.1", Error: errText,
			Details: map[string]string{"username": "mg-bootstrap-admin", "auth_method": "openid-connect", "code_id": canary,
				"redirect_uri": "https://admin.x/admin/master/console/"}}
	}
	r, ok := classifyUser(login("LOGIN", "security-admin-console", ""), RealmMaster, "mg-provisioner")
	if !ok || r.Action != "idp.console.login" || r.Outcome != audit.OutcomeSuccess || !r.ConsoleLogin || !r.Notify ||
		r.Security == nil || r.Security.Kind != KindConsoleLogin || r.Security.Severity != audit.SeverityHigh ||
		r.Username != "mg-bootstrap-admin" || r.Client != "security-admin-console" || r.ActorIP.String() != "10.230.0.1" {
		t.Errorf("console login: %+v %v", r, ok)
	}
	if raw, _ := json.Marshal(r.Details); strings.Contains(string(raw), canary) || strings.Contains(string(raw), "redirect_uri") {
		t.Errorf("login details carry more than the allow-list: %s", raw)
	}
	r, ok = classifyUser(login("LOGIN_ERROR", "security-admin-console", "invalid_user_credentials"), RealmMaster, "mg-provisioner")
	if !ok || r.Outcome != audit.OutcomeFailure || r.Notify || r.Security == nil || r.Security.Kind != KindConsoleLoginFailed ||
		r.Security.Severity != audit.SeverityMedium || r.Details["idp_error"] != "invalid_user_credentials" {
		t.Errorf("failed console login: %+v", r)
	}
	if _, ok := classifyUser(login("CLIENT_LOGIN", "mg-provisioner", ""), RealmMaster, "mg-provisioner"); ok {
		t.Error("the provisioning identity's own client login is imported")
	}
	if r, ok := classifyUser(login("CLIENT_LOGIN_ERROR", "mg-provisioner", "invalid_client_credentials"), RealmMaster,
		"mg-provisioner"); !ok || r.Security.Kind != KindConsoleLoginFailed {
		t.Error("a failed login of the provisioning identity (someone trying its secret) is not imported")
	}
	if r, ok := classifyUser(login("CLIENT_LOGIN", "rogue-client", ""), RealmMaster, "mg-provisioner"); !ok || !r.ConsoleLogin {
		t.Error("a client login of another master client is not an alert")
	}
	if _, ok := classifyUser(login("LOGIN", "mg-portal", ""), RealmTenant, "mg-provisioner"); ok {
		t.Error("an ordinary login of a tenant realm is imported")
	}
	imp := keycloak.UserEvent{ID: "imp", Time: 1, Type: "IMPERSONATE", RealmID: realmID, UserID: userID,
		Details: map[string]string{"impersonator": "admin", "impersonator_realm": "master"}}
	r, ok = classifyUser(imp, RealmTenant, "mg-provisioner")
	if !ok || r.Action != "idp.user.impersonate" || r.Security.Severity != audit.SeverityCritical || !r.Notify ||
		r.UserSub != userID || r.Details["impersonator"] != "admin" {
		t.Errorf("impersonation: %+v", r)
	}
}

// TestCursor: (time, ids at that millisecond) — events before the cursor or already imported at its millisecond are
// done; the cursor only moves forward.
func TestCursor(t *testing.T) {
	var c Cursor
	c.Advance("a", 100)
	c.Advance("b", 100)
	c.Advance("c", 101)
	if c.TimeMs != 101 || len(c.IDs) != 1 || c.IDs[0] != "c" {
		t.Fatalf("cursor %+v", c)
	}
	c.Advance("d", 101)
	c.Advance("z", 50) // older: ignored
	for _, x := range []struct {
		id   string
		ms   int64
		done bool
	}{{"a", 100, true}, {"x", 100, true}, {"c", 101, true}, {"d", 101, true}, {"e", 101, false}, {"f", 102, false}} {
		if got := c.Done(x.id, x.ms); got != x.done {
			t.Errorf("Done(%s, %d) = %v", x.id, x.ms, got)
		}
	}
	if k := CursorKey("admin", "tenant-a"); k != "idp.audit_sync.admin.tenant_a" {
		t.Errorf("key %s", k)
	}
}
