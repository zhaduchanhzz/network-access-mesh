package keycloak

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/idptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

func infraTemplate(t *testing.T, realm string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "..", "infrastructure", "idp", "realms")), realm+".json.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTemplateIsInfrastructureTemplate: the embedded template IS infrastructure/idp/realms/tenant-a.json.tmpl, byte
// for byte (single source: copy the file again after changing the infrastructure template).
func TestTemplateIsInfrastructureTemplate(t *testing.T) {
	if !bytes.Equal(realmTemplateJSON, infraTemplate(t, "tenant-a")) {
		t.Fatal("internal/idp/keycloak/realm.json.tmpl differs from infrastructure/idp/realms/tenant-a.json.tmpl — " +
			"copy the infrastructure template (cp infrastructure/idp/realms/tenant-a.json.tmpl internal/idp/keycloak/realm.json.tmpl)")
	}
}

var placeholder = regexp.MustCompile(`\$\{(MG_[A-Z0-9_]+)\}`)

// TestTemplateMatchesInfrastructure: with the per-realm values the driver sets, the driver's representation equals
// each of the three realms render_idp.py imports (platform, tenant-a, tenant-b) — every key, security settings
// included. Any divergence between the platform template and the driver's per-scope values fails here.
func TestTemplateMatchesInfrastructure(t *testing.T) {
	env := map[string]string{"MG_BASE_DOMAIN": "example.test",
		"MG_IDP_ID_PLATFORM": "01a1e611-32ef-7cf7-90a4-22d4f58bdccf", "MG_IDP_ID_TENANT_A": "01a1e611-32f2-783a-9d2b-dd0f666cdd8a",
		"MG_IDP_ID_TENANT_B": "01a1e611-32f5-708f-bd8a-0c45325ccc8a"}
	for realm, c := range map[string]struct {
		scope  idp.Scope
		idVar  string
		origin string
	}{
		"platform": {idp.ScopePlatform, "MG_IDP_ID_PLATFORM", "admin"},
		"tenant-a": {idp.ScopeTenant, "MG_IDP_ID_TENANT_A", "app"},
		"tenant-b": {idp.ScopeTenant, "MG_IDP_ID_TENANT_B", "app"},
	} {
		text := placeholder.ReplaceAllStringFunc(string(infraTemplate(t, realm)), func(m string) string {
			v, ok := env[placeholder.FindStringSubmatch(m)[1]]
			if !ok {
				t.Fatalf("%s: unknown placeholder %s", realm, m)
			}
			return v
		})
		var want map[string]any
		if err := decodeJSON([]byte(text), &want); err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(env[c.idVar])
		got, err := realmRep(realmParams{Realm: realm, Scope: c.scope, IdPID: id,
			RedirectURI: "https://" + c.origin + ".example.test/api/v1/auth/callback/" + id.String()})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: driver representation differs from the rendered infrastructure realm at %v", realm, diffPaths(got, want, ""))
		}
	}
}

func diffPaths(a, b any, at string) []string {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		var keys []string
		for k := range am {
			keys = append(keys, k)
		}
		for k := range bm {
			if _, ok := am[k]; !ok {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, diffPaths(am[k], bm[k], at+"."+k)...)
		}
		return out
	}
	if !reflect.DeepEqual(a, b) {
		return []string{at}
	}
	return nil
}

// TestTemplateSecuritySettings states the security-relevant settings of every realm the driver creates (§8.2, §8.3,
// P2-T05): independent of the comparison above, so a change made to both templates at once is caught too.
func TestTemplateSecuritySettings(t *testing.T) {
	id := uuid.New()
	for _, sc := range []idp.Scope{idp.ScopeTenant, idp.ScopePlatform} {
		redirect := "https://app.example.test/api/v1/auth/callback/" + id.String()
		rep, err := realmRep(realmParams{Realm: "t-x", Scope: sc, IdPID: id, RedirectURI: redirect})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(rep)
		if bytes.Contains(b, []byte(`"impersonation"`)) || bytes.Contains(b, []byte("${")) {
			t.Fatal("impersonation or a placeholder in the representation")
		}
		for k, v := range map[string]any{"sslRequired": "all", "registrationAllowed": false, "bruteForceProtected": true,
			"permanentLockout": false, "organizationsEnabled": false, "otpPolicyType": "totp", "otpPolicyCodeReusable": false,
			"browserFlow": "mg-browser", "eventsEnabled": true, "adminEventsEnabled": true, "resetPasswordAllowed": false} {
			if !sameJSON(v, rep[k]) {
				t.Errorf("%s: %s = %v, want %v", sc, k, rep[k], v)
			}
		}
		flow, err := flowExecutions(rep, "mg-browser")
		if err != nil {
			t.Fatal(err)
		}
		want := []execWant{{0, "auth-cookie", "ALTERNATIVE"}, {0, "mg-browser-forms", "ALTERNATIVE"},
			{1, "auth-username-password-form", "REQUIRED"}, {1, "auth-otp-form", "REQUIRED"}}
		if !reflect.DeepEqual(flow, want) {
			t.Errorf("%s: browser flow %v", sc, flow)
		}
		clients := clientsOf(rep)
		if !slices.Equal(clientIDs(rep), []string{"admin-cli", DriverClientID, PortalClientID}) {
			t.Errorf("clients %v", clientIDs(rep))
		}
		for cid, c := range clients {
			if c["implicitFlowEnabled"] != false || c["directAccessGrantsEnabled"] != false || c["secret"] != nil {
				t.Errorf("%s: implicit/direct grant or secret", cid)
			}
		}
		p := clients[PortalClientID]
		if !sameJSON(p["redirectUris"], []any{redirect}) || asMap(p["attributes"])["pkce.code.challenge.method"] != "S256" ||
			p["publicClient"] != false || p["serviceAccountsEnabled"] != false || p["standardFlowEnabled"] != true {
			t.Errorf("%s: portal client %v", sc, p)
		}
		if clients["admin-cli"]["enabled"] != false {
			t.Error("admin-cli enabled")
		}
		realmRoles, clientRoles := serviceAccountRoles(rep, DriverClientID)
		if len(realmRoles) != 0 || !sameSet(clientRoles[realmManagement], []string{"manage-users", "view-users", "query-users"}) ||
			len(clientRoles) != 1 {
			t.Errorf("driver service account roles %v %v", realmRoles, clientRoles)
		}
		_, scope := scopeMappingsOf(rep, DriverClientID)
		if !sameSet(scope[realmManagement], []string{"manage-users", "view-users", "query-users"}) {
			t.Errorf("driver scope %v", scope)
		}
		if !slices.Contains(stringList(clients[DriverClientID]["defaultClientScopes"]), "kc-admin-api") {
			t.Error("driver without kc-admin-api")
		}
	}
	if _, err := realmRep(realmParams{Realm: "x", Scope: "org", IdPID: id}); err == nil {
		t.Error("unknown scope accepted")
	}
}

func TestDriverRef(t *testing.T) {
	id := uuid.New()
	ref := DriverRef{Realm: "t-acme", DriverSecret: driverSecretRef(id).String()}
	r, sref, err := ParseDriverRef(ref.Encode())
	if err != nil || r != ref || sref.Name != "idp."+id.String()+".driver" || !sref.IsPlatform() {
		t.Fatalf("round trip: %+v %v %v", r, sref, err)
	}
	for _, bad := range []string{"", "{}", `{"realm":"master","driver_secret_ref":"mgsec://platform/a#1"}`,
		`{"realm":"T_A","driver_secret_ref":"mgsec://platform/a#1"}`, `{"realm":"t-a","driver_secret_ref":"x"}`,
		`{"realm":"t-a","driver_secret_ref":"mgsec://` + uuid.NewString() + `/a#1"}`,
		`{"realm":"t-a","driver_secret_ref":"mgsec://platform/a#1","extra":1}`} {
		if _, _, err := ParseDriverRef(bad); idp.CodeOf(err) != idp.CodeInvalidArgument {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestNormalizeEmailAndSameJSON(t *testing.T) {
	for in, want := range map[string]string{"Alice@Example.COM": "alice@example.com", " a@b.example ": "a@b.example",
		"Alice <a@b.example>": "", "no-at": "", "a@b.example\r\nBcc: x@y": ""} {
		if got := normalizeEmail(in); got != want {
			t.Errorf("normalizeEmail(%q) = %q", in, got)
		}
	}
	var a, b any
	_ = decodeJSON([]byte(`{"l":["x","y"],"n":30,"m":{"k":"v"}}`), &a)
	_ = decodeJSON([]byte(`{"l":["y","x"],"n":30.0,"m":{"k":"v"}}`), &b)
	if !sameJSON(a, b) {
		t.Error("sets and numbers must compare by value")
	}
	_ = decodeJSON([]byte(`{"l":["y"],"n":30,"m":{"k":"v"}}`), &b)
	if sameJSON(a, b) {
		t.Error("different sets compared equal")
	}
}

// TestCredentialsOnlyFromSecretStore: the configuration of the driver holds references only, and when the
// SecretStore cannot provide the credential the driver stops before any request — there is no other source.
func TestCredentialsOnlyFromSecretStore(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Config{}), reflect.TypeOf(Credentials{}), reflect.TypeOf(BootstrapConfig{})} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			name := strings.ToLower(f.Name)
			if (strings.Contains(name, "secret") || strings.Contains(name, "password") || strings.Contains(name, "token")) &&
				f.Type != reflect.TypeOf(secrets.Ref{}) && f.Type != reflect.TypeOf(Credentials{}) &&
				f.Type != reflect.TypeOf((*secrets.SecretStore)(nil)).Elem() {
				t.Errorf("%s.%s is %s: a credential must be a secrets.Ref", typ.Name(), f.Name, f.Type)
			}
		}
	}
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: "auth.example.test", Address: srv.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	st := idptest.NewSecrets()
	st.FailReads = true
	d, err := New(Config{Route: route, Secrets: st, AppHost: "app.example.test", AdminHost: "admin.example.test",
		Provisioner: Credentials{ClientID: DefaultProvisionerClientID, Secret: secrets.PlatformRef(ProvisionerRefName, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	reg := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: uuid.New()}
	_, err = d.EnsureIssuer(t.Context(), idp.IssuerSpec{Registration: reg, Realm: "t-acme"})
	if idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("EnsureIssuer without the provisioner secret: %v", err)
	}
	reg.DriverRef = DriverRef{Realm: "t-acme", DriverSecret: driverSecretRef(reg.IdPID).String()}.Encode()
	if _, err := d.DisableUser(t.Context(), reg, uuid.NewString()); idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("DisableUser without the service-account secret: %v", err)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d requests sent without a credential", n)
	}
	if !slices.Contains(st.Reads, "mgsec://platform/idp.keycloak.provisioner#1") {
		t.Fatalf("the provisioner secret was not read from the store: %v", st.Reads)
	}
	// configuration errors
	for _, bad := range []Config{{}, {Route: route, Secrets: st, AppHost: "app.example.test", AdminHost: "app.example.test",
		Provisioner: Credentials{ClientID: "p", Secret: secrets.PlatformRef("p", 1)}},
		{Route: route, Secrets: st, AppHost: "app.example.test", AdminHost: "admin.example.test",
			Provisioner: Credentials{ClientID: "p", Secret: secrets.TenantRef(uuid.New(), "p", 1)}}} {
		if _, err := New(bad); err == nil {
			t.Errorf("New(%+v) accepted", bad)
		}
	}
}

func TestSpecValidation(t *testing.T) {
	route, _ := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: "auth.example.test", Address: "127.0.0.1:1"})
	d, err := New(Config{Route: route, Secrets: idptest.NewSecrets(), AppHost: "app.example.test", AdminHost: "admin.example.test",
		Provisioner: Credentials{ClientID: DefaultProvisionerClientID, Secret: secrets.PlatformRef(ProvisionerRefName, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	ok := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: uuid.New()}
	for name, spec := range map[string]idp.IssuerSpec{
		"master realm":     {Registration: ok, Realm: "master"},
		"bad realm":        {Registration: ok, Realm: "Tenant_A"},
		"no realm":         {Registration: ok},
		"issuer elsewhere": {Registration: withIssuer(ok, "https://evil.example/realms/t-a"), Realm: "t-a"},
		"tenant w/o id":    {Registration: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant}, Realm: "t-a"},
	} {
		if _, err := d.EnsureIssuer(t.Context(), spec); idp.CodeOf(err) != idp.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if d.Issuer("t-a") != "https://auth.example.test/realms/t-a" {
		t.Fatalf("issuer %s", d.Issuer("t-a"))
	}
	if got := d.redirectURI(idp.Registration{IdPID: ok.IdPID, Scope: idp.ScopePlatform}); got !=
		"https://admin.example.test/api/v1/auth/callback/"+ok.IdPID.String() {
		t.Fatalf("platform redirect %s", got)
	}
	if _, err := d.InviteUser(t.Context(), withRef(ok), idp.Invite{Email: "not an email"}); idp.CodeOf(err) != idp.CodeInvalidArgument {
		t.Fatalf("bad e-mail: %v", err)
	}
	if _, err := d.InviteUser(t.Context(), withRef(ok), idp.Invite{Email: "a@example.test", Actions: []string{"delete_account"}}); idp.CodeOf(err) != idp.CodeInvalidArgument {
		t.Fatalf("unknown action: %v", err)
	}
	if _, err := d.DisableUser(t.Context(), withRef(ok), "../../users"); idp.CodeOf(err) != idp.CodeInvalidArgument {
		t.Fatalf("bad subject: %v", err)
	}
	if _, err := d.RemoveIssuer(t.Context(), withRef(ok), "erase"); idp.CodeOf(err) != idp.CodeInvalidArgument &&
		idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("bad mode: %v", err)
	}
}

func withIssuer(r idp.Registration, iss string) idp.Registration { r.Issuer = iss; return r }

func withRef(r idp.Registration) idp.Registration {
	r.DriverRef = DriverRef{Realm: "t-a", DriverSecret: driverSecretRef(r.IdPID).String()}.Encode()
	return r
}
