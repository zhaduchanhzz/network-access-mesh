package keycloak_test

// Integration with a real Keycloak (the IdP of P2-T05, built from infrastructure/docker/idp and started by
// tests/idp/run_dev.sh) and a real SecretStore on PostgreSQL (internal/secrets on the storetest harness). Gated like
// the other integration tests of the repository:
//
//	MG_TEST_KEYCLOAK_URL         https://auth.<domain> (public base URL of the IdP); unset ⇒ skipped
//	MG_TEST_KEYCLOAK_REQUIRED=1  unset URL fails instead of skipping
//	MG_TEST_KEYCLOAK_CONNECT     host:port dialled for that host (optional — default: the name through the resolver,
//	                             i.e. the proxy's alias auth.<domain> on the edge network, like the edge alias on mg-edge)
//	MG_TEST_KEYCLOAK_CAFILE      CA certificate of the test proxy
//	MG_TEST_KEYCLOAK_ADMIN_CONF  keycloak.conf of the stack: the break-glass admin, put into the SecretStore for
//	                             Bootstrap and used by the test itself only to inspect Keycloak and inject drift
//	MG_TEST_KEYCLOAK_IDP_ID      MG_IDP_ID_TENANT_A — identity_providers.id the imported realm tenant-a was rendered with
//	MG_TEST_PG_ADMIN_URL         PostgreSQL of the SecretStore (storetest)
//
// The driver itself only ever reads credentials from the SecretStore: the provisioning identity (created by Bootstrap)
// and the per-realm service accounts.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/external"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

type kcEnv struct {
	base, host, domain string
	pool               *x509.CertPool
	route              *idp.PlatformRoute
	st                 *secrets.Store
	apiStore           *secrets.Store // the api's view: mg_api_* roles, kek-app only
	tenantID           uuid.UUID
	conf               map[string]string
	adminRef           secrets.Ref
	boot               keycloak.BootstrapResult
	drv                *keycloak.Driver
	adminToken         string
}

func writeKeyring(t *testing.T, name string) *secrets.Keyring {
	t.Helper()
	dir := t.TempDir()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := "test-" + hex.EncodeToString(b[:4])
	if err := os.WriteFile(filepath.Join(dir, id), []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, secrets.ActiveFile), []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := secrets.LoadKeyring(name, dir)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func readConf(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test configuration
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && !strings.HasPrefix(strings.TrimSpace(k), "#") {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func setup(t *testing.T) *kcEnv {
	t.Helper()
	raw := os.Getenv("MG_TEST_KEYCLOAK_URL")
	if raw == "" {
		if os.Getenv("MG_TEST_KEYCLOAK_REQUIRED") == "1" {
			t.Fatal("MG_TEST_KEYCLOAK_URL is not set but MG_TEST_KEYCLOAK_REQUIRED=1")
		}
		t.Skip("MG_TEST_KEYCLOAK_URL not set — Keycloak integration skipped (tests/idp/run_dev.sh)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.HasPrefix(u.Hostname(), "auth.") {
		t.Fatalf("MG_TEST_KEYCLOAK_URL %q", raw)
	}
	e := &kcEnv{base: "https://" + u.Hostname(), host: u.Hostname(), domain: strings.TrimPrefix(u.Hostname(), "auth.")}
	pem, err := os.ReadFile(os.Getenv("MG_TEST_KEYCLOAK_CAFILE")) //nolint:gosec // path given by the test operator
	if err != nil {
		t.Fatal(err)
	}
	e.pool = x509.NewCertPool()
	if !e.pool.AppendCertsFromPEM(pem) {
		t.Fatal("no CA certificate")
	}
	e.route, err = idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: e.host, Address: os.Getenv("MG_TEST_KEYCLOAK_CONNECT"),
		RootCAs: e.pool, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	app, ops := writeKeyring(t, secrets.KEKApp), writeKeyring(t, secrets.KEKOps)
	e.st, err = secrets.New(pg.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 4), secrets.Options{App: app, Ops: ops})
	if err != nil {
		t.Fatal(err)
	}
	e.apiStore, err = secrets.New(pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 2), secrets.Options{App: app})
	if err != nil {
		t.Fatal(err)
	}
	e.tenantID = uuid.New()
	pg.Exec(t, db, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, 'P2-T05a', 'active')`, e.tenantID,
		"p2t05a-"+e.tenantID.String()[:8])
	e.conf = readConf(t, os.Getenv("MG_TEST_KEYCLOAK_ADMIN_CONF"))
	// the operator's step: the break-glass admin password goes into the SecretStore (platform_ops), from a file — never
	// from the environment or an argument
	e.adminRef = secrets.PlatformRef(keycloak.BootstrapAdminRefName, 1)
	if err := e.st.Put(t.Context(), e.adminRef, []byte(e.conf["bootstrap-admin-password"]), secrets.WithPlatformOps()); err != nil {
		t.Fatal(err)
	}
	e.adminToken = e.passwordToken(t)
	return e
}

func (e *kcEnv) passwordToken(t *testing.T) string {
	t.Helper()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	st := e.form(t, "/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"},
		"client_id": {"admin-cli"}, "username": {e.conf["bootstrap-admin-username"]}, "password": {e.conf["bootstrap-admin-password"]}}, &tok)
	if st != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("admin token: HTTP %d", st)
	}
	return tok.AccessToken
}

func (e *kcEnv) form(t *testing.T, p string, v url.Values, out any) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, e.base+p, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.route.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", p, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil && resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

// api calls the Admin REST API with token (the break-glass admin for inspection/drift, or a service account under
// test) and returns the status.
func (e *kcEnv) api(t *testing.T, token, method, p string, in, out any) int {
	t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, e.base+p, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.route.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, p, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("%s %s: %v", method, p, err)
		}
	}
	return resp.StatusCode
}

func (e *kcEnv) admin(t *testing.T, method, p string, in, out any) int {
	t.Helper()
	return e.api(t, e.adminToken, method, p, in, out)
}

// clientToken: a client-credentials token with a secret read from the SecretStore (as the driver does).
func (e *kcEnv) clientToken(t *testing.T, realm, clientID string, ref secrets.Ref) (string, int) {
	t.Helper()
	p, err := e.st.Get(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	st := e.form(t, "/realms/"+realm+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {clientID}, "client_secret": {string(p.Bytes())}}, &tok)
	return tok.AccessToken, st
}

func (e *kcEnv) client(t *testing.T, realm, clientID string) map[string]any {
	t.Helper()
	var list []map[string]any
	if st := e.admin(t, http.MethodGet, "/admin/realms/"+realm+"/clients?clientId="+clientID, nil, &list); st != 200 {
		t.Fatalf("clients of %s: HTTP %d", realm, st)
	}
	if len(list) != 1 {
		t.Fatalf("%s/%s: %d clients", realm, clientID, len(list))
	}
	return list[0]
}

func names(list []map[string]any) []string {
	var out []string
	for _, m := range list {
		out = append(out, m["name"].(string))
	}
	sort.Strings(out)
	return out
}

func (e *kcEnv) saRoles(t *testing.T, realm, clientID string) ([]string, map[string][]string) {
	t.Helper()
	c := e.client(t, realm, clientID)
	var sa map[string]any
	e.admin(t, http.MethodGet, "/admin/realms/"+realm+"/clients/"+c["id"].(string)+"/service-account-user", nil, &sa)
	var m struct {
		RealmMappings  []map[string]any `json:"realmMappings"`
		ClientMappings map[string]struct {
			Mappings []map[string]any `json:"mappings"`
		} `json:"clientMappings"`
	}
	e.admin(t, http.MethodGet, "/admin/realms/"+realm+"/users/"+sa["id"].(string)+"/role-mappings", nil, &m)
	cl := map[string][]string{}
	for k, v := range m.ClientMappings {
		cl[k] = names(v.Mappings)
	}
	return names(m.RealmMappings), cl
}

func mustCode(t *testing.T, what string, err error, code idp.Code) {
	t.Helper()
	if idp.CodeOf(err) != code {
		t.Fatalf("%s: %v, want %s", what, err, code)
	}
}

func randomRealm() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "p2t05a-" + hex.EncodeToString(b)
}

// TestKeycloakDriver runs the acceptance of P2-T05a against the real IdP, in order: least-privilege bootstrap,
// idempotent realm creation, client, discovery (+ T-21 refusals in the real network), invitation/offboarding,
// isolation between realms, impersonation refused, drift repair, adoption of an imported realm, idempotent disable
// and purge, credentials only from the SecretStore.
func TestKeycloakDriver(t *testing.T) {
	e := setup(t)
	ctx := t.Context()
	realmX, realmY := randomRealm(), randomRealm()
	regX := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: e.tenantID, Driver: idp.DriverKeycloak}
	regY := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: e.tenantID, Driver: idp.DriverKeycloak}
	t.Cleanup(func() { // leave no test realm behind, whatever happened
		for _, r := range []string{realmX, realmY} {
			e.admin(t, http.MethodDelete, "/admin/realms/"+r, nil, nil)
		}
	})

	t.Run("bootstrap: provisioning identity with create-realm only", func(t *testing.T) {
		var err error
		e.boot, err = keycloak.Bootstrap(ctx, e.route, e.st, keycloak.BootstrapConfig{AdminUsername: e.conf["bootstrap-admin-username"],
			AdminPassword: e.adminRef, AdoptRealms: []string{"tenant-a"}, AuditRealms: []string{"platform"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("bootstrap: created=%v rotated=%v adopted=%v audited=%v changes=%d secret=%s", e.boot.Created,
			e.boot.Rotated, e.boot.Adopted, e.boot.Audited, len(e.boot.Changes), e.boot.Provisioner.Secret)
		realmRoles, clientRoles := e.saRoles(t, "master", e.boot.Provisioner.ClientID)
		if !slices.Equal(realmRoles, []string{"create-realm"}) {
			t.Fatalf("master realm roles of the provisioning identity: %v", realmRoles)
		}
		for c, roles := range clientRoles {
			if !strings.HasSuffix(c, "-realm") || slices.Contains(roles, "impersonation") {
				t.Fatalf("client roles of the provisioning identity: %s %v", c, roles)
			}
		}
		// P3-T15: exactly view-events of master-realm (console logins) and of the audited platform realm
		for _, c := range []string{"master-realm", "platform-realm"} {
			if !slices.Equal(clientRoles[c], []string{keycloak.ViewEventsRole}) {
				t.Fatalf("%s roles of the provisioning identity: %v (want exactly view-events)", c, clientRoles[c])
			}
		}
		if !slices.Contains(clientRoles["tenant-a-realm"], "manage-realm") {
			t.Fatalf("tenant-a not adopted: %v", clientRoles)
		}
		c := e.client(t, "master", e.boot.Provisioner.ClientID)
		var scopes []map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/master/clients/"+c["id"].(string)+"/default-client-scopes", nil, &scopes)
		if !slices.Equal(names(scopes), []string{"basic", "kc-admin-api"}) || c["directAccessGrantsEnabled"] != false ||
			c["standardFlowEnabled"] != false {
			t.Fatalf("provisioner client: scopes %v", names(scopes))
		}
		// the credential is platform_ops: the api (mg_api_* roles, kek-app only) cannot read it
		if _, err := e.apiStore.Get(ctx, e.boot.Provisioner.Secret); err == nil {
			t.Fatal("the api can read the provisioning identity's secret")
		}
		// again — the platform realm stays audit-only even when it is not named any more (never promoted to managed)
		again, err := keycloak.Bootstrap(ctx, e.route, e.st, keycloak.BootstrapConfig{AdminUsername: e.conf["bootstrap-admin-username"],
			AdminPassword: e.adminRef, Provisioner: e.boot.Provisioner, AdoptRealms: []string{"tenant-a"}})
		if err != nil || again.Created || again.Rotated || len(again.Changes) != 0 || again.Provisioner != e.boot.Provisioner {
			t.Fatalf("bootstrap again: %+v, %v", again, err)
		}
		e.drv, err = keycloak.New(keycloak.Config{Route: e.route, Secrets: e.st, Provisioner: e.boot.Provisioner,
			AppHost: "app." + e.domain, AdminHost: "admin." + e.domain})
		if err != nil {
			t.Fatal(err)
		}
	})
	if e.drv == nil {
		t.FailNow()
	}

	t.Run("create realm, then idempotent", func(t *testing.T) {
		res, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regX, Realm: realmX})
		if err != nil || !res.Created || res.Issuer != e.base+"/realms/"+realmX {
			t.Fatalf("create: %+v, %v", res, err)
		}
		regX.Issuer, regX.DriverRef = res.Issuer, res.DriverRef
		for i := range 2 {
			again, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regX})
			if err != nil || again.Created || len(again.Changes) != 0 || len(again.Unmanaged) != 0 || again.DriverRef != regX.DriverRef {
				t.Fatalf("ensure #%d: %+v, %v", i+2, again, err)
			}
		}
		var realms []map[string]any
		e.admin(t, http.MethodGet, "/admin/realms", nil, &realms)
		n := 0
		for _, r := range realms {
			if r["realm"] == realmX {
				n++
			}
		}
		var clients []map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/clients", nil, &clients)
		var ids []string
		for _, c := range clients {
			ids = append(ids, c["clientId"].(string))
		}
		sort.Strings(ids)
		if n != 1 || !slices.Equal(ids, []string{"account", "account-console", "admin-cli", "broker", "mg-idp-driver",
			"mg-portal", "realm-management", "security-admin-console"}) {
			t.Fatalf("realms named %s: %d; clients %v", realmX, n, ids)
		}
		realmRoles, clientRoles := e.saRoles(t, realmX, keycloak.DriverClientID)
		if len(realmRoles) != 0 || len(clientRoles) != 1 ||
			!slices.Equal(clientRoles["realm-management"], []string{"manage-users", "query-users", "view-users"}) {
			t.Fatalf("service account roles: %v %v", realmRoles, clientRoles)
		}
		var rep map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX, nil, &rep)
		if rep["bruteForceProtected"] != true || rep["sslRequired"] != "all" || rep["registrationAllowed"] != false ||
			rep["browserFlow"] != "mg-browser" || rep["attributes"].(map[string]any)["meshguard.idp_id"] != regX.IdPID.String() {
			t.Fatalf("realm settings: %v", rep)
		}
		_, sref, _ := keycloak.ParseDriverRef(regX.DriverRef)
		if _, err := e.apiStore.Get(ctx, sref); err == nil {
			t.Fatal("the api can read the service-account secret")
		}
	})

	t.Run("portal client, idempotent", func(t *testing.T) {
		res, err := e.drv.EnsureClient(ctx, idp.ClientSpec{Registration: regX})
		if err != nil || res.ClientID != keycloak.PortalClientID || !res.SecretRotated || res.ClientSecretRef == "" {
			t.Fatalf("first: %+v, %v", res, err)
		}
		t.Logf("first EnsureClient: changes %v; live webOrigins %#v", res.Changes, e.client(t, realmX, keycloak.PortalClientID)["webOrigins"])
		regX.ClientID, regX.ClientSecretRef = res.ClientID, res.ClientSecretRef
		again, err := e.drv.EnsureClient(ctx, idp.ClientSpec{Registration: regX})
		if err != nil || again.SecretRotated || len(again.Changes) != 0 || again.ClientSecretRef != regX.ClientSecretRef {
			t.Fatalf("again: %+v, %v", again, err)
		}
		c := e.client(t, realmX, keycloak.PortalClientID)
		var cred struct {
			Value string `json:"value"`
		}
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/clients/"+c["id"].(string)+"/client-secret", nil, &cred)
		ref, _ := secrets.ParseRef(regX.ClientSecretRef)
		stored, err := e.apiStore.Get(ctx, ref) // the api reads the Portal secret (tenant DEK, kek-app)
		if err != nil || string(stored.Bytes()) != cred.Value || ref.Tenant != e.tenantID {
			t.Fatalf("stored Portal secret: %v (tenant %s)", err, ref.Tenant)
		}
		want := "https://app." + e.domain + "/api/v1/auth/callback/" + regX.IdPID.String()
		if !slices.Equal(toStrings(c["redirectUris"]), []string{want}) || c["implicitFlowEnabled"] != false ||
			c["directAccessGrantsEnabled"] != false || c["attributes"].(map[string]any)["pkce.code.challenge.method"] != "S256" {
			t.Fatalf("portal client: %v", c)
		}
	})

	t.Run("discovery through the platform route; T-21 refusals in the real network", func(t *testing.T) {
		d, err := e.drv.CheckDiscovery(ctx, regX)
		if err != nil || d.Issuer != regX.Issuer || d.SigningKeys < 1 {
			t.Fatalf("CheckDiscovery: %+v, %v", d, err)
		}
		// the same issuer through the hardened client: auth.<domain> resolves to the proxy's private address on the
		// edge network (like the edge alias on mg-edge) — refused, nothing fetched
		h, err := idp.NewHardened(idp.HardenedConfig{RootCAs: e.pool})
		if err != nil {
			t.Fatal(err)
		}
		_, err = idp.FetchDiscovery(ctx, h.Client(), regX.Issuer, func(_ context.Context, u *url.URL, _ idp.EndpointKind) error {
			return h.CheckURL(u)
		})
		mustCode(t, "hardened client → platform IdP", err, idp.CodeDestinationRefused)
		t.Logf("hardened client on %s: %v", regX.Issuer, err)
		// the external driver (tenant-supplied issuer) can never reach the platform IdP — not even its public name
		h2, _ := idp.NewHardened(idp.HardenedConfig{RootCAs: e.pool, DenyDomains: []string{e.domain}})
		ext, _ := external.New(external.Config{Client: h2, Secrets: e.st})
		reg := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: e.tenantID, Issuer: regX.Issuer}
		_, err = ext.EnsureIssuer(ctx, idp.IssuerSpec{Registration: reg})
		mustCode(t, "external driver → platform IdP", err, idp.CodeDestinationRefused)
		// the Relying Party's single client: OIDC endpoints through the route, the Admin API refused
		ic := idp.NewIssuerClient(h2, e.route)
		if st, err := getStatus(ctx, ic, regX.Issuer+"/.well-known/openid-configuration"); err != nil || st != 200 {
			t.Fatalf("issuer client discovery: HTTP %d, %v", st, err)
		}
		_, err = getStatus(ctx, ic, e.base+"/admin/realms/"+realmX+"/users")
		mustCode(t, "issuer client → admin API", err, idp.CodeDestinationRefused)
	})

	var alice string
	t.Run("invite and disable users with the realm's own service account", func(t *testing.T) {
		email := "alice-" + realmX + "@" + e.domain
		res, err := e.drv.InviteUser(ctx, regX, idp.Invite{Email: strings.ToUpper(email), FirstName: "Alice", LastName: "Test"})
		if err != nil || !res.Created || res.EmailSent {
			t.Fatalf("invite: %+v, %v", res, err)
		}
		alice = res.Subject
		again, err := e.drv.InviteUser(ctx, regX, idp.Invite{Email: email})
		if err != nil || again.Created || again.Subject != alice {
			t.Fatalf("invite again: %+v, %v", again, err)
		}
		var users []map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/users?email="+url.QueryEscape(email)+"&exact=true", nil, &users)
		if len(users) != 1 || !sameSet(toStrings(users[0]["requiredActions"]), keycloak.DefaultInviteActions) {
			t.Fatalf("users: %v", users)
		}
		// no SMTP on the test IdP: the e-mail fails with a stable code, the user is still there
		_, err = e.drv.InviteUser(ctx, regX, idp.Invite{Email: email, SendEmail: true})
		t.Logf("invite with e-mail, no SMTP at the IdP: %v", err)
		mustCode(t, "e-mail without SMTP", err, idp.CodeEmailFailed)
		d, err := e.drv.DisableUser(ctx, regX, alice)
		if err != nil || !d.Found || d.AlreadyDisabled || !d.SessionsRevoked {
			t.Fatalf("disable: %+v, %v", d, err)
		}
		d, err = e.drv.DisableUser(ctx, regX, alice)
		if err != nil || !d.AlreadyDisabled {
			t.Fatalf("disable again: %+v, %v", d, err)
		}
		var u map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/users/"+alice, nil, &u)
		if u["enabled"] != false {
			t.Fatal("user still enabled")
		}
		_, err = e.drv.InviteUser(ctx, regX, idp.Invite{Email: email})
		mustCode(t, "re-invite a disabled user", err, idp.CodeConflict)
		d, err = e.drv.DisableUser(ctx, regX, uuid.NewString())
		if err != nil || d.Found {
			t.Fatalf("unknown subject: %+v, %v", d, err)
		}
	})

	t.Run("a realm's service account cannot operate on another realm", func(t *testing.T) {
		res, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regY, Realm: realmY})
		if err != nil || !res.Created {
			t.Fatalf("realm Y: %+v, %v", res, err)
		}
		regY.Issuer, regY.DriverRef = res.Issuer, res.DriverRef
		_, srefX, _ := keycloak.ParseDriverRef(regX.DriverRef)
		tokX, st := e.clientToken(t, realmX, keycloak.DriverClientID, srefX)
		if st != 200 {
			t.Fatalf("token of X: HTTP %d", st)
		}
		user := map[string]any{"username": "evil-" + realmX, "enabled": true}
		for _, c := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, "/admin/realms/" + realmY + "/users", nil},
			{http.MethodPost, "/admin/realms/" + realmY + "/users", user},
			{http.MethodGet, "/admin/realms/" + realmY, nil},
			{http.MethodPut, "/admin/realms/" + realmY, map[string]any{"bruteForceProtected": false}},
			{http.MethodDelete, "/admin/realms/" + realmY, nil},
			{http.MethodGet, "/admin/realms/master/users", nil},
			{http.MethodGet, "/admin/realms/tenant-a/users", nil},
			{http.MethodPost, "/admin/realms", map[string]any{"realm": "p2t05a-evil", "enabled": true}},
			{http.MethodGet, "/admin/realms/" + realmX + "/clients", nil},
			{http.MethodPut, "/admin/realms/" + realmX, map[string]any{"bruteForceProtected": false}},
			{http.MethodPost, "/admin/realms/" + realmX + "/clients", map[string]any{"clientId": "evil", "directAccessGrantsEnabled": true}},
		} {
			st := e.api(t, tokX, c.method, c.path, c.body, nil)
			t.Logf("service account of X: %s %s → HTTP %d", c.method, strings.ReplaceAll(strings.ReplaceAll(c.path, realmX, "X"), realmY, "Y"), st)
			if st != http.StatusForbidden && st != http.StatusUnauthorized {
				t.Fatalf("service account of %s: %s %s → HTTP %d", realmX, c.method, c.path, st)
			}
		}
		var repY, repX map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmY, nil, &repY)
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX, nil, &repX)
		if repY["bruteForceProtected"] != true || repX["bruteForceProtected"] != true {
			t.Fatal("a refused call changed a realm")
		}
		// its own realm: users only
		if st := e.api(t, tokX, http.MethodGet, "/admin/realms/"+realmX+"/users", nil, nil); st != 200 {
			t.Fatalf("own users: HTTP %d", st)
		}
		// the driver with X's credential pointed at Y's realm is refused by the IdP
		cross := regY
		cross.DriverRef = keycloak.DriverRef{Realm: realmY, DriverSecret: srefX.String()}.Encode()
		_, err = e.drv.InviteUser(ctx, cross, idp.Invite{Email: "mallory@" + e.domain})
		mustCode(t, "X's secret on Y", err, idp.CodeUnauthenticated)
	})

	t.Run("impersonation is refused", func(t *testing.T) {
		_, srefX, _ := keycloak.ParseDriverRef(regX.DriverRef)
		tokX, _ := e.clientToken(t, realmX, keycloak.DriverClientID, srefX)
		tokP, st := e.clientToken(t, "master", e.boot.Provisioner.ClientID, e.boot.Provisioner.Secret)
		if st != 200 {
			t.Fatalf("provisioner token: HTTP %d", st)
		}
		for who, tok := range map[string]string{"service account": tokX, "provisioning identity": tokP, "break-glass admin": e.adminToken} {
			st := e.api(t, tok, http.MethodPost, "/admin/realms/"+realmX+"/users/"+alice+"/impersonation", map[string]any{}, nil)
			t.Logf("impersonation by the %s: HTTP %d", who, st)
			if st < 400 {
				t.Fatalf("impersonation by the %s: HTTP %d", who, st)
			}
		}
	})

	t.Run("drift is repaired", func(t *testing.T) {
		var rep map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX, nil, &rep)
		e.admin(t, http.MethodPut, "/admin/realms/"+realmX, map[string]any{"bruteForceProtected": false,
			"passwordPolicy": "length(4)", "registrationAllowed": true, "ssoSessionMaxLifespan": 864000}, nil)
		var execs []map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/authentication/flows/mg-browser/executions", nil, &execs)
		for _, x := range execs {
			if x["providerId"] == "auth-otp-form" {
				x["requirement"] = "DISABLED"
				e.admin(t, http.MethodPut, "/admin/realms/"+realmX+"/authentication/flows/mg-browser/executions", x, nil)
			}
		}
		var ra map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/authentication/required-actions/CONFIGURE_TOTP", nil, &ra)
		ra["defaultAction"] = false
		e.admin(t, http.MethodPut, "/admin/realms/"+realmX+"/authentication/required-actions/CONFIGURE_TOTP", ra, nil)
		cli := e.client(t, realmX, "admin-cli")
		cli["enabled"], cli["directAccessGrantsEnabled"] = true, true
		e.admin(t, http.MethodPut, "/admin/realms/"+realmX+"/clients/"+cli["id"].(string), cli, nil)
		// a broader role for the service account
		rm := e.client(t, realmX, "realm-management")
		var role map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/clients/"+rm["id"].(string)+"/roles/manage-clients", nil, &role)
		drv := e.client(t, realmX, keycloak.DriverClientID)
		var sa map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/clients/"+drv["id"].(string)+"/service-account-user", nil, &sa)
		saMappings := "/admin/realms/" + realmX + "/users/" + sa["id"].(string) + "/role-mappings/clients/" + rm["id"].(string)
		e.admin(t, http.MethodPost, saMappings, []any{role}, nil)
		// a client nobody declared
		e.admin(t, http.MethodPost, "/admin/realms/"+realmX+"/clients", map[string]any{"clientId": "rogue-client",
			"publicClient": true, "directAccessGrantsEnabled": true}, nil)
		// the Portal client opened to the implicit flow
		portal := e.client(t, realmX, keycloak.PortalClientID)
		portal["implicitFlowEnabled"] = true
		portal["redirectUris"] = []any{"https://evil.example/*"}
		e.admin(t, http.MethodPut, "/admin/realms/"+realmX+"/clients/"+portal["id"].(string), portal, nil)
		// the driver's secret regenerated behind its back
		e.admin(t, http.MethodPost, "/admin/realms/"+realmX+"/clients/"+drv["id"].(string)+"/client-secret", nil, nil)

		res, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regX})
		if err != nil {
			t.Fatalf("repair: %+v, %v", res, err)
		}
		t.Logf("repaired: %v; unmanaged: %v", res.Changes, res.Unmanaged)
		for _, want := range []string{"realm.bruteForceProtected", "realm.passwordPolicy", "realm.registrationAllowed",
			"realm.ssoSessionMaxLifespan", "flow.mg-browser.auth-otp-form.requirement", "requiredAction.CONFIGURE_TOTP",
			"client.admin-cli.enabled", "client.admin-cli.directAccessGrantsEnabled",
			"serviceaccount.mg-idp-driver.realm-management.-manage-clients", "client.mg-idp-driver.secret"} {
			if !slices.Contains(res.Changes, want) {
				t.Errorf("change %q not reported", want)
			}
		}
		if !slices.Equal(res.Unmanaged, []string{"client.rogue-client"}) {
			t.Errorf("unmanaged %v", res.Unmanaged)
		}
		_, oldRef, _ := keycloak.ParseDriverRef(regX.DriverRef)
		_, newRef, _ := keycloak.ParseDriverRef(res.DriverRef)
		if newRef.Version != oldRef.Version+1 {
			t.Fatalf("driver secret %s → %s", oldRef, newRef)
		}
		if _, err := e.st.Get(ctx, oldRef); !errors.Is(err, secrets.ErrDestroyed) {
			t.Fatalf("old driver secret: %v", err)
		}
		regX.DriverRef = res.DriverRef
		cres, err := e.drv.EnsureClient(ctx, idp.ClientSpec{Registration: regX})
		if err != nil || !slices.Contains(cres.Changes, "client.mg-portal.implicitFlowEnabled") ||
			!slices.Contains(cres.Changes, "client.mg-portal.redirectUris") || cres.SecretRotated {
			t.Fatalf("portal repair: %+v, %v", cres, err)
		}
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX, nil, &rep)
		if rep["bruteForceProtected"] != true || rep["registrationAllowed"] != false {
			t.Fatal("realm settings not restored")
		}
		realmRoles, clientRoles := e.saRoles(t, realmX, keycloak.DriverClientID)
		if len(realmRoles) != 0 || !slices.Equal(clientRoles["realm-management"], []string{"manage-users", "query-users", "view-users"}) {
			t.Fatalf("service account roles after repair: %v %v", realmRoles, clientRoles)
		}
		final, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regX})
		if err != nil || len(final.Changes) != 0 {
			t.Fatalf("after repair: %+v, %v", final, err)
		}
		e.admin(t, http.MethodDelete, "/admin/realms/"+realmX+"/clients/"+e.client(t, realmX, "rogue-client")["id"].(string), nil, nil)
		// realm-admin (a composite holding impersonation) given to the service account: the provisioning identity does
		// not hold impersonation, so Keycloak refuses it the unmapping — detected and reported as drift, never ignored
		var admin map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX+"/clients/"+rm["id"].(string)+"/roles/realm-admin", nil, &admin)
		e.admin(t, http.MethodPost, saMappings, []any{admin}, nil)
		_, err = e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regX})
		t.Logf("service account given realm-admin: %v", err)
		mustCode(t, "realm-admin on the service account", err, idp.CodeDrift)
		e.admin(t, http.MethodDelete, saMappings, []any{admin}, nil) // the break-glass admin repairs it
		if res, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regX}); err != nil || len(res.Changes) != 0 {
			t.Fatalf("after the break-glass repair: %+v, %v", res, err)
		}
	})

	t.Run("an imported realm adopted by Bootstrap matches the template; other realms are refused", func(t *testing.T) {
		idpA, err := uuid.Parse(os.Getenv("MG_TEST_KEYCLOAK_IDP_ID"))
		if err != nil {
			t.Skip("MG_TEST_KEYCLOAK_IDP_ID not set")
		}
		regA := idp.Registration{IdPID: idpA, Scope: idp.ScopeTenant, TenantID: e.tenantID, Driver: idp.DriverKeycloak}
		res, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regA, Realm: "tenant-a"})
		if err != nil || res.Created {
			t.Fatalf("tenant-a: %+v, %v", res, err)
		}
		// no driver_ref yet: only the (Keycloak-generated, unknown) service-account secret is replaced
		if !slices.Equal(res.Changes, []string{"client.mg-idp-driver.secret"}) || len(res.Unmanaged) != 0 {
			t.Fatalf("tenant-a imported from the infrastructure template differs from the driver's template: %v %v",
				res.Changes, res.Unmanaged)
		}
		regA.DriverRef = res.DriverRef
		again, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regA})
		if err != nil || len(again.Changes) != 0 {
			t.Fatalf("tenant-a again: %+v, %v", again, err)
		}
		wrong := regA
		wrong.IdPID, wrong.DriverRef = uuid.New(), ""
		_, err = e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: wrong, Realm: "tenant-a"})
		mustCode(t, "tenant-a under another IdP id", err, idp.CodeConflict)
		plat := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopePlatform, Driver: idp.DriverKeycloak}
		_, err = e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: plat, Realm: "platform"})
		mustCode(t, "platform realm (not adopted)", err, idp.CodeForbidden)
		_, err = e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: plat, Realm: "master"})
		mustCode(t, "master realm", err, idp.CodeInvalidArgument)
	})

	t.Run("disable realm, idempotent; ensure enables it again", func(t *testing.T) {
		for i, wantChanged := range []bool{true, false} {
			res, err := e.drv.RemoveIssuer(ctx, regX, idp.RemoveDisable)
			if err != nil || res.Changed != wantChanged || res.AlreadyAbsent {
				t.Fatalf("disable #%d: %+v, %v", i+1, res, err)
			}
		}
		var rep map[string]any
		e.admin(t, http.MethodGet, "/admin/realms/"+realmX, nil, &rep)
		if rep["enabled"] != false {
			t.Fatal("realm still enabled")
		}
		_, sref, _ := keycloak.ParseDriverRef(regX.DriverRef)
		if _, st := e.clientToken(t, realmX, keycloak.DriverClientID, sref); st != http.StatusForbidden {
			t.Fatalf("token from a disabled realm: HTTP %d", st)
		}
		_, err := e.drv.InviteUser(ctx, regX, idp.Invite{Email: "bob@" + e.domain})
		mustCode(t, "invite into a disabled realm", err, idp.CodeForbidden)
		res, err := e.drv.EnsureIssuer(ctx, idp.IssuerSpec{Registration: regX})
		if err != nil || !slices.Contains(res.Changes, "realm.enabled") {
			t.Fatalf("re-enable: %+v, %v", res, err)
		}
	})

	t.Run("purge realm, idempotent; secrets destroyed", func(t *testing.T) {
		for _, reg := range []*idp.Registration{&regX, &regY} {
			for i, wantAbsent := range []bool{false, true} {
				res, err := e.drv.RemoveIssuer(ctx, *reg, idp.RemovePurge)
				if err != nil || res.AlreadyAbsent != wantAbsent || res.Changed == wantAbsent {
					t.Fatalf("purge #%d: %+v, %v", i+1, res, err)
				}
			}
			ref, sref, _ := keycloak.ParseDriverRef(reg.DriverRef)
			if st := e.admin(t, http.MethodGet, "/admin/realms/"+ref.Realm, nil, nil); st != http.StatusNotFound {
				t.Fatalf("realm %s after purge: HTTP %d", ref.Realm, st)
			}
			if _, err := e.st.Get(ctx, sref); !errors.Is(err, secrets.ErrDestroyed) {
				t.Fatalf("driver secret after purge: %v", err)
			}
			res, err := e.drv.RemoveIssuer(ctx, *reg, idp.RemoveDisable)
			if err != nil || !res.AlreadyAbsent {
				t.Fatalf("disable after purge: %+v, %v", res, err)
			}
		}
		pref, _ := secrets.ParseRef(regX.ClientSecretRef)
		if _, err := e.st.Get(ctx, pref); !errors.Is(err, secrets.ErrDestroyed) {
			t.Fatalf("portal secret after purge: %v", err)
		}
	})

	t.Run("administrative credentials come only from the SecretStore", func(t *testing.T) {
		if err := e.st.Destroy(ctx, e.boot.Provisioner.Secret); err != nil {
			t.Fatal(err)
		}
		d2, err := keycloak.New(keycloak.Config{Route: e.route, Secrets: e.st, Provisioner: e.boot.Provisioner,
			AppHost: "app." + e.domain, AdminHost: "admin." + e.domain})
		if err != nil {
			t.Fatal(err)
		}
		r := randomRealm()
		reg := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: e.tenantID}
		_, err = d2.EnsureIssuer(ctx, idp.IssuerSpec{Registration: reg, Realm: r})
		mustCode(t, "provisioner secret destroyed", err, idp.CodeCredentials)
		if st := e.admin(t, http.MethodGet, "/admin/realms/"+r, nil, nil); st != http.StatusNotFound {
			t.Fatalf("realm created without a credential: HTTP %d", st)
		}
		// Bootstrap restores a working credential (new version, stored first)
		res, err := keycloak.Bootstrap(ctx, e.route, e.st, keycloak.BootstrapConfig{AdminUsername: e.conf["bootstrap-admin-username"],
			AdminPassword: e.adminRef, Provisioner: e.boot.Provisioner})
		if err != nil || !res.Rotated || res.Provisioner.Secret.Version != e.boot.Provisioner.Secret.Version+1 {
			t.Fatalf("re-bootstrap: %+v, %v", res, err)
		}
	})
}

func getStatus(ctx context.Context, c *http.Client, target string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
