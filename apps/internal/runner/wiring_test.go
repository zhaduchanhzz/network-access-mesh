package runner

// Tests of the P2-T16 wiring, including the G2 wiring hazards (coordinator's pre-review of main@2d3797a): each test
// names the hazard it proves. The end-to-end proof through the edge, Keycloak and real Headscale is the dev/CI stack
// (tests/e2e/harness/backend.py, E2E-17 … E2E-25).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// TestEdgeOnly — G2 hazard 5: with MG_TRUSTED_PROXIES set, only the edge's address reaches the public API; any other
// peer of the api's networks gets 403 problem+json; without trusted proxies (dev) every peer does.
func TestEdgeOnly(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	edge := []netip.Prefix{netip.MustParsePrefix("10.249.0.2/32")}
	for peer, want := range map[string]int{"10.249.0.2:51000": http.StatusTeapot, "10.249.0.3:51000": http.StatusForbidden,
		"[::ffff:10.249.0.2]:51000": http.StatusTeapot, "10.249.1.7:51000": http.StatusForbidden, "garbage": http.StatusForbidden} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/auth/session", nil)
		r.RemoteAddr = peer
		rec := httptest.NewRecorder()
		edgeOnly(edge, ok).ServeHTTP(rec, r)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", peer, rec.Code, want)
		}
		if want == http.StatusForbidden && (rec.Header().Get("Content-Type") != "application/problem+json" ||
			rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Body.String(), `"forbidden"`)) {
			t.Errorf("%s: refusal %v %s", peer, rec.Header(), rec.Body)
		}
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.9:1"
	rec := httptest.NewRecorder()
	edgeOnly(nil, ok).ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot {
		t.Errorf("dev (no trusted proxy): %d", rec.Code)
	}
}

// fakeEdgeAdmin answers like the edge admin listener (§14.6) for a request without X-MG-Instance: 404 once the token
// matches, 403 otherwise.
func fakeEdgeAdmin(t *testing.T, token string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-MG-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func randomToken() string {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 40)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alnum[int(b[i])%len(alnum)]
	}
	return string(b)
}

// TestEdgeAdminProbe — §16.2 readiness of the edge admin listener: ready only when the listener answers and accepts
// the token of the file (read at every probe); errors never carry the token.
func TestEdgeAdminProbe(t *testing.T) {
	token := randomToken()
	srv := fakeEdgeAdmin(t, token)
	dir := t.TempDir()
	good := writeFile(t, dir, "good", token+"\n")
	if err := edgeAdminProbe(srv.URL, good)(t.Context()); err != nil {
		t.Fatalf("good token: %v", err)
	}
	other := randomToken()
	for name, c := range map[string]struct {
		url, file string
		want      string
	}{
		"rotated on one side": {srv.URL, writeFile(t, dir, "other", other), "token refused"},
		"not a token":         {srv.URL, writeFile(t, dir, "bad", "short\n"), "does not hold a token"},
		"missing file":        {srv.URL, filepath.Join(dir, "missing"), "read the token file"},
		"listener down":       {"http://127.0.0.1:1", good, "edge admin listener"},
	} {
		err := edgeAdminProbe(c.url, c.file)(t.Context())
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), token) ||
			strings.Contains(err.Error(), other) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// fakeIdPs and fakeSecrets back the client-secret source.
type fakeIdPs map[uuid.UUID]tenants.IdP

func (f fakeIdPs) GetIdP(_ context.Context, id uuid.UUID) (tenants.IdP, error) {
	p, ok := f[id]
	if !ok {
		return tenants.IdP{}, tenants.ErrNotFound
	}
	return p, nil
}

type fakeSecrets struct{ asked []secrets.Ref }

func (f *fakeSecrets) Get(_ context.Context, ref secrets.Ref) (secrets.Plaintext, error) {
	f.asked = append(f.asked, ref)
	return secrets.Plaintext("value-of-" + ref.String()), nil
}

// TestClientSecretsBoundToTheirIdP — G2 hazard 4: the source of identity_providers.client_secret_ref is not a pass-through
// of the SecretStore — a reference is resolved only when it is the client secret of one IdP, recorded by that IdP and
// owned by the IdP's tenant (or the platform for a platform IdP); every other reference is refused before the
// SecretStore is asked.
func TestClientSecretsBoundToTheirIdP(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	idpA, idpB, idpP, idpX := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	refA := secrets.TenantRef(tenantA, provisioning.ClientSecretName(idpA), 2).String()
	refB := secrets.TenantRef(tenantB, provisioning.ClientSecretName(idpB), 1).String()
	refP := secrets.PlatformRef(provisioning.ClientSecretName(idpP), 1).String()
	idps := fakeIdPs{
		idpA: {ID: idpA, Scope: tenants.IdPScopeTenant, TenantID: &tenantA, ClientSecretRef: refA},
		idpB: {ID: idpB, Scope: tenants.IdPScopeTenant, TenantID: &tenantB, ClientSecretRef: refB},
		idpP: {ID: idpP, Scope: tenants.IdPScopePlatform, ClientSecretRef: refP},
		// an IdP of tenant A whose row points at B's secret (a tampered row, or a future bug in a write path)
		idpX: {ID: idpX, Scope: tenants.IdPScopeTenant, TenantID: &tenantA, ClientSecretRef: refB},
	}
	sec := &fakeSecrets{}
	src := clientSecrets(sec, idps)
	for _, ref := range []string{refA, refB, refP} {
		if v, err := src.ClientSecret(t.Context(), ref); err != nil || v != "value-of-"+ref {
			t.Errorf("%s: %q, %v", ref, v, err)
		}
	}
	refused := map[string]string{
		"another kind of secret":          secrets.TenantRef(tenantA, "headscale-api-key", 1).String(),
		"the provisioning identity":       secrets.PlatformRef("idp.keycloak.provisioner", 1).String(),
		"an older version":                secrets.TenantRef(tenantA, provisioning.ClientSecretName(idpA), 1).String(),
		"A's secret under B's tenant":     secrets.TenantRef(tenantB, provisioning.ClientSecretName(idpA), 2).String(),
		"a platform copy of A's secret":   secrets.PlatformRef(provisioning.ClientSecretName(idpA), 2).String(),
		"a tenant copy of the platform's": secrets.TenantRef(tenantA, provisioning.ClientSecretName(idpP), 1).String(),
		"an unknown IdP":                  secrets.TenantRef(tenantA, provisioning.ClientSecretName(uuid.New()), 1).String(),
		"the secret X's row points at":    secrets.TenantRef(tenantA, provisioning.ClientSecretName(idpX), 1).String(),
		"not a reference":                 "mgsec://nope",
	}
	sec.asked = nil
	for name, ref := range refused {
		if v, err := src.ClientSecret(t.Context(), ref); err == nil || v != "" {
			t.Errorf("%s: accepted (%q)", name, v)
		} else if strings.Contains(err.Error(), "value-of") {
			t.Errorf("%s: the error carries a value: %v", name, err)
		}
	}
	if len(sec.asked) != 0 {
		t.Errorf("the SecretStore was asked for %v", sec.asked)
	}
	if _, err := src.ClientSecret(t.Context(), refused["an unknown IdP"]); !errors.Is(err, errClientSecretRef) {
		t.Errorf("unknown IdP: %v", err)
	}
}

// TestClientSecretsAcceptTheDriverName — G2 round 2, I-7: an IdP created by a driver (keycloak/external: P3 idp.ensure)
// records its client secret as idp.<id>.client, `set-idp-client-secret` as idp-client-secret.<id>; the source resolves
// both names, each only for its own IdP and owner (idp.Registration.OwnClientSecretRef) and only when the IdP records
// exactly that reference. Before the fix the driver name was refused and such an IdP could never complete a login.
func TestClientSecretsAcceptTheDriverName(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	idpD, idpE, idpP := uuid.New(), uuid.New(), uuid.New()
	refD := secrets.TenantRef(tenantA, idp.ClientSecretName(idpD), 1).String()      // driver name, tenant
	refE := secrets.TenantRef(tenantB, idp.AdminClientSecretName(idpE), 3).String() // admin name, tenant
	refP := secrets.PlatformRef(idp.ClientSecretName(idpP), 2).String()             // driver name, platform
	idps := fakeIdPs{
		idpD: {ID: idpD, Scope: tenants.IdPScopeTenant, TenantID: &tenantA, Driver: "keycloak", ClientSecretRef: refD},
		idpE: {ID: idpE, Scope: tenants.IdPScopeTenant, TenantID: &tenantB, Driver: "external", ClientSecretRef: refE},
		idpP: {ID: idpP, Scope: tenants.IdPScopePlatform, Driver: "keycloak", ClientSecretRef: refP},
	}
	sec := &fakeSecrets{}
	src := clientSecrets(sec, idps)
	for _, ref := range []string{refD, refE, refP} {
		if v, err := src.ClientSecret(t.Context(), ref); err != nil || v != "value-of-"+ref {
			t.Errorf("%s: %q, %v", ref, v, err)
		}
	}
	// a tampered row (the CHECK of 0007 dropped): IdP T of tenant A records its own name under tenant B's owner — the
	// row and the reference agree, only OwnClientSecretRef refuses it
	idpT := uuid.New()
	refT := secrets.TenantRef(tenantB, idp.ClientSecretName(idpT), 1).String()
	idps[idpT] = tenants.IdP{ID: idpT, Scope: tenants.IdPScopeTenant, TenantID: &tenantA, Driver: "keycloak", ClientSecretRef: refT}
	sec.asked = nil
	for name, ref := range map[string]string{
		"T's own name under another tenant (row tampered)": refT,
		"D's driver name under B's tenant":                 secrets.TenantRef(tenantB, idp.ClientSecretName(idpD), 1).String(),
		"D's other name (not the one recorded)":            secrets.TenantRef(tenantA, idp.AdminClientSecretName(idpD), 1).String(),
		"platform's driver name under a tenant":            secrets.TenantRef(tenantA, idp.ClientSecretName(idpP), 2).String(),
		"D's driver name as a platform secret":             secrets.PlatformRef(idp.ClientSecretName(idpD), 1).String(),
		"driver name with a non-canonical id":              secrets.TenantRef(tenantA, "idp."+strings.ToUpper(idpD.String())+".client", 1).String(),
		"driver-like name of another kind":                 secrets.TenantRef(tenantA, "idp."+idpD.String()+".driver", 1).String(),
		"the keycloak provisioning identity name":          secrets.PlatformRef("idp.keycloak.provisioner", 1).String(),
	} {
		if v, err := src.ClientSecret(t.Context(), ref); err == nil || v != "" {
			t.Errorf("%s: accepted (%q)", name, v)
		}
	}
	if len(sec.asked) != 0 {
		t.Errorf("the SecretStore was asked for %v", sec.asked)
	}
}

// TestIdPClients — G2 hazard 3: the hardened client refuses the deny list of the configuration on top of its built-in
// ranges and every name under MG_BASE_DOMAIN; the platform route serves auth.<domain> only.
func TestIdPClients(t *testing.T) {
	cfg := config.Config{BaseDomain: "example.com", IdPPlatformAddr: "10.249.0.2:443",
		EgressDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("8.8.4.4/32")}}
	h, r, err := idpClients(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"8.8.4.4", "203.0.113.9", "10.249.0.2", "100.64.0.1", "172.24.0.5"} {
		if h.Policy().Check(netip.MustParseAddr(a)) == nil {
			t.Errorf("%s allowed by the hardened client", a)
		}
	}
	if h.Policy().Check(netip.MustParseAddr("8.8.8.8")) != nil {
		t.Error("a public address outside the deny list refused")
	}
	for _, u := range []string{"https://auth.example.com/realms/x", "https://evil.example.com/", "https://example.com/"} {
		pu, _ := url.Parse(u)
		if h.CheckURL(pu) == nil {
			t.Errorf("%s allowed by the hardened client (platform domain)", u)
		}
	}
	if r.Host() != "auth.example.com" {
		t.Errorf("route host %q", r.Host())
	}
}

// TestWiringKeepsDefaults — G2 hazard 9 (and 6): the wiring never overrides monitoring.Config.StaleAfter (tenantsapi
// relies on the default), locator.Options.TenantStatuses (DefaultTenantStatuses) or the job timeouts; the api never
// loads the kek-ops keyring.
func TestWiringKeepsDefaults(t *testing.T) {
	fset := token.NewFileSet()
	for _, f := range []string{"api.go", "worker.go", "deps.go", "runner.go"} {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok {
					switch id.Name {
					case "StaleAfter", "TenantStatuses", "Kinds", "HeartbeatMaxAge":
						t.Errorf("%s: the wiring sets %s (keep the module's default)", fset.Position(kv.Pos()), id.Name)
					}
				}
			}
			return true
		})
	}
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "KEKOps") || strings.Contains(string(src), "kek-ops") {
		t.Error("api.go mentions the kek-ops keyring")
	}
	// the one exception (P3-T08): the registry of tenant.suspend / tenant.resume reaches a suspended tenant's instance —
	// lifecycle.go sets TenantStatuses exactly once, to lifecycle.ReachableStatuses
	file, err := parser.ParseFile(fset, "lifecycle.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var statuses []string
	ast.Inspect(file, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "TenantStatuses" {
				value := "?"
				if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok {
						value = pkg.Name + "." + sel.Sel.Name
					}
				}
				statuses = append(statuses, value)
			}
		}
		return true
	})
	if len(statuses) != 1 || statuses[0] != "lifecycle.ReachableStatuses" {
		t.Errorf("lifecycle.go sets TenantStatuses %v, want exactly [lifecycle.ReachableStatuses]", statuses)
	}
	// the second exception (P3-T09): the registry of tenant.deprovision reaches a deprovisioning tenant's instance —
	// deprovision.go sets TenantStatuses exactly once, to deprovision.ReachableStatuses
	if got := tenantStatusesSet(t, fset, "deprovision.go"); len(got) != 1 || got[0] != "deprovision.ReachableStatuses" {
		t.Errorf("deprovision.go sets TenantStatuses %v, want exactly [deprovision.ReachableStatuses]", got)
	}
}

// tenantStatusesSet returns the values the file assigns to a TenantStatuses field ("pkg.Name" for a selector).
func tenantStatusesSet(t *testing.T, fset *token.FileSet, name string) []string {
	t.Helper()
	file, err := parser.ParseFile(fset, name, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "TenantStatuses" {
				value := "?"
				if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok {
						value = pkg.Name + "." + sel.Sel.Name
					}
				}
				out = append(out, value)
			}
		}
		return true
	})
	return out
}

// wiredEnv is the environment of a wired process on the test database (the shape compose.app.yaml renders).
func wiredEnv(t *testing.T, service, dbURL string, pg *storetest.Env, edgeURL, tokenFile string) map[string]string {
	t.Helper()
	keys := t.TempDir()
	ring := func(name, id string) string {
		d := filepath.Join(keys, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		writeFile(t, d, id, hex.EncodeToString(k)+"\n")
		writeFile(t, d, secrets.ActiveFile, id+"\n")
		return d
	}
	tc, pc := pg.Creds(t, "mg_"+service+"_tenant"), pg.Creds(t, "mg_"+service+"_platform")
	m := map[string]string{
		"MG_ENV": "staging", "MG_LOG_LEVEL": "debug", "MG_BASE_DOMAIN": "mg.test",
		"MG_HTTP_ADDR": freeAddr(t), "MG_INTERNAL_ADDR": freeAddr(t),
		"MG_DB_URL": dbURL, "MG_DB_TENANT_USER": tc.User, "MG_DB_TENANT_PASSWORD_FILE": tc.PasswordFile,
		"MG_DB_PLATFORM_USER": pc.User, "MG_DB_PLATFORM_PASSWORD_FILE": pc.PasswordFile,
		"MG_KEK_APP_DIR": ring("kek-app", "test-app-1"), "MG_EDGE_ADMIN_URL": edgeURL, "MG_EDGE_ADMIN_TOKEN_FILE": tokenFile,
		"MG_EGRESS_DENY_CIDRS": "10.249.0.0/16,10.250.0.0/16,172.24.0.0/13,192.0.2.0/24",
		"MG_IDP_PLATFORM_ADDR": "127.0.0.1:1",
	}
	if service == "api" {
		m["MG_TRUSTED_PROXIES"] = "127.0.0.1"
		m["MG_DB_AUDIT_WRITER_PASSWORD_FILE"] = pg.Creds(t, "mg_audit_writer").PasswordFile
	} else {
		m["MG_KEK_OPS_DIR"] = ring("kek-ops", "test-ops-1")
		m["MG_DB_PARTITION_PASSWORD_FILE"] = pg.Creds(t, "mg_partition_maint").PasswordFile
	}
	return m
}

// startProcess runs run() of service and waits until /readyz answers 200; it returns the internal and public bases.
func startProcess(t *testing.T, service string, env map[string]string) (internal, public string, logs *syncBuffer) {
	t.Helper()
	getenv, environ := environment(env)
	var stdout, stderr syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, service, getenv, environ, &stdout, &stderr) }()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("%s exit code %d\n%s", service, code, stderr.String())
			}
		case <-time.After(60 * time.Second):
			t.Errorf("%s did not stop", service)
		}
	})
	internal, public = "http://"+env["MG_INTERNAL_ADDR"], "http://"+env["MG_HTTP_ADDR"]
	deadline := time.Now().Add(45 * time.Second)
	for {
		if r, err := get(t, internal+"/readyz"); err == nil && r.status == http.StatusOK && strings.Contains(r.body, `"ready":true`) {
			return internal, public, &stdout
		} else if time.Now().After(deadline) {
			t.Fatalf("%s not ready: %+v %v\nstderr: %s\nstdout: %s", service, r, err, stderr.String(), stdout.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestWiredProcesses — the api and the worker wired on a database migrated like a deployment (storetest) with a fake
// edge admin listener: both ready (/readyz: postgres, secretstore, edge_admin); a rotated edge token makes them not
// ready; the api's identity layer uses the chain's request id, client address and problem writer, and its audit
// reaches audit_events (G2 hazard 2); the worker reports its IdP drivers.
func TestWiredProcesses(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	token := randomToken()
	tokens := t.TempDir()
	tokenFile := writeFile(t, tokens, "edge_admin_token", token+"\n")
	edge := fakeEdgeAdmin(t, token)

	apiInternal, apiPublic, _ := startProcess(t, "api", wiredEnv(t, "api", pg.URL(db), pg, edge.URL, tokenFile))
	workerInternal, _, workerLogs := startProcess(t, "worker", wiredEnv(t, "worker", pg.URL(db), pg, edge.URL, tokenFile))

	// G2 hazard 2: a cross-site logout is refused by the identity middleware itself — answered through
	// authzhook.WriteProblem (nosniff, the chain's request id, not the client's malformed one) and audited in
	// audit_events with the client address the chain derived from X-Forwarded-For of the trusted proxy.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, apiPublic+"/api/v1/auth/logout", nil)
	req.Host = "app.mg.test"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("X-Request-Id", "client supplied id")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	rid := resp.Header.Get("X-Request-Id")
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
		rid == "" || rid == "client supplied id" {
		t.Fatalf("cross-site logout: %d %v", resp.StatusCode, resp.Header)
	}
	su := pg.Admin(t, db)
	var ip, action, outcome string
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = su.QueryRow(t.Context(), `SELECT host(actor_ip), action, outcome FROM audit_events WHERE request_id = $1`, rid).
			Scan(&ip, &action, &outcome)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || ip != "198.51.100.7" || action != "auth.session.check" || outcome != "denied" {
		t.Fatalf("audit of the refusal: %s %s %s (%v)", ip, action, outcome, err)
	}
	// an unknown host is answered by the identity middleware through the chain's problem writer
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, apiPublic+"/api/v1/auth/session", nil)
	req.Host = "evil.mg.test"
	if resp, err = http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNotFound ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unknown host: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	// unauthenticated session read on the app origin
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, apiPublic+"/api/v1/auth/session", nil)
	req.Host = "app.mg.test"
	if resp, err = http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /auth/session: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	// a rotated token on the edge's side only: both processes stop being ready, naming the probe only
	writeFile(t, tokens, "edge_admin_token", randomToken()+"\n")
	for name, base := range map[string]string{"api": apiInternal, "worker": workerInternal} {
		r, err := get(t, base+"/readyz")
		if err != nil || r.status != http.StatusServiceUnavailable || r.body != `{"failing":["edge_admin"],"ready":false}`+"\n" {
			t.Errorf("%s with a rotated token: %+v %v", name, r, err)
		}
	}
	if !strings.Contains(workerLogs.String(), `"idp_drivers":["external","keycloak"]`) ||
		!strings.Contains(workerLogs.String(), `"keycloak_provisioner_bootstrapped":false`) {
		t.Errorf("worker log lacks the IdP drivers:\n%s", workerLogs.String())
	}
}

// TestIntegrityReporter — G2 hazard 10 (P2-T08 open item): an integrity failure of the SecretStore becomes one platform
// security event (deduplicated), naming the operation and the reference, never a value.
func TestIntegrityReporter(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	st := pg.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	var logs syncBuffer
	report := integrityReporter(st, "worker", newTestLogger(&logs))
	ref := secrets.TenantRef(uuid.New(), "headscale-api-key", 3)
	for range 3 {
		report(t.Context(), secrets.IntegrityFailure{Op: "get", Ref: ref})
	}
	su := pg.Admin(t, db)
	var n int
	var severity, details string
	if err := su.QueryRow(t.Context(), `SELECT count(*), min(severity), min(details::text) FROM security_events
		WHERE kind = 'secrets.integrity_failure' AND tenant_id IS NULL`).Scan(&n, &severity, &details); err != nil {
		t.Fatal(err)
	}
	if n != 1 || severity != "high" || !strings.Contains(details, ref.String()) || !strings.Contains(details, `"operation": "get"`) {
		t.Fatalf("security events: %d %s %s", n, severity, details)
	}
	if !strings.Contains(logs.String(), "integrity failure recorded as a security event") {
		t.Errorf("log: %s", logs.String())
	}
}

func newTestLogger(w *syncBuffer) *slog.Logger { return logx.New(w, slog.LevelDebug, "test") }
