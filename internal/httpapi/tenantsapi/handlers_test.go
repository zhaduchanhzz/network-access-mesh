package tenantsapi_test

// The registry read operations of P2-T11 through the whole public chain: httpapi.New (P2-T14) with the session layer of
// identity (P2-T06, real OIDC logins against fake IdPs) and authz (P2-T07) in its hooks, on a real PostgreSQL migrated
// like a deployment (storetest). Layer 1 (authz) and layer 2 (object checks of the services) together: a tenant user
// sees only its tenant, another tenant's tenant or member reads as 404, platform staff see registry metadata only.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

const (
	appHost   = "app.mg.test"
	adminHost = "admin.mg.test"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// browser keeps cookies per host and never follows redirects.
type browser struct {
	t   *testing.T
	h   http.Handler
	jar map[string]map[string]string
}

func (b *browser) get(rawURL string) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, rawURL, nil)
	for name, value := range b.jar[req.Host] {
		req.Header.Add("Cookie", name+"="+value)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, line := range rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			b.t.Fatalf("bad Set-Cookie: %v", err)
		}
		if b.jar[req.Host] == nil {
			b.jar[req.Host] = map[string]string{}
		}
		if c.MaxAge < 0 {
			delete(b.jar[req.Host], c.Name)
		} else {
			b.jar[req.Host][c.Name] = c.Value
		}
	}
	return rec
}

func (b *browser) login(host, query string) {
	b.t.Helper()
	start := b.get("https://" + host + "/api/v1/auth/login?" + query)
	if start.Code != http.StatusFound {
		b.t.Fatalf("login start: HTTP %d %s", start.Code, start.Body.String())
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(b.t.Context(), http.MethodGet, start.Header().Get("Location"), nil)
	resp, err := c.Do(req)
	if err != nil {
		b.t.Fatalf("authorize: %v", err)
	}
	_ = resp.Body.Close()
	cb := b.get(resp.Header.Get("Location"))
	if cb.Code != http.StatusFound || b.jar[host][identity.SessionCookieName] == "" {
		b.t.Fatalf("callback: HTTP %d %s", cb.Code, cb.Body.String())
	}
}

func decode[T any](t *testing.T, what string, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("%s: HTTP %d %s", what, rec.Code, rec.Body.String())
	}
	return v
}

func problemOf(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code gen.ProblemCode) {
	t.Helper()
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != status || p.Code != code {
		t.Fatalf("%s: HTTP %d %s, want %d %s", what, rec.Code, rec.Body.String(), status, code)
	}
}

func TestRegistryReadsThroughTheChain(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	su := pg.Admin(t, db)
	st := pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := su.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, sql)
		}
	}

	// registry: tenants A and B with running instances (an API key reference that must never leave the service)
	host := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'mg-staging', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	instA, instB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for i, x := range []struct {
		t, inst uuid.UUID
		slug    string
	}{{a, instA, "tenant-a"}, {b, instB, "tenant-b"}} {
		exec(`INSERT INTO tenants (id, slug, name, status, deployment_region) VALUES ($1, $2::text, $2::text, 'active', 'lab')`,
			x.t, x.slug)
		exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path, api_key_secret_ref,
				api_key_prefix)
			VALUES ($1, $2, $3, 'running', 'v0.29.7', 'sha256:'||repeat('a', 64), $4||'.mesh.mg.test',
				'https://'||$4||'.mesh.mg.test', $4||'.tail.mg.test', 'hs-'||$4||':8080', $5, $6::cidr, '/data', $7, 'secretprefix')`,
			x.inst, x.t, host, x.slug, 30001+i, []string{"10.250.0.0/29", "10.250.0.8/29"}[i],
			"mgsec://"+x.t.String()+"/headscale-api-key#1")
	}

	// IdPs: tenant A's (fake, app origin) and the platform's (fake, admin origin); tenant B's member is seeded directly
	now := time.Now
	fakeA, fakeP := identitytest.NewFakeIdP(t, now), identitytest.NewFakeIdP(t, now)
	idpA, idpP, idpB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	refs := map[string]string{"mgsec://" + a.String() + "/idp-a#1": "secret-a-" + uuid.NewString(),
		"mgsec://platform/idp-p#1": "secret-p-" + uuid.NewString()}
	exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'portal-a', $4, 'external', 'active')`, idpA, a, fakeA.Issuer, "mgsec://"+a.String()+"/idp-a#1")
	exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'platform', $2, 'portal-p', 'mgsec://platform/idp-p#1', 'external', 'active')`, idpP, fakeP.Issuer)
	exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, 'https://idp-b.test', 'portal-b', 'external', 'active')`, idpB, b)
	fakeA.AddClient("portal-a", refs["mgsec://"+a.String()+"/idp-a#1"], "https://"+appHost+"/api/v1/auth/callback/"+idpA.String())
	fakeP.AddClient("portal-p", refs["mgsec://platform/idp-p#1"], "https://"+adminHost+"/api/v1/auth/callback/"+idpP.String())
	identB, memberB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, display_name)
		VALUES ($1, $2, $3, 'tenant', 'sub-b', 'bert@b.test', 'Bert')`, identB, idpB, b)
	exec(`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status)
		SELECT $1, $2, $3, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'tenant_owner'`, memberB, b, identB)

	svc, err := identity.New(st, identity.Config{
		AppHost: appHost, AdminHost: adminHost, HTTPClient: &http.Client{Timeout: 5 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, r string) (string, error) {
			if s, ok := refs[r]; ok {
				return s, nil
			}
			return "", errors.New("unknown secret ref")
		}),
		Logger: slog.New(slog.DiscardHandler), RequestID: authzhook.RequestID, ClientIP: authzhook.ClientIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpapi.New(httpapi.Options{
		Logger: logx.New(&strings.Builder{}, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Auth: identityapi.New(svc),
			Tenants: tenantsapi.New(tenants.New(st, tenants.Options{BaseDomain: "mg.test"}), platform.New(st))},
		Hooks: authzhook.Hooks(svc, authz.New(st)),
	})
	if err != nil {
		t.Fatal(err)
	}
	app, admin := "https://"+appHost+"/api/v1", "https://"+adminHost+"/api/v1"

	// --- a Tenant Owner of A
	alice := &browser{t: t, h: h, jar: map[string]map[string]string{}}
	fakeA.SetUser(identitytest.FakeUser{Sub: "sub-alice", Email: "alice@a.test", EmailVerified: true, Name: "Alice"})
	alice.login(appHost, "scope=tenant&tenant=tenant-a")
	var identA uuid.UUID
	if err := su.QueryRow(ctx, `SELECT id FROM identities WHERE idp_id = $1 AND subject = 'sub-alice'`, idpA).Scan(&identA); err != nil {
		t.Fatal(err)
	}
	memberA := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status)
		SELECT $1, $2, $3, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'tenant_owner'`, memberA, a, identA)

	mine := decode[gen.TenantList](t, "GET /tenants", alice.get(app+"/tenants"))
	if len(mine.Items) != 1 || mine.Items[0].Id != a || mine.Items[0].ControlUrl != "https://tenant-a.mesh.mg.test" ||
		mine.NextCursor != nil {
		t.Fatalf("GET /tenants = %+v", mine)
	}
	rec := alice.get(app + "/tenants/" + a.String())
	ta := decode[gen.Tenant](t, "GET /tenants/A", rec)
	if ta.Slug != "tenant-a" || ta.Status != "active" || ta.Plan != "" || rec.Header().Get("ETag") != `"1"` ||
		ta.DeploymentRegion != "lab" {
		t.Fatalf("GET /tenants/A = %+v, ETag %q", ta, rec.Header().Get("ETag"))
	}
	if strings.Contains(rec.Body.String(), "mgsec://") || strings.Contains(rec.Body.String(), "secretprefix") {
		t.Fatal("the tenant view carries the key reference")
	}
	users := decode[gen.MembershipList](t, "GET /tenants/A/users", alice.get(app+"/tenants/"+a.String()+"/users"))
	if len(users.Items) != 1 || users.Items[0].Id != memberA || users.Items[0].Role != "tenant_owner" ||
		users.Items[0].HeadscaleUsername != "mg-"+memberA.String() || users.Items[0].DisplayName != "Alice" {
		t.Fatalf("GET /tenants/A/users = %+v", users)
	}
	rec = alice.get(app + "/tenants/" + a.String() + "/users/" + memberA.String())
	if m := decode[gen.Membership](t, "GET user", rec); m.IdentityId != identA || rec.Header().Get("ETag") != `"1"` {
		t.Fatalf("GET /tenants/A/users/{alice} = %+v", m)
	}
	// cross-tenant: B's tenant (layer 1) and B's member through A's path (layer 2) both read as 404
	problemOf(t, "tenant B", alice.get(app+"/tenants/"+b.String()), 404, gen.ProblemCodeNotFound)
	problemOf(t, "users of B", alice.get(app+"/tenants/"+b.String()+"/users"), 404, gen.ProblemCodeNotFound)
	problemOf(t, "B's member via A", alice.get(app+"/tenants/"+a.String()+"/users/"+memberB.String()), 404,
		gen.ProblemCodeNotFound)
	problemOf(t, "unknown member", alice.get(app+"/tenants/"+a.String()+"/users/"+uuid.NewString()), 404,
		gen.ProblemCodeNotFound)
	problemOf(t, "limit=0", alice.get(app+"/tenants/"+a.String()+"/users?limit=0"), 422, gen.ProblemCodeValidationFailed)
	problemOf(t, "bad cursor", alice.get(app+"/tenants/"+a.String()+"/users?cursor=@@"), 422, gen.ProblemCodeValidationFailed)
	problemOf(t, "bad role filter", alice.get(app+"/tenants/"+a.String()+"/users?role=Tenant%20Owner"), 422,
		gen.ProblemCodeValidationFailed)
	problemOf(t, "platform route", alice.get(app+"/platform/tenants"), 403, gen.ProblemCodeForbidden)

	// an End User of A reads the tenant but not its members (no tenant.user:read)
	exec(`UPDATE tenant_memberships SET role_id = (SELECT id FROM roles WHERE scope = 'tenant' AND key = 'end_user')
		WHERE id = $1`, memberA)
	decode[gen.Tenant](t, "EU GET /tenants/A", alice.get(app+"/tenants/"+a.String()))
	problemOf(t, "EU users", alice.get(app+"/tenants/"+a.String()+"/users"), 403, gen.ProblemCodeForbidden)

	// --- a Platform Viewer
	staff := &browser{t: t, h: h, jar: map[string]map[string]string{}}
	fakeP.SetUser(identitytest.FakeUser{Sub: "sub-pv", Email: "pv@platform.test", EmailVerified: true, Name: "Viewer"})
	staff.login(adminHost, "scope=platform")
	exec(`INSERT INTO platform_users (identity_id, role_id)
		SELECT i.id, r.id FROM identities i, roles r WHERE i.idp_id = $1 AND r.scope = 'platform' AND r.key = 'platform_viewer'`,
		idpP)
	all := decode[gen.TenantList](t, "GET /platform/tenants", staff.get(admin+"/platform/tenants"))
	if len(all.Items) != 2 || all.Items[0].Id != a || all.Items[1].Id != b {
		t.Fatalf("GET /platform/tenants = %+v", all)
	}
	one := decode[gen.TenantList](t, "filtered", staff.get(admin+"/platform/tenants?q=tenant-b&status=active"))
	if len(one.Items) != 1 || one.Items[0].Id != b {
		t.Fatalf("GET /platform/tenants?q=tenant-b = %+v", one)
	}
	if tb := decode[gen.Tenant](t, "GET /platform/tenants/B", staff.get(admin+"/platform/tenants/"+b.String())); tb.Slug != "tenant-b" {
		t.Fatalf("GET /platform/tenants/B = %+v", tb)
	}
	problemOf(t, "unknown tenant", staff.get(admin+"/platform/tenants/"+uuid.NewString()), 404, gen.ProblemCodeNotFound)
	rec = staff.get(admin + "/platform/instances")
	insts := decode[gen.InstanceList](t, "GET /platform/instances", rec)
	if len(insts.Items) != 2 || insts.Items[0].Id != instA || insts.Items[0].Health.Status != "unknown" ||
		insts.Items[0].NetCidr != "10.250.0.0/29" {
		t.Fatalf("GET /platform/instances = %+v", insts)
	}
	if strings.Contains(rec.Body.String(), "mgsec://") || strings.Contains(rec.Body.String(), "secretprefix") {
		t.Fatal("the instance list carries the key reference or prefix")
	}
	byHost := decode[gen.InstanceList](t, "by host", staff.get(admin+"/platform/instances?host="+host.String()+"&status=running"))
	if len(byHost.Items) != 2 {
		t.Fatalf("GET /platform/instances?host = %+v", byHost)
	}
	if ib := decode[gen.Instance](t, "GET instance B", staff.get(admin+"/platform/instances/"+instB.String())); ib.TenantId != b {
		t.Fatalf("GET /platform/instances/B = %+v", ib)
	}
	problemOf(t, "unknown instance", staff.get(admin+"/platform/instances/"+uuid.NewString()), 404, gen.ProblemCodeNotFound)
	problemOf(t, "bad status", staff.get(admin+"/platform/instances?status=asleep"), 422, gen.ProblemCodeValidationFailed)
	// staff are members of no tenant, and reach no tenant-internal data without a Support Access Grant (P4-T13)
	if mineStaff := decode[gen.TenantList](t, "staff GET /tenants", staff.get(admin+"/tenants")); len(mineStaff.Items) != 0 {
		t.Fatalf("staff GET /tenants = %+v", mineStaff)
	}
	problemOf(t, "staff tenant route", staff.get(admin+"/tenants/"+a.String()+"/users"), 403, gen.ProblemCodeForbidden)

	// anonymous
	anon := &browser{t: t, h: h, jar: map[string]map[string]string{}}
	problemOf(t, "anonymous", anon.get(app+"/tenants"), 401, gen.ProblemCodeUnauthenticated)
	problemOf(t, "anonymous platform", anon.get(admin+"/platform/tenants"), 401, gen.ProblemCodeUnauthenticated)
}
