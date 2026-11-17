package authzhook_test

// Composition test of the public API (P2 integration, no deployment): httpapi.New (P2-T14) with the auth handlers of
// identityapi and the session layer of identity (P2-T06) in Hooks.Session, the authorization of authz (P2-T07) in
// Hooks.Authz — on a real PostgreSQL migrated like a deployment (storetest: goose, RBAC seed, River), with a fake
// OpenID Provider (identitytest) and a minimal browser.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
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

// syncBuffer collects the log lines written by concurrent requests.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// accessLine returns the access-log line (JSON) of the request whose X-Request-Id is id.
func (b *syncBuffer) accessLine(t *testing.T, id string) map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ln := range strings.Split(b.buf.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil && m["request_id"] == id && m["status"] != nil {
			return m
		}
	}
	t.Fatalf("no access line for request %s", id)
	return nil
}

// browser keeps cookies per host and never follows redirects.
type browser struct {
	t   *testing.T
	h   http.Handler
	jar map[string]map[string]string
}

func (b *browser) do(method, rawURL string, hdr http.Header) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), method, rawURL, nil)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for name, value := range b.jar[req.Host] {
		req.Header.Add("Cookie", name+"="+value) // a request cookie carries no attributes
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

func (b *browser) get(rawURL string) *httptest.ResponseRecorder {
	return b.do(http.MethodGet, rawURL, nil)
}

// login runs GET /auth/login → fake IdP → callback and fails unless a session cookie is set.
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
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("authorize: HTTP %d", resp.StatusCode)
	}
	cb := b.get(resp.Header.Get("Location"))
	if cb.Code != http.StatusFound || b.jar[host][identity.SessionCookieName] == "" {
		b.t.Fatalf("callback: HTTP %d %s", cb.Code, cb.Body.String())
	}
}

func decodeProblem(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code gen.ProblemCode) gen.Problem {
	t.Helper()
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != status || p.Code != code ||
		rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("%s: HTTP %d %s, want %d %s problem", what, rec.Code, rec.Body.String(), status, code)
	}
	return p
}

// TestComposedAPI — login through the whole chain, then the authorization outcomes of §8.4 on real data: a tenant
// route without membership ⇒ 404 (other tenant and missing tenant read the same), a membership whose role lacks the
// grant ⇒ 403, a granted operation without handler ⇒ 501, and the CSRF/Origin layer on an unsafe method.
func TestComposedAPI(t *testing.T) {
	env := storetest.Require(t)
	db := env.NewDatabase(t) // goose + RBAC seed + River, like the migrate job
	su := env.Admin(t, db)
	st := env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := su.Exec(t.Context(), sql, args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, sql)
		}
	}

	// Two tenants; A signs in through its own IdP (the fake one).
	fake := identitytest.NewFakeIdP(t, time.Now)
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-a', 'Tenant A', 'active'), ($2, 'tenant-b', 'Tenant B', 'active')`, a, b)
	idp := uuid.Must(uuid.NewV7())
	ref := "mgsec://" + a.String() + "/idp." + idp.String() + ".client#1" // the IdP's own secret (G2 F3)
	exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'portal-a', $4, 'external', 'active')`, idp, a, fake.Issuer, ref)
	secret := "secret-" + uuid.NewString()
	fake.AddClient("portal-a", secret, "https://"+appHost+"/api/v1/auth/callback/"+idp.String())

	svc, err := identity.New(st, identity.Config{
		AppHost: appHost, AdminHost: adminHost,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, r string) (string, error) {
			if r != ref {
				return "", errors.New("unknown secret ref")
			}
			return secret, nil
		}),
		Logger:        slog.New(slog.DiscardHandler),
		RequestID:     authzhook.RequestID,
		ClientIP:      authzhook.ClientIP,
		ProblemWriter: authzhook.WriteProblem,
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	h, err := httpapi.New(httpapi.Options{
		Logger:   logx.New(logs, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Auth: identityapi.New(svc)},
		Hooks:    unaudited(authzhook.Hooks(svc, authz.New(st))),
	})
	if err != nil {
		t.Fatal(err)
	}
	api := "https://" + appHost + "/api/v1"
	br := &browser{t: t, h: h, jar: map[string]map[string]string{}}

	// 1. Login, then GET /auth/session through the whole chain.
	br.login(appHost, "scope=tenant&tenant=tenant-a&return_to=/devices")
	rec := br.get(api + "/auth/session")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/session: HTTP %d %s", rec.Code, rec.Body.String())
	}
	var sess gen.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	var identityID uuid.UUID
	if err := su.QueryRow(t.Context(), `SELECT id FROM identities WHERE idp_id = $1`, idp).Scan(&identityID); err != nil {
		t.Fatal(err)
	}
	if sess.CsrfToken == "" || sess.Origin != "app" || len(sess.Memberships) != 0 {
		t.Fatalf("session: %+v", sess)
	}
	// the session hook recorded the identity for the per-identity limit and the access log
	if line := logs.accessLine(t, rec.Header().Get("X-Request-Id")); line["identity"] != identityID.String() ||
		line["operation"] != "GetAuthSession" {
		t.Errorf("access line of GET /auth/session: %v", line)
	}

	// 2. Tenant routes without membership ⇒ 404, the same for the caller's own tenant, another tenant and none.
	var first gen.Problem
	for i, tenant := range []uuid.UUID{a, b, uuid.New()} {
		p := decodeProblem(t, "no membership", br.get(api+"/tenants/"+tenant.String()+"/devices"), http.StatusNotFound,
			gen.ProblemCodeNotFound)
		if i == 0 {
			first = p
		} else if p.Title != first.Title || *p.Detail != *first.Detail || p.Type != first.Type {
			t.Errorf("tenant %d: %+v differs from %+v (invariant 6)", i, p, first)
		}
	}
	// without a session at all ⇒ 401
	anon := &browser{t: t, h: h, jar: map[string]map[string]string{}}
	decodeProblem(t, "anonymous", anon.get(api+"/tenants/"+a.String()+"/devices"), http.StatusUnauthorized,
		gen.ProblemCodeUnauthenticated)

	// 3. Membership of A as tenant_operator (TP): audit is not granted to TP ⇒ 403.
	exec(`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status)
		SELECT $1, $2, $3, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $4`,
		uuid.Must(uuid.NewV7()), a, identityID, authz.RoleTenantOperator)
	decodeProblem(t, "TP audit", br.get(api+"/tenants/"+a.String()+"/audit"), http.StatusForbidden,
		gen.ProblemCodeForbidden)
	// still 404 in tenant B: membership of A says nothing about B
	decodeProblem(t, "TP in B", br.get(api+"/tenants/"+b.String()+"/devices"), http.StatusNotFound,
		gen.ProblemCodeNotFound)

	// 4. Granted operations without handler ⇒ 501 naming the operation.
	for path, op := range map[string]string{
		"/tenants/" + a.String() + "/devices": "ListDevices", // tenant.device:read
		"/tenants/" + a.String():              "GetTenant",   // tenant.tenant:read
		"/tenants":                            "ListMyTenants",
	} {
		p := decodeProblem(t, op, br.get(api+path), http.StatusNotImplemented, gen.ProblemCodeNotImplemented)
		if p.Detail == nil || !strings.Contains(*p.Detail, op) {
			t.Errorf("%s: detail %v does not name the operation", op, p.Detail)
		}
	}

	// 5. Unsafe method: the CSRF/Origin layer of the session hook, then authz (TP has tenant.device:sync).
	sync := api + "/tenants/" + a.String() + "/devices/sync"
	hdr := func(origin, csrf string) http.Header {
		h := http.Header{"Idempotency-Key": {uuid.NewString()}, "Content-Type": {"application/json"}}
		if origin != "" {
			h.Set("Origin", origin)
		}
		if csrf != "" {
			h.Set(identity.CSRFHeader, csrf)
		}
		return h
	}
	decodeProblem(t, "sync without CSRF token", br.do(http.MethodPost, sync, hdr("https://"+appHost, "")),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	decodeProblem(t, "sync from another origin", br.do(http.MethodPost, sync, hdr("https://evil.example", sess.CsrfToken)),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	decodeProblem(t, "sync with CSRF", br.do(http.MethodPost, sync, hdr("https://"+appHost, sess.CsrfToken)),
		http.StatusNotImplemented, gen.ProblemCodeNotImplemented)

	// 6. Lower role (end_user): device sync not granted ⇒ 403; suspended tenant refuses writes of granted roles.
	exec(`UPDATE tenant_memberships SET role_id = (SELECT id FROM roles WHERE scope = 'tenant' AND key = $1)
		WHERE tenant_id = $2 AND identity_id = $3`, authz.RoleEndUser, a, identityID)
	decodeProblem(t, "EU sync", br.do(http.MethodPost, sync, hdr("https://"+appHost, sess.CsrfToken)),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	exec(`UPDATE tenant_memberships SET role_id = (SELECT id FROM roles WHERE scope = 'tenant' AND key = $1)
		WHERE tenant_id = $2 AND identity_id = $3`, authz.RoleTenantOperator, a, identityID)
	exec(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, a)
	decodeProblem(t, "sync in a suspended tenant", br.do(http.MethodPost, sync, hdr("https://"+appHost, sess.CsrfToken)),
		http.StatusForbidden, gen.ProblemCodeTenantSuspended)
	decodeProblem(t, "read in a suspended tenant", br.get(api+"/tenants/"+a.String()+"/devices"),
		http.StatusNotImplemented, gen.ProblemCodeNotImplemented)

	// 7. Platform route from a tenant session ⇒ 403; the tenant session is unknown on the admin origin ⇒ 401.
	decodeProblem(t, "platform route", br.get(api+"/platform/jobs"), http.StatusForbidden, gen.ProblemCodeForbidden)
	br.jar[adminHost] = br.jar[appHost]
	decodeProblem(t, "app session on admin", br.get("https://"+adminHost+"/api/v1/auth/session"),
		http.StatusUnauthorized, gen.ProblemCodeUnauthenticated)

	// 8. Parameter errors of the new reauth flag are 422 naming it; logout revokes the session at once.
	p := decodeProblem(t, "reauth=yes", br.get(api+"/auth/login?scope=tenant&tenant=tenant-a&reauth=yes"),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	if p.Errors == nil || len(*p.Errors) != 1 || (*p.Errors)[0].Field != "reauth" {
		t.Errorf("reauth=yes: errors %+v", p.Errors)
	}
	if rec := br.do(http.MethodPost, api+"/auth/logout", hdr("https://"+appHost, sess.CsrfToken)); rec.Code != http.StatusOK {
		t.Fatalf("logout: HTTP %d %s", rec.Code, rec.Body.String())
	}
	decodeProblem(t, "after logout", br.get(api+"/auth/session"), http.StatusUnauthorized, gen.ProblemCodeUnauthenticated)

	var n int
	if err := su.QueryRow(t.Context(), `SELECT count(*) FROM sessions WHERE identity_id = $1 AND revoked_at IS NULL`,
		identityID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d live sessions after logout", n)
	}
}

// unaudited completes the hooks of this test with an explicit pass-through Audit hook: httpapi.New requires one once
// handlers are mounted (P2-T16); the audit of the composed API is tested by auditapi and the isolation suite.
func unaudited(h httpapi.Hooks) httpapi.Hooks {
	h.Audit = func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }
	return h
}
