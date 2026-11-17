//go:build mgtestfixture

// Package bootstrapseed_test — P2-T11a end to end: the Super Admins made by `meshguard admin bootstrap-super-admin`
// and the TO/TA made by `meshguard admin seed-membership` (provisioning.Bootstrapper on the api's own store) act
// through the composed public API of the api process (tests/security/sessionfixture: httpapi.New + identityapi +
// authzhook, here with the registry and audit read handlers mounted):
//
//   - a real OIDC login (fake OpenID Providers standing for the realms) of the person whose sub was bootstrapped or
//     seeded lands on the pre-created identity — matched by (idp_id, sub) — and a login with the same e-mail but
//     another sub does not (§8.2: never by e-mail);
//   - the Super Admin reads platform metadata and the platform audit (bootstrap events, actor_type system) but no
//     tenant-internal data without a Support Access Grant (§8.4 invariant 2);
//   - the TO of A reads A (members, audit of the seed) and gets 404 on B (§8.4 invariant 6) — although the same sub
//     string is TA of B: that is another identity, of B's issuer (§8.4 invariant 1).
package bootstrapseed_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// browser is a user agent of the API: host-only cookie jar, no redirect following; logins go through a fake IdP.
type browser struct {
	t   *testing.T
	h   http.Handler
	jar map[string]map[string]string
}

func newBrowser(t *testing.T, h http.Handler) *browser {
	return &browser{t: t, h: h, jar: map[string]map[string]string{}}
}

func (b *browser) get(rawURL string) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, rawURL, nil)
	for name, value := range b.jar[req.Host] {
		req.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // request cookie (attributes only exist in Set-Cookie)
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

// login runs GET /auth/login → the fake IdP's authorization endpoint → the callback of the API.
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

func status(t *testing.T, what string, rec *httptest.ResponseRecorder, want int, code gen.ProblemCode) {
	t.Helper()
	var p gen.Problem
	if rec.Code != want || json.Unmarshal(rec.Body.Bytes(), &p) != nil || p.Code != code {
		t.Fatalf("%s: HTTP %d %s, want %d %s", what, rec.Code, rec.Body.String(), want, code)
	}
}

// unlimited are rate limits no test reaches (as the session fixture's).
func unlimited() httpapi.RateLimits {
	l := ratelimit.Limit{Every: time.Nanosecond, Burst: 1_000_000_000}
	out := httpapi.RateLimits{}
	for _, c := range httpapi.Classes {
		out[c] = httpapi.ClassLimits{PerIP: l, PerIdentity: l}
	}
	return out
}

func TestSeededIdentitiesThroughTheComposedAPI(t *testing.T) {
	secrets := map[string]string{}
	w := sessionfixture.New(t, sessionfixture.Options{
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, ref string) (string, error) {
			if s, ok := secrets[ref]; ok {
				return s, nil
			}
			return "", errors.New("unknown secret ref")
		}),
	})
	ctx := context.Background()
	// The realms: one fake OpenID Provider per IdP row of the world (platform, A, B).
	fakeP, fakeA, fakeB := identitytest.NewFakeIdP(t, time.Now), identitytest.NewFakeIdP(t, time.Now),
		identitytest.NewFakeIdP(t, time.Now)
	for _, x := range []struct {
		idp  uuid.UUID
		fake *identitytest.FakeIdP
		ref  string
		host string
	}{
		// the IdPs' own secrets (G2 F3: owner = the IdP's tenant or platform, name idp.<idp id>.client)
		{w.PlatformIdP, fakeP, "mgsec://platform/idp." + w.PlatformIdP.String() + ".client#1", w.AdminHost},
		{w.A.IdP, fakeA, "mgsec://" + w.A.ID.String() + "/idp." + w.A.IdP.String() + ".client#1", w.AppHost},
		{w.B.IdP, fakeB, "mgsec://" + w.B.ID.String() + "/idp." + w.B.IdP.String() + ".client#1", w.AppHost},
	} {
		secrets[x.ref] = "client-" + uuid.NewString()
		w.Exec(t, `UPDATE identity_providers SET issuer = $2, client_secret_ref = $3 WHERE id = $1`, x.idp,
			x.fake.Issuer, x.ref)
		x.fake.AddClient("mg-portal", secrets[x.ref], "https://"+x.host+"/api/v1/auth/callback/"+x.idp.String())
	}
	// The composed API of the api process with the registry and audit read handlers.
	api, err := httpapi.New(httpapi.Options{
		Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Auth: identityapi.New(w.Identity),
			Tenants: tenantsapi.New(tenants.New(w.Store, tenants.Options{BaseDomain: "mg.test"}), platform.New(w.Store)),
			Audit:   auditapi.New(audit.NewReader(w.Store))},
		Hooks: unaudited(authzhook.Hooks(w.Identity, authz.New(w.Store))), RateLimits: unlimited(),
	})
	if err != nil {
		t.Fatal(err)
	}
	app, admin := "https://"+w.AppHost+"/api/v1", "https://"+w.AdminHost+"/api/v1"

	// --- bootstrap: the world's fixture Super Admin is disabled first, so the platform starts with none
	w.Exec(t, `UPDATE platform_users SET status = 'disabled' WHERE id = $1`,
		w.Actor(t, authz.RoleSuperAdmin, nil).PlatformUserID)
	b := &provisioning.Bootstrapper{Store: w.Store}
	subSA1, subSA2, shared, subTAA, subTOB := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(),
		uuid.NewString()
	var sas []provisioning.SuperAdminResult
	for _, sub := range []string{subSA1, subSA2} {
		r, err := b.BootstrapSuperAdmin(ctx, provisioning.SuperAdminRequest{PlatformIdP: w.PlatformIdP, Subject: sub})
		if err != nil || !r.Created {
			t.Fatalf("bootstrap: %+v %v", r, err)
		}
		sas = append(sas, r)
	}
	if _, err := b.BootstrapSuperAdmin(ctx, provisioning.SuperAdminRequest{PlatformIdP: w.PlatformIdP,
		Subject: uuid.NewString()}); !errors.Is(err, provisioning.ErrBootstrapClosed) {
		t.Fatalf("third bootstrap: %v", err)
	}
	seed := func(tenant, role, sub string) provisioning.MembershipResult {
		t.Helper()
		r, err := b.SeedMembership(ctx, provisioning.MembershipRequest{Tenant: tenant, Role: role, Subject: sub})
		if err != nil || !r.Created {
			t.Fatalf("seed %s %s: %+v %v", tenant, role, r, err)
		}
		return r
	}
	toA := seed("tenant-a", provisioning.RoleTenantOwner, shared) // the same sub string ...
	taB := seed("tenant-b", provisioning.RoleTenantAdmin, shared) // ... under another issuer: another identity
	taA := seed("tenant-a", provisioning.RoleTenantAdmin, subTAA)
	toB := seed("tenant-b", provisioning.RoleTenantOwner, subTOB)
	if toA.IdentityID == taB.IdentityID {
		t.Fatal("one identity for two issuers")
	}

	// --- Super Admin 1: a real login of the bootstrapped sub lands on the pre-created identity
	sa := newBrowser(t, api)
	fakeP.SetUser(identitytest.FakeUser{Sub: subSA1, Email: "sa1@ops.test", EmailVerified: true, Name: "SA One"})
	sa.login(w.AdminHost, "scope=platform")
	s := decode[gen.Session](t, "SA session", sa.get(admin+"/auth/session"))
	if s.Principal.IdentityId != sas[0].IdentityID || s.Principal.PlatformRole == nil ||
		*s.Principal.PlatformRole != "super_admin" || s.Principal.Scope != "platform" || len(s.Memberships) != 0 {
		t.Fatalf("SA session principal %+v (want identity %s)", s.Principal, sas[0].IdentityID)
	}
	// platform metadata: both tenants; the platform audit holds the bootstrap events (actor_type system)
	all := decode[gen.TenantList](t, "SA GET /platform/tenants", sa.get(admin+"/platform/tenants"))
	if len(all.Items) != 2 || all.Items[0].Id != w.A.ID || all.Items[1].Id != w.B.ID {
		t.Fatalf("SA GET /platform/tenants = %+v", all)
	}
	decode[gen.InstanceList](t, "SA GET /platform/instances", sa.get(admin+"/platform/instances"))
	pa := decode[gen.AuditEventList](t, "SA GET /platform/audit", sa.get(admin+"/platform/audit?limit=200"))
	actions := map[string]int{}
	for _, e := range pa.Items {
		actions[e.Action]++
		if e.Action == provisioning.ActionBootstrapSuperAdmin && (e.Actor.Type != "system" || e.Actor.IdentityId != nil ||
			e.Outcome != "success" || e.Resource.Type != "platform_user") {
			t.Errorf("bootstrap event %+v", e)
		}
		if e.Action == provisioning.ActionSeedMembership {
			t.Errorf("a tenant event in the platform audit: %+v", e)
		}
	}
	if actions[provisioning.ActionBootstrapSuperAdmin] != 2 || actions[provisioning.ActionSeedIdentity] != 4 {
		t.Fatalf("platform audit actions %v, want 2 bootstrap + 4 identity seeds", actions)
	}
	// no tenant-internal data without a Support Access Grant, member of no tenant
	status(t, "SA users of A", sa.get(admin+"/tenants/"+w.A.ID.String()+"/users"), 403, gen.ProblemCodeForbidden)
	status(t, "SA audit of A", sa.get(admin+"/tenants/"+w.A.ID.String()+"/audit"), 403, gen.ProblemCodeForbidden)
	status(t, "SA tenant A", sa.get(admin+"/tenants/"+w.A.ID.String()), 403, gen.ProblemCodeForbidden)
	if mine := decode[gen.TenantList](t, "SA GET /tenants", sa.get(admin+"/tenants")); len(mine.Items) != 0 {
		t.Fatalf("SA GET /tenants = %+v", mine)
	}

	// --- same e-mail, another sub: another identity, no role (never matched by e-mail)
	mimic := newBrowser(t, api)
	fakeP.SetUser(identitytest.FakeUser{Sub: uuid.NewString(), Email: "sa1@ops.test", EmailVerified: true, Name: "SA One"})
	mimic.login(w.AdminHost, "scope=platform")
	ms := decode[gen.Session](t, "mimic session", mimic.get(admin+"/auth/session"))
	if ms.Principal.IdentityId == sas[0].IdentityID || ms.Principal.PlatformRole != nil {
		t.Fatalf("a login with the Super Admin's e-mail and another sub got %+v", ms.Principal)
	}
	status(t, "mimic /platform/tenants", mimic.get(admin+"/platform/tenants"), 403, gen.ProblemCodeForbidden)

	// --- TO of A (a real login at A's issuer with the shared sub)
	owner := newBrowser(t, api)
	fakeA.SetUser(identitytest.FakeUser{Sub: shared, Email: "owner@a.test", EmailVerified: true, Name: "Owner A"})
	owner.login(w.AppHost, "scope=tenant&tenant=tenant-a")
	ts := decode[gen.Session](t, "TO session", owner.get(app+"/auth/session"))
	if ts.Principal.IdentityId != toA.IdentityID || len(ts.Memberships) != 1 || ts.Memberships[0].TenantId != w.A.ID ||
		ts.Memberships[0].Role != "tenant_owner" || ts.Memberships[0].MembershipId != toA.MembershipID {
		t.Fatalf("TO session %+v %+v", ts.Principal, ts.Memberships)
	}
	mine := decode[gen.TenantList](t, "TO GET /tenants", owner.get(app+"/tenants"))
	if len(mine.Items) != 1 || mine.Items[0].Id != w.A.ID {
		t.Fatalf("TO GET /tenants = %+v", mine)
	}
	decode[gen.Tenant](t, "TO GET /tenants/A", owner.get(app+"/tenants/"+w.A.ID.String()))
	users := decode[gen.MembershipList](t, "TO users of A", owner.get(app+"/tenants/"+w.A.ID.String()+"/users?limit=200"))
	roles := map[uuid.UUID]string{}
	for _, m := range users.Items {
		roles[m.Id] = m.Role
	}
	if roles[toA.MembershipID] != "tenant_owner" || roles[taA.MembershipID] != "tenant_admin" ||
		roles[taB.MembershipID] != "" || roles[toB.MembershipID] != "" {
		t.Fatalf("TO users of A: %v", roles)
	}
	ta := decode[gen.AuditEventList](t, "TO audit of A", owner.get(app+"/tenants/"+w.A.ID.String()+"/audit?limit=200"))
	var seeded []string
	for _, e := range ta.Items {
		if e.Action == provisioning.ActionSeedMembership {
			if e.Actor.Type != "system" || e.Actor.IdentityId != nil {
				t.Errorf("seed event %+v", e)
			}
			seeded = append(seeded, e.Resource.Id)
		}
	}
	slices.Sort(seeded)
	want := []string{toA.MembershipID.String(), taA.MembershipID.String()}
	slices.Sort(want)
	if !slices.Equal(seeded, want) {
		t.Fatalf("seed events in the audit of A: %v, want exactly A's memberships %v", seeded, want)
	}
	// B, although the same sub string is TA of B (that identity belongs to B's issuer): 404, as a missing tenant
	status(t, "TO of A on B", owner.get(app+"/tenants/"+w.B.ID.String()), 404, gen.ProblemCodeNotFound)
	status(t, "TO of A on B's users", owner.get(app+"/tenants/"+w.B.ID.String()+"/users"), 404, gen.ProblemCodeNotFound)
	status(t, "TO of A on B's audit", owner.get(app+"/tenants/"+w.B.ID.String()+"/audit"), 404, gen.ProblemCodeNotFound)
	status(t, "TO of A on B's member via A", owner.get(app+"/tenants/"+w.A.ID.String()+"/users/"+taB.MembershipID.String()),
		404, gen.ProblemCodeNotFound)
	status(t, "TO of A on platform", owner.get(app+"/platform/tenants"), 403, gen.ProblemCodeForbidden)

	// --- TA of B (a real login at B's issuer with the same sub string): B only
	adminB := newBrowser(t, api)
	fakeB.SetUser(identitytest.FakeUser{Sub: shared, Email: "owner@a.test", EmailVerified: true, Name: "Owner A at B"})
	adminB.login(w.AppHost, "scope=tenant&tenant=tenant-b")
	bs := decode[gen.Session](t, "TA of B session", adminB.get(app+"/auth/session"))
	if bs.Principal.IdentityId != taB.IdentityID || len(bs.Memberships) != 1 || bs.Memberships[0].TenantId != w.B.ID ||
		bs.Memberships[0].Role != "tenant_admin" {
		t.Fatalf("TA of B session %+v %+v", bs.Principal, bs.Memberships)
	}
	decode[gen.MembershipList](t, "TA users of B", adminB.get(app+"/tenants/"+w.B.ID.String()+"/users"))
	status(t, "TA of B on A", adminB.get(app+"/tenants/"+w.A.ID.String()), 404, gen.ProblemCodeNotFound)
	// the cookie of one origin is no session on the other
	stolen := newBrowser(t, api)
	stolen.jar[w.AdminHost] = map[string]string{identity.SessionCookieName: adminB.jar[w.AppHost][identity.SessionCookieName]}
	status(t, "app session on admin", stolen.get(admin+"/platform/tenants"), 401, gen.ProblemCodeUnauthenticated)

	// --- minted sessions (P2-T15a fixture) of the other seeded identities behave the same
	sa2 := w.Login(t, &sessionfixture.Actor{Role: authz.RoleSuperAdmin, Scope: identity.ScopePlatform,
		IdentityID: sas[1].IdentityID, IdPID: w.PlatformIdP, PlatformUserID: sas[1].PlatformUserID})
	if rec := do(api, sa2, "/platform/tenants"); rec.Code != http.StatusOK {
		t.Fatalf("SA 2 /platform/tenants: HTTP %d", rec.Code)
	}
	status(t, "SA 2 users of B", do(api, sa2, "/tenants/"+w.B.ID.String()+"/users"), 403, gen.ProblemCodeForbidden)
	toBs := w.Login(t, &sessionfixture.Actor{Role: authz.RoleTenantOwner, Scope: identity.ScopeTenant, Tenant: w.B,
		IdentityID: toB.IdentityID, IdPID: w.B.IdP, MembershipID: toB.MembershipID})
	if rec := do(api, toBs, "/tenants/"+w.B.ID.String()+"/audit"); rec.Code != http.StatusOK {
		t.Fatalf("TO of B audit: HTTP %d", rec.Code)
	}
	status(t, "TO of B on A's users", do(api, toBs, "/tenants/"+w.A.ID.String()+"/users"), 404, gen.ProblemCodeNotFound)
	taAs := w.Login(t, &sessionfixture.Actor{Role: authz.RoleTenantAdmin, Scope: identity.ScopeTenant, Tenant: w.A,
		IdentityID: taA.IdentityID, IdPID: w.A.IdP, MembershipID: taA.MembershipID})
	status(t, "TA of A on platform audit", do(api, taAs, "/platform/audit"), 403, gen.ProblemCodeForbidden)
	status(t, "TA of A on B", do(api, taAs, "/tenants/"+w.B.ID.String()), 404, gen.ProblemCodeNotFound)
}

// do sends GET path (below /api/v1) with a minted session through h.
func do(h http.Handler, s *sessionfixture.Session, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, s.Request(context.Background(), http.MethodGet, path, nil))
	return rec
}

// unaudited completes the hooks of this test with an explicit pass-through Audit hook: httpapi.New requires one once
// handlers are mounted (P2-T16); the audit of the composed API is tested by auditapi and the isolation suite.
func unaudited(h httpapi.Hooks) httpapi.Hooks {
	h.Audit = func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }
	return h
}
