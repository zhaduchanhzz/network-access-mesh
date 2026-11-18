//go:build mgtestfixture

package isolation_test

// IT-01 (§5.2 boundary 1, §8.4 invariant 1) through the composed API of the api process with real OIDC logins against
// a fake IdP per tenant and one for the platform (identitytest.FakeIdP): an identity of tenant A's IdP never gets a
// session, a membership or a right in tenant B or on the platform — even when its subject collides with a member of B,
// when A's IdP signs a token for B's login or for the platform's, or when the application role tries to give it a
// membership of B (issuer binding, composite foreign key). The module-level proofs of P2-T06 stay where they are
// (internal/identity: TestTenantIssuerIsolation, TestIdPMixUpRejectedBeforeTokenCall — IT-01b,
// TestSharedIssuerOrganisationConstraint — IT-01c); this test adds the composed chain and the data each refusal leaves.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// browser keeps the cookies of one host and drives a login through the composed API and a fake IdP.
type browser struct {
	t    *testing.T
	w    *sessionfixture.World
	host string
	jar  map[string]string
}

func (b *browser) get(rawURL string) *httptest.ResponseRecorder {
	b.t.Helper()
	r := httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, rawURL, nil)
	for k, v := range b.jar {
		r.AddCookie(&http.Cookie{Name: k, Value: v}) //nolint:gosec // request cookie
	}
	rec := httptest.NewRecorder()
	b.w.API.ServeHTTP(rec, r)
	for _, line := range rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			b.t.Fatalf("Set-Cookie: %v", err)
		}
		if c.MaxAge < 0 {
			delete(b.jar, c.Name)
		} else {
			b.jar[c.Name] = c.Value
		}
	}
	return rec
}

// login runs GET /auth/login → the fake IdP's authorization endpoint → GET /auth/callback and returns the answer of
// the callback.
func (b *browser) login(query string) *httptest.ResponseRecorder {
	b.t.Helper()
	start := b.get("https://" + b.host + "/api/v1/auth/login?" + query)
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
	return b.get(resp.Header.Get("Location"))
}

func (b *browser) session() (int, gen.Session) {
	b.t.Helper()
	rec := b.get("https://" + b.host + "/api/v1/auth/session")
	var s gen.Session
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	return rec.Code, s
}

func wantSQLState(t *testing.T, what string, err error, code string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != code {
		t.Errorf("%s: %v, want SQLSTATE %s", what, err, code)
	}
}

func TestIT01IdentityIsolation(t *testing.T) {
	secretOf := map[string]string{}
	w := sessionfixture.New(t, sessionfixture.Options{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, ref string) (string, error) {
			if s, ok := secretOf[ref]; ok {
				return s, nil
			}
			return "", errors.New("unknown secret reference")
		}),
	})
	// Point the fixture's IdPs (A, B, platform) at three fake OpenID Providers.
	fake := map[uuid.UUID]*identitytest.FakeIdP{}
	for _, idp := range []struct {
		id    uuid.UUID
		owner string
		host  string
	}{{w.A.IdP, w.A.ID.String(), w.AppHost}, {w.B.IdP, w.B.ID.String(), w.AppHost}, {w.PlatformIdP, "platform", w.AdminHost}} {
		f := identitytest.NewFakeIdP(t, time.Now)
		client := "portal-" + idp.id.String()[:8]
		ref := "mgsec://" + idp.owner + "/idp." + idp.id.String() + ".client#1" // the IdP's own secret (G2 F3)
		secretOf[ref] = "secret-" + uuid.NewString()
		f.AddClient(client, secretOf[ref], "https://"+idp.host+"/api/v1/auth/callback/"+idp.id.String())
		w.Exec(t, `UPDATE identity_providers SET issuer = $1, client_id = $2, client_secret_ref = $3, driver = 'external'
			WHERE id = $4`, f.Issuer, client, ref, idp.id)
		fake[idp.id] = f
	}
	fakeA, fakeB, fakeP := fake[w.A.IdP], fake[w.B.IdP], fake[w.PlatformIdP]
	count := func(sql string, args ...any) int64 {
		var n int64
		w.Scan(t, sql, args, &n)
		return n
	}
	ownerB := w.Actor(t, authz.RoleTenantOwner, w.B)
	sessionsOf := func(id uuid.UUID) int64 { return count(`SELECT count(*) FROM sessions WHERE identity_id = $1`, id) }

	// 1. Subject collision: A's IdP authenticates a user whose sub is exactly that of B's Owner. The login on A's flow
	// creates a NEW identity bound to A (no membership anywhere); B's Owner is untouched; every tenant operation of B
	// answers 404 to it.
	fakeA.SetUser(identitytest.FakeUser{Sub: ownerB.Subject, Email: ownerB.Email, EmailVerified: true, Name: "Collision"})
	ownerBSessions := sessionsOf(ownerB.IdentityID)
	b := &browser{t: t, w: w, host: w.AppHost, jar: map[string]string{}}
	if rec := b.login("scope=tenant&tenant=" + w.A.Slug); rec.Code != http.StatusFound {
		t.Fatalf("login of A's user: HTTP %d %s", rec.Code, rec.Body.String())
	}
	code, s := b.session()
	if code != http.StatusOK || s.Principal.IdpId != w.A.IdP || s.Principal.IdentityId == ownerB.IdentityID || len(s.Memberships) != 0 {
		t.Fatalf("IT-01: session of A's user: HTTP %d principal %+v memberships %+v", code, s.Principal, s.Memberships)
	}
	var tenantOf uuid.UUID
	w.Scan(t, `SELECT tenant_id FROM identities WHERE id = $1 AND idp_id = $2 AND subject = $3`,
		[]any{s.Principal.IdentityId, w.A.IdP, ownerB.Subject}, &tenantOf)
	if tenantOf != w.A.ID {
		t.Errorf("IT-01: the identity of A's IdP is bound to tenant %s, want A", tenantOf)
	}
	if n := sessionsOf(ownerB.IdentityID); n != ownerBSessions {
		t.Errorf("IT-01: the login of A's user changed the sessions of B's Owner (%d → %d)", ownerBSessions, n)
	}
	var probed int
	for _, op := range authz.Operations() {
		if !op.TenantScoped() || op.Method != http.MethodGet {
			continue
		}
		path := strings.ReplaceAll(op.Path, "{tenantId}", w.B.ID.String())
		for _, p := range []string{"{deviceId}", "{membershipId}", "{jobId}", "{approvalId}", "{invitationId}", "{groupId}"} {
			path = strings.ReplaceAll(path, p, uuid.NewString())
		}
		if strings.Contains(path, "{") {
			t.Fatalf("IT-01: %s: path parameter left in %s — add it to the list above", op.ID, path)
		}
		probed++
		rec := b.get("https://" + w.AppHost + "/api/v1" + path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("IT-01: %s on tenant B with A's identity: HTTP %d, want 404", op.ID, rec.Code)
		}
	}

	// 2. A token of issuer A (signed by A, A's audience) answered by B's IdP on B's login flow ⇒ 401, no identity of
	// B's IdP, no session.
	fakeB.Override(func(c map[string]any) string {
		c["iss"], c["sub"] = fakeA.Issuer, "forged-"+uuid.NewString()
		return identitytest.SignRS256(fakeA.Key, fakeA.KID, c)
	})
	identitiesB, sessionsBefore := count(`SELECT count(*) FROM identities WHERE idp_id = $1`, w.B.IdP), count(`SELECT count(*) FROM sessions`)
	bb := &browser{t: t, w: w, host: w.AppHost, jar: map[string]string{}}
	if rec := bb.login("scope=tenant&tenant=" + w.B.Slug); rec.Code != http.StatusUnauthorized {
		t.Errorf("IT-01: token of issuer A on B's login: HTTP %d, want 401", rec.Code)
	}
	if code, _ := bb.session(); code != http.StatusUnauthorized {
		t.Errorf("IT-01: a session exists after the refused login (HTTP %d)", code)
	}
	if n := count(`SELECT count(*) FROM identities WHERE idp_id = $1`, w.B.IdP); n != identitiesB {
		t.Errorf("IT-01: identities of B's IdP %d → %d after a token of issuer A", identitiesB, n)
	}
	if n := count(`SELECT count(*) FROM sessions`); n != sessionsBefore {
		t.Errorf("IT-01: sessions %d → %d after a token of issuer A on B's login", sessionsBefore, n)
	}
	// …and B's own key vouching for a token that names issuer A (a tenant IdP impersonating another): refused on iss.
	fakeB.Override(func(c map[string]any) string {
		c["iss"], c["sub"] = fakeA.Issuer, "forged-"+uuid.NewString()
		return identitytest.SignRS256(fakeB.Key, fakeB.KID, c)
	})
	bb = &browser{t: t, w: w, host: w.AppHost, jar: map[string]string{}}
	if rec := bb.login("scope=tenant&tenant=" + w.B.Slug); rec.Code != http.StatusUnauthorized {
		t.Errorf("IT-01: B-signed token naming issuer A on B's login: HTTP %d, want 401", rec.Code)
	}
	if n := count(`SELECT count(*) FROM identities WHERE idp_id = $1`, w.B.IdP); n != identitiesB {
		t.Errorf("IT-01: identities of B's IdP %d → %d after a token naming issuer A", identitiesB, n)
	}
	fakeB.Override(nil)

	// 3. A compromised tenant IdP cannot reach the platform: A's IdP signs the answer of the platform login ⇒ 401, no
	// platform identity, no platform user; A's user has no session on the admin origin.
	fakeP.Override(func(c map[string]any) string {
		c["iss"] = fakeA.Issuer
		return identitytest.SignRS256(fakeA.Key, fakeA.KID, c)
	})
	platformIdentities := count(`SELECT count(*) FROM identities WHERE scope = 'platform'`)
	pb := &browser{t: t, w: w, host: w.AdminHost, jar: map[string]string{}}
	if rec := pb.login("scope=platform"); rec.Code != http.StatusUnauthorized {
		t.Errorf("IT-01: token of tenant A's IdP on the platform login: HTTP %d, want 401", rec.Code)
	}
	if n := count(`SELECT count(*) FROM identities WHERE scope = 'platform'`); n != platformIdentities {
		t.Errorf("IT-01: platform identities %d → %d after a token of tenant A's IdP", platformIdentities, n)
	}
	fakeP.Override(nil)
	cookie := b.jar[identity.SessionCookieName]
	onAdmin := &browser{t: t, w: w, host: w.AdminHost, jar: map[string]string{identity.SessionCookieName: cookie}}
	if code, _ := onAdmin.session(); code != http.StatusUnauthorized {
		t.Errorf("IT-01: the session of A's user on the admin origin: HTTP %d, want 401", code)
	}
	if rec := onAdmin.get("https://" + w.AdminHost + "/api/v1/platform/tenants"); rec.Code != http.StatusUnauthorized {
		t.Errorf("IT-01: GET /platform/tenants with A's user's cookie: HTTP %d, want 401", rec.Code)
	}

	// 4. Issuer binding in the database, through the application pools: a membership of B for the identity of A's
	// IdP, or a platform user made of it, is refused by the composite foreign keys (23503) — whoever writes it.
	var roleTV uuid.UUID
	w.Scan(t, `SELECT id FROM roles WHERE scope = 'tenant' AND key = $1`, []any{authz.RoleTenantViewer}, &roleTV)
	err := w.Store.WithTenantTx(t.Context(), w.B.ID, func(q *sqlcdb.Queries) error {
		_, err := q.CreateTenantMembership(t.Context(), sqlcdb.CreateTenantMembershipParams{
			TenantID: w.B.ID, IdentityID: s.Principal.IdentityId, RoleID: roleTV})
		return err
	})
	wantSQLState(t, "IT-01: membership of B for an identity of A's IdP (api tenant pool)", err, "23503")
	err = w.Store.WithTenantTx(t.Context(), w.A.ID, func(q *sqlcdb.Queries) error {
		_, err := q.CreateTenantMembership(t.Context(), sqlcdb.CreateTenantMembershipParams{
			TenantID: w.A.ID, IdentityID: ownerB.IdentityID, RoleID: roleTV})
		return err
	})
	wantSQLState(t, "IT-01: membership of A for an identity of B's IdP (api tenant pool)", err, "23503")
	su := storetest.Require(t).Admin(t, w.DB) // a superuser bypasses RLS, not foreign keys
	_, err = su.Exec(t.Context(), `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id) VALUES ($1, $2, $3)`,
		w.B.ID, s.Principal.IdentityId, roleTV)
	wantSQLState(t, "IT-01: membership of B for an identity of A's IdP (superuser)", err, "23503")
	_, err = su.Exec(t.Context(), `INSERT INTO platform_users (identity_id, role_id)
		SELECT $1, id FROM roles WHERE scope = 'platform' AND key = $2`, s.Principal.IdentityId, authz.RoleSuperAdmin)
	wantSQLState(t, "IT-01: platform user made of an identity of A's IdP (superuser)", err, "23503")
	if n := count(`SELECT count(*) FROM tenant_memberships WHERE identity_id = $1`, s.Principal.IdentityId); n != 0 {
		t.Errorf("IT-01: the identity of A's IdP holds %d memberships", n)
	}
	t.Logf("IT-01: %d tenant reads of B refused with 404 for A's identity; foreign tokens refused on B's and the platform's login", probed)
}
