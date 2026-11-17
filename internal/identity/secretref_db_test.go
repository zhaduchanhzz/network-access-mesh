package identity_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/external"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// appKeyring writes a kek-app keyring with one fresh KEK and loads it.
func appKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	dir := t.TempDir()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	for name, content := range map[string]string{"kek-1": hex.EncodeToString(b) + "\n", secrets.ActiveFile: "kek-1\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// TestForeignClientSecretRefRefused — G2 F3: identity_providers.client_secret_ref must name the IdP's own client
// secret: owner segment = the IdP's tenant (platform for the platform IdP) and name = the client secret of this IdP.
// A superuser points tenant A's IdP at tenant B's Headscale API key (the migration 0007 CHECK dropped first, as in a
// database not yet migrated or a constraint removed by hand), at A's own Headscale key, and at a platform secret: the
// callback fails closed before the SecretStore is read and before any token request (B's key never reaches A's IdP),
// and raises one security event; the external driver refuses to read (EnsureClient) or destroy (RemoveIssuer purge)
// the foreign secret, which stays intact.
func TestForeignClientSecretRefRefused(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	su := pg.Admin(t, db)
	st := pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8)
	ctx := t.Context()
	ss, err := secrets.New(st, secrets.Options{App: appKeyring(t)})
	if err != nil {
		t.Fatal(err)
	}
	logger, err := audit.New(st, pg.OpenAuditWriter(t, db), audit.Config{})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := su.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, sql)
		}
	}
	a, b, idpA := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-a', 'A', 'active'), ($2, 'tenant-b', 'B', 'active')`, a, b)
	fake := identity.NewFakeIdP(t, time.Now)
	own := secrets.TenantRef(a, "idp."+idpA.String()+".client", 1)
	if err := ss.Put(ctx, own, []byte("secret-of-a")); err != nil {
		t.Fatal(err)
	}
	keyB := secrets.TenantRef(b, "headscale-api-key", 1)
	hsKeyB := "hskey-api-" + identity.RandomHex(6) + "-" + identity.RandomHex(16) // the shape of a Headscale API key
	if err := ss.Put(ctx, keyB, []byte(hsKeyB)); err != nil {
		t.Fatal(err)
	}
	keyA := secrets.TenantRef(a, "headscale-api-key", 1)
	if err := ss.Put(ctx, keyA, []byte("hskey-api-"+identity.RandomHex(6)+"-"+identity.RandomHex(16))); err != nil {
		t.Fatal(err)
	}
	platformSecret := secrets.PlatformRef("idp."+idpA.String()+".client", 1)
	if err := ss.Put(ctx, platformSecret, []byte("platform-secret")); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'portal-a', $4, 'external', 'active')`, idpA, a, fake.Issuer, own.String())
	fake.AddClient("portal-a", "secret-of-a", redirectURI(appHost, idpA))
	fake.SetUser(identity.FakeUser{Sub: "alice", Email: "alice@a.test", EmailVerified: true})

	// The api's client-secret source as P2-T16 wires it: the SecretStore, which can decrypt a secret of any tenant.
	var reads atomic.Int32
	svc, err := identity.New(st, identity.Config{
		AppHost: appHost, AdminHost: adminHost, HTTPClient: &http.Client{Timeout: 5 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(ctx context.Context, s string) (string, error) {
			reads.Add(1)
			ref, err := secrets.ParseRef(s)
			if err != nil {
				return "", err
			}
			p, err := ss.Get(ctx, ref)
			if err != nil {
				return "", err
			}
			defer p.Wipe()
			return string(p.Bytes()), nil
		}),
		Logger: slog.New(slog.DiscardHandler), Auditor: auditapi.IdentityAuditor(logger),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, audit: &auditLog{}, secrets: map[string]string{}}
	e.h = svc.Middleware(gen.HandlerWithOptions(gen.NewStrictHandler(apiServer{Handlers: identityapi.New(svc)}, nil),
		gen.StdHTTPServerOptions{BaseURL: "/api/v1"}))
	query := "scope=tenant&tenant=tenant-a"

	exec(`ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS identity_providers_client_secret_ref_owner`)
	for name, ref := range map[string]secrets.Ref{
		"tenant B's Headscale API key":  keyB,
		"tenant A's own Headscale key":  keyA,
		"a platform secret of that IdP": platformSecret,
	} {
		exec(`UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, ref.String(), idpA)
		br := e.browser()
		rec := br.login(appHost, query)
		if rec.Code != http.StatusInternalServerError || problemCode(t, rec) != "internal_error" {
			t.Errorf("%s: callback HTTP %d %s, want 500 internal_error (fail closed)", name, rec.Code, rec.Body.String())
		}
		if br.cookie(appHost, identity.SessionCookieName) != "" {
			t.Errorf("%s: a session was created", name)
		}
		if n := reads.Load(); n != 0 {
			t.Errorf("%s: the SecretStore was read %d times", name, n)
		}
		if n := fake.TokenCalls.Load(); n != 0 {
			t.Errorf("%s: %d token requests reached the IdP", name, n)
		}
	}
	var events int
	if err := su.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE tenant_id IS NULL
			AND kind = $1 AND severity = 'high' AND details ->> 'idp_id' = $2`, idp.KindClientSecretRefNotOwned, idpA.String()).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("security events for the foreign references: %d, want 1 (deduplicated per IdP)", events)
	}

	// The external driver with the row as stored: no Get, no Destroy of B's key.
	h, err := idp.NewHardened(idp.HardenedConfig{})
	if err != nil {
		t.Fatal(err)
	}
	drv, err := external.New(external.Config{Client: h, Secrets: ss})
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, keyB.String(), idpA)
	var stored string
	if err := su.QueryRow(ctx, `SELECT client_secret_ref FROM identity_providers WHERE id = $1`, idpA).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	reg := idp.Registration{IdPID: idpA, Scope: idp.ScopeTenant, TenantID: a, Driver: idp.DriverExternal, Issuer: fake.Issuer,
		ClientID: "portal-a", ClientSecretRef: stored}
	if _, err := drv.EnsureClient(ctx, idp.ClientSpec{Registration: reg, ClientSecret: secrets.Plaintext("rotated")}); idp.CodeOf(err) != idp.Code("secret_ref_not_owned") {
		t.Errorf("EnsureClient with B's key as reference: %v, want secret_ref_not_owned", err)
	}
	if _, err := drv.RemoveIssuer(ctx, reg, idp.RemovePurge); idp.CodeOf(err) != idp.Code("secret_ref_not_owned") {
		t.Errorf("RemoveIssuer purge with B's key as reference: %v, want secret_ref_not_owned", err)
	}
	p, err := ss.Get(ctx, keyB)
	if err != nil || string(p.Bytes()) != hsKeyB {
		t.Fatalf("tenant B's Headscale key after the refusals: %v", err)
	}
	p.Wipe()
	if l, err := ss.Latest(ctx, a, own.Name); err != nil || l.Version != 1 {
		t.Errorf("the IdP's own secret changed: version %v (%v)", l.Version, err)
	}

	// Back to its own reference: the login works.
	exec(`UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, own.String(), idpA)
	br := e.browser()
	br.mustLogin(appHost, query)
	if reads.Load() != 1 || fake.TokenCalls.Load() != 1 {
		t.Fatalf("own reference: %d reads, %d token calls", reads.Load(), fake.TokenCalls.Load())
	}
}
