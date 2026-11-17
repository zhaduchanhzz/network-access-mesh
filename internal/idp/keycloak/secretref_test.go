package keycloak

import (
	"crypto/x509"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/idptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// TestClientSecretRefMustBeTheIdPsOwn — G2 F3, same rule as the external driver: EnsureClient (which reads the stored
// client secret to compare it with Keycloak's) and RemoveIssuer purge (which destroys it) refuse a client_secret_ref
// that is not the IdP's own with secret_ref_not_owned, before any call to Keycloak and without reading or destroying
// the foreign secret; one security event per refusal.
func TestClientSecretRefMustBeTheIdPsOwn(t *testing.T) {
	f := &fakeKC{secret: "s3cr3t", expiresIn: 300}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: "example.com", Address: srv.Listener.Addr().String(), RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	st, rec := idptest.NewSecrets(), &idptest.Security{}
	d, err := New(Config{Route: route, Secrets: st, Security: rec, AppHost: "app.example.org", AdminHost: "admin.example.org",
		Provisioner: Credentials{ClientID: DefaultProvisionerClientID, Secret: secrets.PlatformRef("idp.test.provisioner", 1)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	tenant, idpID := uuid.New(), uuid.New()
	foreign := secrets.TenantRef(uuid.New(), "headscale-api-key", 1)
	if err := st.Put(ctx, foreign, []byte("hskey-api-victim")); err != nil {
		t.Fatal(err)
	}
	reg := idp.Registration{IdPID: idpID, Scope: idp.ScopeTenant, TenantID: tenant, Driver: idp.DriverKeycloak,
		ClientSecretRef: foreign.String(),
		DriverRef:       DriverRef{Realm: "tenant-a", DriverSecret: driverSecretRef(idpID).String()}.Encode()}
	if _, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: reg}); idp.CodeOf(err) != idp.CodeSecretRefNotOwned {
		t.Errorf("EnsureClient: %v, want %s", err, idp.CodeSecretRefNotOwned)
	}
	if _, err := d.RemoveIssuer(ctx, reg, idp.RemovePurge); idp.CodeOf(err) != idp.CodeSecretRefNotOwned {
		t.Errorf("RemoveIssuer purge: %v, want %s", err, idp.CodeSecretRefNotOwned)
	}
	if len(st.Reads) != 0 || st.Destroyed(foreign) || st.Value(foreign) != "hskey-api-victim" {
		t.Errorf("the foreign secret was read (%v) or destroyed (%v)", st.Reads, st.Destroyed(foreign))
	}
	f.mu.Lock()
	calls := len(f.calls)
	f.mu.Unlock()
	if calls != 0 {
		t.Errorf("%d calls reached Keycloak", calls)
	}
	evs := rec.Events()
	if len(evs) != 2 {
		t.Fatalf("%d security events, want 2", len(evs))
	}
	for _, ev := range evs {
		if ev.Kind != idp.KindClientSecretRefNotOwned || ev.Details["idp_id"] != idpID || ev.Details["check"] != "owner" {
			t.Errorf("security event %+v", ev)
		}
	}
}
