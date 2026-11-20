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

// TestTemplateI18n (G4b-E14): the realm template turns i18n on with exactly the Portal's languages and a default among
// them, and a realm the driver creates carries them.
func TestTemplateI18n(t *testing.T) {
	want, err := templateI18n()
	if err != nil {
		t.Fatal(err)
	}
	if want["internationalizationEnabled"] != true || !sameJSON(want["supportedLocales"], []any{"en", "vi"}) ||
		(want["defaultLocale"] != "vi" && want["defaultLocale"] != "en") {
		t.Fatalf("template i18n %v", want)
	}
	rep, err := realmRep(realmParams{Realm: "t-x", Scope: idp.ScopePlatform, IdPID: uuid.New(), RedirectURI: "https://admin.example.test/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if len(diffKeys(want, rep, nil)) != 0 {
		t.Fatalf("realm rep i18n %v %v %v", rep["internationalizationEnabled"], rep["supportedLocales"], rep["defaultLocale"])
	}
}

// TestEnsureI18n (G4b-E14, repair of realms created before the template had i18n): a driver-created realm with i18n
// off gets the template's settings once — a second run, and a realm answering the locales in another order, change
// nothing; a rendered realm and a realm of another IdP are refused without a write.
func TestEnsureI18n(t *testing.T) {
	idpID := uuid.New()
	f := &fakeRealmKC{realm: map[string]any{"id": "x", "realm": "t-new", "internationalizationEnabled": false,
		"supportedLocales": []any{}, "attributes": map[string]any{"meshguard.idp_id": idpID.String(), "meshguard.scope": "tenant"}}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: "example.com", Address: srv.Listener.Addr().String(),
		RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	st := idptest.NewSecrets()
	pref := secrets.PlatformRef(ProvisionerRefName, 1)
	if err := st.Put(t.Context(), pref, []byte("prov-secret")); err != nil {
		t.Fatal(err)
	}
	// no relay: the i18n repair does not need one
	d, err := New(Config{Route: route, Secrets: st, AppHost: "app.example.test", AdminHost: "admin.example.test",
		Provisioner: Credentials{ClientID: DefaultProvisionerClientID, Secret: pref}})
	if err != nil {
		t.Fatal(err)
	}
	reg := idp.Registration{IdPID: idpID, Scope: idp.ScopeTenant, TenantID: uuid.New(), Driver: idp.DriverKeycloak,
		Issuer: "https://example.com/realms/t-new", ClientID: PortalClientID,
		DriverRef: DriverRef{Realm: "t-new", DriverSecret: driverSecretRef(idpID).String()}.Encode()}
	ctx := t.Context()
	if changed, err := d.EnsureI18n(ctx, reg); err != nil || !changed {
		t.Fatalf("first run: changed=%v err=%v", changed, err)
	}
	want, _ := templateI18n()
	if len(f.puts) != 1 || len(f.puts[0]) != len(i18nKeys) || len(diffKeys(want, f.puts[0], nil)) != 0 {
		t.Fatalf("PUTs %v", f.puts)
	}
	if changed, err := d.EnsureI18n(ctx, reg); err != nil || changed {
		t.Fatalf("second run: changed=%v err=%v", changed, err)
	}
	f.mu.Lock()
	f.realm["supportedLocales"] = []any{"en", "vi"} // Keycloak keeps a set: any order
	f.mu.Unlock()
	if changed, err := d.EnsureI18n(ctx, reg); err != nil || changed {
		t.Fatalf("locales in another order: changed=%v err=%v", changed, err)
	}
	adopted := reg
	adopted.DriverRef = "t-new"
	if _, err := d.EnsureI18n(ctx, adopted); idp.CodeOf(err) != idp.CodeUnsupported {
		t.Fatalf("adopted realm: %v", err)
	}
	other := reg
	other.IdPID = uuid.New()
	other.DriverRef = DriverRef{Realm: "t-new", DriverSecret: driverSecretRef(other.IdPID).String()}.Encode()
	if _, err := d.EnsureI18n(ctx, other); idp.CodeOf(err) != idp.CodeConflict {
		t.Fatalf("realm of another IdP: %v", err)
	}
	if len(f.puts) != 1 {
		t.Fatalf("idempotent / refused runs wrote: %v", f.puts)
	}
}
