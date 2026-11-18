package keycloak

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/idptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// TestAdoptedRealmUsesTheProvisioner (P4-T09): a tenant registration whose driver_ref is a bare realm name (a realm
// imported from the template and adopted by idp-bootstrap — Phase 1 tenants) has no mg-idp-driver secret, so the user
// operations read the provisioning identity's secret; the JSON driver_ref keeps using the realm's own service account;
// the master realm, a malformed name and a platform registration with a bare name are refused before any read.
func TestAdoptedRealmUsesTheProvisioner(t *testing.T) {
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
	provisioner := "mgsec://platform/idp.keycloak.provisioner#1"
	reg := idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: uuid.New(), DriverRef: "tenant-a"}
	if _, err := d.DisableUser(t.Context(), reg, uuid.NewString()); idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("DisableUser on an adopted realm: %v", err)
	}
	if _, err := d.InviteUser(t.Context(), reg, idp.Invite{Email: "a@example.test"}); idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("InviteUser on an adopted realm: %v", err)
	}
	if len(st.Reads) < 2 || slices.ContainsFunc(st.Reads, func(r string) bool { return r != provisioner }) {
		t.Fatalf("secrets read %v, want the provisioner's only", st.Reads)
	}
	st.Reads = nil
	reg.DriverRef = DriverRef{Realm: "tenant-a", DriverSecret: driverSecretRef(reg.IdPID).String()}.Encode()
	if _, err := d.DisableUser(t.Context(), reg, uuid.NewString()); idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("DisableUser with the realm's service account: %v", err)
	}
	if len(st.Reads) == 0 || slices.Contains(st.Reads, provisioner) {
		t.Fatalf("secrets read %v, want the realm's mg-idp-driver secret", st.Reads)
	}
	st.Reads = nil
	for _, bad := range []idp.Registration{
		{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: uuid.New(), DriverRef: "master"},
		{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: uuid.New(), DriverRef: "Tenant_A"},
		{IdPID: uuid.New(), Scope: idp.ScopePlatform, DriverRef: "platform"},
	} {
		if _, err := d.DisableUser(t.Context(), bad, uuid.NewString()); idp.CodeOf(err) != idp.CodeInvalidArgument {
			t.Errorf("%+v: %v, want invalid_argument", bad, err)
		}
	}
	if len(st.Reads) != 0 || requests.Load() != 0 {
		t.Fatalf("refused registrations read %v and sent %d requests", st.Reads, requests.Load())
	}
}
