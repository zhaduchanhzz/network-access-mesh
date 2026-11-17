package idp

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// TestOwnClientSecretRef — G2 F3: the reference must be the IdP's own client secret — owner = its tenant (platform for
// the platform IdP), name = idp.<id>.client or idp-client-secret.<id>, any version; everything else is refused with
// CodeSecretRefNotOwned and the failed check as reason.
func TestOwnClientSecretRef(t *testing.T) {
	tenant, other, id := uuid.New(), uuid.New(), uuid.New()
	tr := Registration{IdPID: id, Scope: ScopeTenant, TenantID: tenant}
	pr := Registration{IdPID: id, Scope: ScopePlatform}
	with := func(r Registration, ref string) Registration { r.ClientSecretRef = ref; return r }
	cases := []struct {
		name   string
		reg    Registration
		reason string // "" = accepted
	}{
		{"tenant IdP, drivers' name", with(tr, secrets.TenantRef(tenant, ClientSecretName(id), 1).String()), ""},
		{"tenant IdP, admin command's name, version 7", with(tr, secrets.TenantRef(tenant, AdminClientSecretName(id), 7).String()), ""},
		{"platform IdP, drivers' name", with(pr, secrets.PlatformRef(ClientSecretName(id), 2).String()), ""},
		{"platform IdP, admin command's name", with(pr, secrets.PlatformRef(AdminClientSecretName(id), 1).String()), ""},
		{"another tenant's secret of the same name", with(tr, secrets.TenantRef(other, ClientSecretName(id), 1).String()), "owner"},
		{"a platform secret on a tenant IdP", with(tr, secrets.PlatformRef(ClientSecretName(id), 1).String()), "owner"},
		{"a tenant secret on the platform IdP", with(pr, secrets.TenantRef(tenant, ClientSecretName(id), 1).String()), "owner"},
		{"the tenant's Headscale API key", with(tr, secrets.TenantRef(tenant, "headscale-api-key", 1).String()), "name"},
		{"another IdP's client secret", with(tr, secrets.TenantRef(tenant, ClientSecretName(uuid.New()), 1).String()), "name"},
		{"a platform credential on the platform IdP", with(pr, secrets.PlatformRef("idp.keycloak.provisioner", 1).String()), "name"},
		{"a name that only starts like the IdP's", with(tr, secrets.TenantRef(tenant, ClientSecretName(id)+"x", 1).String()), "name"},
		{"not a reference", with(tr, "idp."+id.String()+".client"), "malformed"},
		{"upper-case owner", with(tr, "mgsec://"+tenant.String()[:8]+"X"+tenant.String()[9:]+"/"+ClientSecretName(id)+"#1"), "malformed"},
		{"no IdP id", with(Registration{Scope: ScopeTenant, TenantID: tenant}, secrets.TenantRef(tenant, ClientSecretName(uuid.Nil), 1).String()), "owner"},
		{"tenant scope without tenant", with(Registration{IdPID: id, Scope: ScopeTenant}, secrets.PlatformRef(ClientSecretName(id), 1).String()), "owner"},
		{"unknown scope", with(Registration{IdPID: id, Scope: "other", TenantID: tenant}, secrets.TenantRef(tenant, ClientSecretName(id), 1).String()), "owner"},
	}
	for _, c := range cases {
		ref, err := c.reg.OwnClientSecretRef("test")
		if c.reason == "" {
			if err != nil || ref.String() != c.reg.ClientSecretRef {
				t.Errorf("%s: %v (%s), want accepted", c.name, err, ref)
			}
			continue
		}
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeSecretRefNotOwned || e.Reason != c.reason || e.Op != "test" {
			t.Errorf("%s: %v, want %s (%s)", c.name, err, CodeSecretRefNotOwned, c.reason)
		}
	}
	if got := tr.ClientSecretOwner(3); got.Name != ClientSecretName(id) || got.Tenant != tenant || got.Version != 3 {
		t.Errorf("ClientSecretOwner = %v", got)
	}
}
