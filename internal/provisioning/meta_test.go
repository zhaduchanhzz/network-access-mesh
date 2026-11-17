package provisioning

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// metaJSON is meta/instance.json exactly as tools/render_instance.py writes it (sorted keys, indent 2).
const metaJSON = `{
  "config_sha256": "0f4c6e5d2a8b9c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
  "image": "docker.io/headscale/headscale@sha256:11f81665e842809db9fe3006a38c56a66e968baa5abd4bac498e86445572b970",
  "instance_id": "0a583337-d4b0-4cd0-a52e-d99e4a812707",
  "net_cidr": "10.250.0.0/29",
  "run_uid": 30001,
  "slug": "tenant-a",
  "template_version": "1",
  "tenant_id": "61668e62-4fc4-4c5c-85c1-60f692d645b9"
}
`

func TestParseMeta(t *testing.T) {
	m, err := ParseMeta(strings.NewReader(metaJSON))
	if err != nil {
		t.Fatal(err)
	}
	if m.Slug != "tenant-a" || m.RunUID != 30001 || m.NetCIDR.String() != "10.250.0.0/29" ||
		m.TenantID.String() != "61668e62-4fc4-4c5c-85c1-60f692d645b9" ||
		m.InstanceID.String() != "0a583337-d4b0-4cd0-a52e-d99e4a812707" ||
		m.ImageDigest != "sha256:11f81665e842809db9fe3006a38c56a66e968baa5abd4bac498e86445572b970" ||
		m.TemplateVersion != "1" {
		t.Fatalf("ParseMeta = %+v", m)
	}

	replace := func(old, repl string) string { return strings.Replace(metaJSON, old, repl, 1) }
	bad := map[string]string{
		"unknown key":          replace(`"slug"`, `"edge_attach": true, "slug"`),
		"missing key":          replace(`"template_version": "1",`, ``),
		"upper-case uuid":      replace("61668e62-4fc4", "61668E62-4FC4"),
		"nil tenant":           replace("61668e62-4fc4-4c5c-85c1-60f692d645b9", "00000000-0000-0000-0000-000000000000"),
		"same ids":             replace("0a583337-d4b0-4cd0-a52e-d99e4a812707", "61668e62-4fc4-4c5c-85c1-60f692d645b9"),
		"slug with upper case": replace(`"tenant-a"`, `"Tenant-A"`),
		"slug with --":         replace(`"tenant-a"`, `"tenant--a"`),
		"reserved slug":        replace(`"tenant-a"`, `"admin"`),
		"punycode slug":        replace(`"tenant-a"`, `"xn--abc"`),
		"/28 network":          replace("10.250.0.0/29", "10.250.0.0/28"),
		"host bits":            replace("10.250.0.0/29", "10.250.0.1/29"),
		"ipv6 network":         replace("10.250.0.0/29", "fd00::/125"),
		"image by tag":         replace("@sha256:11f81665e842809db9fe3006a38c56a66e968baa5abd4bac498e86445572b970", ":0.29.7"),
		"run_uid 0":            replace("30001", "0"),
		"run_uid string":       replace("30001", `"30001"`),
		"config hash":          replace("0f4c6e5d", "zz4c6e5d"),
		"trailing data":        metaJSON + `{}`,
		"not json":             "slug=tenant-a",
		"too large":            metaJSON + strings.Repeat(" ", maxMetaFile),
	}
	for name, in := range bad {
		_, err := ParseMeta(strings.NewReader(in))
		if !errors.Is(err, ErrInvalidMeta) {
			t.Errorf("%s: err = %v, want ErrInvalidMeta", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "61668e62") {
			t.Errorf("%s: the error repeats a value: %v", name, err)
		}
	}
}

func TestValidAPIKey(t *testing.T) {
	// assembled at run time so that no literal looks like a credential to the secret scanner (.gitleaks.toml)
	pfx, rest := "AbC_1"+"2-xyZ09", strings.Repeat("s", 64)
	ok := "hskey-" + "api-" + pfx + "-" + rest
	if !ValidAPIKey(ok) {
		t.Fatal("valid key refused")
	}
	for _, k := range []string{
		"", ok + "x", ok[:len(ok)-1], "hskey-" + "auth-" + pfx + "-" + rest, strings.ToUpper(ok),
		"hskey-" + "api-" + pfx + "." + rest, " " + ok, ok + "\n", "hskey-" + "api-" + pfx[:11] + "-" + rest + "s",
	} {
		if ValidAPIKey(k) {
			t.Errorf("accepted %q", k)
		}
	}
}

// TestKeycloakRealmIdP pins the issuer and client of the realms rendered by tools/render_idp.py (issuers(), PORTAL).
func TestKeycloakRealmIdP(t *testing.T) {
	p := KeycloakRealmIdP(uuid.New(), nil, PlatformRealm, "example.test")
	if p.Scope != "platform" || p.Issuer != "https://auth.example.test/realms/platform" || p.ClientID != "mg-portal" ||
		p.Driver != "keycloak" || p.DriverRef != "platform" || p.TenantID != nil {
		t.Fatalf("platform realm: %+v", p)
	}
	tenant := uuid.New()
	p = KeycloakRealmIdP(uuid.New(), &tenant, "tenant-a", "example.test")
	if p.Scope != "tenant" || p.Issuer != "https://auth.example.test/realms/tenant-a" || *p.TenantID != tenant ||
		p.DriverRef != "tenant-a" {
		t.Fatalf("tenant realm: %+v", p)
	}
}
