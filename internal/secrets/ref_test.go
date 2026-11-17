package secrets

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRefRoundTrip(t *testing.T) {
	tenant := uuid.MustParse("0195f3a2-7c41-7b9e-8d2a-5f0e6c1b9a77")
	for _, r := range []Ref{
		TenantRef(tenant, "headscale.apikey.0195f3a2", 1),
		TenantRef(tenant, "a", 2147483647),
		PlatformRef("oidc.portal_client-secret", 12),
	} {
		s := r.String()
		got, err := ParseRef(s)
		if err != nil || got != r {
			t.Errorf("ParseRef(%q) = %+v, %v; want %+v", s, got, err, r)
		}
		// the CHECK on tenant_instances.api_key_secret_ref (0001)
		if !regexp.MustCompile(`^mgsec://[^/]+/[^#]+#[0-9]+$`).MatchString(s) {
			t.Errorf("%q does not match the reference CHECK of 0001", s)
		}
	}
	if got := PlatformRef("smtp.password", 3).String(); got != "mgsec://platform/smtp.password#3" {
		t.Errorf("String() = %q", got)
	}
}

func TestParseRefRejectsNonCanonical(t *testing.T) {
	const tenant = "0195f3a2-7c41-7b9e-8d2a-5f0e6c1b9a77"
	for _, s := range []string{
		"",
		"mgsec://",
		"MGSEC://platform/x#1",
		" mgsec://platform/x#1",
		"mgsec://platform/x",
		"mgsec://platform#1",
		"mgsec://platform/#1",
		"mgsec://platform/X#1",
		"mgsec://platform/x y#1",
		"mgsec://platform/a/b#1",
		"mgsec://platform/a|b#1",
		"mgsec://platform/x#0",
		"mgsec://platform/x#01",
		"mgsec://platform/x#-1",
		"mgsec://platform/x#+1",
		"mgsec://platform/x#2147483648",
		"mgsec://platform/x#1#2",
		"mgsec://platform/x#1 ",
		"mgsec://Platform/x#1",
		"mgsec://00000000-0000-0000-0000-000000000000/x#1",
		"mgsec://" + strings.ToUpper(tenant) + "/x#1",
		"mgsec://{" + tenant + "}/x#1",
		"mgsec://urn:uuid:" + tenant + "/x#1",
		"mgsec://" + strings.ReplaceAll(tenant, "-", "") + "/x#1",
		"mgsec://platform/" + strings.Repeat("a", 129) + "#1",
	} {
		if r, err := ParseRef(s); err == nil {
			t.Errorf("ParseRef(%q) = %+v, want an error", s, r)
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseRef(%q): %v does not wrap ErrInvalid", s, err)
		}
	}
	// a secret value passed where a reference belongs must not reach the error (and from there a log line)
	const canary = "CANARY-ref-9f2c"
	for _, s := range []string{canary, "mgsec://platform/" + canary + "#1", "mgsec://" + canary + "/x#1"} {
		if _, err := ParseRef(s); err == nil || strings.Contains(err.Error(), canary) {
			t.Errorf("ParseRef(%q): err = %v (must fail without quoting the input)", s, err)
		}
	}
	if err := (Ref{Name: "CANARY-x", Version: 1}).Validate(); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Errorf("Validate: err = %v", err)
	}
}

func TestOwnerValidate(t *testing.T) {
	id := uuid.New()
	for _, o := range []Owner{TenantOwner(id), PlatformOwner, PlatformOpsOwner} {
		if err := o.validate(); err != nil {
			t.Errorf("%v: %v", o, err)
		}
	}
	for _, o := range []Owner{TenantOwner(uuid.Nil), {Scope: ScopePlatform, Tenant: id}, {Scope: "other"}} {
		if err := o.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: err = %v, want ErrInvalid", o, err)
		}
	}
}
