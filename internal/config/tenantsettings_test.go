package config

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestSettingsDocView — defaults for missing or ill-typed keys; malformed values read as unset; sensitive groups
// sorted and deduplicated; dns as stored.
func TestSettingsDocView(t *testing.T) {
	g1, g2 := uuid.MustParse("00000000-0000-7000-8000-000000000002"), uuid.MustParse("00000000-0000-7000-8000-000000000001")
	for _, tc := range []struct {
		raw  string
		want func(TenantSettings) bool
	}{
		{``, func(s TenantSettings) bool {
			return s.Enrollment.IdentityMode == IdentityModePortal && s.Enrollment.WebAuthEnabled && !s.Enrollment.SelfEnroll &&
				!s.Policy.FourEyes && len(s.Policy.SensitiveGroups) == 0 && s.Notifications.NewDevice && s.NodeExpiry == "" &&
				string(s.DNS) == "{}"
		}},
		{`null`, func(s TenantSettings) bool { return s.Notifications.PolicyApplied }},
		{`{"enrollment":{"identity_mode":"weird","web_auth_enabled":"no","preauth_key_ttl_max":"1s"},"node_expiry":"forever"}`,
			func(s TenantSettings) bool {
				return s.Enrollment.IdentityMode == IdentityModePortal && s.Enrollment.WebAuthEnabled &&
					s.Enrollment.PreauthKeyTTLMax == "" && s.NodeExpiry == ""
			}},
		{`{"policy":{"four_eyes":true,"sensitive_groups":["` + g1.String() + `","x","` + g2.String() + `","` + g1.String() + `"]}}`,
			func(s TenantSettings) bool {
				return s.Policy.FourEyes && slices.Equal(s.Policy.SensitiveGroups, []uuid.UUID{g2, g1})
			}},
		{`{"node_expiry":"90d","dns":{"magic_dns":true},"routes":{"four_eyes":true},"notifications":{"new_device":false}}`,
			func(s TenantSettings) bool {
				return s.NodeExpiry == "90d" && strings.Contains(string(s.DNS), "magic_dns") && s.Routes.FourEyes &&
					!s.Notifications.NewDevice
			}},
	} {
		d, err := ParseSettingsDoc([]byte(tc.raw))
		if err != nil || !tc.want(d.View()) {
			t.Errorf("%q: %+v, %v", tc.raw, d.View(), err)
		}
	}
	for _, bad := range []string{`[]`, `1`, `{`, `{}{}`} {
		if _, err := ParseSettingsDoc([]byte(bad)); !errors.Is(err, ErrSettingsDocument) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// TestSettingsDocWrites — SetSecurity and Apply change their keys only; the ETag follows the content, not the key order.
func TestSettingsDocWrites(t *testing.T) {
	d, _ := ParseSettingsDoc([]byte(`{"dns":{"magic_dns":true},"future":{"k":[1,2]},"enrollment":{"preauth_key_ttl_max":"30m"}}`))
	g := uuid.New()
	d.SetSecurity(SecuritySettings{IdentityMode: IdentityModePortal, WebAuthEnabled: false, SelfEnroll: true,
		NodeExpiry: "30d", PolicyFourEyes: true, SensitiveGroups: []uuid.UUID{g}, RoutesFourEyes: true})
	ttl := ""
	off := false
	d.Apply(SettingsPatch{PreauthKeyTTLMax: &ttl, NewDevice: &off})
	raw, err := d.JSON()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"future":{"k":[1,2]}`, `"magic_dns":true`, `"node_expiry":"30d"`, `"self_enroll":true`,
		`"sensitive_groups":["` + g.String() + `"]`, `"new_device":false`} {
		if !strings.Contains(s, want) {
			t.Errorf("%s lacks %s", s, want)
		}
	}
	if strings.Contains(s, "preauth_key_ttl_max") {
		t.Errorf("an empty TTL bound must remove the key: %s", s)
	}
	d.SetSecurity(SecuritySettings{IdentityMode: IdentityModePortal})
	if raw, _ := d.JSON(); strings.Contains(string(raw), "node_expiry") {
		t.Errorf("an empty node_expiry must remove the key: %s", raw)
	}
	if SettingsETag([]byte(`{"a":1,"b":{"c":2}}`)) != SettingsETag([]byte(`{"b": {"c": 2}, "a": 1}`)) ||
		SettingsETag([]byte(`{"a":1}`)) == SettingsETag([]byte(`{"a":2}`)) || SettingsETag(nil) != SettingsETag([]byte(`{}`)) {
		t.Error("SettingsETag must depend on the content only")
	}
}

// TestWeakenings — what lifts a second-person control, and what does not.
func TestWeakenings(t *testing.T) {
	g1, g2 := uuid.New(), uuid.New()
	base := SecuritySettings{PolicyFourEyes: true, RoutesFourEyes: true, SensitiveGroups: []uuid.UUID{g1}}
	for _, tc := range []struct {
		name string
		mut  func(*SecuritySettings)
		want []string
	}{
		{"nothing", func(*SecuritySettings) {}, nil},
		{"policy 4-eyes off", func(s *SecuritySettings) { s.PolicyFourEyes = false }, []string{"policy.four_eyes"}},
		{"routes 4-eyes off", func(s *SecuritySettings) { s.RoutesFourEyes = false }, []string{"routes.four_eyes"}},
		{"group out", func(s *SecuritySettings) { s.SensitiveGroups = []uuid.UUID{g2} }, []string{"policy.sensitive_groups"}},
		{"group added", func(s *SecuritySettings) { s.SensitiveGroups = []uuid.UUID{g1, g2} }, nil},
		{"self-enroll on, node expiry", func(s *SecuritySettings) { s.SelfEnroll, s.NodeExpiry = true, "0" }, nil},
		{"all", func(s *SecuritySettings) { s.PolicyFourEyes, s.RoutesFourEyes, s.SensitiveGroups = false, false, nil },
			[]string{"policy.four_eyes", "routes.four_eyes", "policy.sensitive_groups"}},
	} {
		after := base.Security()
		tc.mut(&after)
		if got := Weakenings(base, after); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if !base.Equal(base.Security()) || base.Equal(SecuritySettings{}) {
		t.Error("Equal")
	}
}

// Security returns s (for the table above).
func (s SecuritySettings) Security() SecuritySettings {
	s.SensitiveGroups = slices.Clone(s.SensitiveGroups)
	return s
}

func TestDurations(t *testing.T) {
	for v, ok := range map[string]bool{"0": true, "1d": true, "3650d": true, "3651d": false, "87600h": true, "87601h": false,
		"0d": false, "01d": false, "2h": true, "90": false, "-1d": false, "1w": false, "": false} {
		if (CheckNodeExpiry(v) == nil) != ok {
			t.Errorf("node_expiry %q: want valid=%v", v, ok)
		}
	}
	for v, ok := range map[string]bool{"5m": true, "4m": false, "1h": true, "2160h": true, "2161h": false, "129600m": true,
		"129601m": false, "0m": false, "1d": false, "": false} {
		if (CheckPreauthKeyTTLMax(v) == nil) != ok {
			t.Errorf("preauth_key_ttl_max %q: want valid=%v", v, ok)
		}
	}
}

func TestSystemSettings(t *testing.T) {
	if _, ok := LookupSystemSetting("idp.audit_sync.admin.platform"); ok {
		t.Error("an internal cursor is served")
	}
	if s, ok := LookupSystemSetting(SettingMaintenance); !ok || s.Writable {
		t.Error("maintenance must be served read-only")
	}
	if _, err := (SystemSetting{Key: SettingMaintenance}).CheckValue([]byte(`{}`)); !errors.Is(err, ErrSettingReadOnly) {
		t.Errorf("maintenance write: %v", err)
	}
	ttl, _ := LookupSystemSetting(SettingApprovalTTLHours)
	for v, ok := range map[string]bool{"1": true, "168": true, " 24 ": true, "0": false, "169": false, `"24"`: false,
		"24.0": false, "2e1": false, "024": false, "null": false} {
		if _, err := ttl.CheckValue([]byte(v)); (err == nil) != ok {
			t.Errorf("approval.ttl_hours %q: %v", v, err)
		}
	}
	keys := []string{}
	for _, s := range SystemSettings() {
		keys = append(keys, s.Key)
	}
	if !slices.IsSorted(keys) || len(keys) != 3 {
		t.Errorf("served keys %v", keys)
	}
}

func TestIdPClaims(t *testing.T) {
	for raw, ok := range map[string]bool{`{}`: true, `{"hd":"a.test"}`: true, `{"tid":["x","y"],"amr":["otp"]}`: true,
		`{"n":1,"b":true}`: true, `{"hd":{"x":1}}`: false, `{"hd":[]}`: false, `{"hd":null}`: false, `{"sub":"x"}`: false,
		`{"iss":"x"}`: false, `{"bad name":"x"}`: false, `{"hd":""}`: false, `[]`: false, `{"hd":[{"a":1}]}`: false} {
		if _, err := ParseRequiredClaims([]byte(raw)); (err == nil) != ok {
			t.Errorf("required_claims %s: %v", raw, err)
		}
	}
	d, err := NormalizeEmailDomains([]string{" B.test", "a.test", "b.test"})
	if err != nil || !slices.Equal(d, []string{"a.test", "b.test"}) {
		t.Errorf("domains: %v, %v", d, err)
	}
	for _, bad := range []string{"localhost", "a..test", "-a.test", "a.test.", "*.a.test"} {
		if _, err := NormalizeEmailDomains([]string{bad}); !errors.Is(err, ErrIdPClaims) {
			t.Errorf("domain %q: %v", bad, err)
		}
	}
	if err := CheckClaimMapping(map[string]string{"email": "upn", "name": "preferred_username"}); err != nil {
		t.Error(err)
	}
	if f, _ := ClaimsErrorField(CheckClaimMapping(map[string]string{"role": "x"})); f != "claim_mapping" {
		t.Errorf("unknown mapped field: %q", f)
	}
}
