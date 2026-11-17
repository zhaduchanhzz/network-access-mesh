package headscale

import (
	"strings"
	"testing"
	"time"
)

// TestPolicyGuard: the adapter-side answer to the decoder leniency of V-06 (P2-T10 recorded what 0.29.7 does with
// each of these documents when they reach it).
func TestPolicyGuard(t *testing.T) {
	ok := []string{
		`{"grants":[]}`,
		`{"grants":[],"ssh":[]}`,
		`{"groups":{"group:eng":["mg-a@"]},"tagOwners":{"tag:web":["group:eng"]},"hosts":{"db":"10.0.0.5/32"},
		  "grants":[{"src":["group:eng"],"dst":["tag:web"],"ip":["tcp:443"]}],"ssh":[],
		  "tests":[{"src":"mg-a@","accept":["tag:web:443"]}],"autoApprovers":{"routes":{}},"nodeAttrs":[],
		  "sshTests":[],"randomizeClientPort":false,"acls":[]}`,
		"  {\"grants\":[]}\n",
	}
	for _, doc := range ok {
		if err := ValidatePolicyDocument(doc); err != nil {
			t.Errorf("rejected a valid document %s: %v", doc, err)
		}
	}
	bad := map[string]string{
		"empty (PL-06)":                 "",
		"whitespace":                    " \n\t",
		"no grants (allow-all)":         `{"ssh":[]}`,
		"empty object (allow-all)":      `{}`,
		"grants null (allow-all)":       `{"grants":null}`,
		"grants object":                 `{"grants":{}}`,
		"Grants spelling":               `{"Grants":[]}`,
		"GRANTS spelling":               `{"GRANTS":[]}`,
		"#grants at top level":          `{"grants":[],"#grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`,
		"#comment inside a grant":       `{"grants":[{"src":["*"],"#dst":["*"],"ip":["*"]}]}`,
		"duplicate grants":              `{"grants":[],"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`,
		"duplicate case-insensitive":    `{"grants":[],"tagOwners":{"tag:a":[],"TAG:A":[]}}`,
		"unknown top-level key":         `{"grants":[],"postures":{}}`,
		"HuJSON comment":                "{\"grants\":[] // deny all\n}",
		"trailing comma":                `{"grants":[],}`,
		"array at top level":            `[{"grants":[]}]`,
		"trailing data":                 `{"grants":[]} {"grants":null}`,
		"acls null":                     `{"grants":[],"acls":null}`,
		"not JSON":                      `grants: []`,
		"nested duplicate in an object": `{"grants":[],"hosts":{"db":"10.0.0.1/32","DB":"10.0.0.2/32"}}`,
	}
	for name, doc := range bad {
		if err := ValidatePolicyDocument(doc); err == nil {
			t.Errorf("%s: accepted %q", name, doc)
		}
	}
	if err := ValidatePolicyDocument(`{"grants":[],"x":"` + strings.Repeat("a", maxPolicyBytes) + `"}`); err == nil {
		t.Error("oversized document accepted")
	}
}

func TestNameRules(t *testing.T) {
	for _, n := range []string{"mg-11111111-1111-4111-8111-111111111111", "ab", "a.b_c-d", "alice@example.com", "tagged-devices"} {
		if err := ValidateUserName(n); err != nil {
			t.Errorf("user %q rejected: %v", n, err)
		}
	}
	for _, n := range []string{"", "a", "1abc", "-ab", "a b", "a/b", "a@b@c", "ä-user", "a%2fb", strings.Repeat("a", 129)} {
		if err := ValidateUserName(n); err == nil {
			t.Errorf("user %q accepted", n)
		}
	}
	for _, n := range []string{"web", "web-1", "a", "0a", strings.Repeat("a", 63)} {
		if err := ValidateGivenName(n); err != nil {
			t.Errorf("node name %q rejected: %v", n, err)
		}
	}
	for _, n := range []string{"", "Web", "web_1", "-web", "web-", "a.b", "a/b", strings.Repeat("a", 64)} {
		if err := ValidateGivenName(n); err == nil {
			t.Errorf("node name %q accepted", n)
		}
	}
	for _, tg := range []string{"tag:web", "tag:a1-b2"} {
		if err := ValidateTag(tg); err != nil {
			t.Errorf("tag %q rejected: %v", tg, err)
		}
	}
	for _, tg := range []string{"web", "tag:", "tag:Web", "tag:1web", "tag:a b", "Tag:web", "tag:web/1"} {
		if err := ValidateTag(tg); err == nil {
			t.Errorf("tag %q accepted", tg)
		}
	}
	good := testAuthID("x")
	if err := ValidateAuthID(good); err != nil {
		t.Errorf("auth id rejected: %v", err)
	}
	for _, id := range []string{good + "x", good[:len(good)-1], strings.Replace(good, "authreq", "auth", 1), "", strings.ToUpper(good)} {
		if err := ValidateAuthID(id); err == nil {
			t.Errorf("auth id %q accepted", id)
		}
	}
}

func TestParseVersion(t *testing.T) {
	v, err := ParseVersion("v0.29.7")
	if err != nil || v.Major != 0 || v.Minor != 29 || v.Patch != 7 || v.Raw != "v0.29.7" {
		t.Fatalf("ParseVersion = %+v, %v", v, err)
	}
	// Build metadata is refused — the reason the patched build (P2-T10a) keeps "v0.29.7" as its version and carries
	// the patch level in the /version commit field and the image labels instead of "v0.29.7+mg.1".
	for _, s := range []string{"0.29", "v0.29.7-rc1", "v0.29.07", "v0.29.x", "dev", "v0.29.7+meta", "v0.29.7+mg.1", "v0.29.7+dirty"} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
	if SupportedVersions() != ">= 0.29.7, < 0.30.0" {
		t.Errorf("supported = %s", SupportedVersions())
	}
}

func TestExpiryClamp(t *testing.T) {
	reg := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	const ninety = 90 * 24 * time.Hour
	exp := func(d time.Duration) *time.Time { x := reg.Add(d); return &x }
	cases := []struct {
		name  string
		node  Node
		clamp bool
	}{
		{"default expiry (registered + node.expiry + ms)", Node{Expiry: exp(ninety + 3*time.Millisecond)}, false},
		{"shorter than the tenant limit", Node{Expiry: exp(time.Hour)}, false},
		{"client asked for 10 years (V-21)", Node{Expiry: exp(10 * 365 * 24 * time.Hour)}, true},
		{"never expires", Node{}, true},
		{"tagged nodes are exempt", Node{Tags: []string{"tag:server"}}, false},
	}
	for _, tc := range cases {
		at, clamp := ExpiryClamp(tc.node, reg, ninety)
		if clamp != tc.clamp {
			t.Errorf("%s: clamp = %v", tc.name, clamp)
		}
		if clamp && !at.Equal(reg.Add(ninety)) {
			t.Errorf("%s: clamp to %s", tc.name, at)
		}
	}
	if _, clamp := ExpiryClamp(Node{}, reg, 0); clamp {
		t.Error("node_expiry 0 (never) must not clamp")
	}
}

func TestRetryDelayBounds(t *testing.T) {
	p := RetryPolicy{BaseDelay: 200 * time.Millisecond, MaxDelay: time.Second}.withDefaults()
	maxJ := func(n int64) int64 { return n - 1 }
	minJ := func(int64) int64 { return 0 }
	for n, want := range map[int][2]time.Duration{1: {100 * time.Millisecond, 200 * time.Millisecond},
		2: {200 * time.Millisecond, 400 * time.Millisecond}, 5: {500 * time.Millisecond, time.Second}, 40: {500 * time.Millisecond, time.Second}} {
		lo, hi := p.delay(n, minJ), p.delay(n, maxJ)
		if lo != want[0] || hi != want[1] {
			t.Errorf("attempt %d: [%s, %s], want %v", n, lo, hi, want)
		}
	}
}
