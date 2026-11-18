package policies

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLintRules: every refusal of the core's lint, with the rule that fires — L2 and L1 are the verification of
// P3-T08a ("chuỗi rỗng/thiếu grants bị chặn").
func TestLintRules(t *testing.T) {
	big := `{"grants":[],"hosts":{"h":"10.0.0.1/32"},"tests":[` + strings.Repeat(`{"src":"a@","accept":["b:1"]},`, 40000) + `{}]}`
	cases := []struct {
		name, doc, rule string
	}{
		{"empty", "", RuleL2},
		{"whitespace", " \n\t\r\n ", RuleL2},
		{"only a comment", "// nothing here\n", RuleSyntax},
		{"not hujson", `{"grants": [}`, RuleSyntax},
		{"array at top", `[]`, RuleSyntax},
		{"string at top", `"grants"`, RuleSyntax},
		{"trailing data", `{"grants":[]} {}`, RuleSyntax},
		{"not utf-8", "{\"grants\":[],\"hosts\":{\"\xff\":\"10.0.0.1/32\"}}", RuleSyntax},
		{"NUL", "{\"grants\":[]}\x00", RuleSyntax},
		{"too large", big, RuleSyntax},
		{"no grants", `{"ssh": []}`, RuleL1},
		{"only tagOwners and groups", `{"tagOwners": {"tag:a": []}, "groups": {"group:x": []}}`, RuleL1},
		{"acls only", `{"acls": [{"action":"accept","src":["*"],"dst":["*:*"]}]}`, RuleL1},
		{"grants null", `{"grants": null}`, RuleL1},
		{"grants object", `{"grants": {}}`, RuleL1},
		{"grants string", `{"grants": "[]"}`, RuleL1},
		{"grants twice", `{"grants": [], "grants": []}`, RuleL1},
		{"Grants (case)", `{"Grants": []}`, RuleL1},
		{"hash member", `{"grants": [], "#grants": []}`, RuleDecoderGuard},
		{"hash member nested", `{"grants": [{"src":["*"],"dst":["*"],"ip":["*"],"#via":["tag:x"]}]}`, RuleDecoderGuard},
		{"case duplicate", `{"grants": [], "GRANTS": []}`, RuleDecoderGuard},
		{"unknown key", `{"grants": [], "nodeattrs": []}`, RuleDecoderGuard},
		{"acls not array", `{"grants": [], "acls": {}}`, RuleDecoderGuard},
	}
	for _, c := range cases {
		_, err := Lint(c.doc)
		le, ok := IsLint(err)
		switch {
		case !ok:
			t.Errorf("%s: err = %v, want lint %s", c.name, err, c.rule)
		case le.Rule != c.rule:
			t.Errorf("%s: rule %s (%s), want %s", c.name, le.Rule, le.Detail, c.rule)
		case strings.Contains(le.Error(), c.doc) && len(c.doc) > 20:
			t.Errorf("%s: the error quotes the document: %s", c.name, le.Error())
		}
	}
}

// TestLintCodes: each rule has its stable error code.
func TestLintCodes(t *testing.T) {
	for rule, code := range map[string]string{RuleL1: "lint_l1_missing_grants", RuleL2: "lint_l2_empty",
		RuleSyntax: "lint_syntax", RuleDecoderGuard: "lint_decoder_guard"} {
		if got := (&LintError{Rule: rule}).Code(); got != code {
			t.Errorf("%s: code %s, want %s", rule, got, code)
		}
	}
}

// TestLintCanonicalRendering: the document sent is the standardized JSON — comments and trailing commas removed,
// two-space indentation, member order and literals kept; the same content in any layout renders the same bytes;
// content_sha256 is over the text as given, applied_sha256 over the rendering.
func TestLintCanonicalRendering(t *testing.T) {
	a := "// header comment\n{\n  /* block */ \"grants\": [\n    {\"src\": [\"autogroup:member\"], \"dst\": [\"autogroup:member\"], \"ip\": [\"tcp:8000\"],}, // trailing\n  ],\n  \"ssh\": [],\n}\n"
	b := `{"grants":[{"src":["autogroup:member"],"dst":["autogroup:member"],"ip":["tcp:8000"]}],"ssh":[]}`
	da, err := Lint(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Lint(b)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"grants\": [\n    {\n      \"src\": [\n        \"autogroup:member\"\n      ],\n      \"dst\": [\n        \"autogroup:member\"\n      ],\n      \"ip\": [\n        \"tcp:8000\"\n      ]\n    }\n  ],\n  \"ssh\": []\n}"
	if da.Applied != want || db.Applied != want {
		t.Fatalf("rendering:\n%s\n---\n%s\nwant\n%s", da.Applied, db.Applied, want)
	}
	if da.AppliedSHA256 != db.AppliedSHA256 || da.AppliedSHA256 != SHA256Hex(want) {
		t.Fatalf("applied sha256 differ: %s %s", da.AppliedSHA256, db.AppliedSHA256)
	}
	if da.ContentSHA256 == db.ContentSHA256 || da.ContentSHA256 != SHA256Hex(a) || da.HuJSON != a {
		t.Fatal("content sha256 must be over the text as given")
	}
	if strings.Contains(da.Applied, "//") || strings.Contains(da.Applied, "/*") || strings.Contains(da.Applied, ",\n  ]") {
		t.Fatalf("comments or trailing commas left: %s", da.Applied)
	}
}

// TestLintRepositoryFixtures: the policies the platform ships (deny-all baseline, suspension — P3-T08 —, allow fixture
// of §22.1) pass, and the allow fixture keeps its single grant.
func TestLintRepositoryFixtures(t *testing.T) {
	for _, name := range []string{"bootstrap-policy.hujson", "suspension-policy.hujson", "test-allow-intra.hujson"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "infrastructure", "headscale", "templates", name)) //nolint:gosec // G304: fixture of the repository
		if err != nil {
			t.Fatal(err)
		}
		d, err := Lint(string(b))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasPrefix(d.Applied, "{\n  \"grants\": [") || d.ContentSHA256 != SHA256Hex(string(b)) {
			t.Errorf("%s: rendering %q", name, d.Applied[:min(len(d.Applied), 40)])
		}
		if name == "test-allow-intra.hujson" && !strings.Contains(d.Applied, `"tcp:8000"`) {
			t.Errorf("%s: grant lost: %s", name, d.Applied)
		}
	}
}
