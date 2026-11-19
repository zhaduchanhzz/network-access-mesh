package policies

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// HuJSON import/export of the Policies editor (P4-T11).

type ioWorld struct {
	cat                               *NameCatalog
	alice, bob, carol, dave, nomail   uuid.UUID
	eng, ops, web, exit, db, srv      uuid.UUID
	tokenAlice, tokenBob, tokenNoMail string
}

func newIOWorld() ioWorld {
	w := ioWorld{alice: uuid.New(), bob: uuid.New(), carol: uuid.New(), dave: uuid.New(), nomail: uuid.New(),
		eng: uuid.New(), ops: uuid.New(), web: uuid.New(), exit: uuid.New(), db: uuid.New(), srv: uuid.New()}
	w.cat = NewNameCatalog(
		[]CatalogUser{
			{ID: w.alice, Email: "Alice@Example.test", Status: "active"},
			{ID: w.bob, Email: "shared@example.test", Status: "active"},
			{ID: w.carol, Email: "SHARED@example.test", Status: "locked"},
			{ID: w.dave, Email: "dave@example.test", Status: "offboarded"},
			{ID: w.nomail, Status: "active"},
		},
		[]NamedID{{ID: w.eng, Name: "eng"}, {ID: w.ops, Name: "ops"}},
		[]NamedID{{ID: w.web, Name: "tag:web"}, {ID: w.exit, Name: "tag:exit"}},
		[]NamedID{{ID: w.db, Name: "db"}, {ID: w.srv, Name: "srv-1"}},
	)
	w.tokenAlice, w.tokenBob, w.tokenNoMail = "Alice@Example.test", userToken(w.bob), userToken(w.nomail)
	return w
}

func pr(t, ref string) Principal { return Principal{Type: t, Ref: ref} }

// fullSource uses every principal type in every position the model allows.
func (w ioWorld) fullSource() PolicySource {
	return PolicySource{
		Grants: []Grant{
			{Src: []Principal{pr(PrincipalUser, w.alice.String()), pr(PrincipalUser, w.bob.String()), pr(PrincipalGroup, w.eng.String()),
				pr(PrincipalAutogroup, AutogroupMember)},
				Dst: []Principal{pr(PrincipalTag, w.web.String()), pr(PrincipalResource, w.db.String()), pr(PrincipalCIDR, "10.0.0.0/8"),
					pr(PrincipalCIDR, "fd7a::1"), pr(PrincipalAutogroup, AutogroupSelf)},
				IP: []string{"tcp:443", "udp:53"}},
			{Src: []Principal{pr(PrincipalUser, w.nomail.String())}, Dst: []Principal{pr(PrincipalAutogroup, AutogroupInternet)},
				IP: []string{"*"}, Via: []Principal{pr(PrincipalTag, w.exit.String())}},
			{Src: []Principal{pr(PrincipalGroup, w.ops.String())}, Dst: []Principal{pr(PrincipalResource, w.srv.String())},
				App: map[string][]map[string]any{"example.com/cap/x": {{"k": "v", "n": json.Number("2")}}}},
		},
		SSH: []SSHRule{{Action: SSHAccept, Src: []Principal{pr(PrincipalGroup, w.eng.String())},
			Dst: []Principal{pr(PrincipalTag, w.web.String())}, Users: []string{"root", "autogroup:nonroot"}}},
		AutoApprovers: &AutoApprovers{Routes: map[string][]Principal{"10.20.0.0/16": {pr(PrincipalTag, w.web.String())}},
			ExitNode: []Principal{pr(PrincipalTag, w.exit.String())}},
	}
}

func canon(t *testing.T, s PolicySource) string {
	t.Helper()
	b, _, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestHuJSONRoundTrip — export writes names (a unique e-mail, otherwise mg-<membership>@; group/tag/resource names;
// canonical addresses), is deterministic, and import of the export gives back the same canonical source.
func TestHuJSONRoundTrip(t *testing.T) {
	w := newIOWorld()
	src := w.fullSource()
	if err := src.Check(); err != nil {
		t.Fatal(err)
	}
	out, err := ExportHuJSON(src, w.cat)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ExportHuJSON(src, w.cat)
	if out.HuJSON != again.HuJSON {
		t.Fatal("export is not deterministic")
	}
	for _, want := range []string{"// MeshGuard policy", `"Alice@Example.test"`, `"` + w.tokenBob + `"`, `"` + w.tokenNoMail + `"`,
		`"group:eng"`, `"tag:web"`, `"db"`, `"10.0.0.0/8"`, `"fd7a::1"`, `"autogroup:self"`, `"via": [`, `"tag:exit"`,
		`"example.com/cap/x"`, `"ssh": [`, `"autoApprovers": {`, `"exitNode": [`, `"10.20.0.0/16"`} {
		if !strings.Contains(out.HuJSON, want) {
			t.Errorf("export lacks %s:\n%s", want, out.HuJSON)
		}
	}
	if strings.Contains(out.HuJSON, "shared@") || strings.Contains(out.HuJSON, `"ref"`) || len(out.Warnings) != 0 {
		t.Errorf("an ambiguous e-mail must not be written; no typed refs; no warning: %v\n%s", out.Warnings, out.HuJSON)
	}
	names := map[string]string{}
	for _, p := range out.Principals {
		names[p.Type+"/"+p.Ref] = p.Name
	}
	if names["user/"+w.alice.String()] != w.tokenAlice || names["resource/"+w.db.String()] != "db" || names["autogroup/self"] != "autogroup:self" {
		t.Errorf("principal names: %v", names)
	}
	im := ImportHuJSON(out.HuJSON, w.cat)
	if im.Result != ResultPassed || im.Source == nil || len(im.Errors) != 0 {
		t.Fatalf("import of the export: %+v", im.Errors)
	}
	if got, want := canon(t, *im.Source), canon(t, src); got != want {
		t.Fatalf("round trip differs:\n got %s\nwant %s", got, want)
	}
	if len(im.Principals) != len(out.Principals) {
		t.Errorf("import principals %d, export %d", len(im.Principals), len(out.Principals))
	}
	// deny-all: "grants": [] and nothing else
	deny, _ := ExportHuJSON(PolicySource{Grants: []Grant{}}, w.cat)
	if !strings.Contains(deny.HuJSON, `"grants": []`) || strings.Contains(deny.HuJSON, `"ssh"`) {
		t.Errorf("deny-all export:\n%s", deny.HuJSON)
	}
	if im := ImportHuJSON(deny.HuJSON, w.cat); im.Result != ResultPassed || len(im.Source.Grants) != 0 || im.Source.SSH == nil {
		t.Errorf("deny-all import: %+v", im)
	}
}

func findingCodes(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Rule+"/"+f.Code)
	}
	return out
}

// TestHuJSONImportRefusals — L1, L2, the decoder guard (case, "#", duplicates, null), L3 (managed and unknown keys),
// L6 (unknown names), syntax; every refusal has no source; findings carry the path and the line.
func TestHuJSONImportRefusals(t *testing.T) {
	w := newIOWorld()
	cases := []struct {
		name, text string
		want       []string
	}{
		{"empty", "", []string{"L2/empty"}},
		{"blank", " \n\t ", []string{"L2/empty"}},
		{"comment only", "// nothing\n", []string{"syntax/invalid_hujson"}},
		{"not hujson", `{"grants": [}`, []string{"syntax/invalid_hujson"}},
		{"array", `[]`, []string{"syntax/not_an_object"}},
		{"no grants", `{}`, []string{"L1/missing_grants"}},
		{"only ssh", `{"ssh": []}`, []string{"L1/missing_grants"}},
		{"null grants", `{"grants": null}`, []string{"L1/null_grants"}},
		{"object grants", `{"grants": {}}`, []string{"L1/grants_not_array"}},
		{"Grants", `{"Grants": []}`, []string{"decoder_guard/misspelled_key", "L1/missing_grants"}},
		{"grants twice", `{"grants": [], "GRANTS": []}`, []string{"decoder_guard/duplicate_key"}},
		{"hash key", `{"grants": [], "#grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`, []string{"decoder_guard/comment_key"}},
		{"managed", `{"grants": [], "groups": {}, "hosts": {}, "tagOwners": {}}`,
			[]string{"L3/managed_key", "L3/managed_key", "L3/managed_key"}},
		{"legacy", `{"grants": [], "acls": [], "nodeAttrs": [], "tests": [], "randomizeClientPort": true}`,
			[]string{"L3/acls_unsupported", "L3/node_attrs", "L3/tests_generated", "L3/unsupported_key"}},
		{"unknown top", `{"grants": [], "derpMap": {}}`, []string{"L3/unknown_key"}},
		{"null ssh", `{"grants": [], "ssh": null}`, []string{"decoder_guard/null_value"}},
		{"nested case", `{"grants": [{"SRC": ["*"], "dst": ["*"], "ip": ["*"]}]}`, []string{"decoder_guard/misspelled_key"}},
		{"nested unknown", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"], "srcPosture": []}]}`, []string{"L3/unknown_key"}},
		{"nested hash", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"], "#via": []}]}`, []string{"decoder_guard/comment_key"}},
		{"nested null", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": null}]}`, []string{"decoder_guard/null_value"}},
		{"group", `{"grants": [{"src": ["group:nope"], "dst": ["*"], "ip": ["*"]}]}`, []string{"L6/undeclared_group"}},
		{"tag", `{"grants": [{"src": ["*"], "dst": ["tag:nope"], "ip": ["*"]}]}`, []string{"L6/undeclared_tag"}},
		{"email", `{"grants": [{"src": ["eve@example.test"], "dst": ["*"], "ip": ["*"]}]}`, []string{"L6/undeclared_user"}},
		{"offboarded", `{"grants": [{"src": ["dave@example.test"], "dst": ["*"], "ip": ["*"]}]}`, []string{"L6/undeclared_user"}},
		{"ambiguous", `{"grants": [{"src": ["shared@EXAMPLE.test"], "dst": ["*"], "ip": ["*"]}]}`, []string{"L6/ambiguous_user"}},
		{"mg offboarded", `{"grants": [{"src": ["` + userToken(w.dave) + `"], "dst": ["*"], "ip": ["*"]}]}`, []string{"L6/undeclared_user"}},
		{"host alias", `{"grants": [{"src": ["*"], "dst": ["nope"], "ip": ["*"]}]}`, []string{"L6/undeclared_resource"}},
		{"autogroup", `{"grants": [{"src": ["autogroup:admin"], "dst": ["*"], "ip": ["*"]}]}`, []string{"syntax/unknown_autogroup"}},
		{"host bits", `{"grants": [{"src": ["10.1.2.3/8"], "dst": ["*"], "ip": ["*"]}]}`, []string{"syntax/invalid_cidr"}},
		{"principal type", `{"grants": [{"src": [1], "dst": ["*"], "ip": ["*"]}]}`, []string{"syntax/not_a_string"}},
		{"no ip", `{"grants": [{"src": ["*"], "dst": ["*"]}]}`, []string{"source/required"}},
		{"via not tag", `{"grants": [{"src": ["*"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["group:eng"]}]}`,
			[]string{"source/type_not_allowed_here"}},
		{"ssh check period", `{"grants": [], "ssh": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:web"], "users": ["root"], "checkPeriod": "1h"}]}`,
			[]string{"source/invalid_check_period"}},
		{"route prefix", `{"grants": [], "autoApprovers": {"routes": {"10.0.0.1/8": ["tag:web"]}}}`, []string{"syntax/invalid_prefix"}},
	}
	for _, c := range cases {
		im := ImportHuJSON(c.text, w.cat)
		if got := findingCodes(im.Errors); im.Result != ResultFailed || im.Source != nil || strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: result %s, errors %v, want %v", c.name, im.Result, got, c.want)
		}
	}
	// paths, lines (comments and trailing commas keep the line numbers), and the HuJSON spelling of model paths
	text := "// header\n{\n  \"grants\": [\n    {\"src\": [\"*\"], \"dst\": [\"group:nope\",], \"ip\": [\"*\"]}, // a comment\n  ],\n}\n"
	im := ImportHuJSON(text, w.cat)
	if len(im.Errors) != 1 || im.Errors[0].Path != "grants[0].dst[0]" || im.Errors[0].Line != 4 {
		t.Fatalf("path/line: %+v", im.Errors)
	}
	im = ImportHuJSON(`{"grants": [], "autoApprovers": {"exitNode": ["group:eng"]}}`, w.cat)
	if im.Result != ResultPassed {
		t.Fatalf("exitNode group: %+v", im.Errors)
	}
	im = ImportHuJSON(`{"grants": [], "ssh": [{"action": "check", "src": ["group:eng"], "dst": ["tag:web"], "users": ["root"], "checkPeriod": "x"}]}`, w.cat)
	if len(im.Errors) != 1 || im.Errors[0].Path != "ssh[0].checkPeriod" {
		t.Fatalf("model path in HuJSON spelling: %+v", im.Errors)
	}
	// at most maxImportFindings findings
	var b strings.Builder
	b.WriteString(`{"grants": [{"src": [`)
	for i := range 80 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"group:none` + strings.Repeat("x", i%3) + `"`)
	}
	b.WriteString(`], "dst": ["*"], "ip": ["*"]}]}`)
	if im := ImportHuJSON(b.String(), w.cat); len(im.Errors) != maxImportFindings {
		t.Errorf("findings are bounded: %d", len(im.Errors))
	}
}

// TestHuJSONImportResolves — every token form resolves to the typed principal of the catalog (case-insensitive
// e-mail, mg-<membership>@, canonical addresses), and HuJSON comments/trailing commas are accepted.
func TestHuJSONImportResolves(t *testing.T) {
	w := newIOWorld()
	text := `{
  // members by e-mail (any case) or by membership; a locked member stays a member
  "grants": [
    {"src": ["alice@example.TEST", "` + userToken(w.carol) + `", "group:ops", "autogroup:tagged"],
     "dst": ["srv-1", "10.0.0.1", "192.168.0.0/24", "*"], "ip": ["tcp:22"],},
  ],
}`
	im := ImportHuJSON(text, w.cat)
	if im.Result != ResultPassed {
		t.Fatalf("errors: %+v", im.Errors)
	}
	g := im.Source.Grants[0]
	want := []Principal{pr(PrincipalUser, w.alice.String()), pr(PrincipalUser, w.carol.String()), pr(PrincipalGroup, w.ops.String()),
		pr(PrincipalAutogroup, AutogroupTagged)}
	wantDst := []Principal{pr(PrincipalResource, w.srv.String()), pr(PrincipalCIDR, "10.0.0.1"), pr(PrincipalCIDR, "192.168.0.0/24"),
		pr(PrincipalCIDR, "*")}
	for i := range want {
		if g.Src[i] != want[i] {
			t.Errorf("src[%d] = %+v, want %+v", i, g.Src[i], want[i])
		}
	}
	for i := range wantDst {
		if g.Dst[i] != wantDst[i] {
			t.Errorf("dst[%d] = %+v, want %+v", i, g.Dst[i], wantDst[i])
		}
	}
	if len(im.Source.Acknowledgements) != 0 || im.Source.SSH == nil {
		t.Errorf("acknowledgements are not part of the text; ssh normalized: %+v", im.Source)
	}
}

// TestHuJSONExportUnresolved — a reference that no longer exists is written as a placeholder with an L6 warning, and
// that placeholder never resolves on import.
func TestHuJSONExportUnresolved(t *testing.T) {
	w := newIOWorld()
	gone := uuid.New().String()
	src := PolicySource{Grants: []Grant{{Src: []Principal{pr(PrincipalGroup, gone), pr(PrincipalUser, w.dave.String())},
		Dst: []Principal{pr(PrincipalTag, gone), pr(PrincipalResource, gone)}, IP: []string{"*"}}}}
	out, err := ExportHuJSON(src, w.cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Warnings) != 4 || out.Warnings[0].Rule != RuleL6 || out.Warnings[0].Path != "grants[0].src[0]" {
		t.Fatalf("warnings: %+v", out.Warnings)
	}
	im := ImportHuJSON(out.HuJSON, w.cat)
	if im.Result != ResultFailed || len(im.Errors) != 4 {
		t.Fatalf("placeholders must not resolve: %v", findingCodes(im.Errors))
	}
}

// TestPolicyHuJSONService — the service reads the names of the CALLER's tenant only (tenant B does not resolve
// tenant A's group, tag, resource or members), exports a stored version's source, and refuses an invalid source.
func TestPolicyHuJSONService(t *testing.T) {
	f := newVersionsFixture(t)
	group, tag, res := f.world(t, f.a)
	ctx := context.Background()
	text := `{"grants": [{"src": ["group:eng", "admin@` + f.a.slug + `.test"], "dst": ["tag:web", "db"], "ip": ["tcp:443"]}]}`
	im, err := f.vs.Import(ctx, f.a.id, text)
	if err != nil {
		t.Fatal(err)
	}
	if im.Result != ResultPassed {
		t.Fatalf("tenant A: %+v", im.Errors)
	}
	g := im.Source.Grants[0]
	if g.Src[0].Ref != group.String() || g.Src[1] != pr(PrincipalUser, f.a.admin.String()) || g.Dst[0].Ref != tag.String() ||
		g.Dst[1].Ref != res.String() {
		t.Fatalf("tenant A resolved %+v", g)
	}
	imB, err := f.vs.Import(ctx, f.b.id, text)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(findingCodes(imB.Errors), ","); got != "L6/undeclared_group,L6/undeclared_user,L6/undeclared_tag,L6/undeclared_resource" {
		t.Fatalf("tenant B must not resolve tenant A's names: %s", got)
	}
	out, err := f.vs.Export(ctx, f.a.id, srcJSON(group, tag, res, "443"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.HuJSON, `"group:eng"`) || !strings.Contains(out.HuJSON, `"tag:web"`) || !strings.Contains(out.HuJSON, `"db"`) ||
		len(out.Warnings) != 0 {
		t.Fatalf("export:\n%s %+v", out.HuJSON, out.Warnings)
	}
	outB, err := f.vs.Export(ctx, f.b.id, srcJSON(group, tag, res, "443"))
	if err != nil || len(outB.Warnings) != 3 {
		t.Fatalf("tenant B export of A's ids: %v %+v", err, outB.Warnings)
	}
	_, err = f.vs.Export(ctx, f.a.id, json.RawMessage(`{"grants":[{"src":[{"type":"group","ref":"eng"}],"dst":[{"type":"cidr","ref":"*"}],"ip":["*"]}]}`))
	wantPolErr(t, "export of an invalid source", err, ErrPolicyInvalid, "invalid_id")
	if pe, _ := AsPolicyError(err); pe.Field != "source.grants[0].src[0].ref" {
		t.Fatalf("field: %q", pe.Field)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id IN ($1, $2)`, f.a.id, f.b.id); n != 0 {
		t.Fatalf("import/export stored %d versions", n)
	}
}
