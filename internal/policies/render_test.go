package policies

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func mustSource(t *testing.T, raw string) PolicySource {
	t.Helper()
	s, err := ParseSource([]byte(raw))
	if err != nil {
		t.Fatalf("ParseSource(%s): %v", raw, err)
	}
	return s
}

// TestParseSource — the typed model is decoded strictly (§7.2): unknown members, null lists, a principal type outside
// its position, a reference that is not an id, a malformed ip, a duplicated or unknown acknowledgement are refused with
// the JSON path of the field; the canonical form is stable.
func TestParseSource(t *testing.T) {
	g := uuid.NewString()
	ok := `{"grants":[{"src":[{"type":"group","ref":"` + g + `"}],"dst":[{"type":"autogroup","ref":"member"}],"ip":["tcp:443"]}]}`
	s := mustSource(t, ok)
	if s.SSH == nil || len(s.Grants) != 1 {
		t.Fatalf("normalized: %+v", s)
	}
	c1, h1, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	c2, h2, _ := mustSource(t, " "+ok+"\n").Canonical()
	if string(c1) != string(c2) || h1 != h2 || h1 != SHA256Hex(string(c1)) {
		t.Fatalf("canonical form not stable: %s / %s", c1, c2)
	}
	for name, tc := range map[string]struct{ raw, field, reason string }{
		"unknown member":       {`{"grants":[],"acls":[]}`, "source", "invalid_json"},
		"nested unknown":       {`{"grants":[{"src":[{"type":"tag","ref":"` + g + `","x":1}],"dst":[{"type":"cidr","ref":"*"}],"ip":["*"]}]}`, "source", "invalid_json"},
		"null grants":          {`{"grants":null}`, "grants", "null"},
		"empty":                {`  `, "source", "required"},
		"via not a tag":        {`{"grants":[{"src":[{"type":"autogroup","ref":"member"}],"dst":[{"type":"autogroup","ref":"internet"}],"ip":["*"],"via":[{"type":"group","ref":"` + g + `"}]}]}`, "grants[0].via[0].type", "type_not_allowed_here"},
		"self as source":       {`{"grants":[{"src":[{"type":"autogroup","ref":"self"}],"dst":[{"type":"autogroup","ref":"member"}],"ip":["*"]}]}`, "grants[0].src[0].ref", "autogroup_not_allowed_here"},
		"ref not an id":        {`{"grants":[{"src":[{"type":"user","ref":"alice@example.com"}],"dst":[{"type":"autogroup","ref":"member"}],"ip":["*"]}]}`, "grants[0].src[0].ref", "invalid_id"},
		"bad ip":               {`{"grants":[{"src":[{"type":"autogroup","ref":"member"}],"dst":[{"type":"autogroup","ref":"member"}],"ip":["tcp:x"]}]}`, "grants[0].ip[0]", "invalid_ip_proto"},
		"no ip":                {`{"grants":[{"src":[{"type":"autogroup","ref":"member"}],"dst":[{"type":"autogroup","ref":"member"}]}]}`, "grants[0].ip", "required"},
		"cidr with host bits":  {`{"grants":[{"src":[{"type":"cidr","ref":"10.0.0.1/24"}],"dst":[{"type":"autogroup","ref":"member"}],"ip":["*"]}]}`, "grants[0].src[0].ref", "invalid_cidr"},
		"ssh bad user":         {`{"grants":[],"ssh":[{"action":"accept","src":[{"type":"autogroup","ref":"member"}],"dst":[{"type":"autogroup","ref":"self"}],"users":["Root!"]}]}`, "ssh[0].users[0]", "invalid_user"},
		"unknown ack rule":     {`{"grants":[],"acknowledgements":[{"rule":"L5","reason":"because"}]}`, "acknowledgements[0].rule", "not_acknowledgeable"},
		"duplicate ack":        {`{"grants":[],"acknowledgements":[{"rule":"L4","reason":"because"},{"rule":"L4","reason":"again!"}]}`, "acknowledgements[1].rule", "duplicate"},
		"short ack reason":     {`{"grants":[],"acknowledgements":[{"rule":"L4","reason":"ok"}]}`, "acknowledgements[0].reason", "invalid_reason"},
		"approver bad prefix":  {`{"grants":[],"auto_approvers":{"routes":{"10.0.0.1/24":[{"type":"tag","ref":"` + g + `"}]}}}`, "auto_approvers.routes", "invalid_prefix"},
		"trailing data":        {`{"grants":[]} {}`, "source", "trailing_data"},
		"check period, accept": {`{"grants":[],"ssh":[{"action":"accept","src":[{"type":"autogroup","ref":"member"}],"dst":[{"type":"autogroup","ref":"self"}],"users":["root"],"check_period":"12h"}]}`, "ssh[0].check_period", "invalid_check_period"},
	} {
		_, err := ParseSource([]byte(tc.raw))
		se, ok := AsSourceError(err)
		if !ok || se.Field != tc.field || se.Reason != tc.reason {
			t.Errorf("%s: got %v, want %s %s", name, err, tc.field, tc.reason)
		}
	}
}

// renderWorld is a tenant's tables for the render tests.
type renderWorld struct {
	in                        *RenderInputs
	alice, bob, gone, eng     uuid.UUID
	empty, web, router, other uuid.UUID
	db                        uuid.UUID
}

func newRenderWorld() renderWorld {
	w := renderWorld{alice: uuid.MustParse("00000000-0000-7000-8000-00000000000a"),
		bob: uuid.MustParse("00000000-0000-7000-8000-00000000000b"), gone: uuid.New(), eng: uuid.New(), empty: uuid.New(),
		web: uuid.New(), router: uuid.New(), other: uuid.New(), db: uuid.New()}
	w.in = &RenderInputs{
		Groups: map[uuid.UUID]RenderGroup{w.eng: {Name: "eng", Members: []uuid.UUID{w.bob, w.alice}},
			w.empty: {Name: "empty", Members: []uuid.UUID{}}},
		Memberships: map[uuid.UUID]string{w.alice: "active", w.bob: "locked", w.gone: "offboarded"},
		Tags: map[uuid.UUID]RenderTag{w.web: {Name: "tag:web"}, w.router: {Name: "tag:router", PlatformManaged: true},
			w.other: {Name: "tag:other"}},
		Catalog:      []string{"tag:other", "tag:router", "tag:web"},
		Resources:    map[uuid.UUID]RenderResource{w.db: {Name: "db", Address: "10.20.0.5/32"}},
		IdentityMode: IdentityModePortal,
	}
	return w
}

func p(typ string, ref any) string {
	return `{"type":"` + typ + `","ref":"` + strings.TrimSpace(func() string {
		if id, ok := ref.(uuid.UUID); ok {
			return id.String()
		}
		return ref.(string)
	}()) + `"}`
}

func codes(fs []Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Rule+":"+f.Code)
	}
	slices.Sort(out)
	return out
}

// TestRenderTypedDeterministic — §7.2: the render of a typed source is deterministic and canonical — the referenced
// groups with their members as mg-<membership>@ (sorted, never an e-mail), the referenced resources as hosts, the
// whole catalog as tagOwners with empty owners, grants always present, ssh [] — and Lint keeps it byte for byte (what
// is sent is what the drift check compares).
func TestRenderTypedDeterministic(t *testing.T) {
	w := newRenderWorld()
	src := mustSource(t, `{"grants":[
		{"src":[`+p("group", w.eng)+`,`+p("user", w.alice)+`],"dst":[`+p("tag", w.web)+`,`+p("resource", w.db)+`],"ip":["tcp:443","tcp:5432"]},
		{"src":[`+p("autogroup", "member")+`],"dst":[`+p("cidr", "10.30.0.0/16")+`],"ip":["icmp:*"]}]}`)
	_, sum, _ := src.Canonical()
	r1 := RenderTyped(src, sum, w.in)
	r2 := RenderTyped(src, sum, w.in)
	if r1.Report.Blocking() || r1.Document.Applied == "" {
		t.Fatalf("report %+v", r1.Report)
	}
	if r1.Document.Applied != r2.Document.Applied || r1.Document.AppliedSHA256 != SHA256Hex(r1.Document.Applied) {
		t.Fatal("render not deterministic")
	}
	want := `{
  "groups": {
    "group:eng": [
      "mg-00000000-0000-7000-8000-00000000000a@",
      "mg-00000000-0000-7000-8000-00000000000b@"
    ]
  },
  "hosts": {
    "db": "10.20.0.5/32"
  },
  "tagOwners": {
    "tag:other": [],
    "tag:router": [],
    "tag:web": []
  },
  "grants": [
    {
      "src": [
        "group:eng",
        "mg-00000000-0000-7000-8000-00000000000a@"
      ],
      "dst": [
        "tag:web",
        "db"
      ],
      "ip": [
        "tcp:443",
        "tcp:5432"
      ]
    },
    {
      "src": [
        "autogroup:member"
      ],
      "dst": [
        "10.30.0.0/16"
      ],
      "ip": [
        "icmp:*"
      ]
    }
  ],
  "ssh": []
}`
	if r1.Document.Applied != want {
		t.Fatalf("rendered\n%s\nwant\n%s", r1.Document.Applied, want)
	}
	again, err := Lint(r1.Document.Applied)
	if err != nil || again.Applied != r1.Document.Applied {
		t.Fatalf("Lint changes the rendered bytes: %v", err)
	}
	if r1.Document.ContentSHA256 != sum || r1.Document.InputsSHA256 == sum || r1.Report.RenderedSHA256 != r1.Document.AppliedSHA256 {
		t.Fatalf("document hashes %+v", r1.Document)
	}
	if !slices.Equal(r1.Document.TagOwners, w.in.Catalog) {
		t.Fatalf("tag owners %v", r1.Document.TagOwners)
	}
	// a group change changes the render (and its inputs), never the content
	w.in.Groups[w.eng] = RenderGroup{Name: "eng", Members: []uuid.UUID{w.alice}}
	r3 := RenderTyped(src, sum, w.in)
	if r3.Document.AppliedSHA256 == r1.Document.AppliedSHA256 || r3.Document.InputsSHA256 == r1.Document.InputsSHA256 ||
		r3.Document.ContentSHA256 != sum {
		t.Fatal("a group change must change the rendered policy and its inputs")
	}
	// deny-all: grants [] and ssh [] are always present (L1)
	empty := RenderTyped(mustSource(t, `{"grants":[]}`), "x", &RenderInputs{})
	if empty.Report.Blocking() || empty.Document.Applied != "{\n  \"grants\": [],\n  \"ssh\": []\n}" {
		t.Fatalf("deny-all rendered %q %+v", empty.Document.Applied, empty.Report)
	}
}

// TestRenderTypedLint — L4–L13 on the model: a wildcard destination is blocked unless acknowledged (then an
// Owner-only warning); danger-all as a source, an SSH check rule, an undeclared or offboarded reference are blocked;
// the rules that need a confirmation (L7, L10 accept, L13) block until acknowledged; L8 warns in a large tenant.
func TestRenderTypedLint(t *testing.T) {
	w := newRenderWorld()
	mem := p("autogroup", "member")
	grant := func(src, dst string, extra string) string {
		return `{"src":[` + src + `],"dst":[` + dst + `],"ip":["*"]` + extra + `}`
	}
	for name, tc := range map[string]struct {
		src      string
		mode     string
		devices  int64
		errors   []string
		warnings []string
		ownerAck bool
	}{
		"wildcard": {src: `{"grants":[` + grant(mem, p("cidr", "*"), "") + `]}`, errors: []string{"L4:wildcard_destination_ack_required"}},
		"default route acknowledged": {src: `{"grants":[` + grant(mem, p("cidr", "0.0.0.0/0"), "") + `],` +
			`"acknowledgements":[{"rule":"L4","reason":"lab exit"}]}`, warnings: []string{"L4:wildcard_destination"}, ownerAck: true},
		"danger-all": {src: `{"grants":[` + grant(p("autogroup", "danger-all"), mem, "") + `]}`,
			errors: []string{"L5:danger_all_source", "L5:danger_all_source"}}, // the model and the output
		"undeclared": {src: `{"grants":[` + grant(p("group", uuid.New())+","+p("user", w.gone), p("tag", uuid.New())+","+p("resource", uuid.New()), "") + `]}`,
			errors: []string{"L6:undeclared_group", "L6:undeclared_resource", "L6:undeclared_tag", "L6:undeclared_user"}},
		"internet without via": {src: `{"grants":[` + grant(mem, p("autogroup", "internet"), "") + `]}`,
			errors: []string{"L7:internet_without_via_ack_required"}},
		"internet via exit": {src: `{"grants":[` + grant(mem, p("autogroup", "internet"), `,"via":[`+p("tag", w.router)+`]`) + `]}`},
		"approver not platform": {src: `{"grants":[],"auto_approvers":{"routes":{"10.0.0.0/24":[` + p("tag", w.web) + `,` +
			p("tag", w.router) + `]},"exit_node":[` + p("group", w.eng) + `]},"acknowledgements":[{"rule":"L7","reason":"lab routes"}]}`,
			warnings: []string{"L7:auto_approver_not_platform", "L7:auto_approver_not_platform"}},
		"self large": {src: `{"grants":[` + grant(mem, p("autogroup", "self"), "") + `]}`, devices: LargeTenantDevices, warnings: []string{"L8:self_large_tenant"}},
		"self small": {src: `{"grants":[` + grant(mem, p("autogroup", "self"), "") + `]}`, devices: 3},
		"ssh accept": {src: `{"grants":[],"ssh":[{"action":"accept","src":[` + mem + `],"dst":[` + p("autogroup", "self") + `],"users":["root"]}]}`, errors: []string{"L10:ssh_accept_ack_required"}},
		"ssh accept ok": {src: `{"grants":[],"ssh":[{"action":"accept","src":[` + mem + `],"dst":[` + p("autogroup", "self") + `],"users":["root"]}],` +
			`"acknowledgements":[{"rule":"L10","reason":"admins only"}]}`, warnings: []string{"L10:ssh_accept"}},
		"ssh check": {src: `{"grants":[],"ssh":[{"action":"check","src":[` + mem + `],"dst":[` + p("autogroup", "self") + `],"users":["root"],"check_period":"12h"}]}`,
			errors: []string{"L10:ssh_check", "L10:ssh_check"}},
		"member oidc":   {src: `{"grants":[` + grant(mem, mem, "") + `]}`, mode: IdentityModeHeadscaleOIDC, errors: []string{"L13:member_oidc_ack_required"}},
		"member portal": {src: `{"grants":[` + grant(mem, mem, "") + `]}`},
	} {
		in := *w.in
		in.Devices, in.IdentityMode = tc.devices, IdentityModePortal
		if tc.mode != "" {
			in.IdentityMode = tc.mode
		}
		r := RenderTyped(mustSource(t, tc.src), "c", &in)
		if want := append([]string{}, tc.errors...); !slices.Equal(codes(r.Report.Errors), sorted(want)) {
			t.Errorf("%s: errors %v, want %v", name, codes(r.Report.Errors), sorted(want))
		}
		if want := append([]string{}, tc.warnings...); !slices.Equal(codes(r.Report.Warnings), sorted(want)) {
			t.Errorf("%s: warnings %v, want %v", name, codes(r.Report.Warnings), sorted(want))
		}
		if r.Report.OwnerAcknowledged() != tc.ownerAck {
			t.Errorf("%s: owner acknowledged %v", name, r.Report.OwnerAcknowledged())
		}
		if (r.Report.Result == ResultFailed) != (len(tc.errors) > 0) {
			t.Errorf("%s: result %s", name, r.Report.Result)
		}
	}
}

func sorted(s []string) []string {
	slices.Sort(s)
	return s
}

// TestOutputLint — the rules on the document sent to Headscale (every path of the core): nodeAttrs and unknown keys
// (L3), danger-all as a source (L5), SSH check (L10), a user token that is not mg-<uuid>@ (L11), owned tagOwners
// (L12) are errors; acls is information (L9). The platform's own templates pass.
func TestOutputLint(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  string
		want []string
	}{
		"clean":     {`{"grants":[{"src":["mg-00000000-0000-7000-8000-00000000000a@"],"dst":["tag:web:443"],"ip":["*"]}],"ssh":[]}`, []string{}},
		"nodeAttrs": {`{"grants":[],"nodeAttrs":[]}`, []string{"L3:node_attrs"}},
		"acls":      {`{"grants":[],"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`, []string{"L9:acls_legacy"}},
		"danger":    {`{"grants":[{"src":["autogroup:danger-all"],"dst":["*"],"ip":["*"]}]}`, []string{"L5:danger_all_source"}},
		"ssh check": {`{"grants":[],"ssh":[{"action":"check","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}]}`, []string{"L10:ssh_check"}},
		"email":     {`{"grants":[{"src":["alice@example.com"],"dst":["*"],"ip":["*"]}]}`, []string{"L11:user_token"}},
		"acl dst":   {`{"grants":[],"acls":[{"action":"accept","src":["*"],"dst":["bob@:22"]}]}`, []string{"L11:user_token", "L9:acls_legacy"}},
		"group tok": {`{"groups":{"group:x":["x@"]},"grants":[]}`, []string{"L11:user_token"}},
		"owned":     {`{"tagOwners":{"tag:a":["group:x"]},"grants":[]}`, []string{"L12:tag_owners"}},
	} {
		if got := codes(OutputLint(tc.doc)); !slices.Equal(got, sorted(tc.want)) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	for _, name := range []string{"bootstrap-policy.hujson", "suspension-policy.hujson", "test-allow-intra.hujson"} {
		d, err := Lint(fixtureText(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := hardLint(d.Applied); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if le, ok := IsLint(hardLint(`{"grants":[],"nodeAttrs":[]}`)); !ok || le.Rule != RuleL3 || le.Code() != "lint_l3" {
		t.Fatalf("hard lint: %v", le)
	}
}

// TestLineDiff — the reviewer's diff: unchanged, removed and added lines in order; the grants added and removed.
func TestLineDiff(t *testing.T) {
	lines, ok := lineDiff("a\nb\nc", "a\nc\nd")
	if !ok {
		t.Fatal("omitted")
	}
	b, _ := json.Marshal(lines)
	if string(b) != `[{"op":"same","text":"a"},{"op":"removed","text":"b"},{"op":"same","text":"c"},{"op":"added","text":"d"}]` {
		t.Fatalf("diff %s", b)
	}
	add, rem := grantChanges(`{"grants":[{"src":["a"],"dst":["b"],"ip":["*"]}]}`, `{"grants":[{"ip":["*"],"dst":["c"],"src":["a"]}]}`)
	if len(add) != 1 || len(rem) != 1 || !strings.Contains(add[0], `"c"`) {
		t.Fatalf("grants +%v -%v", add, rem)
	}
	if _, ok := lineDiff(strings.Repeat("x\n", 3000), strings.Repeat("y\n", 3000)); ok {
		t.Fatal("a large diff must be omitted")
	}
}
