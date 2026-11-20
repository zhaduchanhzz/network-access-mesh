package policies

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// testGenWorld is renderWorld with an inventory: alice (in group eng) has an untagged device, bob (in group ops) has
// none; one device carries tag:web, one tag:router; a subnet resource "lab".
func testGenWorld() (renderWorld, uuid.UUID, uuid.UUID) {
	w := newRenderWorld()
	ops, lab := uuid.New(), uuid.New()
	w.in.Groups[ops] = RenderGroup{Name: "ops", Members: []uuid.UUID{w.bob}}
	w.in.Resources[lab] = RenderResource{Name: "lab", Address: "10.40.0.0/24"}
	w.in.Nodes = []RenderNode{{Owner: w.alice}, {Owner: w.bob, Tags: []string{"tag:web"}}, {Tags: []string{"tag:router"}}}
	return w, ops, lab
}

// TestGenerateTests — P5-T01: one test per grant that can be asserted (first source with a device, first destination
// with an address, ACCEPT on the grant's first testable port, DENY on a port no grant mentions); a grant with via or
// whose destination is only autogroup:self gets none and an Info finding (V-24); a source or destination without a
// device is left out (PL-04), never written to fail. The block is part of the rendered output, deterministic whatever
// the order of the inventory, and passes the output lint (L11 reads its user tokens).
func TestGenerateTests(t *testing.T) {
	w, ops, lab := testGenWorld()
	src := mustSource(t, `{"grants":[
		{"src":[`+p("group", w.eng)+`],"dst":[`+p("tag", w.web)+`],"ip":["tcp:443"]},
		{"src":[`+p("group", ops)+`,`+p("user", w.bob)+`],"dst":[`+p("resource", w.db)+`],"ip":["tcp:5432"]},
		{"src":[`+p("autogroup", "member")+`],"dst":[`+p("autogroup", "self")+`],"ip":["tcp:22"]},
		{"src":[`+p("group", w.eng)+`],"dst":[`+p("resource", lab)+`],"ip":["tcp:80"],"via":[`+p("tag", w.router)+`]},
		{"src":[`+p("cidr", "10.9.0.0/24")+`],"dst":[`+p("resource", lab)+`,`+p("resource", w.db)+`],"ip":["udp:53","80"]},
		{"src":[`+p("user", w.alice)+`],"dst":[`+p("autogroup", "self")+`,`+p("autogroup", "tagged")+`],"ip":["8080-8090"]},
		{"src":[`+p("autogroup", "member")+`],"dst":[`+p("user", w.bob)+`],"ip":["tcp:9000"]}
	]}`)
	_, sum, _ := src.Canonical()
	r := RenderTyped(src, sum, w.in)
	if r.Report.Blocking() {
		t.Fatalf("report %+v", r.Report.Errors)
	}
	deny := "65535"
	wantCases := []TestCase{
		{Grant: 0, Src: "group:eng", Proto: "tcp", Accept: []string{"tag:web:443"}, Deny: []string{"tag:web:" + deny}},
		{Grant: 1, Skipped: TestSkipNoSource},
		{Grant: 2, Skipped: TestSkipSelf},
		{Grant: 3, Skipped: TestSkipVia},
		{Grant: 4, Src: "10.9.0.0/24", Proto: "udp", Accept: []string{"10.40.0.0:53"}, Deny: []string{"10.40.0.0:" + deny}},
		{Grant: 5, Src: "mg-" + w.alice.String() + "@", Accept: []string{"autogroup:tagged:8080"}, Deny: []string{"autogroup:tagged:" + deny}},
		{Grant: 6, Skipped: TestSkipNoDest},
	}
	if !reflect.DeepEqual(r.Report.Tests, wantCases) {
		got, _ := json.MarshalIndent(r.Report.Tests, "", " ")
		t.Fatalf("cases:\n%s", got)
	}
	if c := codes(r.Report.Info); !slices.Equal(c, []string{"tests:self_not_asserted", "tests:self_not_asserted", "tests:via_not_asserted"}) {
		t.Fatalf("info %v", c)
	}
	var out struct {
		Tests []renderedTest `json:"tests"`
	}
	if err := json.Unmarshal([]byte(r.Document.Applied), &out); err != nil || len(out.Tests) != 3 ||
		out.Tests[0].Src != "group:eng" || out.Tests[0].Accept[0] != "tag:web:443" || out.Tests[2].Proto != "" {
		t.Fatalf("rendered tests %+v %v\n%s", out.Tests, err, r.Document.Applied)
	}
	if strings.Index(r.Document.Applied, `"tests"`) < strings.Index(r.Document.Applied, `"ssh"`) {
		t.Fatalf("tests must be the last member:\n%s", r.Document.Applied)
	}
	// the inventory order does not matter
	w.in.Nodes = []RenderNode{w.in.Nodes[2], w.in.Nodes[0], w.in.Nodes[1]}
	if again := RenderTyped(src, sum, w.in); again.Document.Applied != r.Document.Applied {
		t.Fatal("the render depends on the order of the inventory")
	}
	// no device ⇒ only grant 4 keeps its test (a cidr source and a resource destination need no device), the others
	// are skipped with their reason
	w.in.Nodes = nil
	bare := RenderTyped(src, sum, w.in)
	if bare.Report.Blocking() || strings.Count(bare.Document.Applied, `"src": "`) != 1 {
		t.Fatalf("without devices:\n%s", bare.Document.Applied)
	}
	for _, c := range bare.Report.Tests {
		if (c.Skipped == "") != (c.Grant == 4) {
			t.Errorf("case without devices: %+v", c)
		}
	}
	// a source without a device and a resource destination: no block at all — the document is the one of P4-T10
	only := mustSource(t, `{"grants":[{"src":[`+p("group", w.eng)+`],"dst":[`+p("resource", w.db)+`],"ip":["tcp:5432"]}]}`)
	if d := RenderTyped(only, "x", w.in).Document.Applied; strings.Contains(d, `"tests"`) {
		t.Fatalf("an empty block is rendered:\n%s", d)
	}
	// a user token in the block that is not mg-<uuid>@ is L11 (the output lint reads the tests)
	bad := `{"grants":[],"ssh":[],"tests":[{"src":"alice@example.com","accept":["tag:web:443"]}]}`
	if fs := OutputLint(bad); len(fs) != 1 || fs[0].Rule != RuleL11 {
		t.Fatalf("L11 on tests: %+v", fs)
	}
}

// TestGenerateTestsDenyPort — a deny assertion is only written on a port no grant mentions: none when an entry opens
// every port (whatever its protocol) or when no port of 1024–65535 is free.
func TestGenerateTestsDenyPort(t *testing.T) {
	g := func(ips ...string) Grant { return Grant{IP: ips} }
	for name, tc := range map[string]struct {
		grants []Grant
		want   int
	}{
		"none":              {nil, 65535},
		"top port used":     {[]Grant{g("tcp:65535")}, 65534},
		"range":             {[]Grant{g("tcp:60000-65535,80"), g("udp:59999")}, 59998},
		"icmp wildcard":     {[]Grant{g("tcp:443"), g("icmp:*")}, 0},
		"star":              {[]Grant{g("*")}, 0},
		"everything above":  {[]Grant{g("1024-65535")}, 0},
		"app only (no ip)":  {[]Grant{{}}, 65535},
		"several protocols": {[]Grant{g("tcp:65535", "udp:65534", "sctp:65533")}, 65532},
	} {
		if got := denyPort(tc.grants); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		ips   []string
		proto string
		port  int
		ok    bool
	}{
		{[]string{"icmp:*", "tcp:*", "6:80"}, "", 0, false},
		{[]string{"80,443"}, "", 80, true},
		{[]string{"icmp:*", "udp:53"}, "udp", 53, true},
		{[]string{"tcp:8000-8100"}, "tcp", 8000, true},
		{[]string{"sctp:9"}, "sctp", 9, true},
	} {
		proto, port, ok := testPort(tc.ips)
		if proto != tc.proto || port != tc.port || ok != tc.ok {
			t.Errorf("testPort(%v) = %q %d %v", tc.ips, proto, port, ok)
		}
	}
}

// TestGenerateTestsCapped — at most MaxGeneratedTests entries; the rest are reported capped.
func TestGenerateTestsCapped(t *testing.T) {
	w, _, _ := testGenWorld()
	var b strings.Builder
	b.WriteString(`{"grants":[`)
	for i := range MaxGeneratedTests + 3 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"src":[` + p("group", w.eng) + `],"dst":[` + p("tag", w.web) + `],"ip":["tcp:443"]}`)
	}
	b.WriteString(`]}`)
	src := mustSource(t, b.String())
	r := RenderTyped(src, "x", w.in)
	n, capped := 0, 0
	for _, c := range r.Report.Tests {
		switch c.Skipped {
		case "":
			n++
		case TestSkipCapped:
			capped++
		}
	}
	if n != MaxGeneratedTests || capped != 3 || r.Report.Blocking() {
		t.Fatalf("generated %d, capped %d, errors %+v", n, capped, r.Report.Errors)
	}
}

// TestWithoutTests — the restart checks (upgrade, reconfigure) send the applied policy without its tests blocks; a
// policy without them is sent as it is (byte for byte).
func TestWithoutTests(t *testing.T) {
	plain := "{\n  \"grants\": [],\n  \"ssh\": []\n}"
	if got, err := WithoutTests(plain); err != nil || got != plain {
		t.Fatalf("plain: %q %v", got, err)
	}
	with := `{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:22"]}],"ssh":[],"tests":[{"src":"*","accept":["1.2.3.4:22"]}],"sshTests":[]}`
	got, err := WithoutTests(with)
	if err != nil || strings.Contains(got, "tests") || strings.Contains(got, "sshTests") || !strings.Contains(got, `"tcp:22"`) {
		t.Fatalf("with tests: %q %v", got, err)
	}
	if _, err := Lint(got); err != nil {
		t.Fatalf("the stripped policy does not lint: %v", err)
	}
	if _, err := WithoutTests("not json"); err == nil {
		t.Fatal("not JSON must fail")
	}
}
