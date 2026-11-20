package policies

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Generated policy tests (P5-T01 — §7.2 "`tests`, `sshTests`: sinh lúc apply từ inventory hiện tại", PL-04, V-24).
//
// Every typed render adds a Headscale "tests" block built from the grants and the device inventory of the tenant: one
// entry per grant that can be asserted — the grant's first source that resolves to a device, its first destination
// that resolves to an address, ACCEPT on one port the grant opens and, when the policy opens no port range wide enough
// to make it unsafe, DENY on one port no grant of the policy mentions. Headscale runs the block on CheckPolicy (the
// validate dry run) and on SetPolicy (the apply) and refuses the write when an assertion fails (PL-04) — a check of the
// render against the engine that enforces it. It never runs on a restart of the instance (upstream: "Boot-time reload
// of an already-stored policy does not run them"), so a stored block cannot lock an instance out.
//
// What is NOT asserted, by construction:
//
//   - a grant with "via" and a grant whose only destination is autogroup:self: Headscale v0.29.7 evaluates "tests" on
//     the GLOBAL filter, which leaves out both (they are compiled per node) — an accept assertion always fails and a
//     deny assertion passes even where the grant allows the traffic (V-24, verified by the contract test of phase 12:
//     tests/integration/headscale/policytests_test.go). The report says so (Info finding of rule "tests") instead of
//     promising it;
//   - autogroup:internet (refused by Headscale as a test destination), app-only grants (no port), SSH rules
//     ("sshTests" are not generated), IPv6 prefixes and "*";
//   - a source or destination without a device in the inventory: Headscale fails a test whose source or destination
//     resolves to no address (PL-04) — the case is left out, never written to fail.
//
// The generated block is part of the rendered output, so it is part of applied_sha256 and of the string compared by
// the drift check; it is regenerated from the inventory of the moment at every render (validate, apply, rollback), never
// stored with the rules.

// RuleTests is the rule of the findings about the generated tests (Info: what they cannot assert — V-24).
const RuleTests = "tests"

// MaxGeneratedTests bounds the block (one entry per grant — MaxGrants — would stay far below MaxPolicyBytes, the bound
// keeps the rendered document small).
const MaxGeneratedTests = 200

// Reasons of a grant without a generated test (TestCase.Skipped).
const (
	TestSkipVia      = "via_not_assertable"  // V-24: tests do not see via grants
	TestSkipSelf     = "self_not_assertable" // V-24: tests do not see autogroup:self
	TestSkipApp      = "app_only"            // no network port to test
	TestSkipPort     = "no_testable_port"    // only "*" ports or a protocol tests do not take
	TestSkipNoSource = "no_source_device"    // no source of the grant has a device yet (PL-04)
	TestSkipNoDest   = "no_destination"      // no destination of the grant resolves to an address yet (PL-04)
	TestSkipCapped   = "capped"              // MaxGeneratedTests reached
	denyPortFloor    = 1024
	denyPortCeiling  = 65535
	testProtoDefault = "" // TCP/UDP/ICMP — Headscale's default set when proto is omitted
)

// TestCase is one entry of validation_report.tests: a generated test of grant Grant (index in the source) or the reason
// none was generated.
type TestCase struct {
	Grant   int      `json:"grant"`
	Src     string   `json:"src,omitempty"`
	Proto   string   `json:"proto,omitempty"`
	Accept  []string `json:"accept,omitempty"`
	Deny    []string `json:"deny,omitempty"`
	Skipped string   `json:"skipped,omitempty"`
}

// renderedTest is one entry of the rendered "tests" block (Headscale's PolicyTest).
type renderedTest struct {
	Src    string   `json:"src"`
	Proto  string   `json:"proto,omitempty"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

// RenderNode is a device of the inventory (device_inventory_cache — ListPolicyNodes): its owner (uuid.Nil: none) and
// its tags (names, "tag:x"). A tagged device belongs to its tags, not to its owner (Headscale 0.29 — HS-10).
type RenderNode struct {
	Owner uuid.UUID
	Tags  []string
}

// inventory answers "does this alias resolve to a device".
type inventory struct {
	owners   map[uuid.UUID]bool // memberships with an untagged device
	tags     map[string]bool    // tag names with a device
	member   bool               // an untagged device with an owner exists (autogroup:member)
	anyTag   bool               // a tagged device exists (autogroup:tagged)
	hasNodes bool
}

func newInventory(nodes []RenderNode) inventory {
	inv := inventory{owners: map[uuid.UUID]bool{}, tags: map[string]bool{}, hasNodes: len(nodes) > 0}
	for _, n := range nodes {
		if len(n.Tags) > 0 {
			inv.anyTag = true
			for _, t := range n.Tags {
				inv.tags[t] = true
			}
			continue
		}
		if n.Owner != uuid.Nil {
			inv.owners[n.Owner] = true
			inv.member = true
		}
	}
	return inv
}

// testGen builds the block of one render.
type testGen struct {
	in   *RenderInputs
	inv  inventory
	deny int // the deny port; 0 = no deny assertion (a port range of the policy is too wide)
}

// generateTests returns the rendered block (nil when empty), the report entries and the Info findings (V-24).
func generateTests(src PolicySource, in *RenderInputs) ([]renderedTest, []TestCase, []Finding) {
	g := &testGen{in: in, inv: newInventory(in.Nodes), deny: denyPort(src.Grants)}
	var (
		out   []renderedTest
		cases = []TestCase{}
		info  []Finding
	)
	for i, gr := range src.Grants {
		path := "grants[" + strconv.Itoa(i) + "]"
		self := hasAutogroup(gr.Dst, AutogroupSelf)
		if len(gr.Via) > 0 {
			info = append(info, Finding{Rule: RuleTests, Severity: SeverityInfo, Code: "via_not_asserted", Path: path,
				Message: "the generated tests cannot assert access granted through via: Headscale evaluates tests on its global filter, which leaves via grants out (V-24)"})
			cases = append(cases, TestCase{Grant: i, Skipped: TestSkipVia})
			continue
		}
		if self {
			info = append(info, Finding{Rule: RuleTests, Severity: SeverityInfo, Code: "self_not_asserted", Path: path,
				Message: "the generated tests cannot assert access to autogroup:self: Headscale evaluates tests on its global filter, which leaves autogroup:self out (V-24)"})
		}
		tc := g.one(i, gr, self)
		if tc.Skipped == "" && len(out) >= MaxGeneratedTests {
			tc = TestCase{Grant: i, Skipped: TestSkipCapped}
		}
		cases = append(cases, tc)
		if tc.Skipped == "" {
			out = append(out, renderedTest{Src: tc.Src, Proto: tc.Proto, Accept: tc.Accept, Deny: tc.Deny})
		}
	}
	return out, cases, info
}

// one is the test of one grant (without via).
func (g *testGen) one(i int, gr Grant, self bool) TestCase {
	if len(gr.IP) == 0 {
		return TestCase{Grant: i, Skipped: TestSkipApp}
	}
	proto, port, ok := testPort(gr.IP)
	if !ok {
		return TestCase{Grant: i, Skipped: TestSkipPort}
	}
	var dst string
	for _, p := range gr.Dst {
		if d, ok := g.dst(p); ok {
			dst = d
			break
		}
	}
	if dst == "" {
		if self && onlySelfOrInternet(gr.Dst) {
			return TestCase{Grant: i, Skipped: TestSkipSelf}
		}
		return TestCase{Grant: i, Skipped: TestSkipNoDest}
	}
	var src string
	for _, p := range gr.Src {
		if s, ok := g.src(p); ok {
			src = s
			break
		}
	}
	if src == "" {
		return TestCase{Grant: i, Skipped: TestSkipNoSource}
	}
	tc := TestCase{Grant: i, Src: src, Proto: proto, Accept: []string{dst + ":" + strconv.Itoa(port)}}
	if g.deny > 0 {
		tc.Deny = []string{dst + ":" + strconv.Itoa(g.deny)}
	}
	return tc
}

func hasAutogroup(ps []Principal, ref string) bool {
	for _, p := range ps {
		if p.Type == PrincipalAutogroup && p.Ref == ref {
			return true
		}
	}
	return false
}

func onlySelfOrInternet(ps []Principal) bool {
	for _, p := range ps {
		if p.Type != PrincipalAutogroup || (p.Ref != AutogroupSelf && p.Ref != AutogroupInternet) {
			return false
		}
	}
	return true
}

// src is the test source of a principal when it resolves to at least one address (Headscale fails a test whose source
// resolves to none — PL-04).
func (g *testGen) src(p Principal) (string, bool) {
	switch p.Type {
	case PrincipalCIDR:
		if isDefaultRoute(p.Ref) {
			return "", false
		}
		s, err := canonicalCIDR(p.Ref)
		return s, err == nil
	case PrincipalResource:
		res, ok := g.resource(p.Ref)
		if !ok {
			return "", false
		}
		return res.Name, true
	}
	return g.device(p)
}

// dst is the test destination (without the port) of a principal when it resolves to at least one address and is a
// shape Headscale takes as a test destination: one host — never a CIDR, never autogroup:internet or autogroup:self.
func (g *testGen) dst(p Principal) (string, bool) {
	switch p.Type {
	case PrincipalCIDR:
		if isDefaultRoute(p.Ref) {
			return "", false
		}
		return hostOf(p.Ref)
	case PrincipalResource:
		res, ok := g.resource(p.Ref)
		if !ok {
			return "", false
		}
		if a, err := netip.ParseAddr(res.Address); err == nil && a.Zone() == "" {
			return res.Name, true // a single host: its alias
		}
		if pf, err := netip.ParsePrefix(res.Address); err == nil && pf.IsSingleIP() {
			return res.Name, true
		}
		return hostOf(res.Address) // a network: an address inside it (Headscale refuses a CIDR destination)
	}
	return g.device(p)
}

// device resolves a user, group, tag or autogroup (member, tagged) through the inventory.
func (g *testGen) device(p Principal) (string, bool) {
	switch p.Type {
	case PrincipalUser:
		id, err := uuid.Parse(p.Ref)
		if err != nil || !g.inv.owners[id] {
			return "", false
		}
		if st, ok := g.in.Memberships[id]; !ok || st == "offboarded" {
			return "", false
		}
		return userToken(id), true
	case PrincipalGroup:
		id, err := uuid.Parse(p.Ref)
		if err != nil {
			return "", false
		}
		grp, ok := g.in.Groups[id]
		if !ok {
			return "", false
		}
		for _, m := range grp.Members {
			if g.inv.owners[m] {
				return "group:" + grp.Name, true
			}
		}
	case PrincipalTag:
		id, err := uuid.Parse(p.Ref)
		if err != nil {
			return "", false
		}
		t, ok := g.in.Tags[id]
		if ok && g.inv.tags[t.Name] {
			return t.Name, true
		}
	case PrincipalAutogroup:
		switch {
		case p.Ref == AutogroupMember && g.inv.member:
			return "autogroup:member", true
		case p.Ref == AutogroupTagged && g.inv.anyTag:
			return "autogroup:tagged", true
		}
	}
	return "", false
}

func (g *testGen) resource(ref string) (RenderResource, bool) {
	id, err := uuid.Parse(ref)
	if err != nil {
		return RenderResource{}, false
	}
	r, ok := g.in.Resources[id]
	return r, ok
}

func isDefaultRoute(ref string) bool {
	return ref == "*" || ref == "0.0.0.0/0" || ref == "::/0"
}

// hostOf is an IPv4 address (or the first address of an IPv4 prefix) written without a mask; IPv6 is left out (the
// "host:port" form of a test destination is ambiguous with an IPv6 literal).
func hostOf(ref string) (string, bool) {
	if a, err := netip.ParseAddr(ref); err == nil {
		if !a.Is4() {
			return "", false
		}
		return a.String(), true
	}
	pf, err := netip.ParsePrefix(ref)
	if err != nil || !pf.Addr().Is4() || pf.Bits() == 0 {
		return "", false
	}
	return pf.Masked().Addr().String(), true
}

// testPort picks the first entry of a grant's "ip" a test can assert: protocol none (Headscale's default set), tcp,
// udp or sctp, and a port that is not "*" — the first port of its first range.
func testPort(ips []string) (proto string, port int, ok bool) {
	for _, e := range ips {
		p, ports := splitIPProto(e)
		switch p {
		case testProtoDefault, "tcp", "udp", "sctp":
		default:
			continue
		}
		if ports == "*" {
			continue
		}
		first := ports
		if i := strings.IndexByte(first, ','); i >= 0 {
			first = first[:i]
		}
		if i := strings.IndexByte(first, '-'); i >= 0 {
			first = first[:i]
		}
		n, err := strconv.Atoi(first)
		if err != nil || n < 1 || n > denyPortCeiling {
			continue
		}
		return p, n, true
	}
	return "", 0, false
}

// splitIPProto splits "proto:ports" (proto may be absent).
func splitIPProto(e string) (proto, ports string) {
	if i := strings.IndexByte(e, ':'); i >= 0 {
		return e[:i], e[i+1:]
	}
	return "", e
}

// denyPort is a port no "ip" entry of any grant of the policy covers (whatever its protocol), searched from 65535 down
// to 1024 — so a deny assertion on it is true whatever the grants, via and autogroup:self included. 0 when an entry
// opens every port ("*") or nothing is free.
func denyPort(grants []Grant) int {
	type span struct{ lo, hi int }
	var spans []span
	for _, g := range grants {
		for _, e := range g.IP {
			_, ports := splitIPProto(e)
			if ports == "*" {
				return 0
			}
			for _, part := range strings.Split(ports, ",") {
				lo, hi := part, part
				if i := strings.IndexByte(part, '-'); i >= 0 {
					lo, hi = part[:i], part[i+1:]
				}
				a, err1 := strconv.Atoi(lo)
				b, err2 := strconv.Atoi(hi)
				if err1 != nil || err2 != nil {
					return 0 // not a port list the model accepts: no deny assertion
				}
				spans = append(spans, span{a, b})
			}
		}
	}
	for q := denyPortCeiling; q >= denyPortFloor; q-- {
		free := true
		for _, s := range spans {
			if q >= s.lo && q <= s.hi {
				free = false
				break
			}
		}
		if free {
			return q
		}
	}
	return 0
}

// WithoutTests is a canonical policy without its "tests" and "sshTests" blocks — what the CheckPolicy of a planned
// restart, a reconfiguration or an upgrade checks (§7.3): those blocks only run on a write (CheckPolicy, SetPolicy),
// never when the instance starts, and the generated ones name devices of the moment of the apply (PL-04) — a device
// removed since must not block a restart the stored policy does not block. A policy without them is returned as is.
func WithoutTests(applied string) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(applied), &top); err != nil {
		return "", err
	}
	_, t := top["tests"]
	_, s := top["sshTests"]
	if !t && !s {
		return applied, nil
	}
	delete(top, "tests")
	delete(top, "sshTests")
	b, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
