package policies

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func addr(s string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(s)} }

// TestEvaluateAccess pins the principal semantics of the access evaluator (P5-T08) on documents shaped like the
// renderer's output.
func TestEvaluateAccess(t *testing.T) {
	alice, bob := uuid.New(), uuid.New()
	aliceLaptop := AccessPeer{Owner: alice, Addresses: addr("100.64.0.1")}
	alicePhone := AccessPeer{Owner: alice, Addresses: addr("100.64.0.2")}
	bobLaptop := AccessPeer{Owner: bob, Addresses: addr("100.64.0.3")}
	server := AccessPeer{Tags: []string{"tag:server"}, Addresses: addr("100.64.0.10")}
	unknownOwner := AccessPeer{Addresses: addr("100.64.0.4")}
	db := &AccessResource{Name: "db", Address: netip.MustParsePrefix("10.77.0.5/32"), RouterTags: [][]string{{"tag:router"}}}
	subnet := &AccessResource{Name: "lab", Address: netip.MustParsePrefix("10.78.0.0/24"), RouterTags: [][]string{{"tag:other"}}}

	doc := `// rendered
{
  "groups": {"group:eng": ["mg-` + alice.String() + `@"]},
  "hosts": {"db": "10.77.0.5", "lab": "10.78.0.0/24"},
  "tagOwners": {"tag:server": []},
  "grants": [
    {"src": ["group:eng"], "dst": ["tag:server"], "ip": ["tcp:22", "tcp:443"]},
    {"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
    {"src": ["mg-` + bob.String() + `@"], "dst": ["db"], "ip": ["tcp:5432"], "via": ["tag:router"]},
    {"src": ["autogroup:member"], "dst": ["lab"], "ip": ["tcp:80"], "via": ["tag:router"]},
    {"src": ["tag:server"], "dst": ["100.64.0.0/10"], "ip": ["udp:53", "icmp:*"]},
    {"src": ["autogroup:tagged"], "dst": ["autogroup:internet"], "ip": ["*"]},
    {"src": ["*"], "dst": ["*"], "app": {"example.com/cap": [{}]}}
  ],
  "ssh": [],
}`
	for name, c := range map[string]struct {
		q        AccessQuery
		decision string
		reason   string
		grants   []int
	}{
		"group member to tagged server, allowed port": {AccessQuery{Src: aliceLaptop, Dst: &server, Port: 443}, AccessAllowed, "", []int{0}},
		"group member, port not granted":              {AccessQuery{Src: aliceLaptop, Dst: &server, Port: 8080}, AccessDenied, AccessReasonPortNotAllowed, []int{0}},
		"group member, any port":                      {AccessQuery{Src: aliceLaptop, Dst: &server}, AccessAllowed, "", []int{0}},
		"not in the group":                            {AccessQuery{Src: bobLaptop, Dst: &server, Port: 22}, AccessDenied, AccessReasonNoGrant, nil},
		"autogroup:self, same owner":                  {AccessQuery{Src: aliceLaptop, Dst: &alicePhone, Port: 3389}, AccessAllowed, "", []int{1}},
		"autogroup:self, another owner":               {AccessQuery{Src: aliceLaptop, Dst: &bobLaptop, Port: 22}, AccessDenied, AccessReasonNoGrant, nil},
		"user to resource through a via router":       {AccessQuery{Src: bobLaptop, Resource: db, Port: 5432}, AccessAllowed, "", []int{2}},
		"another user to the resource":                {AccessQuery{Src: aliceLaptop, Resource: db, Port: 5432}, AccessDenied, AccessReasonNoGrant, nil},
		"via tag missing on the router":               {AccessQuery{Src: aliceLaptop, Resource: subnet, Port: 80}, AccessDenied, AccessReasonNoGrant, nil},
		"tagged to a device, no TCP":                  {AccessQuery{Src: server, Dst: &aliceLaptop}, AccessDenied, AccessReasonNoTCP, []int{4}},
		"self with an unknown owner is unknown":       {AccessQuery{Src: unknownOwner, Dst: &alicePhone, Port: 22}, AccessUnknown, AccessReasonUnresolved, nil},
	} {
		got := EvaluateAccess([]byte(doc), c.q)
		if got.Decision != c.decision || got.Reason != c.reason || !slices.Equal(got.Grants, append([]int{}, c.grants...)) {
			t.Errorf("%s: got %+v, want %s/%s grants %v", name, got, c.decision, c.reason, c.grants)
		}
	}
	got := EvaluateAccess([]byte(doc), AccessQuery{Src: aliceLaptop, Dst: &server})
	if !slices.Equal(got.Allowed, []string{"tcp:22", "tcp:443"}) {
		t.Errorf("allowed entries %v", got.Allowed)
	}
}

func TestEvaluateAccessDocuments(t *testing.T) {
	a := AccessPeer{Owner: uuid.New(), Addresses: addr("100.64.0.1")}
	b := AccessPeer{Owner: uuid.New(), Addresses: addr("100.64.0.2")}
	for name, c := range map[string]struct {
		doc, decision, reason string
	}{
		"deny-all baseline":   {`{"grants": [], "ssh": []}`, AccessDenied, AccessReasonNoGrant},
		"unreadable":          {`{"grants": [`, AccessUnknown, AccessReasonUnreadable},
		"no grants array":     {`{"ssh": []}`, AccessUnknown, AccessReasonUnsupported},
		"legacy acls":         {`{"grants": [], "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`, AccessUnknown, AccessReasonUnsupported},
		"allow all":           {`{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`, AccessAllowed, ""},
		"port range and list": {`{"grants": [{"src": ["autogroup:member"], "dst": ["100.64.0.2"], "ip": ["22,8000-8010"]}]}`, AccessAllowed, ""},
		"udp only":            {`{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["udp:8005"]}]}`, AccessDenied, AccessReasonPortNotAllowed},
		"unknown principal":   {`{"grants": [{"src": ["someone@example.com"], "dst": ["*"], "ip": ["*"]}]}`, AccessUnknown, AccessReasonUnresolved},
	} {
		got := EvaluateAccess([]byte(c.doc), AccessQuery{Src: a, Dst: &b, Port: 8005})
		if got.Decision != c.decision || got.Reason != c.reason {
			t.Errorf("%s: got %s/%s, want %s/%s", name, got.Decision, got.Reason, c.decision, c.reason)
		}
	}
}

func TestPortAllowed(t *testing.T) {
	for _, c := range []struct {
		spec string
		port int
		want bool
	}{
		{"*", 22, true}, {"tcp:*", 1, true}, {"tcp:22", 22, true}, {"tcp:22", 23, false}, {"22", 22, true},
		{"6:443", 443, true}, {"udp:53", 53, false}, {"icmp:*", 0, false}, {"tcp:80-90", 85, true}, {"tcp:80-90", 91, false},
		{"tcp:22,443", 443, true}, {"tcp:22", 0, true}, {"tcp:x", 0, false},
	} {
		if got := portAllowed(c.spec, c.port); got != c.want {
			t.Errorf("portAllowed(%q, %d) = %v", c.spec, c.port, got)
		}
	}
}
