package console

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseCIDR(t *testing.T) {
	ok := []string{"203.0.113.7/32", "10.230.0.1/32", "192.0.2.0/24", "2001:db8::1/128", "2001:db8:1:100::/56"}
	bad := []string{"", "203.0.113.7", "203.0.113.7/33", "0.0.0.0/0", "10.0.0.0/8", "10.230.0.0/23", "192.0.2.1/24",
		"2001:db8::/48", "::/0", "127.0.0.1/32", "169.254.1.1/32", "224.0.0.1/32", "::1/128", "fe80::1/128",
		"::ffff:10.0.0.1/128", " 10.0.0.1/32", "10.0.0.1/32\n", "10.00.0.1/32"}
	for _, s := range ok {
		if _, err := ParseCIDR(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ParseCIDR(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if c, err := DefaultCIDR(netip.MustParseAddr("::ffff:10.230.0.1")); err != nil || c != "10.230.0.1/32" {
		t.Errorf("default of a mapped address: %q %v", c, err)
	}
	if c, err := DefaultCIDR(netip.MustParseAddr("2001:db8::7")); err != nil || c != "2001:db8::7/128" {
		t.Errorf("default IPv6: %q %v", c, err)
	}
	if _, err := DefaultCIDR(netip.Addr{}); err == nil {
		t.Error("an unknown address has a default CIDR")
	}
}

func TestPayloadValidate(t *testing.T) {
	id := uuid.New()
	good := Payload{IdentityID: id, SourceCIDR: "203.0.113.7/32", DurationMinutes: 30}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Payload{
		"no identity":  {SourceCIDR: "203.0.113.7/32", DurationMinutes: 30},
		"too short":    {IdentityID: id, SourceCIDR: "203.0.113.7/32", DurationMinutes: 4},
		"too long":     {IdentityID: id, SourceCIDR: "203.0.113.7/32", DurationMinutes: 61},
		"wide network": {IdentityID: id, SourceCIDR: "203.0.0.0/16", DurationMinutes: 30},
		"no network":   {IdentityID: id, DurationMinutes: 30},
	} {
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestDecide: a console request passes only for the person of an executed approval, inside its window, from its CIDR.
func TestDecide(t *testing.T) {
	me, other := uuid.New(), uuid.New()
	start := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	grant := func(who uuid.UUID, cidr string, minutes int, at time.Time) Grant {
		p := Payload{IdentityID: who, SourceCIDR: cidr, DurationMinutes: minutes}
		return Grant{ApprovalID: uuid.New(), Payload: p, ApprovedBy: other, StartsAt: at, EndsAt: at.Add(p.Duration())}
	}
	ip := netip.MustParseAddr("10.230.0.1")
	g := grant(me, "10.230.0.1/32", 15, start)
	for _, c := range []struct {
		name   string
		grants []Grant
		who    uuid.UUID
		ip     netip.Addr
		at     time.Time
		allow  bool
		reason string
	}{
		{"inside", []Grant{g}, me, ip, start.Add(5 * time.Minute), true, ReasonAllowed},
		{"start", []Grant{g}, me, ip, start, true, ReasonAllowed},
		{"end", []Grant{g}, me, ip, start.Add(15 * time.Minute), false, ReasonEnded},
		{"before", []Grant{g}, me, ip, start.Add(-time.Second), false, ReasonEnded},
		{"another address", []Grant{g}, me, netip.MustParseAddr("10.230.0.2"), start.Add(time.Minute), false, ReasonSourceIP},
		{"mapped address", []Grant{g}, me, netip.MustParseAddr("::ffff:10.230.0.1"), start.Add(time.Minute), true, ReasonAllowed},
		{"unknown address", []Grant{g}, me, netip.Addr{}, start.Add(time.Minute), false, ReasonSourceIP},
		{"someone else's session", []Grant{g}, other, ip, start.Add(time.Minute), false, ReasonNoSession},
		{"no session", nil, me, ip, start, false, ReasonNoSession},
		{"payload naming another person", []Grant{grant(other, "10.230.0.1/32", 15, start)}, me, ip, start.Add(time.Minute),
			false, ReasonNoSession},
		{"an ended and an open one", []Grant{grant(me, "10.230.0.1/32", 5, start.Add(-time.Hour)), g}, me, ip,
			start.Add(time.Minute), true, ReasonAllowed},
		{"office network", []Grant{grant(me, "10.230.0.0/24", 15, start)}, me, netip.MustParseAddr("10.230.0.77"),
			start.Add(time.Minute), true, ReasonAllowed},
	} {
		d := Decide(c.grants, c.who, c.ip, c.at)
		if d.Allowed != c.allow || d.Reason != c.reason {
			t.Errorf("%s: %+v, want allow=%v %s", c.name, d, c.allow, c.reason)
		}
	}
}

func TestIsImpersonation(t *testing.T) {
	for uri, want := range map[string]bool{
		"/admin/realms/tenant-a/users/2809355a-a2aa-4862-874b-26f46b5456ad/impersonation": true,
		"/admin/realms/tenant-a/users/x/impersonation/":                                   true,
		"/admin/realms/tenant-a/users/x/IMPERSONATION?x=1":                                true,
		"/admin/realms/tenant-a/users/x":                                                  false,
		"/admin/realms/tenant-a/users/x/impersonation-not":                                false,
		"/admin/realms/tenant-a/users/x/role-mappings":                                    false,
		"/admin/master/console/":                                                          false,
		"/realms/master/protocol/openid-connect/auth?redirect=/users/x/impersonation":     false,
	} {
		if got := IsImpersonation(uri); got != want {
			t.Errorf("%q: %v", uri, got)
		}
	}
}

func TestSessionOf(t *testing.T) {
	decided := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	payload := []byte(`{"duration_minutes":15,"identity_id":"` + uuid.NewString() + `","source_cidr":"10.230.0.1/32"}`)
	for _, c := range []struct {
		status string
		at     time.Time
		want   string
	}{
		{"pending", decided, StatusPending}, {"approved", decided, StatusPending}, {"rejected", decided, StatusRejected},
		{"expired", decided, StatusExpired}, {"executed", decided.Add(time.Minute), StatusActive},
		{"executed", decided.Add(15 * time.Minute), StatusEnded},
	} {
		s, ok := SessionOf(c.status, payload, &decided, c.at)
		if !ok || s.Status != c.want {
			t.Errorf("%s at %s: %+v %v, want %s", c.status, c.at, s, ok, c.want)
		}
	}
	if _, ok := SessionOf("executed", []byte(`{"x":1}`), &decided, decided); ok {
		t.Error("a payload that does not decode is a session")
	}
	if _, ok := SessionOf("executed", payload, nil, decided); ok {
		t.Error("an executed request without decision time is a session")
	}
	g, ok := grantOf(uuid.New(), payload, &decided, &[]uuid.UUID{uuid.New()}[0])
	if !ok || !g.EndsAt.Equal(decided.Add(15*time.Minute)) {
		t.Errorf("grant %+v %v", g, ok)
	}
}
