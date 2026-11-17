package devices

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

func TestParseNodeExpiry(t *testing.T) {
	for in, want := range map[string]time.Duration{"2160h": 2160 * time.Hour, "720h": 720 * time.Hour, "90d": 90 * 24 * time.Hour,
		"0": 0, "0s": 0, "0h": 0, " 48h ": 48 * time.Hour} {
		if got, err := ParseNodeExpiry(in); err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-1h", "abc", "1x", "-3d", "99999999d", "1000000h"} {
		if _, err := ParseNodeExpiry(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestClampOf is the rule of §13.4 applied by a sync: strict from created_at for a node seen for the first time within
// its first node_expiry, lenient (from the snapshot time) otherwise — a legitimate re-auth is never clamped; tagged
// nodes and an unknown limit never are.
func TestClampOf(t *testing.T) {
	t0 := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	limit := 720 * time.Hour
	id := uuid.New()
	node := func(created time.Time, exp *time.Time, tags ...string) headscale.Node {
		return headscale.Node{ID: 9, MachineKey: "mkey:9", CreatedAt: created, Expiry: exp, Tags: tags,
			User: &headscale.User{ID: 1, Name: "mg-x"}}
	}
	cases := []struct {
		name      string
		n         headscale.Node
		firstSeen bool
		limit     time.Duration
		want      *time.Time // nil: no clamp
	}{
		{"new node, client asked 10 years", node(t0.Add(-time.Hour), tp(t0.Add(87600*time.Hour))), true, limit, tp(t0.Add(-time.Hour).Add(limit))},
		{"new node, client asked 9999-12-31", node(t0.Add(-time.Hour), tp(time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC))), true, limit, tp(t0.Add(-time.Hour).Add(limit))},
		{"new node, default expiry (+ms)", node(t0.Add(-time.Hour), tp(t0.Add(-time.Hour).Add(limit+3*time.Millisecond))), true, limit, nil},
		{"new node, slightly beyond (2 min)", node(t0.Add(-time.Hour), tp(t0.Add(-time.Hour).Add(limit+2*time.Minute))), true, limit, tp(t0.Add(-time.Hour).Add(limit))},
		{"new node, no expiry", node(t0.Add(-time.Hour), nil), true, limit, tp(t0.Add(-time.Hour).Add(limit))},
		{"known node re-authenticated now", node(t0.Add(-40*24*time.Hour), tp(t0.Add(limit))), false, limit, nil},
		{"known node re-auth asking 5 years", node(t0.Add(-40*24*time.Hour), tp(t0.Add(43800*time.Hour))), false, limit, tp(t0.Add(limit))},
		{"first sight of an old node (adopted instance)", node(t0.Add(-100*24*time.Hour), tp(t0.Add(limit))), true, limit, nil},
		{"tagged node without expiry", node(t0.Add(-time.Hour), nil, "tag:ci"), true, limit, nil},
		{"no limit known", node(t0.Add(-time.Hour), nil), true, 0, nil},
	}
	for _, c := range cases {
		got, ok := clampOf(c.n, id, t0, c.limit, c.firstSeen)
		switch {
		case c.want == nil && ok:
			t.Errorf("%s: clamped to %s, want no clamp", c.name, got.target)
		case c.want != nil && (!ok || !got.target.Equal(*c.want) || got.deviceID != id || got.nodeID != 9):
			t.Errorf("%s: %+v %v, want target %s", c.name, got, ok, c.want)
		}
	}
}

// TestNormalise: owner of a user-owned node from its Headscale user (mg-<membership>), unknown user ⇒ no owner (but
// still decided by Headscale), tagged node (ListNodes: tagged-devices) ⇒ owner kept, no Headscale user id.
func TestNormalise(t *testing.T) {
	m := uuid.New()
	owners := map[string]uuid.UUID{"mg-" + m.String(): m}
	c := normalise(headscale.Node{User: &headscale.User{ID: 4, Name: "mg-" + m.String()}, Name: "laptop"}, owners)
	if !c.setOwner || c.owner == nil || *c.owner != m || deref(c.userID) != 4 || deref(c.name) != "laptop" || c.givenName != nil {
		t.Errorf("user-owned: %+v", c)
	}
	c = normalise(headscale.Node{User: &headscale.User{ID: 5, Name: "outsider"}}, owners)
	if !c.setOwner || c.owner != nil {
		t.Errorf("unknown user: %+v", c)
	}
	c = normalise(headscale.Node{User: &headscale.User{Name: headscale.TaggedDevicesUser}, Tags: []string{"tag:a"}}, owners)
	if c.setOwner || c.owner != nil || c.userID != nil {
		t.Errorf("tagged: %+v", c)
	}
	p := c.update(uuid.New(), uuid.New(), time.Now(), 3)
	if p.IpAddresses == nil || p.ApprovedRoutes == nil || p.Tags == nil || p.SetOwner {
		t.Errorf("update params must carry empty, not nil, arrays: %+v", p)
	}
}

// TestAccess is the own-resource rule (§8.4 invariant 3b, same as authz.Decision.CheckOwner).
func TestAccess(t *testing.T) {
	me, other := uuid.New(), uuid.New()
	row := func(owner *uuid.UUID, tags ...string) sqlcdb.DeviceInventoryCache {
		return sqlcdb.DeviceInventoryCache{OwnerMembershipID: owner, Tags: tags}
	}
	all, own := Access{}, Access{OwnOnly: true, MembershipID: me}
	for _, c := range []struct {
		name string
		a    Access
		r    sqlcdb.DeviceInventoryCache
		want bool
	}{
		{"any: someone else's tagged device", all, row(&other, "tag:x"), true},
		{"own: mine", own, row(&me), true},
		{"own: someone else's", own, row(&other), false},
		{"own: no owner", own, row(nil), false},
		{"own: mine but tagged", own, row(&me, "tag:x"), false},
		{"own without membership", Access{OwnOnly: true}, row(&uuid.Nil), false},
	} {
		if got := c.a.owns(c.r); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCursorAndETag(t *testing.T) {
	tenant := uuid.New()
	q := ListQuery{Tag: "tag:a"}
	b := binding(tenant, Access{}, q)
	c := cursor{seen: time.Date(2026, 11, 17, 8, 0, 0, 123456000, time.UTC), id: uuid.New()}
	s := encodeCursor(c, b)
	got, ok := decodeCursor(s, b)
	if !ok || !got.seen.Equal(c.seen) || got.id != c.id {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
	on := true
	for what, other := range map[string][]byte{
		"other tenant":   binding(uuid.New(), Access{}, q),
		"other filter":   binding(tenant, Access{}, ListQuery{Tag: "tag:b"}),
		"online filter":  binding(tenant, Access{}, ListQuery{Tag: "tag:a", Online: &on}),
		"own-only view":  binding(tenant, Access{OwnOnly: true, MembershipID: uuid.New()}, q),
		"search filter":  binding(tenant, Access{}, ListQuery{Tag: "tag:a", Search: "x"}),
		"owner filter":   binding(tenant, Access{}, ListQuery{Tag: "tag:a", Owner: &c.id}),
		"tampered input": b,
	} {
		in := s
		if what == "tampered input" {
			in = s[:len(s)-2] + "AA"
		}
		if _, ok := decodeCursor(in, other); ok {
			t.Errorf("%s: cursor accepted", what)
		}
	}
	if setETag([]string{"b", "a", "a"}) != setETag([]string{"a", "b"}) || setETag(nil) == setETag([]string{"a"}) {
		t.Error("set ETag must ignore order and duplicates and differ by content")
	}
}

// TestAdapterErrorMapping: the Problem code of each adapter error kind and whether a job retries it.
func TestAdapterErrorMapping(t *testing.T) {
	for _, c := range []struct {
		kind      headscale.Kind
		code      string
		transient bool
	}{
		{headscale.KindUnavailable, CodeInstanceUnavailable, true},
		{headscale.KindCircuitOpen, CodeInstanceUnavailable, true},
		{headscale.KindAPIKeyRejected, CodeInstanceUnavailable, true},
		{headscale.KindEdgeRejected, CodeInstanceUnavailable, true},
		{headscale.KindUnsupportedVersion, CodeInstanceUnavailable, true},
		{headscale.KindInternal, CodeInternal, true},
		{headscale.KindUpstreamRejected, CodeUpstreamRejected, false},
		{headscale.KindValidation, CodeValidationFailed, false},
		{headscale.KindConflict, CodeConflict, false},
		{headscale.KindNotFound, CodeNotFound, false},
	} {
		err := fmt.Errorf("wrapped: %w", &headscale.Error{Op: headscale.OpExpireNode, Kind: c.kind, Code: -1, Upstream: "secret-ish upstream text"})
		e := fromAdapter(err)
		if e.Code != c.code || transient(err) != c.transient {
			t.Errorf("%s: code %s transient %v, want %s %v", c.kind, e.Code, transient(err), c.code, c.transient)
		}
		if e.Detail == "secret-ish upstream text" {
			t.Errorf("%s: the upstream message became the detail", c.kind)
		}
	}
	if e := fromAdapter(context.DeadlineExceeded); e.Code != CodeInstanceUnavailable {
		t.Errorf("deadline: %s", e.Code)
	}
	if e := fromAdapter(errors.New("db down")); e.Code != CodeInternal || !transient(errors.New("db down")) {
		t.Errorf("plain error: %s", e.Code)
	}
	if !isGone(&headscale.Error{Kind: headscale.KindNotFound}) || isGone(&headscale.Error{Kind: headscale.KindConflict}) {
		t.Error("isGone")
	}
}

// TestSchedulerSlots: one period per Interval, each instance at its own deterministic offset.
func TestSchedulerSlots(t *testing.T) {
	sc := &Scheduler{cfg: SchedulerConfig{Interval: time.Minute}}
	t0 := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	changes := map[time.Duration]bool{}
	for _, id := range ids {
		base := sc.slot(id, t0)
		if sc.slot(id, t0.Add(time.Minute)) != base+1 || sc.slot(id, t0) != base {
			t.Fatalf("instance %s: slots %d → %d", id, base, sc.slot(id, t0.Add(time.Minute)))
		}
		for d := time.Second; d <= time.Minute; d += time.Second {
			if sc.slot(id, t0.Add(d)) != base {
				changes[d] = true
				break
			}
		}
	}
	if len(changes) < 2 {
		t.Errorf("five instances start their period at %d distinct offsets; the schedule does not spread them", len(changes))
	}
}
