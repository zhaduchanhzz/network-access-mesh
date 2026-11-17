package reconcile

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// fakeGuard is a KeyGuard with a fixed answer (the database one is exercised by internal/provisioning/apikey).
type fakeGuard struct {
	cur   CurrentKey
	err   error
	calls int
}

func (g *fakeGuard) WithKeyLock(ctx context.Context, _, _ uuid.UUID, fn func(context.Context, CurrentKey) error) error {
	g.calls++
	if g.err != nil {
		return g.err
	}
	return fn(ctx, g.cur)
}

// TestKeyGuard (P3-T10): with a guard, the API key check compares the keys with the prefix and the clock read under the
// instance's API key lock — not with those of the start of the run, which a rotation may have changed meanwhile; a
// guard that cannot lock reports the check unavailable (api_key_rotation_in_progress), never a drift.
func TestKeyGuard(t *testing.T) {
	r := newRig(t)
	// The run read the registry before a rotation (desired prefix = the old key, clock now0). The rotation then created
	// the new key, recorded it and expired the old one, before the guard got the lock.
	old := currentKey()
	old.Expiration = now0.Add(90 * time.Second)
	fresh := headscale.APIKey{ID: 8, Prefix: "newKEY000001", CreatedAt: now0.Add(time.Minute), Expiration: now0.Add(90 * 24 * time.Hour)}
	r.hs.setKeys(old, fresh, expiredKey())
	g := &fakeGuard{cur: CurrentKey{Prefix: fresh.Prefix, Now: now0.Add(2 * time.Minute)}}
	r.in.KeyGuard = g
	rep, evs := r.run(t)
	if c := checkOf(rep, CheckAPIKeys); g.calls != 1 || len(rep.Findings) != 0 || len(evs) != 0 || c.Outcome != OutcomeOK ||
		c.Note != "valid=1" {
		t.Fatalf("guarded: calls %d, check %+v, findings %v, events %v", g.calls, c, kindsOf(rep), eventsOf(evs))
	}
	// negative control: without the guard the same run sees the new key as foreign
	r.in.KeyGuard = nil
	rep, evs = r.run(t)
	if !slices.Equal(kindsOf(rep), []string{DriftAPIKeyForeign + "/high"}) || len(evs) != 1 {
		t.Fatalf("unguarded: findings %v, events %v", kindsOf(rep), eventsOf(evs))
	}
	// the lock is not acquired in time: unavailable, no finding, Headscale not called
	r.hs.calls = nil
	r.in.KeyGuard = &fakeGuard{err: errors.New("store: tenant lock not acquired in time")}
	rep, evs = r.run(t)
	if c := checkOf(rep, CheckAPIKeys); c.Outcome != OutcomeUnavailable || c.Reason != ReasonKeyLocked || len(rep.Findings) != 0 ||
		len(evs) != 0 || slices.Contains(r.hs.called(), "ListAPIKeys") || rep.Status != StatusIncomplete {
		t.Fatalf("lock timeout: check %+v, findings %v, calls %v", c, kindsOf(rep), r.hs.called())
	}
	// no key recorded any more (read under the lock): not applicable
	r.in.KeyGuard = &fakeGuard{cur: CurrentKey{Now: now0}}
	rep, _ = r.run(t)
	if c := checkOf(rep, CheckAPIKeys); c.Outcome != OutcomeNotApplicable || c.Reason != ReasonNotRecorded {
		t.Fatalf("not recorded: %+v", c)
	}
}
