package devices

// Interleavings of inventory.sync (snapshot, apply, expiry clamp) with a revocation or an operator's expire (T-17,
// §7.4, §13.4). Each one is injected at an exact point of a call through the one-shot hooks of the fake Headscale
// (devicestest.Fake.Before/After) or by calling the steps of the sync directly — no sleeps.

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
)

// raceFixture: tenant A with Alice's node 1, whose client asked for 10 years (V-21), put in the register by a sync
// without a limit (nothing clamped yet), then node_expiry = 720h: the next sync has a clamp candidate.
func raceFixture(t *testing.T) (*fixture, *tenantFx, uuid.UUID, time.Time) {
	t.Helper()
	f := newFixture(t)
	a := f.a
	now := time.Now().UTC().Truncate(time.Second)
	far := now.Add(10 * 365 * 24 * time.Hour)
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, now.Add(-2*time.Hour), tp(far)))
	a.hs.PutKey(devicestest.Key{ID: 1, UserID: a.aliceUser, UserName: a.userName(a.alice), Reusable: true, Expiration: now.Add(time.Hour)})
	if rep, err := f.wrk.Sync(context.Background(), a.id, a.instance); err != nil || rep.Clamped+rep.ClampFailed+rep.ClampSkipped != 0 {
		t.Fatalf("first sync: %+v %v", rep, err)
	}
	f.setNodeExpiry(t, a, "720h")
	return f, a, f.deviceOfNode(t, a, 1), far
}

// requestExpire asks for an expire of dev through the API (pending + job).
func (f *fixture) requestExpire(ten *tenantFx, dev uuid.UUID) (RevokeResult, error) {
	id := uuid.New()
	return f.api.Revoke(actorCtx(id, ten.id, ActionExpire), ten.id, dev, Access{IdentityID: id}, RevokeExpire, "")
}

// runJob runs one attempt of a device.revoke job to its end.
func (f *fixture) runJob(job uuid.UUID) error {
	run, err := f.runOf(job, 1, 8)
	if err != nil {
		return err
	}
	return f.wrk.runRevoke(context.Background(), run)
}

// laterCalls lists the ExpireNode calls of node id with a target later than at (+ the read-back window).
func laterCalls(hs *devicestest.Fake, id uint64, at time.Time) []time.Time {
	var out []time.Time
	for _, x := range hs.ExpireCalls(id) {
		if x.After(at.Add(expiryWindow)) {
			out = append(out, x)
		}
	}
	return out
}

// TestStaleSnapshotAppliedAfterRevocation is the race of the batch-5 integration: an inventory.sync lists the nodes
// before the revocation job expires the node, and applies its snapshot after the revocation settled applied
// (synced_at < verified_at). The snapshot must neither write its later expiry over the verified one nor yield a clamp
// candidate — whose ExpireNode(T0 + node_expiry) would extend the node that was just revoked.
func TestStaleSnapshotAppliedAfterRevocation(t *testing.T) {
	for _, requestedBefore := range []bool{true, false} {
		name := "requested after the snapshot"
		if requestedBefore {
			name = "pending at the snapshot"
		}
		t.Run(name, func(t *testing.T) {
			f, a, dev, far := raceFixture(t)
			ctx := context.Background()
			var early RevokeResult
			if requestedBefore {
				var err error
				if early, err = f.requestExpire(a, dev); err != nil {
					t.Fatal(err)
				}
			}
			// ListNodes has answered (10-year expiry); before the answer reaches the sync, the revocation runs to the end.
			ran := make(chan RevokeResult, 1)
			a.hs.After(devicestest.OpListNodes, func(uint64) {
				res, err := early, error(nil)
				if !requestedBefore {
					res, err = f.requestExpire(a, dev)
				}
				if err == nil {
					err = f.runJob(res.JobID)
				}
				if err != nil {
					t.Errorf("revocation during the sync: %v", err)
				}
				ran <- res
			})
			rep, err := f.wrk.Sync(ctx, a.id, a.instance)
			if err != nil {
				t.Fatal(err)
			}
			var res RevokeResult
			select {
			case res = <-ran:
			default:
				t.Fatal("the hook of ListNodes did not run")
			}
			row := f.row(t, dev)
			if row.RevocationState != StateApplied || row.RevocationRequestedAt == nil || row.RevocationVerifiedAt == nil {
				t.Fatalf("revocation not applied: %+v", row)
			}
			revoked := *row.RevocationRequestedAt
			if !row.LastSyncedAt.Before(*row.RevocationVerifiedAt) || !rep.SyncedAt.Equal(row.LastSyncedAt) {
				t.Fatalf("not the race: synced_at %s (report %s), verified_at %s", row.LastSyncedAt, rep.SyncedAt, row.RevocationVerifiedAt)
			}
			if row.Expiry == nil || row.Expiry.After(revoked) {
				t.Errorf("cached expiry %v after the applied revocation (%s): the stale snapshot's %s was written", row.Expiry, revoked, far)
			}
			if n, _ := a.hs.Node(1); n.Expiry == nil || n.Expiry.After(revoked.Add(expiryWindow)) {
				t.Errorf("node expiry on the instance %v after the revocation at %s: the revoked node was extended", n.Expiry, revoked)
			}
			if later := laterCalls(a.hs, 1, revoked); len(later) != 0 {
				t.Errorf("ExpireNode sent with a target later than the revocation: %v", later)
			}
			if rep.Updated != 1 || rep.Clamped != 0 || rep.ClampFailed != 0 || rep.ClampSkipped != 0 {
				t.Errorf("report %+v: a snapshot older than the revocation must yield no clamp candidate", rep)
			}
			if got := f.auditOf(t, dev.String()); !slices.Equal(got, []string{"device.expire.requested/success", "device.expire.succeeded/success"}) {
				t.Errorf("audit of the device: %v", got)
			}
			if n := count(t, f, `SELECT count(*) FROM security_events WHERE details ->> 'device_id' = $1`, dev.String()); n != 0 {
				t.Errorf("%d security events for the revoked device", n)
			}
			if f.openOperations(t, a.id) != 0 {
				t.Error("an audit operation is left open")
			}

			// The next sync lists the revoked node: the same expiry, nothing to clamp.
			f.finishJob(t, res.JobID, "succeeded")
			rep, err = f.wrk.Sync(ctx, a.id, a.instance)
			if r := f.row(t, dev); err != nil || rep.Clamped+rep.ClampFailed+rep.ClampSkipped != 0 || r.Expiry == nil ||
				!r.Expiry.Equal(*row.Expiry) || r.RevocationState != StateApplied {
				t.Errorf("next sync: %+v %v, expiry %v, state %s", rep, err, r.Expiry, r.RevocationState)
			}
		})
	}
}

// TestClampLeavesExpiredNodeAlone: a clamp only ever shortens an expiry. (1) The sync's snapshot shows the 10-year
// expiry, but an operator expires the node (CLI) before the clamp runs: no ExpireNode, no audit pair — the stale
// candidate would set the node back to T0 + node_expiry. (2) A candidate whose target is already past, on a node that
// expired after it: an expiry already ≤ now is never touched; the same candidate on a node without expiry is clamped.
func TestClampLeavesExpiredNodeAlone(t *testing.T) {
	f, a, dev, far := raceFixture(t)
	ctx := context.Background()
	expired := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	a.hs.After(devicestest.OpListNodes, func(uint64) {
		n, _ := a.hs.Node(1)
		n.Expiry = &expired
		a.hs.PutNode(n)
	})
	rep, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil || rep.ClampSkipped != 1 || rep.Clamped != 0 || rep.ClampFailed != 0 {
		t.Fatalf("sync: %+v %v, want the candidate of the stale snapshot skipped", rep, err)
	}
	if n, _ := a.hs.Node(1); n.Expiry == nil || !n.Expiry.Equal(expired) || len(a.hs.ExpireCalls(1)) != 0 {
		t.Errorf("node expired by the operator: expiry %v, ExpireNode calls %v — want untouched", n.Expiry, a.hs.ExpireCalls(1))
	}
	if got := f.auditOf(t, dev.String()); len(got) != 0 {
		t.Errorf("audit of a skipped clamp: %v, want none", got)
	}
	if n := count(t, f, `SELECT count(*) FROM security_events WHERE details ->> 'device_id' = $1`, dev.String()); n != 0 {
		t.Errorf("%d security events for a skipped clamp", n)
	}
	if rep, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil || rep.Clamped+rep.ClampFailed+rep.ClampSkipped != 0 ||
		!deref(f.row(t, dev).Expiry).Equal(expired) {
		t.Errorf("next sync: %+v %v, cached expiry %v, want %s", rep, err, f.row(t, dev).Expiry, expired)
	}

	inst, err := f.reg.ForTenant(ctx, a.id)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := a.hs.Node(1)
	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	n.Expiry = &past
	a.hs.PutNode(n)
	c := clampCandidate{deviceID: dev, nodeID: 1, machineKey: n.MachineKey, observed: &far, target: past.Add(-time.Hour)}
	if r := f.wrk.clamp(ctx, a.id, inst, c, 720*time.Hour, ClampSourceTenant); r != clampSkipped || len(a.hs.ExpireCalls(1)) != 0 {
		t.Errorf("clamp of a node expired at %s to %s: result %d, ExpireNode calls %v — want skipped", past, c.target, r, a.hs.ExpireCalls(1))
	}
	n.Expiry = nil
	a.hs.PutNode(n)
	if r := f.wrk.clamp(ctx, a.id, inst, c, 720*time.Hour, ClampSourceTenant); r != clampDone || len(a.hs.ExpireCalls(1)) != 1 {
		t.Errorf("control — the same candidate on a node without expiry: result %d, ExpireNode calls %v", r, a.hs.ExpireCalls(1))
	}
	// (3) The node changed since the snapshot: tagged (never expires, reviewed separately), or its id handed out again to
	// another machine — neither is written.
	tagged := n
	tagged.Tags = []string{"tag:server"}
	a.hs.PutNode(tagged)
	if r := f.wrk.clamp(ctx, a.id, inst, c, 720*time.Hour, ClampSourceTenant); r != clampSkipped || len(a.hs.ExpireCalls(1)) != 1 {
		t.Errorf("clamp of a node tagged since the snapshot: result %d, ExpireNode calls %v", r, a.hs.ExpireCalls(1))
	}
	other := n
	other.MachineKey = "mkey:" + "another-machine"
	a.hs.PutNode(other)
	if r := f.wrk.clamp(ctx, a.id, inst, c, 720*time.Hour, ClampSourceTenant); r != clampSkipped || len(a.hs.ExpireCalls(1)) != 1 {
		t.Errorf("clamp of a node id now held by another machine: result %d, ExpireNode calls %v", r, a.hs.ExpireCalls(1))
	}
	if f.openOperations(t, a.id) != 0 {
		t.Error("an audit operation is left open")
	}
}

// TestClampSkipsPendingRevocation: the snapshot is applied (a clamp candidate), then a revocation is requested, then
// the clamp runs. The device is pending: the clamp leaves the node to the revocation job — no ExpireNode, although the
// node still shows the 10-year expiry (the job has not run yet) — and the job then applies the revocation.
func TestClampSkipsPendingRevocation(t *testing.T) {
	f, a, dev, _ := raceFixture(t)
	ctx := context.Background()
	inst, err := f.reg.ForTenant(ctx, a.id)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := inst.ListNodes(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var t0 time.Time
	f.scan(t, `SELECT clock_timestamp()`, nil, &t0)
	var rep SyncReport
	clamps, _, err := f.wrk.apply(ctx, a.id, a.instance, t0, nodes, map[string]uuid.UUID{a.userName(a.alice): a.alice}, 720*time.Hour, &rep)
	if err != nil || len(clamps) != 1 || clamps[0].deviceID != dev {
		t.Fatalf("apply: %v, candidates %+v", err, clamps)
	}
	res := f.revoke(t, a, dev, RevokeExpire, "")
	if r := f.wrk.clamp(ctx, a.id, inst, clamps[0], 720*time.Hour, ClampSourceTenant); r != clampSkipped {
		t.Errorf("clamp of a device whose revocation is pending: result %d, want skipped", r)
	}
	if calls := a.hs.ExpireCalls(1); len(calls) != 0 {
		t.Errorf("ExpireNode sent for a device whose revocation is pending: %v", calls)
	}
	if got := f.auditOf(t, dev.String()); !slices.Equal(got, []string{"device.expire.requested/success"}) {
		t.Errorf("audit: %v", got)
	}
	// A snapshot applied while the revocation is pending yields no candidate either: the job owns the expiry.
	f.scan(t, `SELECT clock_timestamp()`, nil, &t0)
	if clamps, _, err := f.wrk.apply(ctx, a.id, a.instance, t0, nodes, map[string]uuid.UUID{a.userName(a.alice): a.alice}, 720*time.Hour,
		&rep); err != nil || len(clamps) != 0 {
		t.Errorf("snapshot applied while pending: %v, candidates %+v", err, clamps)
	}
	if err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 1, 8)); err != nil {
		t.Fatal(err)
	}
	row := f.row(t, dev)
	if n, _ := a.hs.Node(1); row.RevocationState != StateApplied || n.Expiry == nil || !n.Expiry.Equal(row.RevocationRequestedAt.UTC()) {
		t.Errorf("after the job: state %s, node expiry %v, requested %v", row.RevocationState, n.Expiry, row.RevocationRequestedAt)
	}
	if later := laterCalls(a.hs, 1, *row.RevocationRequestedAt); len(later) != 0 {
		t.Errorf("ExpireNode with a target later than the revocation: %v", later)
	}
}

// TestRevocationDuringClampWrite is the narrowest interleaving: the clamp checked the device and re-read the node, sent
// ExpireNode(target), and the device is revoked to the end before that write lands. Nothing held across a Headscale
// call may prevent it (§13.5 d), so the clamp looks at the device again after its write: the revocation started
// meanwhile gets its own expiry applied again, the clamp is recorded failed (revocation_started) and the revocation
// holds. If that second write fails too, the clamp raises a high-severity security event (alert).
func TestRevocationDuringClampWrite(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprintf("re-apply refused %v", refused), func(t *testing.T) {
			f, a, dev, _ := raceFixture(t)
			ctx := context.Background()
			a.hs.Before(devicestest.OpExpireNode, func(uint64) {
				res, err := f.requestExpire(a, dev)
				if err == nil {
					err = f.runJob(res.JobID)
				}
				if err != nil {
					t.Errorf("revocation during the clamp's write: %v", err)
				}
				if refused { // the clamp's write lands, then the instance refuses every write
					a.hs.After(devicestest.OpExpireNode, func(uint64) { a.hs.Refuse(devicestest.OpExpireNode, true) })
				}
			})
			rep, err := f.wrk.Sync(ctx, a.id, a.instance)
			if err != nil {
				t.Fatal(err)
			}
			row := f.row(t, dev)
			if row.RevocationState != StateApplied || row.RevocationRequestedAt == nil {
				t.Fatalf("revocation: %+v", row)
			}
			revoked := *row.RevocationRequestedAt
			calls := a.hs.ExpireCalls(1) // in the order the instance applied them
			if len(calls) != 3 || !calls[0].Equal(revoked) || !calls[1].After(revoked) || !calls[2].Equal(revoked) {
				t.Fatalf("ExpireNode calls %v (revocation at %s): want the revocation, the clamp's target landing after it, the revocation again",
					calls, revoked)
			}
			if rep.ClampFailed != 1 || rep.Clamped != 0 {
				t.Errorf("report %+v: the clamp superseded by the revocation is failed", rep)
			}
			if row.Expiry == nil || !row.Expiry.Equal(revoked) {
				t.Errorf("cached expiry %v, want the revocation's %s", row.Expiry, revoked)
			}
			n, _ := a.hs.Node(1)
			reapplied, severity := !refused, "medium"
			if refused {
				severity = "high"
				if n.Expiry == nil || !n.Expiry.Equal(calls[1]) { // the residual case the alert is for
					t.Errorf("node expiry %v, want the clamp's %s (re-apply refused)", n.Expiry, calls[1])
				}
			} else if n.Expiry == nil || n.Expiry.After(revoked.Add(expiryWindow)) {
				t.Errorf("node expiry %v after the revocation at %s: the clamp undid the revocation", n.Expiry, revoked)
			}
			if c := count(t, f, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'device.expiry_clamp.failed'
					AND details ->> 'reason' = 'revocation_started' AND (details ->> 'revocation_reapplied')::boolean = $2`, dev.String(), reapplied); c != 1 {
				t.Errorf("device.expiry_clamp.failed (revocation_started, reapplied %v): %d, want 1", reapplied, c)
			}
			if c := count(t, f, `SELECT count(*) FROM security_events WHERE kind = 'expiry_overridden' AND details ->> 'device_id' = $1
					AND severity = $2 AND NOT (details ->> 'clamped')::boolean AND (details ->> 'revocation_reapplied')::boolean = $3`,
				dev.String(), severity, reapplied); c != 1 {
				t.Errorf("security event (severity %s, reapplied %v): %d, want 1", severity, reapplied, c)
			}
			if f.openOperations(t, a.id) != 0 {
				t.Error("an audit operation is left open")
			}
		})
	}
}
