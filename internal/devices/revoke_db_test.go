package devices

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// revokeFixture: tenant A synced with Alice's node 1 (+ pre-auth keys of Alice and of Bob).
func revokeFixture(t *testing.T) (*fixture, *tenantFx, uuid.UUID) {
	t.Helper()
	f := newFixture(t)
	a := f.a
	now := time.Now().UTC()
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, now.Add(-time.Hour), tp(now.Add(24*time.Hour))))
	a.hs.PutKey(devicestest.Key{ID: 1, UserID: a.aliceUser, UserName: a.userName(a.alice), Reusable: true, Expiration: now.Add(time.Hour)})
	a.hs.PutKey(devicestest.Key{ID: 2, UserID: a.aliceUser, UserName: a.userName(a.alice), Used: true, Expiration: now.Add(time.Hour)})
	a.hs.PutKey(devicestest.Key{ID: 3, UserID: a.bobUser, UserName: a.userName(a.bob), Expiration: now.Add(time.Hour)})
	if _, err := f.wrk.Sync(context.Background(), a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	return f, a, f.deviceOfNode(t, a, 1)
}

func (f *fixture) revoke(t *testing.T, ten *tenantFx, device uuid.UUID, kind, key string) RevokeResult {
	t.Helper()
	identity := uuid.New()
	action := ActionExpire
	if kind == RevokeDelete {
		action = ActionDelete
	}
	res, err := f.api.Revoke(actorCtx(identity, ten.id, action), ten.id, device, Access{IdentityID: identity}, kind, key)
	if err != nil {
		t.Fatalf("revoke %s: %v", kind, err)
	}
	return res
}

// TestRevokeAppliedAfterReadBack: expire ⇒ pending + job + device.expire.requested; the job expires the user's live
// pre-auth keys (§7.4), calls ExpireNode with the request time, reads it back and only then settles applied
// (+ .succeeded). Delete ⇒ applied + removed from the register.
func TestRevokeAppliedAfterReadBack(t *testing.T) {
	f, a, dev := revokeFixture(t)
	ctx := context.Background()
	res := f.revoke(t, a, dev, RevokeExpire, "idem-key-0001")
	if !res.Created || res.Device.Revocation.State != StatePending || res.Device.Revocation.Kind != RevokeExpire {
		t.Fatalf("request: %+v", res)
	}
	row := f.row(t, dev)
	if row.RevocationJobID == nil || *row.RevocationJobID != res.JobID || row.RevocationRequestedAt == nil {
		t.Fatalf("pending row: %+v", row)
	}
	if got := f.auditOf(t, dev.String()); !slices.Equal(got, []string{"device.expire.requested/success"}) {
		t.Errorf("audit after the request: %v", got)
	}
	if err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 1, 8)); err != nil {
		t.Fatalf("job: %v", err)
	}
	row = f.row(t, dev)
	n, _ := a.hs.Node(1)
	if row.RevocationState != StateApplied || row.RevocationVerifiedAt == nil || n.Expiry == nil ||
		!n.Expiry.Equal(row.RevocationRequestedAt.UTC()) || row.Expiry == nil || !row.Expiry.Equal(*n.Expiry) {
		t.Errorf("after the job: state %s verified %v node expiry %v requested %v cached %v", row.RevocationState,
			row.RevocationVerifiedAt, n.Expiry, row.RevocationRequestedAt, row.Expiry)
	}
	if a.hs.Key(1).Expiration.After(time.Now()) || !a.hs.Key(2).Expiration.After(time.Now()) || !a.hs.Key(3).Expiration.After(time.Now()) {
		t.Errorf("pre-auth keys: live key of Alice %v, spent key %v, Bob's key %v — only the first must be expired",
			a.hs.Key(1).Expiration, a.hs.Key(2).Expiration, a.hs.Key(3).Expiration)
	}
	if got := f.auditOf(t, dev.String()); !slices.Equal(got, []string{"device.expire.requested/success", "device.expire.succeeded/success"}) {
		t.Errorf("audit after the job: %v", got)
	}
	if n := count(t, f, `SELECT count(DISTINCT operation_id) FROM audit_events WHERE resource_id = $1`, dev.String()); n != 1 {
		t.Errorf("operation ids of the pair: %d, want 1", n)
	}
	// The job runs again (a retry after a lost acknowledgement): nothing more happens.
	a.hs.ResetCalls()
	if err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 2, 8)); err != nil || a.hs.Calls(devicestest.OpExpireNode) != 0 {
		t.Errorf("replayed job: %v, ExpireNode %d", err, a.hs.Calls(devicestest.OpExpireNode))
	}

	// Delete: applied once GetNode says the node is gone; the device leaves the register.
	f.finishJob(t, res.JobID, "succeeded") // what the framework records after the handler returned
	del := f.revoke(t, a, dev, RevokeDelete, "")
	if err := f.wrk.runRevoke(ctx, f.run(t, del.JobID, 1, 8)); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	if _, ok := a.hs.Node(1); ok {
		t.Error("the node still exists after the delete")
	}
	row = f.row(t, dev)
	if row.RevocationState != StateApplied || deref(row.RevocationKind) != RevokeDelete || row.RemovedAt == nil {
		t.Errorf("deleted device: %+v", row)
	}
	if _, err := f.api.Get(ctx, a.id, dev, Access{}); !isCode(err, CodeNotFound) {
		t.Errorf("GET after delete: %v", err)
	}
	if f.openOperations(t, a.id) != 0 {
		t.Error("open audit operations left")
	}
}

// TestRevokeFailureModes — the acceptance of §20 P2-T13 with the fake instance: not answering ⇒ pending and retry,
// out of attempts ⇒ failed; Headscale refuses ⇒ failed at once; read-back not matching ⇒ pending; matching ⇒ applied.
func TestRevokeFailureModes(t *testing.T) {
	ctx := context.Background()

	t.Run("unavailable then exhausted", func(t *testing.T) {
		f, a, dev := revokeFixture(t)
		res := f.revoke(t, a, dev, RevokeExpire, "")
		a.hs.SetDown(true)
		for attempt := 1; attempt < 4; attempt++ {
			err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, attempt, 4))
			var je *jobs.Error
			if !errors.As(err, &je) || je.Permanent || je.Code != CodeInstanceUnavailable {
				t.Fatalf("attempt %d: %v, want a transient instance_unavailable", attempt, err)
			}
			if s := f.row(t, dev).RevocationState; s != StatePending {
				t.Fatalf("attempt %d: state %s, want pending", attempt, s)
			}
		}
		err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 4, 4))
		if err == nil {
			t.Fatal("last attempt succeeded")
		}
		if s := f.row(t, dev).RevocationState; s != StateFailed {
			t.Fatalf("after the last attempt: %s, want failed", s)
		}
		if got := f.auditOf(t, dev.String()); !slices.Equal(got, []string{"device.expire.requested/success", "device.expire.failed/failure"}) {
			t.Errorf("audit: %v", got)
		}
		if n := count(t, f, `SELECT count(*) FROM audit_events WHERE action = 'device.expire.failed'
				AND details ->> 'reason' = 'instance_unavailable'`); n != 1 {
			t.Errorf("failed event with reason instance_unavailable: %d", n)
		}
		// A new request after the failure starts a new revocation.
		a.hs.SetDown(false)
		f.finishJob(t, res.JobID, "failed")
		again := f.revoke(t, a, dev, RevokeExpire, "")
		if !again.Created || again.JobID == res.JobID {
			t.Fatalf("new request after failure: %+v", again)
		}
		if err := f.wrk.runRevoke(ctx, f.run(t, again.JobID, 1, 4)); err != nil || f.row(t, dev).RevocationState != StateApplied {
			t.Errorf("second revocation: %v, state %s", err, f.row(t, dev).RevocationState)
		}
		// The failed job's attempt delivered late does nothing.
		if err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 4, 4)); err != nil {
			t.Errorf("superseded job: %v", err)
		}
	})

	t.Run("refused", func(t *testing.T) {
		f, a, dev := revokeFixture(t)
		res := f.revoke(t, a, dev, RevokeExpire, "")
		a.hs.Refuse(devicestest.OpExpireNode, true)
		err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 1, 8))
		var je *jobs.Error
		if !errors.As(err, &je) || !je.Permanent || je.Code != CodeUpstreamRejected {
			t.Fatalf("refused: %v, want a permanent upstream_rejected", err)
		}
		if s := f.row(t, dev).RevocationState; s != StateFailed {
			t.Errorf("state %s, want failed at the first attempt", s)
		}
		if f.openOperations(t, a.id) != 0 {
			t.Error("operation left open")
		}
	})

	t.Run("read-back mismatch then match", func(t *testing.T) {
		f, a, dev := revokeFixture(t)
		res := f.revoke(t, a, dev, RevokeExpire, "")
		a.hs.Ignore(devicestest.OpExpireNode, true) // acknowledged, not applied
		err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 1, 8))
		var je *jobs.Error
		if !errors.As(err, &je) || je.Permanent || je.Code != ReasonReadbackMismatch {
			t.Fatalf("mismatch: %v, want a transient readback_mismatch", err)
		}
		if s := f.row(t, dev).RevocationState; s != StatePending {
			t.Errorf("state %s, want pending", s)
		}
		a.hs.Ignore(devicestest.OpExpireNode, false)
		if err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 2, 8)); err != nil {
			t.Fatal(err)
		}
		if s := f.row(t, dev).RevocationState; s != StateApplied {
			t.Errorf("state %s, want applied", s)
		}
		// Delete acknowledged but the node still listed: pending too.
		f.finishJob(t, res.JobID, "succeeded")
		del := f.revoke(t, a, dev, RevokeDelete, "")
		a.hs.Ignore(devicestest.OpDeleteNode, true)
		if err := f.wrk.runRevoke(ctx, f.run(t, del.JobID, 1, 8)); err == nil || f.row(t, dev).RevocationState != StatePending {
			t.Errorf("delete not applied: %v, state %s", err, f.row(t, dev).RevocationState)
		}
	})

	t.Run("node id reused", func(t *testing.T) {
		f, a, dev := revokeFixture(t)
		res := f.revoke(t, a, dev, RevokeDelete, "")
		other := userNode(a, 1, a.bob, a.bobUser, time.Now(), nil)
		other.MachineKey = "mkey:" + "someone-else"
		a.hs.PutNode(other) // after a restore, node 1 belongs to another machine
		if err := f.wrk.runRevoke(ctx, f.run(t, res.JobID, 1, 8)); err != nil {
			t.Fatal(err)
		}
		if _, ok := a.hs.Node(1); !ok || a.hs.Calls(devicestest.OpDeleteNode) != 0 {
			t.Fatalf("the other machine's node was deleted (DeleteNode calls %d)", a.hs.Calls(devicestest.OpDeleteNode))
		}
		if r := f.row(t, dev); r.RevocationState != StateApplied || r.RemovedAt == nil {
			t.Errorf("device of a node gone: %+v", r)
		}
	})
}

// TestRevokeRequestRules: own-resource rule, same kind pending ⇒ same job, other kind pending ⇒ conflict,
// Idempotency-Key replay ⇒ same job, key of another device ⇒ idempotency_key_reuse, unknown or other tenant ⇒ 404.
func TestRevokeRequestRules(t *testing.T) {
	f, a, dev := revokeFixture(t)
	ctx := context.Background()
	alice, bob := Access{OwnOnly: true, MembershipID: a.alice, IdentityID: uuid.New()}, Access{OwnOnly: true, MembershipID: a.bob, IdentityID: uuid.New()}
	if _, err := f.api.Revoke(ctx, a.id, dev, bob, RevokeExpire, ""); !isReason(err, ReasonNotOwnResource) {
		t.Errorf("Bob revokes Alice's device: %v", err)
	}
	if _, err := f.api.Get(ctx, a.id, dev, bob); !isReason(err, ReasonNotOwnResource) {
		t.Errorf("Bob reads Alice's device: %v", err)
	}
	if _, err := f.api.Revoke(ctx, f.b.id, dev, Access{}, RevokeExpire, ""); !isReason(err, ReasonNoDevice) {
		t.Errorf("device of A through tenant B: %v", err)
	}
	if _, err := f.api.Revoke(ctx, a.id, uuid.New(), Access{}, RevokeExpire, ""); !isReason(err, ReasonNoDevice) {
		t.Errorf("unknown device: %v", err)
	}
	first, err := f.api.Revoke(actorCtx(alice.IdentityID, a.id, ActionExpire), a.id, dev, alice, RevokeExpire, "key-alice-1")
	if err != nil || !first.Created {
		t.Fatalf("Alice expires her device: %+v %v", first, err)
	}
	again, err := f.api.Revoke(actorCtx(alice.IdentityID, a.id, ActionExpire), a.id, dev, alice, RevokeExpire, "key-alice-2")
	if err != nil || again.Created || again.JobID != first.JobID {
		t.Errorf("expire while pending: %+v %v, want the same job", again, err)
	}
	if _, err := f.api.Revoke(ctx, a.id, dev, alice, RevokeDelete, ""); !isReason(err, ReasonRevocationInProgress) {
		t.Errorf("delete while an expire is pending: %v", err)
	}
	if err := f.wrk.runRevoke(ctx, f.run(t, first.JobID, 1, 8)); err != nil {
		t.Fatal(err)
	}
	replay, err := f.api.Revoke(actorCtx(alice.IdentityID, a.id, ActionExpire), a.id, dev, alice, RevokeExpire, "key-alice-1")
	if err != nil || replay.Created || replay.JobID != first.JobID || replay.Device.Revocation.State != StateApplied {
		t.Errorf("replayed Idempotency-Key: %+v %v", replay, err)
	}
	a.hs.PutNode(userNode(a, 2, a.alice, a.aliceUser, time.Now(), nil))
	if _, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	if _, err := f.api.Revoke(ctx, a.id, f.deviceOfNode(t, a, 2), alice, RevokeExpire, "key-alice-1"); !isCode(err, CodeIdempotencyKeyReuse) {
		t.Errorf("same key on another device: %v", err)
	}
	if n := count(t, f, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'device.revoke'`); n != 1 {
		t.Errorf("revoke jobs: %d, want 1", n)
	}
	// The requests that started nothing still left a trace: the repeated one is recorded.
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE action = 'device.expire' AND details ->> 'repeated' = 'true'`); n != 1 {
		t.Errorf("record of the repeated request: %d", n)
	}
}

func isReason(err error, reason string) bool {
	e, ok := AsError(err)
	return ok && e.Reason == reason
}

// TestOrphanedRevocationsSettled: a revocation whose job ended without its handler recording it (timeout before an
// attempt, job.reaper) is settled failed with its audit pair closed — by JobAlert and, as a safety net, by the next
// sync.
func TestOrphanedRevocationsSettled(t *testing.T) {
	f, a, dev := revokeFixture(t)
	ctx := context.Background()
	res := f.revoke(t, a, dev, RevokeExpire, "")
	f.exec(t, `UPDATE provisioning_jobs SET status = 'failed', error = '{"code": "timeout"}', finished_at = now() WHERE id = $1`, res.JobID)
	f.wrk.JobAlert(ctx, jobs.Alert{Reason: jobs.AlertFailed, JobID: res.JobID, TenantID: &a.id, Kind: KindRevoke, Status: jobs.StatusFailed, Code: "timeout"})
	if s := f.row(t, dev).RevocationState; s != StateFailed {
		t.Fatalf("after the alert: %s, want failed", s)
	}
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE action = 'device.expire.failed' AND details ->> 'reason' = 'timeout'`); n != 1 {
		t.Errorf("failed event of the timed-out job: %d", n)
	}
	// Without the alert: the next sync settles it.
	second := f.revoke(t, a, dev, RevokeExpire, "")
	f.exec(t, `UPDATE provisioning_jobs SET status = 'failed', error = '{"code": "worker_lost"}', finished_at = now() WHERE id = $1`, second.JobID)
	rep, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil || rep.SettledRevocations != 1 || f.row(t, dev).RevocationState != StateFailed {
		t.Fatalf("sync safety net: %+v %v, state %s", rep, err, f.row(t, dev).RevocationState)
	}
	if f.openOperations(t, a.id) != 0 {
		t.Error("open audit operation left")
	}
}
