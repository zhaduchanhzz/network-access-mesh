package notifications

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// expectation of one event: the addresses that must receive exactly one e-mail and the members that must have exactly
// one Portal record.
type expectation struct {
	ev      Event
	emails  []string
	members []uuid.UUID
}

// TestEachEventExactlyOneNotificationToTheRightRecipients — the verification of P3-T05b: with a fake SMTP relay, every
// event of the task produces exactly one notification per recipient, to the recipients of §6.3 of the RIGHT tenant
// (tenant B's members never), e-mails only to verified addresses, the Portal record for every member; repeating an
// event (same ref) adds nothing; the body carries no secret.
func TestEachEventExactlyOneNotificationToTheRightRecipients(t *testing.T) {
	f := newFixture(t)
	srv, mailer := relay(t)
	f.worker(t, mailer, 4)
	a, b := f.a, f.b
	em := func(ids ...uuid.UUID) []string {
		var out []string
		for _, id := range ids {
			out = append(out, a.email[id])
		}
		return out
	}
	grant, dev, app, job, inv := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	cases := []expectation{
		{TenantActivated(a.id, "invited-owner@example.test"), append(em(a.owner), "invited-owner@example.test"), []uuid.UUID{a.owner}},
		{Invitation(a.id, inv, "newcomer@example.test", "tenant_owner", time.Now().Add(72*time.Hour), LocaleEN),
			[]string{"newcomer@example.test"}, nil},
		{DeviceNew(a.id, dev, &a.endUser, "eu-laptop", time.Now()), em(a.owner, a.endUser), []uuid.UUID{a.owner, a.endUser}},
		{BreakGlass(a.id, grant, "Staff One", "Super Admin", "incident 7", time.Now().Add(4*time.Hour)), em(a.owner), []uuid.UUID{a.owner}},
		{PolicyApplied(a.id, app, uuid.New(), 2, "baseline", "manual", strings.Repeat("0f", 32)), em(a.owner, a.admin),
			[]uuid.UUID{a.owner, a.admin, a.unverified}},
		{SupportGrantRequested(a.id, grant, "Staff One", "ticket 42", time.Now().Add(time.Hour)), em(a.owner, a.admin),
			[]uuid.UUID{a.owner, a.admin, a.unverified}},
		{DeviceExpiring(a.id, dev, &a.endUser, "eu-laptop", time.Now().Add(48*time.Hour)), em(a.endUser), []uuid.UUID{a.endUser}},
		{DeviceExpiring(a.id, uuid.New(), nil, "router-1", time.Now().Add(48*time.Hour)), em(a.owner, a.admin),
			[]uuid.UUID{a.owner, a.admin, a.unverified}},
		{TenantSuspended(a.id, job), em(a.owner, a.admin), []uuid.UUID{a.owner, a.admin, a.unverified}},
		{TenantResumed(a.id, uuid.New()), em(a.owner, a.admin), []uuid.UUID{a.owner, a.admin, a.unverified}},
		{SupportGrantUsed(a.id, grant, "Staff One", time.Now()), em(a.owner), []uuid.UUID{a.owner}},
		{ApprovalRequested(a.id, uuid.New(), "tenant.settings.four_eyes_off", "", "Alice", time.Now().Add(24*time.Hour)),
			em(a.owner, a.admin), []uuid.UUID{a.owner, a.admin, a.unverified}},
		{APIKeyExpiring(uuid.New(), a.slug, time.Now().Add(10*24*time.Hour)), []string{f.super}, nil},
	}
	for _, c := range cases {
		before := len(srv.Messages())
		st := f.wrk
		res, err := f.enqueue(t, st, c.ev)
		if err != nil {
			t.Fatalf("%s: %v", c.ev.Kind, err)
		}
		if res.Duplicate || len(res.Notifications) != len(c.members)+countNonMember(c, a.slug) || res.Jobs != len(c.emails) {
			t.Fatalf("%s: result %+v, want %d rows %d jobs", c.ev.Kind, res, len(c.members)+countNonMember(c, a.slug), len(c.emails))
		}
		waitFor(t, 20*time.Second, string(c.ev.Kind)+" e-mails", func() bool { return len(srv.Messages()) >= before+len(c.emails) })
		time.Sleep(150 * time.Millisecond) // a duplicate would arrive now
		got := srv.Messages()[before:]
		var to []string
		for _, m := range got {
			to = append(to, m.To...)
			if !m.TLS || strings.Contains(m.Data, "hskey-") || strings.Contains(m.Data, "Bearer ") {
				t.Errorf("%s: message not encrypted or carries a secret", c.ev.Kind)
			}
			if !strings.HasPrefix(m.Header("Subject"), "[MeshGuard]") || m.Header("Message-ID") == "" {
				t.Errorf("%s: headers %q %q", c.ev.Kind, m.Header("Subject"), m.Header("Message-ID"))
			}
		}
		sort.Strings(to)
		want := slices.Clone(c.emails)
		sort.Strings(want)
		if !slices.Equal(to, want) {
			t.Errorf("%s: e-mails to %v, want %v", c.ev.Kind, to, want)
		}
		for _, addr := range to {
			if strings.HasSuffix(addr, "@"+b.slug+".test") {
				t.Errorf("%s: tenant B's member %s was notified", c.ev.Kind, addr)
			}
		}
		// Portal records: exactly one per member.
		if c.ev.TenantID != nil {
			var members []uuid.UUID
			rows, err := f.su.Query(context.Background(), `SELECT recipient_membership_id FROM notification_outbox
				WHERE tenant_id = $1 AND kind = $2 AND payload ->> 'ref' = $3 AND recipient_membership_id IS NOT NULL`,
				a.id, string(c.ev.Kind), c.ev.Ref)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var id uuid.UUID
				_ = rows.Scan(&id)
				members = append(members, id)
			}
			rows.Close()
			if !sameSet(members, c.members) {
				t.Errorf("%s: Portal records for %v, want %v", c.ev.Kind, members, c.members)
			}
		}
		// The same event again: nothing new.
		again, err := f.enqueue(t, st, c.ev)
		if err != nil || !again.Duplicate || len(again.Notifications) != 0 {
			t.Fatalf("%s: repeat %+v %v", c.ev.Kind, again, err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	total := 0
	for _, c := range cases {
		total += len(c.emails)
	}
	if n := len(srv.Messages()); n != total {
		t.Fatalf("relay got %d messages, want %d (one per e-mail recipient)", n, total)
	}
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1`, b.id); n != 0 {
		t.Fatalf("tenant B has %d notifications", n)
	}
	waitFor(t, 10*time.Second, "all rows settled", func() bool {
		return f.count(t, `SELECT count(*) FROM notification_outbox WHERE status <> 'sent'`) == 0
	})
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE status = 'sent' AND sent_at IS NOT NULL
		AND recipient_email IS NOT NULL AND attempts = 1`); n != total {
		t.Fatalf("sent e-mail rows with one attempt: %d, want %d", n, total)
	}
}

// countNonMember is the number of expected addresses that are not a member of the tenant (they get an e-mail-only row).
func countNonMember(c expectation, slug string) int {
	n := 0
	for _, e := range c.emails {
		if !strings.HasSuffix(e, "@"+slug+".test") {
			n++
		}
	}
	return n
}

func sameSet(a, b []uuid.UUID) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.SortFunc(x, func(p, q uuid.UUID) int { return strings.Compare(p.String(), q.String()) })
	slices.SortFunc(y, func(p, q uuid.UUID) int { return strings.Compare(p.String(), q.String()) })
	return slices.Equal(x, y)
}

// TestCrossTenantIsolation: a producer in tenant A's transaction cannot reach tenant B — naming B's member, B's tenant
// id, or writing for B from A's scope. The api of A reads only its own caller's notifications.
func TestCrossTenantIsolation(t *testing.T) {
	f := newFixture(t)
	a, b := f.a, f.b
	// A's device event naming B's End User as owner: B's member is not resolved in A's scope (A's Owner still is).
	res, err := f.enqueue(t, f.wrk, DeviceNew(a.id, uuid.New(), &b.endUser, "x", time.Time{}))
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE recipient_membership_id = $1`, b.endUser); n != 0 || len(res.Notifications) != 1 {
		t.Fatalf("B's member notified from A: %d rows, result %+v", n, res)
	}
	// An event of tenant B enqueued in A's transaction: RLS refuses the write (or B is invisible).
	err = f.wrk.WithTenantJobTx(context.Background(), a.id, func(tx *store.Tx) error {
		_, err := Enqueue(context.Background(), tx, PolicyApplied(b.id, uuid.New(), uuid.New(), 1, "baseline", "manual", "x"))
		return err
	})
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("B's event in A's scope: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1`, b.id); n != 0 {
		t.Fatal("B got a notification")
	}
	// Reads: A's Owner sees exactly its own row; B's Owner, asking about A, sees nothing.
	r := NewReader(f.api)
	page, err := r.ListMine(context.Background(), a.id, a.owner, ListQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Kind != string(KindDeviceNew) {
		t.Fatalf("A owner: %+v %v", page, err)
	}
	if _, ok := page.Items[0].Payload["ref"]; ok {
		t.Fatal("internal ref exposed")
	}
	if p, err := r.ListMine(context.Background(), a.id, b.owner, ListQuery{}); err != nil || len(p.Items) != 0 {
		t.Fatalf("B owner in A: %+v %v", p, err)
	}
	if p, err := r.ListMine(context.Background(), b.id, a.owner, ListQuery{}); err != nil || len(p.Items) != 0 {
		t.Fatalf("A owner in B: %+v %v", p, err)
	}
	if p, err := r.ListMine(context.Background(), a.id, a.endUser, ListQuery{}); err != nil || len(p.Items) != 0 {
		t.Fatalf("A end user sees another member's notification: %+v %v", p, err)
	}
}

// TestRetryThenSentAndPermanentFailure: a 4xx from the relay retries with backoff and the row ends sent after the retry
// (one message, attempts 2); a 5xx fails the row and the job at once; a relay that stays temporary-failing exhausts the
// attempts and fails the row.
func TestRetryThenSentAndPermanentFailure(t *testing.T) {
	f := newFixture(t)
	srv, mailer := relay(t)
	f.worker(t, mailer, 3)
	srv.FailNext(451)
	res, err := f.enqueue(t, f.wrk, BreakGlass(f.a.id, uuid.New(), "Staff", "", "", time.Time{}))
	if err != nil || len(res.Notifications) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	id := res.Notifications[0]
	waitFor(t, 20*time.Second, "sent after a retry", func() bool {
		return f.count(t, `SELECT count(*) FROM notification_outbox WHERE id = $1 AND status = 'sent'`, id) == 1
	})
	if n := f.count(t, `SELECT attempts FROM notification_outbox WHERE id = $1`, id); n != 2 {
		t.Fatalf("attempts %d", n)
	}
	if len(srv.Messages()) != 1 {
		t.Fatalf("messages %d", len(srv.Messages()))
	}
	// 5xx: failed at once.
	srv.FailNext(550)
	res, _ = f.enqueue(t, f.wrk, BreakGlass(f.a.id, uuid.New(), "Staff", "", "", time.Time{}))
	waitFor(t, 20*time.Second, "failed on 550", func() bool {
		return f.count(t, `SELECT count(*) FROM notification_outbox WHERE id = $1 AND status = 'failed' AND attempts = 1`, res.Notifications[0]) == 1
	})
	waitFor(t, 10*time.Second, "job failed", func() bool {
		return f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'notification.send' AND status = 'failed'
			AND error ->> 'code' = 'smtp_rejected'`) == 1
	})
	// Temporary forever: attempts exhausted.
	// The job's limit is fixed at enqueue time from the registry (8 attempts); set this job's own limit to 3 like a
	// deployment that tuned it.
	srv.FailNext(421, 421, 421, 421, 421, 421)
	res, _ = f.enqueue(t, f.wrk, BreakGlass(f.a.id, uuid.New(), "Staff", "", "", time.Time{}))
	f.exec(t, `UPDATE provisioning_jobs SET max_attempts = 3 WHERE kind = 'notification.send' AND input ->> 'notification_id' = $1`,
		res.Notifications[0].String())
	waitFor(t, 30*time.Second, "failed after attempts", func() bool {
		return f.count(t, `SELECT count(*) FROM notification_outbox WHERE id = $1 AND status = 'failed' AND attempts = 3`, res.Notifications[0]) == 1
	})
}

// TestNoRelayCancelsEmailKeepsPortal: without a relay the e-mail rows are cancelled (job succeeds), the Portal records
// stay readable.
func TestNoRelayCancelsEmailKeepsPortal(t *testing.T) {
	f := newFixture(t)
	f.worker(t, nil, 3)
	res, err := f.enqueue(t, f.wrk, TenantSuspended(f.a.id, uuid.New()))
	if err != nil || len(res.Notifications) != 3 || res.Jobs != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	waitFor(t, 20*time.Second, "cancelled", func() bool {
		return f.count(t, `SELECT count(*) FROM notification_outbox WHERE status = 'cancelled'`) == 2
	})
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE status = 'sent' AND recipient_email IS NULL`); n != 1 {
		t.Fatalf("portal-only row: %d", n)
	}
	waitFor(t, 10*time.Second, "jobs succeeded", func() bool {
		return f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'notification.send' AND status = 'succeeded'`) == 2
	})
	page, err := NewReader(f.api).ListMine(context.Background(), f.a.id, f.a.owner, ListQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("portal: %+v %v", page, err)
	}
}

// TestSettingsSwitchOffAndVerifiedOnly: TenantSettings.notifications.policy_applied = false suppresses policy.applied;
// new_device = false drops the Owners' copies but the device's owner is still told; an unverified address never gets
// an e-mail (Portal record only).
func TestSettingsSwitchOffAndVerifiedOnly(t *testing.T) {
	f := newFixture(t)
	f.exec(t, `UPDATE tenants SET settings = '{"notifications": {"policy_applied": false, "new_device": false}}' WHERE id = $1`, f.a.id)
	res, err := f.enqueue(t, f.wrk, PolicyApplied(f.a.id, uuid.New(), uuid.New(), 1, "baseline", "manual", "x"))
	if err != nil || !res.Suppressed || len(res.Notifications) != 0 {
		t.Fatalf("policy_applied off: %+v %v", res, err)
	}
	res, err = f.enqueue(t, f.wrk, DeviceNew(f.a.id, uuid.New(), &f.a.endUser, "d", time.Time{}))
	if err != nil || !res.Suppressed || len(res.Notifications) != 1 {
		t.Fatalf("new_device off: %+v %v", res, err)
	}
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE recipient_membership_id = $1 AND kind = 'device.new'`, f.a.endUser); n != 1 {
		t.Fatal("the device owner was not told")
	}
	// Security notifications cannot be switched off; the unverified Admin gets no e-mail.
	res, err = f.enqueue(t, f.wrk, TenantResumed(f.a.id, uuid.New()))
	if err != nil || res.Suppressed {
		t.Fatalf("%+v %v", res, err)
	}
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE recipient_membership_id = $1 AND recipient_email IS NULL
		AND status = 'sent'`, f.a.unverified); n != 1 {
		t.Fatal("the unverified member must get the Portal record only")
	}
	// An inactive member is never a recipient.
	f.exec(t, `UPDATE tenant_memberships SET status = 'disabled' WHERE id = $1`, f.a.admin)
	res, _ = f.enqueue(t, f.wrk, TenantSuspended(f.a.id, uuid.New()))
	for _, id := range res.Notifications {
		if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE id = $1 AND recipient_membership_id = $2`, id, f.a.admin); n != 0 {
			t.Fatal("a disabled member was notified")
		}
	}
}

// TestListMinePaging: newest first, cursor bound to the list, unread filter.
func TestListMinePaging(t *testing.T) {
	f := newFixture(t)
	for range 5 {
		if _, err := f.enqueue(t, f.wrk, TenantResumed(f.a.id, uuid.New())); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReader(f.api)
	ctx := context.Background()
	p1, err := r.ListMine(ctx, f.a.id, f.a.owner, ListQuery{Limit: 2})
	if err != nil || len(p1.Items) != 2 || p1.NextCursor == "" {
		t.Fatalf("%+v %v", p1, err)
	}
	p2, _ := r.ListMine(ctx, f.a.id, f.a.owner, ListQuery{Limit: 2, Cursor: p1.NextCursor})
	p3, _ := r.ListMine(ctx, f.a.id, f.a.owner, ListQuery{Limit: 2, Cursor: p2.NextCursor})
	if len(p2.Items) != 2 || len(p3.Items) != 1 || p3.NextCursor != "" || !p1.Items[0].CreatedAt.After(p3.Items[0].CreatedAt) &&
		!p1.Items[0].CreatedAt.Equal(p3.Items[0].CreatedAt) {
		t.Fatalf("pages %d %d %q", len(p2.Items), len(p3.Items), p3.NextCursor)
	}
	if _, err := r.ListMine(ctx, f.a.id, f.a.admin, ListQuery{Cursor: p1.NextCursor}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("a cursor of another member's list: %v", err)
	}
	if _, err := r.ListMine(ctx, f.a.id, f.a.owner, ListQuery{Limit: 201}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatal("limit 201 accepted")
	}
	f.exec(t, `UPDATE notification_outbox SET read_at = now() WHERE id = $1`, p1.Items[0].ID)
	unread := true
	u, _ := r.ListMine(ctx, f.a.id, f.a.owner, ListQuery{Unread: &unread})
	read := false
	rd, _ := r.ListMine(ctx, f.a.id, f.a.owner, ListQuery{Unread: &read})
	if len(u.Items) != 4 || len(rd.Items) != 1 || rd.Items[0].ReadAt == nil {
		t.Fatalf("unread %d read %d", len(u.Items), len(rd.Items))
	}
}

