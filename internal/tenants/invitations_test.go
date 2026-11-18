package tenants_test

// Invitations (P3-T05a) on PostgreSQL with the api roles: creation with the role rule of §8.4 3a (the production guard,
// authz.GuardInvitationRole), the active IdP, the outbox event without token, duplicate and member addresses,
// Idempotency-Key replay, revoke, resend (new token, new expiry), effective status, tenant scope; the first-login
// binding itself is tested through the login callback (internal/identity/invitation_test.go) and its refusals here.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// tokenNotifier records the notices (and their tokens) besides writing the outbox like the default notifier.
type tokenNotifier struct{ notices []tenants.InvitationNotice }

func (n *tokenNotifier) InvitationIssued(ctx context.Context, tx *store.Tx, in tenants.InvitationNotice) error {
	n.notices = append(n.notices, in)
	return tenants.OutboxNotifier{}.InvitationIssued(ctx, tx, in)
}

func (f *fixture) scalar(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		f.t.Fatalf("%v\n%s", err, sql)
	}
	return s
}

func actorOf(identityID, membershipID uuid.UUID) tenants.InvitationActor {
	return tenants.InvitationActor{IdentityID: identityID, MembershipID: membershipID, Display: "Owner"}
}

// TestInvitations runs the invitation tests on one database (one creation + migration instead of three — they
// serialize on the cluster lock of storetest); each subtest uses tenants of its own.
func TestInvitations(t *testing.T) {
	base := newFixture(t)
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, *fixture)
	}{
		{"Lifecycle", testInvitationLifecycle},
		{"Idempotency", testInvitationIdempotency},
		{"BindFirstLoginRefusals", testBindFirstLoginRefusals},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := *base
			f.t = t
			tc.fn(t, &f)
		})
	}
}

// testInvitationLifecycle — create, list, revoke, resend through the service as the API calls it.
func testInvitationLifecycle(t *testing.T, f *fixture) {
	clock := time.Now().UTC().Truncate(time.Second)
	notes := &tokenNotifier{}
	svc := tenants.New(f.st, tenants.Options{Notifier: notes, Now: func() time.Time { return clock }})
	ctx := context.Background()
	a, idpA := f.tenant("inv-a", "A", "active", false)
	b, _ := f.tenant("inv-b", "B", "active", false)
	toID, toM := f.member(a, idpA, "Owner A", "owner@a.test", "tenant_owner", "active")
	taID, taM := f.member(a, idpA, "Admin A", "admin@a.test", "tenant_admin", "active")
	owner, admin := actorOf(toID, toM), actorOf(taID, taM)
	guard := tenants.RoleGuard(authz.GuardInvitationRole)

	inv, err := svc.CreateInvitation(ctx, a, admin, tenants.NewInvitation{Email: "  New.User@Example.test ", Role: "tenant_viewer"}, guard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != tenants.InvitationPending || inv.Role != "tenant_viewer" || inv.IdPID != idpA || inv.Email != "New.User@Example.test" ||
		!inv.ExpiresAt.Equal(clock.Add(tenants.DefaultInvitationTTL)) || inv.InvitedBy == nil || *inv.InvitedBy != taID {
		t.Fatalf("invitation %+v", inv)
	}
	// the token reaches the notifier only: its SHA-256 is stored, the outbox payload has no token
	if len(notes.notices) != 1 || len(notes.notices[0].Token) < 40 {
		t.Fatalf("notices %+v", notes.notices)
	}
	sum := sha256.Sum256(mustB64(t, notes.notices[0].Token))
	var stored []byte
	if err := f.su.QueryRow(ctx, `SELECT token_hash FROM tenant_invitations WHERE id = $1`, inv.ID).Scan(&stored); err != nil ||
		!bytes.Equal(stored, sum[:]) {
		t.Fatalf("token_hash %x, want sha256 of the notified token (%v)", stored, err)
	}
	payload := f.scalar(`SELECT payload::text FROM notification_outbox WHERE tenant_id = $1 AND kind = $2
		AND recipient_email = 'new.user@example.test'`, a, tenants.OutboxKindInvitation)
	if bytes.Contains([]byte(payload), []byte(notes.notices[0].Token)) || !bytes.Contains([]byte(payload), []byte(inv.ID.String())) {
		t.Fatalf("outbox payload %s", payload)
	}
	// the outbox row is delivered: it is pending with its notification.send job enqueued in the same transaction
	// (a row without a job stayed pending forever — found by E2E-37 on the mail relay stack)
	row := f.scalar(`SELECT id::text || ' ' || status FROM notification_outbox WHERE tenant_id = $1 AND kind = $2
		AND recipient_email = 'new.user@example.test'`, a, tenants.OutboxKindInvitation)
	id, status, _ := strings.Cut(row, " ")
	if status != "pending" {
		t.Fatalf("outbox row %s", row)
	}
	if n := f.scalar(`SELECT count(*)::text FROM provisioning_jobs WHERE kind = 'notification.send'
		AND input::text LIKE '%' || $1 || '%'`, id); n != "1" {
		t.Fatalf("%s notification.send jobs for the invitation e-mail %s, want 1", n, id)
	}

	// role rule 3a: an Admin cannot invite an Admin; the Owner can; nobody invites an Owner through the API
	_, err = svc.CreateInvitation(ctx, a, admin, tenants.NewInvitation{Email: "boss@example.test", Role: "tenant_admin"}, guard, nil)
	var den *authz.Denial
	if !errors.As(err, &den) || !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("TA invites an Admin: %v", err)
	}
	if _, err := svc.CreateInvitation(ctx, a, owner, tenants.NewInvitation{Email: "boss@example.test", Role: "tenant_admin",
		TTL: 2 * time.Hour}, guard, nil); err != nil {
		t.Fatalf("TO invites an Admin: %v", err)
	}
	for _, bad := range []tenants.NewInvitation{{Email: "x@example.test", Role: "tenant_owner"}, {Email: "x", Role: "tenant_viewer"},
		{Email: "x@example.test", Role: "tenant_viewer", TTL: 31 * 24 * time.Hour}, {Email: "x@example.test", Role: "super_admin"}} {
		if _, err := svc.CreateInvitation(ctx, a, owner, bad, guard, nil); !errors.Is(err, tenants.ErrInvalid) {
			t.Errorf("%+v: %v, want ErrInvalid", bad, err)
		}
	}
	// duplicates: a pending invitation (other case) and a member's address
	if _, err := svc.CreateInvitation(ctx, a, owner, tenants.NewInvitation{Email: "NEW.USER@example.TEST", Role: "end_user"}, guard, nil); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("second pending invitation: %v", err)
	}
	if _, err := svc.CreateInvitation(ctx, a, owner, tenants.NewInvitation{Email: "Admin@A.test", Role: "end_user"}, guard, nil); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("invitation of a member: %v", err)
	}

	// tenant scope: B sees nothing of A, A's invitation reads as missing from B
	if p, err := svc.ListInvitations(ctx, b, tenants.InvitationFilter{}); err != nil || len(p.Items) != 0 {
		t.Fatalf("B lists %v %v", p.Items, err)
	}
	if _, err := svc.GetInvitation(ctx, b, inv.ID); !errors.Is(err, tenants.ErrNotFound) {
		t.Fatalf("A's invitation from B: %v", err)
	}
	if err := svc.RevokeInvitation(ctx, b, inv.ID, owner, guard); !errors.Is(err, tenants.ErrNotFound) {
		t.Fatalf("revoke A's invitation in B: %v", err)
	}

	// expiry is effective at the service clock; an expired address can be invited again (the old row is closed)
	clock = clock.Add(3 * time.Hour)
	p, err := svc.ListInvitations(ctx, a, tenants.InvitationFilter{Status: tenants.InvitationExpired})
	if err != nil || len(p.Items) != 1 || p.Items[0].Email != "boss@example.test" {
		t.Fatalf("expired filter %v %v", p.Items, err)
	}

	// resend: an Admin cannot touch the Admin invitation (3a); the Owner re-sends it — new token, new expiry, pending
	if _, err := svc.ResendInvitation(ctx, a, p.Items[0].ID, admin, 0, guard); !errors.As(err, &den) {
		t.Fatalf("TA re-sends an Admin invitation: %v", err)
	}
	re, err := svc.ResendInvitation(ctx, a, p.Items[0].ID, owner, 48*time.Hour, guard)
	if err != nil || re.Status != tenants.InvitationPending || !re.ExpiresAt.Equal(clock.Add(48*time.Hour)) ||
		len(notes.notices) != 3 || !notes.notices[2].Resent || notes.notices[2].Token == notes.notices[1].Token {
		t.Fatalf("resend %+v %v (%d notices)", re, err, len(notes.notices))
	}

	// revoke: Admin cannot revoke the Admin invitation, Owner can; a second revoke conflicts; resend refuses revoked
	if err := svc.RevokeInvitation(ctx, a, re.ID, admin, guard); !errors.As(err, &den) {
		t.Fatalf("TA revokes an Admin invitation: %v", err)
	}
	if err := svc.RevokeInvitation(ctx, a, re.ID, owner, guard); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeInvitation(ctx, a, re.ID, owner, guard); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := svc.ResendInvitation(ctx, a, re.ID, owner, 0, guard); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("resend revoked: %v", err)
	}
	for action, n := range map[string]int{"invitation.create": 2, "invitation.resend": 1, "invitation.revoke": 1} {
		if got := f.scalar(`SELECT count(*)::text FROM audit_events WHERE tenant_id = $1 AND action = $2 AND outcome = 'success'`,
			a, action); got != itoa(n) {
			t.Errorf("%s events: %s, want %d", action, got, n)
		}
	}
}

// testInvitationIdempotency — the same Idempotency-Key and request returns the stored invitation (nothing created
// twice); the key with another request is refused.
func testInvitationIdempotency(t *testing.T, f *fixture) {
	svc := tenants.New(f.st, tenants.Options{})
	ctx := context.Background()
	a, idpA := f.tenant("idem-a", "A", "active", false)
	toID, toM := f.member(a, idpA, "Owner", "", "tenant_owner", "active")
	in := tenants.NewInvitation{Email: "once@example.test", Role: "tenant_operator"}
	key := &tenants.Idempotency{Key: "key-" + uuid.NewString(), Hash: jobs.RequestHash("POST", "/tenants/"+a.String()+"/invitations",
		[]byte(`{"email":"once@example.test","role":"tenant_operator"}`))}
	first, err := svc.CreateInvitation(ctx, a, actorOf(toID, toM), in, authz.GuardInvitationRole, key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := svc.CreateInvitation(ctx, a, actorOf(toID, toM), in, authz.GuardInvitationRole, key)
	if err != nil || again.ID != first.ID {
		t.Fatalf("replay %+v %v", again, err)
	}
	if n := f.scalar(`SELECT count(*)::text FROM tenant_invitations WHERE tenant_id = $1`, a); n != "1" {
		t.Fatalf("%s invitations after a replay", n)
	}
	// the replay is audited (no audit gap no_event), marked as such, and sends no second e-mail
	if n := f.scalar(`SELECT count(*)::text FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.create'
		AND resource_id = $2 AND details->>'replay' = 'true'`, a, first.ID.String()); n != "1" {
		t.Fatalf("%s invitation.create replay events, want 1", n)
	}
	if n := f.scalar(`SELECT count(*)::text FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.create'
		AND resource_id = $2 AND details->>'replay' IS NULL`, a, first.ID.String()); n != "1" {
		t.Fatalf("%s original invitation.create events, want 1", n)
	}
	other := &tenants.Idempotency{Key: key.Key, Hash: jobs.RequestHash("POST", "/tenants/"+a.String()+"/invitations",
		[]byte(`{"email":"twice@example.test","role":"tenant_operator"}`))}
	if _, err := svc.CreateInvitation(ctx, a, actorOf(toID, toM), tenants.NewInvitation{Email: "twice@example.test",
		Role: "tenant_operator"}, authz.GuardInvitationRole, other); !errors.Is(err, tenants.ErrIdempotencyKeyReuse) {
		t.Fatalf("key reuse: %v", err)
	}
	// a refused request releases its key: the same key and body may be retried once the cause is gone
	k2 := &tenants.Idempotency{Key: "key-" + uuid.NewString(), Hash: key.Hash}
	if _, err := svc.CreateInvitation(ctx, a, actorOf(toID, toM), in, authz.GuardInvitationRole, k2); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("duplicate address with a new key: %v", err)
	}
	var st string
	if err := f.su.QueryRow(ctx, `SELECT status FROM idempotency_keys WHERE key = $1`, k2.Key).Scan(&st); err != nil || st != "failed" {
		t.Fatalf("key of a refused request: %s %v", st, err)
	}
}

// testBindFirstLoginRefusals — the binder alone: membership kept, each refusal reason, single use.
func testBindFirstLoginRefusals(t *testing.T, f *fixture) {
	now := time.Now().UTC()
	svc := tenants.New(f.st, tenants.Options{Now: func() time.Time { return now }})
	ctx := context.Background()
	a, idpA := f.tenant("bind-a", "A", "active", false)
	otherIdP := uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, 'https://idp2.test/a', 'portal', 'external', 'retiring')`, otherIdP, a)
	newIdentity := func(idp uuid.UUID) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		f.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', $4)`, id, idp, a, "s-"+id.String())
		return id
	}
	invite := func(email string, ttl time.Duration) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		f.exec(`INSERT INTO tenant_invitations (id, tenant_id, idp_id, email, role_id, token_hash, expires_at, created_at)
			SELECT $1::uuid, $2, $3, $4, id, sha256(uuid_send(gen_random_uuid())), $5, $6 FROM roles WHERE scope = 'tenant' AND key = 'tenant_viewer'`,
			id, a, idpA, email, now.Add(ttl), now.Add(-time.Hour))
		return id
	}
	bind := func(ident, idp uuid.UUID, email string, verified bool) identity.BindResult {
		t.Helper()
		r, err := svc.BindFirstLogin(ctx, identity.FirstLogin{TenantID: a, IdPID: idp, IdentityID: ident, Email: email,
			EmailVerified: verified})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	invite("ok@example.test", time.Hour)
	invite("late@example.test", -time.Minute)
	if r := bind(newIdentity(idpA), idpA, "", true); r.Refused != identity.ReasonNoInvitation {
		t.Errorf("no e-mail: %+v", r)
	}
	if r := bind(newIdentity(idpA), idpA, "nobody@example.test", true); r.Refused != identity.ReasonNoInvitation {
		t.Errorf("no invitation: %+v", r)
	}
	if r := bind(newIdentity(otherIdP), otherIdP, "ok@example.test", true); r.Refused != identity.ReasonInvitationIdPMismatch {
		t.Errorf("other IdP: %+v", r)
	}
	if r := bind(newIdentity(idpA), idpA, "ok@example.test", false); r.Refused != identity.ReasonInvitationEmailNotVerified {
		t.Errorf("unverified: %+v", r)
	}
	if r := bind(newIdentity(idpA), idpA, "late@example.test", true); r.Refused != identity.ReasonInvitationExpired {
		t.Errorf("expired: %+v", r)
	}
	if st := f.scalar(`SELECT status FROM tenant_invitations WHERE email = 'late@example.test'`); st != tenants.InvitationExpired {
		t.Errorf("expired invitation left %s", st)
	}
	who := newIdentity(idpA)
	r := bind(who, idpA, "OK@example.TEST", true)
	if r.Refused != "" || r.MembershipID == uuid.Nil || r.InvitationID == uuid.Nil {
		t.Fatalf("accept: %+v", r)
	}
	if again := bind(who, idpA, "ok@example.test", true); again.MembershipID != r.MembershipID || again.InvitationID != uuid.Nil {
		t.Fatalf("a member is not bound again: %+v", again)
	}
	if second := bind(newIdentity(idpA), idpA, "ok@example.test", true); second.Refused != identity.ReasonNoInvitation {
		t.Fatalf("single use: %+v", second)
	}
	if n := f.scalar(`SELECT count(*)::text FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.accept'
		AND outcome = 'denied'`, a); n != "3" {
		t.Errorf("denied invitation.accept events: %s (idp mismatch, unverified, expired)", n)
	}
	// §8.4 invariant 5 (P3-T08): no member joins a suspended tenant — the invitation stays pending and binds after resume
	frozen := invite("frozen@example.test", time.Hour)
	f.exec(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, a)
	late := newIdentity(idpA)
	if r := bind(late, idpA, "frozen@example.test", true); r.Refused != identity.ReasonTenantSuspended || r.MembershipID != uuid.Nil {
		t.Errorf("first login while suspended: %+v", r)
	}
	if st := f.scalar(`SELECT status FROM tenant_invitations WHERE id = $1`, frozen); st != tenants.InvitationPending {
		t.Errorf("invitation after a refused login of a suspended tenant: %s", st)
	}
	f.exec(`UPDATE tenants SET status = 'active' WHERE id = $1`, a)
	if r := bind(late, idpA, "frozen@example.test", true); r.Refused != "" || r.InvitationID != frozen {
		t.Errorf("first login after resume: %+v", r)
	}
	if n := f.scalar(`SELECT count(*)::text FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.accept'
		AND outcome = 'denied' AND details ->> 'reason' = 'tenant_suspended'`, a); n != "1" {
		t.Errorf("denied invitation.accept events (tenant_suspended): %s", n)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(out) != 32 {
		t.Fatalf("token %d bytes: %v", len(out), err)
	}
	return out
}
