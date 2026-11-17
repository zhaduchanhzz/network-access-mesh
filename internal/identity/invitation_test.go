package identity_test

// P3-T05a — invitations bound at the first login: the real callback (fake OpenID Providers, PostgreSQL) with the real
// binder of internal/tenants. Verification of §20: an expired invitation, a login through another issuer and another
// e-mail are refused; the binding is (idp_id, sub) of the invitation's IdP, with a verified e-mail, once.

import (
	"context"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// invEnv is an env whose identity service binds first logins with tenants.Service (as the api process).
type invEnv struct {
	*env
	ten *tenants.Service
}

func newInvEnv(t *testing.T) *invEnv {
	t.Helper()
	ie := &invEnv{}
	ie.env = newEnv(t, func(e *env, st *store.Store, cfg *identity.Config) {
		ie.ten = tenants.New(st, tenants.Options{Now: e.clock.Now})
		cfg.Invitations = ie.ten
	})
	return ie
}

func withoutEmailVerification() idpOpt { return func(o *idpOpts) { o.requireEmailVerified = false } }

// roleID returns the id of a seeded tenant role.
func (e *env) roleID(key string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	if err := e.db.QueryRow(context.Background(), `SELECT id FROM roles WHERE scope = 'tenant' AND key = $1`, key).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// invite inserts (as superuser) a pending invitation of ten for email, naming idp, valid for ttl at the env clock.
func (e *env) invite(ten *tenantFix, idp uuid.UUID, email, role string, ttl time.Duration) uuid.UUID {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	now := e.clock.Now()
	e.exec(`INSERT INTO tenant_invitations (id, tenant_id, idp_id, email, role_id, token_hash, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`, id, ten.ID, idp, email, e.roleID(role), hash, now.Add(ttl), now.Add(-time.Minute))
	return id
}

func (e *env) invitationStatus(id uuid.UUID) (string, *uuid.UUID) {
	e.t.Helper()
	var (
		st  string
		acc *uuid.UUID
	)
	if err := e.db.QueryRow(context.Background(), `SELECT status, accepted_identity_id FROM tenant_invitations WHERE id = $1`, id).
		Scan(&st, &acc); err != nil {
		e.t.Fatal(err)
	}
	return st, acc
}

// identityOf returns the identity (idp, sub) and whether it ever completed a login.
func (e *env) identityOf(idp uuid.UUID, sub string) (uuid.UUID, bool, bool) {
	e.t.Helper()
	var (
		id    uuid.UUID
		login *time.Time
	)
	err := e.db.QueryRow(context.Background(), `SELECT id, last_login_at FROM identities WHERE idp_id = $1 AND subject = $2`,
		idp, sub).Scan(&id, &login)
	if err != nil {
		return uuid.Nil, false, false
	}
	return id, true, login != nil
}

// addIdP registers one more IdP of the tenant at fake, with status.
func (e *env) addIdP(ten *tenantFix, fake *identity.FakeIdP, status string) uuid.UUID {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	clientID := "portal-" + identity.RandomHex(4)
	ref := "mgsec://" + ten.ID.String() + "/idp." + id.String() + ".client#1"
	secret := "secret-" + identity.RandomHex(8)
	e.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'tenant', $2, $3, $4, $5, 'external', $6)`, id, ten.ID, fake.Issuer, clientID, ref, status)
	e.mu.Lock()
	e.secrets[ref] = secret
	e.mu.Unlock()
	fake.AddClient(clientID, secret, redirectURI(appHost, id))
	return id
}

func loginQuery(ten *tenantFix) string { return "scope=tenant&tenant=" + ten.Slug }

// TestInvitationBoundAtFirstLogin — the first login of an identity of the invitation's IdP with the verified e-mail
// (other case) creates the membership with the invitation's role, marks the invitation accepted by that identity and
// writes invitation.accept; a second identity with the same e-mail finds nothing to accept (single use).
func TestInvitationBoundAtFirstLogin(t *testing.T) {
	t.Parallel()
	e := newInvEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	inv := e.invite(ten, ten.IdP, "Invitee@Example.test", "tenant_viewer", 24*time.Hour)

	user := identity.FakeUser{Sub: "sub-" + identity.RandomHex(4), Email: "invitee@EXAMPLE.test", EmailVerified: true, Name: "Invitee"}
	fake.SetUser(user)
	b := e.browser()
	b.mustLogin(appHost, loginQuery(ten))
	ident, _, logged := e.identityOf(ten.IdP, user.Sub)
	st, acc := e.invitationStatus(inv)
	if st != tenants.InvitationAccepted || acc == nil || *acc != ident || !logged {
		t.Fatalf("invitation %s accepted by %v (identity %s, logged in %v)", st, acc, ident, logged)
	}
	if n := e.count(`SELECT count(*) FROM tenant_memberships m JOIN roles r ON r.id = m.role_id
		WHERE m.tenant_id = $1 AND m.identity_id = $2 AND r.key = 'tenant_viewer' AND m.status = 'active'`, ten.ID, ident); n != 1 {
		t.Fatalf("%d memberships with the invited role", n)
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.accept'
		AND outcome = 'success' AND actor_identity_id = $2 AND resource_id = $3`, ten.ID, ident, inv.String()); n != 1 {
		t.Fatalf("%d invitation.accept events", n)
	}
	if rec, s := b.session(appHost); rec.Code != http.StatusOK || len(s.Memberships) != 1 || s.Memberships[0].Role != "tenant_viewer" {
		t.Fatalf("session %d %+v", rec.Code, s.Memberships)
	}
	// the same person logs in again: a returning identity, nothing to bind, the membership stays
	again := e.browser()
	again.mustLogin(appHost, loginQuery(ten))

	// another account of the IdP with the same verified e-mail: the invitation was used once
	other := identity.FakeUser{Sub: "sub-" + identity.RandomHex(4), Email: "INVITEE@example.test", EmailVerified: true}
	fake.SetUser(other)
	b2 := e.browser()
	wantDenied(t, e.env, b2, appHost, b2.login(appHost, loginQuery(ten)), http.StatusForbidden, "forbidden", identity.ReasonNoInvitation)
	if id, ok, logged := e.identityOf(ten.IdP, other.Sub); !ok || logged {
		t.Fatalf("refused first login: identity %s exists %v, logged in %v — want an identity that never logged in", id, ok, logged)
	} else if n := e.count(`SELECT count(*) FROM tenant_memberships WHERE identity_id = $1`, id); n != 0 {
		t.Fatalf("refused identity got %d memberships", n)
	}
}

// TestInvitationRefusals — §20 P3-T05a: expired, another issuer (another IdP of the tenant, another tenant's IdP),
// another e-mail and an unverified e-mail are refused with their reason, no session and no membership; the refused
// identity never counts as logged in, so the invitation re-sent afterwards binds it.
func TestInvitationRefusals(t *testing.T) {
	t.Parallel()
	e := newInvEnv(t)
	login := func(t *testing.T, fake *identity.FakeIdP, ten *tenantFix, u identity.FakeUser, reason string) {
		t.Helper()
		fake.SetUser(u)
		b := e.browser()
		wantDenied(t, e.env, b, appHost, b.login(appHost, loginQuery(ten)), http.StatusForbidden, "forbidden", reason)
	}
	newUser := func(email string, verified bool) identity.FakeUser {
		return identity.FakeUser{Sub: "sub-" + identity.RandomHex(4), Email: email, EmailVerified: verified}
	}

	t.Run("expired, then re-sent", func(t *testing.T) {
		fake := e.fakeIdP()
		ten := e.newTenant(fake)
		inv := e.invite(ten, ten.IdP, "late@example.test", "tenant_viewer", time.Hour)
		e.clock.Advance(2 * time.Hour)
		u := newUser("late@example.test", true)
		login(t, fake, ten, u, identity.ReasonInvitationExpired)
		if st, _ := e.invitationStatus(inv); st != tenants.InvitationExpired {
			t.Fatalf("invitation %s, want expired", st)
		}
		if n := e.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.accept'
			AND outcome = 'denied' AND details ->> 'reason' = $2`, ten.ID, identity.ReasonInvitationExpired); n != 1 {
			t.Fatalf("%d denied invitation.accept events", n)
		}
		// an Owner re-sends it (new token, new expiry): the same person, never logged in, is bound now
		owner := uuid.Must(uuid.NewV7())
		ownerMember := uuid.Must(uuid.NewV7())
		e.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', $4)`,
			owner, ten.IdP, ten.ID, "owner-"+identity.RandomHex(4))
		e.exec(`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id) VALUES ($1, $2, $3, $4)`,
			ownerMember, ten.ID, owner, e.roleID("tenant_owner"))
		if _, err := e.ten.ResendInvitation(context.Background(), ten.ID, inv,
			tenants.InvitationActor{IdentityID: owner, MembershipID: ownerMember}, 0, authz.GuardInvitationRole); err != nil {
			t.Fatal(err)
		}
		fake.SetUser(u)
		e.browser().mustLogin(appHost, loginQuery(ten))
		if st, _ := e.invitationStatus(inv); st != tenants.InvitationAccepted {
			t.Fatalf("re-sent invitation %s after login", st)
		}
	})

	t.Run("another e-mail", func(t *testing.T) {
		fake := e.fakeIdP()
		ten := e.newTenant(fake)
		inv := e.invite(ten, ten.IdP, "alice@example.test", "tenant_viewer", 24*time.Hour)
		login(t, fake, ten, newUser("bob@example.test", true), identity.ReasonNoInvitation)
		if st, _ := e.invitationStatus(inv); st != tenants.InvitationPending {
			t.Fatalf("invitation %s, want still pending", st)
		}
	})

	t.Run("unverified e-mail", func(t *testing.T) {
		fake := e.fakeIdP()
		ten := e.newTenant(fake, withoutEmailVerification())
		inv := e.invite(ten, ten.IdP, "carol@example.test", "tenant_viewer", 24*time.Hour)
		login(t, fake, ten, newUser("carol@example.test", false), identity.ReasonInvitationEmailNotVerified)
		if st, _ := e.invitationStatus(inv); st != tenants.InvitationPending {
			t.Fatalf("invitation %s, want still pending", st)
		}
	})

	t.Run("another IdP of the tenant", func(t *testing.T) {
		fakeX := e.fakeIdP()
		ten := e.newTenant(fakeX)
		inv := e.invite(ten, ten.IdP, "dave@example.test", "tenant_viewer", 24*time.Hour)
		// the tenant moves to IdP Y (X retiring): a login through Y with the same verified e-mail is another issuer
		e.exec(`UPDATE identity_providers SET status = 'retiring' WHERE id = $1`, ten.IdP)
		fakeY := e.fakeIdP()
		idpY := e.addIdP(ten, fakeY, "active")
		u := newUser("dave@example.test", true)
		login(t, fakeY, ten, u, identity.ReasonInvitationIdPMismatch)
		if st, _ := e.invitationStatus(inv); st != tenants.InvitationPending {
			t.Fatalf("invitation %s, want still pending", st)
		}
		if _, ok, logged := e.identityOf(idpY, u.Sub); !ok || logged {
			t.Fatalf("identity of Y exists %v logged %v", ok, logged)
		}
		// the database refuses the binding too: FK (accepted_identity_id, idp_id) → identities(id, idp_id)
		idY, _, _ := e.identityOf(idpY, u.Sub)
		if _, err := e.db.Exec(context.Background(), `UPDATE tenant_invitations SET status = 'accepted',
			accepted_identity_id = $1, accepted_at = now() WHERE id = $2`, idY, inv); store.SQLState(err) != "23503" {
			t.Fatalf("acceptance by an identity of another IdP: %v, want 23503", err)
		}
	})

	t.Run("another tenant's issuer", func(t *testing.T) {
		fakeA, fakeB := e.fakeIdP(), e.fakeIdP()
		tenA, tenB := e.newTenant(fakeA), e.newTenant(fakeB)
		inv := e.invite(tenA, tenA.IdP, "erin@example.test", "tenant_viewer", 24*time.Hour)
		// B's IdP vouches for the same address: the identity belongs to B, A's invitation is invisible from B
		login(t, fakeB, tenB, newUser("erin@example.test", true), identity.ReasonNoInvitation)
		if st, _ := e.invitationStatus(inv); st != tenants.InvitationPending {
			t.Fatalf("A's invitation %s after a login at B", st)
		}
	})
}

// TestReturningIdentitiesAreNotBoundByEmail — an identity that already completed a login is never bound by e-mail
// (§6.3): its login goes on without membership and the pending invitation stays pending; a seeded identity keeps its
// membership; a login of another identity over an open session is refused before any identity row is written (G2 F1).
func TestReturningIdentitiesAreNotBoundByEmail(t *testing.T) {
	t.Parallel()
	e := newInvEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)

	old := identity.FakeUser{Sub: "sub-" + identity.RandomHex(4), Email: "frank@example.test", EmailVerified: true}
	oldID := uuid.Must(uuid.NewV7())
	e.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, last_login_at)
		VALUES ($1, $2, $3, 'tenant', $4, $5, true, now() - interval '30 days')`, oldID, ten.IdP, ten.ID, old.Sub, old.Email)
	inv := e.invite(ten, ten.IdP, old.Email, "tenant_viewer", 24*time.Hour)
	fake.SetUser(old)
	e.browser().mustLogin(appHost, loginQuery(ten))
	if st, _ := e.invitationStatus(inv); st != tenants.InvitationPending {
		t.Fatalf("invitation %s after the login of a returning identity", st)
	}
	if n := e.count(`SELECT count(*) FROM tenant_memberships WHERE identity_id = $1`, oldID); n != 0 {
		t.Fatalf("returning identity bound by e-mail: %d memberships", n)
	}

	// seeded (Phase 2): identity + membership by (IdP, sub), never logged in — its membership, not the invitation
	seeded := identity.FakeUser{Sub: "sub-" + identity.RandomHex(4), Email: "grace@example.test", EmailVerified: true}
	seededID := uuid.Must(uuid.NewV7())
	e.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', $4)`,
		seededID, ten.IdP, ten.ID, seeded.Sub)
	e.exec(`INSERT INTO tenant_memberships (tenant_id, identity_id, role_id) VALUES ($1, $2, $3)`,
		ten.ID, seededID, e.roleID("tenant_admin"))
	inv2 := e.invite(ten, ten.IdP, seeded.Email, "tenant_viewer", 24*time.Hour)
	fake.SetUser(seeded)
	b := e.browser()
	b.mustLogin(appHost, loginQuery(ten))
	if st, _ := e.invitationStatus(inv2); st != tenants.InvitationPending {
		t.Fatalf("invitation %s after the login of a seeded identity", st)
	}
	if n := e.count(`SELECT count(*) FROM tenant_memberships m JOIN roles r ON r.id = m.role_id
		WHERE m.identity_id = $1 AND r.key = 'tenant_admin'`, seededID); n != 1 {
		t.Fatal("seeded membership changed")
	}

	// G2 F1 with the binder: another identity over the open session is refused before any row is written
	intruder := identity.FakeUser{Sub: "sub-" + identity.RandomHex(4), Email: "heidi@example.test", EmailVerified: true}
	e.invite(ten, ten.IdP, intruder.Email, "tenant_viewer", 24*time.Hour)
	fake.SetUser(intruder)
	rec := b.login(appHost, loginQuery(ten))
	if rec.Code != http.StatusForbidden || e.audit.last(identity.ActionLogin).Reason != "session_identity_mismatch" {
		t.Fatalf("login over another session: HTTP %d reason %q", rec.Code, e.audit.last(identity.ActionLogin).Reason)
	}
	if _, ok, _ := e.identityOf(ten.IdP, intruder.Sub); ok {
		t.Fatal("an identity row was written for a login refused over another session")
	}
}
