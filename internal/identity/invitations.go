package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Invitation binding at the first login of a tenant identity (P3-T05a, §6.3 tenant_invitations, §8.2).
//
// A person is added to a tenant only through an invitation (or the host-only seed of Phase 2). The invitation names
// the tenant's IdP, an e-mail address and a role; the callback binds it — creates the membership with that role and
// marks the invitation accepted, once — when an identity of THAT IdP that has never completed a login signs in with a
// verified e-mail equal to the invitation's (case-insensitive) before the invitation expires. An identity that already
// completed a login (identities.last_login_at set) is never bound by e-mail; nor is a platform identity. A first login
// that cannot be bound — no pending invitation for the verified e-mail, another IdP, an unverified e-mail, an expired
// invitation — is refused with that reason (403 forbidden, audited): the identity then still counts as never logged
// in, so a re-sent invitation binds it later. The membership and the invitation live in the tenant's tables (tenant
// pool, module tenants), so the binder is an interface wired in apps/* (identity may not import tenants — §13.6).

// Reasons of a refused first login (BindResult.Refused; the reason of the auth.login audit event).
const (
	ReasonNoInvitation               = "no_invitation"                 // no pending invitation for the verified e-mail
	ReasonInvitationIdPMismatch      = "invitation_idp_mismatch"       // the invitation names another IdP of the tenant
	ReasonInvitationEmailNotVerified = "invitation_email_not_verified" // the IdP does not vouch for the e-mail
	ReasonInvitationExpired          = "invitation_expired"
)

// FirstLogin is a tenant identity that has never completed a login, at its login callback — every value comes from the
// verified ID token and the IdP row of the callback, never from the client.
type FirstLogin struct {
	TenantID      uuid.UUID
	IdPID         uuid.UUID
	IdentityID    uuid.UUID
	Email         string // "" when the IdP sent none
	EmailVerified bool
	ClientIP      string
	RequestID     string
}

// BindResult is the outcome of a first-login binding.
type BindResult struct {
	MembershipID uuid.UUID // the identity's membership: created from the invitation, or the one it already had
	InvitationID uuid.UUID // the invitation accepted; uuid.Nil when none was
	// Refused is the reason the identity cannot be bound (Reason* above); the login is refused with it.
	Refused string
}

// InvitationBinder binds a first login to the pending invitation of its tenant (internal/tenants implements it, in
// one transaction of the tenant pool). An error is an infrastructure failure, not a refusal.
type InvitationBinder interface {
	BindFirstLogin(ctx context.Context, in FirstLogin) (BindResult, error)
}

// bindFirstLogin runs before the session of a tenant login is created, when a binder is configured. It refuses a login
// of another identity over an open session first (G2 F1 — before anything is written), ensures the identity row
// (idp_id, sub) exists — the membership and the invitation reference it — without marking it logged in, and asks the
// binder when the identity has never completed a login.
func (s *Service) bindFirstLogin(ctx context.Context, in CallbackRequest, p *idp, prof *tokenProfile, ev *AuditEvent) error {
	if in.Current != nil && in.Current.Origin == in.Origin && (in.Current.IdPID != p.ID || in.Current.Subject != prof.Subject) {
		ev.IdentityID, ev.TenantID, ev.SessionID = in.Current.IdentityID, in.Current.TenantID, in.Current.PublicID
		return forbidden(reasonSessionIdentityMismatch)
	}
	if p.TenantID == nil {
		return newErr(KindInternal, "tenant_idp_without_tenant", nil)
	}
	var ident sqlcdb.Identity
	err := s.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if err := q.InsertFirstLoginIdentity(ctx, sqlcdb.InsertFirstLoginIdentityParams{
			IdpID: p.ID, TenantID: p.TenantID, Scope: string(p.Scope), Subject: prof.Subject,
			Email: nilIfEmpty(prof.Email), EmailVerified: prof.EmailVerified, DisplayName: nilIfEmpty(prof.DisplayName),
			Now: s.now(),
		}); err != nil {
			return err
		}
		var err error
		ident, err = q.GetIdentityBySubject(ctx, sqlcdb.GetIdentityBySubjectParams{IdpID: p.ID, Subject: prof.Subject})
		return err
	})
	if err != nil {
		return newErr(KindInternal, "identity_create_failed", err)
	}
	ev.IdentityID = ident.ID
	switch {
	case ident.Status != IdentityActive:
		return forbidden("identity_disabled")
	case ident.LastLoginAt != nil:
		return nil // a returning identity: never bound by e-mail (§6.3)
	}
	res, err := s.cfg.Invitations.BindFirstLogin(ctx, FirstLogin{
		TenantID: *p.TenantID, IdPID: p.ID, IdentityID: ident.ID, Email: prof.Email, EmailVerified: prof.EmailVerified,
		ClientIP: in.ClientIP, RequestID: in.RequestID,
	})
	switch {
	case err != nil:
		return newErr(KindInternal, "invitation_binding_failed", err)
	case res.Refused != "":
		return forbidden(res.Refused)
	case res.MembershipID == uuid.Nil:
		return newErr(KindInternal, "invitation_binding_failed", errors.New("binder returned no membership"))
	}
	return nil
}
