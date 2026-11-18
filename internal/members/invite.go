package members

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Error codes of member.idp_invite.
const (
	CodeIdPUserDisabled = "idp_user_disabled" // the address belongs to a disabled user (an earlier offboarding): explicit reactivation only
	CodeIdPEmailFailed  = "idp_email_failed"  // the user exists, the IdP could not e-mail its required actions (resend retries)
	CodeIdPInviteFailed = "idp_invite_failed"
)

// MaxInviteLink bounds the lifetime of the IdP's required-actions link (the invitation itself may live 30 days).
const MaxInviteLink = 7 * 24 * time.Hour

// IdPInviteNotifier delivers an invitation (tenants.InvitationNotifier) through Next — the e-mail of the platform
// (OutboxNotifier) — and enqueues member.idp_invite in the same transaction: at a platform-hosted IdP the invited
// person needs an account to sign in with (§8.2: InviteUser creates it and e-mails its required actions). Created and
// re-sent invitations both run it (InviteUser is idempotent: an existing user gets the e-mail again).
type IdPInviteNotifier struct {
	Next tenants.InvitationNotifier
}

var _ tenants.InvitationNotifier = IdPInviteNotifier{}

// idpInviteInput is the input of member.idp_invite: the invitation only (the address is read from it).
type idpInviteInput struct {
	InvitationID uuid.UUID `json:"invitation_id"`
}

// InvitationIssued implements tenants.InvitationNotifier.
func (n IdPInviteNotifier) InvitationIssued(ctx context.Context, tx *store.Tx, in tenants.InvitationNotice) error {
	if n.Next != nil {
		if err := n.Next.InvitationIssued(ctx, tx, in); err != nil {
			return err
		}
	}
	tenantID := in.TenantID
	_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindIdPInvite, TenantID: &tenantID, Object: in.InvitationID.String(),
		Input: idpInviteInput{InvitationID: in.InvitationID}, RequestedBy: in.InvitedBy,
		Resource: &jobs.Resource{Type: "invitation", ID: in.InvitationID.String()}})
	return err
}

// runIdPInvite is the handler of member.idp_invite: the invited address gets an account at the platform-hosted IdP of
// the invitation (driver keycloak: user = e-mail, required actions VERIFY_EMAIL, UPDATE_PASSWORD, CONFIGURE_TOTP,
// e-mailed by the IdP). A tenant-managed IdP (driver external) does not offer it: nothing to do. An invitation that is
// no longer pending is skipped. One audit event invitation.idp_user (actor system) records the outcome.
func (s *Service) runIdPInvite(ctx context.Context, run *jobs.Run) error {
	var in idpInviteInput
	if err := run.DecodeInput(&in); err != nil || in.InvitationID == uuid.Nil || run.TenantID == nil {
		return jobs.Permanent(CodeInvalidInput, errors.Join(errors.New("member.idp_invite: invalid input"), err))
	}
	tenantID := *run.TenantID
	var row sqlcdb.GetInvitationForIdPRow
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.GetInvitationForIdP(ctx, sqlcdb.GetInvitationForIdPParams{TenantID: tenantID, ID: in.InvitationID})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		_ = run.SetOutput(map[string]any{"skipped": "no_invitation"})
		return nil
	case err != nil:
		return jobs.Transient("internal_error", err)
	}
	now := s.now()
	if row.Status != tenants.InvitationPending || !now.Before(row.ExpiresAt) {
		_ = run.SetOutput(map[string]any{"skipped": "not_pending", "status": row.Status})
		return nil
	}
	reg := registration(row.IdpID, row.IdpScope, row.IdpTenantID, row.Driver, row.DriverRef, row.Issuer, row.ClientID,
		row.ClientSecretRef)
	drv, err := s.idps.For(reg)
	if err != nil {
		return jobs.Permanent(CodeNotConfigured, err)
	}
	link := min(row.ExpiresAt.Sub(now), MaxInviteLink)
	res, err := drv.InviteUser(ctx, reg, idp.Invite{Email: row.Email, SendEmail: true, LinkLifespan: max(link, time.Hour)})
	d := audit.Details{"invitation_id": row.ID, "idp_id": row.IdpID}
	var jerr error
	switch {
	case idp.CodeOf(err) == idp.CodeUnsupported:
		_ = run.SetOutput(map[string]any{"idp": idpStateNotApplicable})
		return nil
	case idp.CodeOf(err) == idp.CodeConflict:
		jerr = jobs.Permanent(CodeIdPUserDisabled, err)
	case idp.CodeOf(err) == idp.CodeEmailFailed:
		jerr = jobs.Permanent(CodeIdPEmailFailed, err)
		d["created"] = res.Created
	case err != nil:
		jerr = idpErr(CodeIdPInviteFailed, err)
	}
	if jerr != nil {
		var je *jobs.Error
		if errors.As(jerr, &je) && (je.Permanent || run.Attempt >= run.MaxAttempts) {
			d["reason"] = je.Code
			s.recordInvite(ctx, tenantID, audit.OutcomeFailure, d)
		}
		return jerr
	}
	d["created"], d["email_sent"] = res.Created, res.EmailSent
	s.recordInvite(ctx, tenantID, audit.OutcomeSuccess, d)
	_ = run.SetOutput(map[string]any{"idp": "invited", "created": res.Created, "email_sent": res.EmailSent})
	return nil
}

func (s *Service) recordInvite(ctx context.Context, tenantID uuid.UUID, outcome string, d audit.Details) {
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		t := tenantID
		return audit.Record(audit.WithRequest(ctx, nil), q, audit.Event{Action: ActionInvitationIdPUser, TenantID: &t,
			ActorType: audit.ActorSystem, ActorDisplay: KindIdPInvite, ResourceType: "invitation",
			ResourceID: fmt.Sprint(d["invitation_id"]), Outcome: outcome, Details: d})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "members: recording an IdP invitation failed", "sqlstate", store.SQLState(err))
	}
}
