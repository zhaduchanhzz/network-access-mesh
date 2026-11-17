package tenants

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Invitations (P3-T05a — §6.3 tenant_invitations, §8.2, §13.2 "invitations"): the only way to add a person who never
// logged in. A Tenant Owner/Admin invites an e-mail address with a role (§8.4 rule 3a, checked by the RoleGuard —
// authz.GuardInvitationRole — in the same transaction); the invitation names the tenant's active IdP. The first login
// of an identity of that IdP with that verified e-mail binds it (BindFirstLogin, called by the identity callback).

// Invitation statuses (CHECK of 0009).
const (
	InvitationPending  = "pending"
	InvitationAccepted = "accepted"
	InvitationRevoked  = "revoked"
	InvitationExpired  = "expired"
)

// InvitationStatuses is the set of tenant_invitations.status (enum InvitationStatus of api/openapi.yaml).
var InvitationStatuses = []string{InvitationPending, InvitationAccepted, InvitationRevoked, InvitationExpired}

// InvitableRoles are the roles an invitation of the API may carry (enum InvitationRole): never the Owner — the only
// Owner invitation is the one the orchestrator creates at tenant.configure (§11.3 step 16, §8.4 rule 3a).
var InvitableRoles = []string{"tenant_admin", "tenant_operator", "tenant_viewer", "end_user"}

// Lifetimes and the outbox event of an invitation.
const (
	DefaultInvitationTTL = 7 * 24 * time.Hour
	MaxInvitationTTL     = 30 * 24 * time.Hour
	// OutboxKindInvitation is notification_outbox.kind of an invitation e-mail (sent by notification.send, P3-T05b):
	// recipient_email = the invited address; payload {invitation_id, tenant_id, role, expires_at, resent} — no token,
	// no secret (§6.3).
	OutboxKindInvitation = "tenant.invitation"
	// createOperation is the operationId whose Idempotency-Key CreateInvitation stores (§13.1).
	createOperation = "createTenantInvitation"
	idempotencyLock = 30 * time.Second
)

// Audit actions of the invitation flows (x-audit-action of api/openapi.yaml; accept is written at login).
const (
	ActionInvitationCreate = "invitation.create"
	ActionInvitationRevoke = "invitation.revoke"
	ActionInvitationResend = "invitation.resend"
	ActionInvitationAccept = "invitation.accept"
)

var (
	// ErrIdempotencyInProgress: the same Idempotency-Key is still being served (409 + Retry-After).
	ErrIdempotencyInProgress = errors.New("tenants: a request with this Idempotency-Key is in progress")
	// ErrIdempotencyKeyReuse: the Idempotency-Key was used for another request (422 idempotency_key_reuse).
	ErrIdempotencyKeyReuse = errors.New("tenants: Idempotency-Key used for another request")
)

// InvitationError is a refusal of the invitation operations: Kind is ErrNotFound, ErrInvalid, ErrConflict or one of
// the idempotency errors (errors.Is works through Unwrap); Reason is a stable code for audit and logs.
type InvitationError struct {
	Kind       error
	Reason     string
	RetryAfter time.Duration // ErrIdempotencyInProgress
}

func (e *InvitationError) Error() string {
	return "tenants: invitation: " + e.Kind.Error() + " (" + e.Reason + ")"
}
func (e *InvitationError) Unwrap() error { return e.Kind }

func invErr(kind error, reason string) *InvitationError {
	return &InvitationError{Kind: kind, Reason: reason}
}

// Invitation is the API view of an invitation (schema Invitation) — never the token.
type Invitation struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenant_id"`
	IdPID              uuid.UUID  `json:"idp_id"`
	Email              string     `json:"email"`
	Role               string     `json:"role"`
	Status             string     `json:"status"` // effective: pending past expires_at reads expired
	ExpiresAt          time.Time  `json:"expires_at"`
	InvitedBy          *uuid.UUID `json:"invited_by,omitempty"`
	InvitedByDisplay   string     `json:"invited_by_display,omitempty"`
	AcceptedIdentityID *uuid.UUID `json:"accepted_identity_id,omitempty"`
	AcceptedAt         *time.Time `json:"accepted_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	Version            int64      `json:"version"`
}

// InvitationPage is one page of invitations.
type InvitationPage struct {
	Items      []Invitation
	NextCursor string
}

// InvitationFilter holds the query parameters of GET /tenants/{t}/invitations.
type InvitationFilter struct {
	Page
	Status string // effective status
}

// InvitationActor is the caller of an invitation operation: its identity and its membership in the tenant of the path
// (authz.Decision.MembershipID).
type InvitationActor struct {
	IdentityID   uuid.UUID
	MembershipID uuid.UUID
	Display      string
	ClientIP     netip.Addr
}

// NewInvitation is the body of POST /tenants/{t}/invitations.
type NewInvitation struct {
	Email string
	Role  string        // one of InvitableRoles
	TTL   time.Duration // 0 ⇒ DefaultInvitationTTL; at most MaxInvitationTTL
}

// Idempotency is the Idempotency-Key of a create request and the SHA-256 of the request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// RoleGuard checks the role an invitation carries against the caller (§8.4 rules 3, 3a), inside the transaction that
// creates, revokes or re-sends it: authz.GuardInvitationRole, wired in apps/* (tenants does not import authz — §13.6).
// Its refusals are returned as they are (*authz.Denial: 403/422).
type RoleGuard func(ctx context.Context, q *sqlcdb.Queries, tenantID, actorMembership uuid.UUID, roleKey string) error

// InvitationNotice is what the notifier delivers: the invitation and the one-time token of its link (base64url of 32
// random bytes, only its SHA-256 is stored). The token never reaches the database in clear, a log or an API answer.
type InvitationNotice struct {
	TenantID     uuid.UUID
	InvitationID uuid.UUID
	Email        string
	Role         string
	ExpiresAt    time.Time
	InvitedBy    *uuid.UUID
	Resent       bool
	Token        string
}

// InvitationNotifier delivers an invitation (P3-T05b): called inside the transaction that creates or re-sends it, so
// the notice commits with it; an error rolls the invitation back. It must not store the token in clear.
type InvitationNotifier interface {
	InvitationIssued(ctx context.Context, q *sqlcdb.Queries, n InvitationNotice) error
}

// OutboxNotifier is the default notifier: one notification_outbox row of kind OutboxKindInvitation addressed to the
// invited e-mail, payload without the token (P3-T05b renders and sends it).
type OutboxNotifier struct{}

// InvitationIssued implements InvitationNotifier.
func (OutboxNotifier) InvitationIssued(ctx context.Context, q *sqlcdb.Queries, n InvitationNotice) error {
	payload, err := json.Marshal(map[string]any{
		"invitation_id": n.InvitationID, "tenant_id": n.TenantID, "role": n.Role,
		"expires_at": n.ExpiresAt.UTC().Format(time.RFC3339), "resent": n.Resent,
	})
	if err != nil {
		return err
	}
	t, email := n.TenantID, n.Email
	_, err = q.InsertInvitationNotice(ctx, sqlcdb.InsertInvitationNoticeParams{TenantID: &t, RecipientEmail: &email,
		Kind: OutboxKindInvitation, Payload: payload})
	return err
}

var emailRE = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]+\.[^@\s.]+$`)

// normalizeEmail trims the address and checks its shape (the comparison is case-insensitive in the database: citext).
func normalizeEmail(s string) (string, error) {
	e := strings.TrimSpace(s)
	if len(e) < 3 || len(e) > 320 || !emailRE.MatchString(e) {
		return "", invErr(ErrInvalid, "invalid_email")
	}
	return e, nil
}

func ttlOf(d time.Duration) (time.Duration, error) {
	switch {
	case d == 0:
		return DefaultInvitationTTL, nil
	case d < time.Hour || d > MaxInvitationTTL:
		return 0, invErr(ErrInvalid, "invalid_ttl")
	}
	return d, nil
}

// newToken returns a fresh token and its SHA-256 (tenant_invitations.token_hash).
func newToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(raw), sum[:], nil
}

// effectiveStatus reads a pending invitation past its expiry as expired.
func (s *Service) effectiveStatus(status string, expires time.Time) string {
	if status == InvitationPending && !s.now().Before(expires) {
		return InvitationExpired
	}
	return status
}

func (s *Service) invitationView(r sqlcdb.TenantInvitation, roleKey, invitedBy string) Invitation {
	return Invitation{
		ID: r.ID, TenantID: r.TenantID, IdPID: r.IdpID, Email: r.Email, Role: roleKey,
		Status: s.effectiveStatus(r.Status, r.ExpiresAt), ExpiresAt: r.ExpiresAt, InvitedBy: r.InvitedByIdentityID,
		InvitedByDisplay: invitedBy, AcceptedIdentityID: r.AcceptedIdentityID, AcceptedAt: r.AcceptedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Version: r.Version,
	}
}

func actorEvent(a InvitationActor, ev audit.Event) audit.Event {
	id := a.IdentityID
	ev.ActorIdentityID, ev.ActorDisplay, ev.ResourceType = &id, a.Display, "invitation"
	if a.ClientIP.IsValid() {
		ev.ActorIP = a.ClientIP
	}
	return ev
}

// CreateInvitation is POST /tenants/{tenantId}/invitations: one transaction checks the role (guard, §8.4 3a), takes the
// tenant's active IdP, refuses an address that is already a member or already has a pending invitation (an expired
// one is closed first), stores the invitation with the SHA-256 of a fresh token, hands the notice to the notifier
// (outbox) and writes invitation.create. With an Idempotency-Key, a replay of the same request returns the invitation
// stored by the first one; the key is taken in a transaction of its own before (§13.1).
func (s *Service) CreateInvitation(ctx context.Context, tenantID uuid.UUID, actor InvitationActor, in NewInvitation,
	guard RoleGuard, idem *Idempotency) (Invitation, error) {
	email, err := normalizeEmail(in.Email)
	if err != nil {
		return Invitation{}, err
	}
	if !slices.Contains(InvitableRoles, in.Role) {
		return Invitation{}, invErr(ErrInvalid, "role_not_invitable")
	}
	ttl, err := ttlOf(in.TTL)
	if err != nil {
		return Invitation{}, err
	}
	if guard == nil {
		return Invitation{}, errors.New("tenants: no role guard (authz.GuardInvitationRole)")
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{TenantID: &tenantID, IdentityID: actor.IdentityID, OperationID: createOperation, Key: idem.Key}
		var replay *Invitation
		err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, idempotencyLock)
			if err != nil {
				return err
			}
			switch d.Outcome {
			case jobs.IdempotencyReplay:
				var inv Invitation
				if d.Response == nil || json.Unmarshal(d.Response.Body, &inv) != nil {
					return errors.New("tenants: stored invitation response unreadable")
				}
				inv.Status = s.effectiveStatus(inv.Status, inv.ExpiresAt)
				replay = &inv
			case jobs.IdempotencyInProgress:
				return &InvitationError{Kind: ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
			case jobs.IdempotencyKeyReuse:
				return invErr(ErrIdempotencyKeyReuse, "idempotency_key_reuse")
			}
			return nil
		})
		if err != nil {
			return Invitation{}, err
		}
		if replay != nil {
			return *replay, nil
		}
	}
	now := s.now()
	var out Invitation
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		if err := guard(ctx, q, tenantID, actor.MembershipID, in.Role); err != nil {
			return err
		}
		role, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "tenant", Key: in.Role})
		if err != nil {
			return err
		}
		idp, err := q.GetActiveTenantIdP(ctx, &tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return invErr(ErrConflict, "no_active_idp")
		}
		if err != nil {
			return err
		}
		n, err := q.CountMembersWithEmail(ctx, sqlcdb.CountMembersWithEmailParams{TenantID: tenantID, Email: email})
		if err != nil {
			return err
		}
		if n > 0 {
			return invErr(ErrConflict, "already_member")
		}
		prev, err := q.LockPendingInvitationByEmail(ctx, sqlcdb.LockPendingInvitationByEmailParams{TenantID: tenantID, Email: email})
		switch {
		case err == nil && now.Before(prev.ExpiresAt):
			return invErr(ErrConflict, "invitation_pending")
		case err == nil:
			if err := q.ExpireInvitation(ctx, sqlcdb.ExpireInvitationParams{Now: now, TenantID: tenantID, ID: prev.ID}); err != nil {
				return err
			}
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		token, hash, err := newToken()
		if err != nil {
			return err
		}
		invitedBy := actor.IdentityID
		row, err := q.InsertInvitation(ctx, sqlcdb.InsertInvitationParams{TenantID: tenantID, IdpID: idp, Email: email,
			RoleID: role.ID, InvitedByIdentityID: &invitedBy, TokenHash: hash, ExpiresAt: now.Add(ttl), Now: now})
		if err != nil {
			return conflictFromDB(err)
		}
		if err := s.notifier.InvitationIssued(ctx, q, InvitationNotice{TenantID: tenantID, InvitationID: row.ID,
			Email: row.Email, Role: in.Role, ExpiresAt: row.ExpiresAt, InvitedBy: &invitedBy, Token: token}); err != nil {
			return err
		}
		if err := audit.Record(ctx, q, actorEvent(actor, audit.Event{Action: ActionInvitationCreate, TenantID: &tenantID,
			ResourceID: row.ID.String(), Details: audit.Details{"invitation_id": row.ID, "email": row.Email,
				"role": in.Role, "idp_id": idp, "expires_at": row.ExpiresAt}})); err != nil {
			return err
		}
		out = s.invitationView(row, in.Role, actor.Display)
		if key != nil {
			body, err := json.Marshal(out)
			if err != nil {
				return err
			}
			return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body,
				Resource: &jobs.Resource{Type: "invitation", ID: row.ID.String()}})
		}
		return nil
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithTenantTx(context.WithoutCancel(ctx), tenantID, func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
			})
		}
		return Invitation{}, err
	}
	return out, nil
}

// GetInvitation returns one invitation of the tenant (another tenant's reads ErrNotFound — §8.4 invariant 6).
func (s *Service) GetInvitation(ctx context.Context, tenantID, id uuid.UUID) (Invitation, error) {
	var out Invitation
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetInvitationView(ctx, sqlcdb.GetInvitationViewParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return invErr(ErrNotFound, "invitation_not_found")
		}
		if err != nil {
			return err
		}
		out = s.invitationView(r.TenantInvitation, r.RoleKey, r.InvitedByDisplay)
		return nil
	})
	return out, err
}

// ListInvitations is GET /tenants/{tenantId}/invitations: newest first.
func (s *Service) ListInvitations(ctx context.Context, tenantID uuid.UUID, f InvitationFilter) (InvitationPage, error) {
	limit, after, afterID, err := f.params()
	if err != nil {
		return InvitationPage{}, err
	}
	if f.Status != "" && !slices.Contains(InvitationStatuses, f.Status) {
		return InvitationPage{}, fmt.Errorf("%w: unknown status", ErrInvalid)
	}
	before, beforeID := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), uuid.Max
	if after != nil {
		before, beforeID = *after, *afterID
	}
	page := InvitationPage{Items: []Invitation{}}
	var status *string
	if f.Status != "" {
		status = &f.Status
	}
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListInvitations(ctx, sqlcdb.ListInvitationsParams{TenantID: tenantID, Status: status, Now: s.now(),
			BeforeCreatedAt: before, BeforeID: beforeID, PageLimit: int32(limit + 1)}) //nolint:gosec // limit ≤ MaxLimit
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1].TenantInvitation
			page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		}
		for _, r := range rows {
			page.Items = append(page.Items, s.invitationView(r.TenantInvitation, r.RoleKey, r.InvitedByDisplay))
		}
		return nil
	})
	return page, err
}

// lockForChange locks an invitation of the tenant and checks the caller may act on its role (§8.4 3a).
func lockForChange(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID, actor InvitationActor,
	guard RoleGuard) (sqlcdb.LockInvitationRow, error) {
	if guard == nil {
		return sqlcdb.LockInvitationRow{}, errors.New("tenants: no role guard (authz.GuardInvitationRole)")
	}
	r, err := q.LockInvitation(ctx, sqlcdb.LockInvitationParams{TenantID: tenantID, ID: id})
	if errors.Is(err, store.ErrNoRows) {
		return r, invErr(ErrNotFound, "invitation_not_found")
	}
	if err != nil {
		return r, err
	}
	return r, guard(ctx, q, tenantID, actor.MembershipID, r.RoleKey)
}

// RevokeInvitation is DELETE /tenants/{tenantId}/invitations/{id}: a pending invitation becomes revoked (an invitation
// that is no longer pending ⇒ ErrConflict).
func (s *Service) RevokeInvitation(ctx context.Context, tenantID, id uuid.UUID, actor InvitationActor, guard RoleGuard) error {
	return s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := lockForChange(ctx, q, tenantID, id, actor, guard)
		if err != nil {
			return err
		}
		if r.TenantInvitation.Status != InvitationPending {
			return invErr(ErrConflict, "invitation_not_pending")
		}
		if _, err := q.RevokeInvitation(ctx, sqlcdb.RevokeInvitationParams{Now: s.now(), TenantID: tenantID, ID: id}); err != nil {
			return err
		}
		return audit.Record(ctx, q, actorEvent(actor, audit.Event{Action: ActionInvitationRevoke, TenantID: &tenantID,
			ResourceID: id.String(), Details: audit.Details{"invitation_id": id, "role": r.RoleKey}}))
	})
}

// ResendInvitation is POST /tenants/{tenantId}/invitations/{id}/resend: a pending or expired invitation gets a new
// token (the previous link stops working) and a new expiry, becomes pending again and is handed to the notifier.
func (s *Service) ResendInvitation(ctx context.Context, tenantID, id uuid.UUID, actor InvitationActor, ttl time.Duration,
	guard RoleGuard) (Invitation, error) {
	d, err := ttlOf(ttl)
	if err != nil {
		return Invitation{}, err
	}
	now := s.now()
	var out Invitation
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := lockForChange(ctx, q, tenantID, id, actor, guard)
		if err != nil {
			return err
		}
		if st := r.TenantInvitation.Status; st != InvitationPending && st != InvitationExpired {
			return invErr(ErrConflict, "invitation_not_resendable")
		}
		token, hash, err := newToken()
		if err != nil {
			return err
		}
		row, err := q.ReissueInvitation(ctx, sqlcdb.ReissueInvitationParams{TokenHash: hash, ExpiresAt: now.Add(d), Now: now,
			TenantID: tenantID, ID: id})
		if err != nil {
			return conflictFromDB(err)
		}
		if err := s.notifier.InvitationIssued(ctx, q, InvitationNotice{TenantID: tenantID, InvitationID: id,
			Email: row.Email, Role: r.RoleKey, ExpiresAt: row.ExpiresAt, InvitedBy: row.InvitedByIdentityID, Resent: true,
			Token: token}); err != nil {
			return err
		}
		if err := audit.Record(ctx, q, actorEvent(actor, audit.Event{Action: ActionInvitationResend, TenantID: &tenantID,
			ResourceID: id.String(), Details: audit.Details{"invitation_id": id, "role": r.RoleKey,
				"expires_at": row.ExpiresAt}})); err != nil {
			return err
		}
		v, err := q.GetInvitationView(ctx, sqlcdb.GetInvitationViewParams{TenantID: tenantID, ID: id})
		if err != nil {
			return err
		}
		out = s.invitationView(v.TenantInvitation, v.RoleKey, v.InvitedByDisplay)
		return nil
	})
	return out, err
}

var _ identity.InvitationBinder = (*Service)(nil)

// BindFirstLogin implements identity.InvitationBinder (P3-T05a): in one transaction of the identity's tenant (tenant
// pool — the invitations and memberships of other tenants are invisible), an identity that already has a membership
// keeps it (seeded by `meshguard admin seed-membership`); otherwise the pending invitation for its e-mail is locked
// and accepted when it names the identity's IdP, the IdP vouches for the e-mail and it has not expired — the
// membership gets the invitation's role and invited_by, the invitation becomes accepted (once: the lock and the
// pending filter make a second acceptance see nothing) and invitation.accept is written. A refusal is written as a
// denied invitation.accept (an expired invitation is closed) and returned as BindResult.Refused.
func (s *Service) BindFirstLogin(ctx context.Context, in identity.FirstLogin) (identity.BindResult, error) {
	var res identity.BindResult
	now := s.now()
	err := s.st.WithTenantTx(ctx, in.TenantID, func(q *sqlcdb.Queries) error {
		m, err := q.GetMembershipRole(ctx, sqlcdb.GetMembershipRoleParams{TenantID: in.TenantID, IdentityID: in.IdentityID})
		switch {
		case err == nil:
			res.MembershipID = m.ID
			return nil
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		email := strings.TrimSpace(in.Email)
		if email == "" {
			res.Refused = identity.ReasonNoInvitation
			return nil
		}
		inv, err := q.LockPendingInvitationByEmail(ctx, sqlcdb.LockPendingInvitationByEmailParams{TenantID: in.TenantID,
			Email: email})
		if errors.Is(err, store.ErrNoRows) {
			res.Refused = identity.ReasonNoInvitation
			return nil
		}
		if err != nil {
			return err
		}
		ev := audit.Event{Action: ActionInvitationAccept, TenantID: &in.TenantID, ActorIdentityID: &in.IdentityID,
			ActorDisplay: email, ResourceType: "invitation", ResourceID: inv.ID.String(), RequestID: in.RequestID,
			Details: audit.Details{"invitation_id": inv.ID, "idp_id": in.IdPID}}
		if a, err := netip.ParseAddr(in.ClientIP); err == nil {
			ev.ActorIP = a
		}
		switch {
		case inv.IdpID != in.IdPID:
			res.Refused = identity.ReasonInvitationIdPMismatch
		case !in.EmailVerified:
			res.Refused = identity.ReasonInvitationEmailNotVerified
		case !now.Before(inv.ExpiresAt):
			res.Refused = identity.ReasonInvitationExpired
			if err := q.ExpireInvitation(ctx, sqlcdb.ExpireInvitationParams{Now: now, TenantID: in.TenantID, ID: inv.ID}); err != nil {
				return err
			}
		}
		if res.Refused != "" {
			ev.Outcome = audit.OutcomeDenied
			ev.Details["reason"] = res.Refused
			return audit.Record(ctx, q, ev)
		}
		mem, err := q.InsertInvitedMembership(ctx, sqlcdb.InsertInvitedMembershipParams{TenantID: in.TenantID,
			IdentityID: in.IdentityID, RoleID: inv.RoleID, InvitedBy: inv.InvitedByIdentityID})
		if err != nil {
			return err
		}
		identityID := in.IdentityID
		if _, err := q.AcceptInvitation(ctx, sqlcdb.AcceptInvitationParams{IdentityID: &identityID, Now: now,
			TenantID: in.TenantID, ID: inv.ID}); err != nil {
			return err
		}
		res.MembershipID, res.InvitationID = mem.ID, inv.ID
		ev.Details["membership_id"] = mem.ID
		if inv.InvitedByIdentityID != nil {
			ev.Details["invited_by_identity_id"] = *inv.InvitedByIdentityID
		}
		return audit.Record(ctx, q, ev)
	})
	if err != nil {
		return identity.BindResult{}, fmt.Errorf("tenants: bind first login: %w", err)
	}
	return res, nil
}
