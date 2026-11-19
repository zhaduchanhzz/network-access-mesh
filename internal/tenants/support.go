package tenants

// Support Access Grant (P4-T13, §8.7; table support_access_grants of 0023 + 0028):
//
//   - POST /platform/support-grants — platform staff ask for a time-boxed access to ONE tenant with an effective role of
//     scope support (support_operator; support_admin only through break-glass), a reason, a ticket and 1–480 minutes. The
//     grant is pending; the platform trail records the request, then the tenant's own trail records it and the members
//     who may decide (tenant.support_grant:decide) are notified — transparency (§8.7 step 3);
//   - the tenant decides in its Portal: approve (step-up; ceiling support_operator — "Admin chỉ qua break-glass"; never a
//     tenant role, the schema has only the two support roles), reject, revoke (any time, effective at the next request);
//   - break-glass (§8.7 step 2): a second Super Admin — not the requester, not the grantee (CHECK) — approves; the
//     requester must also be an active Super Admin (trigger mg_support_grant_guard): the dual control lives in the grant
//     itself. The tenant's trail records it, a high security_event is raised and every Tenant Owner is notified;
//   - a Super Admin revokes any grant; grant.expire marks the grants past their window expired (the access decision never
//     waits for it: internal/authz and store.WithTenantTx check the window on every request — §6.1).
//
// Each write runs in one transaction with its audit event; a platform-side write that the tenant must see is then
// recorded in the tenant's own transaction (two pools — the same pattern as RequestDeletion and the platform IdP change
// of P4-T03a).

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Effective roles of a grant (roles of scope support — §8.6 column Staff).
const (
	SupportOperator = "support_operator"
	SupportAdmin    = "support_admin"
)

// Grant statuses (support_access_grants.status, and the effective status of the API).
const (
	GrantPending  = "pending"
	GrantApproved = "approved"
	GrantRejected = "rejected"
	GrantRevoked  = "revoked"
	GrantExpired  = "expired"
)

// Approval kinds.
const (
	ApprovalTenant     = "tenant"
	ApprovalBreakGlass = "breakglass"
)

// MaxSupportGrantMinutes is the longest window of a grant (CHECK of 0023: ≤ 8 hours).
const MaxSupportGrantMinutes = 480

// Audit actions of the grants: the tenant's trail (tenant transaction) and the platform's (tenant_id NULL).
const (
	ActionSupportGrantRequest    = "support_grant.request"
	ActionSupportGrantApprove    = "support_grant.approve"
	ActionSupportGrantReject     = "support_grant.reject"
	ActionSupportGrantRevoke     = "support_grant.revoke"
	ActionSupportGrantBreakGlass = "support_grant.breakglass"
	ActionSupportGrantExpire     = "support_grant.expire"

	ActionPlatformSupportGrantRequest    = "platform.support_grant.request"
	ActionPlatformSupportGrantBreakGlass = "platform.support_grant.breakglass"
	ActionPlatformSupportGrantRevoke     = "platform.support_grant.revoke"
	ActionPlatformSupportGrantExpire     = "platform.support_grant.expire"

	// SecurityKindBreakGlass is the security_event of a break-glass approval (§8.7 step 2 "security_event mức cao").
	SecurityKindBreakGlass = "support.break_glass"

	// CreateSupportGrantOperation is the operationId of POST /platform/support-grants (its Idempotency-Key scope).
	CreateSupportGrantOperation = "createSupportGrant"
)

// Job grant.expire (§13.5): kind, cadence and batch.
const (
	GrantExpireKind     = "grant.expire"
	GrantExpireInterval = time.Minute
	grantExpireBatch    = 500
)

// Refusal reasons of the grants (AdminError.Reason).
const (
	ReasonGrantClosed          = "grant_closed"                  // decided, terminal, or its window is over (409)
	ReasonGrantOpen            = "support_grant_open"            // the requester already holds an open grant on the tenant (409)
	ReasonGrantTenantClosed    = "tenant_not_open"               // the tenant is not active/suspended (409)
	ReasonAdminBreakGlassOnly  = "support_admin_breakglass_only" // a tenant cannot grant support_admin (403)
	ReasonBreakGlassSelf       = "breakglass_self"               // the second Super Admin is the requester/grantee (403)
	ReasonBreakGlassRequester  = "breakglass_requester"          // the requester is not an active Super Admin (409)
	ReasonDeciderNotAllowed    = "decider_not_allowed"           // the trigger refused the decider (403)
	ReasonNotPlatformUser      = "not_platform_user"             // the caller is no active platform user (403)
	reasonInvalidCursor        = "invalid_cursor"
	reasonIdempotencyInvalid   = "invalid_idempotency_key"
	reasonIdempotencyInProcess = "idempotency_in_progress"
)

var (
	// ErrForbidden: the operation refuses this caller for this grant (403).
	ErrForbidden = errors.New("tenants: forbidden")
)

// StaffActor is the platform staff member calling a platform operation on grants.
type StaffActor struct {
	IdentityID uuid.UUID
	AuthTime   time.Time
}

// SupportGrant is schema SupportGrant. Status is the effective status; DecidedBy is the name the caller's side may see.
type SupportGrant struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	TenantSlug   string
	Role         string
	Reason       string
	TicketRef    string
	Status       string
	Active       bool
	ApprovalKind string
	Grantee      string
	DecidedBy    string
	DecidedAt    *time.Time
	StartsAt     time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time

	granteeID     uuid.UUID
	requestedByID uuid.UUID
	rawStatus     string
}

// SupportGrantPage is one page of a list; NextCursor is "" on the last one.
type SupportGrantPage struct {
	Items      []SupportGrant
	NextCursor string
}

// SupportGrantFilter selects a page.
type SupportGrantFilter struct {
	Limit  int
	Cursor string
	Status string // effective status; "" = all
}

// SupportGrantCreate is schema SupportGrantCreate.
type SupportGrantCreate struct {
	TenantID        uuid.UUID
	Role            string
	Reason          string
	TicketRef       string
	DurationMinutes int
}

// SupportIdempotency is the Idempotency-Key of POST /platform/support-grants.
type SupportIdempotency struct {
	Key  string
	Hash []byte
}

// grantRow is the column set shared by the four view queries (identical structs, converted).
type grantRow struct {
	ID                        uuid.UUID
	TenantID                  uuid.UUID
	TenantSlug                string
	GranteePlatformUserID     uuid.UUID
	RequestedByPlatformUserID uuid.UUID
	EffectiveRoleKey          string
	Reason                    string
	TicketRef                 string
	ApprovalKind              *string
	DecidedAt                 *time.Time
	StartsAt                  time.Time
	ExpiresAt                 time.Time
	RevokedAt                 *time.Time
	Status                    string
	CreatedAt                 time.Time
	GranteeDisplay            string
	Active                    bool
	WindowClosed              bool
	DecidedByDisplay          string
}

func grantOf(r grantRow) SupportGrant {
	g := SupportGrant{ID: r.ID, TenantID: r.TenantID, TenantSlug: r.TenantSlug, Role: r.EffectiveRoleKey,
		Reason: r.Reason, TicketRef: r.TicketRef, Status: r.Status, Active: r.Active, Grantee: r.GranteeDisplay,
		DecidedBy: r.DecidedByDisplay, StartsAt: r.StartsAt.UTC(), ExpiresAt: r.ExpiresAt.UTC(),
		CreatedAt: r.CreatedAt.UTC(), granteeID: r.GranteePlatformUserID, requestedByID: r.RequestedByPlatformUserID,
		rawStatus: r.Status}
	if r.ApprovalKind != nil {
		g.ApprovalKind = *r.ApprovalKind
	}
	if r.DecidedAt != nil {
		t := r.DecidedAt.UTC()
		g.DecidedAt = &t
	}
	if r.RevokedAt != nil {
		t := r.RevokedAt.UTC()
		g.RevokedAt = &t
	}
	if (r.Status == GrantPending || r.Status == GrantApproved) && r.WindowClosed {
		g.Status = GrantExpired // the effective status: the window decides, not the job
	}
	if g.Grantee == "" {
		g.Grantee = r.GranteePlatformUserID.String()
	}
	return g
}

// open reports whether a decision or a revocation may still change the grant.
func (g SupportGrant) open() bool { return g.rawStatus == GrantPending || g.rawStatus == GrantApproved }

// ---------------------------------------------------------------------------------------------------- lists

func grantPageParams(f SupportGrantFilter) (limit int, at *time.Time, id *uuid.UUID, status *string, err error) {
	switch {
	case f.Limit == 0:
		limit = 50
	case f.Limit < 1 || f.Limit > 200:
		return 0, nil, nil, nil, adminInvalid("limit", "invalid_limit")
	default:
		limit = f.Limit
	}
	switch f.Status {
	case "":
	case GrantPending, GrantApproved, GrantRejected, GrantRevoked, GrantExpired:
		s := f.Status
		status = &s
	default:
		return 0, nil, nil, nil, adminInvalid("status", "invalid_status")
	}
	if f.Cursor != "" {
		b, derr := base64.RawURLEncoding.Strict().DecodeString(f.Cursor)
		if derr != nil || len(b) != 25 || b[0] != 1 {
			return 0, nil, nil, nil, adminInvalid("cursor", reasonInvalidCursor)
		}
		micros := binary.BigEndian.Uint64(b[1:9])
		u, uerr := uuid.FromBytes(b[9:])
		if micros > 1<<62 || uerr != nil {
			return 0, nil, nil, nil, adminInvalid("cursor", reasonInvalidCursor)
		}
		t := time.UnixMicro(int64(micros)).UTC() //nolint:gosec // bounded above
		at, id = &t, &u
	}
	return limit, at, id, status, nil
}

func grantCursor(t time.Time, id uuid.UUID) string {
	b := make([]byte, 0, 25)
	b = append(b, 1)
	b = binary.BigEndian.AppendUint64(b, uint64(t.UnixMicro())) //nolint:gosec // after 1970
	b = append(b, id[:]...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func grantPage(rows []grantRow, limit int) SupportGrantPage {
	p := SupportGrantPage{Items: make([]SupportGrant, 0, min(len(rows), limit))}
	for i, r := range rows {
		if i == limit {
			last := rows[i-1]
			p.NextCursor = grantCursor(last.CreatedAt, last.ID)
			break
		}
		p.Items = append(p.Items, grantOf(r))
	}
	return p
}

// ListTenantSupportGrants is GET /tenants/{t}/support-grants (tenant pool: RLS shows the grants into this tenant only).
func (s *Service) ListTenantSupportGrants(ctx context.Context, tenantID uuid.UUID, f SupportGrantFilter) (SupportGrantPage, error) {
	limit, at, id, status, err := grantPageParams(f)
	if err != nil {
		return SupportGrantPage{}, err
	}
	var rows []grantRow
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rs, err := q.ListTenantSupportGrants(ctx, sqlcdb.ListTenantSupportGrantsParams{TenantID: tenantID, BeforeAt: at,
			BeforeID: id, Status: status, RowLimit: int32(limit + 1)}) //nolint:gosec // ≤ 201
		for _, r := range rs {
			rows = append(rows, grantRow(r))
		}
		return err
	})
	if err != nil {
		return SupportGrantPage{}, err
	}
	return grantPage(rows, limit), nil
}

// ListPlatformSupportGrants is GET /platform/support-grants (every tenant; metadata only).
func (s *Service) ListPlatformSupportGrants(ctx context.Context, f SupportGrantFilter) (SupportGrantPage, error) {
	limit, at, id, status, err := grantPageParams(f)
	if err != nil {
		return SupportGrantPage{}, err
	}
	var rows []grantRow
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rs, err := q.ListPlatformSupportGrants(ctx, sqlcdb.ListPlatformSupportGrantsParams{BeforeAt: at, BeforeID: id,
			Status: status, RowLimit: int32(limit + 1)}) //nolint:gosec // ≤ 201
		for _, r := range rs {
			rows = append(rows, grantRow(r))
		}
		return err
	})
	if err != nil {
		return SupportGrantPage{}, err
	}
	return grantPage(rows, limit), nil
}

// ---------------------------------------------------------------------------------------------------- request

func validGrantText(s string, maxRunes int) bool {
	return strings.TrimSpace(s) != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= maxRunes &&
		!strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}

func (s *Service) staffStepUp(a StaffActor) error {
	return s.stepUp(Actor{AuthTime: a.AuthTime})
}

// RequestSupportGrant is POST /platform/support-grants.
func (s *Service) RequestSupportGrant(ctx context.Context, a StaffActor, in SupportGrantCreate, idem *SupportIdempotency) (SupportGrant, error) {
	in.Reason, in.TicketRef = strings.TrimSpace(in.Reason), strings.TrimSpace(in.TicketRef)
	switch {
	case in.TenantID == uuid.Nil:
		return SupportGrant{}, adminInvalid("tenant_id", "invalid_tenant")
	case in.Role != SupportOperator && in.Role != SupportAdmin:
		return SupportGrant{}, adminInvalid("effective_role", "invalid_role") // never a tenant role (Owner…)
	case !validGrantText(in.Reason, 1000):
		return SupportGrant{}, adminInvalid("reason", "invalid_reason")
	case !validGrantText(in.TicketRef, 200) || strings.ContainsAny(in.TicketRef, "\n\t"):
		return SupportGrant{}, adminInvalid("ticket_ref", "invalid_ticket_ref")
	case in.DurationMinutes < 1 || in.DurationMinutes > MaxSupportGrantMinutes:
		return SupportGrant{}, adminInvalid("duration_minutes", "invalid_duration")
	}
	if err := s.staffStepUp(a); err != nil {
		return SupportGrant{}, err
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: a.IdentityID, OperationID: CreateSupportGrantOperation, Key: idem.Key}
		var replay *SupportGrant
		err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, 30*time.Second)
			if errors.Is(err, jobs.ErrInvalidIdempotencyKey) {
				return adminInvalid("Idempotency-Key", reasonIdempotencyInvalid)
			}
			if err != nil {
				return err
			}
			switch d.Outcome {
			case jobs.IdempotencyReplay:
				var id uuid.UUID
				if d.Response == nil || json.Unmarshal(d.Response.Body, &id) != nil {
					return errors.New("tenants: stored support grant response unreadable")
				}
				r, err := q.GetPlatformSupportGrant(ctx, id)
				if err != nil {
					return err
				}
				g := grantOf(grantRow(r))
				replay = &g
				return nil
			case jobs.IdempotencyInProgress:
				return &AdminError{Kind: ErrIdempotencyInProgress, Reason: reasonIdempotencyInProcess}
			case jobs.IdempotencyKeyReuse:
				return adminRefuse(ErrIdempotencyKeyReuse, "idempotency_key_reuse")
			}
			return nil
		})
		if err != nil {
			return SupportGrant{}, err
		}
		if replay != nil {
			return *replay, nil
		}
	}
	var out SupportGrant
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		me, err := q.GetSupportGrantRequester(ctx, a.IdentityID)
		if errors.Is(err, store.ErrNoRows) || (err == nil && (me.Status != "active" || me.IdentityStatus != "active")) {
			return adminRefuse(ErrForbidden, ReasonNotPlatformUser)
		}
		if err != nil {
			return err
		}
		t, err := q.GetSupportGrantTarget(ctx, in.TenantID)
		if errors.Is(err, store.ErrNoRows) || (err == nil && t.Status == "deleted") {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if t.Status != "active" && t.Status != "suspended" {
			return adminRefuse(ErrConflict, ReasonGrantTenantClosed)
		}
		n, err := q.CountGranteeOpenSupportGrants(ctx, sqlcdb.CountGranteeOpenSupportGrantsParams{Grantee: me.ID,
			TenantID: in.TenantID})
		if err != nil {
			return err
		}
		if n > 0 {
			return adminRefuse(ErrConflict, ReasonGrantOpen)
		}
		display := me.Display
		if utf8.RuneCountInString(display) > 200 {
			display = string([]rune(display)[:200])
		}
		id, err := q.InsertSupportGrant(ctx, sqlcdb.InsertSupportGrantParams{TenantID: in.TenantID, Grantee: me.ID,
			EffectiveRoleKey: in.Role, Reason: in.Reason, TicketRef: in.TicketRef,
			DurationMinutes: int32(in.DurationMinutes), GranteeDisplay: display}) //nolint:gosec // 1–480
		if err != nil {
			return err
		}
		r, err := q.GetPlatformSupportGrant(ctx, id)
		if err != nil {
			return err
		}
		out = grantOf(grantRow(r))
		if err := audit.Record(ctx, q, audit.Event{Action: ActionPlatformSupportGrantRequest, ResourceType: "support_grant",
			ResourceID: id.String(), SupportGrantID: &id, Details: audit.Details{"tenant_id": in.TenantID,
				"tenant_slug": t.Slug, "effective_role": in.Role, "ticket_ref": in.TicketRef, "reason": in.Reason,
				"duration_minutes": in.DurationMinutes, "expires_at": out.ExpiresAt}}); err != nil {
			return err
		}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(id)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body,
			Resource: &jobs.Resource{Type: "support_grant", ID: id.String()}})
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
			})
		}
		return SupportGrant{}, err
	}
	// the tenant's trail + the deciders' notification (transparency, §8.7 step 3)
	tid, gid := out.TenantID, out.ID
	err = s.st.WithTenantJobTx(audit.WithoutTenant(ctx), tid, func(tx *store.Tx) error {
		if err := audit.Record(ctx, tx.Q, audit.Event{Action: ActionSupportGrantRequest, TenantID: &tid,
			ResourceType: "support_grant", ResourceID: gid.String(), SupportGrantID: &gid, Details: audit.Details{
				"grantee": out.Grantee, "effective_role": out.Role, "ticket_ref": out.TicketRef, "reason": out.Reason,
				"expires_at": out.ExpiresAt}}); err != nil {
			return err
		}
		_, err := notifications.Enqueue(ctx, tx, notifications.SupportGrantRequested(tid, gid, out.Grantee, out.Reason,
			out.ExpiresAt))
		return err
	})
	if err != nil {
		return SupportGrant{}, fmt.Errorf("tenants: record the support grant request in the tenant: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------- tenant decisions

// loadTenantGrant locks and reads a grant into tenantID (tenant pool) — another tenant's grant is not found.
func loadTenantGrant(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID) (SupportGrant, error) {
	if _, err := q.LockTenantSupportGrant(ctx, sqlcdb.LockTenantSupportGrantParams{TenantID: tenantID, ID: id}); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return SupportGrant{}, ErrNotFound
		}
		return SupportGrant{}, err
	}
	r, err := q.GetTenantSupportGrant(ctx, sqlcdb.GetTenantSupportGrantParams{TenantID: tenantID, ID: id})
	if err != nil {
		return SupportGrant{}, err
	}
	return grantOf(grantRow(r)), nil
}

func reloadTenantGrant(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID) (SupportGrant, error) {
	r, err := q.GetTenantSupportGrant(ctx, sqlcdb.GetTenantSupportGrantParams{TenantID: tenantID, ID: id})
	if err != nil {
		return SupportGrant{}, err
	}
	return grantOf(grantRow(r)), nil
}

// guardError maps a refusal of the trigger mg_support_grant_guard.
func guardError(err error) error {
	switch store.SQLState(err) {
	case "42501":
		return adminRefuse(ErrForbidden, ReasonDeciderNotAllowed)
	case "23514":
		return adminRefuse(ErrConflict, ReasonGrantClosed)
	}
	return err
}

// DecideTenantSupportGrant is POST /tenants/{t}/support-grants/{id}/approve (approve = true; step-up; ceiling
// support_operator) or /reject.
func (s *Service) DecideTenantSupportGrant(ctx context.Context, a Actor, tenantID, id uuid.UUID, approve bool) (SupportGrant, error) {
	status, action := GrantRejected, ActionSupportGrantReject
	if approve {
		status, action = GrantApproved, ActionSupportGrantApprove
	}
	var out SupportGrant
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		g, err := loadTenantGrant(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if g.rawStatus != GrantPending || g.Status == GrantExpired {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		if approve {
			if g.Role != SupportOperator { // "Admin chỉ qua break-glass" (§8.6 column Staff)
				return adminRefuse(ErrForbidden, ReasonAdminBreakGlassOnly)
			}
			if err := s.stepUp(a); err != nil {
				return err
			}
		}
		n, err := q.DecideTenantSupportGrant(ctx, sqlcdb.DecideTenantSupportGrantParams{Status: status,
			MembershipID: &a.MembershipID, TenantID: tenantID, ID: id})
		if err != nil {
			return guardError(err)
		}
		if n == 0 {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		if out, err = reloadTenantGrant(ctx, q, tenantID, id); err != nil {
			return err
		}
		return audit.Record(ctx, q, audit.Event{Action: action, ResourceType: "support_grant", ResourceID: id.String(),
			SupportGrantID: &id, Details: audit.Details{"grantee": out.Grantee, "effective_role": out.Role,
				"ticket_ref": out.TicketRef, "expires_at": out.ExpiresAt, "decided_by_membership_id": a.MembershipID}})
	})
	if err != nil {
		return SupportGrant{}, err
	}
	return out, nil
}

// RevokeTenantSupportGrant is POST /tenants/{t}/support-grants/{id}/revoke (pending or approved — break-glass included).
func (s *Service) RevokeTenantSupportGrant(ctx context.Context, a Actor, tenantID, id uuid.UUID) (SupportGrant, error) {
	var out SupportGrant
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		g, err := loadTenantGrant(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if !g.open() {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		n, err := q.RevokeTenantSupportGrant(ctx, sqlcdb.RevokeTenantSupportGrantParams{TenantID: tenantID, ID: id})
		if err != nil {
			return guardError(err)
		}
		if n == 0 {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		if out, err = reloadTenantGrant(ctx, q, tenantID, id); err != nil {
			return err
		}
		return audit.Record(ctx, q, audit.Event{Action: ActionSupportGrantRevoke, ResourceType: "support_grant",
			ResourceID: id.String(), SupportGrantID: &id, Details: audit.Details{"grantee": out.Grantee,
				"status_before": g.Status, "revoked_by": "tenant", "revoked_by_membership_id": a.MembershipID}})
	})
	if err != nil {
		return SupportGrant{}, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------- platform decisions

func loadPlatformGrant(ctx context.Context, q *sqlcdb.Queries, id uuid.UUID) (SupportGrant, error) {
	if _, err := q.LockPlatformSupportGrant(ctx, id); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return SupportGrant{}, ErrNotFound
		}
		return SupportGrant{}, err
	}
	r, err := q.GetPlatformSupportGrant(ctx, id)
	if err != nil {
		return SupportGrant{}, err
	}
	return grantOf(grantRow(r)), nil
}

// ApproveBreakGlass is POST /platform/support-grants/{id}/approve-breakglass — the second Super Admin (§8.7 step 2).
func (s *Service) ApproveBreakGlass(ctx context.Context, a StaffActor, id uuid.UUID) (SupportGrant, error) {
	var out SupportGrant
	var approver string
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		g, err := loadPlatformGrant(ctx, q, id)
		if err != nil {
			return err
		}
		me, err := q.GetSupportGrantRequester(ctx, a.IdentityID)
		if errors.Is(err, store.ErrNoRows) {
			return adminRefuse(ErrForbidden, ReasonNotPlatformUser)
		}
		if err != nil {
			return err
		}
		if me.ID == g.requestedByID || me.ID == g.granteeID { // the dual control: a second person
			return adminRefuse(ErrForbidden, ReasonBreakGlassSelf)
		}
		if g.rawStatus != GrantPending || g.Status == GrantExpired {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		if err := s.staffStepUp(a); err != nil {
			return err
		}
		n, err := q.ApproveSupportGrantBreakglass(ctx, sqlcdb.ApproveSupportGrantBreakglassParams{Approver: &me.ID, ID: id})
		if store.SQLState(err) == "42501" { // the caller is a Super Admin (layer 1) — the requester is not
			return adminRefuse(ErrConflict, ReasonBreakGlassRequester)
		}
		if err != nil {
			return guardError(err)
		}
		if n == 0 {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		r, err := q.GetPlatformSupportGrant(ctx, id)
		if err != nil {
			return err
		}
		out, approver = grantOf(grantRow(r)), me.Display
		return audit.Record(ctx, q, audit.Event{Action: ActionPlatformSupportGrantBreakGlass, ResourceType: "support_grant",
			ResourceID: id.String(), SupportGrantID: &id, Details: audit.Details{"tenant_id": out.TenantID,
				"tenant_slug": out.TenantSlug, "grantee": out.Grantee, "effective_role": out.Role,
				"ticket_ref": out.TicketRef, "expires_at": out.ExpiresAt, "requested_by_platform_user_id": g.requestedByID,
				"approved_by_platform_user_id": me.ID}})
	})
	if err != nil {
		return SupportGrant{}, err
	}
	tid := out.TenantID
	err = s.st.WithTenantJobTx(audit.WithoutTenant(ctx), tid, func(tx *store.Tx) error {
		if err := audit.Record(ctx, tx.Q, audit.Event{Action: ActionSupportGrantBreakGlass, TenantID: &tid,
			ResourceType: "support_grant", ResourceID: id.String(), SupportGrantID: &id, Details: audit.Details{
				"grantee": out.Grantee, "approver": approver, "effective_role": out.Role, "ticket_ref": out.TicketRef,
				"reason": out.Reason, "expires_at": out.ExpiresAt}}); err != nil {
			return err
		}
		if _, err := audit.RecordSecurityEvent(ctx, tx.Q, audit.SecurityEvent{TenantID: &tid, Kind: SecurityKindBreakGlass,
			Severity: audit.SeverityHigh, Source: "support", Details: audit.Details{"grant_id": id,
				"grantee": out.Grantee, "approver": approver, "effective_role": out.Role, "ticket_ref": out.TicketRef,
				"expires_at": out.ExpiresAt}}); err != nil {
			return err
		}
		_, err := notifications.Enqueue(ctx, tx, notifications.BreakGlass(tid, id, out.Grantee, approver, out.Reason,
			out.ExpiresAt))
		return err
	})
	if err != nil {
		return SupportGrant{}, fmt.Errorf("tenants: record the break-glass in the tenant: %w", err)
	}
	return out, nil
}

// RevokePlatformSupportGrant is POST /platform/support-grants/{id}/revoke (Super Admin, any grant).
func (s *Service) RevokePlatformSupportGrant(ctx context.Context, a StaffActor, id uuid.UUID) (SupportGrant, error) {
	var out SupportGrant
	var before string
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		g, err := loadPlatformGrant(ctx, q, id)
		if err != nil {
			return err
		}
		if !g.open() {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		before = g.Status
		n, err := q.RevokePlatformSupportGrant(ctx, id)
		if err != nil {
			return guardError(err)
		}
		if n == 0 {
			return adminRefuse(ErrConflict, ReasonGrantClosed)
		}
		r, err := q.GetPlatformSupportGrant(ctx, id)
		if err != nil {
			return err
		}
		out = grantOf(grantRow(r))
		return audit.Record(ctx, q, audit.Event{Action: ActionPlatformSupportGrantRevoke, ResourceType: "support_grant",
			ResourceID: id.String(), SupportGrantID: &id, Details: audit.Details{"tenant_id": out.TenantID,
				"tenant_slug": out.TenantSlug, "grantee": out.Grantee, "status_before": before}})
	})
	if err != nil {
		return SupportGrant{}, err
	}
	tid := out.TenantID
	err = s.st.WithTenantTx(audit.WithoutTenant(ctx), tid, func(q *sqlcdb.Queries) error {
		return audit.Record(ctx, q, audit.Event{Action: ActionSupportGrantRevoke, TenantID: &tid, ResourceType: "support_grant",
			ResourceID: id.String(), SupportGrantID: &id, Details: audit.Details{"grantee": out.Grantee,
				"status_before": before, "revoked_by": "platform"}})
	})
	if err != nil {
		return SupportGrant{}, fmt.Errorf("tenants: record the revocation in the tenant: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------- grant.expire

// ExpireSupportGrants is the job grant.expire (§13.5; worker, platform pool): the grants still pending or approved past
// their window become expired — a system event on the platform trail and on each tenant's trail. Access never
// depended on it (the window is checked on every request); it keeps the status truthful for the lists.
func (s *Service) ExpireSupportGrants(ctx context.Context, log *slog.Logger) (int, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx = audit.WithRequest(ctx, nil)
	total := 0
	for {
		var rows []sqlcdb.ExpireSupportGrantsRow
		err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			var err error
			if rows, err = q.ExpireSupportGrants(ctx, grantExpireBatch); err != nil {
				return err
			}
			for _, r := range rows {
				gid := r.ID
				if err := audit.Record(ctx, q, audit.Event{Action: ActionPlatformSupportGrantExpire,
					ActorType: audit.ActorSystem, ActorDisplay: GrantExpireKind, ResourceType: "support_grant",
					ResourceID: gid.String(), SupportGrantID: &gid, Details: audit.Details{"tenant_id": r.TenantID,
						"effective_role": r.EffectiveRoleKey, "expires_at": r.ExpiresAt}}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return total, fmt.Errorf("tenants: expire support grants: %w", err)
		}
		for _, r := range rows {
			tid, gid := r.TenantID, r.ID
			if err := s.st.WithTenantTx(ctx, tid, func(q *sqlcdb.Queries) error {
				return audit.Record(ctx, q, audit.Event{Action: ActionSupportGrantExpire, TenantID: &tid,
					ActorType: audit.ActorSystem, ActorDisplay: GrantExpireKind, ResourceType: "support_grant",
					ResourceID: gid.String(), SupportGrantID: &gid, Details: audit.Details{
						"effective_role": r.EffectiveRoleKey, "expires_at": r.ExpiresAt}})
			}); err != nil {
				// the status is already expired (the platform trail has it); a missing tenant copy is logged, not retried
				log.WarnContext(ctx, "support grant expiry not recorded in the tenant", "grant_id", gid.String(),
					"error", err.Error())
			}
		}
		total += len(rows)
		if len(rows) < grantExpireBatch {
			return total, nil
		}
	}
}
