package members

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Tenant role keys the operations distinguish (roles.key of the seed, §8.4).
const (
	RoleOwner    = "tenant_owner"
	RoleAdmin    = "tenant_admin"
	RoleOperator = "tenant_operator"
	RoleViewer   = "tenant_viewer"
	RoleEndUser  = "end_user"
)

// RolesBelowAdmin are the roles PUT /users/{id}/role gives and takes (tenant.membership:assign, §8.6); a change that
// gives or takes Tenant Admin, or demotes an Owner, is PUT /users/{id}/admin-role (tenant.membership:assign_admin).
var RolesBelowAdmin = []string{RoleOperator, RoleViewer, RoleEndUser}

// Job kinds of the module (§13.5).
const (
	KindOffboard  = "member.offboard"
	KindIdPInvite = "member.idp_invite"
	// KindPolicyApply is the level-triggered policy.apply of the policy engine (internal/policies registers its
	// handler): members only enqueues it, with input {"trigger": "group_change"} (§13.6: members never imports policies).
	KindPolicyApply = "policy.apply"
	// TriggerGroupChange is policy_applications.trigger of an application caused by a group change (§7.3).
	TriggerGroupChange = "group_change"
)

// Audit actions (x-audit-action of api/openapi.yaml, and the events of the jobs).
const (
	ActionUserUpdate         = "user.update"
	ActionUserRole           = "user.role.set"
	ActionUserAdminRole      = "user.admin_role.set"
	ActionOwnershipTransfer  = "tenant.ownership.transfer"
	ActionUserSessionsRevoke = "user.sessions.revoke"
	ActionUserOffboard       = "user.offboard" // paired: .requested (api) → .succeeded / .failed (job member.offboard)
	ActionGroupCreate        = "group.create"
	ActionGroupUpdate        = "group.update"
	ActionGroupDelete        = "group.delete"
	ActionGroupMembers       = "group.members.set"
	ActionInvitationIdPUser  = "invitation.idp_user"
)

// ApprovalAction is approval_requests.action of a change of a sensitive group's members (§7.3, §8.6).
const ApprovalAction = "tenant.group.set_members"

// Errors. Every refusal of the service is an *Error whose Kind is one of these; a refusal of the membership rules is
// the *authz.Denial returned by the Guard, as it is.
var (
	ErrNotFound               = errors.New("members: not found")                   // 404 (also another tenant's object)
	ErrInvalid                = errors.New("members: invalid request")             // 422
	ErrConflict               = errors.New("members: conflict")                    // 409
	ErrPreconditionFailed     = errors.New("members: stale If-Match")              // 412
	ErrPreconditionRequired   = errors.New("members: If-Match required")           // 428
	ErrReauthRequired         = errors.New("members: step-up required")            // 401 reauth_required
	ErrIdempotencyInProgress  = errors.New("members: Idempotency-Key in progress") // 409 + Retry-After
	ErrIdempotencyKeyReuse    = errors.New("members: Idempotency-Key reused")      // 422 idempotency_key_reuse
	errApprovalPayloadInvalid = errors.New("members: approval payload names another group")
)

// Error is a refusal: Kind (errors.Is through Unwrap), a stable Reason for audit and logs, the Field of a 422.
type Error struct {
	Kind       error
	Reason     string
	Field      string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return "members: " + e.Kind.Error() + " (" + e.Reason + ")" }
func (e *Error) Unwrap() error { return e.Kind }

func refuse(kind error, reason string) *Error { return &Error{Kind: kind, Reason: reason} }

func invalid(field, reason string) *Error {
	return &Error{Kind: ErrInvalid, Reason: reason, Field: field}
}

// Refusal reasons.
const (
	ReasonNotFound            = "membership_not_found"
	ReasonGroupNotFound       = "group_not_found"
	ReasonOffboarded          = "membership_offboarded"
	ReasonStale               = "if_match_stale"
	ReasonIfMatchMissing      = "if_match_required"
	ReasonStepUp              = "step_up_required"
	ReasonUseAdminRole        = "admin_role_operation"
	ReasonUseRole             = "role_operation"
	ReasonOwnerRole           = "ownership_transfer_only"
	ReasonGroupNameTaken      = "group_name_taken"
	ReasonGroupInUse          = "group_in_use"
	ReasonSensitiveNotEmpty   = "sensitive_group_has_members"
	ReasonMemberNotActive     = "member_not_active"
	ReasonTooManyMembers      = "too_many_members"
	ReasonApprovalNotExecuted = "approval_payload_stale"
)

// Change is one membership change checked by the Guard (authz.MembershipChange).
type Change struct {
	Actor             uuid.UUID // the caller's membership (authz.Decision.MembershipID)
	Target            uuid.UUID
	NewRole           string // "" keeps the role
	Deactivate        bool   // lock or offboard
	OwnershipTransfer bool
}

// Guard checks a change inside the transaction that writes it: authz.GuardMembershipChange, wired in apps/* (members
// does not import authz — §13.6). Its refusals (*authz.Denial) are returned as they are.
type Guard func(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, c Change) error

// Actor is the caller: its identity and session (auth_time — step-up, §8.3 step 7) and its membership in the tenant
// of the path (authz.Decision.MembershipID).
type Actor struct {
	IdentityID   uuid.UUID
	MembershipID uuid.UUID
	Display      string
	ClientIP     netip.Addr
	AuthTime     time.Time
}

// StepUpWindow is the freshness of auth_time the sensitive operations require (§8.3 step 7).
const StepUpWindow = 15 * time.Minute

const clockSkew = 2 * time.Minute

// Config are the collaborators of a Service. Store and Tenants are required; Guard for the api's write operations;
// Headscale and IdP for the worker's jobs.
type Config struct {
	Tenants   *tenants.Service
	Guard     Guard
	Headscale headscale.Registry // worker: member.offboard
	IdP       *idp.Registry      // worker: member.offboard, member.idp_invite
	Logger    *slog.Logger
	Now       func() time.Time
}

// Service is the members module.
type Service struct {
	st      *store.Store
	tenants *tenants.Service
	guard   Guard
	hs      headscale.Registry
	idps    *idp.Registry
	log     *slog.Logger
	now     func() time.Time
}

// New returns the module on the process's store.
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Tenants == nil {
		return nil, errors.New("members: a store and the tenants service are required")
	}
	s := &Service{st: st, tenants: cfg.Tenants, guard: cfg.Guard, hs: cfg.Headscale, idps: cfg.IdP, log: cfg.Logger,
		now: cfg.Now}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// ETag is the strong ETag of a version (§6.1) — the same form as GET /users/{id} and GET /groups/{id}.
func ETag(version int64) string { return strconv.Quote(strconv.FormatInt(version, 10)) }

// checkIfMatch compares If-Match with the current version: missing ⇒ 428, other ⇒ 412.
func checkIfMatch(ifMatch string, version int64) error {
	switch {
	case ifMatch == "":
		return refuse(ErrPreconditionRequired, ReasonIfMatchMissing)
	case ifMatch != ETag(version) && ifMatch != "W/"+ETag(version):
		return refuse(ErrPreconditionFailed, ReasonStale)
	}
	return nil
}

// stepUp is the step-up of §8.3 step 7 on the caller's session.
func (s *Service) stepUp(a Actor) error {
	now := s.now()
	if a.AuthTime.IsZero() || now.Sub(a.AuthTime) > StepUpWindow || a.AuthTime.After(now.Add(clockSkew)) {
		return refuse(ErrReauthRequired, ReasonStepUp)
	}
	return nil
}

func (s *Service) requireGuard() error {
	if s.guard == nil {
		return errors.New("members: no membership guard (authz.GuardMembershipChange)")
	}
	return nil
}

// member reads the view of a membership after a change (the response of the write operations).
func (s *Service) member(ctx context.Context, tenantID, id uuid.UUID) (tenants.Member, error) {
	m, err := s.tenants.GetMember(ctx, tenantID, id)
	if errors.Is(err, tenants.ErrNotFound) {
		return m, refuse(ErrNotFound, ReasonNotFound)
	}
	return m, err
}

func ptr[T any](v T) *T { return &v }
