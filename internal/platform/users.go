package platform

// Platform users (P4-T03a; §8.2 "Thêm nhân sự nền tảng về sau", §8.4 invariant 3, §8.5 platform.user:*):
//
//	GET    /platform/users[/{id}]                 platform.user:read
//	POST   /platform/users                        platform.user:assign (SA: excludes_super_admin) — step-up
//	PATCH  /platform/users/{id}                   platform.user:assign (SA: excludes_super_admin) — step-up, If-Match
//	DELETE /platform/users/{id}                   platform.user:assign (SA: excludes_super_admin) — step-up, If-Match
//	PUT    /platform/users/{id}/super-admin-role  platform.user:assign_super_admin — always 2P (SuperAdminRequest →
//	                                              approval platform.user.super_admin → ExecuteSuperAdmin)
//
// excludes_super_admin (the Super Admin's grant of platform.user:assign) means: the role given is never super_admin
// (the API schema has no such value, and the service refuses it), and a platform user that holds super_admin is never
// the target (403) — its role changes only through the 2P operation. Nobody changes their own platform user (no
// self-escalation, no self-lockout). A role change or a disabling revokes every session of the person in the same
// transaction (§8.3 step 8). The 2P execution takes the advisory lock of `meshguard admin bootstrap-super-admin`
// (P2-T11a) and never leaves zero active Super Admins.

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Platform role keys (§8.4; seeded by database/seeds/rbac.sql).
const (
	RoleSuperAdmin       = "super_admin"
	RolePlatformOperator = "platform_operator"
	RolePlatformSupport  = "platform_support"
	RolePlatformViewer   = "platform_viewer"
)

// AssignableRoles are the platform roles platform.user:assign gives (never super_admin — §8.5).
var AssignableRoles = []string{RolePlatformOperator, RolePlatformSupport, RolePlatformViewer}

// PlatformRoles are every platform role.
var PlatformRoles = []string{RoleSuperAdmin, RolePlatformOperator, RolePlatformSupport, RolePlatformViewer}

// Platform user statuses (CHECK platform_users_status_check of 0025).
const (
	UserActive   = "active"
	UserDisabled = "disabled"
)

// UserStatuses is the value set of platform_users.status.
var UserStatuses = []string{UserActive, UserDisabled}

// Audit actions (x-audit-action of the operations; the 2P execution has its own).
const (
	ActionUserCreate          = "platform.user.create"
	ActionUserUpdate          = "platform.user.update"
	ActionUserDelete          = "platform.user.delete"
	ActionSuperAdminExecute   = "platform.user.super_admin.execute"
	CreateUserOperation       = "createPlatformUser"
	SuperAdminAction          = "platform.user.super_admin" // approval_requests.action
	SuperAdminPermission      = "platform.user:assign_super_admin"
	SuperAdminResourceType    = "platform_user"
	CondExcludesSuperAdmin    = "excludes_super_admin"
	CondTenantIdPDualControl  = "tenant_idp_dual_control"
	maxPlatformSubject        = 255
	maxPlatformUserNameLength = 128
)

// PlatformUser is schema PlatformUser.
type PlatformUser struct {
	ID             uuid.UUID
	IdentityID     uuid.UUID
	Subject        string
	DisplayName    string // display name, else e-mail, else the subject
	Email          string
	Role           string
	Status         string
	IdentityStatus string
	LastLoginAt    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Version        int64
	ETag           string
}

// UserFilter holds the query of GET /platform/users.
type UserFilter struct {
	Status string
	Role   string
	Limit  int
	Cursor string
}

// UserPage is one page of platform users.
type UserPage struct {
	Items      []PlatformUser
	NextCursor string
}

func userView(id, identityID uuid.UUID, status, role, subject string, display, email *string, identityStatus string,
	lastLogin *time.Time, created, updated time.Time, version int64) PlatformUser {
	u := PlatformUser{ID: id, IdentityID: identityID, Subject: subject, Email: deref(email), Role: role, Status: status,
		IdentityStatus: identityStatus, LastLoginAt: lastLogin, CreatedAt: created.UTC(), UpdatedAt: updated.UTC(),
		Version: version, ETag: versionETag(version)}
	switch {
	case deref(display) != "":
		u.DisplayName = *display
	case u.Email != "":
		u.DisplayName = u.Email
	default:
		u.DisplayName = subject
	}
	return u
}

func userOf(r sqlcdb.GetPlatformUserViewRow) PlatformUser {
	return userView(r.ID, r.IdentityID, r.Status, r.RoleKey, r.Subject, r.DisplayName, r.Email, r.IdentityStatus,
		r.LastLoginAt, r.CreatedAt, r.UpdatedAt, r.Version)
}

// ListUsers is GET /platform/users (oldest first).
func (s *Service) ListUsers(ctx context.Context, f UserFilter) (UserPage, error) {
	limit, err := pageLimit(f.Limit)
	if err != nil {
		return UserPage{}, err
	}
	if f.Status != "" && !slices.Contains(UserStatuses, f.Status) {
		return UserPage{}, invalid("status", "invalid_status")
	}
	if f.Role != "" && !slices.Contains(PlatformRoles, f.Role) {
		return UserPage{}, invalid("role", "invalid_role")
	}
	after, afterID, err := decodePageCursor(f.Cursor)
	if err != nil {
		return UserPage{}, err
	}
	p := UserPage{Items: []PlatformUser{}}
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListPlatformUsersPage(ctx, sqlcdb.ListPlatformUsersPageParams{Status: optionalString(f.Status),
			RoleKey: optionalString(f.Role), AfterCreatedAt: after, AfterID: afterID,
			RowLimit: int32(limit + 1)}) //nolint:gosec // limit ≤ MaxLimit
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1]
			p.NextCursor = encodePageCursor(last.CreatedAt, last.ID)
		}
		for _, r := range rows {
			p.Items = append(p.Items, userView(r.ID, r.IdentityID, r.Status, r.RoleKey, r.Subject, r.DisplayName, r.Email,
				r.IdentityStatus, r.LastLoginAt, r.CreatedAt, r.UpdatedAt, r.Version))
		}
		return nil
	})
	return p, err
}

// GetUser is GET /platform/users/{id}.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (PlatformUser, error) {
	var out PlatformUser
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetPlatformUserView(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = userOf(r)
		return nil
	})
	return out, err
}

// UserCreate is POST /platform/users.
type UserCreate struct {
	Subject     string
	Role        string
	DisplayName string
}

var keycloakSubjectRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validSubject: the sub of the platform IdP — a lowercase UUID for the platform-hosted Keycloak (the id of the user),
// 1–255 visible ASCII characters otherwise (OIDC Core §2) — the rule of `bootstrap-super-admin` (P2-T11a Q5).
func validSubject(driver, sub string) bool {
	if sub == "" || len(sub) > maxPlatformSubject {
		return false
	}
	if driver == "keycloak" {
		return keycloakSubjectRE.MatchString(sub)
	}
	for i := 0; i < len(sub); i++ {
		if sub[i] <= ' ' || sub[i] > '~' {
			return false
		}
	}
	return true
}

func validDisplayName(s string) bool {
	return s == "" || (utf8.ValidString(s) && utf8.RuneCountInString(s) <= maxPlatformUserNameLength &&
		strings.TrimSpace(s) != "" && !strings.ContainsFunc(s, unicode.IsControl))
}

// CreateUser is POST /platform/users (§8.2): the person's identity of the platform IdP (sub) is created if absent and
// becomes a platform user of the role — never super_admin. Step-up; an identity that already is a platform user ⇒
// 409. With an Idempotency-Key a replay returns the stored answer.
func (s *Service) CreateUser(ctx context.Context, a Actor, in UserCreate, idem *Idempotency) (PlatformUser, error) {
	if err := s.userCondition(a); err != nil {
		return PlatformUser{}, err
	}
	in.Subject, in.DisplayName = strings.TrimSpace(in.Subject), strings.TrimSpace(in.DisplayName)
	switch {
	case !slices.Contains(AssignableRoles, in.Role):
		// excludes_super_admin: the schema has no super_admin; a value that reaches here anyway is refused the same way
		if in.Role == RoleSuperAdmin {
			return PlatformUser{}, &AdminError{Kind: ErrForbidden, Reason: ReasonSuperAdminTarget, Field: "role"}
		}
		return PlatformUser{}, invalid("role", "invalid_role")
	case !validDisplayName(in.DisplayName):
		return PlatformUser{}, invalid("display_name", "invalid_display_name")
	}
	if err := stepUp(a, time.Now()); err != nil {
		return PlatformUser{}, err
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: a.IdentityID, OperationID: CreateUserOperation, Key: idem.Key}
		var replay *PlatformUser
		err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, idempotencyLock)
			if errors.Is(err, jobs.ErrInvalidIdempotencyKey) {
				return invalid("Idempotency-Key", "invalid_idempotency_key")
			}
			if err != nil {
				return err
			}
			switch d.Outcome {
			case jobs.IdempotencyReplay:
				var v PlatformUser
				if d.Response == nil || json.Unmarshal(d.Response.Body, &v) != nil {
					return errors.New("platform: stored platform user response unreadable")
				}
				replay = &v
				return audit.Record(ctx, q, audit.Event{Action: ActionUserCreate, ResourceType: "platform_user",
					ResourceID: v.ID.String(), Details: audit.Details{"replay": true}})
			case jobs.IdempotencyInProgress:
				return &AdminError{Kind: ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
			case jobs.IdempotencyKeyReuse:
				return refuse(ErrIdempotencyKeyReuse, "idempotency_key_reuse")
			}
			return nil
		})
		if err != nil {
			return PlatformUser{}, err
		}
		if replay != nil {
			return *replay, nil
		}
	}
	var out PlatformUser
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		idps, err := q.ListActivePlatformIdPs(ctx)
		if err != nil {
			return err
		}
		if len(idps) != 1 {
			return refuse(ErrConflict, ReasonNoPlatformIdP)
		}
		idp := idps[0]
		if !validSubject(idp.Driver, in.Subject) {
			return invalid("subject", "invalid_subject")
		}
		role, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "platform", Key: in.Role})
		if err != nil {
			return err
		}
		ident, err := q.GetIdentityBySubject(ctx, sqlcdb.GetIdentityBySubjectParams{IdpID: idp.ID, Subject: in.Subject})
		created := false
		switch {
		case errors.Is(err, store.ErrNoRows):
			ident, err = q.InsertSeededIdentity(ctx, sqlcdb.InsertSeededIdentityParams{IdpID: idp.ID, Scope: "platform",
				Subject: in.Subject, DisplayName: optionalString(in.DisplayName)})
			if err != nil {
				return err // a concurrent first login took the (idp, sub) row: the retry finds it
			}
			created = true
		case err != nil:
			return err
		case ident.Status != UserActive:
			return refuse(ErrConflict, ReasonIdentityDisabled)
		}
		by := a.IdentityID
		pu, err := q.InsertPlatformUserCreatedBy(ctx, sqlcdb.InsertPlatformUserCreatedByParams{IdentityID: ident.ID,
			RoleID: role.ID, CreatedBy: &by})
		if store.SQLState(err) == "23505" {
			return refuse(ErrConflict, ReasonAlreadyMember)
		}
		if err != nil {
			return err
		}
		v, err := q.GetPlatformUserView(ctx, pu.ID)
		if err != nil {
			return err
		}
		out = userOf(v)
		if err := audit.Record(ctx, q, audit.Event{Action: ActionUserCreate, ResourceType: "platform_user",
			ResourceID: pu.ID.String(), Details: audit.Details{"identity_id": ident.ID, "idp_id": idp.ID, "role": in.Role,
				"identity_created": created}}); err != nil {
			return err
		}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(out)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body,
			Resource: &jobs.Resource{Type: "platform_user", ID: pu.ID.String()}})
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
			})
		}
		return PlatformUser{}, err
	}
	return out, nil
}

// userCondition: platform.user:assign reaches here unconditional or with excludes_super_admin (the Super Admin's grant)
// — the operation enforces exactly that condition; any other condition is a decision it does not understand.
func (s *Service) userCondition(a Actor) error {
	if a.Condition != "" && a.Condition != CondExcludesSuperAdmin {
		return refuse(ErrForbidden, ReasonConditionMismatch)
	}
	return nil
}

// UserPatch is PATCH /platform/users/{id}; nil = unchanged.
type UserPatch struct {
	Role   *string
	Status *string
}

// UpdateUser is PATCH /platform/users/{id}: a role below Super Admin and/or the status. The target is locked; a Super
// Admin target ⇒ 403 (excludes_super_admin), one's own platform user ⇒ 403; If-Match; step-up. A role change or a
// disabling revokes every session of the person (§8.3 step 8).
func (s *Service) UpdateUser(ctx context.Context, a Actor, id uuid.UUID, p UserPatch, ifMatch string) (PlatformUser, error) {
	if err := s.userCondition(a); err != nil {
		return PlatformUser{}, err
	}
	if p.Role == nil && p.Status == nil {
		return PlatformUser{}, invalid("body", ReasonEmpty)
	}
	if p.Role != nil && !slices.Contains(AssignableRoles, *p.Role) {
		if *p.Role == RoleSuperAdmin {
			return PlatformUser{}, &AdminError{Kind: ErrForbidden, Reason: ReasonSuperAdminTarget, Field: "role"}
		}
		return PlatformUser{}, invalid("role", "invalid_role")
	}
	if p.Status != nil && !slices.Contains(UserStatuses, *p.Status) {
		return PlatformUser{}, invalid("status", "invalid_status")
	}
	return s.changeUser(ctx, a, id, p, ifMatch, ActionUserUpdate)
}

// DisableUser is DELETE /platform/users/{id}: status disabled (the row stays — audit refers to it) and every session
// revoked; the rules of UpdateUser.
func (s *Service) DisableUser(ctx context.Context, a Actor, id uuid.UUID, ifMatch string) (PlatformUser, error) {
	if err := s.userCondition(a); err != nil {
		return PlatformUser{}, err
	}
	st := UserDisabled
	return s.changeUser(ctx, a, id, UserPatch{Status: &st}, ifMatch, ActionUserDelete)
}

func (s *Service) changeUser(ctx context.Context, a Actor, id uuid.UUID, p UserPatch, ifMatch, action string) (PlatformUser, error) {
	var out PlatformUser
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		cur, err := q.LockPlatformUserRole(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case cur.RoleKey == RoleSuperAdmin:
			return refuse(ErrForbidden, ReasonSuperAdminTarget)
		case cur.IdentityID == a.IdentityID:
			return refuse(ErrForbidden, ReasonSelf)
		}
		if err := stepUp(a, time.Now()); err != nil {
			return err
		}
		if err := ifMatchVersion(ifMatch, cur.Version); err != nil {
			return err
		}
		role, status := cur.RoleKey, cur.Status
		if p.Role != nil {
			role = *p.Role
		}
		if p.Status != nil {
			status = *p.Status
		}
		if role == cur.RoleKey && status == cur.Status {
			v, err := q.GetPlatformUserView(ctx, id)
			if err != nil {
				return err
			}
			out = userOf(v)
			return audit.Record(ctx, q, audit.Event{Action: action, ResourceType: "platform_user", ResourceID: id.String(),
				Details: audit.Details{"changed": []string{}, "role": role, "status": status}})
		}
		r, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "platform", Key: role})
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if _, err := q.UpdatePlatformUser(ctx, sqlcdb.UpdatePlatformUserParams{RoleID: r.ID, Status: status, Now: now, ID: id}); err != nil {
			return err
		}
		revoked, err := q.RevokeIdentitySessions(ctx, sqlcdb.RevokeIdentitySessionsParams{Now: now, IdentityID: cur.IdentityID})
		if err != nil {
			return err
		}
		v, err := q.GetPlatformUserView(ctx, id)
		if err != nil {
			return err
		}
		out = userOf(v)
		var changed []string
		if role != cur.RoleKey {
			changed = append(changed, "role")
		}
		if status != cur.Status {
			changed = append(changed, "status")
		}
		return audit.Record(ctx, q, audit.Event{Action: action, ResourceType: "platform_user", ResourceID: id.String(),
			Details: audit.Details{"identity_id": cur.IdentityID, "changed": changed, "before_role": cur.RoleKey,
				"after_role": role, "before_status": cur.Status, "after_status": status, "sessions_revoked": revoked}})
	})
	return out, err
}

// SuperAdminPayload is the payload of an approval request platform.user.super_admin — what the second Super Admin
// approves and the only input of the execution.
type SuperAdminPayload struct {
	PlatformUserID uuid.UUID `json:"platform_user_id"`
	IdentityID     uuid.UUID `json:"identity_id"`
	Grant          bool      `json:"grant"`
	RoleBefore     string    `json:"role_before"`
	RoleAfter      string    `json:"role_after"`
	Version        int64     `json:"version"`
}

// Validate implements approvals.Validator.
func (p SuperAdminPayload) Validate() error {
	switch {
	case p.PlatformUserID == uuid.Nil || p.IdentityID == uuid.Nil || p.Version < 1:
		return errors.New("super admin payload: platform user, identity and version are required")
	case p.Grant && (p.RoleAfter != RoleSuperAdmin || !slices.Contains(AssignableRoles, p.RoleBefore)):
		return errors.New("super admin payload: a grant goes from a role below Super Admin to super_admin")
	case !p.Grant && (p.RoleBefore != RoleSuperAdmin || !slices.Contains(AssignableRoles, p.RoleAfter)):
		return errors.New("super admin payload: a revocation goes from super_admin to a role below it")
	}
	return nil
}

// SuperAdminRequest checks PUT /platform/users/{id}/super-admin-role and returns the payload of the approval request
// (the handler makes the request — approvals.Service checks the requester's step-up): grant ⇒ an active platform user
// below Super Admin; revoke ⇒ a Super Admin and roleAfter a role below it. Asking for the current state ⇒ 409.
func (s *Service) SuperAdminRequest(ctx context.Context, id uuid.UUID, grant bool, roleAfter string) (SuperAdminPayload, error) {
	if !grant && !slices.Contains(AssignableRoles, roleAfter) {
		return SuperAdminPayload{}, invalid("role_after", "role_after_required")
	}
	if grant && roleAfter != "" {
		return SuperAdminPayload{}, invalid("role_after", "role_after_on_grant")
	}
	var p SuperAdminPayload
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		v, err := q.GetPlatformUserView(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case grant && v.RoleKey == RoleSuperAdmin, !grant && v.RoleKey != RoleSuperAdmin:
			return refuse(ErrConflict, ReasonState)
		case grant && (v.Status != UserActive || v.IdentityStatus != UserActive):
			return refuse(ErrConflict, ReasonIdentityDisabled)
		}
		p = SuperAdminPayload{PlatformUserID: v.ID, IdentityID: v.IdentityID, Grant: grant, RoleBefore: v.RoleKey,
			RoleAfter: RoleSuperAdmin, Version: v.Version}
		if !grant {
			p.RoleAfter = roleAfter
		}
		return nil
	})
	return p, err
}

// SuperAdminExecution names the approved request whose payload ExecuteSuperAdmin runs.
type SuperAdminExecution struct {
	ApprovalID  uuid.UUID
	RequestedBy uuid.UUID
	DecidedBy   uuid.UUID
}

// ExecuteSuperAdmin runs an approved platform.user.super_admin request in the approval's platform transaction q: under
// the advisory lock of every Super Admin assignment (LockSuperAdminAssignment — the bootstrap command takes it too) the
// platform user must still be at the approved version and role (else ReasonStale, nothing written); the role changes,
// every session of the person is revoked, and a revocation that would leave no active Super Admin is refused.
func (s *Service) ExecuteSuperAdmin(ctx context.Context, q *sqlcdb.Queries, e SuperAdminExecution, p SuperAdminPayload) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := q.LockSuperAdminAssignment(ctx); err != nil {
		return err
	}
	cur, err := q.LockPlatformUserRole(ctx, p.PlatformUserID)
	if errors.Is(err, store.ErrNoRows) {
		return refuse(ErrConflict, ReasonStale)
	}
	if err != nil {
		return err
	}
	if cur.Version != p.Version || cur.RoleKey != p.RoleBefore || cur.IdentityID != p.IdentityID {
		return refuse(ErrConflict, ReasonStale)
	}
	if p.Grant && cur.Status != UserActive {
		return refuse(ErrConflict, ReasonStale)
	}
	role, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "platform", Key: p.RoleAfter})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := q.UpdatePlatformUser(ctx, sqlcdb.UpdatePlatformUserParams{RoleID: role.ID, Status: cur.Status, Now: now,
		ID: cur.ID}); err != nil {
		return err
	}
	active, err := q.CountActiveSuperAdmins(ctx)
	if err != nil {
		return err
	}
	if active < 1 {
		return refuse(ErrConflict, ReasonLastSuperAdmin)
	}
	revoked, err := q.RevokeIdentitySessions(ctx, sqlcdb.RevokeIdentitySessionsParams{Now: now, IdentityID: cur.IdentityID})
	if err != nil {
		return err
	}
	return audit.Record(ctx, q, audit.Event{Action: ActionSuperAdminExecute, ResourceType: "platform_user",
		ResourceID: cur.ID.String(), Details: audit.Details{"identity_id": cur.IdentityID, "grant": p.Grant,
			"before_role": p.RoleBefore, "after_role": p.RoleAfter, "approval_id": e.ApprovalID,
			"requested_by_identity_id": e.RequestedBy, "decided_by_identity_id": e.DecidedBy,
			"active_super_admins": active, "sessions_revoked": revoked}})
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
