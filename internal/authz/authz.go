// Package authz decides whether the principal of a request may perform an operation (§8.4–§8.8; layer 1 of §8.8,
// with hooks for layer 2).
//
// The session carries only the identity (§8.3 step 8), so every decision loads the caller's tenant membership — or
// platform user —, its role, the statuses involved and the grant of the requested permission from PostgreSQL through
// internal/store: one query per request, no cache. Roles, permissions and grants are seeded from the matrices of
// §8.5/§8.6 (database/seeds/rbac.sql, generated and checked by tools/openapi_lint.py), and the database enforces the
// issuer binding and the scope of roles with composite foreign keys (migration 0002): a membership never holds an
// identity of another tenant's IdP nor a platform or support role, a platform user never a tenant role, and a
// platform role never a tenant permission.
//
// Outcomes (§8.4, §13.1):
//   - no principal ⇒ ErrUnauthenticated (401 unauthenticated);
//   - a tenant the caller is not an active member of — another tenant's ID, or one that does not exist — ⇒
//     ErrNotFound (404 not_found, invariant 6: existence is not revealed);
//   - an active member or platform user without the grant ⇒ ErrForbidden (403 forbidden);
//   - a write of a tenant role while the tenant is suspended — or being deprovisioned (P3-T09: the job applies the
//     suspension policy and moves the tenant to `deprovisioning`) — ⇒ ErrTenantSuspended (403 tenant_suspended,
//     invariant 5); the reason of the denial says which.
//
// A Decision carries the obligations the service layer must honour: own-resource filtering for grants of scope own
// (x-own-resource, invariant 3b), dual control for x-dual-control operations (§8.6 2P rule) and the condition of a
// conditional grant. Membership changes go through GuardMembershipChange (invariants 3, 3a, last Owner).
package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Permission is a key of the §8.5/§8.6 matrices ("tenant.device:read") or a special x-permission value of §13.1.
type Permission string

// Special x-permission values (§13.1).
const (
	Public        Permission = "public"        // auth/login, auth/callback: no session required
	Authenticated Permission = "authenticated" // any valid session, no role (auth/session…, GET /tenants)
	Internal      Permission = "internal"      // routes that never pass the edge: never authorized by a session
)

// Scope of identities, roles and permissions (identities.scope, roles.scope, permissions.scope).
type Scope string

const (
	ScopePlatform Scope = "platform"
	ScopeTenant   Scope = "tenant"
	ScopeSupport  Scope = "support" // the effective roles of Support Access Grants (§8.7) — roles only
)

// Scope is the scope of a matrix permission ("" for a special value).
func (p Permission) Scope() Scope {
	switch {
	case strings.HasPrefix(string(p), "platform."):
		return ScopePlatform
	case strings.HasPrefix(string(p), "tenant."):
		return ScopeTenant
	}
	return ""
}

// Origin is the portal origin a session is bound to (sessions.origin, §8.3).
type Origin string

const (
	OriginApp   Origin = "app"   // app.<domain>: Tenant Portal, tenant identities
	OriginAdmin Origin = "admin" // admin.<domain>: Platform Console, platform identities
)

// System role keys seeded from §8.4/§8.6 (tools/openapi_lint.py ROLE_KEYS — TestSeedCatalog checks the database).
const (
	RoleSuperAdmin       = "super_admin"
	RolePlatformOperator = "platform_operator"
	RolePlatformSupport  = "platform_support"
	RolePlatformViewer   = "platform_viewer"
	RoleTenantOwner      = "tenant_owner"
	RoleTenantAdmin      = "tenant_admin"
	RoleTenantOperator   = "tenant_operator"
	RoleTenantViewer     = "tenant_viewer"
	RoleEndUser          = "end_user"
	RoleSupportOperator  = "support_operator"
	RoleSupportAdmin     = "support_admin"
)

// Conditions of the conditional cells of §8.5/§8.6 (role_permissions.condition). A grant with a condition is refused
// unless the Requirement lists it in Conditions — the operation then enforces it itself.
const (
	CondSelfEnroll           = "self_enroll"             // EU tenant.enrollment:request — only if the tenant allows self-enrolment
	CondExcludesSuperAdmin   = "excludes_super_admin"    // SA platform.user:assign — never the Super Admin role (separate 2P operation)
	CondTenantIdPDualControl = "tenant_idp_dual_control" // SA platform.idp:manage — rows of scope tenant need 2P
	CondRestoreOnly          = "restore_only"            // PO platform.approval:decide — approvals of a restore only
)

// Grant scopes (role_permissions.scope): own = the ○ cells of §8.6.
const (
	GrantAny = "any"
	GrantOwn = "own"
)

// Statuses read by the decisions. Only "active" grants access (identities, memberships, platform users); the full
// sets of statuses are fixed by P2-T06 / P4-T09 / P4-T03a.
const (
	StatusActive         = "active"
	TenantSuspended      = "suspended"
	TenantDeprovisioning = "deprovisioning" // P3-T09: closed like a suspended tenant until it is deleted
	TenantDeleted        = "deleted"
)

// Principal is who the session says the caller is — an identity, never a role (§8.3 step 8). The identity module
// builds it from the session after checking that the session's origin is the request's origin.
type Principal struct {
	IdentityID uuid.UUID
	Scope      Scope  // identities.scope: ScopePlatform or ScopeTenant
	Origin     Origin // sessions.origin
}

type principalKey struct{}

// WithPrincipal returns ctx carrying the principal of the request.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal of the request, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.IdentityID != uuid.Nil
}

// Requirement is what an operation demands (Operation.Requirement builds it from the spec).
type Requirement struct {
	Permission Permission
	// ReadOnly marks a safe method. The zero value counts as a write: a suspended tenant refuses writes of its
	// roles (§8.4 invariant 5), so forgetting the flag fails closed.
	ReadOnly bool
	// OwnResource (x-own-resource) lets a grant of scope own through; the Decision then obliges the service to
	// restrict the operation to the caller's own resources (§13.1, §8.4 invariant 3b).
	OwnResource bool
	// DualControl (x-dual-control) is copied to the Decision: the service turns the call into an approval request.
	DualControl bool
	// Conditions lists the grant conditions the operation enforces itself; a grant carrying any other condition is
	// refused.
	Conditions []string
}

// Need is the requirement of a write operation that needs perm (no own-resource, no dual control, no condition).
func Need(perm Permission) Requirement { return Requirement{Permission: perm} }

// Decision is a granted request and the obligations attached to it.
type Decision struct {
	Principal      Principal
	TenantID       uuid.UUID // tenant of the path; uuid.Nil on platform routes
	Permission     Permission
	RoleKey        string    // "" for public / authenticated operations
	RoleRank       int       // seniority of the role within its scope
	MembershipID   uuid.UUID // the caller's membership (tenant routes)
	PlatformUserID uuid.UUID // the caller's platform user (platform routes)
	// OwnOnly: the grant has scope own — the service must act only on the caller's own resources (CheckOwner,
	// OwnerFilter).
	OwnOnly bool
	// DualControl: the operation needs a second approver — create an approval request (202 + Location of
	// /approvals/{id}) instead of executing it (§8.6).
	DualControl bool
	// Condition: the grant is conditional — the service must enforce this condition (one of Requirement.Conditions).
	Condition string
}

// NeedsApproval reports whether the operation must become an approval request (§8.6 2P rule) instead of running now.
func (d Decision) NeedsApproval() bool { return d.DualControl }

// OwnerFilter returns the membership a list of an own-only decision must be restricted to (and, for devices, to
// untagged rows — §8.4 invariant 3b); ok is false when the decision covers every resource of the tenant.
func (d Decision) OwnerFilter() (membershipID uuid.UUID, ok bool) {
	return d.MembershipID, d.OwnOnly
}

// CheckOwner applies an own-only decision to one resource: it must belong to the caller's membership and carry no
// tag (§8.4 invariant 3b). Otherwise ErrNotFound — the caller's view of the tenant holds only its own resources, so
// someone else's looks absent, as in its filtered lists. Decisions of scope any always pass.
func (d Decision) CheckOwner(owner *uuid.UUID, tagged bool) error {
	if !d.OwnOnly {
		return nil
	}
	if owner == nil || *owner != d.MembershipID || d.MembershipID == uuid.Nil || tagged {
		return deny(ErrNotFound, "not_own_resource")
	}
	return nil
}

// Errors of negative decisions; Status maps them to the HTTP status and Problem code of §13.1.
var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrNotFound        = errors.New("not found")
	ErrForbidden       = errors.New("forbidden")
	ErrTenantSuspended = errors.New("tenant suspended")
	ErrInvalid         = errors.New("invalid request")
)

// Denial is the error of a negative decision. Kind is one of the sentinel errors (errors.Is works through Unwrap);
// Reason is a short machine-readable cause for the audit trail of denials (§8.8, written by the caller) and logs —
// never for Problem.detail.
type Denial struct {
	Kind   error
	Reason string
}

func (d *Denial) Error() string { return "authz: " + d.Kind.Error() + " (" + d.Reason + ")" }
func (d *Denial) Unwrap() error { return d.Kind }

func deny(kind error, reason string) error { return &Denial{Kind: kind, Reason: reason} }

// Status returns the HTTP status and Problem code (§13.1) of an error returned by this package; any other error is
// an internal error.
func Status(err error) (int, string) {
	switch {
	case err == nil:
		return 200, ""
	case errors.Is(err, ErrUnauthenticated):
		return 401, "unauthenticated"
	case errors.Is(err, ErrNotFound):
		return 404, "not_found"
	case errors.Is(err, ErrTenantSuspended):
		return 403, "tenant_suspended"
	case errors.Is(err, ErrForbidden):
		return 403, "forbidden"
	case errors.Is(err, ErrInvalid):
		return 422, "validation_failed"
	}
	return 500, "internal_error"
}

// access is what one request loads: the caller's membership (tenant routes) or platform user (platform routes), its
// role and the grant of the requested permission (grantScope "" = no grant).
type access struct {
	tenantStatus   string // tenant routes only
	subjectID      uuid.UUID
	subjectStatus  string // tenant_memberships.status / platform_users.status
	identityStatus string
	roleKey        string
	roleRank       int
	grantScope     string
	grantCondition string
}

type loader interface {
	// tenantAccess returns nil when the identity has no membership in the tenant (or the tenant is invisible).
	tenantAccess(ctx context.Context, tenantID, identityID uuid.UUID, perm Permission) (*access, error)
	// platformAccess returns nil when the identity is not a platform user.
	platformAccess(ctx context.Context, identityID uuid.UUID, perm Permission) (*access, error)
}

// Authorizer makes the decisions of layer 1 (§8.8).
type Authorizer struct{ load loader }

// New returns an Authorizer that loads every decision from s.
func New(s *store.Store) *Authorizer { return &Authorizer{load: storeLoader{s}} }

// Require decides whether the principal in ctx may do req in the tenant tenantID (the {tenantId} of a
// /tenants/{tenantId}/… path). tenantID is ignored for platform permissions: platform routes have no tenant context
// even when a tenant ID is their resource (/platform/tenants/{tenantId}).
func (a *Authorizer) Require(ctx context.Context, tenantID uuid.UUID, req Requirement) (Decision, error) {
	switch req.Permission {
	case Public:
		return Decision{Permission: Public}, nil
	case Internal:
		return Decision{}, deny(ErrForbidden, "internal_route")
	}
	p, ok := PrincipalFrom(ctx)
	if !ok {
		return Decision{}, deny(ErrUnauthenticated, "no_principal")
	}
	switch req.Permission.Scope() {
	case ScopeTenant:
		return a.requireTenant(ctx, p, tenantID, req)
	case ScopePlatform:
		return a.requirePlatform(ctx, p, req)
	}
	if req.Permission == Authenticated {
		return Decision{Principal: p, Permission: Authenticated}, nil
	}
	return Decision{}, deny(ErrForbidden, "unknown_permission") // deny by default (§8.4 invariant 4)
}

// RequireOperation decides for an operation of api/openapi.yaml, named by operationId or by its Go name (what the
// strict middlewares of internal/httpapi/gen receive). An operation missing from the spec is refused.
func (a *Authorizer) RequireOperation(ctx context.Context, operation string, tenantID uuid.UUID) (Decision, error) {
	op, ok := OperationByID(operation)
	if !ok {
		return Decision{}, deny(ErrForbidden, "unknown_operation")
	}
	if !op.TenantScoped() {
		tenantID = uuid.Nil
	}
	return a.Require(ctx, tenantID, op.Requirement())
}

// RequireApprover decides for the second person of a dual-control request (§8.5/§8.6 2P rule): the caller must not
// be requestedBy (the identity that asked) and must itself satisfy req — the permission of the approved action, or
// what the approval flow demands for it. The resulting decision never asks for another approval.
func (a *Authorizer) RequireApprover(ctx context.Context, tenantID, requestedBy uuid.UUID, req Requirement) (Decision, error) {
	if p, ok := PrincipalFrom(ctx); ok && p.IdentityID == requestedBy {
		return Decision{}, deny(ErrForbidden, "self_approval")
	}
	req.DualControl = false
	return a.Require(ctx, tenantID, req)
}

func (a *Authorizer) requireTenant(ctx context.Context, p Principal, tenantID uuid.UUID, req Requirement) (Decision, error) {
	if tenantID == uuid.Nil {
		return Decision{}, deny(ErrNotFound, "no_tenant")
	}
	switch {
	case p.Scope == ScopeTenant && p.Origin == OriginApp:
	case p.Scope == ScopePlatform && p.Origin == OriginAdmin:
		// Staff reach tenant-internal operations only through a Support Access Grant (§8.4 invariant 2, §8.7). The
		// table support_access_grants arrives with migration 0015 (P4-T13); until then there is no grant to find.
		return Decision{}, deny(ErrForbidden, "no_support_grant")
	default:
		return Decision{}, deny(ErrForbidden, "origin_scope_mismatch")
	}
	acc, err := a.load.tenantAccess(ctx, tenantID, p.IdentityID, req.Permission)
	if err != nil {
		return Decision{}, fmt.Errorf("authz: load tenant access: %w", err)
	}
	return decideTenant(p, tenantID, req, acc)
}

func (a *Authorizer) requirePlatform(ctx context.Context, p Principal, req Requirement) (Decision, error) {
	if p.Scope != ScopePlatform || p.Origin != OriginAdmin {
		return Decision{}, deny(ErrForbidden, "not_platform_principal")
	}
	acc, err := a.load.platformAccess(ctx, p.IdentityID, req.Permission)
	if err != nil {
		return Decision{}, fmt.Errorf("authz: load platform access: %w", err)
	}
	return decidePlatform(p, req, acc)
}

// decideTenant is the pure decision of a tenant route once the membership is loaded.
func decideTenant(p Principal, tenantID uuid.UUID, req Requirement, acc *access) (Decision, error) {
	switch {
	case acc == nil || acc.tenantStatus == TenantDeleted:
		return Decision{}, deny(ErrNotFound, "not_a_member")
	case acc.subjectStatus != StatusActive || acc.identityStatus != StatusActive:
		return Decision{}, deny(ErrNotFound, "membership_inactive")
	}
	d, err := grantDecision(p, req, acc)
	if err != nil {
		return Decision{}, err
	}
	if acc.tenantStatus == TenantSuspended && !req.ReadOnly {
		return Decision{}, deny(ErrTenantSuspended, "tenant_suspended")
	}
	if acc.tenantStatus == TenantDeprovisioning && !req.ReadOnly {
		return Decision{}, deny(ErrTenantSuspended, "tenant_deprovisioning")
	}
	d.TenantID, d.MembershipID = tenantID, acc.subjectID
	return d, nil
}

// decidePlatform is the pure decision of a platform route once the platform user is loaded.
func decidePlatform(p Principal, req Requirement, acc *access) (Decision, error) {
	switch {
	case acc == nil:
		return Decision{}, deny(ErrForbidden, "not_platform_user")
	case acc.subjectStatus != StatusActive || acc.identityStatus != StatusActive:
		return Decision{}, deny(ErrForbidden, "platform_user_inactive")
	}
	d, err := grantDecision(p, req, acc)
	if err != nil {
		return Decision{}, err
	}
	if d.OwnOnly { // impossible by the CHECK of role_permissions — refuse rather than trust it
		return Decision{}, deny(ErrForbidden, "own_scope_on_platform")
	}
	d.PlatformUserID = acc.subjectID
	return d, nil
}

func grantDecision(p Principal, req Requirement, acc *access) (Decision, error) {
	switch {
	case acc.grantScope == "":
		return Decision{}, deny(ErrForbidden, "no_grant")
	case acc.grantScope != GrantAny && acc.grantScope != GrantOwn:
		return Decision{}, deny(ErrForbidden, "unknown_grant_scope")
	case acc.grantCondition != "" && !slices.Contains(req.Conditions, acc.grantCondition):
		return Decision{}, deny(ErrForbidden, "condition_not_enforced:"+acc.grantCondition)
	case acc.grantScope == GrantOwn && !req.OwnResource:
		// §13.1: a role with scope own may call only operations declaring x-own-resource
		return Decision{}, deny(ErrForbidden, "own_scope_on_shared_operation")
	}
	return Decision{
		Principal:   p,
		Permission:  req.Permission,
		RoleKey:     acc.roleKey,
		RoleRank:    acc.roleRank,
		OwnOnly:     acc.grantScope == GrantOwn,
		DualControl: req.DualControl,
		Condition:   acc.grantCondition,
	}, nil
}

// storeLoader loads decisions through internal/store (one transaction, one query).
type storeLoader struct{ s *store.Store }

func (l storeLoader) tenantAccess(ctx context.Context, tenantID, identityID uuid.UUID, perm Permission) (*access, error) {
	var out *access
	err := l.s.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		row, err := q.GetTenantAccess(ctx, sqlcdb.GetTenantAccessParams{
			TenantID: tenantID, IdentityID: identityID, PermissionKey: string(perm),
		})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &access{
			tenantStatus: row.TenantStatus, subjectID: row.MembershipID, subjectStatus: row.MembershipStatus,
			identityStatus: row.IdentityStatus, roleKey: row.RoleKey, roleRank: int(row.RoleRank),
			grantScope: deref(row.GrantScope), grantCondition: deref(row.GrantCondition),
		}
		return nil
	})
	return out, err
}

func (l storeLoader) platformAccess(ctx context.Context, identityID uuid.UUID, perm Permission) (*access, error) {
	var out *access
	err := l.s.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetPlatformAccess(ctx, sqlcdb.GetPlatformAccessParams{IdentityID: identityID, PermissionKey: string(perm)})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &access{
			subjectID: row.PlatformUserID, subjectStatus: row.PlatformUserStatus, identityStatus: row.IdentityStatus,
			roleKey: row.RoleKey, roleRank: int(row.RoleRank),
			grantScope: deref(row.GrantScope), grantCondition: deref(row.GrantCondition),
		}
		return nil
	})
	return out, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
