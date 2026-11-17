package provisioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// SuperAdminThreshold is the number of active Super Admins from which `meshguard admin bootstrap-super-admin` refuses
// to run (§8.2 "Khởi tạo ban đầu", §8.4 invariant 3): D-11 was decided on 2026-11-16 with two or more platform
// operators, so the bootstrap creates the first two Super Admins and every later one goes through
// PUT /platform/users/{id}/super-admin-role with dual control. The single-operator mode of D-11 (threshold 1) was not
// chosen: it is deliberately not a setting — changing it is a code change that follows a change of D-11 and ADR-13.
const SuperAdminThreshold = 2

// Audit actions of the bootstrap commands (actor_type = system). Each event is written in the transaction of the write
// it describes (audit.Record): it commits or rolls back with it.
const (
	// ActionBootstrapSuperAdmin — a platform event: identity (created or existing) + platform_users row as super_admin.
	ActionBootstrapSuperAdmin = "platform.super_admin.bootstrap"
	// ActionSeedIdentity — a platform event: an identity of a tenant's IdP created ahead of its first login (the
	// identities table is written on the platform pool only — grants of 0002).
	ActionSeedIdentity = "platform.identity.seed"
	// ActionSeedMembership — a tenant event (the tenant's audit lists it): a tenant_memberships row as tenant_owner or
	// tenant_admin.
	ActionSeedMembership = "tenant.membership.seed"
)

// Role keys of database/seeds/rbac.sql the bootstrap commands give (internal/authz names them too; provisioning may
// not import authz — §13.6). Seeding gives tenant_owner or tenant_admin only, never a platform or support role.
const (
	RoleSuperAdmin  = "super_admin"
	RoleTenantOwner = "tenant_owner"
	RoleTenantAdmin = "tenant_admin"
)

// SeedRoles are the roles seed-membership may give (P2-T11a: TO and TA of the test tenants A and B).
var SeedRoles = []string{RoleTenantOwner, RoleTenantAdmin}

var (
	// ErrBootstrapClosed: SuperAdminThreshold active Super Admins exist; the bootstrap path is closed and nothing was
	// written. A further Super Admin needs PUT /platform/users/{id}/super-admin-role with dual control (§8.5).
	ErrBootstrapClosed = errors.New("bootstrap closed")
	// ErrBootstrapRefused: the input or the registry forbids the change (malformed subject, unknown or inactive IdP or
	// tenant, IdP of the wrong scope, disabled identity, existing platform user or membership with another role or
	// status); nothing was written by the step that refused.
	ErrBootstrapRefused = errors.New("refused")
)

// Bootstrapper runs `meshguard admin bootstrap-super-admin` and `meshguard admin seed-membership` on the store of the
// api process: identities and platform_users are written on the platform pool (mg_api_platform), tenant_memberships on
// the tenant pool (mg_api_tenant) — the only roles granted those INSERTs (0002).
type Bootstrapper struct {
	Store *store.Store
	Log   *slog.Logger // nil discards
}

func (b *Bootstrapper) log() *slog.Logger {
	if b.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return b.Log
}

// SuperAdminRequest names the person to make Super Admin by (platform IdP, sub) — never by e-mail (§8.2).
type SuperAdminRequest struct {
	PlatformIdP uuid.UUID // identity_providers.id of the platform IdP (MG_IDP_ID_PLATFORM)
	Subject     string    // the `sub` the platform IdP issues for that person (Keycloak: the user id)
	DisplayName string    // optional; the first login replaces it with the IdP's claims
	RequestID   string    // ties the audit events of one command run; "" ⇒ a new UUIDv7
}

// SuperAdminResult describes what bootstrap-super-admin did.
type SuperAdminResult struct {
	IdPID           uuid.UUID
	Issuer          string
	IdentityID      uuid.UUID
	PlatformUserID  uuid.UUID
	IdentityCreated bool // the identity row was created (false: an earlier login or run had created it)
	Created         bool // false: the identity already was an active Super Admin — nothing written, nothing audited
	ActiveSupers    int  // active Super Admins after the command
	RequestID       string
}

// BootstrapSuperAdmin makes the identity (platform IdP, sub) a Super Admin while fewer than SuperAdminThreshold active
// Super Admins exist, in ONE platform transaction that holds the Super Admin assignment lock: the count, the identity,
// the platform_users row and the audit event commit together, and two concurrent runs cannot both pass the threshold.
// An identity that already is an active Super Admin is reported as such (idempotent, even at the threshold); an
// identity that is a platform user with another role or status, or is disabled, is refused — role changes go through
// the API.
func (b *Bootstrapper) BootstrapSuperAdmin(ctx context.Context, req SuperAdminRequest) (SuperAdminResult, error) {
	res := SuperAdminResult{RequestID: requestID(req.RequestID)}
	if err := checkInput(req.Subject, req.DisplayName); err != nil {
		return res, err
	}
	err := b.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if err := q.LockSuperAdminAssignment(ctx); err != nil {
			return err
		}
		idp, err := q.GetIdentityProvider(ctx, req.PlatformIdP)
		switch {
		case errors.Is(err, store.ErrNoRows):
			return fmt.Errorf("%w: identity provider %s is not registered (run register-platform-idp first)",
				ErrBootstrapRefused, req.PlatformIdP)
		case err != nil:
			return err
		case idp.Scope != scopePlatform || idp.TenantID != nil:
			// §8.4 invariant 1: an identity of a tenant's IdP never gets a platform role.
			return fmt.Errorf("%w: identity provider %s belongs to a tenant, not to the platform", ErrBootstrapRefused, idp.ID)
		case idp.Status != statusActive:
			return fmt.Errorf("%w: the platform identity provider %s is %s, not active", ErrBootstrapRefused, idp.ID, idp.Status)
		}
		if err := subjectForDriver(idp.Driver, req.Subject); err != nil {
			return err
		}
		res.IdPID, res.Issuer = idp.ID, idp.Issuer

		ident, err := q.GetIdentityBySubject(ctx, sqlcdb.GetIdentityBySubjectParams{IdpID: idp.ID, Subject: req.Subject})
		exists := err == nil
		if err != nil && !errors.Is(err, store.ErrNoRows) {
			return err
		}
		if exists {
			if ident.Status != statusActive {
				return fmt.Errorf("%w: identity %s is %s", ErrBootstrapRefused, ident.ID, ident.Status)
			}
			res.IdentityID = ident.ID
			pu, err := q.GetPlatformUserRole(ctx, ident.ID)
			switch {
			case err == nil && pu.RoleKey == RoleSuperAdmin && pu.Status == statusActive:
				n, err := q.CountActiveSuperAdmins(ctx)
				res.PlatformUserID, res.ActiveSupers = pu.ID, int(n)
				return err // already done: nothing to write
			case err == nil:
				return fmt.Errorf("%w: identity %s already is platform user %s (role %s, status %s) — the bootstrap "+
					"never changes an existing platform user", ErrBootstrapRefused, ident.ID, pu.ID, pu.RoleKey, pu.Status)
			case !errors.Is(err, store.ErrNoRows):
				return err
			}
		}

		n, err := q.CountActiveSuperAdmins(ctx)
		if err != nil {
			return err
		}
		if n >= SuperAdminThreshold {
			return fmt.Errorf("%w: %d active Super Admins already (threshold %d) — a further Super Admin is assigned "+
				"through PUT /platform/users/{id}/super-admin-role with dual control", ErrBootstrapClosed, n,
				SuperAdminThreshold)
		}
		if !exists {
			ident, res.IdentityCreated, err = ensureIdentity(ctx, q, idp, req.Subject, req.DisplayName)
			if err != nil {
				return err
			}
			res.IdentityID = ident.ID
		}
		role, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: scopePlatform, Key: RoleSuperAdmin})
		if err != nil {
			return fmt.Errorf("role %s: %w", RoleSuperAdmin, err)
		}
		pu, err := q.InsertPlatformUser(ctx, sqlcdb.InsertPlatformUserParams{IdentityID: ident.ID, RoleID: role.ID})
		if err != nil {
			return dbRefusal("platform user", err)
		}
		res.PlatformUserID, res.Created, res.ActiveSupers = pu.ID, true, int(n)+1
		return audit.Record(ctx, q, audit.Event{
			ActorType: audit.ActorSystem, ActorDisplay: "meshguard admin bootstrap-super-admin",
			Action: ActionBootstrapSuperAdmin, ResourceType: "platform_user", ResourceID: pu.ID.String(),
			RequestID: res.RequestID,
			Details: audit.Details{"identity_id": ident.ID, "idp_id": idp.ID, "role": RoleSuperAdmin,
				"identity_created": res.IdentityCreated, "active_super_admins": res.ActiveSupers,
				"threshold": SuperAdminThreshold},
		})
	})
	if err != nil {
		return SuperAdminResult{RequestID: res.RequestID, IdPID: res.IdPID, Issuer: res.Issuer}, err
	}
	if res.Created {
		b.log().Info("bootstrap-super-admin: super admin created", "identity_id", res.IdentityID.String(),
			"platform_user_id", res.PlatformUserID.String(), "active_super_admins", res.ActiveSupers)
	}
	return res, nil
}

// MembershipRequest names the member by (the tenant's own IdP, sub) — the IdP is the tenant's active row in the
// registry, never chosen by the operator (§8.3 step 1: the IdP is selected from the database by tenant).
type MembershipRequest struct {
	Tenant      string // slug or canonical id
	Role        string // RoleTenantOwner or RoleTenantAdmin
	Subject     string
	DisplayName string // optional
	RequestID   string // "" ⇒ a new UUIDv7
}

// MembershipResult describes what seed-membership did.
type MembershipResult struct {
	TenantID        uuid.UUID
	Slug            string
	IdPID           uuid.UUID
	Issuer          string
	IdentityID      uuid.UUID
	MembershipID    uuid.UUID
	Role            string
	IdentityCreated bool
	Created         bool // false: the identity already held exactly this role, active — nothing written
	RequestID       string
}

// SeedMembership gives the identity (tenant's IdP, sub) the role tenant_owner or tenant_admin in the tenant. It does
// not use tenant_invitations (§8.2: Phase 2 has no invitations). Two transactions, because no role may write both
// tables (0002): the platform one creates the identity if needed (with ActionSeedIdentity), the tenant one creates
// the membership (with ActionSeedMembership, listed in the tenant's audit). An identity left without membership by a
// failed second step grants nothing — the first login of that person creates the same row anyway — and a re-run
// completes the seed. An existing membership with another role or status is refused: role changes go through the
// API and its rules (§8.4 invariant 3a).
func (b *Bootstrapper) SeedMembership(ctx context.Context, req MembershipRequest) (MembershipResult, error) {
	res := MembershipResult{Role: req.Role, RequestID: requestID(req.RequestID)}
	if !slices.Contains(SeedRoles, req.Role) {
		return res, fmt.Errorf("%w: seed-membership gives %s only (got %q)", ErrBootstrapRefused,
			strings.Join(SeedRoles, " or "), clipInput(req.Role))
	}
	if err := checkInput(req.Subject, req.DisplayName); err != nil {
		return res, err
	}
	var ident sqlcdb.Identity
	err := b.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		t, err := findTenant(ctx, q, req.Tenant)
		if err != nil {
			return err
		}
		res.TenantID, res.Slug = t.ID, t.Slug
		idp, err := q.GetActiveTenantIdentityProvider(ctx, &t.ID)
		switch {
		case errors.Is(err, store.ErrNoRows):
			return fmt.Errorf("%w: tenant %s has no active identity provider", ErrBootstrapRefused, t.Slug)
		case err != nil:
			return err
		case idp.Scope != scopeTenant || idp.TenantID == nil || *idp.TenantID != t.ID:
			return fmt.Errorf("%w: identity provider %s does not belong to tenant %s", ErrBootstrapRefused, idp.ID, t.Slug)
		}
		if err := subjectForDriver(idp.Driver, req.Subject); err != nil {
			return err
		}
		res.IdPID, res.Issuer = idp.ID, idp.Issuer
		ident, res.IdentityCreated, err = ensureIdentity(ctx, q, idp, req.Subject, req.DisplayName)
		if err != nil {
			return err
		}
		if ident.Status != statusActive {
			return fmt.Errorf("%w: identity %s is %s", ErrBootstrapRefused, ident.ID, ident.Status)
		}
		res.IdentityID = ident.ID
		if !res.IdentityCreated {
			return nil
		}
		return audit.Record(ctx, q, audit.Event{
			ActorType: audit.ActorSystem, ActorDisplay: "meshguard admin seed-membership",
			Action: ActionSeedIdentity, ResourceType: "identity", ResourceID: ident.ID.String(), RequestID: res.RequestID,
			Details: audit.Details{"idp_id": idp.ID, "scope": scopeTenant, "tenant_id": t.ID},
		})
	})
	if err != nil { // rolled back: nothing of the first step exists
		res.IdentityID, res.IdentityCreated = uuid.Nil, false
		return res, err
	}

	err = b.Store.WithTenantTx(ctx, res.TenantID, func(q *sqlcdb.Queries) error {
		role, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: scopeTenant, Key: req.Role})
		if err != nil {
			return fmt.Errorf("role %s: %w", req.Role, err)
		}
		m, err := q.InsertSeededMembership(ctx, sqlcdb.InsertSeededMembershipParams{
			TenantID: res.TenantID, IdentityID: ident.ID, RoleID: role.ID,
		})
		if errors.Is(err, store.ErrNoRows) { // a membership exists: same role and active ⇒ done, else refused
			cur, err := q.GetMembershipRole(ctx, sqlcdb.GetMembershipRoleParams{TenantID: res.TenantID, IdentityID: ident.ID})
			if err != nil {
				return err
			}
			res.MembershipID = cur.ID
			if cur.RoleKey == req.Role && cur.Status == statusActive {
				return nil
			}
			return fmt.Errorf("%w: identity %s already is member %s of tenant %s (role %s, status %s) — the seed "+
				"never changes an existing membership", ErrBootstrapRefused, ident.ID, cur.ID, res.Slug, cur.RoleKey,
				cur.Status)
		}
		if err != nil {
			return dbRefusal("membership", err)
		}
		res.MembershipID, res.Created = m.ID, true
		tenantID := res.TenantID
		return audit.Record(ctx, q, audit.Event{
			TenantID: &tenantID, ActorType: audit.ActorSystem, ActorDisplay: "meshguard admin seed-membership",
			Action: ActionSeedMembership, ResourceType: "membership", ResourceID: m.ID.String(), RequestID: res.RequestID,
			Details: audit.Details{"identity_id": ident.ID, "idp_id": res.IdPID, "role": req.Role,
				"identity_created": res.IdentityCreated},
		})
	})
	if err != nil {
		res.Created = false
		return res, err
	}
	if res.Created {
		b.log().Info("seed-membership: membership created", "tenant_id", res.TenantID.String(),
			"membership_id", res.MembershipID.String(), "role", res.Role)
	}
	return res, nil
}

const (
	scopePlatform = "platform"
	scopeTenant   = "tenant"
	statusActive  = "active"
)

// seedableTenant are the tenant statuses seed-membership accepts (a tenant being removed or never built is refused).
var seedableTenant = []string{"provisioning", "active", "suspended"}

// findTenant resolves --tenant: a canonical UUID is a tenant id, anything else a slug of a live tenant.
func findTenant(ctx context.Context, q *sqlcdb.Queries, ref string) (sqlcdb.Tenant, error) {
	var (
		t   sqlcdb.Tenant
		err error
	)
	if id, perr := uuid.Parse(ref); perr == nil && id.String() == ref {
		t, err = q.GetTenant(ctx, id)
	} else {
		t, err = q.GetLiveTenantBySlug(ctx, ref)
	}
	switch {
	case errors.Is(err, store.ErrNoRows):
		return t, fmt.Errorf("%w: no tenant %q", ErrBootstrapRefused, clipInput(ref))
	case err != nil:
		return t, err
	case !slices.Contains(seedableTenant, t.Status):
		return t, fmt.Errorf("%w: tenant %s is %s", ErrBootstrapRefused, t.Slug, t.Status)
	}
	return t, nil
}

// ensureIdentity returns the identity (idp, subject), creating it (scope and tenant copied from the IdP — the composite
// foreign keys of 0002 refuse anything else) when no login or earlier run did.
func ensureIdentity(ctx context.Context, q *sqlcdb.Queries, idp sqlcdb.IdentityProvider, subject, displayName string) (
	sqlcdb.Identity, bool, error) {
	var name *string
	if displayName != "" {
		name = &displayName
	}
	ident, err := q.InsertSeededIdentity(ctx, sqlcdb.InsertSeededIdentityParams{
		IdpID: idp.ID, TenantID: idp.TenantID, Scope: idp.Scope, Subject: subject, DisplayName: name,
	})
	if err == nil {
		return ident, true, nil
	}
	if !errors.Is(err, store.ErrNoRows) {
		return ident, false, dbRefusal("identity", err)
	}
	ident, err = q.GetIdentityBySubject(ctx, sqlcdb.GetIdentityBySubjectParams{IdpID: idp.ID, Subject: subject})
	return ident, false, err
}

// dbRefusal names a constraint violation of the database (the issuer binding and role scope of §8.4 invariant 1 are
// composite foreign keys: 23503) as a refusal; anything else stays an error.
func dbRefusal(what string, err error) error {
	switch store.SQLState(err) {
	case "23503", "23505", "23514":
		return fmt.Errorf("%w: the database refused the %s (SQLSTATE %s, constraint %s)", ErrBootstrapRefused, what,
			store.SQLState(err), store.SQLConstraint(err))
	}
	return err
}

// requestID returns id, or a new UUIDv7 that ties the audit events of one command run.
func requestID(id string) string {
	if id != "" {
		return id
	}
	return "admin-" + uuid.Must(uuid.NewV7()).String()
}

// MaxSubjectLen is the bound of OpenID Connect Core §2 ("sub … MUST NOT exceed 255 ASCII characters").
const MaxSubjectLen = 255

// ValidSubject reports whether s can be the `sub` of an OpenID Provider: 1–255 visible ASCII characters (no space, no
// control character). An IdP-specific shape is checked once the IdP is known (subjectForDriver).
func ValidSubject(s string) bool {
	if s == "" || len(s) > MaxSubjectLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// MaxDisplayName bounds --display-name (characters).
const MaxDisplayName = 200

// ValidDisplayName reports whether s is a usable display name: "" (none), or 1–200 characters of valid UTF-8, no
// control character, not only spaces.
func ValidDisplayName(s string) bool {
	if s == "" {
		return true
	}
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxDisplayName || strings.TrimSpace(s) == "" {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

func checkInput(subject, displayName string) error {
	if !ValidSubject(subject) {
		return fmt.Errorf("%w: the subject must be the `sub` claim of the IdP: 1–%d visible ASCII characters",
			ErrBootstrapRefused, MaxSubjectLen)
	}
	if !ValidDisplayName(displayName) {
		return fmt.Errorf("%w: the display name must be 1–%d printable characters", ErrBootstrapRefused, MaxDisplayName)
	}
	return nil
}

// subjectForDriver checks the shape of sub for the IdP's driver: Keycloak issues the user id — a canonical lowercase
// UUID — as `sub` (the realms of infrastructure/idp have no user federation), so anything else (a username, an
// e-mail) is the wrong value and would create an identity no login ever matches.
func subjectForDriver(driver, sub string) error {
	if driver != "keycloak" {
		return nil
	}
	if id, err := uuid.Parse(sub); err != nil || id.String() != sub {
		return fmt.Errorf("%w: a Keycloak `sub` is the user id (a lowercase UUID such as "+
			"0f8fad5b-d9cb-469f-a165-70867728950e), not a username or an e-mail — see infrastructure/host/RUNBOOK.md",
			ErrBootstrapRefused)
	}
	return nil
}

// clipInput bounds an operator value quoted in an error.
func clipInput(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}
