package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Role is a role as the membership rules need it (roles.scope, key, rank).
type Role struct {
	ID    uuid.UUID
	Scope Scope
	Key   string
	Rank  int // seniority within the scope: higher = more senior (column order of §8.5/§8.6)
}

// top reports whether r is the role the ordinary role operations never give: Tenant Owner (only POST
// /ownership-transfer, or the first invitation created by the orchestrator) and Super Admin (only the dual-control
// operation PUT /platform/users/{id}/super-admin-role, or the bootstrap command — §8.2, §8.4 invariant 3).
func (r Role) top() bool {
	return (r.Scope == ScopeTenant && r.Key == RoleTenantOwner) || (r.Scope == ScopePlatform && r.Key == RoleSuperAdmin)
}

// CheckRoleAssignment applies §8.4 invariants 3 and 3a to an actor of role actor giving role next to a membership
// (or platform user) whose role is current — nil for an invitation, which only names next:
//   - next and current are roles of the actor's scope (support roles are never assigned, platform roles never in a
//     tenant: the composite foreign keys refuse them too);
//   - the top role (Tenant Owner, Super Admin) is never given here, and a Super Admin is not demoted here either
//     (platform.user:assign "không gồm role SA");
//   - a Tenant Owner is not bound by 3a; anyone else needs current and next strictly below its own rank.
//
// That next holds no grant the actor lacks is checked in the database by GuardMembershipChange / GuardInvitationRole.
func CheckRoleAssignment(actor Role, current *Role, next Role) error {
	switch {
	case actor.Scope != ScopeTenant && actor.Scope != ScopePlatform:
		return deny(ErrForbidden, "actor_scope")
	case next.Scope != actor.Scope:
		return deny(ErrInvalid, "role_of_another_scope")
	case current != nil && current.Scope != actor.Scope:
		return deny(ErrInvalid, "target_of_another_scope")
	case next.top():
		return deny(ErrForbidden, "top_role_not_assignable")
	case actor.Scope == ScopePlatform && current != nil && current.top():
		return deny(ErrForbidden, "super_admin_not_changed_here")
	case actor.Scope == ScopeTenant && actor.top():
		return nil
	case next.Rank >= actor.Rank:
		return deny(ErrForbidden, "role_not_lower")
	case current != nil && current.Rank >= actor.Rank:
		return deny(ErrForbidden, "target_not_lower")
	}
	return nil
}

// CheckMembershipAction applies 3a to an action that keeps the target's role — lock, offboard, revoke its sessions,
// edit its profile (PATCH/DELETE /users/{id}, DELETE /users/{id}/sessions): the target's role must be strictly below
// the actor's unless the actor is a Tenant Owner; on platform users never a Super Admin.
func CheckMembershipAction(actor, target Role) error {
	switch {
	case target.Scope != actor.Scope:
		return deny(ErrInvalid, "target_of_another_scope")
	case actor.Scope == ScopePlatform && target.top():
		return deny(ErrForbidden, "super_admin_not_changed_here")
	case actor.Scope == ScopeTenant && actor.top():
		return nil
	case target.Rank >= actor.Rank:
		return deny(ErrForbidden, "target_not_lower")
	}
	return nil
}

// CheckLastOwner refuses a change that would leave the tenant without an active Owner (§8.4 invariant 3): the target
// is an active Owner, the change takes the role away or deactivates the membership, and activeOwners — counted under
// lock by GuardMembershipChange — is at most one.
func CheckLastOwner(targetActiveOwner, losesOwnership bool, activeOwners int) error {
	if targetActiveOwner && losesOwnership && activeOwners <= 1 {
		return deny(ErrForbidden, "last_owner")
	}
	return nil
}

// MembershipChange is one change of a tenant membership by the caller (§8.4 invariants 3, 3a).
type MembershipChange struct {
	Actor      uuid.UUID // the caller's membership (Decision.MembershipID)
	Target     uuid.UUID // the membership changed — may be the caller's own
	NewRole    string    // key of the tenant role the target gets; "" keeps its role
	Deactivate bool      // the target leaves status active (lock, offboard)
	// OwnershipTransfer marks POST /ownership-transfer, the only path that gives the Owner role: NewRole must be the
	// Owner role and the actor an active Owner. Demoting the former Owner afterwards is a separate change.
	OwnershipTransfer bool
}

// GuardMembershipChange checks a membership change inside its own write transaction (store.WithTenantTx on the same
// tenant, before the UPDATE — e.g. UpdateTenantMembershipRole). It locks the tenant's active Owner memberships, then
// the actor's and the target's (FOR UPDATE, in id order), so two concurrent demotions of the last two Owners
// serialize and the second sees the first; then it applies CheckRoleAssignment or CheckMembershipAction, checks in the
// database that the new role holds no grant the actor lacks (no role can grant more than it has) and CheckLastOwner.
func GuardMembershipChange(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, ch MembershipChange) error {
	owner, err := roleByKey(ctx, q, RoleTenantOwner)
	if err != nil {
		return err
	}
	owners, err := q.LockActiveTenantOwners(ctx, sqlcdb.LockActiveTenantOwnersParams{
		TenantID: tenantID, OwnerRoleID: owner.ID, ActiveStatus: StatusActive,
	})
	if err != nil {
		return fmt.Errorf("authz: lock owners: %w", err)
	}
	actor, target, err := lockMembers(ctx, q, tenantID, ch.Actor, ch.Target)
	if err != nil {
		return err
	}
	var next *Role
	if ch.NewRole != "" {
		r, err := roleByKey(ctx, q, ch.NewRole)
		if err != nil {
			return err
		}
		next = &r
	}
	if err := decideMembershipChange(ch, actor, target, next, len(owners)); err != nil {
		return err
	}
	if next != nil && !ch.OwnershipTransfer {
		return checkGrantsCovered(ctx, q, *next, actor.role)
	}
	return nil
}

// decideMembershipChange is the pure part of GuardMembershipChange: the actor (active) changes target; next is the
// role the target gets (nil = unchanged); activeOwners is the number of active Owners counted under lock.
func decideMembershipChange(ch MembershipChange, actor, target lockedMember, next *Role, activeOwners int) error {
	targetActiveOwner := target.role.top() && target.status == StatusActive
	loses := ch.Deactivate
	switch {
	case ch.OwnershipTransfer:
		switch {
		case next == nil || !next.top() || next.Scope != ScopeTenant || ch.Deactivate:
			return deny(ErrInvalid, "ownership_transfer_gives_the_owner_role")
		case !actor.role.top():
			return deny(ErrForbidden, "transfer_by_non_owner")
		case target.status != StatusActive:
			return deny(ErrInvalid, "target_inactive")
		case target.role.top():
			return deny(ErrInvalid, "already_owner")
		}
		return nil
	case next != nil:
		if err := CheckRoleAssignment(actor.role, &target.role, *next); err != nil {
			return err
		}
		loses = loses || !next.top()
	default:
		if err := CheckMembershipAction(actor.role, target.role); err != nil {
			return err
		}
	}
	return CheckLastOwner(targetActiveOwner, loses, activeOwners)
}

// GuardInvitationRole checks, inside the transaction that creates or revokes an invitation, the role the invitation
// carries (§8.4 invariant 3a): strictly below the actor's role unless the actor is an Owner, never the Owner role,
// and holding no grant the actor lacks.
func GuardInvitationRole(ctx context.Context, q *sqlcdb.Queries, tenantID, actorMembership uuid.UUID, roleKey string) error {
	actor, _, err := lockMembers(ctx, q, tenantID, actorMembership, actorMembership)
	if err != nil {
		return err
	}
	next, err := roleByKey(ctx, q, roleKey)
	if err != nil {
		return err
	}
	if err := CheckRoleAssignment(actor.role, nil, next); err != nil {
		return err
	}
	return checkGrantsCovered(ctx, q, next, actor.role)
}

type lockedMember struct {
	status string
	role   Role
}

// lockMembers locks the actor's and the target's memberships (id order) and returns them; the actor must be active.
func lockMembers(ctx context.Context, q *sqlcdb.Queries, tenantID, actorID, targetID uuid.UUID) (lockedMember, lockedMember, error) {
	rows, err := q.LockTenantMembershipRoles(ctx, sqlcdb.LockTenantMembershipRolesParams{
		TenantID: tenantID, Ids: []uuid.UUID{actorID, targetID},
	})
	if err != nil {
		return lockedMember{}, lockedMember{}, fmt.Errorf("authz: lock memberships: %w", err)
	}
	var actor, target *lockedMember
	for _, r := range rows {
		m := lockedMember{status: r.Status,
			role: Role{ID: r.RoleID, Scope: Scope(r.RoleScope), Key: r.RoleKey, Rank: int(r.RoleRank)}}
		if r.ID == actorID {
			actor = &m
		}
		if r.ID == targetID {
			target = &m
		}
	}
	switch {
	case actor == nil || actor.status != StatusActive:
		return lockedMember{}, lockedMember{}, deny(ErrForbidden, "actor_inactive")
	case target == nil:
		return lockedMember{}, lockedMember{}, deny(ErrNotFound, "no_such_membership")
	}
	return *actor, *target, nil
}

func roleByKey(ctx context.Context, q *sqlcdb.Queries, key string) (Role, error) {
	r, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: string(ScopeTenant), Key: key})
	if errors.Is(err, store.ErrNoRows) {
		return Role{}, deny(ErrInvalid, "unknown_role")
	}
	if err != nil {
		return Role{}, fmt.Errorf("authz: role %s: %w", key, err)
	}
	return Role{ID: r.ID, Scope: Scope(r.Scope), Key: r.Key, Rank: int(r.Rank)}, nil
}

// checkGrantsCovered refuses next when it holds a grant giver does not (scope any covers own; an unconditional
// grant covers a conditional one).
func checkGrantsCovered(ctx context.Context, q *sqlcdb.Queries, next, giver Role) error {
	n, err := q.CountGrantsNotCovered(ctx, sqlcdb.CountGrantsNotCoveredParams{RoleID: next.ID, GiverRoleID: giver.ID})
	if err != nil {
		return fmt.Errorf("authz: compare grants: %w", err)
	}
	if n > 0 {
		return deny(ErrForbidden, "role_exceeds_actor")
	}
	return nil
}
