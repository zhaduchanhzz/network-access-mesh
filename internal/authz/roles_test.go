package authz

// Tests of the role rules of §8.4 (invariants 3, 3a, last Owner) that need no database, including a property test:
// random sequences of membership changes on random tenants, where every accepted change must respect the rules and
// no sequence may leave a tenant without an active Owner.

import (
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/google/uuid"
)

// The ranks of the seed (database/seeds/rbac.sql — checked against the database by TestRoleLatticeOnSeed).
var (
	owner    = Role{ID: uuid.New(), Scope: ScopeTenant, Key: RoleTenantOwner, Rank: 5}
	admin    = Role{ID: uuid.New(), Scope: ScopeTenant, Key: RoleTenantAdmin, Rank: 4}
	operator = Role{ID: uuid.New(), Scope: ScopeTenant, Key: RoleTenantOperator, Rank: 3}
	viewer   = Role{ID: uuid.New(), Scope: ScopeTenant, Key: RoleTenantViewer, Rank: 2}
	endUser  = Role{ID: uuid.New(), Scope: ScopeTenant, Key: RoleEndUser, Rank: 1}

	superAdmin = Role{ID: uuid.New(), Scope: ScopePlatform, Key: RoleSuperAdmin, Rank: 4}
	platformOp = Role{ID: uuid.New(), Scope: ScopePlatform, Key: RolePlatformOperator, Rank: 3}
	platformVw = Role{ID: uuid.New(), Scope: ScopePlatform, Key: RolePlatformViewer, Rank: 1}
	supportAdm = Role{ID: uuid.New(), Scope: ScopeSupport, Key: RoleSupportAdmin, Rank: 2}

	tenantRoles = []Role{owner, admin, operator, viewer, endUser}
)

func TestCheckRoleAssignment(t *testing.T) {
	ptr := func(r Role) *Role { return &r }
	cases := []struct {
		name          string
		actor         Role
		current       *Role
		next          Role
		kind          error // nil = allowed
		reason        string
		invariantNote string
	}{
		{"owner promotes an operator to admin", owner, ptr(operator), admin, nil, "", "3a: Owner not bound"},
		{"owner demotes another owner", owner, ptr(owner), admin, nil, "", "3a: Owner not bound (last Owner: CheckLastOwner)"},
		{"owner never gives the Owner role here", owner, ptr(admin), owner, ErrForbidden, "top_role_not_assignable", "only /ownership-transfer"},
		{"admin gives viewer to an operator", admin, ptr(operator), viewer, nil, "", ""},
		{"admin invites an end user", admin, nil, endUser, nil, "", "invitation"},
		{"admin cannot give admin", admin, ptr(operator), admin, ErrForbidden, "role_not_lower", "3a: new role strictly lower"},
		{"admin cannot invite an admin", admin, nil, admin, ErrForbidden, "role_not_lower", "3a: invitation role"},
		{"admin cannot demote another admin", admin, ptr(admin), viewer, ErrForbidden, "target_not_lower", "3a: current role strictly lower"},
		{"admin cannot touch an owner", admin, ptr(owner), endUser, ErrForbidden, "target_not_lower", "3a"},
		{"operator cannot give anything above", operator, ptr(endUser), operator, ErrForbidden, "role_not_lower", ""},
		{"platform role in a tenant", owner, ptr(operator), platformOp, ErrInvalid, "role_of_another_scope", "invariant 1"},
		{"support role in a tenant", owner, ptr(operator), supportAdm, ErrInvalid, "role_of_another_scope", "§8.6 support roles"},
		{"tenant role for a platform user", superAdmin, ptr(platformVw), viewer, ErrInvalid, "role_of_another_scope", ""},
		{"target of another scope", owner, ptr(platformVw), viewer, ErrInvalid, "target_of_another_scope", ""},
		{"super admin gives platform operator", superAdmin, ptr(platformVw), platformOp, nil, "", "platform.user:assign"},
		{"super admin never gives Super Admin here", superAdmin, ptr(platformOp), superAdmin, ErrForbidden, "top_role_not_assignable", "2P operation only"},
		{"super admin never demotes a Super Admin here", superAdmin, ptr(superAdmin), platformOp, ErrForbidden, "super_admin_not_changed_here", "\"không gồm role SA\""},
		{"platform operator cannot give operator", platformOp, ptr(platformVw), platformOp, ErrForbidden, "role_not_lower", ""},
		{"support role is never an actor", supportAdm, nil, endUser, ErrForbidden, "actor_scope", ""},
	}
	for _, c := range cases {
		err := CheckRoleAssignment(c.actor, c.current, c.next)
		if c.kind == nil {
			if err != nil {
				t.Errorf("%s (%s): %v, want allowed", c.name, c.invariantNote, err)
			}
			continue
		}
		wantDenied(t, c.name, err, c.kind, c.reason)
	}
}

func TestCheckMembershipAction(t *testing.T) {
	for _, c := range []struct {
		actor, target Role
		reason        string // "" = allowed
	}{
		{owner, owner, ""}, {owner, admin, ""}, {admin, operator, ""}, {admin, endUser, ""},
		{admin, admin, "target_not_lower"}, {admin, owner, "target_not_lower"}, {operator, viewer, ""},
		{viewer, viewer, "target_not_lower"}, {superAdmin, platformOp, ""}, {superAdmin, superAdmin, "super_admin_not_changed_here"},
	} {
		err := CheckMembershipAction(c.actor, c.target)
		name := c.actor.Key + " → " + c.target.Key
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %v, want allowed", name, err)
			}
			continue
		}
		wantDenied(t, name, err, ErrForbidden, c.reason)
	}
	wantDenied(t, "owner on a platform user", CheckMembershipAction(owner, platformVw), ErrInvalid, "target_of_another_scope")
}

func TestCheckLastOwner(t *testing.T) {
	wantDenied(t, "last owner loses the role", CheckLastOwner(true, true, 1), ErrForbidden, "last_owner")
	for _, c := range [][3]any{{true, true, 2}, {true, false, 1}, {false, true, 1}, {false, true, 0}} {
		if err := CheckLastOwner(c[0].(bool), c[1].(bool), c[2].(int)); err != nil {
			t.Errorf("CheckLastOwner%v = %v, want nil", c, err)
		}
	}
}

func TestDecideMembershipChangeTransfer(t *testing.T) {
	active := func(r Role) lockedMember { return lockedMember{status: StatusActive, role: r} }
	o := owner
	a := admin
	cases := []struct {
		name          string
		ch            MembershipChange
		actor, target lockedMember
		next          *Role
		reason        string
	}{
		{"owner transfers ownership to an admin", MembershipChange{OwnershipTransfer: true}, active(owner), active(admin), &o, ""},
		{"admin cannot transfer ownership", MembershipChange{OwnershipTransfer: true}, active(admin), active(operator), &o, "transfer_by_non_owner"},
		{"transfer must give the Owner role", MembershipChange{OwnershipTransfer: true}, active(owner), active(operator), &a, "ownership_transfer_gives_the_owner_role"},
		{"transfer to a locked member", MembershipChange{OwnershipTransfer: true}, active(owner), lockedMember{status: "locked", role: admin}, &o, "target_inactive"},
		{"transfer to an owner", MembershipChange{OwnershipTransfer: true}, active(owner), active(owner), &o, "already_owner"},
		{"role change to Owner outside a transfer", MembershipChange{}, active(owner), active(admin), &o, "top_role_not_assignable"},
	}
	for _, c := range cases {
		err := decideMembershipChange(c.ch, c.actor, c.target, c.next, 1)
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		var d *Denial
		if err == nil || !errors.As(err, &d) || d.Reason != c.reason {
			t.Errorf("%s: err = %v, want reason %s", c.name, err, c.reason)
		}
	}
}

// tenantState is a tenant in the property test: members with a role and a status.
type tenantState struct{ members []lockedMember }

func (s tenantState) activeOwners() int {
	n := 0
	for _, m := range s.members {
		if m.status == StatusActive && m.role.top() {
			n++
		}
	}
	return n
}

// TestPropertyMembershipChanges is the property test of the role lattice: on random tenants, random actors apply
// random changes (role change to any tenant role, lock, offboard, unlock, ownership transfer, actions keeping the
// role). Whatever the sequence:
//   - no accepted change gives the Owner role except a transfer by an active Owner;
//   - a non-Owner actor only ever changes memberships whose role is strictly below its own, into a role strictly below
//     its own (3a) — so no role can raise anyone to or above itself;
//   - the tenant always keeps at least one active Owner (invariant 3).
func TestPropertyMembershipChanges(t *testing.T) {
	accepted, refusedLastOwner := 0, 0
	for seed := uint64(1); seed <= 300; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0x6d67)) //nolint:gosec // deterministic, reproducible property test
		s := tenantState{}
		n := 2 + rng.IntN(7)
		for i := 0; i < n; i++ {
			s.members = append(s.members, lockedMember{status: StatusActive, role: tenantRoles[rng.IntN(len(tenantRoles))]})
		}
		s.members[rng.IntN(n)].role = owner // a tenant starts with an Owner
		for step := 0; step < 80; step++ {
			ai, ti := rng.IntN(n), rng.IntN(n)
			actor, target := s.members[ai], s.members[ti]
			var ch MembershipChange
			var next *Role
			switch k := rng.IntN(6); k {
			case 0, 1: // PUT /users/{id}/role, any tenant role (Owner included: must be refused)
				r := tenantRoles[rng.IntN(len(tenantRoles))]
				next, ch.NewRole = &r, r.Key
				ch.Deactivate = k == 1 && rng.IntN(4) == 0
			case 2: // lock / offboard
				ch.Deactivate = true
			case 3: // ownership transfer
				r := owner
				next, ch.NewRole, ch.OwnershipTransfer = &r, r.Key, true
			default: // profile, sessions, unlock: keeps the role
			}
			if actor.status != StatusActive {
				continue // lockMembers refuses an inactive actor before any rule
			}
			before := s.activeOwners()
			err := decideMembershipChange(ch, actor, target, next, before)
			if err != nil {
				var d *Denial
				if errors.As(err, &d) && d.Reason == "last_owner" {
					refusedLastOwner++
				}
				continue
			}
			accepted++
			// the rules, checked independently of their implementation
			switch {
			case ch.OwnershipTransfer:
				if !actor.role.top() || target.role.top() || target.status != StatusActive {
					t.Fatalf("seed %d step %d: transfer by %s to %s/%s accepted", seed, step, actor.role.Key, target.role.Key, target.status)
				}
			case next != nil:
				if next.top() {
					t.Fatalf("seed %d step %d: Owner role given outside a transfer", seed, step)
				}
				if !actor.role.top() && (target.role.Rank >= actor.role.Rank || next.Rank >= actor.role.Rank) {
					t.Fatalf("seed %d step %d: %s changed %s into %s (3a)", seed, step, actor.role.Key, target.role.Key, next.Key)
				}
			default:
				if !actor.role.top() && target.role.Rank >= actor.role.Rank {
					t.Fatalf("seed %d step %d: %s acted on %s (3a)", seed, step, actor.role.Key, target.role.Key)
				}
			}
			// apply
			m := &s.members[ti]
			if next != nil {
				m.role = *next
			}
			switch {
			case ch.Deactivate:
				m.status = "locked"
			case next == nil && !ch.OwnershipTransfer && rng.IntN(2) == 0:
				m.status = StatusActive // unlock
			}
			if got := s.activeOwners(); got < 1 {
				t.Fatalf("seed %d step %d: no active Owner left (change %+v by %s on %s)", seed, step, ch, actor.role.Key, target.role.Key)
			}
		}
	}
	// the property must not hold vacuously
	if accepted < 1000 || refusedLastOwner == 0 {
		t.Fatalf("accepted %d changes, refused %d for the last Owner: the generator does not exercise the rules", accepted, refusedLastOwner)
	}
	t.Logf("accepted %d changes; %d refused to keep the last Owner", accepted, refusedLastOwner)
}

// TestPropertyNoEscalationChain: following only accepted assignments from any member, no member who is not an Owner
// can ever bring anybody (itself included) to its own rank or above — the reachable roles of a non-Owner actor are
// exactly the roles strictly below it.
func TestPropertyNoEscalationChain(t *testing.T) {
	for _, actor := range tenantRoles {
		reach := map[string]bool{}
		for _, cur := range tenantRoles {
			for _, next := range tenantRoles {
				if CheckRoleAssignment(actor, &cur, next) == nil {
					reach[next.Key] = true
				}
			}
		}
		for _, r := range tenantRoles {
			want := r.Rank < actor.Rank && !r.top()
			if actor.top() {
				want = !r.top()
			}
			if reach[r.Key] != want {
				t.Errorf("%s can give %s: %v, want %v", actor.Key, r.Key, reach[r.Key], want)
			}
		}
	}
}
