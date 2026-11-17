package authz

// GuardMembershipChange / GuardInvitationRole on a real database: §8.4 invariants 3 and 3a with the seeded roles,
// the "no role can grant more than it has" rule evaluated in SQL, and the last-Owner rule under concurrency.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// change runs one membership change the way the members module will (P4-T09): guard, then UPDATE, in one
// transaction of the tenant pool.
func change(ctx context.Context, s *store.Store, tenant uuid.UUID, ch MembershipChange) error {
	return s.WithTenantTx(ctx, tenant, func(q *sqlcdb.Queries) error {
		if err := GuardMembershipChange(ctx, q, tenant, ch); err != nil {
			return err
		}
		return applyChange(ctx, q, tenant, ch)
	})
}

func applyChange(ctx context.Context, q *sqlcdb.Queries, tenant uuid.UUID, ch MembershipChange) error {
	if ch.NewRole != "" {
		r, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: string(ScopeTenant), Key: ch.NewRole})
		if err != nil {
			return err
		}
		if _, err := q.UpdateTenantMembershipRole(ctx, sqlcdb.UpdateTenantMembershipRoleParams{TenantID: tenant, ID: ch.Target, RoleID: r.ID}); err != nil {
			return err
		}
	}
	if ch.Deactivate {
		if _, err := q.UpdateTenantMembershipStatus(ctx, sqlcdb.UpdateTenantMembershipStatusParams{TenantID: tenant, ID: ch.Target, Status: "locked"}); err != nil {
			return err
		}
	}
	return nil
}

func activeOwners(t *testing.T, su *pgx.Conn, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := su.QueryRow(t.Context(), `SELECT count(*) FROM tenant_memberships m JOIN roles r ON r.id = m.role_id
		WHERE m.tenant_id = $1 AND r.key = 'tenant_owner' AND m.status = 'active'`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGuardMembershipChange(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	s := e.openStore(t)
	ctx := t.Context()
	a, b := newTenant(t, su, "active"), newTenant(t, su, "active")
	o1 := a.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	ad1 := a.member(t, su, RoleTenantAdmin, StatusActive, StatusActive)
	ad2 := a.member(t, su, RoleTenantAdmin, StatusActive, StatusActive)
	op := a.member(t, su, RoleTenantOperator, StatusActive, StatusActive)
	lockedAdmin := a.member(t, su, RoleTenantAdmin, "locked", StatusActive)
	otherTenant := b.member(t, su, RoleTenantViewer, StatusActive, StatusActive)

	// custom roles (is_system = false, rank 0 = below End User): one holding a grant Tenant Admin lacks, one not
	exceeding, fitting := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exceedingKey, fittingKey := "custom_billing_"+randomHex(3), "custom_audit_"+randomHex(3)
	exec(t, su, `INSERT INTO roles (id, scope, key, name) VALUES ($1, 'tenant', $2, 'Billing reader'), ($3, 'tenant', $4, 'Auditor')`,
		exceeding, exceedingKey, fitting, fittingKey)
	exec(t, su, `INSERT INTO role_permissions (role_id, role_scope, permission_key, permission_scope)
		VALUES ($1, 'tenant', 'tenant.billing:read', 'tenant'), ($2, 'tenant', 'tenant.audit:read', 'tenant')`, exceeding, fitting)

	for _, c := range []struct {
		name   string
		ch     MembershipChange
		kind   error // nil = allowed (and applied)
		reason string
	}{
		{"admin demotes an operator to viewer", MembershipChange{Actor: ad1.membership, Target: op.membership, NewRole: RoleTenantViewer}, nil, ""},
		{"admin raises a viewer to admin (3a)", MembershipChange{Actor: ad1.membership, Target: op.membership, NewRole: RoleTenantAdmin}, ErrForbidden, "role_not_lower"},
		{"admin demotes another admin (3a)", MembershipChange{Actor: ad1.membership, Target: ad2.membership, NewRole: RoleTenantViewer}, ErrForbidden, "target_not_lower"},
		{"admin locks the owner (3a)", MembershipChange{Actor: ad1.membership, Target: o1.membership, Deactivate: true}, ErrForbidden, "target_not_lower"},
		{"admin gives the Owner role", MembershipChange{Actor: ad1.membership, Target: op.membership, NewRole: RoleTenantOwner}, ErrForbidden, "top_role_not_assignable"},
		{"admin gives a role holding a grant it lacks (no role grants more than it has)", MembershipChange{Actor: ad1.membership, Target: op.membership, NewRole: exceedingKey}, ErrForbidden, "role_exceeds_actor"},
		{"admin gives a lower role within its grants", MembershipChange{Actor: ad1.membership, Target: op.membership, NewRole: fittingKey}, nil, ""},
		{"admin transfers ownership", MembershipChange{Actor: ad1.membership, Target: ad2.membership, NewRole: RoleTenantOwner, OwnershipTransfer: true}, ErrForbidden, "transfer_by_non_owner"},
		{"the last owner demotes itself", MembershipChange{Actor: o1.membership, Target: o1.membership, NewRole: RoleTenantAdmin}, ErrForbidden, "last_owner"},
		{"the last owner locks itself", MembershipChange{Actor: o1.membership, Target: o1.membership, Deactivate: true}, ErrForbidden, "last_owner"},
		{"a locked admin acts", MembershipChange{Actor: lockedAdmin.membership, Target: op.membership, NewRole: RoleEndUser}, ErrForbidden, "actor_inactive"},
		{"target of another tenant (RLS hides it)", MembershipChange{Actor: o1.membership, Target: otherTenant.membership, Deactivate: true}, ErrNotFound, "no_such_membership"},
		{"unknown role", MembershipChange{Actor: o1.membership, Target: op.membership, NewRole: "galactic_emperor"}, ErrInvalid, "unknown_role"},
		{"platform role key in a tenant", MembershipChange{Actor: o1.membership, Target: op.membership, NewRole: RoleSuperAdmin}, ErrInvalid, "unknown_role"},
		{"owner transfers ownership to an admin", MembershipChange{Actor: o1.membership, Target: ad2.membership, NewRole: RoleTenantOwner, OwnershipTransfer: true}, nil, ""},
		{"former sole owner steps down (two owners now)", MembershipChange{Actor: o1.membership, Target: o1.membership, NewRole: RoleTenantAdmin}, nil, ""},
		{"the new sole owner cannot step down", MembershipChange{Actor: ad2.membership, Target: ad2.membership, NewRole: RoleTenantAdmin}, ErrForbidden, "last_owner"},
		{"owner demotes the former owner further", MembershipChange{Actor: ad2.membership, Target: o1.membership, NewRole: RoleTenantViewer}, nil, ""},
	} {
		err := change(ctx, s, a.id, c.ch)
		if c.kind == nil {
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			continue
		}
		wantDenied(t, c.name, err, c.kind, c.reason)
	}
	if n := activeOwners(t, su, a.id); n != 1 {
		t.Errorf("active owners at the end = %d, want 1", n)
	}

	// invitations carry a role as well (3a)
	inv := func(actor uuid.UUID, role string) error {
		return s.WithTenantTx(ctx, a.id, func(q *sqlcdb.Queries) error { return GuardInvitationRole(ctx, q, a.id, actor, role) })
	}
	if err := inv(ad1.membership, RoleTenantViewer); err != nil {
		t.Errorf("admin invites a viewer: %v", err)
	}
	wantDenied(t, "admin invites an admin", inv(ad1.membership, RoleTenantAdmin), ErrForbidden, "role_not_lower")
	wantDenied(t, "owner invites an owner", inv(ad2.membership, RoleTenantOwner), ErrForbidden, "top_role_not_assignable")
	wantDenied(t, "admin invites with a role exceeding it", inv(ad1.membership, exceedingKey), ErrForbidden, "role_exceeds_actor")
	if err := inv(ad2.membership, exceedingKey); err != nil {
		t.Errorf("owner invites with the custom role: %v", err)
	}
}

// TestGuardLastOwnerConcurrent: the two Owners of a tenant step down at the same time. Without the row locks both
// transactions would count two Owners and the tenant would end with none; with them the second transaction waits for
// the first, sees one Owner left and is refused.
func TestGuardLastOwnerConcurrent(t *testing.T) {
	e := requireDB(t)
	su := e.superuser(t)
	s := e.openStore(t)
	ctx := t.Context()
	db := e.database(t)
	a := newTenant(t, su, "active")
	o1 := a.member(t, su, RoleTenantOwner, StatusActive, StatusActive)
	o2 := a.member(t, su, RoleTenantOwner, StatusActive, StatusActive)

	guarded, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- s.WithTenantTx(ctx, a.id, func(q *sqlcdb.Queries) error {
			ch := MembershipChange{Actor: o1.membership, Target: o1.membership, NewRole: RoleTenantAdmin}
			if err := GuardMembershipChange(ctx, q, a.id, ch); err != nil {
				close(guarded)
				return err
			}
			if err := applyChange(ctx, q, a.id, ch); err != nil {
				close(guarded)
				return err
			}
			close(guarded)
			<-release // keep the transaction (and its locks) open
			return nil
		})
	}()
	<-guarded
	second := make(chan error, 1)
	go func() {
		second <- change(ctx, s, a.id, MembershipChange{Actor: o2.membership, Target: o2.membership, NewRole: RoleTenantAdmin})
	}()
	// wait until the second transaction blocks on a row lock (or finishes, which is a failure below)
	waited := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && !waited; time.Sleep(20 * time.Millisecond) {
		if err := su.QueryRow(ctx, `SELECT count(*) > 0 FROM pg_stat_activity
			WHERE datname = $1 AND usename = 'mg_api_tenant' AND wait_event_type = 'Lock'`, db).Scan(&waited); err != nil {
			t.Fatal(err)
		}
		if len(second) > 0 {
			break
		}
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first owner steps down: %v", err)
	}
	err := <-second
	if !waited {
		t.Error("the second transaction never waited for the first one's row locks")
	}
	wantDenied(t, "second owner steps down concurrently", err, ErrForbidden, "last_owner")
	if n := activeOwners(t, su, a.id); n != 1 {
		t.Errorf("active owners = %d, want 1", n)
	}
	var d *Denial
	if !errors.As(err, &d) {
		t.Errorf("second transaction: %v", err)
	}
}
