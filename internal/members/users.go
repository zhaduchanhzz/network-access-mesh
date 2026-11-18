package members

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// identities.status (CHECK of 0002, P2-T06).
const identityDisabled = "disabled"

func memberEvent(tenantID, id uuid.UUID, action string, d audit.Details) audit.Event {
	t := tenantID
	return audit.Event{Action: action, TenantID: &t, ResourceType: "membership", ResourceID: id.String(), Details: d}
}

// lockTarget runs the guard on c and reads the target it locked (a membership of another tenant or none: the guard's
// refusal — 404 — or ErrNotFound).
func (s *Service) lockTarget(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, c Change) (sqlcdb.GetMemberForChangeRow, error) {
	if err := s.guard(ctx, q, tenantID, c); err != nil {
		return sqlcdb.GetMemberForChangeRow{}, err
	}
	row, err := q.GetMemberForChange(ctx, sqlcdb.GetMemberForChangeParams{TenantID: tenantID, ID: c.Target})
	if errors.Is(err, store.ErrNoRows) {
		return row, refuse(ErrNotFound, ReasonNotFound)
	}
	if err == nil && (row.TenantID != tenantID || row.ID != c.Target) { // layer 2 of §8.8
		return row, refuse(ErrNotFound, ReasonNotFound)
	}
	return row, err
}

// revokeSessions revokes every Portal session of the identity — and disables it when disable is set — in one platform
// transaction holding the identity's row lock: a login completing meanwhile either commits before (its session is
// revoked here) or waits and finds the identity disabled (callback: identity_disabled).
func (s *Service) revokeSessions(ctx context.Context, identityID uuid.UUID, disable bool) (int64, error) {
	var n int64
	now := s.now()
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if _, err := q.LockIdentityByID(ctx, identityID); err != nil {
			return err
		}
		if disable {
			if _, err := q.SetIdentityStatus(ctx, sqlcdb.SetIdentityStatusParams{Status: identityDisabled, Now: now,
				ID: identityID}); err != nil {
				return err
			}
		}
		var err error
		n, err = q.RevokeIdentitySessions(ctx, sqlcdb.RevokeIdentitySessionsParams{Now: now, IdentityID: identityID})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("members: revoke the sessions of identity %s: %w", identityID, err)
	}
	return n, nil
}

// SetStatus is PATCH /users/{id}: lock (status locked — the person keeps nothing of the Portal: every session is
// revoked; the nodes are untouched, offboarding cuts the network) or unlock (status active). If-Match is required; the
// target's role must be strictly below the caller's unless the caller is an Owner, and the last active Owner is never
// locked (guard). An offboarded membership never changes again (409).
func (s *Service) SetStatus(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch, status string) (tenants.Member, error) {
	if status != tenants.MemberActive && status != tenants.MemberLocked {
		return tenants.Member{}, invalid("status", "invalid_status")
	}
	if err := s.requireGuard(); err != nil {
		return tenants.Member{}, err
	}
	var (
		identityID uuid.UUID
		revoke     bool
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		row, err := s.lockTarget(ctx, q, tenantID, Change{Actor: a.MembershipID, Target: id,
			Deactivate: status == tenants.MemberLocked})
		if err != nil {
			return err
		}
		if err := checkIfMatch(ifMatch, row.Version); err != nil {
			return err
		}
		if row.Status == tenants.MemberOffboarded {
			return refuse(ErrConflict, ReasonOffboarded)
		}
		identityID = row.IdentityID
		if row.Status == status {
			return audit.Record(ctx, q, memberEvent(tenantID, id, ActionUserUpdate, audit.Details{"status": status,
				"unchanged": true}))
		}
		if _, err := q.UpdateTenantMembershipStatus(ctx, sqlcdb.UpdateTenantMembershipStatusParams{Status: status,
			TenantID: tenantID, ID: id}); err != nil {
			return err
		}
		revoke = status == tenants.MemberLocked
		return audit.Record(ctx, q, memberEvent(tenantID, id, ActionUserUpdate, audit.Details{"status_before": row.Status,
			"status": status}))
	})
	if err != nil {
		return tenants.Member{}, err
	}
	if revoke {
		if _, err := s.revokeSessions(ctx, identityID, false); err != nil {
			return tenants.Member{}, err
		}
	}
	return s.member(ctx, tenantID, id)
}

// isAdminLevel reports a role the admin-role operation handles.
func isAdminLevel(role string) bool { return role == RoleOwner || role == RoleAdmin }

// SetRole is PUT /users/{id}/role (admin false — tenant.membership:assign: both the current and the new role are below
// Tenant Admin) and PUT /users/{id}/admin-role (admin true — tenant.membership:assign_admin, step-up: the change gives
// or takes Tenant Admin, or demotes an Owner). The Owner role is only given by POST /ownership-transfer. The guard
// applies §8.4 invariants 3 and 3a (no role at or above the caller's, no grant the caller lacks, never the last active
// Owner); the person's sessions are revoked (privilege change — §8.3 step 8).
func (s *Service) SetRole(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch, role string, admin bool) (tenants.Member, error) {
	switch {
	case role == RoleOwner:
		return tenants.Member{}, invalid("role", ReasonOwnerRole)
	case !admin && role == RoleAdmin:
		return tenants.Member{}, invalid("role", ReasonUseAdminRole)
	case role != RoleAdmin && !slices.Contains(RolesBelowAdmin, role):
		return tenants.Member{}, invalid("role", "unknown_role")
	}
	if err := s.requireGuard(); err != nil {
		return tenants.Member{}, err
	}
	action := ActionUserRole
	if admin {
		action = ActionUserAdminRole
	}
	var (
		identityID uuid.UUID
		changed    bool
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		row, err := s.lockTarget(ctx, q, tenantID, Change{Actor: a.MembershipID, Target: id, NewRole: role})
		if err != nil {
			return err
		}
		if err := checkIfMatch(ifMatch, row.Version); err != nil {
			return err
		}
		if admin { // step-up after the object checks: another tenant's member is a 404 whatever the session's age
			if err := s.stepUp(a); err != nil {
				return err
			}
		}
		switch {
		case row.Status == tenants.MemberOffboarded:
			return refuse(ErrConflict, ReasonOffboarded)
		case !admin && isAdminLevel(row.RoleKey):
			return invalid("role", ReasonUseAdminRole)
		case admin && !isAdminLevel(row.RoleKey) && role != RoleAdmin:
			return invalid("role", ReasonUseRole)
		}
		identityID = row.IdentityID
		if row.RoleKey == role {
			return audit.Record(ctx, q, memberEvent(tenantID, id, action, audit.Details{"role": role, "unchanged": true}))
		}
		r, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "tenant", Key: role})
		if err != nil {
			return err
		}
		if _, err := q.UpdateTenantMembershipRole(ctx, sqlcdb.UpdateTenantMembershipRoleParams{RoleID: r.ID,
			TenantID: tenantID, ID: id}); err != nil {
			return err
		}
		changed = true
		return audit.Record(ctx, q, memberEvent(tenantID, id, action, audit.Details{"role_before": row.RoleKey,
			"role": role}))
	})
	if err != nil {
		return tenants.Member{}, err
	}
	if changed {
		if _, err := s.revokeSessions(ctx, identityID, false); err != nil {
			return tenants.Member{}, err
		}
	}
	return s.member(ctx, tenantID, id)
}

// PreviousOwnerRoles are the roles the former Owner may keep after POST /ownership-transfer.
var PreviousOwnerRoles = []string{RoleOwner, RoleAdmin}

// TransferOwnership is POST /ownership-transfer (tenant.membership:assign_admin, step-up): an active Owner gives the
// Owner role to another active member — the only path to that role besides the first invitation of the orchestrator
// (§8.4 rule 3a) — and, unless previousRole is tenant_owner, becomes Tenant Admin in the same transaction (default).
// The sessions of both persons are revoked (privilege change).
func (s *Service) TransferOwnership(ctx context.Context, tenantID uuid.UUID, a Actor, target uuid.UUID, previousRole string) (tenants.Member, error) {
	if previousRole == "" {
		previousRole = RoleAdmin
	}
	switch {
	case target == uuid.Nil:
		return tenants.Member{}, invalid("membership_id", "required")
	case !slices.Contains(PreviousOwnerRoles, previousRole):
		return tenants.Member{}, invalid("previous_owner_role", "invalid_role")
	}
	if err := s.stepUp(a); err != nil {
		return tenants.Member{}, err
	}
	if err := s.requireGuard(); err != nil {
		return tenants.Member{}, err
	}
	var revoke []uuid.UUID
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		row, err := s.lockTarget(ctx, q, tenantID, Change{Actor: a.MembershipID, Target: target, NewRole: RoleOwner,
			OwnershipTransfer: true})
		if err != nil {
			return err
		}
		owner, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "tenant", Key: RoleOwner})
		if err != nil {
			return err
		}
		if _, err := q.UpdateTenantMembershipRole(ctx, sqlcdb.UpdateTenantMembershipRoleParams{RoleID: owner.ID,
			TenantID: tenantID, ID: target}); err != nil {
			return err
		}
		revoke = append(revoke, row.IdentityID)
		if previousRole != RoleOwner {
			self, err := s.lockTarget(ctx, q, tenantID, Change{Actor: a.MembershipID, Target: a.MembershipID,
				NewRole: previousRole})
			if err != nil {
				return err
			}
			r, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "tenant", Key: previousRole})
			if err != nil {
				return err
			}
			if _, err := q.UpdateTenantMembershipRole(ctx, sqlcdb.UpdateTenantMembershipRoleParams{RoleID: r.ID,
				TenantID: tenantID, ID: a.MembershipID}); err != nil {
				return err
			}
			revoke = append(revoke, self.IdentityID)
		}
		return audit.Record(ctx, q, memberEvent(tenantID, target, ActionOwnershipTransfer, audit.Details{
			"new_owner_membership_id": target, "role_before": row.RoleKey,
			"previous_owner_membership_id": a.MembershipID, "previous_owner_role": previousRole}))
	})
	if err != nil {
		return tenants.Member{}, err
	}
	for _, id := range revoke {
		if _, err := s.revokeSessions(ctx, id, false); err != nil {
			return tenants.Member{}, err
		}
	}
	return s.member(ctx, tenantID, target)
}

// RevokeUserSessions is DELETE /users/{id}/sessions: every Portal session of the member ends now (§8.3 step 8) — the
// person signs in again only if the membership and the IdP still let them. Rule 3a applies (guard).
func (s *Service) RevokeUserSessions(ctx context.Context, tenantID, id uuid.UUID, a Actor) (int64, error) {
	if err := s.requireGuard(); err != nil {
		return 0, err
	}
	var identityID uuid.UUID
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		row, err := s.lockTarget(ctx, q, tenantID, Change{Actor: a.MembershipID, Target: id})
		identityID = row.IdentityID
		return err
	})
	if err != nil {
		return 0, err
	}
	n, err := s.revokeSessions(ctx, identityID, false)
	if err != nil {
		return 0, err
	}
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		return audit.Record(ctx, q, memberEvent(tenantID, id, ActionUserSessionsRevoke, audit.Details{"sessions_revoked": n}))
	})
	return n, err
}

// OffboardResult is the answer to DELETE /users/{id}: the membership (status offboarded, its offboarding state) and
// the member.offboard job (Location of the 202).
type OffboardResult struct {
	Member          tenants.Member
	JobID           uuid.UUID
	Created         bool  // false: the offboarding was pending or applied already — nothing new started
	SessionsRevoked int64 // sessions that were still live
}

// offboardInput is the input of a member.offboard job: the membership, the moment of the request (the explicit expiry
// of the nodes — a retry sets the same value, §13.4 rule 3) and the audit operation the job finishes.
type offboardInput struct {
	MembershipID uuid.UUID        `json:"membership_id"`
	RequestedAt  time.Time        `json:"requested_at"`
	Operation    *audit.Operation `json:"operation,omitempty"`
}

// jobPending reports a job status that is not finished.
func jobPending(status string) bool {
	return status == "queued" || status == "running" || status == "failed_resumable" || status == "compensating"
}

// Offboard is DELETE /users/{id} (§8.2 vòng đời danh tính, §13.2): phase one — the membership becomes offboarded
// (terminal), leaves its groups (policy.apply group_change when it was in one), user.offboard.requested is written
// and the job member.offboard enqueued, in one tenant transaction under the guard (rule 3a: a Tenant Admin never
// offboards an Owner or another Admin; the last active Owner is never offboarded); then the identity is disabled and
// its sessions revoked (platform pool). Idempotent: on an offboarded membership the pending or applied job is
// answered as it is (the platform part runs again — harmless), a failed one is retried with a new job.
func (s *Service) Offboard(ctx context.Context, tenantID, id uuid.UUID, a Actor) (OffboardResult, error) {
	if err := s.requireGuard(); err != nil {
		return OffboardResult{}, err
	}
	var (
		res        OffboardResult
		identityID uuid.UUID
		op         audit.Operation
	)
	now := s.now().UTC()
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		row, err := s.lockTarget(ctx, q, tenantID, Change{Actor: a.MembershipID, Target: id, Deactivate: true})
		if err != nil {
			return err
		}
		identityID = row.IdentityID
		first := row.Status != tenants.MemberOffboarded
		var groups []uuid.UUID
		if first {
			if _, err := q.UpdateTenantMembershipStatus(ctx, sqlcdb.UpdateTenantMembershipStatusParams{
				Status: tenants.MemberOffboarded, TenantID: tenantID, ID: id}); err != nil {
				return err
			}
			if groups, err = q.RemoveMemberFromGroups(ctx, sqlcdb.RemoveMemberFromGroupsParams{TenantID: tenantID,
				MembershipID: id}); err != nil {
				return err
			}
			if len(groups) > 0 {
				if err := q.BumpGroupVersions(ctx, sqlcdb.BumpGroupVersionsParams{TenantID: tenantID, Ids: groups}); err != nil {
					return err
				}
				if _, err := enqueuePolicyApply(ctx, tx, tenantID, &a.IdentityID); err != nil {
					return err
				}
			}
		}
		prev, err := q.GetLatestResourceJob(ctx, sqlcdb.GetLatestResourceJobParams{TenantID: &tenantID,
			ResourceType: ptr("membership"), ResourceID: ptr(id.String()), Kind: KindOffboard})
		switch {
		case err == nil && (jobPending(prev.Status) || prev.Status == "succeeded"):
			res.JobID = prev.ID
			return audit.Record(ctx, q, memberEvent(tenantID, id, ActionUserOffboard, audit.Details{
				"repeated": true, "state": tenants.OffboardState(prev.Status), "job_id": prev.ID}))
		case err != nil && !errors.Is(err, store.ErrNoRows):
			return err
		}
		op, err = audit.Requested(ctx, q, memberEvent(tenantID, id, ActionUserOffboard, audit.Details{
			"role": row.RoleKey, "headscale_user": row.HeadscaleUsername, "groups_left": len(groups),
			"retry": !first}))
		if err != nil {
			return err
		}
		enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindOffboard, TenantID: &tenantID, Object: id.String(),
			Input: offboardInput{MembershipID: id, RequestedAt: now, Operation: &op}, RequestedBy: &a.IdentityID,
			Resource: &jobs.Resource{Type: "membership", ID: id.String()}})
		if err != nil {
			return err
		}
		res.JobID, res.Created = enq.Job.ID, enq.Created
		return nil
	})
	if err != nil {
		return OffboardResult{}, err
	}
	if res.Created {
		audit.HandOff(ctx, op)
	}
	if res.SessionsRevoked, err = s.revokeSessions(ctx, identityID, true); err != nil {
		return OffboardResult{}, err
	}
	if res.Member, err = s.member(ctx, tenantID, id); err != nil {
		return OffboardResult{}, err
	}
	return res, nil
}

// enqueuePolicyApply enqueues the level-triggered policy.apply of the tenant (trigger group_change) in tx: an
// unfinished one absorbs this change (dedupe key tenant:<id>:policy.apply — the debounce of §7.2).
func enqueuePolicyApply(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, by *uuid.UUID) (jobs.Enqueued, error) {
	return jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindPolicyApply, TenantID: &tenantID,
		Input: map[string]string{"trigger": TriggerGroupChange}, RequestedBy: by})
}
