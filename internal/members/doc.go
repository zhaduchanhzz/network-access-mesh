// Package members is the module `members` of §4.2/§13.6 (P4-T09): the write side of tenant memberships and the
// tenant's groups.
//
//	users      PATCH /users/{id} (lock / unlock), PUT /users/{id}/role (roles below Tenant Admin), PUT
//	           /users/{id}/admin-role (giving or taking Tenant Admin, demoting an Owner — step-up), POST
//	           /ownership-transfer (the only way to the Owner role — step-up), DELETE /users/{id}/sessions, DELETE
//	           /users/{id} (offboarding). Every change runs authz.GuardMembershipChange (§8.4 invariants 3, 3a: no
//	           self-escalation, target role strictly below the caller's unless the caller is an Owner, the last
//	           active Owner is never removed nor demoted) inside its own transaction — injected as a Guard: members
//	           does not import authz (§13.6). Lock, offboard and role changes revoke every Portal session of the
//	           person (§8.3 step 8).
//	offboard   two phases (T-17, like the revocation of a device): the request — in one tenant transaction the
//	           membership becomes offboarded (terminal), leaves its groups (policy.apply group_change), the paired
//	           audit user.offboard.requested is written and the job member.offboard enqueued; then, on the platform
//	           pool, the identity becomes disabled (a new login is refused at the callback whatever the IdP says) and
//	           its sessions are revoked. The job (worker) expires every node of the Headscale user mg-<membership> and
//	           every node the inventory still attributes to it (nodes tagged after registration — V-28), every live
//	           pre-auth key of that user, and disables the user at a platform-hosted IdP (driver keycloak; the
//	           driver of a tenant-managed IdP does not offer it — §8.2, V-23); it closes the audit pair. The state
//	           shown by the API is the state of the latest member.offboard job: pending, applied, failed (DELETE again
//	           retries).
//	groups     CRUD + PUT /groups/{id}/members (If-Match): a change of the members enqueues policy.apply (trigger
//	           group_change) on the desired version — never a new version (§7.3, §13.2); the queued job absorbs
//	           further changes (dedupe key tenant:<id>:policy.apply — the debounce). A group listed in
//	           TenantSettings.policy.sensitive_groups is changed only through a tenant-scope approval request
//	           (approval_requests, action tenant.group.set_members — P3-T04a): the caller gets the payload to request
//	           (202), the approved payload runs ExecuteGroupMembers.
//	invitation an invitation of a tenant whose IdP the platform hosts also creates the user there with its required
//	           actions e-mailed by the IdP (job member.idp_invite through the IdP driver — §8.2 InviteUser).
//
// Dependencies (§13.6): tenants, identity, headscale, idp, audit, notifications and the base modules; never policies,
// devices or provisioning — a group change only enqueues policy.apply, the offboarding job calls the Headscale adapter
// directly.
package members
