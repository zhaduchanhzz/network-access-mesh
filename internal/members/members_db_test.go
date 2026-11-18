package members

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// TestMembers runs the service tests on one database (one migration instead of five); each subtest works on its own
// members, so the order only matters where stated.
func TestMembers(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, *fixture)
	}{
		{"LockUnlock", testLockUnlock},
		{"Roles", testRoles},
		{"OwnershipTransfer", testOwnershipTransfer},
		{"Offboard", testOffboard},
		{"OffboardFailureAndExternalIdP", testOffboardFailureAndExternalIdP},
		{"Groups", testGroups},
		{"SensitiveGroup", testSensitiveGroup},
		{"IdPInvite", testIdPInvite},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, f) })
	}
}

func (f *fixture) version(t *testing.T, ten *tenantFx, name string) string {
	t.Helper()
	m, err := f.api.tenants.GetMember(context.Background(), ten.id, ten.people[name].membership)
	if err != nil {
		t.Fatal(err)
	}
	return ETag(m.Version)
}

// testLockUnlock — PATCH /users/{id}: If-Match (428/412), rule 3a (a Tenant Admin never locks an Owner or another
// Admin), the last Owner, another tenant's member (404), sessions revoked by the lock, unlock.
func testLockUnlock(t *testing.T, f *fixture) {
	a := f.a
	owner, admin := a.actor("owner"), a.actor("admin")
	viewer := a.people["viewer"]
	f.session(t, a, viewer)
	ctx := ctxOf(owner, a.id, ActionUserUpdate)
	if _, err := f.api.SetStatus(ctx, a.id, viewer.membership, owner, "", "locked"); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("without If-Match: %v", err)
	}
	if _, err := f.api.SetStatus(ctx, a.id, viewer.membership, owner, `"999"`, "locked"); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale If-Match: %v", err)
	}
	if _, err := f.api.SetStatus(ctx, a.id, viewer.membership, owner, f.version(t, a, "viewer"), "offboarded"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("status offboarded through PATCH: %v", err)
	}
	m, err := f.api.SetStatus(ctx, a.id, viewer.membership, owner, f.version(t, a, "viewer"), "locked")
	if err != nil || m.Status != tenants.MemberLocked {
		t.Fatalf("lock: %+v %v", m, err)
	}
	if n := f.liveSessions(t, viewer); n != 0 {
		t.Fatalf("%d live sessions after the lock", n)
	}
	for _, tc := range []struct {
		who, target, reason string
	}{
		{"admin", "admin2", "target_not_lower"}, // 3a: another Admin
		{"admin", "owner", "target_not_lower"},  // 3a: an Owner
		{"owner", "owner", "last_owner"},        // the only active Owner
	} {
		actor := a.actor(tc.who)
		_, err := f.api.SetStatus(ctxOf(actor, a.id, ActionUserUpdate), a.id, a.people[tc.target].membership, actor,
			f.version(t, a, tc.target), "locked")
		if got := denialReason(err); got != tc.reason {
			t.Errorf("%s locks %s: %v (reason %q), want %s", tc.who, tc.target, err, got, tc.reason)
		}
	}
	if _, err := f.api.SetStatus(ctx, a.id, f.b.people["viewer"].membership, owner, `"1"`, "locked"); denialReason(err) != "no_such_membership" {
		t.Fatalf("another tenant's member: %v", err)
	}
	if m, err = f.api.SetStatus(ctx, a.id, viewer.membership, admin, f.version(t, a, "viewer"), "active"); err != nil ||
		m.Status != tenants.MemberActive {
		t.Fatalf("unlock by the Admin: %+v %v", m, err)
	}
	if got := f.auditOf(t, viewer.membership.String()); !slices.Equal(got, []string{"user.update/success", "user.update/success"}) {
		t.Fatalf("audit %v", got)
	}
}

// testRoles — PUT /users/{id}/role (below Admin only) and PUT /users/{id}/admin-role (Admin, Owner demotion; step-up).
func testRoles(t *testing.T, f *fixture) {
	a := f.a
	owner, admin := a.actor("owner"), a.actor("admin")
	op := a.people["operator"]
	f.session(t, a, op)
	ctx := ctxOf(admin, a.id, ActionUserRole)
	m, err := f.api.SetRole(ctx, a.id, op.membership, admin, f.version(t, a, "operator"), RoleViewer, false)
	if err != nil || m.Role != RoleViewer || f.liveSessions(t, op) != 0 {
		t.Fatalf("operator → viewer by the Admin: %+v %v (sessions %d)", m, err, f.liveSessions(t, op))
	}
	for _, tc := range []struct {
		actor        Actor
		target, role string
		admin        bool
		reason       string
	}{
		{admin, "operator", RoleAdmin, false, ReasonUseAdminRole},      // Admin through the role operation
		{admin, "operator", RoleOwner, false, ReasonOwnerRole},         // Owner never
		{admin, "admin2", RoleViewer, false, "target_not_lower"},       // 3a before the operation split
		{owner, "admin2", RoleViewer, false, ReasonUseAdminRole},       // an Admin's change is admin-role
		{owner, "operator", RoleOperator, true, ReasonUseRole},         // below Admin both ways: role
		{owner, "owner", RoleAdmin, true, "last_owner"},                // the last Owner is never demoted
		{admin, "operator", "tenant_superuser", false, "unknown_role"}, // not a tenant role
		{admin, "viewer", RoleOperator, false, ""},                     // allowed (control)
	} {
		_, err := f.api.SetRole(ctxOf(tc.actor, a.id, ActionUserRole), a.id, a.people[tc.target].membership, tc.actor,
			f.version(t, a, tc.target), tc.role, tc.admin)
		if got := reasonOf(err); got != tc.reason || (tc.reason == "") != (err == nil) {
			t.Errorf("%s → %s admin=%v: %v (reason %q), want %q", tc.target, tc.role, tc.admin, err, got, tc.reason)
		}
	}
	stale := owner
	stale.AuthTime = time.Now().Add(-20 * time.Minute)
	if _, err := f.api.SetRole(ctx, a.id, op.membership, stale, f.version(t, a, "operator"), RoleAdmin, true); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("admin-role without step-up: %v", err)
	}
	m, err = f.api.SetRole(ctxOf(owner, a.id, ActionUserAdminRole), a.id, op.membership, owner, f.version(t, a, "operator"), RoleAdmin, true)
	if err != nil || m.Role != RoleAdmin {
		t.Fatalf("promote to Admin: %+v %v", m, err)
	}
	if _, err := f.api.SetRole(ctx, a.id, op.membership, admin, f.version(t, a, "operator"), RoleViewer, true); denialReason(err) != "target_not_lower" {
		t.Fatalf("an Admin demotes another Admin through admin-role (guard): %v", err)
	}
	if m, err = f.api.SetRole(ctxOf(owner, a.id, ActionUserAdminRole), a.id, op.membership, owner, f.version(t, a, "operator"),
		RoleOperator, true); err != nil || m.Role != RoleOperator {
		t.Fatalf("demote back: %+v %v", m, err)
	}
	if got := f.auditOf(t, op.membership.String()); !slices.Equal(got, []string{"user.role.set/success",
		"user.admin_role.set/success", "user.admin_role.set/success"}) {
		t.Fatalf("audit %v", got)
	}
}

// testOwnershipTransfer — POST /ownership-transfer on tenant B: step-up, only an Owner, the target must be active; the
// former Owner becomes Admin by default; both sessions revoked; afterwards the former Owner is refused.
func testOwnershipTransfer(t *testing.T, f *fixture) {
	b := f.b
	owner, admin2 := b.actor("owner"), b.people["admin2"]
	f.session(t, b, admin2)
	f.session(t, b, b.people["owner"])
	ctx := ctxOf(owner, b.id, ActionOwnershipTransfer)
	stale := owner
	stale.AuthTime = time.Now().Add(-time.Hour)
	if _, err := f.api.TransferOwnership(ctx, b.id, stale, admin2.membership, ""); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("without step-up: %v", err)
	}
	if _, err := f.api.TransferOwnership(ctx, b.id, owner, uuid.Nil, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no target: %v", err)
	}
	if _, err := f.api.TransferOwnership(ctx, b.id, b.actor("admin"), admin2.membership, ""); denialReason(err) != "transfer_by_non_owner" {
		t.Fatalf("by an Admin: %v", err)
	}
	m, err := f.api.TransferOwnership(ctx, b.id, owner, admin2.membership, "")
	if err != nil || m.Role != RoleOwner {
		t.Fatalf("transfer: %+v %v", m, err)
	}
	if r := f.str(t, `SELECT r.key FROM tenant_memberships m JOIN roles r ON r.id = m.role_id WHERE m.id = $1`,
		b.people["owner"].membership); r != RoleAdmin {
		t.Fatalf("former Owner is %s, want tenant_admin", r)
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_memberships m JOIN roles r ON r.id = m.role_id WHERE m.tenant_id = $1
		AND r.key = 'tenant_owner' AND m.status = 'active'`, b.id); n != 1 {
		t.Fatalf("%d active Owners, want 1", n)
	}
	if f.liveSessions(t, admin2)+f.liveSessions(t, b.people["owner"]) != 0 {
		t.Fatal("sessions survived the transfer")
	}
	if _, err := f.api.TransferOwnership(ctx, b.id, owner, b.people["viewer"].membership, ""); denialReason(err) != "transfer_by_non_owner" {
		t.Fatalf("the former Owner transfers again: %v", err)
	}
	// the new Owner gives it back and stays Owner (two Owners), then the original Owner is an Owner again
	if _, err := f.api.TransferOwnership(ctx, b.id, b.actor("admin2"), b.people["owner"].membership, RoleOwner); err != nil {
		t.Fatalf("transfer back, keeping the role: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_memberships m JOIN roles r ON r.id = m.role_id WHERE m.tenant_id = $1
		AND r.key = 'tenant_owner'`, b.id); n != 2 {
		t.Fatalf("%d Owners, want 2", n)
	}
}

// testOffboard — DELETE /users/{id}: phase one (membership offboarded, out of its groups ⇒ policy.apply, identity
// disabled, sessions revoked, member.offboard enqueued, audit requested), rule 3a, idempotence; phase two (the job):
// the member's nodes expired at the request time — including a node tagged after its registration, from the
// inventory — and read back, the live pre-auth keys of the user (and the tagged node's own key) expired, another
// member's node and key untouched, the user disabled at the IdP, the audit pair closed; state pending → applied.
func testOffboard(t *testing.T, f *fixture) {
	a := f.a
	owner, admin := a.actor("owner"), a.actor("admin")
	user, user2 := a.people["user"], a.people["user2"]
	hs := a.hs
	hs.PutUser(user.hsUser, user.username())
	hs.PutUser(user2.hsUser, user2.username())
	now := time.Now().UTC()
	hs.PutNode(devicestest.Node{ID: 1, MachineKey: "mkey:01", UserID: user.hsUser, UserName: user.username(), CreatedAt: now})
	hs.PutNode(devicestest.Node{ID: 2, MachineKey: "mkey:02", Tags: []string{"tag:srv"}, CreatedAt: now, PreAuthKey: 4})
	hs.PutNode(devicestest.Node{ID: 3, MachineKey: "mkey:03", UserID: user2.hsUser, UserName: user2.username(), CreatedAt: now})
	hs.PutKey(devicestest.Key{ID: 1, UserID: user.hsUser, UserName: user.username(), Reusable: true, Expiration: now.Add(time.Hour)})
	hs.PutKey(devicestest.Key{ID: 2, UserID: user.hsUser, UserName: user.username(), Used: true, Expiration: now.Add(time.Hour)})
	hs.PutKey(devicestest.Key{ID: 3, UserID: user2.hsUser, UserName: user2.username(), Expiration: now.Add(time.Hour)})
	hs.PutKey(devicestest.Key{ID: 4, Reusable: true, Tags: []string{"tag:srv"}, Expiration: now.Add(time.Hour)})
	tagged := uuid.New()
	f.exec(t, `INSERT INTO device_inventory_cache (id, tenant_id, instance_id, headscale_node_id, machine_key, owner_membership_id, tags)
		VALUES ($1, $2, $3, 2, 'mkey:02', $4, '{tag:srv}')`, tagged, a.id, a.instance, user.membership)
	group := uuid.New()
	f.exec(t, `INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, 'offboard-eng')`, group, a.id)
	f.exec(t, `INSERT INTO group_members (tenant_id, group_id, membership_id) VALUES ($1, $2, $3), ($1, $2, $4)`,
		a.id, group, user.membership, user2.membership)
	f.session(t, a, user)
	f.session(t, a, user)

	for _, tc := range []struct{ who, target, reason string }{
		{"admin", "owner", "target_not_lower"}, {"admin", "admin2", "target_not_lower"}, {"owner", "owner", "last_owner"}} {
		actor := a.actor(tc.who)
		if _, err := f.api.Offboard(ctxOf(actor, a.id, ActionUserOffboard), a.id, a.people[tc.target].membership, actor); denialReason(err) != tc.reason {
			t.Errorf("%s offboards %s: %v, want %s", tc.who, tc.target, err, tc.reason)
		}
	}
	if _, err := f.api.Offboard(ctxOf(owner, a.id, ActionUserOffboard), a.id, f.b.people["user"].membership, owner); denialReason(err) != "no_such_membership" {
		t.Fatalf("another tenant's member: %v", err)
	}
	res, err := f.api.Offboard(ctxOf(admin, a.id, ActionUserOffboard), a.id, user.membership, admin)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case !res.Created || res.JobID == uuid.Nil || res.SessionsRevoked != 2:
		t.Fatalf("result %+v", res)
	case res.Member.Status != tenants.MemberOffboarded || res.Member.Offboarding == nil ||
		res.Member.Offboarding.State != tenants.OffboardPending || res.Member.Offboarding.JobID != res.JobID:
		t.Fatalf("member %+v %+v", res.Member, res.Member.Offboarding)
	case f.str(t, `SELECT status FROM identities WHERE id = $1`, user.identity) != "disabled":
		t.Fatal("identity not disabled")
	case f.liveSessions(t, user) != 0:
		t.Fatal("sessions survived")
	case f.count(t, `SELECT count(*) FROM group_members WHERE membership_id = $1`, user.membership) != 0:
		t.Fatal("still a group member")
	case f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = 'policy.apply'
		AND status = 'queued' AND input ->> 'trigger' = 'group_change'`, a.id) != 1:
		t.Fatal("no policy.apply (group_change) for the group left")
	case f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE id = $1 AND kind = 'member.offboard'
		AND resource_type = 'membership' AND resource_id = $2`, res.JobID, user.membership.String()) != 1:
		t.Fatal("job not recorded with its resource")
	}
	again, err := f.api.Offboard(ctxOf(owner, a.id, ActionUserOffboard), a.id, user.membership, owner)
	if err != nil || again.Created || again.JobID != res.JobID {
		t.Fatalf("offboard again while pending: %+v %v", again, err)
	}
	if _, err := f.api.SetStatus(ctxOf(owner, a.id, ActionUserUpdate), a.id, user.membership, owner,
		ETag(again.Member.Version), "active"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unlock an offboarded member: %v", err)
	}

	run := f.run(t, res.JobID, 1, 8)
	if err := f.wrk.runOffboard(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	var in offboardInput
	_ = json.Unmarshal(run.Input, &in)
	for id, want := range map[uint64]bool{1: true, 2: true, 3: false} {
		n, _ := hs.Node(id)
		expired := n.Expiry != nil && n.Expiry.Equal(in.RequestedAt)
		if expired != want {
			t.Errorf("node %d: expiry %v, want expired=%v at %v", id, n.Expiry, want, in.RequestedAt)
		}
	}
	for id, want := range map[uint64]bool{1: true, 2: false, 3: false, 4: true} {
		if expired := !hs.Key(id).Expiration.After(time.Now()); expired != want {
			t.Errorf("key %d expired=%v, want %v", id, expired, want)
		}
	}
	if !slices.Equal(f.kc.disabled, []string{user.subject}) {
		t.Fatalf("IdP disabled %v, want the member's subject", f.kc.disabled)
	}
	if f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE id = $1 AND expiry IS NOT NULL`, tagged) != 1 {
		t.Fatal("inventory expiry of the tagged node not recorded")
	}
	out := map[string]any{}
	_ = json.Unmarshal(run.Output(), &out)
	if out["nodes_expired"] != float64(2) || out["keys_expired"] != float64(2) || out["idp"] != idpStateDisabled {
		t.Fatalf("output %v", out)
	}
	if got := f.auditOf(t, user.membership.String()); !slices.Equal(got, []string{"user.offboard.requested/success",
		"user.offboard/success", "user.offboard.succeeded/success"}) {
		t.Fatalf("audit %v", got)
	}
	f.finishJob(t, res.JobID, "succeeded")
	m, err := f.api.tenants.GetMember(context.Background(), a.id, user.membership)
	if err != nil || m.Offboarding == nil || m.Offboarding.State != tenants.OffboardApplied {
		t.Fatalf("after the job: %+v %v", m.Offboarding, err)
	}
	// a second run of the job (a retry after a lost acknowledgement) changes nothing
	if err := f.wrk.runOffboard(context.Background(), f.run(t, res.JobID, 2, 8)); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if calls := hs.ExpireCalls(1); len(calls) != 1 {
		t.Fatalf("node 1 expired %d times, want once", len(calls))
	}
	applied, err := f.api.Offboard(ctxOf(owner, a.id, ActionUserOffboard), a.id, user.membership, owner)
	if err != nil || applied.Created || applied.JobID != res.JobID || applied.Member.Offboarding.State != tenants.OffboardApplied {
		t.Fatalf("offboard an applied member: %+v %v", applied, err)
	}
}

// testOffboardFailureAndExternalIdP — the instance does not answer: retried, then the job fails and closes the audit
// pair failed; DELETE again starts a new job. A tenant-managed IdP (driver external) is not the platform's to disable.
func testOffboardFailureAndExternalIdP(t *testing.T, f *fixture) {
	a := f.a
	owner := a.actor("owner")
	user2 := a.people["user2"]
	a.hs.SetDown(true)
	res, err := f.api.Offboard(ctxOf(owner, a.id, ActionUserOffboard), a.id, user2.membership, owner)
	if err != nil {
		t.Fatal(err)
	}
	var je *jobs.Error
	if err := f.wrk.runOffboard(context.Background(), f.run(t, res.JobID, 1, 8)); !errors.As(err, &je) || je.Permanent ||
		je.Code != CodeInstance {
		t.Fatalf("instance down, attempt 1: %v", err)
	}
	if got := f.auditOf(t, user2.membership.String()); slices.Contains(got, "user.offboard.failed/failure") {
		t.Fatalf("pair closed before the last attempt: %v", got)
	}
	if err := f.wrk.runOffboard(context.Background(), f.run(t, res.JobID, 8, 8)); !errors.As(err, &je) {
		t.Fatalf("last attempt: %v", err)
	}
	if got := f.auditOf(t, user2.membership.String()); !slices.Contains(got, "user.offboard.failed/failure") {
		t.Fatalf("pair not closed failed: %v", got)
	}
	f.finishJob(t, res.JobID, "failed")
	m, _ := f.api.tenants.GetMember(context.Background(), a.id, user2.membership)
	if m.Offboarding == nil || m.Offboarding.State != tenants.OffboardFailed {
		t.Fatalf("state %+v, want failed", m.Offboarding)
	}
	a.hs.SetDown(false)
	retry, err := f.api.Offboard(ctxOf(owner, a.id, ActionUserOffboard), a.id, user2.membership, owner)
	if err != nil || !retry.Created || retry.JobID == res.JobID || retry.Member.Offboarding.State != tenants.OffboardPending {
		t.Fatalf("retry: %+v %v", retry, err)
	}
	if err := f.wrk.runOffboard(context.Background(), f.run(t, retry.JobID, 1, 8)); err != nil {
		t.Fatalf("retried job: %v", err)
	}
	if n, _ := a.hs.Node(3); n.Expiry == nil {
		t.Fatal("node 3 not expired by the retry")
	}

	// tenant B with its own IdP (external): the job completes without the IdP
	b := f.b
	f.exec(t, `UPDATE identity_providers SET driver = 'external' WHERE id = $1`, b.idp)
	bo := b.actor("admin2") // Owner of B since the ownership transfer
	bu := b.people["user"]
	res, err = f.api.Offboard(ctxOf(bo, b.id, ActionUserOffboard), b.id, bu.membership, bo)
	if err != nil {
		t.Fatal(err)
	}
	run := f.run(t, res.JobID, 1, 8)
	if err := f.wrk.runOffboard(context.Background(), run); err != nil {
		t.Fatalf("external IdP: %v", err)
	}
	out := map[string]any{}
	_ = json.Unmarshal(run.Output(), &out)
	if out["idp"] != idpStateNotApplicable || slices.Contains(f.kc.disabled, bu.subject) {
		t.Fatalf("external IdP: output %v, keycloak calls %v", out, f.kc.disabled)
	}
}

// testGroups — CRUD (Idempotency-Key, name unique, If-Match) and PUT …/members: active members of the tenant only,
// a change enqueues one policy.apply (group_change) that absorbs the next changes, no change ⇒ no job.
func testGroups(t *testing.T, f *fixture) {
	a := f.a
	admin := a.actor("admin")
	ctx := ctxOf(admin, a.id, ActionGroupCreate)
	key := &Idempotency{Key: "k-" + uuid.NewString(), Hash: jobs.RequestHash("POST", "/groups", []byte(`{"name":"ops"}`))}
	g, err := f.api.CreateGroup(ctx, a.id, admin, NewGroup{Name: "ops", Description: " Operations "}, key)
	if err != nil || g.Name != "ops" || g.Description != "Operations" || g.Version != 1 {
		t.Fatalf("create: %+v %v", g, err)
	}
	if again, err := f.api.CreateGroup(ctx, a.id, admin, NewGroup{Name: "ops"}, key); err != nil || again.ID != g.ID {
		t.Fatalf("replay: %+v %v", again, err)
	}
	other := &Idempotency{Key: key.Key, Hash: jobs.RequestHash("POST", "/groups", []byte(`{"name":"dev"}`))}
	if _, err := f.api.CreateGroup(ctx, a.id, admin, NewGroup{Name: "dev"}, other); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("key reused: %v", err)
	}
	if _, err := f.api.CreateGroup(ctx, a.id, admin, NewGroup{Name: "ops"}, nil); reasonOf(err) != ReasonGroupNameTaken {
		t.Fatalf("name taken: %v", err)
	}
	for _, bad := range []string{"Ops", "1ops", "ops_x", "", "o" + string(make([]byte, 60))} {
		if _, err := f.api.CreateGroup(ctx, a.id, admin, NewGroup{Name: bad}, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	page, err := f.api.ListGroups(context.Background(), a.id, GroupFilter{Query: "op"})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != g.ID {
		t.Fatalf("list: %+v %v", page, err)
	}
	if _, err := f.api.GetGroup(context.Background(), f.b.id, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant's path: %v", err)
	}
	viewer, user2 := a.people["viewer"], a.people["user2"]
	ids := []uuid.UUID{viewer.membership, a.people["admin2"].membership}
	mctx := ctxOf(admin, a.id, ActionGroupMembers)
	if _, err := f.api.SetGroupMembers(mctx, a.id, g.ID, admin, "", ids); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("without If-Match: %v", err)
	}
	for name, bad := range map[string][]uuid.UUID{
		"another tenant's member": {viewer.membership, f.b.people["viewer"].membership},
		"an offboarded member":    {user2.membership},
		"an unknown id":           {uuid.New()},
	} {
		if _, err := f.api.SetGroupMembers(mctx, a.id, g.ID, admin, ETag(1), bad); reasonOf(err) != ReasonMemberNotActive {
			t.Errorf("%s: %v", name, err)
		}
	}
	queued := func() int {
		return f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = 'policy.apply'
			AND status = 'queued'`, a.id)
	}
	f.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE tenant_id = $1
		AND kind = 'policy.apply'`, a.id)
	res, err := f.api.SetGroupMembers(mctx, a.id, g.ID, admin, ETag(1), append(ids, ids[0]))
	if err != nil || res.Approval != nil || res.Group.MemberCount != 2 || res.Group.Version != 2 || res.PolicyJob == nil {
		t.Fatalf("set members: %+v %v", res, err)
	}
	if _, err := f.api.SetGroupMembers(mctx, a.id, g.ID, admin, ETag(1), ids); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale If-Match: %v", err)
	}
	same, err := f.api.SetGroupMembers(mctx, a.id, g.ID, admin, ETag(2), ids)
	if err != nil || same.PolicyJob != nil || same.Group.Version != 2 {
		t.Fatalf("same set: %+v %v", same, err)
	}
	more, err := f.api.SetGroupMembers(mctx, a.id, g.ID, admin, ETag(2), ids[:1])
	if err != nil || more.Group.MemberCount != 1 || more.PolicyJob == nil || *more.PolicyJob != *res.PolicyJob || queued() != 1 {
		t.Fatalf("second change (debounced into the queued job): %+v %v, %d queued", more, err, queued())
	}
	up, err := f.api.UpdateGroup(ctxOf(admin, a.id, ActionGroupUpdate), a.id, g.ID, admin, ETag(3), GroupPatch{Name: ptr("ops-team")})
	if err != nil || up.Name != "ops-team" || up.Description != "Operations" || queued() != 1 {
		t.Fatalf("rename: %+v %v", up, err)
	}
	if err := f.api.DeleteGroup(ctx, a.id, g.ID, admin, ETag(3)); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("delete with a stale If-Match: %v", err)
	}
	if err := f.api.DeleteGroup(ctxOf(admin, a.id, ActionGroupDelete), a.id, g.ID, admin, ETag(4)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := f.api.GetGroup(context.Background(), a.id, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted group: %v", err)
	}
	if got := f.auditOf(t, g.ID.String()); !slices.Equal(got, []string{"group.create/success", "group.create/success",
		"group.members.set/success", "group.members.set/success", "group.members.set/success", "group.update/success",
		"group.delete/success"}) {
		t.Fatalf("audit %v", got)
	}
}

// testSensitiveGroup — a group of TenantSettings.policy.sensitive_groups: PUT …/members changes nothing and returns
// the payload to request (sorted, de-duplicated); the approved payload is applied by ExecuteGroupMembers in the
// approval's transaction (resource must match); a sensitive group with members cannot be deleted.
func testSensitiveGroup(t *testing.T, f *fixture) {
	a := f.a
	admin := a.actor("admin")
	ctx := ctxOf(admin, a.id, ActionGroupCreate)
	g, err := f.api.CreateGroup(ctx, a.id, admin, NewGroup{Name: "admins"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE tenants SET settings = jsonb_build_object('policy', jsonb_build_object('sensitive_groups',
		jsonb_build_array($2::text, 'not-a-uuid'))) WHERE id = $1`, a.id, g.ID.String())
	ids := []uuid.UUID{a.people["viewer"].membership, a.people["admin2"].membership, a.people["viewer"].membership}
	res, err := f.api.SetGroupMembers(ctxOf(admin, a.id, ActionGroupMembers), a.id, g.ID, admin, ETag(1), ids)
	if err != nil || res.Group != nil || res.Approval == nil || len(res.Approval.MembershipIDs) != 2 || res.Approval.GroupID != g.ID {
		t.Fatalf("sensitive: %+v %v", res, err)
	}
	if err := res.Approval.Validate(); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM group_members WHERE group_id = $1`, g.ID); n != 0 {
		t.Fatal("members changed before the approval")
	}
	got, err := f.api.GetGroup(context.Background(), a.id, g.ID)
	if err != nil || !got.Sensitive {
		t.Fatalf("group %+v %v", got, err)
	}
	approval := uuid.New()
	exec := func(resource string, p GroupMembersPayload) (*uuid.UUID, error) {
		var job *uuid.UUID
		err := f.apiSt.WithTenantJobTx(ctxOf(a.actor("owner"), a.id, "approval.approve"), a.id, func(tx *store.Tx) error {
			var err error
			job, err = f.api.ExecuteGroupMembers(ctxOf(a.actor("owner"), a.id, "approval.approve"), tx, a.id, approval,
				resource, admin.IdentityID, p)
			return err
		})
		return job, err
	}
	if _, err := exec(uuid.NewString(), *res.Approval); err == nil {
		t.Fatal("a payload naming another resource was executed")
	}
	job, err := exec(g.ID.String(), *res.Approval)
	if err != nil || job == nil {
		t.Fatalf("execute: %v %v", job, err)
	}
	if n := f.count(t, `SELECT count(*) FROM group_members WHERE group_id = $1`, g.ID); n != 2 {
		t.Fatalf("%d members after the approval, want 2", n)
	}
	if err := f.api.DeleteGroup(ctx, a.id, g.ID, admin, ETag(2)); reasonOf(err) != ReasonSensitiveNotEmpty {
		t.Fatalf("delete a sensitive group with members: %v", err)
	}
	if _, err := exec(g.ID.String(), GroupMembersPayload{GroupID: g.ID, MembershipIDs: []uuid.UUID{}}); err != nil {
		t.Fatalf("empty it: %v", err)
	}
	if err := f.api.DeleteGroup(ctxOf(admin, a.id, ActionGroupDelete), a.id, g.ID, admin, ETag(3)); err != nil {
		t.Fatalf("delete the emptied group: %v", err)
	}
	if got := f.str(t, `SELECT details ->> 'approval_id' FROM audit_events WHERE action = 'group.members.set'
		AND resource_id = $1 ORDER BY occurred_at LIMIT 1`, g.ID.String()); got != approval.String() {
		t.Fatalf("audit of the executed approval: %q", got)
	}
	for _, bad := range []GroupMembersPayload{{}, {GroupID: g.ID}, {GroupID: g.ID, MembershipIDs: []uuid.UUID{ids[0], ids[0]}}} {
		if bad.Validate() == nil {
			t.Errorf("payload %+v accepted", bad)
		}
	}
}

// testIdPInvite — member.idp_invite: the invited address gets an account at the platform-hosted IdP (e-mailed
// required actions); a tenant-managed IdP is not applicable; an expired invitation is skipped; an e-mail failure is
// a permanent failure (the user exists — a resend retries) with its audit event.
func testIdPInvite(t *testing.T, f *fixture) {
	a := f.a
	role := f.str(t, `SELECT id::text FROM roles WHERE scope = 'tenant' AND key = 'tenant_viewer'`)
	invite := func(ten *tenantFx, email, expires string) *jobs.Run {
		t.Helper()
		id := uuid.New()
		f.exec(t, `INSERT INTO tenant_invitations (id, tenant_id, idp_id, email, role_id, token_hash, expires_at, created_at)
			VALUES ($1, $2, $3, $4::text, $5::uuid, sha256(convert_to($4::text, 'UTF8')), now() + $6::interval, now() - interval '2 hours')`,
			id, ten.id, ten.idp, email, role, expires)
		var job uuid.UUID
		err := f.apiSt.WithTenantJobTx(context.Background(), ten.id, func(tx *store.Tx) error {
			n := IdPInviteNotifier{}
			if err := n.InvitationIssued(context.Background(), tx, tenants.InvitationNotice{TenantID: ten.id,
				InvitationID: id, Email: email}); err != nil {
				return err
			}
			j, err := tx.Q.GetLatestResourceJob(context.Background(), sqlcdb.GetLatestResourceJobParams{TenantID: &ten.id,
				ResourceType: ptr("invitation"), ResourceID: ptr(id.String()), Kind: KindIdPInvite})
			job = j.ID
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return f.run(t, job, 1, 6)
	}
	r := invite(a, "new.person@a.test", "2 days")
	if err := f.wrk.runIdPInvite(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.kc.invited, "new.person@a.test") {
		t.Fatalf("invited %v", f.kc.invited)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE action = 'invitation.idp_user' AND outcome = 'success'
		AND actor_type = 'system' AND tenant_id = $1`, a.id); n != 1 {
		t.Fatalf("%d success events", n)
	}
	r = invite(a, "late@a.test", "-1 hour")
	if err := f.wrk.runIdPInvite(context.Background(), r); err != nil || slices.Contains(f.kc.invited, "late@a.test") {
		t.Fatalf("expired invitation: %v %v", err, f.kc.invited)
	}
	f.kc.err = idp.NewError(idp.CodeEmailFailed, "keycloak.InviteUser", "execute_actions_email", nil)
	r = invite(a, "nomail@a.test", "2 days")
	var je *jobs.Error
	if err := f.wrk.runIdPInvite(context.Background(), r); !errors.As(err, &je) || !je.Permanent || je.Code != CodeIdPEmailFailed {
		t.Fatalf("e-mail failure: %v", err)
	}
	f.kc.err = nil
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE action = 'invitation.idp_user' AND outcome = 'failure'
		AND details ->> 'reason' = 'idp_email_failed'`); n != 1 {
		t.Fatalf("%d failure events", n)
	}
	// tenant B's IdP is external since the offboarding test
	r = invite(f.b, "x@b.test", "2 days")
	if err := f.wrk.runIdPInvite(context.Background(), r); err != nil {
		t.Fatalf("external IdP: %v", err)
	}
	out := map[string]any{}
	_ = json.Unmarshal(r.Output(), &out)
	if out["idp"] != idpStateNotApplicable {
		t.Fatalf("external IdP output %v", out)
	}
}
