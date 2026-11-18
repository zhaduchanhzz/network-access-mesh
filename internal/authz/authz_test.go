package authz

// Tests that need no database: the decision logic over a fake loader, the decision hooks, the error mapping and the
// generated operation table.

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// auditAction is the format of x-audit-action (tools/openapi_lint.py AUDIT_ACTION).
var auditAction = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// fakeLoader returns fixed rows and records the calls it got.
type fakeLoader struct {
	tenant, platform *access
	err              error
	calls            []string
}

func (f *fakeLoader) tenantAccess(_ context.Context, tenantID, identityID uuid.UUID, perm Permission) (*access, error) {
	f.calls = append(f.calls, "tenant:"+tenantID.String()+":"+identityID.String()+":"+string(perm))
	return f.tenant, f.err
}

func (f *fakeLoader) platformAccess(_ context.Context, identityID uuid.UUID, perm Permission) (*access, error) {
	f.calls = append(f.calls, "platform:"+identityID.String()+":"+string(perm))
	return f.platform, f.err
}

var (
	tenantA  = uuid.MustParse("0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f50")
	identity = uuid.MustParse("0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f51")
	member   = uuid.MustParse("0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f52")
)

func tenantPrincipal() Principal {
	return Principal{IdentityID: identity, Scope: ScopeTenant, Origin: OriginApp}
}

func staffPrincipal() Principal {
	return Principal{IdentityID: identity, Scope: ScopePlatform, Origin: OriginAdmin}
}

func activeMember(scope, cond string) *access {
	return &access{tenantStatus: "active", subjectID: member, subjectStatus: StatusActive, identityStatus: StatusActive,
		roleKey: RoleTenantAdmin, roleRank: 4, grantScope: scope, grantCondition: cond}
}

// wantDenied asserts that err is a Denial of kind with the given reason ("" = any reason).
func wantDenied(t *testing.T, what string, err, kind error, reason string) {
	t.Helper()
	var d *Denial
	switch {
	case !errors.Is(err, kind):
		t.Errorf("%s: err = %v, want %v", what, err, kind)
	case !errors.As(err, &d):
		t.Errorf("%s: err %v is not a *Denial", what, err)
	case reason != "" && d.Reason != reason:
		t.Errorf("%s: reason = %q, want %q", what, d.Reason, reason)
	}
}

func TestRequireSpecialPermissions(t *testing.T) {
	f := &fakeLoader{}
	a := &Authorizer{load: f}
	bare := context.Background()
	if d, err := a.Require(bare, uuid.Nil, Requirement{Permission: Public}); err != nil || d.Permission != Public {
		t.Errorf("public without a session: %+v, %v", d, err)
	}
	_, err := a.Require(bare, uuid.Nil, Requirement{Permission: Authenticated, ReadOnly: true})
	wantDenied(t, "authenticated without a session", err, ErrUnauthenticated, "no_principal")
	ctx := WithPrincipal(bare, tenantPrincipal())
	if d, err := a.Require(ctx, uuid.Nil, Requirement{Permission: Authenticated}); err != nil || d.Principal.IdentityID != identity {
		t.Errorf("authenticated with a session: %+v, %v", d, err)
	}
	_, err = a.Require(ctx, uuid.Nil, Requirement{Permission: Internal})
	wantDenied(t, "internal", err, ErrForbidden, "internal_route")
	for _, p := range []Permission{"", "tenant", "platform", "devices:read", "tenantx.device:read"} {
		_, err = a.Require(ctx, tenantA, Requirement{Permission: p})
		wantDenied(t, "unknown permission "+string(p), err, ErrForbidden, "unknown_permission")
	}
	_, err = a.Require(bare, tenantA, Need("tenant.device:sync"))
	wantDenied(t, "matrix permission without a session", err, ErrUnauthenticated, "no_principal")
	if _, ok := PrincipalFrom(WithPrincipal(bare, Principal{})); ok {
		t.Error("a principal without identity must not count as a principal")
	}
	if len(f.calls) != 0 {
		t.Errorf("no decision above needs the database, got calls %v", f.calls)
	}
}

// TestRequireTenantPrincipals: on a tenant route only a tenant identity on the app origin reaches its membership;
// staff need a Support Access Grant (none exists before P4-T13) and mismatched origins are refused — without a query.
func TestRequireTenantPrincipals(t *testing.T) {
	cases := []struct {
		name   string
		p      Principal
		tenant uuid.UUID
		kind   error
		reason string
	}{
		{"staff without support grant", staffPrincipal(), tenantA, ErrForbidden, "no_support_grant"},
		{"tenant identity on the admin origin", Principal{IdentityID: identity, Scope: ScopeTenant, Origin: OriginAdmin}, tenantA, ErrForbidden, "origin_scope_mismatch"},
		{"platform identity on the app origin", Principal{IdentityID: identity, Scope: ScopePlatform, Origin: OriginApp}, tenantA, ErrForbidden, "origin_scope_mismatch"},
		{"unknown scope", Principal{IdentityID: identity, Scope: ScopeSupport, Origin: OriginApp}, tenantA, ErrForbidden, "origin_scope_mismatch"},
		{"no tenant in the path", tenantPrincipal(), uuid.Nil, ErrNotFound, "no_tenant"},
	}
	for _, c := range cases {
		f := &fakeLoader{tenant: activeMember(GrantAny, "")}
		a := &Authorizer{load: f}
		_, err := a.Require(WithPrincipal(context.Background(), c.p), c.tenant, Need("tenant.device:read"))
		wantDenied(t, c.name, err, c.kind, c.reason)
		if len(f.calls) != 0 {
			t.Errorf("%s: loader called %v", c.name, f.calls)
		}
	}
	f := &fakeLoader{tenant: activeMember(GrantAny, "")}
	a := &Authorizer{load: f}
	d, err := a.Require(WithPrincipal(context.Background(), tenantPrincipal()), tenantA, Need("tenant.device:sync"))
	if err != nil || d.TenantID != tenantA || d.MembershipID != member || d.RoleKey != RoleTenantAdmin || d.RoleRank != 4 {
		t.Errorf("member: %+v, %v", d, err)
	}
	want := []string{"tenant:" + tenantA.String() + ":" + identity.String() + ":tenant.device:sync"}
	if !slices.Equal(f.calls, want) {
		t.Errorf("loader calls = %v, want %v (one query per request, permission of the requirement)", f.calls, want)
	}
	f.err = errors.New("connection refused")
	if _, err := a.Require(WithPrincipal(context.Background(), tenantPrincipal()), tenantA, Need("tenant.device:sync")); err == nil ||
		errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
		t.Errorf("a database error must not look like a decision: %v", err)
	} else if code, _ := Status(err); code != 500 {
		t.Errorf("database error status = %d, want 500", code)
	}
}

func TestDecideTenant(t *testing.T) {
	read := Requirement{Permission: "tenant.audit:read", ReadOnly: true}
	write := Need("tenant.device:sync")
	own := Requirement{Permission: "tenant.device:read", ReadOnly: true, OwnResource: true}
	with := func(f func(a *access)) *access { a := activeMember(GrantAny, ""); f(a); return a }
	cases := []struct {
		name   string
		acc    *access
		req    Requirement
		kind   error
		reason string
	}{
		{"not a member (or another tenant, or no such tenant)", nil, read, ErrNotFound, "not_a_member"},
		{"deleted tenant", with(func(a *access) { a.tenantStatus = TenantDeleted }), read, ErrNotFound, "not_a_member"},
		{"membership locked", with(func(a *access) { a.subjectStatus = "locked" }), read, ErrNotFound, "membership_inactive"},
		{"identity disabled", with(func(a *access) { a.identityStatus = "disabled" }), read, ErrNotFound, "membership_inactive"},
		{"no grant", with(func(a *access) { a.grantScope = "" }), read, ErrForbidden, "no_grant"},
		{"unknown grant scope", with(func(a *access) { a.grantScope = "some" }), read, ErrForbidden, "unknown_grant_scope"},
		{"condition not enforced", with(func(a *access) { a.grantCondition = CondSelfEnroll }), write, ErrForbidden, "condition_not_enforced:self_enroll"},
		{"own grant on a shared operation", with(func(a *access) { a.grantScope = GrantOwn }), read, ErrForbidden, "own_scope_on_shared_operation"},
		{"suspended tenant, write", with(func(a *access) { a.tenantStatus = TenantSuspended }), write, ErrTenantSuspended, "tenant_suspended"},
		{"suspended tenant, write without grant", with(func(a *access) { a.tenantStatus = TenantSuspended; a.grantScope = "" }), write, ErrForbidden, "no_grant"},
		{"deprovisioning tenant, write (P3-T09)", with(func(a *access) { a.tenantStatus = TenantDeprovisioning }), write, ErrTenantSuspended, "tenant_deprovisioning"},
	}
	for _, c := range cases {
		_, err := decideTenant(tenantPrincipal(), tenantA, c.req, c.acc)
		wantDenied(t, c.name, err, c.kind, c.reason)
	}

	if d, err := decideTenant(tenantPrincipal(), tenantA, read, with(func(a *access) { a.tenantStatus = TenantSuspended })); err != nil || d.OwnOnly {
		t.Errorf("suspended tenant, read: %+v, %v (invariant 5 refuses writes only)", d, err)
	}
	d, err := decideTenant(tenantPrincipal(), tenantA, own, with(func(a *access) { a.grantScope = GrantOwn }))
	if err != nil || !d.OwnOnly || d.MembershipID != member {
		t.Errorf("own grant on an x-own-resource operation: %+v, %v", d, err)
	}
	cond := Requirement{Permission: "tenant.enrollment:request", Conditions: []string{CondSelfEnroll}}
	if d, err := decideTenant(tenantPrincipal(), tenantA, cond, with(func(a *access) { a.grantCondition = CondSelfEnroll })); err != nil || d.Condition != CondSelfEnroll {
		t.Errorf("enforced condition: %+v, %v", d, err)
	}
	dual := Requirement{Permission: "tenant.policy:apply", DualControl: true}
	if d, err := decideTenant(tenantPrincipal(), tenantA, dual, activeMember(GrantAny, "")); err != nil || !d.NeedsApproval() {
		t.Errorf("dual control: %+v, %v", d, err)
	}
}

func TestDecidePlatform(t *testing.T) {
	ok := func() *access {
		return &access{subjectID: member, subjectStatus: StatusActive, identityStatus: StatusActive, roleKey: RoleSuperAdmin,
			roleRank: 4, grantScope: GrantAny}
	}
	with := func(f func(a *access)) *access { a := ok(); f(a); return a }
	req := Requirement{Permission: "platform.tenant:read", ReadOnly: true}
	cases := []struct {
		name   string
		acc    *access
		req    Requirement
		reason string
	}{
		{"not a platform user", nil, req, "not_platform_user"},
		{"platform user disabled", with(func(a *access) { a.subjectStatus = "disabled" }), req, "platform_user_inactive"},
		{"identity disabled", with(func(a *access) { a.identityStatus = "disabled" }), req, "platform_user_inactive"},
		{"no grant", with(func(a *access) { a.grantScope = "" }), req, "no_grant"},
		{"condition not enforced", with(func(a *access) { a.grantCondition = CondRestoreOnly }), req, "condition_not_enforced:restore_only"},
		{"own scope on a platform role", with(func(a *access) { a.grantScope = GrantOwn }), Requirement{Permission: "platform.tenant:read", OwnResource: true}, "own_scope_on_platform"},
	}
	for _, c := range cases {
		_, err := decidePlatform(staffPrincipal(), c.req, c.acc)
		wantDenied(t, c.name, err, ErrForbidden, c.reason)
	}
	d, err := decidePlatform(staffPrincipal(), Requirement{Permission: "platform.tenant:delete", DualControl: true}, ok())
	if err != nil || d.PlatformUserID != member || !d.NeedsApproval() || d.TenantID != uuid.Nil {
		t.Errorf("super admin, 2P operation: %+v, %v", d, err)
	}
}

func TestRequirePlatformPrincipals(t *testing.T) {
	for _, p := range []Principal{
		tenantPrincipal(),
		{IdentityID: identity, Scope: ScopePlatform, Origin: OriginApp},
		{IdentityID: identity, Scope: ScopeTenant, Origin: OriginAdmin},
	} {
		f := &fakeLoader{}
		_, err := (&Authorizer{load: f}).Require(WithPrincipal(context.Background(), p), uuid.Nil, Need("platform.tenant:create"))
		wantDenied(t, "platform route, principal "+string(p.Scope)+"/"+string(p.Origin), err, ErrForbidden, "not_platform_principal")
		if len(f.calls) != 0 {
			t.Errorf("loader called %v", f.calls)
		}
	}
	// the tenant ID is ignored for platform permissions (/platform/tenants/{tenantId} has no tenant context)
	f := &fakeLoader{platform: &access{subjectStatus: StatusActive, identityStatus: StatusActive, grantScope: GrantAny}}
	d, err := (&Authorizer{load: f}).Require(WithPrincipal(context.Background(), staffPrincipal()), tenantA,
		Requirement{Permission: "platform.tenant:read", ReadOnly: true})
	if err != nil || d.TenantID != uuid.Nil || len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "platform:") {
		t.Errorf("platform permission with a tenant ID: %+v, %v, calls %v", d, err, f.calls)
	}
}

func TestRequireOperation(t *testing.T) {
	ctx := WithPrincipal(context.Background(), tenantPrincipal())
	f := &fakeLoader{tenant: activeMember(GrantOwn, ""), platform: nil}
	a := &Authorizer{load: f}
	_, err := a.RequireOperation(ctx, "teleportDevice", tenantA)
	wantDenied(t, "operation missing from the spec", err, ErrForbidden, "unknown_operation")

	// Go name (strict middleware) and operationId reach the same operation; x-own-resource lets the own grant in
	for _, name := range []string{"GetDevice", "getDevice"} {
		d, err := a.RequireOperation(ctx, name, tenantA)
		if err != nil || !d.OwnOnly || d.Permission != "tenant.device:read" {
			t.Errorf("%s: %+v, %v", name, d, err)
		}
	}
	// syncDevices has no x-own-resource: an own grant is refused
	_, err = a.RequireOperation(ctx, "SyncDevices", tenantA)
	wantDenied(t, "own grant on syncDevices", err, ErrForbidden, "own_scope_on_shared_operation")

	// a platform operation never takes the tenant ID as context
	f.calls = nil
	_, _ = a.RequireOperation(WithPrincipal(context.Background(), staffPrincipal()), "GetPlatformTenant", tenantA)
	if len(f.calls) != 1 || f.calls[0] != "platform:"+identity.String()+":platform.tenant:read" {
		t.Errorf("getPlatformTenant loader calls = %v", f.calls)
	}
	// the write flag comes from the method: renameDevice (PATCH) is refused while the tenant is suspended
	f.tenant = activeMember(GrantAny, "")
	f.tenant.tenantStatus = TenantSuspended
	_, err = a.RequireOperation(ctx, "renameDevice", tenantA)
	wantDenied(t, "PATCH while suspended", err, ErrTenantSuspended, "tenant_suspended")
	if _, err := a.RequireOperation(ctx, "listDevices", tenantA); err != nil {
		t.Errorf("GET while suspended: %v", err)
	}
}

func TestRequireApprover(t *testing.T) {
	f := &fakeLoader{platform: &access{subjectStatus: StatusActive, identityStatus: StatusActive, grantScope: GrantAny}}
	a := &Authorizer{load: f}
	ctx := WithPrincipal(context.Background(), staffPrincipal())
	req := Requirement{Permission: "platform.tenant:delete", DualControl: true}
	_, err := a.RequireApprover(ctx, uuid.Nil, identity, req)
	wantDenied(t, "requester approving its own request", err, ErrForbidden, "self_approval")
	if len(f.calls) != 0 {
		t.Errorf("self approval must be refused before any query: %v", f.calls)
	}
	d, err := a.RequireApprover(ctx, uuid.Nil, uuid.New(), req)
	if err != nil || d.NeedsApproval() {
		t.Errorf("second person: %+v, %v (approving never asks for another approval)", d, err)
	}
}

func TestDecisionHooks(t *testing.T) {
	other := uuid.New()
	shared := Decision{MembershipID: member}
	ownOnly := Decision{MembershipID: member, OwnOnly: true}
	if err := shared.CheckOwner(&other, true); err != nil {
		t.Errorf("scope any covers every resource: %v", err)
	}
	if err := ownOnly.CheckOwner(&member, false); err != nil {
		t.Errorf("own untagged device: %v", err)
	}
	for name, c := range map[string]struct {
		owner  *uuid.UUID
		tagged bool
	}{"someone else's": {&other, false}, "own but tagged (invariant 3b)": {&member, true}, "no owner": {nil, false}} {
		wantDenied(t, name, ownOnly.CheckOwner(c.owner, c.tagged), ErrNotFound, "not_own_resource")
	}
	if err := (Decision{OwnOnly: true}).CheckOwner(&uuid.Nil, false); err == nil {
		t.Error("an own-only decision without membership must not match the nil UUID")
	}
	if id, ok := ownOnly.OwnerFilter(); !ok || id != member {
		t.Errorf("OwnerFilter = %s, %v", id, ok)
	}
	if _, ok := shared.OwnerFilter(); ok {
		t.Error("OwnerFilter of a scope any decision must not filter")
	}
}

func TestStatus(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
		pc   string
	}{
		{nil, 200, ""},
		{deny(ErrUnauthenticated, "x"), 401, "unauthenticated"},
		{deny(ErrNotFound, "x"), 404, "not_found"},
		{deny(ErrForbidden, "x"), 403, "forbidden"},
		{deny(ErrTenantSuspended, "x"), 403, "tenant_suspended"},
		{deny(ErrInvalid, "x"), 422, "validation_failed"},
		{errors.New("boom"), 500, "internal_error"},
	} {
		if code, pc := Status(c.err); code != c.code || pc != c.pc {
			t.Errorf("Status(%v) = %d %q, want %d %q", c.err, code, pc, c.code, c.pc)
		}
	}
	if msg := deny(ErrForbidden, "no_grant").Error(); !strings.Contains(msg, "no_grant") {
		t.Errorf("Denial message %q lacks the reason", msg)
	}
}

// TestOperationTable checks the generated table against the rules of §13.1 that the spec-lint also enforces — so a
// stale or hand-edited operations_gen.go fails here too.
func TestOperationTable(t *testing.T) {
	ops := Operations()
	if len(ops) == 0 {
		t.Fatal("no operations")
	}
	if !sort.SliceIsSorted(ops, func(i, j int) bool { return ops[i].ID < ops[j].ID }) {
		t.Error("operations are not sorted by operationId")
	}
	seen := map[string]bool{}
	for _, o := range ops {
		switch {
		case seen[o.ID]:
			t.Errorf("%s: duplicate operationId", o.ID)
		case o.Method != strings.ToUpper(o.Method) || o.Path == "" || o.Path[0] != '/':
			t.Errorf("%s: method %q path %q", o.ID, o.Method, o.Path)
		case !auditAction.MatchString(o.AuditAction):
			t.Errorf("%s: x-audit-action %q (§13.1, P2-T08)", o.ID, o.AuditAction)
		}
		seen[o.ID] = true
		switch o.Permission.Scope() {
		case ScopeTenant:
			if !o.TenantScoped() {
				t.Errorf("%s: tenant permission on %s", o.ID, o.Path)
			}
		case ScopePlatform:
			if !strings.HasPrefix(o.Path, "/platform/") || o.OwnResource {
				t.Errorf("%s: platform permission on %s (own=%v)", o.ID, o.Path, o.OwnResource)
			}
		default:
			if !slices.Contains([]Permission{Public, Authenticated, Internal}, o.Permission) || o.OwnResource || o.DualControl || o.TenantScoped() {
				t.Errorf("%s: special permission %q with flags or on a tenant path", o.ID, o.Permission)
			}
		}
		if got, ok := OperationByID(goName(o.ID)); !ok || !reflect.DeepEqual(got, o) {
			t.Errorf("%s: not found by its Go name %s", o.ID, goName(o.ID))
		}
	}
	if _, ok := OperationByID(""); ok {
		t.Error("empty operation name found")
	}
	ops[0].ID = "changed"
	if Operations()[0].ID == "changed" {
		t.Error("Operations must return a copy")
	}
}

// TestOperationConditions — x-conditions of the spec reach the Requirement (P3-T04a): the conditional grant of the
// Platform Operator on platform.approval:decide ("chỉ cho restore", §8.5) is granted on the approve/reject operations
// that declare restore_only — with the condition in the decision for the service to enforce — and refused anywhere it
// is not declared.
func TestOperationConditions(t *testing.T) {
	p := Principal{IdentityID: uuid.New(), Scope: ScopePlatform, Origin: OriginAdmin}
	acc := &access{subjectID: uuid.New(), subjectStatus: StatusActive, identityStatus: StatusActive,
		roleKey: RolePlatformOperator, roleRank: 3, grantScope: GrantAny, grantCondition: CondRestoreOnly}
	for _, id := range []string{"approvePlatformApproval", "rejectPlatformApproval"} {
		op, ok := OperationByID(id)
		if !ok || !slices.Equal(op.Requirement().Conditions, []string{CondRestoreOnly}) {
			t.Fatalf("%s: conditions %v (found %v)", id, op.Conditions, ok)
		}
		d, err := decidePlatform(p, op.Requirement(), acc)
		if err != nil || d.Condition != CondRestoreOnly {
			t.Errorf("%s: decision %+v, %v — want a grant carrying restore_only", id, d, err)
		}
		req := op.Requirement()
		req.Conditions = nil
		var den *Denial
		if _, err := decidePlatform(p, req, acc); !errors.As(err, &den) || den.Reason != "condition_not_enforced:"+CondRestoreOnly {
			t.Errorf("%s without x-conditions: %v — want condition_not_enforced", id, err)
		}
	}
	for _, o := range Operations() {
		if len(o.Conditions) > 0 && o.ID != "approvePlatformApproval" && o.ID != "rejectPlatformApproval" {
			t.Errorf("%s declares conditions %v — extend this test", o.ID, o.Conditions)
		}
	}
}
