package authz

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// TestSuspensionGuardCoversEveryTenantWrite — §8.4 invariant 5 (P3-T08): every operation of the spec is decided through
// RequireOperation (the path of the Authz hook of internal/httpapi) for a caller that holds the operation's grant —
// scope any, or own on an x-own-resource operation, with the operation's own condition when it declares one:
//
//   - every operation of the tenant context (TenantScoped) carries a tenant permission, so it is decided against the
//     tenant's membership and status; while the tenant is suspended its writes (a method other than GET/HEAD) are
//     refused with tenant_suspended and its reads are granted; with the tenant active the same call is granted — the
//     refusal is the suspension's and nothing else;
//   - a platform operation never reads the tenant's status (platform staff are unaffected, including on
//     /platform/tenants/{tenantId}/…).
//
// The table is generated from api/openapi.yaml (operations_gen.go): an operation added later — web-auth/claim and
// enrollment/* of P4-T06 — is covered without touching this test or any handler.
func TestSuspensionGuardCoversEveryTenantWrite(t *testing.T) {
	var writes, reads, platform []string
	for _, op := range Operations() {
		write := op.Method != http.MethodGet && op.Method != http.MethodHead
		switch {
		case op.TenantScoped():
			if op.Permission.Scope() != ScopeTenant {
				t.Errorf("%s %s: x-permission %s is not a tenant permission — the suspension guard would not apply", op.Method,
					op.Path, op.Permission)
				continue
			}
			for _, grant := range grantsOf(op) {
				for _, status := range []string{TenantSuspended, "active"} {
					acc := activeMember(grant, "")
					acc.tenantStatus = status
					if len(op.Conditions) > 0 {
						acc.grantCondition = op.Conditions[0]
					}
					a := &Authorizer{load: &fakeLoader{tenant: acc}}
					_, err := a.RequireOperation(WithPrincipal(context.Background(), tenantPrincipal()), op.ID, tenantA)
					what := op.ID + " (grant " + grant + ", tenant " + status + ")"
					switch {
					case status == TenantSuspended && write:
						wantDenied(t, what, err, ErrTenantSuspended, "tenant_suspended")
					case err != nil:
						t.Errorf("%s: %v, want a grant", what, err)
					}
				}
			}
			if write {
				writes = append(writes, op.ID)
			} else {
				reads = append(reads, op.ID)
			}
		case op.Permission.Scope() == ScopePlatform:
			acc := activeMember(GrantAny, "")
			acc.tenantStatus = TenantSuspended
			f := &fakeLoader{tenant: acc, platform: &access{subjectStatus: StatusActive, identityStatus: StatusActive,
				roleKey: RoleSuperAdmin, grantScope: GrantAny}}
			if len(op.Conditions) > 0 {
				f.platform.grantCondition = op.Conditions[0]
			}
			_, err := (&Authorizer{load: f}).RequireOperation(WithPrincipal(context.Background(), staffPrincipal()), op.ID, tenantA)
			if err != nil || len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "platform:") {
				t.Errorf("%s: platform operation decided with %v, loader calls %v — the tenant's status must not matter", op.ID,
					err, f.calls)
			}
			platform = append(platform, op.ID)
		case op.Path == "/tenants/{tenantId}" || strings.HasPrefix(op.Path, "/tenants/{tenantId}/"):
			t.Errorf("%s: special permission %s on a tenant path", op.ID, op.Permission)
		}
	}
	if len(writes) == 0 || len(reads) == 0 || len(platform) == 0 {
		t.Fatalf("the spec has no tenant write, tenant read or platform operation: %v %v %v", writes, reads, platform)
	}
	for _, id := range []string{"syncDevices", "renameDevice", "createTenantInvitation"} {
		if !slices.Contains(writes, id) {
			t.Errorf("%s is not among the guarded writes %v", id, writes)
		}
	}
	for _, id := range []string{"suspendPlatformTenant", "resumePlatformTenant", "getPlatformTenant"} {
		if !slices.Contains(platform, id) {
			t.Errorf("%s is not among the platform operations %v", id, platform)
		}
	}
	t.Logf("suspended tenant: %d writes refused (tenant_suspended), %d reads granted; %d platform operations unaffected",
		len(writes), len(reads), len(platform))
}

// grantsOf lists the grant scopes that may call the operation: any, and own on an x-own-resource operation.
func grantsOf(op Operation) []string {
	if op.OwnResource {
		return []string{GrantAny, GrantOwn}
	}
	return []string{GrantAny}
}
