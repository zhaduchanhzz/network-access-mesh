//go:build mgtestfixture

package authzmatrix_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
)

// TestSuspendedTenantMatrix — §8.4 invariant 5 through the composed API (P3-T08): tenant A is suspended, then every
// operation of the tenant context is sent by every tenant role of A on its own tenant (every object case of the
// matrix), and every platform operation on tenants by every platform role. The expectation is the one of
// TestAuthzMatrix (§8.5/§8.6, mounted handlers) except for one rule: a write (method other than GET/HEAD) that the
// role would be granted is refused with 403 tenant_suspended by layer 1 — before the handler, audited in A as a denial
// — and nothing else changes: reads go on, refusals for another reason keep their reason (a role without the grant
// still gets forbidden), platform staff are unaffected. The list comes from the spec (authz.Operations): an operation
// added later is covered without changing this test.
func TestSuspendedTenantMatrix(t *testing.T) {
	m := newMatrix(t)
	m.Exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, m.A.ID)
	var refused, readsGranted, platformCalls int
	for _, op := range authz.Operations() {
		unsafe := op.Method != http.MethodGet && op.Method != http.MethodHead
		kind, _ := objectKindOf(op)
		platformOnTenants := op.Permission.Scope() == authz.ScopePlatform && (kind == objTenant || op.ID == "listPlatformTenants")
		for _, a := range m.actors {
			var tc string
			switch {
			case op.TenantScoped() && a.kind == kindTenant && a.fx.Tenant == m.A:
				tc = "own"
			case platformOnTenants && a.kind == kindPlatform:
			default:
				continue
			}
			for _, oc := range m.objectCases(op, a, tc) {
				c := &call{actor: a, op: op, recipe: recipes[op.ID], host: a.host, session: a.session, tenantCase: tc, objectCase: oc}
				m.place(t, c)
				c.exp = m.expect(c)
				switch {
				case op.TenantScoped() && unsafe && c.exp.decision == decGrant:
					c.exp = expectation{status: http.StatusForbidden, code: gen.ProblemCodeTenantSuspended, decision: decDeny,
						denyKind: authz.ErrTenantSuspended, reason: "tenant_suspended"}
					refused++
				case op.TenantScoped() && c.exp.decision == decGrant:
					readsGranted++
				case !op.TenantScoped():
					platformCalls++
				}
				m.calls = append(m.calls, c)
			}
		}
	}
	m.run(m.calls)
	var bad []string
	for _, c := range m.calls {
		if errs := m.check(t, c); len(errs) > 0 {
			bad = append(bad, c.String()+": "+strings.Join(errs, "; "))
		}
	}
	for i, b := range bad {
		if i == 20 {
			t.Errorf("… %d more", len(bad)-20)
			break
		}
		t.Error(b)
	}
	m.checkAudit(t)
	m.checkEnrollmentObjects(t)   // every enrollment write was refused: no request moved
	m.checkEnrollmentHeadscale(t) // and none reached Headscale (no granted createEnrollmentKey: zero keys expected)
	if refused == 0 || readsGranted == 0 || platformCalls == 0 {
		t.Fatalf("degenerate matrix: %d writes refused, %d reads granted, %d platform calls", refused, readsGranted, platformCalls)
	}
	t.Logf("suspended tenant A: %d requests — %d granted writes refused with tenant_suspended, %d granted reads answered, "+
		"%d platform requests on tenants unaffected; %d wrong", len(m.calls), refused, readsGranted, platformCalls, len(bad))
}
