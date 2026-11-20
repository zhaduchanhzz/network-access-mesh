//go:build mgtestfixture

package authzmatrix_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// TestSupportGrantDiagnostics — the Staff column (G) of the tenant.diagnostics:* rows of §8.6 through the composed
// API (P5-T08): two platform staff members hold a live Support Access Grant into tenant A (support_operator, and
// support_admin through break-glass) and send both diagnostics operations on A, on B (no grant) and on a tenant that
// does not exist. Expected: on B and the missing tenant 403 no_support_grant (a denial in the platform's trail); on A
// 200 — the instance state of A, the diagnosis of two devices of A —, and 404 for a diagnosis that names devices of B
// on A's path (the devices are looked up in the tenant of the path only — a denied event in A as the support actor).
// Platform staff WITHOUT a grant are refused by TestAuthzMatrix (no_support_grant), every tenant role there too.
func TestSupportGrantDiagnostics(t *testing.T) {
	m := &matrix{matrixWorld: newMatrixWorld(t), byFixture: map[*sessionfixture.Actor]*actor{}}
	staff := []supportStaff{m.newSupportStaff(t, authz.RoleSupportOperator), m.newSupportStaff(t, authz.RoleSupportAdmin)}
	grantOf := map[*actor]uuid.UUID{}
	ofB := `{"source_device_id":"` + m.obj.devEU["B"].String() + `","target_device_id":"` + m.obj.devOther["B"].String() + `"}`
	ops := 0
	for _, op := range authz.Operations() {
		if !strings.HasPrefix(string(op.Permission), "tenant.diagnostics:") {
			continue
		}
		ops++
		for _, s := range staff {
			grantOf[s.actor] = s.grant
			for _, tc := range []string{"A", "B", "missing"} {
				bodies := []string{""}
				if op.Method == http.MethodPost && tc == "A" {
					bodies = []string{"", ofB} // "" ⇒ the recipe's body (devices of the path's tenant)
				}
				for _, body := range bodies {
					rcp := recipes[op.ID]
					if body != "" {
						rcp.bodyOf = func(*matrix, *call) string { return body }
					}
					c := &call{actor: s.actor, op: op, recipe: rcp, host: s.host, session: s.session, tenantCase: tc}
					m.place(t, c)
					c.exp = m.expectStaff(t, c)
					if body != "" {
						c.exp = expectation{status: http.StatusNotFound, code: gen.ProblemCodeNotFound, decision: decGrant,
							reason: string(gen.ProblemCodeNotFound)}
					}
					m.calls = append(m.calls, c)
				}
			}
		}
	}
	if ops != 2 {
		t.Fatalf("the spec has %d diagnostics operations, want 2", ops)
	}
	m.run(m.calls)
	var granted, refused int
	for _, c := range m.calls {
		bad := m.check(t, c)
		if d, ok := m.rec.get(c.reqs); ok && c.exp.decision == decGrant && d.decision.SupportGrantID != grantOf[c.actor] {
			bad = append(bad, "decision grant "+d.decision.SupportGrantID.String()+", want "+grantOf[c.actor].String())
		}
		bad = append(bad, m.checkStaffAudit(t, c, grantOf[c.actor])...)
		if c.exp.status == http.StatusOK && c.op.Method == http.MethodGet {
			var got gen.TenantDiagnostics
			if err := json.Unmarshal(c.rec.Body.Bytes(), &got); err != nil || got.CheckedAt.IsZero() ||
				got.Devices.Total != 3 || len(got.Unavailable) == 0 {
				bad = append(bad, "instance state of A: "+c.rec.Body.String())
			}
		}
		if c.exp.status == http.StatusOK && c.op.Method == http.MethodPost {
			var got gen.ConnectivityDiagnosis
			if err := json.Unmarshal(c.rec.Body.Bytes(), &got); err != nil || got.PathObservable ||
				got.Source.Id != m.obj.devEU["A"] || got.Target.Device == nil || got.Target.Device.Id != m.obj.devOther["A"] ||
				got.Verdict != gen.ConnectivityDiagnosisVerdictBlocked || len(got.Commands) == 0 {
				bad = append(bad, "diagnosis on A: "+c.rec.Body.String())
			}
		}
		if c.exp.decision == decDeny {
			refused++
		} else {
			granted++
		}
		for _, b := range bad {
			t.Errorf("%s: %s", c, b)
		}
	}
	if granted == 0 || refused == 0 {
		t.Fatalf("degenerate: %d granted, %d refused", granted, refused)
	}
	t.Logf("support staff × diagnostics: %d requests — %d answered under the grant, %d refused by layer 1", len(m.calls),
		granted, refused)
}
