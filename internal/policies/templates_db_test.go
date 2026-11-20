package policies

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// device inserts a device of the inventory (device_inventory_cache) of tenant ten.
func (f *versionsFx) device(t *testing.T, ten *tenantFx, node int64, owner *uuid.UUID, tags []string, extra string) {
	t.Helper()
	f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, ip_addresses,
			owner_membership_id, tags) VALUES ($1, $2, $3, $4, ARRAY['100.64.0.1'::inet], $5, $6)`,
		ten.id, ten.instance, node, "mkey:"+randomHex(8), owner, tags)
	if extra != "" {
		f.exec(t, `UPDATE device_inventory_cache SET `+extra+` WHERE tenant_id = $1 AND headscale_node_id = $2`, ten.id, node)
	}
}

// TestTemplateServiceAndGeneratedTests — P5-T01 with the tables of a tenant:
//   - RenderTemplate renders a template over the CALLER's tables: its fragment, and the report of the fragment with
//     the tests it would generate from the inventory; a group of another tenant ⇒ 422 not_found on its parameter;
//     nothing is stored;
//   - the inventory the tests read (ListPolicyNodes): a removed device, a device being deleted and a device without
//     an address are not there; a tagged device belongs to its tags, not to its owner;
//   - validate sends the generated block with the rendered policy (CheckPolicy) and records it in the report; a
//     refusal of the tests by Headscale is the finding check/tests_failed (the upstream text is never shown).
func TestTemplateServiceAndGeneratedTests(t *testing.T) {
	f := newVersionsFixture(t)
	group, tag, res := f.world(t, f.a)
	ctx := context.Background()
	admin, endUs := f.a.admin, f.a.endUs
	f.device(t, f.a, 1, &admin, []string{}, "")
	// tagged: tag:web, not endUs
	f.device(t, f.a, 2, &endUs, []string{"tag:web"}, "")
	// removed
	f.device(t, f.a, 3, &endUs, []string{}, "removed_at = now()")
	// being deleted
	f.device(t, f.a, 4, &endUs, []string{}, "revocation_kind = 'delete', revocation_state = 'pending'")
	// no address
	f.device(t, f.a, 5, &endUs, []string{}, "ip_addresses = '{}'")
	// expired: still a node
	f.device(t, f.a, 6, &endUs, []string{}, "revocation_kind = 'expire', revocation_state = 'applied'")
	var in *RenderInputs
	if err := f.api.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
		var err error
		in, err = loadRenderInputs(ctx, q, f.a.id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(in.Nodes) != 3 {
		t.Fatalf("inventory %+v", in.Nodes)
	}

	r, err := f.vs.RenderTemplate(ctx, f.a.id, TemplateRequest{TemplateID: TemplateGroupToResource,
		Params: TemplateParams{GroupID: group.String(), ResourceID: res.String(), Ports: []string{"tcp:443"}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != TemplateAppend || r.Version != 1 || len(r.Source.Grants) != 1 || r.Report.Blocking() ||
		len(r.Report.Tests) != 1 || r.Report.Tests[0].Src != "group:eng" || r.Report.Tests[0].Accept[0] != "db:443" {
		t.Fatalf("render: %+v", r)
	}
	_, err = f.vs.RenderTemplate(ctx, f.b.id, TemplateRequest{TemplateID: TemplateGroupToResource,
		Params: TemplateParams{GroupID: group.String(), ResourceID: res.String(), Ports: []string{"tcp:443"}}})
	wantPolErr(t, "a group of another tenant", err, ErrPolicyInvalid, "not_found")
	if pe, _ := AsPolicyError(err); pe.Field != "params.group_id" {
		t.Fatalf("field %q", pe.Field)
	}

	// validate: the block is sent and reported
	cctx, a := f.as(t, f.a, f.a.admin, ActionPolicyCreate)
	src := json.RawMessage(`{"grants":[{"src":[{"type":"group","ref":"` + group.String() + `"}],"dst":[{"type":"tag","ref":"` +
		tag.String() + `"}],"ip":["tcp:443"]},{"src":[{"type":"user","ref":"` + endUs.String() + `"}],"dst":[{"type":"resource","ref":"` +
		res.String() + `"}],"ip":["tcp:5432"]}]}`)
	v, err := f.vs.Create(cctx, f.a.id, a, NewVersion{Source: src}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, err = f.vs.Validate(cctx, f.a.id, v.ID, a, v.ETag()); err != nil || v.State != VersionValidated {
		t.Fatalf("validate: %v %+v", err, v.ValidationReport)
	}
	rep := *v.ValidationReport
	// grant 0: eng (admin's device) → tag:web (the tagged device); grant 1: endUs has an expired untagged device (6)
	if len(rep.Tests) != 2 || rep.Tests[0].Src != "group:eng" || rep.Tests[0].Accept[0] != "tag:web:443" ||
		rep.Tests[0].Deny[0] != "tag:web:65535" || rep.Tests[1].Src != "mg-"+endUs.String()+"@" || rep.Tests[1].Accept[0] != "db:5432" {
		t.Fatalf("report tests %+v", rep.Tests)
	}
	// Headscale refuses the generated tests ⇒ check failed, finding tests_failed, back to draft
	f.a.hs.mu.Lock()
	f.a.hs.checkErr = &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindPolicyRejected,
		Upstream: "test(s) failed:\nmg-x@ -> db:5432: expected ALLOWED, got DENIED"}
	f.a.hs.mu.Unlock()
	t.Cleanup(func() { f.a.hs.mu.Lock(); f.a.hs.checkErr = nil; f.a.hs.mu.Unlock() })
	if v, err = f.vs.Validate(cctx, f.a.id, v.ID, a, v.ETag()); err != nil || v.State != VersionDraft {
		t.Fatalf("validate with refused tests: %v %s", err, v.State)
	}
	rep = *v.ValidationReport
	if rep.Check != ResultFailed || len(rep.Errors) != 1 || rep.Errors[0].Code != "tests_failed" ||
		rep.Errors[0].Rule != RuleCheck || strings.Contains(rep.Errors[0].Message, "expected ALLOWED") || strings.Contains(rep.Errors[0].Message, "mg-x@") {
		t.Fatalf("refused tests: %+v", rep.Errors)
	}
}
