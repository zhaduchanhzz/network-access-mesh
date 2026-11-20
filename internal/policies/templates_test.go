package policies

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
)

// validParams are parameters of every template over testGenWorld.
func validParams(w renderWorld, lab uuid.UUID, t Template) TemplateParams {
	var p TemplateParams
	for _, d := range t.Params {
		switch d.Name {
		case ParamGroupID:
			p.GroupID = w.eng.String()
		case ParamTagID:
			p.TagID = w.router.String()
		case ParamResourceID:
			p.ResourceID = lab.String()
		case ParamPorts:
			p.Ports = d.Default
		}
	}
	return p
}

// TestTemplateCatalog — the catalog is data: unique ids, a version, known modes, parameter kinds and notes (the
// OpenAPI enums), a least-privilege default for every ports parameter; Templates returns copies.
func TestTemplateCatalog(t *testing.T) {
	ids := map[string]bool{}
	kinds := map[string]string{ParamGroupID: ParamKindGroup, ParamTagID: ParamKindTag, ParamResourceID: ParamKindResource,
		ParamPorts: ParamKindPorts}
	notes := []string{NoteTestsSelfNotAsserted, NoteTestsViaNotAsserted, NoteRoutesApproval, NoteSelfLargeTenant, NoteReplacesDraft}
	for _, tm := range Templates() {
		if ids[tm.ID] || tm.Version < 1 || (tm.Mode != TemplateAppend && tm.Mode != TemplateReplace) || tm.Params == nil || tm.Notes == nil {
			t.Errorf("template %+v", tm)
		}
		ids[tm.ID] = true
		for _, p := range tm.Params {
			if kinds[p.Name] != p.Kind || !p.Required || (p.Kind == ParamKindPorts) != (len(p.Default) > 0) {
				t.Errorf("%s: parameter %+v", tm.ID, p)
			}
			for _, d := range p.Default {
				if _, ports := splitIPProto(d); ports == "*" || !ipRE.MatchString(d) {
					t.Errorf("%s: default %q is not least privilege", tm.ID, d)
				}
			}
		}
		for _, n := range tm.Notes {
			if !slices.Contains(notes, n) {
				t.Errorf("%s: note %q", tm.ID, n)
			}
		}
	}
	if len(ids) != 6 {
		t.Fatalf("catalog %v", ids)
	}
	a := Templates()
	a[1].Notes[0] = "changed"
	if Templates()[1].Notes[0] == "changed" {
		t.Fatal("Templates returns the catalog itself")
	}
}

// TestTemplatesRenderAndLint — every template with valid parameters builds the same fragment twice (canonical bytes
// equal), renders over the tenant's tables without a blocking finding and without any acknowledgement (least
// privilege: no wildcard destination, via on the internet), alone and added to an existing draft; the via templates
// carry the V-24 Info finding, own-devices the autogroup:self one; deny-all renders the baseline deny-all.
func TestTemplatesRenderAndLint(t *testing.T) {
	w, _, lab := testGenWorld()
	existing := mustSource(t, `{"grants":[{"src":[`+p("user", w.alice)+`],"dst":[`+p("resource", w.db)+`],"ip":["tcp:5432"]}]}`)
	for _, tm := range Templates() {
		req := TemplateRequest{TemplateID: tm.ID, Params: validParams(w, lab, tm)}
		got, src, err := BuildTemplate(req)
		if err != nil || got.ID != tm.ID {
			t.Fatalf("%s: %v", tm.ID, err)
		}
		_, src2, _ := BuildTemplate(req)
		c1, _, _ := src.Canonical()
		c2, _, _ := src2.Canonical()
		if string(c1) != string(c2) {
			t.Fatalf("%s: not deterministic", tm.ID)
		}
		r := RenderTyped(src, "x", w.in)
		if r.Report.Blocking() || len(r.Report.Warnings) != 0 {
			t.Errorf("%s: %+v %+v", tm.ID, r.Report.Errors, r.Report.Warnings)
		}
		info := codes(r.Report.Info)
		switch tm.ID {
		case TemplateExitNode, TemplateSubnetRouter:
			if !slices.Equal(info, []string{"tests:via_not_asserted"}) || r.Report.Tests[0].Skipped != TestSkipVia {
				t.Errorf("%s: %v %+v", tm.ID, info, r.Report.Tests)
			}
		case TemplateOwnDevices:
			if !slices.Equal(info, []string{"tests:self_not_asserted"}) || r.Report.Tests[0].Skipped != TestSkipSelf {
				t.Errorf("%s: %v %+v", tm.ID, info, r.Report.Tests)
			}
		case TemplateGroupToResource, TemplateAdminsToDevices:
			if len(info) != 0 || r.Report.Tests[0].Skipped != "" {
				t.Errorf("%s: %v %+v", tm.ID, info, r.Report.Tests)
			}
		case TemplateDenyAll:
			// the baseline of provisioning, with the tenant's catalog as the core renders it: the same policy
			base, err := Lint(templates.BootstrapPolicy)
			if err == nil {
				base, err = RenderCatalog(base, w.in.Catalog)
			}
			var x, y map[string]any
			if err != nil || json.Unmarshal([]byte(r.Document.Applied), &x) != nil || json.Unmarshal([]byte(base.Applied), &y) != nil ||
				!reflect.DeepEqual(x, y) || tm.Mode != TemplateReplace {
				t.Errorf("deny-all renders %q, the baseline is %q (%v)", r.Document.Applied, base.Applied, err)
			}
		}
		if tm.Mode == TemplateAppend {
			merged := existing
			merged.Grants = append(slices.Clone(existing.Grants), src.Grants...)
			if m := RenderTyped(merged, "x", w.in); m.Report.Blocking() {
				t.Errorf("%s added to a draft: %+v", tm.ID, m.Report.Errors)
			}
		}
	}
	// the fragment of group-to-resource, exactly
	_, src, _ := BuildTemplate(TemplateRequest{TemplateID: TemplateGroupToResource,
		Params: TemplateParams{GroupID: w.eng.String(), ResourceID: lab.String(), Ports: []string{"tcp:443", "tcp:8443"}}})
	b, _ := json.Marshal(src)
	want := `{"grants":[{"src":[{"type":"group","ref":"` + w.eng.String() + `"}],"dst":[{"type":"resource","ref":"` + lab.String() +
		`"}],"ip":["tcp:443","tcp:8443"]}],"ssh":[]}`
	if string(b) != want {
		t.Fatalf("fragment %s\nwant %s", b, want)
	}
}

// TestBuildTemplateRefusals — the request is checked against the catalog before any table is read.
func TestBuildTemplateRefusals(t *testing.T) {
	g, tag := uuid.NewString(), uuid.NewString()
	v2 := 2
	for name, tc := range map[string]struct {
		req          TemplateRequest
		field, cause string
	}{
		"unknown template": {TemplateRequest{TemplateID: "allow-all"}, "template_id", "unknown_template"},
		"other version":    {TemplateRequest{TemplateID: TemplateDenyAll, Version: &v2}, "version", "unknown_version"},
		"missing group":    {TemplateRequest{TemplateID: TemplateExitNode, Params: TemplateParams{TagID: tag}}, "params.group_id", "required"},
		"extra parameter":  {TemplateRequest{TemplateID: TemplateDenyAll, Params: TemplateParams{GroupID: g}}, "params.group_id", "not_a_parameter"},
		"ports on exit":    {TemplateRequest{TemplateID: TemplateExitNode, Params: TemplateParams{GroupID: g, TagID: tag, Ports: []string{"tcp:1"}}}, "params.ports", "not_a_parameter"},
		"not an id":        {TemplateRequest{TemplateID: TemplateAdminsToDevices, Params: TemplateParams{GroupID: "eng", Ports: []string{"tcp:22"}}}, "params.group_id", "invalid_id"},
		"no port":          {TemplateRequest{TemplateID: TemplateAdminsToDevices, Params: TemplateParams{GroupID: g, Ports: []string{}}}, "params.ports", "invalid_count"},
		"wildcard port":    {TemplateRequest{TemplateID: TemplateAdminsToDevices, Params: TemplateParams{GroupID: g, Ports: []string{"tcp:22", "*"}}}, "params.ports[1]", "invalid_port"},
		"tcp wildcard":     {TemplateRequest{TemplateID: TemplateOwnDevices, Params: TemplateParams{Ports: []string{"tcp:*"}}}, "params.ports[0]", "invalid_port"},
		"bad port":         {TemplateRequest{TemplateID: TemplateOwnDevices, Params: TemplateParams{Ports: []string{"ssh"}}}, "params.ports[0]", "invalid_port"},
		"too many ports": {TemplateRequest{TemplateID: TemplateOwnDevices, Params: TemplateParams{Ports: []string{"1", "2", "3", "4", "5", "6",
			"7", "8", "9", "10", "11"}}}, "params.ports", "invalid_count"},
	} {
		_, _, err := BuildTemplate(tc.req)
		pe, ok := AsPolicyError(err)
		if !ok || pe.Field != tc.field || pe.Reason != tc.cause {
			t.Errorf("%s: %v (field %v)", name, err, pe)
		}
	}
	// references of the tenant are checked by RenderTemplate: one the tables do not hold ⇒ not_found on its parameter
	w, _, _ := testGenWorld()
	if err := templateRefsExist(TemplateParams{GroupID: w.eng.String(), TagID: uuid.NewString()}, w.in); err == nil {
		t.Fatal("unknown tag accepted")
	} else if pe, _ := AsPolicyError(err); pe.Field != "params.tag_id" || pe.Reason != "not_found" {
		t.Fatalf("unknown tag: %v", err)
	}
	if err := templateRefsExist(TemplateParams{GroupID: w.eng.String(), ResourceID: w.db.String(), TagID: w.web.String()}, w.in); err != nil {
		t.Fatal(err)
	}
}
