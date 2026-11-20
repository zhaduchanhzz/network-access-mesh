package policies

import (
	"context"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Policy templates (P5-T01, §7.2): least-privilege starting points of the Portal's editor. A template is DATA — an id,
// a version, its parameters and the notes the editor shows — plus a pure function from its parameters to a fragment of
// PolicySource (typed principals only). The same id, version and parameters always give the same fragment; the
// fragment is linted like any draft (the report of POST /policies/templates/render) and the editor adds it to the draft
// it edits, saved by PATCH as any change — nothing is stored or sent to Headscale here.
//
// Changing what a template produces means a new Version (the editor shows which version a fragment came from); the
// catalog only ever holds the current version of each template.

// Template ids (PolicyTemplate.id of api/openapi.yaml — the editor's texts are keyed by them).
const (
	TemplateDenyAll         = "deny-all"
	TemplateOwnDevices      = "own-devices"
	TemplateGroupToResource = "group-to-resource"
	TemplateAdminsToDevices = "admins-to-devices"
	TemplateExitNode        = "exit-node"
	TemplateSubnetRouter    = "subnet-router"
)

// Template modes: append — the fragment's rules are added to the draft; replace — the draft becomes the fragment.
const (
	TemplateAppend  = "append"
	TemplateReplace = "replace"
)

// Parameter names (PolicyTemplateParams) and kinds.
const (
	ParamGroupID    = "group_id"
	ParamTagID      = "tag_id"
	ParamResourceID = "resource_id"
	ParamPorts      = "ports"

	ParamKindGroup    = "group"
	ParamKindTag      = "tag"
	ParamKindResource = "resource"
	ParamKindPorts    = "ports"
)

// Notes of a template (codes; the editor words them).
const (
	NoteTestsSelfNotAsserted = "tests_self_not_asserted" // V-24
	NoteTestsViaNotAsserted  = "tests_via_not_asserted"  // V-24
	NoteRoutesApproval       = "routes_need_approval"    // the router's routes are approved separately (routes API)
	NoteSelfLargeTenant      = "self_large_tenant"       // L8 — HS-08
	NoteReplacesDraft        = "replaces_draft"
)

// MaxTemplatePorts bounds the ports parameter.
const MaxTemplatePorts = 10

// TemplateParam describes one parameter of a template.
type TemplateParam struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Required bool     `json:"required"`
	Default  []string `json:"default,omitempty"` // ports: the least-privilege suggestion
}

// Template is one entry of the catalog.
type Template struct {
	ID      string          `json:"id"`
	Version int             `json:"version"`
	Mode    string          `json:"mode"`
	Params  []TemplateParam `json:"params"`
	Notes   []string        `json:"notes"`
	build   func(p TemplateParams) PolicySource
}

// TemplateParams are the values of a render request (only those of the template are read; the others must be absent).
type TemplateParams struct {
	GroupID    string   `json:"group_id,omitempty"`
	TagID      string   `json:"tag_id,omitempty"`
	ResourceID string   `json:"resource_id,omitempty"`
	Ports      []string `json:"ports,omitempty"`
}

// TemplateRequest is the body of POST /policies/templates/render.
type TemplateRequest struct {
	TemplateID string         `json:"template_id"`
	Version    *int           `json:"version,omitempty"` // when given, the catalog's version must be it
	Params     TemplateParams `json:"params"`
}

// TemplateResult is a rendered template: the fragment and the report of the fragment linted on its own.
type TemplateResult struct {
	TemplateID string       `json:"template_id"`
	Version    int          `json:"version"`
	Mode       string       `json:"mode"`
	Source     PolicySource `json:"source"`
	Report     Report       `json:"report"`
}

func principal(t, ref string) Principal { return Principal{Type: t, Ref: ref} }

var portsParam = func(def ...string) TemplateParam {
	return TemplateParam{Name: ParamPorts, Kind: ParamKindPorts, Required: true, Default: def}
}

var (
	groupParam    = TemplateParam{Name: ParamGroupID, Kind: ParamKindGroup, Required: true}
	tagParam      = TemplateParam{Name: ParamTagID, Kind: ParamKindTag, Required: true}
	resourceParam = TemplateParam{Name: ParamResourceID, Kind: ParamKindResource, Required: true}
)

// templateCatalog is the catalog, in the order the editor lists it.
var templateCatalog = []Template{
	{ID: TemplateDenyAll, Version: 1, Mode: TemplateReplace, Params: []TemplateParam{}, Notes: []string{NoteReplacesDraft},
		build: func(TemplateParams) PolicySource { return PolicySource{} }},
	{ID: TemplateOwnDevices, Version: 1, Mode: TemplateAppend, Params: []TemplateParam{portsParam("tcp:22")},
		Notes: []string{NoteTestsSelfNotAsserted, NoteSelfLargeTenant},
		build: func(p TemplateParams) PolicySource {
			return PolicySource{Grants: []Grant{{Src: []Principal{principal(PrincipalAutogroup, AutogroupMember)},
				Dst: []Principal{principal(PrincipalAutogroup, AutogroupSelf)}, IP: p.Ports}}}
		}},
	{ID: TemplateGroupToResource, Version: 1, Mode: TemplateAppend,
		Params: []TemplateParam{groupParam, resourceParam, portsParam("tcp:443")}, Notes: []string{},
		build: func(p TemplateParams) PolicySource {
			return PolicySource{Grants: []Grant{{Src: []Principal{principal(PrincipalGroup, p.GroupID)},
				Dst: []Principal{principal(PrincipalResource, p.ResourceID)}, IP: p.Ports}}}
		}},
	{ID: TemplateAdminsToDevices, Version: 1, Mode: TemplateAppend, Params: []TemplateParam{groupParam, portsParam("tcp:22")},
		Notes: []string{},
		build: func(p TemplateParams) PolicySource {
			return PolicySource{Grants: []Grant{{Src: []Principal{principal(PrincipalGroup, p.GroupID)},
				Dst: []Principal{principal(PrincipalAutogroup, AutogroupMember), principal(PrincipalAutogroup, AutogroupTagged)},
				IP:  p.Ports}}}
		}},
	{ID: TemplateExitNode, Version: 1, Mode: TemplateAppend, Params: []TemplateParam{groupParam, tagParam},
		Notes: []string{NoteTestsViaNotAsserted, NoteRoutesApproval},
		build: func(p TemplateParams) PolicySource {
			return PolicySource{Grants: []Grant{{Src: []Principal{principal(PrincipalGroup, p.GroupID)},
				Dst: []Principal{principal(PrincipalAutogroup, AutogroupInternet)}, IP: []string{"*"},
				Via: []Principal{principal(PrincipalTag, p.TagID)}}}}
		}},
	{ID: TemplateSubnetRouter, Version: 1, Mode: TemplateAppend,
		Params: []TemplateParam{groupParam, resourceParam, tagParam, portsParam("tcp:443")},
		Notes:  []string{NoteTestsViaNotAsserted, NoteRoutesApproval},
		build: func(p TemplateParams) PolicySource {
			return PolicySource{Grants: []Grant{{Src: []Principal{principal(PrincipalGroup, p.GroupID)},
				Dst: []Principal{principal(PrincipalResource, p.ResourceID)}, IP: p.Ports,
				Via: []Principal{principal(PrincipalTag, p.TagID)}}}}
		}},
}

// Templates returns the catalog (copies — the caller may not change it).
func Templates() []Template {
	out := make([]Template, len(templateCatalog))
	for i, t := range templateCatalog {
		t.Params = slices.Clone(t.Params)
		for j := range t.Params {
			t.Params[j].Default = slices.Clone(t.Params[j].Default)
		}
		t.Notes = slices.Clone(t.Notes)
		out[i] = t
	}
	return out
}

// TemplateByID returns a template of the catalog.
func TemplateByID(id string) (Template, bool) {
	for _, t := range templateCatalog {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// BuildTemplate checks a request against the catalog and returns the template and its fragment (normalized, checked
// like a draft's source). It reads no table: the references are checked by RenderTemplate.
func BuildTemplate(req TemplateRequest) (Template, PolicySource, error) {
	t, ok := TemplateByID(req.TemplateID)
	if !ok {
		return Template{}, PolicySource{}, &PolicyError{Kind: ErrPolicyInvalid, Reason: "unknown_template", Field: "template_id"}
	}
	if req.Version != nil && *req.Version != t.Version {
		return Template{}, PolicySource{}, &PolicyError{Kind: ErrPolicyInvalid, Reason: "unknown_version", Field: "version"}
	}
	p := req.Params
	has := map[string]bool{}
	for _, d := range t.Params {
		has[d.Name] = true
	}
	given := map[string]bool{ParamGroupID: p.GroupID != "", ParamTagID: p.TagID != "", ParamResourceID: p.ResourceID != "",
		ParamPorts: p.Ports != nil}
	for _, name := range []string{ParamGroupID, ParamTagID, ParamResourceID, ParamPorts} {
		switch {
		case given[name] && !has[name]:
			return Template{}, PolicySource{}, invalidParam(name, "not_a_parameter")
		case !given[name] && has[name]:
			return Template{}, PolicySource{}, invalidParam(name, "required")
		}
	}
	for _, r := range []struct{ name, ref string }{{ParamGroupID, p.GroupID}, {ParamTagID, p.TagID}, {ParamResourceID, p.ResourceID}} {
		if r.ref == "" {
			continue
		}
		if _, err := uuid.Parse(r.ref); err != nil || len(r.ref) != 36 {
			return Template{}, PolicySource{}, invalidParam(r.name, "invalid_id")
		}
	}
	if has[ParamPorts] {
		if len(p.Ports) == 0 || len(p.Ports) > MaxTemplatePorts {
			return Template{}, PolicySource{}, invalidParam(ParamPorts, "invalid_count")
		}
		for i, e := range p.Ports {
			// least privilege: a template never opens every port ("*", "tcp:*").
			if _, ports := splitIPProto(e); !ipRE.MatchString(e) || ports == "*" {
				return Template{}, PolicySource{}, invalidParam(ParamPorts+"["+strconv.Itoa(i)+"]", "invalid_port")
			}
		}
		p.Ports = slices.Clone(p.Ports)
	}
	src := t.build(p).normalized()
	if err := src.Check(); err != nil { // the parameters were checked above: a template that builds a bad source is a bug
		se, _ := AsSourceError(err)
		field, reason := "params", "invalid"
		if se != nil {
			reason = se.Reason
		}
		return Template{}, PolicySource{}, &PolicyError{Kind: ErrPolicyInvalid, Reason: reason, Field: field}
	}
	return t, src, nil
}

func invalidParam(name, reason string) error {
	return &PolicyError{Kind: ErrPolicyInvalid, Reason: reason, Field: "params." + name}
}

// RenderTemplate is POST /policies/templates/render: the fragment of a template whose references exist in the tenant
// (a group, tag or resource of another tenant or none ⇒ 422 on its parameter), with the report of the fragment
// rendered and linted on its own over the tenant's tables (the tests it would generate included).
func (s *VersionService) RenderTemplate(ctx context.Context, tenantID uuid.UUID, req TemplateRequest) (TemplateResult, error) {
	t, src, err := BuildTemplate(req)
	if err != nil {
		return TemplateResult{}, err
	}
	var in *RenderInputs
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		in, err = loadRenderInputs(ctx, q, tenantID)
		return err
	})
	if err != nil {
		return TemplateResult{}, err
	}
	if err := templateRefsExist(req.Params, in); err != nil {
		return TemplateResult{}, err
	}
	_, sum, err := src.Canonical()
	if err != nil {
		return TemplateResult{}, err
	}
	rend := RenderTyped(src, sum, in)
	return TemplateResult{TemplateID: t.ID, Version: t.Version, Mode: t.Mode, Source: src, Report: rend.Report}, nil
}

func templateRefsExist(p TemplateParams, in *RenderInputs) error {
	check := func(name, ref string, exists func(uuid.UUID) bool) error {
		if ref == "" {
			return nil
		}
		if !exists(uuid.MustParse(ref)) {
			return invalidParam(name, "not_found")
		}
		return nil
	}
	if err := check(ParamGroupID, p.GroupID, func(id uuid.UUID) bool { _, ok := in.Groups[id]; return ok }); err != nil {
		return err
	}
	if err := check(ParamTagID, p.TagID, func(id uuid.UUID) bool { _, ok := in.Tags[id]; return ok }); err != nil {
		return err
	}
	return check(ParamResourceID, p.ResourceID, func(id uuid.UUID) bool { _, ok := in.Resources[id]; return ok })
}
