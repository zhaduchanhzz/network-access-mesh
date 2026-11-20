package policiesapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
)

// fakeService records what the handlers pass and answers with a fixed version (or err).
type fakeService struct {
	tenant, id uuid.UUID
	actor      policies.VersionActor
	ifMatch    string
	source     json.RawMessage
	sha        string
	reason     string
	idem       *policies.Idempotency
	against    *uuid.UUID
	err        error
	v          policies.Version
	tmpl       policies.TemplateRequest
}

func (f *fakeService) List(_ context.Context, t uuid.UUID, _ int, _ string) (policies.VersionPage, error) {
	f.tenant = t
	return policies.VersionPage{Items: []policies.Version{f.v}, NextCursor: "3"}, f.err
}
func (f *fakeService) Get(_ context.Context, t, id uuid.UUID) (policies.Version, error) {
	f.tenant, f.id = t, id
	return f.v, f.err
}
func (f *fakeService) Current(_ context.Context, t uuid.UUID) (policies.Current, error) {
	f.tenant = t
	v := f.v
	return policies.Current{Desired: &v, FourEyes: true, ApplyStepUp: true}, f.err
}
func (f *fakeService) Create(_ context.Context, t uuid.UUID, a policies.VersionActor, in policies.NewVersion, idem *policies.Idempotency) (policies.Version, error) {
	f.tenant, f.actor, f.source, f.idem = t, a, in.Source, idem
	return f.v, f.err
}
func (f *fakeService) Update(_ context.Context, t, id uuid.UUID, a policies.VersionActor, ifMatch string, src json.RawMessage) (policies.Version, error) {
	f.tenant, f.id, f.actor, f.ifMatch, f.source = t, id, a, ifMatch, src
	return f.v, f.err
}
func (f *fakeService) Validate(_ context.Context, t, id uuid.UUID, a policies.VersionActor, ifMatch string) (policies.Version, error) {
	f.tenant, f.id, f.actor, f.ifMatch = t, id, a, ifMatch
	return f.v, f.err
}
func (f *fakeService) Submit(_ context.Context, t, id uuid.UUID, a policies.VersionActor, ifMatch string) (policies.Version, error) {
	f.tenant, f.id, f.actor, f.ifMatch = t, id, a, ifMatch
	return f.v, f.err
}
func (f *fakeService) Approve(_ context.Context, t, id uuid.UUID, a policies.VersionActor, ifMatch, sha string) (policies.Version, error) {
	f.tenant, f.id, f.actor, f.ifMatch, f.sha = t, id, a, ifMatch, sha
	return f.v, f.err
}
func (f *fakeService) Reject(_ context.Context, t, id uuid.UUID, a policies.VersionActor, ifMatch, reason string) (policies.Version, error) {
	f.tenant, f.id, f.actor, f.ifMatch, f.reason = t, id, a, ifMatch, reason
	return f.v, f.err
}
func (f *fakeService) Apply(_ context.Context, t, id uuid.UUID, a policies.VersionActor, idem *policies.Idempotency) (policies.Accepted, error) {
	f.tenant, f.id, f.actor, f.idem = t, id, a, idem
	return policies.Accepted{Version: f.v, Job: jobs.Job{ID: uuid.MustParse("00000000-0000-7000-8000-0000000000aa"),
		Kind: policies.KindApply, Status: jobs.StatusQueued, Steps: []jobs.Step{}}}, f.err
}
func (f *fakeService) Rollback(ctx context.Context, t, id uuid.UUID, a policies.VersionActor, idem *policies.Idempotency) (policies.Accepted, error) {
	return f.Apply(ctx, t, id, a, idem)
}
func (f *fakeService) Diff(_ context.Context, t, id uuid.UUID, against *uuid.UUID) (policies.Diff, error) {
	f.tenant, f.id, f.against = t, id, against
	return policies.Diff{VersionID: id, Lines: []policies.DiffLine{{Op: policies.DiffAdded, Text: "x"}},
		GrantsAdded: []string{"g"}, GrantsRemoved: []string{}}, f.err
}

func (f *fakeService) Import(_ context.Context, t uuid.UUID, text string) (policies.ImportResult, error) {
	f.tenant, f.reason = t, text
	src := policies.PolicySource{Grants: []policies.Grant{}, SSH: []policies.SSHRule{}}
	return policies.ImportResult{Result: policies.ResultPassed, Source: &src, Errors: []policies.Finding{},
		Warnings:   []policies.Finding{{Rule: "L6", Severity: "warning", Code: "x", Line: 3, Message: "m"}},
		Principals: []policies.PrincipalName{{Type: "group", Ref: "g", Name: "group:eng"}}}, f.err
}
func (f *fakeService) Export(_ context.Context, t uuid.UUID, src json.RawMessage) (policies.ExportResult, error) {
	f.tenant, f.source = t, src
	return policies.ExportResult{HuJSON: "{\"grants\": []}\n", Warnings: []policies.Finding{}, Principals: []policies.PrincipalName{}}, f.err
}

func (f *fakeService) RenderTemplate(_ context.Context, t uuid.UUID, req policies.TemplateRequest) (policies.TemplateResult, error) {
	f.tenant, f.tmpl = t, req
	if f.err != nil {
		return policies.TemplateResult{}, f.err
	}
	_, src, err := policies.BuildTemplate(req)
	if err != nil {
		return policies.TemplateResult{}, err
	}
	return policies.TemplateResult{TemplateID: req.TemplateID, Version: 1, Mode: policies.TemplateAppend, Source: src,
		Report: policies.Report{Engine: "p4-t10", Result: policies.ResultPassed, Errors: []policies.Finding{},
			Warnings: []policies.Finding{}, Info: []policies.Finding{}, Tests: []policies.TestCase{{Grant: 0, Skipped: policies.TestSkipNoSource}}}}, nil
}

// TestTemplateHandlers (P5-T01) — the catalog lists every template of the package with its parameters and notes; a
// render passes the request through (ids as strings, version kept) and answers the fragment with its report; a
// missing body, an unknown template or a parameter error of the service map to 422; the service's failures map like
// the lifecycle's.
func TestTemplateHandlers(t *testing.T) {
	f := &fakeService{}
	h := New(f)
	ctx := context.Background()
	tenant := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	list, err := h.ListTenantPolicyTemplates(ctx, gen.ListTenantPolicyTemplatesRequestObject{TenantId: tenant})
	l, ok := list.(gen.ListTenantPolicyTemplates200JSONResponse)
	if err != nil || !ok || len(l.Items) != len(policies.Templates()) {
		t.Fatalf("list: %+v %v", list, err)
	}
	for i, tm := range policies.Templates() {
		got := l.Items[i]
		if string(got.Id) != tm.ID || got.Version != tm.Version || string(got.Mode) != tm.Mode || len(got.Params) != len(tm.Params) ||
			len(got.Notes) != len(tm.Notes) {
			t.Errorf("item %d: %+v, want %+v", i, got, tm)
		}
	}
	group := uuid.MustParse("00000000-0000-7000-8000-000000000003")
	resource := uuid.MustParse("00000000-0000-7000-8000-000000000002")
	v := 1
	ports := []string{"tcp:443"}
	body := gen.PolicyTemplateRenderRequest{TemplateId: policies.TemplateGroupToResource, Version: &v,
		Params: gen.PolicyTemplateParams{GroupId: &group, ResourceId: &resource, Ports: &ports}}
	out, err := h.RenderTenantPolicyTemplate(ctx, gen.RenderTenantPolicyTemplateRequestObject{TenantId: tenant, Body: &body})
	r, ok := out.(gen.RenderTenantPolicyTemplate200JSONResponse)
	if err != nil || !ok || f.tenant != tenant || f.tmpl.Params.GroupID != group.String() || f.tmpl.Params.ResourceID != resource.String() ||
		f.tmpl.Version == nil || *f.tmpl.Version != 1 || len(r.Source.Grants) != 1 || len(r.Report.Tests) != 1 {
		t.Fatalf("render: %+v %v (request %+v)", out, err, f.tmpl)
	}
	if g := r.Source.Grants[0]; string(g.Src[0].Type) != policies.PrincipalGroup || g.Src[0].Ref != group.String() ||
		string(g.Dst[0].Type) != policies.PrincipalResource || g.Ip == nil || (*g.Ip)[0] != "tcp:443" {
		t.Errorf("fragment: %+v", g)
	}
	var p *problem.Error
	if _, err := h.RenderTenantPolicyTemplate(ctx, gen.RenderTenantPolicyTemplateRequestObject{TenantId: tenant}); !errors.As(err, &p) ||
		p.Code != gen.ProblemCodeValidationFailed {
		t.Errorf("no body: %v", err)
	}
	bad := gen.PolicyTemplateRenderRequest{TemplateId: "nope", Params: gen.PolicyTemplateParams{}}
	if _, err := h.RenderTenantPolicyTemplate(ctx, gen.RenderTenantPolicyTemplateRequestObject{TenantId: tenant, Body: &bad}); !errors.As(err, &p) ||
		p.Code != gen.ProblemCodeValidationFailed || len(p.Fields) == 0 || p.Fields[0].Field != "template_id" {
		t.Errorf("unknown template: %v", err)
	}
	f.err = &policies.PolicyError{Kind: policies.ErrPolicyInvalid, Reason: "not_found", Field: "params.group_id"}
	if _, err := h.RenderTenantPolicyTemplate(ctx, gen.RenderTenantPolicyTemplateRequestObject{TenantId: tenant, Body: &body}); !errors.As(err, &p) ||
		p.Code != gen.ProblemCodeValidationFailed || p.Fields[0].Field != "params.group_id" {
		t.Errorf("reference of another tenant: %v", err)
	}
}

// TestHuJSONHandlers (P4-T11) — import passes the text through and answers the translation (line of a finding kept);
// export passes the source as JSON; a missing body is refused; a refusal of the service maps like the lifecycle's.
func TestHuJSONHandlers(t *testing.T) {
	f := &fakeService{}
	h := New(f)
	ctx, tenant := context.Background(), uuid.New()
	r, err := h.ImportTenantPolicy(ctx, gen.ImportTenantPolicyRequestObject{TenantId: tenant,
		Body: &gen.PolicyImportRequest{Hujson: "// c\n{\"grants\": []}"}})
	if err != nil {
		t.Fatal(err)
	}
	im := r.(gen.ImportTenantPolicy200JSONResponse)
	if f.tenant != tenant || f.reason != "// c\n{\"grants\": []}" || im.Result != gen.PolicyImportResultPassed || im.Source == nil ||
		len(im.Warnings) != 1 || im.Warnings[0].Line == nil || *im.Warnings[0].Line != 3 || len(im.Principals) != 1 ||
		im.Principals[0].Name != "group:eng" {
		t.Fatalf("import: %+v (service saw %q)", im, f.reason)
	}
	er, err := h.ExportTenantPolicy(ctx, gen.ExportTenantPolicyRequestObject{TenantId: tenant,
		Body: &gen.PolicyExportRequest{Source: gen.PolicySource{Grants: []gen.PolicyGrant{}}}})
	if err != nil {
		t.Fatal(err)
	}
	if ex := er.(gen.ExportTenantPolicy200JSONResponse); ex.Hujson != "{\"grants\": []}\n" || !strings.Contains(string(f.source), `"grants":[]`) {
		t.Fatalf("export: %+v (service saw %s)", ex, f.source)
	}
	if _, err := h.ImportTenantPolicy(ctx, gen.ImportTenantPolicyRequestObject{TenantId: tenant}); err == nil {
		t.Fatal("an import without a body must be refused")
	}
	if _, err := h.ExportTenantPolicy(ctx, gen.ExportTenantPolicyRequestObject{TenantId: tenant}); err == nil {
		t.Fatal("an export without a body must be refused")
	}
	f.err = &policies.PolicyError{Kind: policies.ErrPolicyInvalid, Reason: "invalid_id", Field: "source.grants[0].src[0].ref"}
	_, err = h.ExportTenantPolicy(ctx, gen.ExportTenantPolicyRequestObject{TenantId: tenant,
		Body: &gen.PolicyExportRequest{Source: gen.PolicySource{Grants: []gen.PolicyGrant{}}}})
	var p *problem.Error
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeValidationFailed {
		t.Fatalf("export refusal: %v", err)
	}
}

// TestHandlersMapRequests — parameters, If-Match, bodies, the caller and the Idempotency-Key hash reach the service;
// answers carry the version's etag (ETag header) and the job's Location.
func TestHandlersMapRequests(t *testing.T) {
	ident := uuid.New()
	now := time.Now()
	f := &fakeService{v: policies.Version{ID: uuid.New(), Version: 3, Revision: 4, Kind: policies.KindUser,
		State: policies.VersionDraft, ContentSHA256: strings.Repeat("a", 64)}}
	h := New(f)
	h.actor = func(context.Context) (policies.VersionActor, error) {
		return policies.VersionActor{IdentityID: ident, AuthTime: now}, nil
	}
	ctx, tenant, id := context.Background(), uuid.New(), f.v.ID
	m := `"4"`
	r, err := h.UpdateTenantPolicy(ctx, gen.UpdateTenantPolicyRequestObject{TenantId: tenant, VersionId: id,
		Params: gen.UpdateTenantPolicyParams{IfMatch: &m}, Body: &gen.PolicyUpdate{Source: gen.PolicySource{Grants: []gen.PolicyGrant{}}}})
	if err != nil {
		t.Fatal(err)
	}
	up := r.(gen.UpdateTenantPolicy200JSONResponse)
	if up.Headers.ETag != `"4"` || up.Body.Etag != `"4"` || f.ifMatch != m || f.actor.IdentityID != ident || !f.actor.AuthTime.Equal(now) ||
		!strings.Contains(string(f.source), `"grants":[]`) {
		t.Fatalf("update: %+v, service saw %q %s", up, f.ifMatch, f.source)
	}
	sha := strings.Repeat("b", 64)
	if _, err := h.ApproveTenantPolicy(ctx, gen.ApproveTenantPolicyRequestObject{TenantId: tenant, VersionId: id,
		Params: gen.ApproveTenantPolicyParams{IfMatch: &m}, Body: &gen.PolicyApprove{ContentSha256: sha}}); err != nil || f.sha != sha {
		t.Fatalf("approve: %v %q", err, f.sha)
	}
	ar, err := h.ApplyTenantPolicy(ctx, gen.ApplyTenantPolicyRequestObject{TenantId: tenant, VersionId: id,
		Params: gen.ApplyTenantPolicyParams{IdempotencyKey: "k-0001"}})
	if err != nil {
		t.Fatal(err)
	}
	acc := ar.(gen.ApplyTenantPolicy202JSONResponse)
	want := jobs.RequestHash("POST", "/tenants/"+tenant.String()+"/policies/"+id.String()+"/apply", nil)
	if f.idem == nil || f.idem.Key != "k-0001" || string(f.idem.Hash) != string(want) ||
		!strings.HasSuffix(acc.Headers.Location, "/tenants/"+tenant.String()+"/jobs/00000000-0000-7000-8000-0000000000aa") ||
		acc.Body.Version.Etag != `"4"` || acc.Body.Job.Kind != policies.KindApply {
		t.Fatalf("apply: %+v %+v", acc, f.idem)
	}
	against := uuid.New()
	if _, err := h.DiffTenantPolicy(ctx, gen.DiffTenantPolicyRequestObject{TenantId: tenant, VersionId: id,
		Params: gen.DiffTenantPolicyParams{Against: &against}}); err != nil || f.against == nil || *f.against != against {
		t.Fatalf("diff: %v", err)
	}
	cur, err := h.GetCurrentTenantPolicy(ctx, gen.GetCurrentTenantPolicyRequestObject{TenantId: tenant})
	if c := cur.(gen.GetCurrentTenantPolicy200JSONResponse); err != nil || c.Desired == nil || c.Desired.Etag != `"4"` || !c.FourEyes {
		t.Fatalf("current: %+v %v", cur, err)
	}
	if _, err := h.CreateTenantPolicy(ctx, gen.CreateTenantPolicyRequestObject{TenantId: tenant}); err == nil {
		t.Fatal("a create without a body must be refused")
	}
}

// TestFailureMapping — every refusal of the lifecycle maps to the Problem of §13.1.
func TestFailureMapping(t *testing.T) {
	rep := &policies.Report{Errors: []policies.Finding{{Rule: "L6", Code: "undeclared_group", Path: "grants[0].src[0].ref"}}}
	for _, tc := range []struct {
		err  error
		code gen.ProblemCode
	}{
		{&policies.PolicyError{Kind: policies.ErrPolicyNotFound, Reason: "version_not_found"}, gen.ProblemCodeNotFound},
		{&policies.PolicyError{Kind: policies.ErrPolicyInvalid, Reason: "lint_failed", Field: "source", Report: rep}, gen.ProblemCodeValidationFailed},
		{&policies.PolicyError{Kind: policies.ErrPolicyForbidden, Reason: "self_approval"}, gen.ProblemCodeForbidden},
		{&policies.PolicyError{Kind: policies.ErrPolicyReauthRequired, Reason: "step_up_required"}, gen.ProblemCodeReauthRequired},
		{&policies.PolicyError{Kind: policies.ErrPolicyPreconditionRequired, Reason: "if_match_required"}, gen.ProblemCodePreconditionRequired},
		{&policies.PolicyError{Kind: policies.ErrPolicyPreconditionFailed, Reason: "stale_etag"}, gen.ProblemCodePreconditionFailed},
		{&policies.PolicyError{Kind: policies.ErrPolicyInstanceUnavailable, Reason: "instance_unavailable"}, gen.ProblemCodeInstanceUnavailable},
		{&policies.PolicyError{Kind: policies.ErrPolicyIdempotencyInProgress, Reason: "idempotency_in_progress"}, gen.ProblemCodeConflict},
		{&policies.PolicyError{Kind: policies.ErrPolicyIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}, gen.ProblemCodeIdempotencyKeyReuse},
		{&policies.PolicyError{Kind: policies.ErrPolicyConflict, Reason: "stale_base"}, gen.ProblemCodeConflict},
		{errors.New("boom"), gen.ProblemCodeInternalError},
	} {
		var p *problem.Error
		if !errors.As(failure(tc.err), &p) || p.Code != tc.code {
			t.Errorf("%v ⇒ %v, want %s", tc.err, failure(tc.err), tc.code)
		}
	}
	var p *problem.Error
	if errors.As(failure(&policies.PolicyError{Kind: policies.ErrPolicyInvalid, Reason: "lint_failed", Field: "source", Report: rep}), &p) &&
		(len(p.Fields) != 2 || p.Fields[1].Field != "source.grants[0].src[0].ref") {
		t.Errorf("lint errors of a refused rollback: %+v", p.Fields)
	}
}
