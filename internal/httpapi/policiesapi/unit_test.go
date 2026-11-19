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
