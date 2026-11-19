// Package policiesapi serves the policy lifecycle operations of api/openapi.yaml built by P4-T10
// (httpapi.PolicyHandlers): listTenantPolicies, getCurrentTenantPolicy, getTenantPolicy, diffTenantPolicy
// (`tenant.policy:read`), createTenantPolicy, updateTenantPolicy, validateTenantPolicy, submitTenantPolicy
// (`tenant.policy:edit`), approveTenantPolicy, rejectTenantPolicy (`tenant.policy:approve`), applyTenantPolicy,
// rollbackTenantPolicy (`tenant.policy:apply` — §8.6) — and, for P4-T11 (httpapi.PolicyHuJSONHandlers), the HuJSON
// translator of the editor: importTenantPolicy (`tenant.policy:edit`) and exportTenantPolicy (`tenant.policy:read`). It only translates between the generated types and
// policies.VersionService, which takes every decision (typed model, render, lint, review rule, If-Match, stale base,
// step-up, the policy.apply job).
//
// Wiring (apps/internal/runner — api process):
//
//	versions, _ := policies.NewVersions(apiStore, policies.VersionsConfig{Registry: headscaleRegistry})
//	httpapi.Handlers{…, Policies: policiesapi.New(versions)}
package policiesapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
)

// Service is the part of *policies.VersionService the handlers use.
type Service interface {
	List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) (policies.VersionPage, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (policies.Version, error)
	Current(ctx context.Context, tenantID uuid.UUID) (policies.Current, error)
	Create(ctx context.Context, tenantID uuid.UUID, actor policies.VersionActor, in policies.NewVersion, idem *policies.Idempotency) (policies.Version, error)
	Update(ctx context.Context, tenantID, id uuid.UUID, actor policies.VersionActor, ifMatch string, source json.RawMessage) (policies.Version, error)
	Validate(ctx context.Context, tenantID, id uuid.UUID, actor policies.VersionActor, ifMatch string) (policies.Version, error)
	Submit(ctx context.Context, tenantID, id uuid.UUID, actor policies.VersionActor, ifMatch string) (policies.Version, error)
	Approve(ctx context.Context, tenantID, id uuid.UUID, actor policies.VersionActor, ifMatch, contentSHA256 string) (policies.Version, error)
	Reject(ctx context.Context, tenantID, id uuid.UUID, actor policies.VersionActor, ifMatch, reason string) (policies.Version, error)
	Apply(ctx context.Context, tenantID, id uuid.UUID, actor policies.VersionActor, idem *policies.Idempotency) (policies.Accepted, error)
	Rollback(ctx context.Context, tenantID, id uuid.UUID, actor policies.VersionActor, idem *policies.Idempotency) (policies.Accepted, error)
	Diff(ctx context.Context, tenantID, id uuid.UUID, against *uuid.UUID) (policies.Diff, error)
	Import(ctx context.Context, tenantID uuid.UUID, text string) (policies.ImportResult, error)
	Export(ctx context.Context, tenantID uuid.UUID, source json.RawMessage) (policies.ExportResult, error)
}

var _ Service = (*policies.VersionService)(nil)

// Handlers implements httpapi.PolicyHandlers.
type Handlers struct {
	svc   Service
	actor func(ctx context.Context) (policies.VersionActor, error) // actorOf (a test replaces it)
}

var (
	_ httpapi.PolicyHandlers       = (*Handlers)(nil)
	_ httpapi.PolicyHuJSONHandlers = (*Handlers)(nil) // P4-T11: the same set serves the HuJSON translator
)

// New returns the handler set of P4-T10.
func New(svc Service) *Handlers { return &Handlers{svc: svc, actor: actorOf} }

var errNoSession = errors.New("policiesapi: no session in the request context (hooks missing)")

// actorOf is the caller's identity and the auth_time of its session (step-up) — the authorization hook already decided.
func actorOf(ctx context.Context) (policies.VersionActor, error) {
	s, ok := identity.SessionFromContext(ctx)
	if !ok || s == nil || s.IdentityID == uuid.Nil {
		return policies.VersionActor{}, problem.Internal(errNoSession)
	}
	return policies.VersionActor{IdentityID: s.IdentityID, AuthTime: s.AuthTime}, nil
}

// failure maps an error of the lifecycle: not found ⇒ 404 (another tenant's version too — §8.4 invariant 6), invalid
// ⇒ 422 on its field (a refused rollback lists its lint errors), the review rule ⇒ 403, step-up ⇒ 401
// reauth_required, a state that does not allow the request ⇒ 409, If-Match ⇒ 428/412, the instance ⇒ 503, the
// Idempotency-Key outcomes of §13.1, anything else ⇒ 500.
func failure(err error) error {
	pe, ok := policies.AsPolicyError(err)
	if !ok {
		return problem.Internal(err)
	}
	cause := &authz.Denial{Kind: err, Reason: pe.Reason}
	switch {
	case errors.Is(err, policies.ErrPolicyNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, policies.ErrPolicyInvalid):
		field := pe.Field
		if field == "" {
			field = "body"
		}
		fields := []gen.FieldError{problem.Field(field, pe.Reason, "has an invalid value")}
		if pe.Report != nil {
			for _, f := range pe.Report.Errors {
				p := f.Path
				if p == "" {
					p = "source"
				}
				fields = append(fields, problem.Field("source."+p, f.Code, f.Rule+": "+f.Message))
			}
		}
		return problem.Validation("The request is invalid.", fields...)
	case errors.Is(err, policies.ErrPolicyForbidden):
		detail := map[string]string{
			"self_approval":                  "With 4-eyes on, a version is approved by someone who neither wrote nor submitted it.",
			"owner_acknowledgement_required": "The version acknowledges a rule only a Tenant Owner may accept (L4/L12): an Owner approves it.",
		}[pe.Reason]
		if detail == "" {
			detail = "The review rule refuses this request."
		}
		return &problem.Error{Code: gen.ProblemCodeForbidden, Detail: detail, Cause: cause}
	case errors.Is(err, policies.ErrPolicyReauthRequired):
		return &problem.Error{Code: gen.ProblemCodeReauthRequired, Cause: cause,
			Detail: "This operation needs a recent sign-in (step-up)."}
	case errors.Is(err, policies.ErrPolicyPreconditionRequired):
		return &problem.Error{Code: gen.ProblemCodePreconditionRequired, Cause: cause,
			Detail: "If-Match with the version's etag is required."}
	case errors.Is(err, policies.ErrPolicyPreconditionFailed):
		return &problem.Error{Code: gen.ProblemCodePreconditionFailed, Cause: cause,
			Detail: "The version changed since it was read; read it again."}
	case errors.Is(err, policies.ErrPolicyInstanceUnavailable):
		return &problem.Error{Code: gen.ProblemCodeInstanceUnavailable, Cause: cause,
			Detail: "The tenant's Headscale did not answer; nothing was changed."}
	case errors.Is(err, policies.ErrPolicyIdempotencyInProgress):
		return &problem.Error{Code: gen.ProblemCodeConflict, Cause: cause, RetryAfter: pe.RetryAfter,
			Detail: "A request with this Idempotency-Key is still in progress."}
	case errors.Is(err, policies.ErrPolicyIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, policies.ErrPolicyConflict):
		detail := map[string]string{
			"stale_base":         "The version is not based on the current desired version (stale_base): rebase it.",
			"not_approved":       "Only an approved version can be applied.",
			"review_required":    "4-eyes is on: submit the version; another person approves it.",
			"content_mismatch":   "content_sha256 is not the version's content: review it again.",
			"version_is_desired": "The desired version cannot be edited: create a new version.",
			"never_approved":     "A rollback needs a content that was approved before.",
		}[pe.Reason]
		if detail == "" {
			detail = "The version's state does not allow this request (" + pe.Reason + ")."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	}
	return problem.Internal(err)
}

// toAPI maps a version through its JSON form (the generated type has the same members) and adds its etag.
func toAPI(v policies.Version) (gen.PolicyVersion, error) {
	var out gen.PolicyVersion
	b, err := json.Marshal(v)
	if err != nil {
		return out, problem.Internal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, problem.Internal(err)
	}
	out.Etag = v.ETag()
	return out, nil
}

func convert[T any](v any) (T, error) {
	var out T
	b, err := json.Marshal(v)
	if err != nil {
		return out, problem.Internal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, problem.Internal(err)
	}
	return out, nil
}

func ifMatch(p *gen.IfMatch) string {
	if p == nil {
		return ""
	}
	return *p
}

func bodyMissing() error {
	return problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
}

// sourceOf is the source of a request body as JSON (policies.ParseSource checks it strictly).
func sourceOf(s gen.PolicySource) (json.RawMessage, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, problem.Internal(err)
	}
	return b, nil
}

// jobLocation is the Location of a job for a caller of tenant scope (§13.1 "Thao tác dài").
func jobLocation(tenantID, jobID uuid.UUID) string {
	return httpapi.BaseURL + "/tenants/" + tenantID.String() + "/jobs/" + jobID.String()
}

func accepted(a policies.Accepted) (gen.PolicyApplyAccepted, error) {
	v, err := toAPI(a.Version)
	if err != nil {
		return gen.PolicyApplyAccepted{}, err
	}
	return gen.PolicyApplyAccepted{Version: v, Job: jobsapi.ToAPI(a.Job)}, nil
}

// ListTenantPolicies implements GET /tenants/{tenantId}/policies.
func (h *Handlers) ListTenantPolicies(ctx context.Context, req gen.ListTenantPoliciesRequestObject) (gen.ListTenantPoliciesResponseObject, error) {
	limit, cursor := 0, ""
	if p := req.Params.Limit; p != nil {
		limit = *p
		if limit == 0 {
			limit = -1 // 0 is not "the default": the spec's minimum is 1
		}
	}
	if c := req.Params.Cursor; c != nil {
		cursor = *c
	}
	page, err := h.svc.List(ctx, req.TenantId, limit, cursor)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.PolicyVersionList{Items: make([]gen.PolicyVersion, 0, len(page.Items))}
	for _, v := range page.Items {
		a, err := toAPI(v)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, a)
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListTenantPolicies200JSONResponse(out), nil
}

// GetCurrentTenantPolicy implements GET /tenants/{tenantId}/policies/current.
func (h *Handlers) GetCurrentTenantPolicy(ctx context.Context, req gen.GetCurrentTenantPolicyRequestObject) (gen.GetCurrentTenantPolicyResponseObject, error) {
	c, err := h.svc.Current(ctx, req.TenantId)
	if err != nil {
		return nil, failure(err)
	}
	out, err := convert[gen.PolicyCurrent](c)
	if err != nil {
		return nil, err
	}
	if c.Desired != nil && out.Desired != nil {
		out.Desired.Etag = c.Desired.ETag()
	}
	return gen.GetCurrentTenantPolicy200JSONResponse(out), nil
}

// GetTenantPolicy implements GET /tenants/{tenantId}/policies/{versionId}.
func (h *Handlers) GetTenantPolicy(ctx context.Context, req gen.GetTenantPolicyRequestObject) (gen.GetTenantPolicyResponseObject, error) {
	v, err := h.svc.Get(ctx, req.TenantId, req.VersionId)
	if err != nil {
		return nil, failure(err)
	}
	out, err := toAPI(v)
	if err != nil {
		return nil, err
	}
	return gen.GetTenantPolicy200JSONResponse{Body: out, Headers: gen.GetTenantPolicy200ResponseHeaders{ETag: out.Etag}}, nil
}

// CreateTenantPolicy implements POST /tenants/{tenantId}/policies (Idempotency-Key: the hash covers the method, the
// path with the tenant and the canonical body — §13.1).
func (h *Handlers) CreateTenantPolicy(ctx context.Context, req gen.CreateTenantPolicyRequestObject) (gen.CreateTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyMissing()
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	src, err := sourceOf(req.Body.Source)
	if err != nil {
		return nil, err
	}
	idem := &policies.Idempotency{Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/tenants/"+req.TenantId.String()+"/policies", body)}
	v, err := h.svc.Create(ctx, req.TenantId, a, policies.NewVersion{Source: src, ParentVersionID: req.Body.ParentVersionId}, idem)
	if err != nil {
		return nil, failure(err)
	}
	out, err := toAPI(v)
	if err != nil {
		return nil, err
	}
	return gen.CreateTenantPolicy201JSONResponse{Body: out, Headers: gen.CreateTenantPolicy201ResponseHeaders{ETag: out.Etag}}, nil
}

// UpdateTenantPolicy implements PATCH /tenants/{tenantId}/policies/{versionId}.
func (h *Handlers) UpdateTenantPolicy(ctx context.Context, req gen.UpdateTenantPolicyRequestObject) (gen.UpdateTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyMissing()
	}
	src, err := sourceOf(req.Body.Source)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Update(ctx, req.TenantId, req.VersionId, a, ifMatch(req.Params.IfMatch), src)
	if err != nil {
		return nil, failure(err)
	}
	out, err := toAPI(v)
	if err != nil {
		return nil, err
	}
	return gen.UpdateTenantPolicy200JSONResponse{Body: out, Headers: gen.UpdateTenantPolicy200ResponseHeaders{ETag: out.Etag}}, nil
}

// ValidateTenantPolicy implements POST /tenants/{tenantId}/policies/{versionId}/validate.
func (h *Handlers) ValidateTenantPolicy(ctx context.Context, req gen.ValidateTenantPolicyRequestObject) (gen.ValidateTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Validate(ctx, req.TenantId, req.VersionId, a, ifMatch(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	out, err := toAPI(v)
	if err != nil {
		return nil, err
	}
	return gen.ValidateTenantPolicy200JSONResponse{Body: out, Headers: gen.ValidateTenantPolicy200ResponseHeaders{ETag: out.Etag}}, nil
}

// SubmitTenantPolicy implements POST /tenants/{tenantId}/policies/{versionId}/submit.
func (h *Handlers) SubmitTenantPolicy(ctx context.Context, req gen.SubmitTenantPolicyRequestObject) (gen.SubmitTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Submit(ctx, req.TenantId, req.VersionId, a, ifMatch(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	out, err := toAPI(v)
	if err != nil {
		return nil, err
	}
	return gen.SubmitTenantPolicy200JSONResponse{Body: out, Headers: gen.SubmitTenantPolicy200ResponseHeaders{ETag: out.Etag}}, nil
}

// ApproveTenantPolicy implements POST /tenants/{tenantId}/policies/{versionId}/approve.
func (h *Handlers) ApproveTenantPolicy(ctx context.Context, req gen.ApproveTenantPolicyRequestObject) (gen.ApproveTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyMissing()
	}
	v, err := h.svc.Approve(ctx, req.TenantId, req.VersionId, a, ifMatch(req.Params.IfMatch), req.Body.ContentSha256)
	if err != nil {
		return nil, failure(err)
	}
	out, err := toAPI(v)
	if err != nil {
		return nil, err
	}
	return gen.ApproveTenantPolicy200JSONResponse{Body: out, Headers: gen.ApproveTenantPolicy200ResponseHeaders{ETag: out.Etag}}, nil
}

// RejectTenantPolicy implements POST /tenants/{tenantId}/policies/{versionId}/reject.
func (h *Handlers) RejectTenantPolicy(ctx context.Context, req gen.RejectTenantPolicyRequestObject) (gen.RejectTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyMissing()
	}
	v, err := h.svc.Reject(ctx, req.TenantId, req.VersionId, a, ifMatch(req.Params.IfMatch), req.Body.Reason)
	if err != nil {
		return nil, failure(err)
	}
	out, err := toAPI(v)
	if err != nil {
		return nil, err
	}
	return gen.RejectTenantPolicy200JSONResponse{Body: out, Headers: gen.RejectTenantPolicy200ResponseHeaders{ETag: out.Etag}}, nil
}

// ApplyTenantPolicy implements POST /tenants/{tenantId}/policies/{versionId}/apply (202 + Location of the job).
func (h *Handlers) ApplyTenantPolicy(ctx context.Context, req gen.ApplyTenantPolicyRequestObject) (gen.ApplyTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	path := "/tenants/" + req.TenantId.String() + "/policies/" + req.VersionId.String() + "/apply"
	idem := &policies.Idempotency{Key: req.Params.IdempotencyKey, Hash: jobs.RequestHash("POST", path, nil)}
	r, err := h.svc.Apply(ctx, req.TenantId, req.VersionId, a, idem)
	if err != nil {
		return nil, failure(err)
	}
	out, err := accepted(r)
	if err != nil {
		return nil, err
	}
	return gen.ApplyTenantPolicy202JSONResponse{Body: out,
		Headers: gen.ApplyTenantPolicy202ResponseHeaders{Location: jobLocation(req.TenantId, r.Job.ID)}}, nil
}

// RollbackTenantPolicy implements POST /tenants/{tenantId}/policies/{versionId}/rollback (202 + Location of the job).
func (h *Handlers) RollbackTenantPolicy(ctx context.Context, req gen.RollbackTenantPolicyRequestObject) (gen.RollbackTenantPolicyResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	path := "/tenants/" + req.TenantId.String() + "/policies/" + req.VersionId.String() + "/rollback"
	idem := &policies.Idempotency{Key: req.Params.IdempotencyKey, Hash: jobs.RequestHash("POST", path, nil)}
	r, err := h.svc.Rollback(ctx, req.TenantId, req.VersionId, a, idem)
	if err != nil {
		return nil, failure(err)
	}
	out, err := accepted(r)
	if err != nil {
		return nil, err
	}
	return gen.RollbackTenantPolicy202JSONResponse{Body: out,
		Headers: gen.RollbackTenantPolicy202ResponseHeaders{Location: jobLocation(req.TenantId, r.Job.ID)}}, nil
}

// DiffTenantPolicy implements GET /tenants/{tenantId}/policies/{versionId}/diff.
func (h *Handlers) DiffTenantPolicy(ctx context.Context, req gen.DiffTenantPolicyRequestObject) (gen.DiffTenantPolicyResponseObject, error) {
	d, err := h.svc.Diff(ctx, req.TenantId, req.VersionId, req.Params.Against)
	if err != nil {
		return nil, failure(err)
	}
	out, err := convert[gen.PolicyDiff](d)
	if err != nil {
		return nil, err
	}
	return gen.DiffTenantPolicy200JSONResponse(out), nil
}

// ImportTenantPolicy implements POST /tenants/{tenantId}/policies/import (P4-T11): 200 with the translation or its
// findings — nothing is stored.
func (h *Handlers) ImportTenantPolicy(ctx context.Context, req gen.ImportTenantPolicyRequestObject) (gen.ImportTenantPolicyResponseObject, error) {
	if req.Body == nil {
		return nil, bodyMissing()
	}
	r, err := h.svc.Import(ctx, req.TenantId, req.Body.Hujson)
	if err != nil {
		return nil, failure(err)
	}
	out, err := convert[gen.PolicyImport](r)
	if err != nil {
		return nil, err
	}
	return gen.ImportTenantPolicy200JSONResponse(out), nil
}

// ExportTenantPolicy implements POST /tenants/{tenantId}/policies/export (P4-T11): the source written as HuJSON.
func (h *Handlers) ExportTenantPolicy(ctx context.Context, req gen.ExportTenantPolicyRequestObject) (gen.ExportTenantPolicyResponseObject, error) {
	if req.Body == nil {
		return nil, bodyMissing()
	}
	src, err := sourceOf(req.Body.Source)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Export(ctx, req.TenantId, src)
	if err != nil {
		return nil, failure(err)
	}
	out, err := convert[gen.PolicyExport](r)
	if err != nil {
		return nil, err
	}
	return gen.ExportTenantPolicy200JSONResponse(out), nil
}
