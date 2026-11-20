// Package jobsapi serves the job operations of api/openapi.yaml (P2-T12 backend, handlers P2-T16): listTenantJobs,
// getTenantJob (tenant.job:read — the safe projection of §13.3) and listPlatformJobs, getPlatformJob
// (platform.job:read — getPlatformJob adds the raw, redacted step detail and the full error). It only translates
// between the generated types and internal/jobs, which reads provisioning_jobs in the caller's scope; it never imports
// internal/store (§13.6, internal/archtest).
//
// Defence in depth (§8.8, T-01 / IT-12b), on top of the authorization hook (Hooks.Authz) that decides every operation
// before it runs and of RLS (tenant pool) under the service:
//   - no decision in the context, or a decision about another tenant (or a tenant route on a platform operation) ⇒
//     500 — fail closed, never data;
//   - a tenant list or job is answered only for a decision with a grant on every resource of the tenant: jobs are not
//     owned by a member, so an own-only grant would see the jobs of every member (403, as the tenant dashboard);
//   - every job returned on a tenant route must carry the tenant of the path, otherwise 500 (a job of another tenant
//     is never sent, even if a lower layer let it through); a job of another tenant asked by id is 404, like a
//     missing one (§8.4 invariant 6).
//
// Wiring (P2-T16, apps/internal/runner — api process):
//
//	api, _ := httpapi.New(httpapi.Options{…, Handlers: httpapi.Handlers{…, Jobs: jobsapi.New(jobs.NewService(apiStore))}})
package jobsapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
)

// Service is the part of *jobs.Service the handlers need.
type Service interface {
	ListTenantJobs(ctx context.Context, tenantID uuid.UUID, f jobs.ListFilter) (jobs.JobList, error)
	GetTenantJob(ctx context.Context, tenantID, jobID uuid.UUID) (jobs.Job, error)
	ListPlatformJobs(ctx context.Context, f jobs.ListFilter) (jobs.JobList, error)
	GetPlatformJob(ctx context.Context, jobID uuid.UUID) (jobs.PlatformJob, error)
	ListPlatformTenantJobs(ctx context.Context, tenantID uuid.UUID, f jobs.ListFilter) (jobs.JobList, error)
}

var _ Service = (*jobs.Service)(nil)

// Handlers implements httpapi.JobHandlers.
type Handlers struct {
	svc    Service
	labels Labeler
}

// Labeler names the tenants of a page of the Platform Console (G4b-E12) — *platform.Service.
type Labeler interface {
	Labels(ctx context.Context, tenantIDs, hostIDs []uuid.UUID) (platform.Labels, error)
}

var _ Labeler = (*platform.Service)(nil)

// WithLabels adds the tenant's slug and name to the jobs of the platform views (GET /platform/jobs[/{jobId}]); without
// it they carry the tenant id only.
func (h *Handlers) WithLabels(l Labeler) *Handlers {
	h.labels = l
	return h
}

// tenantLabels reads the labels of the tenants of jobs. They only name what the job already identifies by UUID: no
// labeler or a failed lookup leaves them out (the Console then shows the UUID) rather than failing the read.
func (h *Handlers) tenantLabels(ctx context.Context, ids ...*uuid.UUID) platform.Labels {
	if h.labels == nil {
		return platform.Labels{}
	}
	tids := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id != nil {
			tids = append(tids, *id)
		}
	}
	l, err := h.labels.Labels(ctx, tids, nil)
	if err != nil {
		return platform.Labels{}
	}
	return l
}

var _ httpapi.JobHandlers = (*Handlers)(nil)

// New returns the handlers of the job operations.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

// ReasonOwnOnlyGrant is the audit reason of a job read refused to an own-only grant.
const ReasonOwnOnlyGrant = "own_only_grant"

var (
	// errNoDecision: the handler runs without the authorization hook — fail closed (§8.4 invariant 4).
	errNoDecision = errors.New("jobsapi: no authorization decision in the request context (Hooks.Authz missing)")
	// errWrongDecision: the decision is not about this route (another tenant, a tenant route on a platform one…).
	errWrongDecision = errors.New("jobsapi: the authorization decision does not cover this request")
	// errForeignJob: the service returned a job of another tenant on a tenant route — never sent.
	errForeignJob = errors.New("jobsapi: a job of another tenant reached the tenant view")
	// errOtherJob: the service answered with another job than the one asked.
	errOtherJob = errors.New("jobsapi: the service returned another job")
)

// ListTenantJobs implements GET /tenants/{tenantId}/jobs.
func (h *Handlers) ListTenantJobs(ctx context.Context, req gen.ListTenantJobsRequestObject) (gen.ListTenantJobsResponseObject, error) {
	if err := tenantDecision(ctx, req.TenantId); err != nil {
		return nil, err
	}
	p := req.Params
	f, err := filter(p.Limit, p.Cursor, p.Status, p.Kind)
	if err != nil {
		return nil, err
	}
	list, err := h.svc.ListTenantJobs(ctx, req.TenantId, f)
	if err != nil {
		return nil, serviceError(err, p.Cursor != nil)
	}
	for _, j := range list.Items {
		if j.TenantID == nil || *j.TenantID != req.TenantId {
			return nil, problem.Internal(errForeignJob)
		}
	}
	return gen.ListTenantJobs200JSONResponse(jobList(list)), nil
}

// GetTenantJob implements GET /tenants/{tenantId}/jobs/{jobId}.
func (h *Handlers) GetTenantJob(ctx context.Context, req gen.GetTenantJobRequestObject) (gen.GetTenantJobResponseObject, error) {
	if err := tenantDecision(ctx, req.TenantId); err != nil {
		return nil, err
	}
	j, err := h.svc.GetTenantJob(ctx, req.TenantId, req.JobId)
	if err != nil {
		return nil, serviceError(err, false)
	}
	if j.TenantID == nil || *j.TenantID != req.TenantId || j.ID != req.JobId {
		return nil, problem.Internal(errForeignJob)
	}
	return gen.GetTenantJob200JSONResponse(job(j)), nil
}

// ListPlatformJobs implements GET /platform/jobs (jobs of the platform and of every tenant, safe projection).
func (h *Handlers) ListPlatformJobs(ctx context.Context, req gen.ListPlatformJobsRequestObject) (gen.ListPlatformJobsResponseObject, error) {
	if err := platformDecision(ctx); err != nil {
		return nil, err
	}
	p := req.Params
	f, err := filter(p.Limit, p.Cursor, p.Status, p.Kind)
	if err != nil {
		return nil, err
	}
	list, err := h.svc.ListPlatformJobs(ctx, f)
	if err != nil {
		return nil, serviceError(err, p.Cursor != nil)
	}
	out := jobList(list)
	ids := make([]*uuid.UUID, 0, len(list.Items))
	for _, j := range list.Items {
		ids = append(ids, j.TenantID)
	}
	l := h.tenantLabels(ctx, ids...)
	for i := range out.Items {
		if t, ok := l.Tenant(out.Items[i].TenantId); ok {
			out.Items[i].TenantSlug, out.Items[i].TenantName = &t.Slug, &t.Name
		}
	}
	return gen.ListPlatformJobs200JSONResponse(out), nil
}

// ListPlatformTenantJobs implements GET /platform/tenants/{tenantId}/jobs (P4-T02 — the recent jobs of the tenant
// detail of the Platform Console; mounted through httpapi.PlatformTenantView). A platform route: the {tenantId} of the
// path filters the platform registry, it is not a tenant context (the decision carries no tenant). Every job returned
// must carry the tenant of the path, otherwise 500 — a job of another tenant is never sent.
func (h *Handlers) ListPlatformTenantJobs(ctx context.Context, req gen.ListPlatformTenantJobsRequestObject) (gen.ListPlatformTenantJobsResponseObject, error) {
	if err := platformDecision(ctx); err != nil {
		return nil, err
	}
	p := req.Params
	f, err := filter(p.Limit, p.Cursor, p.Status, p.Kind)
	if err != nil {
		return nil, err
	}
	list, err := h.svc.ListPlatformTenantJobs(ctx, req.TenantId, f)
	if err != nil {
		return nil, serviceError(err, p.Cursor != nil)
	}
	for _, j := range list.Items {
		if j.TenantID == nil || *j.TenantID != req.TenantId {
			return nil, problem.Internal(errForeignJob)
		}
	}
	return gen.ListPlatformTenantJobs200JSONResponse(jobList(list)), nil
}

// GetPlatformJob implements GET /platform/jobs/{jobId}.
func (h *Handlers) GetPlatformJob(ctx context.Context, req gen.GetPlatformJobRequestObject) (gen.GetPlatformJobResponseObject, error) {
	if err := platformDecision(ctx); err != nil {
		return nil, err
	}
	j, err := h.svc.GetPlatformJob(ctx, req.JobId)
	if err != nil {
		return nil, serviceError(err, false)
	}
	if j.ID != req.JobId {
		return nil, problem.Internal(errOtherJob)
	}
	out := platformJob(j)
	if t, ok := h.tenantLabels(ctx, j.TenantID).Tenant(j.TenantID); ok {
		out.TenantSlug, out.TenantName = &t.Slug, &t.Name
	}
	return gen.GetPlatformJob200JSONResponse(out), nil
}

// tenantDecision checks the decision of a tenant route: about this tenant, a grant on every resource of it.
func tenantDecision(ctx context.Context, tenantID uuid.UUID) error {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return problem.Internal(errNoDecision)
	case tenantID == uuid.Nil || d.TenantID != tenantID:
		return problem.Internal(errWrongDecision)
	case d.OwnOnly: // jobs are not owned by a member: an own-only grant would read every member's jobs
		p := problem.New(gen.ProblemCodeForbidden, "The request is not allowed.")
		p.Cause = &authz.Denial{Kind: authz.ErrForbidden, Reason: ReasonOwnOnlyGrant} // for the audit, never sent
		return p
	}
	return nil
}

// platformDecision checks the decision of a platform route (no tenant).
func platformDecision(ctx context.Context) error {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return problem.Internal(errNoDecision)
	case d.TenantID != uuid.Nil:
		return problem.Internal(errWrongDecision)
	}
	return nil
}

const invalidQuery = "The query parameters are invalid."

// filter maps the query parameters (the generated binding checked their types, not their ranges or values).
func filter(limit *int, cursor *string, status *gen.JobStatus, kind *string) (jobs.ListFilter, error) {
	var f jobs.ListFilter
	if limit != nil {
		if *limit < 1 || *limit > jobs.MaxLimit {
			return f, problem.Validation(invalidQuery, problem.Field("limit", "out_of_range", "must be between 1 and 200"))
		}
		f.Limit = *limit
	}
	if status != nil {
		if !status.Valid() {
			return f, problem.Validation(invalidQuery, problem.Field("status", "invalid", "not a job status"))
		}
		f.Status = string(*status)
	}
	if kind != nil {
		if *kind == "" {
			return f, problem.Validation(invalidQuery, problem.Field("kind", "invalid", "not a job kind"))
		}
		f.Kind = *kind
	}
	if cursor != nil {
		if *cursor == "" {
			return f, problem.Validation(invalidQuery, problem.Field("cursor", "invalid", "not a cursor of this list"))
		}
		f.Cursor = *cursor
	}
	return f, nil
}

// serviceError maps an error of the service: an invalid kind or cursor is 422 naming it, a job missing in the
// caller's scope (also another tenant's) 404, anything else 500 (internal log only).
func serviceError(err error, hadCursor bool) error {
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		return problem.New(gen.ProblemCodeNotFound, "The resource does not exist.")
	case errors.Is(err, jobs.ErrInvalidFilter):
		field, msg := "kind", "not a job kind"
		if hadCursor && strings.Contains(err.Error(), "cursor") {
			field, msg = "cursor", "not a cursor of this list"
		}
		return problem.Validation(invalidQuery, problem.Field(field, "invalid", msg))
	}
	return problem.Internal(err)
}

func jobList(l jobs.JobList) gen.JobList {
	out := gen.JobList{Items: make([]gen.Job, 0, len(l.Items)), NextCursor: l.NextCursor}
	for _, j := range l.Items {
		out.Items = append(out.Items, job(j))
	}
	return out
}

// ToAPI maps the safe projection of a job to schema Job (the body of 202 answers of other handler sets).
func ToAPI(j jobs.Job) gen.Job { return job(j) }

// job maps the safe projection (schema Job): steps with their catalog message, the error code only.
func job(j jobs.Job) gen.Job {
	out := gen.Job{Id: j.ID, Kind: j.Kind, TenantId: j.TenantID, Status: gen.JobStatus(j.Status),
		CurrentStep: j.CurrentStep, Resource: resource(j.Resource), Steps: make([]gen.JobStep, 0, len(j.Steps)),
		CreatedAt: j.CreatedAt.UTC()}
	for _, s := range j.Steps {
		out.Steps = append(out.Steps, step(s))
	}
	if j.Error != nil {
		out.Error = &gen.JobError{Code: j.Error.Code}
	}
	return out
}

// platformJob maps the platform view (schema PlatformJob): raw, redacted step detail and the full error.
func platformJob(j jobs.PlatformJob) gen.PlatformJob {
	out := gen.PlatformJob{Id: j.ID, Kind: j.Kind, TenantId: j.TenantID, Status: gen.JobStatus(j.Status),
		CurrentStep: j.CurrentStep, Resource: resource(j.Resource), Steps: make([]gen.PlatformJobStep, 0, len(j.Steps)),
		CreatedAt: j.CreatedAt.UTC()}
	for _, s := range j.Steps {
		ps := step(s.Step)
		p := gen.PlatformJobStep{Name: ps.Name, Status: ps.Status, Attempt: ps.Attempt, StartedAt: ps.StartedAt,
			FinishedAt: ps.FinishedAt, Message: ps.Message}
		if s.CompensationStatus != nil {
			c := gen.JobStepStatus(*s.CompensationStatus)
			p.CompensationStatus = &c
		}
		if len(s.Detail) > 0 {
			d := s.Detail
			p.Detail = &d
		}
		out.Steps = append(out.Steps, p)
	}
	if j.Error != nil {
		e := &gen.PlatformJobError{Code: j.Error.Code, Message: j.Error.Message}
		if len(j.Error.Detail) > 0 {
			d := j.Error.Detail
			e.Detail = &d
		}
		out.Error = e
	}
	return out
}

func step(s jobs.Step) gen.JobStep {
	return gen.JobStep{Name: s.Name, Status: gen.JobStepStatus(s.Status), Attempt: s.Attempt, StartedAt: utc(s.StartedAt),
		FinishedAt: utc(s.FinishedAt), Message: s.Message}
}

func resource(r *jobs.Resource) *gen.ResourceRef {
	if r == nil {
		return nil
	}
	return &gen.ResourceRef{Type: r.Type, Id: r.ID}
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
