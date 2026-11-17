package jobs

// Backend of the job endpoints (§13.2 "jobs", api/openapi.yaml — P2-T02): GET /tenants/{tenantId}/jobs[/{jobId}]
// (listTenantJobs, getTenantJob — tenant.job:read) and GET /platform/jobs[/{jobId}] (listPlatformJobs, getPlatformJob —
// platform.job:read). The route permission is checked before (httpapi + authz); scope is enforced again here: tenant
// calls run in WithTenantTx (RLS) and also filter on tenant_id (§8.8 layer 5).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Resource is the resource a job creates or acts on (schema ResourceRef).
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Job is the safe projection of a job — schema Job (§13.3): the tenant view and every list. A step's message comes
// from a fixed catalog keyed by status and code, the error carries only its stable code: no raw error, host path,
// container name, internal address or other tenant's identifier.
type Job struct {
	ID          uuid.UUID  `json:"id"`
	Kind        string     `json:"kind"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Status      string     `json:"status"`
	CurrentStep *string    `json:"current_step"`
	Resource    *Resource  `json:"resource,omitempty"`
	Steps       []Step     `json:"steps"`
	Error       *ErrorCode `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Step is a step of the safe projection (schema JobStep).
type Step struct {
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	Attempt    int        `json:"attempt"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Message    *string    `json:"message"`
}

// ErrorCode is the error of the safe projection (schema JobError).
type ErrorCode struct {
	Code string `json:"code"`
}

// JobList is one page (schema JobList).
type JobList struct {
	Items      []Job   `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// PlatformJob is a job with the raw (redacted) detail of each step and its full error — schema PlatformJob, returned
// only by GET /platform/jobs/{jobId}.
type PlatformJob struct {
	ID          uuid.UUID      `json:"id"`
	Kind        string         `json:"kind"`
	TenantID    *uuid.UUID     `json:"tenant_id,omitempty"`
	Status      string         `json:"status"`
	CurrentStep *string        `json:"current_step"`
	Resource    *Resource      `json:"resource,omitempty"`
	Steps       []PlatformStep `json:"steps"`
	Error       *PlatformError `json:"error,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// PlatformStep is a step with its raw detail (schema PlatformJobStep).
type PlatformStep struct {
	Step
	Detail map[string]any `json:"detail,omitempty"`
}

// PlatformError is the full error of a job (schema PlatformJobError).
type PlatformError struct {
	Code    string         `json:"code"`
	Message *string        `json:"message,omitempty"`
	Detail  map[string]any `json:"detail,omitempty"`
}

// ListFilter holds the query parameters of the list endpoints.
type ListFilter struct {
	Status string // "" or a job status
	Kind   string // "" or a job kind
	Limit  int    // 0 ⇒ DefaultLimit; 1…MaxLimit
	Cursor string // next_cursor of the previous page
}

// Page sizes of §13.1.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var (
	// ErrInvalidFilter: a filter, limit or cursor out of range ⇒ 422 validation_failed.
	ErrInvalidFilter = errors.New("jobs: invalid list parameters")
	// ErrNotFound: no such job in the caller's scope — also for another tenant's job ⇒ 404 not_found (§13.1).
	ErrNotFound = errors.New("jobs: job not found")
)

// kindParam is the JobKind pattern of api/openapi.yaml.
var kindParam = regexp.MustCompile(`^[a-z][a-z_]*(\.[a-z][a-z_]*)+$`)

// Service answers the job endpoints.
type Service struct {
	st *store.Store
}

// NewService returns the job API backend on st (the api process's store).
func NewService(st *store.Store) *Service { return &Service{st: st} }

// ListTenantJobs is GET /tenants/{tenantId}/jobs: the tenant's jobs, newest first.
func (s *Service) ListTenantJobs(ctx context.Context, tenantID uuid.UUID, f ListFilter) (JobList, error) {
	p, limit, err := f.params()
	if err != nil {
		return JobList{}, err
	}
	p.TenantID = &tenantID
	var out JobList
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		out, err = listPage(ctx, q, p, limit)
		return err
	})
	return out, err
}

// GetTenantJob is GET /tenants/{tenantId}/jobs/{jobId}.
func (s *Service) GetTenantJob(ctx context.Context, tenantID, jobID uuid.UUID) (Job, error) {
	var out Job
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		row, steps, err := getJob(ctx, q, jobID)
		if err != nil {
			return err
		}
		if row.TenantID == nil || *row.TenantID != tenantID {
			return ErrNotFound
		}
		out = project(row, steps)
		return nil
	})
	return out, err
}

// ListPlatformJobs is GET /platform/jobs: jobs of the platform and of every tenant, safe projection.
func (s *Service) ListPlatformJobs(ctx context.Context, f ListFilter) (JobList, error) {
	p, limit, err := f.params()
	if err != nil {
		return JobList{}, err
	}
	var out JobList
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		out, err = listPage(ctx, q, p, limit)
		return err
	})
	return out, err
}

// GetPlatformJob is GET /platform/jobs/{jobId}: the job with raw step detail and its full error.
func (s *Service) GetPlatformJob(ctx context.Context, jobID uuid.UUID) (PlatformJob, error) {
	var out PlatformJob
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, steps, err := getJob(ctx, q, jobID)
		if err != nil {
			return err
		}
		out = projectPlatform(row, steps)
		return nil
	})
	return out, err
}

func getJob(ctx context.Context, q *sqlcdb.Queries, id uuid.UUID) (sqlcdb.ProvisioningJob, []sqlcdb.ProvisioningJobStep, error) {
	row, err := q.GetJob(ctx, id)
	if errors.Is(err, store.ErrNoRows) {
		return row, nil, ErrNotFound
	}
	if err != nil {
		return row, nil, err
	}
	steps, err := q.ListJobSteps(ctx, []uuid.UUID{id})
	return row, steps, err
}

func listPage(ctx context.Context, q *sqlcdb.Queries, p sqlcdb.ListJobsPageParams, limit int) (JobList, error) {
	rows, err := q.ListJobsPage(ctx, p)
	if err != nil {
		return JobList{}, err
	}
	out := JobList{Items: make([]Job, 0, min(len(rows), limit))}
	if len(rows) > limit {
		rows = rows[:limit]
		c := encodeCursor(rows[limit-1].CreatedAt, rows[limit-1].ID)
		out.NextCursor = &c
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	steps, err := q.ListJobSteps(ctx, ids)
	if err != nil {
		return JobList{}, err
	}
	byJob := map[uuid.UUID][]sqlcdb.ProvisioningJobStep{}
	for _, st := range steps {
		byJob[st.JobID] = append(byJob[st.JobID], st)
	}
	for _, r := range rows {
		out.Items = append(out.Items, project(r, byJob[r.ID]))
	}
	return out, nil
}

// params validates the filter and builds the query parameters (one row more than the page, to know if one follows).
func (f ListFilter) params() (sqlcdb.ListJobsPageParams, int, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return sqlcdb.ListJobsPageParams{}, 0, fmt.Errorf("%w: limit must be 1–%d", ErrInvalidFilter, MaxLimit)
	}
	p := sqlcdb.ListJobsPageParams{RowLimit: int32(limit + 1)} //nolint:gosec // bounded above
	if f.Status != "" {
		if !slices.Contains(Statuses, f.Status) {
			return p, 0, fmt.Errorf("%w: unknown status", ErrInvalidFilter)
		}
		p.Status = &f.Status
	}
	if f.Kind != "" {
		if !kindParam.MatchString(f.Kind) || len(f.Kind) > 64 {
			return p, 0, fmt.Errorf("%w: invalid kind", ErrInvalidFilter)
		}
		p.Kind = &f.Kind
	}
	if f.Cursor != "" {
		t, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return p, 0, err
		}
		p.AfterCreatedAt, p.AfterID = &t, &id
	}
	return p, limit, nil
}

// The cursor is opaque to clients: base64url of "<created_at RFC 3339>|<id>" of the last item of the page.
func encodeCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeCursor(s string) (time.Time, uuid.UUID, error) {
	bad := fmt.Errorf("%w: invalid cursor", ErrInvalidFilter)
	if len(s) > 512 {
		return time.Time{}, uuid.Nil, bad
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, uuid.Nil, bad
	}
	ts, idStr, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, bad
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, uuid.Nil, bad
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return time.Time{}, uuid.Nil, bad
	}
	return t, id, nil
}

// storedError is provisioning_jobs.error.
type storedError struct {
	Code    string         `json:"code"`
	Message string         `json:"message,omitempty"`
	Detail  map[string]any `json:"detail,omitempty"`
}

func decodeError(b []byte) *storedError {
	if len(b) == 0 {
		return nil
	}
	var e storedError
	if json.Unmarshal(b, &e) != nil || !codeRE.MatchString(e.Code) {
		return &storedError{Code: CodeHandlerError}
	}
	return &e
}

func resourceOf(r sqlcdb.ProvisioningJob) *Resource {
	if r.ResourceType == nil || r.ResourceID == nil {
		return nil
	}
	return &Resource{Type: *r.ResourceType, ID: *r.ResourceID}
}

// project builds the safe projection.
func project(r sqlcdb.ProvisioningJob, steps []sqlcdb.ProvisioningJobStep) Job {
	j := Job{ID: r.ID, Kind: r.Kind, TenantID: r.TenantID, Status: r.Status, CurrentStep: r.CurrentStep,
		Resource: resourceOf(r), Steps: make([]Step, 0, len(steps)), CreatedAt: r.CreatedAt}
	for _, s := range steps {
		j.Steps = append(j.Steps, safeStep(s))
	}
	if e := decodeError(r.Error); e != nil {
		j.Error = &ErrorCode{Code: e.Code}
	}
	return j
}

// projectPlatform builds the platform view.
func projectPlatform(r sqlcdb.ProvisioningJob, steps []sqlcdb.ProvisioningJobStep) PlatformJob {
	j := PlatformJob{ID: r.ID, Kind: r.Kind, TenantID: r.TenantID, Status: r.Status, CurrentStep: r.CurrentStep,
		Resource: resourceOf(r), Steps: make([]PlatformStep, 0, len(steps)), CreatedAt: r.CreatedAt}
	for _, s := range steps {
		ps := PlatformStep{Step: safeStep(s)}
		if len(s.Detail) > 0 {
			_ = json.Unmarshal(s.Detail, &ps.Detail)
		}
		j.Steps = append(j.Steps, ps)
	}
	if e := decodeError(r.Error); e != nil {
		pe := &PlatformError{Code: e.Code, Detail: e.Detail}
		if e.Message != "" {
			m := scrub(e.Message)
			pe.Message = &m
		}
		j.Error = pe
	}
	return j
}

func safeStep(s sqlcdb.ProvisioningJobStep) Step {
	return Step{Name: s.Name, Status: s.Status, Attempt: int(s.Attempt), StartedAt: s.StartedAt, FinishedAt: s.FinishedAt,
		Message: stepMessage(s.Status, s.ErrorCode)}
}

// codeText is the message catalog of the framework's codes; handler codes are shown as the code itself (they match
// ^[a-z][a-z0-9_]{0,63}$ — CHECK of provisioning_job_steps.error_code).
var codeText = map[string]string{
	CodeTimeout:            "the job ran past its time limit",
	CodeWorkerLost:         "the worker running the job stopped responding",
	CodeQueueLost:          "the job queue dropped the job",
	CodeHandlerError:       "internal error",
	CodeHandlerPanic:       "internal error",
	CodeInterrupted:        "interrupted, will resume",
	CodeRetriesExhausted:   "no attempt left",
	CodeCompensationFailed: "rollback failed",
}

// stepMessage is the tenant-safe message of a step, from the catalog only (§13.3).
func stepMessage(status string, code *string) *string {
	var m string
	switch status {
	case StepRunning:
		m = "In progress"
	case StepSucceeded:
		m = "Completed"
	case StepSkipped:
		m = "Skipped"
	case StepFailed:
		m = "Failed"
		if code != nil && codeRE.MatchString(*code) {
			if t, ok := codeText[*code]; ok {
				m += ": " + t
			} else {
				m += " (" + *code + ")"
			}
		}
	default:
		return nil
	}
	return &m
}
