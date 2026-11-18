// Package backupapi serves the backup/restore operations of P3-T11 (§13.2 platform, §8.5):
//
//   - backupPlatformInstance — POST /platform/instances/{instanceId}/backup (platform.instance:operate): an
//     instance.backup job now, 202 + Location of the job;
//   - restorePlatformInstance — POST /platform/instances/{instanceId}/restore (platform.instance:restore, always dual
//     control): a request of action platform.instance.restore through internal/authz/approvals, 202 + Location of
//     /platform/approvals/{id}; the approved payload ({backup_id, instance_id, restore_point_older_than_backup}) is
//     the only input of the instance.restore job (executed by the action apps/internal/runner registers);
//   - listPlatformBackups — GET /platform/backups (platform.backup:read): the `backups` rows, newest first.
//
// Wiring (apps/internal/runner — api process): httpapi.Handlers{…, Backups: backupapi.New(backupSvc, approvalsSvc)}.
package backupapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
)

// Backups is the part of *backup.Service the handlers use.
type Backups interface {
	RequestBackup(ctx context.Context, actor, instanceID uuid.UUID, idem *backup.Idempotency) (jobs.Job, bool, error)
	CheckRestore(ctx context.Context, p backup.RestorePayload) error
	List(ctx context.Context, f backup.Filter) (backup.Page, error)
}

// Approvals is the part of *approvals.Service the restore request uses.
type Approvals interface {
	RequestIdempotent(ctx context.Context, actor approvals.Actor, in approvals.NewRequest, idem approvals.Idempotency) (approvals.Request, error)
}

var (
	_ Backups   = (*backup.Service)(nil)
	_ Approvals = (*approvals.Service)(nil)
)

// Handlers implements httpapi.BackupHandlers.
type Handlers struct {
	svc  Backups
	appr Approvals
}

var _ httpapi.BackupHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T11.
func New(svc Backups, appr Approvals) *Handlers { return &Handlers{svc: svc, appr: appr} }

const restoreOperation = "restorePlatformInstance"

var errNoSession = errors.New("backupapi: no session or decision in the request context (hooks missing)")

func caller(ctx context.Context) (*identity.Session, authz.Decision, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID || d.TenantID != uuid.Nil {
		return nil, authz.Decision{}, problem.Internal(errNoSession)
	}
	return s, d, nil
}

// BackupPlatformInstance implements POST /platform/instances/{instanceId}/backup.
func (h *Handlers) BackupPlatformInstance(ctx context.Context, req gen.BackupPlatformInstanceRequestObject) (gen.BackupPlatformInstanceResponseObject, error) {
	s, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	path := "/platform/instances/" + req.InstanceId.String() + "/backup"
	job, created, err := h.svc.RequestBackup(ctx, s.IdentityID, req.InstanceId,
		&backup.Idempotency{Key: req.Params.IdempotencyKey, Hash: jobs.RequestHash("POST", path, nil)})
	if err != nil {
		return nil, failure(err)
	}
	if !created {
		if r := audit.RequestFrom(ctx); r != nil {
			r.ReadOnly = true // the job of an earlier request (or its replay): nothing new was written
		}
	}
	return gen.BackupPlatformInstance202JSONResponse{Body: jobsapi.ToAPI(job),
		Headers: gen.BackupPlatformInstance202ResponseHeaders{Location: "/api/v1/platform/jobs/" + job.ID.String()}}, nil
}

// RestorePlatformInstance implements POST /platform/instances/{instanceId}/restore: always a 2P request.
func (h *Handlers) RestorePlatformInstance(ctx context.Context, req gen.RestorePlatformInstanceRequestObject) (gen.RestorePlatformInstanceResponseObject, error) {
	s, d, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if !d.NeedsApproval() { // x-dual-control: never run directly (§8.5)
		return nil, problem.Internal(errors.New("backupapi: the decision does not require a second approver"))
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	if r := strings.TrimSpace(req.Body.Reason); r == "" || utf8.RuneCountInString(r) > 1000 {
		return nil, problem.Validation("The request is invalid.",
			problem.Field("reason", "required", "a reason (1–1000 characters) is required: the approver reads it"))
	}
	p := backup.RestorePayload{BackupID: req.Body.BackupId, InstanceID: req.InstanceId}
	if req.Body.RestorePointOlderThanBackup != nil {
		p.RestorePointOlderThanBackup = *req.Body.RestorePointOlderThanBackup
	}
	if err := h.svc.CheckRestore(ctx, p); err != nil {
		return nil, failure(err)
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	r, err := h.appr.RequestIdempotent(ctx, approvals.Actor{IdentityID: s.IdentityID, Scope: authz.ScopePlatform, AuthTime: s.AuthTime},
		approvals.NewRequest{Action: backup.ActionRestore, ResourceID: req.InstanceId.String(), Payload: p, Reason: req.Body.Reason},
		approvals.Idempotency{Operation: restoreOperation, Key: req.Params.IdempotencyKey,
			Hash: jobs.RequestHash("POST", "/platform/instances/"+req.InstanceId.String()+"/restore", body)})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.RestorePlatformInstance202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.RestorePlatformInstance202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

// ListPlatformBackups implements GET /platform/backups.
func (h *Handlers) ListPlatformBackups(ctx context.Context, req gen.ListPlatformBackupsRequestObject) (gen.ListPlatformBackupsResponseObject, error) {
	f := backup.Filter{InstanceID: req.Params.Instance}
	if req.Params.Limit != nil {
		f.Limit = *req.Params.Limit
		if f.Limit == 0 {
			f.Limit = -1 // an explicit 0 is out of range, not "the default"
		}
	}
	if req.Params.Cursor != nil {
		f.Cursor = *req.Params.Cursor
	}
	if req.Params.Status != nil {
		f.Status = string(*req.Params.Status)
	}
	page, err := h.svc.List(ctx, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.BackupList{Items: make([]gen.Backup, 0, len(page.Items))}
	for _, v := range page.Items {
		b := gen.Backup{Id: v.ID, Kind: gen.BackupKind(v.Kind), Status: gen.BackupStatus(v.Status), TenantId: v.TenantID,
			InstanceId: v.InstanceID, Sequence: v.Sequence, SizeBytes: v.SizeBytes, Sha256: v.SHA256, ManifestSha256: v.ManifestSHA256,
			HeadscaleVersion: v.HeadscaleVersion, StorageUri: v.StorageURI, StartedAt: v.StartedAt, FinishedAt: v.FinishedAt,
			ExpiresAt: v.ExpiresAt, VerifiedAt: v.VerifiedAt, JobId: v.JobID}
		if v.Method != nil {
			m := gen.BackupMethod(*v.Method)
			b.Method = &m
		}
		out.Items = append(out.Items, b)
	}
	if page.NextCursor != "" {
		out.NextCursor = &page.NextCursor
	}
	return gen.ListPlatformBackups200JSONResponse(out), nil
}

// failure maps an error of the backup service to a problem (the Cause carries a stable reason for the audit).
func failure(err error) error {
	e, ok := backup.AsError(err)
	if !ok {
		return problem.Internal(err)
	}
	cause := &authz.Denial{Kind: err, Reason: e.Reason}
	switch e.Kind {
	case backup.ErrNotFound:
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case backup.ErrInvalid:
		field := "body"
		switch e.Reason {
		case "invalid_limit":
			field = "limit"
		case "invalid_cursor":
			field = "cursor"
		case "invalid_status":
			field = "status"
		case "backup_not_of_instance":
			field = "backup_id"
		}
		return problem.Validation("The request is invalid.", problem.Field(field, e.Reason, e.Detail))
	case backup.ErrIdempotencyInProgress:
		return &problem.Error{Code: gen.ProblemCodeConflict, Cause: cause, RetryAfter: e.RetryAfter,
			Detail: "A request with this Idempotency-Key is still in progress."}
	case backup.ErrIdempotencyKeyReuse:
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	}
	return &problem.Error{Code: gen.ProblemCodeConflict, Detail: e.Detail, Cause: cause}
}
