package backup

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ErrorKind classifies an error of the API side.
type ErrorKind int

const (
	ErrNotFound              ErrorKind = iota + 1 // 404
	ErrState                                      // 409: the instance or the backup cannot be backed up / restored now
	ErrInvalid                                    // 422
	ErrIdempotencyInProgress                      // 409 + Retry-After
	ErrIdempotencyKeyReuse                        // 422
)

// Error is a refusal of the API side, with a stable reason.
type Error struct {
	Kind       ErrorKind
	Reason     string
	Detail     string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return "backup: " + e.Reason + ": " + e.Detail }

// AsError returns the *Error in err.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// Idempotency is the Idempotency-Key of a request and the hash of the request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

const idempotencyLock = 2 * time.Minute

// RequestBackup is POST /platform/instances/{id}/backup: an instance.backup job now (dedupe slot "api": while one is
// queued or running, the same job is returned). The request is audited instance.backup.requested (platform event) and
// handed off to the job, which closes the pair.
func (s *Service) RequestBackup(ctx context.Context, actor, instanceID uuid.UUID, idem *Idempotency) (jobs.Job, bool, error) {
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: actor, OperationID: "backupPlatformInstance", Key: idem.Key}
		replay, err := s.beginIdempotent(ctx, *key, idem.Hash)
		if err != nil {
			return jobs.Job{}, false, err
		}
		if replay != nil {
			return *replay, false, nil
		}
	}
	var (
		job     jobs.Job
		created bool
		op      audit.Operation
	)
	err := s.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		r, err := tx.Q.GetInstanceForBackup(ctx, instanceID)
		if errors.Is(err, store.ErrNoRows) {
			return &Error{Kind: ErrNotFound, Reason: "not_found", Detail: "no such instance"}
		}
		if err != nil {
			return err
		}
		if why := (instance{r}).eligible(); why != "" {
			return &Error{Kind: ErrState, Reason: why, Detail: "the instance cannot be backed up in its current state"}
		}
		op, err = audit.Requested(ctx, tx.Q, audit.Event{Action: AuditBackup, ResourceType: "instance", ResourceID: instanceID.String(),
			Details: audit.Details{"tenant_id": r.TenantID.String()}})
		if err != nil {
			return err
		}
		tenant := r.TenantID
		spec := jobs.Spec{Kind: KindBackup, TenantID: &tenant, InstanceID: &instanceID, Slot: SlotAPI,
			Input: BackupInput{Trigger: TriggerAPI, Operation: &op}, RequestedBy: &actor,
			Resource: &jobs.Resource{Type: "instance", ID: instanceID.String()}}
		if key != nil {
			spec.RequestKey = key.Key
		}
		enq, err := jobs.Enqueue(ctx, tx, spec)
		switch {
		case errors.Is(err, jobs.ErrDedupeConflict):
			return &Error{Kind: ErrState, Reason: "lifecycle_busy", Detail: "another job holds the instance"}
		case errors.Is(err, jobs.ErrRequestKeyReuse):
			return &Error{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
		case err != nil:
			return err
		}
		job, created = enq.Job, enq.Created
		if key == nil {
			return nil
		}
		body, err := json.Marshal(job)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, tx.Q, *key, idem.Hash, jobs.StoredResponse{Status: 202, Body: body,
			Resource: &jobs.Resource{Type: "job", ID: job.ID.String()}})
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
			})
		}
		return jobs.Job{}, false, err
	}
	if created {
		audit.HandOff(ctx, op)
	}
	return job, created, nil
}

func (s *Service) beginIdempotent(ctx context.Context, key jobs.IdempotencyKey, hash []byte) (*jobs.Job, error) {
	var replay *jobs.Job
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		d, err := jobs.BeginIdempotent(ctx, q, key, hash, idempotencyLock)
		if err != nil {
			return err
		}
		switch d.Outcome {
		case jobs.IdempotencyReplay:
			var j jobs.Job
			if d.Response == nil || json.Unmarshal(d.Response.Body, &j) != nil || j.ID == uuid.Nil {
				return errors.New("backup: stored response unreadable")
			}
			replay = &j
		case jobs.IdempotencyInProgress:
			return &Error{Kind: ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
		case jobs.IdempotencyKeyReuse:
			return &Error{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
		}
		return nil
	})
	return replay, err
}

// CheckRestore validates a restore request before the approval request exists (POST /platform/instances/{id}/restore):
// the backup is a succeeded backup of this very instance, the instance can be restored.
func (s *Service) CheckRestore(ctx context.Context, p RestorePayload) error {
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := checkRestore(ctx, q, p)
		return err
	})
}

func checkRestore(ctx context.Context, q *sqlcdb.Queries, p RestorePayload) (sqlcdb.GetInstanceForBackupRow, error) {
	if err := p.Validate(); err != nil {
		return sqlcdb.GetInstanceForBackupRow{}, &Error{Kind: ErrInvalid, Reason: "invalid", Detail: err.Error()}
	}
	inst, err := q.GetInstanceForBackup(ctx, p.InstanceID)
	if errors.Is(err, store.ErrNoRows) {
		return inst, &Error{Kind: ErrNotFound, Reason: "not_found", Detail: "no such instance"}
	}
	if err != nil {
		return inst, err
	}
	b, err := q.GetBackupForRestoreRequest(ctx, p.BackupID)
	switch {
	case errors.Is(err, store.ErrNoRows), err == nil && (b.Kind != "instance" || b.InstanceID == nil || *b.InstanceID != p.InstanceID):
		return inst, &Error{Kind: ErrInvalid, Reason: "backup_not_of_instance", Detail: "backup_id names no backup of this instance"}
	case err != nil:
		return inst, err
	case b.Status != "succeeded":
		return inst, &Error{Kind: ErrState, Reason: "backup_not_restorable", Detail: "the backup is " + b.Status}
	}
	if why := (instance{inst}).eligible(); why != "" {
		return inst, &Error{Kind: ErrState, Reason: why, Detail: "the instance cannot be restored in its current state"}
	}
	return inst, nil
}

// EnqueueRestore is the execution of an approved platform.instance.restore (apps/internal/runner registers the
// approval action — authz must not import provisioning): in the approval's transaction the backup and the instance
// are checked again, the operation audited and the lifecycle job instance.restore enqueued.
func (s *Service) EnqueueRestore(ctx context.Context, tx *store.Tx, requestedBy, approvalID uuid.UUID, p RestorePayload) (*uuid.UUID, error) {
	inst, err := checkRestore(ctx, tx.Q, p)
	if err != nil {
		return nil, err
	}
	op, err := audit.Requested(ctx, tx.Q, audit.Event{Action: AuditRestore, ResourceType: "instance", ResourceID: p.InstanceID.String(),
		Details: audit.Details{"tenant_id": inst.TenantID.String(), "backup_id": p.BackupID.String(), "approval_id": approvalID.String(),
			"restore_point_older_than_backup": p.RestorePointOlderThanBackup}})
	if err != nil {
		return nil, err
	}
	tenant, instanceID := inst.TenantID, p.InstanceID
	enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindRestore, TenantID: &tenant, InstanceID: &instanceID,
		Input: RestoreInput{RestorePayload: p, ApprovalID: approvalID, Operation: &op}, RequestedBy: &requestedBy,
		Resource: &jobs.Resource{Type: "instance", ID: instanceID.String()}})
	switch {
	case errors.Is(err, jobs.ErrDedupeConflict):
		return nil, &Error{Kind: ErrState, Reason: "lifecycle_busy", Detail: "another lifecycle job of the tenant is unfinished"}
	case err != nil:
		return nil, err
	case !enq.Created:
		return nil, &Error{Kind: ErrState, Reason: "restore_running", Detail: "a restore of this instance is unfinished"}
	}
	audit.HandOff(ctx, op)
	id := enq.Job.ID
	return &id, nil
}

// ---------------------------------------------------------------------------------------------------- GET /platform/backups

// Filter of GET /platform/backups.
type Filter struct {
	TenantID, InstanceID *uuid.UUID
	Status               string
	Limit                int
	Cursor               string
}

// View is one backup row (no wrapped key, no manifest body — their digest only).
type View struct {
	ID               uuid.UUID
	TenantID         *uuid.UUID
	InstanceID       *uuid.UUID
	Kind             string
	Status           string
	Sequence         *int64
	Method           *string
	SizeBytes        *int64
	SHA256           *string
	ManifestSHA256   *string
	HeadscaleVersion *string
	StorageURI       string
	StartedAt        time.Time
	FinishedAt       *time.Time
	ExpiresAt        *time.Time
	VerifiedAt       *time.Time
	JobID            *uuid.UUID
}

// Page is one page of backups.
type Page struct {
	Items      []View
	NextCursor string
}

// Statuses of a backup row (0011).
var Statuses = []string{"running", "succeeded", "failed", "purged"}

// DefaultLimit / MaxLimit of a page (§13.1).
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// List is GET /platform/backups: newest first.
func (s *Service) List(ctx context.Context, f Filter) (Page, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return Page{}, &Error{Kind: ErrInvalid, Reason: "invalid_limit", Detail: fmt.Sprintf("limit must be 1–%d", MaxLimit)}
	}
	p := sqlcdb.ListPlatformBackupsPageParams{TenantID: f.TenantID, InstanceID: f.InstanceID, RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if f.Status != "" {
		if !slices.Contains(Statuses, f.Status) {
			return Page{}, &Error{Kind: ErrInvalid, Reason: "invalid_status", Detail: "unknown backup status"}
		}
		p.Status = &f.Status
	}
	if f.Cursor != "" {
		t, id, ok := decodeCursor(f.Cursor)
		if !ok {
			return Page{}, &Error{Kind: ErrInvalid, Reason: "invalid_cursor", Detail: "the cursor is not one of this list"}
		}
		p.BeforeStartedAt, p.BeforeID = &t, &id
	}
	var out Page
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListPlatformBackupsPage(ctx, p)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1]
			out.NextCursor = encodeCursor(last.StartedAt, last.ID)
		}
		out.Items = make([]View, 0, len(rows))
		for _, r := range rows {
			out.Items = append(out.Items, View{ID: r.ID, TenantID: r.TenantID, InstanceID: r.InstanceID, Kind: r.Kind, Status: r.Status,
				Sequence: r.Sequence, Method: r.Method, SizeBytes: r.SizeBytes, SHA256: r.Sha256, ManifestSHA256: r.ManifestSha256,
				HeadscaleVersion: r.HeadscaleVersion, StorageURI: r.StorageUri, StartedAt: r.StartedAt.UTC(), FinishedAt: r.FinishedAt,
				ExpiresAt: r.ExpiresAt, VerifiedAt: r.VerifiedAt, JobID: r.JobID})
		}
		return nil
	})
	return out, err
}

const cursorVersion = 1

var b64 = base64.RawURLEncoding

func encodeCursor(t time.Time, id uuid.UUID) string {
	b := make([]byte, 0, 1+8+16)
	b = append(b, cursorVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(t.UnixMicro())) //nolint:gosec // timestamps after 1970
	b = append(b, id[:]...)
	return b64.EncodeToString(b)
}

func decodeCursor(s string) (time.Time, uuid.UUID, bool) {
	b, err := b64.Strict().DecodeString(s)
	if err != nil || len(b) != 1+8+16 || b[0] != cursorVersion {
		return time.Time{}, uuid.Nil, false
	}
	micros := binary.BigEndian.Uint64(b[1:9])
	if micros > 1<<62 {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.FromBytes(b[9:])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.UnixMicro(int64(micros)).UTC(), id, true
}
