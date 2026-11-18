package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// BackupInput is the input of an instance.backup job (no secret).
type BackupInput struct {
	Trigger   string           `json:"trigger,omitempty"` // TriggerSchedule | TriggerAPI
	Operation *audit.Operation `json:"operation,omitempty"`
}

// BackupResult is the output of an instance.backup job.
type BackupResult struct {
	Skipped         string    `json:"skipped,omitempty"`
	BackupID        uuid.UUID `json:"backup_id,omitzero"`
	Sequence        uint64    `json:"sequence,omitempty"`
	Method          string    `json:"method,omitempty"`
	SizeBytes       uint64    `json:"size_bytes,omitempty"`
	ArchiveSHA256   string    `json:"archive_sha256,omitempty"`
	ManifestSHA256  string    `json:"manifest_sha256,omitempty"`
	CreatedAt       time.Time `json:"created_at,omitzero"`
	PurgedBackups   int64     `json:"purged_backups,omitempty"`
	RemovedArchives uint32    `json:"removed_archives,omitempty"`
}

// storageURI names an archive without any credential (the CHECK of 0011 forbids userinfo): the agent of the host, the
// instance, the sequence.
func storageURI(hostID, instanceID uuid.UUID, seq uint64) string {
	return fmt.Sprintf("agent://%s/backups/tenants/%s/%s", hostID, instanceID, backupfmt.ArchiveName(seq))
}

func (s *Service) runBackup(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil || run.InstanceID == nil {
		return jobs.Permanent("invalid_input", errors.New("instance.backup needs a tenant and an instance"))
	}
	var in BackupInput
	if err := run.DecodeInput(&in); err != nil {
		return jobs.Permanent("invalid_input", err)
	}
	res, err := s.backup(ctx, run.ID, *run.TenantID, *run.InstanceID)
	s.closeOperation(ctx, in.Operation, res, err)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := run.SetOutput(res); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	return nil
}

// closeOperation finishes the audit pair of an API-requested backup (platform event — the request was a platform one).
func (s *Service) closeOperation(ctx context.Context, op *audit.Operation, res BackupResult, err error) {
	if op == nil {
		return
	}
	var je *jobs.Error
	if err != nil && errors.As(err, &je) && !je.Permanent && !je.Stop {
		return // retried: the pair is closed by the last attempt
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	werr := s.st.WithPlatformTx(wctx, func(q *sqlcdb.Queries) error {
		if err != nil {
			code := "backup_failed"
			if je != nil {
				code = je.Code
			}
			return op.Failed(wctx, q, code, audit.Details{"instance_id": op.ResourceID})
		}
		return op.Succeeded(wctx, q, audit.Details{"backup_id": res.BackupID.String(), "sequence": res.Sequence,
			"method": res.Method, "skipped": res.Skipped})
	})
	if werr != nil {
		s.log.ErrorContext(ctx, "backup: closing the audit operation failed", "operation", op.ID.String())
	}
}

// backup — §17.1, one attempt.
func (s *Service) backup(ctx context.Context, jobID, tenantID, instanceID uuid.UUID) (BackupResult, error) {
	if err := s.enabled(); err != nil {
		return BackupResult{}, err
	}
	inst, err := s.instance(ctx, tenantID, instanceID)
	if err != nil {
		return BackupResult{}, err
	}
	if why := inst.eligible(); why != "" {
		return BackupResult{Skipped: why}, nil
	}
	// the tenant's backup key (SecretStore, under the tenant's DEK): created at the first backup
	keyRef, backupKey, err := s.backupKey(ctx, tenantID)
	if err != nil {
		return BackupResult{}, err
	}
	defer backupKey.Wipe()
	dataKey, err := backupfmt.NewDataKey()
	if err != nil {
		return BackupResult{}, jobs.Transient("random_unavailable", err)
	}
	defer clear(dataKey)
	recipient, err := backupfmt.DataRecipient(dataKey)
	if err != nil {
		return BackupResult{}, jobs.Permanent("data_key", err)
	}
	// sequence: strictly increasing per instance and time-based, so that it never repeats an archive name even when
	// PostgreSQL forgot rows (a restore of PostgreSQL to an older point — §17.2)
	var (
		rowID      uuid.UUID
		seq        uint64
		retainFrom uint64
	)
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		last, err := q.NextInstanceBackupSequence(ctx, &instanceID)
		if err != nil {
			return err
		}
		seq = max(uint64(last)+1, uint64(s.cfg.Now().UnixMilli())) //nolint:gosec // G115: positive values
		wrapped, err := backupfmt.WrapDataKey(backupKey.Bytes(), dataKey, tenantID, instanceID, seq)
		if err != nil {
			return err
		}
		ref, version, seqI := keyRef.String(), inst.HeadscaleVersion, int64(seq) //nolint:gosec // G115: < 2^63
		row, err := q.InsertInstanceBackup(ctx, sqlcdb.InsertInstanceBackupParams{TenantID: &tenantID, InstanceID: &instanceID,
			StorageUri: storageURI(inst.HostID, instanceID, seq), KeyRef: &ref, HeadscaleVersion: &version, JobID: &jobID,
			Sequence: &seqI, WrappedDataKey: wrapped})
		if err != nil {
			return err
		}
		rowID = row.ID
		// a row of an earlier attempt of a dead worker is failed now: no backup stays running
		if err := q.FailStaleInstanceBackups(ctx, sqlcdb.FailStaleInstanceBackupsParams{InstanceID: &instanceID, KeepID: rowID}); err != nil {
			return err
		}
		kept, err := q.ListSucceededInstanceBackups(ctx, &instanceID)
		if err != nil {
			return err
		}
		retainFrom = s.retainFrom(kept, seq)
		return nil
	})
	if err != nil {
		return BackupResult{}, jobs.Transient("registry_unavailable", err)
	}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.CallTimeout)
	defer cancel()
	resp, err := s.cfg.Agent.Backup(cctx, &agentv1.BackupRequest{Instance: inst.ref(), JobId: jobID.String(), Sequence: seq,
		DataRecipient: recipient, RetainFromSequence: retainFrom})
	if err != nil {
		jerr := agentErr("Backup", err)
		var je *jobs.Error
		if errors.As(jerr, &je) && je.Permanent {
			s.failRow(ctx, tenantID, rowID)
			if kind, sev := securityEventOf(err); kind != "" {
				d := refusalDetails(err)
				d["instance_id"], d["job_id"], d["sequence"] = instanceID.String(), jobID.String(), seq
				s.raise(ctx, tenantID, kind, sev, instanceID.String(), d)
			}
		}
		return BackupResult{}, jerr
	}
	a := resp.GetArtifact()
	m, err := backupfmt.Parse(a.GetManifest(), a.GetManifestSignature(), s.cfg.ManifestKeys)
	if err == nil {
		err = m.Check(backupfmt.Identity{TenantID: tenantID, InstanceID: instanceID, Slug: inst.Slug, Sequence: seq})
	}
	msum := sha256.Sum256(a.GetManifest())
	if err == nil && (m.Archive.SHA256 != a.GetArchiveSha256() || hex.EncodeToString(msum[:]) != a.GetManifestSha256() ||
		uint64(m.Archive.Size) != a.GetSizeBytes() || m.JobID != jobID.String()) { //nolint:gosec // G115: size > 0 (checked by Parse)
		err = errors.New("the artifact differs from its signed manifest")
	}
	if err != nil {
		s.failRow(ctx, tenantID, rowID)
		s.raise(ctx, tenantID, EventManifestInvalid, audit.SeverityCritical, instanceID.String(),
			audit.Details{"instance_id": instanceID.String(), "job_id": jobID.String(), "sequence": seq, "error": err.Error()})
		return BackupResult{}, jobs.Permanent("manifest_invalid", err)
	}
	out := BackupResult{BackupID: rowID, Sequence: seq, Method: m.Method, SizeBytes: a.GetSizeBytes(), ArchiveSHA256: m.Archive.SHA256,
		ManifestSHA256: a.GetManifestSha256(), CreatedAt: m.Time(), RemovedArchives: a.GetRemovedArchives()}
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		size, sum, msha, method := int64(m.Archive.Size), m.Archive.SHA256, a.GetManifestSha256(), m.Method
		exp := s.cfg.Now().Add(s.cfg.Retention).UTC()
		if _, err := q.FinishInstanceBackup(ctx, sqlcdb.FinishInstanceBackupParams{ID: rowID, SizeBytes: &size, Sha256: &sum,
			Manifest: a.GetManifest(), ManifestSignature: a.GetManifestSignature(), ManifestSha256: &msha, Method: &method, ExpiresAt: &exp}); err != nil {
			return err
		}
		if retainFrom > 0 {
			below := int64(retainFrom) //nolint:gosec // G115: < 2^63
			n, err := q.PurgeInstanceBackupsBelow(ctx, sqlcdb.PurgeInstanceBackupsBelowParams{InstanceID: &instanceID, Below: &below})
			if err != nil {
				return err
			}
			out.PurgedBackups = n
		}
		return nil
	})
	if err != nil {
		return BackupResult{}, jobs.Transient("registry_unavailable", err)
	}
	s.log.InfoContext(ctx, "backup: instance backed up", "tenant_id", tenantID.String(), "instance_id", instanceID.String(),
		"sequence", seq, "method", m.Method, "size_bytes", m.Archive.Size, "purged", out.PurgedBackups)
	return out, nil
}

func (s *Service) failRow(ctx context.Context, tenantID, rowID uuid.UUID) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error { return q.FailInstanceBackup(wctx, rowID) }); err != nil {
		s.log.ErrorContext(ctx, "backup: marking a backup failed did not work", "backup_id", rowID.String())
	}
}

// retainFrom is the smallest sequence still kept once this backup (current) succeeded: current itself counts as the
// newest backup; the KeepLatest-1 newest earlier succeeded backups and every one not expired are kept, the rest (older
// than the first expired one past them) removed by the agent with this backup. 0: nothing to remove.
func (s *Service) retainFrom(kept []sqlcdb.ListSucceededInstanceBackupsRow, current uint64) uint64 {
	now := s.cfg.Now()
	from := current
	removable := false
	for i, r := range kept { // newest first
		if r.Sequence == nil || uint64(*r.Sequence) >= current { //nolint:gosec // G115: > 0
			continue
		}
		if i+1 < s.cfg.KeepLatest || r.ExpiresAt == nil || r.ExpiresAt.After(now) {
			from = uint64(*r.Sequence) //nolint:gosec // G115: > 0
			continue
		}
		removable = true
		break
	}
	if !removable {
		return 0
	}
	return from
}

// backupKey returns the tenant's backup key, creating it (32 random bytes) at the first backup.
func (s *Service) backupKey(ctx context.Context, tenantID uuid.UUID) (secrets.Ref, secrets.Plaintext, error) {
	ref, err := s.cfg.Secrets.Latest(ctx, tenantID, backupfmt.BackupKeySecretName)
	if errors.Is(err, secrets.ErrNotFound) {
		k := make([]byte, backupfmt.BackupKeyBytes)
		if _, err := rand.Read(k); err != nil {
			return secrets.Ref{}, nil, jobs.Transient("random_unavailable", err)
		}
		ref = secrets.TenantRef(tenantID, backupfmt.BackupKeySecretName, 1)
		perr := s.cfg.Secrets.Put(ctx, ref, k)
		clear(k)
		if perr != nil && !errors.Is(perr, secrets.ErrExists) {
			return secrets.Ref{}, nil, jobs.Transient("secret_store_unavailable", perr)
		}
		if ref, err = s.cfg.Secrets.Latest(ctx, tenantID, backupfmt.BackupKeySecretName); err != nil {
			return secrets.Ref{}, nil, jobs.Transient("secret_store_unavailable", err)
		}
	} else if err != nil {
		return secrets.Ref{}, nil, jobs.Transient("secret_store_unavailable", err)
	}
	pt, err := s.cfg.Secrets.Get(ctx, ref)
	if err != nil {
		return secrets.Ref{}, nil, jobs.Transient("secret_store_unavailable", err)
	}
	if len(pt) != backupfmt.BackupKeyBytes {
		pt.Wipe()
		return secrets.Ref{}, nil, jobs.Permanent("backup_key_invalid", errors.New("the tenant's backup key is not 32 bytes"))
	}
	return ref, pt, nil
}
