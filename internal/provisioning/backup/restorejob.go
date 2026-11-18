package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// RestorePayload is the payload of the 2P request platform.instance.restore — shown verbatim to the approver and the
// only input of the job it enqueues (§6.3 approval_requests). RestorePointOlderThanBackup is the operator's assertion
// that PostgreSQL was restored to a point older than the backup (§17.2 step 4 branch).
type RestorePayload struct {
	BackupID                    uuid.UUID `json:"backup_id"`
	InstanceID                  uuid.UUID `json:"instance_id"`
	RestorePointOlderThanBackup bool      `json:"restore_point_older_than_backup"`
}

// Validate is called by the approval registry (approvals.Typed) at request, decision and execution.
func (p RestorePayload) Validate() error {
	if p.BackupID == uuid.Nil || p.InstanceID == uuid.Nil {
		return errors.New("backup_id and instance_id are required")
	}
	return nil
}

// RestoreInput is the input of an instance.restore job.
type RestoreInput struct {
	RestorePayload
	ApprovalID uuid.UUID        `json:"approval_id"`
	Operation  *audit.Operation `json:"operation,omitempty"`
}

// RestoreReport is the output of an instance.restore job — the "báo cáo chênh lệch" of §17.2 step 7.
type RestoreReport struct {
	BackupID                    uuid.UUID `json:"backup_id"`
	Sequence                    uint64    `json:"sequence"`
	BackupCreatedAt             time.Time `json:"backup_created_at"`
	RestorePointOlderThanBackup bool      `json:"restore_point_older_than_backup"`
	PreviousDataKeptAs          string    `json:"previous_data_kept_as"`
	PolicySHA256                string    `json:"policy_sha256"`
	ImportedPolicyVersion       int32     `json:"imported_policy_version,omitempty"`
	Reconcile                   struct {
		APIKeysExpired     uint32   `json:"api_keys_expired"`
		PreauthKeysExpired uint32   `json:"preauth_keys_expired"`
		NodesExpired       uint32   `json:"nodes_expired"`
		NodesDeleted       uint32   `json:"nodes_deleted"`
		RoutesReset        uint32   `json:"routes_reset"`
		TagsReset          uint32   `json:"tags_reset"`
		UsersHandled       uint32   `json:"users_handled"`
		Unmatched          int      `json:"unmatched_machine_keys"`
		TagsNotReset       []string `json:"tags_not_reset,omitempty"`
		APIKeyPrefix       string   `json:"api_key_prefix"`
	} `json:"reconcile"`
	// ReEnroll: devices PostgreSQL knew live that the restored instance does not have (registered after the backup).
	ReEnroll []string `json:"re_enroll,omitempty"`
	// NotRecoverable: the revocations PostgreSQL cannot replay (the "older" branch) — the Owner reviews.
	NotRecoverable  string `json:"not_recoverable,omitempty"`
	MembersResolved int    `json:"members_resolved"`
	MembersUnset    int    `json:"members_unset"`
}

// Step names (provisioning_job_steps).
const (
	stepVerify    = "restore.verify"
	stepInstance  = "restore.instance"
	stepReconcile = "restore.reconcile"
	stepEdge      = "restore.edge"
	stepCheck     = "restore.check"
	stepMembers   = "restore.members"
	stepFinish    = "restore.finish"
)

// verified is what the verification of a restore gives the steps.
type verified struct {
	inst     instance
	row      sqlcdb.GetInstanceBackupRow
	manifest *backupfmt.Manifest
	seq      uint64
}

// restoreJob is instance.restore: jobs.Handler + jobs.Compensator (restore lock fix of P3-T11). A permanent error while
// the restore has changed nothing — before its point of no return restore.instance asked the Host Agent to restore
// (jobs.Kind.PointOfNoReturn), or when the Host Agent refused before any change (Refusal.unchanged) — stays permanent:
// the worker compensates (nothing to undo) and the job ends rolled_back, releasing the tenant's lifecycle lock. Past it,
// or when that cannot be shown, the error stops the job failed_resumable as before (§11.3: the lock stays, /retry
// resumes from the failed step; /rollback ⇒ 409 point_of_no_return).
type restoreJob struct{ s *Service }

var _ jobs.Compensator = restoreJob{}

// Run implements jobs.Handler.
func (j restoreJob) Run(ctx context.Context, run *jobs.Run) error { return j.s.runRestore(ctx, run) }

// Compensate implements jobs.Compensator.
func (j restoreJob) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return j.s.compensateRestore(ctx, run, cause)
}

func (s *Service) runRestore(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil || run.InstanceID == nil {
		return jobs.Permanent("invalid_input", errors.New("instance.restore needs a tenant and an instance"))
	}
	var in RestoreInput
	if err := run.DecodeInput(&in); err != nil || in.Validate() != nil || in.InstanceID != *run.InstanceID {
		return jobs.Permanent("invalid_input", errors.New("instance.restore: the input is not the approved payload"))
	}
	rep, err := s.restore(ctx, run, *run.TenantID, in)
	if err != nil {
		var je *jobs.Error
		final := errors.As(err, &je) && (je.Permanent || je.Stop)
		var extra audit.Details
		if final && je.Permanent && ctx.Err() == nil {
			var unchanged bool
			unchanged, err = s.settle(ctx, run.ID, *run.TenantID, in.InstanceID, je.Code, err)
			extra = audit.Details{"instance_changed": !unchanged}
		}
		if in.Operation != nil && final {
			s.closeRestore(ctx, *in.Operation, nil, je.Code, extra)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if in.Operation != nil {
		s.closeRestore(ctx, *in.Operation, &rep, "", nil)
	}
	if err := run.SetOutput(rep); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	return nil
}

// settle decides how a permanent error ends a restore: still permanent when the restore changed nothing (the worker then
// compensates — nothing to undo — and the job ends rolled_back, the lifecycle lock released), Resumable otherwise
// (failed_resumable with the same code, the lock held — §11.3: once the instance may have changed, the tenant's lock
// stays until /retry completes the restore). Unknown (the registry or the Host Agent unreachable) counts as changed.
func (s *Service) settle(ctx context.Context, jobID, tenantID, instanceID uuid.UUID, code string, cause error) (bool, error) {
	unchanged, err := s.unchanged(ctx, jobID, tenantID, instanceID)
	if err != nil {
		s.log.WarnContext(ctx, "backup: whether the restore changed the instance is unknown — the job keeps the lifecycle lock",
			"job_id", jobID.String(), "code", jobs.CodeOf(err))
	}
	if err == nil && unchanged {
		return true, cause
	}
	return false, jobs.Resumable(code, cause)
}

// compensateRestore is the rollback of instance.restore — by the worker after a permanent error, or /rollback of a
// failed_resumable job (a restore cancelled, timed out or out of attempts before it reached the Host Agent, or one of a
// worker before the restore lock fix): nothing to undo, allowed only while the restore changed nothing (unchanged —
// defence in depth behind the point of no return of jobs.Rollback). Every step is marked compensation skipped and the
// audit operation closed (.failed, once).
func (s *Service) compensateRestore(ctx context.Context, run *jobs.Run, cause error) error {
	if run.TenantID == nil || run.InstanceID == nil {
		return jobs.Permanent("invalid_input", errors.New("instance.restore needs a tenant and an instance"))
	}
	var in RestoreInput
	if err := run.DecodeInput(&in); err != nil {
		return jobs.Permanent("invalid_input", errors.New("instance.restore: the input is unreadable"))
	}
	unchanged, err := s.unchanged(ctx, run.ID, *run.TenantID, *run.InstanceID)
	if err != nil {
		return err
	}
	if !unchanged {
		return jobs.Permanent(jobs.ReasonPointOfNoReturn,
			errors.New("the Host Agent may have changed the instance (restore.instance was reached): a restore is not rolled back — /retry completes it"))
	}
	if err := run.CompensateSteps(ctx, nil); err != nil {
		return err
	}
	if in.Operation != nil {
		s.closeRestore(ctx, *in.Operation, nil, jobs.CodeOf(cause), audit.Details{"instance_changed": false, "rolled_back": true})
	}
	return nil
}

// closeRestore closes the audit operation of the restore: .succeeded with the report; .failed once — an operation already
// closed (an earlier attempt, or the run before its compensation) gets no second .failed (a restore completed by /retry
// after a failure still records its .succeeded, as before).
func (s *Service) closeRestore(ctx context.Context, op audit.Operation, rep *RestoreReport, code string, extra audit.Details) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err := s.st.WithPlatformTx(wctx, func(q *sqlcdb.Queries) error {
		if rep == nil {
			st, err := q.OperationState(wctx, op.ID)
			if err != nil || st.Finished {
				return err
			}
			d := audit.Details{"instance_id": op.ResourceID}
			for k, v := range extra {
				d[k] = v
			}
			return op.Failed(wctx, q, code, d)
		}
		return op.Succeeded(wctx, q, audit.Details{"backup_id": rep.BackupID.String(), "sequence": rep.Sequence,
			"restore_point_older_than_backup": rep.RestorePointOlderThanBackup, "policy_sha256": rep.PolicySHA256,
			"api_keys_expired": rep.Reconcile.APIKeysExpired, "nodes_expired": rep.Reconcile.NodesExpired})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "backup: closing the restore audit operation failed", "operation", op.ID.String())
	}
}

// unchanged reports whether a restore job has changed nothing of the instance — the condition of its rollback (§11.3):
// restore.instance never started; or it recorded that the Host Agent was not asked yet, or refused before any change
// (restoreMark with point_of_no_return false); or — a restore.instance of a worker before the restore lock fix, which
// recorded nothing — the Host Agent reports the instance never activated: Restore refuses such an instance before
// anything else (its first check, in every version), and nothing a restore does removes meta/activated.
func (s *Service) unchanged(ctx context.Context, jobID, tenantID, instanceID uuid.UUID) (bool, error) {
	var row *sqlcdb.ProvisioningJobStep
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetJobStep(ctx, sqlcdb.GetJobStepParams{JobID: jobID, Name: stepInstance})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		row = &r
		return nil
	})
	switch {
	case err != nil:
		return false, jobs.Transient("registry_unavailable", err)
	case row == nil:
		return true, nil
	case jobs.PointOfNoReturnPassed(row.Status, row.CreatedResources):
		return false, nil
	case len(row.CreatedResources) > 0 && string(row.CreatedResources) != "null":
		return true, nil // marked {"point_of_no_return": false}
	}
	inst, err := s.instance(ctx, tenantID, instanceID)
	if err != nil {
		return false, err
	}
	st, err := s.agentStatus(ctx, inst)
	if err != nil {
		return false, err
	}
	return !st.GetActivated(), nil
}

// agentStatus is the Host Agent's view of the instance (GetInstanceStatus).
func (s *Service) agentStatus(ctx context.Context, inst instance) (*agentv1.InstanceStatus, error) {
	if s.cfg.Agent == nil {
		return nil, jobs.Permanent("agent_not_configured", errors.New("the worker has no Host Agent (MG_AGENT_SOCKET)"))
	}
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	r, err := s.cfg.Agent.GetInstanceStatus(cctx, &agentv1.GetInstanceStatusRequest{Instance: inst.ref()})
	if err != nil {
		return nil, agentErr("GetInstanceStatus", err)
	}
	return r.GetStatus(), nil
}

// restorable is the Host Agent's view of the instance before it is asked to restore (restore lock fix — the cheap check
// of what Restore refuses first): v1 restores only an activated instance (meta/activated, written with the Noise key
// fingerprint at the first edge attachment), never a quarantined one. A refusal here changed nothing.
func (s *Service) restorable(ctx context.Context, inst instance, sr detailer) error {
	st, err := s.agentStatus(ctx, inst)
	if err != nil {
		return err
	}
	switch {
	case st.GetQuarantined():
		_ = sr.SetDetail(map[string]any{"agent_restore": markNotCalled, "quarantined": true})
		return jobs.Permanent("instance_quarantined",
			errors.New("the Host Agent reports the instance quarantined (meta/quarantined): no restore (§11.4) — nothing was changed"))
	case !st.GetActivated():
		_ = sr.SetDetail(map[string]any{"agent_restore": markNotCalled, "activated": false})
		return jobs.Permanent("instance_not_restorable",
			errors.New("the Host Agent reports the instance never activated (no meta/activated): restore v1 needs an activated instance with a recorded Noise key fingerprint — nothing was changed"))
	}
	return nil
}

// verify — §17.2 step 2, the worker's half (the agent repeats it): the backup row of the tenant (RLS), succeeded, of
// this instance; its manifest signed by a trusted key, describing this tenant, instance, slug and sequence, matching
// the recorded digests — all BEFORE the data key is unwrapped.
func (s *Service) verify(ctx context.Context, jobID, tenantID uuid.UUID, in RestoreInput) (verified, error) {
	inst, err := s.instance(ctx, tenantID, in.InstanceID)
	if err != nil {
		return verified{}, err
	}
	if why := inst.eligible(); why != "" {
		return verified{}, jobs.Permanent("instance_not_restorable", errors.New(why))
	}
	var row sqlcdb.GetInstanceBackupRow
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.GetInstanceBackup(ctx, in.BackupID)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return verified{}, jobs.Permanent("backup_not_found", errors.New("no backup of this tenant with that id"))
	case err != nil:
		return verified{}, jobs.Transient("registry_unavailable", err)
	case row.InstanceID == nil || *row.InstanceID != in.InstanceID || row.TenantID == nil || *row.TenantID != tenantID:
		return verified{}, jobs.Permanent("backup_not_found", errors.New("the backup is not one of this instance"))
	case row.Status != "succeeded" || row.Sequence == nil || row.Sha256 == nil || row.ManifestSha256 == nil:
		return verified{}, jobs.Permanent("backup_not_restorable", fmt.Errorf("the backup is %s", row.Status))
	}
	seq := uint64(*row.Sequence) //nolint:gosec // G115: > 0
	m, err := backupfmt.Parse(row.Manifest, row.ManifestSignature, s.cfg.ManifestKeys)
	if err == nil {
		err = m.Check(backupfmt.Identity{TenantID: tenantID, InstanceID: in.InstanceID, Slug: inst.Slug, Sequence: seq})
	}
	sum := sha256.Sum256(row.Manifest)
	if err == nil && (hex.EncodeToString(sum[:]) != *row.ManifestSha256 || m.Archive.SHA256 != *row.Sha256) {
		err = errors.New("the recorded digests differ from the signed manifest")
	}
	if err != nil {
		s.raise(ctx, tenantID, EventIntegrity, audit.SeverityCritical, "manifest:"+jobID.String(),
			audit.Details{"backup_id": in.BackupID.String(), "instance_id": in.InstanceID.String(), "error": err.Error()})
		return verified{}, jobs.Permanent("manifest_invalid", err)
	}
	return verified{inst: inst, row: row, manifest: m, seq: seq}, nil
}

// restore — §17.2 in the order of provisioning; every step is idempotent (a retried job skips the steps that
// succeeded; the agent recognises a restore of the same job).
func (s *Service) restore(ctx context.Context, run *jobs.Run, tenantID uuid.UUID, in RestoreInput) (RestoreReport, error) {
	if err := s.enabled(); err != nil {
		return RestoreReport{}, err
	}
	if s.cfg.Registry == nil {
		return RestoreReport{}, jobs.Permanent("headscale_not_configured", errors.New("no Headscale registry"))
	}
	v, err := s.verify(ctx, run.ID, tenantID, in)
	if err != nil {
		return RestoreReport{}, err
	}
	rep := RestoreReport{BackupID: in.BackupID, Sequence: v.seq, BackupCreatedAt: v.manifest.Time(),
		RestorePointOlderThanBackup: in.RestorePointOlderThanBackup}
	if err := run.Step(ctx, stepVerify, func(_ context.Context, sr *jobs.StepRun) error {
		return sr.SetDetail(map[string]any{"backup_id": in.BackupID.String(), "sequence": v.seq, "created_at": v.manifest.CreatedAt,
			"headscale_version": v.manifest.HeadscaleVersion, "method": v.manifest.Method, "older_branch": in.RestorePointOlderThanBackup})
	}); err != nil {
		return rep, err
	}
	// the plan is read before anything changes PostgreSQL's view of the devices (inventory.sync runs last)
	plan, devices, err := s.plan(ctx, tenantID, v, in.RestorePointOlderThanBackup)
	if err != nil {
		return rep, err
	}
	if err := run.Step(ctx, stepInstance, func(ctx context.Context, sr *jobs.StepRun) error {
		return s.stepInstance(ctx, run.ID, tenantID, v, in, sr, sr)
	}); err != nil {
		return rep, err
	}
	if err := run.Step(ctx, stepReconcile, func(ctx context.Context, sr *jobs.StepRun) error {
		return s.stepReconcile(ctx, run.ID, tenantID, v, plan, sr)
	}); err != nil {
		return rep, err
	}
	if err := run.Step(ctx, stepEdge, func(ctx context.Context, sr *jobs.StepRun) error {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		r, err := s.cfg.Agent.EnsureEdgeAttachment(cctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: v.inst.ref(), JobId: run.ID.String()})
		if err != nil {
			return agentErr("EnsureEdgeAttachment", err)
		}
		return sr.SetDetail(map[string]any{"attached": r.GetAttached(), "network_members": r.GetNetworkMembers()})
	}); err != nil {
		return rep, err
	}
	if err := run.Step(ctx, stepCheck, func(ctx context.Context, sr *jobs.StepRun) error {
		return s.stepCheck(ctx, run.ID, tenantID, v, devices, sr)
	}); err != nil {
		return rep, err
	}
	if err := run.Step(ctx, stepMembers, func(ctx context.Context, sr *jobs.StepRun) error {
		return s.stepMembers(ctx, tenantID, sr)
	}); err != nil {
		return rep, err
	}
	if err := run.Step(ctx, stepFinish, func(ctx context.Context, sr *jobs.StepRun) error {
		return s.stepFinish(ctx, run.ID, tenantID, v, in, sr)
	}); err != nil {
		return rep, err
	}
	// the report is assembled from the details the steps recorded (a retried job sees them too)
	if err := s.fillReport(ctx, run.ID, tenantID, &rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// ---------------------------------------------------------------------------------------------------- steps

// pointOfNoReturn is how restore.instance of a job records its point of no return (jobs.Kind.PointOfNoReturn — the
// restore lock fix of P3-T11): the job's *jobs.StepRun; nil in an upgrade's rollback (RollbackRestore — the upgrade's
// own compensation decides).
type pointOfNoReturn interface {
	Previous(v any) (bool, error)
	RecordCreated(ctx context.Context, resources any) error
	Attempt() int
}

// restoreMark is created_resources of restore.instance: point_of_no_return false while the Host Agent has not been asked
// to restore (recorded when the step first starts) or refused before any change (Refusal.unchanged, on the job's first
// call); true from just before the call on. A step that started under a worker before the fix recorded nothing.
type restoreMark struct {
	PointOfNoReturn bool   `json:"point_of_no_return"`
	AgentRestore    string `json:"agent_restore"`
	Refusal         string `json:"refusal,omitempty"`
}

const (
	markNotCalled        = "not_called"
	markCalled           = "called"
	markRefusedUnchanged = "refused_unchanged"
)

// stepInstance — §17.2 steps 2–4 at the agent: unwrap the data key (online path), hand it over with the policy to set
// (the current applied policy, or "keep the archive's" on the older branch), record the policy application. In a job
// (pnr not nil) the Host Agent's view of the instance is checked first (restorable) and the point of no return is
// recorded around the call (restoreMark).
func (s *Service) stepInstance(ctx context.Context, jobID, tenantID uuid.UUID, v verified, in RestoreInput, sr detailer,
	pnr pointOfNoReturn,
) error {
	// fresh: this job has not asked the Host Agent to restore yet — known from the step's own record only
	fresh := false
	if pnr != nil {
		var prev restoreMark
		found, err := pnr.Previous(&prev)
		if err != nil {
			return err
		}
		switch {
		case found:
			fresh = !prev.PointOfNoReturn
		case pnr.Attempt() == 1:
			if err := pnr.RecordCreated(ctx, restoreMark{AgentRestore: markNotCalled}); err != nil {
				return err
			}
			fresh = true
		}
		if err := s.restorable(ctx, v.inst, sr); err != nil {
			return err
		}
	}
	ref, err := keyRef(tenantID, v)
	if err != nil {
		return err
	}
	var current *sqlcdb.PolicyApplication
	if !in.RestorePointOlderThanBackup {
		err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			a, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID, InstanceID: v.inst.ID})
			if err != nil {
				return err
			}
			current = &a
			return nil
		})
		switch {
		case errors.Is(err, store.ErrNoRows):
			return jobs.Permanent("no_applied_policy", errors.New("PostgreSQL records no applied policy for the instance: restore with the older-point branch"))
		case err != nil:
			return jobs.Transient("registry_unavailable", err)
		}
	}
	dataKey, err := s.dataKey(ctx, jobID, tenantID, v, ref)
	if err != nil {
		return err
	}
	defer clear(dataKey)
	req := &agentv1.RestoreRequest{Instance: v.inst.ref(), JobId: jobID.String(), DataKey: dataKey,
		Artifact: &agentv1.ArtifactRef{Sequence: v.seq, ArchiveSha256: *v.row.Sha256, ManifestSha256: *v.row.ManifestSha256}}
	if current != nil {
		req.Policy = &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: []byte(current.AppliedHujson)}
	} else {
		req.Policy = &agentv1.RestoreRequest_KeepBackupPolicy{KeepBackupPolicy: true}
	}
	if pnr != nil { // BEFORE the call: from here on the job may have changed the instance
		if err := pnr.RecordCreated(ctx, restoreMark{PointOfNoReturn: true, AgentRestore: markCalled}); err != nil {
			return err
		}
	}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.CallTimeout)
	defer cancel()
	resp, err := s.cfg.Agent.Restore(cctx, req)
	req.DataKey = nil
	if err != nil {
		if kind, sev := securityEventOf(err); kind != "" {
			d := refusalDetails(err)
			d["backup_id"], d["instance_id"] = v.row.ID.String(), v.inst.ID.String()
			s.raise(ctx, tenantID, kind, sev, v.row.ID.String(), d)
		}
		if rf, ok := agentclient.RefusalOf(err); ok && rf.GetUnchanged() && pnr != nil && fresh {
			// refused before any change, on the job's first call: the point of no return is not passed (if this record
			// fails the step stays "called" — the job then keeps the lock, the safe side)
			code := refusalCode(rf.GetReason())
			if rerr := pnr.RecordCreated(context.WithoutCancel(ctx), restoreMark{AgentRestore: markRefusedUnchanged, Refusal: code}); rerr != nil {
				s.log.WarnContext(ctx, "backup: the unchanged refusal of Restore was not recorded — the job keeps the lifecycle lock",
					"job_id", jobID.String())
			}
			_ = sr.SetDetail(map[string]any{"agent_restore": markRefusedUnchanged, "refusal": code})
		}
		return agentErr("Restore", err)
	}
	detail := map[string]any{"previous_data_kept_as": resp.GetPreviousDataKeptAs(), "policy_sha256": resp.GetPolicySha256(),
		"already_restored": resp.GetAlreadyRestored(), "restored_data_sha256": resp.GetRestoredDataSha256()}
	// the policy the restored instance serves, recorded as an application (trigger restore) — the post-start gate and
	// the drift check compare against it
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		if current != nil {
			if resp.GetPolicySha256() != current.AppliedSha256 {
				return fmt.Errorf("%w: the restored instance serves %s, not the applied %s", errPolicyMismatch, resp.GetPolicySha256(), current.AppliedSha256)
			}
			return recordApplication(ctx, q, tenantID, v.inst.ID, current.PolicyVersionID, current.AppliedHujson, current.InputsSha256)
		}
		version, err := importPolicy(ctx, q, tenantID, v.inst.ID, string(resp.GetBackupPolicyHujson()))
		if err != nil {
			return err
		}
		detail["imported_policy_version"] = version
		return nil
	})
	if errors.Is(err, errPolicyMismatch) {
		return jobs.Permanent("policy_mismatch", err)
	}
	if err != nil {
		return jobs.Transient("registry_unavailable", err)
	}
	return sr.SetDetail(detail)
}

var errPolicyMismatch = errors.New("policy mismatch")

// detailer is where a restore step records its detail: the job's *jobs.StepRun, or the collector of an upgrade's
// rollback (RollbackRestore — P3-T13a).
type detailer interface {
	SetDetail(v any) error
}

// dataKey unwraps the data key of a verified backup with the tenant's backup key (the online path — §17.1).
func (s *Service) dataKey(ctx context.Context, jobID, tenantID uuid.UUID, v verified, ref secrets.Ref) ([]byte, error) {
	pt, err := s.cfg.Secrets.Get(ctx, ref)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, jobs.Permanent("backup_key_destroyed", errors.New("the tenant's backup key is gone (crypto-shredded): only the DR path remains"))
		}
		return nil, jobs.Transient("secret_store_unavailable", err)
	}
	dataKey, err := backupfmt.UnwrapDataKey(pt.Bytes(), v.row.WrappedDataKey, tenantID, v.inst.ID, v.seq)
	pt.Wipe()
	if err != nil {
		s.raise(ctx, tenantID, EventIntegrity, audit.SeverityCritical, "unwrap:"+jobID.String(),
			audit.Details{"backup_id": v.row.ID.String(), "error": "the wrapped data key does not open with the tenant's backup key"})
		return nil, jobs.Permanent("data_key_unwrap", err)
	}
	return dataKey, nil
}

// keyRef is the reference of the tenant's backup key a verified backup names.
func keyRef(tenantID uuid.UUID, v verified) (secrets.Ref, error) {
	if v.row.KeyRef == nil {
		return secrets.Ref{}, jobs.Permanent("backup_key_missing", errors.New("the backup names no key"))
	}
	ref, err := secrets.ParseRef(*v.row.KeyRef)
	if err != nil || ref.Tenant != tenantID || ref.Name != backupfmt.BackupKeySecretName {
		return secrets.Ref{}, jobs.Permanent("backup_key_invalid", errors.New("the backup's key reference is not the tenant's backup key"))
	}
	return ref, nil
}

// recordApplication writes the applied application of a restore (trigger restore) with the very string the instance
// serves, superseding the current one (0013: the old row first, in the same transaction).
func recordApplication(ctx context.Context, q *sqlcdb.Queries, tenantID, instanceID, versionID uuid.UUID, text string, inputs *string) error {
	sum := sha256.Sum256([]byte(text))
	a, err := q.InsertPolicyApplication(ctx, sqlcdb.InsertPolicyApplicationParams{TenantID: tenantID, InstanceID: instanceID,
		PolicyVersionID: versionID, Trigger: policies.TriggerRestore, InputsSha256: inputs, AppliedHujson: text,
		AppliedSha256: hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	if _, err := q.SupersedeCurrentPolicyApplication(ctx, sqlcdb.SupersedeCurrentPolicyApplicationParams{TenantID: tenantID,
		InstanceID: instanceID, KeepID: a.ID}); err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = q.FinishPolicyApplication(ctx, sqlcdb.FinishPolicyApplicationParams{State: "applied", HeadscaleUpdatedAt: &now,
		TenantID: tenantID, ID: a.ID})
	return err
}

// importPolicy — §17.2 step 4, older branch: the archive's policy (what the instance serves) becomes a new version in
// state validated — never applied by policy.apply before an Owner/Admin approves it (§7.3) — set as desired, and an
// applied application (trigger restore) with that exact string.
func importPolicy(ctx context.Context, q *sqlcdb.Queries, tenantID, instanceID uuid.UUID, text string) (int32, error) {
	if strings.TrimSpace(text) == "" {
		return 0, errors.New("the restored instance serves no policy")
	}
	n, err := q.NextPolicyVersionNumber(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256([]byte(text))
	report, _ := json.Marshal(map[string]any{"imported": "restore", "note": "policy of the restored backup — PostgreSQL was older than the backup (§17.2 step 4); review and approve it"})
	pv, err := q.InsertImportedPolicyVersion(ctx, sqlcdb.InsertImportedPolicyVersionParams{TenantID: tenantID, Version: n,
		SourceHujson: &text, ContentSha256: hex.EncodeToString(sum[:]), ValidationReport: report})
	if err != nil {
		return 0, err
	}
	if err := q.SetTenantDesiredPolicy(ctx, sqlcdb.SetTenantDesiredPolicyParams{VersionID: &pv.ID, TenantID: tenantID}); err != nil {
		return 0, err
	}
	in := hex.EncodeToString(sum[:])
	return n, recordApplication(ctx, q, tenantID, instanceID, pv.ID, text, &in)
}

// stepReconcile — §17.2 step 5 under the instance's API-key lock (apikey.LockName — the rotation and the reconcile
// take it): PostRestoreReconcile at the agent, then the new key into the SecretStore and the registry; the versions of
// the keys the agent expired are destroyed.
func (s *Service) stepReconcile(ctx context.Context, jobID, tenantID uuid.UUID, v verified, plan *agentv1.ReconcilePlan, sr detailer) error {
	var inner error
	err := s.st.WithTenantLock(ctx, tenantID, apikey.LockName, s.cfg.APIKeyLockWait, func(ctx context.Context) error {
		inner = s.reconcileLocked(ctx, jobID, tenantID, v, plan, sr)
		return inner
	})
	switch {
	case inner != nil:
		return inner
	case err != nil:
		return jobs.Transient("apikey_lock", err)
	}
	return nil
}

func (s *Service) reconcileLocked(ctx context.Context, jobID, tenantID uuid.UUID, v verified, plan *agentv1.ReconcilePlan, sr detailer) error {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	plan.ApiKeyTtl = durationpb.New(s.cfg.APIKeyTTL)
	resp, err := s.cfg.Agent.PostRestoreReconcile(cctx, &agentv1.PostRestoreReconcileRequest{Instance: v.inst.ref(), JobId: jobID.String(), Plan: plan})
	if err != nil {
		return agentErr("PostRestoreReconcile", err)
	}
	key := resp.GetApiKey()
	resp.ApiKey = ""
	if !provisioning.ValidAPIKey(key) {
		return jobs.Permanent("apikey_invalid", errors.New("the agent returned a value that is not a Headscale API key"))
	}
	prefix := headscale.APIKeyPrefix(headscale.NewSecret(key))
	ref, err := s.storeKey(ctx, tenantID, key)
	if err != nil {
		return jobs.Transient("secret_store_unavailable", err)
	}
	var exp *time.Time
	if t := resp.GetApiKeyExpiresAt(); t.IsValid() {
		e := t.AsTime().UTC()
		exp = &e
	}
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r := ref.String()
		_, err := q.SetTenantInstanceAPIKey(ctx, sqlcdb.SetTenantInstanceAPIKeyParams{ApiKeySecretRef: &r, ApiKeyPrefix: &prefix,
			ApiKeyExpiresAt: exp, ID: v.inst.ID, TenantID: tenantID})
		if err != nil {
			return err
		}
		return audit.Record(ctx, q, audit.Event{ActorType: audit.ActorSystem, Action: "instance.apikey.restore", ResourceType: "instance",
			ResourceID: v.inst.ID.String(), Details: audit.Details{"tenant_id": tenantID.String(), "job_id": jobID.String(),
				"prefix": prefix, "api_keys_expired": resp.GetApiKeysExpired()}})
	})
	if err != nil {
		return jobs.Transient("registry_unavailable", err)
	}
	s.cfg.Registry.Invalidate(tenantID)
	for ver := int32(1); ver < ref.Version; ver++ {
		old := secrets.TenantRef(tenantID, provisioning.APIKeySecretName, ver)
		if err := s.cfg.Secrets.Destroy(ctx, old); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			s.log.WarnContext(ctx, "backup: an older API key version was not destroyed", "ref", old.String())
		}
	}
	return sr.SetDetail(map[string]any{"api_key_prefix": prefix, "ref_version": ref.Version, "api_keys_expired": resp.GetApiKeysExpired(),
		"preauth_keys_expired": resp.GetPreauthKeysExpired(), "nodes_expired": resp.GetNodesExpired(), "nodes_deleted": resp.GetNodesDeleted(),
		"routes_reset": resp.GetRoutesReset(), "tags_reset": resp.GetTagsReset(), "users_handled": resp.GetUsersHandled(),
		"unmatched_machine_keys": len(resp.GetUnmatchedMachineKeys()), "tags_not_reset": resp.GetTagsNotReset(),
		"plan_revoked": len(plan.GetRevokedMachineKeys()), "plan_deleted": len(plan.GetDeletedMachineKeys()),
		"plan_nodes": len(plan.GetNodes()), "plan_offboarded": len(plan.GetOffboardedUsers())})
}

func (s *Service) storeKey(ctx context.Context, tenantID uuid.UUID, key string) (secrets.Ref, error) {
	value := []byte(key)
	defer clear(value)
	latest, err := s.cfg.Secrets.Latest(ctx, tenantID, provisioning.APIKeySecretName)
	if errors.Is(err, secrets.ErrNotFound) {
		ref := secrets.TenantRef(tenantID, provisioning.APIKeySecretName, 1)
		return ref, s.cfg.Secrets.Put(ctx, ref, value)
	}
	if err != nil {
		return secrets.Ref{}, err
	}
	return s.cfg.Secrets.Rotate(ctx, latest, value)
}

// stepCheck — §17.2 step 6 over the API, now that the edge is attached: the policy served is the applied one, exactly
// one API key is valid (the one just stored), no pre-auth key of the archive is valid. A failure detaches the edge
// again (Critical) — the hostname never keeps answering with a state that revived revoked access (IT-16).
func (s *Service) stepCheck(ctx context.Context, jobID, tenantID uuid.UUID, v verified, devices []sqlcdb.ListRestorePlanDevicesRow, sr detailer) error {
	var cur sqlcdb.PolicyApplication
	var prefix string
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		cur, err = q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID, InstanceID: v.inst.ID})
		return err
	})
	if err != nil {
		return jobs.Transient("registry_unavailable", err)
	}
	inst, err := s.instance(ctx, tenantID, v.inst.ID)
	if err != nil {
		return err
	}
	if inst.ApiKeyPrefix != nil {
		prefix = *inst.ApiKeyPrefix
	}
	hs, err := s.cfg.Registry.ForTenant(ctx, tenantID)
	if err != nil {
		return jobs.Transient("instance_unavailable", err)
	}
	var problems []string
	pol, err := hs.GetPolicy(ctx)
	if err != nil {
		return jobs.Transient("instance_unavailable", fmt.Errorf("GetPolicy: %w", err))
	}
	if sum := sha256.Sum256([]byte(pol.Data)); hex.EncodeToString(sum[:]) != cur.AppliedSha256 {
		problems = append(problems, "policy_drift")
	}
	now := s.cfg.Now()
	keys, err := hs.ListAPIKeys(ctx)
	if err != nil {
		return jobs.Transient("instance_unavailable", fmt.Errorf("ListAPIKeys: %w", err))
	}
	var valid []string
	for _, k := range keys {
		if k.Expiration.IsZero() || k.Expiration.After(now) {
			valid = append(valid, k.Prefix)
		}
	}
	if len(valid) != 1 || valid[0] != prefix {
		problems = append(problems, "api_keys")
	}
	pre, err := hs.ListPreAuthKeys(ctx)
	if err != nil {
		return jobs.Transient("instance_unavailable", fmt.Errorf("ListPreAuthKeys: %w", err))
	}
	live := 0
	for _, k := range pre {
		if k.Expiration.IsZero() || k.Expiration.After(now) {
			live++
		}
	}
	if live > 0 {
		problems = append(problems, "preauth_keys")
	}
	nodes, err := hs.ListNodes(ctx, "")
	if err != nil {
		return jobs.Transient("instance_unavailable", fmt.Errorf("ListNodes: %w", err))
	}
	have := map[string]bool{}
	for _, n := range nodes {
		have[n.MachineKey] = true
	}
	var reEnroll []string
	for _, d := range devices {
		if d.RemovedAt == nil && !have[d.MachineKey] {
			name := d.ID.String()
			if d.Name != nil {
				name = *d.Name + " (" + d.ID.String() + ")"
			}
			reEnroll = append(reEnroll, name)
		}
	}
	slices.Sort(reEnroll)
	if len(problems) > 0 {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		_, derr := s.cfg.Agent.RemoveEdgeAttachment(cctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: v.inst.ref(), JobId: jobID.String(),
			Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_POLICY_DRIFT})
		cancel()
		s.raise(ctx, tenantID, EventRestoreCheck, audit.SeverityCritical, jobID.String(), audit.Details{"instance_id": v.inst.ID.String(),
			"job_id": jobID.String(), "problems": strings.Join(problems, ","), "edge_detached": derr == nil})
		return jobs.Permanent("restore_check_failed", fmt.Errorf("the restored instance failed %v — the edge was detached again", problems))
	}
	return sr.SetDetail(map[string]any{"policy_sha256": cur.AppliedSha256, "valid_api_keys": 1, "valid_preauth_keys": 0,
		"nodes": len(nodes), "re_enroll": reEnroll})
}

// stepMembers — §17.2 step 6: tenant_memberships.headscale_user_id re-resolved by the name mg-<membership uuid> in ONE
// transaction (NULL first: the restored numeric ids may be the ids the platform recorded for other users); a name not
// found stays NULL (the user is created again at the next enrollment) — a pre-auth key issued later belongs to the
// right user.
func (s *Service) stepMembers(ctx context.Context, tenantID uuid.UUID, sr detailer) error {
	hs, err := s.cfg.Registry.ForTenant(ctx, tenantID)
	if err != nil {
		return jobs.Transient("instance_unavailable", err)
	}
	users, err := hs.ListUsers(ctx, headscale.UserFilter{})
	if err != nil {
		return jobs.Transient("instance_unavailable", fmt.Errorf("ListUsers: %w", err))
	}
	byName := map[string]uint64{}
	for _, u := range users {
		byName[u.Name] = u.ID
	}
	resolved, unset := 0, 0
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		resolved, unset = 0, 0
		rows, err := q.ListMembershipHeadscaleNames(ctx)
		if err != nil {
			return err
		}
		if _, err := q.ClearMembershipHeadscaleUserIDs(ctx); err != nil {
			return err
		}
		for _, r := range rows {
			id, ok := byName[r.HeadscaleUsername]
			if !ok || id == 0 || id > 1<<62 {
				unset++
				continue
			}
			v := int64(id) //nolint:gosec // G115: checked above
			if err := q.SetMembershipHeadscaleUserID(ctx, sqlcdb.SetMembershipHeadscaleUserIDParams{HeadscaleUserID: &v, ID: r.ID}); err != nil {
				return err
			}
			resolved++
		}
		return nil
	})
	if err != nil {
		return jobs.Transient("registry_unavailable", err)
	}
	return sr.SetDetail(map[string]any{"members_resolved": resolved, "members_unset": unset})
}

// stepFinish — §17.2 steps 6–7: inventory.sync (the instance's state into the device book: rows of nodes gone get
// removed_at, a reused numeric id with another machine key is another device), verified_at of the backup, the Owner
// review (older branch: security event), the notification of the Owners — in one transaction.
func (s *Service) stepFinish(ctx context.Context, jobID, tenantID uuid.UUID, v verified, in RestoreInput, sr detailer) error {
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: SyncKind, TenantID: &tenantID, InstanceID: &v.inst.ID,
			Slot: "restore-" + jobID.String()}); err != nil {
			return err
		}
		if err := tx.Q.SetBackupVerified(ctx, v.row.ID); err != nil {
			return err
		}
		if in.RestorePointOlderThanBackup {
			if _, err := audit.RecordSecurityEvent(ctx, tx.Q, audit.SecurityEvent{TenantID: &tenantID, Kind: EventRestoreReview,
				Severity: audit.SeverityHigh, Source: SecuritySource, DedupeKey: EventRestoreReview + ":" + jobID.String(), DedupeWindow: 24 * time.Hour,
				Details: audit.Details{"instance_id": v.inst.ID.String(), "backup_id": v.row.ID.String(), "job_id": jobID.String(),
					"backup_created_at": v.manifest.CreatedAt, "reason": "postgresql_older_than_backup"}}); err != nil {
				return err
			}
		}
		_, err := notifications.Enqueue(ctx, tx, notifications.InstanceRestored(tenantID, jobID, v.manifest.Time(), in.RestorePointOlderThanBackup))
		return err
	})
	if err != nil {
		return jobs.Transient("registry_unavailable", err)
	}
	return sr.SetDetail(map[string]any{"inventory_sync": "enqueued", "owner_review": in.RestorePointOlderThanBackup})
}

// fillReport assembles the report from the steps' details.
func (s *Service) fillReport(ctx context.Context, jobID, tenantID uuid.UUID, rep *RestoreReport) error {
	var steps []sqlcdb.ProvisioningJobStep
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		steps, err = q.ListJobSteps(ctx, []uuid.UUID{jobID})
		return err
	})
	if err != nil {
		return jobs.Transient("registry_unavailable", err)
	}
	for _, st := range steps {
		var d map[string]json.RawMessage
		if json.Unmarshal(st.Detail, &d) != nil {
			continue
		}
		get := func(k string, v any) { _ = json.Unmarshal(d[k], v) }
		switch st.Name {
		case stepInstance:
			get("previous_data_kept_as", &rep.PreviousDataKeptAs)
			get("policy_sha256", &rep.PolicySHA256)
			get("imported_policy_version", &rep.ImportedPolicyVersion)
		case stepReconcile:
			r := &rep.Reconcile
			get("api_keys_expired", &r.APIKeysExpired)
			get("preauth_keys_expired", &r.PreauthKeysExpired)
			get("nodes_expired", &r.NodesExpired)
			get("nodes_deleted", &r.NodesDeleted)
			get("routes_reset", &r.RoutesReset)
			get("tags_reset", &r.TagsReset)
			get("users_handled", &r.UsersHandled)
			get("unmatched_machine_keys", &r.Unmatched)
			get("tags_not_reset", &r.TagsNotReset)
			get("api_key_prefix", &r.APIKeyPrefix)
		case stepCheck:
			get("re_enroll", &rep.ReEnroll)
		case stepMembers:
			get("members_resolved", &rep.MembersResolved)
			get("members_unset", &rep.MembersUnset)
		}
	}
	if rep.RestorePointOlderThanBackup {
		rep.NotRecoverable = "revocations, route and tag changes made after the backup's time are unknown to PostgreSQL and were not replayed: the Owner reviews devices, members and the imported policy"
	}
	return nil
}
