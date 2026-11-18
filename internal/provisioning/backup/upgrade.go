package backup

// The backup subsystem as instance.upgrade uses it (P3-T13a, §11.4 Upgrade, §17.6): the cold backup taken after the
// instance is stopped (the same backup as instance.backup — a cold copy because the instance is stopped — recorded with
// the upgrade's job), the opening of that backup for the preflight with the target binary (verified, data key unwrapped
// — the online path), and the rollback by restore: the restore of §17.2 run inside the upgrade's compensation, in the
// order of provisioning (restore with the applied policy, PostRestoreReconcile under the API-key lock — revocations
// made while the new image ran are replayed, every API key and pre-auth key of the backup expired —, edge, the checks
// over the API, members, inventory.sync and the Owner's notification).

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

// Ready reports whether backups can run in this process (a Host Agent, a manifest key, the SecretStore): the preflight of
// an upgrade checks it before anything is stopped.
func (s *Service) Ready() error { return s.enabled() }

// ColdBackup takes the cold backup of an upgrade: the instance is stopped, so the agent takes a cold copy (§17.1 "Cold
// backup trước upgrade"); the backups row carries the upgrade's job id. A backup that would be skipped (instance or
// tenant not served) or that is not a cold copy is refused — nothing of an upgrade proceeds without it.
func (s *Service) ColdBackup(ctx context.Context, jobID, tenantID, instanceID uuid.UUID) (BackupResult, error) {
	res, err := s.backup(ctx, jobID, tenantID, instanceID, s.cfg.Retention)
	if err != nil {
		return res, err
	}
	switch {
	case res.Skipped != "":
		return res, jobs.Permanent("backup_skipped", fmt.Errorf("the instance is not backed up: %s", res.Skipped))
	case res.Method != backupfmt.MethodColdCopy:
		return res, jobs.Permanent("backup_not_cold", fmt.Errorf("the backup is a %s, not a cold copy: the instance was running", res.Method))
	}
	return res, nil
}

// OpenedBackup is a verified backup of an instance and its unwrapped data key (the caller clears DataKey).
type OpenedBackup struct {
	Artifact         *agentv1.ArtifactRef
	DataKey          []byte
	HeadscaleVersion string
	Image            string
	CreatedAt        time.Time
}

// OpenBackup verifies a backup of the instance — the worker's half of §17.2 step 2: the row of the tenant (RLS),
// succeeded, of this instance; the signed manifest, its identity and digests — and only then unwraps its data key (the
// online path). For the preflight of an upgrade with the target binary on a copy of the data (P3-T13a).
func (s *Service) OpenBackup(ctx context.Context, jobID, tenantID, instanceID, backupID uuid.UUID) (OpenedBackup, error) {
	if err := s.enabled(); err != nil {
		return OpenedBackup{}, err
	}
	v, err := s.verify(ctx, jobID, tenantID, RestoreInput{RestorePayload: RestorePayload{BackupID: backupID, InstanceID: instanceID}})
	if err != nil {
		return OpenedBackup{}, err
	}
	ref, err := keyRef(tenantID, v)
	if err != nil {
		return OpenedBackup{}, err
	}
	dk, err := s.dataKey(ctx, jobID, tenantID, v, ref)
	if err != nil {
		return OpenedBackup{}, err
	}
	return OpenedBackup{Artifact: &agentv1.ArtifactRef{Sequence: v.seq, ArchiveSha256: *v.row.Sha256, ManifestSha256: *v.row.ManifestSha256},
		DataKey: dk, HeadscaleVersion: v.manifest.HeadscaleVersion, Image: v.manifest.Image, CreatedAt: v.manifest.Time()}, nil
}

// collector gathers the details of the restore steps run by RollbackRestore (they belong to the upgrade's step).
type collector struct{ d map[string]any }

func (c *collector) SetDetail(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return errors.New("backup: a step detail is not an object")
	}
	if c.d == nil {
		c.d = map[string]any{}
	}
	maps.Copy(c.d, m)
	return nil
}

// RollbackRestore is the rollback of an upgrade after the switch (§11.4: "dừng → restore backup → image cũ → start" —
// the caller stopped the instance and switched the image back): the restore of §17.2 with the backup of the upgrade —
// verification, restore with the applied policy (the restored database never serves another one), PostRestoreReconcile,
// the edge attached again, the checks over the API (a failure detaches the edge again, Critical), the members
// re-resolved, inventory.sync, verified_at and the Owners' notification. Every part is idempotent (the agent recognises a
// restore of the same job): a /rollback that runs it again completes it. It returns the details of the steps.
func (s *Service) RollbackRestore(ctx context.Context, jobID, tenantID, instanceID, backupID uuid.UUID) (map[string]any, error) {
	if err := s.enabled(); err != nil {
		return nil, err
	}
	if s.cfg.Registry == nil {
		return nil, jobs.Permanent("headscale_not_configured", errors.New("no Headscale registry"))
	}
	in := RestoreInput{RestorePayload: RestorePayload{BackupID: backupID, InstanceID: instanceID}}
	v, err := s.verify(ctx, jobID, tenantID, in)
	if err != nil {
		return nil, err
	}
	plan, devices, err := s.plan(ctx, tenantID, v, false)
	if err != nil {
		return nil, err
	}
	c := &collector{d: map[string]any{"backup_id": backupID.String(), "sequence": v.seq}}
	if err := s.stepInstance(ctx, jobID, tenantID, v, in, c); err != nil {
		return c.d, err
	}
	if err := s.stepReconcile(ctx, jobID, tenantID, v, plan, c); err != nil {
		return c.d, err
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	r, err := s.cfg.Agent.EnsureEdgeAttachment(cctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: v.inst.ref(), JobId: jobID.String()})
	cancel()
	if err != nil {
		return c.d, agentErr("EnsureEdgeAttachment", err)
	}
	c.d["edge_attached"] = r.GetAttached() || r.GetAlreadyAttached()
	if err := s.stepCheck(ctx, jobID, tenantID, v, devices, c); err != nil {
		return c.d, err
	}
	if err := s.stepMembers(ctx, tenantID, c); err != nil {
		return c.d, err
	}
	if err := s.stepFinish(ctx, jobID, tenantID, v, in, c); err != nil {
		return c.d, err
	}
	return c.d, nil
}
