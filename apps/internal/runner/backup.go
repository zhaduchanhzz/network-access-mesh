package runner

import (
	"context"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// newBackups builds backup/restore v1 (P3-T11, §17.1–§17.2) over the worker's dependencies: the Host Agent (typed RPCs),
// the SecretStore (the tenants' backup keys, the API key a restore re-issues), the shared Headscale registry (the
// restore's checks over the API, invalidated after the key changes) and the manifest keys of MG_BACKUP_MANIFEST_PUBKEY.
// Without an agent or a manifest key the handlers still run and fail explicitly (agent_not_configured,
// backup_not_configured) and no backup is scheduled.
func newBackups(cfg config.Config, d *deps, agent *agentclient.Client) *backup.Service {
	bc := backup.Config{Secrets: d.secrets, ManifestKeys: cfg.Backup.ManifestKeys, Interval: cfg.Backup.Interval,
		Retention: cfg.Backup.Retention, Logger: d.log}
	if agent != nil {
		bc.Agent = agent
	}
	if d.headscale != nil {
		bc.Registry = d.headscale
	}
	if agent == nil || !cfg.Backup.Enabled() {
		d.log.Warn("instance.backup is not scheduled by this worker: the Host Agent (MG_AGENT_*) or the manifest key " +
			"(MG_BACKUP_MANIFEST_PUBKEY — key ceremony P2-T04a) is not configured; backup and restore jobs fail explicitly")
	}
	return backup.New(d.st, bc)
}

// backupsEnabled: the schedule runs only with an agent and a manifest key.
func backupsEnabled(cfg config.Config, agent *agentclient.Client) bool {
	return agent != nil && cfg.Backup.Enabled()
}

// restoreAction executes an approved restore (P3-T11, §17.2 step 1, §8.5 platform.instance:restore — 2P; the decider
// of the platform may hold the restore_only condition): in the approval's transaction the backup and the instance are
// checked again and the lifecycle job instance.restore is enqueued with exactly the approved payload.
func restoreAction(svc *backup.Service) approvals.Action {
	return approvals.Typed(approvals.Spec{Name: backup.ActionRestore, Scope: authz.ScopePlatform, ResourceType: "instance",
		Permission: "platform.instance:restore", DecideConditions: []string{authz.CondRestoreOnly}},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p backup.RestorePayload) (*uuid.UUID, error) {
			if e.Request.ResourceID != p.InstanceID.String() {
				return nil, &backup.Error{Kind: backup.ErrInvalid, Reason: "payload_mismatch", Detail: "the payload names another instance than the request"}
			}
			return svc.EnqueueRestore(ctx, tx, e.Request.RequestedBy.IdentityID, e.Request.ID, p)
		})
}
