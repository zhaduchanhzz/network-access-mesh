package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// InstanceOpsStore is the registry side of instance.restart and instance.upgrade (DBStore over PostgreSQL; in-memory
// fakes in the unit tests and the real-Docker test). Every write is idempotent: a step runs again after a retry.
type InstanceOpsStore interface {
	// OpsTarget reads the instance, its tenant's slug and status, the host's public entry and the configuration version
	// in force (as ReconfigureTarget).
	OpsTarget(ctx context.Context, tenantID, instanceID uuid.UUID) (ReconfigureTarget, error)
	// AppliedPolicy reads the policy application in force of the instance and the kind of its version.
	AppliedPolicy(ctx context.Context, tenantID, instanceID uuid.UUID) (PolicyInForce, bool, error)
	// FinishOperation closes the operation (.succeeded, once).
	FinishOperation(ctx context.Context, op audit.Operation, details audit.Details) error
	// FinishUpgrade records a successful upgrade in ONE transaction: image_digest and headscale_version of the
	// instance, a configuration version with the target image (the same sha256) applied, the previous superseded,
	// tenant_instances.config_version_id (conditional on the previous), the operation's .succeeded (once).
	FinishUpgrade(ctx context.Context, f UpgradeFinish) error
	// FailOperation records a failed operation in ONE transaction: the operation's .failed (once — not when the
	// rollback itself failed: the operation stays open until /rollback ends it), the event
	// platform.instance.upgrade_rollback when RollbackEvent is set (its value is the outcome), and the notification
	// instance.operation_failed of the platform staff.
	FailOperation(ctx context.Context, f OpsFailure) error
	// NotifyFailure records only the notification (a job that spent its retries: failed_resumable).
	NotifyFailure(ctx context.Context, f OpsFailure) error
}

// PolicyInForce is the policy application in force: the string sent, its sha256 and the kind of its version
// (baseline, suspension, user).
type PolicyInForce struct {
	HuJSON string
	SHA256 string
	Kind   string
}

// UpgradeFinish is upgrade.finish.
type UpgradeFinish struct {
	TenantID, InstanceID uuid.UUID
	PreviousVersionID    uuid.UUID
	Version              NewConfigVersion
	ImageDigest          string
	HeadscaleVersion     string
	Operation            audit.Operation
	Details              audit.Details
}

// OpsFailure is the outcome of a failed operation.
type OpsFailure struct {
	TenantID, InstanceID, JobID uuid.UUID
	Kind                        string // instance.restart | instance.upgrade
	Operation                   audit.Operation
	Reason                      string // stable code
	Outcome                     string // OutcomeRolledBack | OutcomeRollbackFailed | OutcomeResumable
	TenantSlug                  string
	Details                     audit.Details
	// RollbackEvent: record platform.instance.upgrade_rollback with this outcome (true success, false failure).
	RollbackEvent *bool
}

var _ InstanceOpsStore = (*DBStore)(nil)

// OpsTarget implements InstanceOpsStore.
func (d *DBStore) OpsTarget(ctx context.Context, tenantID, instanceID uuid.UUID) (ReconfigureTarget, error) {
	return d.ReconfigureTarget(ctx, tenantID, instanceID)
}

// AppliedPolicy implements InstanceOpsStore (policy_applications and policy_versions are tables of the tenant — RLS).
func (d *DBStore) AppliedPolicy(ctx context.Context, tenantID, instanceID uuid.UUID) (PolicyInForce, bool, error) {
	var (
		out   PolicyInForce
		found bool
	)
	err := d.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		a, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID, InstanceID: instanceID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: a.PolicyVersionID})
		if err != nil {
			return err
		}
		out, found = PolicyInForce{HuJSON: a.AppliedHujson, SHA256: a.AppliedSha256, Kind: v.Kind}, true
		return nil
	})
	return out, found, err
}

// FinishOperation implements InstanceOpsStore.
func (d *DBStore) FinishOperation(ctx context.Context, op audit.Operation, details audit.Details) error {
	return d.RecordUnchanged(ctx, op, details)
}

// FinishUpgrade implements InstanceOpsStore.
func (d *DBStore) FinishUpgrade(ctx context.Context, f UpgradeFinish) error {
	params, err := json.Marshal(f.Version.Params)
	if err != nil {
		return err
	}
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.GetTenantInstance(ctx, f.InstanceID)
		if err != nil {
			return notFound(err)
		}
		if inst.TenantID != f.TenantID || inst.ConfigVersionID == nil {
			return fmt.Errorf("%w: instance %s has no configuration version", ErrState, f.InstanceID)
		}
		switch *inst.ConfigVersionID {
		case f.Version.ID: // recorded by an earlier run
		case f.PreviousVersionID:
			if _, err := q.GetInstanceConfigVersion(ctx, sqlcdb.GetInstanceConfigVersionParams{TenantID: f.TenantID,
				InstanceID: f.InstanceID, ID: f.Version.ID}); errors.Is(err, store.ErrNoRows) {
				if _, err := q.InsertPendingConfigVersion(ctx, sqlcdb.InsertPendingConfigVersionParams{ID: f.Version.ID,
					TenantID: f.TenantID, InstanceID: f.InstanceID, TemplateVersion: fmt.Sprint(f.Version.TemplateVersion), Params: params,
					RenderedConfig: fmt.Sprintf("the configuration in force (sha256 unchanged) on the image %s — upgrade (P3-T13a); "+
						"rendered by the host agent from typed parameters (template v%d)", f.ImageDigest, f.Version.TemplateVersion),
					ConfigSha256: f.Version.ConfigSHA256, CreatedBy: f.Version.CreatedBy}); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			var derp *int32
			if inst.DerpRegionID != nil {
				derp = inst.DerpRegionID
			}
			n, err := q.SwapInstanceConfigVersion(ctx, sqlcdb.SwapInstanceConfigVersionParams{ConfigVersionID: f.Version.ID,
				DerpRegionID: derp, ID: f.InstanceID, TenantID: f.TenantID, ExpectedVersionID: f.PreviousVersionID})
			if err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("%w: instance %s changed configuration version meanwhile", ErrState, f.InstanceID)
			}
		default:
			return fmt.Errorf("%w: instance %s points at another configuration version", ErrState, f.InstanceID)
		}
		if _, err := q.TransitionConfigVersionStatus(ctx, sqlcdb.TransitionConfigVersionStatusParams{Status: ConfigApplied,
			TenantID: f.TenantID, ID: f.Version.ID, FromStatus: []string{ConfigPending, ConfigApplied}}); err != nil {
			return err
		}
		if _, err := q.TransitionConfigVersionStatus(ctx, sqlcdb.TransitionConfigVersionStatusParams{Status: ConfigSuperseded,
			TenantID: f.TenantID, ID: f.PreviousVersionID, FromStatus: []string{ConfigApplied}}); err != nil {
			return err
		}
		if _, err := q.SetTenantInstanceRuntime(ctx, sqlcdb.SetTenantInstanceRuntimeParams{HeadscaleVersion: f.HeadscaleVersion,
			ImageDigest: f.ImageDigest, ID: f.InstanceID, TenantID: f.TenantID}); err != nil {
			return err
		}
		done, err := operationFinished(ctx, q, f.Operation)
		if err != nil || done {
			return err
		}
		return f.Operation.Succeeded(ctx, q, f.Details)
	})
}

// FailOperation implements InstanceOpsStore.
func (d *DBStore) FailOperation(ctx context.Context, f OpsFailure) error {
	return d.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		q := tx.Q
		if f.Outcome != OutcomeRollbackFailed {
			done, err := operationFinished(ctx, q, f.Operation)
			if err != nil {
				return err
			}
			if !done {
				if err := f.Operation.Failed(ctx, q, f.Reason, f.Details); err != nil {
					return err
				}
			}
		}
		if f.RollbackEvent != nil {
			ev := audit.Event{Action: ActionUpgradeRollback, ActorType: audit.ActorSystem, ActorDisplay: f.Kind,
				ResourceType: "instance", ResourceID: f.InstanceID.String(), Details: f.Details}
			if !*f.RollbackEvent {
				ev.Outcome = audit.OutcomeFailure
			}
			if err := audit.Record(ctx, q, ev); err != nil {
				return err
			}
		}
		return d.enqueueFailure(ctx, tx, f)
	})
}

// NotifyFailure implements InstanceOpsStore.
func (d *DBStore) NotifyFailure(ctx context.Context, f OpsFailure) error {
	return d.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error { return d.enqueueFailure(ctx, tx, f) })
}

func (d *DBStore) enqueueFailure(ctx context.Context, tx *store.Tx, f OpsFailure) error {
	op := "restart"
	if f.Kind == UpgradeKind {
		op = "upgrade"
	}
	slug := f.TenantSlug
	if slug == "" {
		slug = "unknown"
	}
	_, err := d.notify.Enqueue(ctx, tx, notifications.InstanceOperationFailed(f.InstanceID, f.JobID, slug, op, f.Reason, f.Outcome))
	return err
}
