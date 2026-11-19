package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ReconfigureStore is the registry side of instance.reconfigure (DBStore over PostgreSQL; in-memory fakes in the unit
// tests and the real-Docker test). Every write is idempotent: a step runs again after a retry or /retry.
type ReconfigureStore interface {
	// ReconfigureTarget reads the instance, its tenant's slug and status, the host's public entry and the configuration
	// version in force (Current nil when the instance has none).
	ReconfigureTarget(ctx context.Context, tenantID, instanceID uuid.UUID) (ReconfigureTarget, error)
	// ConfigVersion reads one configuration version of the instance.
	ConfigVersion(ctx context.Context, tenantID, instanceID, versionID uuid.UUID) (ConfigVersion, error)
	// InsertConfigVersion records v (`pending`) unless a version with its id exists — it is returned then.
	InsertConfigVersion(ctx context.Context, tenantID, instanceID uuid.UUID, v NewConfigVersion) (ConfigVersion, error)
	// CurrentPolicy reads the policy application in force of the instance (found = false when none is recorded).
	CurrentPolicy(ctx context.Context, tenantID, instanceID uuid.UUID) (AppliedPolicy, bool, error)
	// ApplyConfig makes the version the one in force in ONE transaction: version `applied`, the previous `superseded`,
	// tenant_instances.config_version_id (conditional on the previous), the operation's .succeeded (once).
	ApplyConfig(ctx context.Context, r ApplyConfigRequest) error
	// RevertConfig: the version `failed`; the instance points at the previous version again (`applied`) when it pointed
	// at the version.
	RevertConfig(ctx context.Context, tenantID, instanceID, versionID, previousID uuid.UUID) error
	// RecordUnchanged closes the operation of a reconfiguration that changed nothing (.succeeded, once).
	RecordUnchanged(ctx context.Context, op audit.Operation, details audit.Details) error
	// RecordRollback records the outcome of the rollback: success ⇒ the operation's .failed (once) and the event
	// platform.instance.config_rollback when files were restored; Failed ⇒ only that event, with outcome failure.
	RecordRollback(ctx context.Context, r RollbackRecord) error
}

// ReconfigureTarget is the instance a reconfiguration acts on.
type ReconfigureTarget struct {
	Instance     InstanceRecord // with the host's public entry
	TenantSlug   string
	TenantStatus string
	Current      *ConfigVersion // the version in force; nil when none
}

// ConfigVersion is an instance_config_versions row (no secret: rendered_config is a description).
type ConfigVersion struct {
	ID              uuid.UUID
	Version         int32
	Status          string
	TemplateVersion string
	ConfigSHA256    string
	Params          json.RawMessage
}

// NewConfigVersion is the version config.record writes.
type NewConfigVersion struct {
	ID              uuid.UUID
	TemplateVersion uint32
	ConfigSHA256    string
	Params          configParams
	CreatedBy       *uuid.UUID
}

// AppliedPolicy is the policy application in force (exactly the string sent, and its sha256).
type AppliedPolicy struct {
	HuJSON string
	SHA256 string
}

// ApplyConfigRequest is config.apply.
type ApplyConfigRequest struct {
	TenantID, InstanceID         uuid.UUID
	VersionID, PreviousVersionID uuid.UUID
	DERPRegionID                 int32
	Operation                    audit.Operation
	Details                      audit.Details
}

// RollbackRecord is the outcome of a rollback.
type RollbackRecord struct {
	TenantID, InstanceID uuid.UUID
	Operation            audit.Operation
	Reason               string // stable code
	Failed               bool   // the rollback itself failed
	Details              audit.Details
}

var _ ReconfigureStore = (*DBStore)(nil)

func versionOf(v sqlcdb.InstanceConfigVersion) ConfigVersion {
	return ConfigVersion{ID: v.ID, Version: v.Version, Status: v.Status, TemplateVersion: v.TemplateVersion,
		ConfigSHA256: v.ConfigSha256, Params: v.Params}
}

// ReconfigureTarget implements ReconfigureStore.
func (d *DBStore) ReconfigureTarget(ctx context.Context, tenantID, instanceID uuid.UUID) (ReconfigureTarget, error) {
	var out ReconfigureTarget
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetReconfigureTarget(ctx, sqlcdb.GetReconfigureTargetParams{ID: instanceID, TenantID: tenantID})
		if err != nil {
			return notFound(err)
		}
		i := row.TenantInstance
		out.Instance = InstanceRecord{ID: i.ID, TenantID: i.TenantID, HostID: i.HostID, HostName: row.HostName,
			Status: i.Status, ImageDigest: i.ImageDigest, HeadscaleVersion: i.HeadscaleVersion,
			ControlHostname: i.ControlHostname, BaseDomain: i.BaseDomain, RunUID: i.RunUid, NetCIDR: i.NetCidr,
			APIKeyExpiresAt: i.ApiKeyExpiresAt, APIKeyRef: deref(i.ApiKeySecretRef), APIKeyPrefix: deref(i.ApiKeyPrefix),
			NoiseFingerprint: deref(i.NoiseKeyFingerprint)}
		if i.StunPort != nil {
			out.Instance.STUNPort = *i.StunPort
		}
		if i.DerpRegionID != nil {
			out.Instance.DERPRegionID = *i.DerpRegionID
		}
		var pe struct {
			IPv4 string `json:"ipv4"`
		}
		if len(row.HostPublicEntry) > 0 && json.Unmarshal(row.HostPublicEntry, &pe) == nil && pe.IPv4 != "" {
			if a, err := netip.ParseAddr(pe.IPv4); err == nil {
				out.Instance.PublicEntryIPv4 = a
			}
		}
		out.TenantSlug, out.TenantStatus = row.TenantSlug, row.TenantStatus
		if i.ConfigVersionID == nil {
			return nil
		}
		v, err := q.GetInstanceConfigVersion(ctx, sqlcdb.GetInstanceConfigVersionParams{TenantID: tenantID,
			InstanceID: instanceID, ID: *i.ConfigVersionID})
		if err != nil {
			return notFound(err)
		}
		cv := versionOf(v)
		out.Current = &cv
		return nil
	})
	return out, err
}

// ConfigVersion implements ReconfigureStore.
func (d *DBStore) ConfigVersion(ctx context.Context, tenantID, instanceID, versionID uuid.UUID) (ConfigVersion, error) {
	var out ConfigVersion
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		v, err := q.GetInstanceConfigVersion(ctx, sqlcdb.GetInstanceConfigVersionParams{TenantID: tenantID,
			InstanceID: instanceID, ID: versionID})
		if err != nil {
			return notFound(err)
		}
		out = versionOf(v)
		return nil
	})
	return out, err
}

// InsertConfigVersion implements ReconfigureStore.
func (d *DBStore) InsertConfigVersion(ctx context.Context, tenantID, instanceID uuid.UUID, nv NewConfigVersion) (ConfigVersion, error) {
	var out ConfigVersion
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		v, err := q.GetInstanceConfigVersion(ctx, sqlcdb.GetInstanceConfigVersionParams{TenantID: tenantID,
			InstanceID: instanceID, ID: nv.ID})
		switch {
		case err == nil:
			out = versionOf(v) // recorded by an earlier attempt
			return nil
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		params, err := json.Marshal(nv.Params)
		if err != nil {
			return err
		}
		v, err = q.InsertPendingConfigVersion(ctx, sqlcdb.InsertPendingConfigVersionParams{ID: nv.ID, TenantID: tenantID,
			InstanceID: instanceID, TemplateVersion: fmt.Sprint(nv.TemplateVersion), Params: params,
			RenderedConfig: fmt.Sprintf("rendered by the host agent from typed parameters (template v%d); "+
				"the files on the host are identified by config_sha256", nv.TemplateVersion),
			ConfigSha256: nv.ConfigSHA256, CreatedBy: nv.CreatedBy})
		if err != nil {
			return err
		}
		out = versionOf(v)
		return nil
	})
	return out, err
}

// CurrentPolicy implements ReconfigureStore (policy_applications is a table of the tenant — RLS).
func (d *DBStore) CurrentPolicy(ctx context.Context, tenantID, instanceID uuid.UUID) (AppliedPolicy, bool, error) {
	var (
		out   AppliedPolicy
		found bool
	)
	err := d.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		a, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID,
			InstanceID: instanceID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out, found = AppliedPolicy{HuJSON: a.AppliedHujson, SHA256: a.AppliedSha256}, true
		return nil
	})
	return out, found, err
}

// operationFinished reports whether the operation already has its outcome event (a step that ran again).
func operationFinished(ctx context.Context, q *sqlcdb.Queries, op audit.Operation) (bool, error) {
	if op.ID == uuid.Nil {
		return true, nil // nothing to close
	}
	s, err := q.OperationState(ctx, op.ID)
	if err != nil {
		return false, err
	}
	return s.Finished, nil
}

// closeOperation writes the outcome event of op through write: an operation of the platform in q (the platform
// transaction of the change), an operation of a tenant-scope caller — PUT /tenants/{t}/dns/settings (P4-T12) opened it in
// the tenant's transaction — in a transaction of that tenant once the platform transaction committed (RLS of 0004: a
// platform transaction writes platform events only, a tenant transaction only its tenant's). A crash between the two
// leaves the operation open (Logger.OpenOperations reports it), never a change without its event.
func (d *DBStore) closeOperation(ctx context.Context, op audit.Operation, write func(q *sqlcdb.Queries) error) error {
	if op.TenantID == nil {
		return errors.New("orchestrator: closeOperation is for tenant operations")
	}
	return d.st.WithTenantTx(ctx, *op.TenantID, func(q *sqlcdb.Queries) error {
		done, err := operationFinished(ctx, q, op)
		if err != nil || done {
			return err
		}
		return write(q)
	})
}

// ApplyConfig implements ReconfigureStore.
func (d *DBStore) ApplyConfig(ctx context.Context, r ApplyConfigRequest) error {
	if err := d.applyConfig(ctx, r); err != nil {
		return err
	}
	if r.Operation.TenantID == nil {
		return nil
	}
	return d.closeOperation(ctx, r.Operation, func(q *sqlcdb.Queries) error { return r.Operation.Succeeded(ctx, q, r.Details) })
}

func (d *DBStore) applyConfig(ctx context.Context, r ApplyConfigRequest) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.GetTenantInstance(ctx, r.InstanceID)
		if err != nil {
			return notFound(err)
		}
		if inst.TenantID != r.TenantID || inst.ConfigVersionID == nil {
			return fmt.Errorf("%w: instance %s has no configuration version", ErrState, r.InstanceID)
		}
		switch *inst.ConfigVersionID {
		case r.VersionID: // applied by an earlier run
		case r.PreviousVersionID:
			var derp *int32
			if r.DERPRegionID > 0 {
				derp = &r.DERPRegionID
			}
			n, err := q.SwapInstanceConfigVersion(ctx, sqlcdb.SwapInstanceConfigVersionParams{ConfigVersionID: r.VersionID,
				DerpRegionID: derp, ID: r.InstanceID, TenantID: r.TenantID, ExpectedVersionID: r.PreviousVersionID})
			if err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("%w: instance %s changed configuration version meanwhile", ErrState, r.InstanceID)
			}
		default:
			return fmt.Errorf("%w: instance %s points at another configuration version", ErrState, r.InstanceID)
		}
		if _, err := q.TransitionConfigVersionStatus(ctx, sqlcdb.TransitionConfigVersionStatusParams{Status: ConfigApplied,
			TenantID: r.TenantID, ID: r.VersionID, FromStatus: []string{ConfigPending, ConfigApplied}}); err != nil {
			return err
		}
		if r.PreviousVersionID != r.VersionID {
			if _, err := q.TransitionConfigVersionStatus(ctx, sqlcdb.TransitionConfigVersionStatusParams{
				Status: ConfigSuperseded, TenantID: r.TenantID, ID: r.PreviousVersionID,
				FromStatus: []string{ConfigApplied}}); err != nil {
				return err
			}
		}
		if r.Operation.TenantID != nil {
			return nil // closed in the tenant's transaction (ApplyConfig)
		}
		done, err := operationFinished(ctx, q, r.Operation)
		if err != nil || done {
			return err
		}
		return r.Operation.Succeeded(ctx, q, r.Details)
	})
}

// RevertConfig implements ReconfigureStore.
func (d *DBStore) RevertConfig(ctx context.Context, tenantID, instanceID, versionID, previousID uuid.UUID) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.GetTenantInstance(ctx, instanceID)
		if err != nil {
			return notFound(err)
		}
		if inst.TenantID != tenantID {
			return ErrNotFound
		}
		if inst.ConfigVersionID != nil && *inst.ConfigVersionID == versionID && previousID != versionID {
			prev, err := q.GetInstanceConfigVersion(ctx, sqlcdb.GetInstanceConfigVersionParams{TenantID: tenantID,
				InstanceID: instanceID, ID: previousID})
			if err != nil {
				return notFound(err)
			}
			var derp *int32
			if p, perr := decodeParams(prev.Params); perr == nil && p.DERPRegionID > 0 {
				v := int32(p.DERPRegionID) //nolint:gosec // 900–999
				derp = &v
			}
			if _, err := q.SwapInstanceConfigVersion(ctx, sqlcdb.SwapInstanceConfigVersionParams{ConfigVersionID: previousID,
				DerpRegionID: derp, ID: instanceID, TenantID: tenantID, ExpectedVersionID: versionID}); err != nil {
				return err
			}
			if _, err := q.TransitionConfigVersionStatus(ctx, sqlcdb.TransitionConfigVersionStatusParams{
				Status: ConfigApplied, TenantID: tenantID, ID: previousID, FromStatus: []string{ConfigSuperseded}}); err != nil {
				return err
			}
		}
		if previousID == versionID {
			return nil
		}
		_, err = q.TransitionConfigVersionStatus(ctx, sqlcdb.TransitionConfigVersionStatusParams{Status: ConfigFailed,
			TenantID: tenantID, ID: versionID, FromStatus: []string{ConfigPending, ConfigApplied}})
		return err
	})
}

// RecordUnchanged implements ReconfigureStore.
func (d *DBStore) RecordUnchanged(ctx context.Context, op audit.Operation, details audit.Details) error {
	if op.TenantID != nil {
		return d.closeOperation(ctx, op, func(q *sqlcdb.Queries) error { return op.Succeeded(ctx, q, details) })
	}
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		done, err := operationFinished(ctx, q, op)
		if err != nil || done {
			return err
		}
		return op.Succeeded(ctx, q, details)
	})
}

// RecordRollback implements ReconfigureStore.
func (d *DBStore) RecordRollback(ctx context.Context, r RollbackRecord) error {
	if r.Operation.TenantID != nil && !r.Failed {
		if err := d.closeOperation(ctx, r.Operation, func(q *sqlcdb.Queries) error {
			return r.Operation.Failed(ctx, q, r.Reason, r.Details)
		}); err != nil {
			return err
		}
		if written, _ := r.Details["config_written"].(bool); !written {
			return nil
		}
		return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			return audit.Record(ctx, q, audit.Event{Action: ActionConfigRollback, ActorType: audit.ActorSystem,
				ActorDisplay: ReconfigureKind, ResourceType: "instance", ResourceID: r.InstanceID.String(), Details: r.Details})
		})
	}
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		ev := audit.Event{Action: ActionConfigRollback, ActorType: audit.ActorSystem, ActorDisplay: ReconfigureKind,
			ResourceType: "instance", ResourceID: r.InstanceID.String(), Details: r.Details}
		if r.Failed {
			ev.Outcome = audit.OutcomeFailure
			return audit.Record(ctx, q, ev)
		}
		done, err := operationFinished(ctx, q, r.Operation)
		if err != nil || done {
			return err
		}
		if err := r.Operation.Failed(ctx, q, r.Reason, r.Details); err != nil {
			return err
		}
		if written, _ := r.Details["config_written"].(bool); !written {
			return nil // nothing was written on the host: nothing was rolled back there
		}
		return audit.Record(ctx, q, ev)
	})
}
