package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

var _ BackfillStore = (*DBStore)(nil)

// BackfillTarget implements BackfillStore: the tenant (with its plan's limits), its live instance with the host's public
// entry and the version in force (ReconfigureTarget), the holder of its lifecycle lock, its relay rows and whether it
// has a desired policy version — platform transactions, reads only.
func (d *DBStore) BackfillTarget(ctx context.Context, tenantID uuid.UUID) (BackfillTarget, error) {
	var out BackfillTarget
	var err error
	if out.Tenant, err = d.Tenant(ctx, tenantID); err != nil {
		return out, err
	}
	var instanceID uuid.UUID
	err = d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		t, err := q.GetTenant(ctx, tenantID)
		if err != nil {
			return notFound(err)
		}
		out.DesiredPolicy = t.DesiredPolicyVersionID != nil
		inst, err := q.GetLiveInstanceForTenant(ctx, tenantID)
		if err != nil {
			return notFound(err)
		}
		instanceID = inst.ID
		key := jobs.LockKey(tenantID)
		switch j, err := q.GetLockHolder(ctx, key); {
		case err == nil:
			out.LockHolder, out.LockHolderKey, out.LockHolderKind, out.LockHolderStatus = j.ID, key, j.Kind, j.Status
			if j.InstanceID != nil {
				out.LockHolderInstance = *j.InstanceID
			}
			var e struct {
				Code string `json:"code"`
			}
			if len(j.Error) > 0 && json.Unmarshal(j.Error, &e) == nil {
				out.LockHolderCode = e.Code
			}
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		switch r, err := q.GetTenantRelayRegionByCode(ctx, sqlcdb.GetTenantRelayRegionByCodeParams{TenantID: tenantID,
			Code: relayCode(t.Slug)}); {
		case err == nil:
			out.RelayRegion = true
			n, err := q.CountRelayAssignmentsOfInstance(ctx, sqlcdb.CountRelayAssignmentsOfInstanceParams{TenantID: tenantID,
				InstanceID: inst.ID, RelayRegionID: r.ID})
			if err != nil {
				return err
			}
			out.RelayAssigned = n > 0
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	rt, err := d.ReconfigureTarget(ctx, tenantID, instanceID)
	if err != nil {
		return out, err
	}
	out.Instance, out.Current = rt.Instance, rt.Current
	return out, nil
}

// BeginBackfill implements BackfillStore.
func (d *DBStore) BeginBackfill(ctx context.Context, ev audit.Event) (audit.Operation, error) {
	var op audit.Operation
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		op, err = audit.Requested(ctx, q, ev)
		return err
	})
	return op, err
}

// FailBackfill implements BackfillStore.
func (d *DBStore) FailBackfill(ctx context.Context, op audit.Operation, reason string, details audit.Details) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error { return op.Failed(ctx, q, reason, details) })
}

// RecordBackfill implements BackfillStore: one platform transaction — the configuration version (applied, applied_at
// now) and config_version_id + derp_region_id while the instance has no version yet (or already this content), the
// fingerprint while none is recorded (or the same), the relay rows (upserts of step 17), "<op>.succeeded".
func (d *DBStore) RecordBackfill(ctx context.Context, r BackfillRecord) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.GetTenantInstance(ctx, r.InstanceID)
		if err != nil || inst.TenantID != r.TenantID {
			return ErrNotFound
		}
		if r.Config != nil {
			if err := recordBackfillConfig(ctx, q, inst, r); err != nil {
				return err
			}
		}
		if r.Fingerprint != "" {
			switch {
			case inst.NoiseKeyFingerprint == nil:
				if err := q.SetInstanceNoiseFingerprint(ctx, sqlcdb.SetInstanceNoiseFingerprintParams{Fingerprint: r.Fingerprint,
					ID: r.InstanceID, TenantID: r.TenantID}); err != nil {
					return err
				}
			case *inst.NoiseKeyFingerprint != r.Fingerprint:
				return fmt.Errorf("%w: another Noise key fingerprint was recorded meanwhile", ErrState)
			}
		}
		if rr := r.Relay; rr != nil {
			t, host := rr.TenantID, rr.HostID
			p := sqlcdb.UpsertEmbeddedRelayRegionParams{TenantID: &t, Code: rr.Code, Name: rr.Name, DerpRegionID: rr.DERPRegionID,
				Hostname: rr.Hostname, HostID: &host}
			if rr.IPv4.IsValid() {
				a := rr.IPv4
				p.Ipv4 = &a
			}
			if rr.STUNPort > 0 {
				sp := rr.STUNPort
				p.StunPort = &sp
			}
			region, err := q.UpsertEmbeddedRelayRegion(ctx, p)
			if err != nil {
				return err
			}
			if _, err := q.UpsertRelayAssignment(ctx, sqlcdb.UpsertRelayAssignmentParams{TenantID: rr.TenantID,
				InstanceID: rr.InstanceID, RelayRegionID: region.ID}); err != nil {
				return err
			}
		}
		return r.Operation.Succeeded(ctx, q, r.Details)
	})
}

func recordBackfillConfig(ctx context.Context, q *sqlcdb.Queries, inst sqlcdb.TenantInstance, r BackfillRecord) error {
	c := r.Config
	v, err := q.GetInstanceConfigVersionBySHA(ctx, sqlcdb.GetInstanceConfigVersionBySHAParams{TenantID: r.TenantID,
		InstanceID: r.InstanceID, ConfigSha256: c.ConfigSHA256})
	switch {
	case errors.Is(err, store.ErrNoRows):
		params, err := json.Marshal(c.Params)
		if err != nil {
			return err
		}
		if v, err = q.InsertInstanceConfigVersion(ctx, sqlcdb.InsertInstanceConfigVersionParams{TenantID: r.TenantID,
			InstanceID: r.InstanceID, TemplateVersion: fmt.Sprint(c.TemplateVersion), Params: params,
			RenderedConfig: fmt.Sprintf("backfilled (P3-T14b) for an instance built by hand: config.yaml on the host "+
				"(config_sha256) is byte-identical to the host agent's rendering of these typed parameters (template v%d)",
				c.TemplateVersion), ConfigSha256: c.ConfigSHA256}); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if inst.ConfigVersionID != nil && *inst.ConfigVersionID != v.ID {
		return fmt.Errorf("%w: the instance got another configuration version meanwhile", ErrState)
	}
	if _, err := q.TransitionConfigVersionStatus(ctx, sqlcdb.TransitionConfigVersionStatusParams{Status: "applied",
		TenantID: r.TenantID, ID: v.ID, FromStatus: []string{"applied"}}); err != nil {
		return err
	}
	derp := r.DERPRegionID
	return q.SetInstanceConfigVersion(ctx, sqlcdb.SetInstanceConfigVersionParams{ConfigVersionID: v.ID, DerpRegionID: &derp,
		ID: r.InstanceID, TenantID: r.TenantID})
}
