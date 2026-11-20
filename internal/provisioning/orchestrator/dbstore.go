package orchestrator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// DBStore is the Store of the worker over its two pools: registry rows (tenants, tenant_instances, identity_providers,
// relay_*) in platform transactions, tenant-internal rows (policy_versions, policy_applications, tenant_invitations,
// notification_outbox) in transactions of the tenant (RLS).
type DBStore struct {
	st       *store.Store
	notify   notifications.Enqueuer
	invites  tenants.InvitationNotifier // step 16: the Owner's account at a platform-hosted IdP (G4b-E1); nil ⇒ none
	now      func() time.Time
	lockWait time.Duration
}

var _ Store = (*DBStore)(nil)

// NewDBStore returns the Store of the worker. notify nil ⇒ notifications.Default.
func NewDBStore(st *store.Store, notify notifications.Enqueuer) *DBStore {
	if notify == nil {
		notify = notifications.Default
	}
	return &DBStore{st: st, notify: notify, now: time.Now, lockWait: 2 * time.Minute}
}

// WithOwnerInvite makes step 16 deliver the Owner invitation through n as well, in the same transaction as the
// invitation (G4b-E1): the worker passes members.IdPInviteNotifier{} — the job member.idp_invite that creates the
// Owner's account at the platform-hosted IdP and has the IdP e-mail its required actions, exactly as for an invitation
// sent from the Portal (the platform e-mail of the invitation stays notify's). Without it the Owner of a tenant whose
// IdP the platform hosts has no account to sign in with.
func (d *DBStore) WithOwnerInvite(n tenants.InvitationNotifier) *DBStore {
	d.invites = n
	return d
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// Tenant implements Store.
func (d *DBStore) Tenant(ctx context.Context, tenantID uuid.UUID) (TenantRecord, error) {
	var out TenantRecord
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetProvisionTenant(ctx, tenantID)
		if err != nil {
			return notFound(err)
		}
		t := row.Tenant
		out = TenantRecord{ID: t.ID, Slug: t.Slug, Name: t.Name, Status: t.Status, Settings: t.Settings}
		if t.DeploymentRegion != nil {
			out.Region = *t.DeploymentRegion
		}
		if row.PlanKey != nil {
			out.PlanKey = *row.PlanKey
		}
		out.Instance, err = instanceLimits(row.PlanLimits, row.PlanOverrides)
		return err
	})
	return out, err
}

// instanceLimits is PlanLimits.instance of the plan, each key overridden by the subscription (§13.3).
func instanceLimits(limits, overrides []byte) (InstanceLimits, error) {
	var out InstanceLimits
	for _, raw := range [][]byte{limits, overrides} {
		if len(raw) == 0 {
			continue
		}
		var v struct {
			Instance *struct {
				CPUs     *float64 `json:"cpus"`
				MemoryMB *int64   `json:"memory_mb"`
				PIDs     *int64   `json:"pids"`
			} `json:"instance"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return out, fmt.Errorf("orchestrator: plan limits unreadable: %w", err)
		}
		if v.Instance == nil {
			continue
		}
		if v.Instance.CPUs != nil {
			out.CPUs = *v.Instance.CPUs
		}
		if v.Instance.MemoryMB != nil {
			out.MemoryMB = *v.Instance.MemoryMB
		}
		if v.Instance.PIDs != nil {
			out.PIDs = *v.Instance.PIDs
		}
	}
	return out, nil
}

// Instance implements Store.
func (d *DBStore) Instance(ctx context.Context, tenantID, instanceID uuid.UUID) (InstanceRecord, error) {
	var out InstanceRecord
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetProvisionInstance(ctx, sqlcdb.GetProvisionInstanceParams{ID: instanceID, TenantID: tenantID})
		if err != nil {
			return notFound(err)
		}
		i := row.TenantInstance
		out = InstanceRecord{ID: i.ID, TenantID: i.TenantID, HostID: i.HostID, HostName: row.HostName, Status: i.Status,
			ImageDigest: i.ImageDigest, HeadscaleVersion: i.HeadscaleVersion, ControlHostname: i.ControlHostname,
			BaseDomain: i.BaseDomain, RunUID: i.RunUid, NetCIDR: i.NetCidr, APIKeyExpiresAt: i.ApiKeyExpiresAt,
			APIKeyRef: deref(i.ApiKeySecretRef), APIKeyPrefix: deref(i.ApiKeyPrefix), NoiseFingerprint: deref(i.NoiseKeyFingerprint)}
		if i.StunPort != nil {
			out.STUNPort = *i.StunPort
		}
		if i.DerpRegionID != nil {
			out.DERPRegionID = *i.DerpRegionID
		}
		var pe struct {
			IPv4 string `json:"ipv4"`
		}
		if len(row.HostPublicEntry) > 0 && json.Unmarshal(row.HostPublicEntry, &pe) == nil && pe.IPv4 != "" {
			if a, err := netip.ParseAddr(pe.IPv4); err == nil {
				out.PublicEntryIPv4 = a
			}
		}
		return nil
	})
	return out, err
}

// TransitionInstance implements Store.
func (d *DBStore) TransitionInstance(ctx context.Context, tenantID, instanceID uuid.UUID, from []string, to string) (string, error) {
	var found string
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantInstance(ctx, instanceID)
		if err != nil {
			return notFound(err)
		}
		if r.TenantID != tenantID {
			return ErrNotFound
		}
		found = r.Status
		if r.Status == to || !slices.Contains(from, r.Status) {
			return nil
		}
		_, err = q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{Status: to,
			ID: instanceID, TenantID: tenantID, FromStatus: r.Status})
		return err
	})
	return found, err
}

// SetFingerprint implements Store.
func (d *DBStore) SetFingerprint(ctx context.Context, tenantID, instanceID uuid.UUID, fp string) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		return q.SetInstanceNoiseFingerprint(ctx, sqlcdb.SetInstanceNoiseFingerprintParams{Fingerprint: fp, ID: instanceID,
			TenantID: tenantID})
	})
}

// SetRuntime implements Store.
func (d *DBStore) SetRuntime(ctx context.Context, tenantID, instanceID uuid.UUID, version, digest string) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.SetTenantInstanceRuntime(ctx, sqlcdb.SetTenantInstanceRuntimeParams{HeadscaleVersion: version,
			ImageDigest: digest, ID: instanceID, TenantID: tenantID})
		return notFound(err)
	})
}

// RecordConfig implements Store.
func (d *DBStore) RecordConfig(ctx context.Context, tenantID, instanceID uuid.UUID, c ConfigRecord) (uuid.UUID, error) {
	var id uuid.UUID
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		v, err := q.GetInstanceConfigVersionBySHA(ctx, sqlcdb.GetInstanceConfigVersionBySHAParams{TenantID: tenantID,
			InstanceID: instanceID, ConfigSha256: c.ConfigSHA256})
		switch {
		case errors.Is(err, store.ErrNoRows):
			params, err := json.Marshal(c.Params)
			if err != nil {
				return err
			}
			v, err = q.InsertInstanceConfigVersion(ctx, sqlcdb.InsertInstanceConfigVersionParams{TenantID: tenantID,
				InstanceID: instanceID, TemplateVersion: fmt.Sprint(c.TemplateVersion), Params: params,
				RenderedConfig: fmt.Sprintf("rendered by the host agent from typed parameters (template v%d); "+
					"the files on the host are identified by config_sha256", c.TemplateVersion),
				ConfigSha256: c.ConfigSHA256})
			if err != nil {
				return err
			}
		case err != nil:
			return err
		}
		id = v.ID
		var derp *int32
		if c.DERPRegionID > 0 {
			derp = &c.DERPRegionID
		}
		return q.SetInstanceConfigVersion(ctx, sqlcdb.SetInstanceConfigVersionParams{ConfigVersionID: v.ID,
			DerpRegionID: derp, ID: instanceID, TenantID: tenantID})
	})
	return id, err
}

// SetAPIKey implements Store.
func (d *DBStore) SetAPIKey(ctx context.Context, tenantID, instanceID uuid.UUID, ref, prefix string, expires *time.Time) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		p := sqlcdb.SetTenantInstanceAPIKeyParams{ID: instanceID, TenantID: tenantID}
		if ref != "" {
			p.ApiKeySecretRef, p.ApiKeyPrefix, p.ApiKeyExpiresAt = &ref, &prefix, expires
		}
		_, err := q.SetTenantInstanceAPIKey(ctx, p)
		return notFound(err)
	})
}

// IdP implements Store.
func (d *DBStore) IdP(ctx context.Context, tenantID, idpID uuid.UUID) (IdPRecord, bool, error) {
	var (
		out   IdPRecord
		found bool
	)
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetIdentityProvider(ctx, idpID)
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.TenantID == nil || *r.TenantID != tenantID {
			return fmt.Errorf("%w: identity provider %s belongs to another tenant", ErrState, idpID)
		}
		found = true
		out = IdPRecord{ID: r.ID, TenantID: tenantID, Driver: r.Driver, Issuer: r.Issuer, ClientID: r.ClientID,
			ClientSecretRef: deref(r.ClientSecretRef), DriverRef: deref(r.DriverRef), Status: r.Status,
			AllowedEmailDomains: r.AllowedEmailDomains}
		_ = json.Unmarshal(r.RequiredClaims, &out.RequiredClaims)
		return nil
	})
	return out, found, err
}

// SaveIdP implements Store.
func (d *DBStore) SaveIdP(ctx context.Context, r IdPRecord) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		tenant := r.TenantID
		cur, err := q.GetIdentityProvider(ctx, r.ID)
		switch {
		case errors.Is(err, store.ErrNoRows):
			claims, err := json.Marshal(r.RequiredClaims)
			if err != nil || r.RequiredClaims == nil {
				claims = []byte(`{}`)
			}
			domains := r.AllowedEmailDomains
			if domains == nil {
				domains = []string{}
			}
			_, err = q.InsertProvisionIdP(ctx, sqlcdb.InsertProvisionIdPParams{ID: r.ID, TenantID: &tenant, Issuer: r.Issuer,
				ClientID: r.ClientID, ClientSecretRef: optional(r.ClientSecretRef), RequiredClaims: claims,
				AllowedEmailDomains: domains, Driver: r.Driver, DriverRef: optional(r.DriverRef)})
			return err
		case err != nil:
			return err
		}
		if cur.TenantID == nil || *cur.TenantID != r.TenantID || cur.Issuer != r.Issuer || cur.ClientID != r.ClientID ||
			cur.Driver != r.Driver {
			return fmt.Errorf("%w: identity provider %s is registered with other immutable values", ErrState, r.ID)
		}
		if deref(cur.DriverRef) == r.DriverRef && deref(cur.ClientSecretRef) == r.ClientSecretRef {
			return nil
		}
		_, err = q.UpdateProvisionIdP(ctx, sqlcdb.UpdateProvisionIdPParams{DriverRef: optional(r.DriverRef),
			ClientSecretRef: optional(r.ClientSecretRef), ID: r.ID, TenantID: &tenant})
		return err
	})
}

// SetIdPStatus implements Store.
func (d *DBStore) SetIdPStatus(ctx context.Context, tenantID, idpID uuid.UUID, from, to string) (bool, error) {
	var changed bool
	err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		t := tenantID
		_, err := q.TransitionIdentityProviderStatus(ctx, sqlcdb.TransitionIdentityProviderStatusParams{Status: to,
			ID: idpID, TenantID: &t, FromStatus: from})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		changed = err == nil
		return err
	})
	return changed, err
}

// RecordBaselinePolicy implements Store: under the tenant's policy lock (the lock of the policy core — §7.2), in one
// tenant transaction.
func (d *DBStore) RecordBaselinePolicy(ctx context.Context, tenantID, instanceID uuid.UUID, hujson string) error {
	sum := policies.SHA256Hex(hujson)
	return d.st.WithTenantLock(ctx, tenantID, "policy", d.lockWait, func(ctx context.Context) error {
		return d.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			cur, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID,
				InstanceID: instanceID})
			switch {
			case err == nil && cur.AppliedSha256 == sum:
				return nil // recorded by an earlier run
			case err == nil:
				return fmt.Errorf("%w: the instance already has another applied policy", ErrState)
			case !errors.Is(err, store.ErrNoRows):
				return err
			}
			v, err := q.LatestHuJSONPolicyVersion(ctx, sqlcdb.LatestHuJSONPolicyVersionParams{TenantID: tenantID,
				Kind: policies.KindBaseline, ContentSha256: sum})
			if errors.Is(err, store.ErrNoRows) {
				n, err := q.NextPolicyVersionNumber(ctx, tenantID)
				if err != nil {
					return err
				}
				report, _ := json.Marshal(map[string]any{"engine": "p3-t05", "source": "bootstrap-policy.hujson",
					"note": "baseline deny-all set by the agent at step 12 and read back through the API at step 15"})
				text := hujson
				v, err = q.InsertHuJSONPolicyVersion(ctx, sqlcdb.InsertHuJSONPolicyVersionParams{TenantID: tenantID,
					Version: n, Kind: policies.KindBaseline, SourceHujson: &text, ContentSha256: sum, ValidationReport: report})
				if err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			if err := q.SetTenantDesiredPolicy(ctx, sqlcdb.SetTenantDesiredPolicyParams{VersionID: &v.ID, TenantID: tenantID}); err != nil {
				return err
			}
			app, err := q.InsertPolicyApplication(ctx, sqlcdb.InsertPolicyApplicationParams{TenantID: tenantID,
				InstanceID: instanceID, PolicyVersionID: v.ID, Trigger: policies.TriggerBootstrap, InputsSha256: &sum,
				AppliedHujson: hujson, AppliedSha256: sum})
			if err != nil {
				return err
			}
			if _, err := q.SupersedeCurrentPolicyApplication(ctx, sqlcdb.SupersedeCurrentPolicyApplicationParams{
				TenantID: tenantID, InstanceID: instanceID, KeepID: app.ID}); err != nil {
				return err
			}
			_, err = q.FinishPolicyApplication(ctx, sqlcdb.FinishPolicyApplicationParams{State: policies.StateApplied,
				TenantID: tenantID, ID: app.ID})
			return err
		})
	})
}

// Configure implements Store: settings and the IdP in a platform transaction, then the Owner invitation, its audit
// event, its notification and (WithOwnerInvite) the job that creates the Owner's IdP account in one transaction of the
// tenant.
func (d *DBStore) Configure(ctx context.Context, r ConfigureRequest) (uuid.UUID, error) {
	if err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if len(r.Settings) > 0 {
			if err := q.SetTenantSettings(ctx, sqlcdb.SetTenantSettingsParams{Settings: r.Settings, ID: r.TenantID}); err != nil {
				return err
			}
		}
		t := r.TenantID
		_, err := q.TransitionIdentityProviderStatus(ctx, sqlcdb.TransitionIdentityProviderStatusParams{
			Status: tenants.IdPStatusActive, ID: r.IdPID, TenantID: &t, FromStatus: "pending"})
		if errors.Is(err, store.ErrNoRows) {
			cur, err := q.GetIdentityProvider(ctx, r.IdPID)
			if err != nil {
				return notFound(err)
			}
			if cur.Status != tenants.IdPStatusActive {
				return fmt.Errorf("%w: identity provider %s is %s", ErrState, r.IdPID, cur.Status)
			}
			return nil
		}
		return err
	}); err != nil {
		return uuid.Nil, err
	}
	var invitation uuid.UUID
	now := d.now()
	err := d.st.WithTenantJobTx(ctx, r.TenantID, func(tx *store.Tx) error {
		q := tx.Q
		n, err := q.CountMembersWithEmail(ctx, sqlcdb.CountMembersWithEmailParams{TenantID: r.TenantID, Email: r.OwnerEmail})
		if err != nil {
			return err
		}
		if n > 0 {
			return nil // the Owner signed in already (a re-run after the invitation was accepted)
		}
		prev, err := q.LockPendingInvitationByEmail(ctx, sqlcdb.LockPendingInvitationByEmailParams{TenantID: r.TenantID,
			Email: r.OwnerEmail})
		switch {
		case err == nil && now.Before(prev.ExpiresAt):
			invitation = prev.ID // created by an earlier run
			return nil
		case err == nil:
			if err := q.ExpireInvitation(ctx, sqlcdb.ExpireInvitationParams{Now: now, TenantID: r.TenantID, ID: prev.ID}); err != nil {
				return err
			}
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		role, err := q.GetRoleByScopeKey(ctx, sqlcdb.GetRoleByScopeKeyParams{Scope: "tenant", Key: RoleTenantOwner})
		if err != nil {
			return err
		}
		raw := make([]byte, 32) // the binding is by IdP + verified e-mail at the first login (P3-T05a): the token is
		if _, err := rand.Read(raw); err != nil {
			return err // never sent anywhere; only its hash is stored (column NOT NULL, UNIQUE)
		}
		hash := sha256.Sum256(raw)
		clear(raw)
		row, err := q.InsertInvitation(ctx, sqlcdb.InsertInvitationParams{TenantID: r.TenantID, IdpID: r.IdPID,
			Email: r.OwnerEmail, RoleID: role.ID, TokenHash: hash[:], ExpiresAt: now.Add(tenants.DefaultInvitationTTL), Now: now})
		if err != nil {
			return err
		}
		invitation = row.ID
		tid := r.TenantID
		if err := audit.Record(ctx, q, audit.Event{Action: tenants.ActionInvitationCreate, TenantID: &tid,
			ActorType: audit.ActorSystem, ResourceType: "invitation", ResourceID: row.ID.String(),
			Details: audit.Details{"invitation_id": row.ID, "email": row.Email, "role": RoleTenantOwner,
				"idp_id": r.IdPID, "expires_at": row.ExpiresAt, "source": JobKind}}); err != nil {
			return err
		}
		if _, err := d.notify.Enqueue(ctx, tx, notifications.Invitation(r.TenantID, row.ID, row.Email, RoleTenantOwner,
			row.ExpiresAt, "")); err != nil {
			return err
		}
		if d.invites == nil {
			return nil
		}
		// G4b-E1: the Owner's IdP account (member.idp_invite; deduplicated per invitation — a re-run that finds the
		// invitation above returns before this point, and the job of a committed invitation already exists)
		return d.invites.InvitationIssued(ctx, tx, tenants.InvitationNotice{TenantID: r.TenantID, InvitationID: row.ID,
			Email: row.Email, Role: RoleTenantOwner, ExpiresAt: row.ExpiresAt})
	})
	return invitation, err
}

// RoleTenantOwner is the role of the invitation of step 16 (§8.4: the only Owner invitation is the orchestrator's).
const RoleTenantOwner = "tenant_owner"

// RevokeInvitation implements Store (a revoked or accepted invitation is left alone).
func (d *DBStore) RevokeInvitation(ctx context.Context, tenantID, invitationID uuid.UUID) error {
	return d.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		_, err := q.RevokeInvitation(ctx, sqlcdb.RevokeInvitationParams{Now: d.now(), TenantID: tenantID, ID: invitationID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		return err
	})
}

// RevokePendingInvitation implements Store.
func (d *DBStore) RevokePendingInvitation(ctx context.Context, tenantID uuid.UUID, email string) error {
	return d.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		inv, err := q.LockPendingInvitationByEmail(ctx, sqlcdb.LockPendingInvitationByEmailParams{TenantID: tenantID, Email: email})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = q.RevokeInvitation(ctx, sqlcdb.RevokeInvitationParams{Now: d.now(), TenantID: tenantID, ID: inv.ID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		return err
	})
}

// AssignRelay implements Store.
func (d *DBStore) AssignRelay(ctx context.Context, r RelayRequest) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		t, host := r.TenantID, r.HostID
		p := sqlcdb.UpsertEmbeddedRelayRegionParams{TenantID: &t, Code: r.Code, Name: r.Name, DerpRegionID: r.DERPRegionID,
			Hostname: r.Hostname, HostID: &host}
		if r.IPv4.IsValid() {
			a := r.IPv4
			p.Ipv4 = &a
		}
		if r.STUNPort > 0 {
			sp := r.STUNPort
			p.StunPort = &sp
		}
		region, err := q.UpsertEmbeddedRelayRegion(ctx, p)
		if err != nil {
			return err
		}
		_, err = q.UpsertRelayAssignment(ctx, sqlcdb.UpsertRelayAssignmentParams{TenantID: r.TenantID,
			InstanceID: r.InstanceID, RelayRegionID: region.ID})
		return err
	})
}

// RemoveRelay implements Store: the assignment, then the region when no other assignment uses it.
func (d *DBStore) RemoveRelay(ctx context.Context, tenantID, instanceID uuid.UUID, code string) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		region, err := q.GetTenantRelayRegionByCode(ctx, sqlcdb.GetTenantRelayRegionByCodeParams{TenantID: tenantID, Code: code})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := q.DeleteRelayAssignment(ctx, sqlcdb.DeleteRelayAssignmentParams{TenantID: tenantID,
			InstanceID: instanceID, RelayRegionID: region.ID}); err != nil {
			return err
		}
		_, err = q.DeleteRelayRegion(ctx, sqlcdb.DeleteRelayRegionParams{TenantID: tenantID, ID: region.ID})
		return err
	})
}

// Activate implements Store: one platform transaction moves instance and tenant and closes the audit operation (only
// the run that made the change writes the event), then the notification in a transaction of the tenant (deduplicated
// by its ref, so a re-run never notifies twice).
func (d *DBStore) Activate(ctx context.Context, r ActivateRequest) error {
	if err := d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.GetTenantInstance(ctx, r.InstanceID)
		if err != nil {
			return notFound(err)
		}
		changed := false
		switch inst.Status {
		case tenants.InstanceRunning:
		case tenants.InstanceStarting:
			if _, err := q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{
				Status: tenants.InstanceRunning, ID: r.InstanceID, TenantID: r.TenantID, FromStatus: inst.Status}); err != nil {
				return err
			}
			changed = true
		default:
			return fmt.Errorf("%w: instance %s is %s", ErrState, r.InstanceID, inst.Status)
		}
		t, err := q.GetTenant(ctx, r.TenantID)
		if err != nil {
			return notFound(err)
		}
		switch t.Status {
		case tenants.StatusActive:
		case tenants.StatusProvisioning:
			if _, err := q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: tenants.StatusActive,
				ID: r.TenantID, FromStatus: tenants.StatusProvisioning}); err != nil {
				return err
			}
			changed = true
		default:
			return fmt.Errorf("%w: tenant %s is %s", ErrState, r.TenantID, t.Status)
		}
		if !changed || r.Operation.ID == uuid.Nil {
			return nil
		}
		return r.Operation.Succeeded(ctx, q, r.Details)
	}); err != nil {
		return err
	}
	return d.st.WithTenantJobTx(ctx, r.TenantID, func(tx *store.Tx) error {
		var emails []string
		if r.OwnerEmail != "" {
			emails = []string{r.OwnerEmail}
		}
		_, err := d.notify.Enqueue(ctx, tx, notifications.TenantActivated(r.TenantID, emails...))
		return err
	})
}

// WithAPIKeyLock implements Store.
func (d *DBStore) WithAPIKeyLock(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error {
	return d.st.WithTenantLock(ctx, tenantID, APIKeyLockName, d.lockWait, fn)
}

// Fail implements Store.
func (d *DBStore) Fail(ctx context.Context, tenantID uuid.UUID, op audit.Operation, reason string, details audit.Details) error {
	return d.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: tenants.StatusFailed,
			ID: tenantID, FromStatus: tenants.StatusProvisioning})
		if errors.Is(err, store.ErrNoRows) {
			return nil // already failed (a compensation that ran again) — its event was written then
		}
		if err != nil || op.ID == uuid.Nil {
			return err
		}
		return op.Failed(ctx, q, reason, details)
	})
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
