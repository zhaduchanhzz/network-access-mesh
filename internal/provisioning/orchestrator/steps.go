package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// BaselineSHA256 is the sha256 of the baseline deny-all policy the agent sets at step 12 (bootstrap-policy.hujson,
// embedded in the agent from the same source).
var BaselineSHA256 = func() string {
	s := sha256.Sum256([]byte(templates.BootstrapPolicy))
	return hex.EncodeToString(s[:])
}()

// ---------------------------------------------------------------------------------------------------- 3 placement.allocate

func (p *Provisioner) stepPlacement(ctx context.Context, a *attempt, s stepCtx) error {
	var res placementResources
	found, err := s.Previous(&res)
	if err != nil {
		return err
	}
	if !found || res.InstanceID == uuid.Nil {
		// The instance ID is chosen BEFORE the allocation and recorded: a retry allocates the same instance (P3-T04).
		res.InstanceID = uuid.New()
		if err := record(ctx, s, res); err != nil {
			return err
		}
	}
	alloc, err := p.cfg.Placer.Allocate(ctx, platform.AllocationRequest{TenantID: a.in.TenantID, InstanceID: res.InstanceID,
		HeadscaleVersion: p.cfg.HeadscaleVersion, ImageDigest: p.cfg.HeadscaleDigest})
	switch {
	case errors.Is(err, platform.ErrNoCapacity):
		// An operational condition (no host with a public entry, full, pools exhausted): the operator fixes the hosts
		// and /retry — or /rollback. Retrying in place would not help.
		return jobs.Resumable("no_capacity", err)
	case errors.Is(err, platform.ErrConflict), errors.Is(err, platform.ErrInvalid), errors.Is(err, platform.ErrNotFound):
		return jobs.Permanent("placement_refused", err)
	case err != nil:
		return jobs.Transient("registry_unavailable", fmt.Errorf("placement: %w", err))
	}
	return detail(s, map[string]any{"instance_id": alloc.InstanceID, "host": alloc.HostName, "run_uid": alloc.RunUID,
		"net_cidr": alloc.NetCIDR.String(), "control_hostname": alloc.ControlHostname, "existing": alloc.Existing})
}

// ---------------------------------------------------------------------------------------------------- 4 dns.ensure

func (p *Provisioner) stepDNS(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	if p.cfg.DNS == nil {
		return detail(s, map[string]any{"mode": "skipped", "hostname": inst.ControlHostname})
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	res, err := p.cfg.DNS.Check(cctx, inst.ControlHostname, inst.PublicEntryIPv4)
	addrs := make([]string, 0, len(res.Addresses))
	for _, x := range res.Addresses {
		addrs = append(addrs, x.String())
	}
	if derr := detail(s, map[string]any{"mode": "wildcard", "hostname": inst.ControlHostname,
		"want": inst.PublicEntryIPv4.String(), "resolved": addrs}); derr != nil {
		return derr
	}
	switch {
	case err != nil:
		return jobs.Transient("dns_unresolved", fmt.Errorf("resolve %s: %w", inst.ControlHostname, err))
	case !res.OK:
		return jobs.Transient("dns_mismatch", fmt.Errorf("%s does not resolve to the public entry %s",
			inst.ControlHostname, inst.PublicEntryIPv4))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 5 secrets.generate

func (p *Provisioner) stepSecrets(ctx context.Context, a *attempt, s stepCtx) error {
	v, err := p.cfg.Secrets.EnsureDEK(ctx, secrets.TenantOwner(a.in.TenantID))
	if err != nil {
		if errors.Is(err, secrets.ErrKeyDestroyed) {
			return jobs.Permanent("tenant_keys_destroyed", err)
		}
		return jobs.Transient("secret_store_unavailable", fmt.Errorf("ensure the tenant DEK: %w", err))
	}
	return detail(s, map[string]any{"dek_version": v})
}

// ---------------------------------------------------------------------------------------------------- 6 idp.ensure

// idpResources is created_resources of step 6.
type idpResources struct {
	IdPID  uuid.UUID `json:"idp_id"`
	Driver string    `json:"driver"`
	Realm  string    `json:"realm,omitempty"`
}

func (p *Provisioner) stepIdP(ctx context.Context, a *attempt, s stepCtx) error {
	in := a.in.IdP
	drv, err := p.cfg.IdP.Driver(in.Driver)
	if err != nil {
		return jobs.Permanent("idp_unknown_driver", err)
	}
	cur, exists, err := p.cfg.Store.IdP(ctx, a.in.TenantID, in.ID)
	if err != nil {
		return storeErr("load the identity provider", err)
	}
	res := idpResources{IdPID: in.ID, Driver: in.Driver}
	reg := idp.Registration{IdPID: in.ID, Scope: idp.ScopeTenant, TenantID: a.in.TenantID, Driver: in.Driver,
		Issuer: in.Issuer, ClientID: in.ClientID}
	if exists {
		reg.Issuer, reg.ClientID, reg.DriverRef, reg.ClientSecretRef = cur.Issuer, cur.ClientID, cur.DriverRef, cur.ClientSecretRef
		switch {
		case cur.Status == "disabled" && a.in.RetryOf != nil:
			// /retry after a rollback: the compensation of the job it replaces disabled this IdP (same id — the realm
			// carries it); provisioning again re-enables it (EnsureIssuer below enables the realm again).
			if _, err := p.cfg.Store.SetIdPStatus(ctx, a.in.TenantID, in.ID, "disabled", "pending"); err != nil {
				return storeErr("re-enable the identity provider", err)
			}
		case cur.Status != "pending" && cur.Status != tenants.IdPStatusActive:
			return jobs.Permanent("registry_state", fmt.Errorf("identity provider %s is %s", in.ID, cur.Status))
		}
	}
	if in.Driver == DriverKeycloak {
		res.Realm = a.in.Slug
		reg.ClientID = provisioning.PortalClientID
	}
	if err := record(ctx, s, res); err != nil {
		return err
	}
	if in.Driver == DriverExternal && reg.ClientSecretRef == "" && in.PendingSecretRef != "" {
		ref, err := p.adoptPendingSecret(ctx, a, in)
		if err != nil {
			return err
		}
		reg.ClientSecretRef = ref
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	ir, err := drv.EnsureIssuer(cctx, idp.IssuerSpec{Registration: reg, Realm: res.Realm, DisplayName: a.tenant.Name})
	if err != nil {
		return idpErr("EnsureIssuer", err)
	}
	reg.Issuer, reg.DriverRef = ir.Issuer, ir.DriverRef
	cr, err := drv.EnsureClient(cctx, idp.ClientSpec{Registration: reg})
	if err != nil {
		return idpErr("EnsureClient", err)
	}
	reg.ClientID, reg.ClientSecretRef = cr.ClientID, cr.ClientSecretRef
	if err := p.cfg.Store.SaveIdP(ctx, IdPRecord{ID: in.ID, TenantID: a.in.TenantID, Driver: in.Driver, Issuer: reg.Issuer,
		ClientID: reg.ClientID, ClientSecretRef: reg.ClientSecretRef, DriverRef: reg.DriverRef,
		RequiredClaims: in.RequiredClaims, AllowedEmailDomains: in.AllowedEmailDomains}); err != nil {
		return storeErr("record the identity provider", err)
	}
	return detail(s, map[string]any{"idp_id": in.ID, "driver": in.Driver, "issuer": reg.Issuer, "client_id": reg.ClientID,
		"issuer_created": ir.Created, "client_created": cr.Created, "changes": len(ir.Changes) + len(cr.Changes)})
}

// adoptPendingSecret moves the external IdP's client secret from the pending platform secret the API stored to the
// tenant's own reference mgsec://<tenant>/idp.<id>.client#n (tenant DEK), then destroys the pending copy.
func (p *Provisioner) adoptPendingSecret(ctx context.Context, a *attempt, in IdPInput) (string, error) {
	pending, err := secrets.ParseRef(in.PendingSecretRef)
	if err != nil || !pending.IsPlatform() || pending.Name != PendingClientSecretName(in.ID) {
		return "", jobs.Permanent("invalid_input", errors.New("the pending client secret reference is not this IdP's"))
	}
	name := idp.ClientSecretName(in.ID)
	latest, err := p.cfg.Secrets.Latest(ctx, a.in.TenantID, name)
	if err == nil {
		_ = p.cfg.Secrets.Destroy(ctx, pending)
		return latest.String(), nil // moved by an earlier run
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		return "", jobs.Transient("secret_store_unavailable", err)
	}
	pt, err := p.cfg.Secrets.Get(ctx, pending)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) || errors.Is(err, secrets.ErrExpired) || errors.Is(err, secrets.ErrDestroyed) {
			return "", jobs.Permanent("idp_client_secret_missing", errors.New("the pending client secret is gone"))
		}
		return "", jobs.Transient("secret_store_unavailable", err)
	}
	value := pt.Bytes()
	defer clear(value)
	ref := secrets.TenantRef(a.in.TenantID, name, 1)
	if err := p.cfg.Secrets.Put(ctx, ref, value); err != nil && !errors.Is(err, secrets.ErrExists) {
		return "", jobs.Transient("secret_store_unavailable", err)
	}
	if err := p.cfg.Secrets.Destroy(ctx, pending); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		p.cfg.Logger.Warn("tenant.provision: the pending client secret could not be destroyed (it expires)", "ref", pending.String())
	}
	return ref.String(), nil
}

// PendingClientSecretName is the platform secret under which the API keeps an external IdP's client secret until step
// 6 moves it under the tenant's DEK (the tenant row does not exist yet when the API receives it).
func PendingClientSecretName(idpID uuid.UUID) string {
	return "idp-pending." + idpID.String() + ".client"
}

// ---------------------------------------------------------------------------------------------------- 7–10 agent phases

// agentResources is created_resources of steps 7, 9, 10: what the agent derives from the slug and instance id.
type agentResources struct {
	InstanceID uuid.UUID `json:"instance_id"`
	Object     string    `json:"object"`
}

func (p *Provisioner) ensurePhase(ctx context.Context, a *attempt, s stepCtx, phase agentv1.TargetPhase,
	object string) (*agentv1.EnsureInstanceResponse, InstanceRecord, error) {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return nil, inst, err
	}
	spec, err := p.instanceSpec(a, inst)
	if err != nil {
		return nil, inst, err
	}
	if object != "" {
		if err := record(ctx, s, agentResources{InstanceID: inst.ID, Object: object}); err != nil {
			return nil, inst, err
		}
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	resp, err := p.cfg.Agent.EnsureInstance(cctx, &agentv1.EnsureInstanceRequest{Spec: spec, TargetPhase: phase,
		JobId: a.r.JobID().String()})
	if err != nil {
		return nil, inst, agentErr("EnsureInstance("+phase.String()+")", err)
	}
	return resp, inst, nil
}

func (p *Provisioner) stepStorage(ctx context.Context, a *attempt, s stepCtx) error {
	_, inst, err := p.ensurePhase(ctx, a, s, agentv1.TargetPhase_TARGET_PHASE_STORAGE, "instance_directory")
	if err != nil {
		p.recordStartGuard(ctx, a, StepStorage, err)
		return err
	}
	return detail(s, map[string]any{"instance_id": inst.ID, "run_uid": inst.RunUID})
}

func (p *Provisioner) stepConfig(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	spec, err := p.instanceSpec(a, inst)
	if err != nil {
		return err
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	v, err := p.cfg.Agent.ValidateConfig(cctx, &agentv1.ValidateConfigRequest{Spec: spec, JobId: a.r.JobID().String()})
	if err != nil {
		return agentErr("ValidateConfig", err)
	}
	if !v.GetValid() {
		_ = detail(s, map[string]any{"valid": false, "exit_code": v.GetExitCode(), "configtest": v.GetDetail()})
		return jobs.Permanent("config_invalid", fmt.Errorf("headscale configtest refused the rendered configuration (exit %d)",
			v.GetExitCode()))
	}
	resp, err := p.cfg.Agent.EnsureInstance(cctx, &agentv1.EnsureInstanceRequest{Spec: spec,
		TargetPhase: agentv1.TargetPhase_TARGET_PHASE_CONFIG, JobId: a.r.JobID().String()})
	if err != nil {
		return agentErr("EnsureInstance(config)", err)
	}
	if resp.GetConfigSha256() != v.GetConfigSha256() || !hexRE.MatchString(resp.GetConfigSha256()) {
		return jobs.Permanent("config_hash_mismatch", errors.New("the configuration written differs from the one validated"))
	}
	id, err := p.cfg.Store.RecordConfig(ctx, a.in.TenantID, inst.ID, ConfigRecord{TemplateVersion: resp.GetTemplateVersion(),
		ConfigSHA256: resp.GetConfigSha256(), DERPRegionID: p.derpRegion(inst), Params: specParams(spec)})
	if err != nil {
		return storeErr("record the configuration version", err)
	}
	return detail(s, map[string]any{"valid": true, "config_sha256": resp.GetConfigSha256(),
		"template_version": resp.GetTemplateVersion(), "config_version_id": id})
}

func (p *Provisioner) stepNetwork(ctx context.Context, a *attempt, s stepCtx) error {
	resp, _, err := p.ensurePhase(ctx, a, s, agentv1.TargetPhase_TARGET_PHASE_NETWORK, "tenant_network")
	if err != nil {
		return err
	}
	n := resp.GetStatus().GetNetwork()
	return detail(s, map[string]any{"subnet": n.GetSubnet(), "internal": n.GetInternal(), "edge_attached": n.GetEdgeAttached()})
}

func (p *Provisioner) stepStart(ctx context.Context, a *attempt, s stepCtx) error {
	id, err := a.instanceID(ctx)
	if err != nil {
		return err
	}
	if err := record(ctx, s, agentResources{InstanceID: id, Object: "container"}); err != nil {
		return err
	}
	// starting: steps 10–18 (§13.3) — set before the container exists, so a crash leaves the registry truthful.
	if _, err := p.cfg.Store.TransitionInstance(ctx, a.in.TenantID, id, []string{tenants.InstanceAllocated},
		tenants.InstanceStarting); err != nil {
		return storeErr("mark the instance starting", err)
	}
	resp, _, err := p.ensurePhase(ctx, a, s, agentv1.TargetPhase_TARGET_PHASE_CONTAINER, "container")
	if err != nil {
		p.recordStartGuard(ctx, a, StepStart, err)
		return err
	}
	st := resp.GetStatus()
	return detail(s, map[string]any{"container_state": st.GetContainerState().String(), "image_digest": st.GetImageDigest()})
}

// ---------------------------------------------------------------------------------------------------- 11 wait_healthy

func (p *Provisioner) stepWaitHealthy(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	ref := &agentv1.InstanceRef{InstanceId: inst.ID.String(), TenantId: inst.TenantID.String(), Slug: a.in.Slug}
	deadline := p.cfg.Now().Add(p.cfg.HealthTimeout)
	var last *agentv1.InstanceStatus
	for {
		cctx, cancel := p.call(ctx)
		resp, err := p.cfg.Agent.GetInstanceStatus(cctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
		cancel()
		if err != nil {
			return agentErr("GetInstanceStatus", err)
		}
		last = resp.GetStatus()
		if last.GetContainerState() == agentv1.ContainerState_CONTAINER_STATE_RUNNING &&
			last.GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY {
			break
		}
		if !p.cfg.Now().Before(deadline) {
			_ = detail(s, map[string]any{"container_state": last.GetContainerState().String(),
				"health": last.GetHealth().String(), "waited_s": p.cfg.HealthTimeout.Seconds()})
			// §11.3 step 11: not healthy within 90 s ⇒ the step fails (and the job compensates — §11.2).
			return jobs.Permanent("instance_unhealthy", fmt.Errorf("instance not healthy after %s (%s, %s)",
				p.cfg.HealthTimeout, last.GetContainerState(), last.GetHealth()))
		}
		t := time.NewTimer(p.cfg.HealthPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	fp := last.GetNoiseKeyFingerprint()
	if !hexRE.MatchString(fp) {
		// The helper container computing it failed (the agent then reports it empty): try again.
		return jobs.Transient("fingerprint_unavailable", errors.New("the agent reported no Noise key fingerprint"))
	}
	if err := p.cfg.Store.SetFingerprint(ctx, a.in.TenantID, inst.ID, fp); err != nil {
		return storeErr("record the Noise key fingerprint", err)
	}
	return detail(s, map[string]any{"health": last.GetHealth().String(), "noise_key_fingerprint": fp})
}

// ---------------------------------------------------------------------------------------------------- 12 policy.bootstrap

func (p *Provisioner) stepPolicyBootstrap(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	resp, err := p.cfg.Agent.BootstrapPolicy(cctx, &agentv1.BootstrapPolicyRequest{Instance: instRef(a, inst),
		JobId: a.r.JobID().String(), Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL})
	if err != nil {
		p.recordStartGuard(ctx, a, StepPolicyBoot, err)
		return agentErr("BootstrapPolicy", err)
	}
	if resp.GetPolicySha256() != BaselineSHA256 {
		return jobs.Permanent("policy_mismatch", errors.New("the policy read back is not the baseline deny-all"))
	}
	return detail(s, map[string]any{"policy_sha256": resp.GetPolicySha256()})
}

func instRef(a *attempt, inst InstanceRecord) *agentv1.InstanceRef {
	return &agentv1.InstanceRef{InstanceId: inst.ID.String(), TenantId: inst.TenantID.String(), Slug: a.in.Slug}
}

// ---------------------------------------------------------------------------------------------------- 13 apikey.bootstrap

// apiKeyResources is created_resources of step 13: the secret versions this job may create — never the key.
type apiKeyResources struct {
	SecretName string `json:"secret_name"`
	FromRef    string `json:"from_ref,omitempty"` // the latest version before the step ("" = none)
	Ref        string `json:"ref,omitempty"`      // the version this job stored
	Prefix     string `json:"prefix,omitempty"`   // public prefix of the key
}

// stepAPIKey runs under the tenant's API-key lock (APIKeyLockName — the lock of the rotation job of P3-T10 and of the
// reconcile key check): no two operations ever bootstrap, rotate or expire the keys of one instance at once.
func (p *Provisioner) stepAPIKey(ctx context.Context, a *attempt, s stepCtx) error {
	return p.underAPIKeyLock(ctx, a, func(ctx context.Context) error { return p.stepAPIKeyLocked(ctx, a, s) })
}

// underAPIKeyLock: fn's own error as it is; a failure to take the lock is transient.
func (p *Provisioner) underAPIKeyLock(ctx context.Context, a *attempt, fn func(ctx context.Context) error) error {
	var inner error
	err := p.cfg.Store.WithAPIKeyLock(ctx, a.in.TenantID, func(ctx context.Context) error {
		inner = fn(ctx)
		return inner
	})
	switch {
	case inner != nil:
		return inner
	case err != nil:
		return jobs.Transient("apikey_lock", fmt.Errorf("lock %s: %w", APIKeyLockName, err))
	}
	return nil
}

func (p *Provisioner) stepAPIKeyLocked(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	res := apiKeyResources{SecretName: provisioning.APIKeySecretName}
	var prev apiKeyResources
	if found, err := s.Previous(&prev); err != nil {
		return err
	} else if found {
		res = prev // keep what an earlier attempt recorded (its stored version too)
	} else {
		latest, err := p.cfg.Secrets.Latest(ctx, a.in.TenantID, provisioning.APIKeySecretName)
		switch {
		case err == nil:
			res.FromRef = latest.String()
		case !errors.Is(err, secrets.ErrNotFound):
			return jobs.Transient("secret_store_unavailable", err)
		}
	}
	if err := record(ctx, s, res); err != nil {
		return err
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	// keep_prefix = the key the registry holds: the agent expires every other valid key first — also a key created by
	// an earlier attempt that died before storing it — and keeps the registered one if still valid.
	resp, err := p.cfg.Agent.BootstrapApiKey(cctx, &agentv1.BootstrapApiKeyRequest{Instance: instRef(a, inst),
		JobId: a.r.JobID().String(), Ttl: durationpb.New(p.cfg.APIKeyTTL), KeepPrefix: inst.APIKeyPrefix})
	if err != nil {
		p.recordStartGuard(ctx, a, StepAPIKey, err)
		return agentErr("BootstrapApiKey", err)
	}
	key := resp.GetApiKey()
	resp.ApiKey = "" // the response is never logged; drop the only copy we do not need
	if !resp.GetCreated() {
		if inst.APIKeyRef == "" || resp.GetPrefix() != inst.APIKeyPrefix {
			return jobs.Permanent("apikey_state", errors.New("the agent kept a key the registry does not reference"))
		}
		return detail(s, map[string]any{"created": false, "prefix": resp.GetPrefix(), "expired_keys": resp.GetExpiredKeys()})
	}
	if !provisioning.ValidAPIKey(key) {
		return jobs.Permanent("apikey_invalid", errors.New("the agent returned a value that is not a Headscale API key"))
	}
	prefix := headscale.APIKeyPrefix(headscale.NewSecret(key))
	ref, err := p.storeKey(ctx, a.in.TenantID, key)
	if err != nil {
		return jobs.Transient("secret_store_unavailable", fmt.Errorf("store the API key: %w", err))
	}
	res.Ref, res.Prefix = ref.String(), prefix
	if err := record(ctx, s, res); err != nil {
		return err
	}
	var exp *time.Time
	if t := resp.GetExpiresAt(); t.IsValid() {
		e := t.AsTime().UTC()
		exp = &e
	}
	if err := p.cfg.Store.SetAPIKey(ctx, a.in.TenantID, inst.ID, ref.String(), prefix, exp); err != nil {
		return storeErr("record the API key reference", err)
	}
	// Older versions hold keys the agent just expired: erase them.
	for v := int32(1); v < ref.Version; v++ {
		old := secrets.TenantRef(a.in.TenantID, provisioning.APIKeySecretName, v)
		if err := p.cfg.Secrets.Destroy(ctx, old); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			p.cfg.Logger.Warn("tenant.provision: an older API key version was not destroyed", "ref", old.String())
		}
	}
	d := map[string]any{"created": true, "prefix": prefix, "ref_version": ref.Version, "expired_keys": resp.GetExpiredKeys()}
	if exp != nil {
		d["expires_at"] = exp.Format(time.RFC3339)
	}
	return detail(s, d)
}

// storeKey stores the key as version 1, or as the version after the latest one (also after a run that stored a
// version and died before recording it). The value never leaves this function except into the SecretStore.
func (p *Provisioner) storeKey(ctx context.Context, tenantID uuid.UUID, key string) (secrets.Ref, error) {
	value := []byte(key)
	defer clear(value)
	latest, err := p.cfg.Secrets.Latest(ctx, tenantID, provisioning.APIKeySecretName)
	if errors.Is(err, secrets.ErrNotFound) {
		ref := secrets.TenantRef(tenantID, provisioning.APIKeySecretName, 1)
		return ref, p.cfg.Secrets.Put(ctx, ref, value)
	}
	if err != nil {
		return secrets.Ref{}, err
	}
	return p.cfg.Secrets.Rotate(ctx, latest, value)
}

// ---------------------------------------------------------------------------------------------------- 14 edge.attach

type edgeResources struct {
	EdgeAttach  bool      `json:"edge_attach"`
	ActivatedBy uuid.UUID `json:"activated_by"` // meta/activated carries this job id (§11.3 step 14)
}

func (p *Provisioner) stepEdgeAttach(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	if err := record(ctx, s, edgeResources{EdgeAttach: true, ActivatedBy: a.r.JobID()}); err != nil {
		return err
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	resp, err := p.cfg.Agent.EnsureEdgeAttachment(cctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: instRef(a, inst),
		JobId: a.r.JobID().String()})
	if err != nil {
		p.recordStartGuard(ctx, a, StepEdgeAttach, err)
		return agentErr("EnsureEdgeAttachment", err)
	}
	return detail(s, map[string]any{"attached": resp.GetAttached(), "already_attached": resp.GetAlreadyAttached(),
		"network_members": resp.GetNetworkMembers()})
}

// ---------------------------------------------------------------------------------------------------- 15 policy.verify

func (p *Provisioner) stepPolicyVerify(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	hs, err := p.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return headscaleErr("ForTenant", err)
	}
	pol, err := hs.GetPolicy(cctx)
	if err != nil {
		if errors.Is(err, headscale.ErrNoPolicy) {
			return jobs.Permanent("no_policy", errors.New("the instance has no policy (allow-all) after step 12"))
		}
		return headscaleErr("GetPolicy", err)
	}
	sum := sha256.Sum256([]byte(pol.Data))
	got := hex.EncodeToString(sum[:])
	if got != BaselineSHA256 {
		_ = detail(s, map[string]any{"policy_sha256": got, "want_sha256": BaselineSHA256})
		return jobs.Permanent("policy_mismatch", errors.New("the policy read through the API is not the baseline"))
	}
	version, err := hs.Version(cctx)
	if err != nil {
		return headscaleErr("Version", err)
	}
	if version != "" && version != inst.HeadscaleVersion {
		if err := p.cfg.Store.SetRuntime(ctx, a.in.TenantID, inst.ID, version, inst.ImageDigest); err != nil {
			return storeErr("record the Headscale version", err)
		}
	}
	if err := p.cfg.Store.RecordBaselinePolicy(ctx, a.in.TenantID, inst.ID, templates.BootstrapPolicy); err != nil {
		return storeErr("record the baseline policy", err)
	}
	return detail(s, map[string]any{"policy_sha256": got, "headscale_version": version})
}

// ---------------------------------------------------------------------------------------------------- 16 tenant.configure

type configureResources struct {
	OwnerEmail   string    `json:"owner_email"`
	InvitationID uuid.UUID `json:"invitation_id,omitzero"`
}

func (p *Provisioner) stepConfigure(ctx context.Context, a *attempt, s stepCtx) error {
	res := configureResources{OwnerEmail: a.in.OwnerEmail}
	if err := record(ctx, s, res); err != nil {
		return err
	}
	inv, err := p.cfg.Store.Configure(ctx, ConfigureRequest{TenantID: a.in.TenantID, IdPID: a.in.IdP.ID,
		Settings: rawJSON(a.in.Settings), OwnerEmail: a.in.OwnerEmail})
	if err != nil {
		return storeErr("configure the tenant", err)
	}
	res.InvitationID = inv
	if err := record(ctx, s, res); err != nil {
		return err
	}
	return detail(s, map[string]any{"invitation_id": inv, "settings": len(rawJSON(a.in.Settings)) > 0})
}

// ---------------------------------------------------------------------------------------------------- 17 relay.assign

type relayResources struct {
	Code       string    `json:"code"`
	InstanceID uuid.UUID `json:"instance_id"`
}

func relayCode(slug string) string { return "mg-" + slug }

func (p *Provisioner) stepRelay(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	code := relayCode(a.in.Slug)
	if err := record(ctx, s, relayResources{Code: code, InstanceID: inst.ID}); err != nil {
		return err
	}
	if err := p.cfg.Store.AssignRelay(ctx, RelayRequest{TenantID: a.in.TenantID, InstanceID: inst.ID, HostID: inst.HostID,
		Code: code, Name: "MeshGuard " + a.in.Slug, Hostname: inst.ControlHostname, DERPRegionID: p.derpRegion(inst),
		IPv4: inst.PublicEntryIPv4, STUNPort: int32(p.cfg.STUNPort)}); err != nil {
		return storeErr("assign the relay", err)
	}
	if p.cfg.Prober == nil {
		return jobs.Resumable("prober_not_configured", errors.New("no prober configured (MG_PROBER_URL): the relay cannot be verified"))
	}
	stun := netip.AddrPortFrom(inst.PublicEntryIPv4, p.cfg.STUNPort).String()
	cctx, cancel := p.call(ctx)
	defer cancel()
	r, err := p.cfg.Prober.Relay(cctx, RelayProbe{Address: p.cfg.EdgeAddress, Host: inst.ControlHostname, STUN: stun})
	if err != nil {
		return jobs.Transient("prober_unavailable", fmt.Errorf("relay probe: %w", err))
	}
	if derr := detail(s, map[string]any{"code": code, "derp_region_id": p.derpRegion(inst), "stun": stun, "probe": r}); derr != nil {
		return derr
	}
	if !r.OK {
		return jobs.Transient("relay_probe_failed", errors.New("the DERP probe or the shared STUN did not answer as expected"))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 18 edge.verify

func (p *Provisioner) stepEdgeVerify(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	if !hexRE.MatchString(inst.NoiseFingerprint) {
		return jobs.Permanent("registry_state", errors.New("no Noise key fingerprint recorded at step 11"))
	}
	if p.cfg.Prober == nil {
		return jobs.Resumable("prober_not_configured", errors.New("no prober configured (MG_PROBER_URL): the edge cannot be verified"))
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	r, err := p.cfg.Prober.Edge(cctx, EdgeProbe{Address: p.cfg.EdgeAddress, Host: inst.ControlHostname,
		PublicKey: "mkey:" + inst.NoiseFingerprint})
	if err != nil {
		return jobs.Transient("prober_unavailable", fmt.Errorf("edge probe: %w", err))
	}
	if derr := detail(s, map[string]any{"probe": r}); derr != nil {
		return derr
	}
	switch {
	case len(r.Exposed) > 0:
		// The edge answers a path it must hide on the public listener (§14.6): a security failure — compensate.
		return jobs.Permanent("edge_exposes_paths", fmt.Errorf("the public listener answers %d forbidden path(s)", len(r.Exposed)))
	case r.KeyMismatch:
		return jobs.Permanent("edge_key_mismatch", errors.New("/key answers another Noise key than the instance's"))
	case !r.OK:
		return jobs.Transient("edge_probe_failed", errors.New("the edge did not answer as expected yet"))
	}
	hs, err := p.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return headscaleErr("ForTenant", err)
	}
	h, err := hs.Health(cctx)
	if err != nil {
		return headscaleErr("Health", err)
	}
	if !h.DatabaseConnectivity {
		return jobs.Transient("instance_unhealthy", errors.New("GET /api/v1/health: no database connectivity"))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 19 activate

func (p *Provisioner) stepActivate(ctx context.Context, a *attempt, s stepCtx) error {
	inst, err := p.instance(ctx, a)
	if err != nil {
		return err
	}
	if err := p.cfg.Store.Activate(ctx, ActivateRequest{TenantID: a.in.TenantID, InstanceID: inst.ID,
		Operation: a.in.Operation, OwnerEmail: a.in.OwnerEmail,
		Details: audit.Details{"job_id": a.r.JobID(), "instance_id": inst.ID, "slug": a.in.Slug,
			"control_hostname": inst.ControlHostname}}); err != nil {
		return storeErr("activate", err)
	}
	return detail(s, map[string]any{"tenant_status": tenants.StatusActive, "instance_status": tenants.InstanceRunning})
}
