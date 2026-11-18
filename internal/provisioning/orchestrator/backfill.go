package orchestrator

// Backfill of an adopted instance (P3-T14b, §11.4 "chuẩn hóa A/B"): an instance built by hand in Phase 1
// (tools/render_instance.py + tenant-deploy.sh + reattach-edge.sh) and registered by `admin adopt-instance` (P2-T11)
// lacks what the provisioning state machine writes after step 3 — and so the operations that rely on it refuse it or
// cover it only partly:
//
//   - instance_config_versions + tenant_instances.config_version_id/derp_region_id (step 8): reconcile's config check
//     is not_applicable (not_recorded); instance.reconfigure (P3-T13) and instance.upgrade (P3-T13a) refuse with
//     no_config_version;
//   - tenant_instances.noise_key_fingerprint (step 11): reconcile's noise_key check is not_applicable; the edge.verify
//     of instance.restart (P3-T13a) has no key to probe for;
//   - meta/activated, the fingerprint in meta/instance.json and the edge_attach flag (step 14, written by the agent's
//     EnsureEdgeAttachment): the agent's start guard does not protect the instance (it starts on an empty data/), and
//     its edge supervisor reports the hand-made attachment as attached_unflagged and never re-attaches it after the
//     edge was recreated or the host rebooted;
//   - relay_regions (embedded mg-<slug>) + relay_assignments (step 17): GET /tenants/{t}/relay is empty and relay.probe
//     has nothing to probe (P3-T05c).
//
// Backfill writes exactly these from the instance's REAL state, read through the Host Agent, and never touches the
// tenant's data: no file of data/ (Noise key, DERP key, db.sqlite) is read or written — the fingerprint is the agent's
// helper's —, no configuration is written, the container is never restarted. The configuration version is recorded
// only when the agent's rendering of the orchestrator's parameters (the defaults of tenant.provision ⊕ the plan's
// limits ⊕ the operator's overrides) is byte-identical to config.yaml on the host (same sha256 — ValidateConfig renders
// and runs configtest in a throwaway container, writes nothing): the version then describes the instance truthfully,
// and reconfigure/upgrade/rollback re-render exactly it. Anything else is refused, nothing written. Bringing an
// instance to another configuration is instance.reconfigure's job (health gate, rollback), never this one's.
//
// Running it again changes nothing (each item is written only when absent; no audit event without a change). A dry
// run reads and validates everything and returns the plan.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ActionInstanceBackfill is the audit action of a backfill (platform scope, paired .requested → .succeeded/.failed).
const ActionInstanceBackfill = "platform.instance.backfill"

// Items of a backfill (BackfillItem.Name).
const (
	BackfillConfigVersion = "config_version"        // instance_config_versions + config_version_id (step 8)
	BackfillFingerprint   = "noise_key_fingerprint" // tenant_instances.noise_key_fingerprint (step 11)
	BackfillActivation    = "activation"            // meta/activated + edge_attach flag through the agent (step 14)
	BackfillRelay         = "relay"                 // relay_regions mg-<slug> + relay_assignments (step 17)
)

// States of an item.
const (
	ItemPresent    = "present"     // already recorded: nothing to do
	ItemWouldWrite = "would_write" // dry run: would be written
	ItemWritten    = "written"
)

// Refusal codes of a backfill (BackfillError.Code): nothing was written.
const (
	BackfillNotRunning      = "instance_not_running"    // registry: not running (quarantined, stopped…)
	BackfillTenantState     = "tenant_not_active"       // tenant neither active nor suspended
	BackfillLifecycleBusy   = "lifecycle_job_running"   // a job holds the tenant's lifecycle lock
	BackfillRegistryState   = "registry_state"          // no public entry, subnet or run_uid
	BackfillHostState       = "host_state"              // the agent reports the instance not serving as registered
	BackfillQuarantined     = "instance_quarantined"    // meta/quarantined on the host
	BackfillNoFingerprint   = "fingerprint_unavailable" // the agent could not compute the Noise key fingerprint
	BackfillFingerprintDiff = "fingerprint_mismatch"    // registry and host disagree on the Noise key (RT-06)
	BackfillConfigVersionAt = "config_hash_mismatch"    // the version in force is not the configuration on the host
	BackfillConfigDiffers   = "config_render_mismatch"  // the agent's rendering of the parameters ≠ config.yaml on the host
	BackfillConfigInvalid   = "config_invalid"          // configtest refused the rendering
	BackfillParams          = "invalid_parameters"      // an override out of bounds
)

// BackfillError is a refusal: the instance is not in a state the backfill may record (nothing was written), or a
// failure after the audit operation was opened (Written says what was).
type BackfillError struct {
	Code string
	Msg  string
}

func (e *BackfillError) Error() string { return "backfill: " + e.Code + ": " + e.Msg }

func refuse(code, format string, args ...any) error {
	return &BackfillError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// BackfillAgent is the part of the Host Agent the backfill calls (agentclient.Client).
type BackfillAgent interface {
	GetHostInfo(ctx context.Context, in *agentv1.GetHostInfoRequest, opts ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error)
	GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, opts ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error)
	ValidateConfig(ctx context.Context, in *agentv1.ValidateConfigRequest, opts ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error)
	EnsureEdgeAttachment(ctx context.Context, in *agentv1.EnsureEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error)
}

// BackfillTarget is what the registry holds about the tenant's live instance.
type BackfillTarget struct {
	Tenant   TenantRecord   // with the plan's instance limits
	Instance InstanceRecord // live instance, with its host's public entry
	Current  *ConfigVersion // version in force; nil when none
	// LockHolder is the job holding the tenant's lifecycle lock (uuid.Nil = none).
	LockHolder    uuid.UUID
	LockHolderKey string
	RelayRegion   bool // relay_regions mg-<slug> exists
	RelayAssigned bool // a relay_assignments row of the instance exists
	DesiredPolicy bool // tenants.desired_policy_version_id is set (P3-T08a policy-apply)
}

// BackfillRecord is the registry write of a backfill (one transaction, with the audit outcome).
type BackfillRecord struct {
	TenantID, InstanceID uuid.UUID
	Operation            audit.Operation
	// Config: the version to record (nil = present already). The instance must still have no version, or this one.
	Config *NewConfigVersion
	// DERPRegionID rendered (tenant_instances.derp_region_id).
	DERPRegionID int32
	Fingerprint  string        // "" = present already
	Relay        *RelayRequest // nil = present already
	Details      audit.Details
}

// BackfillStore is the registry side of the backfill (DBStore).
type BackfillStore interface {
	BackfillTarget(ctx context.Context, tenantID uuid.UUID) (BackfillTarget, error)
	// BeginBackfill commits "<ActionInstanceBackfill>.requested" (before the agent writes anything).
	BeginBackfill(ctx context.Context, ev audit.Event) (audit.Operation, error)
	// RecordBackfill writes the record and "<op>.succeeded" in one transaction; it re-checks under the transaction that
	// nothing else recorded a version or another fingerprint meanwhile (ErrState).
	RecordBackfill(ctx context.Context, r BackfillRecord) error
	// FailBackfill writes "<op>.failed" (reason: a stable code).
	FailBackfill(ctx context.Context, op audit.Operation, reason string, details audit.Details) error
}

// BackfillDefaults are the parameters tenant.provision gives a new instance (the worker's MG_PROVISION_* and the
// orchestrator's defaults — Config of the Provisioner).
type BackfillDefaults struct {
	Nameservers    []netip.Addr
	NodeExpiryDays uint32           // 0: DefaultNodeExpiryDays
	DERPRegionID   uint32           // 0: DefaultDERPRegionID (an instance with derp_region_id keeps its own)
	LogLevel       agentv1.LogLevel // UNSPECIFIED: info
	MemoryMiB      uint32           // 0: DefaultMemoryMiB (the plan's limits win, as in tenant.provision)
	CPUMillis      uint32           // 0: DefaultCPUMillis
	PIDs           uint32           // 0: DefaultPIDs
	STUNPort       uint16           // shared STUN of the relay row; 0: DefaultSTUNPort
}

// BackfillOverrides are the operator's values for an instance whose Phase-1 parameter file differs from the defaults
// (infrastructure/environments/<env>/tenants/<slug>.json). nil / empty = the default.
type BackfillOverrides struct {
	NodeExpiryDays *uint32
	Nameservers    []string
	LogLevel       string // info | warn | error
	DERPRegionID   *uint32
	MemoryMiB      *uint32
	CPUMillis      *uint32
	PIDs           *uint32
}

// BackfillRequest is one backfill.
type BackfillRequest struct {
	TenantID  uuid.UUID
	Overrides BackfillOverrides
	DryRun    bool
	Actor     string // display name of the operator / command (audit actor_display; actor type system)
}

// BackfillItem is one item of the plan.
type BackfillItem struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// BackfillPlan is the outcome of a backfill (or of its dry run): public values only.
type BackfillPlan struct {
	TenantID            uuid.UUID      `json:"tenant_id"`
	InstanceID          uuid.UUID      `json:"instance_id"`
	Slug                string         `json:"slug"`
	DryRun              bool           `json:"dry_run"`
	Changed             bool           `json:"changed"`
	OperationID         *uuid.UUID     `json:"operation_id,omitempty"`
	Params              map[string]any `json:"params,omitempty"`
	TemplateVersion     uint32         `json:"template_version,omitempty"`
	ConfigSHA256        string         `json:"config_sha256,omitempty"`   // config.yaml on the host
	RenderedSHA256      string         `json:"rendered_sha256,omitempty"` // the agent's rendering of Params
	NoiseKeyFingerprint string         `json:"noise_key_fingerprint,omitempty"`
	StartedAt           string         `json:"container_started_at,omitempty"`
	Items               []BackfillItem `json:"items"`
	Notes               []string       `json:"notes,omitempty"`
	Refusal             string         `json:"refusal,omitempty"`
	Error               string         `json:"error,omitempty"`
}

// Backfiller runs the backfill (`meshguard-worker admin backfill-instance`).
type Backfiller struct {
	Store       BackfillStore
	Agent       BackfillAgent
	Defaults    BackfillDefaults
	CallTimeout time.Duration // one agent call; 0: 2 min
	Logger      *slog.Logger
}

func (b *Backfiller) call(ctx context.Context) (context.Context, context.CancelFunc) {
	d := b.CallTimeout
	if d <= 0 {
		d = 2 * time.Minute
	}
	return context.WithTimeout(ctx, d)
}

func (b *Backfiller) log() *slog.Logger {
	if b.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return b.Logger
}

// Backfill reads the registry and the host, validates, and — unless DryRun — records what is missing. A refusal is a
// *BackfillError (nothing written); the plan is returned in every case with what was found.
func (b *Backfiller) Backfill(ctx context.Context, req BackfillRequest) (BackfillPlan, error) {
	plan := BackfillPlan{TenantID: req.TenantID, DryRun: req.DryRun, Items: []BackfillItem{}}
	t, err := b.Store.BackfillTarget(ctx, req.TenantID)
	if err != nil {
		return plan, fmt.Errorf("backfill: read the registry: %w", err)
	}
	inst := t.Instance
	plan.InstanceID, plan.Slug = inst.ID, t.Tenant.Slug
	ref := &agentv1.InstanceRef{InstanceId: inst.ID.String(), TenantId: inst.TenantID.String(), Slug: t.Tenant.Slug}

	// 1. the registry
	switch {
	case inst.Status != tenants.InstanceRunning:
		return plan, refuse(BackfillNotRunning, "the instance is %s, not running", inst.Status)
	case t.Tenant.Status != tenants.StatusActive && t.Tenant.Status != tenants.StatusSuspended:
		return plan, refuse(BackfillTenantState, "the tenant is %s", t.Tenant.Status)
	case t.LockHolder != uuid.Nil:
		return plan, refuse(BackfillLifecycleBusy, "job %s (%s) holds the tenant's lifecycle lock", t.LockHolder, t.LockHolderKey)
	case !inst.PublicEntryIPv4.IsValid() || !inst.NetCIDR.IsValid() || inst.RunUID <= 0:
		return plan, refuse(BackfillRegistryState, "the instance has no public entry, subnet or run_uid")
	}

	// 2. the host, as the agent sees it (read only)
	st, err := b.status(ctx, ref)
	if err != nil {
		return plan, err
	}
	plan.ConfigSHA256, plan.NoiseKeyFingerprint = st.GetConfigSha256(), st.GetNoiseKeyFingerprint()
	if s := st.GetStartedAt(); s != nil {
		plan.StartedAt = s.AsTime().UTC().Format(time.RFC3339Nano)
	}
	if err := serving(st, inst); err != nil {
		return plan, err
	}
	fp := st.GetNoiseKeyFingerprint()
	if inst.NoiseFingerprint != "" && !strings.EqualFold(inst.NoiseFingerprint, fp) {
		return plan, refuse(BackfillFingerprintDiff, "the registry records another Noise key fingerprint than the host's "+
			"(%s ≠ %s) — never overwritten: investigate (§11.4 start guard, RT-06)", inst.NoiseFingerprint, fp)
	}

	// 3. the configuration version: the agent's rendering of the orchestrator's parameters = config.yaml on the host
	params, err := b.params(t, req.Overrides)
	if err != nil {
		return plan, err
	}
	plan.Params = params.public()
	var cfg *NewConfigVersion
	switch {
	case t.Current != nil && strings.EqualFold(t.Current.ConfigSHA256, st.GetConfigSha256()):
		plan.add(BackfillConfigVersion, ItemPresent, fmt.Sprintf("version %d (%s)", t.Current.Version, t.Current.Status))
	case t.Current != nil:
		return plan, refuse(BackfillConfigVersionAt, "version %d in force has sha256 %s, config.yaml on the host %s — a drift "+
			"reconcile reports; not the backfill's to record", t.Current.Version, t.Current.ConfigSHA256, st.GetConfigSha256())
	default:
		v, err := b.render(ctx, ref, params)
		if err != nil {
			return plan, err
		}
		plan.TemplateVersion, plan.RenderedSHA256 = v.TemplateVersion, v.ConfigSHA256
		if !strings.EqualFold(v.ConfigSHA256, st.GetConfigSha256()) {
			return plan, refuse(BackfillConfigDiffers, "the agent renders sha256 %s from the parameters, config.yaml on the host is %s "+
				"— give the instance's Phase-1 values as overrides (its parameter file), or leave it to the orchestrator",
				v.ConfigSHA256, st.GetConfigSha256())
		}
		cfg = &v
		plan.add(BackfillConfigVersion, b.pending(req), "sha256 "+v.ConfigSHA256)
	}

	// 4. fingerprint, activation, relay
	recordFP := ""
	if inst.NoiseFingerprint == "" {
		recordFP = fp
		plan.add(BackfillFingerprint, b.pending(req), fp)
	} else {
		plan.add(BackfillFingerprint, ItemPresent, fp)
	}
	activate := !st.GetActivated() || !st.GetEdgeAttachFlag()
	if activate {
		plan.add(BackfillActivation, b.pending(req), fmt.Sprintf("activated=%t edge_attach=%t (edge attached=%t, no restart)",
			st.GetActivated(), st.GetEdgeAttachFlag(), st.GetNetwork().GetEdgeAttached()))
	} else {
		plan.add(BackfillActivation, ItemPresent, "activated, edge_attach")
	}
	var relay *RelayRequest
	if !t.RelayRegion || !t.RelayAssigned {
		relay = &RelayRequest{TenantID: inst.TenantID, InstanceID: inst.ID, HostID: inst.HostID, Code: relayCode(t.Tenant.Slug),
			Name: "MeshGuard " + t.Tenant.Slug, Hostname: inst.ControlHostname, DERPRegionID: int32(params.DERPRegionID), //nolint:gosec // 900–999
			IPv4: inst.PublicEntryIPv4, STUNPort: int32(b.stunPort())}
		plan.add(BackfillRelay, b.pending(req), relay.Code)
	} else {
		plan.add(BackfillRelay, ItemPresent, relayCode(t.Tenant.Slug))
	}
	if !t.DesiredPolicy {
		plan.Notes = append(plan.Notes, "the tenant has no desired policy version: the post-start gate of restart/upgrade/"+
			"reconfigure is skipped until `admin policy-apply --tenant "+t.Tenant.Slug+"` records the policy in force (P3-T08a)")
	}
	if cfg == nil && recordFP == "" && !activate && relay == nil {
		return plan, nil
	}
	if req.DryRun {
		plan.Changed = true
		return plan, nil
	}

	// 5. write: audit .requested, the agent's activation, the registry with .succeeded
	tenantID := inst.TenantID
	op, err := b.Store.BeginBackfill(ctx, audit.Event{ActorType: audit.ActorSystem, ActorDisplay: req.Actor,
		Action: ActionInstanceBackfill, ResourceType: "instance", ResourceID: inst.ID.String(),
		Details: audit.Details{"tenant_id": tenantID.String(), "slug": t.Tenant.Slug, "items": plan.pendingNames(),
			"config_sha256": st.GetConfigSha256(), "noise_key_fingerprint": fp}})
	if err != nil {
		return plan, fmt.Errorf("backfill: record the audit event before any change: %w", err)
	}
	plan.OperationID = &op.ID
	fail := func(code string, err error) (BackfillPlan, error) {
		if ferr := b.Store.FailBackfill(context.WithoutCancel(ctx), op, code, audit.Details{"tenant_id": tenantID.String()}); ferr != nil {
			b.log().Error("backfill: audit .failed not recorded", "operation_id", op.ID.String(), "error", ferr.Error())
		}
		return plan, err
	}
	if activate {
		if err := b.activate(ctx, ref, op.ID, st); err != nil {
			var be *BackfillError
			code := "agent_error"
			if errors.As(err, &be) {
				code = be.Code
			}
			return fail(code, err)
		}
		plan.mark(BackfillActivation)
	}
	derp := int32(params.DERPRegionID) //nolint:gosec // 900–999
	details := audit.Details{"tenant_id": tenantID.String(), "slug": t.Tenant.Slug, "items": plan.pendingNames(),
		"config_sha256": st.GetConfigSha256(), "noise_key_fingerprint": fp, "derp_region_id": derp}
	if err := b.Store.RecordBackfill(ctx, BackfillRecord{TenantID: tenantID, InstanceID: inst.ID, Operation: op, Config: cfg,
		DERPRegionID: derp, Fingerprint: recordFP, Relay: relay, Details: details}); err != nil {
		return fail("registry_write_failed", fmt.Errorf("backfill: record in the registry: %w", err))
	}
	for _, n := range []string{BackfillConfigVersion, BackfillFingerprint, BackfillRelay} {
		plan.mark(n)
	}
	plan.Changed = true
	return plan, nil
}

func (b *Backfiller) pending(req BackfillRequest) string {
	if req.DryRun {
		return ItemWouldWrite
	}
	return "pending"
}

func (p *BackfillPlan) add(name, state, detail string) {
	p.Items = append(p.Items, BackfillItem{Name: name, State: state, Detail: detail})
}

func (p *BackfillPlan) mark(name string) {
	for i := range p.Items {
		if p.Items[i].Name == name && p.Items[i].State == "pending" {
			p.Items[i].State = ItemWritten
		}
	}
}

func (p *BackfillPlan) pendingNames() []string {
	out := []string{}
	for _, it := range p.Items {
		if it.State == "pending" || it.State == ItemWritten {
			out = append(out, it.Name)
		}
	}
	return out
}

func (b *Backfiller) stunPort() uint16 {
	if b.Defaults.STUNPort == 0 {
		return DefaultSTUNPort
	}
	return b.Defaults.STUNPort
}

func (b *Backfiller) status(ctx context.Context, ref *agentv1.InstanceRef) (*agentv1.InstanceStatus, error) {
	cctx, cancel := b.call(ctx)
	defer cancel()
	r, err := b.Agent.GetInstanceStatus(cctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
	if err != nil {
		return nil, fmt.Errorf("backfill: %w", agentErr("GetInstanceStatus", err))
	}
	return r.GetStatus(), nil
}

// serving: the instance runs, healthy, the registry's image, on its own internal network with the edge, with a
// configuration file and a computable Noise key fingerprint — the state of an activated instance (§11.3 steps 10–14).
func serving(st *agentv1.InstanceStatus, inst InstanceRecord) error {
	nw := st.GetNetwork()
	switch {
	case st.GetQuarantined():
		return refuse(BackfillQuarantined, "the instance is quarantined on the host (meta/quarantined) — §11.4")
	case st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING:
		return refuse(BackfillHostState, "container %s", st.GetContainerState())
	case st.GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY:
		return refuse(BackfillHostState, "container health %s", st.GetHealth())
	case st.GetImageDigest() != inst.ImageDigest:
		return refuse(BackfillHostState, "the container runs %q, the registry records %s", st.GetImageDigest(), inst.ImageDigest)
	case !nw.GetExists() || !nw.GetInternal() || nw.GetSubnet() != inst.NetCIDR.String():
		return refuse(BackfillHostState, "network: exists=%t internal=%t subnet=%s (registry %s)", nw.GetExists(),
			nw.GetInternal(), nw.GetSubnet(), inst.NetCIDR)
	case !hexRE.MatchString(st.GetConfigSha256()):
		return refuse(BackfillHostState, "no config.yaml")
	case !hexRE.MatchString(st.GetNoiseKeyFingerprint()):
		return refuse(BackfillNoFingerprint, "the agent reports no Noise key fingerprint (data/noise_private.key, helper)")
	}
	return nil
}

// params are the parameters tenant.provision would give this instance today (instanceSpec): the registry's identity
// (image, run_uid, net_cidr, stun port, DERP region), the host's public entry, the defaults, the plan's limits — and
// the operator's overrides on top.
func (b *Backfiller) params(t BackfillTarget, o BackfillOverrides) (configParams, error) {
	d := b.Defaults
	inst := t.Instance
	p := configParams{ImageDigest: inst.ImageDigest, RunUID: uint32(inst.RunUID), NetCIDR: inst.NetCIDR.String(), //nolint:gosec // > 0
		PublicEntryIPv4: inst.PublicEntryIPv4.String(), NodeExpiryDays: orDefault(d.NodeExpiryDays, DefaultNodeExpiryDays),
		DERPRegionID: orDefault(d.DERPRegionID, DefaultDERPRegionID), LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO.String()}
	if d.LogLevel != agentv1.LogLevel_LOG_LEVEL_UNSPECIFIED {
		p.LogLevel = d.LogLevel.String()
	}
	if inst.DERPRegionID > 0 {
		p.DERPRegionID = uint32(inst.DERPRegionID)
	}
	if inst.STUNPort > 0 {
		sp := uint32(inst.STUNPort)
		p.StunPort = &sp
	}
	for _, a := range d.Nameservers {
		p.Nameservers = append(p.Nameservers, a.String())
	}
	lim := specLimits(orDefault(d.MemoryMiB, DefaultMemoryMiB), orDefault(d.CPUMillis, DefaultCPUMillis),
		orDefault(d.PIDs, DefaultPIDs), t.Tenant.Instance)
	p.MemoryMiB, p.CPUMillis, p.PIDs = lim.GetMemoryMib(), lim.GetCpuMillis(), lim.GetPids()

	ch := ConfigChange{LogLevel: o.LogLevel, NodeExpiryDays: o.NodeExpiryDays, Nameservers: o.Nameservers, DERPRegionID: o.DERPRegionID}
	if err := ch.Normalize(); err != nil {
		var ce *CreateError
		if errors.As(err, &ce) {
			return p, refuse(BackfillParams, "%s: %s", ce.Field, ce.Reason)
		}
		return p, refuse(BackfillParams, "%v", err)
	}
	if ch.LogLevel != "" {
		p.LogLevel = logLevels[ch.LogLevel].String()
	}
	if ch.NodeExpiryDays != nil {
		p.NodeExpiryDays = *ch.NodeExpiryDays
	}
	if ch.Nameservers != nil {
		p.Nameservers = slices.Clone(ch.Nameservers)
	}
	if ch.DERPRegionID != nil {
		p.DERPRegionID = *ch.DERPRegionID
	}
	for _, x := range []struct {
		v      *uint32
		dst    *uint32
		lo, hi uint32
		name   string
	}{{o.MemoryMiB, &p.MemoryMiB, minMemoryMiB, maxMemoryMiB, "memory_mib"}, {o.CPUMillis, &p.CPUMillis, minCPUMillis, maxCPUMillis, "cpu_millis"},
		{o.PIDs, &p.PIDs, minPIDs, maxPIDs, "pids"}} {
		if x.v == nil {
			continue
		}
		if *x.v < x.lo || *x.v > x.hi {
			return p, refuse(BackfillParams, "%s: out_of_range (%d–%d)", x.name, x.lo, x.hi)
		}
		*x.dst = *x.v
	}
	if len(p.Nameservers) == 0 {
		return p, refuse(BackfillParams, "nameservers: none configured (MG_PROVISION_NAMESERVERS) nor given")
	}
	return p, nil
}

func orDefault(v, d uint32) uint32 {
	if v == 0 {
		return d
	}
	return v
}

// public is the parameters as the plan prints them (the keys of instance_config_versions.params).
func (p configParams) public() map[string]any {
	raw, _ := json.Marshal(p)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// render asks the agent to render and configtest the parameters (a throwaway container; nothing written).
func (b *Backfiller) render(ctx context.Context, ref *agentv1.InstanceRef, p configParams) (NewConfigVersion, error) {
	spec, err := p.spec(ref)
	if err != nil {
		return NewConfigVersion{}, refuse(BackfillParams, "%v", err)
	}
	cctx, cancel := b.call(ctx)
	defer cancel()
	hi, err := b.Agent.GetHostInfo(cctx, &agentv1.GetHostInfoRequest{})
	if err != nil {
		return NewConfigVersion{}, fmt.Errorf("backfill: %w", agentErr("GetHostInfo", err))
	}
	v, err := b.Agent.ValidateConfig(cctx, &agentv1.ValidateConfigRequest{Spec: spec, JobId: uuid.NewString()})
	if err != nil {
		return NewConfigVersion{}, fmt.Errorf("backfill: %w", agentErr("ValidateConfig", err))
	}
	if !v.GetValid() {
		return NewConfigVersion{}, refuse(BackfillConfigInvalid, "headscale configtest refused the rendering (exit %d)", v.GetExitCode())
	}
	if !hexRE.MatchString(v.GetConfigSha256()) {
		return NewConfigVersion{}, fmt.Errorf("backfill: ValidateConfig answered no configuration sha256")
	}
	return NewConfigVersion{ID: uuid.New(), TemplateVersion: hi.GetTemplateVersion(), ConfigSHA256: v.GetConfigSha256(),
		Params: p}, nil
}

// activate is step 14 on an instance already attached by hand: EnsureEdgeAttachment runs the start guard's data
// check and records the Noise key fingerprint in meta/instance.json, writes meta/activated and the edge_attach flag;
// the edge is already a member, so the network does not change. Then the status must show the activation, the same
// fingerprint, the same configuration and the same container start — no restart.
func (b *Backfiller) activate(ctx context.Context, ref *agentv1.InstanceRef, op uuid.UUID, before *agentv1.InstanceStatus) error {
	cctx, cancel := b.call(ctx)
	_, err := b.Agent.EnsureEdgeAttachment(cctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: ref, JobId: op.String()})
	cancel()
	if err != nil {
		return fmt.Errorf("backfill: %w", agentErr("EnsureEdgeAttachment", err))
	}
	after, err := b.status(ctx, ref)
	if err != nil {
		return err
	}
	switch {
	case !after.GetActivated() || !after.GetEdgeAttachFlag():
		return refuse(BackfillHostState, "after EnsureEdgeAttachment: activated=%t edge_attach=%t", after.GetActivated(),
			after.GetEdgeAttachFlag())
	case !after.GetNetwork().GetEdgeAttached():
		return refuse(BackfillHostState, "after EnsureEdgeAttachment: the edge is not attached")
	case after.GetNoiseKeyFingerprint() != before.GetNoiseKeyFingerprint():
		return refuse(BackfillFingerprintDiff, "the Noise key fingerprint changed during the backfill")
	case after.GetConfigSha256() != before.GetConfigSha256():
		return refuse(BackfillHostState, "config.yaml changed during the backfill")
	case after.GetContainerId() != before.GetContainerId() || !after.GetStartedAt().AsTime().Equal(before.GetStartedAt().AsTime()):
		return refuse(BackfillHostState, "the container was restarted or recreated during the backfill")
	}
	return nil
}
