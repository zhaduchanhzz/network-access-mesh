package orchestrator

// instance.reconfigure (P3-T13, §11.4 row Reconfigure, §13.5): a new configuration version of a running instance,
// applied with a restart behind a health gate, rolled back automatically when it does not come up.
//
//	1 config.validate  the new typed spec = the version in force (instance_config_versions.params) ⊕ the requested
//	                   change ⊕ the registry's identity and the host's public entry (derp.server.ipv4 — §17.4); Agent
//	                   GetHostInfo (template version) + ValidateConfig (configtest in a throw-away container); the
//	                   same sha256 as the version in force ⇒ nothing to do: the job ends here, no restart
//	2 config.record    instance_config_versions row `pending` (id chosen first, in created_resources)
//	                                                           ⟲ version → failed; the instance points at the previous
//	3 policy.check     CheckPolicy of the applied policy (§7.3; canonical rendering of the policy core) — before
//	                   anything is written
//	4 config.write     Agent EnsureInstance(TARGET_PHASE_CONFIG): atomic write, sha256 = the validated one
//	                                                           ⟲ the previous version written back
//	5 instance.restart Agent RestartInstance (start guard)     ⟲ previous version written back + restart + health gate
//	6 instance.health  container running + healthy after the restart with the new sha256; Noise key unchanged;
//	                   GET /api/v1/health through the adapter; post-start gate (GetPolicy = applied_sha256 — §11.4)
//	7 edge.verify      Prober.Edge (/key = the instance's key, forbidden paths 404); no prober ⇒ skipped
//	8 config.apply     version `applied`, the previous `superseded`, tenant_instances.config_version_id, audit .succeeded
//
// Failure handling is the one of §11.3: transient errors retried in place 5 times then failed_resumable (/retry
// resumes, /rollback undoes); a permanent error ⇒ compensation in reverse order ⇒ rolled_back, the new version
// `failed`, audit .failed + platform.instance.config_rollback; a compensation that fails ⇒ failed_resumable
// (compensation_failed) + a Critical security event. The instance's data/ is never touched: the agent writes config/,
// compose.yaml and meta/ only (EnsureInstance with an existing data/), and a quarantined instance is never restarted.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ReconfigureKind is the job kind of the instance reconfiguration (§13.5; lifecycle group, compensable).
const ReconfigureKind = "instance.reconfigure"

// The steps of instance.reconfigure, in order.
const (
	RStepValidate = "config.validate"
	RStepRecord   = "config.record"
	RStepPolicy   = "policy.check"
	RStepWrite    = "config.write"
	RStepRestart  = "instance.restart"
	RStepHealth   = "instance.health"
	RStepEdge     = StepEdgeVerify // the short edge.verify of §11.4
	RStepApply    = "config.apply"
)

// ReconfigureSteps lists the steps of instance.reconfigure in order.
var ReconfigureSteps = []string{RStepValidate, RStepRecord, RStepPolicy, RStepWrite, RStepRestart, RStepHealth, RStepEdge,
	RStepApply}

// Statuses of instance_config_versions.status (§6.3; provisioning step 8 records its first version `applied`).
const (
	ConfigPending    = "pending"    // recorded by a reconfigure, not in force yet
	ConfigApplied    = "applied"    // in force: the version tenant_instances.config_version_id points at
	ConfigSuperseded = "superseded" // was in force, replaced by a newer applied version
	ConfigFailed     = "failed"     // did not pass the health gate (or a later step): the previous version restored
)

// Audit actions of the reconfiguration.
const (
	// ActionInstanceReconfigure is the paired operation (x-audit-action): .requested (API) → .succeeded / .failed (job).
	ActionInstanceReconfigure = "platform.instance.reconfigure"
	// ActionConfigRollback records the automatic rollback (outcome success, or failure when it could not complete).
	ActionConfigRollback = "platform.instance.config_rollback"
)

// Security events of the reconfiguration (platform scope, details carry tenant_id).
const (
	SecRollbackFailed    = "instance.reconfigure_rollback_failed" // Critical: the previous version is not back
	SecPolicyCheckFailed = "instance.policy_check_failed"         // High: the applied policy does not pass CheckPolicy
	SecPolicyMissing     = "instance.policy_missing"              // Critical: no policy after the restart (allow-all)
	SecPolicyDrift       = "instance.policy_drift"                // High: the policy read back is not the applied one
	SecNoiseKeyChanged   = "instance.noise_key_changed"           // Critical: another Noise key after the restart
)

// Sources of a reconfiguration (job input).
const (
	SourcePlatform = "platform_api" // POST /platform/instances/{id}/reconfigure
)

// ReconfigureInput is the input of an instance.reconfigure job.
type ReconfigureInput struct {
	TenantID    uuid.UUID    `json:"tenant_id"`
	InstanceID  uuid.UUID    `json:"instance_id"`
	Change      ConfigChange `json:"change"`
	Source      string       `json:"source"`
	RequestedBy *uuid.UUID   `json:"requested_by,omitempty"`
	// Operation is the audit operation opened in the transaction that enqueued the job; the job closes it.
	Operation audit.Operation `json:"operation"`
}

func (in ReconfigureInput) validate() error {
	switch {
	case in.TenantID == uuid.Nil || in.InstanceID == uuid.Nil:
		return errors.New("tenant or instance missing")
	case in.Operation.ID == uuid.Nil:
		return errors.New("audit operation missing")
	}
	c := in.Change
	return c.Normalize()
}

// ReconfigureAgent is the part of the Host Agent the reconfiguration calls — typed RPCs only (§11.1); the generated
// agentv1.AgentServiceClient (agentclient.Client) implements it.
type ReconfigureAgent interface {
	GetHostInfo(ctx context.Context, in *agentv1.GetHostInfoRequest, opts ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error)
	ValidateConfig(ctx context.Context, in *agentv1.ValidateConfigRequest, opts ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error)
	EnsureInstance(ctx context.Context, in *agentv1.EnsureInstanceRequest, opts ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error)
	GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, opts ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error)
	RestartInstance(ctx context.Context, in *agentv1.RestartInstanceRequest, opts ...grpc.CallOption) (*agentv1.RestartInstanceResponse, error)
	RemoveEdgeAttachment(ctx context.Context, in *agentv1.RemoveEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error)
}

// ReconfigureConfig are the collaborators and settings of an InstanceReconfigurer.
type ReconfigureConfig struct {
	Store     ReconfigureStore
	Agent     ReconfigureAgent
	Headscale headscale.Registry
	Prober    Prober           // nil: edge.verify is recorded skipped (the adapter's health check still crosses the edge)
	Security  SecurityRecorder // nil: security events are only logged
	Logger    *slog.Logger
	// EdgeAddress is the edge's public listener as the prober reaches it (MG_PROVISION_EDGE_ADDR).
	EdgeAddress string

	// Timing (§11.3). Zero values take the defaults of the provisioning (5 retries, 2 s → 60 s, 90 s, 2 s, 2 min).
	StepRetries   int
	RetryBase     time.Duration
	RetryMax      time.Duration
	HealthTimeout time.Duration
	HealthPoll    time.Duration
	CallTimeout   time.Duration
	Now           func() time.Time
}

func (c *ReconfigureConfig) defaults() error {
	if c.StepRetries == 0 {
		c.StepRetries = DefaultStepRetries
	}
	if c.RetryBase == 0 {
		c.RetryBase = 2 * time.Second
	}
	if c.RetryMax == 0 {
		c.RetryMax = time.Minute
	}
	if c.HealthTimeout == 0 {
		c.HealthTimeout = DefaultHealthTimeout
	}
	if c.HealthPoll == 0 {
		c.HealthPoll = 2 * time.Second
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = 2 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	switch {
	case c.Store == nil || c.Agent == nil || c.Headscale == nil:
		return errors.New("orchestrator: reconfigure needs a store, the Host Agent and the Headscale registry")
	case c.StepRetries < 0 || c.RetryMax < c.RetryBase:
		return errors.New("orchestrator: invalid retry settings")
	}
	return nil
}

// InstanceReconfigurer runs instance.reconfigure in the worker: jobs.Handler and jobs.Compensator (the rollback).
type InstanceReconfigurer struct {
	cfg ReconfigureConfig
}

var (
	_ jobs.Handler     = (*InstanceReconfigurer)(nil)
	_ jobs.Compensator = (*InstanceReconfigurer)(nil)
)

// NewReconfigurer checks the configuration and returns the handler of instance.reconfigure.
func NewReconfigurer(cfg ReconfigureConfig) (*InstanceReconfigurer, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	return &InstanceReconfigurer{cfg: cfg}, nil
}

// Register registers the handler of instance.reconfigure on the worker.
func (c *InstanceReconfigurer) Register(w *jobs.Worker) error { return w.Register(ReconfigureKind, c) }

// Run implements jobs.Handler.
func (c *InstanceReconfigurer) Run(ctx context.Context, run *jobs.Run) error {
	return c.run(ctx, jobRunner{run})
}

// Compensate implements jobs.Compensator: the automatic rollback (and /rollback of a failed_resumable job).
func (c *InstanceReconfigurer) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return c.compensate(ctx, jobRunner{run}, cause)
}

// JobRunner is the attempt a reconfiguration runs on — *jobs.Run in the worker (Run, Compensate) — and StepContext the
// running step it hands to a step function. The real-Docker test of apps/agent, which has no database, drives the same
// state machine with an in-memory JobRunner through RunAttempt and CompensateAttempt.
type (
	JobRunner   = runner
	StepContext = stepCtx
)

// RunAttempt runs one attempt of the reconfiguration on r (what Run does on a *jobs.Run).
func (c *InstanceReconfigurer) RunAttempt(ctx context.Context, r JobRunner) error {
	return c.run(ctx, r)
}

// CompensateAttempt runs the rollback on r after cause (what Compensate does on a *jobs.Run).
func (c *InstanceReconfigurer) CompensateAttempt(ctx context.Context, r JobRunner, cause error) error {
	return c.compensate(ctx, r, cause)
}

// ---------------------------------------------------------------------------------------------------- the machine

// rcAttempt is one attempt: the runner and the input.
type rcAttempt struct {
	r  runner
	in ReconfigureInput
}

func (c *InstanceReconfigurer) input(r runner) (*rcAttempt, error) {
	a := &rcAttempt{r: r}
	if err := r.Input(&a.in); err != nil {
		return nil, jobs.Permanent("invalid_input", fmt.Errorf("job input unreadable: %w", err))
	}
	if err := a.in.validate(); err != nil {
		return nil, jobs.Permanent("invalid_input", err)
	}
	return a, nil
}

func (c *InstanceReconfigurer) run(ctx context.Context, r runner) error {
	a, err := c.input(r)
	if err != nil {
		return err
	}
	r.SetResource("instance", a.in.InstanceID.String())
	if err := c.step(ctx, r, RStepValidate, func(ctx context.Context, s stepCtx) error { return c.stepValidate(ctx, a, s) }); err != nil {
		return err
	}
	vr, err := a.validated(ctx)
	if err != nil {
		return err
	}
	if vr.Unchanged {
		// The rendered configuration is the one in force: nothing is written, nothing restarts (§11.4).
		if err := c.step(ctx, r, RStepApply, func(ctx context.Context, s stepCtx) error { return c.stepUnchanged(ctx, a, s, vr) }); err != nil {
			return err
		}
		return r.SetOutput(map[string]any{"tenant_id": a.in.TenantID, "instance_id": a.in.InstanceID, "changed": false,
			"config_version_id": vr.PreviousVersionID, "config_sha256": vr.ConfigSHA256})
	}
	for _, st := range []struct {
		name string
		fn   func(ctx context.Context, a *rcAttempt, s stepCtx) error
	}{
		{RStepRecord, c.stepRecord}, {RStepPolicy, c.stepPolicy}, {RStepWrite, c.stepWrite}, {RStepRestart, c.stepRestart},
		{RStepHealth, c.stepHealth}, {RStepEdge, c.stepEdge}, {RStepApply, c.stepApply},
	} {
		if err := c.step(ctx, r, st.name, func(ctx context.Context, s stepCtx) error { return st.fn(ctx, a, s) }); err != nil {
			return err
		}
	}
	rr, err := a.recorded(ctx)
	if err != nil {
		return err
	}
	return r.SetOutput(map[string]any{"tenant_id": a.in.TenantID, "instance_id": a.in.InstanceID, "changed": true,
		"config_version_id": rr.VersionID, "previous_version_id": rr.PreviousVersionID, "config_sha256": vr.ConfigSHA256,
		"previous_config_sha256": vr.PreviousSHA256})
}

// step runs one step with the retry policy of §11.3 (as the provisioning steps): a transient failure is retried in
// place StepRetries times with backoff, then jobs.Resumable; permanent, resumable and the end of ctx return at once.
func (c *InstanceReconfigurer) step(ctx context.Context, r runner, name string, fn func(ctx context.Context, s stepCtx) error) error {
	for try := 0; ; try++ {
		err := r.Step(ctx, name, fn)
		switch {
		case err == nil:
			return nil
		case jobs.IsPermanent(err), jobs.IsResumable(err), ctx.Err() != nil:
			return err
		case try >= c.cfg.StepRetries:
			return jobs.Resumable(jobs.CodeOf(err), fmt.Errorf("step %s: %d retries spent: %w", name, try, err))
		}
		if werr := sleep(ctx, c.backoff(try+1)); werr != nil {
			return err
		}
	}
}

// backoff is RetryBase·2^(n−1), capped at RetryMax, ± 20 %.
func (c *InstanceReconfigurer) backoff(n int) time.Duration {
	d := c.cfg.RetryBase
	for i := 1; i < n && d < c.cfg.RetryMax; i++ {
		d *= 2
	}
	d = min(d, c.cfg.RetryMax)
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // scheduling jitter
}

func (c *InstanceReconfigurer) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.cfg.CallTimeout)
}

// validated reads what config.validate recorded.
func (a *rcAttempt) validated(ctx context.Context) (validateResources, error) {
	var vr validateResources
	found, err := a.r.StepResources(ctx, RStepValidate, &vr)
	if err != nil {
		return vr, err
	}
	if !found || vr.PreviousVersionID == uuid.Nil || !hexRE.MatchString(vr.ConfigSHA256) {
		return vr, jobs.Permanent("invalid_state", errors.New("config.validate recorded no candidate configuration"))
	}
	return vr, nil
}

// recorded reads what config.record recorded.
func (a *rcAttempt) recorded(ctx context.Context) (recordResources, error) {
	var rr recordResources
	found, err := a.r.StepResources(ctx, RStepRecord, &rr)
	if err != nil {
		return rr, err
	}
	if !found || rr.VersionID == uuid.Nil {
		return rr, jobs.Permanent("invalid_state", errors.New("config.record recorded no configuration version"))
	}
	return rr, nil
}

// target loads the instance; with runnable, a quarantined instance, one that is not running or a tenant that is not
// active/suspended is refused (permanent: nothing of the instance is touched — §11.4).
func (c *InstanceReconfigurer) target(ctx context.Context, a *rcAttempt, runnable bool) (ReconfigureTarget, error) {
	t, err := c.cfg.Store.ReconfigureTarget(ctx, a.in.TenantID, a.in.InstanceID)
	if err != nil {
		return t, storeErr("load the instance", err)
	}
	if !runnable {
		return t, nil
	}
	switch {
	case t.Instance.Status == tenants.InstanceQuarantined:
		return t, jobs.Permanent("instance_quarantined", errors.New("the instance is quarantined: no job restarts it (§11.4)"))
	case t.Instance.Status != tenants.InstanceRunning:
		return t, jobs.Permanent("instance_not_running", fmt.Errorf("the instance is %s, not running", t.Instance.Status))
	case t.TenantStatus != tenants.StatusActive && t.TenantStatus != tenants.StatusSuspended:
		return t, jobs.Permanent("tenant_state", fmt.Errorf("the tenant is %s", t.TenantStatus))
	}
	return t, nil
}

func (t ReconfigureTarget) ref() *agentv1.InstanceRef {
	return &agentv1.InstanceRef{InstanceId: t.Instance.ID.String(), TenantId: t.Instance.TenantID.String(), Slug: t.TenantSlug}
}

// ---------------------------------------------------------------------------------------------------- parameters

// configParams is instance_config_versions.params: the typed parameters sent to the agent (the keys of specParams),
// never a secret. A version is re-rendered from them alone (the rollback writes the previous one back).
type configParams struct {
	ImageDigest     string   `json:"image_digest"`
	RunUID          uint32   `json:"run_uid"`
	NetCIDR         string   `json:"net_cidr"`
	MemoryMiB       uint32   `json:"memory_mib"`
	CPUMillis       uint32   `json:"cpu_millis"`
	PIDs            uint32   `json:"pids"`
	NodeExpiryDays  uint32   `json:"node_expiry_days"`
	Nameservers     []string `json:"nameservers"`
	DERPRegionID    uint32   `json:"derp_region_id"`
	PublicEntryIPv4 string   `json:"public_entry_ipv4"`
	LogLevel        string   `json:"log_level"` // the enum name: LOG_LEVEL_INFO …
	StunPort        *uint32  `json:"stun_port,omitempty"`
}

func decodeParams(raw []byte) (configParams, error) {
	var p configParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, jobs.Permanent("registry_state", fmt.Errorf("configuration parameters unreadable: %w", err))
	}
	return p, nil
}

// spec is the typed InstanceSpec of the parameters for the instance ref.
func (p configParams) spec(ref *agentv1.InstanceRef) (*agentv1.InstanceSpec, error) {
	lvl, ok := agentv1.LogLevel_value[p.LogLevel]
	if !ok || lvl == int32(agentv1.LogLevel_LOG_LEVEL_UNSPECIFIED) {
		return nil, jobs.Permanent("registry_state", fmt.Errorf("configuration parameters: log level %q", p.LogLevel))
	}
	hs := &agentv1.HeadscaleParams{NodeExpiryDays: p.NodeExpiryDays, Nameservers: slices.Clone(p.Nameservers),
		DerpRegionId: p.DERPRegionID, PublicEntryIpv4: p.PublicEntryIPv4, LogLevel: agentv1.LogLevel(lvl)}
	if p.StunPort != nil {
		sp := *p.StunPort
		hs.StunPort = &sp
	}
	return &agentv1.InstanceSpec{Instance: ref, ImageDigest: p.ImageDigest, RunUid: p.RunUID, NetCidr: p.NetCIDR,
		Limits: &agentv1.ResourceLimits{MemoryMib: p.MemoryMiB, CpuMillis: p.CPUMillis, Pids: p.PIDs}, Headscale: hs}, nil
}

// paramsOf is the parameters of a spec (the same keys and values as specParams).
func paramsOf(spec *agentv1.InstanceSpec) configParams {
	h := spec.GetHeadscale()
	p := configParams{ImageDigest: spec.GetImageDigest(), RunUID: spec.GetRunUid(), NetCIDR: spec.GetNetCidr(),
		MemoryMiB: spec.GetLimits().GetMemoryMib(), CPUMillis: spec.GetLimits().GetCpuMillis(), PIDs: spec.GetLimits().GetPids(),
		NodeExpiryDays: h.GetNodeExpiryDays(), Nameservers: slices.Clone(h.GetNameservers()), DERPRegionID: h.GetDerpRegionId(),
		PublicEntryIPv4: h.GetPublicEntryIpv4(), LogLevel: h.GetLogLevel().String()}
	if h.StunPort != nil {
		sp := h.GetStunPort()
		p.StunPort = &sp
	}
	return p
}

// paramChange is one parameter that differs from the version in force (step detail and audit — public values only).
type paramChange struct {
	Param string `json:"param"`
	From  any    `json:"from"`
	To    any    `json:"to"`
}

// mergeParams is the candidate: the version in force, the registry's identity (image, run_uid, net_cidr — the agent
// refuses any other), the host's current public entry, and the requested change.
func mergeParams(t ReconfigureTarget, base configParams, ch ConfigChange) (configParams, []paramChange, error) {
	inst := t.Instance
	if !inst.PublicEntryIPv4.IsValid() || !inst.NetCIDR.IsValid() || inst.RunUID <= 0 {
		return base, nil, jobs.Permanent("registry_state", errors.New("the instance has no public entry, subnet or run_uid"))
	}
	p := base
	p.Nameservers = slices.Clone(base.Nameservers)
	p.ImageDigest, p.RunUID, p.NetCIDR = inst.ImageDigest, uint32(inst.RunUID), inst.NetCIDR.String() //nolint:gosec // > 0
	p.PublicEntryIPv4 = inst.PublicEntryIPv4.String()
	if p.MemoryMiB == 0 || p.CPUMillis == 0 || p.PIDs == 0 {
		p.MemoryMiB, p.CPUMillis, p.PIDs = DefaultMemoryMiB, DefaultCPUMillis, DefaultPIDs
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
	var changes []paramChange
	add := func(name string, from, to any, differ bool) {
		if differ {
			changes = append(changes, paramChange{Param: name, From: from, To: to})
		}
	}
	add("log_level", base.LogLevel, p.LogLevel, base.LogLevel != p.LogLevel)
	add("node_expiry_days", base.NodeExpiryDays, p.NodeExpiryDays, base.NodeExpiryDays != p.NodeExpiryDays)
	add("nameservers", base.Nameservers, p.Nameservers, !slices.Equal(base.Nameservers, p.Nameservers))
	add("derp_region_id", base.DERPRegionID, p.DERPRegionID, base.DERPRegionID != p.DERPRegionID)
	add("public_entry_ipv4", base.PublicEntryIPv4, p.PublicEntryIPv4, base.PublicEntryIPv4 != p.PublicEntryIPv4)
	add("image_digest", base.ImageDigest, p.ImageDigest, base.ImageDigest != p.ImageDigest)
	return p, changes, nil
}

func changedNames(cs []paramChange) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Param)
	}
	return out
}

// ---------------------------------------------------------------------------------------------------- 1 config.validate

// validateResources is created_resources of config.validate: the version in force when the job started and the
// candidate the agent validated (parameters, sha256, template) — every later step and the rollback read them, so a
// resumed job never renders anything else.
type validateResources struct {
	PreviousVersionID uuid.UUID     `json:"previous_version_id"`
	PreviousSHA256    string        `json:"previous_config_sha256"`
	ConfigSHA256      string        `json:"config_sha256"`
	TemplateVersion   uint32        `json:"template_version"`
	Params            configParams  `json:"params"`
	Changes           []paramChange `json:"changes,omitempty"`
	Unchanged         bool          `json:"unchanged,omitempty"`
}

func (c *InstanceReconfigurer) stepValidate(ctx context.Context, a *rcAttempt, s stepCtx) error {
	t, err := c.target(ctx, a, true)
	if err != nil {
		return err
	}
	if t.Current == nil {
		return jobs.Permanent("no_config_version", errors.New("the instance has no configuration version (built by hand — P3-T14b)"))
	}
	base, err := decodeParams(t.Current.Params)
	if err != nil {
		return err
	}
	params, changes, err := mergeParams(t, base, a.in.Change)
	if err != nil {
		return err
	}
	spec, err := params.spec(t.ref())
	if err != nil {
		return err
	}
	cctx, cancel := c.call(ctx)
	defer cancel()
	hi, err := c.cfg.Agent.GetHostInfo(cctx, &agentv1.GetHostInfoRequest{})
	if err != nil {
		return agentErr("GetHostInfo", err)
	}
	v, err := c.cfg.Agent.ValidateConfig(cctx, &agentv1.ValidateConfigRequest{Spec: spec, JobId: a.r.JobID().String()})
	if err != nil {
		return agentErr("ValidateConfig", err)
	}
	d := map[string]any{"previous_version_id": t.Current.ID, "previous_config_sha256": t.Current.ConfigSHA256,
		"changes": changes, "template_version": hi.GetTemplateVersion()}
	if !v.GetValid() {
		d["valid"], d["exit_code"], d["configtest"] = false, v.GetExitCode(), v.GetDetail()
		_ = detail(s, d)
		return jobs.Permanent("config_invalid", fmt.Errorf("headscale configtest refused the new configuration (exit %d)",
			v.GetExitCode()))
	}
	if !hexRE.MatchString(v.GetConfigSha256()) {
		return jobs.Permanent("agent_error", errors.New("ValidateConfig answered no configuration sha256"))
	}
	res := validateResources{PreviousVersionID: t.Current.ID, PreviousSHA256: t.Current.ConfigSHA256,
		ConfigSHA256: v.GetConfigSha256(), TemplateVersion: hi.GetTemplateVersion(), Params: paramsOf(spec), Changes: changes,
		Unchanged: v.GetConfigSha256() == t.Current.ConfigSHA256}
	if err := record(ctx, s, res); err != nil {
		return err
	}
	d["valid"], d["config_sha256"], d["unchanged"] = true, res.ConfigSHA256, res.Unchanged
	return detail(s, d)
}

// stepUnchanged closes the audit operation of a request that changes nothing (the job's last step, config.apply).
func (c *InstanceReconfigurer) stepUnchanged(ctx context.Context, a *rcAttempt, s stepCtx, vr validateResources) error {
	if err := c.cfg.Store.RecordUnchanged(ctx, a.in.Operation, audit.Details{"job_id": a.r.JobID(),
		"instance_id": a.in.InstanceID, "tenant_id": a.in.TenantID, "changed": false, "config_sha256": vr.ConfigSHA256}); err != nil {
		return storeErr("close the audit operation", err)
	}
	return detail(s, map[string]any{"changed": false, "config_version_id": vr.PreviousVersionID,
		"config_sha256": vr.ConfigSHA256})
}

// ---------------------------------------------------------------------------------------------------- 2 config.record

// recordResources is created_resources of config.record (and of config.write): the new version and the one it
// replaces.
type recordResources struct {
	VersionID         uuid.UUID `json:"version_id"`
	PreviousVersionID uuid.UUID `json:"previous_version_id"`
}

func (c *InstanceReconfigurer) stepRecord(ctx context.Context, a *rcAttempt, s stepCtx) error {
	vr, err := a.validated(ctx)
	if err != nil {
		return err
	}
	var res recordResources
	if found, err := s.Previous(&res); err != nil {
		return err
	} else if !found || res.VersionID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return jobs.Transient("internal", err)
		}
		res = recordResources{VersionID: id, PreviousVersionID: vr.PreviousVersionID}
		if err := record(ctx, s, res); err != nil {
			return err
		}
	}
	v, err := c.cfg.Store.InsertConfigVersion(ctx, a.in.TenantID, a.in.InstanceID, NewConfigVersion{ID: res.VersionID,
		TemplateVersion: vr.TemplateVersion, ConfigSHA256: vr.ConfigSHA256, Params: vr.Params, CreatedBy: a.in.RequestedBy})
	if err != nil {
		return storeErr("record the configuration version", err)
	}
	if v.ConfigSHA256 != vr.ConfigSHA256 {
		return jobs.Permanent("registry_state", errors.New("the recorded version holds another configuration"))
	}
	return detail(s, map[string]any{"version_id": v.ID, "version": v.Version, "status": v.Status,
		"previous_version_id": res.PreviousVersionID})
}

// ---------------------------------------------------------------------------------------------------- 3 policy.check

func (c *InstanceReconfigurer) stepPolicy(ctx context.Context, a *rcAttempt, s stepCtx) error {
	pol, found, err := c.cfg.Store.CurrentPolicy(ctx, a.in.TenantID, a.in.InstanceID)
	if err != nil {
		return storeErr("load the applied policy", err)
	}
	if !found {
		// No application recorded (an instance whose baseline was never recorded): nothing to check against.
		return detail(s, map[string]any{"checked": false, "reason": "no_applied_policy"})
	}
	// The application in force holds the string as it was set — the provisioning's baseline is HuJSON with comments,
	// set through the CLI (§11.3 step 12) —; the adapter checks plain JSON only (V-06): CheckPolicy gets the canonical
	// rendering of the policy core (comments and trailing commas removed, the same rules), Headscale parses both alike.
	doc, lerr := policies.Lint(pol.HuJSON)
	if lerr != nil {
		c.security(ctx, a, SecPolicyCheckFailed, audit.SeverityHigh, "policy_check:"+a.in.InstanceID.String(),
			audit.Details{"applied_sha256": pol.SHA256, "kind": "lint"})
		_ = detail(s, map[string]any{"checked": true, "applied_sha256": pol.SHA256, "result": "lint_rejected"})
		return jobs.Permanent("policy_check_failed", fmt.Errorf("the applied policy does not pass the lint: %w", lerr))
	}
	cctx, cancel := c.call(ctx)
	defer cancel()
	hs, err := c.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return headscaleErr("ForTenant", err)
	}
	if err := hs.CheckPolicy(cctx, doc.Applied); err != nil {
		if he, ok := headscale.AsError(err); ok && (he.Kind == headscale.KindPolicyRejected ||
			he.Kind == headscale.KindValidation || he.Kind == headscale.KindUpstreamRejected) {
			// §7.3: a stored policy that does not pass CheckPolicy would stop the instance from starting (HS-09) —
			// the restart is blocked and an alert raised (re-applying it is the policy engine's — P4-T10).
			c.security(ctx, a, SecPolicyCheckFailed, audit.SeverityHigh, "policy_check:"+a.in.InstanceID.String(),
				audit.Details{"applied_sha256": pol.SHA256, "kind": string(he.Kind)})
			_ = detail(s, map[string]any{"checked": true, "applied_sha256": pol.SHA256, "result": string(he.Kind)})
			return jobs.Permanent("policy_check_failed", errors.New("the applied policy does not pass CheckPolicy: the restart is blocked"))
		}
		return headscaleErr("CheckPolicy", err)
	}
	return detail(s, map[string]any{"checked": true, "applied_sha256": pol.SHA256})
}

// ---------------------------------------------------------------------------------------------------- 4 config.write

func (c *InstanceReconfigurer) stepWrite(ctx context.Context, a *rcAttempt, s stepCtx) error {
	vr, err := a.validated(ctx)
	if err != nil {
		return err
	}
	rr, err := a.recorded(ctx)
	if err != nil {
		return err
	}
	t, err := c.target(ctx, a, true)
	if err != nil {
		return err
	}
	spec, err := vr.Params.spec(t.ref())
	if err != nil {
		return err
	}
	if err := record(ctx, s, rr); err != nil { // BEFORE the write: the rollback writes the previous version back
		return err
	}
	cctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.cfg.Agent.EnsureInstance(cctx, &agentv1.EnsureInstanceRequest{Spec: spec,
		TargetPhase: agentv1.TargetPhase_TARGET_PHASE_CONFIG, JobId: a.r.JobID().String()})
	if err != nil {
		c.startGuard(ctx, a, RStepWrite, err)
		return agentErr("EnsureInstance(config)", err)
	}
	if resp.GetConfigSha256() != vr.ConfigSHA256 {
		return jobs.Permanent("config_hash_mismatch", errors.New("the configuration written differs from the one validated"))
	}
	return detail(s, map[string]any{"config_sha256": resp.GetConfigSha256(), "template_version": resp.GetTemplateVersion(),
		"version_id": rr.VersionID})
}

// ---------------------------------------------------------------------------------------------------- 5 instance.restart

// restartResources is created_resources of instance.restart: the container's start time before the restart (the
// health gate requires a later one — the container that answers is the restarted one).
type restartResources struct {
	Restarted       bool      `json:"restarted"`
	BeforeStartedAt time.Time `json:"before_started_at,omitzero"`
}

func (c *InstanceReconfigurer) stepRestart(ctx context.Context, a *rcAttempt, s stepCtx) error {
	t, err := c.target(ctx, a, true) // never restart a quarantined instance (§11.4), even if quarantined since step 1
	if err != nil {
		return err
	}
	var res restartResources
	if found, err := s.Previous(&res); err != nil {
		return err
	} else if !found {
		before, err := c.status(ctx, t.ref())
		if err != nil {
			return err
		}
		res = restartResources{Restarted: true, BeforeStartedAt: startedAt(before)}
		if err := record(ctx, s, res); err != nil {
			return err
		}
	}
	cctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.cfg.Agent.RestartInstance(cctx, &agentv1.RestartInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
	if err != nil {
		c.startGuard(ctx, a, RStepRestart, err)
		return agentErr("RestartInstance", err)
	}
	return detail(s, map[string]any{"container_state": resp.GetStatus().GetContainerState().String(),
		"started_at": startedAt(resp.GetStatus()).Format(time.RFC3339Nano)})
}

func startedAt(st *agentv1.InstanceStatus) time.Time {
	if ts := st.GetStartedAt(); ts.IsValid() {
		return ts.AsTime().UTC()
	}
	return time.Time{}
}

func (c *InstanceReconfigurer) status(ctx context.Context, ref *agentv1.InstanceRef) (*agentv1.InstanceStatus, error) {
	cctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.cfg.Agent.GetInstanceStatus(cctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
	if err != nil {
		return nil, agentErr("GetInstanceStatus", err)
	}
	return resp.GetStatus(), nil
}

// ---------------------------------------------------------------------------------------------------- 6 instance.health

func (c *InstanceReconfigurer) stepHealth(ctx context.Context, a *rcAttempt, s stepCtx) error {
	vr, err := a.validated(ctx)
	if err != nil {
		return err
	}
	var rs restartResources
	if _, err := a.r.StepResources(ctx, RStepRestart, &rs); err != nil {
		return err
	}
	t, err := c.target(ctx, a, false)
	if err != nil {
		return err
	}
	deadline := c.cfg.Now().Add(c.cfg.HealthTimeout)
	st, d, err := c.gate(ctx, a, t, vr.ConfigSHA256, rs.BeforeStartedAt, deadline)
	if err != nil {
		_ = detail(s, d)
		return err
	}
	if fp := st.GetNoiseKeyFingerprint(); fp != "" && t.Instance.NoiseFingerprint != "" && fp != t.Instance.NoiseFingerprint {
		// The start guard should have refused this restart: another Noise key means another identity of the control
		// plane (RT-06) — never accepted.
		c.security(ctx, a, SecNoiseKeyChanged, audit.SeverityCritical, "noise_key:"+a.in.InstanceID.String(),
			audit.Details{"recorded": t.Instance.NoiseFingerprint, "reported": fp})
		_ = detail(s, d)
		return jobs.Permanent("noise_key_changed", errors.New("the restarted instance reports another Noise key"))
	}
	pd, err := c.postStartGate(ctx, a, t)
	for k, v := range pd {
		d[k] = v
	}
	if err != nil {
		_ = detail(s, d)
		return err
	}
	return detail(s, d)
}

// gate waits until the container runs, is healthy, was started after `after` (the restart) and reports the
// configuration want, then until GET /api/v1/health through the adapter answers with database connectivity — all
// before deadline (§11.3 step 11: 90 s). Not met ⇒ permanent instance_unhealthy (the rollback follows).
func (c *InstanceReconfigurer) gate(ctx context.Context, a *rcAttempt, t ReconfigureTarget, want string, after,
	deadline time.Time) (*agentv1.InstanceStatus, map[string]any, error) {
	d := map[string]any{}
	var last *agentv1.InstanceStatus
	for {
		st, err := c.status(ctx, t.ref())
		if err != nil {
			return nil, d, err
		}
		last = st
		started := startedAt(st)
		ok := st.GetContainerState() == agentv1.ContainerState_CONTAINER_STATE_RUNNING &&
			st.GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY && st.GetConfigSha256() == want &&
			(after.IsZero() || started.After(after))
		d["container_state"], d["health"], d["config_sha256"] = st.GetContainerState().String(), st.GetHealth().String(), st.GetConfigSha256()
		if ok {
			d["started_at"] = started.Format(time.RFC3339Nano)
			break
		}
		if !c.cfg.Now().Before(deadline) {
			d["waited_s"] = c.cfg.HealthTimeout.Seconds()
			return nil, d, jobs.Permanent("instance_unhealthy", fmt.Errorf("instance not healthy with the new configuration after %s (%s, %s)",
				c.cfg.HealthTimeout, st.GetContainerState(), st.GetHealth()))
		}
		if err := sleep(ctx, c.cfg.HealthPoll); err != nil {
			return nil, d, err
		}
	}
	for {
		err := c.apiHealth(ctx, a.in.TenantID)
		if err == nil {
			d["api_health"] = "ok"
			return last, d, nil
		}
		d["api_health"] = jobs.CodeOf(err)
		if !c.cfg.Now().Before(deadline) {
			d["waited_s"] = c.cfg.HealthTimeout.Seconds()
			return nil, d, jobs.Permanent("instance_unhealthy", fmt.Errorf("GET /api/v1/health did not answer healthy within %s: %w",
				c.cfg.HealthTimeout, err))
		}
		if err := sleep(ctx, c.cfg.HealthPoll); err != nil {
			return nil, d, err
		}
	}
}

// apiHealth is GET /api/v1/health through the adapter (the edge's admin listener): database connectivity required.
func (c *InstanceReconfigurer) apiHealth(ctx context.Context, tenantID uuid.UUID) error {
	cctx, cancel := c.call(ctx)
	defer cancel()
	hs, err := c.cfg.Headscale.ForTenant(cctx, tenantID)
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

// postStartGate is §11.4 Post-start gate: GetPolicy against the applied policy. No policy at all (allow-all — the DB
// was replaced?) ⇒ Critical, the edge detached (flag cleared) and the job fails; a different policy ⇒ High (the
// repair, policy.apply drift_repair, is the policy engine's); none recorded ⇒ not checked.
func (c *InstanceReconfigurer) postStartGate(ctx context.Context, a *rcAttempt, t ReconfigureTarget) (map[string]any, error) {
	pol, found, err := c.cfg.Store.CurrentPolicy(ctx, a.in.TenantID, a.in.InstanceID)
	if err != nil {
		return nil, storeErr("load the applied policy", err)
	}
	if !found {
		return map[string]any{"post_start_gate": "no_applied_policy"}, nil
	}
	cctx, cancel := c.call(ctx)
	defer cancel()
	hs, err := c.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return nil, headscaleErr("ForTenant", err)
	}
	got, err := hs.GetPolicy(cctx)
	if errors.Is(err, headscale.ErrNoPolicy) {
		c.security(ctx, a, SecPolicyMissing, audit.SeverityCritical, "policy_missing:"+a.in.InstanceID.String(),
			audit.Details{"applied_sha256": pol.SHA256})
		if _, derr := c.cfg.Agent.RemoveEdgeAttachment(cctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: t.ref(),
			JobId: a.r.JobID().String(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_POLICY_DRIFT}); derr != nil {
			return map[string]any{"post_start_gate": "no_policy"}, agentErr("RemoveEdgeAttachment", derr)
		}
		return map[string]any{"post_start_gate": "no_policy", "edge_detached": true},
			jobs.Permanent("no_policy", errors.New("the restarted instance has no policy (allow-all): edge detached"))
	}
	if err != nil {
		return nil, headscaleErr("GetPolicy", err)
	}
	sum := sha256.Sum256([]byte(got.Data))
	if hex.EncodeToString(sum[:]) != pol.SHA256 {
		c.security(ctx, a, SecPolicyDrift, audit.SeverityHigh, "policy_drift:"+a.in.InstanceID.String(),
			audit.Details{"applied_sha256": pol.SHA256, "read_sha256": hex.EncodeToString(sum[:])})
		return map[string]any{"post_start_gate": "drift", "applied_sha256": pol.SHA256}, nil
	}
	return map[string]any{"post_start_gate": "ok", "applied_sha256": pol.SHA256}, nil
}

// ---------------------------------------------------------------------------------------------------- 7 edge.verify

func (c *InstanceReconfigurer) stepEdge(ctx context.Context, a *rcAttempt, s stepCtx) error {
	if c.cfg.Prober == nil {
		return detail(s, map[string]any{"probe": "skipped", "reason": "prober_not_configured"})
	}
	t, err := c.target(ctx, a, false)
	if err != nil {
		return err
	}
	if !hexRE.MatchString(t.Instance.NoiseFingerprint) {
		return jobs.Permanent("registry_state", errors.New("no Noise key fingerprint recorded for the instance"))
	}
	cctx, cancel := c.call(ctx)
	defer cancel()
	r, err := c.cfg.Prober.Edge(cctx, EdgeProbe{Address: c.cfg.EdgeAddress, Host: t.Instance.ControlHostname,
		PublicKey: "mkey:" + t.Instance.NoiseFingerprint})
	if err != nil {
		return jobs.Transient("prober_unavailable", fmt.Errorf("edge probe: %w", err))
	}
	if derr := detail(s, map[string]any{"probe": r}); derr != nil {
		return derr
	}
	switch {
	case len(r.Exposed) > 0:
		return jobs.Permanent("edge_exposes_paths", fmt.Errorf("the public listener answers %d forbidden path(s)", len(r.Exposed)))
	case r.KeyMismatch:
		return jobs.Permanent("edge_key_mismatch", errors.New("/key answers another Noise key than the instance's"))
	case !r.OK:
		return jobs.Transient("edge_probe_failed", errors.New("the edge did not answer as expected yet"))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 8 config.apply

func (c *InstanceReconfigurer) stepApply(ctx context.Context, a *rcAttempt, s stepCtx) error {
	vr, err := a.validated(ctx)
	if err != nil {
		return err
	}
	rr, err := a.recorded(ctx)
	if err != nil {
		return err
	}
	if err := c.cfg.Store.ApplyConfig(ctx, ApplyConfigRequest{TenantID: a.in.TenantID, InstanceID: a.in.InstanceID,
		VersionID: rr.VersionID, PreviousVersionID: rr.PreviousVersionID, DERPRegionID: int32(vr.Params.DERPRegionID), //nolint:gosec // 900–999
		Operation: a.in.Operation, Details: audit.Details{"job_id": a.r.JobID(), "instance_id": a.in.InstanceID,
			"tenant_id": a.in.TenantID, "config_version_id": rr.VersionID, "previous_version_id": rr.PreviousVersionID,
			"config_sha256": vr.ConfigSHA256, "previous_config_sha256": vr.PreviousSHA256,
			"changed": changedNames(vr.Changes)}}); err != nil {
		return storeErr("apply the configuration version", err)
	}
	return detail(s, map[string]any{"version_id": rr.VersionID, "status": ConfigApplied,
		"superseded_version_id": rr.PreviousVersionID})
}

// ---------------------------------------------------------------------------------------------------- rollback

// compensate is the rollback (§11.4): in reverse order, the instance restarted on the previous version (written back
// first) and checked healthy, the previous version written back, the new version `failed` and the instance pointing at
// the previous one; then audit .failed + platform.instance.config_rollback. A rollback that fails raises a Critical
// security event; the job ends failed_resumable (compensation_failed) and /rollback resumes it.
func (c *InstanceReconfigurer) compensate(ctx context.Context, r runner, cause error) error {
	a, err := c.input(r)
	if err != nil {
		return err
	}
	fns := map[string]jobs.CompensateFunc{
		RStepRestart: c.retried(a, c.undoRestart),
		RStepWrite:   c.retried(a, c.undoWrite),
		RStepRecord:  c.retried(a, c.undoRecord),
	}
	var written, restarted bool
	var wr recordResources
	if found, ferr := r.StepResources(ctx, RStepWrite, &wr); ferr == nil {
		written = found
	}
	var rs restartResources
	if found, ferr := r.StepResources(ctx, RStepRestart, &rs); ferr == nil {
		restarted = found
	}
	reason := jobs.CodeOf(cause)
	if err := r.CompensateSteps(ctx, fns); err != nil {
		c.rollbackFailed(ctx, a, reason, err, written, restarted)
		return err
	}
	vr, _ := a.validated(ctx)
	details := audit.Details{"job_id": a.r.JobID(), "instance_id": a.in.InstanceID, "tenant_id": a.in.TenantID,
		"rolled_back": true, "config_written": written, "restarted": restarted, "restored_version_id": vr.PreviousVersionID,
		"restored_config_sha256": vr.PreviousSHA256, "failed_version_id": wr.VersionID}
	if err := c.cfg.Store.RecordRollback(ctx, RollbackRecord{TenantID: a.in.TenantID, InstanceID: a.in.InstanceID,
		Operation: a.in.Operation, Reason: reason, Details: details}); err != nil {
		return storeErr("record the rollback", err)
	}
	c.cfg.Logger.Warn("instance.reconfigure rolled back", "tenant_id", a.in.TenantID.String(),
		"instance_id", a.in.InstanceID.String(), "job_id", a.r.JobID().String(), "reason", reason,
		"config_written", written, "restarted", restarted, "alert", true)
	return nil
}

// retried wraps a compensation with the retry policy of the steps.
func (c *InstanceReconfigurer) retried(a *rcAttempt, fn func(ctx context.Context, a *rcAttempt, s jobs.CompensationStep) error) jobs.CompensateFunc {
	return func(ctx context.Context, s jobs.CompensationStep) error {
		for try := 0; ; try++ {
			err := fn(ctx, a, s)
			switch {
			case err == nil:
				return nil
			case jobs.IsPermanent(err), ctx.Err() != nil, try >= c.cfg.StepRetries:
				return err
			}
			if werr := sleep(ctx, c.backoff(try+1)); werr != nil {
				return err
			}
		}
	}
}

// restore writes the previous version back (EnsureInstance(TARGET_PHASE_CONFIG) — idempotent: the files that differ
// only) and returns the target and the sha256 the agent reports.
func (c *InstanceReconfigurer) restore(ctx context.Context, a *rcAttempt) (ReconfigureTarget, string, error) {
	vr, err := a.validated(ctx)
	if err != nil {
		return ReconfigureTarget{}, "", err
	}
	t, err := c.target(ctx, a, false)
	if err != nil {
		return t, "", err
	}
	prev, err := c.cfg.Store.ConfigVersion(ctx, a.in.TenantID, a.in.InstanceID, vr.PreviousVersionID)
	if err != nil {
		return t, "", storeErr("load the previous configuration version", err)
	}
	pp, err := decodeParams(prev.Params)
	if err != nil {
		return t, "", err
	}
	spec, err := pp.spec(t.ref())
	if err != nil {
		return t, "", err
	}
	cctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.cfg.Agent.EnsureInstance(cctx, &agentv1.EnsureInstanceRequest{Spec: spec,
		TargetPhase: agentv1.TargetPhase_TARGET_PHASE_CONFIG, JobId: a.r.JobID().String()})
	if err != nil {
		c.startGuard(ctx, a, "rollback", err)
		return t, "", agentErr("EnsureInstance(config, previous version)", err)
	}
	sha := resp.GetConfigSha256()
	if sha != prev.ConfigSHA256 {
		// The agent's template changed since that version was rendered: the previous parameters are back, with the
		// rendering of the current template (reconcile reports the sha256 against the registry).
		c.cfg.Logger.Warn("instance.reconfigure rollback: the previous version renders another sha256 with the current template",
			"instance_id", a.in.InstanceID.String(), "recorded", prev.ConfigSHA256, "written", sha)
	}
	return t, sha, nil
}

func (c *InstanceReconfigurer) undoWrite(ctx context.Context, a *rcAttempt, _ jobs.CompensationStep) error {
	_, _, err := c.restore(ctx, a)
	return err
}

// undoRestart: the previous version written back, the instance restarted on it and checked healthy (container and
// GET /api/v1/health). A quarantined instance is never started: its files are restored only.
func (c *InstanceReconfigurer) undoRestart(ctx context.Context, a *rcAttempt, _ jobs.CompensationStep) error {
	t, sha, err := c.restore(ctx, a)
	if err != nil {
		return err
	}
	if t.Instance.Status == tenants.InstanceQuarantined {
		c.cfg.Logger.Warn("instance.reconfigure rollback: the instance is quarantined — previous files restored, not restarted",
			"instance_id", a.in.InstanceID.String())
		return nil
	}
	before, err := c.status(ctx, t.ref())
	if err != nil {
		return err
	}
	cctx, cancel := c.call(ctx)
	_, err = c.cfg.Agent.RestartInstance(cctx, &agentv1.RestartInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
	cancel()
	if err != nil {
		c.startGuard(ctx, a, "rollback", err)
		return agentErr("RestartInstance(previous version)", err)
	}
	if _, _, err := c.gate(ctx, a, t, sha, startedAt(before), c.cfg.Now().Add(c.cfg.HealthTimeout)); err != nil {
		return jobs.Permanent("rollback_unhealthy", fmt.Errorf("the previous version did not come back healthy: %w", err))
	}
	return nil
}

func (c *InstanceReconfigurer) undoRecord(ctx context.Context, a *rcAttempt, s jobs.CompensationStep) error {
	var rr recordResources
	if found, err := s.Decode(&rr); err != nil || !found || rr.VersionID == uuid.Nil {
		return err
	}
	if err := c.cfg.Store.RevertConfig(ctx, a.in.TenantID, a.in.InstanceID, rr.VersionID, rr.PreviousVersionID); err != nil {
		return storeErr("mark the configuration version failed", err)
	}
	return nil
}

// rollbackFailed: the previous version may not be in force — a Critical security event and the unpaired audit event
// (outcome failure); the operation stays open until /rollback (or /retry) ends the job.
func (c *InstanceReconfigurer) rollbackFailed(ctx context.Context, a *rcAttempt, reason string, err error, written, restarted bool) {
	code := jobs.CodeOf(err)
	c.cfg.Logger.Error("instance.reconfigure: the rollback failed — the previous configuration may not be in force",
		"tenant_id", a.in.TenantID.String(), "instance_id", a.in.InstanceID.String(), "job_id", a.r.JobID().String(),
		"reason", reason, "code", code, "alert", true)
	d := audit.Details{"job_id": a.r.JobID(), "instance_id": a.in.InstanceID, "tenant_id": a.in.TenantID, "reason": reason,
		"compensation_code": code, "config_written": written, "restarted": restarted}
	c.security(ctx, a, SecRollbackFailed, audit.SeverityCritical, "reconfigure_rollback:"+a.r.JobID().String(), d)
	if rerr := c.cfg.Store.RecordRollback(context.WithoutCancel(ctx), RollbackRecord{TenantID: a.in.TenantID,
		InstanceID: a.in.InstanceID, Operation: a.in.Operation, Reason: code, Failed: true, Details: d}); rerr != nil {
		c.cfg.Logger.Error("instance.reconfigure: the audit event of the failed rollback was not recorded", "error", rerr.Error())
	}
}

// ---------------------------------------------------------------------------------------------------- events

// security records a platform security event (best effort: logged when it cannot be written).
func (c *InstanceReconfigurer) security(ctx context.Context, a *rcAttempt, kind, severity, dedupe string, d audit.Details) {
	c.cfg.Logger.Error("instance.reconfigure: security event", "kind", kind, "severity", severity,
		"tenant_id", a.in.TenantID.String(), "instance_id", a.in.InstanceID.String(), "job_id", a.r.JobID().String(), "alert", true)
	if c.cfg.Security == nil {
		return
	}
	details := audit.Details{"tenant_id": a.in.TenantID, "instance_id": a.in.InstanceID, "job_id": a.r.JobID()}
	for k, v := range d {
		details[k] = v
	}
	if _, err := c.cfg.Security.RecordSecurityEvent(context.WithoutCancel(ctx), audit.SecurityEvent{Kind: kind,
		Severity: severity, Source: "provisioning", Details: details, DedupeKey: dedupe, DedupeWindow: time.Hour}); err != nil {
		c.cfg.Logger.Error("instance.reconfigure: security event not recorded", "kind", kind, "error", err.Error())
	}
}

// startGuard raises the Critical event of a start-guard refusal of the agent (§11.4).
func (c *InstanceReconfigurer) startGuard(ctx context.Context, a *rcAttempt, step string, err error) {
	if startGuardRefusal(err) {
		c.security(ctx, a, "instance.start_guard_failed", audit.SeverityCritical, "start_guard:"+a.in.TenantID.String(),
			audit.Details{"step": step})
	}
}

// logLevels maps the API's log levels to the agent's enum (§11.3 step 8: info, warn, error).
var logLevels = map[string]agentv1.LogLevel{"info": agentv1.LogLevel_LOG_LEVEL_INFO,
	"warn": agentv1.LogLevel_LOG_LEVEL_WARN, "error": agentv1.LogLevel_LOG_LEVEL_ERROR}
