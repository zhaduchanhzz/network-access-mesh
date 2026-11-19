package orchestrator

// Shared machinery of instance.restart and instance.upgrade (P3-T13a, §11.4 rows Restart, Upgrade, Post-start gate;
// §13.5): the collaborators, the retry policy of the steps (§11.3), the health gate after a start, the post-start gate
// with the re-application of a policy changed out of band (policy.apply drift_repair through the policy core), the
// detection of a replaced database (the platform's API key refused — §13.4), the security events, and the closing of
// the operation with the notification of the platform staff.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Job kinds (§13.5: lifecycle group, dedupe instance:<id>:<kind>, compensable — P3-T13a).
const (
	RestartKind = "instance.restart"
	UpgradeKind = "instance.upgrade"
)

// Audit actions of the operations (x-audit-action of the API: .requested → .succeeded / .failed) and of the rollback.
const (
	ActionInstanceRestart = "platform.instance.restart"
	ActionInstanceUpgrade = "platform.instance.upgrade"
	// ActionUpgradeRollback records the rollback of an upgrade by restore (outcome success, or failure).
	ActionUpgradeRollback = "platform.instance.upgrade_rollback"
)

// Security events of the operations (platform scope, details carry tenant_id).
const (
	SecDatabaseReplaced      = "instance.database_replaced"       // Critical: the platform's API key is refused after a start
	SecUpgradeRollbackFailed = "instance.upgrade_rollback_failed" // Critical: the previous image and data are not back
	SecStartGuardFailed      = "instance.start_guard_failed"      // Critical: the agent's start guard refused a start
)

// SourceWave is the source of an upgrade enqueued by `meshguard-worker admin upgrade-wave`.
const SourceWave = "admin_wave"

// Outcomes of a failed operation (notification instance.operation_failed).
const (
	OutcomeRolledBack     = "rolled_back"
	OutcomeRollbackFailed = "rollback_failed"
	OutcomeResumable      = "resumable"
)

// InstanceOpsAgent is the part of the Host Agent the two jobs call — typed RPCs only (§11.1); agentclient.Client
// implements it.
type InstanceOpsAgent interface {
	GetHostInfo(ctx context.Context, in *agentv1.GetHostInfoRequest, opts ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error)
	ValidateConfig(ctx context.Context, in *agentv1.ValidateConfigRequest, opts ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error)
	GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, opts ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error)
	StartInstance(ctx context.Context, in *agentv1.StartInstanceRequest, opts ...grpc.CallOption) (*agentv1.StartInstanceResponse, error)
	StopInstance(ctx context.Context, in *agentv1.StopInstanceRequest, opts ...grpc.CallOption) (*agentv1.StopInstanceResponse, error)
	RestartInstance(ctx context.Context, in *agentv1.RestartInstanceRequest, opts ...grpc.CallOption) (*agentv1.RestartInstanceResponse, error)
	UpgradeInstance(ctx context.Context, in *agentv1.UpgradeInstanceRequest, opts ...grpc.CallOption) (*agentv1.UpgradeInstanceResponse, error)
	InspectImage(ctx context.Context, in *agentv1.InspectImageRequest, opts ...grpc.CallOption) (*agentv1.InspectImageResponse, error)
	PreflightUpgrade(ctx context.Context, in *agentv1.PreflightUpgradeRequest, opts ...grpc.CallOption) (*agentv1.PreflightUpgradeResponse, error)
	RemoveEdgeAttachment(ctx context.Context, in *agentv1.RemoveEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error)
}

// PolicyApplier is the policy core (*policies.Service — P3-T08a): the post-start gate re-applies the applied policy
// with trigger drift_repair (§11.4).
type PolicyApplier interface {
	Apply(ctx context.Context, req policies.ApplyRequest) (policies.Result, error)
	// ApplyDesired renders the desired version (typed — P4-T10) with the tables of now and applies it.
	ApplyDesired(ctx context.Context, req policies.DesiredRequest) (policies.Result, error)
}

var _ PolicyApplier = (*policies.Service)(nil)

// UpgradeBackups is the backup subsystem as the upgrade uses it (P3-T11 — *backup.Service in the worker; the real-Docker
// test drives the agent's Backup/Restore directly).
type UpgradeBackups interface {
	// Ready: an error when backups cannot run here (no agent, no manifest key) — the upgrade stops before any change.
	Ready() error
	ColdBackup(ctx context.Context, jobID, tenantID, instanceID uuid.UUID) (backup.BackupResult, error)
	OpenBackup(ctx context.Context, jobID, tenantID, instanceID, backupID uuid.UUID) (backup.OpenedBackup, error)
	RollbackRestore(ctx context.Context, jobID, tenantID, instanceID, backupID uuid.UUID) (map[string]any, error)
}

var _ UpgradeBackups = (*backup.Service)(nil)

// InstanceOpsConfig are the collaborators and settings of the two handlers.
type InstanceOpsConfig struct {
	Store     InstanceOpsStore
	Agent     InstanceOpsAgent
	Headscale headscale.Registry // the instance over the edge (health, policy, version, smoke); a registry that reaches suspended tenants
	Policies  PolicyApplier      // nil: a policy changed out of band is reported (High), not re-applied
	Backups   UpgradeBackups     // required by instance.upgrade
	Prober    Prober             // nil: edge.verify is recorded skipped
	Security  SecurityRecorder   // nil: security events are only logged
	Logger    *slog.Logger
	// EdgeAddress is the edge's public listener as the prober reaches it (MG_PROVISION_EDGE_ADDR).
	EdgeAddress string

	// Timing (§11.3). Zero values take the defaults (5 retries, 2 s → 60 s, 90 s, 2 s, 2 min, 4 min).
	StepRetries   int
	RetryBase     time.Duration
	RetryMax      time.Duration
	HealthTimeout time.Duration
	HealthPoll    time.Duration
	CallTimeout   time.Duration
	// LongCallTimeout bounds the calls that copy or decrypt the data (cold backup, preflight, restore) — the whole job
	// stays within the lifecycle timeout of 10 minutes.
	LongCallTimeout time.Duration
	Now             func() time.Time
}

func (c *InstanceOpsConfig) defaults() error {
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
	if c.LongCallTimeout == 0 {
		c.LongCallTimeout = 4 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	switch {
	case c.Store == nil || c.Agent == nil || c.Headscale == nil:
		return errors.New("orchestrator: instance operations need a store, the Host Agent and the Headscale registry")
	case c.StepRetries < 0 || c.RetryMax < c.RetryBase:
		return errors.New("orchestrator: invalid retry settings")
	}
	return nil
}

// OpsInput is the input of an instance.restart or instance.upgrade job.
type OpsInput struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	InstanceID uuid.UUID `json:"instance_id"`
	// ImageDigest is the target of an upgrade (sha256:<64 hex>); empty for a restart.
	ImageDigest string     `json:"image_digest,omitempty"`
	Source      string     `json:"source"`
	RequestedBy *uuid.UUID `json:"requested_by,omitempty"`
	// Wave names the upgrade wave that enqueued the job (admin upgrade-wave), empty otherwise.
	Wave string `json:"wave,omitempty"`
	// Operation is the audit operation opened in the transaction that enqueued the job; the job closes it.
	Operation audit.Operation `json:"operation"`
}

func (in OpsInput) validate(kind string) error {
	switch {
	case in.TenantID == uuid.Nil || in.InstanceID == uuid.Nil:
		return errors.New("tenant or instance missing")
	case in.Operation.ID == uuid.Nil:
		return errors.New("audit operation missing")
	case kind == UpgradeKind && !digestRE.MatchString(in.ImageDigest):
		return errors.New("the target image digest is not sha256:<64 hex>")
	case kind == RestartKind && in.ImageDigest != "":
		return errors.New("a restart names no image")
	}
	return nil
}

// instanceOps is the core shared by the two handlers.
type instanceOps struct {
	cfg  InstanceOpsConfig
	kind string
}

// opsAttempt is one attempt: the runner and the input.
type opsAttempt struct {
	r  runner
	in OpsInput
}

func (c *instanceOps) input(r runner) (*opsAttempt, error) {
	a := &opsAttempt{r: r}
	if err := r.Input(&a.in); err != nil {
		return nil, jobs.Permanent("invalid_input", fmt.Errorf("job input unreadable: %w", err))
	}
	if err := a.in.validate(c.kind); err != nil {
		return nil, jobs.Permanent("invalid_input", err)
	}
	return a, nil
}

// step runs one step with the retry policy of §11.3: a transient failure is retried in place StepRetries times with
// backoff, then jobs.Resumable; permanent, resumable and the end of ctx return at once.
func (c *instanceOps) step(ctx context.Context, r runner, name string, fn func(ctx context.Context, s stepCtx) error) error {
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

// retried wraps a compensation with the retry policy of the steps.
func (c *instanceOps) retried(fn func(ctx context.Context, s jobs.CompensationStep) error) jobs.CompensateFunc {
	return func(ctx context.Context, s jobs.CompensationStep) error {
		for try := 0; ; try++ {
			err := fn(ctx, s)
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

// backoff is RetryBase·2^(n−1), capped at RetryMax, ± 20 %.
func (c *instanceOps) backoff(n int) time.Duration {
	d := c.cfg.RetryBase
	for i := 1; i < n && d < c.cfg.RetryMax; i++ {
		d *= 2
	}
	d = min(d, c.cfg.RetryMax)
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // scheduling jitter
}

func (c *instanceOps) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.cfg.CallTimeout)
}

func (c *instanceOps) longCall(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.cfg.LongCallTimeout)
}

// target loads the instance; with runnable, a quarantined instance, one that is not running or a tenant that is not
// active/suspended is refused (permanent: nothing of the instance is touched — §11.4).
func (c *instanceOps) target(ctx context.Context, a *opsAttempt, runnable bool) (ReconfigureTarget, error) {
	t, err := c.cfg.Store.OpsTarget(ctx, a.in.TenantID, a.in.InstanceID)
	if err != nil {
		return t, storeErr("load the instance", err)
	}
	if !runnable {
		return t, nil
	}
	switch {
	case t.Instance.Status == tenants.InstanceQuarantined:
		return t, jobs.Permanent("instance_quarantined", errors.New("the instance is quarantined: no job restarts or upgrades it (§11.4)"))
	case t.Instance.Status != tenants.InstanceRunning:
		return t, jobs.Permanent("instance_not_running", fmt.Errorf("the instance is %s, not running", t.Instance.Status))
	case t.TenantStatus != tenants.StatusActive && t.TenantStatus != tenants.StatusSuspended:
		return t, jobs.Permanent("tenant_state", fmt.Errorf("the tenant is %s", t.TenantStatus))
	}
	return t, nil
}

func (c *instanceOps) status(ctx context.Context, ref *agentv1.InstanceRef) (*agentv1.InstanceStatus, error) {
	cctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.cfg.Agent.GetInstanceStatus(cctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
	if err != nil {
		return nil, agentErr("GetInstanceStatus", err)
	}
	return resp.GetStatus(), nil
}

// invalidate drops the registry's cached target of the tenant (after a start on another image or another database).
func (c *instanceOps) invalidate(tenantID uuid.UUID) {
	if r, ok := c.cfg.Headscale.(interface{ Invalidate(uuid.UUID) }); ok {
		r.Invalidate(tenantID)
	}
}

// ---------------------------------------------------------------------------------------------------- health gate

// gateWant is what the health gate requires of the started container.
type gateWant struct {
	ConfigSHA256 string    // "" ⇒ not checked
	ImageDigest  string    // "" ⇒ not checked
	After        time.Time // zero ⇒ not checked: started after this time (the container that answers is the started one)
}

// gate is the health gate after a start (§11.3 step 11, §11.4): within HealthTimeout the container runs, is healthy and
// is the wanted one (configuration, image, start time); its Noise key is the recorded one; then GET /api/v1/health
// through the adapter answers with database connectivity. The platform's API key refused there ⇒ the database was
// replaced (§13.4): Critical, the edge detached, permanent database_replaced — never waited for.
func (c *instanceOps) gate(ctx context.Context, a *opsAttempt, t ReconfigureTarget, want gateWant) (map[string]any, error) {
	deadline := c.cfg.Now().Add(c.cfg.HealthTimeout)
	d := map[string]any{}
	var last *agentv1.InstanceStatus
	for {
		st, err := c.status(ctx, t.ref())
		if err != nil {
			return d, err
		}
		last = st
		started := startedAt(st)
		ok := st.GetContainerState() == agentv1.ContainerState_CONTAINER_STATE_RUNNING &&
			st.GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY &&
			(want.ConfigSHA256 == "" || st.GetConfigSha256() == want.ConfigSHA256) &&
			(want.ImageDigest == "" || st.GetImageDigest() == want.ImageDigest) &&
			(want.After.IsZero() || started.After(want.After))
		d["container_state"], d["health"], d["config_sha256"], d["image_digest"] = st.GetContainerState().String(),
			st.GetHealth().String(), st.GetConfigSha256(), st.GetImageDigest()
		if ok {
			d["started_at"] = started.Format(time.RFC3339Nano)
			break
		}
		if !c.cfg.Now().Before(deadline) {
			d["waited_s"] = c.cfg.HealthTimeout.Seconds()
			return d, jobs.Permanent("instance_unhealthy", fmt.Errorf("instance not healthy after %s (%s, %s)", c.cfg.HealthTimeout,
				st.GetContainerState(), st.GetHealth()))
		}
		if err := sleep(ctx, c.cfg.HealthPoll); err != nil {
			return d, err
		}
	}
	if fp := last.GetNoiseKeyFingerprint(); fp != "" && t.Instance.NoiseFingerprint != "" && fp != t.Instance.NoiseFingerprint {
		// the start guard should have refused it: another Noise key is another identity of the control plane (RT-06)
		c.security(ctx, a, SecNoiseKeyChanged, audit.SeverityCritical, "noise_key:"+a.in.InstanceID.String(),
			audit.Details{"recorded": t.Instance.NoiseFingerprint, "reported": fp})
		return d, jobs.Permanent("noise_key_changed", errors.New("the started instance reports another Noise key"))
	}
	c.invalidate(a.in.TenantID)
	for {
		err := c.apiHealth(ctx, a.in.TenantID)
		if err == nil {
			d["api_health"] = "ok"
			return d, nil
		}
		if apiKeyRejected(err) {
			d["api_health"] = "api_key_rejected"
			return d, c.databaseReplaced(ctx, a, t, "health")
		}
		d["api_health"] = jobs.CodeOf(err)
		if !c.cfg.Now().Before(deadline) {
			d["waited_s"] = c.cfg.HealthTimeout.Seconds()
			return d, jobs.Permanent("instance_unhealthy", fmt.Errorf("GET /api/v1/health did not answer healthy within %s: %w",
				c.cfg.HealthTimeout, err))
		}
		if err := sleep(ctx, c.cfg.HealthPoll); err != nil {
			return d, err
		}
	}
}

// apiKeyRejected: the instance refused the platform's API key (the adapter reloaded the secret and tried again once).
func apiKeyRejected(err error) bool {
	he, ok := headscale.AsError(err)
	return ok && he.Kind == headscale.KindAPIKeyRejected
}

// apiHealth is GET /api/v1/health through the adapter: database connectivity required. The adapter's own error is
// returned as is (apiKeyRejected inspects it).
func (c *instanceOps) apiHealth(ctx context.Context, tenantID uuid.UUID) error {
	cctx, cancel := c.call(ctx)
	defer cancel()
	hs, err := c.cfg.Headscale.ForTenant(cctx, tenantID)
	if err != nil {
		return err
	}
	h, err := hs.Health(cctx)
	if err != nil {
		return err
	}
	if !h.DatabaseConnectivity {
		return jobs.Transient("instance_unhealthy", errors.New("GET /api/v1/health: no database connectivity"))
	}
	return nil
}

// databaseReplaced is the containment of §11.4 Post-start gate when the instance does not know the platform's API key
// (or serves no policy): Critical security event, the edge_attach flag cleared and the edge detached (the hostname
// answers 404) until an operator restores the instance — never an automatic API key bootstrap (§13.4).
func (c *instanceOps) databaseReplaced(ctx context.Context, a *opsAttempt, t ReconfigureTarget, where string) error {
	c.security(ctx, a, SecDatabaseReplaced, audit.SeverityCritical, "database_replaced:"+a.in.InstanceID.String(),
		audit.Details{"where": where, "edge_detached": true})
	if err := c.detach(ctx, a, t); err != nil {
		return err
	}
	return jobs.Permanent("database_replaced", errors.New("the started instance refuses the platform's API key (database replaced?): edge detached"))
}

func (c *instanceOps) detach(ctx context.Context, a *opsAttempt, t ReconfigureTarget) error {
	cctx, cancel := c.call(context.WithoutCancel(ctx))
	defer cancel()
	if _, err := c.cfg.Agent.RemoveEdgeAttachment(cctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: t.ref(),
		JobId: a.r.JobID().String(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_POLICY_DRIFT}); err != nil {
		return agentErr("RemoveEdgeAttachment", err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- post-start gate

// postStartGate is §11.4 Post-start gate: GetPolicy against the applied policy. The same ⇒ ok. Another policy (changed
// out of band — the database's policy is not the platform's) ⇒ High security event and the applied policy applied
// again at once through the policy core (trigger drift_repair), read back identical — or the gate fails
// (policy_repair_failed). No policy at all (allow-all), or the platform's API key refused ⇒ Critical, the edge detached,
// the gate fails. Nothing recorded ⇒ not checked.
func (c *instanceOps) postStartGate(ctx context.Context, a *opsAttempt, t ReconfigureTarget) (map[string]any, error) {
	pol, found, err := c.cfg.Store.AppliedPolicy(ctx, a.in.TenantID, a.in.InstanceID)
	if err != nil {
		return nil, storeErr("load the applied policy", err)
	}
	if !found {
		return map[string]any{"post_start_gate": "no_applied_policy"}, nil
	}
	got, err := c.readPolicy(ctx, a.in.TenantID)
	switch {
	case errors.Is(err, headscale.ErrNoPolicy):
		c.security(ctx, a, SecPolicyMissing, audit.SeverityCritical, "policy_missing:"+a.in.InstanceID.String(),
			audit.Details{"applied_sha256": pol.SHA256, "edge_detached": true})
		if derr := c.detach(ctx, a, t); derr != nil {
			return map[string]any{"post_start_gate": "no_policy"}, derr
		}
		return map[string]any{"post_start_gate": "no_policy", "edge_detached": true},
			jobs.Permanent("no_policy", errors.New("the started instance has no policy (allow-all): edge detached"))
	case apiKeyRejected(err):
		return map[string]any{"post_start_gate": "api_key_rejected", "edge_detached": true}, c.databaseReplaced(ctx, a, t, "post_start_gate")
	case err != nil:
		return nil, headscaleErr("GetPolicy", err)
	}
	if got == pol.SHA256 {
		return map[string]any{"post_start_gate": "ok", "applied_sha256": pol.SHA256}, nil
	}
	c.security(ctx, a, SecPolicyDrift, audit.SeverityHigh, "policy_drift:"+a.in.InstanceID.String(),
		audit.Details{"applied_sha256": pol.SHA256, "read_sha256": got, "repair": c.cfg.Policies != nil})
	d := map[string]any{"post_start_gate": "drift", "applied_sha256": pol.SHA256, "read_sha256": got}
	if c.cfg.Policies == nil {
		return d, nil // reported only (no policy core in this process)
	}
	var (
		res  policies.Result
		aerr error
	)
	if pol.Kind == policies.KindUser {
		// a version of the policy module (typed, or approved HuJSON — P4-T10): the core applies only platform
		// versions as text; the module renders the desired version again (the instance of a suspended tenant runs the
		// suspension policy, a platform version — never this branch)
		res, aerr = c.cfg.Policies.ApplyDesired(ctx, policies.DesiredRequest{TenantID: a.in.TenantID,
			Trigger: policies.TriggerDriftRepair, Actor: c.kind, Suspended: true})
	} else {
		res, aerr = c.cfg.Policies.Apply(ctx, policies.ApplyRequest{TenantID: a.in.TenantID, Kind: pol.Kind, HuJSON: pol.HuJSON,
			Trigger: policies.TriggerDriftRepair, Actor: c.kind})
	}
	if aerr != nil {
		d["repair"] = "failed"
		return d, jobs.Permanent("policy_repair_failed", fmt.Errorf("the applied policy could not be applied again: %w", aerr))
	}
	again, err := c.readPolicy(ctx, a.in.TenantID)
	if err != nil {
		return d, headscaleErr("GetPolicy", err)
	}
	if again != res.AppliedSHA256 {
		d["repair"] = "read_back_differs"
		return d, jobs.Permanent("policy_repair_failed", errors.New("the policy read back after the repair is not the one applied"))
	}
	d["post_start_gate"], d["repair"], d["repaired_sha256"], d["application_id"] = "repaired", "applied", again, res.ApplicationID
	return d, nil
}

// readPolicy is the sha256 of GetPolicy (the string as Headscale stores it).
func (c *instanceOps) readPolicy(ctx context.Context, tenantID uuid.UUID) (string, error) {
	cctx, cancel := c.call(ctx)
	defer cancel()
	hs, err := c.cfg.Headscale.ForTenant(cctx, tenantID)
	if err != nil {
		return "", err
	}
	p, err := hs.GetPolicy(cctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(p.Data))
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------------------------------- edge.verify

func (c *instanceOps) edgeVerify(ctx context.Context, a *opsAttempt, s stepCtx) error {
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

// ---------------------------------------------------------------------------------------------------- events

// security records a platform security event (best effort: logged when it cannot be written).
func (c *instanceOps) security(ctx context.Context, a *opsAttempt, kind, severity, dedupe string, d audit.Details) {
	c.cfg.Logger.Error(c.kind+": security event", "kind", kind, "severity", severity, "tenant_id", a.in.TenantID.String(),
		"instance_id", a.in.InstanceID.String(), "job_id", a.r.JobID().String(), "alert", true)
	if c.cfg.Security == nil {
		return
	}
	details := audit.Details{"tenant_id": a.in.TenantID, "instance_id": a.in.InstanceID, "job_id": a.r.JobID(), "operation": c.kind}
	for k, v := range d {
		details[k] = v
	}
	if _, err := c.cfg.Security.RecordSecurityEvent(context.WithoutCancel(ctx), audit.SecurityEvent{Kind: kind,
		Severity: severity, Source: "provisioning", Details: details, DedupeKey: dedupe, DedupeWindow: time.Hour}); err != nil {
		c.cfg.Logger.Error(c.kind+": security event not recorded", "kind", kind, "error", err.Error())
	}
}

// startGuard raises the Critical event of a start-guard refusal of the agent (§11.4).
func (c *instanceOps) startGuard(ctx context.Context, a *opsAttempt, step string, err error) {
	if startGuardRefusal(err) {
		c.security(ctx, a, SecStartGuardFailed, audit.SeverityCritical, "start_guard:"+a.in.TenantID.String(),
			audit.Details{"step": step})
	}
}

// fail closes the operation of a failed job (.failed once, the rollback event of an upgrade) and notifies the platform
// staff (instance.operation_failed). Best effort for the notification: logged when it cannot be written.
func (c *instanceOps) fail(ctx context.Context, a *opsAttempt, code, outcome string, d audit.Details, rollbackEvent *bool) error {
	t, terr := c.cfg.Store.OpsTarget(context.WithoutCancel(ctx), a.in.TenantID, a.in.InstanceID)
	slug := ""
	if terr == nil {
		slug = t.TenantSlug
	}
	details := audit.Details{"job_id": a.r.JobID(), "instance_id": a.in.InstanceID, "tenant_id": a.in.TenantID, "outcome": outcome}
	for k, v := range d {
		details[k] = v
	}
	err := c.cfg.Store.FailOperation(context.WithoutCancel(ctx), OpsFailure{TenantID: a.in.TenantID, InstanceID: a.in.InstanceID,
		JobID: a.r.JobID(), Kind: c.kind, Operation: a.in.Operation, Reason: code, Outcome: outcome, TenantSlug: slug,
		Details: details, RollbackEvent: rollbackEvent})
	c.cfg.Logger.Warn(c.kind+" failed", "tenant_id", a.in.TenantID.String(), "instance_id", a.in.InstanceID.String(),
		"job_id", a.r.JobID().String(), "code", code, "outcome", outcome, "alert", true)
	if err != nil {
		return storeErr("record the failure", err)
	}
	return nil
}

// resumable notifies the platform staff of a job that spent its retries (failed_resumable: no compensation, the lock
// held until /retry or /rollback). A cancelled job notifies nobody (the operator asked).
func (c *instanceOps) resumable(ctx context.Context, a *opsAttempt, err error) {
	code := jobs.CodeOf(err)
	if !jobs.IsResumable(err) || code == jobs.CodeCancelled {
		return
	}
	t, terr := c.cfg.Store.OpsTarget(context.WithoutCancel(ctx), a.in.TenantID, a.in.InstanceID)
	slug := ""
	if terr == nil {
		slug = t.TenantSlug
	}
	if nerr := c.cfg.Store.NotifyFailure(context.WithoutCancel(ctx), OpsFailure{TenantID: a.in.TenantID, InstanceID: a.in.InstanceID,
		JobID: a.r.JobID(), Kind: c.kind, Reason: code, Outcome: OutcomeResumable, TenantSlug: slug}); nerr != nil {
		c.cfg.Logger.Error(c.kind+": the notification of a resumable failure was not recorded", "error", nerr.Error())
	}
}
