package orchestrator

// instance.upgrade (P3-T13a, §11.4 row Upgrade, §17.6, T-16): a new Headscale image for a running instance, from the
// allowlist of the Host Agent, rolled back by restore when it does not come up.
//
//	 1 upgrade.preflight   no change yet. Instance running (quarantined ⇒ refused), tenant active/suspended, a
//	                       configuration version recorded; both digests in the agent's allowlist; the versions their
//	                       binaries report (InspectImage — the daemon pulls the target now, before any downtime); the path
//	                       of §11.4 (same minor, patch not lower — equal: another build —, or exactly the next minor;
//	                       HS-04/RT-10) and an adapter for the target version (the contract of internal/headscale); GET
//	                       /version of the running instance = the current image's version; configtest of the target
//	                       binary on the configuration in force (scratch data — the strict syntax gate), its sha256 = the
//	                       version in force (an upgrade changes the image only); CheckPolicy of the applied policy
//	 2 instance.stop       Agent StopInstance                         ⟲ start the previous image again (+ health gates)
//	 3 backup.cold         cold backup (stopped ⇒ cold copy, signed manifest, backups row of this job — P3-T11)
//	 4 upgrade.configtest  Agent PreflightUpgrade: the cold backup decrypted into staging, `headscale configtest` of the
//	                       TARGET binary on that copy (opens and migrates the database, loads the stored policy); the
//	                       live data/ is never mounted — a refusal ends here: the previous image starts on the
//	                       untouched data, job rolled_back
//	 5 image.switch        Agent UpgradeInstance (compare-and-swap, compose.yaml with the target image, container created
//	                       again, not started)                         ⟲ ROLLBACK BY RESTORE: stop, switch back, restore
//	                                                                     the cold backup, edge, checks, health gates
//	 6 instance.start      Agent StartInstance (start guard)
//	 7 instance.health     container running + healthy on the target image with the configuration in force, the same
//	                       Noise key; GET /api/v1/health (API key refused ⇒ database replaced: Critical, edge detached)
//	 8 policy.gate         post-start gate (drift ⇒ applied again; no policy ⇒ Critical, edge detached)
//	 9 upgrade.smoke       GET /version = the target version; contract smoke over the adapter (users, nodes, pre-auth
//	                       keys, API keys — the platform's key valid)
//	10 edge.verify         Prober; none ⇒ skipped
//	11 upgrade.finish      registry: image_digest + headscale_version, a configuration version with the target image
//	                       (same sha256) applied, the previous superseded; audit .succeeded
//
// Failure before the switch ⇒ nothing changed but the downtime; after it ⇒ rollback = restore of the cold backup on the
// previous image (minor versions are not downgraded — RT-10). A rollback that fails ⇒ failed_resumable
// (compensation_failed) + Critical instance.upgrade_rollback_failed; /rollback resumes it. Every failure notifies the
// platform staff (instance.operation_failed).

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// The steps of instance.upgrade, in order.
const (
	UStepPreflight  = "upgrade.preflight"
	UStepStop       = "instance.stop"
	UStepBackup     = "backup.cold"
	UStepConfigtest = "upgrade.configtest"
	UStepSwitch     = "image.switch"
	UStepStart      = "instance.start"
	UStepHealth     = "instance.health"
	UStepPolicy     = "policy.gate"
	UStepSmoke      = "upgrade.smoke"
	UStepEdge       = StepEdgeVerify
	UStepFinish     = "upgrade.finish"
)

// UpgradeSteps lists the steps of instance.upgrade in order.
var UpgradeSteps = []string{UStepPreflight, UStepStop, UStepBackup, UStepConfigtest, UStepSwitch, UStepStart, UStepHealth,
	UStepPolicy, UStepSmoke, UStepEdge, UStepFinish}

// InstanceUpgrader runs instance.upgrade in the worker: jobs.Handler and jobs.Compensator (the rollback).
type InstanceUpgrader struct{ ops *instanceOps }

var (
	_ jobs.Handler     = (*InstanceUpgrader)(nil)
	_ jobs.Compensator = (*InstanceUpgrader)(nil)
)

// NewUpgrader checks the configuration and returns the handler of instance.upgrade.
func NewUpgrader(cfg InstanceOpsConfig) (*InstanceUpgrader, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	if cfg.Backups == nil {
		return nil, errors.New("orchestrator: instance.upgrade needs the backup subsystem (cold backup, rollback by restore)")
	}
	return &InstanceUpgrader{ops: &instanceOps{cfg: cfg, kind: UpgradeKind}}, nil
}

// Register registers the handler of instance.upgrade on the worker.
func (c *InstanceUpgrader) Register(w *jobs.Worker) error { return w.Register(UpgradeKind, c) }

// Run implements jobs.Handler.
func (c *InstanceUpgrader) Run(ctx context.Context, run *jobs.Run) error {
	return c.run(ctx, jobRunner{run})
}

// Compensate implements jobs.Compensator: the rollback (and /rollback of a failed_resumable job).
func (c *InstanceUpgrader) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return c.compensate(ctx, jobRunner{run}, cause)
}

// RunAttempt / CompensateAttempt drive the same state machine on an in-memory JobRunner (the real-Docker test).
func (c *InstanceUpgrader) RunAttempt(ctx context.Context, r JobRunner) error { return c.run(ctx, r) }

// CompensateAttempt runs the rollback on r after cause.
func (c *InstanceUpgrader) CompensateAttempt(ctx context.Context, r JobRunner, cause error) error {
	return c.compensate(ctx, r, cause)
}

// preflightResources is created_resources of upgrade.preflight: everything later steps and the rollback need, decided
// once (a resumed job never re-decides the path or the parameters).
type preflightResources struct {
	Unchanged         bool         `json:"unchanged,omitempty"`
	FromDigest        string       `json:"from_digest"`
	FromVersion       string       `json:"from_version"`
	ToDigest          string       `json:"to_digest"`
	ToVersion         string       `json:"to_version"`
	Path              string       `json:"path"`
	ConfigVersionID   uuid.UUID    `json:"config_version_id"`
	ConfigSHA256      string       `json:"config_sha256"`
	TemplateVersion   string       `json:"template_version"`
	Params            configParams `json:"params"` // the version in force — the previous image
	NewConfigVersion  uuid.UUID    `json:"new_config_version_id"`
	AppliedPolicySHA  string       `json:"applied_policy_sha256,omitempty"`
	PolicyCheckResult string       `json:"policy_check,omitempty"`
}

func (p preflightResources) spec(ref *agentv1.InstanceRef, digest string) (*agentv1.InstanceSpec, error) {
	q := p.Params
	q.Nameservers = slices.Clone(p.Params.Nameservers)
	q.ImageDigest = digest
	return q.spec(ref)
}

type stoppedResources struct {
	Stopped bool `json:"stopped"`
}

type backupResources struct {
	BackupID       uuid.UUID `json:"backup_id"`
	Sequence       uint64    `json:"sequence"`
	ArchiveSHA256  string    `json:"archive_sha256"`
	ManifestSHA256 string    `json:"manifest_sha256"`
}

type switchResources struct {
	Switched bool `json:"switched"`
}

// startResources: the target image was asked to start (the target binary may have opened — and migrated — the live
// data: the rollback is then a restore).
type startResources struct {
	Started bool `json:"started"`
}

func (c *InstanceUpgrader) run(ctx context.Context, r runner) error {
	o := c.ops
	a, err := o.input(r)
	if err != nil {
		return err
	}
	r.SetResource("instance", a.in.InstanceID.String())
	err = c.steps(ctx, a)
	if err != nil {
		o.resumable(ctx, a, err)
		return err
	}
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	out := map[string]any{"tenant_id": a.in.TenantID, "instance_id": a.in.InstanceID, "changed": !pf.Unchanged,
		"image_digest": a.in.ImageDigest}
	if !pf.Unchanged {
		out["previous_image_digest"], out["headscale_version"], out["previous_headscale_version"], out["path"] = pf.FromDigest,
			pf.ToVersion, pf.FromVersion, pf.Path
		out["config_version_id"] = pf.NewConfigVersion
	}
	return r.SetOutput(out)
}

func (c *InstanceUpgrader) steps(ctx context.Context, a *opsAttempt) error {
	o, r := c.ops, a.r
	if err := o.step(ctx, r, UStepPreflight, func(ctx context.Context, s stepCtx) error { return c.stepPreflight(ctx, a, s) }); err != nil {
		return err
	}
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	if pf.Unchanged {
		return o.step(ctx, r, UStepFinish, func(ctx context.Context, s stepCtx) error {
			if err := o.cfg.Store.FinishOperation(ctx, a.in.Operation, audit.Details{"job_id": a.r.JobID(), "instance_id": a.in.InstanceID,
				"tenant_id": a.in.TenantID, "changed": false, "image_digest": a.in.ImageDigest}); err != nil {
				return storeErr("close the audit operation", err)
			}
			return detail(s, map[string]any{"changed": false, "reason": "already_on_target"})
		})
	}
	for _, st := range []struct {
		name string
		fn   func(ctx context.Context, a *opsAttempt, s stepCtx) error
	}{
		{UStepStop, c.stepStop}, {UStepBackup, c.stepBackup}, {UStepConfigtest, c.stepConfigtest}, {UStepSwitch, c.stepSwitch},
		{UStepStart, c.stepStart}, {UStepHealth, c.stepHealth}, {UStepPolicy, c.stepPolicy}, {UStepSmoke, c.stepSmoke},
		{UStepEdge, func(ctx context.Context, a *opsAttempt, s stepCtx) error { return o.edgeVerify(ctx, a, s) }},
		{UStepFinish, c.stepFinish},
	} {
		if err := o.step(ctx, r, st.name, func(ctx context.Context, s stepCtx) error { return st.fn(ctx, a, s) }); err != nil {
			return err
		}
	}
	return nil
}

// preflight reads what upgrade.preflight decided.
func (c *InstanceUpgrader) preflight(ctx context.Context, a *opsAttempt) (preflightResources, error) {
	var pf preflightResources
	found, err := a.r.StepResources(ctx, UStepPreflight, &pf)
	if err != nil {
		return pf, err
	}
	if !found || (!pf.Unchanged && (!digestRE.MatchString(pf.FromDigest) || pf.ToDigest != a.in.ImageDigest || !hexRE.MatchString(pf.ConfigSHA256))) {
		return pf, jobs.Permanent("invalid_state", errors.New("upgrade.preflight recorded no decision"))
	}
	return pf, nil
}

// ---------------------------------------------------------------------------------------------------- 1 preflight

func (c *InstanceUpgrader) stepPreflight(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	t, err := o.target(ctx, a, true)
	if err != nil {
		return err
	}
	to := a.in.ImageDigest
	if t.Instance.ImageDigest == to {
		if err := record(ctx, s, preflightResources{Unchanged: true, FromDigest: to, ToDigest: to}); err != nil {
			return err
		}
		return detail(s, map[string]any{"unchanged": true, "image_digest": to})
	}
	if t.Current == nil {
		return jobs.Permanent("no_config_version", errors.New("the instance has no configuration version (built by hand — P3-T14b)"))
	}
	if err := o.cfg.Backups.Ready(); err != nil {
		return err // backup_not_configured / agent_not_configured: no cold backup, no upgrade — nothing stopped
	}
	params, err := decodeParams(t.Current.Params)
	if err != nil {
		return err
	}
	if params.ImageDigest != "" && params.ImageDigest != t.Instance.ImageDigest {
		return jobs.Permanent("registry_state", errors.New("the configuration version in force names another image than the registry"))
	}
	params.ImageDigest = t.Instance.ImageDigest
	d := map[string]any{"from_digest": t.Instance.ImageDigest, "to_digest": to, "config_version_id": t.Current.ID}
	fail := func(code string, err error) error {
		d["refused"] = code
		_ = detail(s, d)
		return jobs.Permanent(code, err)
	}
	// both images in the agent's allowlist (it stays the authority — §11.1)
	cctx, cancel := o.call(ctx)
	hi, err := o.cfg.Agent.GetHostInfo(cctx, &agentv1.GetHostInfoRequest{})
	cancel()
	if err != nil {
		return agentErr("GetHostInfo", err)
	}
	allowed := map[string]bool{}
	for _, img := range hi.GetAllowedImages() {
		allowed[img.GetDigest()] = true
	}
	if !allowed[to] || !allowed[t.Instance.ImageDigest] {
		return fail("image_not_allowed", errors.New("the target or the current image is not in the Host Agent's allowlist"))
	}
	from, err := c.inspect(ctx, a, t, t.Instance.ImageDigest)
	if err != nil {
		return err
	}
	target, err := c.inspect(ctx, a, t, to)
	if err != nil {
		return err
	}
	d["from_version"], d["to_version"] = from.GetHeadscaleVersion(), target.GetHeadscaleVersion()
	path, err := backupfmt.UpgradePath(from.GetHeadscaleVersion(), target.GetHeadscaleVersion())
	if err != nil {
		return fail("version_path_refused", err)
	}
	d["path"] = path
	if _, err := headscale.CheckSupported(target.GetHeadscaleVersion()); err != nil {
		return fail("version_unsupported", err)
	}
	// the instance runs what the registry says (GET /version through the adapter)
	running, err := c.runningVersion(ctx, a)
	if err != nil {
		return err
	}
	if !sameVersion(running, from.GetHeadscaleVersion()) {
		d["running_version"] = running
		return fail("version_mismatch", fmt.Errorf("the instance reports %s, its image %s", running, from.GetHeadscaleVersion()))
	}
	// configtest of the target binary on the configuration in force (scratch data): the strict syntax gate
	spec, err := (preflightResources{Params: params}).spec(t.ref(), to)
	if err != nil {
		return err
	}
	cctx, cancel = o.call(ctx)
	v, err := o.cfg.Agent.ValidateConfig(cctx, &agentv1.ValidateConfigRequest{Spec: spec, JobId: a.r.JobID().String()})
	cancel()
	if err != nil {
		return agentErr("ValidateConfig", err)
	}
	if !v.GetValid() {
		d["exit_code"], d["configtest"] = v.GetExitCode(), v.GetDetail()
		return fail("config_invalid", fmt.Errorf("configtest of the target image refused the configuration in force (exit %d)", v.GetExitCode()))
	}
	if v.GetConfigSha256() != t.Current.ConfigSHA256 {
		d["config_sha256"] = v.GetConfigSha256()
		return fail("config_drift", errors.New("the configuration in force renders another sha256 today: reconfigure first, then upgrade"))
	}
	// CheckPolicy of the applied policy (canonical rendering — as instance.reconfigure)
	res := preflightResources{FromDigest: t.Instance.ImageDigest, FromVersion: from.GetHeadscaleVersion(), ToDigest: to,
		ToVersion: target.GetHeadscaleVersion(), Path: path, ConfigVersionID: t.Current.ID, ConfigSHA256: t.Current.ConfigSHA256,
		TemplateVersion: t.Current.TemplateVersion, Params: params}
	pol, found, err := o.cfg.Store.AppliedPolicy(ctx, a.in.TenantID, a.in.InstanceID)
	if err != nil {
		return storeErr("load the applied policy", err)
	}
	if found {
		res.AppliedPolicySHA = pol.SHA256
		if code, err := c.checkPolicy(ctx, a, pol); err != nil {
			if code != "" {
				return fail(code, err)
			}
			return err
		}
		res.PolicyCheckResult = "ok"
	}
	var prev preflightResources
	if found, err := s.Previous(&prev); err != nil {
		return err
	} else if found && prev.NewConfigVersion != uuid.Nil {
		res.NewConfigVersion = prev.NewConfigVersion
	} else if res.NewConfigVersion, err = uuid.NewV7(); err != nil {
		return jobs.Transient("internal", err)
	}
	if err := record(ctx, s, res); err != nil {
		return err
	}
	d["config_sha256"], d["policy_check"] = res.ConfigSHA256, res.PolicyCheckResult
	return detail(s, d)
}

func (c *InstanceUpgrader) inspect(ctx context.Context, a *opsAttempt, t ReconfigureTarget, digest string) (*agentv1.InspectImageResponse, error) {
	cctx, cancel := c.ops.longCall(ctx)
	defer cancel()
	r, err := c.ops.cfg.Agent.InspectImage(cctx, &agentv1.InspectImageRequest{Instance: t.ref(), JobId: a.r.JobID().String(),
		ImageDigest: digest})
	if err != nil {
		return nil, agentErr("InspectImage", err)
	}
	return r, nil
}

func (c *InstanceUpgrader) runningVersion(ctx context.Context, a *opsAttempt) (string, error) {
	cctx, cancel := c.ops.call(ctx)
	defer cancel()
	hs, err := c.ops.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return "", headscaleErr("ForTenant", err)
	}
	v, err := hs.Version(cctx)
	if err != nil {
		return "", headscaleErr("Version", err)
	}
	return v, nil
}

// sameVersion compares two release versions ("v0.29.7" = "0.29.7"; build metadata ignored).
func sameVersion(a, b string) bool {
	va, oka := backupfmt.ParseVersion(a)
	vb, okb := backupfmt.ParseVersion(b)
	return oka && okb && va == vb
}

// checkPolicy is CheckPolicy of the applied policy (canonical rendering of the policy core) on the running instance: a
// refusal returns its stable code (the upgrade stops before anything changes).
func (c *InstanceUpgrader) checkPolicy(ctx context.Context, a *opsAttempt, pol PolicyInForce) (string, error) {
	o := c.ops
	doc, lerr := policies.Lint(pol.HuJSON)
	if lerr != nil {
		o.security(ctx, a, SecPolicyCheckFailed, audit.SeverityHigh, "policy_check:"+a.in.InstanceID.String(),
			audit.Details{"applied_sha256": pol.SHA256, "kind": "lint"})
		return "policy_check_failed", fmt.Errorf("the applied policy does not pass the lint: %w", lerr)
	}
	cctx, cancel := o.call(ctx)
	defer cancel()
	hs, err := o.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return "", headscaleErr("ForTenant", err)
	}
	if err := hs.CheckPolicy(cctx, doc.Applied); err != nil {
		if he, ok := headscale.AsError(err); ok && (he.Kind == headscale.KindPolicyRejected ||
			he.Kind == headscale.KindValidation || he.Kind == headscale.KindUpstreamRejected) {
			o.security(ctx, a, SecPolicyCheckFailed, audit.SeverityHigh, "policy_check:"+a.in.InstanceID.String(),
				audit.Details{"applied_sha256": pol.SHA256, "kind": string(he.Kind)})
			return "policy_check_failed", errors.New("the applied policy does not pass CheckPolicy: the upgrade is not started")
		}
		return "", headscaleErr("CheckPolicy", err)
	}
	return "", nil
}

// ---------------------------------------------------------------------------------------------------- 2–4 stop, backup, preflight

func (c *InstanceUpgrader) stepStop(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	t, err := o.target(ctx, a, true)
	if err != nil {
		return err
	}
	if err := record(ctx, s, stoppedResources{Stopped: true}); err != nil { // BEFORE: the rollback starts it again
		return err
	}
	cctx, cancel := o.call(ctx)
	defer cancel()
	resp, err := o.cfg.Agent.StopInstance(cctx, &agentv1.StopInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
	if err != nil {
		return agentErr("StopInstance", err)
	}
	return detail(s, map[string]any{"container_state": resp.GetStatus().GetContainerState().String()})
}

func (c *InstanceUpgrader) stepBackup(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	var prev backupResources
	if found, err := s.Previous(&prev); err != nil {
		return err
	} else if found && prev.BackupID != uuid.Nil {
		return detail(s, map[string]any{"backup_id": prev.BackupID, "sequence": prev.Sequence, "reused": true})
	}
	cctx, cancel := o.longCall(ctx)
	defer cancel()
	res, err := o.cfg.Backups.ColdBackup(cctx, a.r.JobID(), a.in.TenantID, a.in.InstanceID)
	if err != nil {
		return err
	}
	br := backupResources{BackupID: res.BackupID, Sequence: res.Sequence, ArchiveSHA256: res.ArchiveSHA256, ManifestSHA256: res.ManifestSHA256}
	if err := record(ctx, s, br); err != nil {
		return err
	}
	return detail(s, map[string]any{"backup_id": res.BackupID, "sequence": res.Sequence, "method": res.Method,
		"size_bytes": res.SizeBytes, "archive_sha256": res.ArchiveSHA256})
}

func (c *InstanceUpgrader) backupOf(ctx context.Context, a *opsAttempt) (backupResources, error) {
	var b backupResources
	found, err := a.r.StepResources(ctx, UStepBackup, &b)
	if err != nil {
		return b, err
	}
	if !found || b.BackupID == uuid.Nil {
		return b, jobs.Permanent("invalid_state", errors.New("backup.cold recorded no backup"))
	}
	return b, nil
}

func (c *InstanceUpgrader) stepConfigtest(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	b, err := c.backupOf(ctx, a)
	if err != nil {
		return err
	}
	t, err := o.target(ctx, a, false)
	if err != nil {
		return err
	}
	spec, err := pf.spec(t.ref(), pf.ToDigest)
	if err != nil {
		return err
	}
	cctx, cancel := o.longCall(ctx)
	defer cancel()
	ob, err := o.cfg.Backups.OpenBackup(cctx, a.r.JobID(), a.in.TenantID, a.in.InstanceID, b.BackupID)
	if err != nil {
		return err
	}
	defer clear(ob.DataKey)
	resp, err := o.cfg.Agent.PreflightUpgrade(cctx, &agentv1.PreflightUpgradeRequest{Spec: spec, JobId: a.r.JobID().String(),
		FromImageDigest: pf.FromDigest, Artifact: ob.Artifact, DataKey: ob.DataKey})
	if err != nil {
		return agentErr("PreflightUpgrade", err)
	}
	d := map[string]any{"valid": resp.GetValid(), "exit_code": resp.GetExitCode(), "backup_headscale_version": resp.GetBackupHeadscaleVersion(),
		"target_headscale_version": resp.GetTargetHeadscaleVersion(), "backup_id": b.BackupID}
	if resp.GetDetail() != "" {
		d["configtest"] = resp.GetDetail()
	}
	if derr := detail(s, d); derr != nil {
		return derr
	}
	switch {
	case !resp.GetValid():
		return jobs.Permanent("preflight_failed", fmt.Errorf("configtest of the target image refused a copy of the data (exit %d): the previous image starts again",
			resp.GetExitCode()))
	case resp.GetConfigSha256() != pf.ConfigSHA256:
		return jobs.Permanent("config_drift", errors.New("the preflight rendered another configuration than the one in force"))
	case !sameVersion(resp.GetTargetHeadscaleVersion(), pf.ToVersion):
		return jobs.Permanent("version_mismatch", errors.New("the target image reports another version than at the preflight"))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 5–9 switch, start, gates

func (c *InstanceUpgrader) stepSwitch(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	t, err := o.target(ctx, a, true) // a quarantined instance is never switched or started
	if err != nil {
		return err
	}
	spec, err := pf.spec(t.ref(), pf.ToDigest)
	if err != nil {
		return err
	}
	if err := record(ctx, s, switchResources{Switched: true}); err != nil { // BEFORE: the rollback restores
		return err
	}
	cctx, cancel := o.call(ctx)
	defer cancel()
	resp, err := o.cfg.Agent.UpgradeInstance(cctx, &agentv1.UpgradeInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String(),
		FromImageDigest: pf.FromDigest, ToImageDigest: pf.ToDigest, Spec: spec})
	if err != nil {
		return agentErr("UpgradeInstance", err)
	}
	return detail(s, map[string]any{"image_digest": resp.GetStatus().GetImageDigest(),
		"container_state": resp.GetStatus().GetContainerState().String()})
}

func (c *InstanceUpgrader) stepStart(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	t, err := o.target(ctx, a, true)
	if err != nil {
		return err
	}
	if err := record(ctx, s, startResources{Started: true}); err != nil { // BEFORE: from here the rollback restores
		return err
	}
	cctx, cancel := o.call(ctx)
	defer cancel()
	resp, err := o.cfg.Agent.StartInstance(cctx, &agentv1.StartInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
	if err != nil {
		o.startGuard(ctx, a, UStepStart, err)
		return agentErr("StartInstance", err)
	}
	return detail(s, map[string]any{"container_state": resp.GetStatus().GetContainerState().String(),
		"image_digest": resp.GetStatus().GetImageDigest()})
}

func (c *InstanceUpgrader) stepHealth(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	t, err := o.target(ctx, a, false)
	if err != nil {
		return err
	}
	d, err := o.gate(ctx, a, t, gateWant{ConfigSHA256: pf.ConfigSHA256, ImageDigest: pf.ToDigest})
	_ = detail(s, d)
	return err
}

func (c *InstanceUpgrader) stepPolicy(ctx context.Context, a *opsAttempt, s stepCtx) error {
	t, err := c.ops.target(ctx, a, false)
	if err != nil {
		return err
	}
	d, err := c.ops.postStartGate(ctx, a, t)
	_ = detail(s, d)
	return err
}

// stepSmoke — §11.4: GET /version is the target's version, then the contract smoke through the adapter: the reads every
// later job relies on answer (users, nodes, pre-auth keys) and the platform's API key is the one valid key.
func (c *InstanceUpgrader) stepSmoke(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	t, err := o.target(ctx, a, false)
	if err != nil {
		return err
	}
	cctx, cancel := o.call(ctx)
	defer cancel()
	hs, err := o.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return headscaleErr("ForTenant", err)
	}
	d := map[string]any{}
	smoke := func(name string, fn func() (int, error)) error {
		n, err := fn()
		if err != nil {
			d[name] = jobs.CodeOf(headscaleErr(name, err))
			_ = detail(s, d)
			if he, ok := headscale.AsError(err); ok && (he.Kind == headscale.KindUnavailable || he.Kind == headscale.KindCircuitOpen) {
				return headscaleErr(name, err)
			}
			return jobs.Permanent("contract_smoke_failed", fmt.Errorf("%s through the adapter failed on the new version: %w", name, err))
		}
		d[name] = n
		return nil
	}
	v, err := hs.Version(cctx)
	if err != nil {
		return headscaleErr("Version", err)
	}
	d["version"] = v
	if !sameVersion(v, pf.ToVersion) {
		_ = detail(s, d)
		return jobs.Permanent("version_mismatch", fmt.Errorf("GET /version reports %s, want %s", v, pf.ToVersion))
	}
	steps := []struct {
		name string
		fn   func() (int, error)
	}{
		{"users", func() (int, error) { u, err := hs.ListUsers(cctx, headscale.UserFilter{}); return len(u), err }},
		{"nodes", func() (int, error) { n, err := hs.ListNodes(cctx, ""); return len(n), err }},
		{"preauth_keys", func() (int, error) { k, err := hs.ListPreAuthKeys(cctx); return len(k), err }},
		{"api_keys", func() (int, error) {
			keys, err := hs.ListAPIKeys(cctx)
			if err != nil {
				return 0, err
			}
			now := o.cfg.Now()
			for _, k := range keys {
				if k.Prefix == t.Instance.APIKeyPrefix && (k.Expiration.IsZero() || k.Expiration.After(now)) {
					return len(keys), nil
				}
			}
			return len(keys), errors.New("the platform's API key is not a valid key of the instance")
		}},
	}
	for _, st := range steps {
		if err := smoke(st.name, st.fn); err != nil {
			return err
		}
	}
	return detail(s, d)
}

// ---------------------------------------------------------------------------------------------------- 11 finish

func (c *InstanceUpgrader) stepFinish(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	params := pf.Params
	params.ImageDigest = pf.ToDigest
	if err := o.cfg.Store.FinishUpgrade(ctx, UpgradeFinish{TenantID: a.in.TenantID, InstanceID: a.in.InstanceID,
		PreviousVersionID: pf.ConfigVersionID, Version: NewConfigVersion{ID: pf.NewConfigVersion, TemplateVersion: templateNumber(pf.TemplateVersion),
			ConfigSHA256: pf.ConfigSHA256, Params: params, CreatedBy: a.in.RequestedBy},
		ImageDigest: pf.ToDigest, HeadscaleVersion: pf.ToVersion, Operation: a.in.Operation,
		Details: audit.Details{"job_id": a.r.JobID(), "instance_id": a.in.InstanceID, "tenant_id": a.in.TenantID, "changed": true,
			"image_digest": pf.ToDigest, "previous_image_digest": pf.FromDigest, "headscale_version": pf.ToVersion,
			"previous_headscale_version": pf.FromVersion, "path": pf.Path, "config_version_id": pf.NewConfigVersion,
			"wave": a.in.Wave}}); err != nil {
		return storeErr("record the upgrade", err)
	}
	c.ops.invalidate(a.in.TenantID)
	return detail(s, map[string]any{"image_digest": pf.ToDigest, "headscale_version": pf.ToVersion,
		"config_version_id": pf.NewConfigVersion})
}

// templateNumber reads a template version recorded as text ("2").
func templateNumber(s string) uint32 {
	var n uint32
	if _, err := fmt.Sscan(s, &n); err != nil {
		return 0
	}
	return n
}

// ---------------------------------------------------------------------------------------------------- rollback

// compensate is the rollback (§11.4): after the switch, ROLLBACK BY RESTORE — the instance stopped, the previous image
// switched back, the cold backup restored (policy set offline first, PostRestoreReconcile, the edge, the checks over the
// API), then the health gates on the previous image; before the switch, the previous image started again on the
// untouched data. Then audit .failed (+ platform.instance.upgrade_rollback when restored) and the notification of the
// platform staff. A rollback that fails ⇒ Critical, operation left open, failed_resumable (compensation_failed).
func (c *InstanceUpgrader) compensate(ctx context.Context, r runner, cause error) error {
	o := c.ops
	a, err := o.input(r)
	if err != nil {
		return err
	}
	var sw switchResources
	switched, _ := r.StepResources(ctx, UStepSwitch, &sw)
	switched = switched && sw.Switched
	var st startResources
	started, _ := r.StepResources(ctx, UStepStart, &st)
	restored := switched && started && st.Started // the rollback is a restore (the target binary ran on the data)
	fns := map[string]jobs.CompensateFunc{
		UStepSwitch: o.retried(func(ctx context.Context, _ jobs.CompensationStep) error { return c.undoSwitch(ctx, a) }),
		UStepStop:   o.retried(func(ctx context.Context, _ jobs.CompensationStep) error { return c.undoStop(ctx, a) }),
	}
	reason := jobs.CodeOf(cause)
	if err := r.CompensateSteps(ctx, fns); err != nil {
		code := jobs.CodeOf(err)
		o.cfg.Logger.Error("instance.upgrade: the rollback failed — the previous image and data may not be back",
			"tenant_id", a.in.TenantID.String(), "instance_id", a.in.InstanceID.String(), "job_id", a.r.JobID().String(),
			"reason", reason, "code", code, "alert", true)
		o.security(ctx, a, SecUpgradeRollbackFailed, audit.SeverityCritical, "upgrade_rollback:"+a.r.JobID().String(),
			audit.Details{"reason": reason, "compensation_code": code, "switched": switched})
		failed := false
		if ferr := o.fail(ctx, a, code, OutcomeRollbackFailed, audit.Details{"reason": reason, "switched": switched}, &failed); ferr != nil {
			o.cfg.Logger.Error("instance.upgrade: the failed rollback was not recorded", "error", ferr.Error())
		}
		return err
	}
	ok := true
	var rollback *bool
	if switched {
		rollback = &ok
	}
	return o.fail(ctx, a, reason, OutcomeRolledBack, audit.Details{"switched_back": switched, "restored": restored,
		"rolled_back": true}, rollback)
}

// undoSwitch — the rollback by restore (§11.4: dừng → restore backup → image cũ → start).
func (c *InstanceUpgrader) undoSwitch(ctx context.Context, a *opsAttempt) error {
	o := c.ops
	pf, err := c.preflight(ctx, a)
	if err != nil {
		return err
	}
	b, err := c.backupOf(ctx, a)
	if err != nil {
		return err
	}
	t, err := o.target(ctx, a, false)
	if err != nil {
		return err
	}
	if t.Instance.Status == tenants.InstanceQuarantined {
		// a quarantined instance is never started (§11.4): its data and files stay for the investigation
		o.cfg.Logger.Warn("instance.upgrade rollback: the instance is quarantined — not restored, not started",
			"instance_id", a.in.InstanceID.String())
		return nil
	}
	cctx, cancel := o.call(ctx)
	_, err = o.cfg.Agent.StopInstance(cctx, &agentv1.StopInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
	cancel()
	if err != nil {
		return agentErr("StopInstance", err)
	}
	spec, err := pf.spec(t.ref(), pf.FromDigest)
	if err != nil {
		return err
	}
	cctx, cancel = o.call(ctx)
	_, err = o.cfg.Agent.UpgradeInstance(cctx, &agentv1.UpgradeInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String(),
		FromImageDigest: pf.ToDigest, ToImageDigest: pf.FromDigest, Spec: spec})
	cancel()
	if err != nil {
		return agentErr("UpgradeInstance(previous image)", err)
	}
	var st startResources
	if found, err := a.r.StepResources(ctx, UStepStart, &st); err != nil {
		return err
	} else if !found || !st.Started {
		// the target image never started: the live data was never opened by it — the previous image starts on it
		cctx, cancel = o.call(ctx)
		_, err = o.cfg.Agent.StartInstance(cctx, &agentv1.StartInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
		cancel()
		if err != nil {
			o.startGuard(ctx, a, "rollback", err)
			return agentErr("StartInstance(previous image)", err)
		}
	} else {
		lctx, lcancel := o.longCall(ctx)
		_, err = o.cfg.Backups.RollbackRestore(lctx, a.r.JobID(), a.in.TenantID, a.in.InstanceID, b.BackupID)
		lcancel()
		if err != nil {
			return err
		}
	}
	if _, err := o.gate(ctx, a, t, gateWant{ConfigSHA256: pf.ConfigSHA256, ImageDigest: pf.FromDigest}); err != nil {
		return jobs.Permanent("rollback_unhealthy", fmt.Errorf("the previous image did not come back healthy: %w", err))
	}
	if _, err := o.postStartGate(ctx, a, t); err != nil {
		return err
	}
	return nil
}

// undoStop — before the switch: the previous image started again on the untouched data, behind the health gates. After
// the switch the restore started it already (undoSwitch) — nothing to do here then.
func (c *InstanceUpgrader) undoStop(ctx context.Context, a *opsAttempt) error {
	o := c.ops
	var sw switchResources
	if found, err := a.r.StepResources(ctx, UStepSwitch, &sw); err != nil {
		return err
	} else if found && sw.Switched {
		return nil
	}
	t, err := o.target(ctx, a, false)
	if err != nil {
		return err
	}
	if t.Instance.Status == tenants.InstanceQuarantined {
		o.cfg.Logger.Warn("instance.upgrade rollback: the instance is quarantined — not started again", "instance_id", a.in.InstanceID.String())
		return nil
	}
	cctx, cancel := o.call(ctx)
	_, err = o.cfg.Agent.StartInstance(cctx, &agentv1.StartInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
	cancel()
	if err != nil {
		o.startGuard(ctx, a, "rollback", err)
		return agentErr("StartInstance(previous image)", err)
	}
	want := gateWant{ImageDigest: t.Instance.ImageDigest}
	if t.Current != nil {
		want.ConfigSHA256 = t.Current.ConfigSHA256
	}
	if _, err := o.gate(ctx, a, t, want); err != nil {
		return jobs.Permanent("rollback_unhealthy", fmt.Errorf("the previous image did not come back healthy: %w", err))
	}
	if _, err := o.postStartGate(ctx, a, t); err != nil {
		return err
	}
	return nil
}
