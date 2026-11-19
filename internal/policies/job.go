package policies

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// The policy.apply job (§13.5 — level-triggered: its input names the reason, never a policy; the handler reads the
// desired state when it runs). ONE handler (P4-T09 + P4-T15, full pipeline P4-T10) for every reason a tenant's policy
// is applied again: the tag catalog (tag_change), the groups (group_change — internal/members), the resources
// (resource_change — P4-T12), an apply or a rollback of a version (manual, rollback — the policies API), a drift
// (drift_repair — the drift check) and the suspension of the tenant (suspend — enqueued in the transaction of the
// suspend request, so the deny-all policy does not wait for the lifecycle lock — §11.4). Changes made while a job is
// queued are carried by that job (dedupe key tenant:<id>:policy.apply — the debounce of §7.2); a change while it is
// applying is caught by the convergence rounds below.

// KindApply is the job kind (jobs.DefaultKinds: dedupe tenant:{tenant}:policy.apply).
const KindApply = "policy.apply"

// codeInvalidInput is the permanent error code of a job whose input is not one of policy.apply.
const codeInvalidInput = "invalid_input"

// ApplyJobInput is the input of a policy.apply job.
type ApplyJobInput struct {
	// Trigger is the reason recorded on the application (policy_applications.trigger): tag_change, group_change,
	// resource_change, manual, rollback, drift_repair, suspend. "" ⇒ manual.
	Trigger string `json:"trigger,omitempty"`
}

// jobTriggers are the triggers a policy.apply job may carry (bootstrap, resume and restore belong to the jobs that call
// the core themselves).
var jobTriggers = map[string]bool{TriggerTagChange: true, TriggerGroupChange: true, TriggerResourceChange: true,
	TriggerManual: true, TriggerDriftRepair: true, TriggerRollback: true, TriggerSuspend: true}

// maxConvergeRounds bounds how many times one job applies again when the inputs changed while it was applying (a
// change committed meanwhile found this job unfinished and did not enqueue another — dedupe of §13.5).
const maxConvergeRounds = 3

// Skip reasons of a policy.apply job that has nothing to apply (the job succeeds, its output says why).
const (
	SkipTenantNotActive = "tenant_not_active"    // suspended (the suspension policy stays — resume renders the desired one), deleting…
	SkipNoDesired       = "no_desired_policy"    // the tenant never had a policy applied (provisioning applies the baseline)
	SkipNotApproved     = "desired_not_approved" // e.g. a policy imported by a restore, waiting for review (§17.2)
	SkipNoInstance      = "no_instance"          // no live instance
)

// ApplyJobOutput is the output of a policy.apply job.
type ApplyJobOutput struct {
	Trigger        string    `json:"trigger"`
	Skipped        string    `json:"skipped,omitempty"`
	Mode           string    `json:"mode,omitempty"`  // desired | suspension
	State          string    `json:"state,omitempty"` // of the last application (applied)
	ApplicationID  uuid.UUID `json:"application_id,omitzero"`
	VersionID      uuid.UUID `json:"version_id,omitzero"`
	Version        int       `json:"version,omitempty"`
	AppliedSHA256  string    `json:"applied_sha256,omitempty"`
	InputsSHA256   string    `json:"inputs_sha256,omitempty"`
	TagOwners      []string  `json:"tag_owners,omitempty"`
	Rounds         int       `json:"rounds,omitempty"`
	ReadbackSHA256 string    `json:"readback_sha256,omitempty"`
}

// Register registers the policy.apply handler on the worker (apps/ wiring — jobs imports no business module).
func (s *Service) Register(w *jobs.Worker) error {
	return w.Register(KindApply, jobs.HandlerFunc(s.runApplyJob))
}

// runApplyJob is the handler of policy.apply: each round reads the tenant's state (planApply) and applies what it
// calls for — the desired version through ApplyDesired (rendered with the groups, resources, catalog and memberships
// of now, linted, one policy_applications row on that same version), or the suspension policy through the core —; when
// what would be applied changed while it applied, it applies again, at most maxConvergeRounds times. A lint refusal or
// a refusal by Headscale is permanent; an instance that does not answer or the policy lock is retried. No job step:
// the application row is the record of each round, the output that of the job.
func (s *Service) runApplyJob(ctx context.Context, run *jobs.Run) error {
	var in ApplyJobInput
	if len(run.Input) > 0 {
		if err := run.DecodeInput(&in); err != nil {
			return jobs.Permanent(codeInvalidInput, err)
		}
	}
	if in.Trigger == "" {
		in.Trigger = TriggerManual
	}
	if !jobTriggers[in.Trigger] {
		return jobs.Permanent(codeInvalidInput, fmt.Errorf("trigger %q is not one of a policy.apply job", in.Trigger))
	}
	if run.TenantID == nil {
		return jobs.Permanent(codeInvalidInput, errors.New("policy.apply needs a tenant"))
	}
	tenantID := *run.TenantID
	out := ApplyJobOutput{Trigger: in.Trigger}
	for round := 1; round <= maxConvergeRounds; round++ {
		p, err := s.planApply(ctx, tenantID, in.Trigger)
		if err != nil {
			if errors.Is(err, store.ErrNoRows) {
				return jobs.Permanent("no_tenant", err)
			}
			return jobs.Transient("store", fmt.Errorf("read the desired policy: sqlstate %q", store.SQLState(err)))
		}
		if p.mode == modeSkip {
			out.Skipped = p.skip
			return run.SetOutput(out)
		}
		var res Result
		switch p.mode {
		case modeSuspension:
			res, err = s.Apply(ctx, ApplyRequest{TenantID: tenantID, Kind: KindSuspension, HuJSON: s.susText,
				Trigger: p.trigger, Actor: KindApply})
		default:
			res, err = s.ApplyDesired(ctx, DesiredRequest{TenantID: tenantID, Trigger: p.trigger, Actor: KindApply})
			switch {
			case errors.Is(err, ErrDesiredChanged):
				out.Rounds = round
				continue // another apply or a rollback committed meanwhile: render the new desired state
			case errors.Is(err, ErrNoDesired):
				out.Skipped = SkipNoDesired
				return run.SetOutput(out)
			case errors.Is(err, ErrDesiredNotApproved):
				out.Skipped = SkipNotApproved
				return run.SetOutput(out)
			}
		}
		if err != nil {
			return s.jobError(err, &out, run)
		}
		out.Skipped, out.Mode = "", p.mode
		out.ApplicationID, out.VersionID, out.Version, out.State = res.ApplicationID, res.VersionID, res.Version, res.State
		out.AppliedSHA256, out.InputsSHA256, out.TagOwners = res.AppliedSHA256, res.InputsSHA256, res.TagOwners
		out.ReadbackSHA256, out.Rounds, out.Trigger = res.ReadbackSHA256, round, p.trigger
		now, err := s.appliedNow(ctx, tenantID, in.Trigger)
		if err != nil {
			return jobs.Transient("store", fmt.Errorf("read the render inputs: sqlstate %q", store.SQLState(err)))
		}
		if now == res.AppliedSHA256 {
			break
		}
	} // still changing after the last round: the next change enqueues the next job
	return run.SetOutput(out)
}

// jobError classifies an error of the core for the job (the output records what is known).
func (s *Service) jobError(err error, out *ApplyJobOutput, run *jobs.Run) error {
	if le, ok := IsLint(err); ok {
		return jobs.Permanent("policy_lint_"+strings.ToLower(le.Rule), err) // codes are lowercase (CHECK of 0006)
	}
	if errors.Is(err, ErrNoInstance) {
		out.Skipped = SkipNoInstance
		return run.SetOutput(out)
	}
	if errors.Is(err, store.ErrLockTimeout) {
		return jobs.Transient("policy_lock_timeout", err)
	}
	var ae *ApplyError
	if errors.As(err, &ae) {
		out.ApplicationID = ae.Result.ApplicationID
		_ = run.SetOutput(out)
		switch ae.Code {
		case CodeInstanceUnavailable, CodeOutcomeUnknown, CodeReadbackFailed, CodeInternal:
			return jobs.Transient(ae.Code, err)
		}
		return jobs.Permanent(ae.Code, err)
	}
	return jobs.Transient("policy_apply", err)
}
