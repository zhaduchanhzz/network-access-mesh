package policies

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// The policy.apply job (§13.5 — level-triggered: its input names the reason, never a policy; the handler reads the
// desired state when it runs). ONE handler for every table rendered at apply time: the tag catalog (P4-T15, trigger
// tag_change — Service.Apply renders the current catalog, "tagOwners" + L6), the groups (P4-T09, group_change —
// internal/members enqueues it), the resources (P4-T12, resource_change). Changes made while a job is queued are carried
// by that job (dedupe key tenant:<id>:policy.apply — the debounce of §7.2); a change while it is applying is caught by
// the convergence rounds below. The full pipeline — typed versions, groups and hosts rendered from their tables, tests,
// drift — is P4-T10's.

// KindApply is the job kind (jobs.DefaultKinds: dedupe tenant:{tenant}:policy.apply).
const KindApply = "policy.apply"

// codeInvalidInput is the permanent error code of a job whose input is not one of policy.apply.
const codeInvalidInput = "invalid_input"

// ApplyJobInput is the input of a policy.apply job.
type ApplyJobInput struct {
	// Trigger is the reason recorded on the application (policy_applications.trigger): tag_change for the catalog;
	// group_change / resource_change for P4-T09 / P4-T12; manual, drift_repair. "" ⇒ manual.
	Trigger string `json:"trigger,omitempty"`
}

// jobTriggers are the triggers a policy.apply job may carry (the others belong to the lifecycle jobs, which call
// Service.Apply themselves: bootstrap, suspend, resume, restore, rollback).
var jobTriggers = map[string]bool{TriggerTagChange: true, TriggerGroupChange: true, TriggerResourceChange: true,
	TriggerManual: true, TriggerDriftRepair: true}

// maxConvergeRounds bounds how many times one job applies again when the inputs changed while it was applying (a
// catalog change committed meanwhile found this job unfinished and did not enqueue another — dedupe of §13.5).
const maxConvergeRounds = 3

// Skip reasons of a policy.apply job that has nothing to apply (the job succeeds, its output says why).
const (
	SkipTenantNotActive = "tenant_not_active"    // suspended (the suspension policy stays — resume renders the catalog), deleting…
	SkipNoDesired       = "no_desired_policy"    // the tenant never had a policy applied (provisioning applies the baseline)
	SkipNotApproved     = "desired_not_approved" // e.g. a policy imported by a restore, waiting for review (§17.2)
	SkipTypedPolicy     = "typed_policy"         // a typed version (P4-T10's pipeline)
	SkipNoInstance      = "no_instance"          // no live instance
)

// ApplyJobOutput is the output of a policy.apply job.
type ApplyJobOutput struct {
	Trigger        string    `json:"trigger"`
	Skipped        string    `json:"skipped,omitempty"`
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

// desired is what a policy.apply job applies.
type desired struct {
	text    string
	content string // content_sha256
	skip    string
}

// desiredPolicy reads the tenant's state: an active tenant with an approved HuJSON desired version (the platform's
// baseline or a fixture — the kinds the core applies) is applied; anything else is skipped with its reason.
func (s *Service) desiredPolicy(ctx context.Context, tenantID uuid.UUID) (desired, error) {
	var out desired
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		t, err := q.GetTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		switch {
		case t.Status != "active":
			out.skip = SkipTenantNotActive
			return nil
		case t.DesiredPolicyVersionID == nil:
			out.skip = SkipNoDesired
			return nil
		}
		v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *t.DesiredPolicyVersionID})
		if err != nil {
			return err
		}
		switch {
		case v.State != "approved":
			out.skip = SkipNotApproved
		case v.Kind != KindBaseline || v.SourceHujson == nil:
			out.skip = SkipTypedPolicy
		default:
			out.text, out.content = *v.SourceHujson, v.ContentSha256
		}
		return nil
	})
	return out, err
}

// runApplyJob is the handler of policy.apply: the tenant's desired version applied through Service.Apply (catalog
// rendered, lock, CheckPolicy → SetPolicy → GetPolicy, one policy_applications row per application — on the same
// approved version, never a new version) with the job's trigger; when the inputs changed while it applied (the
// catalog), it applies again, at most maxConvergeRounds times. A lint refusal (L6 — the desired policy references a tag
// that is no longer declared) or a refusal by Headscale is permanent; an instance that does not answer or the policy
// lock is retried. No job step: the application row is the record of each round, the output that of the job.
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
		d, err := s.desiredPolicy(ctx, tenantID)
		if err != nil {
			if errors.Is(err, store.ErrNoRows) {
				return jobs.Permanent("no_tenant", err)
			}
			return jobs.Transient("store", fmt.Errorf("read the desired policy: sqlstate %q", store.SQLState(err)))
		}
		if d.skip != "" {
			out.Skipped = d.skip
			return run.SetOutput(out)
		}
		res, err := s.Apply(ctx, ApplyRequest{TenantID: tenantID, Kind: KindBaseline, HuJSON: d.text,
			Trigger: in.Trigger, Actor: KindApply})
		if err != nil {
			return s.jobError(err, &out, run)
		}
		out.ApplicationID, out.VersionID, out.Version, out.State = res.ApplicationID, res.VersionID, res.Version, res.State
		out.AppliedSHA256, out.InputsSHA256, out.TagOwners = res.AppliedSHA256, res.InputsSHA256, res.TagOwners
		out.ReadbackSHA256, out.Rounds = res.ReadbackSHA256, round
		again, err := s.inputsNow(ctx, tenantID, d)
		if err != nil {
			return jobs.Transient("store", fmt.Errorf("read the tag catalog: sqlstate %q", store.SQLState(err)))
		}
		if again == res.InputsSHA256 {
			break
		}
	} // still changing after the last round: the next change enqueues the next job
	return run.SetOutput(out)
}

// inputsNow is the inputs_sha256 the desired policy would be applied with now (another round when it differs).
func (s *Service) inputsNow(ctx context.Context, tenantID uuid.UUID, d desired) (string, error) {
	cur, err := s.desiredPolicy(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if cur.skip != "" || cur.content != d.content {
		return "", nil // the desired state changed: one more round decides
	}
	doc, err := Lint(cur.text)
	if err != nil {
		return "", nil
	}
	r, err := s.renderCatalog(ctx, tenantID, doc)
	if err != nil {
		if _, lint := IsLint(err); lint {
			return "", nil // the next round records the refusal
		}
		return "", err
	}
	return r.InputsSHA256, nil
}

// jobError classifies an error of Service.Apply for the job (the output records what is known).
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
