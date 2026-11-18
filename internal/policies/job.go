package policies

import (
	"context"
	"errors"
	"fmt"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// KindApply is the level-triggered job of §13.5: its only parameters are the tenant (the job's) and the trigger that
// enqueued it — the handler reads the desired state when it runs, so changes made while a job is queued are carried
// by that job (dedupe key tenant:<id>:policy.apply: the debounce of §7.2).
const KindApply = "policy.apply"

// jobTriggers are the triggers a policy.apply job may carry (input {"trigger": …}).
var jobTriggers = map[string]bool{TriggerGroupChange: true, TriggerResourceChange: true, TriggerTagChange: true,
	TriggerDriftRepair: true, TriggerManual: true}

// applyJobInput is the input of policy.apply.
type applyJobInput struct {
	Trigger string `json:"trigger"`
}

// Job error codes of policy.apply.
const (
	codeInvalidInput = "invalid_input"
)

// Register adds the handler of policy.apply to the worker (apps/worker).
func (s *Service) Register(w *jobs.Worker) error {
	return w.Register(KindApply, jobs.HandlerFunc(s.runApplyJob))
}

// runApplyJob re-applies the tenant's desired version with the job's trigger (§7.3: a change of the tables rendered at
// apply time — groups, resources, the tag catalog — is a new policy_applications row on the same approved version,
// never a new version). Until the typed model of P4-T10 renders those tables, the desired version is a HuJSON version
// and the application sends its content again (same bytes); P4-T10 replaces the render, not this job. Skipped: a
// tenant that is not active (a suspended tenant enforces its suspension policy — resume re-applies the desired one), a
// tenant without a desired version, a desired version this core cannot render.
func (s *Service) runApplyJob(ctx context.Context, run *jobs.Run) error {
	var in applyJobInput
	if err := run.DecodeInput(&in); err != nil || run.TenantID == nil {
		return jobs.Permanent(codeInvalidInput, errors.Join(errors.New("policy.apply: invalid input"), err))
	}
	if in.Trigger == "" {
		in.Trigger = TriggerManual
	}
	if !jobTriggers[in.Trigger] {
		return jobs.Permanent(codeInvalidInput, fmt.Errorf("policy.apply: trigger %q", in.Trigger))
	}
	tenantID := *run.TenantID
	var (
		status string
		ver    *sqlcdb.PolicyVersion
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		t, err := q.GetTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		status = t.Status
		if t.DesiredPolicyVersionID == nil {
			return nil
		}
		v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *t.DesiredPolicyVersionID})
		if err != nil {
			return err
		}
		ver = &v
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return jobs.Permanent("no_tenant", err)
		}
		return jobs.Transient(CodeInternal, err)
	}
	skip := ""
	switch {
	case status != tenants.StatusActive:
		skip = "tenant_not_active"
	case ver == nil:
		skip = "no_desired_policy"
	case ver.Kind != KindBaseline || ver.SourceHujson == nil || ver.State != "approved":
		skip = "typed_policy_not_rendered" // the typed model and its renderer come with P4-T10
	}
	if skip != "" {
		_ = run.SetOutput(map[string]any{"skipped": skip, "trigger": in.Trigger})
		return nil
	}
	res, err := s.Apply(ctx, ApplyRequest{TenantID: tenantID, Kind: KindBaseline, HuJSON: *ver.SourceHujson,
		Trigger: in.Trigger, Actor: KindApply})
	if err != nil {
		code := CodeInternal
		var ae *ApplyError
		switch {
		case errors.As(err, &ae):
			code = ae.Code
		case errors.Is(err, ErrNoInstance):
			code = CodeNoInstance
		}
		if code == CodeInstanceUnavailable || code == CodeInternal || code == CodeOutcomeUnknown {
			return jobs.Transient(code, err)
		}
		return jobs.Permanent(code, err)
	}
	_ = run.SetOutput(map[string]any{"application_id": res.ApplicationID, "state": res.State, "version": res.Version,
		"trigger": in.Trigger, "applied_sha256": res.AppliedSHA256})
	return nil
}
