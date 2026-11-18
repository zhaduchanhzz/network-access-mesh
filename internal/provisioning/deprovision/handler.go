package deprovision

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Handler runs tenant.deprovision in the worker.
type Handler struct {
	cfg Config
}

// New checks the configuration and returns the handler.
func New(cfg Config) (*Handler, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	return &Handler{cfg: cfg}, nil
}

// Register registers the handler of tenant.deprovision on the worker.
func (h *Handler) Register(w *jobs.Worker) error { return w.Register(Kind, job{h}) }

// job is tenant.deprovision: jobs.Handler + jobs.Compensator (run only by /rollback, before the point of no return).
type job struct{ h *Handler }

var _ jobs.Compensator = job{}

// Run implements jobs.Handler. A permanent error stops the job failed_resumable instead of compensating: undoing a
// deprovision (before its point of no return) is an operator's decision (/rollback), never an automatic one.
func (j job) Run(ctx context.Context, run *jobs.Run) error {
	err := j.h.run(ctx, run)
	if jobs.IsPermanent(err) {
		return jobs.Resumable(jobs.CodeOf(err), err)
	}
	return err
}

// Compensate implements jobs.Compensator: /rollback before the point of no return — the tenant back in its status
// behind its desired policy, in reverse order; the final backup stays in the book. Past the point of no return it
// refuses (jobs.Rollback refuses first; this is the second line).
func (j job) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return j.h.undo(ctx, run, cause)
}

// ---------------------------------------------------------------------------------------------------- the run

func (h *Handler) run(ctx context.Context, run *jobs.Run) error {
	in, err := h.input(run)
	if err != nil {
		return err
	}
	run.SetResource("tenant", in.TenantID.String())
	a := &attempt{h: h, run: run, in: in}
	for _, s := range []struct {
		name string
		fn   func(context.Context, *jobs.StepRun) error
	}{
		{StepFinalBackup, a.finalBackup},
		{StepPolicy, a.suspendPolicy},
		{StepDeprovision, a.toDeprovisioning},
		{StepNodesExpire, a.expireNodes},
		{StepAccessRevoke, a.revokeAccess},
		{StepTargets, a.removeTargets},
		{StepEdgeDetach, a.detachEdge},
		{StepInstance, a.removeInstance},
		{StepStorage, a.removeStorage},
		{StepIdP, a.disableIdP},
		{StepRelay, a.removeRelay},
		{StepDelete, a.deleteRegistry},
		{StepKeysSchedule, a.scheduleKeys},
		{StepNotify, a.notify},
	} {
		if err := h.step(ctx, run, s.name, s.fn); err != nil {
			return err
		}
	}
	return run.SetOutput(a.output)
}

// undo is the compensation of /rollback, before the point of no return only.
func (h *Handler) undo(ctx context.Context, run *jobs.Run, cause error) error {
	in, err := h.input(run)
	if err != nil {
		return err
	}
	k, _ := jobs.KindOf(Kind)
	var passed bool
	if err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		passed, err = jobs.PastPointOfNoReturn(ctx, q, k, run.ID)
		return err
	}); err != nil {
		return dbErr("read the point of no return", err)
	}
	if passed {
		return jobs.Permanent(jobs.ReasonPointOfNoReturn, errors.New("the deprovision passed its point of no return (nodes.expire): it cannot be rolled back"))
	}
	a := &attempt{h: h, run: run, in: in}
	if err := run.CompensateSteps(ctx, map[string]jobs.CompensateFunc{
		StepDeprovision: h.retried(a.undoDeprovisioning),
		StepPolicy:      h.retried(a.undoPolicy),
	}); err != nil {
		return err
	}
	return h.closeOperation(ctx, in, func(q *sqlcdb.Queries) error {
		return in.Operation.Failed(ctx, q, jobs.CodeOf(cause), audit.Details{"job_id": run.ID, "rolled_back": true})
	})
}

// ---------------------------------------------------------------------------------------------------- helpers

// attempt is one run (or compensation) of a job.
type attempt struct {
	h      *Handler
	run    *jobs.Run
	in     Input
	output map[string]any
}

func (a *attempt) out(k string, v any) {
	if a.output == nil {
		a.output = map[string]any{"tenant_id": a.in.TenantID}
	}
	a.output[k] = v
}

func (h *Handler) input(run *jobs.Run) (Input, error) {
	var in Input
	if err := run.DecodeInput(&in); err != nil {
		return in, jobs.Permanent("invalid_input", fmt.Errorf("job input unreadable: %w", err))
	}
	if err := in.validate(); err != nil {
		return in, jobs.Permanent("invalid_input", err)
	}
	if run.TenantID == nil || *run.TenantID != in.TenantID {
		return in, jobs.Permanent("invalid_input", errors.New("the job's tenant is not the input's"))
	}
	return in, nil
}

func (h *Handler) tenant(ctx context.Context, id uuid.UUID) (sqlcdb.Tenant, error) {
	var t sqlcdb.Tenant
	err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		t, err = q.GetTenant(ctx, id)
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return t, jobs.Permanent("registry_state", fmt.Errorf("tenant %s not found", id))
	}
	if err != nil {
		return t, dbErr("read the tenant", err)
	}
	return t, nil
}

// instance is the job's instance (Input.InstanceID) as the registry has it now; ok = false when the job has none.
func (a *attempt) instance(ctx context.Context) (sqlcdb.GetDeprovisionInstanceRow, bool, error) {
	var out sqlcdb.GetDeprovisionInstanceRow
	if a.in.InstanceID == nil {
		return out, false, nil
	}
	err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		out, err = q.GetDeprovisionInstance(ctx, sqlcdb.GetDeprovisionInstanceParams{ID: *a.in.InstanceID, TenantID: a.in.TenantID})
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return out, false, jobs.Permanent("registry_state", fmt.Errorf("instance %s of the job not found", *a.in.InstanceID))
	}
	if err != nil {
		return out, false, dbErr("read the instance", err)
	}
	return out, true, nil
}

func (a *attempt) ref() *agentv1.InstanceRef {
	return &agentv1.InstanceRef{InstanceId: a.in.InstanceID.String(), TenantId: a.in.TenantID.String(), Slug: a.in.Slug}
}

// step runs one step with the retry policy of §11.3: a transient failure is retried in place up to StepRetries times
// with exponential backoff (each try one attempt of the step); spent ⇒ jobs.Resumable (failed_resumable, no
// compensation). A permanent failure, a cancellation or the end of ctx is returned at once.
func (h *Handler) step(ctx context.Context, run *jobs.Run, name string, fn func(ctx context.Context, s *jobs.StepRun) error) error {
	for try := 0; ; try++ {
		err := run.Step(ctx, name, fn)
		switch {
		case err == nil:
			return nil
		case jobs.IsPermanent(err), jobs.IsResumable(err), ctx.Err() != nil:
			return err
		case try >= h.cfg.StepRetries:
			return jobs.Resumable(jobs.CodeOf(err), fmt.Errorf("step %s: %d retries spent: %w", name, try, err))
		}
		if serr := sleep(ctx, h.backoff(try+1)); serr != nil {
			return err
		}
	}
}

// retried wraps a compensation with the retry policy of the steps.
func (h *Handler) retried(fn jobs.CompensateFunc) jobs.CompensateFunc {
	return func(ctx context.Context, s jobs.CompensationStep) error {
		for try := 0; ; try++ {
			err := fn(ctx, s)
			switch {
			case err == nil:
				return nil
			case jobs.IsPermanent(err), ctx.Err() != nil, try >= h.cfg.StepRetries:
				return err
			}
			if serr := sleep(ctx, h.backoff(try+1)); serr != nil {
				return err
			}
		}
	}
}

// backoff is the delay before try n (n ≥ 1): RetryBase·2^(n−1), capped at RetryMax, ± 20 %.
func (h *Handler) backoff(n int) time.Duration {
	d := h.cfg.RetryBase
	for i := 1; i < n && d < h.cfg.RetryMax; i++ {
		d *= 2
	}
	d = min(d, h.cfg.RetryMax)
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // scheduling jitter
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (h *Handler) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, h.cfg.CallTimeout)
}

// record stores created_resources BEFORE the step acts (§11.3).
func record(ctx context.Context, s *jobs.StepRun, v any) error {
	if err := s.RecordCreated(ctx, v); err != nil {
		var je *jobs.Error
		if errors.As(err, &je) {
			return err
		}
		return jobs.Transient("step_bookkeeping", err)
	}
	return nil
}

// setDetail sets the raw detail of a step (identifiers, codes, counts — never a secret).
func setDetail(s *jobs.StepRun, v map[string]any) { _ = s.SetDetail(v) }

// closeOperation closes the audit pair once (a re-run finds it finished).
func (h *Handler) closeOperation(ctx context.Context, in Input, fn func(q *sqlcdb.Queries) error) error {
	err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		st, err := q.OperationState(ctx, in.Operation.ID)
		if err != nil || st.Finished {
			return err
		}
		return fn(q)
	})
	if err != nil {
		return dbErr("close the audit operation", err)
	}
	return nil
}

// security records a platform security event (best effort is not enough for an override: a failure is transient).
func (h *Handler) security(ctx context.Context, ev audit.SecurityEvent) error {
	if h.cfg.Security != nil {
		if _, err := h.cfg.Security.RecordSecurityEvent(ctx, ev); err != nil {
			return dbErr("record a security event", err)
		}
		return nil
	}
	err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(ctx, q, ev)
		return err
	})
	if err != nil {
		return dbErr("record a security event", err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- error classes

// dbErr classifies a database error: transient (an error that already carries a job code keeps it).
func dbErr(what string, err error) error {
	var je *jobs.Error
	if errors.As(err, &je) {
		return err
	}
	return jobs.Transient("registry_unavailable", fmt.Errorf("%s: sqlstate %q", what, store.SQLState(err)))
}

// agentErr classifies an error of the Host Agent (as the orchestrator does): unreachable, busy or deadline ⇒
// transient; a typed refusal ⇒ permanent, code agent_<reason>.
func agentErr(rpc string, err error) error {
	msg := rpc + ": " + status.Convert(err).Message()
	ref, hasRefusal := agentclient.RefusalOf(err)
	if hasRefusal {
		msg = fmt.Sprintf("%s: %s refused (%s): %s", rpc, ref.GetField(), refusalCode(ref.GetReason()), ref.GetMessage())
	}
	switch {
	case agentclient.Retryable(err):
		code := "agent_unavailable"
		if status.Code(err) == codes.Aborted {
			code = "agent_busy"
		}
		return jobs.Transient(code, errors.New(msg))
	case hasRefusal:
		return jobs.Permanent("agent_"+refusalCode(ref.GetReason()), errors.New(msg))
	}
	return jobs.Permanent("agent_error", errors.New(msg))
}

func refusalCode(r agentv1.RefusalReason) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "REFUSAL_REASON_"))
}

// notFoundAtAgent: the agent has nothing of the instance any more (a step that ran before).
func notFoundAtAgent(err error) bool { return status.Code(err) == codes.NotFound }

// headscaleErr classifies an adapter error: unavailable, circuit open or no reachable instance ⇒ transient; the rest
// permanent (code headscale_<kind>).
func headscaleErr(op string, err error) error {
	var he *headscale.Error
	switch {
	case errors.As(err, &he) && (he.Kind == headscale.KindUnavailable || he.Kind == headscale.KindCircuitOpen):
		return jobs.Transient("instance_unavailable", fmt.Errorf("%s: %s", op, he.Kind))
	case errors.Is(err, headscale.ErrNoInstance):
		return jobs.Transient("instance_unavailable", fmt.Errorf("%s: no reachable instance", op))
	case errors.As(err, &he):
		return jobs.Permanent("headscale_"+string(he.Kind), fmt.Errorf("%s: %s", op, he.Kind))
	}
	return jobs.Transient("instance_unavailable", fmt.Errorf("%s: %s", op, err.Error()))
}

// applyErr classifies an error of the policy core (as tenant.suspend does).
func applyErr(err error) error {
	if err == nil {
		return nil
	}
	if le, ok := policies.IsLint(err); ok {
		return jobs.Permanent("policy_lint", fmt.Errorf("lint %s: %s", le.Rule, le.Detail))
	}
	var ae *policies.ApplyError
	if errors.As(err, &ae) {
		switch ae.Code {
		case policies.CodePolicyRejected, policies.CodeNoInstance:
			return jobs.Permanent(ae.Code, err)
		}
		return jobs.Transient(ae.Code, err)
	}
	switch {
	case errors.Is(err, policies.ErrNoInstance):
		return jobs.Permanent(policies.CodeNoInstance, err)
	case errors.Is(err, policies.ErrInvalidRequest):
		return jobs.Permanent("invalid_request", err)
	case errors.Is(err, store.ErrLockTimeout):
		return jobs.Transient("policy_locked", err)
	}
	return jobs.Transient("policy_unavailable", err)
}

// idpErr classifies an IdP driver error: unavailable, timeout, upstream or credentials ⇒ transient; the rest permanent.
func idpErr(op string, err error) error {
	switch c := idp.CodeOf(err); c {
	case idp.CodeUnavailable, idp.CodeTimeout, idp.CodeUpstream, idp.CodeCredentials:
		return jobs.Transient("idp_"+string(c), fmt.Errorf("%s: %w", op, err))
	case "":
		return jobs.Transient("idp_unavailable", fmt.Errorf("%s: %w", op, err))
	default:
		return jobs.Permanent("idp_"+string(c), fmt.Errorf("%s: %w", op, err))
	}
}

// liveInstance: the instance still holds host resources (a running/stopped/starting… instance; never `removed`).
func liveInstance(status string) bool { return status != tenants.InstanceRemoved }
