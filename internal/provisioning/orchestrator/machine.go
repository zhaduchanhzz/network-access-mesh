package orchestrator

import (
	"context"
	"encoding/json"
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
)

// Provisioner runs tenant.provision in the worker: jobs.Handler (steps 3–19) and jobs.Compensator (reverse order).
type Provisioner struct {
	cfg Config
}

var (
	_ jobs.Handler     = (*Provisioner)(nil)
	_ jobs.Compensator = (*Provisioner)(nil)
)

// New checks the configuration and returns the state machine.
func New(cfg Config) (*Provisioner, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	return &Provisioner{cfg: cfg}, nil
}

// Register registers the handler of tenant.provision on the worker.
func (p *Provisioner) Register(w *jobs.Worker) error { return w.Register(JobKind, p) }

// ---------------------------------------------------------------------------------------------------- runner

// stepCtx is the running step (jobs.StepRun).
type stepCtx interface {
	RecordCreated(ctx context.Context, resources any) error
	SetDetail(v any) error
	Previous(v any) (bool, error)
}

// runner is the attempt of the job the state machine runs on: *jobs.Run in the worker, an in-memory fake in the unit
// tests of the state machine.
type runner interface {
	JobID() uuid.UUID
	Input(v any) error
	Step(ctx context.Context, name string, fn func(ctx context.Context, s stepCtx) error) error
	StepResources(ctx context.Context, name string, v any) (bool, error)
	CompensateSteps(ctx context.Context, fns map[string]jobs.CompensateFunc) error
	SetOutput(v any) error
	SetResource(typ, id string)
}

// jobRunner adapts *jobs.Run.
type jobRunner struct{ r *jobs.Run }

func (j jobRunner) JobID() uuid.UUID         { return j.r.ID }
func (j jobRunner) Input(v any) error        { return j.r.DecodeInput(v) }
func (j jobRunner) SetOutput(v any) error    { return j.r.SetOutput(v) }
func (j jobRunner) SetResource(t, id string) { j.r.SetResource(t, id) }
func (j jobRunner) Step(ctx context.Context, name string, fn func(ctx context.Context, s stepCtx) error) error {
	return j.r.Step(ctx, name, func(ctx context.Context, s *jobs.StepRun) error { return fn(ctx, s) })
}
func (j jobRunner) StepResources(ctx context.Context, name string, v any) (bool, error) {
	return j.r.StepResources(ctx, name, v)
}
func (j jobRunner) CompensateSteps(ctx context.Context, fns map[string]jobs.CompensateFunc) error {
	return j.r.CompensateSteps(ctx, fns)
}

// Run implements jobs.Handler.
func (p *Provisioner) Run(ctx context.Context, run *jobs.Run) error {
	return p.run(ctx, jobRunner{run})
}

// Compensate implements jobs.Compensator.
func (p *Provisioner) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return p.compensate(ctx, jobRunner{run}, cause)
}

// ---------------------------------------------------------------------------------------------------- the machine

// attempt is the state of one attempt: the input and what the registry holds.
type attempt struct {
	r      runner
	in     Input
	tenant TenantRecord
}

// workerSteps are steps 3–19 with their functions, in order.
func (p *Provisioner) workerSteps() []struct {
	name string
	fn   func(ctx context.Context, a *attempt, s stepCtx) error
} {
	return []struct {
		name string
		fn   func(ctx context.Context, a *attempt, s stepCtx) error
	}{
		{StepPlacement, p.stepPlacement}, {StepDNS, p.stepDNS}, {StepSecrets, p.stepSecrets}, {StepIdP, p.stepIdP},
		{StepStorage, p.stepStorage}, {StepConfig, p.stepConfig}, {StepNetwork, p.stepNetwork}, {StepStart, p.stepStart},
		{StepWaitHealthy, p.stepWaitHealthy}, {StepPolicyBoot, p.stepPolicyBootstrap}, {StepAPIKey, p.stepAPIKey},
		{StepEdgeAttach, p.stepEdgeAttach}, {StepPolicyVerify, p.stepPolicyVerify}, {StepConfigure, p.stepConfigure},
		{StepRelay, p.stepRelay}, {StepEdgeVerify, p.stepEdgeVerify}, {StepActivate, p.stepActivate},
	}
}

func (p *Provisioner) run(ctx context.Context, r runner) error {
	a := &attempt{r: r}
	if err := r.Input(&a.in); err != nil {
		return jobs.Permanent("invalid_input", fmt.Errorf("job input unreadable: %w", err))
	}
	if err := a.in.validate(); err != nil {
		return jobs.Permanent("invalid_input", err)
	}
	t, err := p.cfg.Store.Tenant(ctx, a.in.TenantID)
	if err != nil {
		return storeErr("load the tenant", err)
	}
	if t.Slug != a.in.Slug {
		return jobs.Permanent("invalid_input", errors.New("the job's slug is not the tenant's"))
	}
	a.tenant = t
	r.SetResource("tenant", a.in.TenantID.String())
	for _, st := range p.workerSteps() {
		if err := p.step(ctx, r, st.name, func(ctx context.Context, s stepCtx) error { return st.fn(ctx, a, s) }); err != nil {
			return err
		}
	}
	inst, err := a.instanceID(ctx)
	if err != nil {
		return err
	}
	return r.SetOutput(map[string]any{"tenant_id": a.in.TenantID, "instance_id": inst, "slug": a.in.Slug})
}

// step runs one step with the retry policy of §11.3: a transient failure is retried in place up to StepRetries times
// with exponential backoff (RetryBase → RetryMax ± 20 %) — every try is one attempt of the step in
// provisioning_job_steps —; spent ⇒ jobs.Resumable (failed_resumable, no compensation). A permanent failure, a
// cancellation (Resumable) or the end of ctx (worker stopping, job deadline) is returned at once.
func (p *Provisioner) step(ctx context.Context, r runner, name string, fn func(ctx context.Context, s stepCtx) error) error {
	for try := 0; ; try++ {
		err := r.Step(ctx, name, fn)
		switch {
		case err == nil:
			return nil
		case jobs.IsPermanent(err), jobs.IsResumable(err), ctx.Err() != nil:
			return err
		case try >= p.cfg.StepRetries:
			return jobs.Resumable(jobs.CodeOf(err), fmt.Errorf("step %s: %d retries spent: %w", name, try, err))
		}
		t := time.NewTimer(p.backoff(try + 1))
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
	}
}

// backoff is the delay before try n (n ≥ 1): RetryBase·2^(n−1), capped at RetryMax, ± 20 %.
func (p *Provisioner) backoff(n int) time.Duration {
	d := p.cfg.RetryBase
	for i := 1; i < n && d < p.cfg.RetryMax; i++ {
		d *= 2
	}
	d = min(d, p.cfg.RetryMax)
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // scheduling jitter
}

// placementResources is created_resources of step 3.
type placementResources struct {
	InstanceID uuid.UUID `json:"instance_id"`
}

// instanceID is the instance chosen by step 3 (from its created_resources).
func (a *attempt) instanceID(ctx context.Context) (uuid.UUID, error) {
	var res placementResources
	found, err := a.r.StepResources(ctx, StepPlacement, &res)
	if err != nil {
		return uuid.Nil, err
	}
	if !found || res.InstanceID == uuid.Nil {
		return uuid.Nil, jobs.Permanent("invalid_state", errors.New("placement.allocate recorded no instance"))
	}
	return res.InstanceID, nil
}

// instance reads the instance of the job from the registry.
func (p *Provisioner) instance(ctx context.Context, a *attempt) (InstanceRecord, error) {
	id, err := a.instanceID(ctx)
	if err != nil {
		return InstanceRecord{}, err
	}
	inst, err := p.cfg.Store.Instance(ctx, a.in.TenantID, id)
	if err != nil {
		return inst, storeErr("load the instance", err)
	}
	return inst, nil
}

// call bounds one external call (agent, Headscale, prober, IdP) by CallTimeout.
func (p *Provisioner) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, p.cfg.CallTimeout)
}

// ---------------------------------------------------------------------------------------------------- errors

// storeErr classifies a registry error: a missing row or an unexpected state is permanent, a database error transient.
func storeErr(what string, err error) error {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrState) {
		return jobs.Permanent("registry_state", fmt.Errorf("%s: %w", what, err))
	}
	var je *jobs.Error
	if errors.As(err, &je) {
		return err
	}
	return jobs.Transient("registry_unavailable", fmt.Errorf("%s: %w", what, err))
}

// agentErr classifies an error of the Host Agent: unreachable, busy (per-instance lock) or deadline ⇒ transient; a
// typed refusal of the request (INVALID_ARGUMENT, FAILED_PRECONDITION…) or UNIMPLEMENTED ⇒ permanent, code
// agent_<reason>. The message keeps the RPC, the refused field and the agent's text (which never repeats a value).
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

// refusalCode is the stable lower-case code of a refusal reason (REFUSAL_REASON_STATE ⇒ state).
func refusalCode(r agentv1.RefusalReason) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "REFUSAL_REASON_"))
}

// startGuardRefusal: the agent refused because the start guard failed (§11.4) — a security event.
func startGuardRefusal(err error) bool {
	ref, ok := agentclient.RefusalOf(err)
	return ok && ref.GetReason() == agentv1.RefusalReason_REFUSAL_REASON_STATE &&
		strings.Contains(strings.ToLower(ref.GetMessage()), "start guard")
}

// headscaleErr classifies an adapter error: unavailable, circuit open or no reachable instance yet ⇒ transient; the
// rest permanent (no_policy is a critical state: the instance would be allow-all).
func headscaleErr(op string, err error) error {
	var he *headscale.Error
	switch {
	case errors.As(err, &he) && (he.Kind == headscale.KindUnavailable || he.Kind == headscale.KindCircuitOpen):
		return jobs.Transient("instance_unavailable", fmt.Errorf("%s: %s", op, he.Kind))
	case errors.Is(err, headscale.ErrNoInstance):
		return jobs.Transient("instance_unavailable", fmt.Errorf("%s: no reachable instance in the registry yet", op))
	case errors.As(err, &he):
		return jobs.Permanent("headscale_"+string(he.Kind), fmt.Errorf("%s: %s", op, he.Kind))
	}
	return jobs.Transient("instance_unavailable", fmt.Errorf("%s: %s", op, err.Error()))
}

// idpErr classifies an IdP driver error: network-level failures ⇒ transient, refusals ⇒ permanent.
func idpErr(op string, err error) error {
	c := idp.CodeOf(err)
	switch c {
	case idp.CodeTimeout, idp.CodeUnavailable, idp.CodeUpstream, idp.CodeCredentials:
		return jobs.Transient("idp_"+string(c), fmt.Errorf("%s: %s", op, err.Error()))
	}
	return jobs.Permanent("idp_"+string(c), fmt.Errorf("%s: %s", op, err.Error()))
}

// recordStartGuard raises the security event of a start-guard refusal (best effort).
func (p *Provisioner) recordStartGuard(ctx context.Context, a *attempt, step string, err error) {
	if !startGuardRefusal(err) {
		return
	}
	p.cfg.Logger.Error("tenant.provision: the agent's start guard refused the instance", "step", step,
		"tenant_id", a.in.TenantID.String(), "job_id", a.r.JobID().String(), "alert", true)
	if p.cfg.Security == nil {
		return
	}
	t := a.in.TenantID
	if _, serr := p.cfg.Security.RecordSecurityEvent(context.WithoutCancel(ctx), audit.SecurityEvent{TenantID: nil,
		Kind: "instance.start_guard_failed", Severity: audit.SeverityCritical, Source: "provisioning",
		Details:   audit.Details{"tenant_id": t, "job_id": a.r.JobID(), "step": step},
		DedupeKey: "start_guard:" + t.String(), DedupeWindow: time.Hour}); serr != nil {
		p.cfg.Logger.Error("tenant.provision: security event not recorded", "error", serr.Error())
	}
}

// detail marshals a step detail (identifiers, codes, public values — never a secret).
func detail(s stepCtx, v map[string]any) error {
	if err := s.SetDetail(v); err != nil {
		return jobs.Permanent("invalid_step", err)
	}
	return nil
}

// record stores created_resources BEFORE the step creates what it names (§11.3).
func record(ctx context.Context, s stepCtx, v any) error {
	if err := s.RecordCreated(ctx, v); err != nil {
		var je *jobs.Error
		if errors.As(err, &je) {
			return err
		}
		return jobs.Transient("step_bookkeeping", err)
	}
	return nil
}

// rawJSON is a JSON object (settings of the request) or nil.
func rawJSON(b json.RawMessage) json.RawMessage {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return b
}
