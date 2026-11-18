package orchestrator

// instance.restart (P3-T13a, §11.4 rows Restart and Post-start gate, §13.5): a controlled restart of a running instance
// through the Host Agent, behind the health gate and the post-start gate.
//
//	1 instance.restart  instance running (quarantined ⇒ refused), tenant active/suspended; the container's start time
//	                    recorded; Agent RestartInstance — the start guard of the agent (data/ files, Noise key, data-check;
//	                    a refusal ⇒ Critical, the agent already contained the instance)
//	2 instance.health   container running + healthy, started after the restart, the configuration in force, the same
//	                    Noise key; GET /api/v1/health through the adapter — the platform's API key refused ⇒ the database
//	                    was replaced: Critical, edge detached (§13.4)
//	3 policy.gate       post-start gate: GetPolicy = applied_sha256; changed out of band ⇒ applied again at once
//	                    (policy.apply drift_repair) and read back; no policy ⇒ Critical, edge detached
//	4 edge.verify       Prober (/key = the instance's key, forbidden paths 404); no prober ⇒ skipped
//	5 restart.finish    audit .succeeded
//
// A restart cannot be undone: a permanent failure ends rolled_back — the compensation has nothing to undo, it closes the
// operation (.failed), notifies the platform staff and releases the tenant's lifecycle lock (an instance whose database
// was replaced must stay restorable — instance.restore is a lifecycle job). Transient failures are retried in place, then
// failed_resumable (/retry resumes, /rollback closes).

import (
	"context"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// The steps of instance.restart, in order.
const (
	RSStepRestart = "instance.restart"
	RSStepHealth  = "instance.health"
	RSStepPolicy  = "policy.gate"
	RSStepEdge    = StepEdgeVerify
	RSStepFinish  = "restart.finish"
)

// RestartSteps lists the steps of instance.restart in order.
var RestartSteps = []string{RSStepRestart, RSStepHealth, RSStepPolicy, RSStepEdge, RSStepFinish}

// InstanceRestarter runs instance.restart in the worker: jobs.Handler and jobs.Compensator.
type InstanceRestarter struct{ ops *instanceOps }

var (
	_ jobs.Handler     = (*InstanceRestarter)(nil)
	_ jobs.Compensator = (*InstanceRestarter)(nil)
)

// NewRestarter checks the configuration and returns the handler of instance.restart.
func NewRestarter(cfg InstanceOpsConfig) (*InstanceRestarter, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	return &InstanceRestarter{ops: &instanceOps{cfg: cfg, kind: RestartKind}}, nil
}

// Register registers the handler of instance.restart on the worker.
func (c *InstanceRestarter) Register(w *jobs.Worker) error { return w.Register(RestartKind, c) }

// Run implements jobs.Handler.
func (c *InstanceRestarter) Run(ctx context.Context, run *jobs.Run) error {
	return c.run(ctx, jobRunner{run})
}

// Compensate implements jobs.Compensator.
func (c *InstanceRestarter) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return c.compensate(ctx, jobRunner{run}, cause)
}

// RunAttempt / CompensateAttempt drive the same state machine on an in-memory JobRunner (the real-Docker test).
func (c *InstanceRestarter) RunAttempt(ctx context.Context, r JobRunner) error { return c.run(ctx, r) }

// CompensateAttempt runs the compensation on r after cause.
func (c *InstanceRestarter) CompensateAttempt(ctx context.Context, r JobRunner, cause error) error {
	return c.compensate(ctx, r, cause)
}

// restartResources is created_resources of instance.restart: the container's start time before the restart.
type restartedResources struct {
	BeforeStartedAt time.Time `json:"before_started_at,omitzero"`
}

func (c *InstanceRestarter) run(ctx context.Context, r runner) error {
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
	return r.SetOutput(map[string]any{"tenant_id": a.in.TenantID, "instance_id": a.in.InstanceID, "restarted": true})
}

func (c *InstanceRestarter) steps(ctx context.Context, a *opsAttempt) error {
	o, r := c.ops, a.r
	if err := o.step(ctx, r, RSStepRestart, func(ctx context.Context, s stepCtx) error { return c.stepRestart(ctx, a, s) }); err != nil {
		return err
	}
	if err := o.step(ctx, r, RSStepHealth, func(ctx context.Context, s stepCtx) error { return c.stepHealth(ctx, a, s) }); err != nil {
		return err
	}
	if err := o.step(ctx, r, RSStepPolicy, func(ctx context.Context, s stepCtx) error {
		t, err := o.target(ctx, a, false)
		if err != nil {
			return err
		}
		d, err := o.postStartGate(ctx, a, t)
		_ = detail(s, d)
		return err
	}); err != nil {
		return err
	}
	if err := o.step(ctx, r, RSStepEdge, func(ctx context.Context, s stepCtx) error { return o.edgeVerify(ctx, a, s) }); err != nil {
		return err
	}
	return o.step(ctx, r, RSStepFinish, func(ctx context.Context, s stepCtx) error {
		if err := o.cfg.Store.FinishOperation(ctx, a.in.Operation, audit.Details{"job_id": a.r.JobID(), "instance_id": a.in.InstanceID,
			"tenant_id": a.in.TenantID, "restarted": true}); err != nil {
			return storeErr("close the audit operation", err)
		}
		return detail(s, map[string]any{"restarted": true})
	})
}

func (c *InstanceRestarter) stepRestart(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	t, err := o.target(ctx, a, true) // never restart a quarantined instance (§11.4)
	if err != nil {
		return err
	}
	var res restartedResources
	if found, err := s.Previous(&res); err != nil {
		return err
	} else if !found {
		before, err := o.status(ctx, t.ref())
		if err != nil {
			return err
		}
		res = restartedResources{BeforeStartedAt: startedAt(before)}
		if err := record(ctx, s, res); err != nil {
			return err
		}
	}
	cctx, cancel := o.call(ctx)
	defer cancel()
	resp, err := o.cfg.Agent.RestartInstance(cctx, &agentv1.RestartInstanceRequest{Instance: t.ref(), JobId: a.r.JobID().String()})
	if err != nil {
		o.startGuard(ctx, a, RSStepRestart, err)
		return agentErr("RestartInstance", err)
	}
	return detail(s, map[string]any{"container_state": resp.GetStatus().GetContainerState().String(),
		"started_at": startedAt(resp.GetStatus()).Format(time.RFC3339Nano)})
}

func (c *InstanceRestarter) stepHealth(ctx context.Context, a *opsAttempt, s stepCtx) error {
	o := c.ops
	var rs restartedResources
	if _, err := a.r.StepResources(ctx, RSStepRestart, &rs); err != nil {
		return err
	}
	t, err := o.target(ctx, a, false)
	if err != nil {
		return err
	}
	want := gateWant{After: rs.BeforeStartedAt}
	if t.Current != nil {
		want.ConfigSHA256 = t.Current.ConfigSHA256
	}
	d, err := o.gate(ctx, a, t, want)
	_ = detail(s, d)
	return err
}

// compensate: nothing to undo — the operation is closed (.failed with the cause's code), the platform staff notified;
// every step is marked compensation skipped and the job ends rolled_back (the lock released).
func (c *InstanceRestarter) compensate(ctx context.Context, r runner, cause error) error {
	o := c.ops
	a, err := o.input(r)
	if err != nil {
		return err
	}
	if err := r.CompensateSteps(ctx, map[string]jobs.CompensateFunc{}); err != nil {
		return err
	}
	return o.fail(ctx, a, jobs.CodeOf(cause), OutcomeRolledBack, audit.Details{"restart_undone": false}, nil)
}
