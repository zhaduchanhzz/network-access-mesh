package quarantine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Agent is the part of the Host Agent the two jobs call (*agentclient.Client).
type Agent interface {
	GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, opts ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error)
	QuarantineInstance(ctx context.Context, in *agentv1.QuarantineInstanceRequest, opts ...grpc.CallOption) (*agentv1.QuarantineInstanceResponse, error)
	ReleaseInstance(ctx context.Context, in *agentv1.ReleaseInstanceRequest, opts ...grpc.CallOption) (*agentv1.ReleaseInstanceResponse, error)
	EnsureEdgeAttachment(ctx context.Context, in *agentv1.EnsureEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error)
}

// Config are the collaborators and settings of a Handler.
type Config struct {
	Store *store.Store // the worker's store
	// Agent isolates and releases the instance on its host. nil (no Host Agent configured): instance.quarantine stops at
	// instance.isolate with agent_not_configured (Critical — the registry stays quarantined), instance.release fails.
	Agent Agent
	// Headscale is the registry of the post-start gate of a release; it must reach the instance of a suspended tenant
	// (locator TenantStatuses active + suspended — the registry of lifecycle).
	Headscale headscale.Registry
	Notifier  notifications.Enqueuer // nil ⇒ notifications.Default
	Logger    *slog.Logger
	// Timing (§11.3); zero values take the defaults.
	StepRetries    int           // 5 — retries in place of a transient failure
	IsolateRetries int           // 8 — the isolation keeps trying until the job's 5 minutes are spent
	RetryBase      time.Duration // 2 s
	RetryMax       time.Duration // 60 s
	CallTimeout    time.Duration // one agent or Headscale call: 2 min
	ReleaseTimeout time.Duration // the ReleaseInstance call (start, health ≤ 90 s, policy): 4 min
}

// Handler runs instance.quarantine and instance.release in the worker.
type Handler struct{ cfg Config }

// New checks the configuration and returns the handler of both kinds.
func New(cfg Config) (*Handler, error) {
	if cfg.Store == nil || cfg.Headscale == nil {
		return nil, errors.New("quarantine: a store and a Headscale registry are required")
	}
	if cfg.Notifier == nil {
		cfg.Notifier = notifications.Default
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	for _, d := range []struct {
		v   *int
		def int
	}{{&cfg.StepRetries, 5}, {&cfg.IsolateRetries, 8}} {
		if *d.v == 0 {
			*d.v = d.def
		}
	}
	for _, d := range []struct {
		v   *time.Duration
		def time.Duration
	}{{&cfg.RetryBase, 2 * time.Second}, {&cfg.RetryMax, time.Minute}, {&cfg.CallTimeout, 2 * time.Minute},
		{&cfg.ReleaseTimeout, 4 * time.Minute}} {
		if *d.v == 0 {
			*d.v = d.def
		}
	}
	if cfg.StepRetries < 0 || cfg.IsolateRetries < 0 || cfg.RetryMax < cfg.RetryBase {
		return nil, errors.New("quarantine: invalid retry settings")
	}
	return &Handler{cfg: cfg}, nil
}

// Register registers the handlers of instance.quarantine and instance.release on the worker.
func (h *Handler) Register(w *jobs.Worker) error {
	if err := w.Register(KindQuarantine, jobs.HandlerFunc(h.quarantine)); err != nil {
		return err
	}
	return w.Register(KindRelease, jobs.HandlerFunc(h.release))
}

// ---------------------------------------------------------------------------------------------------- quarantine

// quarantine is instance.quarantine (steps 3–5; 1–2 ran in the API). A failure never lifts the quarantine.
func (h *Handler) quarantine(ctx context.Context, run *jobs.Run) error {
	var in Input
	if err := decode(run, &in); err != nil {
		return err
	}
	run.SetResource("instance", in.InstanceID.String())
	err := h.step(ctx, run, StepIsolate, h.cfg.IsolateRetries, func(ctx context.Context, s *jobs.StepRun) error {
		return h.isolate(ctx, s, run.ID, in)
	})
	if err == nil {
		err = h.step(ctx, run, StepVerify, h.cfg.IsolateRetries, func(ctx context.Context, s *jobs.StepRun) error {
			return h.verifyIsolated(ctx, s, in)
		})
	}
	if err != nil {
		if interrupted(ctx) {
			return err // the worker stops: the job resumes after the restart
		}
		h.quarantineIncomplete(ctx, run.ID, in, err)
		return final(err)
	}
	if err := h.step(ctx, run, StepNotify, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		return h.finishQuarantine(ctx, s, run.ID, in)
	}); err != nil {
		return err
	}
	return run.SetOutput(map[string]any{"instance_id": in.InstanceID, "tenant_id": in.TenantID,
		"status": tenants.InstanceQuarantined, "outcome": notifications.OutcomeIsolated})
}

// isolate is step 3: the registry status re-asserted, then the agent isolates the instance.
func (h *Handler) isolate(ctx context.Context, s *jobs.StepRun, jobID uuid.UUID, in Input) error {
	was, err := h.reassert(ctx, in)
	if err != nil {
		return err
	}
	detail := map[string]any{"registry_status_before": was, "from": in.From}
	if h.cfg.Agent == nil {
		setDetail(s, detail)
		return jobs.Permanent("agent_not_configured", errors.New("no Host Agent configured: the instance cannot be isolated on its host"))
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.CallTimeout)
	defer cancel()
	resp, err := h.cfg.Agent.QuarantineInstance(cctx, &agentv1.QuarantineInstanceRequest{Instance: ref(in.TenantID, in.InstanceID, in.Slug),
		JobId: jobID.String()})
	switch {
	case err != nil && notFound(err) && nothingOnHost(in.From):
		detail["host"] = "no_instance_on_host"
		setDetail(s, detail)
		return nil
	case err != nil && notFound(err):
		setDetail(s, detail)
		return jobs.Permanent("instance_not_on_agent", errors.New(
			"the Host Agent does not manage this instance (deployed by hand?): isolate it by hand (RUNBOOK)"))
	case err != nil:
		setDetail(s, detail)
		return agentErr("QuarantineInstance", err)
	}
	detail["marked_now"], detail["edge_was_attached"], detail["container_was_running"] = resp.GetMarkedNow(),
		resp.GetEdgeWasAttached(), resp.GetContainerWasRunning()
	setDetail(s, detail)
	return nil
}

// nothingOnHost: an instance quarantined before it was ever deployed (allocated) or after its deployment failed has
// nothing on the host when the agent does not know it.
func nothingOnHost(from string) bool {
	return from == tenants.InstanceAllocated || from == tenants.InstanceFailed
}

// reassert puts the registry status back to quarantined when it changed since the request (a release that ended
// meanwhile); it returns the status it found.
func (h *Handler) reassert(ctx context.Context, in Input) (string, error) {
	var was string
	err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.LockInstanceForQuarantine(ctx, in.InstanceID)
		if errors.Is(err, store.ErrNoRows) {
			return jobs.Permanent("registry_state", fmt.Errorf("instance %s not found", in.InstanceID))
		}
		if err != nil {
			return err
		}
		was = inst.Status
		switch {
		case inst.TenantID != in.TenantID:
			return jobs.Permanent("invalid_input", errors.New("the instance belongs to another tenant than the job's"))
		case inst.Status == tenants.InstanceQuarantined:
			return nil
		case inst.Status == tenants.InstanceRemoved:
			return jobs.Permanent(ReasonRemoved, fmt.Errorf("instance %s was removed", in.InstanceID))
		}
		_, err = q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{
			Status: tenants.InstanceQuarantined, ID: in.InstanceID, TenantID: in.TenantID, FromStatus: inst.Status})
		return err
	})
	return was, dbErr("re-assert the quarantine in the registry", err)
}

// verifyIsolated is step 4: the agent's own view of the instance — marked, no flag, edge not attached, not running.
func (h *Handler) verifyIsolated(ctx context.Context, s *jobs.StepRun, in Input) error {
	if h.cfg.Agent == nil {
		return jobs.Permanent("agent_not_configured", errors.New("no Host Agent configured"))
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.CallTimeout)
	defer cancel()
	r, err := h.cfg.Agent.GetInstanceStatus(cctx, &agentv1.GetInstanceStatusRequest{Instance: ref(in.TenantID, in.InstanceID, in.Slug)})
	switch {
	case err != nil && notFound(err) && nothingOnHost(in.From):
		setDetail(s, map[string]any{"host": "no_instance_on_host"})
		return nil
	case err != nil:
		return agentErr("GetInstanceStatus", err)
	}
	st := r.GetStatus()
	running := containerRunning(st.GetContainerState())
	setDetail(s, map[string]any{"quarantined": st.GetQuarantined(), "edge_attach_flag": st.GetEdgeAttachFlag(),
		"edge_attached": st.GetNetwork().GetEdgeAttached(), "container_state": st.GetContainerState().String()})
	if !st.GetQuarantined() || st.GetEdgeAttachFlag() || st.GetNetwork().GetEdgeAttached() || running {
		// the edge supervisor contains a marked instance again within one cycle: the retry sees it
		return jobs.Transient("containment_incomplete", fmt.Errorf("marked %v, flag %v, edge attached %v, container %s",
			st.GetQuarantined(), st.GetEdgeAttachFlag(), st.GetNetwork().GetEdgeAttached(), st.GetContainerState()))
	}
	return nil
}

func containerRunning(s agentv1.ContainerState) bool {
	switch s {
	case agentv1.ContainerState_CONTAINER_STATE_ABSENT, agentv1.ContainerState_CONTAINER_STATE_CREATED,
		agentv1.ContainerState_CONTAINER_STATE_EXITED, agentv1.ContainerState_CONTAINER_STATE_DEAD:
		return false
	}
	return true // running, restarting, paused — or a state the worker does not know (fail closed)
}

// finishQuarantine is step 5: the notification of the platform staff, then the audit pair closes (once).
func (h *Handler) finishQuarantine(ctx context.Context, s *jobs.StepRun, jobID uuid.UUID, in Input) error {
	var notified int
	if err := h.cfg.Store.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		r, err := h.cfg.Notifier.Enqueue(ctx, tx, notifications.InstanceQuarantined(in.InstanceID, in.Slug, jobID,
			notifications.OutcomeIsolated))
		notified = len(r.Notifications)
		if err != nil {
			return err
		}
		return succeeded(ctx, tx.Q, in.Operation, audit.Details{"job_id": jobID, "from": in.From,
			"outcome": notifications.OutcomeIsolated})
	}); err != nil {
		if errors.Is(err, notifications.ErrInvalidEvent) {
			return jobs.Permanent("notification_invalid", err)
		}
		return dbErr("notify", err)
	}
	setDetail(s, map[string]any{"notifications": notified})
	return nil
}

// quarantineIncomplete records a quarantine the job could not complete: Critical security event, the staff told
// ("incomplete" — the instance may still serve), the audit pair closed with .failed. The registry stays quarantined.
func (h *Handler) quarantineIncomplete(ctx context.Context, jobID uuid.UUID, in Input, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.cfg.CallTimeout)
	defer cancel()
	code := jobs.CodeOf(cause)
	err := h.cfg.Store.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		if _, err := audit.RecordSecurityEvent(ctx, tx.Q, audit.SecurityEvent{Kind: EventQuarantineIncomplete,
			Severity: audit.SeverityCritical, Source: Source, Details: audit.Details{"instance_id": in.InstanceID,
				"tenant_id": in.TenantID, "slug": in.Slug, "job_id": jobID, "code": code},
			DedupeKey: "job:" + jobID.String(), DedupeWindow: 24 * time.Hour}); err != nil {
			return err
		}
		if _, err := h.cfg.Notifier.Enqueue(ctx, tx, notifications.InstanceQuarantined(in.InstanceID, in.Slug, jobID,
			notifications.OutcomeIncomplete)); err != nil {
			return err
		}
		return failed(ctx, tx.Q, in.Operation, code, audit.Details{"job_id": jobID, "outcome": notifications.OutcomeIncomplete})
	})
	h.cfg.Logger.Error("instance quarantine incomplete: the registry keeps it quarantined, isolate it by hand",
		"instance_id", in.InstanceID, "tenant_id", in.TenantID, "job_id", jobID, "code", code, "record_error", errString(err))
}

// ---------------------------------------------------------------------------------------------------- release

// prepared is created_resources of release.prepare.
type prepared struct {
	ExpectedPolicySHA256 string    `json:"expected_policy_sha256"`
	PolicyApplicationID  uuid.UUID `json:"policy_application_id"`
}

// statusMove is created_resources of registry.starting.
type statusMove struct {
	From string `json:"from"`
}

// release is instance.release (steps 2–8). Any failure after release.prepare isolates the instance again.
func (h *Handler) release(ctx context.Context, run *jobs.Run) error {
	var in ReleaseInput
	if err := decode(run, &in); err != nil {
		return err
	}
	run.SetResource("instance", in.InstanceID.String())
	var p prepared
	touched, err := h.releaseSteps(ctx, run, in, &p)
	if err != nil {
		if interrupted(ctx) {
			return err
		}
		h.releaseFailed(ctx, run.ID, in, touched, err)
		return final(err)
	}
	if err := h.step(ctx, run, StepNotify, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		return h.finishRelease(ctx, s, run.ID, in, p)
	}); err != nil {
		return err
	}
	return run.SetOutput(map[string]any{"instance_id": in.InstanceID, "tenant_id": in.TenantID,
		"status": tenants.InstanceRunning, "policy_sha256": p.ExpectedPolicySHA256, "approval_id": in.ApprovalID})
}

// releaseSteps runs steps 2–7; touched: release.prepare succeeded — from there on a failure isolates the instance again.
func (h *Handler) releaseSteps(ctx context.Context, run *jobs.Run, in ReleaseInput, p *prepared) (touched bool, err error) {
	if err := h.step(ctx, run, StepPrepare, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		return h.prepare(ctx, s, in)
	}); err != nil {
		return false, err
	}
	found, err := run.StepResources(ctx, StepPrepare, p)
	if err != nil {
		return false, err
	}
	if !found || p.ExpectedPolicySHA256 == "" {
		return false, jobs.Permanent("invalid_state", errors.New("release.prepare recorded no policy"))
	}
	r := ref(in.TenantID, in.InstanceID, in.Slug)
	if err := h.step(ctx, run, StepRelease, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		cctx, cancel := context.WithTimeout(ctx, h.cfg.ReleaseTimeout)
		defer cancel()
		if h.cfg.Agent == nil {
			return jobs.Permanent("agent_not_configured", errors.New("no Host Agent configured"))
		}
		resp, err := h.cfg.Agent.ReleaseInstance(cctx, &agentv1.ReleaseInstanceRequest{Instance: r, JobId: run.ID.String(),
			ExpectedPolicySha256: p.ExpectedPolicySHA256})
		if err != nil {
			if startGuardRefusal(err) {
				h.securityEvent(ctx, EventStartGuard, audit.SeverityCritical, run.ID, in, audit.Details{"code": "start_guard"})
			}
			return agentErr("ReleaseInstance", err)
		}
		setDetail(s, map[string]any{"was_quarantined": resp.GetWasQuarantined(), "policy_sha256": resp.GetPolicySha256(),
			"container_state": resp.GetStatus().GetContainerState().String(), "health": resp.GetStatus().GetHealth().String()})
		return nil
	}); err != nil {
		return true, err
	}
	if err := h.step(ctx, run, StepStarting, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		return h.move(ctx, s, in, tenants.InstanceQuarantined, tenants.InstanceStarting)
	}); err != nil {
		return true, err
	}
	if err := h.step(ctx, run, StepAttach, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		cctx, cancel := context.WithTimeout(ctx, h.cfg.CallTimeout)
		defer cancel()
		resp, err := h.cfg.Agent.EnsureEdgeAttachment(cctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: r, JobId: run.ID.String()})
		if err != nil {
			if startGuardRefusal(err) {
				h.securityEvent(ctx, EventStartGuard, audit.SeverityCritical, run.ID, in, audit.Details{"code": "start_guard"})
			}
			return agentErr("EnsureEdgeAttachment", err)
		}
		setDetail(s, map[string]any{"attached": resp.GetAttached(), "already_attached": resp.GetAlreadyAttached(),
			"network_members": resp.GetNetworkMembers()})
		return nil
	}); err != nil {
		return true, err
	}
	if err := h.step(ctx, run, StepGate, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		return h.postStartGate(ctx, s, run.ID, in, p.ExpectedPolicySHA256)
	}); err != nil {
		return true, err
	}
	if err := h.step(ctx, run, StepRunning, h.cfg.StepRetries, func(ctx context.Context, s *jobs.StepRun) error {
		return h.move(ctx, s, in, tenants.InstanceStarting, tenants.InstanceRunning)
	}); err != nil {
		return true, err
	}
	return true, nil
}

// prepare is step 2: the instance quarantined, its tenant active or suspended, the sha256 of the policy the registry
// says it serves (the current applied policy_applications row) — the policy the released instance must serve.
func (h *Handler) prepare(ctx context.Context, s *jobs.StepRun, in ReleaseInput) error {
	var inst sqlcdb.GetInstanceForQuarantineRow
	if err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		inst, err = q.GetInstanceForQuarantine(ctx, in.InstanceID)
		return err
	}); errors.Is(err, store.ErrNoRows) {
		return jobs.Permanent("registry_state", fmt.Errorf("instance %s not found", in.InstanceID))
	} else if err != nil {
		return dbErr("read the instance", err)
	}
	switch {
	case inst.TenantID != in.TenantID:
		return jobs.Permanent("invalid_input", errors.New("the instance belongs to another tenant than the job's"))
	case inst.Status != tenants.InstanceQuarantined:
		return jobs.Permanent(ReasonNotQuarantined, fmt.Errorf("the instance is %s, not quarantined", inst.Status))
	case inst.TenantStatus != tenants.StatusActive && inst.TenantStatus != tenants.StatusSuspended:
		return jobs.Permanent("tenant_state", fmt.Errorf("the tenant is %s", inst.TenantStatus))
	}
	var app sqlcdb.PolicyApplication
	err := h.cfg.Store.WithTenantTx(ctx, in.TenantID, func(q *sqlcdb.Queries) error {
		var err error
		app, err = q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: in.TenantID,
			InstanceID: in.InstanceID})
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return jobs.Permanent("no_applied_policy", errors.New(
			"no applied policy recorded for the instance: the policy it must serve is unknown — not released"))
	}
	if err != nil {
		return dbErr("read the applied policy", err)
	}
	p := prepared{ExpectedPolicySHA256: app.AppliedSha256, PolicyApplicationID: app.ID}
	if err := record(ctx, s, p); err != nil {
		return err
	}
	setDetail(s, map[string]any{"expected_policy_sha256": p.ExpectedPolicySHA256, "policy_application_id": app.ID,
		"tenant_status": inst.TenantStatus})
	return nil
}

// move moves the instance from → to in the registry (conditional); already in `to` (an earlier attempt) is done. A
// quarantine requested meanwhile (status quarantined when moving starting → running) fails the release.
func (h *Handler) move(ctx context.Context, s *jobs.StepRun, in ReleaseInput, from, to string) error {
	if err := record(ctx, s, statusMove{From: from}); err != nil {
		return err
	}
	var now string
	err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{Status: to,
			ID: in.InstanceID, TenantID: in.TenantID, FromStatus: from})
		if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		inst, gerr := q.GetInstanceForQuarantine(ctx, in.InstanceID)
		if gerr != nil {
			return gerr
		}
		now = inst.Status
		return nil
	})
	switch {
	case err != nil:
		return dbErr("move the instance status", err)
	case now == "" || now == to:
		setDetail(s, map[string]any{"from": from, "to": to, "changed": now == ""})
		return nil
	case now == tenants.InstanceQuarantined:
		return jobs.Permanent(CodeQuarantineRequested, errors.New("the instance was quarantined again during the release"))
	}
	return jobs.Permanent("registry_state", fmt.Errorf("the instance is %s, not %s", now, from))
}

// postStartGate is step 6 — §11.4 Post-start gate through the Headscale API: the instance accepts the platform's API
// key (Health — a rejected key means a replaced database, §13.4), its database answers, and GetPolicy is exactly the
// applied policy. A missing policy, a rejected key or another policy is permanent (Critical / High).
func (h *Handler) postStartGate(ctx context.Context, s *jobs.StepRun, jobID uuid.UUID, in ReleaseInput, want string) error {
	cctx, cancel := context.WithTimeout(ctx, h.cfg.CallTimeout)
	defer cancel()
	inst, err := h.cfg.Headscale.ForTenant(cctx, in.TenantID)
	if err != nil {
		return headscaleErr("ForTenant", err)
	}
	hl, err := inst.Health(cctx)
	if err != nil {
		if errors.Is(err, headscale.ErrAPIKeyRejected) {
			h.securityEvent(ctx, EventPostStartGate, audit.SeverityCritical, jobID, in, audit.Details{"code": "api_key_rejected"})
		}
		return headscaleErr("Health", err)
	}
	if !hl.DatabaseConnectivity {
		return jobs.Transient("instance_unhealthy", errors.New("the instance reports no database connectivity"))
	}
	pol, err := inst.GetPolicy(cctx)
	if errors.Is(err, headscale.ErrNoPolicy) {
		h.securityEvent(ctx, EventPostStartGate, audit.SeverityCritical, jobID, in, audit.Details{"code": "no_policy"})
		return jobs.Permanent("no_policy", errors.New("the instance has no policy (allow-all)"))
	}
	if err != nil {
		return headscaleErr("GetPolicy", err)
	}
	sum := sha256.Sum256([]byte(pol.Data))
	got := hex.EncodeToString(sum[:])
	setDetail(s, map[string]any{"post_start_gate": "checked", "applied_sha256": want, "read_sha256": got})
	if got != want {
		h.securityEvent(ctx, EventPostStartGate, audit.SeverityHigh, jobID, in, audit.Details{"code": "policy_drift",
			"applied_sha256": want, "read_sha256": got})
		return jobs.Permanent("policy_drift", fmt.Errorf("the instance serves the policy sha256 %s, not the applied %s", got, want))
	}
	return nil
}

// finishRelease is step 8: security event instance.released (high), the staff told, the audit pair closed (once).
func (h *Handler) finishRelease(ctx context.Context, s *jobs.StepRun, jobID uuid.UUID, in ReleaseInput, p prepared) error {
	var notified int
	if err := h.cfg.Store.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		if _, err := audit.RecordSecurityEvent(ctx, tx.Q, audit.SecurityEvent{Kind: EventReleased, Severity: audit.SeverityHigh,
			Source: Source, Details: audit.Details{"instance_id": in.InstanceID, "tenant_id": in.TenantID, "slug": in.Slug,
				"job_id": jobID, "approval_id": in.ApprovalID, "policy_sha256": p.ExpectedPolicySHA256},
			DedupeKey: "job:" + jobID.String(), DedupeWindow: 24 * time.Hour}); err != nil {
			return err
		}
		r, err := h.cfg.Notifier.Enqueue(ctx, tx, notifications.InstanceReleased(in.InstanceID, in.Slug, jobID,
			notifications.OutcomeReleased))
		notified = len(r.Notifications)
		if err != nil {
			return err
		}
		return succeeded(ctx, tx.Q, in.Operation, audit.Details{"job_id": jobID, "approval_id": in.ApprovalID,
			"policy_sha256": p.ExpectedPolicySHA256})
	}); err != nil {
		if errors.Is(err, notifications.ErrInvalidEvent) {
			return jobs.Permanent("notification_invalid", err)
		}
		return dbErr("notify", err)
	}
	setDetail(s, map[string]any{"notifications": notified})
	return nil
}

// releaseFailed is the end of a release that did not complete: when it may have touched the instance (release.prepare
// succeeded), the instance is isolated again (QuarantineInstance) and the registry moved back from starting to
// quarantined; then security event instance.release_failed (high), the staff told ("refused"), the audit pair closed.
func (h *Handler) releaseFailed(ctx context.Context, jobID uuid.UUID, in ReleaseInput, touched bool, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.cfg.CallTimeout)
	defer cancel()
	code := jobs.CodeOf(cause)
	isolated, back := "not_needed", "not_needed"
	if touched {
		isolated = "no_agent"
		if h.cfg.Agent != nil {
			_, err := h.cfg.Agent.QuarantineInstance(ctx, &agentv1.QuarantineInstanceRequest{
				Instance: ref(in.TenantID, in.InstanceID, in.Slug), JobId: jobID.String()})
			isolated = "isolated"
			if err != nil {
				isolated = "failed: " + status.Code(err).String()
			}
		}
		err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			_, err := q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{
				Status: tenants.InstanceQuarantined, ID: in.InstanceID, TenantID: in.TenantID, FromStatus: tenants.InstanceStarting})
			if errors.Is(err, store.ErrNoRows) {
				return nil // still (or again) quarantined
			}
			return err
		})
		back = "quarantined"
		if err != nil {
			back = "failed"
		}
	}
	severity := audit.SeverityHigh
	if strings.HasPrefix(isolated, "failed") || back == "failed" {
		severity = audit.SeverityCritical
	}
	err := h.cfg.Store.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		if _, err := audit.RecordSecurityEvent(ctx, tx.Q, audit.SecurityEvent{Kind: EventReleaseFailed, Severity: severity,
			Source: Source, Details: audit.Details{"instance_id": in.InstanceID, "tenant_id": in.TenantID, "slug": in.Slug,
				"job_id": jobID, "approval_id": in.ApprovalID, "code": code, "isolated_again": isolated, "registry": back},
			DedupeKey: "job:" + jobID.String(), DedupeWindow: 24 * time.Hour}); err != nil {
			return err
		}
		if _, err := h.cfg.Notifier.Enqueue(ctx, tx, notifications.InstanceReleased(in.InstanceID, in.Slug, jobID,
			notifications.OutcomeRefused)); err != nil {
			return err
		}
		return failed(ctx, tx.Q, in.Operation, code, audit.Details{"job_id": jobID, "approval_id": in.ApprovalID,
			"isolated_again": isolated})
	})
	h.cfg.Logger.Warn("instance release failed: the instance stays quarantined", "instance_id", in.InstanceID,
		"job_id", jobID, "code", code, "isolated_again", isolated, "registry", back, "record_error", errString(err))
}

// securityEvent records a platform security event of the release (its own transaction; a failure is logged).
func (h *Handler) securityEvent(ctx context.Context, kind, severity string, jobID uuid.UUID, in ReleaseInput, d audit.Details) {
	d["instance_id"], d["tenant_id"], d["slug"], d["job_id"] = in.InstanceID, in.TenantID, in.Slug, jobID
	err := h.cfg.Store.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(ctx, q, audit.SecurityEvent{Kind: kind, Severity: severity, Source: Source,
			Details: d, DedupeKey: kind + ":job:" + jobID.String(), DedupeWindow: 24 * time.Hour})
		return err
	})
	if err != nil {
		h.cfg.Logger.Error("security event not recorded", "kind", kind, "job_id", jobID, "error", err.Error())
	}
}

// ---------------------------------------------------------------------------------------------------- helpers

func ref(tenantID, instanceID uuid.UUID, slug string) *agentv1.InstanceRef {
	return &agentv1.InstanceRef{InstanceId: instanceID.String(), TenantId: tenantID.String(), Slug: slug}
}

// input is the input of one of the two kinds.
type input interface {
	validate() error
	ids() (tenant, instance uuid.UUID)
}

func (in Input) ids() (uuid.UUID, uuid.UUID)        { return in.TenantID, in.InstanceID }
func (in ReleaseInput) ids() (uuid.UUID, uuid.UUID) { return in.TenantID, in.InstanceID }

// decode reads and checks the job's input: valid, and naming the job's own tenant and instance.
func decode[T input](run *jobs.Run, in *T) error {
	if err := run.DecodeInput(in); err != nil {
		return jobs.Permanent("invalid_input", fmt.Errorf("job input unreadable: %w", err))
	}
	if err := (*in).validate(); err != nil {
		return jobs.Permanent("invalid_input", err)
	}
	tid, iid := (*in).ids()
	if run.TenantID == nil || *run.TenantID != tid || run.InstanceID == nil || *run.InstanceID != iid {
		return jobs.Permanent("invalid_input", errors.New("the job's tenant or instance is not the input's"))
	}
	return nil
}

// interrupted: the worker is stopping (not the job's deadline) — the attempt resumes after the restart.
func interrupted(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.Canceled)
}

// final makes a failure end the job (never retried by the queue: a release needs a new approval, a quarantine a new
// request — the registry stays quarantined either way).
func final(err error) error {
	var je *jobs.Error
	if errors.As(err, &je) && je.Permanent {
		return err
	}
	return jobs.Permanent(jobs.CodeOf(err), err)
}

func succeeded(ctx context.Context, q *sqlcdb.Queries, op audit.Operation, d audit.Details) error {
	st, err := q.OperationState(ctx, op.ID)
	if err != nil || st.Finished {
		return err
	}
	return op.Succeeded(ctx, q, d)
}

func failed(ctx context.Context, q *sqlcdb.Queries, op audit.Operation, code string, d audit.Details) error {
	st, err := q.OperationState(ctx, op.ID)
	if err != nil || st.Finished {
		return err
	}
	return op.Failed(ctx, q, code, d)
}

// step runs one step with the retry policy of §11.3: a transient failure is retried in place up to retries times
// with exponential backoff; spent ⇒ Resumable. A permanent failure, a stop (step gate, /cancel) or the end of ctx is
// returned at once.
func (h *Handler) step(ctx context.Context, run *jobs.Run, name string, retries int, fn func(ctx context.Context, s *jobs.StepRun) error) error {
	for try := 0; ; try++ {
		err := run.Step(ctx, name, fn)
		switch {
		case err == nil:
			return nil
		case jobs.IsPermanent(err), jobs.IsResumable(err), ctx.Err() != nil:
			return err
		case try >= retries:
			return jobs.Resumable(jobs.CodeOf(err), fmt.Errorf("step %s: %d retries spent: %w", name, try, err))
		}
		t := time.NewTimer(h.backoff(try + 1))
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
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

func setDetail(s *jobs.StepRun, v map[string]any) { _ = s.SetDetail(v) }

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// notFound: the agent does not know the instance (NOT_FOUND refusal).
func notFound(err error) bool {
	r, ok := agentclient.RefusalOf(err)
	return status.Code(err) == codes.NotFound && ok && r.GetReason() == agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND
}

// startGuardRefusal: the agent refused because the start guard failed (§11.4).
func startGuardRefusal(err error) bool {
	r, ok := agentclient.RefusalOf(err)
	return ok && r.GetReason() == agentv1.RefusalReason_REFUSAL_REASON_STATE &&
		strings.Contains(strings.ToLower(r.GetMessage()), "start guard")
}

// agentErr classifies an error of the Host Agent: unreachable, busy (per-instance lock) or deadline ⇒ transient; a
// typed refusal or UNIMPLEMENTED ⇒ permanent, code agent_<reason>.
func agentErr(rpc string, err error) error {
	msg := rpc + ": " + status.Convert(err).Message()
	r, refused := agentclient.RefusalOf(err)
	if refused {
		msg = fmt.Sprintf("%s: %s refused (%s): %s", rpc, r.GetField(), refusalCode(r.GetReason()), r.GetMessage())
	}
	switch {
	case agentclient.Retryable(err):
		code := "agent_unavailable"
		if status.Code(err) == codes.Aborted {
			code = "agent_busy"
		}
		return jobs.Transient(code, errors.New(msg))
	case refused:
		return jobs.Permanent("agent_"+refusalCode(r.GetReason()), errors.New(msg))
	}
	return jobs.Permanent("agent_error", errors.New(msg))
}

func refusalCode(r agentv1.RefusalReason) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "REFUSAL_REASON_"))
}

// headscaleErr classifies an adapter error: unavailable, circuit open or no reachable instance (the registry not seen
// yet) ⇒ transient; a rejected API key (§13.4: suspect a replaced database) and the rest ⇒ permanent.
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

// dbErr classifies a database error: transient (an error that already carries a job code keeps it).
func dbErr(what string, err error) error {
	if err == nil {
		return nil
	}
	var je *jobs.Error
	if errors.As(err, &je) {
		return err
	}
	return jobs.Transient("registry_unavailable", fmt.Errorf("%s: sqlstate %q", what, store.SQLState(err)))
}
