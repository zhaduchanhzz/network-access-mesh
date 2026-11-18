package faultinject

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// layer builds the error of a fault the way the real collaborator of that layer fails.
type layer interface {
	err(call string, m Mode) error
}

func msg(call string) string { return ErrInjected.Error() + " at " + call }

// ---------------------------------------------------------------------------------------------------- Host Agent

type agentLayer struct{}

// err: a typed refusal (FAILED_PRECONDITION + Refusal, as apps/agent answers a request it will not serve) or
// UNAVAILABLE (the agent restarting) — agentclient.RefusalOf / agentclient.Retryable see them as the real thing.
func (agentLayer) err(call string, m Mode) error {
	if m == Permanent {
		st, derr := status.New(codes.FailedPrecondition, msg(call)).WithDetails(&agentv1.Refusal{
			Reason: agentv1.RefusalReason_REFUSAL_REASON_STATE, Field: "fault_injection", Message: msg(call)})
		if derr != nil {
			return status.Error(codes.FailedPrecondition, msg(call))
		}
		return st.Err()
	}
	return status.Error(codes.Unavailable, msg(call))
}

// Agent decorates the Host Agent client of the state machine (orchestrator.Agent; *agentclient.Client in production).
type Agent struct {
	Next orchestrator.Agent
	In   *Injector
}

var _ orchestrator.Agent = (*Agent)(nil)

func phaseCall(p agentv1.TargetPhase) string {
	switch p {
	case agentv1.TargetPhase_TARGET_PHASE_STORAGE:
		return "agent.EnsureInstance:STORAGE"
	case agentv1.TargetPhase_TARGET_PHASE_CONFIG:
		return "agent.EnsureInstance:CONFIG"
	case agentv1.TargetPhase_TARGET_PHASE_NETWORK:
		return "agent.EnsureInstance:NETWORK"
	case agentv1.TargetPhase_TARGET_PHASE_CONTAINER:
		return "agent.EnsureInstance:CONTAINER"
	}
	return "agent.EnsureInstance:" + p.String()
}

// wrap runs one call of the agent through the injector.
func wrapRPC[T any](in *Injector, call string, real func() (T, error)) (T, error) {
	var zero T
	if err := in.before(agentLayer{}, call); err != nil {
		return zero, err
	}
	out, err := real()
	if err != nil {
		return out, err
	}
	if ierr := in.after(agentLayer{}, call); ierr != nil {
		return zero, ierr
	}
	return out, nil
}

// ValidateConfig implements orchestrator.Agent.
func (a *Agent) ValidateConfig(ctx context.Context, r *agentv1.ValidateConfigRequest, o ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	return wrapRPC(a.In, "agent.ValidateConfig", func() (*agentv1.ValidateConfigResponse, error) { return a.Next.ValidateConfig(ctx, r, o...) })
}

// EnsureInstance implements orchestrator.Agent (the call name carries the target phase).
func (a *Agent) EnsureInstance(ctx context.Context, r *agentv1.EnsureInstanceRequest, o ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	return wrapRPC(a.In, phaseCall(r.GetTargetPhase()), func() (*agentv1.EnsureInstanceResponse, error) { return a.Next.EnsureInstance(ctx, r, o...) })
}

// GetInstanceStatus implements orchestrator.Agent.
func (a *Agent) GetInstanceStatus(ctx context.Context, r *agentv1.GetInstanceStatusRequest, o ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	return wrapRPC(a.In, "agent.GetInstanceStatus", func() (*agentv1.GetInstanceStatusResponse, error) { return a.Next.GetInstanceStatus(ctx, r, o...) })
}

// RemoveInstance implements orchestrator.Agent.
func (a *Agent) RemoveInstance(ctx context.Context, r *agentv1.RemoveInstanceRequest, o ...grpc.CallOption) (*agentv1.RemoveInstanceResponse, error) {
	return wrapRPC(a.In, "agent.RemoveInstance", func() (*agentv1.RemoveInstanceResponse, error) { return a.Next.RemoveInstance(ctx, r, o...) })
}

// BootstrapPolicy implements orchestrator.Agent.
func (a *Agent) BootstrapPolicy(ctx context.Context, r *agentv1.BootstrapPolicyRequest, o ...grpc.CallOption) (*agentv1.BootstrapPolicyResponse, error) {
	return wrapRPC(a.In, "agent.BootstrapPolicy", func() (*agentv1.BootstrapPolicyResponse, error) { return a.Next.BootstrapPolicy(ctx, r, o...) })
}

// BootstrapApiKey implements orchestrator.Agent. A fault after the call drops the response — the API key the agent
// created in Headscale is then known to nobody (the "key created, not stored" case of §11.3 step 13).
func (a *Agent) BootstrapApiKey(ctx context.Context, r *agentv1.BootstrapApiKeyRequest, o ...grpc.CallOption) (*agentv1.BootstrapApiKeyResponse, error) { //nolint:revive // generated RPC name
	return wrapRPC(a.In, "agent.BootstrapApiKey", func() (*agentv1.BootstrapApiKeyResponse, error) { return a.Next.BootstrapApiKey(ctx, r, o...) })
}

// EnsureEdgeAttachment implements orchestrator.Agent.
func (a *Agent) EnsureEdgeAttachment(ctx context.Context, r *agentv1.EnsureEdgeAttachmentRequest, o ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	return wrapRPC(a.In, "agent.EnsureEdgeAttachment", func() (*agentv1.EnsureEdgeAttachmentResponse, error) {
		return a.Next.EnsureEdgeAttachment(ctx, r, o...)
	})
}

// RemoveEdgeAttachment implements orchestrator.Agent.
func (a *Agent) RemoveEdgeAttachment(ctx context.Context, r *agentv1.RemoveEdgeAttachmentRequest, o ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	return wrapRPC(a.In, "agent.RemoveEdgeAttachment", func() (*agentv1.RemoveEdgeAttachmentResponse, error) {
		return a.Next.RemoveEdgeAttachment(ctx, r, o...)
	})
}

// ---------------------------------------------------------------------------------------------------- registry

type storeLayer struct{}

// err: ErrState is how DBStore reports a row in a state the step cannot work from (permanent); any other error is a
// database failure (transient).
func (storeLayer) err(call string, m Mode) error {
	if m == Permanent {
		return fmt.Errorf("%w: %w", ErrInjected, fmt.Errorf("%s: %w", call, orchestrator.ErrState))
	}
	return fmt.Errorf("%w: %s: connection reset by peer", ErrInjected, call)
}

// Store decorates the registry of the state machine (orchestrator.Store; DBStore in production). Calls without a
// fault point are the embedded store's.
type Store struct {
	orchestrator.Store
	In *Injector
}

func storeCall(in *Injector, call string, real func() error) error {
	if err := in.before(storeLayer{}, call); err != nil {
		return err
	}
	if err := real(); err != nil {
		return err
	}
	return in.after(storeLayer{}, call)
}

// RecordConfig implements orchestrator.Store.
func (s *Store) RecordConfig(ctx context.Context, tenantID, instanceID uuid.UUID, c orchestrator.ConfigRecord) (uuid.UUID, error) {
	var id uuid.UUID
	err := storeCall(s.In, "store.RecordConfig", func() error {
		var err error
		id, err = s.Store.RecordConfig(ctx, tenantID, instanceID, c)
		return err
	})
	return id, err
}

// SetFingerprint implements orchestrator.Store.
func (s *Store) SetFingerprint(ctx context.Context, tenantID, instanceID uuid.UUID, fingerprint string) error {
	return storeCall(s.In, "store.SetFingerprint", func() error { return s.Store.SetFingerprint(ctx, tenantID, instanceID, fingerprint) })
}

// SetAPIKey implements orchestrator.Store.
func (s *Store) SetAPIKey(ctx context.Context, tenantID, instanceID uuid.UUID, ref, prefix string, expires *time.Time) error {
	return storeCall(s.In, "store.SetAPIKey", func() error { return s.Store.SetAPIKey(ctx, tenantID, instanceID, ref, prefix, expires) })
}

// RecordBaselinePolicy implements orchestrator.Store.
func (s *Store) RecordBaselinePolicy(ctx context.Context, tenantID, instanceID uuid.UUID, hujson string) error {
	return storeCall(s.In, "store.RecordBaselinePolicy", func() error {
		return s.Store.RecordBaselinePolicy(ctx, tenantID, instanceID, hujson)
	})
}

// Configure implements orchestrator.Store.
func (s *Store) Configure(ctx context.Context, r orchestrator.ConfigureRequest) (uuid.UUID, error) {
	var id uuid.UUID
	err := storeCall(s.In, "store.Configure", func() error {
		var err error
		id, err = s.Store.Configure(ctx, r)
		return err
	})
	return id, err
}

// AssignRelay implements orchestrator.Store.
func (s *Store) AssignRelay(ctx context.Context, r orchestrator.RelayRequest) error {
	return storeCall(s.In, "store.AssignRelay", func() error { return s.Store.AssignRelay(ctx, r) })
}

// Activate implements orchestrator.Store.
func (s *Store) Activate(ctx context.Context, r orchestrator.ActivateRequest) error {
	return storeCall(s.In, "store.Activate", func() error { return s.Store.Activate(ctx, r) })
}

// ---------------------------------------------------------------------------------------------------- Headscale

type headscaleLayer struct{ op headscale.Op }

// err: an adapter error of the kind the real adapter returns for a refusal (permanent) or an unreachable instance
// (transient, retried by the state machine).
func (l headscaleLayer) err(call string, m Mode) error {
	kind := headscale.KindUpstreamRejected
	if m == Transient {
		kind = headscale.KindUnavailable
	}
	return &headscale.Error{Op: l.op, Kind: kind, Code: -1, Upstream: msg(call), Err: ErrInjected}
}

// Headscale decorates the adapter registry (headscale.Registry; the worker's CachingRegistry in production).
type Headscale struct {
	Next headscale.Registry
	In   *Injector
}

var _ headscale.Registry = (*Headscale)(nil)

// ForTenant implements headscale.Registry.
func (h *Headscale) ForTenant(ctx context.Context, tenantID uuid.UUID) (headscale.Instance, error) {
	inst, err := h.Next.ForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return &hsInstance{Instance: inst, in: h.In}, nil
}

type hsInstance struct {
	headscale.Instance
	in *Injector
}

func hsCall[T any](in *Injector, op headscale.Op, call string, real func() (T, error)) (T, error) {
	var zero T
	l := headscaleLayer{op: op}
	if err := in.before(l, call); err != nil {
		return zero, err
	}
	out, err := real()
	if err != nil {
		return out, err
	}
	if ierr := in.after(l, call); ierr != nil {
		return zero, ierr
	}
	return out, nil
}

func (i *hsInstance) GetPolicy(ctx context.Context) (headscale.Policy, error) {
	return hsCall(i.in, "GetPolicy", "headscale.GetPolicy", func() (headscale.Policy, error) { return i.Instance.GetPolicy(ctx) })
}

func (i *hsInstance) Version(ctx context.Context) (string, error) {
	return hsCall(i.in, "Version", "headscale.Version", func() (string, error) { return i.Instance.Version(ctx) })
}

func (i *hsInstance) Health(ctx context.Context) (headscale.Health, error) {
	return hsCall(i.in, "Health", "headscale.Health", func() (headscale.Health, error) { return i.Instance.Health(ctx) })
}

// ---------------------------------------------------------------------------------------------------- prober

type proberLayer struct{}

func (proberLayer) err(call string, _ Mode) error {
	return fmt.Errorf("%w: %s: prober unreachable", ErrInjected, call)
}

// Prober decorates the prober of steps 17 and 18. A permanent fault of Edge is a probe that ran and found a forbidden
// path answered by the edge (§14.6) — the permanent failure of step 18 (edge_exposes_paths).
type Prober struct {
	Next orchestrator.Prober
	In   *Injector
}

var _ orchestrator.Prober = (*Prober)(nil)

// Relay implements orchestrator.Prober.
func (p *Prober) Relay(ctx context.Context, r orchestrator.RelayProbe) (orchestrator.ProbeResult, error) {
	if err := p.In.before(proberLayer{}, "prober.Relay"); err != nil {
		return orchestrator.ProbeResult{}, err
	}
	res, err := p.Next.Relay(ctx, r)
	if err != nil {
		return res, err
	}
	if ierr := p.In.after(proberLayer{}, "prober.Relay"); ierr != nil {
		return orchestrator.ProbeResult{}, ierr
	}
	return res, nil
}

// exposed is the answer of an edge probe that found a forbidden path published (permanent).
func exposed(res orchestrator.ProbeResult) orchestrator.ProbeResult {
	res.OK = false
	res.Exposed = append(res.Exposed, "/api/v1/apikey")
	res.Checks = append(res.Checks, orchestrator.ProbeCheck{Name: "/api/v1/apikey", OK: false, Status: 200,
		Code: "fault_injection"})
	return res
}

// Edge implements orchestrator.Prober.
func (p *Prober) Edge(ctx context.Context, r orchestrator.EdgeProbe) (orchestrator.ProbeResult, error) {
	f, ok := p.In.decide("prober.Edge", false)
	if ok {
		if f.Mode == Permanent {
			return exposed(orchestrator.ProbeResult{}), nil
		}
		return orchestrator.ProbeResult{}, proberLayer{}.err("prober.Edge", f.Mode)
	}
	res, err := p.Next.Edge(ctx, r)
	if err != nil {
		return res, err
	}
	if f, ok := p.In.decide("prober.Edge", true); ok {
		switch f.Mode {
		case Permanent:
			return exposed(res), nil
		case Kill:
			p.In.kill()
		}
		return orchestrator.ProbeResult{}, proberLayer{}.err("prober.Edge", Transient)
	}
	return res, nil
}

// ---------------------------------------------------------------------------------------------------- placer

type placerLayer struct{}

func (placerLayer) err(call string, m Mode) error {
	if m == Permanent {
		return fmt.Errorf("%w: %s: %w", ErrInjected, call, platform.ErrConflict)
	}
	return fmt.Errorf("%w: %s: connection reset by peer", ErrInjected, call)
}

// Placer decorates step 3 (orchestrator.Placer; *platform.Placer in production).
type Placer struct {
	Next orchestrator.Placer
	In   *Injector
}

var _ orchestrator.Placer = (*Placer)(nil)

// Allocate implements orchestrator.Placer.
func (p *Placer) Allocate(ctx context.Context, req platform.AllocationRequest) (platform.Allocation, error) {
	if err := p.In.before(placerLayer{}, "placer.Allocate"); err != nil {
		return platform.Allocation{}, err
	}
	a, err := p.Next.Allocate(ctx, req)
	if err != nil {
		return a, err
	}
	if ierr := p.In.after(placerLayer{}, "placer.Allocate"); ierr != nil {
		return platform.Allocation{}, ierr
	}
	return a, nil
}

// Release implements orchestrator.Placer.
func (p *Placer) Release(ctx context.Context, tenantID, instanceID uuid.UUID) (bool, error) {
	if err := p.In.before(placerLayer{}, "placer.Release"); err != nil {
		return false, err
	}
	ok, err := p.Next.Release(ctx, tenantID, instanceID)
	if err != nil {
		return ok, err
	}
	if ierr := p.In.after(placerLayer{}, "placer.Release"); ierr != nil {
		return false, ierr
	}
	return ok, nil
}

// ---------------------------------------------------------------------------------------------------- SecretStore

type secretsLayer struct{}

func (secretsLayer) err(call string, m Mode) error {
	if m == Permanent {
		return fmt.Errorf("%w: %s: %w", ErrInjected, call, secrets.ErrKeyDestroyed)
	}
	return fmt.Errorf("%w: %s: connection reset by peer", ErrInjected, call)
}

// Secrets decorates the SecretStore (EnsureDEK — step 5); the other methods are the embedded store's.
type Secrets struct {
	orchestrator.SecretStore
	In *Injector
}

// EnsureDEK implements orchestrator.SecretStore.
func (s *Secrets) EnsureDEK(ctx context.Context, owner secrets.Owner) (int32, error) {
	if err := s.In.before(secretsLayer{}, "secrets.EnsureDEK"); err != nil {
		return 0, err
	}
	v, err := s.SecretStore.EnsureDEK(ctx, owner)
	if err != nil {
		return v, err
	}
	if ierr := s.In.after(secretsLayer{}, "secrets.EnsureDEK"); ierr != nil {
		return 0, ierr
	}
	return v, nil
}

// ---------------------------------------------------------------------------------------------------- IdP

type idpLayer struct{ op string }

func (l idpLayer) err(_ string, m Mode) error {
	code := idp.CodeConflict
	if m == Transient {
		code = idp.CodeUnavailable
	}
	return idp.NewError(code, l.op, "fault_injection", ErrInjected)
}

// IdP decorates the IdP drivers of step 6 (orchestrator.IdPDrivers; *idp.Registry in production).
type IdP struct {
	Next orchestrator.IdPDrivers
	In   *Injector
}

var _ orchestrator.IdPDrivers = (*IdP)(nil)

// Driver implements orchestrator.IdPDrivers.
func (d *IdP) Driver(name string) (idp.IdPDriver, error) {
	drv, err := d.Next.Driver(name)
	if err != nil {
		return nil, err
	}
	return &idpDriver{IdPDriver: drv, in: d.In}, nil
}

type idpDriver struct {
	idp.IdPDriver
	in *Injector
}

func idpCall[T any](in *Injector, op, call string, real func() (T, error)) (T, error) {
	var zero T
	l := idpLayer{op: op}
	if err := in.before(l, call); err != nil {
		return zero, err
	}
	out, err := real()
	if err != nil {
		return out, err
	}
	if ierr := in.after(l, call); ierr != nil {
		return zero, ierr
	}
	return out, nil
}

func (d *idpDriver) EnsureIssuer(ctx context.Context, spec idp.IssuerSpec) (idp.IssuerResult, error) {
	return idpCall(d.in, "EnsureIssuer", "idp.EnsureIssuer", func() (idp.IssuerResult, error) { return d.IdPDriver.EnsureIssuer(ctx, spec) })
}

func (d *idpDriver) EnsureClient(ctx context.Context, spec idp.ClientSpec) (idp.ClientResult, error) {
	return idpCall(d.in, "EnsureClient", "idp.EnsureClient", func() (idp.ClientResult, error) { return d.IdPDriver.EnsureClient(ctx, spec) })
}

// IsInjected reports whether err is (or wraps) a failure of this package — gRPC status errors included.
func IsInjected(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrInjected) {
		return true
	}
	if st, ok := status.FromError(err); ok {
		return len(st.Message()) >= len(ErrInjected.Error()) && st.Message()[:len(ErrInjected.Error())] == ErrInjected.Error()
	}
	return false
}
