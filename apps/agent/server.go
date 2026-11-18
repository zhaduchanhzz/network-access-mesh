package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Limits of the gRPC server: a message above MaxMessageBytes is refused by gRPC itself (RESOURCE_EXHAUSTED) before
// any handler sees it; the header list is capped too (the token is the only header the agent reads).
const (
	maxSendBytes   = 4 << 20
	maxHeaderBytes = 16 << 10
	maxStreams     = 64
)

// server implements agentv1.AgentServiceServer. Every call goes through intercept (authorization, unknown fields,
// refusal → status, one audit line), then the handler: validate → per-instance lock → guard → driver.
type server struct {
	agentv1.UnimplementedAgentServiceServer
	host    *agentspec.Host
	v       *agentspec.Validator
	guard   *agentspec.Guard
	drv     Driver
	locks   *instanceLocks
	token   []byte
	log     *slog.Logger
	started time.Time
	edge    string
}

func newServer(cfg *Config, token []byte, drv Driver, inv agentspec.Inventory, log *slog.Logger) *server {
	return &server{
		host:    &cfg.Host,
		v:       &agentspec.Validator{Host: &cfg.Host},
		guard:   &agentspec.Guard{Host: &cfg.Host, Inventory: inv, Edge: cfg.Edge},
		drv:     drv,
		locks:   &instanceLocks{held: map[uuid.UUID]chan struct{}{}, wait: cfg.LockWait},
		token:   token,
		log:     log,
		started: time.Now().UTC(),
		edge:    cfg.Edge,
	}
}

// grpcServer builds the gRPC server: peer credentials, size limits, the interceptor; no reflection, no TCP.
func (s *server) grpcServer(cfg *Config) *grpc.Server {
	gs := grpc.NewServer(
		grpc.Creds(&peerCreds{uids: cfg.PeerUIDs, gids: cfg.PeerGIDs, self: cfg.selfUID, log: s.log}),
		grpc.MaxRecvMsgSize(agentspec.MaxMessageBytes),
		grpc.MaxSendMsgSize(maxSendBytes),
		grpc.MaxHeaderListSize(maxHeaderBytes),
		grpc.MaxConcurrentStreams(maxStreams),
		grpc.ConnectionTimeout(5*time.Second),
		grpc.UnaryInterceptor(s.intercept),
		grpc.StreamInterceptor(func(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
			return status.Error(codes.Unimplemented, "the agent has no streaming method")
		}),
	)
	agentv1.RegisterAgentServiceServer(gs, s)
	return gs
}

// intercept wraps every call. The audit line is written whatever the outcome — refusals included — with the
// kernel-attested peer, the method, the instance and job ids (only when they are canonical UUIDs), the gRPC code
// and the refusal reason/field; never a request or response body (they may carry secrets).
func (s *server) intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	start := time.Now()
	var pi peerInfo
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("agent_panic", "method", path.Base(info.FullMethod), "panic", fmt.Sprint(p))
			resp, err = nil, status.Error(codes.Internal, "internal error")
		}
		s.audit(ctx, info.FullMethod, req, pi, err, time.Since(start))
	}()
	if pi, err = s.authorize(ctx, info.FullMethod); err != nil {
		return nil, s.toStatus(err)
	}
	if m, ok := req.(proto.Message); ok {
		if err = agentspec.UnknownField(m); err != nil {
			return nil, s.toStatus(err)
		}
	}
	resp, err = handler(ctx, req)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return resp, nil
}

var reasonCodes = map[agentv1.RefusalReason]codes.Code{
	agentv1.RefusalReason_REFUSAL_REASON_MALFORMED:           codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_INVALID_ID:          codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_INVALID_SLUG:        codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_IMAGE_NOT_ALLOWED:   codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_UID_OUT_OF_RANGE:    codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_NETWORK_OUT_OF_POOL: codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_PORT_OUT_OF_RANGE:   codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_OUT_OF_BOUNDS:       codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_TOO_LARGE:           codes.InvalidArgument,
	agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT:      codes.FailedPrecondition,
	agentv1.RefusalReason_REFUSAL_REASON_CONFLICT:            codes.FailedPrecondition,
	agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH:   codes.FailedPrecondition,
	agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH:         codes.FailedPrecondition,
	agentv1.RefusalReason_REFUSAL_REASON_STATE:               codes.FailedPrecondition,
	agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND:           codes.NotFound,
	agentv1.RefusalReason_REFUSAL_REASON_BUSY:                codes.Aborted,
	agentv1.RefusalReason_REFUSAL_REASON_UNAUTHENTICATED:     codes.Unauthenticated,
	agentv1.RefusalReason_REFUSAL_REASON_PERMISSION_DENIED:   codes.PermissionDenied,
}

// toStatus maps an error to the status the worker sees: a refusal carries its typed detail; a context error its
// code; a status passes through; anything else is INTERNAL with a redacted message.
func (s *server) toStatus(err error) error {
	if r, ok := agentspec.AsRefusal(err); ok {
		code, known := reasonCodes[r.Reason]
		if !known {
			code = codes.InvalidArgument
		}
		st, derr := status.New(code, r.Error()).WithDetails(r.Proto())
		if derr != nil {
			return status.Error(code, r.Error())
		}
		return st.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	return status.Error(codes.Internal, logx.RedactString(err.Error()))
}

func (s *server) audit(ctx context.Context, method string, req any, pi peerInfo, err error, d time.Duration) {
	st := status.Convert(err)
	attrs := []any{
		"method", path.Base(method), "code", st.Code().String(), "duration_ms", d.Milliseconds(),
		"peer_uid", pi.UID, "peer_gid", pi.GID, "peer_pid", pi.PID,
		"instance_id", auditID(instanceOf(req)), "job_id", auditID(jobOf(req)),
	}
	outcome, level := "ok", slog.LevelInfo
	switch {
	case err == nil && method == healthMethod:
		level = slog.LevelDebug // the container healthcheck calls it every 30 s
	case err == nil:
	case st.Code() == codes.Unimplemented:
		outcome = "unimplemented"
	default:
		outcome, level = "error", slog.LevelError
		for _, det := range st.Details() {
			if r, ok := det.(*agentv1.Refusal); ok {
				outcome, level = "refused", slog.LevelWarn
				attrs = append(attrs, "reason", r.GetReason().String(), "field", r.GetField(), "message", r.GetMessage())
			}
		}
		if outcome == "error" {
			attrs = append(attrs, "message", st.Message())
		}
	}
	s.log.Log(ctx, level, "agent_call", append(attrs, "outcome", outcome)...)
}

func instanceOf(req any) string {
	if r, ok := req.(interface{ GetInstance() *agentv1.InstanceRef }); ok && r.GetInstance() != nil {
		return r.GetInstance().GetInstanceId()
	}
	if r, ok := req.(interface{ GetSpec() *agentv1.InstanceSpec }); ok {
		return r.GetSpec().GetInstance().GetInstanceId()
	}
	return ""
}

func jobOf(req any) string {
	if r, ok := req.(interface{ GetJobId() string }); ok {
		return r.GetJobId()
	}
	return ""
}

// auditID logs an id only in its canonical form: a refused request may carry anything in these fields.
func auditID(s string) string {
	if s == "" {
		return "-"
	}
	if _, err := agentspec.UUID("", s); err != nil {
		return "(invalid)"
	}
	return s
}

// ---------------------------------------------------------------------------------------------------- per-instance lock

// instanceLocks is the per-instance mutual exclusion of §11.5 (backup, restore, upgrade, reconfigure, start/stop,
// remove…): a second operation on the same instance waits at most wait, then is refused BUSY (the job retries).
type instanceLocks struct {
	mu   sync.Mutex
	held map[uuid.UUID]chan struct{}
	wait time.Duration
}

func (l *instanceLocks) lock(ctx context.Context, id uuid.UUID) (func(), error) {
	timer := time.NewTimer(l.wait)
	defer timer.Stop()
	for {
		l.mu.Lock()
		ch, busy := l.held[id]
		if !busy {
			ch = make(chan struct{})
			l.held[id] = ch
			l.mu.Unlock()
			return func() {
				l.mu.Lock()
				delete(l.held, id)
				close(ch)
				l.mu.Unlock()
			}, nil
		}
		l.mu.Unlock()
		select {
		case <-ch:
		case <-timer.C:
			return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_BUSY, Field: "instance",
				Msg: "another operation holds this instance's lock — retry later"}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// tryLock takes the instance's lock without waiting (the edge supervisor: an instance busy with an operation is left
// to its next cycle).
func (l *instanceLocks) tryLock(id uuid.UUID) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, busy := l.held[id]; busy {
		return nil, false
	}
	ch := make(chan struct{})
	l.held[id] = ch
	return func() {
		l.mu.Lock()
		delete(l.held, id)
		close(ch)
		l.mu.Unlock()
	}, true
}

// locked runs fn under the instance's lock.
func (s *server) locked(ctx context.Context, ref agentspec.Ref, fn func() error) error {
	unlock, err := s.locks.lock(ctx, ref.InstanceID)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// onInstance is the common path of a mutating call on an existing instance: lock, guard (the instance must exist
// and every object it would touch must be its own), then the driver.
func onInstance[T any](ctx context.Context, s *server, c agentspec.Call, mustExist bool, fn func() (T, error)) (T, error) {
	var out T
	err := s.locked(ctx, c.Ref, func() error {
		if _, err := s.guard.CheckRef(ctx, c.Ref, mustExist); err != nil {
			return err
		}
		var err error
		out, err = fn()
		return err
	})
	return out, err
}

// ---------------------------------------------------------------------------------------------------- handlers

func (s *server) Health(context.Context, *agentv1.HealthRequest) (*agentv1.HealthResponse, error) {
	return &agentv1.HealthResponse{
		Status:        agentv1.ServingStatus_SERVING_STATUS_SERVING,
		Version:       buildinfo.Version,
		Commit:        buildinfo.Commit,
		StartedAt:     timestamppb.New(s.started),
		Driver:        s.drv.Name(),
		AllowedImages: uint32(s.host.Images.Len()), //nolint:gosec // G115: at most 256
	}, nil
}

func (s *server) GetHostInfo(context.Context, *agentv1.GetHostInfoRequest) (*agentv1.GetHostInfoResponse, error) {
	out := &agentv1.GetHostInfoResponse{
		RunUidRange:     &agentv1.UintRange{Min: s.host.RunUIDs.Min, Max: s.host.RunUIDs.Max},
		TenantNetPool:   s.host.TenantPool.String(),
		PublicEntryIpv4: s.host.PublicEntry.String(),
		TemplateVersion: agentspec.TemplateVersion,
		Version:         buildinfo.Version,
	}
	if r := s.host.STUNPorts; r != nil {
		out.StunPortRange = &agentv1.UintRange{Min: r.Min, Max: r.Max}
	}
	for _, img := range s.host.Images.All() {
		out.AllowedImages = append(out.AllowedImages, &agentv1.AllowedImage{Repository: img.Repository, Digest: img.Digest})
	}
	return out, nil
}

func (s *server) ValidateConfig(ctx context.Context, r *agentv1.ValidateConfigRequest) (*agentv1.ValidateConfigResponse, error) {
	spec, _, err := s.v.ValidateConfig(r)
	if err != nil {
		return nil, err
	}
	var out *agentv1.ValidateConfigResponse
	err = s.locked(ctx, spec.Ref, func() error {
		if err := s.guard.CheckSpec(ctx, spec); err != nil {
			return err
		}
		var err error
		out, err = s.drv.ValidateConfig(ctx, spec)
		return err
	})
	return out, err
}

func (s *server) EnsureInstance(ctx context.Context, r *agentv1.EnsureInstanceRequest) (*agentv1.EnsureInstanceResponse, error) {
	e, err := s.v.EnsureInstance(r)
	if err != nil {
		return nil, err
	}
	if e.DryRun {
		// read-only: no lock, nothing touched
		if err := s.guard.CheckSpec(ctx, e.Spec); err != nil {
			return nil, err
		}
		return &agentv1.EnsureInstanceResponse{TemplateVersion: agentspec.TemplateVersion, PlannedActions: s.host.Plan(e.Spec, e.Phase)}, nil
	}
	var out *agentv1.EnsureInstanceResponse
	err = s.locked(ctx, e.Spec.Ref, func() error {
		if err := s.guard.CheckSpec(ctx, e.Spec); err != nil {
			return err
		}
		var err error
		out, err = s.drv.EnsureInstance(ctx, e)
		return err
	})
	return out, err
}

func (s *server) GetInstanceStatus(ctx context.Context, r *agentv1.GetInstanceStatusRequest) (*agentv1.GetInstanceStatusResponse, error) {
	ref, err := s.v.GetInstanceStatus(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.guard.CheckRef(ctx, ref, true); err != nil {
		return nil, err
	}
	st, err := s.drv.InstanceStatus(ctx, ref, r.GetIncludeApiKeys())
	if err != nil {
		return nil, err
	}
	return &agentv1.GetInstanceStatusResponse{Status: st}, nil
}

func (s *server) ListInstances(ctx context.Context, _ *agentv1.ListInstancesRequest) (*agentv1.ListInstancesResponse, error) {
	list, err := s.drv.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	aliases, err := s.guard.EdgeAliases(ctx) // reconcile (P3-T12): hs-<slug> names on the edge's networks — read only
	if err != nil {
		return nil, err
	}
	return &agentv1.ListInstancesResponse{Instances: list, EdgeAliases: aliases}, nil
}

func statusCall[R interface {
	GetInstance() *agentv1.InstanceRef
	GetJobId() string
}](ctx context.Context, s *server, r R, op func(context.Context, agentspec.Call) (*agentv1.InstanceStatus, error)) (*agentv1.InstanceStatus, error) {
	c, err := s.v.Call(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, c, true, func() (*agentv1.InstanceStatus, error) { return op(ctx, c) })
}

func (s *server) StartInstance(ctx context.Context, r *agentv1.StartInstanceRequest) (*agentv1.StartInstanceResponse, error) {
	st, err := statusCall(ctx, s, r, s.drv.StartInstance)
	if err != nil {
		return nil, err
	}
	return &agentv1.StartInstanceResponse{Status: st}, nil
}

func (s *server) StopInstance(ctx context.Context, r *agentv1.StopInstanceRequest) (*agentv1.StopInstanceResponse, error) {
	st, err := statusCall(ctx, s, r, s.drv.StopInstance)
	if err != nil {
		return nil, err
	}
	return &agentv1.StopInstanceResponse{Status: st}, nil
}

func (s *server) RestartInstance(ctx context.Context, r *agentv1.RestartInstanceRequest) (*agentv1.RestartInstanceResponse, error) {
	st, err := statusCall(ctx, s, r, s.drv.RestartInstance)
	if err != nil {
		return nil, err
	}
	return &agentv1.RestartInstanceResponse{Status: st}, nil
}

func (s *server) RemoveInstance(ctx context.Context, r *agentv1.RemoveInstanceRequest) (*agentv1.RemoveInstanceResponse, error) {
	rm, err := s.v.RemoveInstance(r)
	if err != nil {
		return nil, err
	}
	// an absent directory is not an error (idempotent compensation), but whatever exists must be this instance's
	return onInstance(ctx, s, rm.Call, false, func() (*agentv1.RemoveInstanceResponse, error) { return s.drv.RemoveInstance(ctx, rm) })
}

func (s *server) UpgradeInstance(ctx context.Context, r *agentv1.UpgradeInstanceRequest) (*agentv1.UpgradeInstanceResponse, error) {
	u, err := s.v.UpgradeInstance(r)
	if err != nil {
		return nil, err
	}
	st, err := onInstance(ctx, s, u.Call, true, func() (*agentv1.InstanceStatus, error) {
		if err := s.guard.CheckSpec(ctx, u.Spec); err != nil {
			return nil, err
		}
		return s.drv.UpgradeInstance(ctx, u)
	})
	if err != nil {
		return nil, err
	}
	return &agentv1.UpgradeInstanceResponse{Status: st}, nil
}

// InspectImage is read-only for the instance (no lock): the guard checks the instance exists and is its own.
func (s *server) InspectImage(ctx context.Context, r *agentv1.InspectImageRequest) (*agentv1.InspectImageResponse, error) {
	i, err := s.v.InspectImage(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.guard.CheckRef(ctx, i.Ref, true); err != nil {
		return nil, err
	}
	return s.drv.InspectImage(ctx, i)
}

// PreflightUpgrade runs under the instance's lock (it reads the instance's state and writes its staging directory).
func (s *server) PreflightUpgrade(ctx context.Context, r *agentv1.PreflightUpgradeRequest) (*agentv1.PreflightUpgradeResponse, error) {
	p, err := s.v.PreflightUpgrade(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, p.Call, true, func() (*agentv1.PreflightUpgradeResponse, error) {
		if err := s.guard.CheckSpec(ctx, p.Spec); err != nil {
			return nil, err
		}
		return s.drv.PreflightUpgrade(ctx, p)
	})
}

func (s *server) WriteDnsRecords(ctx context.Context, r *agentv1.WriteDnsRecordsRequest) (*agentv1.WriteDnsRecordsResponse, error) {
	d, err := s.v.WriteDNSRecords(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, d.Call, true, func() (*agentv1.WriteDnsRecordsResponse, error) { return s.drv.WriteDNSRecords(ctx, d) })
}

func (s *server) BootstrapPolicy(ctx context.Context, r *agentv1.BootstrapPolicyRequest) (*agentv1.BootstrapPolicyResponse, error) {
	c, kind, err := s.v.BootstrapPolicy(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, c, true, func() (*agentv1.BootstrapPolicyResponse, error) { return s.drv.BootstrapPolicy(ctx, c, kind) })
}

func (s *server) BootstrapApiKey(ctx context.Context, r *agentv1.BootstrapApiKeyRequest) (*agentv1.BootstrapApiKeyResponse, error) {
	k, err := s.v.BootstrapAPIKey(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, k.Call, true, func() (*agentv1.BootstrapApiKeyResponse, error) { return s.drv.BootstrapAPIKey(ctx, k) })
}

func (s *server) Backup(ctx context.Context, r *agentv1.BackupRequest) (*agentv1.BackupResponse, error) {
	b, err := s.v.Backup(r)
	if err != nil {
		return nil, err
	}
	a, err := onInstance(ctx, s, b.Call, true, func() (*agentv1.BackupArtifact, error) { return s.drv.Backup(ctx, b) })
	if err != nil {
		return nil, err
	}
	return &agentv1.BackupResponse{Artifact: a}, nil
}

func (s *server) Restore(ctx context.Context, r *agentv1.RestoreRequest) (*agentv1.RestoreResponse, error) {
	rs, err := s.v.Restore(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, rs.Call, true, func() (*agentv1.RestoreResponse, error) { return s.drv.Restore(ctx, rs) })
}

func (s *server) PostRestoreReconcile(ctx context.Context, r *agentv1.PostRestoreReconcileRequest) (*agentv1.PostRestoreReconcileResponse, error) {
	rc, err := s.v.PostRestoreReconcile(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, rc.Call, true, func() (*agentv1.PostRestoreReconcileResponse, error) { return s.drv.PostRestoreReconcile(ctx, rc) })
}

func (s *server) EnsureEdgeAttachment(ctx context.Context, r *agentv1.EnsureEdgeAttachmentRequest) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	c, err := s.v.Call(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, c, true, func() (*agentv1.EnsureEdgeAttachmentResponse, error) {
		if err := s.guard.CheckEdgeAttach(ctx, c.Ref); err != nil {
			return nil, err
		}
		return s.drv.EnsureEdgeAttachment(ctx, c)
	})
}

func (s *server) RemoveEdgeAttachment(ctx context.Context, r *agentv1.RemoveEdgeAttachmentRequest) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	d, err := s.v.RemoveEdgeAttachment(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, d.Call, true, func() (*agentv1.RemoveEdgeAttachmentResponse, error) { return s.drv.RemoveEdgeAttachment(ctx, d) })
}
