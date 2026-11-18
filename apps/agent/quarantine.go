package main

import (
	"context"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Quarantine of an instance (§11.4, P3-T18) on the agent's side. QuarantineInstance writes meta/quarantined first and
// contains the instance (flag cleared, container stopped, edge detached); from then on the server refuses (STATE) every
// call that could make the instance serve or change it, under the instance's lock — so no operation already queued
// behind the lock, nor any later one, restarts or re-attaches it — until ReleaseInstance (run only by the
// instance.release job of an approved 2P request) has started it through the start guard, seen it healthy and serving
// the applied policy. Allowed while quarantined: GetInstanceStatus, ListInstances, StopInstance, RemoveEdgeAttachment
// (not as a compensation, which would remove meta/activated), RemoveInstance keeping data, Backup (read-only — it may
// help the investigation), QuarantineInstance, ReleaseInstance.

// errQuarantined is the refusal of a call a quarantined instance does not accept.
func errQuarantined() error {
	return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_STATE, Field: "instance",
		Msg: "the instance is quarantined (§11.4): nothing starts, attaches or changes it until a release (2P)"}
}

// refuseQuarantined refuses a call on a quarantined instance — called under the instance's lock, after the guard.
func (s *server) refuseQuarantined(ctx context.Context, ref agentspec.Ref) error {
	q, err := s.drv.Quarantined(ctx, ref)
	if err != nil {
		return err
	}
	if q {
		return errQuarantined()
	}
	return nil
}

// onActive is onInstance for a call a quarantined instance refuses.
func onActive[T any](ctx context.Context, s *server, c agentspec.Call, fn func() (T, error)) (T, error) {
	return onInstance(ctx, s, c, true, func() (T, error) {
		if err := s.refuseQuarantined(ctx, c.Ref); err != nil {
			var zero T
			return zero, err
		}
		return fn()
	})
}

func (s *server) QuarantineInstance(ctx context.Context, r *agentv1.QuarantineInstanceRequest) (*agentv1.QuarantineInstanceResponse, error) {
	c, err := s.v.QuarantineInstance(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, c, true, func() (*agentv1.QuarantineInstanceResponse, error) {
		return s.drv.QuarantineInstance(ctx, c)
	})
}

func (s *server) ReleaseInstance(ctx context.Context, r *agentv1.ReleaseInstanceRequest) (*agentv1.ReleaseInstanceResponse, error) {
	rel, err := s.v.ReleaseInstance(r)
	if err != nil {
		return nil, err
	}
	return onInstance(ctx, s, rel.Call, true, func() (*agentv1.ReleaseInstanceResponse, error) {
		return s.drv.ReleaseInstance(ctx, rel)
	})
}
