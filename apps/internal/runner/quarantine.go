package runner

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/quarantine"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// newQuarantine builds instance.quarantine and instance.release (P3-T18, §11.4) for the worker: the Host Agent (nil
// when it is not configured — the quarantine job then reports agent_not_configured, Critical, and the registry keeps the
// instance quarantined) and, for the post-start gate of a release, the Headscale registry that reaches a suspended
// tenant's instance (the registry of lifecycle — reachableRegistry). Always wired: the step gate and the API side need
// no agent.
func newQuarantine(cfg config.Config, d *deps, agent *agentclient.Client) (*quarantine.Handler, error) {
	reg, err := reachableRegistry(cfg, d)
	if err != nil {
		return nil, err
	}
	qc := quarantine.Config{Store: d.st, Headscale: reg, Logger: d.log}
	if agent != nil { // never a typed nil in the interface
		qc.Agent = agent
	} else {
		d.log.Warn("instance.quarantine cannot isolate an instance on its host: the Host Agent (MG_AGENT_*) is not " +
			"configured — a quarantine moves the registry only and its job fails agent_not_configured (Critical)")
	}
	return quarantine.New(qc)
}

// releaseAction executes an approved release (P3-T18, §8.5 platform.instance:release — 2P for every role): in the
// transaction that marks the request executed, quarantine.ExecuteRelease checks the instance is still quarantined with
// no quarantine in progress and enqueues instance.release. A refusal keeps the request approved (409 to the approver).
func releaseAction() approvals.Action {
	return approvals.Typed(approvals.Spec{Name: quarantine.ReleaseApprovalAction, Scope: authz.ScopePlatform,
		ResourceType: quarantine.ReleaseResourceType, Permission: quarantine.ReleasePermission},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p quarantine.ReleasePayload) (*uuid.UUID, error) {
			if e.Request.DecidedBy == nil {
				return nil, &approvals.Error{Kind: approvals.ErrConflict, Reason: approvals.ReasonNotPending}
			}
			if e.Request.ResourceID != p.InstanceID.String() {
				return nil, &approvals.Error{Kind: approvals.ErrConflict, Reason: approvals.ReasonInvalidPayload}
			}
			id, err := quarantine.ExecuteRelease(ctx, tx, quarantine.ReleaseExecution{ApprovalID: e.Request.ID,
				RequestedBy: e.Request.RequestedBy.IdentityID, ApprovedBy: e.Request.DecidedBy.IdentityID, Payload: p})
			var re *quarantine.RequestError
			switch {
			case errors.As(err, &re) && errors.Is(err, quarantine.ErrNotFound):
				return nil, &approvals.Error{Kind: approvals.ErrNotFound, Reason: re.Reason}
			case errors.As(err, &re):
				return nil, &approvals.Error{Kind: approvals.ErrConflict, Reason: re.Reason}
			case err != nil:
				return nil, err
			}
			return &id, nil
		})
}
