package runner

import (
	"context"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// newPolicies builds the policy module of the worker (P4-T10): policy.apply — ONE handler (the desired version
// rendered with the tables of now: groups, resources, tag catalog, memberships; the suspension policy of a tenant
// being suspended) — and policy.drift_check over the shared registry (an active tenant's instance), the reachable
// registry (reachableRegistry — a suspended tenant's instance: the suspension policy, its drift check) and, with a
// Host Agent, the edge detach of an instance that serves no policy (§13.4). Without the agent the drift check raises
// the Critical event only.
func newPolicies(cfg config.Config, d *deps, agent *agentclient.Client) (*policies.Service, error) {
	sus, err := reachableRegistry(cfg, d)
	if err != nil {
		return nil, err
	}
	pc := policies.Config{Registry: d.headscale, Suspended: sus, Logger: d.log}
	if agent != nil {
		pc.Edge = edgeDetacher{st: d.st, agent: agent}
	} else {
		d.log.Warn("policy.drift_check cannot detach the edge of an instance without a policy: the Host Agent " +
			"(MG_AGENT_*) is not configured — the Critical event is still raised")
	}
	return policies.New(d.st, pc)
}

// edgeDetacher is policies.EdgeDetacher over the Host Agent: RemoveEdgeAttachment with reason POLICY_DRIFT (the agent
// clears the edge_attach flag and detaches — the hostname answers 404 until an operator restores the instance).
type edgeDetacher struct {
	st    *store.Store
	agent agentv1.AgentServiceClient
}

func (e edgeDetacher) DetachEdge(ctx context.Context, tenantID, instanceID, jobID uuid.UUID) error {
	var slug string
	if err := e.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		t, err := q.GetTenant(ctx, tenantID)
		slug = t.Slug
		return err
	}); err != nil {
		return err
	}
	_, err := e.agent.RemoveEdgeAttachment(ctx, &agentv1.RemoveEdgeAttachmentRequest{
		Instance: &agentv1.InstanceRef{InstanceId: instanceID.String(), TenantId: tenantID.String(), Slug: slug},
		JobId:    jobID.String(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_POLICY_DRIFT})
	return err
}
