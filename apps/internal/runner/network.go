package runner

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/network"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// newNetwork builds the network module (P4-T12) over the process's store: the Headscale registry (routes), the device
// register of internal/devices (network may not read it itself — §13.6), the tag catalog check of internal/policies in
// the writing transaction (P4-T15), the internal entry point of instance.reconfigure (P3-T13) for the DNS settings, and
// the platform's domain for the DNS names.
func newNetwork(cfg config.Config, d *deps) (*network.Service, error) {
	return network.New(d.st, network.Config{Registry: d.headscale, Devices: devices.RouteRegister{}, Tags: policies.RequireTags,
		Reconfigure: reconfigureForDNS, BaseDomain: cfg.BaseDomain, Logger: d.log})
}

// reconfigureForDNS is orchestrator.EnqueueReconfigure for PUT /tenants/{t}/dns/settings, in the tenant's transaction:
// the nameservers are the change; the operation's audit action is the caller's x-audit-action (the job closes it in the
// tenant's audit). The orchestrator's refusals become network errors (409 conflict, 404, 422).
func reconfigureForDNS(ctx context.Context, tx *store.Tx, req network.ReconfigureRequest) (jobs.Job, bool, error) {
	j, created, err := orchestrator.EnqueueReconfigure(ctx, tx, orchestrator.ReconfigureRequest{TenantID: req.TenantID,
		InstanceID: req.InstanceID, Change: orchestrator.ConfigChange{Nameservers: req.Nameservers}, RequestedBy: req.RequestedBy,
		Source: req.Source, Action: req.Action})
	if err == nil {
		return j, created, nil
	}
	if errors.Is(err, orchestrator.ErrNotFound) {
		return jobs.Job{}, false, &network.Error{Code: network.CodeNotFound, Reason: "instance_not_found", Err: err,
			Detail: "The resource does not exist."}
	}
	var ce *orchestrator.CreateError
	if errors.As(err, &ce) {
		switch {
		case errors.Is(ce.Kind, orchestrator.ErrInvalid):
			return jobs.Job{}, false, &network.Error{Code: network.CodeValidationFailed, Reason: ce.Reason, Field: "nameservers",
				Detail: "the nameservers are not accepted for the instance's configuration", Err: err}
		case errors.Is(ce.Kind, orchestrator.ErrConflict):
			detail := map[string]string{
				"reconfigure_in_progress": "Another reconfiguration of the tenant's instance is in progress; try again when it ends.",
				"instance_not_running":    "The tenant's instance is not running.",
				"instance_quarantined":    "The tenant's instance is isolated (quarantine).",
				"no_config_version":       "The tenant's instance has no configuration version recorded by the platform yet.",
				"tenant_not_active":       "The tenant is not active.",
			}[ce.Reason]
			if detail == "" {
				detail = "The DNS settings cannot be changed in the instance's current state."
			}
			return jobs.Job{}, false, &network.Error{Code: network.CodeConflict, Reason: ce.Reason, Detail: detail, Err: err}
		}
	}
	return jobs.Job{}, false, err
}

// routeApprovalAction executes an approved route approval (P4-T12, §8.6 "duyệt route khi routes.four_eyes bật"): the
// approver held tenant.approval:decide and tenant.route:approve; the exact approved prefixes are written to Headscale in
// the approval's transaction, only while the device's approved routes still have the ETag of the request. Without the
// network module (tests of the other actions) the action is registered and refuses to run.
func routeApprovalAction(net *network.Service) approvals.Action {
	return approvals.Typed(approvals.Spec{Name: network.RouteApprovalAction, Scope: authz.ScopeTenant, ResourceType: "device",
		Permission: "tenant.route:approve"},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p network.RouteApprovalPayload) (*uuid.UUID, error) {
			if net == nil || e.Request.TenantID == nil {
				return nil, errors.New("route approval: no network module in this process")
			}
			return net.ExecuteRouteApproval(ctx, tx, *e.Request.TenantID, e.Request.ID, e.Request.ResourceID,
				e.Request.RequestedBy.IdentityID, p)
		})
}

// agentRecords writes the records file through the Host Agent (WriteDnsRecords): network.RecordsWriter of the worker.
type agentRecords struct {
	agent interface {
		WriteDnsRecords(ctx context.Context, in *agentv1.WriteDnsRecordsRequest, opts ...grpc.CallOption) (*agentv1.WriteDnsRecordsResponse, error)
	}
}

// WriteRecords implements network.RecordsWriter: a refusal the agent may lift by itself (unavailable, busy, deadline)
// is transient, any other refusal permanent.
func (a agentRecords) WriteRecords(ctx context.Context, ref network.InstanceRef, jobID uuid.UUID, recs []network.DNSRecord) (string, error) {
	req := &agentv1.WriteDnsRecordsRequest{JobId: jobID.String(), Instance: &agentv1.InstanceRef{InstanceId: ref.InstanceID.String(),
		TenantId: ref.TenantID.String(), Slug: ref.Slug}, Records: make([]*agentv1.DnsRecord, 0, len(recs))}
	for _, r := range recs {
		t := agentv1.DnsRecordType_DNS_RECORD_TYPE_A
		if r.Type == network.TypeAAAA {
			t = agentv1.DnsRecordType_DNS_RECORD_TYPE_AAAA
		}
		req.Records = append(req.Records, &agentv1.DnsRecord{Name: r.Name, Type: t, Value: r.Value.String()})
	}
	resp, err := a.agent.WriteDnsRecords(ctx, req)
	if err != nil {
		if agentclient.Retryable(err) {
			return "", jobs.Transient("agent_unavailable", err)
		}
		reason := "agent_refused"
		if r, ok := agentclient.RefusalOf(err); ok {
			reason = "agent_" + r.GetReason().String()
		}
		return "", jobs.Permanent(strings.ToLower(reason), err)
	}
	return resp.GetRecordsSha256(), nil
}

// registerRecordsJob registers dns.records_write when the worker has the Host Agent; without it the jobs stay queued
// until a configured worker takes them (like instance.reconfigure).
func registerRecordsJob(d *deps, w *jobs.Worker, net *network.Service, agent *agentclient.Client) error {
	if agent == nil {
		d.log.Warn("dns.records_write is not run by this worker: the Host Agent (MG_AGENT_*) is not configured — DNS record " +
			"changes stay queued until a configured worker takes them")
		return nil
	}
	return net.RegisterRecordsJob(w, agentRecords{agent: agent})
}
