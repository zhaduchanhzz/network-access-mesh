package runner

import (
	"context"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/deprovision"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// newDeprovision builds tenant.deprovision (P3-T09, §11.4) for the worker: a Headscale registry of its own whose
// locator reaches the instance of a DEPROVISIONING tenant (deprovision.ReachableStatuses — the registry every other
// job and the api use refuses it, G2 L1, and must keep doing so), the policy core over that registry (the suspension
// policy), the Host Agent (edge, container, network, data directory — nil: only tenants without an instance can be
// deprovisioned), the backup service (the final backup, in-process), the SecretStore and the IdP drivers; and the
// periodic crypto-shredding tenant.keys_destroy after MG_DEPROVISION_KEY_GRACE. TestWiringKeepsDefaults allows
// TenantStatuses in this file only, with exactly deprovision.ReachableStatuses.
func newDeprovision(cfg config.Config, d *deps, agent *agentclient.Client, bk *backup.Service, drivers *idp.Registry) (*deprovision.Handler, *deprovision.Shredder, error) {
	loc, err := locator.New(d.tenants, d.secrets, locator.Options{AdminURL: cfg.Edge.URL, EdgeTokenFile: cfg.Edge.TokenFile,
		TenantStatuses: deprovision.ReachableStatuses, Logger: d.log})
	if err != nil {
		return nil, nil, err
	}
	reg := headscale.NewRegistry(loc, headscale.Options{Logger: d.log})
	core, err := policies.New(d.st, policies.Config{Registry: reg, Logger: d.log})
	if err != nil {
		return nil, nil, err
	}
	hc := deprovision.Config{Store: d.st, Backups: bk, Secrets: d.secrets, IdP: drivers, Policies: core, Headscale: reg,
		Security: platformSecurity{st: d.st}, Logger: d.log, KeyGrace: cfg.Deprovision.KeyGrace}
	if agent != nil {
		hc.Agent = agent
	} else {
		d.log.Warn("tenant.deprovision without a Host Agent (MG_AGENT_*): only tenants without a live instance can be deprovisioned")
	}
	h, err := deprovision.New(hc)
	if err != nil {
		return nil, nil, err
	}
	sh, err := deprovision.NewShredder(deprovision.ShredderConfig{Store: d.st, Secrets: d.secrets, IdP: drivers, Logger: d.log})
	if err != nil {
		return nil, nil, err
	}
	return h, sh, nil
}

// deprovisionAction executes an approved deprovision (P3-T09, §11.4, §8.5 platform.tenant:delete — 2P, Super Admin):
// in the approval's transaction the tenant is checked again and the lifecycle job tenant.deprovision is enqueued with
// exactly the approved payload.
func deprovisionAction(req *deprovision.Requester) approvals.Action {
	return approvals.Typed(approvals.Spec{Name: deprovision.Action, Scope: authz.ScopePlatform, ResourceType: "tenant",
		Permission: deprovision.Permission},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p deprovision.Payload) (*uuid.UUID, error) {
			if e.Request.ResourceID != p.TenantID.String() {
				return nil, &deprovision.RequestError{Kind: deprovision.ErrInvalid, Reason: deprovision.ReasonPayloadMismatch}
			}
			return req.EnqueueApproved(ctx, tx, e.Request.RequestedBy.IdentityID, e.Request.ID, p)
		})
}
