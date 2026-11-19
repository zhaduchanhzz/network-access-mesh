package runner

// P4-T03a wiring: the approval actions of the administration (a Super Admin role change, a platform change of a tenant
// IdP — both platform 2P; a security settings change that lifts a second-person control — tenant scope), the
// notification of the deciders of a tenant approval request, and the SecretStore adapter of a tenant IdP's client
// secret. The actions live here, in the composition root (like those of P3-T09/T11/T18, P4-T09): internal/httpapi may
// not import internal/store (§13.6).

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// adminActions are the three approval actions of P4-T03a (nil services: registered, refusing to run).
func adminActions(p *platform.Service, t *tenants.Service) []approvals.Action {
	return []approvals.Action{superAdminAction(p), tenantIdPAction(t), securitySettingsAction(t)}
}

// executionOf names the executed request for the services (requester, decider).
func executionOf(e approvals.Execution) (uuid.UUID, uuid.UUID, uuid.UUID) {
	decided := uuid.Nil
	if e.Request.DecidedBy != nil {
		decided = e.Request.DecidedBy.IdentityID
	}
	return e.Request.ID, e.Request.RequestedBy.IdentityID, decided
}

// approvalRefusal turns a refusal of an executing service into the refusal of the approval (409, nothing written —
// the request stays approved until it expires): a target that changed since the request is target_changed.
func approvalRefusal(err error) error {
	var (
		pe *platform.AdminError
		te *tenants.AdminError
	)
	switch {
	case errors.Is(err, tenants.ErrStale):
		return approvals.TargetChanged()
	case errors.As(err, &pe):
		if pe.Reason == platform.ReasonStale {
			return approvals.TargetChanged()
		}
		return &approvals.Error{Kind: approvals.ErrConflict, Reason: pe.Reason}
	case errors.As(err, &te):
		return &approvals.Error{Kind: approvals.ErrConflict, Reason: te.Reason}
	}
	return err
}

// superAdminAction executes an approved platform.user.super_admin request (§8.4 invariant 3, §8.5): the decider is a
// second Super Admin (platform.user:assign_super_admin); the role changes in the approval's platform transaction under
// the advisory lock of every Super Admin assignment (the bootstrap command takes it too).
func superAdminAction(p *platform.Service) approvals.Action {
	return approvals.Typed(approvals.Spec{Name: platform.SuperAdminAction, Scope: authz.ScopePlatform,
		ResourceType: platform.SuperAdminResourceType, Permission: platform.SuperAdminPermission},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, pl platform.SuperAdminPayload) (*uuid.UUID, error) {
			if p == nil {
				return nil, errors.New("super admin role: no platform service in this process")
			}
			if e.Request.ResourceID != pl.PlatformUserID.String() {
				return nil, errors.New("super admin role: the payload names another platform user than the request")
			}
			id, by, decided := executionOf(e)
			return nil, approvalRefusal(p.ExecuteSuperAdmin(ctx, tx.Q, platform.SuperAdminExecution{ApprovalID: id,
				RequestedBy: by, DecidedBy: decided}, pl))
		})
}

// tenantIdPAction executes an approved platform.idp.update_tenant request (§8.2 "mọi thay đổi do nền tảng khởi xướng
// lên IdP của tenant cần … break-glass 2P, và ghi audit hiển thị cho tenant"): the decider holds platform.idp:manage —
// the Super Admin's grant carries tenant_idp_dual_control, which this very approval satisfies (ApproverConditions). The
// row is written in the TENANT's transaction with the tenant's audit and the Owners' notification.
func tenantIdPAction(t *tenants.Service) approvals.Action {
	return approvals.Typed(approvals.Spec{Name: tenants.PlatformIdPChangeApprovalAction, Scope: authz.ScopePlatform,
		ResourceType: "identity_provider", Permission: "platform.idp:manage",
		ApproverConditions: []string{authz.CondTenantIdPDualControl}},
		func(ctx context.Context, _ *store.Tx, e approvals.Execution, p tenants.PlatformIdPChange) (*uuid.UUID, error) {
			if t == nil {
				return nil, errors.New("tenant idp change: no tenants service in this process")
			}
			if e.Request.ResourceID != p.IdPID.String() {
				return nil, errors.New("tenant idp change: the payload names another identity provider than the request")
			}
			id, by, decided := executionOf(e)
			return nil, approvalRefusal(t.ApplyPlatformIdPChange(ctx, p, tenants.ApprovalExecution{ApprovalID: id,
				RequestedBy: by, DecidedBy: decided}))
		})
}

// securitySettingsAction executes an approved tenant.settings.update_security request (§8.6 "tắt 4-eyes … do một
// Tenant Owner/Admin khác duyệt"): the deciding permission is tenant.approval:decide itself (TO, TA); the settings are
// written in the approval's tenant transaction, only if they still have the ETag the request was made on.
func securitySettingsAction(t *tenants.Service) approvals.Action {
	return approvals.Typed(approvals.Spec{Name: tenants.SecuritySettingsApprovalAction, Scope: authz.ScopeTenant,
		ResourceType: "settings", Permission: "tenant.approval:decide"},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p tenants.SecuritySettingsPayload) (*uuid.UUID, error) {
			if t == nil || e.Request.TenantID == nil {
				return nil, errors.New("security settings: no tenants service in this process")
			}
			id, by, decided := executionOf(e)
			return nil, approvalRefusal(t.ExecuteSecuritySettings(ctx, tx, *e.Request.TenantID, tenants.ApprovalExecution{
				ApprovalID: id, RequestedBy: by, DecidedBy: decided}, p))
		})
}

// notifyDeciders (approvals.Config.Notify) tells the members who may decide a tenant approval request that it waits (the approval queue of the
// tenant — notification approval.requested, P3-T04a kind, produced from P4-T03a), in the request's transaction.
func notifyDeciders(ctx context.Context, tx *store.Tx, r approvals.Request) error {
	if r.Scope != authz.ScopeTenant || r.TenantID == nil {
		return nil
	}
	_, err := notifications.Enqueue(ctx, tx, notifications.ApprovalRequested(*r.TenantID, r.ID, r.Action, "", "", r.ExpiresAt))
	return err
}

// idpClientSecrets stores the client secret of a tenant's external IdP in the SecretStore under the IdP's own name
// (idp.AdminClientSecretName, owner = the tenant — the only reference the login callback and the CHECK of 0007 accept):
// version 1 the first time, the next version afterwards.
type idpClientSecrets struct{ s *secrets.Store }

var _ tenants.ClientSecrets = idpClientSecrets{}

func (c idpClientSecrets) Store(ctx context.Context, tenantID, idpID uuid.UUID, secret []byte) (string, error) {
	if c.s == nil || tenantID == uuid.Nil {
		return "", errors.New("idp client secret: no SecretStore or no tenant")
	}
	name := idp.AdminClientSecretName(idpID)
	latest, err := c.s.Latest(ctx, tenantID, name)
	var ref secrets.Ref
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		ref = secrets.TenantRef(tenantID, name, 1)
		err = c.s.Put(ctx, ref, secret)
	case err == nil:
		ref, err = c.s.Rotate(ctx, latest, secret)
	}
	if err != nil {
		return "", err
	}
	return ref.String(), nil
}

func (c idpClientSecrets) Destroy(ctx context.Context, ref string) error {
	r, err := secrets.ParseRef(ref)
	if err != nil || c.s == nil {
		return err
	}
	return c.s.Destroy(ctx, r)
}
