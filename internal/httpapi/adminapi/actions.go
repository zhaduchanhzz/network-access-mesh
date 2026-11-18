package adminapi

// The approval actions of P4-T03a, registered by apps/internal/runner (approvals.Registry) and by the tests that
// compose the API: a Super Admin role change and a platform change of a tenant IdP (platform 2P), a security settings
// change that lifts a second-person control (tenant scope); and NotifyDeciders, the hook that tells the deciders of a
// tenant approval request that it waits.

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ApprovalActions are the three actions of P4-T03a (nil services: registered, refusing to run).
func ApprovalActions(p *platform.Service, t *tenants.Service) []approvals.Action {
	return []approvals.Action{SuperAdminAction(p), TenantIdPAction(t), SecuritySettingsAction(t)}
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

// SuperAdminAction executes an approved platform.user.super_admin request (§8.4 invariant 3, §8.5): the decider is a
// second Super Admin (platform.user:assign_super_admin); the role changes in the approval's platform transaction under
// the advisory lock of every Super Admin assignment (the bootstrap command takes it too).
func SuperAdminAction(p *platform.Service) approvals.Action {
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

// TenantIdPAction executes an approved platform.idp.update_tenant request (§8.2 "mọi thay đổi do nền tảng khởi xướng
// lên IdP của tenant cần … break-glass 2P, và ghi audit hiển thị cho tenant"): the decider holds platform.idp:manage —
// the Super Admin's grant carries tenant_idp_dual_control, which this very approval satisfies (ApproverConditions). The
// row is written in the TENANT's transaction with the tenant's audit and the Owners' notification.
func TenantIdPAction(t *tenants.Service) approvals.Action {
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

// SecuritySettingsAction executes an approved tenant.settings.update_security request (§8.6 "tắt 4-eyes … do một
// Tenant Owner/Admin khác duyệt"): the deciding permission is tenant.approval:decide itself (TO, TA); the settings are
// written in the approval's tenant transaction, only if they still have the ETag the request was made on.
func SecuritySettingsAction(t *tenants.Service) approvals.Action {
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

// NotifyDeciders (approvals.Config.Notify) tells the members who may decide a tenant approval request that it waits (the approval queue of the
// tenant — notification approval.requested, P3-T04a kind, produced from P4-T03a), in the request's transaction.
func NotifyDeciders(ctx context.Context, tx *store.Tx, r approvals.Request) error {
	if r.Scope != authz.ScopeTenant || r.TenantID == nil {
		return nil
	}
	_, err := notifications.Enqueue(ctx, tx, notifications.ApprovalRequested(*r.TenantID, r.ID, r.Action, "", "", r.ExpiresAt))
	return err
}
