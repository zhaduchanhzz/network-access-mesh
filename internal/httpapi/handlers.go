package httpapi

import (
	"context"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
)

// The operations of api/openapi.yaml are split into one interface per building task (the `x-task` of each operation,
// §13.2): a task implements its interface in a handler set and the lead mounts it in Handlers — the generated code is
// never edited. TestHandlerGroupsFollowSpec keeps the split identical to the spec; when the spec gains an operation,
// `var _ gen.StrictServerInterface = dispatcher{}` stops compiling until the operation is added to one interface and
// to NotImplemented.

// AuthHandlers — P2-T06 (`identity`): OIDC login and callback, session, logout, own sessions.
type AuthHandlers interface {
	AuthLogin(ctx context.Context, request gen.AuthLoginRequestObject) (gen.AuthLoginResponseObject, error)
	AuthCallback(ctx context.Context, request gen.AuthCallbackRequestObject) (gen.AuthCallbackResponseObject, error)
	AuthLogout(ctx context.Context, request gen.AuthLogoutRequestObject) (gen.AuthLogoutResponseObject, error)
	GetAuthSession(ctx context.Context, request gen.GetAuthSessionRequestObject) (gen.GetAuthSessionResponseObject, error)
	ListAuthSessions(ctx context.Context, request gen.ListAuthSessionsRequestObject) (gen.ListAuthSessionsResponseObject, error)
	RevokeAuthSession(ctx context.Context, request gen.RevokeAuthSessionRequestObject) (gen.RevokeAuthSessionResponseObject, error)
}

// TenantHandlers — P2-T11 (`tenants`/`platform`, read): tenants of the caller, members, platform registry and instances.
type TenantHandlers interface {
	ListMyTenants(ctx context.Context, request gen.ListMyTenantsRequestObject) (gen.ListMyTenantsResponseObject, error)
	GetTenant(ctx context.Context, request gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error)
	ListTenantUsers(ctx context.Context, request gen.ListTenantUsersRequestObject) (gen.ListTenantUsersResponseObject, error)
	GetTenantUser(ctx context.Context, request gen.GetTenantUserRequestObject) (gen.GetTenantUserResponseObject, error)
	ListPlatformTenants(ctx context.Context, request gen.ListPlatformTenantsRequestObject) (gen.ListPlatformTenantsResponseObject, error)
	GetPlatformTenant(ctx context.Context, request gen.GetPlatformTenantRequestObject) (gen.GetPlatformTenantResponseObject, error)
	ListPlatformInstances(ctx context.Context, request gen.ListPlatformInstancesRequestObject) (gen.ListPlatformInstancesResponseObject, error)
	GetPlatformInstance(ctx context.Context, request gen.GetPlatformInstanceRequestObject) (gen.GetPlatformInstanceResponseObject, error)
}

// DeviceHandlers — P2-T13 (`devices`): inventory, rename, two-phase revocation, sync.
type DeviceHandlers interface {
	ListDevices(ctx context.Context, request gen.ListDevicesRequestObject) (gen.ListDevicesResponseObject, error)
	GetDevice(ctx context.Context, request gen.GetDeviceRequestObject) (gen.GetDeviceResponseObject, error)
	RenameDevice(ctx context.Context, request gen.RenameDeviceRequestObject) (gen.RenameDeviceResponseObject, error)
	DeleteDevice(ctx context.Context, request gen.DeleteDeviceRequestObject) (gen.DeleteDeviceResponseObject, error)
	ExpireDevice(ctx context.Context, request gen.ExpireDeviceRequestObject) (gen.ExpireDeviceResponseObject, error)
	SyncDevices(ctx context.Context, request gen.SyncDevicesRequestObject) (gen.SyncDevicesResponseObject, error)
}

// AuditHandlers — P2-T08 (`audit`): audit events of a tenant and of the platform.
type AuditHandlers interface {
	ListTenantAuditEvents(ctx context.Context, request gen.ListTenantAuditEventsRequestObject) (gen.ListTenantAuditEventsResponseObject, error)
	ListPlatformAuditEvents(ctx context.Context, request gen.ListPlatformAuditEventsRequestObject) (gen.ListPlatformAuditEventsResponseObject, error)
}

// JobHandlers — P2-T12 (`jobs`): jobs of a tenant (safe projection) and of the platform.
type JobHandlers interface {
	ListTenantJobs(ctx context.Context, request gen.ListTenantJobsRequestObject) (gen.ListTenantJobsResponseObject, error)
	GetTenantJob(ctx context.Context, request gen.GetTenantJobRequestObject) (gen.GetTenantJobResponseObject, error)
	ListPlatformJobs(ctx context.Context, request gen.ListPlatformJobsRequestObject) (gen.ListPlatformJobsResponseObject, error)
	GetPlatformJob(ctx context.Context, request gen.GetPlatformJobRequestObject) (gen.GetPlatformJobResponseObject, error)
}

// MonitoringHandlers — P2-T13a (`monitoring`): tenant dashboard and platform health.
type MonitoringHandlers interface {
	GetTenantDashboard(ctx context.Context, request gen.GetTenantDashboardRequestObject) (gen.GetTenantDashboardResponseObject, error)
	GetPlatformHealth(ctx context.Context, request gen.GetPlatformHealthRequestObject) (gen.GetPlatformHealthResponseObject, error)
}

// NotificationHandlers — P3-T05b (`notifications`): the caller's own Portal notifications.
type NotificationHandlers interface {
	ListNotifications(ctx context.Context, request gen.ListNotificationsRequestObject) (gen.ListNotificationsResponseObject, error)
}

// ApprovalHandlers — P3-T04a (`authz` approvals): dual control of the platform and of a tenant (§8.5/§8.6 2P rule).
type ApprovalHandlers interface {
	ListPlatformApprovals(ctx context.Context, request gen.ListPlatformApprovalsRequestObject) (gen.ListPlatformApprovalsResponseObject, error)
	GetPlatformApproval(ctx context.Context, request gen.GetPlatformApprovalRequestObject) (gen.GetPlatformApprovalResponseObject, error)
	ApprovePlatformApproval(ctx context.Context, request gen.ApprovePlatformApprovalRequestObject) (gen.ApprovePlatformApprovalResponseObject, error)
	RejectPlatformApproval(ctx context.Context, request gen.RejectPlatformApprovalRequestObject) (gen.RejectPlatformApprovalResponseObject, error)
	ListTenantApprovals(ctx context.Context, request gen.ListTenantApprovalsRequestObject) (gen.ListTenantApprovalsResponseObject, error)
	GetTenantApproval(ctx context.Context, request gen.GetTenantApprovalRequestObject) (gen.GetTenantApprovalResponseObject, error)
	ApproveTenantApproval(ctx context.Context, request gen.ApproveTenantApprovalRequestObject) (gen.ApproveTenantApprovalResponseObject, error)
	RejectTenantApproval(ctx context.Context, request gen.RejectTenantApprovalRequestObject) (gen.RejectTenantApprovalResponseObject, error)
}

// InvitationHandlers — P3-T05a (`tenants`): invitations of a tenant (§6.3 tenant_invitations).
type InvitationHandlers interface {
	ListTenantInvitations(ctx context.Context, request gen.ListTenantInvitationsRequestObject) (gen.ListTenantInvitationsResponseObject, error)
	CreateTenantInvitation(ctx context.Context, request gen.CreateTenantInvitationRequestObject) (gen.CreateTenantInvitationResponseObject, error)
	RevokeTenantInvitation(ctx context.Context, request gen.RevokeTenantInvitationRequestObject) (gen.RevokeTenantInvitationResponseObject, error)
	ResendTenantInvitation(ctx context.Context, request gen.ResendTenantInvitationRequestObject) (gen.ResendTenantInvitationResponseObject, error)
}

// HostHandlers — P3-T04 (`platform` placement): hosts, their capacity, public entry and allocation ranges.
type HostHandlers interface {
	ListPlatformHosts(ctx context.Context, request gen.ListPlatformHostsRequestObject) (gen.ListPlatformHostsResponseObject, error)
	GetPlatformHost(ctx context.Context, request gen.GetPlatformHostRequestObject) (gen.GetPlatformHostResponseObject, error)
	CreatePlatformHost(ctx context.Context, request gen.CreatePlatformHostRequestObject) (gen.CreatePlatformHostResponseObject, error)
	UpdatePlatformHost(ctx context.Context, request gen.UpdatePlatformHostRequestObject) (gen.UpdatePlatformHostResponseObject, error)
}

// IdPConsoleHandlers — P3-T15 (`idp` console session, §8.2 (3)): the Keycloak administration console session — always
// dual control — and its list.
type IdPConsoleHandlers interface {
	ListIdpConsoleSessions(ctx context.Context, request gen.ListIdpConsoleSessionsRequestObject) (gen.ListIdpConsoleSessionsResponseObject, error)
	RequestIdpConsoleSession(ctx context.Context, request gen.RequestIdpConsoleSessionRequestObject) (gen.RequestIdpConsoleSessionResponseObject, error)
}

// ProvisioningHandlers — P3-T05 (`provisioning` orchestrator): tenant creation (steps 1–2 of tenant.provision) and the
// controls of lifecycle jobs (§11.3, §13.2).
type ProvisioningHandlers interface {
	CreatePlatformTenant(ctx context.Context, request gen.CreatePlatformTenantRequestObject) (gen.CreatePlatformTenantResponseObject, error)
	RetryPlatformJob(ctx context.Context, request gen.RetryPlatformJobRequestObject) (gen.RetryPlatformJobResponseObject, error)
	CancelPlatformJob(ctx context.Context, request gen.CancelPlatformJobRequestObject) (gen.CancelPlatformJobResponseObject, error)
	RollbackPlatformJob(ctx context.Context, request gen.RollbackPlatformJobRequestObject) (gen.RollbackPlatformJobResponseObject, error)
}

// LifecycleHandlers — P3-T08 (`provisioning` lifecycle): suspension of a tenant and its reversal (§11.4, §13.2). The
// refusal of a suspended tenant's writes is not a handler's: it is layer 1 (internal/authz), for every operation.
type LifecycleHandlers interface {
	SuspendPlatformTenant(ctx context.Context, request gen.SuspendPlatformTenantRequestObject) (gen.SuspendPlatformTenantResponseObject, error)
	ResumePlatformTenant(ctx context.Context, request gen.ResumePlatformTenantRequestObject) (gen.ResumePlatformTenantResponseObject, error)
}

// DeprovisionHandlers — P3-T09 (`provisioning` deprovision): the deletion of a tenant, always dual control (§11.4,
// §13.2 DELETE /platform/tenants/{id}).
type DeprovisionHandlers interface {
	DeletePlatformTenant(ctx context.Context, request gen.DeletePlatformTenantRequestObject) (gen.DeletePlatformTenantResponseObject, error)
}

// RelayHandlers — P3-T05c (`relay`): the tenant's relays and the platform's relay regions, read-only in the MVP, each
// health with its checked_at (§10.6).
type RelayHandlers interface {
	GetTenantRelay(ctx context.Context, request gen.GetTenantRelayRequestObject) (gen.GetTenantRelayResponseObject, error)
	ListPlatformRelayRegions(ctx context.Context, request gen.ListPlatformRelayRegionsRequestObject) (gen.ListPlatformRelayRegionsResponseObject, error)
}

// ReconfigureHandlers — P3-T13 (`provisioning` orchestrator): the reconfiguration of an instance (job
// instance.reconfigure — §11.4).
type ReconfigureHandlers interface {
	ReconfigurePlatformInstance(ctx context.Context, request gen.ReconfigurePlatformInstanceRequestObject) (gen.ReconfigurePlatformInstanceResponseObject, error)
}

// BackupHandlers — P3-T11 (backup/restore v1, §17.1–§17.2): an instance backup now, a restore — always dual control —
// and the backup book.
type BackupHandlers interface {
	BackupPlatformInstance(ctx context.Context, request gen.BackupPlatformInstanceRequestObject) (gen.BackupPlatformInstanceResponseObject, error)
	RestorePlatformInstance(ctx context.Context, request gen.RestorePlatformInstanceRequestObject) (gen.RestorePlatformInstanceResponseObject, error)
	ListPlatformBackups(ctx context.Context, request gen.ListPlatformBackupsRequestObject) (gen.ListPlatformBackupsResponseObject, error)
}

// InstanceOpsHandlers — P3-T13a (`provisioning` orchestrator): the restart and the upgrade of an instance (jobs
// instance.restart, instance.upgrade — §11.4).
type InstanceOpsHandlers interface {
	RestartPlatformInstance(ctx context.Context, request gen.RestartPlatformInstanceRequestObject) (gen.RestartPlatformInstanceResponseObject, error)
	UpgradePlatformInstance(ctx context.Context, request gen.UpgradePlatformInstanceRequestObject) (gen.UpgradePlatformInstanceResponseObject, error)
}

// QuarantineHandlers — P3-T18 (`provisioning` quarantine): the quarantine of an instance (job instance.quarantine,
// immediate) and its release (always dual control, job instance.release after the approval — §11.4).
type QuarantineHandlers interface {
	QuarantinePlatformInstance(ctx context.Context, request gen.QuarantinePlatformInstanceRequestObject) (gen.QuarantinePlatformInstanceResponseObject, error)
	ReleasePlatformInstance(ctx context.Context, request gen.ReleasePlatformInstanceRequestObject) (gen.ReleasePlatformInstanceResponseObject, error)
}

// MemberHandlers — P4-T09 (`members`): the write side of the users of a tenant (lock, roles, ownership transfer,
// sessions, two-phase offboarding) and its groups (sensitive groups through a tenant-scope approval — §7.3).
type MemberHandlers interface {
	UpdateTenantUser(ctx context.Context, request gen.UpdateTenantUserRequestObject) (gen.UpdateTenantUserResponseObject, error)
	OffboardTenantUser(ctx context.Context, request gen.OffboardTenantUserRequestObject) (gen.OffboardTenantUserResponseObject, error)
	SetTenantUserRole(ctx context.Context, request gen.SetTenantUserRoleRequestObject) (gen.SetTenantUserRoleResponseObject, error)
	SetTenantUserAdminRole(ctx context.Context, request gen.SetTenantUserAdminRoleRequestObject) (gen.SetTenantUserAdminRoleResponseObject, error)
	TransferTenantOwnership(ctx context.Context, request gen.TransferTenantOwnershipRequestObject) (gen.TransferTenantOwnershipResponseObject, error)
	RevokeTenantUserSessions(ctx context.Context, request gen.RevokeTenantUserSessionsRequestObject) (gen.RevokeTenantUserSessionsResponseObject, error)
	ListTenantGroups(ctx context.Context, request gen.ListTenantGroupsRequestObject) (gen.ListTenantGroupsResponseObject, error)
	CreateTenantGroup(ctx context.Context, request gen.CreateTenantGroupRequestObject) (gen.CreateTenantGroupResponseObject, error)
	GetTenantGroup(ctx context.Context, request gen.GetTenantGroupRequestObject) (gen.GetTenantGroupResponseObject, error)
	UpdateTenantGroup(ctx context.Context, request gen.UpdateTenantGroupRequestObject) (gen.UpdateTenantGroupResponseObject, error)
	DeleteTenantGroup(ctx context.Context, request gen.DeleteTenantGroupRequestObject) (gen.DeleteTenantGroupResponseObject, error)
	SetTenantGroupMembers(ctx context.Context, request gen.SetTenantGroupMembersRequestObject) (gen.SetTenantGroupMembersResponseObject, error)
}

// Handlers is the extension point of the API: one handler set per building task. A nil set answers every operation
// of its interface with 501 not_implemented. A set may also implement only part of its interface by embedding
// NotImplemented. Handlers return a *problem.Error for an expected failure (not_found, conflict…); any other error
// becomes 500 internal_error and its text goes to the internal log only.
type Handlers struct {
	Auth          AuthHandlers         // P2-T06
	Tenants       TenantHandlers       // P2-T11
	Devices       DeviceHandlers       // P2-T13
	Audit         AuditHandlers        // P2-T08
	Jobs          JobHandlers          // P2-T12
	Monitoring    MonitoringHandlers   // P2-T13a
	Hosts         HostHandlers         // P3-T04
	Approvals     ApprovalHandlers     // P3-T04a
	Invitations   InvitationHandlers   // P3-T05a
	Notifications NotificationHandlers // P3-T05b
	IdPConsole    IdPConsoleHandlers   // P3-T15
	Provisioning  ProvisioningHandlers // P3-T05
	Lifecycle     LifecycleHandlers    // P3-T08
	Relay         RelayHandlers        // P3-T05c
	Reconfigure   ReconfigureHandlers  // P3-T13
	Backups       BackupHandlers       // P3-T11
	InstanceOps   InstanceOpsHandlers  // P3-T13a
	Deprovision   DeprovisionHandlers  // P3-T09
	Quarantine    QuarantineHandlers   // P3-T18
	Members       MemberHandlers       // P4-T09
}

func (h Handlers) mounted() bool {
	return h.Auth != nil || h.Tenants != nil || h.Devices != nil || h.Audit != nil || h.Jobs != nil || h.Monitoring != nil ||
		h.Notifications != nil || h.Approvals != nil || h.Invitations != nil || h.Hosts != nil || h.IdPConsole != nil ||
		h.Provisioning != nil || h.Lifecycle != nil || h.Relay != nil || h.Reconfigure != nil || h.Backups != nil ||
		h.InstanceOps != nil || h.Quarantine != nil || h.Deprovision != nil || h.Members != nil
}

// dispatcher implements gen.StrictServerInterface by promotion from the disjoint interfaces.
type dispatcher struct {
	AuthHandlers
	TenantHandlers
	DeviceHandlers
	AuditHandlers
	JobHandlers
	MonitoringHandlers
	NotificationHandlers
	ApprovalHandlers
	InvitationHandlers
	HostHandlers
	IdPConsoleHandlers
	ProvisioningHandlers
	LifecycleHandlers
	RelayHandlers
	ReconfigureHandlers
	BackupHandlers
	InstanceOpsHandlers
	QuarantineHandlers
	DeprovisionHandlers
	MemberHandlers
}

var _ gen.StrictServerInterface = dispatcher{}

func newDispatcher(h Handlers) dispatcher {
	d := dispatcher{h.Auth, h.Tenants, h.Devices, h.Audit, h.Jobs, h.Monitoring, h.Notifications, h.Approvals, h.Invitations,
		h.Hosts, h.IdPConsole, h.Provisioning, h.Lifecycle, h.Relay, h.Reconfigure, h.Backups, h.InstanceOps,
		h.Quarantine, h.Deprovision, h.Members}
	if d.MemberHandlers == nil {
		d.MemberHandlers = NotImplemented{}
	}
	if d.InstanceOpsHandlers == nil {
		d.InstanceOpsHandlers = NotImplemented{}
	}
	if d.DeprovisionHandlers == nil {
		d.DeprovisionHandlers = NotImplemented{}
	}
	if d.BackupHandlers == nil {
		d.BackupHandlers = NotImplemented{}
	}
	if d.RelayHandlers == nil {
		d.RelayHandlers = NotImplemented{}
	}
	if d.ProvisioningHandlers == nil {
		d.ProvisioningHandlers = NotImplemented{}
	}
	if d.LifecycleHandlers == nil {
		d.LifecycleHandlers = NotImplemented{}
	}
	if d.ReconfigureHandlers == nil {
		d.ReconfigureHandlers = NotImplemented{}
	}
	if d.QuarantineHandlers == nil {
		d.QuarantineHandlers = NotImplemented{}
	}
	if d.ApprovalHandlers == nil {
		d.ApprovalHandlers = NotImplemented{}
	}
	if d.InvitationHandlers == nil {
		d.InvitationHandlers = NotImplemented{}
	}
	if d.IdPConsoleHandlers == nil {
		d.IdPConsoleHandlers = NotImplemented{}
	}
	if d.AuthHandlers == nil {
		d.AuthHandlers = NotImplemented{}
	}
	if d.TenantHandlers == nil {
		d.TenantHandlers = NotImplemented{}
	}
	if d.DeviceHandlers == nil {
		d.DeviceHandlers = NotImplemented{}
	}
	if d.AuditHandlers == nil {
		d.AuditHandlers = NotImplemented{}
	}
	if d.JobHandlers == nil {
		d.JobHandlers = NotImplemented{}
	}
	if d.MonitoringHandlers == nil {
		d.MonitoringHandlers = NotImplemented{}
	}
	if d.NotificationHandlers == nil {
		d.NotificationHandlers = NotImplemented{}
	}
	if d.HostHandlers == nil {
		d.HostHandlers = NotImplemented{}
	}
	return d
}

// NotImplemented answers every operation with 501 not_implemented. Embed it in a handler set that implements only
// some operations of its interface.
type NotImplemented struct{}

var _ gen.StrictServerInterface = NotImplemented{}

func (NotImplemented) AuthLogin(context.Context, gen.AuthLoginRequestObject) (gen.AuthLoginResponseObject, error) {
	return nil, problem.NotImplemented("AuthLogin")
}

func (NotImplemented) AuthCallback(context.Context, gen.AuthCallbackRequestObject) (gen.AuthCallbackResponseObject, error) {
	return nil, problem.NotImplemented("AuthCallback")
}

func (NotImplemented) AuthLogout(context.Context, gen.AuthLogoutRequestObject) (gen.AuthLogoutResponseObject, error) {
	return nil, problem.NotImplemented("AuthLogout")
}

func (NotImplemented) GetAuthSession(context.Context, gen.GetAuthSessionRequestObject) (gen.GetAuthSessionResponseObject, error) {
	return nil, problem.NotImplemented("GetAuthSession")
}

func (NotImplemented) ListAuthSessions(context.Context, gen.ListAuthSessionsRequestObject) (gen.ListAuthSessionsResponseObject, error) {
	return nil, problem.NotImplemented("ListAuthSessions")
}

func (NotImplemented) RevokeAuthSession(context.Context, gen.RevokeAuthSessionRequestObject) (gen.RevokeAuthSessionResponseObject, error) {
	return nil, problem.NotImplemented("RevokeAuthSession")
}

func (NotImplemented) ListMyTenants(context.Context, gen.ListMyTenantsRequestObject) (gen.ListMyTenantsResponseObject, error) {
	return nil, problem.NotImplemented("ListMyTenants")
}

func (NotImplemented) GetTenant(context.Context, gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	return nil, problem.NotImplemented("GetTenant")
}

func (NotImplemented) ListTenantUsers(context.Context, gen.ListTenantUsersRequestObject) (gen.ListTenantUsersResponseObject, error) {
	return nil, problem.NotImplemented("ListTenantUsers")
}

func (NotImplemented) GetTenantUser(context.Context, gen.GetTenantUserRequestObject) (gen.GetTenantUserResponseObject, error) {
	return nil, problem.NotImplemented("GetTenantUser")
}

func (NotImplemented) ListPlatformTenants(context.Context, gen.ListPlatformTenantsRequestObject) (gen.ListPlatformTenantsResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformTenants")
}

func (NotImplemented) GetPlatformTenant(context.Context, gen.GetPlatformTenantRequestObject) (gen.GetPlatformTenantResponseObject, error) {
	return nil, problem.NotImplemented("GetPlatformTenant")
}

func (NotImplemented) ListPlatformInstances(context.Context, gen.ListPlatformInstancesRequestObject) (gen.ListPlatformInstancesResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformInstances")
}

func (NotImplemented) GetPlatformInstance(context.Context, gen.GetPlatformInstanceRequestObject) (gen.GetPlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("GetPlatformInstance")
}

func (NotImplemented) ListDevices(context.Context, gen.ListDevicesRequestObject) (gen.ListDevicesResponseObject, error) {
	return nil, problem.NotImplemented("ListDevices")
}

func (NotImplemented) GetDevice(context.Context, gen.GetDeviceRequestObject) (gen.GetDeviceResponseObject, error) {
	return nil, problem.NotImplemented("GetDevice")
}

func (NotImplemented) RenameDevice(context.Context, gen.RenameDeviceRequestObject) (gen.RenameDeviceResponseObject, error) {
	return nil, problem.NotImplemented("RenameDevice")
}

func (NotImplemented) DeleteDevice(context.Context, gen.DeleteDeviceRequestObject) (gen.DeleteDeviceResponseObject, error) {
	return nil, problem.NotImplemented("DeleteDevice")
}

func (NotImplemented) ExpireDevice(context.Context, gen.ExpireDeviceRequestObject) (gen.ExpireDeviceResponseObject, error) {
	return nil, problem.NotImplemented("ExpireDevice")
}

func (NotImplemented) SyncDevices(context.Context, gen.SyncDevicesRequestObject) (gen.SyncDevicesResponseObject, error) {
	return nil, problem.NotImplemented("SyncDevices")
}

func (NotImplemented) ListTenantAuditEvents(context.Context, gen.ListTenantAuditEventsRequestObject) (gen.ListTenantAuditEventsResponseObject, error) {
	return nil, problem.NotImplemented("ListTenantAuditEvents")
}

func (NotImplemented) ListPlatformAuditEvents(context.Context, gen.ListPlatformAuditEventsRequestObject) (gen.ListPlatformAuditEventsResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformAuditEvents")
}

func (NotImplemented) ListTenantJobs(context.Context, gen.ListTenantJobsRequestObject) (gen.ListTenantJobsResponseObject, error) {
	return nil, problem.NotImplemented("ListTenantJobs")
}

func (NotImplemented) GetTenantJob(context.Context, gen.GetTenantJobRequestObject) (gen.GetTenantJobResponseObject, error) {
	return nil, problem.NotImplemented("GetTenantJob")
}

func (NotImplemented) ListPlatformJobs(context.Context, gen.ListPlatformJobsRequestObject) (gen.ListPlatformJobsResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformJobs")
}

func (NotImplemented) GetPlatformJob(context.Context, gen.GetPlatformJobRequestObject) (gen.GetPlatformJobResponseObject, error) {
	return nil, problem.NotImplemented("GetPlatformJob")
}

func (NotImplemented) GetTenantDashboard(context.Context, gen.GetTenantDashboardRequestObject) (gen.GetTenantDashboardResponseObject, error) {
	return nil, problem.NotImplemented("GetTenantDashboard")
}

func (NotImplemented) GetPlatformHealth(context.Context, gen.GetPlatformHealthRequestObject) (gen.GetPlatformHealthResponseObject, error) {
	return nil, problem.NotImplemented("GetPlatformHealth")
}

func (NotImplemented) ListNotifications(context.Context, gen.ListNotificationsRequestObject) (gen.ListNotificationsResponseObject, error) {
	return nil, problem.NotImplemented("ListNotifications")
}

func (NotImplemented) ListPlatformApprovals(context.Context, gen.ListPlatformApprovalsRequestObject) (gen.ListPlatformApprovalsResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformApprovals")
}

func (NotImplemented) GetPlatformApproval(context.Context, gen.GetPlatformApprovalRequestObject) (gen.GetPlatformApprovalResponseObject, error) {
	return nil, problem.NotImplemented("GetPlatformApproval")
}

func (NotImplemented) ApprovePlatformApproval(context.Context, gen.ApprovePlatformApprovalRequestObject) (gen.ApprovePlatformApprovalResponseObject, error) {
	return nil, problem.NotImplemented("ApprovePlatformApproval")
}

func (NotImplemented) RejectPlatformApproval(context.Context, gen.RejectPlatformApprovalRequestObject) (gen.RejectPlatformApprovalResponseObject, error) {
	return nil, problem.NotImplemented("RejectPlatformApproval")
}

func (NotImplemented) ListTenantApprovals(context.Context, gen.ListTenantApprovalsRequestObject) (gen.ListTenantApprovalsResponseObject, error) {
	return nil, problem.NotImplemented("ListTenantApprovals")
}

func (NotImplemented) GetTenantApproval(context.Context, gen.GetTenantApprovalRequestObject) (gen.GetTenantApprovalResponseObject, error) {
	return nil, problem.NotImplemented("GetTenantApproval")
}

func (NotImplemented) ApproveTenantApproval(context.Context, gen.ApproveTenantApprovalRequestObject) (gen.ApproveTenantApprovalResponseObject, error) {
	return nil, problem.NotImplemented("ApproveTenantApproval")
}

func (NotImplemented) RejectTenantApproval(context.Context, gen.RejectTenantApprovalRequestObject) (gen.RejectTenantApprovalResponseObject, error) {
	return nil, problem.NotImplemented("RejectTenantApproval")
}

func (NotImplemented) ListTenantInvitations(context.Context, gen.ListTenantInvitationsRequestObject) (gen.ListTenantInvitationsResponseObject, error) {
	return nil, problem.NotImplemented("ListTenantInvitations")
}

func (NotImplemented) CreateTenantInvitation(context.Context, gen.CreateTenantInvitationRequestObject) (gen.CreateTenantInvitationResponseObject, error) {
	return nil, problem.NotImplemented("CreateTenantInvitation")
}

func (NotImplemented) RevokeTenantInvitation(context.Context, gen.RevokeTenantInvitationRequestObject) (gen.RevokeTenantInvitationResponseObject, error) {
	return nil, problem.NotImplemented("RevokeTenantInvitation")
}

func (NotImplemented) ResendTenantInvitation(context.Context, gen.ResendTenantInvitationRequestObject) (gen.ResendTenantInvitationResponseObject, error) {
	return nil, problem.NotImplemented("ResendTenantInvitation")
}

func (NotImplemented) ListPlatformHosts(context.Context, gen.ListPlatformHostsRequestObject) (gen.ListPlatformHostsResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformHosts")
}

func (NotImplemented) GetPlatformHost(context.Context, gen.GetPlatformHostRequestObject) (gen.GetPlatformHostResponseObject, error) {
	return nil, problem.NotImplemented("GetPlatformHost")
}

func (NotImplemented) CreatePlatformHost(context.Context, gen.CreatePlatformHostRequestObject) (gen.CreatePlatformHostResponseObject, error) {
	return nil, problem.NotImplemented("CreatePlatformHost")
}

func (NotImplemented) UpdatePlatformHost(context.Context, gen.UpdatePlatformHostRequestObject) (gen.UpdatePlatformHostResponseObject, error) {
	return nil, problem.NotImplemented("UpdatePlatformHost")
}

func (NotImplemented) ListIdpConsoleSessions(context.Context, gen.ListIdpConsoleSessionsRequestObject) (gen.ListIdpConsoleSessionsResponseObject, error) {
	return nil, problem.NotImplemented("ListIdpConsoleSessions")
}

func (NotImplemented) RequestIdpConsoleSession(context.Context, gen.RequestIdpConsoleSessionRequestObject) (gen.RequestIdpConsoleSessionResponseObject, error) {
	return nil, problem.NotImplemented("RequestIdpConsoleSession")
}

func (NotImplemented) DeletePlatformTenant(context.Context, gen.DeletePlatformTenantRequestObject) (gen.DeletePlatformTenantResponseObject, error) {
	return nil, problem.NotImplemented("DeletePlatformTenant")
}

func (NotImplemented) BackupPlatformInstance(context.Context, gen.BackupPlatformInstanceRequestObject) (gen.BackupPlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("BackupPlatformInstance")
}

func (NotImplemented) RestorePlatformInstance(context.Context, gen.RestorePlatformInstanceRequestObject) (gen.RestorePlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("RestorePlatformInstance")
}

func (NotImplemented) ListPlatformBackups(context.Context, gen.ListPlatformBackupsRequestObject) (gen.ListPlatformBackupsResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformBackups")
}

func (NotImplemented) CreatePlatformTenant(context.Context, gen.CreatePlatformTenantRequestObject) (gen.CreatePlatformTenantResponseObject, error) {
	return nil, problem.NotImplemented("CreatePlatformTenant")
}

func (NotImplemented) RetryPlatformJob(context.Context, gen.RetryPlatformJobRequestObject) (gen.RetryPlatformJobResponseObject, error) {
	return nil, problem.NotImplemented("RetryPlatformJob")
}

func (NotImplemented) CancelPlatformJob(context.Context, gen.CancelPlatformJobRequestObject) (gen.CancelPlatformJobResponseObject, error) {
	return nil, problem.NotImplemented("CancelPlatformJob")
}

func (NotImplemented) RollbackPlatformJob(context.Context, gen.RollbackPlatformJobRequestObject) (gen.RollbackPlatformJobResponseObject, error) {
	return nil, problem.NotImplemented("RollbackPlatformJob")
}

func (NotImplemented) SuspendPlatformTenant(context.Context, gen.SuspendPlatformTenantRequestObject) (gen.SuspendPlatformTenantResponseObject, error) {
	return nil, problem.NotImplemented("SuspendPlatformTenant")
}

func (NotImplemented) ResumePlatformTenant(context.Context, gen.ResumePlatformTenantRequestObject) (gen.ResumePlatformTenantResponseObject, error) {
	return nil, problem.NotImplemented("ResumePlatformTenant")
}

func (NotImplemented) GetTenantRelay(context.Context, gen.GetTenantRelayRequestObject) (gen.GetTenantRelayResponseObject, error) {
	return nil, problem.NotImplemented("GetTenantRelay")
}

func (NotImplemented) ListPlatformRelayRegions(context.Context, gen.ListPlatformRelayRegionsRequestObject) (gen.ListPlatformRelayRegionsResponseObject, error) {
	return nil, problem.NotImplemented("ListPlatformRelayRegions")
}

func (NotImplemented) RestartPlatformInstance(context.Context, gen.RestartPlatformInstanceRequestObject) (gen.RestartPlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("RestartPlatformInstance")
}

func (NotImplemented) UpgradePlatformInstance(context.Context, gen.UpgradePlatformInstanceRequestObject) (gen.UpgradePlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("UpgradePlatformInstance")
}

func (NotImplemented) ReconfigurePlatformInstance(context.Context, gen.ReconfigurePlatformInstanceRequestObject) (gen.ReconfigurePlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("ReconfigurePlatformInstance")
}

func (NotImplemented) QuarantinePlatformInstance(context.Context, gen.QuarantinePlatformInstanceRequestObject) (gen.QuarantinePlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("QuarantinePlatformInstance")
}

func (NotImplemented) ReleasePlatformInstance(context.Context, gen.ReleasePlatformInstanceRequestObject) (gen.ReleasePlatformInstanceResponseObject, error) {
	return nil, problem.NotImplemented("ReleasePlatformInstance")
}

func (NotImplemented) UpdateTenantUser(context.Context, gen.UpdateTenantUserRequestObject) (gen.UpdateTenantUserResponseObject, error) {
	return nil, problem.NotImplemented("UpdateTenantUser")
}

func (NotImplemented) OffboardTenantUser(context.Context, gen.OffboardTenantUserRequestObject) (gen.OffboardTenantUserResponseObject, error) {
	return nil, problem.NotImplemented("OffboardTenantUser")
}

func (NotImplemented) SetTenantUserRole(context.Context, gen.SetTenantUserRoleRequestObject) (gen.SetTenantUserRoleResponseObject, error) {
	return nil, problem.NotImplemented("SetTenantUserRole")
}

func (NotImplemented) SetTenantUserAdminRole(context.Context, gen.SetTenantUserAdminRoleRequestObject) (gen.SetTenantUserAdminRoleResponseObject, error) {
	return nil, problem.NotImplemented("SetTenantUserAdminRole")
}

func (NotImplemented) TransferTenantOwnership(context.Context, gen.TransferTenantOwnershipRequestObject) (gen.TransferTenantOwnershipResponseObject, error) {
	return nil, problem.NotImplemented("TransferTenantOwnership")
}

func (NotImplemented) RevokeTenantUserSessions(context.Context, gen.RevokeTenantUserSessionsRequestObject) (gen.RevokeTenantUserSessionsResponseObject, error) {
	return nil, problem.NotImplemented("RevokeTenantUserSessions")
}

func (NotImplemented) ListTenantGroups(context.Context, gen.ListTenantGroupsRequestObject) (gen.ListTenantGroupsResponseObject, error) {
	return nil, problem.NotImplemented("ListTenantGroups")
}

func (NotImplemented) CreateTenantGroup(context.Context, gen.CreateTenantGroupRequestObject) (gen.CreateTenantGroupResponseObject, error) {
	return nil, problem.NotImplemented("CreateTenantGroup")
}

func (NotImplemented) GetTenantGroup(context.Context, gen.GetTenantGroupRequestObject) (gen.GetTenantGroupResponseObject, error) {
	return nil, problem.NotImplemented("GetTenantGroup")
}

func (NotImplemented) UpdateTenantGroup(context.Context, gen.UpdateTenantGroupRequestObject) (gen.UpdateTenantGroupResponseObject, error) {
	return nil, problem.NotImplemented("UpdateTenantGroup")
}

func (NotImplemented) DeleteTenantGroup(context.Context, gen.DeleteTenantGroupRequestObject) (gen.DeleteTenantGroupResponseObject, error) {
	return nil, problem.NotImplemented("DeleteTenantGroup")
}

func (NotImplemented) SetTenantGroupMembers(context.Context, gen.SetTenantGroupMembersRequestObject) (gen.SetTenantGroupMembersResponseObject, error) {
	return nil, problem.NotImplemented("SetTenantGroupMembers")
}
