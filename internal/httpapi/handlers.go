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

// Handlers is the extension point of the API: one handler set per building task. A nil set answers every operation
// of its interface with 501 not_implemented. A set may also implement only part of its interface by embedding
// NotImplemented. Handlers return a *problem.Error for an expected failure (not_found, conflict…); any other error
// becomes 500 internal_error and its text goes to the internal log only.
type Handlers struct {
	Auth       AuthHandlers       // P2-T06
	Tenants    TenantHandlers     // P2-T11
	Devices    DeviceHandlers     // P2-T13
	Audit      AuditHandlers      // P2-T08
	Jobs       JobHandlers        // P2-T12
	Monitoring MonitoringHandlers // P2-T13a
}

func (h Handlers) mounted() bool {
	return h.Auth != nil || h.Tenants != nil || h.Devices != nil || h.Audit != nil || h.Jobs != nil || h.Monitoring != nil
}

// dispatcher implements gen.StrictServerInterface by promotion from the six disjoint interfaces.
type dispatcher struct {
	AuthHandlers
	TenantHandlers
	DeviceHandlers
	AuditHandlers
	JobHandlers
	MonitoringHandlers
}

var _ gen.StrictServerInterface = dispatcher{}

func newDispatcher(h Handlers) dispatcher {
	d := dispatcher{h.Auth, h.Tenants, h.Devices, h.Audit, h.Jobs, h.Monitoring}
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
