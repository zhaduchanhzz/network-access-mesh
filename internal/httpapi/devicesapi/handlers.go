// Package devicesapi serves the device operations of api/openapi.yaml (tag devices, P2-T13): listDevices, getDevice,
// renameDevice, expireDevice, deleteDevice and syncDevices. It only translates between the generated types and
// internal/devices, which takes every decision; it never imports internal/store nor internal/headscale (§13.6,
// internal/archtest).
//
// The authorization hook (authzhook.Authz, Hooks.Authz) decides every operation before it runs; the handlers read the
// decision from the context (authzhook.DecisionFrom) for the own-resource rule of the End User (§8.4 invariant 3b,
// x-own-resource) and answer 500 when it is missing — never an unfiltered inventory.
//
// Wiring (P2-T16, apps/internal/runner — api process):
//
//	reg := headscale.NewRegistry(<Locator of P2-T11>, headscale.Options{Logger: log})
//	devicesSvc, _ := devices.New(apiStore, devices.Config{Registry: reg, Logger: log, Registerer: promReg})
//	api, _ := httpapi.New(httpapi.Options{…, Hooks: hooks, Handlers: httpapi.Handlers{…, Devices: devicesapi.New(devicesSvc)}})
//
// and in the worker process (same Registry type, worker store):
//
//	devicesSvc, _ := devices.New(workerStore, devices.Config{Registry: reg, Logger: log, Registerer: promReg})
//	worker, _ := jobs.NewWorker(workerStore, cfg, jobs.Options{…, Alerter: <fan-out to devicesSvc.JobAlert>})
//	_ = devicesSvc.Register(worker)
//	go devicesSvc.NewScheduler(devices.SchedulerConfig{}).Run(ctx)
package devicesapi

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// Service is the part of *devices.Service the handlers need.
type Service interface {
	List(ctx context.Context, tenantID uuid.UUID, a devices.Access, q devices.ListQuery) (devices.Page, error)
	Get(ctx context.Context, tenantID, deviceID uuid.UUID, a devices.Access) (devices.Device, error)
	Rename(ctx context.Context, tenantID, deviceID uuid.UUID, a devices.Access, givenName string) (devices.Device, error)
	Revoke(ctx context.Context, tenantID, deviceID uuid.UUID, a devices.Access, kind, requestKey string) (devices.RevokeResult, error)
	RequestSync(ctx context.Context, tenantID uuid.UUID, a devices.Access, requestKey string) (jobs.Job, error)
}

var _ Service = (*devices.Service)(nil)

// Handlers implements httpapi.DeviceHandlers.
type Handlers struct {
	svc Service
}

var _ httpapi.DeviceHandlers = (*Handlers)(nil)

// New returns the handlers of the device operations.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

// errNoDecision: the handler runs without the authorization hook — fail closed (§8.4 invariant 4).
var errNoDecision = errors.New("devicesapi: no authorization decision in the request context (Hooks.Authz missing)")

// access is the caller's access to the inventory, from the authorization decision of the request.
func access(ctx context.Context) (devices.Access, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	if !ok {
		return devices.Access{}, problem.Internal(errNoDecision)
	}
	return devices.Access{OwnOnly: d.OwnOnly, MembershipID: d.MembershipID, IdentityID: d.Principal.IdentityID}, nil
}

// ListDevices implements GET /tenants/{tenantId}/devices.
func (h *Handlers) ListDevices(ctx context.Context, req gen.ListDevicesRequestObject) (gen.ListDevicesResponseObject, error) {
	a, err := access(ctx)
	if err != nil {
		return nil, err
	}
	p := req.Params
	q := devices.ListQuery{Online: p.Online, Owner: p.Owner}
	if p.Limit != nil {
		q.Limit = *p.Limit
		if q.Limit == 0 { // 0 is not "the default": the spec's minimum is 1
			q.Limit = -1
		}
	}
	if p.Cursor != nil {
		q.Cursor = *p.Cursor
	}
	if p.Tag != nil {
		q.Tag = *p.Tag
	}
	if p.Q != nil {
		q.Search = *p.Q
		if q.Search == "" {
			return nil, problem.Validation("The query parameters are invalid.", problem.Field("q", "invalid", "must not be empty"))
		}
	}
	if p.Fresh != nil {
		q.Fresh = *p.Fresh
	}
	page, err := h.svc.List(ctx, req.TenantId, a, q)
	if err != nil {
		return nil, problemOf(err)
	}
	out := gen.DeviceList{Items: make([]gen.Device, 0, len(page.Items))}
	for _, d := range page.Items {
		out.Items = append(out.Items, device(d))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListDevices200JSONResponse(out), nil
}

// GetDevice implements GET /tenants/{tenantId}/devices/{deviceId}.
func (h *Handlers) GetDevice(ctx context.Context, req gen.GetDeviceRequestObject) (gen.GetDeviceResponseObject, error) {
	a, err := access(ctx)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.Get(ctx, req.TenantId, req.DeviceId, a)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.GetDevice200JSONResponse(device(d)), nil
}

// RenameDevice implements PATCH /tenants/{tenantId}/devices/{deviceId}.
func (h *Handlers) RenameDevice(ctx context.Context, req gen.RenameDeviceRequestObject) (gen.RenameDeviceResponseObject, error) {
	a, err := access(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	d, err := h.svc.Rename(ctx, req.TenantId, req.DeviceId, a, req.Body.GivenName)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.RenameDevice200JSONResponse(device(d)), nil
}

// ExpireDevice implements POST /tenants/{tenantId}/devices/{deviceId}/expire (202, two-phase revocation).
func (h *Handlers) ExpireDevice(ctx context.Context, req gen.ExpireDeviceRequestObject) (gen.ExpireDeviceResponseObject, error) {
	a, err := access(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.Revoke(ctx, req.TenantId, req.DeviceId, a, devices.RevokeExpire, req.Params.IdempotencyKey)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.ExpireDevice202JSONResponse{Body: device(res.Device),
		Headers: gen.ExpireDevice202ResponseHeaders{Location: jobLocation(req.TenantId, res.JobID)}}, nil
}

// DeleteDevice implements DELETE /tenants/{tenantId}/devices/{deviceId} (202, two-phase revocation).
func (h *Handlers) DeleteDevice(ctx context.Context, req gen.DeleteDeviceRequestObject) (gen.DeleteDeviceResponseObject, error) {
	a, err := access(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.Revoke(ctx, req.TenantId, req.DeviceId, a, devices.RevokeDelete, "")
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.DeleteDevice202JSONResponse{Body: device(res.Device),
		Headers: gen.DeleteDevice202ResponseHeaders{Location: jobLocation(req.TenantId, res.JobID)}}, nil
}

// SyncDevices implements POST /tenants/{tenantId}/devices/sync (202 + the inventory.sync job).
func (h *Handlers) SyncDevices(ctx context.Context, req gen.SyncDevicesRequestObject) (gen.SyncDevicesResponseObject, error) {
	a, err := access(ctx)
	if err != nil {
		return nil, err
	}
	j, err := h.svc.RequestSync(ctx, req.TenantId, a, req.Params.IdempotencyKey)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.SyncDevices202JSONResponse{Body: job(j),
		Headers: gen.SyncDevices202ResponseHeaders{Location: jobLocation(req.TenantId, j.ID)}}, nil
}

// jobLocation is the Location of a job for a caller of tenant scope (§13.1 "Thao tác dài").
func jobLocation(tenantID, jobID uuid.UUID) string {
	return httpapi.BaseURL + "/tenants/" + tenantID.String() + "/jobs/" + jobID.String()
}

// problemOf maps a service error to the problem of §13.1. A device the own-only caller may not see carries the
// authorization reason, so the audit middleware records the denial with it (never sent to the client).
func problemOf(err error) error {
	e, ok := devices.AsError(err)
	if !ok {
		return problem.Internal(err)
	}
	code := gen.ProblemCode(e.Code)
	if !code.Valid() || code == gen.ProblemCodeInternalError {
		return problem.Internal(err)
	}
	p := &problem.Error{Code: code, Detail: e.Detail, Cause: err}
	switch {
	case e.Reason == devices.ReasonNotOwnResource:
		p.Cause = &authz.Denial{Kind: authz.ErrNotFound, Reason: devices.ReasonNotOwnResource}
	case code == gen.ProblemCodeValidationFailed && e.Field != "":
		p.Fields = []gen.FieldError{problem.Field(e.Field, "invalid", e.Detail)}
	case code == gen.ProblemCodeInstanceUnavailable:
		p.RetryAfter = 30 * time.Second
	}
	if p.Detail == "" {
		p.Detail = "The request could not be completed."
	}
	return p
}

// device maps a device to the schema Device (§13.3).
func device(d devices.Device) gen.Device {
	out := gen.Device{
		Id: d.ID, Name: d.Name, GivenName: d.GivenName, IpAddresses: make([]string, 0, len(d.IPAddresses)), Tags: d.Tags,
		RegisterMethod: d.RegisterMethod, Online: d.Online, LastSeen: d.LastSeen, Expiry: d.Expiry,
		Routes:   gen.DeviceRoutes{Advertised: prefixes(d.AdvertisedRoutes), Approved: prefixes(d.ApprovedRoutes), Etag: d.RoutesETag},
		TagsEtag: d.TagsETag, SyncedAt: d.SyncedAt,
		Revocation: gen.DeviceRevocation{State: gen.DeviceRevocationState(d.Revocation.State),
			RequestedAt: d.Revocation.RequestedAt, VerifiedAt: d.Revocation.VerifiedAt},
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	for _, a := range d.IPAddresses {
		out.IpAddresses = append(out.IpAddresses, a.String())
	}
	if d.Revocation.Kind != "" {
		k := gen.DeviceRevocationKind(d.Revocation.Kind)
		out.Revocation.Kind = &k
	}
	if d.Owner != nil {
		out.Owner = &gen.DeviceOwner{MembershipId: d.Owner.MembershipID, DisplayName: d.Owner.DisplayName}
	}
	return out
}

func prefixes[T interface{ String() string }](in []T) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

// job maps the safe projection of a job to the schema Job (§13.3).
func job(j jobs.Job) gen.Job {
	out := gen.Job{Id: j.ID, Kind: j.Kind, TenantId: j.TenantID, Status: gen.JobStatus(j.Status), CurrentStep: j.CurrentStep,
		Steps: make([]gen.JobStep, 0, len(j.Steps)), CreatedAt: j.CreatedAt}
	if j.Resource != nil {
		out.Resource = &gen.ResourceRef{Type: j.Resource.Type, Id: j.Resource.ID}
	}
	if j.Error != nil {
		out.Error = &gen.JobError{Code: j.Error.Code}
	}
	for _, s := range j.Steps {
		out.Steps = append(out.Steps, gen.JobStep{Name: s.Name, Status: gen.JobStepStatus(s.Status), Attempt: s.Attempt,
			StartedAt: s.StartedAt, FinishedAt: s.FinishedAt, Message: s.Message})
	}
	return out
}
