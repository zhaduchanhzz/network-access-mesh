// Package networkapi serves the network operations of api/openapi.yaml built by P4-T12 (httpapi.NetworkHandlers):
// routes (listTenantRoutes — tenant.route:read; approveTenantRoutes, revokeTenantRoutes — tenant.route:approve), DNS
// (getTenantDns, listTenantDnsRecords — tenant.dns:read; updateTenantDnsSettings, createTenantDnsRecord,
// deleteTenantDnsRecord — tenant.dns:update) and the Network Resource Catalog (listTenantResources, getTenantResource
// — tenant.resource:read; create/update/deleteTenantResource — tenant.resource:manage) — §8.6. It only translates
// between the generated types and internal/network, which takes every decision; a route approval under
// routes.four_eyes becomes a tenant approval request (internal/authz/approvals — the single mechanism).
//
// Wiring (apps/internal/runner — api process):
//
//	net, _ := network.New(apiStore, network.Config{Registry: reg, Devices: devices.RouteRegister{}, Tags: policies.RequireTags, …})
//	httpapi.Handlers{…, Network: networkapi.New(net, approvalsSvc)}
package networkapi

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/network"
)

// Service is the part of *network.Service the handlers use.
type Service interface {
	ListRoutes(ctx context.Context, tenantID uuid.UUID) ([]network.RouteDevice, error)
	ApproveRoutes(ctx context.Context, tenantID uuid.UUID, a network.Actor, ifMatch string, in network.RouteChangeInput, idem *network.Idempotency) (network.RouteResult, error)
	RevokeRoutes(ctx context.Context, tenantID uuid.UUID, a network.Actor, ifMatch string, in network.RouteChangeInput) (network.RouteDevice, error)
	GetDNS(ctx context.Context, tenantID uuid.UUID) (network.DNSView, error)
	UpdateDNSSettings(ctx context.Context, tenantID uuid.UUID, a network.Actor, ifMatch string, nameservers []string) (jobs.Job, bool, error)
	ListDNSRecords(ctx context.Context, tenantID uuid.UUID) ([]network.DNSRecord, error)
	CreateDNSRecord(ctx context.Context, tenantID uuid.UUID, a network.Actor, in network.DNSRecordInput, idem *network.Idempotency) (network.DNSRecordChange, error)
	DeleteDNSRecord(ctx context.Context, tenantID, id uuid.UUID, a network.Actor, ifMatch string) (network.DNSRecordChange, error)
	ListResources(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) (network.ResourcePage, error)
	GetResource(ctx context.Context, tenantID, id uuid.UUID) (network.Resource, error)
	CreateResource(ctx context.Context, tenantID uuid.UUID, a network.Actor, in network.ResourceInput, idem *network.Idempotency) (network.ResourceChange, error)
	UpdateResource(ctx context.Context, tenantID, id uuid.UUID, a network.Actor, ifMatch string, p network.ResourcePatch) (network.ResourceChange, error)
	DeleteResource(ctx context.Context, tenantID, id uuid.UUID, a network.Actor, ifMatch string) (network.ResourceChange, error)
}

// Approvals creates the tenant approval request of a route approval under routes.four_eyes.
type Approvals interface {
	RequestIdempotent(ctx context.Context, actor approvals.Actor, in approvals.NewRequest, idem approvals.Idempotency) (approvals.Request, error)
}

var (
	_ Service   = (*network.Service)(nil)
	_ Approvals = (*approvals.Service)(nil)
)

// Handlers implements httpapi.NetworkHandlers.
type Handlers struct {
	svc   Service
	appr  Approvals
	actor func(ctx context.Context) (caller, error) // callerOf (a test replaces it)
}

var _ httpapi.NetworkHandlers = (*Handlers)(nil)

// New returns the handler set of P4-T12.
func New(svc Service, appr Approvals) *Handlers {
	return &Handlers{svc: svc, appr: appr, actor: callerOf}
}

// caller is the identity of a write and the auth time of its session (the step-up of an approval request).
type caller struct {
	identityID uuid.UUID
	authTime   time.Time
}

func (c caller) actor() network.Actor { return network.Actor{IdentityID: c.identityID} }

var errNoSession = errors.New("networkapi: no session or decision in the request context (hooks missing)")

func callerOf(ctx context.Context) (caller, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s == nil || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return caller{}, problem.Internal(errNoSession)
	}
	return caller{identityID: s.IdentityID, authTime: s.AuthTime}, nil
}

// problemOf maps a service error to the problem of §13.1.
func problemOf(err error) error {
	e, ok := network.AsError(err)
	if !ok {
		return problem.Internal(err)
	}
	code := gen.ProblemCode(e.Code)
	if !code.Valid() || code == gen.ProblemCodeInternalError {
		return problem.Internal(err)
	}
	p := &problem.Error{Code: code, Detail: e.Detail, Cause: err, RetryAfter: e.RetryAfter}
	switch {
	case code == gen.ProblemCodeNotFound:
		p.Cause = &authz.Denial{Kind: authz.ErrNotFound, Reason: e.Reason}
	case code == gen.ProblemCodeValidationFailed && e.Field != "":
		p.Fields = []gen.FieldError{problem.Field(e.Field, e.Reason, e.Detail)}
	case code == gen.ProblemCodeInstanceUnavailable && p.RetryAfter == 0:
		p.RetryAfter = 30 * time.Second
	}
	if p.Detail == "" {
		p.Detail = "The request could not be completed."
	}
	return p
}

func ifMatch(p *gen.IfMatch) string {
	if p == nil {
		return ""
	}
	return *p
}

func noBody() error {
	return problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
}

// idempotency is the Idempotency-Key of a request and the hash of its method, path (with the tenant) and body.
func idempotency(key, method, path string, body any) (*network.Idempotency, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	return &network.Idempotency{Key: key, Hash: jobs.RequestHash(method, path, b)}, nil
}

func jobLocation(tenantID, jobID uuid.UUID) string {
	return httpapi.BaseURL + "/tenants/" + tenantID.String() + "/jobs/" + jobID.String()
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

// ---------------------------------------------------------------------------------------------------- routes

func routeDevice(d network.RouteDevice) gen.RouteDevice {
	out := gen.RouteDevice{DeviceId: d.DeviceID, Name: d.Name, GivenName: d.GivenName, Tags: d.Tags, Online: d.Online,
		AdvertisedRoutes: strs(d.Advertised), ApprovedRoutes: strs(d.Approved), PendingRoutes: strs(d.Pending),
		RoutesEtag: d.ETag, SyncedAt: d.SyncedAt, Warnings: make([]gen.RouteWarning, 0, len(d.Warnings))}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	out.ExitNode.Advertised, out.ExitNode.Approved = d.ExitAdvertised, d.ExitApproved
	for _, w := range d.Warnings {
		gw := gen.RouteWarning{Code: gen.RouteWarningCode(w.Code), OtherDeviceId: w.OtherDeviceID}
		if w.Prefix != "" {
			p := w.Prefix
			gw.Prefix = &p
		}
		if w.OtherPrefix != "" {
			p := w.OtherPrefix
			gw.OtherPrefix = &p
		}
		out.Warnings = append(out.Warnings, gw)
	}
	return out
}

func strs[T interface{ String() string }](in []T) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, v.String())
	}
	return out
}

func routeInput(b *gen.RouteChange) network.RouteChangeInput {
	in := network.RouteChangeInput{DeviceID: b.DeviceId, Prefixes: b.Prefixes}
	if b.ConfirmExitNode != nil {
		in.ConfirmExitNode = *b.ConfirmExitNode
	}
	return in
}

// ListTenantRoutes implements GET /tenants/{tenantId}/routes.
func (h *Handlers) ListTenantRoutes(ctx context.Context, req gen.ListTenantRoutesRequestObject) (gen.ListTenantRoutesResponseObject, error) {
	ds, err := h.svc.ListRoutes(ctx, req.TenantId)
	if err != nil {
		return nil, problemOf(err)
	}
	out := gen.RouteList{Items: make([]gen.RouteDevice, 0, len(ds))}
	for _, d := range ds {
		out.Items = append(out.Items, routeDevice(d))
	}
	return gen.ListTenantRoutes200JSONResponse(out), nil
}

// ApproveTenantRoutes implements POST /tenants/{tenantId}/routes/approve (200, or 202 + a tenant approval request).
func (h *Handlers) ApproveTenantRoutes(ctx context.Context, req gen.ApproveTenantRoutesRequestObject) (gen.ApproveTenantRoutesResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	path := "/tenants/" + req.TenantId.String() + "/routes/approve"
	idem, err := idempotency(req.Params.IdempotencyKey, "POST", path, req.Body)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.ApproveRoutes(ctx, req.TenantId, c.actor(), ifMatch(req.Params.IfMatch), routeInput(req.Body), idem)
	if err != nil {
		return nil, problemOf(err)
	}
	if res.Approval == nil {
		d := routeDevice(*res.Device)
		return gen.ApproveTenantRoutes200JSONResponse{Body: d, Headers: gen.ApproveTenantRoutes200ResponseHeaders{ETag: d.RoutesEtag}}, nil
	}
	if h.appr == nil {
		return nil, problem.Internal(errors.New("networkapi: no approvals service wired"))
	}
	r, err := h.appr.RequestIdempotent(ctx, approvals.Actor{IdentityID: c.identityID, Scope: authz.ScopeTenant, AuthTime: c.authTime},
		approvals.NewRequest{Action: network.RouteApprovalAction, TenantID: req.TenantId, ResourceID: res.Approval.DeviceID.String(),
			Payload: res.Approval, Reason: "POST " + path},
		approvals.Idempotency{Operation: "approveTenantRoutes", Key: idem.Key, Hash: idem.Hash})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.ApproveTenantRoutes202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.ApproveTenantRoutes202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

// RevokeTenantRoutes implements POST /tenants/{tenantId}/routes/revoke.
func (h *Handlers) RevokeTenantRoutes(ctx context.Context, req gen.RevokeTenantRoutesRequestObject) (gen.RevokeTenantRoutesResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	d, err := h.svc.RevokeRoutes(ctx, req.TenantId, c.actor(), ifMatch(req.Params.IfMatch), routeInput(req.Body))
	if err != nil {
		return nil, problemOf(err)
	}
	v := routeDevice(d)
	return gen.RevokeTenantRoutes200JSONResponse{Body: v, Headers: gen.RevokeTenantRoutes200ResponseHeaders{ETag: v.RoutesEtag}}, nil
}

// ---------------------------------------------------------------------------------------------------- dns

func dnsView(v network.DNSView) gen.DnsView {
	out := gen.DnsView{MagicDns: v.MagicDNS, BaseDomain: v.BaseDomain, Nameservers: v.Nameservers, Etag: v.ETag, Records: v.Records}
	if out.Nameservers == nil {
		out.Nameservers = []string{}
	}
	if v.ConfigVersion != nil {
		n := int(*v.ConfigVersion)
		out.ConfigVersion = &n
	}
	if v.Pending != nil {
		p := &gen.DnsPending{JobId: v.Pending.JobID, Status: gen.JobStatus(v.Pending.Status)}
		if v.Pending.Nameservers != nil {
			ns := v.Pending.Nameservers
			p.Nameservers = &ns
		}
		out.Pending = p
	}
	return out
}

func dnsRecord(r network.DNSRecord) gen.DnsRecord {
	return gen.DnsRecord{Id: r.ID, Name: r.Name, Type: gen.DnsRecordType(r.Type), Value: r.Value.String(), CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, Etag: r.ETag()}
}

// GetTenantDns implements GET /tenants/{tenantId}/dns.
func (h *Handlers) GetTenantDns(ctx context.Context, req gen.GetTenantDnsRequestObject) (gen.GetTenantDnsResponseObject, error) {
	v, err := h.svc.GetDNS(ctx, req.TenantId)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.GetTenantDns200JSONResponse{Body: dnsView(v), Headers: gen.GetTenantDns200ResponseHeaders{ETag: v.ETag}}, nil
}

// UpdateTenantDnsSettings implements PUT /tenants/{tenantId}/dns/settings (202 + instance.reconfigure).
func (h *Handlers) UpdateTenantDnsSettings(ctx context.Context, req gen.UpdateTenantDnsSettingsRequestObject) (gen.UpdateTenantDnsSettingsResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	j, _, err := h.svc.UpdateDNSSettings(ctx, req.TenantId, c.actor(), ifMatch(req.Params.IfMatch), req.Body.Nameservers)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.UpdateTenantDnsSettings202JSONResponse{Body: job(j),
		Headers: gen.UpdateTenantDnsSettings202ResponseHeaders{Location: jobLocation(req.TenantId, j.ID)}}, nil
}

// ListTenantDnsRecords implements GET /tenants/{tenantId}/dns/records.
func (h *Handlers) ListTenantDnsRecords(ctx context.Context, req gen.ListTenantDnsRecordsRequestObject) (gen.ListTenantDnsRecordsResponseObject, error) {
	rs, err := h.svc.ListDNSRecords(ctx, req.TenantId)
	if err != nil {
		return nil, problemOf(err)
	}
	out := gen.DnsRecordList{Items: make([]gen.DnsRecord, 0, len(rs))}
	for _, r := range rs {
		out.Items = append(out.Items, dnsRecord(r))
	}
	return gen.ListTenantDnsRecords200JSONResponse(out), nil
}

// CreateTenantDnsRecord implements POST /tenants/{tenantId}/dns/records.
func (h *Handlers) CreateTenantDnsRecord(ctx context.Context, req gen.CreateTenantDnsRecordRequestObject) (gen.CreateTenantDnsRecordResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	idem, err := idempotency(req.Params.IdempotencyKey, "POST", "/tenants/"+req.TenantId.String()+"/dns/records", req.Body)
	if err != nil {
		return nil, err
	}
	ch, err := h.svc.CreateDNSRecord(ctx, req.TenantId, c.actor(), network.DNSRecordInput{Name: req.Body.Name,
		Type: string(req.Body.Type), Value: req.Body.Value}, idem)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.CreateTenantDnsRecord201JSONResponse(gen.DnsRecordChange{Record: dnsRecord(ch.Record), Job: job(ch.Job)}), nil
}

// DeleteTenantDnsRecord implements DELETE /tenants/{tenantId}/dns/records/{recordId} (202 + the records job).
func (h *Handlers) DeleteTenantDnsRecord(ctx context.Context, req gen.DeleteTenantDnsRecordRequestObject) (gen.DeleteTenantDnsRecordResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	ch, err := h.svc.DeleteDNSRecord(ctx, req.TenantId, req.RecordId, c.actor(), ifMatch(req.Params.IfMatch))
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.DeleteTenantDnsRecord202JSONResponse{Body: job(ch.Job),
		Headers: gen.DeleteTenantDnsRecord202ResponseHeaders{Location: jobLocation(req.TenantId, ch.Job.ID)}}, nil
}

// ---------------------------------------------------------------------------------------------------- resources

func resource(r network.Resource) gen.NetworkResource {
	out := gen.NetworkResource{Id: r.ID, Name: r.Name, Kind: gen.NetworkResourceKind(r.Kind), Address: r.AddressString(),
		Ports: r.Ports, Protocol: gen.NetworkResourceProtocol(r.Protocol), Tags: r.Tags, OwnerGroupId: r.OwnerGroupID,
		Version: r.Version, Etag: r.ETag(), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if r.Description != "" {
		d := r.Description
		out.Description = &d
	}
	return out
}

// ListTenantResources implements GET /tenants/{tenantId}/resources.
func (h *Handlers) ListTenantResources(ctx context.Context, req gen.ListTenantResourcesRequestObject) (gen.ListTenantResourcesResponseObject, error) {
	limit, cursor := 0, ""
	if p := req.Params.Limit; p != nil {
		limit = *p
		if limit == 0 {
			limit = -1 // 0 is not "the default": the spec's minimum is 1
		}
	}
	if p := req.Params.Cursor; p != nil {
		cursor = *p
	}
	page, err := h.svc.ListResources(ctx, req.TenantId, limit, cursor)
	if err != nil {
		return nil, problemOf(err)
	}
	out := gen.NetworkResourceList{Items: make([]gen.NetworkResource, 0, len(page.Items))}
	for _, r := range page.Items {
		out.Items = append(out.Items, resource(r))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListTenantResources200JSONResponse(out), nil
}

// GetTenantResource implements GET /tenants/{tenantId}/resources/{resourceId}.
func (h *Handlers) GetTenantResource(ctx context.Context, req gen.GetTenantResourceRequestObject) (gen.GetTenantResourceResponseObject, error) {
	r, err := h.svc.GetResource(ctx, req.TenantId, req.ResourceId)
	if err != nil {
		return nil, problemOf(err)
	}
	return gen.GetTenantResource200JSONResponse{Body: resource(r), Headers: gen.GetTenantResource200ResponseHeaders{ETag: r.ETag()}}, nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// CreateTenantResource implements POST /tenants/{tenantId}/resources.
func (h *Handlers) CreateTenantResource(ctx context.Context, req gen.CreateTenantResourceRequestObject) (gen.CreateTenantResourceResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, noBody()
	}
	idem, err := idempotency(req.Params.IdempotencyKey, "POST", "/tenants/"+req.TenantId.String()+"/resources", b)
	if err != nil {
		return nil, err
	}
	in := network.ResourceInput{Name: b.Name, Kind: string(b.Kind), Address: b.Address, Ports: deref(b.Ports),
		Protocol: string(deref(b.Protocol)), Tags: deref(b.Tags), OwnerGroupID: b.OwnerGroupId, Description: deref(b.Description)}
	ch, err := h.svc.CreateResource(ctx, req.TenantId, c.actor(), in, idem)
	if err != nil {
		return nil, problemOf(err)
	}
	r := resource(ch.Resource)
	return gen.CreateTenantResource201JSONResponse{Body: r, Headers: gen.CreateTenantResource201ResponseHeaders{ETag: r.Etag}}, nil
}

// UpdateTenantResource implements PATCH /tenants/{tenantId}/resources/{resourceId}.
func (h *Handlers) UpdateTenantResource(ctx context.Context, req gen.UpdateTenantResourceRequestObject) (gen.UpdateTenantResourceResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, noBody()
	}
	p := network.ResourcePatch{Name: b.Name, Address: b.Address, Ports: b.Ports, Tags: b.Tags, OwnerGroupID: b.OwnerGroupId,
		Description: b.Description}
	if b.Kind != nil {
		k := string(*b.Kind)
		p.Kind = &k
	}
	if b.Protocol != nil {
		pr := string(*b.Protocol)
		p.Protocol = &pr
	}
	ch, err := h.svc.UpdateResource(ctx, req.TenantId, req.ResourceId, c.actor(), ifMatch(req.Params.IfMatch), p)
	if err != nil {
		return nil, problemOf(err)
	}
	r := resource(ch.Resource)
	return gen.UpdateTenantResource200JSONResponse{Body: r, Headers: gen.UpdateTenantResource200ResponseHeaders{ETag: r.Etag}}, nil
}

// DeleteTenantResource implements DELETE /tenants/{tenantId}/resources/{resourceId}.
func (h *Handlers) DeleteTenantResource(ctx context.Context, req gen.DeleteTenantResourceRequestObject) (gen.DeleteTenantResourceResponseObject, error) {
	c, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.svc.DeleteResource(ctx, req.TenantId, req.ResourceId, c.actor(), ifMatch(req.Params.IfMatch)); err != nil {
		return nil, problemOf(err)
	}
	return gen.DeleteTenantResource204Response{}, nil
}
