// Package hostsapi serves the host operations of api/openapi.yaml built by P3-T04 (httpapi.HostHandlers):
// listPlatformHosts, getPlatformHost (platform.host:read — SA, PO, PS, PV) and createPlatformHost, updatePlatformHost
// (platform.host:manage — SA, PO; §8.5). It only translates between the generated types and internal/platform, which
// takes every decision (validation mirroring the CHECKs of 0014, the 409 rules under the host row lock, the ETag,
// Idempotency-Key, audit platform.host.create / platform.host.update).
//
// Authorization (layer 1, internal/httpapi/authzhook) decided the route before a handler runs: tenant identities are
// refused on every /platform route (403), platform roles without platform.host:manage on the writes (403). A write
// needs the decision in the context — the identity of the Idempotency-Key — and answers 500 without it (fail closed).
// Step-up is not required by §8.5 for these operations.
//
// Wiring (apps/internal/runner — api process):
//
//	hostsapi.New(platform.New(apiStore))
//
// mounted as httpapi.Handlers{Hosts: …} behind authzhook.Hooks and auditapi.Middleware.
package hostsapi

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
)

// Service is the part of *platform.Service the handlers use.
type Service interface {
	ListHosts(ctx context.Context, f platform.HostFilter) (platform.HostPage, error)
	GetHost(ctx context.Context, id uuid.UUID) (platform.HostView, error)
	CreateHost(ctx context.Context, in platform.HostConfig, w platform.HostWrite) (platform.HostView, error)
	UpdateHost(ctx context.Context, id uuid.UUID, p platform.HostPatch, w platform.HostWrite) (platform.HostView, error)
}

var _ Service = (*platform.Service)(nil)

// Handlers implements httpapi.HostHandlers.
type Handlers struct {
	svc Service
}

var _ httpapi.HostHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T04.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

// errNoDecision: a write runs without the authorization hook — fail closed (§8.4 invariant 4).
var errNoDecision = errors.New("hostsapi: no authorization decision in the request context (Hooks.Authz missing)")

// failure maps an error of the service to the problem of §13.1: 404, 422 with the field errors, 409 (conflict; a
// request in flight with the same Idempotency-Key also carries Retry-After), 412, 428, 422 idempotency_key_reuse,
// anything else 500 (the cause goes to the internal log only).
func failure(err error) error {
	var (
		inv  *platform.ValidationError
		conf *platform.HostConflictError
		busy *platform.IdempotencyBusyError
	)
	switch {
	case errors.Is(err, platform.ErrNotFound):
		return problem.New(gen.ProblemCodeNotFound, "The resource does not exist.")
	case errors.As(err, &inv):
		fields := make([]gen.FieldError, 0, len(inv.Fields))
		for _, f := range inv.Fields {
			fields = append(fields, problem.Field(f.Field, f.Code, f.Message))
		}
		return &problem.Error{Code: gen.ProblemCodeValidationFailed, Detail: "The host is invalid.", Fields: fields, Cause: err}
	case errors.Is(err, platform.ErrInvalid):
		return &problem.Error{Code: gen.ProblemCodeValidationFailed, Detail: "The request parameters are invalid.",
			Fields: []gen.FieldError{problem.Field("query", "invalid", "a filter, the limit or the cursor is out of range")},
			Cause:  err}
	case errors.As(err, &conf):
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: conflictDetail(conf), Cause: err}
	case errors.As(err, &busy):
		return &problem.Error{Code: gen.ProblemCodeConflict, RetryAfter: busy.RetryAfter, Cause: err,
			Detail: "A request with this Idempotency-Key is still in progress."}
	case errors.Is(err, platform.ErrIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: err,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, platform.ErrPreconditionRequired):
		return &problem.Error{Code: gen.ProblemCodePreconditionRequired, Cause: err,
			Detail: "If-Match with the current ETag of the host is required."}
	case errors.Is(err, platform.ErrPreconditionFailed):
		return &problem.Error{Code: gen.ProblemCodePreconditionFailed, Cause: err,
			Detail: "The host changed since it was read; read it again."}
	}
	return problem.Internal(err)
}

// conflictDetail is the client text of a refused write: what the rule is, never a submitted value.
func conflictDetail(c *platform.HostConflictError) string {
	switch c.Reason {
	case platform.ConflictNameTaken:
		return "A host with this name is already registered."
	case platform.ConflictCapacityBelowLive:
		return "capacity.max_instances is below the number of instances of the host that are not removed."
	}
	return "region and the allocation ranges cannot change while the host has instances that are not removed."
}

func limitOf(p *gen.Limit) int {
	if p == nil {
		return 0
	}
	if *p == 0 {
		return -1 // an explicit 0 is out of range, not "default"
	}
	return *p
}

// ListPlatformHosts implements GET /platform/hosts.
func (h *Handlers) ListPlatformHosts(ctx context.Context, req gen.ListPlatformHostsRequestObject) (gen.ListPlatformHostsResponseObject, error) {
	f := platform.HostFilter{Limit: limitOf(req.Params.Limit)}
	if req.Params.Cursor != nil {
		f.Cursor = *req.Params.Cursor
	}
	if req.Params.Status != nil {
		f.Status = string(*req.Params.Status)
	}
	if req.Params.Region != nil {
		f.Region = *req.Params.Region
		if f.Region == "" {
			return nil, failure(platform.ErrInvalid)
		}
	}
	p, err := h.svc.ListHosts(ctx, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListPlatformHosts200JSONResponse{Items: make([]gen.Host, 0, len(p.Items))}
	for _, v := range p.Items {
		out.Items = append(out.Items, toHost(v))
	}
	if p.NextCursor != "" {
		c := p.NextCursor
		out.NextCursor = &c
	}
	return out, nil
}

// GetPlatformHost implements GET /platform/hosts/{hostId}.
func (h *Handlers) GetPlatformHost(ctx context.Context, req gen.GetPlatformHostRequestObject) (gen.GetPlatformHostResponseObject, error) {
	v, err := h.svc.GetHost(ctx, req.HostId)
	if err != nil {
		return nil, failure(err)
	}
	if v.ID != req.HostId {
		return nil, failure(platform.ErrNotFound)
	}
	return gen.GetPlatformHost200JSONResponse{Body: toHost(v), Headers: gen.GetPlatformHost200ResponseHeaders{ETag: v.ETag}}, nil
}

// CreatePlatformHost implements POST /platform/hosts (Idempotency-Key: the hash covers the method, the path and the
// canonical body — §13.1).
func (h *Handlers) CreatePlatformHost(ctx context.Context, req gen.CreatePlatformHostRequestObject) (gen.CreatePlatformHostResponseObject, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	if !ok || d.Principal.IdentityID == uuid.Nil {
		return nil, problem.Internal(errNoDecision)
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	b := req.Body
	maxInstances, entry, fe := jsonFields(b.Capacity, b.PublicEntry)
	in := platform.HostConfig{Name: b.Name, Region: b.Region, MaxInstances: maxInstances,
		RunUIDRange: intRange(b.RunUidRange), TenantNetPool: b.TenantNetPool}
	if entry != nil {
		in.PublicEntry = *entry
	}
	if b.Status != nil {
		in.Status = string(*b.Status)
	}
	if b.StunPortRange != nil {
		r := intRange(*b.StunPortRange)
		in.STUNPortRange = &r
	}
	if len(fe) > 0 { // every invalid field at once: the rest of the body as the service checks it
		parsed := slices.Clone(fe)
		for _, f := range in.Check() {
			if !slices.ContainsFunc(parsed, func(p platform.FieldError) bool { return group(p.Field) == group(f.Field) }) {
				fe = append(fe, f)
			}
		}
		return nil, failure(&platform.ValidationError{Fields: fe})
	}
	v, err := h.svc.CreateHost(ctx, in, platform.HostWrite{Idempotency: &platform.Idempotency{
		IdentityID: d.Principal.IdentityID, Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/platform/hosts", raw)}})
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreatePlatformHost201JSONResponse{Body: toHost(v), Headers: gen.CreatePlatformHost201ResponseHeaders{ETag: v.ETag}}, nil
}

// UpdatePlatformHost implements PATCH /platform/hosts/{hostId} (If-Match required: 428 without it, 412 when stale).
func (h *Handlers) UpdatePlatformHost(ctx context.Context, req gen.UpdatePlatformHostRequestObject) (gen.UpdatePlatformHostResponseObject, error) {
	if _, ok := authzhook.DecisionFrom(ctx); !ok {
		return nil, problem.Internal(errNoDecision)
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	b := req.Body
	maxInstances, entry, fe := jsonFields(b.Capacity, b.PublicEntry)
	if len(fe) > 0 {
		return nil, failure(&platform.ValidationError{Fields: fe})
	}
	p := platform.HostPatch{Region: b.Region, TenantNetPool: b.TenantNetPool, MaxInstances: maxInstances, PublicEntry: entry}
	if b.Status != nil {
		s := string(*b.Status)
		p.Status = &s
	}
	if b.RunUidRange != nil {
		r := intRange(*b.RunUidRange)
		p.RunUIDRange = &r
	}
	if b.StunPortRange != nil {
		r := intRange(*b.StunPortRange)
		p.STUNPortRange = &r
	}
	w := platform.HostWrite{}
	if req.Params.IfMatch != nil {
		w.IfMatch = *req.Params.IfMatch
	}
	v, err := h.svc.UpdateHost(ctx, req.HostId, p, w)
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdatePlatformHost200JSONResponse{Body: toHost(v), Headers: gen.UpdatePlatformHost200ResponseHeaders{ETag: v.ETag}}, nil
}

func intRange(r gen.HostRange) platform.IntRange {
	return platform.IntRange{First: r.First, Last: r.Last}
}

// group is the top-level field of a field path ("public_entry.ipv4" → "public_entry").
func group(field string) string {
	g, _, _ := strings.Cut(field, ".")
	return g
}

// jsonFields reads the two jsonb objects of a host body (kept raw by the generated types — x-go-type) the way the
// CHECKs of 0014 read the columns: platform.ParseCapacity, platform.ParsePublicEntry. nil = absent.
func jsonFields(capacity, entry *json.RawMessage) (*int64, *platform.PublicEntry, []platform.FieldError) {
	var (
		maxInstances *int64
		pe           *platform.PublicEntry
		fe           []platform.FieldError
	)
	if capacity != nil {
		n, errs := platform.ParseCapacity(*capacity)
		fe = append(fe, errs...)
		maxInstances = &n
	}
	if entry != nil {
		e, errs := platform.ParsePublicEntry(*entry)
		fe = append(fe, errs...)
		pe = &e
	}
	return maxInstances, pe, fe
}

// toHost maps the platform view to schema Host.
func toHost(v platform.HostView) gen.Host {
	out := gen.Host{
		Id: v.ID, Name: v.Name, Region: v.Region, Status: gen.HostStatus(v.Status),
		Capacity:      gen.HostCapacity{MaxInstances: int64(v.MaxInstances)},
		RunUidRange:   gen.HostRange{First: int64(v.RunUIDFirst), Last: int64(v.RunUIDLast)},
		TenantNetPool: v.TenantNetPool.String(), LastHeartbeatAt: v.LastHeartbeatAt, CreatedAt: v.CreatedAt.UTC(),
		UpdatedAt: v.UpdatedAt.UTC(), Etag: v.ETag,
		Usage: gen.HostUsage{LiveInstances: v.Usage.LiveInstances, ByStatus: gen.StatusCounts{},
			RunUidsFree: v.Usage.RunUIDsFree, NetSlotsFree: v.Usage.NetSlotsFree,
			StunPortsFree: v.Usage.STUNPortsFree},
	}
	for s, n := range v.Usage.ByStatus {
		out.Usage.ByStatus[s] = n
	}
	if v.PublicEntry.IsValid() {
		out.PublicEntry.Ipv4 = ptr(v.PublicEntry.String())
	}
	if v.EntryMode != "" {
		out.PublicEntry.Mode = ptr(gen.HostEntryMode(v.EntryMode))
	}
	if v.STUNPortFirst != 0 {
		out.StunPortRange = &gen.HostRange{First: int64(v.STUNPortFirst), Last: int64(v.STUNPortLast)}
	}
	return out
}

func ptr[T any](v T) *T { return &v }
