package audit

import (
	"context"
	"net/netip"
	"sync"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// Request is the audit scope of one API request. The HTTP audit middleware (internal/httpapi/auditapi) builds it before
// authorization — who acts, from where, in which tenant, for which operation — and puts it in the request context
// (WithRequest); Record and Requested take their defaults from it, and it tracks what the request wrote so that
// Logger.Finish can close the request once the handler returned. Use it through a pointer.
type Request struct {
	Operation string // Go name of the operation of api/openapi.yaml (logs, metrics)
	Action    string // its x-audit-action
	ReadOnly  bool   // GET / HEAD: success not audited, failures left to the access log

	ActorType       string     // ActorIdentity, or ActorSupport inside a granted tenant (P4-T13)
	ActorIdentityID *uuid.UUID // nil for an anonymous request
	ActorTenantID   *uuid.UUID // tenant of the actor's identity; nil for platform staff
	ActorDisplay    string
	SupportGrantID  *uuid.UUID

	TenantID     *uuid.UUID // tenant of the path /tenants/{tenantId}/…; nil on every other route
	ResourceType string
	ResourceID   string
	RequestID    string
	ClientIP     netip.Addr

	mu       sync.Mutex
	recorded int
	ops      []tracked
}

// tracked is an operation started during the request.
type tracked struct {
	op        Operation
	handedOff bool
}

type requestKey struct{}

// WithRequest returns ctx carrying the audit scope r.
func WithRequest(ctx context.Context, r *Request) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}

// RequestFrom returns the audit scope of the request, or nil outside an API request (jobs, commands).
func RequestFrom(ctx context.Context) *Request {
	r, _ := ctx.Value(requestKey{}).(*Request)
	return r
}

func (r *Request) markRecorded() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.recorded++
	r.mu.Unlock()
}

func (r *Request) track(op Operation) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.ops = append(r.ops, tracked{op: op})
	r.mu.Unlock()
}

func (r *Request) handOff(id uuid.UUID) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.ops {
		if r.ops[i].op.ID == id {
			r.ops[i].handedOff = true
		}
	}
}

// snapshot returns how many events the request recorded in business transactions and the operations it started.
func (r *Request) snapshot() (recorded int, ops []tracked) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recorded, append([]tracked(nil), r.ops...)
}

// fill sets the unset fields of ev from the request scope r (may be nil) — and the request id from ctx when there is no
// scope. withTenant also defaults the tenant to the tenant of the path: only for writes inside the business
// transaction, where RLS checks it. A detached write never inherits a tenant (Event.TenantID).
func fill(ctx context.Context, ev *Event, r *Request, withTenant bool) {
	if r == nil {
		if ev.RequestID == "" {
			ev.RequestID = requestid.From(ctx)
		}
		return
	}
	if ev.Action == "" {
		ev.Action = r.Action
	}
	if ev.ActorType == "" {
		ev.ActorType = r.ActorType
	}
	if ev.ActorIdentityID == nil {
		ev.ActorIdentityID = r.ActorIdentityID
	}
	if ev.ActorDisplay == "" {
		ev.ActorDisplay = r.ActorDisplay
	}
	if ev.SupportGrantID == nil {
		ev.SupportGrantID = r.SupportGrantID
	}
	if ev.ResourceType == "" {
		ev.ResourceType = r.ResourceType
	}
	if ev.ResourceID == "" && ev.ResourceType == r.ResourceType {
		ev.ResourceID = r.ResourceID
	}
	if ev.RequestID == "" {
		ev.RequestID = r.RequestID
	}
	if !ev.ActorIP.IsValid() {
		ev.ActorIP = r.ClientIP
	}
	if withTenant && ev.TenantID == nil {
		ev.TenantID = r.TenantID
	}
}
