// Package auditapi connects the audit module (P2-T08) to the public API: the handlers of the two list operations of
// api/openapi.yaml (tag audit: listTenantAuditEvents, listPlatformAuditEvents), the strict middleware of the
// httpapi.Hooks.Audit slot that audits denials and failures and closes the paired events of a request, and the
// identity.Auditor that writes the identity module's events to audit_events. It lives under internal/httpapi because
// internal/audit may import only store and kit (§13.6), and it never imports internal/store (internal/archtest): the
// audit module is reached through the small interfaces below, implemented by *audit.Reader and *audit.Logger.
//
// Wiring (P2-T16, apps/internal/runner — api process):
//
//	writer, _ := store.OpenAuditWriter(ctx, dbURL, store.Credentials{User: store.AuditWriterRole, PasswordFile: …})
//	logger, _ := audit.New(apiStore, writer, audit.Config{Log: log, Registerer: reg})
//	svc, _ := identity.New(apiStore, identity.Config{…, Auditor: auditapi.IdentityAuditor(logger)})
//	hooks := authzhook.Hooks(svc, authz.New(apiStore))
//	hooks.Audit = auditapi.Middleware(logger)
//	api, _ := httpapi.New(httpapi.Options{…, Hooks: hooks, Handlers: httpapi.Handlers{
//		Auth: identityapi.New(svc), Audit: auditapi.New(audit.NewReader(apiStore)), /* … */}})
package auditapi

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
)

// Reader is the part of *audit.Reader the handlers need.
type Reader interface {
	ListTenant(ctx context.Context, tenantID uuid.UUID, q audit.Query) (audit.Page, error)
	ListPlatform(ctx context.Context, q audit.Query) (audit.Page, error)
}

var _ Reader = (*audit.Reader)(nil)

// Handlers implements httpapi.AuditHandlers. Authorization (tenant.audit:read, platform.audit:read) is decided before
// they run (Hooks.Authz); the tenant of a tenant list is the {tenantId} of the path, nothing else.
type Handlers struct {
	r Reader
}

var _ httpapi.AuditHandlers = (*Handlers)(nil)

// New returns the handlers of the audit operations.
func New(r Reader) *Handlers { return &Handlers{r: r} }

// ListTenantAuditEvents implements GET /tenants/{tenantId}/audit.
func (h *Handlers) ListTenantAuditEvents(ctx context.Context, req gen.ListTenantAuditEventsRequestObject) (gen.ListTenantAuditEventsResponseObject, error) {
	p := req.Params
	q, err := query(p.Limit, p.Cursor, p.Actor, p.Action, p.Outcome, p.From, p.To)
	if err != nil {
		return nil, err
	}
	page, err := h.r.ListTenant(ctx, req.TenantId, q)
	if err != nil {
		return nil, listError(err)
	}
	return gen.ListTenantAuditEvents200JSONResponse(list(page)), nil
}

// ListPlatformAuditEvents implements GET /platform/audit (platform events only).
func (h *Handlers) ListPlatformAuditEvents(ctx context.Context, req gen.ListPlatformAuditEventsRequestObject) (gen.ListPlatformAuditEventsResponseObject, error) {
	p := req.Params
	q, err := query(p.Limit, p.Cursor, p.Actor, p.Action, p.Outcome, p.From, p.To)
	if err != nil {
		return nil, err
	}
	page, err := h.r.ListPlatform(ctx, q)
	if err != nil {
		return nil, listError(err)
	}
	return gen.ListPlatformAuditEvents200JSONResponse(list(page)), nil
}

// query maps the parameters (the generated binding checked their types, not their ranges) to an audit.Query.
func query(limit *int, cursor *string, actor *uuid.UUID, action *string, outcome *gen.AuditOutcome,
	from, to *time.Time,
) (audit.Query, error) {
	q := audit.Query{Actor: actor, From: from, To: to}
	if limit != nil {
		if *limit < 1 || *limit > audit.MaxLimit {
			return q, problem.Validation("The query parameters are invalid.",
				problem.Field("limit", "out_of_range", "must be between 1 and 200"))
		}
		q.Limit = *limit
	}
	if cursor != nil {
		q.Cursor = *cursor
	}
	if action != nil {
		q.Action = *action
	}
	if outcome != nil {
		if !outcome.Valid() {
			return q, problem.Validation("The query parameters are invalid.",
				problem.Field("outcome", "invalid", "must be success, denied or failure"))
		}
		q.Outcome = string(*outcome)
	}
	return q, nil
}

// listError maps a reader error: an invalid parameter is 422 naming it, anything else 500 (internal log only).
func listError(err error) error {
	var qe *audit.QueryError
	if errors.As(err, &qe) {
		return problem.Validation("The query parameters are invalid.", problem.Field(qe.Field, qe.Code, qe.Message))
	}
	return problem.Internal(err)
}

// list maps a page to AuditEventList (§13.3 AuditEvent).
func list(p audit.Page) gen.AuditEventList {
	out := gen.AuditEventList{Items: make([]gen.AuditEvent, 0, len(p.Items))}
	for _, e := range p.Items {
		ev := gen.AuditEvent{
			Id: e.ID, OccurredAt: e.OccurredAt, Action: e.Action, Outcome: gen.AuditOutcome(e.Outcome),
			RequestId: e.RequestID, OperationId: e.OperationID, Details: e.Details,
			Actor:    gen.AuditActor{Type: gen.AuditActorType(e.ActorType), IdentityId: e.ActorIdentityID, SupportGrantId: e.SupportGrantID},
			Resource: gen.ResourceRef{Type: e.ResourceType, Id: e.ResourceID},
		}
		if e.ActorDisplay != "" {
			name := e.ActorDisplay
			ev.Actor.DisplayName = &name
		}
		if ev.Details == nil {
			ev.Details = map[string]any{}
		}
		out.Items = append(out.Items, ev)
	}
	if p.NextCursor != "" {
		c := p.NextCursor
		out.NextCursor = &c
	}
	return out
}
