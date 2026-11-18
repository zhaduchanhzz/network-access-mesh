// Package tagsapi serves the tag catalog operations of api/openapi.yaml built by P4-T15 (httpapi.TagHandlers):
// listTenantTags (`tenant.tag:read` — TO, TA, TP, TV, support), createTenantTag, updateTenantTag, deleteTenantTag
// (`tenant.tag:manage` — TO, TA — §8.6). It only translates between the generated types and policies.TagService, which
// takes every decision (format, purpose, uniqueness, If-Match, references that keep a tag, the policy.apply job with
// trigger tag_change).
//
// Wiring (apps/internal/runner — api process):
//
//	tags, _ := policies.NewTags(apiStore, policies.TagsConfig{})
//	httpapi.Handlers{…, Tags: tagsapi.New(tags, devicesapi.New(devicesSvc))}  // devicesSvc: devices.Config{Tags: tags}
package tagsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
)

// Service is the part of *policies.TagService the handlers use.
type Service interface {
	List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) (policies.TagPage, error)
	Create(ctx context.Context, tenantID uuid.UUID, actor policies.TagActor, in policies.NewTag, idem *policies.Idempotency) (policies.TagChange, error)
	Update(ctx context.Context, tenantID, id uuid.UUID, actor policies.TagActor, ifMatch string, description *string) (policies.TagChange, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID, actor policies.TagActor, ifMatch string) (policies.TagChange, error)
}

var _ Service = (*policies.TagService)(nil)

// DeviceTagger serves PUT /tenants/{t}/devices/{id}/tags — devicesapi.Handlers (the device module owns the call to
// Headscale; the catalog check is policies.TagService.CheckTags, wired into devices).
type DeviceTagger interface {
	SetDeviceTags(ctx context.Context, request gen.SetDeviceTagsRequestObject) (gen.SetDeviceTagsResponseObject, error)
}

// Handlers implements httpapi.TagHandlers.
type Handlers struct {
	svc   Service
	dev   DeviceTagger
	actor func(ctx context.Context) (policies.TagActor, error) // actorOf (a test replaces it)
}

var _ httpapi.TagHandlers = (*Handlers)(nil)

// New returns the handler set of P4-T15; dev serves setDeviceTags (nil ⇒ 501).
func New(svc Service, dev DeviceTagger) *Handlers {
	return &Handlers{svc: svc, dev: dev, actor: actorOf}
}

// SetDeviceTags implements PUT /tenants/{tenantId}/devices/{deviceId}/tags through the device handlers.
func (h *Handlers) SetDeviceTags(ctx context.Context, req gen.SetDeviceTagsRequestObject) (gen.SetDeviceTagsResponseObject, error) {
	if h.dev == nil {
		return nil, problem.NotImplemented("SetDeviceTags")
	}
	return h.dev.SetDeviceTags(ctx, req)
}

var errNoSession = errors.New("tagsapi: no session in the request context (hooks missing)")

// actorOf is the caller's identity (the session — the authorization hook already decided).
func actorOf(ctx context.Context) (policies.TagActor, error) {
	s, ok := identity.SessionFromContext(ctx)
	if !ok || s == nil || s.IdentityID == uuid.Nil {
		return policies.TagActor{}, problem.Internal(errNoSession)
	}
	return policies.TagActor{IdentityID: s.IdentityID}, nil
}

// failure maps an error of the catalog: not found ⇒ 404 (another tenant's tag too — §8.4 invariant 6), invalid ⇒ 422
// on its field, conflict ⇒ 409 (with the reference counts of a tag in use), If-Match ⇒ 428/412, the Idempotency-Key
// outcomes of §13.1, anything else ⇒ 500.
func failure(err error) error {
	te, ok := policies.AsTagError(err)
	if !ok {
		return problem.Internal(err)
	}
	cause := &authz.Denial{Kind: err, Reason: te.Reason}
	switch {
	case errors.Is(err, policies.ErrTagNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, policies.ErrTagInvalid), errors.Is(err, policies.ErrTagNotInCatalog):
		field := te.Field
		if field == "" {
			field = "body"
		}
		return problem.Validation("The request is invalid.", problem.Field(field, te.Reason, "has an invalid value"))
	case errors.Is(err, policies.ErrTagPreconditionRequired):
		return &problem.Error{Code: gen.ProblemCodePreconditionRequired, Cause: cause,
			Detail: "If-Match with the tag's etag is required."}
	case errors.Is(err, policies.ErrTagPreconditionFailed):
		return &problem.Error{Code: gen.ProblemCodePreconditionFailed, Cause: cause,
			Detail: "The tag changed since it was read; read it again."}
	case errors.Is(err, policies.ErrTagIdempotencyInProgress):
		return &problem.Error{Code: gen.ProblemCodeConflict, Cause: cause, RetryAfter: te.RetryAfter,
			Detail: "A request with this Idempotency-Key is still in progress."}
	case errors.Is(err, policies.ErrTagIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, policies.ErrTagConflict):
		detail := map[string]string{
			"tag_exists":           "A tag with this name is already in the tenant's catalog.",
			"tag_platform_managed": "This tag is managed by the platform and cannot be changed here.",
		}[te.Reason]
		if te.Reason == "tag_in_use" && te.References != nil {
			r := te.References
			detail = fmt.Sprintf("The tag is still in use: %d device(s), %d enrollment key(s), %d network resource(s), "+
				"%d policy version(s) or applied policies refer to it.", r.Devices, r.Keys, r.Resources, r.Policies)
		}
		if detail == "" {
			detail = "The request conflicts with the current state of the tag catalog."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	}
	return problem.Internal(err)
}

func toAPI(t policies.Tag) gen.Tag {
	return gen.Tag{Id: t.ID, Name: t.Name, Purpose: gen.TagPurpose(t.Purpose), PlatformManaged: t.PlatformManaged,
		Description: t.Description, Version: t.Version, Etag: t.ETag(), CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt}
}

func ifMatch(p *gen.IfMatch) string {
	if p == nil {
		return ""
	}
	return *p
}

// ListTenantTags implements GET /tenants/{tenantId}/tags.
func (h *Handlers) ListTenantTags(ctx context.Context, req gen.ListTenantTagsRequestObject) (gen.ListTenantTagsResponseObject, error) {
	limit, cursor := 0, ""
	if p := req.Params.Limit; p != nil {
		limit = *p
		if limit == 0 {
			limit = -1 // 0 is not "the default": the spec's minimum is 1
		}
	}
	if c := req.Params.Cursor; c != nil {
		cursor = *c
	}
	page, err := h.svc.List(ctx, req.TenantId, limit, cursor)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.TagList{Items: make([]gen.Tag, 0, len(page.Items))}
	for _, t := range page.Items {
		out.Items = append(out.Items, toAPI(t))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListTenantTags200JSONResponse(out), nil
}

// CreateTenantTag implements POST /tenants/{tenantId}/tags (Idempotency-Key: the hash covers the method, the path with
// the tenant and the canonical body — §13.1).
func (h *Handlers) CreateTenantTag(ctx context.Context, req gen.CreateTenantTagRequestObject) (gen.CreateTenantTagResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	idem := &policies.Idempotency{Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/tenants/"+req.TenantId.String()+"/tags", body)}
	in := policies.NewTag{Name: req.Body.Name, Description: req.Body.Description}
	if req.Body.Purpose != nil {
		in.Purpose = string(*req.Body.Purpose)
	}
	c, err := h.svc.Create(ctx, req.TenantId, a, in, idem)
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreateTenantTag201JSONResponse(toAPI(c.Tag)), nil
}

// UpdateTenantTag implements PATCH /tenants/{tenantId}/tags/{tagId}.
func (h *Handlers) UpdateTenantTag(ctx context.Context, req gen.UpdateTenantTagRequestObject) (gen.UpdateTenantTagResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	d := req.Body.Description
	c, err := h.svc.Update(ctx, req.TenantId, req.TagId, a, ifMatch(req.Params.IfMatch), &d)
	if err != nil {
		return nil, failure(err)
	}
	t := toAPI(c.Tag)
	return gen.UpdateTenantTag200JSONResponse{Body: t, Headers: gen.UpdateTenantTag200ResponseHeaders{ETag: t.Etag}}, nil
}

// DeleteTenantTag implements DELETE /tenants/{tenantId}/tags/{tagId}.
func (h *Handlers) DeleteTenantTag(ctx context.Context, req gen.DeleteTenantTagRequestObject) (gen.DeleteTenantTagResponseObject, error) {
	a, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.svc.Delete(ctx, req.TenantId, req.TagId, a, ifMatch(req.Params.IfMatch)); err != nil {
		return nil, failure(err)
	}
	return gen.DeleteTenantTag204Response{}, nil
}
