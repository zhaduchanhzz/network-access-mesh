package tagsapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
)

type fakeService struct {
	tenant, id uuid.UUID
	actor      policies.TagActor
	in         policies.NewTag
	idem       *policies.Idempotency
	ifMatch    string
	desc       *string
	limit      int
	cursor     string
	err        error
	tag        policies.Tag
}

func (f *fakeService) List(_ context.Context, t uuid.UUID, limit int, cursor string) (policies.TagPage, error) {
	f.tenant, f.limit, f.cursor = t, limit, cursor
	return policies.TagPage{Items: []policies.Tag{f.tag}, NextCursor: "next"}, f.err
}

func (f *fakeService) Create(_ context.Context, t uuid.UUID, a policies.TagActor, in policies.NewTag, idem *policies.Idempotency) (policies.TagChange, error) {
	f.tenant, f.actor, f.in, f.idem = t, a, in, idem
	return policies.TagChange{Tag: f.tag}, f.err
}

func (f *fakeService) Update(_ context.Context, t, id uuid.UUID, a policies.TagActor, ifMatch string, d *string) (policies.TagChange, error) {
	f.tenant, f.id, f.actor, f.ifMatch, f.desc = t, id, a, ifMatch, d
	return policies.TagChange{Tag: f.tag}, f.err
}

func (f *fakeService) Delete(_ context.Context, t, id uuid.UUID, a policies.TagActor, ifMatch string) (policies.TagChange, error) {
	f.tenant, f.id, f.actor, f.ifMatch = t, id, a, ifMatch
	return policies.TagChange{Tag: f.tag}, f.err
}

// sessionOf resolves the caller like actorOf, from a fixed identity (no session ⇒ the same 500).
func sessionOf(id uuid.UUID) func(context.Context) (policies.TagActor, error) {
	return func(ctx context.Context) (policies.TagActor, error) {
		if ctx.Value(noSession{}) != nil {
			return actorOf(ctx)
		}
		return policies.TagActor{IdentityID: id}, nil
	}
}

type noSession struct{}

// TestHandlersMapRequests: parameters, If-Match, the body and the caller reach the service; the tag maps to the schema
// with its etag; without a session nothing is called.
func TestHandlersMapRequests(t *testing.T) {
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	desc := "web"
	tag := policies.Tag{ID: uuid.New(), Name: "tag:web", Purpose: policies.PurposeCustom, Description: &desc, Version: 3,
		CreatedAt: now, UpdatedAt: now}
	svc := &fakeService{tag: tag}
	tenant, who := uuid.New(), uuid.New()
	h := New(svc, nil)
	h.actor = sessionOf(who)
	ctx := context.Background()

	limit, cursor := 7, "c"
	res, err := h.ListTenantTags(ctx, gen.ListTenantTagsRequestObject{TenantId: tenant,
		Params: gen.ListTenantTagsParams{Limit: &limit, Cursor: &cursor}})
	list, ok := res.(gen.ListTenantTags200JSONResponse)
	if err != nil || !ok || len(list.Items) != 1 || list.Items[0].Etag != `"3"` || list.NextCursor == nil ||
		svc.limit != 7 || svc.cursor != "c" || svc.tenant != tenant {
		t.Fatalf("list: %+v %v (%+v)", res, err, svc)
	}
	zero := 0
	if _, err := h.ListTenantTags(ctx, gen.ListTenantTagsRequestObject{TenantId: tenant,
		Params: gen.ListTenantTagsParams{Limit: &zero}}); err != nil || svc.limit != -1 {
		t.Fatalf("limit=0 passed as %d", svc.limit)
	}

	purpose := gen.TagCreatePurpose("server")
	cr, err := h.CreateTenantTag(ctx, gen.CreateTenantTagRequestObject{TenantId: tenant,
		Params: gen.CreateTenantTagParams{IdempotencyKey: "key-123456"},
		Body:   &gen.CreateTenantTagJSONRequestBody{Name: "tag:web", Purpose: &purpose}})
	if _, ok := cr.(gen.CreateTenantTag201JSONResponse); err != nil || !ok || svc.in.Name != "tag:web" ||
		svc.in.Purpose != "server" || svc.actor.IdentityID != who || svc.idem == nil || svc.idem.Key != "key-123456" ||
		len(svc.idem.Hash) != 32 {
		t.Fatalf("create: %+v %v (%+v)", cr, err, svc)
	}

	im := `"3"`
	up, err := h.UpdateTenantTag(ctx, gen.UpdateTenantTagRequestObject{TenantId: tenant, TagId: tag.ID,
		Params: gen.UpdateTenantTagParams{IfMatch: &im}, Body: &gen.UpdateTenantTagJSONRequestBody{Description: "db"}})
	u, ok := up.(gen.UpdateTenantTag200JSONResponse)
	if err != nil || !ok || u.Headers.ETag != `"3"` || svc.ifMatch != `"3"` || svc.desc == nil || *svc.desc != "db" || svc.id != tag.ID {
		t.Fatalf("update: %+v %v", up, err)
	}
	del, err := h.DeleteTenantTag(ctx, gen.DeleteTenantTagRequestObject{TenantId: tenant, TagId: tag.ID})
	if _, ok := del.(gen.DeleteTenantTag204Response); err != nil || !ok || svc.ifMatch != "" {
		t.Fatalf("delete: %+v %v", del, err)
	}
	// setDeviceTags without device handlers ⇒ 501
	if _, err := h.SetDeviceTags(ctx, gen.SetDeviceTagsRequestObject{}); !isCode(err, gen.ProblemCodeNotImplemented) {
		t.Fatalf("set device tags without delegate: %v", err)
	}
	// no session ⇒ 500, the service is not called
	svc.tenant = uuid.Nil
	if _, err := h.DeleteTenantTag(context.WithValue(ctx, noSession{}, true), gen.DeleteTenantTagRequestObject{TenantId: tenant}); !isCode(err, gen.ProblemCodeInternalError) ||
		svc.tenant != uuid.Nil {
		t.Fatalf("without session: %v", err)
	}
}

func isCode(err error, code gen.ProblemCode) bool {
	var p *problem.Error
	return errors.As(err, &p) && p.Code == code
}

// TestFailureMapping: every refusal of the catalog is the Problem of §13.1 — 404, 422 on its field, 409 (with the
// reference counts of a tag in use), 428, 412, the Idempotency-Key outcomes; anything else 500.
func TestFailureMapping(t *testing.T) {
	inUse := &policies.TagError{Kind: policies.ErrTagConflict, Reason: "tag_in_use",
		References: &policies.TagReferenceCounts{Devices: 2, Keys: 1}}
	cases := []struct {
		err    error
		code   gen.ProblemCode
		status int
		field  string
	}{
		{&policies.TagError{Kind: policies.ErrTagNotFound, Reason: "tag_not_found"}, gen.ProblemCodeNotFound, 404, ""},
		{&policies.TagError{Kind: policies.ErrTagInvalid, Reason: "invalid_tag_name", Field: "name"}, gen.ProblemCodeValidationFailed, 422, "name"},
		{&policies.TagError{Kind: policies.ErrTagNotInCatalog, Reason: "tag_not_in_catalog", Field: "tags"}, gen.ProblemCodeValidationFailed, 422, "tags"},
		{&policies.TagError{Kind: policies.ErrTagConflict, Reason: "tag_exists"}, gen.ProblemCodeConflict, 409, ""},
		{inUse, gen.ProblemCodeConflict, 409, ""},
		{&policies.TagError{Kind: policies.ErrTagPreconditionRequired, Reason: "if_match_required"}, gen.ProblemCodePreconditionRequired, 428, ""},
		{&policies.TagError{Kind: policies.ErrTagPreconditionFailed, Reason: "stale_etag"}, gen.ProblemCodePreconditionFailed, 412, ""},
		{&policies.TagError{Kind: policies.ErrTagIdempotencyInProgress, Reason: "x", RetryAfter: time.Second}, gen.ProblemCodeConflict, 409, ""},
		{&policies.TagError{Kind: policies.ErrTagIdempotencyKeyReuse, Reason: "x"}, gen.ProblemCodeIdempotencyKeyReuse, 422, ""},
		{errors.New("db"), gen.ProblemCodeInternalError, 500, ""},
	}
	for _, c := range cases {
		var p *problem.Error
		if !errors.As(failure(c.err), &p) || p.Code != c.code || p.Status() != c.status {
			t.Errorf("%v: %+v", c.err, p)
			continue
		}
		if c.field != "" && (len(p.Fields) != 1 || p.Fields[0].Field != c.field) {
			t.Errorf("%v: fields %+v", c.err, p.Fields)
		}
	}
	var p *problem.Error
	_ = errors.As(failure(inUse), &p)
	if p.Detail != "The tag is still in use: 2 device(s), 1 enrollment key(s), 0 network resource(s), 0 policy version(s) or applied policies refer to it." {
		t.Errorf("in use detail %q", p.Detail)
	}
}
