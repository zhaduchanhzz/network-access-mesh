package policies

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// tagsFx is the catalog side of the fixture: the api's store (mg_api_tenant — CRUD of tenant_tags) and the service.
type tagsFx struct {
	*fixture
	api  *store.Store
	tags *TagService
}

func newTagsFixture(t *testing.T) *tagsFx {
	t.Helper()
	f := newFixture(t)
	api := f.env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 4)
	svc, err := NewTags(api, TagsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return &tagsFx{fixture: f, api: api, tags: svc}
}

// actor is the Tenant Admin of ten as the request scope of an API call (the audit actor) and as the TagActor.
func (f *tagsFx) actor(t *testing.T, ten *tenantFx, action string) (context.Context, TagActor) {
	t.Helper()
	var ident uuid.UUID
	f.scan(t, `SELECT identity_id FROM tenant_memberships WHERE id = $1`, []any{ten.admin}, &ident)
	tid := ten.id
	ctx := audit.WithRequest(context.Background(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &ident, ActorDisplay: "admin", TenantID: &tid, RequestID: "req-" + randomHex(4)})
	return ctx, TagActor{IdentityID: ident}
}

func (f *tagsFx) create(t *testing.T, ten *tenantFx, name string) TagChange {
	t.Helper()
	ctx, a := f.actor(t, ten, ActionTagCreate)
	c, err := f.tags.Create(ctx, ten.id, a, NewTag{Name: name}, nil)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return c
}

func wantTagErr(t *testing.T, what string, err, kind error, reason string) *TagError {
	t.Helper()
	te, ok := AsTagError(err)
	if !ok || !errors.Is(err, kind) || (reason != "" && te.Reason != reason) {
		t.Fatalf("%s: got %v, want %v (%s)", what, err, kind, reason)
	}
	return te
}

// TestTagCatalogCRUD — the catalog API's rules: a tenant tag (custom by default) is created once (409 on the same name,
// 422 on a bad name or a platform purpose); the description changes only with the current If-Match (428 without, 412
// stale); every change writes its audit event and enqueues policy.apply with trigger tag_change in the same transaction
// (an unfinished job of the tenant is reused — §13.5); a platform tag is read-only (409); another tenant's tag is
// not found; the list pages in (created_at, id) order; an Idempotency-Key replay returns the first tag.
func TestTagCatalogCRUD(t *testing.T) {
	f := newTagsFixture(t)
	ctx, a := f.actor(t, f.a, ActionTagCreate)
	web := f.create(t, f.a, "tag:web")
	if web.Tag.Purpose != PurposeCustom || web.Tag.Version != 1 || web.Tag.ETag() != `"1"` || web.JobID == uuid.Nil {
		t.Fatalf("created %+v", web)
	}
	desc := "  databases  "
	db, err := f.tags.Create(ctx, f.a.id, a, NewTag{Name: "tag:db", Purpose: PurposeServer, Description: &desc}, nil)
	if err != nil || db.Tag.Description == nil || *db.Tag.Description != "databases" || db.Tag.Purpose != PurposeServer {
		t.Fatalf("server tag: %+v %v", db, err)
	}
	if db.JobID != web.JobID {
		t.Fatalf("the unfinished policy.apply job of the tenant must be reused: %s vs %s", db.JobID, web.JobID)
	}
	if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = 'policy.apply'
		AND status = 'queued' AND input->>'trigger' = 'tag_change' AND dedupe_key = 'tenant:'||$1::text||':policy.apply'`, f.a.id); n != 1 {
		t.Fatalf("policy.apply jobs %d", n)
	}
	_, err = f.tags.Create(ctx, f.a.id, a, NewTag{Name: "tag:web"}, nil)
	wantTagErr(t, "duplicate", err, ErrTagConflict, "tag_exists")
	_, err = f.tags.Create(ctx, f.a.id, a, NewTag{Name: "tag:Web"}, nil)
	wantTagErr(t, "bad name", err, ErrTagInvalid, "invalid_tag_name")
	_, err = f.tags.Create(ctx, f.a.id, a, NewTag{Name: "tag:edge", Purpose: PurposeRouter}, nil)
	wantTagErr(t, "router purpose", err, ErrTagInvalid, "purpose_platform_only")
	_, err = f.tags.Create(ctx, f.a.id, a, NewTag{Name: "tag:edge", Purpose: "x"}, nil)
	wantTagErr(t, "unknown purpose", err, ErrTagInvalid, "invalid_purpose")

	// the same name in tenant B is another tag
	webB := f.create(t, f.b, "tag:web")
	if webB.Tag.ID == web.Tag.ID {
		t.Fatal("tenants share a tag")
	}

	uctx, ua := f.actor(t, f.a, ActionTagUpdate)
	d2 := "web servers"
	_, err = f.tags.Update(uctx, f.a.id, web.Tag.ID, ua, "", &d2)
	wantTagErr(t, "no If-Match", err, ErrTagPreconditionRequired, "if_match_required")
	_, err = f.tags.Update(uctx, f.a.id, web.Tag.ID, ua, `"7"`, &d2)
	wantTagErr(t, "stale If-Match", err, ErrTagPreconditionFailed, "stale_etag")
	up, err := f.tags.Update(uctx, f.a.id, web.Tag.ID, ua, web.Tag.ETag(), &d2)
	if err != nil || up.Tag.Version != 2 || up.Tag.Description == nil || *up.Tag.Description != d2 || up.Tag.Name != "tag:web" {
		t.Fatalf("update: %+v %v", up, err)
	}
	// isolation: tenant B never sees nor changes tenant A's tag
	if _, err := f.tags.Get(context.Background(), f.b.id, web.Tag.ID); !errors.Is(err, ErrTagNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	_, err = f.tags.Update(uctx, f.b.id, web.Tag.ID, ua, up.Tag.ETag(), &d2)
	wantTagErr(t, "cross-tenant update", err, ErrTagNotFound, "")
	dctx, da := f.actor(t, f.a, ActionTagDelete)
	_, err = f.tags.Delete(dctx, f.b.id, web.Tag.ID, da, "")
	wantTagErr(t, "cross-tenant delete", err, ErrTagNotFound, "")

	// a platform tag (created by the platform — here the superuser) is read-only: 409, and the database refuses too
	pm := uuid.New()
	f.exec(t, `INSERT INTO tenant_tags (id, tenant_id, name, purpose, platform_managed) VALUES ($1, $2, 'tag:mg-router', 'router', true)`,
		pm, f.a.id)
	_, err = f.tags.Update(uctx, f.a.id, pm, ua, `"1"`, &d2)
	wantTagErr(t, "platform update", err, ErrTagConflict, "tag_platform_managed")
	_, err = f.tags.Delete(dctx, f.a.id, pm, da, "")
	wantTagErr(t, "platform delete", err, ErrTagConflict, "tag_platform_managed")
	err = f.api.WithTenantTx(context.Background(), f.a.id, func(q *sqlcdb.Queries) error {
		n, err := q.DeleteTenantTag(context.Background(), sqlcdb.DeleteTenantTagParams{TenantID: f.a.id, ID: pm})
		if err == nil && n != 0 {
			return errors.New("the api role deleted a platform tag")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// delete with a stale If-Match ⇒ 412; without ⇒ deleted; again ⇒ 404
	_, err = f.tags.Delete(dctx, f.a.id, db.Tag.ID, da, `"9"`)
	wantTagErr(t, "stale delete", err, ErrTagPreconditionFailed, "")
	del, err := f.tags.Delete(dctx, f.a.id, db.Tag.ID, da, "")
	if err != nil || del.Tag.Name != "tag:db" || del.JobID == uuid.Nil {
		t.Fatalf("delete: %+v %v", del, err)
	}
	_, err = f.tags.Delete(dctx, f.a.id, db.Tag.ID, da, "")
	wantTagErr(t, "delete again", err, ErrTagNotFound, "")

	// the list pages in (created_at, id) order; foreign cursor / bad limit ⇒ 422
	for _, n := range []string{"tag:p1", "tag:p2", "tag:p3"} {
		f.create(t, f.a, n)
	}
	var names []string
	cursor := ""
	for range 10 {
		page, err := f.tags.List(context.Background(), f.a.id, 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range page.Items {
			names = append(names, it.Name)
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	if strings.Join(names, ",") != "tag:web,tag:mg-router,tag:p1,tag:p2,tag:p3" {
		t.Fatalf("pages %v", names)
	}
	_, err = f.tags.List(context.Background(), f.a.id, 0, "nope")
	wantTagErr(t, "cursor", err, ErrTagInvalid, "invalid_cursor")
	_, err = f.tags.List(context.Background(), f.a.id, MaxTagLimit+1, "")
	wantTagErr(t, "limit", err, ErrTagInvalid, "invalid_limit")

	// audit: create ×5 (web, db, p1–p3 by the Admin of A), update ×1, delete ×1 — actor = the Admin, resource tag
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND resource_type = 'tag'
		AND actor_type = 'identity' AND outcome = 'success' AND action IN ('tag.create', 'tag.update', 'tag.delete')`, f.a.id); n != 7 {
		t.Fatalf("audit events %d, want 7", n)
	}
	var upd string
	f.scan(t, `SELECT details::text FROM audit_events WHERE tenant_id = $1 AND action = 'tag.update'`, []any{f.a.id}, &upd)
	if !strings.Contains(upd, `"description": "web servers"`) || !strings.Contains(upd, `"policy_apply_job_id"`) {
		t.Fatalf("update event details %s", upd)
	}

	// Idempotency-Key: the replay returns the first tag, another body is 422, nothing new is written
	ictx, ia := f.actor(t, f.b, ActionTagCreate)
	idem := &Idempotency{Key: "k-" + randomHex(6), Hash: jobs.RequestHash("POST", "/tenants/"+f.b.id.String()+"/tags", []byte(`{"name":"tag:once"}`))}
	first, err := f.tags.Create(ictx, f.b.id, ia, NewTag{Name: "tag:once"}, idem)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.tags.Create(ictx, f.b.id, ia, NewTag{Name: "tag:once"}, idem)
	if err != nil || replay.Tag.ID != first.Tag.ID {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	other := &Idempotency{Key: idem.Key, Hash: jobs.RequestHash("POST", "/tenants/"+f.b.id.String()+"/tags", []byte(`{"name":"tag:twice"}`))}
	_, err = f.tags.Create(ictx, f.b.id, ia, NewTag{Name: "tag:twice"}, other)
	wantTagErr(t, "key reuse", err, ErrTagIdempotencyKeyReuse, "")
	if n := f.count(t, `SELECT count(*) FROM tenant_tags WHERE tenant_id = $1 AND name IN ('tag:once', 'tag:twice')`, f.b.id); n != 1 {
		t.Fatalf("tags after replay %d", n)
	}
}

// TestTagCatalogChecks — RequireTags/CheckTags, the rule of PUT /devices/{id}/tags and of the requested_tags of an
// enrollment request (P4-T06): names sorted without duplicates; a tag outside the catalog (another tenant's included)
// ⇒ ErrTagNotInCatalog listing it; empty or malformed ⇒ ErrTagInvalid; a platform tag is in the catalog.
func TestTagCatalogChecks(t *testing.T) {
	f := newTagsFixture(t)
	f.create(t, f.a, "tag:web")
	f.create(t, f.a, "tag:db")
	f.create(t, f.b, "tag:only-b")
	f.exec(t, `INSERT INTO tenant_tags (tenant_id, name, purpose, platform_managed) VALUES ($1, 'tag:mg-exit', 'exit', true)`, f.a.id)
	ctx := context.Background()
	got, err := f.tags.CheckTags(ctx, f.a.id, []string{"tag:web", "tag:db", "tag:web", "tag:mg-exit"}, "tags")
	if err != nil || strings.Join(got, ",") != "tag:db,tag:mg-exit,tag:web" {
		t.Fatalf("check: %v %v", got, err)
	}
	_, err = f.tags.CheckTags(ctx, f.a.id, []string{"tag:web", "tag:only-b", "tag:nope"}, "requested_tags")
	te := wantTagErr(t, "undeclared", err, ErrTagNotInCatalog, "tag_not_in_catalog")
	if field, _, tags, ok := te.Validation(); !ok || field != "requested_tags" || !slices.Equal(tags, []string{"tag:nope", "tag:only-b"}) {
		t.Fatalf("validation %s %v %v", field, tags, ok)
	}
	_, err = f.tags.CheckTags(ctx, f.a.id, nil, "tags")
	wantTagErr(t, "empty", err, ErrTagInvalid, "tags_empty")
	_, err = f.tags.CheckTags(ctx, f.a.id, []string{"web"}, "tags")
	wantTagErr(t, "malformed", err, ErrTagInvalid, "invalid_tag_name")

	// in the caller's transaction, the checked tags are locked FOR SHARE: a concurrent delete waits for that
	// transaction, then sees the reference it committed (here: the key request of P4-T06)
	var webID uuid.UUID
	f.scan(t, `SELECT id FROM tenant_tags WHERE tenant_id = $1 AND name = 'tag:web'`, []any{f.a.id}, &webID)
	locked, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.api.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
			if _, err := RequireTags(ctx, q, f.a.id, []string{"tag:web"}, "requested_tags"); err != nil {
				return err
			}
			close(locked)
			<-release
			_, err := q.InsertTenantTag(ctx, sqlcdb.InsertTenantTagParams{TenantID: f.a.id, Name: "tag:side", Purpose: "custom"})
			return err
		})
	}()
	<-locked
	dctx, da := f.actor(t, f.a, ActionTagDelete)
	delDone := make(chan error, 1)
	go func() {
		_, err := f.tags.Delete(dctx, f.a.id, webID, da, "")
		delDone <- err
	}()
	select {
	case err := <-delDone:
		t.Fatalf("the delete did not wait for the FOR SHARE lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	f.exec(t, `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id, method, requested_tags)
		VALUES ($1, $2, $3, 'preauth_key', '{tag:web}')`, f.a.id, f.a.instance, f.a.admin)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	err = <-delDone
	if te := wantTagErr(t, "delete after the key", err, ErrTagConflict, "tag_in_use"); te.References.Keys != 1 {
		t.Fatalf("references %+v", te.References)
	}
}

// TestTagDeleteReferences — the verification of P4-T15 on the catalog's side: a tag still carried by a device, an
// enrollment key, a network resource or a policy that can still be applied is not deleted (409 tag_in_use with the
// counts); once every reference is gone the delete succeeds. References of another tenant do not count.
func TestTagDeleteReferences(t *testing.T) {
	f := newTagsFixture(t)
	tag := f.create(t, f.a, "tag:srv").Tag
	f.create(t, f.b, "tag:srv")
	dctx, da := f.actor(t, f.a, ActionTagDelete)
	deleteIt := func() error { _, err := f.tags.Delete(dctx, f.a.id, tag.ID, da, ""); return err }
	refs := func(what string) TagReferenceCounts {
		t.Helper()
		te := wantTagErr(t, what, deleteIt(), ErrTagConflict, "tag_in_use")
		return *te.References
	}

	// tenant B's device, key and resource with the same name never block tenant A
	f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, tags)
		VALUES ($1, $2, 1, 'mkey:b', 'b1', '{tag:srv}')`, f.b.id, f.b.instance)

	// 1. a live device carries it (a removed one does not)
	f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, tags, removed_at)
		VALUES ($1, $2, 9, 'mkey:gone', 'gone', '{tag:srv}', now())`, f.a.id, f.a.instance)
	f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, tags)
		VALUES ($1, $2, 1, 'mkey:a', 'a1', '{tag:other,tag:srv}')`, f.a.id, f.a.instance)
	if c := refs("device"); c != (TagReferenceCounts{Devices: 1}) {
		t.Fatalf("device refs %+v", c)
	}
	f.exec(t, `UPDATE device_inventory_cache SET tags = '{}' WHERE tenant_id = $1 AND machine_key = 'mkey:a'`, f.a.id)

	// 2. an enrollment request that can still issue a tagged key (a revoked one cannot)
	f.exec(t, `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id, method, requested_tags, status)
		VALUES ($1, $2, $3, 'preauth_key', '{tag:srv}', 'revoked')`, f.a.id, f.a.instance, f.a.admin)
	f.exec(t, `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id, method, requested_tags, status,
			issued_at, credential_expires_at, headscale_preauthkey_id)
		VALUES ($1, $2, $3, 'preauth_key', '{tag:srv}', 'credential_issued', now(), now() + interval '10 minutes', 5)`,
		f.a.id, f.a.instance, f.a.admin)
	if c := refs("key"); c != (TagReferenceCounts{Keys: 1}) {
		t.Fatalf("key refs %+v", c)
	}
	f.exec(t, `UPDATE enrollment_requests SET status = 'expired' WHERE tenant_id = $1 AND status = 'credential_issued'`, f.a.id)

	// 3. a network resource
	f.exec(t, `INSERT INTO network_resources (tenant_id, name, kind, address, tags) VALUES ($1, 'db', 'host', '10.0.0.5/32', '{tag:srv}')`, f.a.id)
	if c := refs("resource"); c != (TagReferenceCounts{Resources: 1}) {
		t.Fatalf("resource refs %+v", c)
	}
	f.exec(t, `DELETE FROM network_resources WHERE tenant_id = $1`, f.a.id)

	// 4. a policy that can still be applied: the desired version AND the applied string reference it in a grant
	pol := `{"grants": [{"src": ["autogroup:member"], "dst": ["tag:srv:443"], "ip": ["tcp:443"]}]}`
	res, err := apply(t, f.fixture, f.a, KindBaseline, pol)
	if err != nil || res.State != StateApplied {
		t.Fatalf("apply %+v %v", res, err)
	}
	if c := refs("policy"); c != (TagReferenceCounts{Policies: 2}) {
		t.Fatalf("policy refs %+v", c)
	}
	// a typed version of P4-T10 referring to the tag by its ID (draft — not applied yet) counts as well
	f.exec(t, `INSERT INTO policy_versions (tenant_id, version, kind, source, content_sha256, state)
		VALUES ($1, 99, 'user', jsonb_build_object('grants', jsonb_build_array(jsonb_build_object('src',
			jsonb_build_array(jsonb_build_object('type', 'tag', 'tag_id', $2::text))))), repeat('b', 64), 'draft')`, f.a.id, tag.ID)
	if c := refs("typed"); c != (TagReferenceCounts{Policies: 3}) {
		t.Fatalf("typed refs %+v", c)
	}
	f.exec(t, `UPDATE policy_versions SET state = 'rejected', rejected_at = now() WHERE tenant_id = $1 AND version = 99`, f.a.id)

	// the policy no longer references it: a new baseline without the tag (its own "tagOwners" render does not count)
	res, err = apply(t, f.fixture, f.a, KindBaseline, `{"grants": [], "ssh": []}`)
	if err != nil || res.State != StateApplied || !strings.Contains(f.a.hs.Stored(), `"tag:srv": []`) {
		t.Fatalf("baseline %+v %v\n%s", res, err, f.a.hs.Stored())
	}
	if err := deleteIt(); err != nil {
		t.Fatalf("delete without references: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_tags WHERE name = 'tag:srv'`); n != 1 {
		t.Fatalf("tenant B's tag must stay (%d left)", n)
	}
}

// TestApplyRendersCatalog — L6 and the "tagOwners" render in the core (Service.Apply): a policy referencing a tag the
// catalog does not declare is refused before Headscale (policy.lint_rejected with rule L6 and the names, nothing
// stored); declared, the applied document carries "tagOwners" = the catalog with empty owners, inputs_sha256 covers it
// and the version content stays the text as given.
func TestApplyRendersCatalog(t *testing.T) {
	f := newTagsFixture(t)
	pol := "// web\n{\"grants\": [{\"src\": [\"tag:web\"], \"dst\": [\"tag:db:5432\"], \"ip\": [\"tcp:5432\"]}], \"ssh\": []}"
	_, err := apply(t, f.fixture, f.a, KindBaseline, pol)
	if le, ok := IsLint(err); !ok || le.Rule != RuleL6 || !slices.Equal(le.Tags, []string{"tag:db", "tag:web"}) {
		t.Fatalf("L6: %v", err)
	}
	if f.reg.count() != 0 || len(f.a.hs.Calls()) != 0 {
		t.Fatal("Headscale reached despite L6")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'policy.lint_rejected'
		AND details->>'rule' = 'L6' AND details->'tags' = '["tag:db", "tag:web"]'::jsonb`, f.a.id); n != 1 {
		t.Fatal("L6 audit")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.a.id); n != 0 {
		t.Fatal("a version was stored")
	}
	f.create(t, f.a, "tag:web")
	f.create(t, f.a, "tag:db")
	f.create(t, f.a, "tag:spare")
	res, err := apply(t, f.fixture, f.a, KindBaseline, pol)
	if err != nil || res.State != StateApplied {
		t.Fatalf("apply %+v %v", res, err)
	}
	stored := f.a.hs.Stored()
	if !strings.HasSuffix(stored, "\"tagOwners\": {\n    \"tag:db\": [],\n    \"tag:spare\": [],\n    \"tag:web\": []\n  }\n}") ||
		res.AppliedSHA256 != SHA256Hex(stored) || !slices.Equal(res.TagOwners, []string{"tag:db", "tag:spare", "tag:web"}) {
		t.Fatalf("applied %+v\n%s", res, stored)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications a JOIN policy_versions v ON v.id = a.policy_version_id
		WHERE a.id = $1 AND a.inputs_sha256 = $2 AND a.inputs_sha256 <> v.content_sha256 AND v.source_hujson = $3
		AND a.applied_hujson = $4`, res.ApplicationID, res.InputsSHA256, pol, stored); n != 1 {
		t.Fatal("application row")
	}
}

// TestPolicyApplyJob — the policy.apply job of a catalog change, through the job framework: it applies the desired
// version again (no new version) with the current catalog rendered and records trigger tag_change; a tenant that is not
// active, or whose desired version is not approved, is skipped; a desired policy that references a tag no longer
// declared fails permanently on L6 (nothing sent).
func TestPolicyApplyJob(t *testing.T) {
	f := newTagsFixture(t)
	base, err := apply(t, f.fixture, f.a, KindBaseline, fixtureText(t, "bootstrap-policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, f.fixture, f.b, KindBaseline, `{"grants": [{"src": ["tag:web"], "dst": ["*"], "ip": ["*"]}]}`); err == nil {
		t.Fatal("tenant B: L6 expected without a catalog")
	}
	f.create(t, f.b, "tag:web")
	if _, err := apply(t, f.fixture, f.b, KindBaseline, `{"grants": [{"src": ["tag:web"], "dst": ["*"], "ip": ["*"]}]}`); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `DELETE FROM river.river_job`) // jobs left by the earlier tests of the shared database
	f.exec(t, `UPDATE provisioning_jobs SET status = 'cancelled', finished_at = now()
		WHERE kind = 'policy.apply' AND status IN ('queued', 'running')`)
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 50*time.Millisecond, 200*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	w, err := jobs.NewWorker(f.st, cfg, jobs.Options{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(c)
	})
	wait := func(id uuid.UUID) (string, string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			var status, out string
			f.scan(t, `SELECT status, COALESCE(output::text, '') || COALESCE(' error='||(error->>'code'), '')
				FROM provisioning_jobs WHERE id = $1`, []any{id}, &status, &out)
			if status == jobs.StatusSucceeded || status == jobs.StatusFailed {
				return status, out
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("job %s did not finish", id)
		return "", ""
	}

	// tenant A: a tag is declared ⇒ the job applies the desired baseline again with "tagOwners"
	c := f.create(t, f.a, "tag:web")
	if st, out := wait(c.JobID); st != jobs.StatusSucceeded || !strings.Contains(out, `"trigger": "tag_change"`) ||
		!strings.Contains(out, `"tag_owners": ["tag:web"]`) {
		t.Fatalf("job: %s %s", st, out)
	}
	if !strings.Contains(f.a.hs.Stored(), "\"tagOwners\": {\n    \"tag:web\": []\n  }") {
		t.Fatalf("Headscale holds\n%s", f.a.hs.Stored())
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1 AND trigger = 'tag_change'
		AND state = 'applied' AND superseded_at IS NULL AND policy_version_id = $2`, f.a.id, base.VersionID); n != 1 {
		t.Fatal("tag_change application on the desired version")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.a.id); n != 1 {
		t.Fatal("the job must not create a version")
	}
	// the tag deleted ⇒ an empty catalog over a baseline without "tagOwners": the baseline's own bytes again
	dctx, da := f.actor(t, f.a, ActionTagDelete)
	d, err := f.tags.Delete(dctx, f.a.id, c.Tag.ID, da, "")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := wait(d.JobID); st != jobs.StatusSucceeded || strings.Contains(f.a.hs.Stored(), "tagOwners") ||
		SHA256Hex(f.a.hs.Stored()) != base.AppliedSHA256 {
		t.Fatalf("after delete: %s\n%s", st, f.a.hs.Stored())
	}

	// tenant B: the desired policy grants tag:web; an operator deletes the tag behind the API (superuser) ⇒ the next
	// job fails permanently on L6 and sends nothing
	before := len(f.b.hs.Calls())
	f.exec(t, `DELETE FROM tenant_tags WHERE tenant_id = $1 AND name = 'tag:web'`, f.b.id)
	c2 := f.create(t, f.b, "tag:other")
	if st, out := wait(c2.JobID); st != jobs.StatusFailed || !strings.Contains(out, "policy_lint_l6") {
		t.Fatalf("L6 job: %s %s", st, out)
	}
	if len(f.b.hs.Calls()) != before {
		t.Fatal("Headscale reached by a job refused on L6")
	}

	// suspended tenant ⇒ skipped (the suspension policy stays)
	f.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, f.a.id)
	c3 := f.create(t, f.a, "tag:late")
	if st, out := wait(c3.JobID); st != jobs.StatusSucceeded || !strings.Contains(out, SkipTenantNotActive) {
		t.Fatalf("suspended: %s %s", st, out)
	}
}
