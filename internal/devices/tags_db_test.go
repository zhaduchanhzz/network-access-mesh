package devices

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
)

// fakeCatalog is the tag catalog of the tests (policies.TagService in apps/): the declared names per tenant; a refusal of
// the input carries Validation() like *policies.TagError.
type fakeCatalog struct {
	tags  map[uuid.UUID][]string
	calls int
}

type catalogRefusal struct {
	reason string
	tags   []string
}

func (e *catalogRefusal) Error() string { return "catalog: " + e.reason }
func (e *catalogRefusal) Validation() (string, string, []string, bool) {
	return "tags", e.reason, e.tags, true
}

func (c *fakeCatalog) CheckTags(_ context.Context, tenantID uuid.UUID, names []string, _ string) ([]string, error) {
	c.calls++
	out := slices.Clone(names)
	sort.Strings(out)
	out = slices.Compact(out)
	var missing []string
	for _, n := range out {
		if !slices.Contains(c.tags[tenantID], n) {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, &catalogRefusal{reason: "tag_not_in_catalog", tags: missing}
	}
	return out, nil
}

// TestSetTags — PUT /devices/{id}/tags (P4-T15): an empty list, a missing If-Match and a tag outside the tenant's
// catalog are refused before anything is written or sent (422 / 428 / 422 listing the tags); a stale If-Match — the
// hash of the tags Headscale holds NOW, read with GetNode — is 412; a tag Headscale's policy does not declare is 422;
// success replaces the set on Headscale and in the register (the owner cleared — a tagged node has no user, PL-09) with
// the audit pair device.tag.requested/succeeded; another tenant's device is not found.
func TestSetTags(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, time.Now(), nil))
	if _, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	dev := f.deviceOfNode(t, a, 1)
	a.hs.ResetCalls()
	identity := uuid.New()
	actx := actorCtx(identity, a.id, ActionTag)

	// no catalog wired ⇒ fail closed
	if _, err := f.api.SetTags(actx, a.id, dev, Access{}, `"x"`, []string{"tag:web"}); !isReason(err, ReasonNoTagCatalog) {
		t.Fatalf("without a catalog: %v", err)
	}
	cat := &fakeCatalog{tags: map[uuid.UUID][]string{a.id: {"tag:web", "tag:db"}, f.b.id: {"tag:only-b"}}}
	f.api.tags = cat
	etag := setETag(nil)

	if _, err := f.api.SetTags(actx, a.id, dev, Access{}, etag, nil); !isCode(err, CodeValidationFailed) {
		t.Errorf("empty list: %v", err)
	}
	if _, err := f.api.SetTags(actx, a.id, dev, Access{}, "", []string{"tag:web"}); !isCode(err, CodePreconditionReq) {
		t.Errorf("no If-Match: %v", err)
	}
	_, err := f.api.SetTags(actx, a.id, dev, Access{}, etag, []string{"tag:web", "tag:only-b", "tag:nope"})
	e, ok := AsError(err)
	if !ok || e.Code != CodeValidationFailed || e.Field != "tags" || e.Reason != "tag_not_in_catalog" ||
		!strings.Contains(e.Detail, "tag:nope, tag:only-b") {
		t.Errorf("undeclared tags: %v", err)
	}
	if n := a.hs.Calls(devicestest.OpGetNode) + a.hs.Calls(devicestest.OpSetTags); n != 0 {
		t.Errorf("refused requests reached Headscale %d times", n)
	}
	if got := f.auditOf(t, dev.String()); len(got) != 0 {
		t.Errorf("refused requests audited as operations: %v", got)
	}

	// stale If-Match: Headscale is read, never written
	if _, err := f.api.SetTags(actx, a.id, dev, Access{}, `"0123"`, []string{"tag:web"}); !isCode(err, CodePreconditionFailed) {
		t.Errorf("stale If-Match: %v", err)
	}
	if a.hs.Calls(devicestest.OpGetNode) != 1 || a.hs.Calls(devicestest.OpSetTags) != 0 {
		t.Errorf("stale If-Match calls: get %d set %d", a.hs.Calls(devicestest.OpGetNode), a.hs.Calls(devicestest.OpSetTags))
	}
	// the policy applied on Headscale does not declare tag:db yet (policy.apply not run) ⇒ 422 from Headscale
	a.hs.SetPolicyTags("tag:web")
	if _, err := f.api.SetTags(actx, a.id, dev, Access{}, etag, []string{"tag:db"}); !isCode(err, CodeValidationFailed) {
		t.Errorf("tag outside Headscale's policy: %v", err)
	}
	if r := f.row(t, dev); len(r.Tags) != 0 || r.OwnerMembershipID == nil {
		t.Errorf("register changed by a refused write: %+v", r.Tags)
	}
	a.hs.SetPolicyTags("tag:web", "tag:db")

	// success
	d, err := f.api.SetTags(actx, a.id, dev, Access{}, etag, []string{"tag:web", "tag:db", "tag:web"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.Tags, []string{"tag:db", "tag:web"}) || d.Owner != nil || d.TagsETag != setETag([]string{"tag:web", "tag:db"}) {
		t.Errorf("device after tagging: %+v", d)
	}
	if n, _ := a.hs.Node(1); !slices.Equal(n.Tags, []string{"tag:db", "tag:web"}) {
		t.Errorf("Headscale holds %v", n.Tags)
	}
	if r := f.row(t, dev); !slices.Equal(r.Tags, []string{"tag:db", "tag:web"}) || r.OwnerMembershipID != nil {
		t.Errorf("register %v owner %v", r.Tags, r.OwnerMembershipID)
	}
	want := []string{"device.tag.requested/success", "device.tag.failed/failure", "device.tag.requested/success",
		"device.tag.failed/failure", "device.tag.requested/success", "device.tag.succeeded/success"}
	if got := f.auditOf(t, dev.String()); !slices.Equal(got, want) {
		t.Errorf("audit: %v", got)
	}
	// the old ETag is stale now
	if _, err := f.api.SetTags(actx, a.id, dev, Access{}, etag, []string{"tag:web"}); !isCode(err, CodePreconditionFailed) {
		t.Errorf("reused ETag: %v", err)
	}

	// isolation: tenant B never reaches tenant A's device (its catalog check passes, the device is not found)
	if _, err := f.api.SetTags(actorCtx(identity, f.b.id, ActionTag), f.b.id, dev, Access{}, d.TagsETag,
		[]string{"tag:only-b"}); !isCode(err, CodeNotFound) {
		t.Errorf("cross-tenant: %v", err)
	}
	// node gone from Headscale ⇒ 404
	a.hs.RemoveNode(1)
	if _, err := f.api.SetTags(actx, a.id, dev, Access{}, d.TagsETag, []string{"tag:web"}); !isReason(err, ReasonNodeGone) {
		t.Errorf("node gone: %v", err)
	}
	// catalog infrastructure error ⇒ internal, never a validation
	if e, ok := AsError(catalogError(errors.New("db down"))); !ok || e.Code != CodeInternal {
		t.Errorf("catalog error mapped to %v", e)
	}
}
