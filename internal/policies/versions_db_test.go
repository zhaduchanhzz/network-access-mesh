package policies

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// versionsFx is the lifecycle side of the fixture: the api's store (mg_api_tenant) and the VersionService over the
// fake registry; the worker's Service (f.svc) runs the policy.apply jobs the API enqueues.
type versionsFx struct {
	*tagsFx
	vs  *VersionService
	now time.Time
}

func newVersionsFixture(t *testing.T) *versionsFx {
	t.Helper()
	tf := newTagsFixture(t)
	f := &versionsFx{tagsFx: tf, now: time.Now()}
	vs, err := NewVersions(tf.api, VersionsConfig{Registry: tf.reg, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	f.vs = vs
	return f
}

// as returns the request scope and the VersionActor of a member (fresh step-up).
func (f *versionsFx) as(t *testing.T, ten *tenantFx, membership uuid.UUID, action string) (context.Context, VersionActor) {
	t.Helper()
	var ident uuid.UUID
	f.scan(t, `SELECT identity_id FROM tenant_memberships WHERE id = $1`, []any{membership}, &ident)
	tid := ten.id
	ctx := audit.WithRequest(context.Background(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &ident, ActorDisplay: "member", TenantID: &tid, RequestID: "req-" + randomHex(4)})
	return ctx, VersionActor{IdentityID: ident, AuthTime: f.now.Add(-time.Minute)}
}

// runJob runs a job the API enqueued through the policy.apply handler (as the worker would).
func (f *versionsFx) runJob(t *testing.T, ten *tenantFx, id uuid.UUID) (*jobs.Run, error) {
	t.Helper()
	var raw []byte
	var kind string
	f.scan(t, `SELECT kind, input FROM provisioning_jobs WHERE id = $1`, []any{id}, &kind, &raw)
	tid := ten.id
	r := &jobs.Run{ID: id, Kind: kind, TenantID: &tid, Input: json.RawMessage(raw), Attempt: 1, MaxAttempts: 6,
		Deadline: time.Now().Add(time.Minute), Store: f.st}
	var err error
	if kind == KindDriftCheck {
		err = f.svc.runDriftJob(context.Background(), r)
	} else {
		err = f.svc.runApplyJob(context.Background(), r)
	}
	f.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, id)
	return r, err
}

func wantPolErr(t *testing.T, what string, err, kind error, reason string) {
	t.Helper()
	pe, ok := AsPolicyError(err)
	if !ok || !errors.Is(err, kind) || (reason != "" && pe.Reason != reason) {
		t.Fatalf("%s: got %v, want %v (%s)", what, err, kind, reason)
	}
}

// world inserts the tables a typed policy references in tenant ten: group eng (Admin + End User), the catalog tag
// tag:web, the resource db.
func (f *versionsFx) world(t *testing.T, ten *tenantFx) (group, tag, res uuid.UUID) {
	t.Helper()
	group, tag, res = uuid.New(), uuid.New(), uuid.New()
	f.exec(t, `INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, 'eng')`, group, ten.id)
	f.exec(t, `INSERT INTO group_members (tenant_id, group_id, membership_id) VALUES ($1, $2, $3), ($1, $2, $4)`,
		ten.id, group, ten.admin, ten.endUs)
	f.exec(t, `INSERT INTO tenant_tags (id, tenant_id, name, purpose) VALUES ($1, $2, 'tag:web', 'server')`, tag, ten.id)
	f.exec(t, `INSERT INTO network_resources (id, tenant_id, name, kind, address) VALUES ($1, $2, 'db', 'host', '10.20.0.5/32')`,
		res, ten.id)
	return group, tag, res
}

func srcJSON(group, tag, res uuid.UUID, port string) json.RawMessage {
	return json.RawMessage(`{"grants":[{"src":[{"type":"group","ref":"` + group.String() + `"}],` +
		`"dst":[{"type":"tag","ref":"` + tag.String() + `"},{"type":"resource","ref":"` + res.String() + `"}],"ip":["tcp:` + port + `"]}]}`)
}

// draft creates, validates and self-approves a version (4-eyes off) as the Admin.
func (f *versionsFx) approved(t *testing.T, ten *tenantFx, src json.RawMessage) Version {
	t.Helper()
	ctx, a := f.as(t, ten, ten.admin, ActionPolicyCreate)
	v, err := f.vs.Create(ctx, ten.id, a, NewVersion{Source: src}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, err = f.vs.Validate(ctx, ten.id, v.ID, a, v.ETag()); err != nil || v.State != VersionValidated {
		t.Fatalf("validate: %+v %v", v.ValidationReport, err)
	}
	if v, err = f.vs.Approve(ctx, ten.id, v.ID, a, v.ETag(), v.ContentSHA256); err != nil || v.State != VersionApproved {
		t.Fatalf("approve: %v", err)
	}
	return v
}

// TestPolicyLifecycle — P4-T10 (§7.3) with 4-eyes off: draft → PATCH (If-Match: 428/412; back to draft) → validate
// (render + lint + CheckPolicy dry run ⇒ validated) → self-review approve (content_sha256 of what was seen) → apply
// (desired, the previous one superseded, policy.apply enqueued in the same transaction) → the job renders groups,
// hosts and the catalog from the tables and applies them (read-back sha256, one application on the same version); a
// draft based on an older desired version ⇒ 409 stale_base; a group change re-renders (group_change, no new version);
// the desired version cannot be edited; rollback inherits the approval of the same content; reject; diff; current.
func TestPolicyLifecycle(t *testing.T) {
	f := newVersionsFixture(t)
	base, err := apply(t, f.fixture, f.a, KindBaseline, fixtureText(t, "bootstrap-policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	group, tag, res := f.world(t, f.a)
	ctx, admin := f.as(t, f.a, f.a.admin, ActionPolicyCreate)

	// create: draft, N+1, parent = the desired baseline
	v, err := f.vs.Create(ctx, f.a.id, admin, NewVersion{Source: srcJSON(group, tag, res, "80")}, nil)
	if err != nil || v.State != VersionDraft || v.Version != base.Version+1 || v.Revision != 1 || v.ParentVersionID == nil ||
		*v.ParentVersionID != base.VersionID || v.Source == nil || v.Desired {
		t.Fatalf("create: %+v %v", v, err)
	}
	if _, err := f.vs.Create(ctx, f.a.id, admin, NewVersion{Source: json.RawMessage(`{"grants":null}`)}, nil); err == nil {
		t.Fatal("grants: null must be refused")
	} else {
		wantPolErr(t, "null grants", err, ErrPolicyInvalid, "null")
	}
	// PATCH: If-Match required, a stale one refused, back to draft with a new revision
	_, err = f.vs.Update(ctx, f.a.id, v.ID, admin, "", srcJSON(group, tag, res, "443"))
	wantPolErr(t, "patch without If-Match", err, ErrPolicyPreconditionRequired, "")
	_, err = f.vs.Update(ctx, f.a.id, v.ID, admin, `"7"`, srcJSON(group, tag, res, "443"))
	wantPolErr(t, "patch stale", err, ErrPolicyPreconditionFailed, "")
	if v, err = f.vs.Update(ctx, f.a.id, v.ID, admin, v.ETag(), srcJSON(group, tag, res, "443")); err != nil ||
		v.Revision != 2 || v.State != VersionDraft {
		t.Fatalf("patch: %+v %v", v, err)
	}
	// approve before validate ⇒ 409; validate ⇒ validated with a report of the rendered policy
	_, err = f.vs.Approve(ctx, f.a.id, v.ID, admin, v.ETag(), v.ContentSHA256)
	wantPolErr(t, "approve a draft", err, ErrPolicyConflict, "not_validated")
	calls := len(f.a.hs.Calls())
	if v, err = f.vs.Validate(ctx, f.a.id, v.ID, admin, v.ETag()); err != nil || v.State != VersionValidated ||
		v.ValidationReport == nil || v.ValidationReport.Result != ResultPassed || v.ValidationReport.Check != ResultPassed ||
		v.ValidationReport.RenderedSHA256 == "" {
		t.Fatalf("validate: %+v %v", v, err)
	}
	if got := f.a.hs.Calls()[calls:]; len(got) != 1 || got[0] != "CheckPolicy" {
		t.Fatalf("validate must only dry-run the rendered policy: %v", got)
	}
	_, err = f.vs.Approve(ctx, f.a.id, v.ID, admin, v.ETag(), strings.Repeat("0", 64))
	wantPolErr(t, "approve another content", err, ErrPolicyConflict, "content_mismatch")
	if v, err = f.vs.Approve(ctx, f.a.id, v.ID, admin, v.ETag(), v.ContentSHA256); err != nil || v.State != VersionApproved ||
		v.ReviewMode == nil || *v.ReviewMode != ReviewSelf || v.ApprovedBy == nil || *v.ApprovedBy != admin.IdentityID {
		t.Fatalf("self-review: %+v %v", v, err)
	}
	// a second draft on the same base: approved, then stale once the first is applied
	other := f.approved(t, f.a, srcJSON(group, tag, res, "8443"))

	// apply: desired + superseded + policy.apply (manual) in one transaction; the job renders and applies
	acc, err := f.vs.Apply(ctx, f.a.id, v.ID, admin, nil)
	if err != nil || !acc.Version.Desired || acc.Job.Kind != KindApply || acc.Job.Status != jobs.StatusQueued {
		t.Fatalf("apply: %+v %v", acc, err)
	}
	var baseState string
	f.scan(t, `SELECT state FROM policy_versions WHERE id = $1`, []any{base.VersionID}, &baseState)
	if baseState != VersionSuperseded {
		t.Fatalf("previous desired version %s, want superseded", baseState)
	}
	run, err := f.runJob(t, f.a, acc.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := output(t, run)
	stored := f.a.hs.Stored()
	if out["state"] != StateApplied || out["mode"] != modeDesired || out["version_id"] != v.ID.String() ||
		out["applied_sha256"] != SHA256Hex(stored) || out["trigger"] != TriggerManual {
		t.Fatalf("job output %v", out)
	}
	for _, want := range []string{`"group:eng": [`, "mg-" + f.a.admin.String() + "@", "mg-" + f.a.endUs.String() + "@",
		`"db": "10.20.0.5/32"`, `"tag:web": []`, `"tcp:443"`} {
		if !strings.Contains(stored, want) {
			t.Fatalf("Headscale holds\n%s\nwant %s", stored, want)
		}
	}
	if strings.Contains(stored, "@"+f.a.slug) || strings.Contains(stored, ".test") {
		t.Fatal("an e-mail reached Headscale")
	}
	_, err = f.vs.Apply(ctx, f.a.id, other.ID, admin, nil)
	wantPolErr(t, "apply a stale base", err, ErrPolicyConflict, "stale_base")

	// a group change: the same version rendered again (group_change), no new version
	versions := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.a.id)
	f.exec(t, `INSERT INTO group_members (tenant_id, group_id, membership_id) VALUES ($1, $2, $3)`, f.a.id, group, f.a.viewer)
	run, err = f.runJob(t, f.a, enqueueApplyRun(t, f.fixture, f.a, map[string]string{"trigger": TriggerGroupChange}).ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.a.hs.Stored(), "mg-"+f.a.viewer.String()+"@") || output(t, run)["version_id"] != v.ID.String() ||
		f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.a.id) != versions {
		t.Fatalf("group change: %v\n%s", output(t, run), f.a.hs.Stored())
	}
	// the desired version cannot be edited; a platform version neither
	cur, _ := f.vs.Get(ctx, f.a.id, v.ID)
	_, err = f.vs.Update(ctx, f.a.id, v.ID, admin, cur.ETag(), srcJSON(group, tag, res, "22"))
	wantPolErr(t, "patch the desired version", err, ErrPolicyConflict, "version_is_desired")
	bv, _ := f.vs.Get(ctx, f.a.id, base.VersionID)
	_, err = f.vs.Update(ctx, f.a.id, base.VersionID, admin, bv.ETag(), srcJSON(group, tag, res, "22"))
	wantPolErr(t, "patch a baseline", err, ErrPolicyConflict, "platform_version")

	// rollback to the content of the applied version: N+1, approval inherited, desired, trigger rollback
	_, err = f.vs.Rollback(ctx, f.a.id, base.VersionID, admin, nil)
	wantPolErr(t, "rollback to a baseline", err, ErrPolicyConflict, "not_typed")
	applied := f.a.hs.Stored()
	rb, err := f.vs.Rollback(ctx, f.a.id, v.ID, admin, nil)
	if err != nil || rb.Version.State != VersionApproved || rb.Version.RollbackOf == nil || *rb.Version.RollbackOf != v.ID ||
		rb.Version.ContentSHA256 != v.ContentSHA256 || rb.Version.ApprovedBy == nil || *rb.Version.ApprovedBy != admin.IdentityID ||
		rb.Version.ParentVersionID == nil || *rb.Version.ParentVersionID != v.ID || !rb.Version.Desired {
		t.Fatalf("rollback: %+v %v", rb.Version, err)
	}
	if run, err = f.runJob(t, f.a, rb.Job.ID); err != nil || output(t, run)["trigger"] != TriggerRollback ||
		f.a.hs.Stored() != applied {
		t.Fatalf("rollback job: %v %v", err, output(t, run))
	}

	// reject: submit (peer review asked), reject with a reason; a rejected version is closed
	ctx2, _ := f.as(t, f.a, f.a.owner, ActionPolicyRejected)
	_, owner := f.as(t, f.a, f.a.owner, ActionPolicyRejected)
	nv, _ := f.vs.Create(ctx, f.a.id, admin, NewVersion{Source: srcJSON(group, tag, res, "9000")}, nil)
	nv, _ = f.vs.Validate(ctx, f.a.id, nv.ID, admin, nv.ETag())
	if nv, err = f.vs.Submit(ctx, f.a.id, nv.ID, admin, nv.ETag()); err != nil || nv.State != VersionPendingApproval {
		t.Fatalf("submit: %v", err)
	}
	_, err = f.vs.Reject(ctx2, f.a.id, nv.ID, owner, nv.ETag(), " ")
	wantPolErr(t, "reject without a reason", err, ErrPolicyInvalid, "invalid_reason")
	if nv, err = f.vs.Reject(ctx2, f.a.id, nv.ID, owner, nv.ETag(), "port 9000 is not needed"); err != nil || nv.State != VersionRejected {
		t.Fatalf("reject: %v", err)
	}
	_, err = f.vs.Update(ctx, f.a.id, nv.ID, admin, nv.ETag(), srcJSON(group, tag, res, "22"))
	wantPolErr(t, "patch a rejected version", err, ErrPolicyConflict, "version_closed")

	// diff of the other draft against the desired version; current
	d, err := f.vs.Diff(ctx, f.a.id, other.ID, nil)
	if err != nil || d.AgainstID == nil || *d.AgainstID != rb.Version.ID || len(d.GrantsAdded) != 1 || len(d.GrantsRemoved) != 1 ||
		!strings.Contains(d.GrantsAdded[0], "tcp:8443") || d.LinesOmitted {
		t.Fatalf("diff: %+v %v", d, err)
	}
	c, err := f.vs.Current(ctx, f.a.id)
	if err != nil || c.Desired == nil || c.Desired.ID != rb.Version.ID || c.Applied == nil || c.Applied.AppliedSHA256 != SHA256Hex(applied) ||
		c.Applied.Trigger != TriggerRollback || c.FourEyes {
		t.Fatalf("current: %+v %v", c, err)
	}
	// another tenant sees none of it
	if _, err := f.vs.Get(ctx, f.b.id, v.ID); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("tenant B reads tenant A's version: %v", err)
	}
	for _, action := range []string{ActionPolicyCreate, ActionPolicyUpdate, ActionPolicyValidate, ActionPolicyApproved,
		ActionPolicyDesired, ActionPolicyRollback, ActionPolicySubmit, ActionPolicyRejected} {
		if f.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2`, f.a.id, action) == 0 {
			t.Errorf("no audit event %s", action)
		}
	}
	var mode string
	f.scan(t, `SELECT details->>'review_mode' FROM audit_events WHERE tenant_id = $1 AND action = $2 ORDER BY occurred_at LIMIT 1`,
		[]any{f.a.id, ActionPolicyApproved}, &mode)
	if mode != ReviewSelf {
		t.Fatalf("policy.approved review_mode %q", mode)
	}
}

// TestPolicyFourEyes — TenantSettings.policy.four_eyes (read only): approve only from pending_approval, never by the
// author or the submitter (403), review_mode peer; apply and rollback need a step-up (401 reauth_required); an
// acknowledgement only an Owner may give (L4) needs an Owner as the approver.
func TestPolicyFourEyes(t *testing.T) {
	f := newVersionsFixture(t)
	if _, err := apply(t, f.fixture, f.a, KindBaseline, fixtureText(t, "bootstrap-policy.hujson")); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE tenants SET settings = '{"policy":{"four_eyes":true}}' WHERE id = $1`, f.a.id)
	group, tag, res := f.world(t, f.a)
	ctx, admin := f.as(t, f.a, f.a.admin, ActionPolicyCreate)
	octx, owner := f.as(t, f.a, f.a.owner, ActionPolicyApproved)
	v, _ := f.vs.Create(ctx, f.a.id, admin, NewVersion{Source: srcJSON(group, tag, res, "443")}, nil)
	v, _ = f.vs.Validate(ctx, f.a.id, v.ID, admin, v.ETag())
	_, err := f.vs.Approve(ctx, f.a.id, v.ID, admin, v.ETag(), v.ContentSHA256)
	wantPolErr(t, "self-review with 4-eyes", err, ErrPolicyConflict, "review_required")
	if v, err = f.vs.Submit(ctx, f.a.id, v.ID, admin, v.ETag()); err != nil {
		t.Fatal(err)
	}
	_, err = f.vs.Approve(ctx, f.a.id, v.ID, admin, v.ETag(), v.ContentSHA256)
	wantPolErr(t, "the submitter approves", err, ErrPolicyForbidden, "self_approval")
	if v, err = f.vs.Approve(octx, f.a.id, v.ID, owner, v.ETag(), v.ContentSHA256); err != nil || *v.ReviewMode != ReviewPeer ||
		*v.ApprovedBy != owner.IdentityID || *v.SubmittedBy != admin.IdentityID {
		t.Fatalf("peer approval: %+v %v", v, err)
	}
	stale := owner
	stale.AuthTime = f.now.Add(-StepUpWindow - time.Minute)
	_, err = f.vs.Apply(octx, f.a.id, v.ID, stale, nil)
	wantPolErr(t, "apply without step-up", err, ErrPolicyReauthRequired, "step_up_required")
	if _, err := f.vs.Apply(octx, f.a.id, v.ID, owner, nil); err != nil {
		t.Fatalf("apply with step-up: %v", err)
	}
	if c, _ := f.vs.Current(ctx, f.a.id); !c.FourEyes || !c.ApplyStepUp {
		t.Fatalf("current: %+v", c)
	}

	// L4 acknowledged: only an Owner's approval counts
	wild := json.RawMessage(`{"grants":[{"src":[{"type":"autogroup","ref":"member"}],"dst":[{"type":"cidr","ref":"*"}],"ip":["*"]}],` +
		`"acknowledgements":[{"rule":"L4","reason":"lab tenant, open by design"}]}`)
	w, _ := f.vs.Create(ctx, f.a.id, admin, NewVersion{Source: wild}, nil)
	if w, err = f.vs.Validate(ctx, f.a.id, w.ID, admin, w.ETag()); err != nil || w.State != VersionValidated ||
		!w.ValidationReport.OwnerAcknowledged() {
		t.Fatalf("validate L4 acknowledged: %+v %v", w.ValidationReport, err)
	}
	w, _ = f.vs.Submit(ctx, f.a.id, w.ID, admin, w.ETag())
	vctx, viewer := f.as(t, f.a, f.a.viewer, ActionPolicyApproved)
	_, err = f.vs.Approve(vctx, f.a.id, w.ID, viewer, w.ETag(), w.ContentSHA256)
	wantPolErr(t, "L4 approved by a non-Owner", err, ErrPolicyForbidden, "owner_acknowledgement_required")
	if _, err := f.vs.Approve(octx, f.a.id, w.ID, owner, w.ETag(), w.ContentSHA256); err != nil {
		t.Fatalf("Owner approval: %v", err)
	}
	// unacknowledged: validate keeps it a draft with the error
	bare := json.RawMessage(`{"grants":[{"src":[{"type":"autogroup","ref":"member"}],"dst":[{"type":"cidr","ref":"*"}],"ip":["*"]}]}`)
	b, _ := f.vs.Create(ctx, f.a.id, admin, NewVersion{Source: bare}, nil)
	calls := len(f.a.hs.Calls())
	if b, err = f.vs.Validate(ctx, f.a.id, b.ID, admin, b.ETag()); err != nil || b.State != VersionDraft ||
		b.ValidationReport.Result != ResultFailed || b.ValidationReport.Check != "skipped" {
		t.Fatalf("validate L4: %+v %v", b.ValidationReport, err)
	}
	if len(f.a.hs.Calls()) != calls {
		t.Fatal("a blocking lint must not reach Headscale")
	}
	// Headscale refuses the dry run ⇒ draft with a check error; unreachable ⇒ 503, nothing changes
	c, _ := f.vs.Create(ctx, f.a.id, admin, NewVersion{Source: srcJSON(group, tag, res, "8080")}, nil)
	f.a.hs.mu.Lock()
	f.a.hs.checkErr = &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindPolicyRejected}
	f.a.hs.mu.Unlock()
	if c, err = f.vs.Validate(ctx, f.a.id, c.ID, admin, c.ETag()); err != nil || c.State != VersionDraft || c.ValidationReport.Check != ResultFailed {
		t.Fatalf("check refused: %+v %v", c.ValidationReport, err)
	}
	f.a.hs.mu.Lock()
	f.a.hs.checkErr = &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindUnavailable}
	f.a.hs.mu.Unlock()
	_, err = f.vs.Validate(ctx, f.a.id, c.ID, admin, c.ETag())
	wantPolErr(t, "instance unavailable", err, ErrPolicyInstanceUnavailable, "")
	f.a.hs.mu.Lock()
	f.a.hs.checkErr = nil
	f.a.hs.mu.Unlock()
}

// TestTypedPipelineRefusals — the job's lint runs before any Headscale call: a group deleted after the approval ⇒ the
// job fails permanently on L6 (policy.lint_rejected, nothing sent). The deny-all of a tenant being suspended (an
// unfinished tenant.suspend) is applied by policy.apply without the lifecycle lock (§11.4); a suspended tenant keeps
// it on a catalog/group change.
func TestTypedPipelineRefusals(t *testing.T) {
	f := newVersionsFixture(t)
	if _, err := apply(t, f.fixture, f.a, KindBaseline, fixtureText(t, "bootstrap-policy.hujson")); err != nil {
		t.Fatal(err)
	}
	group, tag, res := f.world(t, f.a)
	ctx, admin := f.as(t, f.a, f.a.admin, ActionPolicyCreate)
	v := f.approved(t, f.a, srcJSON(group, tag, res, "443"))
	acc, err := f.vs.Apply(ctx, f.a.id, v.ID, admin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.runJob(t, f.a, acc.Job.ID); err != nil {
		t.Fatal(err)
	}
	stored := f.a.hs.Stored()
	f.exec(t, `DELETE FROM group_members WHERE group_id = $1`, group)
	f.exec(t, `DELETE FROM groups WHERE id = $1`, group)
	calls := len(f.a.hs.Calls())
	_, err = f.runJob(t, f.a, enqueueApplyRun(t, f.fixture, f.a, map[string]string{"trigger": TriggerGroupChange}).ID)
	var je *jobs.Error
	if !errors.As(err, &je) || !je.Permanent || je.Code != "policy_lint_l6" || len(f.a.hs.Calls()) != calls || f.a.hs.Stored() != stored {
		t.Fatalf("L6 at apply time: %v, calls %v", err, f.a.hs.Calls()[calls:])
	}
	if f.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'policy.lint_rejected'
		AND details->>'rule' = 'L6'`, f.a.id) == 0 {
		t.Fatal("no policy.lint_rejected for the refused render")
	}

	// tenant B is being suspended: an unfinished tenant.suspend ⇒ the suspension policy, without waiting for the lock
	if _, err := apply(t, f.fixture, f.b, KindBaseline, fixtureText(t, "test-allow-intra.hujson")); err != nil {
		t.Fatal(err)
	}
	susp := uuid.New()
	f.exec(t, `INSERT INTO provisioning_jobs (id, tenant_id, kind, dedupe_key, lock_key, status, attempt, max_attempts)
		VALUES ($1, $2, 'tenant.suspend', $3, $3, 'queued', 0, 5)`, susp, f.b.id, jobs.LockKey(f.b.id))
	run, err := f.runJob(t, f.b, enqueueApplyRun(t, f.fixture, f.b, map[string]string{"trigger": TriggerSuspend}).ID)
	deny, _ := Lint(f.svc.susText)
	if err != nil || output(t, run)["mode"] != modeSuspension || output(t, run)["trigger"] != TriggerSuspend ||
		f.b.hs.Stored() != deny.Applied {
		t.Fatalf("suspension: %v %v\n%s", err, output(t, run), f.b.hs.Stored())
	}
	// a group change while the tenant is suspending: the suspension again (level-triggered)
	if run, err = f.runJob(t, f.b, enqueueApplyRun(t, f.fixture, f.b, map[string]string{"trigger": TriggerTagChange}).ID); err != nil ||
		output(t, run)["mode"] != modeSuspension {
		t.Fatalf("tag change while suspending: %v %v", err, output(t, run))
	}
	f.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, susp)
	f.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, f.b.id)
	if run, err = f.runJob(t, f.b, enqueueApplyRun(t, f.fixture, f.b, map[string]string{"trigger": TriggerGroupChange}).ID); err != nil ||
		output(t, run)["skipped"] != SkipTenantNotActive {
		t.Fatalf("suspended, group change: %v %v", err, output(t, run))
	}
	if run, err = f.runJob(t, f.b, enqueueApplyRun(t, f.fixture, f.b, map[string]string{"trigger": TriggerDriftRepair}).ID); err != nil ||
		output(t, run)["mode"] != modeSuspension || f.b.hs.Stored() != deny.Applied {
		t.Fatalf("suspended, drift repair: %v %v", err, output(t, run))
	}
}

// fakeEdge records the edge detaches of the drift check.
type fakeEdge struct{ detached []uuid.UUID }

func (e *fakeEdge) DetachEdge(_ context.Context, _, instance, _ uuid.UUID) error {
	e.detached = append(e.detached, instance)
	return nil
}

// TestDriftCheck — policy.drift_check (§7.3, §13.4): in sync ⇒ ok; another policy on the instance ⇒ High
// instance.policy_drift + policy.apply (drift_repair), which applies the desired state again; no policy (allow-all) ⇒
// Critical instance.policy_missing + the edge detached, the job fails; the API key refused ⇒ Critical
// instance.database_replaced, no detach (never an automatic apikey.bootstrap). The schedule enqueues one check per
// instance and period.
func TestDriftCheck(t *testing.T) {
	f := newVersionsFixture(t)
	edge := &fakeEdge{}
	f.svc.edge = edge
	base, err := apply(t, f.fixture, f.a, KindBaseline, fixtureText(t, "test-allow-intra.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	drift := func() (*jobs.Run, error) {
		t.Helper()
		var id uuid.UUID
		err := f.st.WithTenantJobTx(context.Background(), f.a.id, func(tx *store.Tx) error {
			e, err := jobs.Enqueue(context.Background(), tx, jobs.Spec{Kind: KindDriftCheck, TenantID: &f.a.id,
				InstanceID: &f.a.instance, Slot: randomHex(4)})
			id = e.Job.ID
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return f.runJob(t, f.a, id)
	}
	if r, err := drift(); err != nil || output(t, r)["state"] != DriftInSync {
		t.Fatalf("in sync: %v %v", err, output(t, r))
	}
	// changed out of band
	f.a.hs.mu.Lock()
	f.a.hs.stored = `{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`
	f.a.hs.mu.Unlock()
	r, err := drift()
	out := output(t, r)
	if err != nil || out["state"] != DriftDrift || out["repair_job_id"] == nil {
		t.Fatalf("drift: %v %v", err, out)
	}
	if f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2 AND severity = 'high'`,
		f.a.id, SecPolicyDrift) != 1 {
		t.Fatal("no High instance.policy_drift event")
	}
	repair := uuid.MustParse(out["repair_job_id"].(string))
	if rr, err := f.runJob(t, f.a, repair); err != nil || output(t, rr)["trigger"] != TriggerDriftRepair ||
		SHA256Hex(f.a.hs.Stored()) != base.AppliedSHA256 {
		t.Fatalf("repair: %v %v", err, output(t, rr))
	}
	if r, err := drift(); err != nil || output(t, r)["state"] != DriftInSync {
		t.Fatalf("after the repair: %v %v", err, output(t, r))
	}
	// no policy: Critical + edge detached + permanent failure
	f.a.hs.mu.Lock()
	f.a.hs.getErr = &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy}
	f.a.hs.mu.Unlock()
	r, err = drift()
	var je *jobs.Error
	if !errors.As(err, &je) || je.Code != "no_policy" || output(t, r)["edge_detached"] != true || len(edge.detached) != 1 ||
		edge.detached[0] != f.a.instance {
		t.Fatalf("no policy: %v %v %v", err, output(t, r), edge.detached)
	}
	if f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2 AND severity = 'critical'`,
		f.a.id, SecPolicyMissing) != 1 {
		t.Fatal("no Critical instance.policy_missing event")
	}
	// API key refused: Critical, no detach, no bootstrap
	f.a.hs.mu.Lock()
	f.a.hs.getErr = &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindAPIKeyRejected}
	f.a.hs.mu.Unlock()
	r, err = drift()
	if !errors.As(err, &je) || je.Code != "database_replaced" || len(edge.detached) != 1 || output(t, r)["state"] != DriftAPIKeyRejected {
		t.Fatalf("api key rejected: %v %v", err, output(t, r))
	}
	if f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2 AND severity = 'critical'`,
		f.a.id, SecDatabaseReplaced) != 1 {
		t.Fatal("no Critical instance.database_replaced event")
	}
	f.a.hs.mu.Lock()
	f.a.hs.getErr = nil
	f.a.hs.mu.Unlock()

	// the schedule: the first tick notes the period, the next period enqueues one check per instance
	sc := f.svc.NewScheduler(DriftSchedulerConfig{Interval: time.Minute, Tick: time.Second})
	now := time.Now()
	if n, err := sc.Tick(context.Background(), now); err != nil || n != 0 {
		t.Fatalf("first tick: %d %v", n, err)
	}
	if _, err := sc.Tick(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = $2 AND status = 'queued'`,
		f.a.id, KindDriftCheck) != 1 {
		t.Fatal("the schedule did not enqueue the drift check of tenant A")
	}
}
