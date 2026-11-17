package policies

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

func fixtureText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "infrastructure", "headscale", "templates", name)) //nolint:gosec // G304: fixture of the repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// portPolicy allows tcp:<port> between members (a distinct, valid policy per port).
func portPolicy(port int) string {
	return fmt.Sprintf("// fixture %d\n{\"grants\": [{\"src\": [\"autogroup:member\"], \"dst\": [\"autogroup:member\"], \"ip\": [\"tcp:%d\"]},], \"ssh\": []}\n", port, port)
}

func apply(t *testing.T, f *fixture, ten *tenantFx, kind, text string) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return f.svc.Apply(ctx, ApplyRequest{TenantID: ten.id, Kind: kind, HuJSON: text, Actor: "test"})
}

// TestApplyAllowFixtureReadbackMatches — the verification of P3-T08a on the core's side: the allow fixture is stored as
// a version from its HuJSON text, applied CheckPolicy → SetPolicy → GetPolicy, and the read-back sha256 equals
// applied_sha256; the application is the instance's current one, the version is desired, the audit pair is complete
// and the Tenant Owner and Admin get the policy.applied notification. Re-applying the same content reuses the version
// and supersedes the previous application; a new content is version N+1 and supersedes the previous version.
func TestApplyAllowFixtureReadbackMatches(t *testing.T) {
	f := newFixture(t)
	allow := fixtureText(t, "test-allow-intra.hujson")
	res, err := apply(t, f, f.a, KindBaseline, allow)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := Lint(allow)
	switch {
	case res.State != StateApplied || res.ReadbackSHA256 != res.AppliedSHA256 || res.AppliedSHA256 != doc.AppliedSHA256:
		t.Fatalf("result %+v", res)
	case SHA256Hex(f.a.hs.Stored()) != res.AppliedSHA256 || f.a.hs.Stored() != doc.Applied:
		t.Fatalf("Headscale holds %q", f.a.hs.Stored())
	case !res.VersionCreated || res.Version != 1 || res.ContentSHA256 != SHA256Hex(allow):
		t.Fatalf("version %+v", res)
	}
	if got := f.a.hs.Calls(); fmt.Sprint(got) != "[CheckPolicy SetPolicy GetPolicy]" {
		t.Fatalf("calls %v", got)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1 AND id = $2 AND kind = 'baseline'
		AND state = 'approved' AND source_hujson = $3 AND content_sha256 = $4 AND approved_by IS NULL
		AND approved_content_sha256 = content_sha256`, f.a.id, res.VersionID, allow, SHA256Hex(allow)); n != 1 {
		t.Fatal("version row")
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE id = $1 AND desired_policy_version_id = $2`, f.a.id, res.VersionID); n != 1 {
		t.Fatal("desired version not set")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND state = 'applied' AND superseded_at IS NULL
		AND applied_hujson = $2 AND applied_sha256 = $3 AND trigger = 'manual' AND finished_at IS NOT NULL
		AND headscale_updated_at IS NOT NULL AND instance_id = $4 AND inputs_sha256 = $5`, res.ApplicationID, doc.Applied,
		doc.AppliedSHA256, f.a.instance, doc.ContentSHA256); n != 1 {
		t.Fatal("application row")
	}
	if n := f.count(t, `SELECT count(DISTINCT operation_id) FROM audit_events WHERE tenant_id = $1 AND resource_id = $2
		AND action IN ('policy.apply.requested', 'policy.apply.succeeded') AND actor_type = 'system'
		HAVING count(*) = 2`, f.a.id, res.ApplicationID.String()); n != 1 {
		t.Fatal("audit pair requested/succeeded")
	}
	// policy.applied → Owner + Admin (not Viewer, not End User), one e-mail job each.
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'policy.applied'
		AND recipient_membership_id IN ($2, $3) AND status = 'pending' AND payload ->> 'application_id' = $4`,
		f.a.id, f.a.owner, f.a.admin, res.ApplicationID.String()); n != 2 {
		t.Fatalf("policy.applied notifications: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE kind = 'policy.applied'`); n != 2 {
		t.Fatalf("notifications in total: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = 'notification.send'`, f.a.id); n != 2 {
		t.Fatalf("notification.send jobs: %d", n)
	}

	// Same content again: version reused, previous application superseded.
	again, err := apply(t, f, f.a, KindBaseline, allow)
	if err != nil || again.VersionCreated || again.VersionID != res.VersionID || again.State != StateApplied {
		t.Fatalf("re-apply: %+v %v", again, err)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND superseded_at IS NOT NULL AND state = 'applied'`,
		res.ApplicationID); n != 1 {
		t.Fatal("first application not superseded")
	}
	// Deny-all baseline: version 2, version 1 superseded.
	base := fixtureText(t, "bootstrap-policy.hujson")
	b, err := apply(t, f, f.a, KindBaseline, base)
	if err != nil || b.Version != 2 || !b.VersionCreated {
		t.Fatalf("baseline: %+v %v", b, err)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE id = $1 AND state = 'superseded'`, res.VersionID); n != 1 {
		t.Fatal("version 1 not superseded")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE id = $1 AND parent_version_id = $2`, b.VersionID, res.VersionID); n != 1 {
		t.Fatal("parent of version 2")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE instance_id = $1 AND state = 'applied' AND superseded_at IS NULL`,
		f.a.instance); n != 1 {
		t.Fatal("exactly one current application")
	}
	// Tenant B untouched.
	if f.b.hs.Stored() != "" || f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1`, f.b.id) != 0 {
		t.Fatal("tenant B touched")
	}
}

// TestApplyLintBlocksBeforeHeadscale: an empty policy, whitespace, a policy without "grants", "grants": null and the
// fixture with its grants removed are refused by the lint — the registry is never asked for the instance, nothing is
// stored, only policy.lint_rejected is audited.
func TestApplyLintBlocksBeforeHeadscale(t *testing.T) {
	f := newFixture(t)
	cases := map[string]string{
		"empty": "", "whitespace": "  \n", "no grants": `{"ssh": []}`, "grants null": `{"grants": null}`,
		"only groups": "// allow-all if sent\n{\"groups\": {\"group:x\": []}}\n",
	}
	for name, doc := range cases {
		_, err := apply(t, f, f.a, KindBaseline, doc)
		le, ok := IsLint(err)
		if !ok || (le.Rule != RuleL1 && le.Rule != RuleL2) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if f.reg.count() != 0 || len(f.a.hs.Calls()) != 0 {
		t.Fatalf("Headscale reached: registry %d calls %v", f.reg.count(), f.a.hs.Calls())
	}
	for _, table := range []string{"policy_versions", "policy_applications", "notification_outbox"} {
		if n := f.count(t, "SELECT count(*) FROM "+table); n != 0 {
			t.Errorf("%s: %d rows", table, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'policy.lint_rejected'
		AND outcome = 'failure' AND details ->> 'rule' IN ('L1', 'L2') AND details ? 'error_code'`, f.a.id); n != len(cases) {
		t.Fatalf("lint audit events: %d", n)
	}
	// A tenant that does not exist: refused, nothing audited.
	if _, err := f.svc.Apply(context.Background(), ApplyRequest{TenantID: uuid.New(), HuJSON: ""}); err == nil {
		t.Fatal("unknown tenant accepted")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE action = 'policy.lint_rejected'`); n != len(cases) {
		t.Fatalf("audit for an unknown tenant: %d", n)
	}
}

// TestApplyRefusedIsNotApplied: Headscale refuses the policy at CheckPolicy (NotApplied) ⇒ failed policy_rejected,
// SetPolicy never called, the running policy and the desired version unchanged, the audit pair closed with .failed.
func TestApplyRefusedIsNotApplied(t *testing.T) {
	f := newFixture(t)
	first, err := apply(t, f, f.a, KindBaseline, portPolicy(1000))
	if err != nil {
		t.Fatal(err)
	}
	before := f.a.hs.Stored()
	f.a.hs.checkErr = &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindPolicyRejected,
		Outcome: headscale.OutcomeNotApplied}
	res, err := apply(t, f, f.a, KindBaseline, portPolicy(2000))
	var ae *ApplyError
	if !errors.As(err, &ae) || ae.Code != CodePolicyRejected || res.State != StateFailed || res.Reasserted {
		t.Fatalf("err %v res %+v", err, res)
	}
	if f.a.hs.Stored() != before {
		t.Fatal("the running policy changed")
	}
	calls := f.a.hs.Calls()
	if calls[len(calls)-1] != "CheckPolicy" {
		t.Fatalf("calls after the refusal: %v", calls)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND state = 'failed'
		AND error_code = 'policy_rejected' AND finished_at IS NOT NULL`, res.ApplicationID); n != 1 {
		t.Fatal("failed row")
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE id = $1 AND desired_policy_version_id = $2`, f.a.id, first.VersionID); n != 1 {
		t.Fatal("desired version changed by a failed application")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND state = 'applied' AND superseded_at IS NULL`,
		first.ApplicationID); n != 1 {
		t.Fatal("the current application changed")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'policy.apply.failed'
		AND details ->> 'reason' = 'policy_rejected'`, res.ApplicationID.String()); n != 1 {
		t.Fatal("audit .failed")
	}
	if n := f.count(t, `SELECT count(*) FROM notification_outbox WHERE payload ->> 'application_id' = $1`, res.ApplicationID.String()); n != 0 {
		t.Fatal("a failed application notified")
	}
}

// TestApplyUnknownOutcomeReasserts — §7.3/V-26: SetPolicy answers an error after the instance swapped the policy in
// memory (OutcomeUnknown) ⇒ the row goes unknown, the previous applied policy is sent again and read back, then the
// row is failed (outcome_unknown, reasserted) and the previous application stays current. When re-asserting fails too,
// a security event policy.state_unknown is raised.
func TestApplyUnknownOutcomeReasserts(t *testing.T) {
	f := newFixture(t)
	first, err := apply(t, f, f.a, KindBaseline, portPolicy(1000))
	if err != nil {
		t.Fatal(err)
	}
	prev := f.a.hs.Stored()
	f.a.hs.swapOnErr = true
	f.a.hs.setErrs = []error{&headscale.Error{Op: headscale.OpSetPolicy, Kind: headscale.KindUnavailable,
		Outcome: headscale.OutcomeUnknown}}
	res, err := apply(t, f, f.a, KindBaseline, portPolicy(2000))
	var ae *ApplyError
	if !errors.As(err, &ae) || ae.Code != CodeOutcomeUnknown || !res.Reasserted {
		t.Fatalf("err %v res %+v", err, res)
	}
	if f.a.hs.Stored() != prev {
		t.Fatalf("the previous policy was not re-asserted: %q", f.a.hs.Stored())
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND state = 'applied' AND superseded_at IS NULL`,
		first.ApplicationID); n != 1 {
		t.Fatal("the previous application is no longer current")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND state = 'failed' AND error_code = 'outcome_unknown'`,
		res.ApplicationID); n != 1 {
		t.Fatal("failed row")
	}
	if n := f.count(t, `SELECT count(*) FROM security_events WHERE kind = 'policy.state_unknown'`); n != 0 {
		t.Fatal("security event although re-asserted")
	}
	// Re-assert fails as well: unknown state ⇒ security event, still recorded failed.
	f.a.hs.setErrs = []error{
		&headscale.Error{Op: headscale.OpSetPolicy, Kind: headscale.KindUnavailable, Outcome: headscale.OutcomeUnknown},
		&headscale.Error{Op: headscale.OpSetPolicy, Kind: headscale.KindUnavailable, Outcome: headscale.OutcomeUnknown}}
	res2, err := apply(t, f, f.a, KindBaseline, portPolicy(3000))
	if !errors.As(err, &ae) || res2.Reasserted || res2.State != StateFailed {
		t.Fatalf("err %v res %+v", err, res2)
	}
	if n := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = 'policy.state_unknown'
		AND severity = 'high' AND details ->> 'application_id' = $2`, f.a.id, res2.ApplicationID.String()); n != 1 {
		t.Fatal("no security event for an unknown state")
	}
}

// TestApplyReadbackMismatch: GetPolicy returns something else than what was sent ⇒ failed readback_mismatch after
// re-asserting the previous policy; a failing GetPolicy ⇒ readback_failed.
func TestApplyReadbackMismatch(t *testing.T) {
	f := newFixture(t)
	if _, err := apply(t, f, f.a, KindBaseline, portPolicy(1000)); err != nil {
		t.Fatal(err)
	}
	f.a.hs.mangle = func(s string) string { return s + " " }
	res, err := apply(t, f, f.a, KindBaseline, portPolicy(2000))
	var ae *ApplyError
	if !errors.As(err, &ae) || ae.Code != CodeReadbackMismatch || res.ReadbackSHA256 == res.AppliedSHA256 {
		t.Fatalf("err %v res %+v", err, res)
	}
	f.a.hs.mangle = nil
	f.a.hs.getErr = &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindUnavailable}
	res, err = apply(t, f, f.a, KindBaseline, portPolicy(3000))
	if !errors.As(err, &ae) || ae.Code != CodeReadbackFailed || res.State != StateFailed {
		t.Fatalf("err %v res %+v", err, res)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1 AND state = 'failed'`, f.a.id); n != 2 {
		t.Fatalf("failed rows %d", n)
	}
}

// TestApplySerializedPerTenant: concurrent applications of one tenant never overlap at Headscale (per-tenant advisory
// lock), while two tenants proceed in parallel; afterwards exactly one application is current and it is the one
// Headscale holds; the recorded intervals [created_at, finished_at] of the tenant's applications are disjoint.
func TestApplySerializedPerTenant(t *testing.T) {
	f := newFixture(t)
	g := &concurrency{}
	for _, h := range []*fakeHS{f.a.hs, f.b.hs} {
		h.delay, h.global = 60*time.Millisecond, g
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := apply(t, f, f.a, KindBaseline, portPolicy(8001+i))
			errs <- err
		}()
	}
	for i := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := apply(t, f, f.b, KindBaseline, portPolicy(9001+i))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.a.hs.max != 1 || f.b.hs.max != 1 {
		t.Fatalf("calls overlapped inside a tenant: A %d, B %d", f.a.hs.max, f.b.hs.max)
	}
	if g.max < 2 {
		t.Fatalf("tenants A and B never ran in parallel (max %d): the lock is not per tenant", g.max)
	}
	for _, ten := range []*tenantFx{f.a, f.b} {
		var current string
		f.scan(t, `SELECT applied_hujson FROM policy_applications WHERE instance_id = $1 AND state = 'applied'
			AND superseded_at IS NULL`, []any{ten.instance}, &current)
		if current != ten.hs.Stored() {
			t.Fatalf("%s: current application differs from what Headscale holds", ten.slug)
		}
		if n := f.count(t, `SELECT count(*) FROM policy_applications x JOIN policy_applications y
			ON x.tenant_id = y.tenant_id AND x.id < y.id
			AND x.created_at < y.finished_at AND y.created_at < x.finished_at
			WHERE x.tenant_id = $1`, ten.id); n != 0 {
			t.Fatalf("%s: %d overlapping applications", ten.slug, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1 AND state = 'applied'`, f.a.id); n != 5 {
		t.Fatalf("A applied %d", n)
	}
}

// TestApplySuspensionKeepsDesired — §7.3: a suspension application does not change the desired version; the same
// suspension text reuses its version; resuming with the desired text reuses the desired version.
func TestApplySuspensionKeepsDesired(t *testing.T) {
	f := newFixture(t)
	allow := fixtureText(t, "test-allow-intra.hujson")
	a, err := apply(t, f, f.a, KindBaseline, allow)
	if err != nil {
		t.Fatal(err)
	}
	susp := `{"grants": [], "ssh": []}`
	ctx := context.Background()
	s1, err := f.svc.Apply(ctx, ApplyRequest{TenantID: f.a.id, Kind: KindSuspension, HuJSON: susp, Trigger: TriggerSuspend})
	if err != nil || !s1.VersionCreated {
		t.Fatalf("%+v %v", s1, err)
	}
	s2, err := f.svc.Apply(ctx, ApplyRequest{TenantID: f.a.id, Kind: KindSuspension, HuJSON: susp, Trigger: TriggerSuspend})
	if err != nil || s2.VersionCreated || s2.VersionID != s1.VersionID {
		t.Fatalf("%+v %v", s2, err)
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE id = $1 AND desired_policy_version_id = $2`, f.a.id, a.VersionID); n != 1 {
		t.Fatal("suspension changed the desired version")
	}
	r, err := f.svc.Apply(ctx, ApplyRequest{TenantID: f.a.id, HuJSON: allow, Trigger: TriggerResume})
	if err != nil || r.VersionCreated || r.VersionID != a.VersionID {
		t.Fatalf("resume: %+v %v", r, err)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND trigger = 'resume' AND state = 'applied'
		AND superseded_at IS NULL`, r.ApplicationID); n != 1 {
		t.Fatal("resume application")
	}
}

// TestApplyRequestChecks: no instance, user kind, unknown trigger.
func TestApplyRequestChecks(t *testing.T) {
	f := newFixture(t)
	f.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, f.b.instance)
	if _, err := apply(t, f, f.b, KindBaseline, portPolicy(1)); !errors.Is(err, ErrNoInstance) {
		t.Fatalf("no instance: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.b.id); n != 0 {
		t.Fatal("a version was stored without an instance")
	}
	for _, req := range []ApplyRequest{{TenantID: f.a.id, Kind: KindUser, HuJSON: portPolicy(1)},
		{TenantID: f.a.id, Trigger: "group_change", HuJSON: portPolicy(1)}, {HuJSON: portPolicy(1)}} {
		if _, err := f.svc.Apply(context.Background(), req); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%+v: %v", req, err)
		}
	}
}

// TestTenantLockTimeout: a held policy lock makes another holder of the same tenant wait and give up after its bound
// (store.ErrLockTimeout); another tenant's lock is independent.
func TestTenantLockTimeout(t *testing.T) {
	f := newFixture(t)
	held, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.st.WithTenantLock(context.Background(), f.a.id, lockName, time.Second, func(context.Context) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	start := time.Now()
	err := f.st.WithTenantLock(context.Background(), f.a.id, lockName, 300*time.Millisecond, func(context.Context) error {
		return errors.New("must not run")
	})
	if !errors.Is(err, store.ErrLockTimeout) || time.Since(start) > 5*time.Second {
		t.Fatalf("second holder: %v after %s", err, time.Since(start))
	}
	ran := false
	if err := f.st.WithTenantLock(context.Background(), f.b.id, lockName, 300*time.Millisecond, func(context.Context) error {
		ran = true
		return nil
	}); err != nil || !ran {
		t.Fatalf("other tenant: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := f.st.WithTenantLock(context.Background(), f.a.id, lockName, 300*time.Millisecond, func(context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("lock not released: %v", err)
	}
}
