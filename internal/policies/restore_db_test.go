package policies

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

func review(t *testing.T, f *fixture, ten *tenantFx, dry bool, run uuid.UUID) RunningResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := f.svc.ReviewRunning(ctx, RunningReview{TenantID: ten.id, RunID: run, DryRun: dry, Actor: "test",
		RestorePoint: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatalf("ReviewRunning(%s, dry %v): %v", ten.slug, dry, err)
	}
	return res
}

// TestReviewRunningNeverOverwrites — the policy step of P3-T17 (§17.2 step 4) with a fake Headscale: when the instance
// runs what the database recorded nothing is written; when it runs a NEWER policy (applied in the gap a restore lost)
// a dry run writes nothing, the run records it — current application trigger restore holding exactly the running string
// (the previous one superseded), a version kind user in state validated made desired, audit policy.restore_adopted and
// the tenant-scoped security event policy.restore_review_required — and NEVER calls SetPolicy/CheckPolicy: Headscale
// keeps the newer policy; a member user the policy names without an active membership is listed; running again finds
// a match; the other tenant is untouched.
func TestReviewRunningNeverOverwrites(t *testing.T) {
	f := newFixture(t)
	allow := fixtureText(t, "test-allow-intra.hujson")
	applied, err := apply(t, f, f.a, KindBaseline, allow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, f, f.b, KindBaseline, allow); err != nil {
		t.Fatal(err)
	}
	run := uuid.New()
	if r := review(t, f, f.a, false, run); r.Outcome != RunningMatch || r.Review || r.RunningSHA256 != applied.AppliedSHA256 {
		t.Fatalf("Headscale runs the recorded policy: %+v", r)
	}

	// a newer policy, applied in the gap: it names the Owner's Headscale user and one no membership has
	var owner string
	f.scan(t, `SELECT headscale_username FROM tenant_memberships WHERE id = $1`, []any{f.a.owner}, &owner)
	ghost := "mg-" + uuid.NewString()
	newer := fmt.Sprintf(`{
  "grants": [{"src": ["%s@", "%s@"], "dst": ["autogroup:member"], "ip": ["tcp:9443"]}],
  "ssh": []
}`, owner, ghost)
	f.a.hs.mu.Lock()
	f.a.hs.stored, f.a.hs.calls = newer, nil
	f.a.hs.mu.Unlock()
	counts := func() string {
		return fmt.Sprintf("%d|%d|%d|%d", f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.a.id),
			f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1`, f.a.id),
			f.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2`, f.a.id, ActionRestoreAdopted),
			f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2`, f.a.id, SecurityRestoreReview))
	}
	before := counts()
	dry := review(t, f, f.a, true, run)
	if dry.Outcome != RunningWouldAdopt || !dry.Review || dry.RunningSHA256 != SHA256Hex(newer) ||
		!slices.Equal(dry.UnmappedUsers, []string{ghost}) || counts() != before {
		t.Fatalf("dry run: %+v, counts %s → %s", dry, before, counts())
	}
	r := review(t, f, f.a, false, run)
	if r.Outcome != RunningAdopted || !r.Review || r.VersionStatus != "validated" || r.VersionID == nil ||
		r.ApplicationID == nil || r.RecordedSHA != applied.AppliedSHA256 || !slices.Equal(r.UnmappedUsers, []string{ghost}) {
		t.Fatalf("adopted: %+v", r)
	}
	if calls := f.a.hs.Calls(); slices.Contains(calls, "SetPolicy") || slices.Contains(calls, "CheckPolicy") {
		t.Fatalf("Headscale was written: %v", calls)
	}
	if f.a.hs.Stored() != newer {
		t.Fatal("the running policy changed")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions v JOIN tenants t ON t.desired_policy_version_id = v.id
		WHERE v.id = $1 AND v.tenant_id = $2 AND v.kind = 'user' AND v.state = 'validated' AND v.source_hujson = $3
		AND v.content_sha256 = $4 AND v.approved_at IS NULL AND v.parent_version_id = $5`, *r.VersionID, f.a.id, newer,
		SHA256Hex(newer), applied.VersionID); n != 1 {
		t.Fatal("the imported version is not the validated, desired, unapproved copy of the running policy")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1 AND id = $2 AND trigger = 'restore'
		AND state = 'applied' AND superseded_at IS NULL AND applied_hujson = $3 AND finished_at IS NOT NULL`,
		f.a.id, *r.ApplicationID, newer); n != 1 {
		t.Fatal("the running policy is not the current application")
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND superseded_at IS NOT NULL`,
		applied.ApplicationID); n != 1 {
		t.Fatal("the previous application is not superseded")
	}
	if got := counts(); got != fmt.Sprintf("%d|%d|1|1", f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`,
		f.a.id), f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1`, f.a.id)) {
		t.Fatalf("audit/security events: %s", got)
	}
	if again := review(t, f, f.a, false, uuid.New()); again.Outcome != RunningMatch {
		t.Fatalf("second run: %+v", again)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1 AND trigger = 'restore'`, f.b.id); n != 0 {
		t.Fatalf("tenant B got %d restore applications", n)
	}
}

// TestReviewRunningEdgeCases — a running policy the lint refuses is imported as a draft (never validated, never
// desired-and-applied); an instance that stores no policy (allow-all at its next restart) is flagged with the security
// event and nothing else; an unreachable instance or a missing instance writes nothing.
func TestReviewRunningEdgeCases(t *testing.T) {
	f := newFixture(t)
	if _, err := apply(t, f, f.a, KindBaseline, fixtureText(t, "test-allow-intra.hujson")); err != nil {
		t.Fatal(err)
	}
	f.a.hs.mu.Lock()
	f.a.hs.stored = `{"ssh": []}` // no grants: L1
	f.a.hs.mu.Unlock()
	r := review(t, f, f.a, false, uuid.New())
	if r.Outcome != RunningAdopted || r.VersionStatus != "draft" || r.LintRule != RuleL1 {
		t.Fatalf("lint-refused running policy: %+v", r)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE id = $1 AND state = 'draft' AND kind = 'user'`, *r.VersionID); n != 1 {
		t.Fatal("not imported as a draft")
	}

	f.b.hs.mu.Lock()
	f.b.hs.stored = ""
	f.b.hs.mu.Unlock()
	versions := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.b.id)
	if r := review(t, f, f.b, false, uuid.New()); r.Outcome != RunningNoPolicy || !r.Review {
		t.Fatalf("no policy: %+v", r)
	}
	if n := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2 AND details->>'reason' = 'no_policy'`,
		f.b.id, SecurityRestoreReview); n != 1 || versions != f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.b.id) {
		t.Fatalf("no policy: %d security events, versions changed", n)
	}
	f.b.hs.mu.Lock()
	f.b.hs.getErr = &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindUnavailable}
	f.b.hs.mu.Unlock()
	if r := review(t, f, f.b, false, uuid.New()); r.Outcome != RunningUnavailable || r.ErrorCode != "headscale_unavailable" {
		t.Fatalf("unreachable: %+v", r)
	}
	f.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, f.b.instance)
	if r := review(t, f, f.b, false, uuid.New()); r.Outcome != RunningNoInstance {
		t.Fatalf("no instance: %+v", r)
	}
}
