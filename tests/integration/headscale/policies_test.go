package contract

// Phase 12 (P3-T08a): the minimal policy core (internal/policies) against the real Headscale of the contract run (the
// patched build), through the real admin listener of the edge, with the register database of the device phases 8–11
// (worker roles, RLS). The verification of the task: "Với Headscale thật: áp fixture allow ⇒ sha khớp; chuỗi
// rỗng/thiếu grants bị chặn".
//
//   - lint: an empty policy, whitespace, a policy without "grants", "grants": null and the deny-all baseline with its
//     "grants" removed are refused before any call — the policy Headscale stores is unchanged and no application row
//     is written;
//   - the allow fixture of the repository (infrastructure/headscale/templates/test-allow-intra.hujson, mounted by run.sh
//     at $HSCT_FIXTURES) applied through the core: CheckPolicy → SetPolicy → GetPolicy, read-back sha256 = applied_sha256
//     = sha256 of what GetPolicy returns now, the version holds the HuJSON text as given (comments included);
//   - a policy Headscale refuses (a grant naming a group that is not declared) ⇒ failed policy_rejected, the running
//     policy unchanged;
//   - concurrent applications on the tenant are serialised by the per-tenant advisory lock: all applied, recorded
//     intervals disjoint, exactly one current application and it is what Headscale holds;
//   - finally the deny-all baseline (bootstrap-policy.hujson) is applied — the instance ends deny-all.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
)

func fixturePolicy(t *testing.T, name string) string {
	t.Helper()
	dir := os.Getenv("HSCT_FIXTURES")
	if dir == "" {
		t.Fatal("HSCT_FIXTURES is not set (run.sh mounts infrastructure/headscale/templates)")
	}
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: directory set by run.sh (test harness)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestP12_PolicyCoreAppliesFixture(t *testing.T) {
	d := devSetup(t)
	inst := d.inst(t)
	c := ctx(t)
	lf, err := os.OpenFile(filepath.Join(d.stateDir, "adapter.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304/G703: run.sh's state directory
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lf.Close() })
	svc, err := policies.New(d.wrkSt, policies.Config{Registry: d.reg, Logger: logx.New(lf, slog.LevelDebug, "policies"),
		LockWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	apply := func(text, trigger string) (policies.Result, error) {
		return svc.Apply(c, policies.ApplyRequest{TenantID: tenantID, HuJSON: text, Trigger: trigger, Actor: "hsct phase 12"})
	}
	stored := func() string {
		p, err := inst.GetPolicy(c)
		if errors.Is(err, headscale.ErrNoPolicy) {
			return ""
		}
		if err != nil {
			t.Fatalf("GetPolicy: %s", describe(err))
		}
		return p.Data
	}
	apps := func() int {
		return d.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1`, tenantID)
	}

	// 1. Lint: refused before any call.
	before, beforeApps := stored(), apps()
	base := fixturePolicy(t, "bootstrap-policy.hujson")
	var lintObs []string
	for name, doc := range map[string]string{"empty": "", "whitespace": " \n\t", "no grants": `{"ssh": []}`,
		"grants null": `{"grants": null, "ssh": []}`, "baseline without grants": `// grants removed` + "\n" + `{"ssh": []}`} {
		_, err := apply(doc, policies.TriggerManual)
		le, ok := policies.IsLint(err)
		if !ok || (le.Rule != policies.RuleL1 && le.Rule != policies.RuleL2) {
			t.Fatalf("%s: %v", name, err)
		}
		lintObs = append(lintObs, name+" ⇒ "+le.Rule)
	}
	if stored() != before || apps() != beforeApps {
		t.Fatal("a refused policy reached Headscale or the register")
	}
	d.record(t, "P3-T08a", "lint L1/L2 trước mọi lời gọi Headscale",
		fmt.Sprintf("%v; policy Headscale đang lưu không đổi (sha256 %s), 0 hàng policy_applications mới", lintObs,
			policies.SHA256Hex(before)[:16]), "lint chặn ⇒ không ghi version/application, chỉ audit policy.lint_rejected")

	// 2. The allow fixture.
	allow := fixturePolicy(t, "test-allow-intra.hujson")
	res, err := apply(allow, policies.TriggerManual)
	if err != nil {
		t.Fatalf("apply allow fixture: %v", err)
	}
	now := stored()
	if res.State != policies.StateApplied || res.ReadbackSHA256 != res.AppliedSHA256 || policies.SHA256Hex(now) != res.AppliedSHA256 {
		t.Fatalf("allow fixture: %+v, Headscale holds sha256 %s", res, policies.SHA256Hex(now))
	}
	if n := d.count(t, `SELECT count(*) FROM policy_versions WHERE id = $1 AND source_hujson = $2 AND content_sha256 = $3
		AND kind = 'baseline' AND state = 'approved'`, res.VersionID, allow, policies.SHA256Hex(allow)); n != 1 {
		t.Fatal("version row of the fixture")
	}
	if n := d.count(t, `SELECT count(*) FROM policy_applications WHERE id = $1 AND state = 'applied' AND superseded_at IS NULL
		AND applied_sha256 = $2 AND headscale_updated_at IS NOT NULL`, res.ApplicationID, res.AppliedSHA256); n != 1 {
		t.Fatal("application row of the fixture")
	}
	d.record(t, "P3-T08a", "áp fixture allow (test-allow-intra.hujson) qua lõi policy",
		fmt.Sprintf("version %d (content_sha256 %s… = sha256 của HuJSON nguyên văn), applied_sha256 %s…, đọc lại GetPolicy %s… ⇒ khớp",
			res.Version, res.ContentSHA256[:16], res.AppliedSHA256[:16], res.ReadbackSHA256[:16]),
		"CheckPolicy → SetPolicy → GetPolicy; so sha256 của chuỗi GetPolicy trả về, không chuẩn hóa")

	// 3. Refused by Headscale: undeclared group (PL-04) ⇒ failed, running policy unchanged.
	_, err = apply(`{"grants": [{"src": ["group:nope"], "dst": ["*"], "ip": ["*"]}]}`, policies.TriggerManual)
	var ae *policies.ApplyError
	if !errors.As(err, &ae) || ae.Code != policies.CodePolicyRejected || stored() != now {
		t.Fatalf("refused policy: %v", err)
	}
	d.record(t, "P3-T08a", "policy bị Headscale từ chối (group chưa khai báo)",
		fmt.Sprintf("application failed %s (%s), policy đang lưu không đổi", ae.Code, describe(ae.Err)),
		"CheckPolicy từ chối ⇒ không gọi SetPolicy")

	// 4. Concurrent applications serialised by the per-tenant advisory lock.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doc := fmt.Sprintf(`{"grants": [{"src": ["autogroup:member"], "dst": ["autogroup:member"], "ip": ["tcp:%d"]}], "ssh": []}`, 7001+i)
			_, err := apply(doc, policies.TriggerManual)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent apply: %v", err)
		}
	}
	var current string
	if err := d.su.QueryRow(context.Background(), `SELECT applied_hujson FROM policy_applications WHERE instance_id = $1
		AND state = 'applied' AND superseded_at IS NULL`, instanceID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	overlap := d.count(t, `SELECT count(*) FROM policy_applications x JOIN policy_applications y
		ON x.tenant_id = y.tenant_id AND x.id < y.id AND x.created_at < y.finished_at AND y.created_at < x.finished_at
		WHERE x.tenant_id = $1`, tenantID)
	if current != stored() || overlap != 0 {
		t.Fatalf("after concurrent applications: current matches Headscale %v, overlapping %d", current == stored(), overlap)
	}
	d.record(t, "P3-T08a", "4 lần áp đồng thời trên cùng tenant",
		fmt.Sprintf("4/4 applied, 0 cặp khoảng [created_at, finished_at] chồng nhau, đúng 1 hàng hiện hành = policy Headscale đang lưu (sha256 %s…)",
			policies.SHA256Hex(current)[:16]), "khóa advisory theo tenant (store.WithTenantLock)")

	// 5. End deny-all.
	if res, err := apply(base, policies.TriggerBootstrap); err != nil || policies.SHA256Hex(stored()) != res.AppliedSHA256 {
		t.Fatalf("baseline: %+v %v", res, err)
	}
}
