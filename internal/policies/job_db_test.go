package policies

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// enqueueApply enqueues policy.apply of a tenant with input and returns the jobs.Run a worker hands to the handler.
func enqueueApply(t *testing.T, f *fixture, ten *tenantFx, input any) *jobs.Run {
	t.Helper()
	var job jobs.Job
	err := f.st.WithTenantJobTx(context.Background(), ten.id, func(tx *store.Tx) error {
		enq, err := jobs.Enqueue(context.Background(), tx, jobs.Spec{Kind: KindApply, TenantID: &ten.id, Input: input})
		job = enq.Job
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	f.scan(t, `SELECT input FROM provisioning_jobs WHERE id = $1`, []any{job.ID}, &raw)
	tid := ten.id
	return &jobs.Run{ID: job.ID, Kind: KindApply, TenantID: &tid, Input: json.RawMessage(raw), Attempt: 1, MaxAttempts: 6,
		Deadline: time.Now().Add(time.Minute), Store: f.st}
}

func output(t *testing.T, r *jobs.Run) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(r.Output(), &out); err != nil {
		t.Fatalf("output %s: %v", r.Output(), err)
	}
	return out
}

// TestApplyJobGroupChange — P4-T09 (§7.3, §13.5 policy.apply): a group change re-applies the DESIRED version with trigger
// group_change — a new policy_applications row on the same approved version, never a new version; the handler reads
// the desired state when it runs (level-triggered). Skipped: no desired version, a tenant that is not active (its
// suspension policy stays), an unknown trigger is a permanent error.
func TestApplyJobGroupChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := enqueueApply(t, f, f.a, map[string]string{"trigger": TriggerGroupChange})
	if err := f.svc.runApplyJob(ctx, r); err != nil {
		t.Fatal(err)
	}
	if out := output(t, r); out["skipped"] != "no_desired_policy" {
		t.Fatalf("without a desired version: %v", out)
	}
	f.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, r.ID)

	first, err := apply(t, f, f.a, KindBaseline, portPolicy(7))
	if err != nil {
		t.Fatal(err)
	}
	r = enqueueApply(t, f, f.a, map[string]string{"trigger": TriggerGroupChange})
	if err := f.svc.runApplyJob(ctx, r); err != nil {
		t.Fatal(err)
	}
	out := output(t, r)
	if out["state"] != StateApplied || out["trigger"] != TriggerGroupChange || out["version"] != float64(first.Version) {
		t.Fatalf("re-application: %v", out)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, f.a.id); n != 1 {
		t.Fatalf("%d versions, want 1 (a group change never creates a version)", n)
	}
	var trigger, state string
	var version uuid.UUID
	f.scan(t, `SELECT trigger, state, policy_version_id FROM policy_applications WHERE tenant_id = $1
		ORDER BY created_at DESC, id DESC LIMIT 1`, []any{f.a.id}, &trigger, &state, &version)
	if trigger != TriggerGroupChange || state != StateApplied || version != first.VersionID {
		t.Fatalf("latest application %s %s %s, want group_change applied on %s", trigger, state, version, first.VersionID)
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1 AND state = 'applied'
		AND superseded_at IS NULL`, f.a.id); n != 1 {
		t.Fatalf("%d current applications, want 1", n)
	}
	f.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, r.ID)

	// a suspended tenant keeps its suspension policy
	f.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, f.a.id)
	before := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1`, f.a.id)
	r = enqueueApply(t, f, f.a, map[string]string{"trigger": TriggerGroupChange})
	if err := f.svc.runApplyJob(ctx, r); err != nil || output(t, r)["skipped"] != "tenant_not_active" {
		t.Fatalf("suspended tenant: %v %v", err, output(t, r))
	}
	if n := f.count(t, `SELECT count(*) FROM policy_applications WHERE tenant_id = $1`, f.a.id); n != before {
		t.Fatal("an application was recorded for a suspended tenant")
	}
	f.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, r.ID)
	f.exec(t, `UPDATE tenants SET status = 'active' WHERE id = $1`, f.a.id)

	r = enqueueApply(t, f, f.a, map[string]string{"trigger": "membership_change"})
	var je *jobs.Error
	if err := f.svc.runApplyJob(ctx, r); !errors.As(err, &je) || !je.Permanent || je.Code != codeInvalidInput {
		t.Fatalf("unknown trigger: %v", err)
	}
	var tenant sqlcdb.Tenant
	_ = f.st.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
		var err error
		tenant, err = q.GetTenant(ctx, f.a.id)
		return err
	})
	if tenant.DesiredPolicyVersionID == nil || *tenant.DesiredPolicyVersionID != first.VersionID {
		t.Fatalf("desired version changed: %v", tenant.DesiredPolicyVersionID)
	}
}
