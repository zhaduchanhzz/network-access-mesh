//go:build linux && dockerintegration

package provisioning

// The cases of P3-T07 (master §20; E2E-48…E2E-51, numbers reserved by P3-T05):
//
//	E2E-48  a permanent failure at every worker step 3–19 (the mandatory 11–18: the instance directory already holds
//	        Headscale's keys and DB) ⇒ compensation in reverse order ⇒ rolled_back; nothing left (orphan detector).
//	E2E-49  the worker killed (SIGKILL) inside step 13 right after the agent created the API key, before it is stored
//	        ⇒ job.reaper ⇒ failed_resumable (worker_lost) ⇒ /retry resumes at step 13: the orphan key is expired and
//	        the only valid key is the one in the SecretStore; and killed inside step 16 right after the Owner invitation
//	        was committed, before its id was recorded ⇒ /rollback ⇒ rolled_back, the invitation revoked.
//	E2E-50  transient failures that outlast the in-place retries ⇒ failed_resumable (no compensation, resources kept)
//	        ⇒ /retry continues from the failed step (earlier steps not run again) ⇒ succeeded.
//	E2E-51  rolled_back ⇒ /retry creates a NEW job that starts at step 3 (steps 1–2 skipped) ⇒ succeeded.

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/faultinject"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/orphans"
)

// permanentCase is one case of E2E-48: the fault and the code the job must end with.
type permanentCase struct {
	n     int    // step number of §11.3
	step  string // step name
	fault faultinject.Fault
	code  string // provisioning_jobs.error->>'code'
	// what the step had made when it failed (After = true) — undone by the compensation
	made string
}

var permanentCases = []permanentCase{
	{3, orchestrator.StepPlacement, faultinject.Fault{Call: "placer.Allocate", Mode: faultinject.Permanent, After: true}, "placement_refused", "instance row allocated"},
	{5, orchestrator.StepSecrets, faultinject.Fault{Call: "secrets.EnsureDEK", Mode: faultinject.Permanent, After: true}, "tenant_keys_destroyed", "tenant DEK (kept by design)"},
	{6, orchestrator.StepIdP, faultinject.Fault{Call: "idp.EnsureIssuer", Mode: faultinject.Permanent}, "idp_conflict", "—"},
	{7, orchestrator.StepStorage, faultinject.Fault{Call: "agent.EnsureInstance:STORAGE", Mode: faultinject.Permanent, After: true}, "agent_state", "instance directory"},
	{8, orchestrator.StepConfig, faultinject.Fault{Call: "agent.EnsureInstance:CONFIG", Mode: faultinject.Permanent, After: true}, "agent_state", "config.yaml, compose.yaml"},
	{9, orchestrator.StepNetwork, faultinject.Fault{Call: "agent.EnsureInstance:NETWORK", Mode: faultinject.Permanent, After: true}, "agent_state", "network mg-t-<slug>"},
	{10, orchestrator.StepStart, faultinject.Fault{Call: "agent.EnsureInstance:CONTAINER", Mode: faultinject.Permanent, After: true}, "agent_state", "container (Noise key, DB in data/)"},
	{11, orchestrator.StepWaitHealthy, faultinject.Fault{Call: "agent.GetInstanceStatus", Mode: faultinject.Permanent, After: true}, "agent_state", "healthy instance"},
	{12, orchestrator.StepPolicyBoot, faultinject.Fault{Call: "agent.BootstrapPolicy", Mode: faultinject.Permanent, After: true}, "agent_state", "deny-all policy"},
	{13, orchestrator.StepAPIKey, faultinject.Fault{Call: "agent.BootstrapApiKey", Mode: faultinject.Permanent, After: true}, "agent_state", "API key in Headscale, never stored"},
	{14, orchestrator.StepEdgeAttach, faultinject.Fault{Call: "agent.EnsureEdgeAttachment", Mode: faultinject.Permanent, After: true}, "agent_state", "edge attached, meta/activated"},
	{15, orchestrator.StepPolicyVerify, faultinject.Fault{Call: "headscale.GetPolicy", Mode: faultinject.Permanent}, "headscale_upstream_rejected", "—"},
	{16, orchestrator.StepConfigure, faultinject.Fault{Call: "store.Configure", Mode: faultinject.Permanent, After: true}, "registry_state", "Owner invitation (id not recorded), IdP active"},
	{17, orchestrator.StepRelay, faultinject.Fault{Call: "store.AssignRelay", Mode: faultinject.Permanent, After: true}, "registry_state", "relay rows"},
	{18, orchestrator.StepEdgeVerify, faultinject.Fault{Call: "prober.Edge", Mode: faultinject.Permanent, After: true}, "edge_exposes_paths", "—"},
	{19, orchestrator.StepActivate, faultinject.Fault{Call: "store.Activate", Mode: faultinject.Permanent}, "registry_state", "—"},
}

// mandatory are the steps the task names (11–18): their failure happens with keys in the instance directory.
func mandatory(n int) bool { return n >= 11 && n <= 18 }

// withMandatoryFirst orders the cases so the mandatory ones run first (a run cut short still covers them).
func withMandatoryFirst(cs []permanentCase) []permanentCase {
	out := slices.Clone(cs)
	slices.SortStableFunc(out, func(a, b permanentCase) int {
		switch {
		case mandatory(a.n) && !mandatory(b.n):
			return -1
		case !mandatory(a.n) && mandatory(b.n):
			return 1
		}
		return a.n - b.n
	})
	return out
}

// TestProvisioningFaultInjection is the harness: one database, one agent, one edge; every case in sequence, each with
// its own tenant and worker processes; the orphan detector after each.
func TestProvisioningFaultInjection(t *testing.T) {
	h := newHarness(t)
	results := []string{}
	record := func(s string) { results = append(results, s) }
	t.Cleanup(func() {
		t.Logf("summary of the cases:\n  %s", strings.Join(results, "\n  "))
	})

	t.Run("E2E-48_permanent_failure_compensates", func(t *testing.T) {
		for _, c := range withMandatoryFirst(permanentCases) {
			t.Run(fmt.Sprintf("step%02d_%s", c.n, c.step), func(t *testing.T) {
				record(h.permanent(t, c))
			})
		}
	})
	t.Run("E2E-49_worker_killed", func(t *testing.T) {
		t.Run("mid_apikey_then_retry", func(t *testing.T) { record(h.killedMidAPIKey(t)) })
		t.Run("mid_configure_then_rollback", func(t *testing.T) { record(h.killedMidConfigure(t)) })
	})
	t.Run("E2E-50_failed_resumable_retry", func(t *testing.T) {
		for _, c := range []struct {
			name, step, code string
			fault            faultinject.Fault
			// expected findings of the detector while the job waits in failed_resumable (resources kept)
			waiting []string
		}{
			{"step12_agent_unavailable", orchestrator.StepPolicyBoot, "agent_unavailable",
				faultinject.Fault{Call: "agent.BootstrapPolicy", Mode: faultinject.Transient}, nil},
			{"step13_answers_lost", orchestrator.StepAPIKey, "agent_unavailable",
				faultinject.Fault{Call: "agent.BootstrapApiKey", Mode: faultinject.Transient, After: true},
				// every try created a key whose answer was lost; the agent expired the previous one each time: exactly
				// one valid key is left that nobody stored — until /retry expires it
				[]string{orphans.APIKeyUnregistered}},
			{"step17_prober_unreachable", orchestrator.StepRelay, "prober_unavailable",
				faultinject.Fault{Call: "prober.Relay", Mode: faultinject.Transient}, nil},
		} {
			t.Run(c.name, func(t *testing.T) { record(h.resumable(t, c.name, c.step, c.code, c.fault, c.waiting)) })
		}
	})
	t.Run("E2E-51_retry_after_rollback_new_job", func(t *testing.T) { record(h.retryAfterRollback(t)) })

	t.Run("final", func(t *testing.T) {
		inv := h.noOrphans(t)
		if l := h.leaks(t); len(l) != 0 {
			t.Fatalf("an API key reached a worker log: %v", l)
		}
		n := h.teardown(t)
		t.Logf("final: %s; %d live instance(s) torn down (edge detached, compose down, network removed — directories left to run.sh)",
			inv.Summary(), n)
	})
}

// slugFor names the tenant of a case: <prefix>-<short>, within the slug rules (≤ 32 characters).
func (h *harness) slugFor(short string) string {
	s := h.e.prefix + "-" + short
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.TrimRight(s, "-")
}

// assertRolledBack checks a rolled_back job: the failing step, its code, every step compensated (or skipped), the
// tenant failed, the instance removed, the audit closed .failed.
func (h *harness) assertRolledBack(t *testing.T, c orchestrator.Created, step, code string) []stepRow {
	t.Helper()
	steps := h.steps(t, c.Job.ID)
	if got := h.jobErrorCode(t, c.Job.ID); got != code {
		t.Fatalf("error code %q, want %q; steps:%s", got, code, describeSteps(steps))
	}
	wantStatus, wantCode := jobs.StepFailed, code
	if code == jobs.CodeWorkerLost { // the step the dead worker was in never finished
		wantStatus, wantCode = jobs.StepRunning, ""
	}
	last := steps[len(steps)-1]
	if last.Name != step || last.Status != wantStatus || last.ErrorCode != wantCode {
		t.Fatalf("last step %+v, want %s %s %s; steps:%s", last, step, wantStatus, wantCode, describeSteps(steps))
	}
	for _, s := range steps {
		if s.Name == orchestrator.StepValidate || s.Name == orchestrator.StepRegistryCreate {
			continue
		}
		if s.Compensation != jobs.StepSucceeded && s.Compensation != jobs.StepSkipped {
			t.Fatalf("step %s compensation %q; steps:%s", s.Name, s.Compensation, describeSteps(steps))
		}
	}
	if st := scalar[string](t, h, `SELECT status FROM tenants WHERE id = $1`, c.TenantID); st != "failed" {
		t.Fatalf("tenant %s", st)
	}
	if n := scalar[int64](t, h, `SELECT count(*) FROM tenant_instances WHERE tenant_id = $1 AND status <> 'removed'`, c.TenantID); n != 0 {
		t.Fatalf("%d instance(s) of the rolled-back tenant not removed", n)
	}
	if got := scalar[string](t, h, `SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events
		WHERE action LIKE 'platform.tenant.create%' AND resource_id = $1::text`, c.TenantID.String()); !strings.HasSuffix(got, ".failed") {
		t.Fatalf("audit %s", got)
	}
	return steps
}

func compensated(steps []stepRow) string {
	var out []string
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].Compensation == jobs.StepSucceeded {
			out = append(out, steps[i].Name)
		}
	}
	return strings.Join(out, " → ")
}

// permanent is one case of E2E-48.
func (h *harness) permanent(t *testing.T, c permanentCase) string {
	start := time.Now()
	slug := h.slugFor(fmt.Sprintf("p%02d", c.n))
	f := c.fault
	f.Times = 1
	w := h.startWorker(t, slug, faultinject.Plan{f})
	cr := h.create(t, slug)
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusRolledBack)
	w.stop(t)
	steps := h.assertRolledBack(t, cr, c.step, c.code)
	if c.n >= 10 {
		// the instance had started (its data/ holds the Noise key and the DB; from step 13 an API key): the whole
		// directory went with step 7's compensation, after the edge (14) and the container (10) — reverse order
		for _, s := range []string{orchestrator.StepStart, orchestrator.StepNetwork, orchestrator.StepStorage} {
			if st, _ := stepByName(steps, s); st.Compensation != jobs.StepSucceeded {
				t.Fatalf("step %s compensation %q", s, st.Compensation)
			}
		}
	}
	inv := h.noOrphans(t)
	return fmt.Sprintf("E2E-48 step %2d %-22s %-38s ⇒ rolled_back %-28s %5.1fs; compensated: %s; detector: %d dirs, %d live key versions",
		c.n, c.step, f.String(), c.code, time.Since(start).Seconds(), compensated(steps), len(inv.Host.Dirs), liveVersions(inv))
}

func liveVersions(inv orphans.Inventory) int {
	n := 0
	for _, s := range inv.Registry.Secrets {
		if !s.Destroyed && s.Name == orphans.APIKeySecretName {
			n++
		}
	}
	return n
}

// killedMidAPIKey is E2E-49.
func (h *harness) killedMidAPIKey(t *testing.T) string {
	start := time.Now()
	slug := h.slugFor("kill13")
	w1 := h.startWorker(t, slug+"-killed", faultinject.Plan{{Call: "agent.BootstrapApiKey", Mode: faultinject.Kill, Times: 1}})
	cr := h.create(t, slug)
	w1.waitKilled(t, 5*time.Minute)

	// The state the dead worker left: job running, step 13 running (its resources recorded first), no key stored or
	// registered — and exactly one valid key in Headscale, the one the agent created and returned to a dead process.
	if st := scalar[string](t, h, `SELECT status FROM provisioning_jobs WHERE id = $1`, cr.Job.ID); st != jobs.StatusRunning {
		t.Fatalf("job %s after the kill", st)
	}
	s13, _ := stepByName(h.steps(t, cr.Job.ID), orchestrator.StepAPIKey)
	if s13.Status != jobs.StepRunning || s13.Attempt != 1 || !strings.Contains(s13.Resources, `"secret_name"`) {
		t.Fatalf("step 13 after the kill: %+v", s13)
	}
	inst, status, prefix := h.instanceOf(t, cr.TenantID)
	if status != orphans.StatusStarting || prefix != "" || len(h.liveKeyVersions(t, cr.TenantID)) != 0 {
		t.Fatalf("instance %s %s prefix %q, key versions %v", inst, status, prefix, h.liveKeyVersions(t, cr.TenantID))
	}
	orphan := validPrefixes(h.keys(t, cr.TenantID, inst, slug))
	if len(orphan) != 1 {
		t.Fatalf("valid keys after the kill: %v, want exactly the one created", orphan)
	}
	fs, _ := h.findings(t, false)
	if k := kindsOf(fs); k != orphans.APIKeyUnregistered {
		t.Fatalf("detector after the kill: %v (want the unstored key only)", fs)
	}
	t.Logf("killed after BootstrapApiKey: job running, step 13 running, key %s valid in Headscale and stored nowhere", orphan[0])

	// The worker never comes back for this attempt: once timeout_at has passed, job.reaper of the restarted worker settles
	// the job. The harness moves timeout_at instead of waiting the 10 minutes of the lifecycle group.
	w2 := h.startWorker(t, slug+"-restarted", nil)
	h.reap(t, cr.Job.ID)
	r := h.retry(t, cr.Job.ID)
	if r.NewJob || r.Job.ID != cr.Job.ID {
		t.Fatalf("/retry of failed_resumable: %+v", r)
	}
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusSucceeded)
	w2.stop(t)

	steps := h.steps(t, cr.Job.ID)
	for _, s := range steps {
		want := 1
		if s.Name == orchestrator.StepAPIKey {
			want = 2 // the dead attempt, then the one after /retry
		}
		if s.Status != jobs.StepSucceeded || s.Attempt != want {
			t.Fatalf("step %s %s attempt %d (want %d); steps:%s", s.Name, s.Status, s.Attempt, want, describeSteps(steps))
		}
	}
	_, status, prefix = h.instanceOf(t, cr.TenantID)
	keys := h.keys(t, cr.TenantID, inst, slug)
	valid := validPrefixes(keys)
	if status != orphans.StatusRunning || len(valid) != 1 || valid[0] != prefix || keys[orphan[0]] {
		t.Fatalf("after /retry: instance %s, valid keys %v, registry %s, orphan %s valid=%v", status, valid, prefix, orphan[0], keys[orphan[0]])
	}
	if v := h.liveKeyVersions(t, cr.TenantID); len(v) != 1 {
		t.Fatalf("live key versions %v", v)
	}
	h.noOrphans(t) // includes: the stored key (SecretStore) is the registry's prefix and authenticates through the edge
	return fmt.Sprintf("E2E-49 SIGKILL after BootstrapApiKey (key %s created, stored nowhere) ⇒ reaper worker_lost ⇒ /retry ⇒ "+
		"step 13 attempt 2: %s expired, the only valid key %s = SecretStore #%d; %5.1fs", orphan[0], orphan[0], prefix,
		h.liveKeyVersions(t, cr.TenantID)[0], time.Since(start).Seconds())
}

// killedMidConfigure is the second case of E2E-49: the worker dies right after step 16 committed the Owner invitation,
// before it recorded the invitation's id; the operator rolls back (/rollback of the failed_resumable job): the
// compensation runs every completed step and the interrupted one, and revokes the invitation by the e-mail it recorded
// first (the bug P3-T07 found — undoConfigure needed the id).
func (h *harness) killedMidConfigure(t *testing.T) string {
	start := time.Now()
	slug := h.slugFor("kill16")
	w1 := h.startWorker(t, slug+"-killed", faultinject.Plan{{Call: "store.Configure", Mode: faultinject.Kill, Times: 1}})
	cr := h.create(t, slug)
	w1.waitKilled(t, 5*time.Minute)
	s16, _ := stepByName(h.steps(t, cr.Job.ID), orchestrator.StepConfigure)
	if s16.Status != jobs.StepRunning || strings.Contains(s16.Resources, "invitation_id") {
		t.Fatalf("step 16 after the kill: %+v", s16)
	}
	if n := scalar[int64](t, h, `SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'`, cr.TenantID); n != 1 {
		t.Fatalf("%d pending invitation(s) after the kill, want the one step 16 committed", n)
	}
	w2 := h.startWorker(t, slug+"-restarted", nil)
	h.reap(t, cr.Job.ID)
	r := h.rollback(t, cr.Job.ID)
	if r.Job.Status != jobs.StatusCompensating {
		t.Fatalf("/rollback: %+v", r)
	}
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusRolledBack)
	w2.stop(t)
	steps := h.assertRolledBack(t, cr, orchestrator.StepConfigure, jobs.CodeWorkerLost)
	if s, _ := stepByName(steps, orchestrator.StepConfigure); s.Compensation != jobs.StepSucceeded {
		t.Fatalf("step 16 compensation %q", s.Compensation)
	}
	if n := scalar[int64](t, h, `SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'revoked'`, cr.TenantID); n != 1 {
		t.Fatalf("%d revoked invitation(s)", n)
	}
	h.noOrphans(t)
	return fmt.Sprintf("E2E-49 SIGKILL after store.Configure (invitation committed, id not recorded) ⇒ reaper worker_lost ⇒ /rollback ⇒ "+
		"rolled_back, invitation revoked by its e-mail, compensated: %s; %5.1fs", compensated(steps), time.Since(start).Seconds())
}

func kindsOf(fs []orphans.Finding) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return strings.Join(out, ",")
}

// resumable is one case of E2E-50.
func (h *harness) resumable(t *testing.T, name, step, code string, f faultinject.Fault, waiting []string) string {
	start := time.Now()
	slug := h.slugFor("r" + strings.SplitN(name, "_", 2)[0])
	w1 := h.startWorker(t, slug+"-faulty", faultinject.Plan{f})
	cr := h.create(t, slug)
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusFailedResumable)
	w1.stop(t)
	if got := h.jobErrorCode(t, cr.Job.ID); got != code {
		t.Fatalf("error code %s, want %s", got, code)
	}
	steps := h.steps(t, cr.Job.ID)
	failed := steps[len(steps)-1]
	tries := orchestrator.DefaultStepRetries + 1
	if failed.Name != step || failed.Status != jobs.StepFailed || failed.Attempt != tries {
		t.Fatalf("failed step %+v, want %s failed after %d tries; steps:%s", failed, step, tries, describeSteps(steps))
	}
	for _, s := range steps {
		if s.Compensation != "" {
			t.Fatalf("failed_resumable compensated step %s", s.Name)
		}
	}
	if st := scalar[string](t, h, `SELECT status FROM tenants WHERE id = $1`, cr.TenantID); st != "provisioning" {
		t.Fatalf("tenant %s while failed_resumable", st)
	}
	// Resources kept, nothing extra: the detector sees the instance as it stands (and, after lost key answers, the one
	// valid key nobody stored).
	fs, _ := h.findings(t, true)
	if got, want := kindsOf(fs), strings.Join(waiting, ","); got != want {
		t.Fatalf("detector while failed_resumable: %v, want [%s]", fs, want)
	}

	w2 := h.startWorker(t, slug+"-fixed", nil)
	r := h.retry(t, cr.Job.ID)
	if r.NewJob || r.Job.ID != cr.Job.ID || r.From != jobs.StatusFailedResumable {
		t.Fatalf("/retry: %+v", r)
	}
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusSucceeded)
	w2.stop(t)
	after := h.steps(t, cr.Job.ID)
	resumed := ""
	for _, s := range after {
		want := 1
		if s.Name == step {
			want = tries + 1
			resumed = s.Name
		}
		if s.Status != jobs.StepSucceeded || s.Attempt != want {
			t.Fatalf("step %s %s attempt %d, want %d (earlier steps never run again); steps:%s", s.Name, s.Status, s.Attempt,
				want, describeSteps(after))
		}
	}
	inst, status, prefix := h.instanceOf(t, cr.TenantID)
	valid := validPrefixes(h.keys(t, cr.TenantID, inst, slug))
	if status != orphans.StatusRunning || len(valid) != 1 || valid[0] != prefix {
		t.Fatalf("instance %s, valid keys %v, registry %s", status, valid, prefix)
	}
	h.noOrphans(t)
	return fmt.Sprintf("E2E-50 %-26s %s ×%d ⇒ failed_resumable %s (detector: [%s]) ⇒ /retry resumes at %s ⇒ succeeded; valid key = SecretStore; %5.1fs",
		name, f.Call, tries, code, strings.Join(waiting, ","), resumed, time.Since(start).Seconds())
}

// retryAfterRollback is E2E-51.
func (h *harness) retryAfterRollback(t *testing.T) string {
	start := time.Now()
	slug := h.slugFor("rollback")
	w1 := h.startWorker(t, slug+"-faulty", faultinject.Plan{{Call: "prober.Edge", Mode: faultinject.Permanent, After: true, Times: 1}})
	cr := h.create(t, slug)
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusRolledBack)
	w1.stop(t)
	h.assertRolledBack(t, cr, orchestrator.StepEdgeVerify, "edge_exposes_paths")
	oldInst, _, _ := h.instanceOf(t, cr.TenantID)
	h.noOrphans(t)

	w2 := h.startWorker(t, slug+"-retry", nil)
	r := h.retry(t, cr.Job.ID)
	if !r.NewJob || r.Job.ID == cr.Job.ID || r.From != jobs.StatusRolledBack {
		t.Fatalf("/retry of rolled_back: %+v", r)
	}
	h.waitJob(t, r.Job.ID, 5*time.Minute, jobs.StatusSucceeded)
	w2.stop(t)
	steps := h.steps(t, r.Job.ID)
	if len(steps) != len(orchestrator.Steps) {
		t.Fatalf("new job: %d steps; steps:%s", len(steps), describeSteps(steps))
	}
	for i, s := range steps {
		wantStatus, wantAttempt := jobs.StepSucceeded, 1
		if i < 2 {
			wantStatus, wantAttempt = jobs.StepSkipped, 0
		}
		if s.Name != orchestrator.Steps[i] || s.Status != wantStatus || s.Attempt != wantAttempt {
			t.Fatalf("new job step %d: %+v; steps:%s", i+1, s, describeSteps(steps))
		}
	}
	if st := scalar[string](t, h, `SELECT status FROM provisioning_jobs WHERE id = $1`, cr.Job.ID); st != jobs.StatusRolledBack {
		t.Fatalf("the rolled-back job became %s", st)
	}
	newInst, status, prefix := h.instanceOf(t, cr.TenantID)
	if newInst == oldInst || status != orphans.StatusRunning {
		t.Fatalf("instance %s %s (old %s)", newInst, status, oldInst)
	}
	if st := scalar[string](t, h, `SELECT status FROM tenant_instances WHERE id = $1`, oldInst); st != orphans.StatusRemoved {
		t.Fatalf("old instance %s", st)
	}
	if st := scalar[string](t, h, `SELECT status FROM tenants WHERE id = $1`, cr.TenantID); st != "active" {
		t.Fatalf("tenant %s", st)
	}
	valid := validPrefixes(h.keys(t, cr.TenantID, newInst, slug))
	if len(valid) != 1 || valid[0] != prefix {
		t.Fatalf("valid keys %v, registry %s", valid, prefix)
	}
	h.noOrphans(t)
	return fmt.Sprintf("E2E-51 edge.verify permanent ⇒ rolled_back ⇒ /retry ⇒ new job %s (steps 1–2 skipped, 3–19 attempt 1), "+
		"new instance %s (old %s removed), tenant active; %5.1fs", short(r.Job.ID), short(newInst), short(oldInst), time.Since(start).Seconds())
}

func short(id uuid.UUID) string { return id.String()[:8] }
