package jobs

// Tests that need no database.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// planKinds are the job kinds of the §13.5 table.
var planKinds = []string{
	"tenant.provision", "tenant.suspend", "tenant.resume", "tenant.deprovision",
	"instance.reconfigure", "instance.restart", "instance.upgrade", "instance.quarantine", "instance.release",
	"instance.backup", "instance.restore", "apikey.rotate", "backup.purge", "inventory.sync", "device.revoke",
	"policy.apply", "policy.drift_check", "instance.reconcile", "host.reconcile", "instance.oidc_check", "partition.maintain",
	"notification.send", "idp.audit_sync", "enrollment.reconcile", "usage.collect", "health.probe", "relay.probe", "job.reaper",
	"grant.expire", "session.gc", "retention.sweep", "tenant.keys_destroy",
}

// TestKindsRegistry: every kind of §13.5 is registered exactly once with a name the DB (CHECK) and the API (JobKind
// pattern) accept; the lifecycle group of §13.5 (d) holds the tenant lock, instance.backup releases it on failure, and
// no other kind takes it.
func TestKindsRegistry(t *testing.T) {
	got := KindNames()
	want := slices.Clone(planKinds)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("registered kinds = %v\nwant %v", got, want)
	}
	dbRE := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	lifecycle := []string{"tenant.provision", "tenant.suspend", "tenant.resume", "tenant.deprovision",
		"instance.reconfigure", "instance.restart", "instance.upgrade", "instance.restore"}
	for name, k := range DefaultKinds() {
		if !dbRE.MatchString(name) || !kindParam.MatchString(name) {
			t.Errorf("%s: name rejected by the DB CHECK or the JobKind pattern", name)
		}
		want := LockNone
		switch {
		case slices.Contains(lifecycle, name):
			want = LockHold
		case name == "instance.backup":
			want = LockRelease
		}
		if k.Lock != want {
			t.Errorf("%s: lock policy %d, want %d", name, k.Lock, want)
		}
		if (k.Lock == LockHold) != (k.Queue == QueueLifecycle) {
			t.Errorf("%s: queue %s — the lifecycle queue is exactly the lifecycle group", name, k.Queue)
		}
	}
	// §13.5 dedupe keys: one lifecycle key per tenant for tenant.*, kind inside the instance keys
	tenant, inst := uuid.New(), uuid.New()
	for kind, want := range map[string]string{
		"tenant.provision":   "tenant:" + tenant.String() + ":lifecycle",
		"tenant.suspend":     "tenant:" + tenant.String() + ":lifecycle",
		"instance.restart":   "instance:" + inst.String() + ":instance.restart",
		"instance.restore":   "instance:" + inst.String() + ":restore",
		"instance.backup":    "instance:" + inst.String() + ":backup:s1",
		"policy.apply":       "tenant:" + tenant.String() + ":policy.apply",
		"device.revoke":      "device:dev-1:revoke",
		"partition.maintain": "partition.maintain:s1",
		"job.reaper":         "job.reaper:s1",
	} {
		got, err := registry[kind].dedupeKey(Spec{TenantID: &tenant, InstanceID: &inst, Object: "dev-1", Slot: "s1"})
		if err != nil || got != want {
			t.Errorf("%s: dedupe key %q (err %v), want %q", kind, got, err, want)
		}
	}
	if _, err := registry["instance.backup"].dedupeKey(Spec{TenantID: &tenant, InstanceID: &inst}); !errors.Is(err, ErrInvalidSpec) {
		t.Errorf("instance.backup without a slot: err %v, want ErrInvalidSpec", err)
	}
	if got := LockKey(tenant); got != "tenant:"+tenant.String()+":lifecycle" {
		t.Errorf("LockKey = %q", got)
	}
}

// TestDefaultConfigExplicit: §11.3 (checked at P2-T12) — the lifecycle queue's worker timeout and River's stuck-job
// rescue threshold are set explicitly and match (15 min), the whole-job timeout of the lifecycle group is 10 min, and
// job.reaper (every minute) always acts before River's rescuer; none of River's timeouts is left at its default.
func TestDefaultConfigExplicit(t *testing.T) {
	c := DefaultConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.RescueStuckJobsAfter != 15*time.Minute || c.ReaperInterval != time.Minute {
		t.Errorf("RescueStuckJobsAfter %s, ReaperInterval %s; want 15m and 1m", c.RescueStuckJobsAfter, c.ReaperInterval)
	}
	for name, k := range c.Kinds {
		if k.Lock == LockHold && (k.Timeout != 10*time.Minute || k.WorkerTimeout != c.RescueStuckJobsAfter || k.MaxAttempts != 6) {
			t.Errorf("%s: timeout %s, worker timeout %s, attempts %d; want 10m, = rescue threshold, 1 + 5 retries",
				name, k.Timeout, k.WorkerTimeout, k.MaxAttempts)
		}
		if k.Timeout+c.ReaperInterval >= c.RescueStuckJobsAfter {
			t.Errorf("%s: job.reaper would not act before River's rescuer", name)
		}
	}
	w := &Worker{cfg: c, metrics: newMetrics(nil), handlers: map[string]Handler{}}
	rc := w.riverConfig()
	defaults := (&river.Config{}).WithDefaults()
	for name, v := range map[string][2]time.Duration{
		"JobTimeout":           {rc.JobTimeout, defaults.JobTimeout},
		"RescueStuckJobsAfter": {rc.RescueStuckJobsAfter, defaults.RescueStuckJobsAfter},
		"CompletedRetention":   {rc.CompletedJobRetentionPeriod, 0},
		"CancelledRetention":   {rc.CancelledJobRetentionPeriod, 0},
		"DiscardedRetention":   {rc.DiscardedJobRetentionPeriod, 0},
		"SoftStopTimeout":      {rc.SoftStopTimeout, defaults.SoftStopTimeout},
		"JobStuckThreshold":    {rc.JobStuckThreshold, 0},
		"FetchCooldown":        {rc.FetchCooldown, 0},
		"FetchPollInterval":    {rc.FetchPollInterval, 0},
	} {
		if v[0] <= 0 {
			t.Errorf("River %s not set explicitly", name)
		}
		if name == "RescueStuckJobsAfter" && v[0] == v[1] {
			t.Errorf("River %s left at the library default %s", name, v[1])
		}
	}
	if rc.ReindexerSchedule == nil || len(rc.Queues) != 4 || rc.Queues[QueueLifecycle].MaxWorkers < 1 ||
		rc.Queues[QueueUrgent].MaxWorkers < 1 {
		t.Errorf("River config: reindexer %v, queues %v", rc.ReindexerSchedule, rc.Queues)
	}
	qw := &queueWorker{w: w}
	if got := qw.Timeout(&river.Job[queueArgs]{Args: queueArgs{JobKind: "tenant.provision"}}); got != 15*time.Minute {
		t.Errorf("worker timeout of the lifecycle queue = %s, want 15m", got)
	}

	for name, mutate := range map[string]func(*Config){
		"rescue below lifecycle timeout + reaper": func(c *Config) { c.RescueStuckJobsAfter = 10 * time.Minute },
		"zero retry base":                         func(c *Config) { c.RetryBase = 0 },
		"worker timeout below timeout": func(c *Config) {
			k := c.Kinds["policy.apply"]
			k.WorkerTimeout = time.Second
			c.Kinds["policy.apply"] = k
		},
		"queue without workers": func(c *Config) { delete(c.Queues, QueueMaintenance) },
	} {
		c := DefaultConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted: %s", name)
		}
	}
}

// TestBackoff: exponential from 2 s, capped at 60 s, ±20 % jitter (§11.3).
func TestBackoff(t *testing.T) {
	for attempt, base := range map[int]time.Duration{1: 2 * time.Second, 2: 4 * time.Second, 3: 8 * time.Second,
		5: 32 * time.Second, 6: time.Minute, 30: time.Minute, 400: time.Minute} {
		for range 50 {
			d := backoff(attempt, 2*time.Second, time.Minute)
			if d < base*8/10 || d > base*12/10 {
				t.Fatalf("attempt %d: delay %s outside %s ± 20 %%", attempt, d, base)
			}
		}
	}
}

// TestErrorsAndScrub: codes survive wrapping, unknown codes fall back, credentials never reach a stored message.
func TestErrorsAndScrub(t *testing.T) {
	code, perm, msg := classify(errors.Join(errors.New("ctx"), Permanent("upstream_rejected", errors.New("boom"))))
	if code != "upstream_rejected" || !perm || !strings.Contains(msg, "boom") {
		t.Errorf("classify permanent = %q %v %q", code, perm, msg)
	}
	if code, perm, _ := classify(Transient("Bad Code!", errors.New("x"))); code != CodeHandlerError || perm {
		t.Errorf("invalid code kept: %q %v", code, perm)
	}
	stored := string(jobError("instance_unavailable", "calling with "+canary+" failed"))
	if strings.Contains(stored, "CANARY") || !strings.Contains(stored, "[REDACTED]") {
		t.Errorf("credential in stored error: %s", stored)
	}
	if long := scrub(strings.Repeat("x", 5000)); len(long) > maxMessage+4 {
		t.Errorf("message not bounded: %d bytes", len(long))
	}
	var e storedError
	if err := json.Unmarshal(jobError("Not A Code", "m"), &e); err != nil || e.Code != CodeHandlerError {
		t.Errorf("invalid code stored as %q (%v)", e.Code, err)
	}
}

// TestCursor: the page cursor round-trips and malformed cursors are rejected (422).
func TestCursor(t *testing.T) {
	at := time.Date(2026, 11, 17, 4, 5, 6, 123456000, time.UTC)
	id := uuid.New()
	gotAt, gotID, err := decodeCursor(encodeCursor(at, id))
	if err != nil || !gotAt.Equal(at) || gotID != id {
		t.Fatalf("cursor round trip: %s %s %v", gotAt, gotID, err)
	}
	for _, bad := range []string{"%%%", "bm9waXBl", encodeCursor(at, id)[:10], strings.Repeat("A", 600)} {
		if _, _, err := decodeCursor(bad); !errors.Is(err, ErrInvalidFilter) {
			t.Errorf("cursor %q accepted", bad)
		}
	}
	for _, f := range []ListFilter{{Limit: 201}, {Limit: -1}, {Status: "done"}, {Kind: "Tenant.Provision"}, {Kind: "nodot"}} {
		if _, _, err := f.params(); !errors.Is(err, ErrInvalidFilter) {
			t.Errorf("filter %+v accepted", f)
		}
	}
	if p, limit, err := (ListFilter{}).params(); err != nil || limit != DefaultLimit || p.RowLimit != DefaultLimit+1 {
		t.Errorf("default filter: %+v %d %v", p, limit, err)
	}
}

// TestProjectionContract: the safe projection carries no raw error or step detail, step messages come from the
// catalog, and both projections decode strictly into the types generated from api/openapi.yaml (P2-T02).
func TestProjectionContract(t *testing.T) {
	tenant := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	code := "instance_unavailable"
	rt, rid := "tenant", tenant.String()
	row := sqlcdb.ProvisioningJob{ID: uuid.New(), TenantID: &tenant, Kind: "instance.restart", Status: StatusFailedResumable,
		CurrentStep: ptr("instance.stop"), Attempt: 6, MaxAttempts: 6, Input: []byte(`{}`), CreatedAt: now,
		ResourceType: &rt, ResourceID: &rid,
		Error: []byte(`{"code":"worker_lost","message":"agent at /opt/meshguard/tenants/x unreachable","detail":{"host":"10.250.0.2"}}`)}
	steps := []sqlcdb.ProvisioningJobStep{
		{JobID: row.ID, Seq: 0, Name: "config.render", Status: StepSucceeded, Attempt: 1, StartedAt: &now, FinishedAt: &now},
		{JobID: row.ID, Seq: 1, Name: "instance.stop", Status: StepFailed, Attempt: 2, StartedAt: &now, FinishedAt: &now,
			ErrorCode: &code, Detail: []byte(`{"error":"docker: container mg-t-x exited"}`)},
	}
	safe, err := json.Marshal(project(row, steps))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"/opt/meshguard", "10.250.0.2", "docker", "mg-t-x", `"detail"`, `"message":"agent`} {
		if bytes.Contains(safe, []byte(leak)) {
			t.Errorf("safe projection leaks %q: %s", leak, safe)
		}
	}
	if !bytes.Contains(safe, []byte(`"Failed (instance_unavailable)"`)) || !bytes.Contains(safe, []byte(`{"code":"worker_lost"}`)) {
		t.Errorf("safe projection lacks the catalog message or the error code: %s", safe)
	}
	strict := func(b []byte, v any) {
		t.Helper()
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("does not decode into %T: %v\n%s", v, err, b)
		}
	}
	var g gen.Job
	strict(safe, &g)
	if g.Id != row.ID || g.Status != gen.JobStatus(StatusFailedResumable) || len(g.Steps) != 2 || g.Error == nil ||
		g.Error.Code != "worker_lost" || g.Resource == nil || g.Resource.Id != rid {
		t.Errorf("decoded gen.Job = %+v", g)
	}
	for _, st := range g.Steps {
		if !st.Status.Valid() {
			t.Errorf("step %s: status %q is not a JobStepStatus of the API", st.Name, st.Status)
		}
	}
	list, _ := json.Marshal(JobList{Items: []Job{project(row, steps)}})
	strict(list, &gen.JobList{})
	plat, _ := json.Marshal(projectPlatform(row, steps))
	var pg gen.PlatformJob
	strict(plat, &pg)
	if pg.Error == nil || pg.Error.Message == nil || len(pg.Steps) != 2 || pg.Steps[1].Detail == nil {
		t.Errorf("platform projection lacks the raw error or step detail: %s", plat)
	}
	// the statuses of provisioning_jobs (DB CHECK) are exactly the JobStatus enum of the API
	spec, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(spec, []byte("enum: [queued, running, failed_resumable, compensating, rolled_back, succeeded, failed, cancelled]")) {
		t.Error("JobStatus enum of api/openapi.yaml differs from the statuses of provisioning_jobs")
	}
	// and the statuses of provisioning_job_steps (DB CHECK) are exactly the JobStepStatus enum
	stepStatuses := []string{StepRunning, StepSucceeded, StepFailed, StepSkipped}
	if !bytes.Contains(spec, []byte("enum: ["+strings.Join(stepStatuses, ", ")+"]")) {
		t.Error("JobStepStatus enum of api/openapi.yaml differs from the statuses of provisioning_job_steps")
	}
	for _, st := range stepStatuses {
		if !gen.JobStepStatus(st).Valid() {
			t.Errorf("step status %q is not a generated JobStepStatus value", st)
		}
	}
}

// TestRequestHash: formatting of the JSON body does not change the hash; method, path and content do.
func TestRequestHash(t *testing.T) {
	a := RequestHash("post", "/api/v1/tenants/x/devices/y/expire", []byte(`{"b":1,"a":[1,2]}`))
	b := RequestHash("POST", "/api/v1/tenants/x/devices/y/expire", []byte("{ \"a\": [1, 2],\n \"b\": 1 }"))
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Errorf("same request, different hash")
	}
	for _, other := range [][]byte{
		RequestHash("POST", "/api/v1/tenants/z/devices/y/expire", []byte(`{"b":1,"a":[1,2]}`)),
		RequestHash("POST", "/api/v1/tenants/x/devices/y/expire", []byte(`{"b":2,"a":[1,2]}`)),
		RequestHash("PUT", "/api/v1/tenants/x/devices/y/expire", []byte(`{"b":1,"a":[1,2]}`)),
	} {
		if bytes.Equal(a, other) {
			t.Error("different request, same hash")
		}
	}
}

// TestRetentionNeverTargetsAudit: no query of the job framework deletes from audit_events (§6.1: audit retention is the
// drop of partitions only); the privilege side is checked on PostgreSQL in TestRetentionSweep.
func TestRetentionNeverTargetsAudit(t *testing.T) {
	sql, err := os.ReadFile(filepath.Join("..", "..", "database", "queries", "jobs.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?is)(DELETE\s+FROM|TRUNCATE)\s+(\w+\.)?audit_events`).Match(sql) {
		t.Error("database/queries/jobs.sql deletes from audit_events")
	}
}

func ptr[T any](v T) *T { return &v }

// TestStepGateErrors (P3-T18): the gate's verdict reaches the job as is when it is a job error, as Resumable step_gate
// otherwise (never retried in place, no compensation); no gate ⇒ nothing stops; the gate sees the job's identity.
func TestStepGateErrors(t *testing.T) {
	tenant, inst := uuid.New(), uuid.New()
	run := &Run{ID: uuid.New(), Kind: "instance.reconfigure", TenantID: &tenant, InstanceID: &inst, w: &Worker{}}
	if err := run.gate(context.Background(), nil); err != nil {
		t.Fatalf("no gate: %v", err)
	}
	var seen GateRun
	run.w.gate = func(_ context.Context, _ *sqlcdb.Queries, g GateRun) error {
		seen = g
		return Resumable("instance_quarantined", errors.New("quarantined"))
	}
	if err := run.gate(context.Background(), nil); CodeOf(err) != "instance_quarantined" || !IsResumable(err) ||
		seen.ID != run.ID || seen.Kind != run.Kind || *seen.TenantID != tenant || *seen.InstanceID != inst {
		t.Fatalf("gate error %v, seen %+v", err, seen)
	}
	run.w.gate = func(context.Context, *sqlcdb.Queries, GateRun) error { return errors.New("plain") }
	if err := run.gate(context.Background(), nil); CodeOf(err) != "step_gate" || !IsResumable(err) {
		t.Fatalf("plain gate error ⇒ %v", err)
	}
	run.w.gate = func(context.Context, *sqlcdb.Queries, GateRun) error { return nil }
	if err := run.gate(context.Background(), nil); err != nil {
		t.Fatalf("open gate: %v", err)
	}
}
