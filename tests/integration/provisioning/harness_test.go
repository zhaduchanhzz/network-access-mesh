//go:build linux && dockerintegration

package provisioning

// The harness side of the run: the api's half of provisioning (Creator — POST /platform/tenants steps 1–2 —, Control —
// /retry, /rollback — with the api's database roles), the worker processes, the observations of the database, the
// agent and Docker, and the orphan detector.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/deprovision"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/faultinject"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/orphans"
)

type harness struct {
	e       env
	pg      *storetest.Env
	db      string
	su      *pgx.Conn
	api     *store.Store
	wrk     *store.Store
	sec     *secrets.Store
	keyring string
	creator *orchestrator.Creator
	control *orchestrator.Control
	// the 2P path of the deprovision (P3-T09): the api's requester, the approvals service, two Super Admins
	deprov  *deprovision.Requester
	appr    *approvals.Service
	staff   [2]approvals.Actor
	agent   *agentclient.Client
	docker  *client.Client
	actor   uuid.UUID
	logDir  string
	mu      sync.Mutex
	workers int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	e := mustEnv(t)
	pg := storetest.Require(t)
	h := &harness{e: e, pg: pg, actor: uuid.New(), logDir: os.Getenv("PIT_LOG_DIR")}
	if h.logDir == "" {
		h.logDir = t.TempDir()
	}
	h.db = pg.NewDatabase(t)
	h.su = pg.Admin(t, h.db)
	// The host of the run — the same run_uid range, tenant pool and public entry as the agent's configuration.
	h.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry)
		VALUES ($1, 'pit-host', 'lab', int4range($2, $3, '[]'), $4::cidr, jsonb_build_object('ipv4', $5::text, 'mode', 'direct'))`,
		uuid.New(), e.runUIDs[0], e.runUIDs[1], e.pool.String(), e.publicIPv4)
	// quota.max_tenants (0012: 10, the MVP cap) counts every tenant not `deleted` — rolled-back (failed) ones included:
	// the run creates ~22 tenants.
	h.exec(t, `UPDATE system_settings SET value = '100' WHERE key = 'quota.max_tenants'`)
	h.api = pg.OpenStore(t, h.db, "mg_api_tenant", "mg_api_platform", 6)
	h.wrk = pg.OpenStore(t, h.db, "mg_worker_tenant", "mg_worker_platform", 6)
	// kek-app of the run, shared by the harness and its worker processes (same UID)
	h.keyring = t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	for name, v := range map[string]string{"kek-1": hex.EncodeToString(k) + "\n", secrets.ActiveFile: "kek-1\n"} {
		if err := os.WriteFile(filepath.Join(h.keyring, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kr, err := secrets.LoadKeyring(secrets.KEKApp, h.keyring)
	if err != nil {
		t.Fatal(err)
	}
	if h.sec, err = secrets.New(h.wrk, secrets.Options{App: kr}); err != nil {
		t.Fatal(err)
	}
	apiSec, err := secrets.New(h.api, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	if h.creator, err = orchestrator.NewCreator(orchestrator.CreatorConfig{Store: h.api, Secrets: apiSec,
		Quota: usage.NewChecker(h.api), QuotaTx: usage.TenantCreationTx, BaseDomain: e.baseDomain}); err != nil {
		t.Fatal(err)
	}
	h.control = orchestrator.NewControl(h.api).WithQuota(usage.TenantCreationTx)
	h.deprov = deprovision.NewRequester(h.api)
	reg, err := approvals.NewRegistry(approvals.Typed(approvals.Spec{Name: deprovision.Action, Scope: authz.ScopePlatform,
		ResourceType: "tenant", Permission: deprovision.Permission},
		func(ctx context.Context, tx *store.Tx, ex approvals.Execution, p deprovision.Payload) (*uuid.UUID, error) {
			return h.deprov.EnqueueApproved(ctx, tx, ex.Request.RequestedBy.IdentityID, ex.Request.ID, p)
		}))
	if err != nil {
		t.Fatal(err)
	}
	if h.appr, err = approvals.New(h.api, approvals.Config{Approvers: authz.New(h.api), Registry: reg}); err != nil {
		t.Fatal(err)
	}
	pidp := uuid.New()
	h.exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://auth.pit.test/realms/platform', 'mg-console', 'keycloak', 'active')`, pidp)
	for i := range h.staff {
		id := uuid.New()
		h.exec(t, `INSERT INTO identities (id, idp_id, scope, subject, display_name) VALUES ($1, $2, 'platform', $3, 'Super Admin')`,
			id, pidp, "sa-"+id.String())
		h.exec(t, `INSERT INTO platform_users (identity_id, role_id) SELECT $1, id FROM roles WHERE scope = 'platform' AND key = 'super_admin'`, id)
		h.staff[i] = approvals.Actor{IdentityID: id, Scope: authz.ScopePlatform}
	}
	if h.agent, err = agentclient.New(agentclient.Config{Socket: e.socket(), TokenFile: e.agentTokenFile()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.agent.Close() })
	if h.docker, err = client.New(client.WithHost("unix://" + filepath.Join("/var/run", "docker.sock"))); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.docker.Close() })
	h.ready(t)
	return h
}

// ready waits for the agent (Health over its socket, as the worker) and the test edge (admin listener).
func (h *harness) ready(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		hr, aerr := h.agent.Health(ctx, &agentv1.HealthRequest{})
		cancel()
		eerr := h.edgeUp(t)
		if aerr == nil && eerr == nil {
			t.Logf("agent %s (driver %s, %d allowed images), test edge up", hr.GetVersion(), hr.GetDriver(), hr.GetAllowedImages())
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not ready: agent %v, edge %v", aerr, eerr)
		}
		time.Sleep(time.Second)
	}
}

func (h *harness) edgeUp(t *testing.T) error {
	tok, err := agentclient.ReadToken(h.e.edgeTokenFile())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.e.edgeAdmin+"/version", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-MG-Token", tok)
	req.Header.Set("X-MG-Instance", h.e.prefix+"-nobody")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound { // the instance does not exist: the edge's dial error is a 404
		return fmt.Errorf("edge admin listener answered %d", resp.StatusCode)
	}
	return nil
}

func (h *harness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.su.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("exec: %v\n%s", err, sql)
	}
}

func scalar[T any](t *testing.T, h *harness, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := h.su.QueryRow(t.Context(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return v
}

// ---------------------------------------------------------------------------------------------------- the api side

func (h *harness) reqCtx(t *testing.T, action string) context.Context {
	id := h.actor
	return audit.WithRequest(t.Context(), &audit.Request{Action: action, ActorType: audit.ActorIdentity, ActorIdentityID: &id,
		ActorDisplay: "operator", RequestID: "pit-" + uuid.NewString()[:8]})
}

// create is POST /platform/tenants (steps 1–2 in the api's transaction).
func (h *harness) create(t *testing.T, slug string) orchestrator.Created {
	t.Helper()
	c, err := h.creator.Create(h.reqCtx(t, orchestrator.ActionTenantCreate), h.actor, orchestrator.CreateRequest{Slug: slug,
		Name: "Tenant " + slug, PlanKey: "standard", OwnerEmail: "owner@" + slug + ".example",
		IdP: orchestrator.IdPRequest{Driver: orchestrator.DriverKeycloak}, Settings: []byte(`{"dns": {"magic_dns": true}}`)},
		&orchestrator.Idempotency{Key: "pit-" + slug, Hash: []byte(strings.Repeat("h", 32))})
	if err != nil {
		t.Fatalf("create %s: %v", slug, err)
	}
	return c
}

// deprovision is DELETE /platform/tenants/{id} by one Super Admin (step-up) and its approval by the second one (§8.5
// 2P, P3-T09): the checks of the request, the approval request, the approval that enqueues tenant.deprovision.
func (h *harness) deprovision(t *testing.T, tenant uuid.UUID, slug string, skip bool) uuid.UUID {
	t.Helper()
	a, b := h.staff[0], h.staff[1]
	a.AuthTime, b.AuthTime = time.Now(), time.Now()
	p, err := h.deprov.Check(h.reqCtxAs(t, a.IdentityID, "platform.tenant.delete.request"), tenant, slug, skip)
	if err != nil {
		t.Fatalf("deprovision %s: %v", slug, err)
	}
	r, err := h.appr.Request(h.reqCtxAs(t, a.IdentityID, "platform.tenant.delete.request"), a, approvals.NewRequest{
		Action: deprovision.Action, ResourceID: tenant.String(), Payload: p, Reason: "provisioning harness"})
	if err != nil {
		t.Fatalf("deprovision %s: approval request: %v", slug, err)
	}
	done, err := h.appr.Approve(h.reqCtxAs(t, b.IdentityID, "platform.approval.approve"), b,
		approvals.Ref{Scope: authz.ScopePlatform, ID: r.ID}, r.PayloadSHA256)
	if err != nil || done.JobID == nil {
		t.Fatalf("deprovision %s: approval: %+v %v", slug, done, err)
	}
	return *done.JobID
}

func (h *harness) reqCtxAs(t *testing.T, actor uuid.UUID, action string) context.Context {
	return audit.WithRequest(t.Context(), &audit.Request{Action: action, ActorType: audit.ActorIdentity, ActorIdentityID: &actor,
		ActorDisplay: "super admin", RequestID: "pit-" + uuid.NewString()[:8]})
}

func (h *harness) retry(t *testing.T, job uuid.UUID) orchestrator.ControlResult {
	t.Helper()
	r, err := h.control.Retry(h.reqCtx(t, orchestrator.ActionJobRetry), h.actor, job,
		&orchestrator.Idempotency{Key: "pit-retry-" + job.String(), Hash: []byte(strings.Repeat("r", 32))})
	if err != nil {
		t.Fatalf("/retry %s: %v", job, err)
	}
	return r
}

func (h *harness) rollback(t *testing.T, job uuid.UUID) orchestrator.ControlResult {
	t.Helper()
	r, err := h.control.Rollback(h.reqCtx(t, orchestrator.ActionJobRollback), h.actor, job,
		&orchestrator.Idempotency{Key: "pit-rollback-" + job.String(), Hash: []byte(strings.Repeat("b", 32))})
	if err != nil {
		t.Fatalf("/rollback %s: %v", job, err)
	}
	return r
}

// reap stands in for the time a dead worker's job waits: timeout_at is moved to the past, and job.reaper (every 2 s in
// the worker processes of the run) settles the job failed_resumable (worker_lost) instead of after 10 minutes.
func (h *harness) reap(t *testing.T, job uuid.UUID) {
	t.Helper()
	h.exec(t, `UPDATE provisioning_jobs SET timeout_at = now() - interval '1 second' WHERE id = $1 AND status = 'running'`, job)
	h.waitJob(t, job, 2*time.Minute, jobs.StatusFailedResumable)
	if code := h.jobErrorCode(t, job); code != jobs.CodeWorkerLost {
		t.Fatalf("reaped with %s, want %s", code, jobs.CodeWorkerLost)
	}
}

// ---------------------------------------------------------------------------------------------------- jobs, steps

type stepRow struct {
	Seq          int
	Name         string
	Status       string
	Attempt      int
	ErrorCode    string
	Compensation string
	Resources    string
}

func (h *harness) steps(t *testing.T, job uuid.UUID) []stepRow {
	t.Helper()
	rows, err := h.su.Query(t.Context(), `SELECT seq, name, status, attempt, COALESCE(error_code, ''),
		COALESCE(compensation_status, ''), COALESCE(created_resources::text, '') FROM provisioning_job_steps WHERE job_id = $1 ORDER BY seq`, job)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []stepRow
	for rows.Next() {
		var s stepRow
		if err := rows.Scan(&s.Seq, &s.Name, &s.Status, &s.Attempt, &s.ErrorCode, &s.Compensation, &s.Resources); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func stepByName(steps []stepRow, name string) (stepRow, bool) {
	for _, s := range steps {
		if s.Name == name {
			return s, true
		}
	}
	return stepRow{}, false
}

func describeSteps(steps []stepRow) string {
	var b strings.Builder
	for _, s := range steps {
		fmt.Fprintf(&b, "\n  %2d %-22s %-10s attempt %d %s comp=%s", s.Seq, s.Name, s.Status, s.Attempt, s.ErrorCode, s.Compensation)
	}
	return b.String()
}

// jobErrorCode is provisioning_jobs.error->>'code'.
func (h *harness) jobErrorCode(t *testing.T, job uuid.UUID) string {
	return scalar[string](t, h, `SELECT COALESCE(error->>'code', '') FROM provisioning_jobs WHERE id = $1`, job)
}

// waitJob waits until the job is in one of want; a job that settles elsewhere fails the test at once.
func (h *harness) waitJob(t *testing.T, job uuid.UUID, timeout time.Duration, want ...string) string {
	t.Helper()
	settled := []string{jobs.StatusSucceeded, jobs.StatusRolledBack, jobs.StatusFailedResumable, jobs.StatusFailed, jobs.StatusCancelled}
	deadline := time.Now().Add(timeout)
	for {
		s := scalar[string](t, h, `SELECT status FROM provisioning_jobs WHERE id = $1`, job)
		if slices.Contains(want, s) {
			return s
		}
		if slices.Contains(settled, s) || time.Now().After(deadline) {
			t.Fatalf("job %s is %s (error %s), want %v; steps:%s", job, s, h.jobErrorCode(t, job), want, describeSteps(h.steps(t, job)))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------------------------------- worker processes

type worker struct {
	name string
	cmd  *exec.Cmd
	log  string
	done chan struct{}
	err  error
}

// startWorker starts one worker process of the run with a fault plan and waits until its job worker runs.
func (h *harness) startWorker(t *testing.T, name string, plan faultinject.Plan) *worker {
	t.Helper()
	h.mu.Lock()
	h.workers++
	n := h.workers
	h.mu.Unlock()
	w := &worker{name: fmt.Sprintf("%02d-%s", n, name), done: make(chan struct{})}
	w.log = filepath.Join(h.logDir, w.name+".log")
	f, err := os.Create(w.log) //nolint:gosec // G304: the run's own log directory
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G204: this test binary, a fixed test name
	w.cmd = exec.CommandContext(context.WithoutCancel(t.Context()), os.Args[0], "-test.run=^TestWorkerProcess$", "-test.v",
		"-test.count=1", "-test.timeout=60m")
	w.cmd.Env = append(os.Environ(), "PIT_ROLE=worker", "PIT_DB="+h.db, "PIT_KEYRING="+h.keyring, "PIT_FAULTS="+plan.Encode())
	w.cmd.Stderr = f
	w.cmd.Cancel = func() error { return w.cmd.Process.Signal(syscall.SIGTERM) }
	out, err := w.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	go func() { // read stdout to EOF (the process ended), then Wait — never Wait before the reads are done
		sc := bufio.NewScanner(out)
		once := sync.Once{}
		for sc.Scan() {
			line := sc.Text()
			_, _ = io.WriteString(f, line+"\n")
			if strings.Contains(line, markReady) {
				once.Do(func() { close(ready) })
			}
		}
		w.err = w.cmd.Wait()
		_ = f.Close()
		close(w.done)
	}()
	select {
	case <-ready:
	case <-w.done:
		t.Fatalf("worker %s exited before it was ready: %v\n%s", w.name, w.err, tail(w.log, 40))
	case <-time.After(90 * time.Second):
		t.Fatalf("worker %s not ready\n%s", w.name, tail(w.log, 40))
	}
	t.Cleanup(func() { w.stop(t) })
	t.Logf("worker %s started (pid %d), faults: %v", w.name, w.cmd.Process.Pid, plan)
	return w
}

// stop ends the worker gracefully (SIGTERM — jobs resume elsewhere), SIGKILL after 30 s.
func (w *worker) stop(t *testing.T) {
	select {
	case <-w.done:
		return
	default:
	}
	_ = w.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-w.done:
	case <-time.After(30 * time.Second):
		_ = w.cmd.Process.Kill()
		<-w.done
		t.Errorf("worker %s did not stop on SIGTERM", w.name)
	}
	if s := summary(w.log); s != "" {
		t.Logf("worker %s: %s", w.name, s)
	}
}

// waitKilled waits until the worker process died of SIGKILL (a kill fault).
func (w *worker) waitKilled(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-w.done:
	case <-time.After(timeout):
		t.Fatalf("worker %s still alive after %v\n%s", w.name, timeout, tail(w.log, 40))
	}
	var ee *exec.ExitError
	if !errors.As(w.err, &ee) {
		t.Fatalf("worker %s: %v, want killed", w.name, w.err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("worker %s ended with %v, want SIGKILL", w.name, w.err)
	}
}

func tail(path string, n int) string {
	b, _ := os.ReadFile(path) //nolint:gosec // G304: the run's own log
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func summary(path string) string {
	b, _ := os.ReadFile(path) //nolint:gosec // G304: the run's own log
	for _, l := range strings.Split(string(b), "\n") {
		if s, ok := strings.CutPrefix(l, markSummary); ok {
			return s
		}
	}
	return ""
}

// leaks returns the worker logs that contain an API key or its secret part (hskey-api-…): never allowed (§11.3).
func (h *harness) leaks(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(h.logDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, en := range entries {
		b, _ := os.ReadFile(filepath.Join(h.logDir, en.Name())) //nolint:gosec // G304: the run's own log
		if strings.Contains(string(b), "hskey-api-") {
			out = append(out, en.Name())
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------------- observations

// scope is the run's scope for the orphan detector.
func (h *harness) scope(settled bool) orphans.Scope {
	return orphans.Scope{SlugPrefix: h.e.prefix + "-", TenantsDir: h.e.tenantsDir(), Edge: h.e.edge,
		EdgeNetwork: h.e.edgeNetwork, Settled: settled, AllowSecrets: []string{"backup-key"}}
}

// sources are the real sources of the detector; Headscale is a fresh registry (no cached target) on the worker's roles.
func (h *harness) sources(t *testing.T) orphans.Sources {
	t.Helper()
	loc, err := locator.New(tenants.New(h.wrk, tenants.Options{BaseDomain: h.e.baseDomain}), h.sec,
		locator.Options{AdminURL: h.e.edgeAdmin, EdgeTokenFile: h.e.edgeTokenFile()})
	if err != nil {
		t.Fatal(err)
	}
	return orphans.Sources{DB: h.su, Docker: h.docker, Agent: h.agent, Secrets: h.sec,
		Headscale: headscale.NewRegistry(loc, headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1}})}
}

// noOrphans runs the orphan detector over the run (nothing in flight) and fails on any finding.
func (h *harness) noOrphans(t *testing.T) orphans.Inventory {
	t.Helper()
	return orphans.Require(t, t.Context(), h.sources(t), h.scope(true))
}

// findings runs the detector and returns the findings without failing (an intermediate state of a case).
func (h *harness) findings(t *testing.T, settled bool) ([]orphans.Finding, orphans.Inventory) {
	t.Helper()
	inv, err := orphans.Collect(t.Context(), h.sources(t), h.scope(settled))
	if err != nil {
		t.Fatal(err)
	}
	return orphans.Check(inv), inv
}

// instanceOf is the tenant's live instance (or the last one).
func (h *harness) instanceOf(t *testing.T, tenant uuid.UUID) (id uuid.UUID, status, prefix string) {
	t.Helper()
	err := h.su.QueryRow(t.Context(), `SELECT id, status, COALESCE(api_key_prefix, '') FROM tenant_instances
		WHERE tenant_id = $1 ORDER BY (status <> 'removed') DESC, created_at DESC LIMIT 1`, tenant).Scan(&id, &status, &prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id, status, prefix
}

// keys are the API keys of an instance as Headscale holds them (through the agent): prefix → valid now.
func (h *harness) keys(t *testing.T, tenant, instance uuid.UUID, slug string) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	r, err := h.agent.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{IncludeApiKeys: true,
		Instance: &agentv1.InstanceRef{InstanceId: instance.String(), TenantId: tenant.String(), Slug: slug}})
	if err != nil {
		t.Fatalf("keys of %s: %v", slug, err)
	}
	out := map[string]bool{}
	now := time.Now()
	for _, k := range r.GetStatus().GetApiKeys() {
		p := strings.TrimSuffix(strings.TrimPrefix(k.GetPrefix(), "hskey-api-"), "-***")
		e := k.GetExpiration()
		out[p] = e == nil || e.AsTime().Unix() <= 0 || e.AsTime().After(now)
	}
	return out
}

func validPrefixes(m map[string]bool) []string {
	var out []string
	for p, v := range m {
		if v {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// liveKeyVersions are the live versions of the tenant's headscale-api-key.
func (h *harness) liveKeyVersions(t *testing.T, tenant uuid.UUID) []int32 {
	t.Helper()
	rows, err := h.su.Query(t.Context(), `SELECT version FROM secrets WHERE tenant_id = $1 AND name = 'headscale-api-key'
		AND destroyed_at IS NULL ORDER BY version`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int32
	for rows.Next() {
		var v int32
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// teardown removes what the successful cases left running, the way Deprovision will (edge first, then compose down and
// the network); the activated directories stay for run.sh (DELETE_ARCHIVED needs the signed backup of P3-T11).
func (h *harness) teardown(t *testing.T) int {
	t.Helper()
	rows, err := h.su.Query(t.Context(), `SELECT i.id, i.tenant_id, t.slug FROM tenant_instances i JOIN tenants t ON t.id = i.tenant_id
		WHERE i.status <> 'removed' AND t.slug LIKE $1`, h.e.prefix+"-%")
	if err != nil {
		t.Fatal(err)
	}
	type inst struct {
		id, tenant uuid.UUID
		slug       string
	}
	var list []inst
	for rows.Next() {
		var i inst
		if err := rows.Scan(&i.id, &i.tenant, &i.slug); err != nil {
			t.Fatal(err)
		}
		list = append(list, i)
	}
	rows.Close()
	for _, i := range list {
		ref := &agentv1.InstanceRef{InstanceId: i.id.String(), TenantId: i.tenant.String(), Slug: i.slug}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		if _, err := h.agent.RemoveEdgeAttachment(ctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: ref, JobId: uuid.NewString(),
			Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION}); err != nil {
			t.Errorf("detach %s: %v", i.slug, err)
		}
		if _, err := h.agent.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: ref, JobId: uuid.NewString(),
			Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP}); err != nil {
			t.Errorf("remove %s: %v", i.slug, err)
		}
		cancel()
	}
	return len(list)
}
