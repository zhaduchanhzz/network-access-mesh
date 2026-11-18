package lifecycle

// PostgreSQL integration harness of suspend/resume (internal/store/storetest): one database for the package (database
// creation is serialised across every package of the run), every test with its own host and tenants — each with a
// running instance, four members (Owner, Admin, Viewer, End User — verified addresses) and its desired policy (the allow
// fixture of §22.1 applied through the real policy core) — and the real job framework (River worker) running the
// handler of this package. Headscale is a fake per tenant (policy and pre-auth key calls) behind a registry that, like
// the production locator, refuses a tenant whose status is not in its list (G2 L1). The real Headscale and the real
// locator are exercised by the e2e cases E2E-56…E2E-58 on the dev/CI stack.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// fakeHS is the part of a Headscale instance the jobs call: the policy (stored like 0.29.7 — GetPolicy returns exactly
// what SetPolicy stored) and the pre-auth keys (ExpirePreAuthKey sets the expiration to now, as Headscale does).
type fakeHS struct {
	headscale.Instance

	mu        sync.Mutex
	stored    string
	calls     []string
	checkErr  error // CheckPolicy answers this (persistent)
	checkFor  string
	keys      []headscale.PreAuthKey
	listErr   error // ListPreAuthKeys answers this (persistent)
	expireErr error // ExpirePreAuthKey answers this (persistent)
}

func (f *fakeHS) call(op string) { f.calls = append(f.calls, op) }

func (f *fakeHS) CheckPolicy(_ context.Context, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("CheckPolicy")
	if err := headscale.ValidatePolicyDocument(p); err != nil {
		return &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindValidation}
	}
	if f.checkErr != nil && (f.checkFor == "" || f.checkFor == p) {
		return f.checkErr
	}
	return nil
}

func (f *fakeHS) SetPolicy(_ context.Context, p string) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("SetPolicy")
	f.stored = p
	return headscale.Policy{Data: p, UpdatedAt: time.Now()}, nil
}

func (f *fakeHS) GetPolicy(context.Context) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("GetPolicy")
	if f.stored == "" {
		return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy}
	}
	return headscale.Policy{Data: f.stored, UpdatedAt: time.Now()}, nil
}

func (f *fakeHS) ListPreAuthKeys(context.Context) ([]headscale.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ListPreAuthKeys")
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Clone(f.keys), nil
}

func (f *fakeHS) ExpirePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call(fmt.Sprintf("ExpirePreAuthKey:%d", id))
	if f.expireErr != nil {
		return f.expireErr
	}
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys[i].Expiration = time.Now().Add(-time.Second)
		}
	}
	return nil
}

func (f *fakeHS) set(fn func(f *fakeHS)) { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }

func (f *fakeHS) Stored() string { f.mu.Lock(); defer f.mu.Unlock(); return f.stored }

func (f *fakeHS) Calls() []string { f.mu.Lock(); defer f.mu.Unlock(); return slices.Clone(f.calls) }

func (f *fakeHS) Keys() []headscale.PreAuthKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.keys)
}

// gatedReg is the headscale.Registry of the tests: like the production locator it reads the tenant's status in the
// registry at every ForTenant and refuses (instance_unavailable wrapping ErrNoInstance) a tenant outside statuses.
type gatedReg struct {
	st       *store.Store
	statuses []string
	mu       sync.Mutex
	hs       map[uuid.UUID]*fakeHS
}

func (r *gatedReg) ForTenant(ctx context.Context, t uuid.UUID) (headscale.Instance, error) {
	var status string
	if err := r.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetTenant(ctx, t)
		status = row.Status
		return err
	}); err != nil || !slices.Contains(r.statuses, status) {
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1,
			Err: fmt.Errorf("tenant is %q: %w", status, headscale.ErrNoInstance)}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hs[t]
	if !ok {
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1, Err: headscale.ErrNoInstance}
	}
	return h, nil
}

// tenantFx is one fixture tenant.
type tenantFx struct {
	id, instance                  uuid.UUID
	slug                          string
	owner, admin, viewer, endUser uuid.UUID // memberships
	adminIdentity                 uuid.UUID
	hs                            *fakeHS
	desired                       uuid.UUID // the allow fixture version
}

// rig is one test's world.
type rig struct {
	env    *storetest.Env
	db     string
	su     *pgx.Conn
	mu     sync.Mutex
	api    *store.Store // mg_api_* (the Requester)
	wrk    *store.Store // mg_worker_* (the handler, the policy core)
	reg    *gatedReg
	core   *policies.Service
	req    *Requester
	h      *Handler
	worker *jobs.Worker
	actor  uuid.UUID // the platform staff member asking
	host   uuid.UUID
	n      int
}

var shared struct {
	mu sync.Mutex
	db string
	n  int
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// allowFixture is the allow policy of §22.1 (every node of the tenant sees the others on TCP 8000).
func allowFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "infrastructure", "headscale", "templates", "test-allow-intra.hujson")) //nolint:gosec // G304: fixture of the repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rigOptions tune newRig.
type rigOptions struct {
	statuses []string               // the registry's reachable statuses; nil ⇒ ReachableStatuses (what the worker wires)
	noWorker bool                   // API-side tests: the jobs stay queued
	notifier notifications.Enqueuer // nil ⇒ notifications.Default
}

func newRig(t *testing.T, o rigOptions) *rig {
	t.Helper()
	env := storetest.Require(t)
	shared.mu.Lock()
	if shared.db == "" {
		shared.db = env.NewDatabase(t)
	}
	db := shared.db
	shared.mu.Unlock()
	g := &rig{env: env, db: db, su: env.Admin(t, db), actor: uuid.New(), host: uuid.New()}
	g.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, $2, 'lab', int4range(30000, 40000), '10.250.0.0/16')`, g.host, "host-"+randomHex(6))
	g.api = env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 6)
	g.wrk = env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 10)
	statuses := o.statuses
	if statuses == nil {
		statuses = ReachableStatuses
	}
	g.reg = &gatedReg{st: g.wrk, statuses: statuses, hs: map[uuid.UUID]*fakeHS{}}
	core, err := policies.New(g.wrk, policies.Config{Registry: g.reg, LockWait: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	g.core = core
	g.req = NewRequester(g.api)
	g.h, err = New(Config{Store: g.wrk, Policies: core, Headscale: g.reg, Notifier: o.notifier,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetryBase: 10 * time.Millisecond, RetryMax: 40 * time.Millisecond, StepRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !o.noWorker {
		g.startWorker(t)
	}
	return g
}

// startWorker starts a River worker with the handler of this package. River jobs left by earlier tests of the shared
// database are removed first (their tenants are not this test's).
func (g *rig) startWorker(t *testing.T) {
	t.Helper()
	g.exec(t, `DELETE FROM river.river_job`)
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 50*time.Millisecond, 200*time.Millisecond
	cfg.LockBusySnooze, cfg.LockHeldSnooze = 100*time.Millisecond, 200*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	w, err := jobs.NewWorker(g.wrk, cfg, jobs.Options{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.h.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(ctx)
	})
	g.worker = w
}

// newTenant creates an active tenant with its instance, members and pre-auth keys, and applies the allow fixture
// through the policy core: the desired version.
func (g *rig) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	shared.mu.Lock()
	shared.n++
	i := shared.n
	shared.mu.Unlock()
	g.n++
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), slug: "s" + randomHex(5) + fmt.Sprintf("%03d", i%1000)}
	ten.hs = &fakeHS{}
	g.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	g.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		ten.instance, ten.id, g.host, ten.slug+".mesh.test", ten.slug+".ts.test", "hs-"+ten.slug+":8080", 30000+g.n,
		fmt.Sprintf("10.250.%d.0/29", g.n), "/opt/meshguard/tenants/"+ten.instance.String())
	idp := uuid.New()
	g.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, idp, ten.id, "https://idp.invalid/realms/"+ten.slug)
	member := func(name, role string) (uuid.UUID, uuid.UUID) {
		ident, m := uuid.New(), uuid.Nil
		g.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, ident, idp, ten.id, name+"-"+ten.slug, name+"@"+ten.slug+".test", name)
		g.scan(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
			SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3 RETURNING id`,
			[]any{ten.id, ident, role}, &m)
		return m, ident
	}
	ten.owner, _ = member("owner", "tenant_owner")
	ten.admin, ten.adminIdentity = member("admin", "tenant_admin")
	ten.viewer, _ = member("viewer", "tenant_viewer")
	ten.endUser, _ = member("eu", "end_user")
	now := time.Now()
	ten.hs.keys = []headscale.PreAuthKey{
		{ID: 1, KeyPrefix: "aaaaaaaaaaaa", Reusable: true, Expiration: now.Add(time.Hour)},             // valid, reusable
		{ID: 2, KeyPrefix: "bbbbbbbbbbbb", Expiration: now.Add(10 * time.Minute)},                      // valid, unused
		{ID: 3, KeyPrefix: "cccccccccccc", Used: true, Expiration: now.Add(time.Hour)},                 // single use, used
		{ID: 4, KeyPrefix: "dddddddddddd", Reusable: true, Expiration: now.Add(-time.Hour)},            // expired
		{ID: 5, KeyPrefix: "eeeeeeeeeeee", Reusable: true, Used: true, Expiration: now.Add(time.Hour)}, // reusable, used
	}
	g.reg.mu.Lock()
	g.reg.hs[ten.id] = ten.hs
	g.reg.mu.Unlock()
	res, err := g.core.Apply(t.Context(), policies.ApplyRequest{TenantID: ten.id, HuJSON: allowFixture(t),
		Trigger: policies.TriggerManual, Actor: "fixture"})
	if err != nil {
		t.Fatalf("apply the allow fixture: %v", err)
	}
	ten.desired = res.VersionID
	return ten
}

func (g *rig) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := g.su.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (g *rig) scan(t *testing.T, sql string, args []any, dest ...any) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.su.QueryRow(context.Background(), sql, args...).Scan(dest...); err != nil {
		t.Fatalf("superuser query: %v\n%s", err, sql)
	}
}

func (g *rig) str(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	g.scan(t, sql, args, &s)
	return s
}

func (g *rig) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	g.scan(t, sql, args, &n)
	return n
}

// reqCtx is the request scope the HTTP layer gives the API side (audit actor and action).
func (g *rig) reqCtx(t *testing.T, action string) context.Context {
	id := g.actor
	return audit.WithRequest(t.Context(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &id, ActorDisplay: "operator", RequestID: "req-" + uuid.NewString()[:8]})
}

func (g *rig) suspend(t *testing.T, ten *tenantFx, key string) (Requested, error) {
	t.Helper()
	return g.req.Suspend(g.reqCtx(t, ActionSuspend), g.actor, ten.id, idem(key, ten.id, "suspend"))
}

func (g *rig) resume(t *testing.T, ten *tenantFx, key string) (Requested, error) {
	t.Helper()
	return g.req.Resume(g.reqCtx(t, ActionResume), g.actor, ten.id, idem(key, ten.id, "resume"))
}

func idem(key string, tenant uuid.UUID, action string) *Idempotency {
	if key == "" {
		return nil
	}
	return &Idempotency{Key: key, Hash: jobs.RequestHash("POST", "/platform/tenants/"+tenant.String()+"/"+action, nil)}
}

// wait polls the job until it reaches a status in want (or fails the test after timeout).
func (g *rig) wait(t *testing.T, job uuid.UUID, want ...string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		status = g.str(t, `SELECT status FROM provisioning_jobs WHERE id = $1`, job)
		if slices.Contains(want, status) {
			return status
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s is %s after 60 s, want one of %v (steps %s, error %s)", job, status, want,
		g.str(t, `SELECT coalesce(string_agg(name || ':' || status || coalesce(':' || error_code, ''), ' ' ORDER BY seq), '')
			FROM provisioning_job_steps WHERE job_id = $1`, job),
		g.str(t, `SELECT coalesce(error::text, '') FROM provisioning_jobs WHERE id = $1`, job))
	return status
}

// steps returns "name:status" of the job's steps in order.
func (g *rig) steps(t *testing.T, job uuid.UUID) string {
	t.Helper()
	return g.str(t, `SELECT coalesce(string_agg(name || ':' || status, ' ' ORDER BY seq), '') FROM provisioning_job_steps
		WHERE job_id = $1`, job)
}

// compensation returns "name:compensation_status" of the job's steps in order.
func (g *rig) compensation(t *testing.T, job uuid.UUID) string {
	t.Helper()
	return g.str(t, `SELECT coalesce(string_agg(name || ':' || coalesce(compensation_status, '-'), ' ' ORDER BY seq), '')
		FROM provisioning_job_steps WHERE job_id = $1`, job)
}

func (g *rig) status(t *testing.T, ten *tenantFx) string {
	t.Helper()
	return g.str(t, `SELECT status FROM tenants WHERE id = $1`, ten.id)
}

// control runs a job control of internal/jobs in a platform transaction of the api's store.
func (g *rig) control(t *testing.T, fn func(ctx context.Context, tx *store.Tx, id uuid.UUID) (jobs.Controlled, error),
	job uuid.UUID) (jobs.Controlled, error) {
	t.Helper()
	var out jobs.Controlled
	err := g.api.WithPlatformJobTx(t.Context(), func(tx *store.Tx) error {
		var err error
		out, err = fn(t.Context(), tx, job)
		return err
	})
	return out, err
}
