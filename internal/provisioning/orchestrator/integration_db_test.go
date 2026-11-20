package orchestrator

// The whole flow against PostgreSQL 18 (internal/store/storetest) with the real job framework (River worker), the
// real registry writes (DBStore, platform.Placer, secrets.Store, notifications, audit) and the real Headscale adapter
// path (locator + CachingRegistry → a fake edge admin listener with fake instances — headscaletest); only the Host
// Agent, the IdP driver and the prober are fakes. The API side (Creator, Control) runs with the api's roles.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/members"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

const testDomain = "example.test"

// edgeAgent is the fake agent whose instances are fake Headscales behind the fake edge: the API key it bootstraps is
// one the edge accepts, so the real adapter path (locator → SecretStore → edge) authenticates with it.
type edgeAgent struct {
	*fakeAgent
	edge  *headscaletest.Edge
	mu    sync.Mutex
	insts map[string]*headscaletest.Instance
}

func (a *edgeAgent) EnsureInstance(ctx context.Context, in *agentv1.EnsureInstanceRequest, o ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	if in.GetTargetPhase() == agentv1.TargetPhase_TARGET_PHASE_CONTAINER {
		a.mu.Lock()
		if a.insts[in.GetSpec().GetInstance().GetSlug()] == nil {
			a.insts[in.GetSpec().GetInstance().GetSlug()] = a.edge.AddInstance(in.GetSpec().GetInstance().GetSlug())
		}
		a.mu.Unlock()
	}
	return a.fakeAgent.EnsureInstance(ctx, in, o...)
}

func (a *edgeAgent) BootstrapApiKey(ctx context.Context, in *agentv1.BootstrapApiKeyRequest, o ...grpc.CallOption) (*agentv1.BootstrapApiKeyResponse, error) { //nolint:revive // generated name
	if _, err := a.fakeAgent.BootstrapApiKey(ctx, in, o...); err != nil { // the host model (order checks)
		return nil, err
	}
	a.mu.Lock()
	inst := a.insts[in.GetInstance().GetSlug()]
	a.mu.Unlock()
	if p := in.GetKeepPrefix(); p != "" {
		for _, k := range inst.Keys() {
			if k.Prefix == p && k.Valid(time.Now()) {
				return &agentv1.BootstrapApiKeyResponse{Prefix: p, ExpiresAt: timestamppb.New(*k.Expiration)}, nil
			}
		}
	}
	full, prefix := inst.NewKey(in.GetTtl().AsDuration())
	a.fakeAgent.mu.Lock() // edgeAgent has its own mu: the key is the fake agent's
	a.lastKey = full
	a.fakeAgent.mu.Unlock()
	return &agentv1.BootstrapApiKeyResponse{ApiKey: full, Prefix: prefix, Created: true,
		ExpiresAt: timestamppb.New(time.Now().Add(in.GetTtl().AsDuration()))}, nil
}

type dbRig struct {
	su      *pgx.Conn
	api     *store.Store
	wrk     *store.Store
	creator *Creator
	control *Control
	agent   *edgeAgent
	prober  *fakeProber
	kc      *fakeIdP
	edge    *headscaletest.Edge
	worker  *jobs.Worker
	actor   uuid.UUID
	host    uuid.UUID
	mu      sync.Mutex
	policy  map[string]string // slug → policy the fake instances report
}

func newDBRig(t *testing.T) *dbRig {
	t.Helper()
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	g := &dbRig{su: env.Admin(t, db), api: env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 6),
		wrk: env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 10), actor: uuid.New(), host: uuid.New(),
		policy: map[string]string{}}
	g.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 30100), '10.250.0.0/24', '{"ipv4": "192.0.2.10", "mode": "direct"}')`, g.host)
	dir := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	writeFile(t, filepath.Join(dir, "kek-1"), hex.EncodeToString(k)+"\n")
	writeFile(t, filepath.Join(dir, secrets.ActiveFile), "kek-1\n")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	apiSec, err := secrets.New(g.api, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	wrkSec, err := secrets.New(g.wrk, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	tok := headscaletest.NewToken()
	g.edge = headscaletest.NewEdge(t, tok)
	g.edge.SetHook(func(r headscaletest.Request, _ int) (int, string, bool) {
		if r.Method != "GET" || r.Path != "/api/v1/policy" {
			return 0, "", false
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		b, _ := json.Marshal(map[string]string{"policy": g.policy[r.Slug], "updatedAt": time.Now().UTC().Format(time.RFC3339)})
		return 200, string(b), true
	})
	tokenFile := filepath.Join(t.TempDir(), "edge_admin_token")
	writeFile(t, tokenFile, tok+"\n")
	ten := tenants.New(g.wrk, tenants.Options{BaseDomain: testDomain})
	loc, err := locator.New(ten, wrkSec, locator.Options{AdminURL: g.edge.URL(), EdgeTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	reg := headscale.NewRegistry(loc, headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1}})
	placer, err := platform.NewPlacer(g.wrk, platform.PlacerOptions{BaseDomain: testDomain})
	if err != nil {
		t.Fatal(err)
	}
	g.agent = &edgeAgent{fakeAgent: newFakeAgent(), edge: g.edge, insts: map[string]*headscaletest.Instance{}}
	g.prober = &fakeProber{relay: ProbeResult{OK: true}, edge: ProbeResult{OK: true}}
	g.kc = &fakeIdP{name: DriverKeycloak, realms: map[string]string{}}
	dns := dnsFunc(func(_ context.Context, host string, want netip.Addr) (DNSResult, error) {
		if !strings.HasSuffix(host, ".mesh."+testDomain) {
			return DNSResult{}, errors.New("unknown name")
		}
		return DNSResult{Addresses: []netip.Addr{want}, OK: true}, nil
	})
	p, err := New(Config{Store: NewDBStore(g.wrk, nil).WithOwnerInvite(members.IdPInviteNotifier{}), Agent: g.agent, Placer: placer, Secrets: wrkSec,
		IdP: fakeDrivers{DriverKeycloak: g.kc}, Headscale: reg, DNS: dns, Prober: g.prober,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		HeadscaleDigest: "sha256:" + strings.Repeat("d", 64), HeadscaleVersion: "v0.29.7",
		Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, EdgeAddress: "10.249.0.2:443",
		RetryBase: 20 * time.Millisecond, RetryMax: 50 * time.Millisecond, HealthPoll: 10 * time.Millisecond,
		HealthTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 50*time.Millisecond, 200*time.Millisecond
	cfg.LockBusySnooze, cfg.LockHeldSnooze = 100*time.Millisecond, 200*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	w, err := jobs.NewWorker(g.wrk, cfg, jobs.Options{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Register(w); err != nil {
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
	if g.creator, err = NewCreator(CreatorConfig{Store: g.api, Secrets: apiSec, Quota: usage.NewChecker(g.api),
		QuotaTx: usage.TenantCreationTx, BaseDomain: testDomain}); err != nil {
		t.Fatal(err)
	}
	g.control = NewControl(g.api)
	return g
}

type dnsFunc func(ctx context.Context, host string, want netip.Addr) (DNSResult, error)

func (f dnsFunc) Check(ctx context.Context, host string, want netip.Addr) (DNSResult, error) {
	return f(ctx, host, want)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (g *dbRig) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := g.su.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec: %v\n%s", err, sql)
	}
}

func dbScalar[T any](t *testing.T, g *dbRig, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := g.su.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return v
}

// reqCtx is the request scope the HTTP layer gives the API side (audit actor and action).
func (g *dbRig) reqCtx(t *testing.T, action string) context.Context {
	id := g.actor
	return audit.WithRequest(t.Context(), &audit.Request{Action: action, ActorType: audit.ActorIdentity, ActorIdentityID: &id,
		ActorDisplay: "operator", RequestID: "req-" + uuid.NewString()[:8]})
}

func (g *dbRig) setPolicy(slug, p string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policy[slug] = p
}

func (g *dbRig) create(t *testing.T, slug string) Created {
	t.Helper()
	g.setPolicy(slug, templates.BootstrapPolicy)
	c, err := g.creator.Create(g.reqCtx(t, ActionTenantCreate), g.actor, CreateRequest{Slug: slug, Name: "Tenant " + slug,
		PlanKey: "standard", OwnerEmail: "owner@" + slug + ".example", IdP: IdPRequest{Driver: DriverKeycloak},
		Settings: []byte(`{"dns": {"magic_dns": true}}`)}, &Idempotency{Key: "key-" + slug + "-0001", Hash: []byte(strings.Repeat("h", 32))})
	if err != nil {
		t.Fatalf("create %s: %v", slug, err)
	}
	return c
}

func (g *dbRig) waitJob(t *testing.T, id uuid.UUID, status string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		s := dbScalar[string](t, g, `SELECT status FROM provisioning_jobs WHERE id = $1`, id)
		if s == status {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s is %s, want %s (error %s)", id, s,
				status, dbScalar[string](t, g, `SELECT COALESCE(error::text, '') FROM provisioning_jobs WHERE id = $1`, id))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestProvisionEndToEndDB(t *testing.T) {
	g := newDBRig(t)
	c := g.create(t, "acme")
	if c.Job.Kind != JobKind || c.Job.Status != jobs.StatusQueued || len(c.Job.Steps) != 2 ||
		c.Job.Steps[0].Name != StepValidate || c.Job.Steps[1].Name != StepRegistryCreate {
		t.Fatalf("202 body %+v", c.Job)
	}
	// Idempotency-Key: the same request returns the same job, no second tenant.
	again, err := g.creator.Create(g.reqCtx(t, ActionTenantCreate), g.actor, CreateRequest{Slug: "acme", Name: "Tenant acme",
		PlanKey: "standard", OwnerEmail: "owner@acme.example", IdP: IdPRequest{Driver: DriverKeycloak},
		Settings: []byte(`{"dns": {"magic_dns": true}}`)}, &Idempotency{Key: "key-acme-0001", Hash: []byte(strings.Repeat("h", 32))})
	if err != nil || !again.Replayed || again.Job.ID != c.Job.ID {
		t.Fatalf("replay: %v %+v", err, again)
	}
	g.waitJob(t, c.Job.ID, jobs.StatusSucceeded)

	// 19 steps, in order, all succeeded once.
	rows, err := g.su.Query(context.Background(), `SELECT name, status, attempt FROM provisioning_job_steps WHERE job_id = $1 ORDER BY seq`, c.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n, s string
		var a int
		if err := rows.Scan(&n, &s, &a); err != nil {
			t.Fatal(err)
		}
		if s != jobs.StepSucceeded || a != 1 {
			t.Errorf("step %s %s attempt %d", n, s, a)
		}
		names = append(names, n)
	}
	rows.Close()
	if strings.Join(names, ",") != strings.Join(Steps, ",") {
		t.Fatalf("steps %v", names)
	}
	tid := c.TenantID
	checks := map[string]string{
		`SELECT status FROM tenants WHERE id = $1`:                                                                        "active",
		`SELECT status FROM tenant_instances WHERE tenant_id = $1`:                                                        "running",
		`SELECT noise_key_fingerprint FROM tenant_instances WHERE tenant_id = $1`:                                         strings.Repeat("ab", 32),
		`SELECT derp_region_id::text FROM tenant_instances WHERE tenant_id = $1`:                                          "901",
		`SELECT status FROM identity_providers WHERE tenant_id = $1`:                                                      "active",
		`SELECT settings->'dns'->>'magic_dns' FROM tenants WHERE id = $1`:                                                 "true",
		`SELECT kind||'/'||state||'/'||version FROM policy_versions WHERE tenant_id = $1`:                                 "baseline/approved/1",
		`SELECT trigger||'/'||state FROM policy_applications WHERE tenant_id = $1`:                                        "bootstrap/applied",
		`SELECT (desired_policy_version_id IS NOT NULL)::text FROM tenants WHERE id = $1`:                                 "true",
		`SELECT r.status||'/'||r.email FROM tenant_invitations i JOIN roles r ON r.id = i.role_id WHERE i.tenant_id = $1`: "",
		`SELECT kind||'/'||code||'/'||derp_region_id FROM relay_regions WHERE tenant_id = $1`:                             "embedded/mg-acme/901",
		`SELECT status FROM relay_assignments WHERE tenant_id = $1`:                                                       "active",
		`SELECT count(*)::text FROM instance_config_versions WHERE tenant_id = $1`:                                        "1",
		`SELECT count(*)::text FROM subscriptions WHERE tenant_id = $1 AND status = 'active'`:                             "1",
	}
	delete(checks, `SELECT r.status||'/'||r.email FROM tenant_invitations i JOIN roles r ON r.id = i.role_id WHERE i.tenant_id = $1`)
	checks[`SELECT i.status||'/'||r.key||'/'||i.email FROM tenant_invitations i JOIN roles r ON r.id = i.role_id WHERE i.tenant_id = $1`] = "pending/tenant_owner/owner@acme.example"
	for q, want := range checks {
		if got := dbScalar[string](t, g, q, tid); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	// The API key: registered by reference, stored encrypted, accepted by the instance through the edge.
	ref := dbScalar[string](t, g, `SELECT api_key_secret_ref FROM tenant_instances WHERE tenant_id = $1`, tid)
	if ref != fmt.Sprintf("mgsec://%s/headscale-api-key#1", tid) {
		t.Fatalf("api key ref %s", ref)
	}
	if n := dbScalar[int64](t, g, `SELECT count(*) FROM provisioning_job_steps s, provisioning_jobs j
		WHERE s.job_id = j.id AND (s.detail::text LIKE '%hskey-api%' OR s.created_resources::text LIKE '%hskey-api%'
		OR j.input::text LIKE '%hskey-api%' OR COALESCE(j.output::text, '') LIKE '%hskey-api%' OR COALESCE(j.error::text,'') LIKE '%hskey-api%')`); n != 0 {
		t.Fatal("an API key is stored in a job row")
	}
	if n := dbScalar[int64](t, g, `SELECT count(*) FROM audit_events WHERE details::text LIKE '%hskey-api%'`); n != 0 {
		t.Fatal("an API key is in the audit")
	}
	// Audit: the operation platform.tenant.create closed by the worker; outbox: invitation + activation.
	if got := dbScalar[string](t, g, `SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events
		WHERE action LIKE 'platform.tenant.create%'`); got != "platform.tenant.create.requested,platform.tenant.create.succeeded" {
		t.Fatalf("audit %s", got)
	}
	if got := dbScalar[string](t, g, `SELECT string_agg(kind, ',' ORDER BY created_at) FROM notification_outbox WHERE tenant_id = $1`, tid); got != "tenant.invitation,tenant.activated" {
		t.Fatalf("outbox %s", got)
	}
	// G4b-E1: the Owner invitation also enqueued member.idp_invite (the Owner's account at the platform-hosted IdP),
	// once, for that invitation.
	if got := dbScalar[string](t, g, `SELECT string_agg(j.kind||'/'||j.dedupe_key, ',') FROM provisioning_jobs j
		JOIN tenant_invitations i ON j.dedupe_key = 'invitation:'||i.id||':idp_invite' WHERE j.tenant_id = $1`, tid); got !=
		"member.idp_invite/invitation:"+dbScalar[string](t, g, `SELECT id::text FROM tenant_invitations WHERE tenant_id = $1`, tid)+":idp_invite" {
		t.Fatalf("Owner IdP invitation job: %q", got)
	}
	// The policy step read the baseline through the real adapter path, authenticated with the bootstrapped key.
	var sawPolicy bool
	for _, r := range g.edge.Requests() {
		if r.Path == "/api/v1/policy" && r.Slug == "acme" && r.TokenOK {
			sawPolicy = true
		}
	}
	if !sawPolicy {
		t.Fatal("GET /api/v1/policy never reached the instance")
	}

	// A second tenant with the same slug is refused (step 1).
	if _, err := g.creator.Create(g.reqCtx(t, ActionTenantCreate), g.actor, CreateRequest{Slug: "acme", Name: "Other",
		PlanKey: "standard", OwnerEmail: "x@acme.example", IdP: IdPRequest{Driver: DriverKeycloak}}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate slug: %v", err)
	}
	for _, bad := range []CreateRequest{
		{Slug: "admin", Name: "x", PlanKey: "standard", OwnerEmail: "a@b.example", IdP: IdPRequest{Driver: DriverKeycloak}},
		{Slug: "ok-slug", Name: "x", PlanKey: "nope", OwnerEmail: "a@b.example", IdP: IdPRequest{Driver: DriverKeycloak}},
		{Slug: "ok-slug", Name: "x", PlanKey: "standard", OwnerEmail: "not-an-email", IdP: IdPRequest{Driver: DriverKeycloak}},
		{Slug: "ok-slug", Name: "x", PlanKey: "standard", OwnerEmail: "a@b.example", IdP: IdPRequest{Driver: "ldap"}},
	} {
		if _, err := g.creator.Create(g.reqCtx(t, ActionTenantCreate), g.actor, bad, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v, want ErrInvalid", bad, err)
		}
	}
}

func TestProvisionRollbackAndRetryDB(t *testing.T) {
	g := newDBRig(t)
	// The edge publishes a forbidden path: permanent ⇒ compensation ⇒ rolled_back, tenant failed.
	g.prober.mu.Lock()
	g.prober.edge = ProbeResult{Exposed: []string{"/api/v1/node"}}
	g.prober.mu.Unlock()
	c := g.create(t, "beta")
	g.waitJob(t, c.Job.ID, jobs.StatusRolledBack)
	tid := c.TenantID
	for q, want := range map[string]string{
		`SELECT status FROM tenants WHERE id = $1`:                                                                        "failed",
		`SELECT status FROM tenant_instances WHERE tenant_id = $1`:                                                        "removed",
		`SELECT status FROM identity_providers WHERE tenant_id = $1`:                                                      "disabled",
		`SELECT status FROM tenant_invitations WHERE tenant_id = $1`:                                                      "revoked",
		`SELECT count(*)::text FROM relay_regions WHERE tenant_id = $1`:                                                   "0",
		`SELECT (api_key_secret_ref IS NULL)::text FROM tenant_instances WHERE tenant_id = $1`:                            "true",
		`SELECT count(*)::text FROM secrets WHERE tenant_id = $1 AND name = 'headscale-api-key' AND destroyed_at IS NULL`: "0",
		`SELECT error->>'code' FROM provisioning_jobs WHERE tenant_id = $1 AND kind = 'tenant.provision'`:                 "edge_exposes_paths",
	} {
		if got := dbScalar[string](t, g, q, tid); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	if n := dbScalar[int64](t, g, `SELECT count(*) FROM provisioning_job_steps WHERE job_id = $1 AND compensation_status IS NULL
		AND name NOT IN ('validate', 'registry.create')`, c.Job.ID); n != 0 {
		t.Fatalf("%d steps without compensation status", n)
	}
	if got := dbScalar[string](t, g, `SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events
		WHERE action LIKE 'platform.tenant.create%'`); got != "platform.tenant.create.requested,platform.tenant.create.failed" {
		t.Fatalf("audit %s", got)
	}
	m := g.agent.model()
	if m.dir || m.container || m.network || m.edge {
		t.Fatalf("host left behind: %+v", m)
	}

	// P3-T09: a failed tenant takes no place under quota.max_tenants, so /retry (failed → provisioning) takes one under
	// the cap's lock: with the cap reached it is refused (403 quota_exceeded) and nothing changes.
	used := dbScalar[int64](t, g, `SELECT count(*) FROM tenants WHERE status NOT IN ('deleted', 'failed')`)
	g.exec(t, `UPDATE system_settings SET value = to_jsonb($1::bigint) WHERE key = 'quota.max_tenants'`, used)
	capped := NewControl(g.api).WithQuota(usage.TenantCreationTx)
	if _, err := capped.Retry(g.reqCtx(t, ActionJobRetry), g.actor, c.Job.ID, nil); !errors.Is(err, tenants.ErrQuotaExceeded) {
		t.Fatalf("/retry with the cap reached: %v, want a quota refusal", err)
	}
	if got := dbScalar[string](t, g, `SELECT status FROM tenants WHERE id = $1`, tid); got != "failed" {
		t.Fatalf("tenant %s after a refused retry", got)
	}
	g.exec(t, `UPDATE system_settings SET value = '100' WHERE key = 'quota.max_tenants'`)

	// /retry of the rolled_back job: a NEW job from step 3, the tenant provisioning again — and it succeeds.
	g.prober.mu.Lock()
	g.prober.edge = ProbeResult{OK: true}
	g.prober.mu.Unlock()
	r, err := capped.Retry(g.reqCtx(t, ActionJobRetry), g.actor, c.Job.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.NewJob || r.Job.ID == c.Job.ID || r.From != jobs.StatusRolledBack || len(r.Job.Steps) != 2 ||
		r.Job.Steps[0].Status != jobs.StepSkipped {
		t.Fatalf("retry %+v", r)
	}
	g.waitJob(t, r.Job.ID, jobs.StatusSucceeded)
	if got := dbScalar[string](t, g, `SELECT status FROM tenants WHERE id = $1`, tid); got != "active" {
		t.Fatal(got)
	}
	if n := dbScalar[int64](t, g, `SELECT count(*) FROM tenant_instances WHERE tenant_id = $1`, tid); n != 2 {
		t.Fatalf("%d instance rows (the removed one is kept: its UID is never reused)", n)
	}
	if got := dbScalar[string](t, g, `SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events
		WHERE action LIKE 'platform.job.%'`); got != "platform.job.retry" {
		t.Fatalf("control audit %s", got)
	}
}

func TestProvisionResumableRetryCancelDB(t *testing.T) {
	g := newDBRig(t)
	// The relay probe keeps failing: retried in place, then failed_resumable (no compensation, lock held).
	g.prober.mu.Lock()
	g.prober.relay = ProbeResult{OK: false}
	g.prober.mu.Unlock()
	c := g.create(t, "gamma")
	g.waitJob(t, c.Job.ID, jobs.StatusFailedResumable)
	if got := dbScalar[string](t, g, `SELECT error->>'code' FROM provisioning_jobs WHERE id = $1`, c.Job.ID); got != "relay_probe_failed" {
		t.Fatal(got)
	}
	if got := dbScalar[int32](t, g, `SELECT attempt FROM provisioning_job_steps WHERE job_id = $1 AND name = 'relay.assign'`, c.Job.ID); got != DefaultStepRetries+1 {
		t.Fatalf("relay attempts %d", got)
	}
	if got := dbScalar[string](t, g, `SELECT status FROM tenants WHERE id = $1`, c.TenantID); got != "provisioning" {
		t.Fatal(got)
	}
	// Another lifecycle job of the tenant cannot even be queued (dedupe) and could not run (lock).
	err := g.wrk.WithTenantJobTx(t.Context(), c.TenantID, func(tx *store.Tx) error {
		_, err := jobs.Enqueue(t.Context(), tx, jobs.Spec{Kind: "tenant.suspend", TenantID: &c.TenantID})
		return err
	})
	if !errors.Is(err, jobs.ErrDedupeConflict) {
		t.Fatalf("second lifecycle job: %v", err)
	}
	// /retry resumes from relay.assign.
	g.prober.mu.Lock()
	g.prober.relay = ProbeResult{OK: true}
	g.prober.mu.Unlock()
	r, err := g.control.Retry(g.reqCtx(t, ActionJobRetry), g.actor, c.Job.ID, nil)
	if err != nil || r.NewJob || r.Job.ID != c.Job.ID {
		t.Fatalf("retry %v %+v", err, r)
	}
	g.waitJob(t, c.Job.ID, jobs.StatusSucceeded)
	if got := dbScalar[int32](t, g, `SELECT attempt FROM provisioning_job_steps WHERE job_id = $1 AND name = 'storage.create'`, c.Job.ID); got != 1 {
		t.Fatalf("storage.create ran %d times", got)
	}

	// /cancel of a job that never started: cancelled, the tenant failed, the audit operation closed.
	if err := g.worker.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	d := g.create(t, "delta")
	cr, err := g.control.Cancel(g.reqCtx(t, ActionJobCancel), g.actor, d.Job.ID, &Idempotency{Key: "cancel-delta-1", Hash: []byte(strings.Repeat("c", 32))})
	if err != nil || cr.Job.Status != jobs.StatusCancelled {
		t.Fatalf("cancel %v %+v", err, cr)
	}
	if got := dbScalar[string](t, g, `SELECT status FROM tenants WHERE id = $1`, d.TenantID); got != "failed" {
		t.Fatal(got)
	}
	// The same /cancel replayed with its Idempotency-Key answers the stored job and acts no more.
	replay, err := g.control.Cancel(g.reqCtx(t, ActionJobCancel), g.actor, d.Job.ID, &Idempotency{Key: "cancel-delta-1",
		Hash: []byte(strings.Repeat("c", 32))})
	if err != nil || replay.Job.ID != d.Job.ID || replay.Changed {
		t.Fatalf("replayed cancel %v %+v", err, replay)
	}
	if _, err := g.control.Cancel(g.reqCtx(t, ActionJobCancel), g.actor, d.Job.ID, &Idempotency{Key: "cancel-delta-1",
		Hash: []byte(strings.Repeat("x", 32))}); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("same key, other request: %v", err)
	}
	if got := dbScalar[int64](t, g, `SELECT count(*) FROM audit_events WHERE action = 'platform.tenant.create.failed'`); got != 1 {
		t.Fatalf("failed events %d", got)
	}
	// Refused controls: retry of a cancelled job, rollback of a succeeded one, an unknown job.
	if _, err := g.control.Retry(g.reqCtx(t, ActionJobRetry), g.actor, d.Job.ID, nil); !errors.Is(err, jobs.ErrJobState) {
		t.Fatalf("retry cancelled: %v", err)
	}
	if _, err := g.control.Rollback(g.reqCtx(t, ActionJobRollback), g.actor, c.Job.ID, nil); !errors.Is(err, jobs.ErrJobState) {
		t.Fatalf("rollback succeeded: %v", err)
	}
	if _, err := g.control.Cancel(g.reqCtx(t, ActionJobCancel), g.actor, uuid.New(), nil); !errors.Is(err, jobs.ErrNotFound) {
		t.Fatalf("cancel unknown: %v", err)
	}
}
