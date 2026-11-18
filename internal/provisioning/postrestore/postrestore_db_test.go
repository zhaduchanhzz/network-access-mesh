package postrestore_test

// PostgreSQL integration tests of the post-restore reconcile (P3-T17): a real database migrated like a deployment
// (storetest) with the worker's roles, holding what a restored dump holds — live sessions, open approval requests, an
// executed Keycloak console session, pending invitations, a job left queued — and fakes for what lies outside the
// database (the Host Agent's inventory, the Headscale key probe, the key rotation of P3-T10, the policy step of the
// policy core): they record every call, so the tests see what the run asked of them. The real Host Agent, Headscale and
// rotation are exercised end to end by E2E-72 (tests/integration/provisioning).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/postrestore"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// ---------------------------------------------------------------------------------------------------- fakes

type fakeAgent struct {
	mu      sync.Mutex
	entries []*agentv1.InventoryEntry
	calls   int
}

func (a *fakeAgent) GetInstanceStatus(context.Context, *agentv1.GetInstanceStatusRequest, ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not used")
}

func (a *fakeAgent) ListInstances(context.Context, *agentv1.ListInstancesRequest, ...grpc.CallOption) (*agentv1.ListInstancesResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	return &agentv1.ListInstancesResponse{Instances: a.entries}, nil
}

type fakeRotator struct {
	mu       sync.Mutex
	requests []apikey.Request
	results  map[uuid.UUID]apikey.Result
	errs     map[uuid.UUID]error
}

func (r *fakeRotator) Rotate(_ context.Context, req apikey.Request) (apikey.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	return r.results[req.TenantID], r.errs[req.TenantID]
}

type fakeReviewer struct {
	mu       sync.Mutex
	requests []policies.RunningReview
	results  map[uuid.UUID]policies.RunningResult
}

func (r *fakeReviewer) ReviewRunning(_ context.Context, req policies.RunningReview) (policies.RunningResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	res := r.results[req.TenantID]
	res.TenantID = req.TenantID
	if res.Outcome == "" {
		res.Outcome = policies.RunningMatch
	}
	return res, nil
}

type fakeInstance struct {
	headscale.Instance
	err error
}

func (i fakeInstance) ListAPIKeys(context.Context) ([]headscale.APIKey, error) { return nil, i.err }

type fakeRegistry struct {
	mu    sync.Mutex
	errs  map[uuid.UUID]error
	calls int
}

func (r *fakeRegistry) ForTenant(_ context.Context, t uuid.UUID) (headscale.Instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return fakeInstance{err: r.errs[t]}, nil
}

type fakeSecurity struct {
	mu     sync.Mutex
	events []audit.SecurityEvent
}

func (s *fakeSecurity) RecordSecurityEvent(_ context.Context, ev audit.SecurityEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return true, nil
}

// ---------------------------------------------------------------------------------------------------- world

type tenantFx struct {
	id, instance, idp, identity uuid.UUID
	slug                        string
}

type world struct {
	t                *testing.T
	db               string
	su               *pgx.Conn
	st               *store.Store
	host             uuid.UUID
	platformIdP      uuid.UUID
	sa1, sa2         uuid.UUID // platform identities
	a, b, c          *tenantFx // a, b running and on the host; c registered, nothing on the host (lost)
	orphan           uuid.UUID // on the host, unknown to the registry
	agent            *fakeAgent
	keys             *fakeRotator
	policies         *fakeReviewer
	reg              *fakeRegistry
	sec              *fakeSecurity
	svc              *postrestore.Service
	queuedJob        uuid.UUID
	consoleGrant     uuid.UUID // executed console session still in its window
	oldConsoleGrant  uuid.UUID // executed console session long over
	sessionsTotal    int       // sessions not revoked in the dump
	sessionsLive     int       // … and not expired
	restorePoint     time.Time
	pendingApprovals int
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.su.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		w.t.Fatalf("query: %v\n%s", err, sql)
	}
	return n
}

func (w *world) tenant(slug string, n int, onHost bool) *tenantFx {
	t := &tenantFx{id: uuid.New(), instance: uuid.New(), idp: uuid.New(), identity: uuid.New(), slug: slug}
	w.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, t.id, slug, "Tenant "+slug)
	w.exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
			server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		t.instance, t.id, w.host, slug+".mesh.test", slug+".ts.test", "hs-"+slug+":8080", 30000+n,
		fmt.Sprintf("10.250.%d.0/29", n), "/opt/meshguard/tenants/"+t.instance.String())
	w.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, t.idp, t.id, "https://idp.test/realms/"+slug)
	w.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email) VALUES ($1, $2, $3, 'tenant', $4, $5)`,
		t.identity, t.idp, t.id, "user-"+slug, "user@"+slug+".test")
	if onHost {
		w.agent.entries = append(w.agent.entries, &agentv1.InventoryEntry{InstanceId: t.instance.String(), TenantId: t.id.String(),
			Slug: slug, HasDirectory: true, HasContainer: true, HasNetwork: true})
	}
	return t
}

// session inserts a session created `age` ago; revoked and expired as asked.
func (w *world) session(identity, idp uuid.UUID, origin string, age time.Duration, revoked, expired bool) {
	expires := "now() + interval '8 hours'"
	if expired {
		expires = "now() - interval '1 minute'"
	}
	rev := "NULL"
	if revoked {
		rev = "now() - interval '1 minute'"
	}
	w.exec(`INSERT INTO sessions (id_hash, identity_id, idp_id, origin, created_at, auth_time, idle_expires_at,
			absolute_expires_at, revoked_at)
		VALUES (sha256(convert_to($1, 'UTF8')), $2, $3, $4, now() - $5::interval, now() - $5::interval, `+expires+`, `+expires+`, `+rev+`)`,
		uuid.NewString(), identity, idp, origin, fmt.Sprintf("%d seconds", int(age.Seconds())))
	if !revoked {
		w.sessionsTotal++
		if !expired {
			w.sessionsLive++
		}
	}
}

// approval inserts an approval request of the platform (tenant nil) or of a tenant.
func (w *world) approval(tenant *tenantFx, action, status string, decidedAgo time.Duration, payload string) uuid.UUID {
	id := uuid.New()
	scope, tid, requester, approver := "platform", (*uuid.UUID)(nil), w.sa1, &w.sa2
	if tenant != nil {
		scope, tid, requester, approver = "tenant", &tenant.id, tenant.identity, nil
	}
	decided := (*time.Time)(nil)
	if status != "pending" {
		d := time.Now().Add(-decidedAgo)
		decided = &d
	} else {
		approver = nil
	}
	w.exec(`INSERT INTO approval_requests (id, scope, tenant_id, action, resource_type, resource_id, payload, payload_sha256,
			requested_by_identity_id, approved_by_identity_id, decided_at, status, expires_at, created_at)
		VALUES ($1, $2, $3, $4, 'tenant', 'x', $5::jsonb, $10, $6, $7, $8, $9,
			now() + interval '20 hours', now() - interval '4 hours')`,
		id, scope, tid, action, payload, requester, approver, decided, status, fmt.Sprintf("%x", sha256.Sum256([]byte(payload))))
	return id
}

func newWorld(t *testing.T, withAgent bool) *world {
	t.Helper()
	pg := storetest.Require(t)
	w := &world{t: t, host: uuid.New(), platformIdP: uuid.New(), sa1: uuid.New(), sa2: uuid.New(), orphan: uuid.New(),
		agent: &fakeAgent{}, keys: &fakeRotator{results: map[uuid.UUID]apikey.Result{}, errs: map[uuid.UUID]error{}},
		policies: &fakeReviewer{results: map[uuid.UUID]policies.RunningResult{}},
		reg:      &fakeRegistry{errs: map[uuid.UUID]error{}}, sec: &fakeSecurity{},
		restorePoint: time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)}
	w.db = pg.NewDatabase(t)
	w.su = pg.Admin(t, w.db)
	w.exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool) VALUES ($1, 'host-pr', 'lab',
		int4range(30000, 40000), '10.250.0.0/16')`, w.host)
	w.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.test/realms/platform', 'mg-portal', 'keycloak', 'active')`, w.platformIdP)
	for i, id := range []uuid.UUID{w.sa1, w.sa2} {
		w.exec(`INSERT INTO identities (id, idp_id, scope, subject, email) VALUES ($1, $2, 'platform', $3, $4)`, id,
			w.platformIdP, fmt.Sprintf("sa-%d", i), fmt.Sprintf("sa%d@example.test", i))
	}
	w.a, w.b, w.c = w.tenant("pr-a", 1, true), w.tenant("pr-b", 2, true), w.tenant("pr-c", 3, false)
	w.agent.entries = append(w.agent.entries, &agentv1.InventoryEntry{InstanceId: w.orphan.String(), TenantId: uuid.NewString(),
		Slug: "pr-ghost", HasDirectory: true, HasContainer: true, HasNetwork: true})

	// what the dump holds
	w.session(w.sa1, w.platformIdP, "admin", 3*time.Hour, false, false)
	w.session(w.sa2, w.platformIdP, "admin", 26*time.Hour, false, true) // idle-expired, never revoked
	w.session(w.a.identity, w.a.idp, "app", 3*time.Hour, false, false)
	w.session(w.b.identity, w.b.idp, "app", 5*time.Hour, true, false) // revoked before the dump
	w.exec(`INSERT INTO auth_requests (state_hash, idp_id, scope, origin, nonce, pkce_verifier_enc, browser_binding_hash,
		expires_at) VALUES (sha256('\x05'), $1, 'platform', 'admin', 'n', '\x00', sha256('\x01'), now() + interval '5 minutes')`,
		w.platformIdP)
	w.approval(nil, "tenant.delete", "pending", 0, `{}`)
	w.approval(nil, "tenant.restore", "approved", time.Hour, `{"backup_id": "b"}`)
	w.approval(w.a, "tenant.settings.disable_four_eyes", "pending", 0, `{}`)
	w.pendingApprovals = 3
	consolePayload := func(id uuid.UUID) string {
		return fmt.Sprintf(`{"duration_minutes": 60, "identity_id": "%s", "source_cidr": "192.0.2.0/24"}`, id)
	}
	w.consoleGrant = w.approval(nil, console.Action, "executed", 10*time.Minute, consolePayload(w.sa1))
	w.oldConsoleGrant = w.approval(nil, console.Action, "executed", 3*time.Hour, consolePayload(w.sa1))
	role := uuid.Nil
	if err := w.su.QueryRow(context.Background(), `SELECT id FROM roles WHERE scope = 'tenant' AND key = 'tenant_admin'`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	for i, tn := range []*tenantFx{w.a, w.b} {
		w.exec(`INSERT INTO tenant_invitations (tenant_id, idp_id, email, role_id, token_hash, expires_at)
			VALUES ($1, $2, $3, $4, sha256(convert_to($5::text, 'UTF8')), now() + interval '7 days')`, tn.id, tn.idp,
			fmt.Sprintf("invitee%d@%s.test", i, tn.slug), role, "token-"+tn.slug)
	}
	w.exec(`INSERT INTO tenant_invitations (tenant_id, idp_id, email, role_id, token_hash, expires_at, status)
		VALUES ($1, $2, 'gone@pr-a.test', $3, sha256('\x07'), now() + interval '7 days', 'revoked')`, w.a.id, w.a.idp, role)
	w.queuedJob = uuid.New()
	w.exec(`INSERT INTO provisioning_jobs (id, tenant_id, kind, status) VALUES ($1, $2, 'notification.send', 'queued')`,
		w.queuedJob, w.a.id)

	// the outside world after the dump: B's stored key was rotated away (refused), B runs a newer policy
	w.reg.errs[w.b.id] = &headscale.Error{Op: headscale.OpListAPIKeys, Kind: headscale.KindAPIKeyRejected}
	w.keys.results[w.a.id] = apikey.Result{Outcome: apikey.OutcomeSkipped, SkipReason: apikey.SkipNotDue, PreviousPrefix: "aaaaaaaaaaaa",
		KeyPrefix: "aaaaaaaaaaaa"}
	w.keys.results[w.b.id] = apikey.Result{Outcome: apikey.OutcomeBootstrapped, Mode: apikey.ModeBootstrap,
		BootstrapReason: apikey.ReasonKeyRejected, PreviousPrefix: "bbbbbbbbbbbb", KeyPrefix: "cccccccccccc", AgentExpired: 2}
	v := uuid.New()
	w.policies.results[w.b.id] = policies.RunningResult{Outcome: policies.RunningAdopted, Review: true, VersionID: &v,
		Version: 4, VersionStatus: "validated"}

	w.st = pg.OpenStore(t, w.db, "mg_worker_tenant", "mg_worker_platform", 6)
	cfg := postrestore.Config{Headscale: w.reg, Keys: w.keys, Policies: w.policies, Security: w.sec, Actor: "test"}
	if withAgent {
		cfg.Agent = w.agent
	}
	svc, err := postrestore.New(w.st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	return w
}

func (w *world) run(dry bool) postrestore.Report {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep, err := w.svc.Run(ctx, postrestore.Request{RestorePoint: w.restorePoint, DryRun: dry})
	if err != nil {
		w.t.Fatalf("Run(dry %v): %v\n%s", dry, err, dump(rep))
	}
	return rep
}

func dump(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// state is a digest of everything the run may change (equal before and after a dry run).
func (w *world) state() string {
	return fmt.Sprintf("sessions open %d · auth %d · approvals open %d · console executed %d · invitations pending %d · "+
		"instances failed %d · jobs %d · audit %d · settings %d",
		w.count(`SELECT count(*) FROM sessions WHERE revoked_at IS NULL`), w.count(`SELECT count(*) FROM auth_requests`),
		w.count(`SELECT count(*) FROM approval_requests WHERE status IN ('pending', 'approved')`),
		w.count(`SELECT count(*) FROM approval_requests WHERE status = 'executed'`),
		w.count(`SELECT count(*) FROM tenant_invitations WHERE status = 'pending'`),
		w.count(`SELECT count(*) FROM tenant_instances WHERE status = 'failed'`), w.count(`SELECT count(*) FROM provisioning_jobs`),
		w.count(`SELECT count(*) FROM audit_events`), w.count(`SELECT count(*) FROM system_settings WHERE key = 'maintenance'`))
}

// ---------------------------------------------------------------------------------------------------- tests

// TestPostRestoreReconcile — the whole run on a restored database (§17.2): a dry run counts everything and changes
// nothing (no write, no rotation, no security event, the policy step asked in dry-run mode, the key probe read-only);
// the run puts maintenance ON with the post_restore record, revokes every session of the dump (expired ones included)
// and deletes its auth requests, expires every open approval request and the console session still in its window (the
// one long over is left alone), revokes every pending invitation, reports the orphan instance on the host (not deleted,
// not adopted: no registry row appears) and marks the lost one failed, asks the rotation for the running instances only
// with AllowBootstrap and trigger post_restore (B re-issued), reviews the policies (B flagged), enqueues inventory.sync
// for the running instances, lists the queued job of the dump, writes audit.gap for the platform and every tenant,
// closes its audit pair and records reconciled; a second run is idempotent (a session opened since is revoked, nothing
// else is written twice) and `maintenance off` is then allowed.
func TestPostRestoreReconcile(t *testing.T) {
	w := newWorld(t, true)
	before := w.state()
	dry := w.run(true)
	if got := w.state(); got != before {
		t.Fatalf("a dry run changed the database:\nbefore %s\nafter  %s", before, got)
	}
	if len(w.keys.requests) != 0 || len(w.sec.events) != 0 || len(w.policies.requests) != 2 || !w.policies.requests[0].DryRun {
		t.Fatalf("dry run: %d rotations, %d security events, policy requests %+v", len(w.keys.requests), len(w.sec.events),
			w.policies.requests)
	}
	keyOutcome := func(rep postrestore.Report, slug string) string {
		for _, k := range rep.APIKeys {
			if k.Slug == slug {
				return k.Outcome + "/" + k.Reason
			}
		}
		return "-"
	}
	if !dry.DryRun || dry.Status != postrestore.StatusCompleted || dry.Sessions.Revoked != int64(w.sessionsTotal) ||
		dry.Sessions.LiveAtCutoff != int64(w.sessionsLive) || dry.Approvals.Expired != int64(w.pendingApprovals) ||
		dry.Approvals.ConsoleGrantsExpired != 1 || dry.Invitations.Revoked != 2 || len(dry.Instances.Orphans) != 1 ||
		len(dry.Instances.Lost) != 1 || dry.Instances.Lost[0].MarkedFailed || keyOutcome(dry, "pr-a") != "ok/" ||
		keyOutcome(dry, "pr-b") != "would_reissue/key_rejected" || dry.InventorySync.Enqueued != 2 || dry.AuditGap.Written != 0 {
		t.Fatalf("dry-run report:\n%s", dump(dry))
	}

	rep := w.run(false)
	if rep.Status != postrestore.StatusCompleted || len(rep.Incomplete) != 0 || rep.DryRun {
		t.Fatalf("report:\n%s", dump(rep))
	}
	// 1. maintenance ON + post_restore record
	var m platform.Maintenance
	if err := w.su.QueryRow(context.Background(), `SELECT value FROM system_settings WHERE key = 'maintenance'`).Scan(&m); err != nil {
		t.Fatal(err)
	}
	if !m.Enabled || m.Reason != platform.ReasonPostRestore || m.PostRestore == nil || m.PostRestore.Status != platform.PostRestoreReconciled ||
		!m.PostRestore.RestorePoint.Equal(w.restorePoint) || m.PostRestore.Runs != 1 || !m.PostRestore.GapRecorded ||
		m.PostRestore.RunID != rep.RunID || m.PostRestore.ReviewRequired != len(rep.ReviewRequired) || !rep.Maintenance.SetByRun {
		t.Fatalf("maintenance flag %+v / %+v", m, m.PostRestore)
	}
	// 2. revocations
	if n := w.count(`SELECT count(*) FROM sessions WHERE revoked_at IS NULL`); n != 0 || rep.Sessions.Revoked != int64(w.sessionsTotal) ||
		rep.Sessions.LiveAtCutoff != int64(w.sessionsLive) || rep.Sessions.AuthRequestsDeleted != 1 ||
		w.count(`SELECT count(*) FROM sessions WHERE id_token_hint_enc IS NOT NULL`) != 0 {
		t.Fatalf("sessions: %d still valid; report %+v", n, rep.Sessions)
	}
	if n := w.count(`SELECT count(*) FROM approval_requests WHERE status IN ('pending', 'approved')`); n != 0 ||
		rep.Approvals.Expired != int64(w.pendingApprovals) || rep.Approvals.ConsoleGrantsExpired != 1 ||
		w.count(`SELECT count(*) FROM approval_requests WHERE id = $1 AND status = 'expired'`, w.consoleGrant) != 1 ||
		w.count(`SELECT count(*) FROM approval_requests WHERE id = $1 AND status = 'executed'`, w.oldConsoleGrant) != 1 ||
		rep.Approvals.ByScopeStatus["platform/pending"] != 1 || rep.Approvals.ByScopeStatus["tenant/pending"] != 1 ||
		rep.Approvals.ByScopeStatus["platform/approved"] != 1 {
		t.Fatalf("approvals: %d open; report %+v", n, rep.Approvals)
	}
	if n := w.count(`SELECT count(*) FROM tenant_invitations WHERE status = 'pending'`); n != 0 || rep.Invitations.Revoked != 2 ||
		rep.Invitations.ByTenant["pr-a"] != 1 || rep.Invitations.ByTenant["pr-b"] != 1 || rep.SupportGrants.Status != "not_in_schema" {
		t.Fatalf("invitations: %d pending; report %+v", n, rep.Invitations)
	}
	// 3. instances: the orphan reported only, the lost one failed
	if len(rep.Instances.Orphans) != 1 || rep.Instances.Orphans[0].InstanceID != w.orphan.String() ||
		rep.Instances.Orphans[0].Slug != "pr-ghost" || !strings.Contains(rep.Instances.Orphans[0].Action, "report only") ||
		w.count(`SELECT count(*) FROM tenant_instances WHERE id = $1`, w.orphan) != 0 || rep.Instances.Inventory != "checked" ||
		rep.Instances.Host != 3 || rep.Instances.Registry != 3 {
		t.Fatalf("orphans: %+v", rep.Instances)
	}
	if len(rep.Instances.Lost) != 1 || rep.Instances.Lost[0].InstanceID != w.c.instance || !rep.Instances.Lost[0].MarkedFailed ||
		w.count(`SELECT count(*) FROM tenant_instances WHERE id = $1 AND status = 'failed'`, w.c.instance) != 1 ||
		w.count(`SELECT count(*) FROM audit_events WHERE action = 'platform.instance.lost' AND resource_id = $1`, w.c.instance.String()) != 1 {
		t.Fatalf("lost: %+v", rep.Instances.Lost)
	}
	if len(w.sec.events) != 1 || w.sec.events[0].Kind != "reconcile.unknown_instance" {
		t.Fatalf("security events: %+v", w.sec.events)
	}
	// 4. keys: the running instances only, AllowBootstrap, trigger post_restore
	var rotated []uuid.UUID
	for _, r := range w.keys.requests {
		if !r.AllowBootstrap || r.Trigger != apikey.TriggerRestore || r.Force {
			t.Fatalf("rotation request %+v", r)
		}
		rotated = append(rotated, r.TenantID)
	}
	if !slices.Equal(rotated, []uuid.UUID{w.a.id, w.b.id}) || keyOutcome(rep, "pr-a") != "ok/" ||
		keyOutcome(rep, "pr-b") != "reissued/key_rejected" || keyOutcome(rep, "pr-c") != "skipped/instance_lost" {
		t.Fatalf("keys: requests %v, report %+v", rotated, rep.APIKeys)
	}
	// 5. policies: A and B reviewed (not C), B flagged
	if n := len(w.policies.requests); n != 4 || w.policies.requests[2].DryRun || w.policies.requests[2].RunID != rep.RunID ||
		!w.policies.requests[2].RestorePoint.Equal(w.restorePoint) || len(rep.Policies) != 2 {
		t.Fatalf("policy requests %+v", w.policies.requests)
	}
	reasons := map[string][]string{}
	for _, it := range rep.ReviewRequired {
		key := it.Slug
		if it.TenantID == nil {
			key = "orphan:" + it.Slug
		}
		reasons[key] = it.Reasons
	}
	if !slices.Equal(reasons["pr-b"], []string{postrestore.ReviewPolicyDiffers}) ||
		!slices.Equal(reasons["pr-c"], []string{postrestore.ReviewInstanceLost}) ||
		!slices.Equal(reasons["orphan:pr-ghost"], []string{postrestore.ReviewOrphan}) || len(reasons) != 3 {
		t.Fatalf("review: %+v", rep.ReviewRequired)
	}
	// 6. inventory.sync for A and B (running), queued (the worker is in maintenance)
	if rep.InventorySync.Enqueued != 2 || !slices.Equal(rep.InventorySync.Skipped, []string{"pr-c"}) ||
		w.count(`SELECT count(*) FROM provisioning_jobs WHERE kind = 'inventory.sync' AND status = 'queued'
			AND instance_id IN ($1, $2)`, w.a.instance, w.b.instance) != 2 {
		t.Fatalf("inventory.sync: %+v", rep.InventorySync)
	}
	// 7. open jobs of the dump
	if len(rep.OpenJobs) != 1 || rep.OpenJobs[0].ID != w.queuedJob || rep.OpenJobs[0].Kind != "notification.send" {
		t.Fatalf("open jobs: %+v", rep.OpenJobs)
	}
	// 8. audit.gap + the audit pair
	unix := fmt.Sprint(w.restorePoint.Unix())
	if n := w.count(`SELECT count(*) FROM audit_events WHERE action = 'audit.gap' AND details->>'restore_point_unix' = $1`, unix); n != 4 ||
		w.count(`SELECT count(*) FROM audit_events WHERE action = 'audit.gap' AND tenant_id IS NULL`) != 1 ||
		w.count(`SELECT count(*) FROM audit_events WHERE action = 'audit.gap' AND tenant_id = $1 AND actor_type = 'system'`, w.c.id) != 1 ||
		rep.AuditGap.Written != 4 || !rep.AuditGap.Platform || rep.AuditGap.Tenants != 3 {
		t.Fatalf("audit.gap: %d events, report %+v", n, rep.AuditGap)
	}
	if got := w.count(`SELECT count(*) FROM audit_events WHERE action IN ('platform.restore.reconcile.requested',
		'platform.restore.reconcile.succeeded') AND resource_id = $1`, rep.RunID.String()); got != 2 ||
		w.count(`SELECT count(*) FROM audit_events WHERE action = 'platform.maintenance.enable' AND details->>'reason' = 'post_restore'`) != 1 {
		t.Fatalf("audit pair: %d", got)
	}
	gap := rep.Gap
	if !gap.From.Equal(w.restorePoint) || gap.To.Before(gap.From) || gap.Seconds < 7000 {
		t.Fatalf("gap %+v", gap)
	}

	// a platform operator signs in during maintenance, then the command runs again
	w.session(w.sa1, w.platformIdP, "admin", time.Second, false, false)
	again := w.run(false)
	if again.Sessions.Revoked != 1 || again.Approvals.Expired != 0 || again.Invitations.Revoked != 0 || again.AuditGap.Written != 0 ||
		again.InventorySync.Enqueued != 0 || again.InventorySync.Existing != 2 || again.Maintenance.SetByRun || again.Maintenance.Run != 2 ||
		len(again.Instances.Lost) != 0 || w.count(`SELECT count(*) FROM audit_events WHERE action = 'audit.gap'`) != 4 {
		t.Fatalf("second run:\n%s", dump(again))
	}
	res, err := platform.New(w.st).SetMaintenance(context.Background(), platform.MaintenanceChange{Actor: platform.SystemActor{Command: "off"}})
	if err != nil || !res.Changed || res.After.Enabled {
		t.Fatalf("maintenance off after the reconcile: %+v %v", res, err)
	}
}

// TestPostRestoreWithoutAgent — no Host Agent configured (dev/CI stack): the instance step cannot run — reported
// unavailable, the run is incomplete, nothing is marked lost — and everything else is done. The maintenance flag of the
// database is unreadable (damaged): it counts as ON and the run writes a valid one.
func TestPostRestoreWithoutAgent(t *testing.T) {
	w := newWorld(t, false)
	w.exec(`INSERT INTO system_settings (key, value) VALUES ('maintenance', '"damaged"')`)
	rep := w.run(false)
	if rep.Status != postrestore.StatusIncomplete || !slices.Equal(rep.Incomplete, []string{"instances:host:agent_not_configured"}) ||
		rep.Instances.Inventory != "unavailable" || len(rep.Instances.Lost) != 0 || len(rep.Instances.Orphans) != 0 ||
		w.count(`SELECT count(*) FROM tenant_instances WHERE status = 'failed'`) != 0 || rep.Sessions.Revoked != int64(w.sessionsTotal) {
		t.Fatalf("report:\n%s", dump(rep))
	}
	var status string
	var enabled bool
	if err := w.su.QueryRow(context.Background(), `SELECT value->'post_restore'->>'status', (value->>'enabled')::boolean
		FROM system_settings WHERE key = 'maintenance'`).Scan(&status, &enabled); err != nil ||
		status != platform.PostRestoreReconciled || !enabled || !rep.Maintenance.Previous || rep.Maintenance.SetByRun {
		t.Fatalf("post_restore status %q, enabled %v, report %+v (%v)", status, enabled, rep.Maintenance, err)
	}
}

// TestPostRestoreRefusals — refused before anything is written: no restore point, a restore point after the database
// clock, and a schema that already holds support_access_grants (P4-T05) which this version cannot revoke.
func TestPostRestoreRefusals(t *testing.T) {
	w := newWorld(t, true)
	before := w.state()
	ctx := context.Background()
	for name, req := range map[string]postrestore.Request{
		"no restore point": {},
		"in the future":    {RestorePoint: time.Now().Add(time.Hour)},
	} {
		rep, err := w.svc.Run(ctx, req)
		if !errors.Is(err, postrestore.ErrInvalidRequest) || rep.Status != postrestore.StatusFailed {
			t.Errorf("%s: %v %s", name, err, rep.Status)
		}
	}
	w.exec(`CREATE TABLE support_access_grants (id uuid PRIMARY KEY)`)
	if _, err := w.svc.Run(ctx, postrestore.Request{RestorePoint: w.restorePoint}); !errors.Is(err, postrestore.ErrUnsupportedSchema) {
		t.Fatalf("support_access_grants present: %v", err)
	}
	if got := w.state(); got != before || len(w.keys.requests) != 0 || w.agent.calls != 0 {
		t.Fatalf("a refused run changed something:\nbefore %s\nafter  %s", before, got)
	}
}

// TestPostRestoreKeyFailure — a key that cannot be re-issued (the agent refused) makes the run incomplete and flags the
// tenant; the other steps still run.
func TestPostRestoreKeyFailure(t *testing.T) {
	w := newWorld(t, true)
	w.keys.errs[w.b.id] = errors.New("agent refused")
	delete(w.keys.results, w.b.id)
	rep := w.run(false)
	if rep.Status != postrestore.StatusIncomplete || len(rep.Incomplete) != 1 || !strings.HasPrefix(rep.Incomplete[0], "api_key:pr-b:") ||
		rep.InventorySync.Enqueued != 2 || rep.AuditGap.Written != 4 {
		t.Fatalf("report:\n%s", dump(rep))
	}
	for _, it := range rep.ReviewRequired {
		if it.Slug == "pr-b" && !slices.Contains(it.Reasons, postrestore.ReviewKeyFailed) {
			t.Fatalf("pr-b not flagged for its key: %+v", it)
		}
	}
}
