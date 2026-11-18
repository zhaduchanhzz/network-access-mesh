package quarantine

// PostgreSQL integration harness of quarantine/release (internal/store/storetest): one database for the package, each
// test with its own host and tenants (a running instance with its applied policy — the allow fixture through the real
// policy core), platform staff (two Super Admins, a Platform Operator) and the real job framework (River worker with
// the step gate of this package) running the handlers of this package. The Host Agent is an in-memory model of the
// host state of each instance (marker, flag, edge, container, served policy) speaking the agent's typed refusals;
// Headscale is a fake per tenant behind a registry that, like the production locator, reaches only a starting or
// running instance of an active or suspended tenant. The real agent, Docker, the edge and Headscale are exercised by
// apps/agent TestQuarantineReleaseEndToEnd (make agent-it).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// ---------------------------------------------------------------------------------------------------- fake agent

// hostState is what the fake agent knows of one instance on its host.
type hostState struct {
	tenant                            uuid.UUID
	marked, flag, attached, running   bool
	activated                         bool
	served                            string // the policy the instance serves (sha256 of its HuJSON)
	dataSum                           string // stands for data/: never changed by the agent
	quarantines, releases, startCalls int
}

// fakeAgent models the agent's quarantine contract: the marker first, then containment; a marked instance refuses
// starts and attachments; ReleaseInstance starts (start guard), checks the served policy, then unmarks.
type fakeAgent struct {
	mu    sync.Mutex
	inst  map[uuid.UUID]*hostState
	calls []string
	// failures
	busy          int  // QuarantineInstance answers BUSY this many more times
	alwaysBusy    bool // QuarantineInstance always BUSY
	startGuard    bool // ReleaseInstance: start guard violation (contained, refused)
	releaseBlock  chan struct{}
	releaseEnter  chan struct{} // closed when ReleaseInstance is entered (blocking tests)
	attachErr     error
	statusRunning bool // GetInstanceStatus lies: the container keeps running (containment incomplete)
}

func newFakeAgent() *fakeAgent { return &fakeAgent{inst: map[uuid.UUID]*hostState{}} }

func agentRefusal(code codes.Code, reason agentv1.RefusalReason, msg string) error {
	st, err := status.New(code, msg).WithDetails(&agentv1.Refusal{Reason: reason, Field: "instance", Message: msg})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

func (a *fakeAgent) state(ref *agentv1.InstanceRef) (*hostState, error) {
	id := uuid.MustParse(ref.GetInstanceId())
	h, ok := a.inst[id]
	if !ok {
		return nil, agentRefusal(codes.NotFound, agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, "no instance directory")
	}
	if h.tenant.String() != ref.GetTenantId() {
		return nil, agentRefusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, "identity")
	}
	return h, nil
}

func (a *fakeAgent) status(ref *agentv1.InstanceRef, h *hostState) *agentv1.InstanceStatus {
	cs := agentv1.ContainerState_CONTAINER_STATE_EXITED
	if h.running || a.statusRunning {
		cs = agentv1.ContainerState_CONTAINER_STATE_RUNNING
	}
	return &agentv1.InstanceStatus{Instance: ref, ContainerState: cs, Quarantined: h.marked, EdgeAttachFlag: h.flag,
		Activated: h.activated, Network: &agentv1.NetworkState{Exists: true, EdgeAttached: h.attached}}
}

func (a *fakeAgent) GetInstanceStatus(_ context.Context, in *agentv1.GetInstanceStatusRequest, _ ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "GetInstanceStatus")
	h, err := a.state(in.GetInstance())
	if err != nil {
		return nil, err
	}
	return &agentv1.GetInstanceStatusResponse{Status: a.status(in.GetInstance(), h)}, nil
}

func (a *fakeAgent) QuarantineInstance(_ context.Context, in *agentv1.QuarantineInstanceRequest, _ ...grpc.CallOption) (*agentv1.QuarantineInstanceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "QuarantineInstance")
	if a.alwaysBusy || a.busy > 0 {
		a.busy--
		return nil, agentRefusal(codes.Aborted, agentv1.RefusalReason_REFUSAL_REASON_BUSY, "busy")
	}
	h, err := a.state(in.GetInstance())
	if err != nil {
		return nil, err
	}
	out := &agentv1.QuarantineInstanceResponse{MarkedNow: !h.marked, EdgeWasAttached: h.attached || h.flag, ContainerWasRunning: h.running}
	h.marked, h.flag, h.attached, h.running = true, false, false, false
	h.quarantines++
	out.Status = a.status(in.GetInstance(), h)
	return out, nil
}

func (a *fakeAgent) ReleaseInstance(ctx context.Context, in *agentv1.ReleaseInstanceRequest, _ ...grpc.CallOption) (*agentv1.ReleaseInstanceResponse, error) {
	a.mu.Lock()
	block, enter := a.releaseBlock, a.releaseEnter
	a.calls = append(a.calls, "ReleaseInstance")
	a.mu.Unlock()
	if enter != nil {
		close(enter)
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	h, err := a.state(in.GetInstance())
	if err != nil {
		return nil, err
	}
	h.releases++
	if a.startGuard {
		h.running = false // contained: never started
		return nil, agentRefusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE,
			"start guard (§11.4): fingerprint_mismatch — the instance was not started")
	}
	h.running, h.startCalls = true, h.startCalls+1
	if h.served != in.GetExpectedPolicySha256() {
		h.running = false
		return nil, agentRefusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE,
			"the instance serves another policy: not released")
	}
	was := h.marked
	h.marked = false
	return &agentv1.ReleaseInstanceResponse{WasQuarantined: was, PolicySha256: h.served, Status: a.status(in.GetInstance(), h)}, nil
}

func (a *fakeAgent) EnsureEdgeAttachment(_ context.Context, in *agentv1.EnsureEdgeAttachmentRequest, _ ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "EnsureEdgeAttachment")
	h, err := a.state(in.GetInstance())
	if err != nil {
		return nil, err
	}
	switch {
	case h.marked:
		return nil, agentRefusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "the instance is quarantined")
	case a.attachErr != nil:
		return nil, a.attachErr
	case !h.running:
		return nil, agentRefusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "not running")
	}
	was := h.attached
	h.flag, h.attached, h.activated = true, true, true
	return &agentv1.EnsureEdgeAttachmentResponse{Attached: true, AlreadyAttached: was, NetworkMembers: 2}, nil
}

func (a *fakeAgent) set(fn func(a *fakeAgent)) { a.mu.Lock(); defer a.mu.Unlock(); fn(a) }

func (a *fakeAgent) host(id uuid.UUID) hostState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.inst[id]
}

func (a *fakeAgent) count(name string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.calls {
		if c == name {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------------------------------- fake Headscale

// fakeHS is the part of a Headscale instance the policy core and the post-start gate call.
type fakeHS struct {
	headscale.Instance

	mu          sync.Mutex
	stored      string
	keyRejected bool
	noDB        bool
	gates       int
}

func (f *fakeHS) CheckPolicy(_ context.Context, p string) error {
	if err := headscale.ValidatePolicyDocument(p); err != nil {
		return &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindValidation}
	}
	return nil
}

func (f *fakeHS) SetPolicy(_ context.Context, p string) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stored = p
	return headscale.Policy{Data: p, UpdatedAt: time.Now()}, nil
}

func (f *fakeHS) GetPolicy(context.Context) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stored == "" {
		return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy, Err: headscale.ErrNoPolicy}
	}
	return headscale.Policy{Data: f.stored, UpdatedAt: time.Now()}, nil
}

func (f *fakeHS) Health(context.Context) (headscale.Health, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gates++
	if f.keyRejected {
		return headscale.Health{}, &headscale.Error{Op: headscale.OpHealth, Kind: headscale.KindAPIKeyRejected, Err: headscale.ErrAPIKeyRejected}
	}
	return headscale.Health{DatabaseConnectivity: !f.noDB}, nil
}

func (f *fakeHS) set(fn func(f *fakeHS)) { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }

// gatedReg reaches, like the production locator, only a starting or running instance of an active or suspended tenant.
type gatedReg struct {
	st *store.Store
	mu sync.Mutex
	hs map[uuid.UUID]*fakeHS
}

func (r *gatedReg) ForTenant(ctx context.Context, t uuid.UUID) (headscale.Instance, error) {
	var tenant, inst string
	err := r.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetTenant(ctx, t)
		if err != nil {
			return err
		}
		tenant = row.Status
		i, err := q.GetLiveInstanceForTenant(ctx, t)
		inst = i.Status
		return err
	})
	if err != nil || !slices.Contains([]string{tenants.StatusActive, tenants.StatusSuspended}, tenant) ||
		!slices.Contains([]string{tenants.InstanceStarting, tenants.InstanceRunning}, inst) {
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1,
			Err: fmt.Errorf("tenant %q instance %q: %w", tenant, inst, headscale.ErrNoInstance)}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hs[t], nil
}

// ---------------------------------------------------------------------------------------------------- the rig

type tenantFx struct {
	id, instance uuid.UUID
	slug         string
	hs           *fakeHS
	appliedSHA   string
}

type rig struct {
	env    *storetest.Env
	db     string
	su     *pgx.Conn
	mu     sync.Mutex
	api    *store.Store
	wrk    *store.Store
	agent  *fakeAgent
	reg    *gatedReg
	core   *policies.Service
	req    *Requester
	h      *Handler
	appr   *approvals.Service
	worker *jobs.Worker
	host   uuid.UUID
	pidp   uuid.UUID
	sa1    approvals.Actor // requester
	sa2    approvals.Actor // second Super Admin
	po     approvals.Actor
	emails []string
	n      int
	// lifecycle test handler: a two-step instance.restart that waits between its steps
	restartBetween chan struct{}
	restartPaused  chan struct{}
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

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func allowFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "infrastructure", "headscale", "templates", "test-allow-intra.hujson")) //nolint:gosec // G304: fixture of the repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type rigOptions struct {
	noAgent        bool
	noWorker       bool
	isolateRetries int
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
	g := &rig{env: env, db: db, su: env.Admin(t, db), host: uuid.New(), agent: newFakeAgent(), pidp: uuid.New()}
	g.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, $2, 'lab', int4range(30000, 40000), '10.250.0.0/16')`, g.host, "host-"+randomHex(6))
	g.exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', $2, 'mg-portal', 'keycloak', 'active')`, g.pidp, "https://idp.invalid/realms/p"+randomHex(4))
	g.api = env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 6)
	g.wrk = env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 10)
	g.reg = &gatedReg{st: g.wrk, hs: map[uuid.UUID]*fakeHS{}}
	core, err := policies.New(g.wrk, policies.Config{Registry: g.reg, LockWait: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	g.core = core
	g.req = NewRequester(g.api)
	cfg := Config{Store: g.wrk, Headscale: g.reg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetryBase: 10 * time.Millisecond, RetryMax: 40 * time.Millisecond, StepRetries: 2, IsolateRetries: o.isolateRetries}
	if cfg.IsolateRetries == 0 {
		cfg.IsolateRetries = 3
	}
	if !o.noAgent {
		cfg.Agent = g.agent
	}
	if g.h, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	g.sa1, g.sa2, g.po = g.staff(t, "super_admin"), g.staff(t, "super_admin"), g.staff(t, "platform_operator")
	for _, a := range []approvals.Actor{g.sa1, g.sa2, g.po} {
		g.emails = append(g.emails, staffEmail(a.IdentityID))
	}
	actions, err := approvals.NewRegistry(approvals.Typed(approvals.Spec{Name: ReleaseApprovalAction, Scope: authz.ScopePlatform,
		ResourceType: ReleaseResourceType, Permission: ReleasePermission},
		func(ctx context.Context, tx *store.Tx, e approvals.Execution, p ReleasePayload) (*uuid.UUID, error) {
			id, err := ExecuteRelease(ctx, tx, ReleaseExecution{ApprovalID: e.Request.ID, RequestedBy: e.Request.RequestedBy.IdentityID,
				ApprovedBy: e.Request.DecidedBy.IdentityID, Payload: p})
			if err != nil {
				var re *RequestError
				if ok := asRequestError(err, &re); ok {
					return nil, &approvals.Error{Kind: approvals.ErrConflict, Reason: re.Reason}
				}
				return nil, err
			}
			return &id, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	if g.appr, err = approvals.New(g.api, approvals.Config{Approvers: authz.New(g.api), Registry: actions}); err != nil {
		t.Fatal(err)
	}
	if !o.noWorker {
		g.startWorker(t)
	}
	return g
}

func asRequestError(err error, re **RequestError) bool {
	e, ok := err.(*RequestError) //nolint:errorlint // ExecuteRelease returns it unwrapped
	if ok {
		*re = e
	}
	return ok
}

// staff creates a platform identity with role, freshly stepped up.
func (g *rig) staff(t *testing.T, role string) approvals.Actor {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	g.exec(t, `INSERT INTO identities (id, idp_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, 'platform', $3, $4, true, $5)`, id, g.pidp, "sub-"+id.String(), staffEmail(id), role)
	g.exec(t, `INSERT INTO platform_users (identity_id, role_id) SELECT $1, id FROM roles WHERE scope = 'platform' AND key = $2`, id, role)
	a := approvals.Actor{IdentityID: id, Scope: authz.ScopePlatform, AuthTime: time.Now()}
	if role == "platform_operator" {
		a.Condition = authz.CondRestoreOnly
	}
	return a
}

// startWorker starts a River worker with the handlers of this package, the step gate, and a test lifecycle job
// (instance.restart: step one, wait, step two).
func (g *rig) startWorker(t *testing.T) {
	t.Helper()
	g.exec(t, `DELETE FROM river.river_job`)
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 50*time.Millisecond, 200*time.Millisecond
	cfg.LockBusySnooze, cfg.LockHeldSnooze = 100*time.Millisecond, 200*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	w, err := jobs.NewWorker(g.wrk, cfg, jobs.Options{Registerer: prometheus.NewRegistry(), StepGate: Gate})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.h.Register(w); err != nil {
		t.Fatal(err)
	}
	g.restartBetween, g.restartPaused = make(chan struct{}), make(chan struct{}, 4)
	if err := w.Register(lifecycleKind, restartJob{g}); err != nil {
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

// lifecycleKind is the kind the stand-in lifecycle job is registered under: lifecycle group (LockHold) and compensable.
const lifecycleKind = "instance.reconfigure"

// restartJob is a stand-in lifecycle job: step instance.stop, then it waits for the test, then step instance.start — a
// job holding the tenant's lifecycle lock across a quarantine. Its compensation undoes instance.stop (gated like any
// compensation).
type restartJob struct{ g *rig }

func (j restartJob) Run(ctx context.Context, run *jobs.Run) error {
	if err := run.Step(ctx, "instance.stop", func(context.Context, *jobs.StepRun) error { return nil }); err != nil {
		return err
	}
	j.g.restartPaused <- struct{}{}
	select {
	case <-j.g.restartBetween:
	case <-ctx.Done():
		return ctx.Err()
	}
	return run.Step(ctx, "instance.start", func(context.Context, *jobs.StepRun) error { return nil })
}

func (j restartJob) Compensate(ctx context.Context, run *jobs.Run, _ error) error {
	return run.CompensateSteps(ctx, map[string]jobs.CompensateFunc{
		"instance.stop": func(context.Context, jobs.CompensationStep) error { return nil },
	})
}

// newTenant creates an active tenant with a running instance on the fake host, attached and serving the allow fixture
// applied through the policy core (its current applied row).
func (g *rig) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	shared.mu.Lock()
	shared.n++
	i := shared.n
	shared.mu.Unlock()
	g.n++
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), slug: "q" + randomHex(5) + fmt.Sprintf("%03d", i%1000), hs: &fakeHS{}}
	g.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	g.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		ten.instance, ten.id, g.host, ten.slug+".mesh.test", ten.slug+".ts.test", "hs-"+ten.slug+":8080", 30000+(i%9000),
		fmt.Sprintf("10.250.%d.%d/29", (i/32)%256, (i%32)*8), "/opt/meshguard/tenants/"+ten.instance.String())
	g.reg.mu.Lock()
	g.reg.hs[ten.id] = ten.hs
	g.reg.mu.Unlock()
	res, err := g.core.Apply(t.Context(), policies.ApplyRequest{TenantID: ten.id, HuJSON: allowFixture(t),
		Trigger: policies.TriggerManual, Actor: "fixture"})
	if err != nil {
		t.Fatalf("apply the allow fixture: %v", err)
	}
	ten.appliedSHA = res.AppliedSHA256
	g.agent.set(func(a *fakeAgent) {
		a.inst[ten.instance] = &hostState{tenant: ten.id, flag: true, attached: true, running: true, activated: true,
			served: ten.appliedSHA, dataSum: randomHex(8)}
	})
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

func (g *rig) str(t *testing.T, sql string, args ...any) string {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	var s string
	if err := g.su.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return s
}

func (g *rig) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	var n int
	if err := g.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return n
}

func (g *rig) instanceStatus(t *testing.T, ten *tenantFx) string {
	t.Helper()
	return g.str(t, `SELECT status FROM tenant_instances WHERE id = $1`, ten.instance)
}

// reqCtx is the request scope the HTTP layer gives the API side (audit actor and action).
func (g *rig) reqCtx(t *testing.T, actor uuid.UUID, action string) context.Context {
	return audit.WithRequest(t.Context(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &actor, ActorDisplay: "operator", RequestID: "req-" + uuid.NewString()[:8]})
}

func (g *rig) quarantine(t *testing.T, ten *tenantFx, key string) (Requested, error) {
	t.Helper()
	var idem *Idempotency
	if key != "" {
		idem = &Idempotency{Key: key, Hash: jobs.RequestHash("POST", "/platform/instances/"+ten.instance.String()+"/quarantine", []byte(`{"reason":"test"}`))}
	}
	return g.req.Quarantine(g.reqCtx(t, g.sa1.IdentityID, ActionQuarantine), g.sa1.IdentityID, ten.instance, "suspected compromise (test)", idem)
}

// requestRelease is the API side of POST /release: the payload check, then the approval request of sa1.
func (g *rig) requestRelease(t *testing.T, ten *tenantFx) (approvals.Request, error) {
	t.Helper()
	p, err := g.req.ReleasePayload(t.Context(), ten.instance)
	if err != nil {
		return approvals.Request{}, err
	}
	return g.appr.Request(g.reqCtx(t, g.sa1.IdentityID, "platform.instance.release.request"), g.sa1,
		approvals.NewRequest{Action: ReleaseApprovalAction, ResourceID: ten.instance.String(), Payload: p, Reason: "investigation closed"})
}

func (g *rig) approve(t *testing.T, who approvals.Actor, r approvals.Request) (approvals.Request, error) {
	t.Helper()
	who.AuthTime = time.Now()
	return g.appr.Approve(g.reqCtx(t, who.IdentityID, "platform.approval.approve"), who, approvals.Ref{Scope: authz.ScopePlatform, ID: r.ID},
		r.PayloadSHA256)
}

// wait polls the job until it reaches a status in want.
func (g *rig) wait(t *testing.T, job uuid.UUID, want ...string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var st string
	for time.Now().Before(deadline) {
		st = g.str(t, `SELECT status FROM provisioning_jobs WHERE id = $1`, job)
		if slices.Contains(want, st) {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s is %s after 60 s, want %v (steps %s, error %s)", job, st, want, g.steps(t, job),
		g.str(t, `SELECT coalesce(error::text, '') FROM provisioning_jobs WHERE id = $1`, job))
	return st
}

// steps returns "name:status[:error]" of the job's steps in order.
func (g *rig) steps(t *testing.T, job uuid.UUID) string {
	t.Helper()
	return g.str(t, `SELECT coalesce(string_agg(name || ':' || status || coalesce(':' || error_code, ''), ' ' ORDER BY seq), '')
		FROM provisioning_job_steps WHERE job_id = $1`, job)
}

func (g *rig) errCode(t *testing.T, job uuid.UUID) string {
	t.Helper()
	return g.str(t, `SELECT coalesce(error->>'code', '') FROM provisioning_jobs WHERE id = $1`, job)
}

// events counts the platform security events of kind about the instance.
func (g *rig) events(t *testing.T, kind string, ten *tenantFx) int {
	t.Helper()
	return g.count(t, `SELECT count(*) FROM security_events WHERE kind = $1 AND tenant_id IS NULL AND details->>'instance_id' = $2`,
		kind, ten.instance.String())
}

// auditPair returns the actions of the audit operation of action about the instance, in order.
func (g *rig) auditActions(t *testing.T, action string, ten *tenantFx) string {
	t.Helper()
	return g.str(t, `SELECT coalesce(string_agg(action || ':' || outcome, ' ' ORDER BY occurred_at, id), '') FROM audit_events
		WHERE action LIKE $1 || '.%' AND resource_id = $2`, action, ten.instance.String())
}

// notified counts the platform notifications of kind/outcome about the instance sent to this rig's three staff (the
// database is shared: other tests' staff receive them too).
func (g *rig) notified(t *testing.T, kind, outcome string, ten *tenantFx) int {
	t.Helper()
	return g.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id IS NULL AND kind = $1
		AND payload->>'instance_id' = $2 AND payload->>'outcome' = $3 AND recipient_email = ANY($4::text[])`,
		kind, ten.instance.String(), outcome, g.emails)
}

func staffEmail(id uuid.UUID) string {
	return "s" + id.String()[:8] + id.String()[24:] + "@platform.test"
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

// quarantineJob runs a quarantine to its end and returns the job.
func (g *rig) quarantined(t *testing.T, ten *tenantFx) uuid.UUID {
	t.Helper()
	out, err := g.quarantine(t, ten, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, out.Job.ID, jobs.StatusSucceeded)
	return out.Job.ID
}
