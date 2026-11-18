package deprovision

// PostgreSQL integration harness of the deprovision (internal/store/storetest): one database for the package, every
// test with its own host and tenants — each with a running instance, members with live Portal sessions, a pending
// invitation, an open approval on its instance, relay rows, an active keycloak IdP, the instance API key, a backup key
// and an IdP client secret in the REAL SecretStore, a subscription and its desired policy applied through the real
// policy core — and the real job framework (River worker) running the handler; the 2P request goes through the real
// approvals service with two Super Admins. Headscale (nodes, pre-auth keys, policy), the Host Agent (edge, container,
// network, directory, archives), the final backup and the IdP driver are fakes that model what they own and can fail
// AFTER their effect (the answer lost — a worker that died mid-step). Docker, the real agent, Headscale and the real
// backup path are exercised by the provisioning harness (tests/integration/provisioning, E2E-73…E2E-75).

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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// ---------------------------------------------------------------------------------------------------- fake Headscale

type fakeHS struct {
	headscale.Instance

	mu          sync.Mutex
	stored      string
	nodes       []headscale.Node
	keys        []headscale.PreAuthKey
	expireAfter int   // ExpireNode: this many calls fail AFTER the node expired (the answer lost — transient)
	expireErr   error // ExpireNode: answers this BEFORE any effect (persistent)
	calls       []string
}

func (f *fakeHS) call(op string) { f.calls = append(f.calls, op) }

func (f *fakeHS) CheckPolicy(_ context.Context, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("CheckPolicy")
	if err := headscale.ValidatePolicyDocument(p); err != nil {
		return &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindValidation}
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
	if f.stored == "" {
		return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy}
	}
	return headscale.Policy{Data: f.stored, UpdatedAt: time.Now()}, nil
}

func (f *fakeHS) ListNodes(context.Context, string) ([]headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ListNodes")
	return slices.Clone(f.nodes), nil
}

func (f *fakeHS) ExpireNode(_ context.Context, id uint64, at *time.Time) (headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call(fmt.Sprintf("ExpireNode:%d", id))
	if f.expireErr != nil {
		return headscale.Node{}, f.expireErr
	}
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			e := time.Now()
			if at != nil {
				e = *at
			}
			f.nodes[i].Expiry = &e
			if f.expireAfter > 0 {
				f.expireAfter--
				return headscale.Node{}, &headscale.Error{Op: headscale.OpExpireNode, Kind: headscale.KindUnavailable}
			}
			return f.nodes[i], nil
		}
	}
	return headscale.Node{}, &headscale.Error{Op: headscale.OpExpireNode, Kind: headscale.KindNotFound}
}

func (f *fakeHS) ListPreAuthKeys(context.Context) ([]headscale.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ListPreAuthKeys")
	return slices.Clone(f.keys), nil
}

func (f *fakeHS) ExpirePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call(fmt.Sprintf("ExpirePreAuthKey:%d", id))
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys[i].Expiration = time.Now().Add(-time.Second)
		}
	}
	return nil
}

func (f *fakeHS) set(fn func(f *fakeHS)) { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }

func (f *fakeHS) Stored() string { f.mu.Lock(); defer f.mu.Unlock(); return f.stored }

func (f *fakeHS) validNodes(now time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, x := range f.nodes {
		if x.Expiry == nil || x.Expiry.After(now) {
			n++
		}
	}
	return n
}

// gatedReg is the headscale.Registry of the tests: like the production locator it reads the tenant's status at every
// ForTenant and refuses a tenant outside statuses; forTenantErr fails that many calls (transient).
type gatedReg struct {
	st           *store.Store
	statuses     []string
	mu           sync.Mutex
	hs           map[uuid.UUID]*fakeHS
	forTenantErr int
}

func (r *gatedReg) ForTenant(ctx context.Context, t uuid.UUID) (headscale.Instance, error) {
	r.mu.Lock()
	if r.forTenantErr > 0 {
		r.forTenantErr--
		r.mu.Unlock()
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1, Err: headscale.ErrNoInstance}
	}
	r.mu.Unlock()
	var st string
	if err := r.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetTenant(ctx, t)
		st = row.Status
		return err
	}); err != nil || !slices.Contains(r.statuses, st) {
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1,
			Err: fmt.Errorf("tenant is %q: %w", st, headscale.ErrNoInstance)}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hs[t]
	if !ok {
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1, Err: headscale.ErrNoInstance}
	}
	return h, nil
}

// ---------------------------------------------------------------------------------------------------- fake Host Agent

// hostModel is what the agent holds of one instance.
type hostModel struct {
	edge, container, network, dir bool
	archives                      []uint64 // signed archives in backups/tenants/<instance>/
}

type fakeAgent struct {
	mu     sync.Mutex
	hosts  map[string]*hostModel // instance id → model
	calls  []string
	after  map[string]int // call → that many calls fail AFTER their effect (UNAVAILABLE: the answer lost)
	refuse map[string]int // call → that many calls are refused BEFORE any effect (FAILED_PRECONDITION)
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{hosts: map[string]*hostModel{}, after: map[string]int{}, refuse: map[string]int{}}
}

func (a *fakeAgent) host(id string) *hostModel {
	h, ok := a.hosts[id]
	if !ok {
		h = &hostModel{}
		a.hosts[id] = h
	}
	return h
}

func (a *fakeAgent) fault(call string) (before, after error) {
	if a.refuse[call] > 0 {
		a.refuse[call]--
		return status.Error(codes.FailedPrecondition, "refused by the test"), nil
	}
	if a.after[call] > 0 {
		a.after[call]--
		return nil, status.Error(codes.Unavailable, "answer lost (test)")
	}
	return nil, nil
}

func (a *fakeAgent) RemoveEdgeAttachment(_ context.Context, in *agentv1.RemoveEdgeAttachmentRequest, _ ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	call := "RemoveEdgeAttachment:" + in.GetReason().String()
	a.calls = append(a.calls, call)
	before, after := a.fault("RemoveEdgeAttachment")
	if before != nil {
		return nil, before
	}
	h := a.host(in.GetInstance().GetInstanceId())
	was := h.edge
	h.edge = false
	if after != nil {
		return nil, after
	}
	return &agentv1.RemoveEdgeAttachmentResponse{Detached: was, WasAttached: was}, nil
}

func (a *fakeAgent) RemoveInstance(_ context.Context, in *agentv1.RemoveInstanceRequest, _ ...grpc.CallOption) (*agentv1.RemoveInstanceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	name := "RemoveInstance:" + in.GetData().String()
	if in.GetData() == agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED {
		name += fmt.Sprintf(":%d", in.GetArchivedBackupSequence())
	}
	a.calls = append(a.calls, name)
	before, after := a.fault("RemoveInstance:" + in.GetData().String())
	if before != nil {
		return nil, before
	}
	h := a.host(in.GetInstance().GetInstanceId())
	if h.edge {
		return nil, status.Error(codes.FailedPrecondition, "the edge is attached — RemoveEdgeAttachment first")
	}
	if in.GetData() == agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED &&
		!slices.Contains(h.archives, in.GetArchivedBackupSequence()) {
		return nil, status.Error(codes.FailedPrecondition, "no signed archive of this sequence")
	}
	out := &agentv1.RemoveInstanceResponse{ContainerRemoved: h.container, NetworkRemoved: h.network}
	h.container, h.network = false, false
	switch in.GetData() {
	case agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED, agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED:
		out.DirectoryRemoved = h.dir
		h.dir = false
	}
	if after != nil {
		return nil, after
	}
	return out, nil
}

func (a *fakeAgent) Calls() []string { a.mu.Lock(); defer a.mu.Unlock(); return slices.Clone(a.calls) }

func (a *fakeAgent) model(id uuid.UUID) hostModel {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.host(id.String())
}

// ---------------------------------------------------------------------------------------------------- fake final backup

// fakeBackups records a signed-looking backup of the job in the book (the real path — the agent's helper, the manifest
// — is the provisioning harness's) and the archive in the agent's model.
type fakeBackups struct {
	exec  func(sql string, args ...any) error // never t.Fatal: it runs in the worker's goroutine
	agent *fakeAgent
	mu    sync.Mutex
	calls int
	after int   // that many calls fail AFTER the backup was recorded (transient — the answer lost)
	err   error // answered BEFORE anything (persistent)
	keeps []time.Duration
}

func (b *fakeBackups) FinalBackup(_ context.Context, jobID, tenantID, instanceID uuid.UUID, keep time.Duration) (backup.BackupResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.keeps = append(b.keeps, keep)
	if b.err != nil {
		return backup.BackupResult{}, b.err
	}
	seq := uint64(time.Now().UnixMilli()) + uint64(b.calls) //nolint:gosec // positive
	id := uuid.New()
	if err := b.exec(`INSERT INTO backups (id, tenant_id, instance_id, kind, status, storage_uri, key_ref, headscale_version,
			sequence, wrapped_data_key, finished_at, size_bytes, sha256, manifest, manifest_signature, manifest_sha256, method,
			expires_at, job_id)
		VALUES ($1, $2::uuid, $3::uuid, 'instance', 'succeeded',
			'agent://test/backups/tenants/'||$3::uuid::text||'/'||$4::bigint::text||'.tar.age',
			'mgsec://'||$2::uuid::text||'/backup-key#1', '0.29.7', $4::bigint, decode(repeat('ab', 60), 'hex'), now(), 100,
			repeat('0', 64), convert_to('{}', 'UTF8'), decode(repeat('cd', 64), 'hex'), repeat('e', 64), 'vacuum_into',
			now() + $5::interval, $6)`,
		id, tenantID, instanceID, int64(seq), fmt.Sprintf("%d seconds", int64(keep/time.Second)), jobID); err != nil { //nolint:gosec // test values
		return backup.BackupResult{}, jobs.Transient("registry_unavailable", err)
	}
	b.agent.mu.Lock()
	h := b.agent.host(instanceID.String())
	h.archives = append(h.archives, seq)
	b.agent.mu.Unlock()
	if b.after > 0 {
		b.after--
		return backup.BackupResult{}, jobs.Transient("agent_unavailable", fmt.Errorf("answer lost (test)"))
	}
	return backup.BackupResult{BackupID: id, Sequence: seq, Method: "vacuum_into", SizeBytes: 100}, nil
}

func (b *fakeBackups) Calls() int { b.mu.Lock(); defer b.mu.Unlock(); return b.calls }

func (b *fakeBackups) set(fn func(b *fakeBackups)) { b.mu.Lock(); defer b.mu.Unlock(); fn(b) }

// ---------------------------------------------------------------------------------------------------- fake IdP

type fakeKeycloak struct {
	mu      sync.Mutex
	removes []string // driverRef:mode
	after   int      // RemoveIssuer: that many calls fail AFTER their effect (unavailable)
	realms  map[string]string
}

var _ idp.IdPDriver = (*fakeKeycloak)(nil)

func (d *fakeKeycloak) Name() string { return idp.DriverKeycloak }
func (d *fakeKeycloak) EnsureIssuer(context.Context, idp.IssuerSpec) (idp.IssuerResult, error) {
	return idp.IssuerResult{}, idp.NewError(idp.CodeUnsupported, "EnsureIssuer", "test", nil)
}
func (d *fakeKeycloak) EnsureClient(context.Context, idp.ClientSpec) (idp.ClientResult, error) {
	return idp.ClientResult{}, idp.NewError(idp.CodeUnsupported, "EnsureClient", "test", nil)
}
func (d *fakeKeycloak) InviteUser(context.Context, idp.Registration, idp.Invite) (idp.InviteResult, error) {
	return idp.InviteResult{}, idp.NewError(idp.CodeUnsupported, "InviteUser", "test", nil)
}
func (d *fakeKeycloak) DisableUser(context.Context, idp.Registration, string) (idp.DisableResult, error) {
	return idp.DisableResult{}, idp.NewError(idp.CodeUnsupported, "DisableUser", "test", nil)
}
func (d *fakeKeycloak) CheckDiscovery(context.Context, idp.Registration) (idp.Discovery, error) {
	return idp.Discovery{}, nil
}

func (d *fakeKeycloak) RemoveIssuer(_ context.Context, reg idp.Registration, mode idp.RemoveMode) (idp.RemoveResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removes = append(d.removes, reg.DriverRef+":"+string(mode))
	d.realms[reg.DriverRef] = string(mode)
	if d.after > 0 {
		d.after--
		return idp.RemoveResult{}, idp.NewError(idp.CodeUnavailable, "RemoveIssuer", "test", nil)
	}
	return idp.RemoveResult{Mode: mode, Changed: true}, nil
}

func (d *fakeKeycloak) Removes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.removes)
}

type drivers map[string]idp.IdPDriver

func (m drivers) Driver(name string) (idp.IdPDriver, error) {
	if d, ok := m[name]; ok {
		return d, nil
	}
	return nil, idp.NewError(idp.CodeUnknownDriver, "Driver", name, nil)
}

// ---------------------------------------------------------------------------------------------------- the rig

// tenantFx is one fixture tenant.
type tenantFx struct {
	id, instance, idp       uuid.UUID
	slug                    string
	owner, admin            uuid.UUID // identities
	sessions                int
	invitation, approval    uuid.UUID
	hs                      *fakeHS
	desired                 uuid.UUID
	apiKey, backupKey, idpC secrets.Ref
}

type rig struct {
	env     *storetest.Env
	db      string
	su      *pgx.Conn
	mu      sync.Mutex
	api     *store.Store // mg_api_*: the Requester, the approvals service
	wrk     *store.Store // mg_worker_*: the handler, the policy core, the SecretStore
	sec     *secrets.Store
	reg     *gatedReg
	core    *policies.Service
	agent   *fakeAgent
	backups *fakeBackups
	kc      *fakeKeycloak
	req     *Requester
	appr    *approvals.Service
	h       *Handler
	worker  *jobs.Worker
	host    uuid.UUID
	pidp    uuid.UUID
	staff   [2]approvals.Actor // two Super Admins
	grace   time.Duration
	n       int
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

func allowFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "infrastructure", "headscale", "templates", "test-allow-intra.hujson")) //nolint:gosec // G304: fixture of the repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type rigOptions struct {
	noWorker    bool
	noAgent     bool
	unreachable bool // the handler's Headscale registry never reaches an instance (the policy core's does)
	grace       time.Duration
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
	g := &rig{env: env, db: db, su: env.Admin(t, db), host: uuid.New(), pidp: uuid.New(), grace: o.grace}
	if g.grace == 0 {
		g.grace = 48 * time.Hour
	}
	g.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, $2, 'lab', int4range(30000, 40000), '10.250.0.0/16')`, g.host, "host-"+randomHex(6))
	g.exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', $2, 'mg-console', 'keycloak', 'active')`, g.pidp, "https://idp.invalid/realms/platform-"+randomHex(4))
	g.exec(t, `UPDATE system_settings SET value = '1000' WHERE key = 'quota.max_tenants'`)
	g.api = env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 6)
	g.wrk = env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 10)
	kdir := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	for name, v := range map[string]string{"kek-1": hex.EncodeToString(k) + "\n", secrets.ActiveFile: "kek-1\n"} {
		if err := os.WriteFile(filepath.Join(kdir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kr, err := secrets.LoadKeyring(secrets.KEKApp, kdir)
	if err != nil {
		t.Fatal(err)
	}
	if g.sec, err = secrets.New(g.wrk, secrets.Options{App: kr}); err != nil {
		t.Fatal(err)
	}
	g.reg = &gatedReg{st: g.wrk, statuses: ReachableStatuses, hs: map[uuid.UUID]*fakeHS{}}
	if g.core, err = policies.New(g.wrk, policies.Config{Registry: g.reg, LockWait: 30 * time.Second}); err != nil {
		t.Fatal(err)
	}
	g.agent = newFakeAgent()
	g.backups = &fakeBackups{agent: g.agent, exec: func(sql string, args ...any) error {
		g.mu.Lock()
		defer g.mu.Unlock()
		_, err := g.su.Exec(context.Background(), sql, args...)
		return err
	}}
	g.kc = &fakeKeycloak{realms: map[string]string{}}
	g.req = NewRequester(g.api)
	reg, err := approvals.NewRegistry(approvals.Typed(approvals.Spec{Name: Action, Scope: authz.ScopePlatform, ResourceType: "tenant",
		Permission: Permission}, func(ctx context.Context, tx *store.Tx, e approvals.Execution, p Payload) (*uuid.UUID, error) {
		if e.Request.ResourceID != p.TenantID.String() {
			return nil, &RequestError{Kind: ErrInvalid, Reason: ReasonPayloadMismatch}
		}
		return g.req.EnqueueApproved(ctx, tx, e.Request.RequestedBy.IdentityID, e.Request.ID, p)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if g.appr, err = approvals.New(g.api, approvals.Config{Approvers: authz.New(g.api), Registry: reg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	for i := range g.staff {
		g.staff[i] = g.superAdmin(t)
	}
	cfg := Config{Store: g.wrk, Backups: g.backups, Secrets: g.sec, IdP: drivers{idp.DriverKeycloak: g.kc}, Policies: g.core,
		Headscale: g.reg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), KeyGrace: g.grace,
		RetryBase: 10 * time.Millisecond, RetryMax: 40 * time.Millisecond, StepRetries: 2}
	if !o.noAgent {
		cfg.Agent = g.agent
	}
	if o.unreachable {
		cfg.Headscale = unreachable{}
	}
	if g.h, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	if !o.noWorker {
		g.startWorker(t)
	}
	return g
}

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

func (g *rig) superAdmin(t *testing.T) approvals.Actor {
	t.Helper()
	id := uuid.New()
	g.exec(t, `INSERT INTO identities (id, idp_id, scope, subject, display_name) VALUES ($1, $2, 'platform', $3, 'SA')`,
		id, g.pidp, "sa-"+id.String())
	g.exec(t, `INSERT INTO platform_users (identity_id, role_id) SELECT $1, id FROM roles WHERE scope = 'platform' AND key = 'super_admin'`, id)
	return approvals.Actor{IdentityID: id, Scope: authz.ScopePlatform, AuthTime: time.Now()}
}

// newTenant creates an active tenant with its live instance and everything a deprovision must remove.
func (g *rig) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	shared.mu.Lock()
	shared.n++
	i := shared.n
	shared.mu.Unlock()
	g.n++
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), idp: uuid.New(), slug: "d" + randomHex(5) + fmt.Sprintf("%03d", i%1000)}
	g.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	g.exec(t, `INSERT INTO subscriptions (tenant_id, plan_id) SELECT $1, id FROM subscription_plans WHERE key = 'standard'`, ten.id)
	g.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		ten.instance, ten.id, g.host, ten.slug+".mesh.test", ten.slug+".ts.test", "hs-"+ten.slug+":8080", 30000+i,
		fmt.Sprintf("10.250.%d.%d/29", (i/32)%250, (i%32)*8), "/opt/meshguard/tenants/"+ten.instance.String())
	ctx := t.Context()
	// the tenant's secrets in the real SecretStore (its DEK on the first one)
	put := func(name string, v string) secrets.Ref {
		ref := secrets.TenantRef(ten.id, name, 1)
		if err := g.sec.Put(ctx, ref, []byte(v)); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	ten.apiKey = put(provisioning.APIKeySecretName, "hskey-api-abcdefghijkl-"+randomHex(16))
	ten.backupKey = put(backupfmt.BackupKeySecretName, randomHex(16))
	ten.idpC = put(idp.ClientSecretName(ten.idp), randomHex(12))
	g.exec(t, `UPDATE tenant_instances SET api_key_secret_ref = $2, api_key_prefix = 'abcdefghijkl' WHERE id = $1`,
		ten.instance, ten.apiKey.String())
	g.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, driver_ref, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', $4, 'keycloak', $5, 'active')`, ten.idp, ten.id,
		"https://idp.invalid/realms/"+ten.slug, ten.idpC.String(), ten.slug)
	member := func(name, role string) uuid.UUID {
		ident := uuid.New()
		g.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, ident, ten.idp, ten.id, name+"-"+ten.slug, name+"@"+ten.slug+".test", name)
		g.exec(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
			SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3`, ten.id, ident, role)
		// two live Portal sessions of the identity
		for range 2 {
			g.exec(t, `INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at)
				VALUES (sha256(convert_to(gen_random_uuid()::text, 'UTF8')), $1, $2, 'app', now(), now() + interval '1 hour',
					now() + interval '8 hours')`, ident, ten.idp)
			ten.sessions++
		}
		return ident
	}
	ten.owner = member("owner", "tenant_owner")
	ten.admin = member("admin", "tenant_admin")
	ten.invitation = uuid.New()
	g.exec(t, `INSERT INTO tenant_invitations (id, tenant_id, idp_id, email, role_id, token_hash, expires_at)
		SELECT $1, $2, $3, 'new@'||$4||'.test', id, sha256(convert_to(gen_random_uuid()::text, 'UTF8')), now() + interval '1 day'
		FROM roles WHERE scope = 'tenant' AND key = 'tenant_viewer'`, ten.invitation, ten.id, ten.idp, ten.slug)
	// an open platform request on the instance (a restore asked before the deletion) — never approvable after it
	ten.approval = uuid.New()
	g.exec(t, `INSERT INTO approval_requests (id, scope, action, resource_type, resource_id, payload, payload_sha256,
			requested_by_identity_id, expires_at)
		VALUES ($1, 'platform', 'platform.instance.restore', 'instance', $2::text, '{}', repeat('a', 64), $3, now() + interval '1 day')`,
		ten.approval, ten.instance, g.staff[0].IdentityID)
	region := uuid.New()
	g.exec(t, `INSERT INTO relay_regions (id, code, name, kind, derp_region_id, hostname, verify_mode, tenant_id, host_id)
		VALUES ($1, 'mg-'||$2, 'Relay '||$2, 'embedded', 901, $2||'.mesh.test', 'in_process', $3, $4)`, region, ten.slug, ten.id, g.host)
	g.exec(t, `INSERT INTO relay_assignments (tenant_id, instance_id, relay_region_id) VALUES ($1, $2, $3)`, ten.id, ten.instance, region)
	// Headscale: a user node, a tagged node without expiry, a node expired already; valid and spent pre-auth keys
	now := time.Now()
	future, past := now.Add(90*24*time.Hour), now.Add(-time.Hour)
	ten.hs = &fakeHS{nodes: []headscale.Node{{ID: 1, Name: "n1", Expiry: &future}, {ID: 2, Name: "n2", Tags: []string{"tag:server"}},
		{ID: 3, Name: "n3", Expiry: &past}},
		keys: []headscale.PreAuthKey{{ID: 1, KeyPrefix: "aaaaaaaaaaaa", Reusable: true, Expiration: now.Add(time.Hour)},
			{ID: 2, KeyPrefix: "bbbbbbbbbbbb", Expiration: now.Add(10 * time.Minute)},
			{ID: 3, KeyPrefix: "cccccccccccc", Used: true, Expiration: now.Add(time.Hour)}}}
	g.reg.mu.Lock()
	g.reg.hs[ten.id] = ten.hs
	g.reg.mu.Unlock()
	g.agent.mu.Lock()
	*g.agent.host(ten.instance.String()) = hostModel{edge: true, container: true, network: true, dir: true}
	g.agent.mu.Unlock()
	res, err := g.core.Apply(ctx, policies.ApplyRequest{TenantID: ten.id, HuJSON: allowFixture(t), Trigger: policies.TriggerManual,
		Actor: "fixture"})
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
func (g *rig) reqCtx(t *testing.T, actor uuid.UUID, action string) context.Context {
	return audit.WithRequest(t.Context(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &actor, ActorDisplay: "operator", RequestID: "req-" + uuid.NewString()[:8]})
}

// request is DELETE /platform/tenants/{id} by staff[0] then the approval by staff[1]: it returns the job.
func (g *rig) request(t *testing.T, ten *tenantFx, skip bool) uuid.UUID {
	t.Helper()
	a, b := g.staff[0], g.staff[1]
	a.AuthTime, b.AuthTime = time.Now(), time.Now()
	p, err := g.req.Check(g.reqCtx(t, a.IdentityID, Action+".request"), ten.id, ten.slug, skip)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	r, err := g.appr.Request(g.reqCtx(t, a.IdentityID, Action+".request"), a, approvals.NewRequest{Action: Action,
		ResourceID: ten.id.String(), Payload: p, Reason: "customer left (test)"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	done, err := g.appr.Approve(g.reqCtx(t, b.IdentityID, "platform.approval.approve"), b,
		approvals.Ref{Scope: authz.ScopePlatform, ID: r.ID}, r.PayloadSHA256)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if done.Status != approvals.StatusExecuted || done.JobID == nil {
		t.Fatalf("approval %+v", done)
	}
	return *done.JobID
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
	t.Fatalf("job %s is %s after 60 s, want one of %v (steps %s, error %s)", job, st, want, g.steps(t, job),
		g.str(t, `SELECT coalesce(error::text, '') FROM provisioning_jobs WHERE id = $1`, job))
	return st
}

// steps returns "name:status" of the job's steps in order.
func (g *rig) steps(t *testing.T, job uuid.UUID) string {
	t.Helper()
	return g.str(t, `SELECT coalesce(string_agg(name || ':' || status || coalesce(':' || error_code, ''), ' ' ORDER BY seq), '')
		FROM provisioning_job_steps WHERE job_id = $1`, job)
}

func (g *rig) attempts(t *testing.T, job uuid.UUID) string {
	t.Helper()
	return g.str(t, `SELECT coalesce(string_agg(name || ':' || attempt, ' ' ORDER BY seq), '') FROM provisioning_job_steps
		WHERE job_id = $1`, job)
}

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
