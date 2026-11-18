package backup_test

// Database tests of backup/restore v1 on the worker side (P3-T11): a real PostgreSQL migrated like a deployment
// (storetest, worker roles), the real SecretStore, the job framework (River), the production locator and registry in
// front of the fake edge admin listener of headscaletest — and a fake Host Agent that signs manifests with a test key
// and checks the data key it is handed against the recipient it encrypted to. The agent side with real sqlite3/age and
// a real Headscale: apps/agent/integration_backup_test.go (agent-it).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

const appliedPolicy = "{\n  \"grants\": [],\n  \"ssh\": []\n}"

// fakeAgent plays the Host Agent: Backup signs a manifest of the requested identity (archive digest derived from the
// data recipient), Restore refuses a data key that is not the archive's, PostRestoreReconcile creates a new key on the
// fake Headscale and expires every other one.
type fakeAgent struct {
	mu         sync.Mutex
	t          *testing.T
	signer     ed25519.PrivateKey
	f          *fix
	recipients map[uint64][]byte
	backups    []*agentv1.BackupRequest
	restores   []*agentv1.RestoreRequest
	plans      []*agentv1.ReconcilePlan
	attached   int
	detached   int
	backupErr  error
	served     string // the policy the restored instance serves (keep branch)
}

func (a *fakeAgent) Backup(_ context.Context, in *agentv1.BackupRequest, _ ...grpc.CallOption) (*agentv1.BackupResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.backups = append(a.backups, in)
	if a.backupErr != nil {
		return nil, a.backupErr
	}
	a.recipients[in.GetSequence()] = in.GetDataRecipient()
	sum := sha256.Sum256(append([]byte(fmt.Sprint(in.GetSequence())), in.GetDataRecipient()...))
	files := make([]backupfmt.File, 0, len(backupfmt.ArchivePaths))
	for _, p := range backupfmt.ArchivePaths {
		files = append(files, backupfmt.File{Path: p, Size: 10, SHA256: strings.Repeat("a", 64)})
	}
	rcp, _ := backupfmt.RecipientString(in.GetDataRecipient())
	m := &backupfmt.Manifest{Format: backupfmt.Format, TenantID: in.GetInstance().GetTenantId(), InstanceID: in.GetInstance().GetInstanceId(),
		Slug: in.GetInstance().GetSlug(), Sequence: in.GetSequence(), JobID: in.GetJobId(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Method: backupfmt.MethodVacuumInto, Image: "ghcr.io/x/headscale@sha256:" + strings.Repeat("b", 64), HeadscaleVersion: "0.29.7",
		TemplateVersion: "1", ConfigSHA256: strings.Repeat("c", 64), NoiseFingerprint: strings.Repeat("d", 64), SQLiteVersion: "3.54.1",
		Files: files, Archive: backupfmt.Archive{SHA256: hex.EncodeToString(sum[:]), Size: 4096, Encryption: backupfmt.EncryptionAgeV1,
			Recipients: []string{"data-key:" + rcp, "recovery:x"}}, SigningKey: backupfmt.KeyID(a.signer.Public().(ed25519.PublicKey))}
	raw, err := m.Encode()
	if err != nil {
		return nil, err
	}
	ms := sha256.Sum256(raw)
	return &agentv1.BackupResponse{Artifact: &agentv1.BackupArtifact{Sequence: in.GetSequence(), ArchiveSha256: m.Archive.SHA256,
		ManifestSha256: hex.EncodeToString(ms[:]), SizeBytes: 4096, Method: agentv1.BackupMethod_BACKUP_METHOD_VACUUM_INTO,
		CreatedAt: timestamppb.Now(), HeadscaleVersion: "0.29.7", Manifest: raw, ManifestSignature: backupfmt.Sign(a.signer, raw),
		NoiseKeyFingerprint: m.NoiseFingerprint}}, nil
}

func refusal(code codes.Code, reason agentv1.RefusalReason, msg string) error {
	st, _ := status.New(code, msg).WithDetails(&agentv1.Refusal{Reason: reason, Field: "instance", Message: msg})
	return st.Err()
}

func (a *fakeAgent) Restore(_ context.Context, in *agentv1.RestoreRequest, _ ...grpc.CallOption) (*agentv1.RestoreResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.restores = append(a.restores, in)
	pub, err := backupfmt.DataRecipient(in.GetDataKey())
	if err != nil || !bytes.Equal(pub, a.recipients[in.GetArtifact().GetSequence()]) {
		return nil, refusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY, "the archive does not decrypt with this data key")
	}
	if p := in.GetAppliedPolicyHujson(); p != nil {
		a.f.setPolicy(string(p))
		s := sha256.Sum256(p)
		return &agentv1.RestoreResponse{PolicySha256: hex.EncodeToString(s[:]), PreviousDataKeptAs: "data.prev-x"}, nil
	}
	a.f.setPolicy(a.served)
	s := sha256.Sum256([]byte(a.served))
	return &agentv1.RestoreResponse{PolicySha256: hex.EncodeToString(s[:]), PreviousDataKeptAs: "data.prev-x", BackupPolicyHujson: []byte(a.served)}, nil
}

func (a *fakeAgent) PostRestoreReconcile(_ context.Context, in *agentv1.PostRestoreReconcileRequest, _ ...grpc.CallOption) (*agentv1.PostRestoreReconcileResponse, error) {
	a.mu.Lock()
	a.plans = append(a.plans, in.GetPlan())
	a.mu.Unlock()
	full, prefix := a.f.inst.NewKey(in.GetPlan().GetApiKeyTtl().AsDuration())
	expired := uint32(0)
	for _, k := range a.f.inst.Keys() {
		if k.Prefix != prefix && k.Valid(time.Now()) {
			a.f.expireKey(full, k.Prefix)
			expired++
		}
	}
	var exp *timestamppb.Timestamp
	for _, k := range a.f.inst.Keys() {
		if k.Prefix == prefix && k.Expiration != nil {
			exp = timestamppb.New(*k.Expiration)
		}
	}
	return &agentv1.PostRestoreReconcileResponse{ApiKey: full, ApiKeyPrefix: prefix, ApiKeyExpiresAt: exp, ApiKeysExpired: expired,
		PreauthKeysExpired: 1, NodesExpired: uint32(len(in.GetPlan().GetRevokedMachineKeys()))}, nil //nolint:gosec // test
}

func (a *fakeAgent) EnsureEdgeAttachment(context.Context, *agentv1.EnsureEdgeAttachmentRequest, ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attached++
	return &agentv1.EnsureEdgeAttachmentResponse{Attached: true, NetworkMembers: 2}, nil
}

func (a *fakeAgent) RemoveEdgeAttachment(context.Context, *agentv1.RemoveEdgeAttachmentRequest, ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.detached++
	return &agentv1.RemoveEdgeAttachmentResponse{Detached: true}, nil
}

type fix struct {
	t        *testing.T
	pg       *storetest.Env
	db       string
	su       *pgx.Conn
	mu       sync.Mutex
	st       *store.Store
	ss       *secrets.Store
	edge     *headscaletest.Edge
	inst     *headscaletest.Instance
	token    string
	shared   *headscale.CachingRegistry
	agent    *fakeAgent
	svc      *backup.Service
	keys     []ed25519.PublicKey
	tenant   uuid.UUID
	instance uuid.UUID
	host     uuid.UUID
	version  uuid.UUID
	// the fake Headscale's API state (served through the edge hook)
	policy       string
	nodes        []map[string]any
	users        []map[string]any
	validPreAuth bool
}

func (f *fix) setPolicy(p string) { f.mu.Lock(); f.policy = p; f.mu.Unlock() }

// expireKey expires a key of the fake instance through its API, authenticated with key.
func (f *fix) expireKey(key, prefix string) {
	body, _ := json.Marshal(map[string]string{"prefix": prefix})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, f.edge.URL()+"/api/v1/apikey/expire", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-MG-Token", f.token)
	req.Header.Set("X-MG-Instance", "tenant-a")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func newFix(t *testing.T) *fix {
	t.Helper()
	pg := storetest.Require(t)
	f := &fix{t: t, pg: pg, db: pg.NewDatabase(t), tenant: uuid.New(), instance: uuid.New(), host: uuid.New(), version: uuid.New(),
		token: headscaletest.NewToken(), policy: appliedPolicy}
	f.su = pg.Admin(t, f.db)
	f.st = pg.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 8)
	dir := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	write(t, filepath.Join(dir, "kek-1"), hex.EncodeToString(k)+"\n")
	write(t, filepath.Join(dir, secrets.ActiveFile), "kek-1\n")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	log := logx.New(io.Discard, slog.LevelDebug, "backup-db")
	if f.ss, err = secrets.New(f.st, secrets.Options{App: kr, Logger: log}); err != nil {
		t.Fatal(err)
	}
	ten := tenants.New(f.st, tenants.Options{BaseDomain: "mg.test"})
	f.edge = headscaletest.NewEdge(t, f.token)
	f.inst = f.edge.AddInstance("tenant-a")
	f.edge.SetHook(f.hook)
	tokFile := filepath.Join(t.TempDir(), "edge_admin_token")
	write(t, tokFile, f.token+"\n")
	loc, err := locator.New(ten, f.ss, locator.Options{AdminURL: f.edge.URL(), EdgeTokenFile: tokFile, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	f.shared = headscale.NewRegistry(loc, headscale.Options{Logger: log})
	f.exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-a', 'Tenant A', 'active')`, f.tenant)
	f.exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
			server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', 'v0.29.7', 'sha256:'||repeat('a', 64), 'tenant-a.mesh.mg.test', 'https://tenant-a.mesh.mg.test',
			'tenant-a.tail.mg.test', 'hs-tenant-a:8080', 30001, '10.250.0.8/29', '/opt/meshguard/tenants/x')`, f.instance, f.tenant, f.host)
	k0, p0 := f.inst.NewKey(90 * 24 * time.Hour)
	ref := secrets.TenantRef(f.tenant, provisioning.APIKeySecretName, 1)
	if err := f.ss.Put(context.Background(), ref, []byte(k0)); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE tenant_instances SET api_key_secret_ref = $1, api_key_prefix = $2 WHERE id = $3`, ref.String(), p0, f.instance)
	sum := sha256.Sum256([]byte(appliedPolicy))
	f.exec(`INSERT INTO policy_versions (id, tenant_id, version, kind, source_hujson, content_sha256, state, approved_at,
			approved_content_sha256) VALUES ($1, $2, 1, 'baseline', $3, $4, 'approved', now(), $4)`, f.version, f.tenant, appliedPolicy,
		hex.EncodeToString(sum[:]))
	f.exec(`UPDATE tenants SET desired_policy_version_id = $1 WHERE id = $2`, f.version, f.tenant)
	f.exec(`INSERT INTO policy_applications (tenant_id, instance_id, policy_version_id, trigger, applied_hujson, applied_sha256,
			state, finished_at) VALUES ($1, $2, $3, 'bootstrap', $4, $5, 'applied', now())`, f.tenant, f.instance, f.version,
		appliedPolicy, hex.EncodeToString(sum[:]))
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	f.keys = []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}
	f.agent = &fakeAgent{t: t, signer: signer, f: f, recipients: map[uint64][]byte{}}
	f.svc = backup.New(f.st, backup.Config{Agent: f.agent, Secrets: f.ss, Registry: f.shared, ManifestKeys: f.keys,
		Interval: time.Hour, Retention: 7 * 24 * time.Hour, KeepLatest: 1, Logger: log})
	return f
}

// hook serves the parts of the Headscale API the fake edge does not: the policy, nodes, users, pre-auth keys.
func (f *fix) hook(r headscaletest.Request, _ int) (int, string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodGet {
		return 0, "", false
	}
	var v any
	switch r.Path {
	case "/api/v1/policy":
		v = map[string]any{"policy": f.policy, "updatedAt": time.Now().UTC()}
	case "/api/v1/node":
		v = map[string]any{"nodes": f.nodes}
	case "/api/v1/user":
		v = map[string]any{"users": f.users}
	case "/api/v1/preauthkey":
		keys := []map[string]any{{"id": "1", "key": "hskey-auth-xxxxxxxxxxxx-***", "expiration": time.Now().Add(-time.Hour).UTC()}}
		if f.validPreAuth {
			keys = append(keys, map[string]any{"id": "2", "key": "hskey-auth-yyyyyyyyyyyy-***", "expiration": time.Now().Add(time.Hour).UTC()})
		}
		v = map[string]any{"preAuthKeys": keys}
	default:
		return 0, "", false
	}
	b, _ := json.Marshal(v)
	return http.StatusOK, string(b), true
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fix) exec(sql string, args ...any) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.su.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (f *fix) count(sql string, args ...any) int {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return n
}

func (f *fix) str(sql string, args ...any) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var s string
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		f.t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return s
}

// worker starts the job framework with the service's handlers.
func (f *fix) worker() {
	f.t.Helper()
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax, cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 100*time.Millisecond, time.Second, 0, 2*time.Second, 4
	w, err := jobs.NewWorker(f.st, cfg, jobs.Options{Registerer: prometheus.NewRegistry(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.svc.Register(w); err != nil {
		f.t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(c)
	})
}

// wait waits for the only job of kind to end and returns its status, error code and output.
func (f *fix) wait(kind string) (status, code, output string) {
	f.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for f.count(`SELECT count(*) FROM provisioning_jobs WHERE kind = $1 AND status IN ('succeeded', 'failed', 'failed_resumable')`, kind) == 0 {
		if time.Now().After(deadline) {
			f.t.Fatalf("%s did not finish", kind)
		}
		time.Sleep(100 * time.Millisecond)
	}
	s := f.str(`SELECT status || '|' || coalesce(error->>'code', '') || '|' || coalesce(output::text, '') FROM provisioning_jobs
		WHERE kind = $1 ORDER BY created_at DESC LIMIT 1`, kind)
	parts := strings.SplitN(s, "|", 3)
	return parts[0], parts[1], parts[2]
}

// backupNow runs one scheduled backup through the framework and returns the backup row's id.
func (f *fix) backupNow() uuid.UUID {
	f.t.Helper()
	sc := f.svc.NewScheduler(time.Minute)
	if n, err := sc.Tick(context.Background(), time.Now()); err != nil || n != 1 {
		f.t.Fatalf("schedule: %d %v", n, err)
	}
	if st, code, out := f.wait(backup.KindBackup); st != "succeeded" {
		f.t.Fatalf("instance.backup: %s %s %s", st, code, out)
	}
	return uuid.MustParse(f.str(`SELECT id::text FROM backups WHERE status = 'succeeded' ORDER BY started_at DESC LIMIT 1`))
}

// TestBackupJob — §17.1 worker side: a scheduled backup writes a `backups` row with the sequence, the wrapped data
// key (the agent gets only its public recipient), the verified signed manifest and the tenant's backup key reference;
// the same period gets no second job; the next backup asks the agent to drop the archives past retention and their
// rows become purged.
func TestBackupJob(t *testing.T) {
	f := newFix(t)
	f.worker()
	id := f.backupNow()
	if n := f.count(`SELECT count(*) FROM backups WHERE id = $1 AND kind = 'instance' AND status = 'succeeded' AND sequence > 0
		AND octet_length(wrapped_data_key) = 60 AND manifest IS NOT NULL AND octet_length(manifest_signature) = 64
		AND manifest_sha256 ~ '^[0-9a-f]{64}$' AND method = 'vacuum_into' AND key_ref = $2 AND sha256 ~ '^[0-9a-f]{64}$'
		AND expires_at > now() + interval '6 days' AND storage_uri LIKE 'agent://%'`, id,
		secrets.TenantRef(f.tenant, backupfmt.BackupKeySecretName, 1).String()); n != 1 {
		t.Fatalf("backup row: %d", n)
	}
	if len(f.agent.backups) != 1 || len(f.agent.backups[0].GetDataRecipient()) != 32 {
		t.Fatalf("agent requests: %v", f.agent.backups)
	}
	// the wrapped data key opens with the tenant's backup key — and only for this tenant/instance/sequence (T-15)
	var wrapped []byte
	var seq int64
	if err := f.su.QueryRow(context.Background(), `SELECT wrapped_data_key, sequence FROM backups WHERE id = $1`, id).Scan(&wrapped, &seq); err != nil {
		t.Fatal(err)
	}
	bk, err := f.ss.Get(context.Background(), secrets.TenantRef(f.tenant, backupfmt.BackupKeySecretName, 1))
	if err != nil {
		t.Fatal(err)
	}
	dk, err := backupfmt.UnwrapDataKey(bk.Bytes(), wrapped, f.tenant, f.instance, uint64(seq)) //nolint:gosec // G115: a sequence > 0
	if err != nil {
		t.Fatal(err)
	}
	if pub, _ := backupfmt.DataRecipient(dk); !bytes.Equal(pub, f.agent.backups[0].GetDataRecipient()) {
		t.Fatal("the data recipient sent to the agent is not the wrapped data key's")
	}
	if _, err := backupfmt.UnwrapDataKey(bk.Bytes(), wrapped, uuid.New(), f.instance, uint64(seq)); err == nil { //nolint:gosec // G115: a sequence > 0
		t.Fatal("the wrapped key opens for another tenant")
	}
	// same period: nothing new
	if n, _ := f.svc.NewScheduler(time.Minute).Tick(context.Background(), time.Now()); n != 0 {
		t.Fatalf("same period: %d jobs", n)
	}
	// retention: the first backup expired; the next one (another period) removes it (KeepLatest 1)
	f.exec(`UPDATE backups SET expires_at = now() - interval '1 hour', started_at = now() - interval '3 hours' WHERE id = $1`, id)
	f.exec(`DELETE FROM provisioning_jobs WHERE kind = 'instance.backup'`)
	f.backupNow()
	if got := f.agent.backups[1].GetRetainFromSequence(); got == 0 || got <= uint64(seq) { //nolint:gosec // G115: a sequence > 0
		t.Fatalf("retain_from_sequence %d (first sequence %d)", got, seq)
	}
	if n := f.count(`SELECT count(*) FROM backups WHERE id = $1 AND status = 'purged'`, id); n != 1 {
		t.Fatal("the expired backup's row is not purged")
	}
	if n := f.count(`SELECT count(*) FROM secrets WHERE tenant_id = $1 AND name = 'backup-key'`, f.tenant); n != 1 {
		t.Fatalf("backup key versions: %d", n)
	}
}

// TestBackupRefusalsAreSecurityEvents — IT-15 / T-15 on the worker: a hostile data directory (UNSAFE_PATH) fails the
// job and the row with a tenant security event; a manifest signed by another key is never recorded (critical event).
func TestBackupRefusalsAreSecurityEvents(t *testing.T) {
	f := newFix(t)
	f.worker()
	f.agent.backupErr = refusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH,
		"backup refused (fail closed): symlink in data/ (never followed or read) db.sqlite-wal")
	if _, err := f.svc.NewScheduler(time.Minute).Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if st, code, _ := f.wait(backup.KindBackup); st != "failed" || code != "agent_unsafe_path" {
		t.Fatalf("job: %s %s", st, code)
	}
	if n := f.count(`SELECT count(*) FROM backups WHERE status = 'failed' AND finished_at IS NOT NULL`); n != 1 {
		t.Fatalf("failed rows: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = 'backup.unsafe_data' AND severity = 'high'
		AND details->>'refusal' = 'unsafe_path'`, f.tenant); n != 1 {
		t.Fatalf("security events: %d", n)
	}
	// a manifest signed by another key
	f.agent.backupErr = nil
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f.agent.signer = other
	f.exec(`DELETE FROM provisioning_jobs WHERE kind = 'instance.backup'`)
	f.exec(`UPDATE backups SET started_at = now() - interval '3 hours'`)
	if _, err := f.svc.NewScheduler(time.Minute).Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if st, code, _ := f.wait(backup.KindBackup); st != "failed" || code != "manifest_invalid" {
		t.Fatalf("job: %s %s", st, code)
	}
	if n := f.count(`SELECT count(*) FROM backups WHERE status = 'succeeded'`); n != 0 {
		t.Fatal("a backup with an untrusted manifest was recorded")
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE kind = 'backup.manifest_invalid' AND severity = 'critical'`); n != 1 {
		t.Fatalf("manifest events: %d", n)
	}
}

// member inserts a tenant membership (IdP, identity) with a status and a recorded headscale_user_id.
func (f *fix) member(status string, hsUserID *int64) uuid.UUID {
	f.t.Helper()
	idp, ident, role, m := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sfx := idp.String()[:8]
	f.exec(`INSERT INTO roles (id, scope, key, name) VALUES ($1, 'tenant', 'member_'||$2, 'Member')`, role, sfx)
	f.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, 'https://idp.test/realms/'||$3, 'portal', 'keycloak', $4)`, idp, f.tenant, sfx, "disabled")
	f.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email) VALUES ($1, $2, $3, 'tenant', 'u-'||$4, $4||'@x.test')`,
		ident, idp, f.tenant, sfx)
	f.exec(`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status, headscale_user_id) VALUES ($1, $2, $3, $4, $5, $6)`,
		m, f.tenant, ident, role, status, hsUserID)
	return m
}

// owner adds an active Tenant Owner (the audience of the restore's notification); it has no Headscale user.
func (f *fix) owner() {
	f.t.Helper()
	m := f.member("active", nil)
	f.exec(`INSERT INTO roles (scope, key, name) VALUES ('tenant', 'tenant_owner', 'Tenant Owner') ON CONFLICT DO NOTHING`)
	f.exec(`UPDATE tenant_memberships SET role_id = (SELECT id FROM roles WHERE scope = 'tenant' AND key = 'tenant_owner')
		WHERE id = $1`, m)
}

func mkey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "mkey:" + hex.EncodeToString(b)
}

// enqueueRestore is the execution of an approved platform.instance.restore (the action of apps/internal/runner).
func (f *fix) enqueueRestore(p backup.RestorePayload) (*uuid.UUID, error) {
	var id *uuid.UUID
	err := f.st.WithPlatformJobTx(context.Background(), func(tx *store.Tx) error {
		var err error
		id, err = f.svc.EnqueueRestore(context.Background(), tx, uuid.New(), uuid.New(), p)
		return err
	})
	return id, err
}

// TestRestoreJob — §17.2 through the framework (normal branch, IT-16 at the worker): the worker verifies the manifest
// and unwraps the data key (the agent accepts it: it is the archive's), hands over the applied policy, builds the plan
// by machine key (revoked, deleted after the backup, desired routes/tags, offboarded users), stores the new API key
// (every other key dead), attaches the edge, checks the instance over the API, re-resolves the membership ids by name,
// enqueues inventory.sync, records verified_at, the policy application (trigger restore), the audit pair and the
// notification.
func TestRestoreJob(t *testing.T) {
	f := newFix(t)
	f.worker()
	id := f.backupNow()
	backupAt := time.Now()
	// PostgreSQL after the backup: a live device with a route and a tag, a revoked one, one deleted after the backup,
	// one deleted long before (not replayed), an offboarded member, a member whose stale numeric id must be re-resolved
	live, revoked, gone, old := mkey(), mkey(), mkey(), mkey()
	f.exec(`INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, approved_routes, tags)
		VALUES ($1, $2, 1, $3, 'router', ARRAY['10.9.0.0/24'::cidr], ARRAY['tag:router'])`, f.tenant, f.instance, live)
	f.exec(`INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, revocation_state,
			revocation_kind, revocation_requested_at) VALUES ($1, $2, 2, $3, 'stolen', 'applied', 'expire', now())`, f.tenant, f.instance, revoked)
	f.exec(`INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, removed_at)
		VALUES ($1, $2, 3, $3, 'deleted', now() + interval '1 second')`, f.tenant, f.instance, gone)
	f.exec(`INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, removed_at)
		VALUES ($1, $2, 4, $3, 'ancient', $4)`, f.tenant, f.instance, old, backupAt.Add(-48*time.Hour))
	stale := int64(77)
	off := f.member("offboarded", nil)
	keep := f.member("active", &stale)
	f.owner()
	f.mu.Lock()
	f.users = []map[string]any{{"id": "12", "name": "mg-" + keep.String()}, {"id": "77", "name": "someone-else"}}
	f.nodes = []map[string]any{{"id": "1", "machineKey": live, "name": "router"}}
	f.mu.Unlock()
	jobID, err := f.enqueueRestore(backup.RestorePayload{BackupID: id, InstanceID: f.instance})
	if err != nil || jobID == nil {
		t.Fatalf("enqueue: %v", err)
	}
	st, code, out := f.wait(backup.KindRestore)
	if st != "succeeded" {
		t.Fatalf("instance.restore: %s %s %s", st, code, out)
	}
	// the agent: the applied policy, the archive's data key, the plan by machine key
	if len(f.agent.restores) != 1 || string(f.agent.restores[0].GetAppliedPolicyHujson()) != appliedPolicy {
		t.Fatalf("restore requests: %d", len(f.agent.restores))
	}
	p := f.agent.plans[0]
	if !slices.Equal(p.GetRevokedMachineKeys(), []string{revoked}) || !slices.Equal(p.GetDeletedMachineKeys(), []string{gone}) ||
		len(p.GetNodes()) != 2 || !slices.Equal(p.GetOffboardedUsers(), []string{"mg-" + off.String()}) || p.GetRestorePointOlderThanBackup() {
		t.Fatalf("plan: revoked %v deleted %v nodes %d offboarded %v", p.GetRevokedMachineKeys(), p.GetDeletedMachineKeys(), len(p.GetNodes()), p.GetOffboardedUsers())
	}
	for _, n := range p.GetNodes() {
		if n.GetMachineKey() == live && (!slices.Equal(n.GetApprovedRoutes(), []string{"10.9.0.0/24"}) || !slices.Equal(n.GetTags(), []string{"tag:router"})) {
			t.Fatalf("desired state of the live device: %v %v", n.GetApprovedRoutes(), n.GetTags())
		}
	}
	// the new API key: version 2, the only valid key at the instance, the older version destroyed
	if got := f.inst.ValidPrefixes(); len(got) != 1 || f.str(`SELECT api_key_prefix FROM tenant_instances WHERE id = $1`, f.instance) != got[0] {
		t.Fatalf("valid keys %v", got)
	}
	if n := f.count(`SELECT count(*) FROM secrets WHERE tenant_id = $1 AND name = 'headscale-api-key' AND
		((version = 1 AND destroyed_at IS NOT NULL) OR (version = 2 AND destroyed_at IS NULL))`, f.tenant); n != 2 {
		t.Fatalf("api key versions: %d", n)
	}
	if f.agent.attached != 1 || f.agent.detached != 0 {
		t.Fatalf("edge: attached %d detached %d", f.agent.attached, f.agent.detached)
	}
	// membership ids re-resolved by name in one transaction (stale 77 is someone else's id in the restored instance)
	if got := f.str(`SELECT coalesce(headscale_user_id::text, 'null') FROM tenant_memberships WHERE id = $1`, keep); got != "12" {
		t.Fatalf("re-resolved id: %s", got)
	}
	if got := f.str(`SELECT coalesce(headscale_user_id::text, 'null') FROM tenant_memberships WHERE id = $1`, off); got != "null" {
		t.Fatalf("offboarded member's id: %s", got)
	}
	if n := f.count(`SELECT count(*) FROM provisioning_jobs WHERE kind = 'inventory.sync' AND instance_id = $1`, f.instance); n != 1 {
		t.Fatal("no inventory.sync after the restore")
	}
	if n := f.count(`SELECT count(*) FROM backups WHERE id = $1 AND verified_at IS NOT NULL`, id); n != 1 {
		t.Fatal("verified_at not set")
	}
	if n := f.count(`SELECT count(*) FROM policy_applications WHERE instance_id = $1 AND trigger = 'restore' AND state = 'applied'
		AND superseded_at IS NULL AND applied_hujson = $2`, f.instance, appliedPolicy); n != 1 {
		t.Fatal("no current application of the restore")
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'instance.restored'
		AND payload->>'owner_review' = 'none'`, f.tenant); n == 0 {
		t.Fatal("no notification of the Owners")
	}
	var rep backup.RestoreReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Sequence == 0 || rep.MembersResolved != 1 || rep.MembersUnset != 2 ||
		rep.Reconcile.APIKeysExpired != 1 || rep.PolicySHA256 == "" {
		t.Fatalf("report: %v %s", err, out)
	}
	if n := f.count(`SELECT count(*) FROM security_events`); n != 0 {
		t.Fatalf("security events: %d", n)
	}
	if strings.Contains(out, "hskey-") || f.count(`SELECT count(*) FROM provisioning_job_steps WHERE detail::text LIKE '%hskey-%'`) != 0 {
		t.Fatal("a key reached the job")
	}
}

// TestRestoreOlderPointBranch — §17.2 step 4 branch: the archive's policy kept and imported as a validated version
// set as desired (never applied by policy.apply before an approval), no revocation list and no route/tag reset in the
// plan, the tenant flagged for Owner review (security event + notification "required").
func TestRestoreOlderPointBranch(t *testing.T) {
	f := newFix(t)
	f.worker()
	id := f.backupNow()
	f.exec(`INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, approved_routes,
			revocation_state, revocation_kind, revocation_requested_at)
		VALUES ($1, $2, 1, $3, 'router', ARRAY['10.9.0.0/24'::cidr], 'applied', 'expire', now())`, f.tenant, f.instance, mkey())
	f.agent.served = "{\n  \"grants\": [{\"src\": [\"*\"], \"dst\": [\"*\"], \"ip\": [\"*\"]}]\n}"
	f.member("offboarded", nil)
	f.owner()
	if _, err := f.enqueueRestore(backup.RestorePayload{BackupID: id, InstanceID: f.instance, RestorePointOlderThanBackup: true}); err != nil {
		t.Fatal(err)
	}
	if st, code, out := f.wait(backup.KindRestore); st != "succeeded" {
		t.Fatalf("instance.restore: %s %s %s", st, code, out)
	}
	if !f.agent.restores[0].GetKeepBackupPolicy() {
		t.Fatal("the older branch must keep the archive's policy")
	}
	p := f.agent.plans[0]
	if !p.GetRestorePointOlderThanBackup() || len(p.GetRevokedMachineKeys())+len(p.GetDeletedMachineKeys())+len(p.GetNodes())+len(p.GetOffboardedUsers()) != 0 {
		t.Fatalf("plan of the older branch: %v", p)
	}
	if n := f.count(`SELECT count(*) FROM policy_versions v JOIN tenants t ON t.desired_policy_version_id = v.id
		WHERE v.tenant_id = $1 AND v.state = 'validated' AND v.kind = 'user' AND v.source_hujson = $2`, f.tenant, f.agent.served); n != 1 {
		t.Fatal("the archive's policy is not imported as the desired validated version")
	}
	if n := f.count(`SELECT count(*) FROM policy_applications WHERE instance_id = $1 AND trigger = 'restore' AND superseded_at IS NULL
		AND applied_hujson = $2`, f.instance, f.agent.served); n != 1 {
		t.Fatal("no application of the served policy")
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = 'restore.owner_review' AND severity = 'high'`, f.tenant); n != 1 {
		t.Fatal("no Owner review event")
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'instance.restored'
		AND payload->>'owner_review' = 'required'`, f.tenant); n == 0 {
		t.Fatal("no Owner review notification")
	}
}

// TestRestoreRefusals — T-15 / AC-19 at the worker, all BEFORE the agent decrypts anything: a backup of another
// instance cannot be named; a changed manifest, a manifest of another key, a data key wrapped for another tenant
// stop the job (no Restore call); a restored instance that still has a valid pre-auth key over the API gets its edge
// detached again with a critical event (IT-16).
func TestRestoreRefusals(t *testing.T) {
	f := newFix(t)
	f.worker()
	id := f.backupNow()
	// another instance's id with this backup
	if _, err := f.enqueueRestore(backup.RestorePayload{BackupID: id, InstanceID: uuid.New()}); err == nil {
		t.Fatal("restore of a backup into another instance enqueued")
	}
	if _, err := f.enqueueRestore(backup.RestorePayload{BackupID: uuid.New(), InstanceID: f.instance}); err == nil {
		t.Fatal("restore of an unknown backup enqueued")
	}
	run := func(name, sql string, args ...any) {
		t.Helper()
		f.exec(`DELETE FROM provisioning_jobs WHERE kind = 'instance.restore'`)
		f.exec(`UPDATE backups SET manifest = $1, manifest_signature = $2, wrapped_data_key = $3 WHERE id = $4`,
			origManifest, origSig, origWrapped, id)
		if sql != "" {
			f.exec(sql, args...)
		}
		restores := len(f.agent.restores)
		if _, err := f.enqueueRestore(backup.RestorePayload{BackupID: id, InstanceID: f.instance}); err != nil {
			t.Fatalf("%s: enqueue %v", name, err)
		}
		st, code, _ := f.wait(backup.KindRestore)
		if st == "succeeded" || len(f.agent.restores) != restores {
			t.Fatalf("%s: job %s %s, restore calls %d → %d", name, st, code, restores, len(f.agent.restores))
		}
		t.Logf("%s: %s (%s), the agent was not asked to decrypt", name, st, code)
	}
	if err := f.su.QueryRow(context.Background(), `SELECT manifest, manifest_signature, wrapped_data_key FROM backups WHERE id = $1`, id).
		Scan(&origManifest, &origSig, &origWrapped); err != nil {
		t.Fatal(err)
	}
	run("changed manifest", `UPDATE backups SET manifest = convert_to(replace(convert_from(manifest, 'UTF8'), $1, $2), 'UTF8') WHERE id = $3`,
		f.tenant.String(), uuid.NewString(), id)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	run("manifest signed by another key", `UPDATE backups SET manifest_signature = $1 WHERE id = $2`, backupfmt.Sign(other, origManifest), id)
	// a data key wrapped by another tenant's backup key (T-15): the tenant's key does not open it
	otherKey := make([]byte, 32)
	_, _ = rand.Read(otherKey)
	dk, _ := backupfmt.NewDataKey()
	var seq int64
	_ = f.su.QueryRow(context.Background(), `SELECT sequence FROM backups WHERE id = $1`, id).Scan(&seq)
	w, _ := backupfmt.WrapDataKey(otherKey, dk, uuid.New(), f.instance, uint64(seq)) //nolint:gosec // G115: a sequence > 0
	run("data key wrapped for another tenant", `UPDATE backups SET wrapped_data_key = $1 WHERE id = $2`, w, id)
	if n := f.count(`SELECT count(*) FROM security_events WHERE kind = 'backup.integrity' AND severity = 'critical'`); n != 3 {
		t.Fatalf("integrity events: %d", n)
	}
	// IT-16 check over the API: a pre-auth key still valid after the reconcile ⇒ edge detached again, critical event
	f.mu.Lock()
	f.validPreAuth = true
	f.mu.Unlock()
	f.exec(`DELETE FROM provisioning_jobs WHERE kind = 'instance.restore'`)
	f.exec(`UPDATE backups SET manifest = $1, manifest_signature = $2, wrapped_data_key = $3 WHERE id = $4`, origManifest, origSig, origWrapped, id)
	if _, err := f.enqueueRestore(backup.RestorePayload{BackupID: id, InstanceID: f.instance}); err != nil {
		t.Fatal(err)
	}
	if st, code, _ := f.wait(backup.KindRestore); st == "succeeded" || code != "restore_check_failed" {
		t.Fatalf("check: %s %s", st, code)
	}
	if f.agent.detached != 1 {
		t.Fatalf("edge detached %d times", f.agent.detached)
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE kind = 'restore.check_failed' AND severity = 'critical'
		AND details->>'problems' LIKE '%preauth_keys%'`); n != 1 {
		t.Fatal("no critical event of the failed check")
	}
}

var origManifest, origSig, origWrapped []byte

// TestBackupAPI — the service behind POST /platform/instances/{id}/backup, GET /platform/backups and the request-time
// check of POST /platform/instances/{id}/restore: one queued API backup per instance (the same job back); an
// Idempotency-Key replays its job, the same key with another body is a reuse; an unknown instance is not found; the
// list is newest first, filtered, paged by cursor; a restore names a succeeded backup of that very instance.
func TestBackupAPI(t *testing.T) {
	f := newFix(t)
	ctx := context.Background()
	actor := uuid.New()
	// the api process's service: its own pools (mg_api_*), no agent (apps/internal/runner/api.go)
	api := backup.New(f.pg.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 4), backup.Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	kindOf := func(err error) backup.ErrorKind {
		t.Helper()
		e, ok := backup.AsError(err)
		if !ok {
			t.Fatalf("not a backup error: %v", err)
		}
		return e.Kind
	}
	// no worker: the job stays queued
	j1, created, err := api.RequestBackup(ctx, actor, f.instance, nil)
	if err != nil || !created {
		t.Fatalf("first request: %v %v", created, err)
	}
	j2, created, err := api.RequestBackup(ctx, uuid.New(), f.instance, nil)
	if err != nil || created || j2.ID != j1.ID {
		t.Fatalf("second request while the first is queued: %v %v %v", j2.ID, created, err)
	}
	h1, h2 := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	k1, _, err := api.RequestBackup(ctx, actor, f.instance, &backup.Idempotency{Key: "key-1", Hash: h1[:]})
	if err != nil || k1.ID != j1.ID {
		t.Fatalf("with a key: %v %v", k1.ID, err)
	}
	if k2, _, err := api.RequestBackup(ctx, actor, f.instance, &backup.Idempotency{Key: "key-1", Hash: h1[:]}); err != nil || k2.ID != j1.ID {
		t.Fatalf("replay: %v %v", k2.ID, err)
	}
	if _, _, err := api.RequestBackup(ctx, actor, f.instance, &backup.Idempotency{Key: "key-1", Hash: h2[:]}); kindOf(err) != backup.ErrIdempotencyKeyReuse {
		t.Fatalf("same key, another body: %v", err)
	}
	if _, _, err := api.RequestBackup(ctx, actor, uuid.New(), nil); kindOf(err) != backup.ErrNotFound {
		t.Fatalf("unknown instance: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.backup' AND instance_id = $1`, f.instance); n != 1 {
		t.Fatalf("instance.backup jobs: %d", n)
	}
	// the list: three rows of the instance, one failed, newest first
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for i, id := range ids {
		status, extra := "'succeeded'", "4096, repeat('c', 64), now(), convert_to('{}', 'UTF8'), decode(repeat('cd', 64), 'hex'), repeat('e', 64), 'vacuum_into'"
		if i == 1 {
			status, extra = "'failed'", "NULL, NULL, now(), NULL, NULL, NULL, NULL"
		}
		f.exec(`INSERT INTO backups (id, tenant_id, instance_id, kind, status, storage_uri, key_ref, headscale_version, started_at,
				sequence, wrapped_data_key, size_bytes, sha256, finished_at, manifest, manifest_signature, manifest_sha256, method)
			VALUES ($1, $2, $3, 'instance', `+status+`, 'agent://x', $4, '0.29.7', now() - make_interval(hours => $5),
				$6, decode(repeat('ab', 60), 'hex'), `+extra+`)`,
			id, f.tenant, f.instance, secrets.TenantRef(f.tenant, backupfmt.BackupKeySecretName, 1).String(), 3-i, 100+i)
	}
	p, err := api.List(ctx, backup.Filter{InstanceID: &f.instance, Limit: 2})
	if err != nil || len(p.Items) != 2 || p.Items[0].ID != ids[2] || p.Items[1].ID != ids[1] || p.NextCursor == "" {
		t.Fatalf("first page: %v %+v", err, p)
	}
	if p.Items[0].ManifestSHA256 == nil || p.Items[0].Sequence == nil || *p.Items[0].Sequence != 102 {
		t.Fatalf("view: %+v", p.Items[0])
	}
	p2, err := api.List(ctx, backup.Filter{InstanceID: &f.instance, Limit: 2, Cursor: p.NextCursor})
	if err != nil || len(p2.Items) != 1 || p2.Items[0].ID != ids[0] || p2.NextCursor != "" {
		t.Fatalf("second page: %v %+v", err, p2)
	}
	if p3, err := api.List(ctx, backup.Filter{Status: "failed"}); err != nil || len(p3.Items) != 1 || p3.Items[0].ID != ids[1] {
		t.Fatalf("status filter: %v %+v", err, p3)
	}
	other := uuid.New()
	if p4, err := api.List(ctx, backup.Filter{TenantID: &other}); err != nil || len(p4.Items) != 0 {
		t.Fatalf("tenant filter: %v %+v", err, p4)
	}
	for name, flt := range map[string]backup.Filter{"limit": {Limit: 201}, "status": {Status: "done"}, "cursor": {Cursor: "x"}} {
		if _, err := api.List(ctx, flt); kindOf(err) != backup.ErrInvalid {
			t.Errorf("invalid %s: %v", name, err)
		}
	}
	// the restore request check
	for name, c := range map[string]struct {
		p    backup.RestorePayload
		want backup.ErrorKind
	}{
		"succeeded backup of the instance": {backup.RestorePayload{BackupID: ids[2], InstanceID: f.instance}, 0},
		"failed backup":                    {backup.RestorePayload{BackupID: ids[1], InstanceID: f.instance}, backup.ErrState},
		"backup of another instance":       {backup.RestorePayload{BackupID: ids[2], InstanceID: uuid.New()}, backup.ErrNotFound},
		"unknown backup":                   {backup.RestorePayload{BackupID: uuid.New(), InstanceID: f.instance}, backup.ErrInvalid},
		"no backup id":                     {backup.RestorePayload{InstanceID: f.instance}, backup.ErrInvalid},
	} {
		err := api.CheckRestore(ctx, c.p)
		if (c.want == 0) != (err == nil) || (err != nil && kindOf(err) != c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
