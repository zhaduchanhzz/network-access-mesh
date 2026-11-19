//go:build linux && dockerintegration

package main

// Integration test of instance.upgrade and instance.restart (P3-T13a — master §20: "Upgrade lỗi ⇒ tự lùi; configtest
// của binary đích lỗi ⇒ instance chạy lại image cũ, dữ liệu gốc không đổi; post-start gate: policy bị đổi ngoài luồng
// trước khi restart ⇒ được áp lại; db.sqlite bị thay bằng DB trống ⇒ edge bị gỡ + cảnh báo Critical") on a real Docker
// Engine: the orchestrator's state machines (orchestrator.InstanceUpgrader / InstanceRestarter — the code the worker
// runs) drive a REAL agent over its Unix socket against a real, activated Headscale 0.29.7 instance, with BOTH
// allowlisted images (the MeshGuard build [images.mg-headscale] and the official image [images.headscale]), the real
// cold backup, the real preflight (configtest of the target binary on a decrypted copy) and the real restore. No
// PostgreSQL, no network here: the registry is in memory, and the adapter side is a test double that answers through
// the Headscale CLI inside the container (docker exec over the Unix socket of the instance — the same database the REST
// API serves): policy, health (the platform's API key must be a valid key of the instance's database), version, the
// reads of the contract smoke; the policy core is the CLI's `policy set`.
//
//  1. configtest of the target binary refuses a copy of the data (FORCED: a decorator around the agent's Docker engine
//     writes, right before the preflight's configtest, a policy row the loader cannot parse into the database of the
//     DECRYPTED COPY only — a stored policy invalid for the new version; the target binary really loads and refuses it
//     [configtest = NewHeadscale → NewState: migrations + the stored policy + NewPolicyManager]) ⇒ rolled_back: the previous
//     image runs again, data/ byte for byte as it was when the instance stopped (checksums taken by a decorator of the
//     compose runner at `stop` and right before the next `start`), the same database inode, no data.prev-*, the live
//     data/ never mounted by the target;
//  2. upgrade MeshGuard build → official image ⇒ succeeded: the container on the official digest, healthy, GET
//     /version v0.29.7, users/nodes/policy/Noise key preserved, the edge attached, the registry on the target;
//  3. upgrade back to the MeshGuard build, the contract smoke failing after the switch (played by the adapter double) ⇒
//     rollback BY RESTORE of the cold backup on the previous (official) image: data.prev-* kept, users/nodes/policy as
//     before, the edge attached again;
//  4. restart with a policy changed out of band (CLI `policy set`) ⇒ the post-start gate re-applies the applied policy;
//  5. db.sqlite replaced by an empty SQLite database, then restart ⇒ the instance starts on it, refuses the platform's
//     API key ⇒ Critical instance.database_replaced, edge_attach cleared and the edge detached, rolled_back.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ---------------------------------------------------------------------------------------------------- decorators

// upEngine is the agent's Docker engine; armed, it plays a stored policy the target version refuses: right before the
// preflight's configtest runs, a new policy row the policy loader cannot parse is written into the database of the
// DECRYPTED COPY (the bind of /var/lib/headscale — never the live data/), then the target binary runs on it for real.
type upEngine struct {
	compose.Engine
	mu       sync.Mutex
	armed    bool
	injected error // nil once the policy row was written into the copy
	done     bool
	binds    [][]compose.Bind // binds of every preflight configtest run
}

// badPolicy is a stored policy no policy loader accepts (truncated HuJSON).
const badPolicy = `{"acls": [{"action": "accept", "src": ["*"], "dst": [`

func (e *upEngine) RunOnce(ctx context.Context, s compose.OneShot) (compose.OneShotResult, error) {
	if s.Labels[compose.LabelHelper] == "pfconfigtest" {
		e.mu.Lock()
		e.binds = append(e.binds, slices.Clone(s.Binds))
		if e.armed {
			e.armed, e.done = false, true
			for _, b := range s.Binds {
				if b.Target == "/var/lib/headscale" {
					e.injected = storePolicy(ctx, b.Source, badPolicy)
				}
			}
		}
		e.mu.Unlock()
	}
	return e.Engine.RunOnce(ctx, s)
}

// storePolicy appends a policy row to data/db.sqlite of dir (policies: id, created_at, updated_at, deleted_at, data —
// Headscale reads the last row) with the static sqlite3 of the agent image, then gives every file back to the owner of
// the database (the test is root; the copy belongs to run_uid).
func storePolicy(ctx context.Context, dir, policy string) error {
	db := filepath.Join(dir, "db.sqlite")
	fi, err := os.Lstat(db)
	if err != nil {
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	q := "INSERT INTO policies (created_at, updated_at, data) VALUES (datetime('now'), datetime('now'), '" +
		strings.ReplaceAll(policy, "'", "''") + "');"
	if out, err := exec.CommandContext(ctx, compose.SQLiteBinary, "-batch", "-bail", db, q).CombinedOutput(); err != nil { //nolint:gosec // test
		return fmt.Errorf("sqlite3: %w %s", err, out)
	}
	ents, _ := os.ReadDir(dir)
	for _, en := range ents {
		_ = os.Lchown(filepath.Join(dir, en.Name()), int(st.Uid), int(st.Gid))
	}
	return nil
}

// upCompose is the agent's compose runner; it records the checksums of data/ right after a `stop` and right before a
// `start` (the bracket of everything an upgrade does on a stopped instance).
type upCompose struct {
	compose.Runner
	mu          sync.Mutex
	stop, start []map[string]string
	sumsFor     func(dir string) map[string]string
}

func (c *upCompose) Compose(ctx context.Context, p compose.Project, args ...string) error {
	if len(args) > 0 && args[0] == "start" {
		s := c.sumsFor(p.Dir)
		c.mu.Lock()
		c.start = append(c.start, s)
		c.mu.Unlock()
	}
	err := c.Runner.Compose(ctx, p, args...)
	if err == nil && len(args) > 0 && args[0] == "stop" {
		s := c.sumsFor(p.Dir)
		c.mu.Lock()
		c.stop = append(c.stop, s)
		c.mu.Unlock()
	}
	return err
}

// dirSums is sha256 of every file of <instance>/data (db.sqlite, its -wal/-shm, the keys) and the database's inode.
func dirSums(dir string) map[string]string {
	out := map[string]string{}
	ents, _ := os.ReadDir(filepath.Join(dir, "data"))
	for _, e := range ents {
		p := filepath.Join(dir, "data", e.Name())
		b, err := os.ReadFile(p) //nolint:gosec // G304: test
		if err != nil {
			continue
		}
		s := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(s[:])
		if e.Name() == "db.sqlite" {
			if fi, err := os.Lstat(p); err == nil {
				out["db.sqlite#inode"] = strconv.FormatUint(fi.Sys().(*syscall.Stat_t).Ino, 10)
			}
		}
	}
	return out
}

// startUpgradeIT is startIT with both allowlisted images and the decorated engine and compose runner.
func startUpgradeIT(ctx context.Context, t *testing.T, e itEnv, official string, extra map[string]string, eng *upEngine,
	run *upCompose) *itAgent {
	t.Helper()
	for _, d := range []struct {
		rel  string
		mode os.FileMode
	}{{"tenants", 0o750}, {"backups", 0o700}, {"backups/tenants", 0o700}, {"run", 0o750}, {"cfg", 0o700}} {
		if err := os.Mkdir(filepath.Join(e.root, d.rel), d.mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, d := range []string{"tenants", "backups", "run", "cfg"} {
			_ = os.RemoveAll(filepath.Join(e.root, d))
		}
	})
	write(t, filepath.Join(e.root, "cfg", "token"), token, 0o440)
	write(t, filepath.Join(e.root, "cfg", "allowlist"), "# test allowlist (versions.lock [images.mg-headscale], [images.headscale])\n"+
		e.image+"\n"+official+"\n", 0o644)
	env := map[string]string{
		"MG_ENV": "ci", "MG_LOG_LEVEL": "debug", "MG_AGENT_SOCKET": filepath.Join(e.root, "run", "agent.sock"),
		"MG_AGENT_SOCKET_GID": "20003", "MG_AGENT_PEER_UIDS": "65532",
		"MG_AGENT_TOKEN_FILE": filepath.Join(e.root, "cfg", "token"), "MG_AGENT_IMAGE_ALLOWLIST_FILE": filepath.Join(e.root, "cfg", "allowlist"),
		"MG_AGENT_TENANTS_DIR": filepath.Join(e.root, "tenants"), "MG_AGENT_BACKUPS_DIR": filepath.Join(e.root, "backups", "tenants"),
		"MG_AGENT_RUN_UID_RANGE": "30000-39999", "MG_AGENT_TENANT_NET_POOL": e.pool, "MG_AGENT_PUBLIC_ENTRY_IPV4": "192.0.2.10",
		"MG_BASE_DOMAIN": "agentit.test", "MG_AGENT_COMPOSE_BIN": os.Getenv("MG_AGENT_COMPOSE_BIN"), "MG_AGENT_LOCK_WAIT": "10s",
		"MG_AGENT_HELPER_IMAGE": e.helper,
	}
	if env["MG_AGENT_COMPOSE_BIN"] == "" {
		env["MG_AGENT_COMPOSE_BIN"] = "/usr/local/bin/docker-compose"
	}
	maps.Copy(env, extra)
	cfg, err := LoadConfig(getenv(env), environ(env))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cfg.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	cfg.PeerUIDs, cfg.SocketGID = []uint32{0}, -1 // the test process (root) is the worker
	logs := &syncBuffer{}
	h := &harness{logs: logs, cfg: cfg, sock: cfg.Socket, tenants: cfg.Host.TenantsDir}
	base, err := compose.NewEngine(cfg.DockerHost)
	if err != nil {
		t.Fatal(err)
	}
	eng.Engine = base
	run.Runner = &compose.CLI{Command: []string{cfg.ComposeBin}, DockerHost: cfg.DockerHost, ConfigDir: cfg.DockerConfig}
	inv := compose.NewInventory(base)
	c, err := compose.New(compose.Config{Host: &cfg.Host, Guard: &agentspec.Guard{Host: &cfg.Host, Inventory: inv, Edge: cfg.Edge},
		AgentGID: os.Getegid(), Engine: eng, Compose: run, Edge: cfg.Edge, EdgeNetwork: cfg.EdgeNetwork, HelperImage: cfg.HelperImage,
		Backup: cfg.Backup, MaxDBBytes: cfg.MaxDBBytes, Log: h.logger()})
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(cfg, tok, composeDriver{c: c}, inv, h.logger())
	l, err := listenUnix(ctx, cfg.Socket, -1)
	if err != nil {
		t.Fatal(err)
	}
	gs := srv.grpcServer(cfg)
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent log:\n%s", logs.String())
		}
	})
	return &itAgent{cfg: cfg, srv: srv, drv: composeDriver{c: c}, inv: inv, logs: logs, client: h.dial(t, cfg.TokenFile)}
}

// ---------------------------------------------------------------------------------------------------- the adapter side

// cliHS answers like the instance does through the adapter, from the CLI inside its container: the same database the
// REST API serves. Every call first checks that the platform's API key is a valid key of that database (the adapter's
// Bearer authentication) — a replaced database knows no key: KindAPIKeyRejected.
type cliHS struct {
	headscale.Instance
	eng       compose.Engine
	container string
	mu        sync.Mutex
	prefix    string // the platform's API key prefix
	smokeFail bool   // ListUsers fails (the contract smoke after the switch)
}

func (h *cliHS) exec(ctx context.Context, op headscale.Op, args ...string) ([]byte, error) {
	res, err := h.eng.Exec(ctx, h.container, append([]string{"headscale"}, args...), 30*time.Second)
	if err != nil {
		return nil, &headscale.Error{Op: op, Kind: headscale.KindUnavailable, Err: err}
	}
	if res.ExitCode != 0 {
		return res.Stdout, &headscale.Error{Op: op, Kind: headscale.KindUpstreamRejected, Upstream: strings.TrimSpace(string(res.Stderr) + string(res.Stdout))}
	}
	return res.Stdout, nil
}

func (h *cliHS) authorized(ctx context.Context, op headscale.Op) error {
	out, err := h.exec(ctx, op, "apikeys", "list", "-o", "json")
	if err != nil {
		return err
	}
	var keys []hsKeyIT
	_ = json.Unmarshal(bytes.TrimSpace(out), &keys)
	h.mu.Lock()
	want := h.prefix
	h.mu.Unlock()
	for _, k := range keys {
		if strings.Contains(k.Prefix, want) && k.valid() {
			return nil
		}
	}
	return &headscale.Error{Op: op, Kind: headscale.KindAPIKeyRejected, Err: headscale.ErrAPIKeyRejected}
}

func (h *cliHS) Health(ctx context.Context) (headscale.Health, error) {
	if err := h.authorized(ctx, headscale.OpHealth); err != nil {
		return headscale.Health{}, err
	}
	return headscale.Health{DatabaseConnectivity: true}, nil
}

func (h *cliHS) GetPolicy(ctx context.Context) (headscale.Policy, error) {
	if err := h.authorized(ctx, headscale.OpGetPolicy); err != nil {
		return headscale.Policy{}, err
	}
	out, err := h.exec(ctx, headscale.OpGetPolicy, "policy", "get", "-o", "json")
	if err != nil {
		if he, ok := headscale.AsError(err); ok && strings.Contains(he.Upstream, "not found") {
			return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy, Err: headscale.ErrNoPolicy}
		}
		return headscale.Policy{}, err
	}
	return headscale.Policy{Data: string(bytes.TrimSuffix(out, []byte("\n")))}, nil // RT-15: one trailing newline
}

func (h *cliHS) CheckPolicy(_ context.Context, p string) error {
	if !json.Valid([]byte(p)) {
		return &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindValidation, Err: errors.New("not plain JSON")}
	}
	return nil
}

func (h *cliHS) Version(ctx context.Context) (string, error) {
	out, err := h.exec(ctx, headscale.OpVersion, "version", "-o", "json")
	if err != nil {
		return "", err
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &v); err != nil {
		return "", err
	}
	return v.Version, nil
}

func (h *cliHS) list(ctx context.Context, op headscale.Op, args ...string) (int, error) {
	if err := h.authorized(ctx, op); err != nil {
		return 0, err
	}
	out, err := h.exec(ctx, op, append(args, "-o", "json")...)
	if err != nil {
		return 0, err
	}
	var l []json.RawMessage
	_ = json.Unmarshal(bytes.TrimSpace(out), &l)
	return len(l), nil
}

func (h *cliHS) ListUsers(ctx context.Context, _ headscale.UserFilter) ([]headscale.User, error) {
	h.mu.Lock()
	fail := h.smokeFail
	h.mu.Unlock()
	if fail {
		return nil, &headscale.Error{Op: headscale.OpListUsers, Kind: headscale.KindUpstreamRejected, Upstream: "played contract failure"}
	}
	n, err := h.list(ctx, headscale.OpListUsers, "users", "list")
	return make([]headscale.User, n), err
}

func (h *cliHS) ListNodes(ctx context.Context, _ string) ([]headscale.Node, error) {
	n, err := h.list(ctx, headscale.OpListNodes, "nodes", "list")
	return make([]headscale.Node, n), err
}

func (h *cliHS) ListPreAuthKeys(ctx context.Context) ([]headscale.PreAuthKey, error) {
	n, err := h.list(ctx, headscale.OpListPreAuthKeys, "preauthkeys", "list")
	return make([]headscale.PreAuthKey, n), err
}

func (h *cliHS) ListAPIKeys(ctx context.Context) ([]headscale.APIKey, error) {
	if err := h.authorized(ctx, headscale.OpListAPIKeys); err != nil {
		return nil, err
	}
	out, err := h.exec(ctx, headscale.OpListAPIKeys, "apikeys", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var keys []hsKeyIT
	_ = json.Unmarshal(bytes.TrimSpace(out), &keys)
	var l []headscale.APIKey
	for _, k := range keys {
		p := strings.TrimSuffix(strings.TrimPrefix(k.Prefix, "hskey-api-"), "-***")
		var exp time.Time
		if k.Expiration != nil {
			exp = time.Unix(k.Expiration.Seconds, 0)
		}
		l = append(l, headscale.APIKey{Prefix: p, Expiration: exp})
	}
	return l, nil
}

type cliRegistry struct{ hs *cliHS }

func (r cliRegistry) ForTenant(context.Context, uuid.UUID) (headscale.Instance, error) {
	return r.hs, nil
}

// cliPolicies is the policy core of the test: the applied string set over the CLI (a file the test writes in config/),
// read back.
type cliPolicies struct {
	hs   *cliHS
	file string // <instance>/config/test-policy.hujson
	gid  int
	reqs []policies.ApplyRequest
}

// ApplyDesired is not used here: the instance runs a platform version (the core's text path).
func (p *cliPolicies) ApplyDesired(context.Context, policies.DesiredRequest) (policies.Result, error) {
	return policies.Result{}, errors.New("cliPolicies: no typed version in this test")
}

func (p *cliPolicies) Apply(ctx context.Context, req policies.ApplyRequest) (policies.Result, error) {
	p.reqs = append(p.reqs, req)
	if err := os.WriteFile(p.file, []byte(req.HuJSON), 0o440); err != nil { //nolint:gosec // G306: a policy file like the agent's
		return policies.Result{}, err
	}
	if err := os.Chown(p.file, 0, p.gid); err != nil {
		return policies.Result{}, err
	}
	if _, err := p.hs.exec(ctx, headscale.OpSetPolicy, "policy", "set", "--file", "/etc/headscale/"+filepath.Base(p.file)); err != nil {
		return policies.Result{}, err
	}
	got, err := p.hs.GetPolicy(ctx)
	if err != nil {
		return policies.Result{}, err
	}
	s := sha256.Sum256([]byte(got.Data))
	return policies.Result{State: policies.StateApplied, AppliedSHA256: hex.EncodeToString(s[:]), ApplicationID: uuid.New()}, nil
}

// ---------------------------------------------------------------------------------------------------- backups, registry

// itBackups is the backup subsystem over the real agent: data keys in memory (the worker's SecretStore in production).
type itBackups struct {
	ac      *agentclient.Client
	ref     *agentv1.InstanceRef
	verify  []ed25519.PublicKey
	policy  []byte
	hs      *cliHS
	mu      sync.Mutex
	taken   map[uuid.UUID]*agentv1.BackupArtifact
	keys    map[uuid.UUID][]byte
	restore []string
}

func (b *itBackups) Ready() error { return nil }

func (b *itBackups) ColdBackup(ctx context.Context, jobID, _, _ uuid.UUID) (backup.BackupResult, error) {
	dk, _ := backupfmt.NewDataKey()
	pub, _ := backupfmt.DataRecipient(dk)
	r, err := b.ac.Backup(ctx, &agentv1.BackupRequest{Instance: b.ref, JobId: jobID.String(), Sequence: uint64(time.Now().UnixMilli()), //nolint:gosec // test
		DataRecipient: pub})
	if err != nil {
		return backup.BackupResult{}, err
	}
	a := r.GetArtifact()
	if _, err := backupfmt.Parse(a.GetManifest(), a.GetManifestSignature(), b.verify); err != nil {
		return backup.BackupResult{}, err
	}
	id := uuid.New()
	b.mu.Lock()
	b.taken[id], b.keys[id] = a, dk
	b.mu.Unlock()
	method := backupfmt.MethodVacuumInto
	if a.GetMethod() == agentv1.BackupMethod_BACKUP_METHOD_COLD_COPY {
		method = backupfmt.MethodColdCopy
	}
	return backup.BackupResult{BackupID: id, Sequence: a.GetSequence(), Method: method, ArchiveSHA256: a.GetArchiveSha256(),
		ManifestSHA256: a.GetManifestSha256(), SizeBytes: a.GetSizeBytes()}, nil
}

func (b *itBackups) artifact(id uuid.UUID) (*agentv1.BackupArtifact, []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.taken[id], slices.Clone(b.keys[id])
}

func (b *itBackups) OpenBackup(_ context.Context, _, _, _, id uuid.UUID) (backup.OpenedBackup, error) {
	a, dk := b.artifact(id)
	if a == nil {
		return backup.OpenedBackup{}, jobs.Permanent("backup_not_found", errors.New("no such backup"))
	}
	return backup.OpenedBackup{Artifact: &agentv1.ArtifactRef{Sequence: a.GetSequence(), ArchiveSha256: a.GetArchiveSha256(),
		ManifestSha256: a.GetManifestSha256()}, DataKey: dk, HeadscaleVersion: a.GetHeadscaleVersion()}, nil
}

// RollbackRestore is the restore of §17.2 as the production RollbackRestore runs it, minus PostgreSQL: Restore with the
// applied policy, PostRestoreReconcile (every API key of the backup expired, a new platform key), the edge attached
// again.
func (b *itBackups) RollbackRestore(ctx context.Context, jobID, _, _, id uuid.UUID) (map[string]any, error) {
	a, dk := b.artifact(id)
	if a == nil {
		return nil, errors.New("no such backup")
	}
	r, err := b.ac.Restore(ctx, &agentv1.RestoreRequest{Instance: b.ref, JobId: jobID.String(), DataKey: dk,
		Artifact: &agentv1.ArtifactRef{Sequence: a.GetSequence(), ArchiveSha256: a.GetArchiveSha256(), ManifestSha256: a.GetManifestSha256()},
		Policy:   &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: b.policy}})
	if err != nil {
		return nil, err
	}
	rc, err := b.ac.PostRestoreReconcile(ctx, &agentv1.PostRestoreReconcileRequest{Instance: b.ref, JobId: jobID.String(),
		Plan: &agentv1.ReconcilePlan{ApiKeyTtl: durationpb.New(2160 * time.Hour)}})
	if err != nil {
		return nil, err
	}
	b.hs.mu.Lock()
	b.hs.prefix = rc.GetApiKeyPrefix()
	b.hs.mu.Unlock()
	if _, err := b.ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: b.ref, JobId: jobID.String()}); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.restore = append(b.restore, r.GetPreviousDataKeptAs())
	b.mu.Unlock()
	return map[string]any{"previous_data_kept_as": r.GetPreviousDataKeptAs(), "api_keys_expired": rc.GetApiKeysExpired()}, nil
}

// itOpsStore is the registry of the instance in memory.
type itOpsStore struct {
	mu       sync.Mutex
	target   orchestrator.ReconfigureTarget
	audit    []string
	finished map[uuid.UUID]bool
	upgrades []orchestrator.UpgradeFinish
	notified []string
}

func (s *itOpsStore) OpsTarget(context.Context, uuid.UUID, uuid.UUID) (orchestrator.ReconfigureTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.target
	cv := *s.target.Current
	t.Current = &cv
	return t, nil
}

func (s *itOpsStore) AppliedPolicy(context.Context, uuid.UUID, uuid.UUID) (orchestrator.PolicyInForce, bool, error) {
	return orchestrator.PolicyInForce{HuJSON: templates.BootstrapPolicy, SHA256: orchestrator.BaselineSHA256, Kind: policies.KindBaseline}, true, nil
}

func (s *itOpsStore) close(op audit.Operation, what string) {
	if s.finished[op.ID] {
		return
	}
	s.finished[op.ID] = true
	s.audit = append(s.audit, op.Action+"."+what)
}

func (s *itOpsStore) FinishOperation(_ context.Context, op audit.Operation, _ audit.Details) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.close(op, "succeeded")
	return nil
}

func (s *itOpsStore) FinishUpgrade(_ context.Context, f orchestrator.UpgradeFinish) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.target.Current.ID == f.PreviousVersionID {
		params, _ := json.Marshal(f.Version.Params)
		s.target.Current = &orchestrator.ConfigVersion{ID: f.Version.ID, Version: s.target.Current.Version + 1,
			Status: orchestrator.ConfigApplied, TemplateVersion: s.target.Current.TemplateVersion, ConfigSHA256: f.Version.ConfigSHA256, Params: params}
		s.target.Instance.ImageDigest, s.target.Instance.HeadscaleVersion = f.ImageDigest, f.HeadscaleVersion
		s.upgrades = append(s.upgrades, f)
	}
	s.close(f.Operation, "succeeded")
	return nil
}

func (s *itOpsStore) FailOperation(_ context.Context, f orchestrator.OpsFailure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Outcome != orchestrator.OutcomeRollbackFailed {
		s.close(f.Operation, "failed "+f.Reason)
	}
	if f.RollbackEvent != nil {
		s.audit = append(s.audit, fmt.Sprintf("%s %v", orchestrator.ActionUpgradeRollback, *f.RollbackEvent))
	}
	s.notified = append(s.notified, f.Outcome+":"+f.Reason)
	return nil
}

func (s *itOpsStore) NotifyFailure(_ context.Context, f orchestrator.OpsFailure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notified = append(s.notified, f.Outcome+":"+f.Reason)
	return nil
}

type itSecurity struct {
	mu     sync.Mutex
	events []audit.SecurityEvent
}

func (s *itSecurity) RecordSecurityEvent(_ context.Context, ev audit.SecurityEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return true, nil
}

func (s *itSecurity) count(kind, severity string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Kind == kind && e.Severity == severity {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------------------------------- the test

func TestUpgradeEndToEnd(t *testing.T) {
	e := itConfig(t)
	official := os.Getenv("MG_IT_IMAGE_OFFICIAL")
	if !strings.Contains(official, "@sha256:") {
		t.Fatal("MG_IT_IMAGE_OFFICIAL (versions.lock [images.headscale], <repository>@sha256:<digest>) is required (run.sh)")
	}
	ctx := context.Background()
	dc, err := client.New(client.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()

	// ---- the key ceremony of the test host (as TestBackupRestoreEndToEnd)
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(e.root, "manifest_signing_key")
	write(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), 0o400)
	t.Cleanup(func() { _ = os.Remove(keyFile) })
	recoveryKey, _ := backupfmt.NewDataKey()
	recoveryPub, _ := backupfmt.DataRecipient(recoveryKey)
	recovery, _ := backupfmt.RecipientString(recoveryPub)

	edgeName, edgeNet := e.prefix+"-upedge", e.prefix+"-upedgenet"
	ueng, ucmp := &upEngine{}, &upCompose{sumsFor: dirSums}
	a := startUpgradeIT(ctx, t, e, official, map[string]string{"MG_AGENT_EDGE_CONTAINER": edgeName, "MG_AGENT_EDGE_NETWORK": edgeNet,
		"MG_AGENT_MANIFEST_SIGNING_KEY_FILE": keyFile, "MG_AGENT_BACKUP_RECOVERY_RECIPIENT": recovery,
		"MG_BACKUP_MANIFEST_PUBKEY":    backupfmt.PublicKeySPKI(signer.Public().(ed25519.PublicKey)),
		"MG_AGENT_BACKUP_MAX_DB_BYTES": strconv.Itoa(256 << 20), "MG_AGENT_BACKUP_TIMEOUT": "3m"}, ueng, ucmp)
	ac := a.client
	job := func() string { return uuid.NewString() }

	// ---- the fake edge
	enr, err := dc.NetworkCreate(ctx, edgeNet, client.NetworkCreateOptions{Driver: "bridge",
		IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(e.nets[7])}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), enr.ID, client.NetworkRemoveOptions{}) })
	cr, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{Name: edgeName,
		Config: &container.Config{Image: e.alpine, Cmd: []string{"sleep", "3600"}, User: "10001:10001", Labels: map[string]string{"meshguard.it": e.prefix}},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(edgeNet), ReadonlyRootfs: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{edgeNet: {GwPriority: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = dc.ContainerRemove(context.Background(), edgeName, client.ContainerRemoveOptions{Force: true})
	})
	if _, err := dc.ContainerStart(ctx, cr.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}

	// ---- a throwaway tenant on the MeshGuard build, activated, with a platform API key and some data
	_, mgDigest, _ := strings.Cut(e.image, "@")
	_, offDigest, _ := strings.Cut(official, "@")
	ref := &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: e.prefix + "-up"}
	const uid = 39931
	params := map[string]any{"image_digest": mgDigest, "run_uid": uid, "net_cidr": e.nets[4], "memory_mib": 256, "cpu_millis": 500,
		"pids": 128, "node_expiry_days": 90, "nameservers": []string{"192.0.2.53"}, "derp_region_id": 992,
		"public_entry_ipv4": "192.0.2.10", "log_level": "LOG_LEVEL_INFO"}
	spec := &agentv1.InstanceSpec{Instance: ref, ImageDigest: mgDigest, RunUid: uid, NetCidr: e.nets[4],
		Limits: &agentv1.ResourceLimits{MemoryMib: 256, CpuMillis: 500, Pids: 128},
		Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 992,
			PublicEntryIpv4: "192.0.2.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}
	dir := filepath.Join(a.cfg.Host.TenantsDir, ref.GetInstanceId())
	t.Cleanup(func() {
		_, _ = ac.RemoveEdgeAttachment(context.Background(), &agentv1.RemoveEdgeAttachmentRequest{Instance: ref, JobId: job(),
			Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION})
		_, _ = ac.RemoveInstance(context.Background(), &agentv1.RemoveInstanceRequest{Instance: ref, JobId: job(),
			Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP})
		_ = os.RemoveAll(dir)
		_ = os.RemoveAll(filepath.Join(a.cfg.Host.BackupsDir, ref.GetInstanceId()))
	})
	for _, ph := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
		agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
		c, cancel := context.WithTimeout(ctx, 6*time.Minute)
		_, err := ac.EnsureInstance(c, &agentv1.EnsureInstanceRequest{Spec: spec, TargetPhase: ph, JobId: job()})
		cancel()
		if err != nil {
			t.Fatalf("EnsureInstance(%s): %v", ph, err)
		}
	}
	status := func() *agentv1.InstanceStatus {
		t.Helper()
		r, err := ac.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetStatus()
	}
	for start := time.Now(); status().GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY; time.Sleep(time.Second) {
		if time.Since(start) > 90*time.Second {
			t.Fatal("the tenant is not healthy after 90 s")
		}
	}
	if _, err := ac.BootstrapPolicy(ctx, &agentv1.BootstrapPolicyRequest{Instance: ref, JobId: job(),
		Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL}); err != nil {
		t.Fatal(err)
	}
	key, err := ac.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{Instance: ref, JobId: job(), Ttl: durationpb.New(2160 * time.Hour)})
	if err != nil || !key.GetCreated() {
		t.Fatalf("BootstrapApiKey: %v", err)
	}
	if r, err := ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: ref, JobId: job()}); err != nil || !r.GetAttached() {
		t.Fatalf("EnsureEdgeAttachment: %v %v", r, err)
	}
	eng, err := compose.NewEngine("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	ctr := "mg-hs-" + ref.GetSlug()
	cli := func(args ...string) []byte {
		t.Helper()
		res, err := eng.Exec(ctx, ctr, append([]string{"headscale"}, args...), 30*time.Second)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("headscale %v: %v exit %d: %s", args, err, res.ExitCode, res.Stderr)
		}
		return res.Stdout
	}
	cli("users", "create", "alice", "-o", "json")
	var b12 [12]byte
	_, _ = rand.Read(b12[:])
	authID := "hskey-authreq-" + hex.EncodeToString(b12[:])
	cli("debug", "create-node", "--user", "alice", "--name", "n1", "--key", authID, "-o", "json")
	cli("auth", "register", "--auth-id", authID, "--user", "alice", "-o", "json")
	// the tenant's state as the instance serves it (users, nodes by name and machine key, policy, Noise key)
	tenantState := func() string {
		t.Helper()
		var users []struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(cli("users", "list", "-o", "json"), &users)
		var nodes []hsNodeIT
		_ = json.Unmarshal(cli("nodes", "list", "-o", "json"), &nodes)
		var parts []string
		for _, u := range users {
			parts = append(parts, "user="+u.Name)
		}
		for _, n := range nodes {
			parts = append(parts, "node="+n.Name+"/"+n.MachineKey)
		}
		slices.Sort(parts)
		pol := sha256.Sum256(bytes.TrimSuffix(cli("policy", "get", "-o", "json"), []byte("\n")))
		return strings.Join(parts, ",") + " policy=" + hex.EncodeToString(pol[:])[:12] + " noise=" +
			fileSum(t, filepath.Join(dir, "data", "noise_private.key"))[:12]
	}
	st0 := status()
	if !st0.GetActivated() || st0.GetImageDigest() != mgDigest {
		t.Fatalf("the tenant is not activated on the MeshGuard build: %v", st0)
	}
	state0 := tenantState()
	if !strings.Contains(state0, "user=alice") || !strings.Contains(state0, "node=n1/mkey:") {
		t.Fatalf("tenant state %s", state0)
	}

	// ---- the registry and the two jobs, as the worker builds them
	pj, _ := json.Marshal(params)
	v1 := uuid.New()
	instID, _ := uuid.Parse(ref.GetInstanceId())
	tenID, _ := uuid.Parse(ref.GetTenantId())
	store := &itOpsStore{finished: map[uuid.UUID]bool{}, target: orchestrator.ReconfigureTarget{TenantSlug: ref.GetSlug(),
		TenantStatus: tenants.StatusActive,
		Instance: orchestrator.InstanceRecord{ID: instID, TenantID: tenID, Status: tenants.InstanceRunning, ImageDigest: mgDigest,
			HeadscaleVersion: "v0.29.7", ControlHostname: ref.GetSlug() + ".mesh.agentit.test", RunUID: uid,
			NetCIDR: netip.MustParsePrefix(e.nets[4]), PublicEntryIPv4: netip.MustParseAddr("192.0.2.10"),
			NoiseFingerprint: st0.GetNoiseKeyFingerprint(), APIKeyPrefix: key.GetPrefix()},
		Current: &orchestrator.ConfigVersion{ID: v1, Version: 1, Status: orchestrator.ConfigApplied,
			TemplateVersion: fmt.Sprint(st0.GetTemplateVersion()), ConfigSHA256: st0.GetConfigSha256(), Params: pj}}}
	hs := &cliHS{eng: eng, container: ctr, prefix: key.GetPrefix()}
	bk := &itBackups{ac: ac, ref: ref, verify: []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}, policy: []byte(templates.BootstrapPolicy),
		hs: hs, taken: map[uuid.UUID]*agentv1.BackupArtifact{}, keys: map[uuid.UUID][]byte{}}
	pol := &cliPolicies{hs: hs, file: filepath.Join(dir, "config", "test-policy.hujson"), gid: uid}
	sec := &itSecurity{}
	logs := &syncBuffer{}
	oc := orchestrator.InstanceOpsConfig{Store: store, Agent: ac, Headscale: cliRegistry{hs}, Policies: pol, Backups: bk, Security: sec,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), RetryBase: 200 * time.Millisecond, RetryMax: time.Second,
		HealthPoll: time.Second, HealthTimeout: 60 * time.Second, CallTimeout: 4 * time.Minute, LongCallTimeout: 5 * time.Minute}
	up, err := orchestrator.NewUpgrader(oc)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := orchestrator.NewRestarter(oc)
	if err != nil {
		t.Fatal(err)
	}
	attempt := func(kind, digest string) *itRunner {
		action := orchestrator.ActionInstanceUpgrade
		if kind == orchestrator.RestartKind {
			action = orchestrator.ActionInstanceRestart
		}
		in := orchestrator.OpsInput{TenantID: tenID, InstanceID: instID, ImageDigest: digest, Source: orchestrator.SourcePlatform,
			Operation: audit.Operation{ID: uuid.New(), Action: action, ActorType: audit.ActorSystem, ResourceType: "instance",
				ResourceID: ref.GetInstanceId()}}
		b, _ := json.Marshal(in)
		return &itRunner{id: uuid.New(), input: b}
	}
	stepLine := func(r *itRunner) string {
		var out []string
		for _, s := range r.steps {
			out = append(out, s.name+":"+s.status)
		}
		return strings.Join(out, ",")
	}
	// one delivery as the worker makes it: the handler, then — after a permanent error — the compensation
	upgradeRun := func(r *itRunner) (error, error) {
		runErr := up.RunAttempt(ctx, r)
		if jobs.IsPermanent(runErr) {
			return runErr, up.CompensateAttempt(ctx, r, runErr)
		}
		return runErr, nil
	}
	restartRun := func(r *itRunner) (error, error) {
		runErr := rs.RunAttempt(ctx, r)
		if jobs.IsPermanent(runErr) {
			return runErr, rs.CompensateAttempt(ctx, r, runErr)
		}
		return runErr, nil
	}
	healthyOn := func(digest string) *agentv1.InstanceStatus {
		t.Helper()
		st := status()
		if st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING || st.GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY ||
			st.GetImageDigest() != digest || st.GetNoiseKeyFingerprint() != st0.GetNoiseKeyFingerprint() || st.GetConfigSha256() != st0.GetConfigSha256() {
			t.Fatalf("instance %s %s on %s (want %s), fp %s, config %s", st.GetContainerState(), st.GetHealth(), st.GetImageDigest(), digest,
				st.GetNoiseKeyFingerprint(), st.GetConfigSha256())
		}
		return st
	}
	edgeAttached := func() bool {
		st := status()
		return st.GetEdgeAttachFlag() && st.GetNetwork().GetEdgeAttached()
	}
	prevDirs := func() []string {
		ents, _ := os.ReadDir(dir)
		var out []string
		for _, en := range ents {
			if strings.HasPrefix(en.Name(), "data.prev-") {
				out = append(out, en.Name())
			}
		}
		return out
	}

	// ---- 1. configtest of the target binary refuses a copy of the data ⇒ the previous image on the untouched data
	ueng.armed = true
	r1 := attempt(orchestrator.UpgradeKind, offDigest)
	t1 := time.Now()
	runErr, compErr := upgradeRun(r1)
	if jobs.CodeOf(runErr) != "preflight_failed" || compErr != nil || !ueng.done || ueng.injected != nil {
		t.Fatalf("forced configtest failure: run %v (code %s), compensation %v, injected %v, steps %s\n%s", runErr, jobs.CodeOf(runErr),
			compErr, ueng.injected, stepLine(r1), logs.String())
	}
	ct := string(r1.step(orchestrator.UStepConfigtest).detail)
	healthyOn(mgDigest)
	if len(ucmp.stop) != 1 || len(ucmp.start) != 1 || !maps.Equal(ucmp.stop[0], ucmp.start[0]) || len(ucmp.stop[0]) < 3 {
		t.Fatalf("data/ between the stop and the start again: %v → %v", ucmp.stop, ucmp.start)
	}
	if len(prevDirs()) != 0 || !edgeAttached() || state0 != tenantState() {
		t.Fatalf("after the refused preflight: prev %v, edge %v, state %s (was %s)", prevDirs(), edgeAttached(), tenantState(), state0)
	}
	for _, binds := range ueng.binds {
		for _, b := range binds {
			if b.Source == filepath.Join(dir, "data") {
				t.Fatal("the target binary was given the live data/")
			}
		}
	}
	if !strings.Contains(ct, "policy") || len(bk.taken) != 1 {
		t.Fatalf("configtest detail %s, backups %d", ct, len(bk.taken))
	}
	for _, art := range bk.taken {
		if art.GetMethod() != agentv1.BackupMethod_BACKUP_METHOD_COLD_COPY {
			t.Fatalf("the backup of the upgrade is %s, not a cold copy", art.GetMethod())
		}
	}
	t.Logf("1. configtest of the target refused the copy (%v): steps %s; configtest %.200s; the MeshGuard build runs again; "+
		"data/ identical between the stop and the start (%d files + inode); no data.prev-*", time.Since(t1).Round(time.Second),
		stepLine(r1), ct, len(ucmp.stop[0])-1)

	// ---- 2. upgrade MeshGuard build → official image
	r2 := attempt(orchestrator.UpgradeKind, offDigest)
	t2 := time.Now()
	if runErr, compErr := upgradeRun(r2); runErr != nil || compErr != nil {
		t.Fatalf("upgrade: %v / %v (steps %s)\n%s", runErr, compErr, stepLine(r2), logs.String())
	}
	healthyOn(offDigest)
	if v, err := hs.Version(ctx); err != nil || v != "v0.29.7" {
		t.Fatalf("version %q %v", v, err)
	}
	if state0 != tenantState() || !edgeAttached() || len(store.upgrades) != 1 || store.target.Instance.ImageDigest != offDigest {
		t.Fatalf("after the upgrade: state %s (was %s), edge %v, registry %v", tenantState(), state0, edgeAttached(), store.target.Instance.ImageDigest)
	}
	t.Logf("2. upgrade MeshGuard build → official in %v: steps %s; running the official digest, healthy, state %s, edge attached",
		time.Since(t2).Round(time.Second), stepLine(r2), state0)

	// ---- 3. back to the MeshGuard build, the contract smoke fails after the switch ⇒ rollback by restore
	hs.mu.Lock()
	hs.smokeFail = true
	hs.mu.Unlock()
	r3 := attempt(orchestrator.UpgradeKind, mgDigest)
	t3 := time.Now()
	runErr, compErr = upgradeRun(r3)
	hs.mu.Lock()
	hs.smokeFail = false
	hs.mu.Unlock()
	if jobs.CodeOf(runErr) != "contract_smoke_failed" || compErr != nil {
		t.Fatalf("failure after the switch: run %v, compensation %v (steps %s)\n%s", runErr, compErr, stepLine(r3), logs.String())
	}
	healthyOn(offDigest)
	if len(bk.restore) != 1 || len(prevDirs()) != 1 || !edgeAttached() || tenantState() != state0 {
		t.Fatalf("after the rollback: restores %v, prev %v, edge %v, state %s (was %s)", bk.restore, prevDirs(), edgeAttached(), tenantState(), state0)
	}
	if store.target.Instance.ImageDigest != offDigest || !slices.Contains(store.audit, orchestrator.ActionUpgradeRollback+" true") {
		t.Fatalf("registry %s, audit %v", store.target.Instance.ImageDigest, store.audit)
	}
	t.Logf("3. failure after the switch (contract smoke) ⇒ rolled back by restore in %v: the official image again, healthy, data "+
		"from the cold backup (previous data/ kept as %s), state %s, edge attached", time.Since(t3).Round(time.Second), bk.restore[0], tenantState())

	// ---- 4. restart with a policy changed out of band ⇒ re-applied by the post-start gate
	oob := filepath.Join(dir, "config", "oob-policy.hujson")
	write(t, oob, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`, 0o440)
	if err := os.Chown(oob, 0, uid); err != nil {
		t.Fatal(err)
	}
	cli("policy", "set", "--file", "/etc/headscale/oob-policy.hujson")
	if tenantState() == state0 {
		t.Fatal("the out-of-band policy was not set")
	}
	r4 := attempt(orchestrator.RestartKind, "")
	if runErr, compErr := restartRun(r4); runErr != nil || compErr != nil {
		t.Fatalf("restart: %v / %v (steps %s)\n%s", runErr, compErr, stepLine(r4), logs.String())
	}
	gate := string(r4.step(orchestrator.RSStepPolicy).detail)
	if tenantState() != state0 || !strings.Contains(gate, `"post_start_gate":"repaired"`) || len(pol.reqs) != 1 ||
		pol.reqs[0].Trigger != policies.TriggerDriftRepair || sec.count(orchestrator.SecPolicyDrift, audit.SeverityHigh) != 1 {
		t.Fatalf("post-start gate %s, state %s (want %s), re-applications %d", gate, tenantState(), state0, len(pol.reqs))
	}
	_ = os.Remove(oob)
	t.Logf("4. restart with a policy changed out of band: steps %s; post-start gate %s", stepLine(r4), gate)

	// ---- 5. db.sqlite replaced by an empty database ⇒ edge detached + Critical
	sqlite := exec.CommandContext(ctx, compose.SQLiteBinary, filepath.Join(dir, "data", "db.sqlite.new"), "PRAGMA user_version = 1; VACUUM;") //nolint:gosec // test
	if out, err := sqlite.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3: %v %s", err, out)
	}
	newDB := filepath.Join(dir, "data", "db.sqlite.new")
	if err := os.Chown(newDB, uid, uid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(newDB, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"db.sqlite-wal", "db.sqlite-shm"} {
		_ = os.Remove(filepath.Join(dir, "data", f))
	}
	if err := os.Rename(newDB, filepath.Join(dir, "data", "db.sqlite")); err != nil {
		t.Fatal(err)
	}
	r5 := attempt(orchestrator.RestartKind, "")
	runErr, compErr = restartRun(r5)
	st5 := status()
	if jobs.CodeOf(runErr) != "database_replaced" || compErr != nil {
		t.Fatalf("replaced database: run %v, compensation %v (steps %s)\n%s", runErr, compErr, stepLine(r5), logs.String())
	}
	if st5.GetEdgeAttachFlag() || st5.GetNetwork().GetEdgeAttached() || sec.count(orchestrator.SecDatabaseReplaced, audit.SeverityCritical) != 1 ||
		!slices.Contains(store.notified, "rolled_back:database_replaced") {
		t.Fatalf("after the replaced database: flag %v, edge on network %v, critical events %d, notified %v", st5.GetEdgeAttachFlag(),
			st5.GetNetwork().GetEdgeAttached(), sec.count(orchestrator.SecDatabaseReplaced, audit.SeverityCritical), store.notified)
	}
	t.Logf("5. db.sqlite replaced by an empty database: restart ⇒ %s; edge detached (flag %v, on network %v), Critical %s, staff notified",
		jobs.CodeOf(runErr), st5.GetEdgeAttachFlag(), st5.GetNetwork().GetEdgeAttached(), orchestrator.SecDatabaseReplaced)
}
