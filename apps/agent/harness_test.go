//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

const (
	tenantID   = "11111111-1111-4111-8111-111111111111"
	instanceID = "22222222-2222-4222-8222-222222222222"
	jobID      = "33333333-3333-4333-8333-333333333333"
	otherID    = "44444444-4444-4444-8444-444444444444"
	repo       = "ghcr.io/zhaduchanhzz/network-access-mesh/headscale"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
	digestX = "sha256:" + strings.Repeat("c", 64)
	token   = strings.Repeat("0123456789abcdef", 4)
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// lines returns the JSON log records with that msg.
func (s *syncBuffer) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// recordingDriver counts the calls that reach the driver: a refused request must never reach it.
type recordingDriver struct {
	noDriver
	mu      sync.Mutex
	calls   []string
	ensured []agentspec.Ensure
	block   chan struct{} // when set, StartInstance waits on it
}

func (d *recordingDriver) record(name string) {
	d.mu.Lock()
	d.calls = append(d.calls, name)
	d.mu.Unlock()
}

func (d *recordingDriver) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func (d *recordingDriver) Name() string { return "recording" }

func (d *recordingDriver) EnsureInstance(_ context.Context, e agentspec.Ensure) (*agentv1.EnsureInstanceResponse, error) {
	d.record("EnsureInstance")
	d.mu.Lock()
	d.ensured = append(d.ensured, e)
	d.mu.Unlock()
	return &agentv1.EnsureInstanceResponse{TemplateVersion: agentspec.TemplateVersion}, nil
}

func (d *recordingDriver) StartInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error) {
	d.record("StartInstance")
	if d.block != nil {
		select {
		case <-d.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &agentv1.InstanceStatus{Instance: &agentv1.InstanceRef{InstanceId: c.Ref.InstanceID.String()}}, nil
}

func (d *recordingDriver) BootstrapAPIKey(_ context.Context, k agentspec.APIKey) (*agentv1.BootstrapApiKeyResponse, error) {
	d.record("BootstrapAPIKey")
	return &agentv1.BootstrapApiKeyResponse{ApiKey: "hskey-api-abcdefghijkl-" + strings.Repeat("s", 64), Prefix: "abcdefghijkl", Created: true}, nil
}

type fakeInventory struct {
	nets []agentspec.NetworkInfo
	ctrs []agentspec.ContainerInfo
}

func (f *fakeInventory) Networks(context.Context) ([]agentspec.NetworkInfo, error) {
	return f.nets, nil
}
func (f *fakeInventory) Containers(context.Context) ([]agentspec.ContainerInfo, error) {
	return f.ctrs, nil
}

type harness struct {
	dir, sock, tenants string
	cfg                *Config
	drv                Driver
	rec                *recordingDriver
	logs               *syncBuffer
	gs                 *grpc.Server
	client             *agentclient.Client
}

// env is the configuration of a test agent; mutate it before start.
func testEnv(dir string) map[string]string {
	return map[string]string{
		"MG_ENV":                        "ci",
		"MG_LOG_LEVEL":                  "debug",
		"MG_AGENT_SOCKET":               filepath.Join(dir, "run", "agent.sock"),
		"MG_AGENT_SOCKET_GID":           "20003",
		"MG_AGENT_PEER_UIDS":            "65532",
		"MG_AGENT_TOKEN_FILE":           filepath.Join(dir, "token"),
		"MG_AGENT_IMAGE_ALLOWLIST_FILE": filepath.Join(dir, "allowlist"),
		"MG_AGENT_TENANTS_DIR":          filepath.Join(dir, "tenants"),
		"MG_AGENT_BACKUPS_DIR":          filepath.Join(dir, "backups"),
		"MG_AGENT_RUN_UID_RANGE":        "30000-39999",
		"MG_AGENT_TENANT_NET_POOL":      "10.250.0.0/16",
		"MG_AGENT_PUBLIC_ENTRY_IPV4":    "203.0.113.10",
		"MG_BASE_DOMAIN":                "example.com",
		"MG_AGENT_LOCK_WAIT":            "300ms",
	}
}

func getenv(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func environ(env map[string]string) []string {
	var out []string
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// testDir is short (sun_path) and removed at the end.
func testDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mga")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, d := range []string{"run", "tenants", "backups"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token+"\n"), 0o440); err != nil { //nolint:gosec // G306: the mode of the real token (root:mg-sec-worker 0440)
		t.Fatal(err)
	}
	allow := "# test\n" + repo + "@" + digestA + "\ndocker.io/headscale/headscale@" + digestB + "\n"
	if err := os.WriteFile(filepath.Join(dir, "allowlist"), []byte(allow), 0o644); err != nil { //nolint:gosec // G306: an allowlist is public, read-only for the worker
		t.Fatal(err)
	}
	return dir
}

type option func(h *harness, env map[string]string)

func withDriver(d Driver) option { return func(h *harness, _ map[string]string) { h.drv = d } }

// start runs an agent on a temporary socket. By default the test process's UID is an allowed worker UID (set after
// LoadConfig, which refuses 0 — CI runs the tests as root).
func start(t *testing.T, inv agentspec.Inventory, peerUIDs []uint32, opts ...option) *harness {
	t.Helper()
	h := &harness{dir: testDir(t), logs: &syncBuffer{}, rec: &recordingDriver{}}
	h.drv = h.rec
	env := testEnv(h.dir)
	for _, o := range opts {
		o(h, env)
	}
	cfg, err := LoadConfig(getenv(env), environ(env))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cfg.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if peerUIDs == nil {
		peerUIDs = []uint32{uint32(os.Getuid())} //nolint:gosec // test
	}
	cfg.PeerUIDs, cfg.SocketGID = peerUIDs, -1
	h.cfg, h.sock, h.tenants = cfg, cfg.Socket, cfg.Host.TenantsDir
	srv := newServer(cfg, tok, h.drv, inv, h.logger())
	l, err := listenUnix(context.Background(), cfg.Socket, cfg.SocketGID)
	if err != nil {
		t.Fatal(err)
	}
	gs := srv.grpcServer(cfg) // local: the goroutine must not read h.gs, which restart() replaces (data race)
	h.gs = gs
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	h.client = h.dial(t, cfg.TokenFile)
	return h
}

func (h *harness) logger() *slog.Logger { return logx.New(h.logs, slog.LevelDebug, "agent") }

func (h *harness) dial(t *testing.T, tokenFile string) *agentclient.Client {
	t.Helper()
	c, err := agentclient.New(agentclient.Config{Socket: h.sock, TokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func tctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func goodRef() *agentv1.InstanceRef {
	return &agentv1.InstanceRef{InstanceId: instanceID, TenantId: tenantID, Slug: "acme"}
}

func goodSpec() *agentv1.InstanceSpec {
	return &agentv1.InstanceSpec{
		Instance: goodRef(), ImageDigest: digestA, RunUid: 30001, NetCidr: "10.250.0.8/29",
		Limits: &agentv1.ResourceLimits{MemoryMib: 512, CpuMillis: 1000, Pids: 256},
		Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"1.1.1.1"}, DerpRegionId: 901,
			PublicEntryIpv4: "203.0.113.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO},
	}
}

func goodEnsure() *agentv1.EnsureInstanceRequest {
	return &agentv1.EnsureInstanceRequest{Spec: goodSpec(), TargetPhase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER, JobId: jobID}
}

// writeInstance lays out an instance directory the way the agent (and tenant-deploy.sh) does.
func writeInstance(t *testing.T, tenants, id, tenant, slug string) {
	t.Helper()
	dir := filepath.Join(tenants, id)
	if err := os.MkdirAll(filepath.Join(dir, "meta"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o750) //nolint:gosec // G302: the layout of the agent (directories 0750) under test
	meta, _ := json.Marshal(map[string]any{"instance_id": id, "tenant_id": tenant, "slug": slug, "run_uid": 30001,
		"net_cidr": "10.250.0.8/29", "template_version": "1", "config_sha256": strings.Repeat("0", 64), "image": repo + "@" + digestA})
	f := filepath.Join(dir, "meta", "instance.json")
	if err := os.WriteFile(f, meta, 0o400); err != nil {
		t.Fatal(err)
	}
}
