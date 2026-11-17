//go:build linux && dockerintegration

package main

// Integration test of the agent operations of P3-T03 on a real Docker Engine (master §20 P3-T03): ValidateConfig in a
// throw-away container, BootstrapPolicy, BootstrapApiKey, Ensure/RemoveEdgeAttachment, the edge supervisor and the
// start guard. The agent runs alone — no PostgreSQL, no worker anywhere in this test: the edge supervisor and the
// start guard rely on Docker and the local files only. Entry point: tests/integration/agent/run.sh (`make agent-it`).
//
// The shared edge is played by a container of [images.alpine] named <prefix>-edge, attached to a plain bridge network
// <prefix>-edgenet with gw_priority 1 (as mg-edge is on the network mg-edge — §14.3); tenant networks are attached to
// it at run time like to mg-edge.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)

// itAgent is a real agent of the test host: socket, token, guard with the real inventory, compose driver.
type itAgent struct {
	cfg    *Config
	srv    *server
	drv    Driver
	inv    agentspec.Inventory
	logs   *syncBuffer
	client *agentclient.Client
}

// startIT lays out the test host under MG_IT_ROOT (root-owned like layout.sh: tenants/, backups/, run/, the token and
// the allowlist) and starts an agent on it. extra overrides the environment.
func startIT(ctx context.Context, t *testing.T, e itEnv, extra map[string]string) *itAgent {
	t.Helper()
	for _, d := range []struct {
		rel  string
		mode fs.FileMode
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
	write(t, filepath.Join(e.root, "cfg", "allowlist"), "# test allowlist (versions.lock [images.mg-headscale])\n"+e.image+"\n", 0o644)
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
	for k, v := range extra {
		env[k] = v
	}
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
	drv, inv, err := buildDriver(ctx, cfg, h.logger())
	if err != nil {
		t.Fatal(err)
	}
	if drv.Name() != "compose" {
		t.Fatalf("driver %s", drv.Name())
	}
	srv := newServer(cfg, tok, drv, inv, h.logger())
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
	return &itAgent{cfg: cfg, srv: srv, drv: drv, inv: inv, logs: logs, client: h.dial(t, cfg.TokenFile)}
}

// itTenant is one throwaway tenant of the operations test.
type itTenant struct {
	ref  *agentv1.InstanceRef
	spec *agentv1.InstanceSpec
	uid  int
	dir  string
}

func (x itTenant) data() string    { return filepath.Join(x.dir, "data") }
func (x itTenant) network() string { return "mg-t-" + x.ref.GetSlug() }

// dataFiles reads every file of data/ (the test is root: the agent itself never reads them).
func dataFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, en := range entries {
		b, err := os.ReadFile(filepath.Join(dir, en.Name())) //nolint:gosec // G304: test
		if err != nil {
			t.Fatal(err)
		}
		out[en.Name()] = b
	}
	return out
}

// setData makes data/ hold exactly files, owned by uid (0600).
func setData(t *testing.T, dir string, files map[string][]byte, uid int) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		if err := os.Remove(filepath.Join(dir, en.Name())); err != nil {
			t.Fatal(err)
		}
	}
	for name, b := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
}

func otherNoiseKey(t *testing.T) []byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return []byte("privkey:" + hex.EncodeToString(k[:]))
}

// TestAgentOperationsEndToEnd — the verification of P3-T03 (master §20) on real Docker, with no PostgreSQL and no
// worker: ValidateConfig never touches data/; BootstrapPolicy/BootstrapApiKey through the CLI in the container (the
// key never logged); EnsureEdgeAttachment refuses an alias hs-<slug> already on another network of the edge and a
// foreign network member; the recreated edge is re-attached by the supervisor to exactly the flagged networks; an
// activated instance with an empty data/ or another Noise key is not started, its edge_attach flag is cleared, the
// edge detached, a Critical event logged; db.sqlite removed or the key replaced under a running instance ⇒ the same
// within one supervisor cycle.
func TestAgentOperationsEndToEnd(t *testing.T) {
	e := itConfig(t)
	ctx := context.Background()
	dc, err := client.New(client.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()
	eng, err := compose.NewEngine("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	before := observe(t, dc, e.root)
	edgeName, edgeNet := e.prefix+"-edge", e.prefix+"-edgenet"
	const interval = 2 * time.Second
	a := startIT(ctx, t, e, map[string]string{"MG_AGENT_EDGE_CONTAINER": edgeName, "MG_AGENT_EDGE_NETWORK": edgeNet,
		"MG_AGENT_EDGE_SUPERVISOR_INTERVAL": interval.String()})
	ac := a.client
	sup, ok := a.drv.(edgeSupervisor)
	if !ok {
		t.Fatal("the compose driver is not an edge supervisor")
	}
	// the supervisor, as run() starts it — stopped and started again by the test
	var stopSup func()
	startSup := func() {
		sctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { a.srv.superviseEdge(sctx, sup, interval); close(done) }()
		stopSup = func() { cancel(); <-done; stopSup = nil }
	}
	t.Cleanup(func() {
		if stopSup != nil {
			stopSup()
		}
	})
	job := func() string { return uuid.NewString() }
	refused := func(what string, err error, code codes.Code, want agentv1.RefusalReason) {
		t.Helper()
		r, ok := agentclient.RefusalOf(err)
		if status.Code(err) != code || !ok || r.GetReason() != want {
			t.Fatalf("%s: %v, want %s %s", what, err, code, want)
		}
	}

	// ---- the fake edge: a plain bridge network with gw_priority 1, like mg-edge
	enr, err := dc.NetworkCreate(ctx, edgeNet, client.NetworkCreateOptions{Driver: "bridge",
		IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(e.nets[7])}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), enr.ID, client.NetworkRemoveOptions{}) })
	removeCtr := func(name string) {
		_, _ = dc.ContainerRemove(context.Background(), name, client.ContainerRemoveOptions{Force: true})
	}
	sleeper := func(name string, nw string, ep *network.EndpointSettings) string {
		t.Helper()
		cr, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{Name: name,
			Config: &container.Config{Image: e.alpine, Cmd: []string{"sleep", "3600"}, User: "10001:10001", Labels: map[string]string{"meshguard.it": e.prefix}},
			HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(nw), ReadonlyRootfs: true, CapDrop: []string{"ALL"},
				SecurityOpt: []string{"no-new-privileges:true"}},
			NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{nw: ep}}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { removeCtr(name) })
		if _, err := dc.ContainerStart(ctx, cr.ID, client.ContainerStartOptions{}); err != nil {
			t.Fatal(err)
		}
		return cr.ID
	}
	edgeID := sleeper(edgeName, edgeNet, &network.EndpointSettings{GwPriority: 1})
	edgeNets := func() []string {
		t.Helper()
		ci, err := dc.ContainerInspect(ctx, edgeName, client.ContainerInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for nw := range ci.Container.NetworkSettings.Networks {
			out = append(out, nw)
		}
		sort.Strings(out)
		return out
	}
	startSup()

	// ---- tenants A and B: typed parameters only
	_, digest, _ := strings.Cut(e.image, "@")
	tenant := func(suffix string, uid int, cidr string) itTenant {
		ref := &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: e.prefix + "-" + suffix}
		return itTenant{ref: ref, uid: uid, dir: filepath.Join(a.cfg.Host.TenantsDir, ref.GetInstanceId()),
			spec: &agentv1.InstanceSpec{Instance: ref, ImageDigest: digest, RunUid: uint32(uid), NetCidr: cidr, //nolint:gosec // G115: test
				Limits: &agentv1.ResourceLimits{MemoryMib: 256, CpuMillis: 500, Pids: 128},
				Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 990,
					PublicEntryIpv4: "192.0.2.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}}
	}
	ta, tb := tenant("a", 39911, e.nets[4]), tenant("b", 39912, e.nets[5])
	for _, x := range []itTenant{ta, tb} {
		t.Cleanup(func() { // whatever happened: no edge, no container, no network, no directory of the tenant
			for _, r := range []agentv1.EdgeDetachReason{agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION} {
				_, _ = ac.RemoveEdgeAttachment(context.Background(), &agentv1.RemoveEdgeAttachmentRequest{Instance: x.ref, JobId: job(), Reason: r})
			}
			_, _ = ac.RemoveInstance(context.Background(), &agentv1.RemoveInstanceRequest{Instance: x.ref, JobId: job(),
				Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP})
			_ = os.RemoveAll(x.dir) // activated: the agent never deletes it (DELETE_ARCHIVED is P3-T11) — the test does
		})
	}
	ensure := func(x itTenant, phase agentv1.TargetPhase) *agentv1.EnsureInstanceResponse {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 6*time.Minute)
		defer cancel()
		r, err := ac.EnsureInstance(c, &agentv1.EnsureInstanceRequest{Spec: x.spec, TargetPhase: phase, JobId: job()})
		if err != nil {
			t.Fatalf("EnsureInstance(%s, %s): %v", x.ref.GetSlug(), phase, err)
		}
		return r
	}
	statusOf := func(x itTenant, keys bool) *agentv1.InstanceStatus {
		t.Helper()
		r, err := ac.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: x.ref, IncludeApiKeys: keys})
		if err != nil {
			t.Fatalf("GetInstanceStatus(%s): %v", x.ref.GetSlug(), err)
		}
		return r.GetStatus()
	}
	waitHealthy := func(x itTenant, what string) {
		t.Helper()
		start := time.Now()
		for time.Since(start) < 90*time.Second {
			if statusOf(x, false).GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY {
				t.Logf("%s: healthy after %v", what, time.Since(start).Round(100*time.Millisecond))
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: not healthy after 90 s", what)
	}
	attach := func(x itTenant) (*agentv1.EnsureEdgeAttachmentResponse, error) {
		return ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: x.ref, JobId: job()})
	}
	mustAttach := func(x itTenant) *agentv1.EnsureEdgeAttachmentResponse {
		t.Helper()
		r, err := attach(x)
		if err != nil || !r.GetAttached() || r.GetNetworkMembers() != 2 {
			t.Fatalf("EnsureEdgeAttachment(%s): %v %v", x.ref.GetSlug(), r, err)
		}
		return r
	}
	startInstance := func(x itTenant) error {
		_, err := ac.StartInstance(ctx, &agentv1.StartInstanceRequest{Instance: x.ref, JobId: job()})
		return err
	}
	stopInstance := func(x itTenant) {
		t.Helper()
		if _, err := ac.StopInstance(ctx, &agentv1.StopInstanceRequest{Instance: x.ref, JobId: job()}); err != nil {
			t.Fatal(err)
		}
	}
	meta := func(x itTenant) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(x.dir, "meta", "instance.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	// /key of the instance as the edge reaches it (hs-<slug>:8080 by Docker DNS on the tenant network)
	keyViaEdge := func(x itTenant) string {
		t.Helper()
		res, err := eng.Exec(ctx, edgeName, []string{"wget", "-qO-", "-T", "5", "http://hs-" + x.ref.GetSlug() + ":8080/key?v=113"}, 20*time.Second)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("GET /key through the edge: %v exit %d %s", err, res.ExitCode, res.Stderr)
		}
		var k struct {
			PublicKey string `json:"publicKey"`
		}
		if err := json.Unmarshal(res.Stdout, &k); err != nil {
			t.Fatalf("/key: %q", res.Stdout)
		}
		return k.PublicKey
	}
	criticals := func(x itTenant, reason, trigger string) int {
		n := 0
		for _, l := range a.logs.lines(t, "start_guard_failed") {
			if l["instance_id"] == x.ref.GetInstanceId() && l["severity"] == "critical" && l["reason"] == reason && l["trigger"] == trigger {
				n++
			}
		}
		return n
	}
	helpersLeft := func() []string {
		t.Helper()
		cl, err := dc.ContainerList(ctx, client.ContainerListOptions{All: true})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cl.Items {
			if n := strings.TrimPrefix(c.Names[0], "/"); strings.HasPrefix(n, "mg-helper-"+e.prefix+"-") {
				out = append(out, n)
			}
		}
		return out
	}

	// ---- 1. ValidateConfig: configtest in a throw-away container, a scratch data directory — data/ never touched
	if _, err := ac.ValidateConfig(ctx, &agentv1.ValidateConfigRequest{Spec: ta.spec, JobId: job()}); err == nil {
		t.Fatal("ValidateConfig before the storage phase")
	} else {
		refused("ValidateConfig without directory", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE)
	}
	ensure(ta, agentv1.TargetPhase_TARGET_PHASE_STORAGE)
	dataInfo := func(x itTenant) string {
		fi, err := os.Lstat(x.data())
		if err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(x.data())
		st := fi.Sys().(*syscall.Stat_t)
		return fmt.Sprintf("ino=%d mtime=%s entries=%d", st.Ino, fi.ModTime().Format(time.RFC3339Nano), len(entries))
	}
	d0 := dataInfo(ta)
	var vsha string
	for i := range 2 {
		start := time.Now()
		v, err := ac.ValidateConfig(ctx, &agentv1.ValidateConfigRequest{Spec: ta.spec, JobId: job()})
		if err != nil || !v.GetValid() || v.GetExitCode() != 0 || len(v.GetConfigSha256()) != 64 {
			t.Fatalf("ValidateConfig: %v %v", v, err)
		}
		t.Logf("ValidateConfig %d: valid, exit 0, %v", i+1, time.Since(start).Round(10*time.Millisecond))
		vsha = v.GetConfigSha256()
	}
	if d := dataInfo(ta); d != d0 || !strings.HasSuffix(d, "entries=0") {
		t.Fatalf("ValidateConfig touched data/: %s → %s", d0, d)
	}
	if _, err := os.Stat(filepath.Join(ta.dir, "config.next")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("config.next/ left behind")
	}
	if _, err := os.Stat(filepath.Join(ta.dir, "config", "config.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("ValidateConfig wrote config/")
	}
	if h := helpersLeft(); len(h) != 0 {
		t.Fatalf("helper containers left: %v", h)
	}

	// ---- 2. A up to healthy; no edge before a policy; policy; API keys
	ensure(ta, agentv1.TargetPhase_TARGET_PHASE_CONFIG)
	ensure(ta, agentv1.TargetPhase_TARGET_PHASE_NETWORK)
	if r := ensure(ta, agentv1.TargetPhase_TARGET_PHASE_CONTAINER); r.GetConfigSha256() != vsha {
		t.Fatalf("config_sha256 %s, ValidateConfig said %s", r.GetConfigSha256(), vsha)
	}
	waitHealthy(ta, "A first start")
	_, err = attach(ta)
	refused("EnsureEdgeAttachment before BootstrapPolicy", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE)
	if m := meta(ta); m["edge_attach"] != nil || m["noise_key_fingerprint"] != nil {
		t.Fatalf("a refused attachment wrote meta: %v", m)
	}
	if _, err := os.Stat(filepath.Join(ta.dir, "meta", "activated")); !errors.Is(err, fs.ErrNotExist) || slices.Contains(edgeNets(), ta.network()) {
		t.Fatal("a refused attachment activated or attached")
	}
	baseline := sha256Hex([]byte(templates.BootstrapPolicy))
	for range 2 {
		p, err := ac.BootstrapPolicy(ctx, &agentv1.BootstrapPolicyRequest{Instance: ta.ref, JobId: job(), Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL})
		if err != nil || p.GetPolicySha256() != baseline {
			t.Fatalf("BootstrapPolicy: %v %v (want %s)", p, err, baseline)
		}
	}
	var keys []string
	bootKey := func(keep string) *agentv1.BootstrapApiKeyResponse {
		t.Helper()
		r, err := ac.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{Instance: ta.ref, JobId: job(), Ttl: durationpb.New(24 * time.Hour), KeepPrefix: keep})
		if err != nil {
			t.Fatalf("BootstrapApiKey: %v", err)
		}
		if r.GetApiKey() != "" {
			keys = append(keys, r.GetApiKey())
		}
		return r
	}
	k1 := bootKey("")
	if !k1.GetCreated() || !strings.HasPrefix(k1.GetApiKey(), "hskey-api-"+k1.GetPrefix()+"-") || len(k1.GetPrefix()) != 12 ||
		k1.GetExpiresAt().AsTime().Sub(time.Now().Add(24*time.Hour)).Abs() > 2*time.Minute {
		t.Fatalf("first key: created %v prefix %q expires %v", k1.GetCreated(), k1.GetPrefix(), k1.GetExpiresAt().AsTime())
	}
	if k := bootKey(k1.GetPrefix()); k.GetCreated() || k.GetApiKey() != "" || k.GetExpiredKeys() != 0 {
		t.Fatalf("kept key: created %v expired %d", k.GetCreated(), k.GetExpiredKeys())
	}
	k2 := bootKey("")
	if !k2.GetCreated() || k2.GetExpiredKeys() != 1 || k2.GetPrefix() == k1.GetPrefix() {
		t.Fatalf("second key: created %v expired %d", k2.GetCreated(), k2.GetExpiredKeys())
	}
	valid := 0
	for _, k := range statusOf(ta, true).GetApiKeys() {
		if k.GetExpiration().AsTime().After(time.Now()) {
			valid++
			if k.GetPrefix() != k2.GetPrefix() {
				t.Fatalf("valid key %s", k.GetPrefix())
			}
		}
	}
	if valid != 1 {
		t.Fatalf("%d valid API keys", valid)
	}
	t.Logf("BootstrapPolicy: sha256 %s… (read back = baseline, set once); BootstrapApiKey: created, kept, expired-then-created", baseline[:12])

	// ---- 3. first attachment of A: fingerprint recorded = the instance's /key, activated, flag, exactly two members
	r := mustAttach(ta)
	if r.GetAlreadyAttached() {
		t.Fatal("already attached on the first attachment")
	}
	m := meta(ta)
	fpA, _ := m["noise_key_fingerprint"].(string)
	if m["edge_attach"] != true || len(fpA) != 64 {
		t.Fatalf("meta after the attachment: %v", m)
	}
	if st := statusOf(ta, false); !st.GetActivated() || !st.GetEdgeAttachFlag() || !st.GetNetwork().GetEdgeAttached() ||
		st.GetNoiseKeyFingerprint() != fpA || !slices.Equal(st.GetNetwork().GetMembers(), sortedStrings(edgeName, "mg-hs-"+ta.ref.GetSlug())) {
		t.Fatalf("status after the attachment: %v", st)
	}
	if pk := keyViaEdge(ta); pk != "mkey:"+fpA {
		t.Fatalf("the instance serves %s, the helper fingerprinted %s", pk, fpA)
	}
	if r := mustAttach(ta); !r.GetAlreadyAttached() {
		t.Fatal("second attachment not idempotent")
	}
	t.Logf("A attached: fingerprint %s… = publicKey of /key through the edge", fpA[:12])

	// ---- 4. B up, policy; alias hs-<B> already on another network of the edge ⇒ refused, nothing changed
	for _, p := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
		agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
		ensure(tb, p)
	}
	waitHealthy(tb, "B first start")
	if _, err := ac.BootstrapPolicy(ctx, &agentv1.BootstrapPolicyRequest{Instance: tb.ref, JobId: job(), Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL}); err != nil {
		t.Fatal(err)
	}
	aliasNet, impostor := e.prefix+"-alias", e.prefix+"-impostor"
	anr, err := dc.NetworkCreate(ctx, aliasNet, client.NetworkCreateOptions{Driver: "bridge", Internal: true,
		IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(e.nets[6])}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), anr.ID, client.NetworkRemoveOptions{}) })
	sleeper(impostor, aliasNet, &network.EndpointSettings{Aliases: []string{"hs-" + tb.ref.GetSlug()}})
	if _, err := dc.NetworkConnect(ctx, aliasNet, client.NetworkConnectOptions{Container: edgeName}); err != nil {
		t.Fatal(err)
	}
	pre := observe(t, dc, e.root)
	_, err = attach(tb)
	refused("alias hs-<slug> on another network of the edge", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_CONFLICT)
	if d := diff(pre, observe(t, dc, e.root)); len(d) != 0 || slices.Contains(edgeNets(), tb.network()) || meta(tb)["edge_attach"] != nil {
		t.Fatalf("the refused attachment touched the host: %v", d)
	}
	_, _ = dc.NetworkDisconnect(ctx, aliasNet, client.NetworkDisconnectOptions{Container: edgeName, Force: true})
	removeCtr(impostor)
	// a foreign member on B's network ⇒ refused
	sleeper(impostor, tb.network(), &network.EndpointSettings{})
	_, err = attach(tb)
	refused("foreign member on the tenant network", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT)
	if slices.Contains(edgeNets(), tb.network()) {
		t.Fatal("attached to a network with a foreign member")
	}
	removeCtr(impostor)
	t.Log("refused: alias collision (CONFLICT), foreign member (FOREIGN_OBJECT) — nothing changed")

	// ---- 5. the edge is recreated (new ID, its own network only): the supervisor re-attaches exactly the flagged A
	want := []string{edgeNet, ta.network()}
	sort.Strings(want)
	if got := edgeNets(); !slices.Equal(got, want) {
		t.Fatalf("edge networks before the recreation: %v", got)
	}
	removeCtr(edgeName)
	recreated := time.Now()
	newID := sleeper(edgeName, edgeNet, &network.EndpointSettings{GwPriority: 1})
	if newID == edgeID {
		t.Fatal("same container ID")
	}
	for !slices.Equal(edgeNets(), want) {
		if time.Since(recreated) > 3*interval+20*time.Second {
			t.Fatalf("not re-attached: %v (want %v)", edgeNets(), want)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("edge recreated: re-attached to exactly %v after %v (B, unflagged, not attached)", want, time.Since(recreated).Round(100*time.Millisecond))
	time.Sleep(2 * interval) // two more cycles: still exactly that set
	if got := edgeNets(); !slices.Equal(got, want) {
		t.Fatalf("edge networks after two more cycles: %v", got)
	}
	if pk := keyViaEdge(ta); pk != "mkey:"+fpA {
		t.Fatalf("A through the recreated edge: %s", pk)
	}
	if !strings.Contains(a.logs.String(), `"msg":"edge_recreated"`) {
		t.Fatal("no edge_recreated line")
	}

	// ---- 6. B attached, detached (flag first), never re-attached by the supervisor without the flag
	mustAttach(tb)
	det := func(x itTenant) *agentv1.RemoveEdgeAttachmentResponse {
		t.Helper()
		r, err := ac.RemoveEdgeAttachment(ctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: x.ref, JobId: job(),
			Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_QUARANTINE})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := det(tb); !r.GetWasAttached() || slices.Contains(edgeNets(), tb.network()) || meta(tb)["edge_attach"] != nil {
		t.Fatalf("detach: %v", r)
	}
	if r := det(tb); r.GetWasAttached() {
		t.Fatal("detach not idempotent")
	}
	time.Sleep(2 * interval)
	if slices.Contains(edgeNets(), tb.network()) {
		t.Fatal("the supervisor re-attached B without the flag")
	}
	mustAttach(tb)
	fpB, _ := meta(tb)["noise_key_fingerprint"].(string)

	// ---- 7. start guard through the RPCs (supervisor stopped: the RPC path contains on its own)
	stopSup()
	// 7a. B activated, data/ emptied ⇒ start refused, flag cleared, edge detached, Critical
	stopInstance(tb)
	savedB := dataFiles(t, tb.data())
	setData(t, tb.data(), nil, tb.uid)
	err = startInstance(tb)
	refused("start with an empty data/", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE)
	stB := statusOf(tb, false)
	if stB.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_EXITED || stB.GetEdgeAttachFlag() || stB.GetNetwork().GetEdgeAttached() ||
		slices.Contains(edgeNets(), tb.network()) || criticals(tb, "data_file_missing", "start") != 1 {
		t.Fatalf("empty data/: state %s flag %v edge %v criticals %d", stB.GetContainerState(), stB.GetEdgeAttachFlag(),
			stB.GetNetwork().GetEdgeAttached(), criticals(tb, "data_file_missing", "start"))
	}
	if len(dataFiles(t, tb.data())) != 0 {
		t.Fatal("Headscale ran on the empty data/ (a fresh key and database — RT-06)")
	}
	_, err = ac.EnsureInstance(ctx, &agentv1.EnsureInstanceRequest{Spec: tb.spec, TargetPhase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER, JobId: job()})
	refused("compose up with an empty data/", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE)
	setData(t, tb.data(), savedB, tb.uid)
	if err := startInstance(tb); err != nil {
		t.Fatal(err)
	}
	waitHealthy(tb, "B after data/ restored")
	mustAttach(tb)
	t.Log("start guard (RPC): empty data/ ⇒ refused, flag cleared, edge detached, Critical; restored ⇒ started and attached")
	// 7b. A activated, another Noise key ⇒ start refused, contained, Critical
	stopInstance(ta)
	savedA := dataFiles(t, ta.data())
	files := dataFiles(t, ta.data())
	files["noise_private.key"] = otherNoiseKey(t)
	setData(t, ta.data(), files, ta.uid)
	err = startInstance(ta)
	refused("start with another Noise key", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE)
	stA := statusOf(ta, false)
	if stA.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_EXITED || stA.GetEdgeAttachFlag() || slices.Contains(edgeNets(), ta.network()) ||
		criticals(ta, "fingerprint_mismatch", "start") != 1 || stA.GetNoiseKeyFingerprint() == fpA {
		t.Fatalf("another Noise key: state %s flag %v criticals %d", stA.GetContainerState(), stA.GetEdgeAttachFlag(), criticals(ta, "fingerprint_mismatch", "start"))
	}
	setData(t, ta.data(), savedA, ta.uid)
	if err := startInstance(ta); err != nil {
		t.Fatal(err)
	}
	waitHealthy(ta, "A after data/ restored")
	mustAttach(ta)
	t.Log("start guard (RPC): another Noise key ⇒ refused, flag cleared, edge detached, Critical; restored ⇒ started and attached")

	// ---- 8. start guard in the supervisor: within one cycle of a change under a running, attached instance
	startSup()
	time.Sleep(interval) // one quiet cycle first
	contained := func(x itTenant, reason string) time.Duration {
		t.Helper()
		start := time.Now()
		for {
			st := statusOf(x, false)
			if !st.GetEdgeAttachFlag() && !slices.Contains(edgeNets(), x.network()) && st.GetContainerState() == agentv1.ContainerState_CONTAINER_STATE_EXITED &&
				criticals(x, reason, "edge_supervisor") > 0 {
				return time.Since(start)
			}
			if time.Since(start) > interval+30*time.Second {
				t.Fatalf("%s not contained: flag %v edge %v state %s", x.ref.GetSlug(), st.GetEdgeAttachFlag(), slices.Contains(edgeNets(), x.network()), st.GetContainerState())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// 8a. data/db.sqlite removed under A
	if err := os.Remove(filepath.Join(ta.data(), "db.sqlite")); err != nil {
		t.Fatal(err)
	}
	t.Logf("supervisor: db.sqlite removed under running A ⇒ contained after %v (interval %v)", contained(ta, "data_file_missing").Round(100*time.Millisecond), interval)
	// 8b. the Noise key of B replaced
	kb := filepath.Join(tb.data(), "noise_private.key")
	if err := os.Remove(kb); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kb, otherNoiseKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(kb, tb.uid, tb.uid)
	t.Logf("supervisor: Noise key of running B replaced ⇒ contained after %v", contained(tb, "fingerprint_mismatch").Round(100*time.Millisecond))
	if slices.Contains(edgeNets(), ta.network()) || slices.Contains(edgeNets(), tb.network()) {
		t.Fatal("still attached")
	}
	// restored ⇒ start, re-attach (the fingerprint recorded at activation is still the reference)
	setData(t, ta.data(), savedA, ta.uid)
	setData(t, tb.data(), savedB, tb.uid)
	for _, x := range []itTenant{ta, tb} {
		if err := startInstance(x); err != nil {
			t.Fatal(err)
		}
		waitHealthy(x, x.ref.GetSlug()+" after the supervisor containment")
		mustAttach(x)
	}
	if meta(tb)["noise_key_fingerprint"] != fpB || meta(ta)["noise_key_fingerprint"] != fpA {
		t.Fatal("the recorded fingerprint changed")
	}
	stopSup()

	// ---- 9. the API keys never reached a log line; no helper container left; Critical events counted
	for _, k := range keys {
		if strings.Contains(a.logs.String(), k[len("hskey-api-")+13:]) || strings.Contains(a.logs.String(), k) {
			t.Fatal("an API key reached the agent log")
		}
	}
	if h := helpersLeft(); len(h) != 0 {
		t.Fatalf("helper containers left: %v", h)
	}
	crit := len(a.logs.lines(t, "start_guard_failed"))
	if crit < 4 {
		t.Fatalf("%d Critical events", crit)
	}

	// ---- 10. clean up as a deprovision would (detach first), then compare with the world before the test
	for _, x := range []itTenant{ta, tb} {
		if _, err := ac.RemoveEdgeAttachment(ctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: x.ref, JobId: job(),
			Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION}); err != nil {
			t.Fatal(err)
		}
		_, err := ac.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: x.ref, JobId: job(), Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED})
		refused("DELETE_IF_NEVER_ACTIVATED of an activated instance", err, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE)
		if r, err := ac.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: x.ref, JobId: job(), Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP}); err != nil ||
			!r.GetContainerRemoved() || !r.GetNetworkRemoved() {
			t.Fatalf("remove KEEP: %v %v", r, err)
		}
		if err := os.RemoveAll(x.dir); err != nil {
			t.Fatal(err)
		}
	}
	removeCtr(edgeName)
	_, _ = dc.NetworkRemove(ctx, enr.ID, client.NetworkRemoveOptions{})
	_, _ = dc.NetworkRemove(ctx, anr.ID, client.NetworkRemoveOptions{})
	for _, d := range diff(before, observe(t, dc, e.root)) {
		if !strings.HasPrefix(d, "+ path ") || strings.HasPrefix(d, "+ path tenants/") {
			t.Errorf("left behind or changed: %s", d)
		}
	}
	t.Logf("operations end to end: ok; %d Critical start-guard events; %d API keys created, none in the log; no helper container left", crit, len(keys))
}

func sortedStrings(s ...string) []string {
	sort.Strings(s)
	return s
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
