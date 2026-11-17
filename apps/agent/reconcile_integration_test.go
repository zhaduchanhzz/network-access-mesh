//go:build linux && dockerintegration

package main

// Integration test of the report-only reconcile (P3-T12) on a real Docker Engine, through a real agent (socket, token,
// guard, compose driver) and the worker's client — same harness as TestComposeDriverEndToEnd (tests/integration/agent/
// run.sh). A throwaway tenant is created; a foreign network and a foreign container labelled meshguard.instance_id are
// created BY HAND (Engine API, as an operator or an intruder would); reconcile then reports them — and the drift of the
// tenant against a desired state that differs — and the host is exactly as it was: nothing adopted, nothing changed,
// nothing removed; the agent's audit shows reads only.

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
)

func TestReconcileReportsForeignObjectsUntouched(t *testing.T) {
	e := itConfig(t)
	ctx := context.Background()
	dc, err := client.New(client.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()

	// ---- a real agent under <root>/rec (its own tenants directory, socket and token)
	base := filepath.Join(e.root, "rec")
	for _, d := range []string{"", "tenants", "backups", "backups/tenants", "run", "cfg"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	write(t, filepath.Join(base, "cfg", "token"), token, 0o440)
	write(t, filepath.Join(base, "cfg", "allowlist"), "# test allowlist\n"+e.image+"\n", 0o644)
	env := map[string]string{
		"MG_ENV": "ci", "MG_LOG_LEVEL": "debug", "MG_AGENT_SOCKET": filepath.Join(base, "run", "agent.sock"),
		"MG_AGENT_SOCKET_GID": "20003", "MG_AGENT_PEER_UIDS": "65532",
		"MG_AGENT_TOKEN_FILE": filepath.Join(base, "cfg", "token"), "MG_AGENT_IMAGE_ALLOWLIST_FILE": filepath.Join(base, "cfg", "allowlist"),
		"MG_AGENT_TENANTS_DIR": filepath.Join(base, "tenants"), "MG_AGENT_BACKUPS_DIR": filepath.Join(base, "backups", "tenants"),
		"MG_AGENT_RUN_UID_RANGE": "30000-39999", "MG_AGENT_TENANT_NET_POOL": e.pool, "MG_AGENT_PUBLIC_ENTRY_IPV4": "192.0.2.10",
		"MG_BASE_DOMAIN": "agentit.test", "MG_AGENT_COMPOSE_BIN": os.Getenv("MG_AGENT_COMPOSE_BIN"), "MG_AGENT_LOCK_WAIT": "10s",
	}
	if env["MG_AGENT_COMPOSE_BIN"] == "" {
		env["MG_AGENT_COMPOSE_BIN"] = "/usr/local/bin/docker-compose"
	}
	cfg, err := LoadConfig(getenv(env), environ(env))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cfg.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	cfg.PeerUIDs, cfg.SocketGID = []uint32{0}, -1
	logs := &syncBuffer{}
	h := &harness{logs: logs, cfg: cfg, sock: cfg.Socket, tenants: cfg.Host.TenantsDir}
	drv, inv, err := buildDriver(ctx, cfg, h.logger())
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(cfg, tok, drv, inv, h.logger())
	l, err := listenUnix(ctx, cfg.Socket, -1)
	if err != nil {
		t.Fatal(err)
	}
	gs := srv.grpcServer(cfg)
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	ac := h.dial(t, cfg.TokenFile)
	defer func() {
		if t.Failed() {
			t.Logf("agent log:\n%s", logs.String())
		}
	}()

	// ---- the throwaway tenant, up to a healthy container
	_, digest, _ := strings.Cut(e.image, "@")
	slug := e.prefix + "-rec"
	ref := &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: slug}
	spec := &agentv1.InstanceSpec{Instance: ref, ImageDigest: digest, RunUid: 39911, NetCidr: e.nets[0],
		Limits: &agentv1.ResourceLimits{MemoryMib: 256, CpuMillis: 500, Pids: 128},
		Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 990,
			PublicEntryIpv4: "192.0.2.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}
	t.Cleanup(func() {
		_, _ = ac.RemoveInstance(context.Background(), &agentv1.RemoveInstanceRequest{Instance: ref, JobId: uuid.NewString(),
			Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED})
	})
	var cfgSum string
	for _, p := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
		agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
		c, cancel := context.WithTimeout(ctx, 6*time.Minute)
		r, err := ac.EnsureInstance(c, &agentv1.EnsureInstanceRequest{Spec: spec, TargetPhase: p, JobId: uuid.NewString()})
		cancel()
		if err != nil {
			t.Fatalf("EnsureInstance(%s): %v", p, err)
		}
		if r.GetConfigSha256() != "" {
			cfgSum = r.GetConfigSha256()
		}
	}
	for start := time.Now(); ; time.Sleep(time.Second) {
		r, err := ac.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
		if err == nil && r.GetStatus().GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY {
			break
		}
		if time.Since(start) > 90*time.Second {
			t.Fatalf("not healthy: %v %v", r, err)
		}
	}

	// ---- created by hand: a labelled network and a labelled container that no registry row knows
	ghostNet, ghostCtr := uuid.NewString(), uuid.NewString()
	nr, err := dc.NetworkCreate(ctx, "mg-t-"+e.prefix+"-ghost", client.NetworkCreateOptions{Driver: "bridge", Internal: true,
		IPAM:   &network.IPAM{Config: []network.IPAMConfig{{Subnet: itPrefix(t, e.nets[1])}}},
		Labels: map[string]string{"meshguard.instance_id": ghostNet, "meshguard.role": "tenant"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), nr.ID, client.NetworkRemoveOptions{}) })
	cr, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{Name: "mg-hs-" + e.prefix + "-ghost",
		Config: &container.Config{Image: e.image, Cmd: []string{"version"}, User: "39912:39912",
			Labels: map[string]string{"meshguard.instance_id": ghostCtr, "meshguard.tenant_id": uuid.NewString(),
				"com.docker.compose.project": "mg-t-" + e.prefix + "-ghost2"}},
		HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = dc.ContainerRemove(context.Background(), cr.ID, client.ContainerRemoveOptions{Force: true})
	})

	// ---- reconcile (report only) through the worker's client
	before := ownWorld(t, dc, e)
	callsBefore := len(logs.lines(t, "agent_call"))
	in := &reconcile.Inspector{Agent: ac, AgentTimeout: time.Minute} // AgentUID/GID 0: the agent runs as root here
	d := reconcile.Desired{InstanceID: uuid.MustParse(ref.GetInstanceId()), TenantID: uuid.MustParse(ref.GetTenantId()), Slug: slug,
		Status: "running", ImageDigest: digest, NetCIDR: itPrefix(t, e.nets[0]), RunUID: 39911, ConfigSHA256: cfgSum}
	rep, evs := in.Instance(ctx, d)
	// no edge in this test: edge_not_attached is the only finding; every agent check ran against real Docker
	if k := rep.Kinds(); len(rep.Findings) != 1 || k[reconcile.DriftEdgeDetached] != 1 || len(evs) != 0 {
		t.Fatalf("tenant as provisioned: %+v", rep)
	}
	for _, c := range rep.Checks {
		if c.Name == reconcile.CheckPaths && (c.Outcome != reconcile.OutcomeOK || c.Note != "paths=10") {
			t.Errorf("paths check %+v", c)
		}
	}
	// the registry wants another image and another config: reported, with a security event for the digest
	wrong := d
	wrong.ImageDigest, wrong.ConfigSHA256 = "sha256:"+strings.Repeat("b", 64), strings.Repeat("d", 64)
	rep, evs = in.Instance(ctx, wrong)
	if k := rep.Kinds(); k[reconcile.DriftImageDigest] != 1 || k[reconcile.DriftConfigHash] != 1 || len(evs) != 1 ||
		evs[0].Kind != "reconcile.image_digest_mismatch" {
		t.Fatalf("drift against the registry: %+v (%d events)", rep.Findings, len(evs))
	}
	// the host: both hand-made objects are unknown instances (other agents' objects on a shared host may add more)
	regs := []reconcile.Registered{{InstanceID: d.InstanceID, TenantID: d.TenantID, Slug: slug, Status: "running"}}
	host, hevs := in.Host(ctx, regs)
	unknown := map[string][]string{}
	for _, f := range host.Findings {
		if f.Kind == reconcile.DriftUnknownInstance {
			unknown[f.Subject] = f.Items
		}
		if f.Subject == d.InstanceID.String() {
			t.Errorf("the tenant itself reported: %+v", f)
		}
	}
	if !slices.Equal(unknown[ghostNet], []string{"network"}) || !slices.Equal(unknown[ghostCtr], []string{"container"}) {
		t.Fatalf("hand-made objects not reported as unknown: %v\n%+v", unknown, host)
	}
	nEvents := 0
	for _, ev := range hevs {
		if ev.Kind == "reconcile.unknown_instance" && (ev.Details["instance_id"] == ghostNet || ev.Details["instance_id"] == ghostCtr) {
			nEvents++
		}
	}
	if nEvents != 2 {
		t.Errorf("security events for the hand-made objects: %d, want 2", nEvents)
	}

	// ---- nothing adopted, changed or removed; the agent saw reads only
	if dd := diff(before, ownWorld(t, dc, e)); len(dd) != 0 {
		t.Fatalf("reconcile changed the host: %v", dd)
	}
	calls := logs.lines(t, "agent_call")[callsBefore:]
	for _, c := range calls {
		if m := c["method"]; m != "GetInstanceStatus" && m != "ListInstances" {
			t.Errorf("reconcile called %v", m)
		}
	}
	if len(calls) != 3 {
		t.Errorf("%d agent calls during reconcile, want 3 (two statuses, one inventory)", len(calls))
	}
	if ni, err := dc.NetworkInspect(ctx, "mg-t-"+e.prefix+"-ghost", client.NetworkInspectOptions{}); err != nil ||
		ni.Network.Labels["meshguard.instance_id"] != ghostNet {
		t.Errorf("the hand-made network changed: %v", err)
	}
	t.Logf("reconcile: tenant drift %v; host: %d findings (%d unknown instances, both hand-made objects among them); "+
		"%d agent calls, all reads; host unchanged", rep.Kinds(), len(host.Findings), len(unknown), len(calls))

	// cleanup through the API like the end-to-end test (the tenant was never activated)
	if _, err := ac.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: ref, JobId: uuid.NewString(),
		Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED}); err != nil {
		t.Fatalf("remove: %v", err)
	}
}

func itPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ownWorld is the part of the host this test owns: its containers and networks (names derived from the prefix — other
// agents may run tests on the same Docker host at the same time) and every path under the test root.
func ownWorld(t *testing.T, dc *client.Client, e itEnv) world {
	t.Helper()
	w := observe(t, dc, e.root)
	for name := range w.ctrs {
		if !strings.HasPrefix(name, "mg-hs-"+e.prefix+"-") {
			delete(w.ctrs, name)
		}
	}
	for name := range w.nets {
		if !strings.HasPrefix(name, "mg-t-"+e.prefix+"-") {
			delete(w.nets, name)
		}
	}
	return w
}
