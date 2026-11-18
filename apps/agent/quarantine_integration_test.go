//go:build linux && dockerintegration

package main

// Integration test of the quarantine of an instance (P3-T18 — master §20 "Quarantine ⇒ hostname của tenant trả 404
// thống nhất, container dừng, data/ còn nguyên; reconcile không restart; … sau release instance qua start guard và
// post-start gate") on a real Docker Engine: a real agent (socket, token, guard, compose driver, edge supervisor every
// 2 s), real Headscale 0.29.7 instances and a real Caddy edge — [images.caddy], the Caddy of [images.mg-edge] — serving
// the TENANT SITE BLOCK OF THE PRODUCTION TEMPLATE (infrastructure/caddy/Caddyfile.tmpl, rendered by run.sh: the
// allow-list of paths, upstream hs-<label>.:8080 by Docker DNS, handle_errors 502/503/504 ⇒ 404), over plain HTTP on
// :8080 (the template's TLS, access log and listener binding are left out). The test drives the agent RPCs in the order
// the worker's jobs call them (internal/provisioning/quarantine): QuarantineInstance then GetInstanceStatus
// (instance.isolate, instance.verify); ReleaseInstance with the applied policy's sha256, EnsureEdgeAttachment and the
// post-start gate through the instance's own API with its API key (instance.release). No PostgreSQL, no worker: the
// registry side (approvals, step gate, schedules) is internal/provisioning/quarantine's DB tests.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)

const meshDomain = "mesh.agentit.test" // the domain run.sh renders the edge's tenant site for

var httpStatusRE = regexp.MustCompile(`HTTP/1\.[01] (\d{3})`)

// sumsOf is sha256 of every file of a directory (the test reads them as root; the agent never does).
func sumsOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: test
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(s[:])
	}
	return out
}

func TestQuarantineReleaseEndToEnd(t *testing.T) {
	e := itConfig(t)
	caddyImage, caddyfile := os.Getenv("MG_IT_CADDY"), os.Getenv("MG_IT_EDGE_CADDYFILE")
	if caddyImage == "" || caddyfile == "" {
		t.Fatal("MG_IT_CADDY and MG_IT_EDGE_CADDYFILE are required (tests/integration/agent/run.sh)")
	}
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
	edgeName, edgeNet := e.prefix+"-cedge", e.prefix+"-cedgenet"
	const interval = 2 * time.Second
	a := startIT(ctx, t, e, map[string]string{"MG_AGENT_EDGE_CONTAINER": edgeName, "MG_AGENT_EDGE_NETWORK": edgeNet,
		"MG_AGENT_EDGE_SUPERVISOR_INTERVAL": interval.String()})
	ac := a.client
	sup, ok := a.drv.(edgeSupervisor)
	if !ok {
		t.Fatal("the compose driver is not an edge supervisor")
	}
	sctx, stopSup := context.WithCancel(ctx)
	supDone := make(chan struct{})
	go func() { a.srv.superviseEdge(sctx, sup, interval); close(supDone) }()
	t.Cleanup(func() { stopSup(); <-supDone })
	job := func() string { return uuid.NewString() }

	// ---- the edge: Caddy with the production tenant site, on a bridge network with gw_priority 1 (like mg-edge)
	enr, err := dc.NetworkCreate(ctx, edgeNet, client.NetworkCreateOptions{Driver: "bridge",
		IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(e.nets[7])}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), enr.ID, client.NetworkRemoveOptions{}) })
	removeCtr := func(name string) {
		_, _ = dc.ContainerRemove(context.Background(), name, client.ContainerRemoveOptions{Force: true})
	}
	cr, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{Name: edgeName,
		Config: &container.Config{Image: caddyImage, Cmd: []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
			Labels: map[string]string{"meshguard.it": e.prefix}},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(edgeNet), ReadonlyRootfs: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}, Tmpfs: map[string]string{"/data": "", "/config": "", "/tmp": ""},
			Mounts: []mount.Mount{{Type: mount.TypeBind, Source: caddyfile, Target: "/etc/caddy/Caddyfile", ReadOnly: true}}},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{edgeNet: {GwPriority: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeCtr(edgeName) })
	if _, err := dc.ContainerStart(ctx, cr.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	// get is one request to the edge's tenant site (Host: <label>.mesh…), from inside the edge (the test has no network)
	get := func(label, path string, headers ...string) (int, []byte) {
		t.Helper()
		cmd := []string{"wget", "-S", "-q", "-O", "-", "-T", "5", "--header", "Host: " + label + "." + meshDomain}
		for _, h := range headers {
			cmd = append(cmd, "--header", h)
		}
		res, err := eng.Exec(ctx, edgeName, append(cmd, "http://127.0.0.1:8080"+path), 20*time.Second)
		if err != nil {
			t.Fatalf("GET %s%s through the edge: %v", label, path, err)
		}
		m := httpStatusRE.FindAllSubmatch(res.Stderr, -1)
		if len(m) == 0 {
			t.Fatalf("GET %s%s: no HTTP status (exit %d): %s", label, path, res.ExitCode, res.Stderr)
		}
		var code int
		_, _ = fmt.Sscanf(string(m[len(m)-1][1]), "%d", &code)
		return code, res.Stdout
	}
	// the edge serves: an unknown tenant is the uniform 404 of §14.6 (and the reference for it below)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		res, err := eng.Exec(ctx, edgeName, []string{"wget", "-S", "-q", "-O", "/dev/null", "-T", "2", "http://127.0.0.1:8080/"}, 10*time.Second)
		if err == nil && len(httpStatusRE.FindSubmatch(res.Stderr)) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	unknownCode, unknownBody := get("nosuchtenant-"+e.prefix, "/key?v=113")
	if unknownCode != 404 {
		t.Fatalf("unknown tenant through the edge: %d", unknownCode)
	}

	// ---- tenants A (quarantined) and B (bystander): provisioned and activated like §11.3 steps 7–14
	_, digest, _ := strings.Cut(e.image, "@")
	tenant := func(suffix string, uid int, cidr string) itTenant {
		ref := &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: e.prefix + "-q" + suffix}
		return itTenant{ref: ref, uid: uid, dir: filepath.Join(a.cfg.Host.TenantsDir, ref.GetInstanceId()),
			spec: &agentv1.InstanceSpec{Instance: ref, ImageDigest: digest, RunUid: uint32(uid), NetCidr: cidr, //nolint:gosec // G115: test
				Limits: &agentv1.ResourceLimits{MemoryMib: 256, CpuMillis: 500, Pids: 128},
				Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 990,
					PublicEntryIpv4: "192.0.2.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}}
	}
	ta, tb := tenant("a", 39921, e.nets[4]), tenant("b", 39922, e.nets[5])
	for _, x := range []itTenant{ta, tb} {
		t.Cleanup(func() {
			_, _ = ac.RemoveEdgeAttachment(context.Background(), &agentv1.RemoveEdgeAttachmentRequest{Instance: x.ref, JobId: job(),
				Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION})
			_, _ = ac.RemoveInstance(context.Background(), &agentv1.RemoveInstanceRequest{Instance: x.ref, JobId: job(),
				Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP})
			_ = os.RemoveAll(x.dir)
		})
	}
	statusOf := func(x itTenant) *agentv1.InstanceStatus {
		t.Helper()
		r, err := ac.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: x.ref})
		if err != nil {
			t.Fatalf("GetInstanceStatus(%s): %v", x.ref.GetSlug(), err)
		}
		return r.GetStatus()
	}
	waitHealthy := func(x itTenant) {
		t.Helper()
		start := time.Now()
		for time.Since(start) < 90*time.Second {
			if statusOf(x).GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: not healthy after 90 s", x.ref.GetSlug())
	}
	label := func(x itTenant) string { return x.ref.GetSlug() }
	keys := map[string]string{}
	for _, x := range []itTenant{ta, tb} {
		for _, p := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
			agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
			c, cancel := context.WithTimeout(ctx, 6*time.Minute)
			if _, err := ac.EnsureInstance(c, &agentv1.EnsureInstanceRequest{Spec: x.spec, TargetPhase: p, JobId: job()}); err != nil {
				cancel()
				t.Fatalf("EnsureInstance(%s, %s): %v", x.ref.GetSlug(), p, err)
			}
			cancel()
		}
		waitHealthy(x)
		if _, err := ac.BootstrapPolicy(ctx, &agentv1.BootstrapPolicyRequest{Instance: x.ref, JobId: job(),
			Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL}); err != nil {
			t.Fatal(err)
		}
		k, err := ac.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{Instance: x.ref, JobId: job(), Ttl: durationpb.New(24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		keys[x.ref.GetSlug()] = k.GetApiKey()
		if _, err := ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: x.ref, JobId: job()}); err != nil {
			t.Fatal(err)
		}
	}
	fpOf := func(x itTenant) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(x.dir, "meta", "instance.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		fp, _ := m["noise_key_fingerprint"].(string)
		return fp
	}
	serves := func(x itTenant, what string) {
		t.Helper()
		var code int
		var body []byte
		for i := 0; i < 20; i++ { // Docker DNS of a just-attached network
			if code, body = get(label(x), "/key?v=113"); code == 200 {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		var k struct {
			PublicKey string `json:"publicKey"`
		}
		if code != 200 || json.Unmarshal(body, &k) != nil || k.PublicKey != "mkey:"+fpOf(x) {
			t.Fatalf("%s: %s/key through the edge: %d %s (want 200 mkey:%s)", what, x.ref.GetSlug(), code, body, fpOf(x))
		}
	}
	uniform404 := func(x itTenant, what string) {
		t.Helper()
		for _, p := range []string{"/key?v=113", "/ts2021", "/derp/probe"} {
			code, body := get(label(x), p)
			if code != unknownCode || string(body) != string(unknownBody) {
				t.Fatalf("%s: %s%s through the edge: %d %q, want the uniform %d %q of an unknown tenant", what,
					x.ref.GetSlug(), p, code, body, unknownCode, unknownBody)
			}
		}
	}
	serves(ta, "A before")
	serves(tb, "B before")
	fpA := fpOf(ta)
	keysBefore := sumsOf(t, ta.data())
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
		return out
	}
	containerState := func(x itTenant) string {
		t.Helper()
		ci, err := dc.ContainerInspect(ctx, "mg-hs-"+x.ref.GetSlug(), client.ContainerInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return string(ci.Container.State.Status)
	}
	isolated := func(what string) {
		t.Helper()
		st := statusOf(ta)
		if !st.GetQuarantined() || st.GetEdgeAttachFlag() || st.GetNetwork().GetEdgeAttached() || slices.Contains(edgeNets(), ta.network()) ||
			containerState(ta) != "exited" {
			t.Fatalf("%s: A not isolated: quarantined %v flag %v edge %v state %s", what, st.GetQuarantined(), st.GetEdgeAttachFlag(),
				slices.Contains(edgeNets(), ta.network()), containerState(ta))
		}
		uniform404(ta, what)
		serves(tb, what+" (B)")
	}
	stateRefused := func(what string, err error) {
		t.Helper()
		r, ok := agentclient.RefusalOf(err)
		if status.Code(err) != codes.FailedPrecondition || !ok || r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_STATE {
			t.Fatalf("%s: %v, want STATE", what, err)
		}
	}

	// ---- 1. quarantine (instance.isolate + instance.verify): 404 like an unknown tenant, stopped, data/ intact
	start := time.Now()
	q, err := ac.QuarantineInstance(ctx, &agentv1.QuarantineInstanceRequest{Instance: ta.ref, JobId: job()})
	if err != nil || !q.GetMarkedNow() || !q.GetEdgeWasAttached() || !q.GetContainerWasRunning() {
		t.Fatalf("QuarantineInstance: %+v %v", q, err)
	}
	took := time.Since(start)
	isolated("quarantine")
	sumsQ := sumsOf(t, ta.data())
	for _, f := range []string{"noise_private.key", "derp_server_private.key"} {
		if sumsQ[f] != keysBefore[f] {
			t.Fatalf("%s changed by the quarantine", f)
		}
	}
	t.Logf("quarantine: isolated in %v — %s answers the uniform %d (= unknown tenant), container exited, B still served",
		took.Round(10*time.Millisecond), ta.ref.GetSlug(), unknownCode)

	// ---- 2. supervisor cycles and every way to restart or re-attach it: nothing changes, data/ byte for byte
	time.Sleep(3 * interval)
	isolated("three supervisor cycles")
	stateRefused("StartInstance", func() error {
		_, err := ac.StartInstance(ctx, &agentv1.StartInstanceRequest{Instance: ta.ref, JobId: job()})
		return err
	}())
	stateRefused("RestartInstance", func() error {
		_, err := ac.RestartInstance(ctx, &agentv1.RestartInstanceRequest{Instance: ta.ref, JobId: job()})
		return err
	}())
	stateRefused("EnsureInstance(container)", func() error {
		_, err := ac.EnsureInstance(ctx, &agentv1.EnsureInstanceRequest{Spec: ta.spec, TargetPhase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER, JobId: job()})
		return err
	}())
	stateRefused("EnsureEdgeAttachment", func() error {
		_, err := ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: ta.ref, JobId: job()})
		return err
	}())
	stateRefused("BootstrapApiKey", func() error {
		_, err := ac.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{Instance: ta.ref, JobId: job(), Ttl: durationpb.New(24 * time.Hour)})
		return err
	}())
	// the reads of reconcile (status, inventory) change nothing
	for range 3 {
		if _, err := ac.ListInstances(ctx, &agentv1.ListInstancesRequest{}); err != nil {
			t.Fatal(err)
		}
		statusOf(ta)
	}
	time.Sleep(interval)
	isolated("refused calls + reconcile reads")
	if got := sumsOf(t, ta.data()); !mapsEq(got, sumsQ) {
		t.Fatalf("data/ changed while quarantined: %v → %v", sumsQ, got)
	}
	t.Log("quarantined: 3 supervisor cycles, start/restart/compose up/attach/API key refused (STATE), reconcile reads — data/ checksums unchanged")
	// behind the agent's back: the container started and the edge connected by hand ⇒ contained again within a cycle
	if _, err := dc.ContainerStart(ctx, "mg-hs-"+ta.ref.GetSlug(), client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.NetworkConnect(ctx, ta.network(), client.NetworkConnectOptions{Container: edgeName}); err != nil {
		t.Fatal(err)
	}
	bypass := time.Now()
	for {
		st := statusOf(ta)
		if !st.GetNetwork().GetEdgeAttached() && containerState(ta) == "exited" && len(a.logs.lines(t, "quarantine_breach")) > 0 {
			break
		}
		if time.Since(bypass) > interval+30*time.Second {
			t.Fatalf("the bypass was not contained: edge %v state %s", st.GetNetwork().GetEdgeAttached(), containerState(ta))
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("bypass (docker start + network connect by hand) contained after %v; Critical quarantine_breach logged",
		time.Since(bypass).Round(100*time.Millisecond))
	isolated("after the bypass")
	for _, f := range []string{"noise_private.key", "derp_server_private.key"} {
		if sumsOf(t, ta.data())[f] != keysBefore[f] {
			t.Fatalf("%s changed", f)
		}
	}

	// ---- 3. release (instance.release): another policy ⇒ refused; another Noise key ⇒ the start guard refuses
	baseline := sha256Hex([]byte(templates.BootstrapPolicy))
	release := func(sha string) (*agentv1.ReleaseInstanceResponse, error) {
		c, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		return ac.ReleaseInstance(c, &agentv1.ReleaseInstanceRequest{Instance: ta.ref, JobId: job(), ExpectedPolicySha256: sha})
	}
	_, err = release(strings.Repeat("0", 64))
	stateRefused("release with another policy", err)
	isolated("refused release (policy)")
	key := filepath.Join(ta.data(), "noise_private.key")
	saved, err := os.ReadFile(key) //nolint:gosec // G304: test
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(key)
	if err := os.WriteFile(key, otherNoiseKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chown(key, ta.uid, ta.uid)
	_, err = release(baseline)
	stateRefused("release with another Noise key", err)
	if r, _ := agentclient.RefusalOf(err); !strings.Contains(r.GetMessage(), "start guard") {
		t.Fatalf("not refused by the start guard: %v", err)
	}
	isolated("refused release (start guard)")
	_ = os.Remove(key)
	if err := os.WriteFile(key, saved, 0o600); err != nil { //nolint:gosec // G703: test — the key read back from the test's own instance
		t.Fatal(err)
	}
	_ = os.Chown(key, ta.uid, ta.uid)
	t.Log("release refused for another policy and for another Noise key (start guard): still quarantined, stopped, 404")

	// ---- 4. release with the applied policy: start guard, healthy, policy; then the edge and the post-start gate
	rel, err := release(baseline)
	if err != nil || !rel.GetWasQuarantined() || rel.GetPolicySha256() != baseline {
		t.Fatalf("release: %+v %v", rel, err)
	}
	if st := statusOf(ta); st.GetQuarantined() || st.GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY || st.GetNetwork().GetEdgeAttached() {
		t.Fatalf("after ReleaseInstance: %+v", st)
	}
	uniform404(ta, "released, edge not attached yet") // the worker attaches only after the registry moved to starting
	if _, err := ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: ta.ref, JobId: job()}); err != nil {
		t.Fatal(err)
	}
	// the post-start gate of the worker, through the instance's API with its API key: accepted, the applied policy
	api := func(path string) (int, []byte) {
		t.Helper()
		res, err := eng.Exec(ctx, edgeName, []string{"wget", "-S", "-q", "-O", "-", "-T", "5", "--header",
			"Authorization: Bearer " + keys[ta.ref.GetSlug()], "http://hs-" + ta.ref.GetSlug() + ":8080" + path}, 20*time.Second)
		if err != nil {
			t.Fatalf("API %s: %v", path, err)
		}
		m := httpStatusRE.FindAllSubmatch(res.Stderr, -1)
		code := 0
		if len(m) > 0 {
			_, _ = fmt.Sscanf(string(m[len(m)-1][1]), "%d", &code)
		}
		return code, res.Stdout
	}
	if code, _ := api("/api/v1/health"); code != 200 {
		t.Fatalf("post-start gate: health %d", code)
	}
	code, body := api("/api/v1/policy")
	var pol struct {
		Policy string `json:"policy"`
	}
	if code != 200 || json.Unmarshal(body, &pol) != nil || sha256Hex([]byte(pol.Policy)) != baseline {
		t.Fatalf("post-start gate: policy %d sha %s (want %s)", code, sha256Hex([]byte(pol.Policy)), baseline)
	}
	serves(ta, "released")
	if fpOf(ta) != fpA {
		t.Fatal("the fingerprint changed across quarantine and release")
	}
	time.Sleep(2 * interval)
	serves(ta, "released, two supervisor cycles later")
	t.Logf("release: start guard + healthy + policy %s… on the agent, edge attached, post-start gate (API key accepted, GetPolicy = applied), /key 200 mkey:%s…",
		baseline[:12], fpA[:12])

	// ---- 5. clean up (detach first), compare with the world before the test
	stopSup()
	<-supDone
	for _, x := range []itTenant{ta, tb} {
		if _, err := ac.RemoveEdgeAttachment(ctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: x.ref, JobId: job(),
			Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION}); err != nil {
			t.Fatal(err)
		}
		if _, err := ac.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: x.ref, JobId: job(),
			Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP}); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(x.dir); err != nil {
			t.Fatal(err)
		}
	}
	removeCtr(edgeName)
	_, _ = dc.NetworkRemove(ctx, enr.ID, client.NetworkRemoveOptions{})
	for _, d := range diff(before, observe(t, dc, e.root)) {
		if !strings.HasPrefix(d, "+ path ") || strings.HasPrefix(d, "+ path tenants/") {
			t.Errorf("left behind or changed: %s", d)
		}
	}
	for _, k := range keys {
		if strings.Contains(a.logs.String(), k) {
			t.Fatal("an API key reached the agent log")
		}
	}
}

func mapsEq(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
