//go:build linux && dockerintegration

package main

// Integration test of the compose driver on a real Docker Engine (P3-T02). Not part of `go test ./...`: it needs the
// Docker socket and root, and runs INSIDE the agent image with the production hardening (network none, read-only
// rootfs, cap_drop ALL + CHOWN/FOWNER/DAC_OVERRIDE, no-new-privileges) — which is also the test of the agent's
// minimal capability set (§14.4). Entry point: tests/integration/agent/run.sh (`make agent-it`), which builds the
// image and this test binary, mounts the Docker socket and a temporary root at the same path inside and outside the
// container, and diffs `docker ps -a`, `docker network ls` and the root before/after.
//
// Environment (set by run.sh): MG_IT_ROOT (absolute, empty, same path on the host), MG_IT_IMAGE (the mg-headscale
// image of versions.lock, <repository>@sha256:<digest>), MG_IT_PREFIX (slug prefix), MG_IT_POOL (tenant pool of the
// test host, inside 10.250.240.0/20), MG_IT_NET (a /29 of it; the test uses it and the next three), MG_AGENT_COMPOSE_BIN.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
)

type itEnv struct {
	root, image, prefix, pool string
	nets                      [4]string // four consecutive /29 from MG_IT_NET: the tenant, then three negative cases
}

func itConfig(t *testing.T) itEnv {
	t.Helper()
	e := itEnv{root: os.Getenv("MG_IT_ROOT"), image: os.Getenv("MG_IT_IMAGE"), prefix: os.Getenv("MG_IT_PREFIX"), pool: os.Getenv("MG_IT_POOL")}
	base, err := netip.ParsePrefix(os.Getenv("MG_IT_NET"))
	if e.root == "" || e.image == "" || e.prefix == "" || e.pool == "" || err != nil || base.Bits() != 29 {
		t.Fatal("MG_IT_ROOT, MG_IT_IMAGE, MG_IT_PREFIX, MG_IT_POOL and MG_IT_NET (a /29) are required (tests/integration/agent/run.sh)")
	}
	a := base.Addr().As4()
	for i := range e.nets {
		b := a
		b[3] += byte(8 * i)
		e.nets[i] = netip.PrefixFrom(netip.AddrFrom4(b), 29).String()
	}
	if os.Geteuid() != 0 {
		t.Fatal("runs as root inside the agent image")
	}
	return e
}

// world is what the test may observe of the host: every container and network (ID, name, state, image) and every
// path under the test root (type, owner, mode, size — not mtimes of directories, which an entry added below changes).
type world struct {
	ctrs, nets map[string]string // name → description
	paths      map[string]string // relative path → description
}

func observe(t *testing.T, c *client.Client, root string) world {
	t.Helper()
	ctx := context.Background()
	w := world{ctrs: map[string]string{}, nets: map[string]string{}, paths: map[string]string{}}
	cl, err := c.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range cl.Items {
		w.ctrs[strings.TrimPrefix(s.Names[0], "/")] = fmt.Sprintf("%s %s %s %d", s.ID, s.State, s.Image, s.Created)
	}
	nl, err := c.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nl.Items {
		w.nets[n.Name] = n.ID
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		rel, _ := filepath.Rel(root, p)
		size := ""
		if fi.Mode().IsRegular() {
			size = fmt.Sprint(fi.Size())
		}
		w.paths[rel] = fmt.Sprintf("%v %d:%d %s", fi.Mode(), st.Uid, st.Gid, size)
		if d.IsDir() && d.Name() == "data" && filepath.Base(filepath.Dir(filepath.Dir(p))) == "tenants" {
			return filepath.SkipDir // the tenant's own files (Headscale writes its database at any time)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// diff lists what differs between two observations: added, removed or changed entries.
func diff(a, b world) []string {
	var out []string
	cmp := func(kind string, x, y map[string]string) {
		for k, v := range x {
			if w, ok := y[k]; !ok {
				out = append(out, "- "+kind+" "+k)
			} else if w != v {
				out = append(out, "~ "+kind+" "+k)
			}
		}
		for k := range y {
			if _, ok := x[k]; !ok {
				out = append(out, "+ "+kind+" "+k)
			}
		}
	}
	cmp("container", a.ctrs, b.ctrs)
	cmp("network", a.nets, b.nets)
	cmp("path", a.paths, b.paths)
	sort.Strings(out)
	return out
}

// fileSum is sha256 of a file the test reads as root (the agent itself never reads data/).
func fileSum(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: test
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestComposeDriverEndToEnd(t *testing.T) {
	e := itConfig(t)
	ctx := context.Background()
	dc, err := client.New(client.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()
	before := observe(t, dc, e.root)

	// ---- the test host: layout of /opt/meshguard under MG_IT_ROOT (root-owned like layout.sh), token, allowlist
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
	ac := h.dial(t, cfg.TokenFile)
	defer func() {
		if t.Failed() {
			t.Logf("agent log:\n%s", logs.String())
		}
	}()

	// ---- the throwaway tenant, typed parameters only
	_, digest, _ := strings.Cut(e.image, "@")
	slug := e.prefix + "-it"
	ref := &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: slug}
	spec := &agentv1.InstanceSpec{Instance: ref, ImageDigest: digest, RunUid: 39901, NetCidr: e.nets[0],
		Limits: &agentv1.ResourceLimits{MemoryMib: 256, CpuMillis: 500, Pids: 128},
		Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 990,
			PublicEntryIpv4: "192.0.2.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}
	idir := filepath.Join(cfg.Host.TenantsDir, ref.GetInstanceId())
	job := func() string { return uuid.NewString() }
	ensure := func(phase agentv1.TargetPhase) *agentv1.EnsureInstanceResponse {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 6*time.Minute)
		defer cancel()
		r, err := ac.EnsureInstance(c, &agentv1.EnsureInstanceRequest{Spec: spec, TargetPhase: phase, JobId: job()})
		if err != nil {
			t.Fatalf("EnsureInstance(%s): %v", phase, err)
		}
		return r
	}
	statusOf := func() *agentv1.InstanceStatus {
		t.Helper()
		r, err := ac.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
		if err != nil {
			t.Fatalf("GetInstanceStatus: %v", err)
		}
		return r.GetStatus()
	}
	// §11.3 step 11: the health gate polls the status, healthy within 90 s
	waitHealthy := func(what string) *agentv1.InstanceStatus {
		t.Helper()
		start := time.Now()
		for time.Since(start) < 90*time.Second {
			st := statusOf()
			if st.GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY {
				t.Logf("%s: healthy after %v", what, time.Since(start).Round(100*time.Millisecond))
				return st
			}
			if st.GetHealth() == agentv1.HealthState_HEALTH_STATE_UNHEALTHY {
				t.Fatalf("%s: unhealthy", what)
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: not healthy after 90 s", what)
		return nil
	}
	t.Cleanup(func() { // whatever happened: remove the tenant (best effort)
		_, _ = ac.RemoveInstance(context.Background(), &agentv1.RemoveInstanceRequest{Instance: ref, JobId: job(),
			Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED})
	})

	// ---- 1. storage → config → network → container, the throwaway tenant end to end
	resp := ensure(agentv1.TargetPhase_TARGET_PHASE_STORAGE)
	if resp.GetStatus().GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_ABSENT {
		t.Fatalf("storage: %v", resp)
	}
	for rel, want := range map[string]string{"": "drwxr-x--- 0:39901", "config": "drwxr-x--- 0:39901", "records": "drwxr-x--- 0:39901",
		"meta": "drwx------ 0:0", "data": "drwx------ 39901:39901", "meta/instance.json": "-r-------- 0:0"} {
		fi, err := os.Lstat(filepath.Join(idir, rel))
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if got := fmt.Sprintf("%v %d:%d", fi.Mode().Perm()|fi.Mode()&fs.ModeDir, st.Uid, st.Gid); !strings.HasPrefix(got, strings.Fields(want)[0]) ||
			!strings.HasSuffix(got, strings.Fields(want)[1]) {
			t.Errorf("%s: %s, want %s", rel, got, want)
		}
	}
	resp = ensure(agentv1.TargetPhase_TARGET_PHASE_CONFIG)
	if len(resp.GetConfigSha256()) != 64 || resp.GetTemplateVersion() != 1 {
		t.Fatalf("config: %v", resp)
	}
	ensure(agentv1.TargetPhase_TARGET_PHASE_NETWORK)
	ni, err := dc.NetworkInspect(ctx, "mg-t-"+slug, client.NetworkInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := ni.Network; !n.Internal || len(n.IPAM.Config) != 1 || n.IPAM.Config[0].Subnet != netip.MustParsePrefix(e.nets[0]) ||
		n.Labels["meshguard.instance_id"] != ref.GetInstanceId() || n.Labels["meshguard.role"] != "tenant" || n.Driver != "bridge" {
		t.Fatalf("network %+v", n)
	}
	resp = ensure(agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	st := waitHealthy("first start")
	if st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING || st.GetImageDigest() != digest ||
		st.GetConfigSha256() != resp.GetConfigSha256() || !st.GetNetwork().GetExists() || st.GetNetwork().GetSubnet() != e.nets[0] ||
		!slices.Equal(st.GetNetwork().GetMembers(), []string{"mg-hs-" + slug}) || st.GetNetwork().GetEdgeAttached() {
		t.Fatalf("status %v", st)
	}
	ci, err := dc.ContainerInspect(ctx, "mg-hs-"+slug, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := ci.Container
	if c.Config.User != "39901:39901" || !c.HostConfig.ReadonlyRootfs || !slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) ||
		len(c.HostConfig.CapAdd) != 0 || c.HostConfig.Privileged || len(c.HostConfig.PortBindings) != 0 ||
		c.Config.Labels["meshguard.instance_id"] != ref.GetInstanceId() || c.Config.Labels["com.docker.compose.project"] != "mg-t-"+slug ||
		len(c.NetworkSettings.Networks) != 1 || c.Config.Image != e.image {
		t.Fatalf("container hardening/labels: user %q ro %v capdrop %v capadd %v ports %v nets %d image %s", c.Config.User,
			c.HostConfig.ReadonlyRootfs, c.HostConfig.CapDrop, c.HostConfig.CapAdd, c.HostConfig.PortBindings, len(c.NetworkSettings.Networks), c.Config.Image)
	}
	if ep := c.NetworkSettings.Networks["mg-t-"+slug]; ep == nil || !slices.Contains(ep.Aliases, "hs-"+slug) {
		t.Fatalf("alias hs-%s missing on mg-t-%s: %+v", slug, slug, ep)
	}
	// the guard's view of Docker (P3-T03's alias check) sees the alias through the container list
	nets, err := inv.Networks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nets {
		if n.Name == "mg-t-"+slug && (len(n.Members) != 1 || !slices.Contains(n.Members[0].Aliases, "hs-"+slug)) {
			t.Fatalf("inventory of mg-t-%s: %+v", slug, n.Members)
		}
	}
	// Headscale wrote its keys and database into data/, owned by run_uid
	noise := filepath.Join(idir, "data", "noise_private.key")
	for _, f := range []string{noise, filepath.Join(idir, "data", "db.sqlite")} {
		fi, err := os.Lstat(f)
		if err != nil || fi.Sys().(*syscall.Stat_t).Uid != 39901 {
			t.Fatalf("%s: %v", f, err)
		}
	}
	noiseSum := fileSum(t, noise)
	// nothing outside the instance's directory, network and project was touched
	running := observe(t, dc, e.root)
	for _, d := range diff(before, running) {
		ok := d == "+ container mg-hs-"+slug || d == "+ network mg-t-"+slug ||
			strings.HasPrefix(d, "+ path tenants") || strings.HasPrefix(d, "+ path backups") || strings.HasPrefix(d, "+ path run") ||
			strings.HasPrefix(d, "+ path cfg")
		if !ok {
			t.Errorf("unexpected change while the tenant runs: %s", d)
		}
		if p, isPath := strings.CutPrefix(d, "+ path "); isPath && strings.HasPrefix(p, "tenants/") && !strings.HasPrefix(p, "tenants/"+ref.GetInstanceId()) {
			t.Errorf("path outside the instance directory: %s", p)
		}
	}

	// ---- 2. idempotency: every call again changes nothing
	snap := func() string {
		w := observe(t, dc, e.root)
		var b strings.Builder
		for _, m := range []map[string]string{w.ctrs, w.nets, w.paths} {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "%s %s\n", k, m[k])
			}
		}
		_ = filepath.WalkDir(idir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !strings.Contains(p, "/data") {
				fi, _ := os.Lstat(p)
				fmt.Fprintf(&b, "%s ino=%d mtime=%s\n", p, fi.Sys().(*syscall.Stat_t).Ino, fi.ModTime().Format(time.RFC3339Nano))
			}
			return nil
		})
		s := statusOf()
		fmt.Fprintf(&b, "container %s started %s\n", s.GetContainerId(), s.GetStartedAt().AsTime())
		return b.String()
	}
	s1 := snap()
	for round := range 2 {
		for _, p := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
			agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
			ensure(p)
		}
		if _, err := ac.ListInstances(ctx, &agentv1.ListInstancesRequest{}); err != nil {
			t.Fatal(err)
		}
		if s2 := snap(); s2 != s1 {
			t.Fatalf("round %d of repeated calls changed the host:\n--- before\n%s\n--- after\n%s", round+1, s1, s2)
		}
	}
	t.Log("idempotent: 2 rounds × 4 EnsureInstance phases + status + inventory, host unchanged (inodes, mtimes, container, network)")

	// ---- 3. stop / start / restart (each twice where idempotent)
	call := func(name string, f func() (*agentv1.InstanceStatus, error), want agentv1.ContainerState) *agentv1.InstanceStatus {
		t.Helper()
		st, err := f()
		if err != nil || st.GetContainerState() != want {
			t.Fatalf("%s: %v %v", name, st.GetContainerState(), err)
		}
		return st
	}
	stop := func() (*agentv1.InstanceStatus, error) {
		r, err := ac.StopInstance(ctx, &agentv1.StopInstanceRequest{Instance: ref, JobId: job()})
		return r.GetStatus(), err
	}
	startI := func() (*agentv1.InstanceStatus, error) {
		r, err := ac.StartInstance(ctx, &agentv1.StartInstanceRequest{Instance: ref, JobId: job()})
		return r.GetStatus(), err
	}
	restart := func() (*agentv1.InstanceStatus, error) {
		r, err := ac.RestartInstance(ctx, &agentv1.RestartInstanceRequest{Instance: ref, JobId: job()})
		return r.GetStatus(), err
	}
	id0 := statusOf().GetContainerId()
	call("stop", stop, agentv1.ContainerState_CONTAINER_STATE_EXITED)
	call("stop again", stop, agentv1.ContainerState_CONTAINER_STATE_EXITED)
	call("start", startI, agentv1.ContainerState_CONTAINER_STATE_RUNNING)
	call("start again", startI, agentv1.ContainerState_CONTAINER_STATE_RUNNING)
	st = waitHealthy("start")
	started := st.GetStartedAt().AsTime()
	st = call("restart", restart, agentv1.ContainerState_CONTAINER_STATE_RUNNING)
	if !st.GetStartedAt().AsTime().After(started) || st.GetContainerId() != id0 {
		t.Fatalf("restart: started %v (was %v), container %s (was %s)", st.GetStartedAt().AsTime(), started, st.GetContainerId(), id0)
	}
	waitHealthy("restart")

	// ---- 4. remove keeping data, again, then converge back from "directory without container and network"
	remove := func(d agentv1.DataDisposition) *agentv1.RemoveInstanceResponse {
		t.Helper()
		r, err := ac.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: ref, JobId: job(), Data: d})
		if err != nil {
			t.Fatalf("RemoveInstance(%s): %v", d, err)
		}
		return r
	}
	if r := remove(agentv1.DataDisposition_DATA_DISPOSITION_KEEP); !r.GetContainerRemoved() || !r.GetNetworkRemoved() || r.GetDirectoryRemoved() {
		t.Fatalf("remove KEEP: %v", r)
	}
	if r := remove(agentv1.DataDisposition_DATA_DISPOSITION_KEEP); r.GetContainerRemoved() || r.GetNetworkRemoved() || r.GetDirectoryRemoved() {
		t.Fatalf("remove KEEP again: %v", r)
	}
	if _, err := dc.ContainerInspect(ctx, "mg-hs-"+slug, client.ContainerInspectOptions{}); err == nil {
		t.Fatal("container still exists")
	}
	if _, err := dc.NetworkInspect(ctx, "mg-t-"+slug, client.NetworkInspectOptions{}); err == nil {
		t.Fatal("network still exists")
	}
	if fileSum(t, noise) != noiseSum {
		t.Fatal("KEEP changed data/")
	}
	ensure(agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	waitHealthy("converged from directory only")
	if fileSum(t, noise) != noiseSum {
		t.Fatal("the Noise key changed: data/ was not kept across remove KEEP + ensure")
	}

	// ---- 5. negative: objects with a derived name that are not this instance's are refused, never touched
	foreign := func(name string, err error) {
		t.Helper()
		r, ok := agentclient.RefusalOf(err)
		if status.Code(err) != codes.FailedPrecondition || !ok || r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT {
			t.Fatalf("%s: %v, want FOREIGN_OBJECT", name, err)
		}
	}
	other := func(slug, cidr string) *agentv1.InstanceSpec {
		s := &agentv1.InstanceSpec{Instance: &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: slug},
			ImageDigest: digest, RunUid: 39902, NetCidr: cidr, Limits: spec.GetLimits(), Headscale: spec.GetHeadscale()}
		return s
	}
	negNet, negCtr, negBare := e.prefix+"-neg", e.prefix+"-neg2", e.prefix+"-neg3"
	nr, err := dc.NetworkCreate(ctx, "mg-t-"+negNet, client.NetworkCreateOptions{Driver: "bridge", Internal: true,
		IPAM:   &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(e.nets[1])}}},
		Labels: map[string]string{"meshguard.instance_id": uuid.NewString(), "meshguard.role": "tenant"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), nr.ID, client.NetworkRemoveOptions{}) })
	br, err := dc.NetworkCreate(ctx, "mg-t-"+negBare, client.NetworkCreateOptions{Driver: "bridge", Internal: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), br.ID, client.NetworkRemoveOptions{}) })
	cr, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{Name: "mg-hs-" + negCtr,
		Config:     &container.Config{Image: e.image, Cmd: []string{"version"}, User: "39903:39903"},
		HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = dc.ContainerRemove(context.Background(), cr.ID, client.ContainerRemoveOptions{Force: true})
	})
	preNeg := observe(t, dc, e.root)
	for _, c := range []struct {
		name string
		spec *agentv1.InstanceSpec
	}{
		{"network of another instance with the derived name", other(negNet, e.nets[1])},
		{"unlabelled network with the derived name", other(negBare, e.nets[2])},
		{"unlabelled container with the derived name", other(negCtr, e.nets[3])},
	} {
		for _, p := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
			_, err := ac.EnsureInstance(ctx, &agentv1.EnsureInstanceRequest{Spec: c.spec, TargetPhase: p, JobId: job()})
			foreign(c.name, err)
		}
		_, err := ac.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: c.spec.GetInstance(), JobId: job(),
			Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED})
		foreign(c.name+" (remove)", err)
	}
	if d := diff(preNeg, observe(t, dc, e.root)); len(d) != 0 {
		t.Fatalf("refused calls touched the host: %v", d)
	}

	// ---- 6. remove deleting data (never activated), again; nothing of the tenant is left
	if r := remove(agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED); !r.GetContainerRemoved() || !r.GetNetworkRemoved() || !r.GetDirectoryRemoved() {
		t.Fatalf("remove DELETE_IF_NEVER_ACTIVATED: %v", r)
	}
	if r := remove(agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED); r.GetContainerRemoved() || r.GetNetworkRemoved() || r.GetDirectoryRemoved() {
		t.Fatalf("remove again: %v", r)
	}
	list, err := ac.ListInstances(ctx, &agentv1.ListInstancesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range list.GetInstances() {
		if en.GetInstanceId() == ref.GetInstanceId() {
			t.Fatalf("still in the inventory: %v", en)
		}
	}
	// back to the world before the test (but the three foreign objects, removed by their cleanup)
	_, _ = dc.ContainerRemove(ctx, cr.ID, client.ContainerRemoveOptions{Force: true})
	_, _ = dc.NetworkRemove(ctx, nr.ID, client.NetworkRemoveOptions{})
	_, _ = dc.NetworkRemove(ctx, br.ID, client.NetworkRemoveOptions{})
	after := observe(t, dc, e.root)
	for _, d := range diff(before, after) {
		if !strings.HasPrefix(d, "+ path ") || strings.HasPrefix(d, "+ path tenants/") {
			t.Errorf("left behind or changed: %s", d)
		}
	}
	if entries, _ := os.ReadDir(cfg.Host.TenantsDir); len(entries) != 0 {
		t.Fatalf("tenants directory not empty: %v", entries)
	}
	refusedLines := 0
	for _, line := range logs.lines(t, "agent_call") {
		if line["outcome"] == "refused" {
			refusedLines++
		}
	}
	t.Logf("end to end: ok; %d refused calls audited; the throwaway tenant, its network and its directory are gone", refusedLines)
}
