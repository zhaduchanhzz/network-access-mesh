//go:build linux

package compose

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// needRoot: the driver chowns to run_uid (CAP_CHOWN). CI and the build VM run the tests as root.
func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("the storage tests need root (chown to run_uid)")
		}
		t.Skip("needs root: chown to run_uid")
	}
}

type rig struct {
	d    *Driver
	e    *fakeEngine
	r    *fakeCompose
	h    *agentspec.Host
	s    agentspec.InstanceSpec
	g    *agentspec.Guard
	dir  string // tenants directory
	idir string // instance directory
	logs *logBuf
}

func newRig(t *testing.T) *rig {
	t.Helper()
	needRoot(t)
	dir := t.TempDir()
	h, s := testSpec(t, dir)
	e := newFakeEngine()
	g := &agentspec.Guard{Host: h, Inventory: NewInventory(e), Edge: "mg-edge"}
	r := &fakeCompose{e: e}
	logs := &logBuf{}
	d, err := New(Config{Host: h, Guard: g, AgentGID: os.Getegid(), Engine: e, Compose: r, Edge: "mg-edge", HelperImage: testHelperImage,
		Log: logx.New(logs, slog.LevelDebug, "agent")})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{d: d, e: e, r: r, h: h, s: s, g: g, dir: dir, idir: filepath.Join(dir, s.Ref.InstanceID.String()), logs: logs}
}

func (rg *rig) ensure(t *testing.T, phase agentv1.TargetPhase) *agentv1.EnsureInstanceResponse {
	t.Helper()
	// the server's path: guard first, then the driver
	if err := rg.g.CheckSpec(context.Background(), rg.s); err != nil {
		t.Fatalf("guard: %v", err)
	}
	resp, err := rg.d.EnsureInstance(context.Background(), agentspec.Ensure{Spec: rg.s, Phase: phase, JobID: uuid.New()})
	if err != nil {
		t.Fatalf("EnsureInstance(%s): %v", phase, err)
	}
	return resp
}

func (rg *rig) call() agentspec.Call { return agentspec.Call{Ref: rg.s.Ref, JobID: uuid.New()} }

func reason(err error) agentv1.RefusalReason {
	if r, ok := agentspec.AsRefusal(err); ok {
		return r.Reason
	}
	return 0
}

// snapshot is the observable state of the host for one instance: every path under the tenants directory with
// owner, mode, inode, size and mtime; every network and container with its ID and state.
func (rg *rig) snapshot(t *testing.T) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(rg.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		rel, _ := filepath.Rel(rg.dir, p)
		lines = append(lines, strings.Join([]string{rel, fi.Mode().String(), strconv.Itoa(int(st.Uid)), strconv.Itoa(int(st.Gid)),
			strconv.FormatUint(st.Ino, 10), strconv.FormatInt(fi.Size(), 10), fi.ModTime().Format(time.RFC3339Nano)}, " "))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctrs, _ := rg.e.Containers(context.Background())
	for _, c := range ctrs {
		lines = append(lines, "ctr "+c.Name+" "+c.ID+" "+c.State+" "+c.StartedAt.String())
	}
	nets, _ := rg.e.Networks(context.Background())
	for _, n := range nets {
		lines = append(lines, "net "+n.Name+" "+n.ID)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func ownerMode(t *testing.T, p string) (int, int, fs.FileMode) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid), fi.Mode()
}

// TestEnsureInstanceLayout: the layout of §14.2 / tenant-deploy.sh after each phase — directories root-owned
// (0750/0700), only data/ owned by run_uid, files root:run_gid 0440 (compose.yaml root:root 0440, meta 0400), the
// network internal with the /29 and the two labels, the container of the project with this instance's labels.
func TestEnsureInstanceLayout(t *testing.T) {
	rg := newRig(t)
	run := int(rg.s.RunUID)
	resp := rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_STORAGE)
	if resp.GetConfigSha256() != "" || resp.GetStatus().GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_ABSENT {
		t.Fatalf("storage phase response %v", resp)
	}
	want := map[string]struct {
		uid, gid int
		mode     fs.FileMode
	}{
		"":                   {0, run, fs.ModeDir | 0o750},
		"config":             {0, run, fs.ModeDir | 0o750},
		"records":            {0, run, fs.ModeDir | 0o750},
		"meta":               {0, 0, fs.ModeDir | 0o700},
		"data":               {run, run, fs.ModeDir | 0o700},
		"meta/instance.json": {0, 0, 0o400},
	}
	for rel, w := range want {
		uid, gid, mode := ownerMode(t, filepath.Join(rg.idir, rel))
		if uid != w.uid || gid != w.gid || mode != w.mode {
			t.Errorf("%s: %d:%d %v, want %d:%d %v", rel, uid, gid, mode, w.uid, w.gid, w.mode)
		}
	}
	meta, _ := os.ReadFile(filepath.Join(rg.idir, "meta", "instance.json"))
	if string(meta) != `{
  "instance_id": "22222222-2222-4222-8222-222222222222",
  "net_cidr": "10.250.0.8/29",
  "run_uid": 30001,
  "slug": "acme",
  "tenant_id": "11111111-1111-4111-8111-111111111111"
}
` {
		t.Fatalf("storage meta %s", meta)
	}
	if entries, _ := os.ReadDir(rg.dir); len(entries) != 1 {
		t.Fatalf("tenants directory holds %d entries (a hidden creating directory left?)", len(entries))
	}
	resp = rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONFIG)
	r, _ := Render(rg.h, rg.s)
	if resp.GetConfigSha256() != r.ConfigSHA256 || resp.GetStatus().GetConfigSha256() != r.ConfigSHA256 || resp.GetStatus().GetTemplateVersion() != 1 {
		t.Fatalf("config phase: %v", resp)
	}
	for rel, w := range map[string]struct {
		uid, gid int
		mode     fs.FileMode
	}{
		"compose.yaml": {0, 0, 0o440}, "config/config.yaml": {0, run, 0o440}, "config/bootstrap-policy.hujson": {0, run, 0o440},
		"records/extra-records.json": {0, run, 0o440}, "meta/instance.json": {0, 0, 0o400},
	} {
		uid, gid, mode := ownerMode(t, filepath.Join(rg.idir, rel))
		if uid != w.uid || gid != w.gid || mode != w.mode {
			t.Errorf("%s: %d:%d %v, want %d:%d %v", rel, uid, gid, mode, w.uid, w.gid, w.mode)
		}
	}
	if rg.e.count("CreateNetwork") != 0 || rg.r.count("up") != 0 {
		t.Fatal("the config phase touched Docker")
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_NETWORK)
	nw, _ := rg.e.Network(context.Background(), "mg-t-acme")
	if nw == nil || !nw.Internal || len(nw.Subnets) != 1 || nw.Subnets[0] != netip.MustParsePrefix("10.250.0.8/29") ||
		nw.Labels[agentspec.LabelInstanceID] != rg.s.Ref.InstanceID.String() || nw.Labels[agentspec.LabelRole] != "tenant" || len(nw.Labels) != 2 {
		t.Fatalf("network %+v", nw)
	}
	resp = rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	st := resp.GetStatus()
	if st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING || st.GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY ||
		st.GetImageDigest() != rg.s.Image.Digest || !st.GetNetwork().GetExists() || st.GetNetwork().GetSubnet() != "10.250.0.8/29" ||
		!st.GetNetwork().GetInternal() || len(st.GetNetwork().GetMembers()) != 1 || st.GetNetwork().GetEdgeAttached() || st.GetActivated() ||
		len(st.GetPaths()) != 13 || st.GetStartedAt() == nil || len(st.GetNoiseKeyFingerprint()) != 64 {
		t.Fatalf("status %v", st)
	}
	for _, p := range st.GetPaths() {
		if !p.GetExists() {
			t.Errorf("path %s missing", p.GetKind())
		}
		if p.GetKind() == agentv1.PathKind_PATH_KIND_DATA_DIR && (p.GetUid() != uint32(run) || p.GetMode() != 0o700) { //nolint:gosec // G115: test
			t.Errorf("data/ status %v", p)
		}
	}
	// the guard's view (P3-T03 alias check) sees the container with its alias on the tenant network
	nets, _ := rg.g.Inventory.Networks(context.Background())
	for _, n := range nets {
		if n.Name == "mg-t-acme" && (len(n.Members) != 1 || n.Members[0].Container != "mg-hs-acme" || !contains(n.Members[0].Aliases, "hs-acme")) {
			t.Errorf("inventory members %+v", n.Members)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// TestEnsureInstanceIsIdempotent — the verification of P3-T02: every phase called again changes nothing (no file
// rewritten — same inode and mtime —, no network created again, the same container) and returns no error.
func TestEnsureInstanceIsIdempotent(t *testing.T) {
	rg := newRig(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	before := rg.snapshot(t)
	for range 3 {
		for _, p := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
			agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
			rg.ensure(t, p)
			if _, err := rg.d.InstanceStatus(context.Background(), rg.s.Ref, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if after := rg.snapshot(t); after != before {
		t.Fatalf("repeated EnsureInstance changed the host:\n--- before\n%s\n--- after\n%s", before, after)
	}
	if n := rg.e.count("CreateNetwork"); n != 1 {
		t.Fatalf("network created %d times", n)
	}
}

// TestPartialStatesConverge: whatever was left by an interrupted run or changed on the host converges.
func TestPartialStatesConverge(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	id := rg.s.Ref.InstanceID.String()
	// an interrupted creation left the hidden directory: removed, the instance created
	if err := os.MkdirAll(filepath.Join(rg.dir, "."+id+".creating", "meta"), 0o700); err != nil {
		t.Fatal(err)
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_STORAGE)
	if _, err := os.Stat(filepath.Join(rg.dir, "."+id+".creating")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("leftover creating directory kept")
	}
	// directory present, nothing else: straight to the container
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	// drift: modes, a deleted records file, an edited config, a missing records/ directory
	_ = os.Chmod(filepath.Join(rg.idir, "config"), 0o777) //nolint:gosec // G302: the drift under test
	_ = os.Chmod(filepath.Join(rg.idir, "data"), 0o755)   //nolint:gosec // G302: the drift under test
	_ = os.Chown(filepath.Join(rg.idir, "compose.yaml"), 0, 30001)
	_ = os.Remove(filepath.Join(rg.idir, "records", "extra-records.json"))
	if err := os.WriteFile(filepath.Join(rg.idir, "config", "config.yaml"), []byte("tampered\n"), 0o640); err != nil { //nolint:gosec // G306: test
		t.Fatal(err)
	}
	// the container was stopped and the network removed meanwhile
	if _, err := rg.d.StopInstance(ctx, rg.call()); err != nil {
		t.Fatal(err)
	}
	_ = rg.e.RemoveContainer(ctx, "mg-hs-acme", 0)
	_ = rg.e.RemoveNetwork(ctx, "mg-t-acme")
	resp := rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	if resp.GetStatus().GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING || !resp.GetStatus().GetNetwork().GetExists() {
		t.Fatalf("did not converge: %v", resp.GetStatus())
	}
	r, _ := Render(rg.h, rg.s)
	if got, _ := os.ReadFile(filepath.Join(rg.idir, "config", "config.yaml")); string(got) != string(r.Config) {
		t.Fatal("tampered config.yaml not rewritten")
	}
	if got, _ := os.ReadFile(filepath.Join(rg.idir, "records", "extra-records.json")); string(got) != "[]\n" {
		t.Fatal("records not re-created")
	}
	for rel, mode := range map[string]fs.FileMode{"config": fs.ModeDir | 0o750, "data": fs.ModeDir | 0o700, "compose.yaml": 0o440} {
		if _, gid, m := ownerMode(t, filepath.Join(rg.idir, rel)); m != mode || (rel == "compose.yaml" && gid != 0) {
			t.Errorf("%s not corrected: %v gid %d", rel, m, gid)
		}
	}
	// records written by WriteDnsRecords later are kept (never reset to [])
	recs := `[{"name":"db.acme.tail.example.com","type":"A","value":"100.64.0.5"}]`
	if err := os.WriteFile(filepath.Join(rg.idir, "records", "extra-records.json"), []byte(recs), 0o440); err != nil { //nolint:gosec // G306: test
		t.Fatal(err)
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	if got, _ := os.ReadFile(filepath.Join(rg.idir, "records", "extra-records.json")); string(got) != recs {
		t.Fatal("existing records overwritten by EnsureInstance")
	}
}

// TestLifecycle: stop/start/restart are idempotent; start/restart need the container, stop does not.
func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	if st, err := rg.d.StopInstance(ctx, rg.call()); err != nil || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_ABSENT {
		t.Fatalf("stop without a container: %v %v", st, err)
	}
	for name, op := range map[string]func(context.Context, agentspec.Call) (*agentv1.InstanceStatus, error){"start": rg.d.StartInstance, "restart": rg.d.RestartInstance} {
		if _, err := op(ctx, rg.call()); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
			t.Errorf("%s without a container: %v", name, err)
		}
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	for range 2 {
		st, err := rg.d.StopInstance(ctx, rg.call())
		if err != nil || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_EXITED {
			t.Fatalf("stop: %v %v", st, err)
		}
	}
	for range 2 {
		st, err := rg.d.StartInstance(ctx, rg.call())
		if err != nil || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING {
			t.Fatalf("start: %v %v", st, err)
		}
	}
	st0, _ := rg.d.InstanceStatus(ctx, rg.s.Ref, false)
	time.Sleep(5 * time.Millisecond)
	st, err := rg.d.RestartInstance(ctx, rg.call())
	if err != nil || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING || !st.GetStartedAt().AsTime().After(st0.GetStartedAt().AsTime()) ||
		st.GetContainerId() != st0.GetContainerId() {
		t.Fatalf("restart: %v %v", st, err)
	}
	// start needs the network
	_ = rg.e.RemoveContainer(ctx, "mg-hs-acme", 0)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	if _, err := rg.d.StopInstance(ctx, rg.call()); err != nil {
		t.Fatal(err)
	}
	rg.e.mu.Lock()
	delete(rg.e.ctrs["mg-hs-acme"].Networks, "mg-t-acme")
	delete(rg.e.nets, "mg-t-acme")
	rg.e.mu.Unlock()
	if _, err := rg.d.StartInstance(ctx, rg.call()); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("start without the network: %v", err)
	}
}

// TestRemoveInstance: KEEP removes container and network and keeps the directory; DELETE_IF_NEVER_ACTIVATED removes
// the directory too; repeated, both are no-ops; refused requests touch nothing.
func TestRemoveInstance(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	keep := agentspec.Remove{Call: rg.call(), Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP}
	del := agentspec.Remove{Call: rg.call(), Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED}
	// nothing exists: idempotent compensation
	if out, err := rg.d.RemoveInstance(ctx, del); err != nil || out.GetContainerRemoved() || out.GetNetworkRemoved() || out.GetDirectoryRemoved() {
		t.Fatalf("remove of nothing: %v %v", out, err)
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	if err := os.WriteFile(filepath.Join(rg.idir, "data", "db.sqlite"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := rg.d.RemoveInstance(ctx, keep)
	if err != nil || !out.GetContainerRemoved() || !out.GetNetworkRemoved() || out.GetDirectoryRemoved() {
		t.Fatalf("remove KEEP: %v %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(rg.idir, "data", "db.sqlite")); err != nil {
		t.Fatal("KEEP lost data/")
	}
	if out, err := rg.d.RemoveInstance(ctx, keep); err != nil || out.GetContainerRemoved() || out.GetNetworkRemoved() {
		t.Fatalf("remove KEEP again: %v %v", out, err)
	}
	// the directory without container converges back, data kept
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	if _, err := os.Stat(filepath.Join(rg.idir, "data", "db.sqlite")); err != nil {
		t.Fatal("data/ lost by EnsureInstance")
	}
	// refused before anything is touched: activated, edge attached, foreign member, archived without backup
	if err := os.WriteFile(filepath.Join(rg.idir, "meta", "activated"), nil, 0o400); err != nil {
		t.Fatal(err)
	}
	before := rg.snapshot(t)
	if _, err := rg.d.RemoveInstance(ctx, del); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("DELETE_IF_NEVER_ACTIVATED on an activated instance: %v", err)
	}
	rg.e.addContainer(Container{Name: "mg-edge", State: "running", Networks: map[string][]string{"mg-t-acme": nil}})
	if _, err := rg.d.RemoveInstance(ctx, keep); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("remove with the edge attached: %v", err)
	}
	_ = rg.e.RemoveContainer(ctx, "mg-edge", 0)
	rg.e.addContainer(Container{Name: "spy", State: "running", Networks: map[string][]string{"mg-t-acme": nil}})
	if _, err := rg.d.RemoveInstance(ctx, keep); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("remove with a foreign member: %v", err)
	}
	_ = rg.e.RemoveContainer(ctx, "spy", 0)
	arch := agentspec.Remove{Call: rg.call(), Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED, ArchiveSequence: 7}
	if _, err := rg.d.RemoveInstance(ctx, arch); status.Code(err) != codes.Unimplemented {
		t.Fatalf("DELETE_ARCHIVED: %v", err)
	}
	if after := rg.snapshot(t); after != before {
		t.Fatalf("a refused removal touched the host:\n%s\n---\n%s", before, after)
	}
	_ = os.Remove(filepath.Join(rg.idir, "meta", "activated"))
	out, err = rg.d.RemoveInstance(ctx, del)
	if err != nil || !out.GetContainerRemoved() || !out.GetNetworkRemoved() || !out.GetDirectoryRemoved() {
		t.Fatalf("remove DELETE_IF_NEVER_ACTIVATED: %v %v", out, err)
	}
	if entries, _ := os.ReadDir(rg.dir); len(entries) != 0 {
		t.Fatalf("tenants directory not empty: %v", entries)
	}
	if out, err := rg.d.RemoveInstance(ctx, del); err != nil || out.GetDirectoryRemoved() {
		t.Fatalf("remove again: %v %v", out, err)
	}
	// a container of the project left behind without compose.yaml is still removed (labels checked)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	_ = os.Remove(filepath.Join(rg.idir, "compose.yaml"))
	if out, err := rg.d.RemoveInstance(ctx, keep); err != nil || !out.GetContainerRemoved() || rg.r.count("down") != 3 {
		t.Fatalf("remove without compose.yaml: %v %v (down %d)", out, err, rg.r.count("down"))
	}
}

// TestActivatedInstance: data/ of an activated instance is never re-created empty; an activated instance with its
// data/ is ensured normally (reconfigure path).
func TestActivatedInstance(t *testing.T) {
	rg := newRig(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	rg.activate(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	if err := os.RemoveAll(filepath.Join(rg.idir, "data")); err != nil {
		t.Fatal(err)
	}
	_, err := rg.d.EnsureInstance(context.Background(), agentspec.Ensure{Spec: rg.s, Phase: agentv1.TargetPhase_TARGET_PHASE_STORAGE, JobID: uuid.New()})
	if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("activated instance without data/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rg.idir, "data")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("data/ re-created for an activated instance")
	}
	st, err := rg.d.InstanceStatus(context.Background(), rg.s.Ref, false)
	if err != nil || !st.GetActivated() {
		t.Fatalf("status: %v %v", st, err)
	}
}

// TestRefusals: what the driver itself refuses — an image change (UpgradeInstance), unusable records, symlinks
// anywhere it reads or writes, a network that appears foreign between the guard and the call.
func TestRefusals(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONFIG)
	other := rg.s
	other.Image.Digest = "sha256:" + strings.Repeat("b", 64)
	if _, err := rg.d.EnsureInstance(ctx, agentspec.Ensure{Spec: other, Phase: agentv1.TargetPhase_TARGET_PHASE_CONFIG}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_CONFLICT {
		t.Fatalf("image change: %v", err)
	}
	rec := filepath.Join(rg.idir, "records", "extra-records.json")
	_ = os.Chmod(rec, 0o600)
	if err := os.WriteFile(rec, []byte("{not an array"), 0o440); err != nil { //nolint:gosec // G306: test
		t.Fatal(err)
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_NETWORK)
	if _, err := rg.d.EnsureInstance(ctx, agentspec.Ensure{Spec: rg.s, Phase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("garbage records: %v", err)
	}
	if rg.r.count("up") != 0 {
		t.Fatal("compose up with unusable records")
	}
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideBefore, _ := os.Stat(outside)
	cases := map[string]string{
		"records file": rec,
		"compose.yaml": filepath.Join(rg.idir, "compose.yaml"),
		"config.yaml":  filepath.Join(rg.idir, "config", "config.yaml"),
		"meta":         filepath.Join(rg.idir, "meta", "instance.json"),
		"config dir":   filepath.Join(rg.idir, "config"),
		"data dir":     filepath.Join(rg.idir, "data"),
	}
	for name, p := range cases {
		backup := p + ".bak"
		if err := os.Rename(p, backup); err != nil {
			t.Fatal(err)
		}
		target := victim
		if name == "config dir" || name == "data dir" {
			target = outside
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		_, err := rg.d.EnsureInstance(ctx, agentspec.Ensure{Spec: rg.s, Phase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER})
		if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH {
			t.Errorf("symlink as %s: %v", name, err)
		}
		_ = os.Remove(p)
		if err := os.Rename(backup, p); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" { //nolint:gosec // G304: test file
		t.Fatal("a symlink was followed")
	}
	if fi, _ := os.Stat(outside); fi.Mode() != outsideBefore.Mode() || fi.Sys().(*syscall.Stat_t).Uid != outsideBefore.Sys().(*syscall.Stat_t).Uid ||
		fi.Sys().(*syscall.Stat_t).Gid != outsideBefore.Sys().(*syscall.Stat_t).Gid {
		t.Fatalf("a symlinked directory was chmod-ed or chown-ed: %v", fi.Mode())
	}
	// a network created by someone else between the guard and the call is not adopted
	_ = os.WriteFile(rec, []byte("[]\n"), 0o440) //nolint:gosec // G306: test
	_ = rg.e.RemoveNetwork(ctx, "mg-t-acme")
	rg.e.createHook = func(f *fakeEngine) {
		f.addNetwork(Network{Name: "mg-t-acme", Internal: true, Subnets: []netip.Prefix{rg.s.NetCIDR},
			Labels: map[string]string{agentspec.LabelInstanceID: "33333333-3333-4333-8333-333333333333", agentspec.LabelRole: "tenant"}})
	}
	if _, err := rg.d.EnsureInstance(ctx, agentspec.Ensure{Spec: rg.s, Phase: agentv1.TargetPhase_TARGET_PHASE_NETWORK}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT {
		t.Fatalf("racing foreign network: %v", err)
	}
	// include_api_keys needs the CLI in a running container (P3-T03)
	if _, err := rg.d.InstanceStatus(ctx, rg.s.Ref, true); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("include_api_keys without a container: %v", err)
	}
}

// TestGuardRefusesForeignObjects: the guard (agentspec) with the driver's inventory refuses an object with a derived
// name that is not labelled for the instance — the driver is never reached.
func TestGuardRefusesForeignObjects(t *testing.T) {
	rg := newRig(t)
	rg.e.addNetwork(Network{Name: "mg-t-acme", Internal: true, Subnets: []netip.Prefix{rg.s.NetCIDR}})
	if err := rg.g.CheckSpec(context.Background(), rg.s); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT {
		t.Fatalf("unlabelled network: %v", err)
	}
	rg2 := newRig(t)
	rg2.e.addContainer(Container{Name: "mg-hs-acme", State: "created", Labels: map[string]string{"com.docker.compose.project": "mg-t-acme"}})
	if err := rg2.g.CheckSpec(context.Background(), rg2.s); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT {
		t.Fatalf("unlabelled container: %v", err)
	}
	rg3 := newRig(t)
	rg3.e.addNetwork(Network{Name: "other", Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/24")}})
	if err := rg3.g.CheckSpec(context.Background(), rg3.s); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_CONFLICT {
		t.Fatalf("overlapping subnet: %v", err)
	}
}

// TestConcurrentCreationOfTheSameSlug: two instances racing for the same slug — the per-instance locks do not
// exclude each other; the driver's creation lock and re-check let exactly one through.
func TestConcurrentCreationOfTheSameSlug(t *testing.T) {
	rg := newRig(t)
	other := rg.s
	other.Ref.InstanceID = uuid.MustParse("44444444-4444-4444-8444-444444444444")
	other.RunUID++
	other.NetCIDR = netip.MustParsePrefix("10.250.0.16/29")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, s := range []agentspec.InstanceSpec{rg.s, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = rg.d.EnsureInstance(context.Background(), agentspec.Ensure{Spec: s, Phase: agentv1.TargetPhase_TARGET_PHASE_STORAGE})
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case reason(err) != agentv1.RefusalReason_REFUSAL_REASON_CONFLICT:
			t.Fatalf("loser: %v", err)
		}
	}
	if entries, _ := os.ReadDir(rg.dir); ok != 1 || len(entries) != 1 {
		t.Fatalf("%d creations succeeded, %d directories", ok, len(entries))
	}
}

// TestListInstances: directories, containers and networks by instance — orphans reported, never adopted.
func TestListInstances(t *testing.T) {
	rg := newRig(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	orphanDir := "55555555-5555-4555-8555-555555555555"
	if err := os.Mkdir(filepath.Join(rg.dir, orphanDir), 0o750); err != nil { //nolint:gosec // G301: test
		t.Fatal(err)
	}
	_ = os.Mkdir(filepath.Join(rg.dir, "not-a-uuid"), 0o750) //nolint:gosec // G301: test
	rg.e.addContainer(Container{Name: "mg-hs-ghost", State: "exited", Labels: map[string]string{
		agentspec.LabelInstanceID: "66666666-6666-4666-8666-666666666666", agentspec.LabelTenantID: "77777777-7777-4777-8777-777777777777",
		agentspec.LabelComposeProject: "mg-t-ghost"}})
	rg.e.addNetwork(Network{Name: "mg-t-junk", Labels: map[string]string{agentspec.LabelInstanceID: "../../etc"}})
	list, err := rg.d.ListInstances(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*agentv1.InventoryEntry{}
	for _, e := range list {
		got[e.GetInstanceId()] = e
	}
	if len(list) != 3 {
		t.Fatalf("inventory %v", list)
	}
	if e := got[rg.s.Ref.InstanceID.String()]; !e.GetHasDirectory() || !e.GetHasContainer() || !e.GetHasNetwork() || e.GetSlug() != "acme" ||
		e.GetTenantId() != rg.s.Ref.TenantID.String() {
		t.Errorf("instance entry %v", e)
	}
	if e := got[orphanDir]; !e.GetHasDirectory() || e.GetHasContainer() || e.GetSlug() != "" {
		t.Errorf("orphan directory entry %v", e)
	}
	if e := got["66666666-6666-4666-8666-666666666666"]; e.GetHasDirectory() || !e.GetHasContainer() || e.GetSlug() != "ghost" {
		t.Errorf("orphan container entry %v", e)
	}
}
