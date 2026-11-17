//go:build linux

package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

const testHelperImage = "ghcr.io/zhaduchanhzz/network-access-mesh/agent@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// logBuf is a goroutine-safe sink for the driver's JSON log.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// lines returns the records with that msg.
func (l *logBuf) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// RFC 7748 §6.1: Alice's private key and its X25519 public key.
const (
	rfcPrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfcPublic  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)

func (rg *rig) meta(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(rg.idir, "meta", "instance.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeMeta(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (rg *rig) fingerprintOnDisk(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(rg.idir, "data", "noise_private.key"))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := NoiseFingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// activate records the activation the way EnsureEdgeAttachment does, without the edge (TestActivatedInstance).
func (rg *rig) activate(t *testing.T) {
	t.Helper()
	tr, err := rg.d.open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Close() }()
	l := newLayout(rg.s.Ref.InstanceID.String())
	m := rg.meta(t)
	m[metaFingerprint] = rg.fingerprintOnDisk(t)
	if err := writeMetaMap(tr, l, m); err != nil {
		t.Fatal(err)
	}
	if err := writeActivation(tr, l, uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

// withEdge adds the shared edge: mg-edge running on the network mg-edge (gw_priority 1).
func (rg *rig) withEdge() {
	rg.e.addNetwork(Network{Name: "mg-edge", Subnets: []netip.Prefix{netip.MustParsePrefix("10.249.0.0/24")}})
	rg.e.addContainer(Container{Name: "mg-edge", State: "running", Labels: map[string]string{"meshguard.role": "edge"},
		Networks: map[string][]string{"mg-edge": {"mg-edge"}}, GwPriority: map[string]int{"mg-edge": 1}})
}

// provision runs a spec through §11.3 steps 7–12: storage → container, then the baseline policy.
func (rg *rig) provision(t *testing.T, s agentspec.InstanceSpec) {
	t.Helper()
	if err := rg.g.CheckSpec(context.Background(), s); err != nil {
		t.Fatalf("guard: %v", err)
	}
	if _, err := rg.d.EnsureInstance(context.Background(), agentspec.Ensure{Spec: s, Phase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER, JobID: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	if _, err := rg.d.BootstrapPolicy(context.Background(), agentspec.Call{Ref: s.Ref, JobID: uuid.New()}, agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL); err != nil {
		t.Fatal(err)
	}
}

// attachRef is the server's path of EnsureEdgeAttachment: guard (alias, members), then the driver.
func (rg *rig) attachRef(ref agentspec.Ref, job uuid.UUID) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	if err := rg.g.CheckEdgeAttach(context.Background(), ref); err != nil {
		return nil, err
	}
	return rg.d.EnsureEdgeAttachment(context.Background(), agentspec.Call{Ref: ref, JobID: job})
}

// second is another instance of the same host.
func (rg *rig) second(slug string) agentspec.InstanceSpec {
	o := rg.s
	o.Ref = agentspec.Ref{InstanceID: uuid.New(), TenantID: uuid.New(), Slug: slug}
	o.RunUID = rg.s.RunUID + 1
	o.NetCIDR = netip.MustParsePrefix("10.250.0.16/29")
	return o
}

func (rg *rig) edgeOn(nw string) bool {
	c, _ := rg.e.Container(context.Background(), "mg-edge")
	if c == nil {
		return false
	}
	_, ok := c.Networks[nw]
	return ok
}

func lockAll(uuid.UUID) (func(), bool) { return func() {}, true }

// ---------------------------------------------------------------------------------------------------- fingerprint

// TestNoiseFingerprint: the fingerprint is the X25519 public key (RFC 7748 vector); the helper accepts only a regular
// file of the expected size holding a key — never a symlink, a FIFO (no blocking), a directory, a large file.
func TestNoiseFingerprint(t *testing.T) {
	for _, ok := range []string{"privkey:" + rfcPrivate, "privkey:" + rfcPrivate + "\n", "  privkey:" + rfcPrivate + "\r\n"} {
		if fp, err := NoiseFingerprint([]byte(ok)); err != nil || fp != rfcPublic {
			t.Fatalf("%q: %s %v", ok, fp, err)
		}
	}
	for _, bad := range []string{"", "privkey:" + strings.ToUpper(rfcPrivate), "nodekey:" + rfcPrivate, "privkey:" + rfcPrivate[:62],
		"privkey:" + rfcPrivate + "00", "privkey:" + rfcPrivate + "\nmore", rfcPrivate} {
		if _, err := NoiseFingerprint([]byte(bad)); !errors.Is(err, ErrNoiseKeyInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", "privkey:"+rfcPrivate)
	if fp, err := FingerprintNoiseKeyFile(good); err != nil || fp != rfcPublic {
		t.Fatalf("file: %s %v", fp, err)
	}
	if _, err := FingerprintNoiseKeyFile(filepath.Join(dir, "absent")); !errors.Is(err, ErrNoiseKeyAbsent) {
		t.Errorf("absent: %v", err)
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(good, link)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	_ = os.Mkdir(sub, 0o700)
	big := write("big", "privkey:"+rfcPrivate+strings.Repeat(" ", 100))
	short := write("short", "privkey:")
	for name, p := range map[string]string{"symlink": link, "fifo": fifo, "directory": sub, "too large": big, "too small": short} {
		done := make(chan error, 1)
		go func() { _, err := FingerprintNoiseKeyFile(p); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNoiseKeyInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the helper blocked", name)
		}
	}
}

// ---------------------------------------------------------------------------------------------------- ValidateConfig

// TestValidateConfig: configtest runs in a throw-away container — the pinned image, the tenant's run_uid, the rendered
// config and records read-only, a scratch data directory on tmpfs, never data/ — and leaves nothing behind; the
// result is typed; detail is redacted.
func TestValidateConfig(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	if _, err := rg.d.ValidateConfig(ctx, rg.s); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("before storage: %v", err)
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_STORAGE)
	// a leftover config.next/ of an interrupted run is replaced
	if err := os.MkdirAll(filepath.Join(rg.idir, "config.next", "junk"), 0o700); err != nil {
		t.Fatal(err)
	}
	// what ValidateConfig may change: nothing but the mtime of the instance directory (config.next/ comes and goes)
	snap := func() string {
		var keep []string
		for _, line := range strings.Split(rg.snapshot(t), "\n") {
			if !strings.HasPrefix(line, rg.s.Ref.InstanceID.String()+" ") {
				keep = append(keep, line)
			}
		}
		return strings.Join(keep, "\n")
	}
	var before string
	for i := range 3 {
		res, err := rg.d.ValidateConfig(ctx, rg.s)
		if err != nil || !res.GetValid() || res.GetExitCode() != 0 || len(res.GetConfigSha256()) != 64 || res.GetDetail() != "" {
			t.Fatalf("valid config: %v %v", res, err)
		}
		if _, err := os.Stat(filepath.Join(rg.idir, "config.next")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("config.next/ left behind")
		}
		if i == 0 {
			before = snap()
		} else if after := snap(); after != before {
			t.Fatalf("ValidateConfig changed the host:\n%s\n---\n%s", before, after)
		}
	}
	run := rg.e.runs[len(rg.e.runs)-1]
	uid := fmt.Sprint(rg.s.RunUID)
	if run.Image != rg.s.Image.Reference() || !slices.Equal(run.Cmd, []string{"configtest"}) || run.User != uid+":"+uid ||
		run.Labels[agentspec.LabelInstanceID] != "" || run.Labels[LabelHelperInstanceID] != rg.s.Ref.InstanceID.String() ||
		!strings.HasPrefix(run.Name, "mg-helper-acme-configtest-") || run.Timeout <= 0 {
		t.Fatalf("helper container %+v", run)
	}
	for _, b := range run.Binds {
		if !b.ReadOnly || strings.HasSuffix(b.Source, "/data") || (b.Target != "/etc/headscale" && b.Target != "/etc/headscale-records") {
			t.Fatalf("bind %+v: only config.next/ and records/, read-only", b)
		}
	}
	if !strings.HasPrefix(run.Tmpfs["/var/lib/headscale"], "uid="+uid+",gid="+uid+",mode=0700") {
		t.Fatalf("scratch data directory %v", run.Tmpfs)
	}
	// the same configuration is what EnsureInstance(config) writes
	resp := rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONFIG)
	if v, _ := rg.d.ValidateConfig(ctx, rg.s); v.GetConfigSha256() != resp.GetConfigSha256() {
		t.Fatalf("config_sha256 %s vs %s", v.GetConfigSha256(), resp.GetConfigSha256())
	}
	// syntax error: exit 1, stderr redacted
	canary := "hskey-api-abcdefghijkl-" + strings.Repeat("Z", 64)
	rg.e.configtest = func([]byte) OneShotResult {
		return OneShotResult{ExitCode: 1, Stderr: []byte("FTL error loading config: near " + canary)}
	}
	res, err := rg.d.ValidateConfig(ctx, rg.s)
	if err != nil || res.GetValid() || res.GetExitCode() != 1 || !strings.Contains(res.GetDetail(), "error loading config") ||
		strings.Contains(res.GetDetail(), canary[10:]) {
		t.Fatalf("invalid config: %v %v", res, err)
	}
	// exit 0 with a configuration warning (node.expiry not parsed ⇒ no expiry) is not valid
	rg.e.configtest = func([]byte) OneShotResult {
		return OneShotResult{Stdout: []byte(`{"level":"info","message":"Opening database"}` + "\n" +
			`{"level":"warn","value":"90x","message":"failed to parse node.expiry, defaulting to no expiry"}` + "\n")}
	}
	if res, err := rg.d.ValidateConfig(ctx, rg.s); err != nil || res.GetValid() || res.GetExitCode() != 0 || !strings.Contains(res.GetDetail(), "node.expiry") {
		t.Fatalf("warning: %v %v", res, err)
	}
	// a long output is truncated to 4 KiB
	rg.e.configtest = func([]byte) OneShotResult {
		return OneShotResult{ExitCode: 1, Stderr: bytes.Repeat([]byte("é"), 10<<10)}
	}
	if res, _ := rg.d.ValidateConfig(ctx, rg.s); len(res.GetDetail()) > maxDetail || !strings.HasSuffix(res.GetDetail(), "…") {
		t.Fatalf("detail of %d bytes", len(res.GetDetail()))
	}
	// the helper cannot run: an error, and still nothing left behind
	rg.e.setRunErr(status.Error(codes.DeadlineExceeded, "helper killed"))
	if _, err := rg.d.ValidateConfig(ctx, rg.s); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("helper failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rg.idir, "config.next")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("config.next/ left behind after a failure")
	}
}

// ---------------------------------------------------------------------------------------------------- BootstrapPolicy

// TestBootstrapPolicy: the baseline is set through the CLI, read back (one newline removed — RT-15) and compared;
// set once only; a policy file that is not the template, or a stopped container, is refused.
func TestBootstrapPolicy(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	call := rg.call()
	if _, err := rg.d.BootstrapPolicy(ctx, call, agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND {
		t.Fatalf("no instance: %v", err)
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	want := sha256Hex([]byte(templates.BootstrapPolicy))
	for range 2 {
		res, err := rg.d.BootstrapPolicy(ctx, call, agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL)
		if err != nil || res.GetPolicySha256() != want {
			t.Fatalf("bootstrap: %v %v", res, err)
		}
	}
	if hs := rg.e.hs["mg-hs-acme"]; hs.sets != 1 || string(hs.policy) != templates.BootstrapPolicy {
		t.Fatalf("policy set %d times: %q", hs.sets, hs.policy)
	}
	if _, err := rg.d.BootstrapPolicy(ctx, call, agentv1.PolicyKind(99)); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_MALFORMED {
		t.Fatalf("unknown kind: %v", err)
	}
	// a policy file that is not the template (and a different policy in the instance) is never set
	rg.e.hs["mg-hs-acme"].policy = []byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`)
	pf := filepath.Join(rg.idir, "config", "bootstrap-policy.hujson")
	_ = os.Chmod(pf, 0o600)
	if err := os.WriteFile(pf, []byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`), 0o440); err != nil { //nolint:gosec // G306: test
		t.Fatal(err)
	}
	if _, err := rg.d.BootstrapPolicy(ctx, call, agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("tampered policy file: %v", err)
	}
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONFIG) // the agent rewrites its file
	if res, err := rg.d.BootstrapPolicy(ctx, call, agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL); err != nil || res.GetPolicySha256() != want {
		t.Fatalf("after the rewrite: %v %v", res, err)
	}
	if _, err := rg.d.StopInstance(ctx, call); err != nil {
		t.Fatal(err)
	}
	if _, err := rg.d.BootstrapPolicy(ctx, call, agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("stopped container: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------------- BootstrapApiKey

// TestBootstrapAPIKey: §11.3 step 13 — explicit expiration, every other valid key expired first, a valid key with the
// kept prefix means no new key; the key is in the response only: never in a log line or an error.
func TestBootstrapAPIKey(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	boot := func(keep string) *agentv1.BootstrapApiKeyResponse {
		t.Helper()
		res, err := rg.d.BootstrapAPIKey(ctx, agentspec.APIKey{Call: rg.call(), TTL: 2160 * time.Hour, KeepPrefix: keep})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	first := boot("")
	m := apiKeyRE.FindStringSubmatch(first.GetApiKey())
	if !first.GetCreated() || m == nil || m[1] != first.GetPrefix() || first.GetExpiredKeys() != 0 ||
		first.GetExpiresAt().AsTime().Sub(time.Now().Add(2160*time.Hour)).Abs() > time.Minute {
		t.Fatalf("first: created %v prefix %q expires %v", first.GetCreated(), first.GetPrefix(), first.GetExpiresAt())
	}
	if !slices.Contains(rg.e.calls, "Exec headscale apikeys create -e 2160h -o json") {
		t.Fatalf("no explicit expiration: %v", rg.e.calls)
	}
	kept := boot(first.GetPrefix())
	if kept.GetCreated() || kept.GetApiKey() != "" || kept.GetPrefix() != first.GetPrefix() || kept.GetExpiredKeys() != 0 {
		t.Fatalf("kept: %v", kept)
	}
	// a key created by an earlier attempt and never stored: expired before a new one is created
	again := boot("")
	if !again.GetCreated() || again.GetExpiredKeys() != 1 || again.GetPrefix() == first.GetPrefix() {
		t.Fatalf("again: created %v expired %d", again.GetCreated(), again.GetExpiredKeys())
	}
	third := boot(again.GetPrefix())
	if third.GetCreated() || third.GetExpiredKeys() != 0 {
		t.Fatalf("third: %v", third)
	}
	st, err := rg.d.InstanceStatus(ctx, rg.s.Ref, true)
	if err != nil || len(st.GetApiKeys()) != 2 {
		t.Fatalf("status keys: %v %v", st.GetApiKeys(), err)
	}
	valid := 0
	for _, k := range st.GetApiKeys() {
		if k.GetExpiration().AsTime().After(time.Now()) {
			valid++
			if k.GetPrefix() != again.GetPrefix() {
				t.Fatalf("valid key %s", k.GetPrefix())
			}
		}
	}
	if valid != 1 {
		t.Fatalf("%d valid keys", valid)
	}
	// the keys never reach the log, nor an error
	for _, key := range []string{first.GetApiKey(), again.GetApiKey()} {
		if strings.Contains(rg.logs.String(), key[len("hskey-api-xxxxxxxxxxxx-"):]) {
			t.Fatal("an API key reached the log")
		}
	}
	if len(rg.logs.lines(t, "api_key_bootstrapped")) != 2 {
		t.Fatal("no audit of the bootstrap")
	}
	rg.e.createOutput = []byte(`{"key":"hskey-api-abcdefghijkl-` + strings.Repeat("Q", 64) + `"}`)
	_, err = rg.d.BootstrapAPIKey(ctx, agentspec.APIKey{Call: rg.call(), TTL: 24 * time.Hour})
	if err == nil || strings.Contains(err.Error(), strings.Repeat("Q", 64)) {
		t.Fatalf("malformed output: %v", err)
	}
	rg.e.createOutput = nil
	// the secret type never prints itself
	sec := APIKeySecret{v: first.GetApiKey()}
	var sl bytes.Buffer
	slog.New(slog.NewJSONHandler(&sl, nil)).Info("x", "key", sec, "struct", struct{ K APIKeySecret }{sec})
	js, _ := json.Marshal(map[string]any{"k": sec})
	txt, _ := sec.MarshalText()
	for name, out := range map[string]string{"%v": fmt.Sprintf("%v", sec), "%+v": fmt.Sprintf("%+v", sec), "%#v": fmt.Sprintf("%#v", sec),
		"%s": fmt.Sprintf("s=%s", sec), "%q": fmt.Sprintf("%q", sec), "%x": fmt.Sprintf("%x", sec), "struct %+v": fmt.Sprintf("%+v", struct{ K APIKeySecret }{sec}),
		"slog": sl.String(), "json": string(js), "text": string(txt), "String": sec.String()} {
		if strings.Contains(out, first.GetPrefix()) || !strings.Contains(out, logx.Redacted) {
			t.Errorf("%s prints the key: %s", name, out)
		}
	}
	if sec.Reveal() != first.GetApiKey() {
		t.Fatal("Reveal")
	}
	// stopped container: refused, nothing created
	if _, err := rg.d.StopInstance(ctx, rg.call()); err != nil {
		t.Fatal(err)
	}
	if _, err := rg.d.BootstrapAPIKey(ctx, agentspec.APIKey{Call: rg.call(), TTL: 24 * time.Hour}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("stopped: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------------- edge attachment

// TestEdgeAttachment: §11.3 step 14 — no edge before a policy; the first attachment records the fingerprint, writes
// meta/activated then the flag, then attaches; repeated, nothing changes; a foreign member is refused; detach clears
// the flag first and is idempotent; a compensation removes the activation only when its own job wrote it.
func TestEdgeAttachment(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	rg.ensure(t, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	job := uuid.New()
	if _, err := rg.attachRef(rg.s.Ref, job); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("no edge: %v", err)
	}
	rg.withEdge()
	before := rg.snapshot(t)
	if _, err := rg.attachRef(rg.s.Ref, job); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("no policy (allow-all window): %v", err)
	}
	if after := rg.snapshot(t); after != before || rg.edgeOn("mg-t-acme") {
		t.Fatal("a refused attachment touched the host")
	}
	if _, err := rg.d.BootstrapPolicy(ctx, rg.call(), agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL); err != nil {
		t.Fatal(err)
	}
	res, err := rg.attachRef(rg.s.Ref, job)
	if err != nil || !res.GetAttached() || res.GetAlreadyAttached() || res.GetNetworkMembers() != 2 || !rg.edgeOn("mg-t-acme") {
		t.Fatalf("attach: %v %v", res, err)
	}
	m := rg.meta(t)
	if m[metaEdgeAttach] != true || m[metaFingerprint] != rg.fingerprintOnDisk(t) {
		t.Fatalf("meta %v", m)
	}
	act, _ := os.ReadFile(filepath.Join(rg.idir, "meta", "activated"))
	if !strings.Contains(string(act), job.String()) {
		t.Fatalf("meta/activated %q", act)
	}
	if uid, gid, mode := ownerMode(t, filepath.Join(rg.idir, "meta", "activated")); uid != os.Geteuid() || gid != os.Getegid() || mode != 0o400 {
		t.Fatalf("meta/activated %d:%d %v", uid, gid, mode)
	}
	st, _ := rg.d.InstanceStatus(ctx, rg.s.Ref, false)
	if !st.GetActivated() || !st.GetEdgeAttachFlag() || !st.GetNetwork().GetEdgeAttached() || st.GetNoiseKeyFingerprint() != m[metaFingerprint] {
		t.Fatalf("status %v", st)
	}
	snap := rg.snapshot(t)
	res, err = rg.attachRef(rg.s.Ref, uuid.New())
	if err != nil || !res.GetAlreadyAttached() || rg.snapshot(t) != snap {
		t.Fatalf("again: %v %v", res, err)
	}
	// detach: flag first, idempotent; the activation stays (quarantine)
	q := agentspec.EdgeDetach{Call: rg.call(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_QUARANTINE}
	if r, err := rg.d.RemoveEdgeAttachment(ctx, q); err != nil || !r.GetWasAttached() || !r.GetDetached() || rg.edgeOn("mg-t-acme") {
		t.Fatalf("detach: %v %v", r, err)
	}
	if r, err := rg.d.RemoveEdgeAttachment(ctx, q); err != nil || r.GetWasAttached() {
		t.Fatalf("detach again: %v %v", r, err)
	}
	if m := rg.meta(t); m[metaEdgeAttach] != nil || m[metaFingerprint] == nil {
		t.Fatalf("meta after detach %v", m)
	}
	// a foreign member on the tenant network: refused (the guard), nothing attached
	rg.e.addContainer(Container{Name: "spy", State: "running", Networks: map[string][]string{"mg-t-acme": {"spy"}}})
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT || rg.edgeOn("mg-t-acme") {
		t.Fatalf("foreign member: %v", err)
	}
	if _, err := rg.d.EnsureEdgeAttachment(ctx, rg.call()); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT {
		t.Fatalf("foreign member (driver): %v", err)
	}
	_ = rg.e.RemoveContainer(ctx, "spy", 0)
	// re-attach after a detach: the fingerprint is compared, not recorded again
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err != nil || !rg.edgeOn("mg-t-acme") {
		t.Fatalf("re-attach: %v", err)
	}
	// compensation of another job: the activation stays; of the same job: removed with the fingerprint
	other := agentspec.EdgeDetach{Call: rg.call(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_COMPENSATION}
	if _, err := rg.d.RemoveEdgeAttachment(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(rg.idir, "meta", "activated")); err != nil {
		t.Fatal("another job's compensation removed the activation")
	}
	own := agentspec.EdgeDetach{Call: agentspec.Call{Ref: rg.s.Ref, JobID: job}, Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_COMPENSATION}
	if _, err := rg.d.RemoveEdgeAttachment(ctx, own); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(rg.idir, "meta", "activated")); !errors.Is(err, os.ErrNotExist) || rg.meta(t)[metaFingerprint] != nil {
		t.Fatal("the compensation of the activating job kept the activation")
	}
	// never activated again: the directory may be removed by its compensation
	if _, err := rg.d.RemoveInstance(ctx, agentspec.Remove{Call: rg.call(), Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED}); err != nil {
		t.Fatal(err)
	}
}

// TestEdgeAliasConflict: hs-<slug> already present on another network of the edge — refused, nothing changed.
func TestEdgeAliasConflict(t *testing.T) {
	rg := newRig(t)
	rg.withEdge()
	rg.provision(t, rg.s)
	rg.e.addNetwork(Network{Name: "lan-x", Internal: true, Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.9.0/29")}})
	rg.e.addContainer(Container{Name: "impostor", State: "running", Networks: map[string][]string{"lan-x": {"impostor", "hs-acme"}}})
	_ = rg.e.ConnectNetwork(context.Background(), "lan-x", "mg-edge")
	before := rg.snapshot(t)
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_CONFLICT {
		t.Fatalf("alias conflict: %v", err)
	}
	if rg.snapshot(t) != before || rg.edgeOn("mg-t-acme") {
		t.Fatal("a refused attachment touched the host")
	}
}

// ---------------------------------------------------------------------------------------------------- start guard

// TestStartGuard: an activated instance whose data/ is empty, or whose Noise key differs from the recorded
// fingerprint, is not started (start, restart, compose up), gets no API key and no policy; the violation is contained
// (flag cleared, edge detached, container stopped) and logged Critical. An indeterminate check refuses without
// containment.
func TestStartGuard(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	rg.withEdge()
	rg.provision(t, rg.s)
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(rg.idir, "data")
	saved := map[string][]byte{}
	for _, f := range dataFiles {
		saved[f], _ = os.ReadFile(filepath.Join(data, f)) //nolint:gosec // G304: test
	}
	restore := func() {
		for f, b := range saved {
			p := filepath.Join(data, f)
			_ = os.Remove(p)
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Chown(p, int(rg.s.RunUID), int(rg.s.RunUID))
		}
	}
	reattach := func() {
		t.Helper()
		if _, err := rg.d.StartInstance(ctx, rg.call()); err != nil {
			t.Fatal(err)
		}
		if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err != nil {
			t.Fatal(err)
		}
	}
	refusedAndContained := func(what string, err error) {
		t.Helper()
		if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE || !strings.Contains(err.Error(), "start guard") {
			t.Fatalf("%s: %v", what, err)
		}
		c, _ := rg.e.Container(ctx, "mg-hs-acme")
		if rg.meta(t)[metaEdgeAttach] != nil || rg.edgeOn("mg-t-acme") || c.State == "running" {
			t.Fatalf("%s: not contained (flag %v, edge %v, container %s)", what, rg.meta(t)[metaEdgeAttach], rg.edgeOn("mg-t-acme"), c.State)
		}
	}
	criticals := func() int { return len(rg.logs.lines(t, "start_guard_failed")) }

	// 1. empty data/ (stopped instance, edge attached): start refused, contained, Critical
	if _, err := rg.d.StopInstance(ctx, rg.call()); err != nil {
		t.Fatal(err)
	}
	for f := range saved {
		_ = os.Remove(filepath.Join(data, f))
	}
	n0 := criticals()
	_, err := rg.d.StartInstance(ctx, rg.call())
	refusedAndContained("start with an empty data/", err)
	if criticals() != n0+1 {
		t.Fatal("no Critical event")
	}
	ev := rg.logs.lines(t, "start_guard_failed")[n0]
	if ev["severity"] != "critical" || ev["reason"] != reasonFileMissing || ev["instance_id"] != rg.s.Ref.InstanceID.String() || ev["trigger"] != "start" {
		t.Fatalf("event %v", ev)
	}
	if _, err := os.Stat(filepath.Join(data, "db.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the refused start created a database (RT-06)")
	}
	for name, call := range map[string]func() error{
		"restart": func() error { _, err := rg.d.RestartInstance(ctx, rg.call()); return err },
		"compose up": func() error {
			_, err := rg.d.EnsureInstance(ctx, agentspec.Ensure{Spec: rg.s, Phase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER})
			return err
		},
	} {
		refusedAndContained(name+" with an empty data/", call())
	}
	if rg.r.count("up") != 1 || rg.r.count("start") != 0 || rg.r.count("restart") != 0 {
		t.Fatalf("compose ran: up %d start %d restart %d", rg.r.count("up"), rg.r.count("start"), rg.r.count("restart"))
	}
	restore()
	reattach()

	// 2. a Noise key with another fingerprint (stopped instance, edge attached)
	if _, err := rg.d.StopInstance(ctx, rg.call()); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(data, "noise_private.key")
	_ = os.Remove(key)
	if err := os.WriteFile(key, newNoiseKey(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = rg.d.StartInstance(ctx, rg.call())
	refusedAndContained("start with another Noise key", err)
	if ev := rg.logs.lines(t, "start_guard_failed"); ev[len(ev)-1]["reason"] != reasonFingerprintDiffer {
		t.Fatalf("event %v", ev[len(ev)-1])
	}
	restore()
	reattach()

	// 3. running and attached, key replaced: no API key, no policy bootstrap — contained
	_ = os.Remove(key)
	_ = os.WriteFile(key, newNoiseKey(), 0o600)
	_, err = rg.d.BootstrapAPIKey(ctx, agentspec.APIKey{Call: rg.call(), TTL: 24 * time.Hour})
	refusedAndContained("API key with another Noise key", err)
	_, err = rg.d.BootstrapPolicy(ctx, rg.call(), agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL)
	refusedAndContained("policy with another Noise key", err)
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err == nil {
		t.Fatal("attached with another Noise key")
	}
	restore()
	reattach()

	// 4. data/ itself gone: the storage phase refuses (never re-created) and contains
	if _, err := rg.d.StopInstance(ctx, rg.call()); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(data)
	_, err = rg.d.EnsureInstance(ctx, agentspec.Ensure{Spec: rg.s, Phase: agentv1.TargetPhase_TARGET_PHASE_STORAGE})
	if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE || rg.meta(t)[metaEdgeAttach] != nil || rg.edgeOn("mg-t-acme") {
		t.Fatalf("data/ gone: %v", err)
	}
	if _, err := os.Stat(data); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("data/ re-created")
	}
	_ = os.Mkdir(data, 0o700)
	_ = os.Chown(data, int(rg.s.RunUID), int(rg.s.RunUID))
	restore()
	reattach()

	// 5. indeterminate (the helper cannot run, key file changed): refused UNAVAILABLE, nothing contained
	_ = os.Chtimes(key, time.Now(), time.Now().Add(time.Hour)) // a new identity: the cache does not answer
	rg.e.setRunErr(errors.New("docker unavailable"))
	if _, err := rg.d.RestartInstance(ctx, rg.call()); status.Code(err) != codes.Unavailable {
		t.Fatalf("indeterminate: %v", err)
	}
	if rg.meta(t)[metaEdgeAttach] != true || !rg.edgeOn("mg-t-acme") {
		t.Fatal("an indeterminate check was treated as a violation")
	}
	rg.e.setRunErr(nil)
	if _, err := rg.d.RestartInstance(ctx, rg.call()); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------------------------------- supervisor

// TestEdgeSupervisor: the edge recreated (new ID, no tenant network) is re-attached to exactly the flagged networks;
// an unflagged network is never attached (nor detached when attached by hand); the start guard runs every cycle —
// db.sqlite or the Noise key changed under a running, attached instance ⇒ contained within one cycle; an
// indeterminate guard detaches without clearing the flag and the next conclusive cycle re-attaches; a busy instance
// is skipped; the fingerprint helper runs once per key file; a drifted default gateway is reported.
func TestEdgeSupervisor(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t)
	rg.withEdge()
	rg.provision(t, rg.s)
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
	b := rg.second("beta")
	rg.provision(t, b) // running, policy set, never attached
	cycle := func() EdgeReport {
		t.Helper()
		rep, err := rg.d.EdgeCycle(ctx, lockAll)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	rep := cycle()
	if rep.Instances != 2 || rep.Flagged != 1 || rep.Attached != 1 || len(rep.NewlyAttached) != 0 || rep.GatewayDrift || len(rep.Failed) != 0 {
		t.Fatalf("steady state: %+v", rep)
	}
	runs := rg.e.helperRuns(FingerprintCommand)
	for range 3 {
		cycle()
	}
	if rg.e.helperRuns(FingerprintCommand) != runs {
		t.Fatalf("the fingerprint helper ran again for an unchanged key (%d → %d)", runs, rg.e.helperRuns(FingerprintCommand))
	}
	// the edge is recreated: a new container, its static networks only
	_ = rg.e.RemoveContainer(ctx, "mg-edge", 0)
	rg.e.addContainer(Container{Name: "mg-edge", State: "running", Networks: map[string][]string{"mg-edge": {"mg-edge"}}, GwPriority: map[string]int{"mg-edge": 1}})
	rep = cycle()
	if !slices.Equal(rep.NewlyAttached, []string{"acme"}) || !rg.edgeOn("mg-t-acme") || rg.edgeOn("mg-t-beta") {
		t.Fatalf("after the recreation: %+v (acme %v, beta %v)", rep, rg.edgeOn("mg-t-acme"), rg.edgeOn("mg-t-beta"))
	}
	if c, _ := rg.e.Container(ctx, "mg-edge"); len(c.Networks) != 2 {
		t.Fatalf("edge networks %v", c.Networks)
	}
	// attached by hand without the flag: left alone, reported
	_ = rg.e.ConnectNetwork(ctx, "mg-t-beta", "mg-edge")
	if rep = cycle(); !slices.Equal(rep.Unflagged, []string{"beta"}) || !rg.edgeOn("mg-t-beta") {
		t.Fatalf("unflagged: %+v", rep)
	}
	_ = rg.e.DisconnectNetwork(ctx, "mg-t-beta", "mg-edge")
	// a busy instance is skipped
	busy := func(id uuid.UUID) (func(), bool) { return func() {}, id != rg.s.Ref.InstanceID }
	if rep, _ = rg.d.EdgeCycle(ctx, busy); !slices.Equal(rep.Busy, []string{rg.s.Ref.InstanceID.String()}) {
		t.Fatalf("busy: %+v", rep)
	}
	// indeterminate (key changed, helper unavailable): detached, flag kept; the next conclusive cycle re-attaches
	key := filepath.Join(rg.idir, "data", "noise_private.key")
	_ = os.Chtimes(key, time.Now(), time.Now().Add(time.Hour))
	rg.e.setRunErr(errors.New("docker unavailable"))
	if rep = cycle(); !slices.Equal(rep.Detached, []string{"acme"}) || rg.edgeOn("mg-t-acme") || rg.meta(t)[metaEdgeAttach] != true {
		t.Fatalf("indeterminate: %+v", rep)
	}
	rg.e.setRunErr(nil)
	if rep = cycle(); !slices.Equal(rep.NewlyAttached, []string{"acme"}) || !rg.edgeOn("mg-t-acme") {
		t.Fatalf("after the indeterminate cycle: %+v", rep)
	}
	// db.sqlite removed under the running, attached instance: contained within one cycle
	_ = os.Remove(filepath.Join(rg.idir, "data", "db.sqlite"))
	rep = cycle()
	c, _ := rg.e.Container(ctx, "mg-hs-acme")
	if !slices.Equal(rep.Contained, []string{"acme"}) || rg.edgeOn("mg-t-acme") || rg.meta(t)[metaEdgeAttach] != nil || c.State != "exited" {
		t.Fatalf("db.sqlite missing: %+v (state %s)", rep, c.State)
	}
	ev := rg.logs.lines(t, "start_guard_failed")
	if len(ev) == 0 || ev[len(ev)-1]["trigger"] != "edge_supervisor" || ev[len(ev)-1]["severity"] != "critical" {
		t.Fatalf("events %v", ev)
	}
	// the flag is gone: never re-attached by the supervisor, even once data/ is back
	_ = os.WriteFile(filepath.Join(rg.idir, "data", "db.sqlite"), []byte("SQLite format 3"), 0o600)
	cycle()
	if rg.edgeOn("mg-t-acme") {
		t.Fatal("re-attached without the flag")
	}
	// the Noise key replaced under the running instance B once attached: contained too
	if _, err := rg.attachRef(b.Ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
	bkey := filepath.Join(rg.dir, b.Ref.InstanceID.String(), "data", "noise_private.key")
	_ = os.Remove(bkey)
	_ = os.WriteFile(bkey, newNoiseKey(), 0o600)
	if rep = cycle(); !slices.Equal(rep.Contained, []string{"beta"}) || rg.edgeOn("mg-t-beta") {
		t.Fatalf("Noise key replaced: %+v", rep)
	}
	// the default gateway of the edge drifted off mg-edge
	rg.e.mu.Lock()
	rg.e.ctrs["mg-edge"].GwPriority = map[string]int{"mg-edge": 0, "mg-t-acme": 0}
	rg.e.mu.Unlock()
	if rep = cycle(); !rep.GatewayDrift || len(rg.logs.lines(t, "edge_gateway_drift")) == 0 {
		t.Fatalf("gateway drift: %+v", rep)
	}
	// no edge at all: nothing to do, no error
	_ = rg.e.RemoveContainer(ctx, "mg-edge", 0)
	if rep = cycle(); rep.EdgeID != "" {
		t.Fatalf("no edge: %+v", rep)
	}
}

// TestEdgeStarts: a start of the edge container is signalled to the supervisor.
func TestEdgeStarts(t *testing.T) {
	rg := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch := rg.d.EdgeStarts(ctx)
	rg.e.starts <- struct{}{}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no start signalled")
	}
	cancel()
	deadline := time.After(5 * time.Second)
	for open := true; open; {
		select {
		case _, open = <-ch:
		case <-deadline:
			t.Fatal("the start channel was not closed with its context")
		}
	}
}
