//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

func TestHealthAndHostInfo(t *testing.T) {
	h := start(t, nil, nil)
	c := tctx(t)
	r, err := h.client.Health(c, &agentv1.HealthRequest{})
	if err != nil || r.GetStatus() != agentv1.ServingStatus_SERVING_STATUS_SERVING || r.GetDriver() != "recording" || r.GetAllowedImages() != 2 {
		t.Fatalf("Health = %v, %v", r, err)
	}
	hi, err := h.client.GetHostInfo(c, &agentv1.GetHostInfoRequest{})
	if err != nil || hi.GetRunUidRange().GetMin() != 30000 || hi.GetTenantNetPool() != "10.250.0.0/16" || len(hi.GetAllowedImages()) != 2 ||
		hi.GetStunPortRange() != nil || hi.GetPublicEntryIpv4() != "203.0.113.10" {
		t.Fatalf("GetHostInfo = %v, %v", hi, err)
	}
}

// TestNoDriverAnswersUnimplemented: the P3-T01 agent validates, guards, then answers UNIMPLEMENTED.
func TestNoDriverAnswersUnimplemented(t *testing.T) {
	h := start(t, nil, nil, withDriver(noDriver{}))
	c := tctx(t)
	writeInstance(t, h.tenants, instanceID, tenantID, "acme")
	calls := map[string]func() error{
		"EnsureInstance": func() error { _, err := h.client.EnsureInstance(c, goodEnsure()); return err },
		"ValidateConfig": func() error {
			_, err := h.client.ValidateConfig(c, &agentv1.ValidateConfigRequest{Spec: goodSpec(), JobId: jobID})
			return err
		},
		"StartInstance": func() error {
			_, err := h.client.StartInstance(c, &agentv1.StartInstanceRequest{Instance: goodRef(), JobId: jobID})
			return err
		},
		"GetInstanceStatus": func() error {
			_, err := h.client.GetInstanceStatus(c, &agentv1.GetInstanceStatusRequest{Instance: goodRef()})
			return err
		},
		"ListInstances": func() error { _, err := h.client.ListInstances(c, &agentv1.ListInstancesRequest{}); return err },
	}
	for name, call := range calls {
		if err := call(); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s: %v, want UNIMPLEMENTED", name, err)
		}
	}
	if !strings.Contains(h.logs.String(), `"outcome":"unimplemented"`) {
		t.Error("no audit line for the unimplemented calls")
	}
	// the dry run works without a driver
	r := goodEnsure()
	r.DryRun = true
	plan, err := h.client.EnsureInstance(c, r)
	if err != nil || len(plan.GetPlannedActions()) != 14 || plan.GetTemplateVersion() != agentspec.TemplateVersion {
		t.Fatalf("dry run = %v, %v", plan, err)
	}
	if got := plan.GetPlannedActions()[0].GetTarget(); got != filepath.Join(h.tenants, instanceID) {
		t.Fatalf("first planned target %q", got)
	}
}

func TestValidRequestReachesTheDriver(t *testing.T) {
	h := start(t, nil, nil)
	if _, err := h.client.EnsureInstance(tctx(t), goodEnsure()); err != nil {
		t.Fatal(err)
	}
	if h.rec.count() != 1 || h.rec.ensured[0].Spec.Image.Reference() != repo+"@"+digestA ||
		h.rec.ensured[0].Spec.NetCIDR != netip.MustParsePrefix("10.250.0.8/29") {
		t.Fatalf("driver saw %+v", h.rec.ensured)
	}
	ok := h.logs.lines(t, "agent_call")
	last := ok[len(ok)-1]
	if last["outcome"] != "ok" || last["instance_id"] != instanceID || last["job_id"] != jobID || last["method"] != "EnsureInstance" {
		t.Fatalf("audit line %v", last)
	}
}

type refusalCase struct {
	name   string
	call   func(ctx context.Context, c *agentclient.Client) error
	code   codes.Code
	reason agentv1.RefusalReason // 0: no Refusal detail expected (gRPC's own refusal)
	field  string
}

func ensure(mut func(r *agentv1.EnsureInstanceRequest)) func(context.Context, *agentclient.Client) error {
	return func(ctx context.Context, c *agentclient.Client) error {
		r := goodEnsure()
		mut(r)
		_, err := c.EnsureInstance(ctx, r)
		return err
	}
}

// TestRefusalsOverTheSocket: the P3-T01 verification end to end — a wrong spec or a parameter outside the allowed
// set is refused with a typed status, logged, and never reaches the driver.
func TestRefusalsOverTheSocket(t *testing.T) {
	unknownField := func() []byte {
		b := protowire.AppendTag(nil, 1000, protowire.BytesType)
		return protowire.AppendBytes(b, []byte("--privileged"))
	}()
	big := make([]*agentv1.DnsRecord, 40000)
	for i := range big {
		big[i] = &agentv1.DnsRecord{Name: fmt.Sprintf("host-%d.acme.tail.example.com", i), Type: agentv1.DnsRecordType_DNS_RECORD_TYPE_A, Value: "100.64.0.1"}
	}
	many := big[:agentspec.MaxDNSRecords+1]
	cases := []refusalCase{
		{"wrong digest", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.ImageDigest = digestX }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_IMAGE_NOT_ALLOWED, "spec.image_digest"},
		{"image by tag", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.ImageDigest = "alpine:latest" }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, "spec.image_digest"},
		{"path traversal in instance_id", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.Instance.InstanceId = "../../../etc" }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_INVALID_ID, "spec.instance.instance_id"},
		{"absolute path in instance_id", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.Instance.InstanceId = "/var/run/docker.sock" }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_INVALID_ID, "spec.instance.instance_id"},
		{"path traversal in slug", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.Instance.Slug = "../mg-edge" }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_INVALID_SLUG, "spec.instance.slug"},
		{"run_uid 0", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.RunUid = 0 }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_UID_OUT_OF_RANGE, "spec.run_uid"},
		{"run_uid out of range", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.RunUid = 65532 }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_UID_OUT_OF_RANGE, "spec.run_uid"},
		{"port without a host range", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.Headscale.StunPort = proto.Uint32(3478) }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_PORT_OUT_OF_RANGE, "spec.headscale.stun_port"},
		{"network outside the pool", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.NetCidr = "10.249.0.0/29" }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_NETWORK_OUT_OF_POOL, "spec.net_cidr"},
		{"network name instead of a CIDR", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.NetCidr = "mg-data" }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, "spec.net_cidr"},
		{"unknown field", ensure(func(r *agentv1.EnsureInstanceRequest) { r.Spec.Headscale.ProtoReflect().SetUnknown(unknownField) }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, "spec.headscale"},
		{"unknown enum value", ensure(func(r *agentv1.EnsureInstanceRequest) { r.TargetPhase = 77 }),
			codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, "target_phase"},
		{"too many records", func(ctx context.Context, c *agentclient.Client) error {
			_, err := c.WriteDnsRecords(ctx, &agentv1.WriteDnsRecordsRequest{Instance: goodRef(), JobId: jobID, Records: many})
			return err
		}, codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_TOO_LARGE, "records"},
		{"oversize message", func(ctx context.Context, c *agentclient.Client) error {
			_, err := c.WriteDnsRecords(ctx, &agentv1.WriteDnsRecordsRequest{Instance: goodRef(), JobId: jobID, Records: big})
			return err
		}, codes.ResourceExhausted, 0, ""},
		{"oversize policy", func(ctx context.Context, c *agentclient.Client) error {
			_, err := c.Restore(ctx, &agentv1.RestoreRequest{Instance: goodRef(), JobId: jobID,
				Artifact: &agentv1.ArtifactRef{Sequence: 1, ArchiveSha256: strings.Repeat("1", 64), ManifestSha256: strings.Repeat("2", 64)},
				DataKey:  make([]byte, 32), Policy: &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: make([]byte, agentspec.MaxPolicyBytes+1)}})
			return err
		}, codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_TOO_LARGE, "applied_policy_hujson"},
		{"no job id", func(ctx context.Context, c *agentclient.Client) error {
			_, err := c.StopInstance(ctx, &agentv1.StopInstanceRequest{Instance: goodRef()})
			return err
		}, codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, "job_id"},
		{"short api key ttl", func(ctx context.Context, c *agentclient.Client) error {
			_, err := c.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{Instance: goodRef(), JobId: jobID, Ttl: durationpb.New(time.Minute)})
			return err
		}, codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_OUT_OF_BOUNDS, "ttl"},
		{"unknown instance", func(ctx context.Context, c *agentclient.Client) error {
			_, err := c.StartInstance(ctx, &agentv1.StartInstanceRequest{Instance: goodRef(), JobId: jobID})
			return err
		}, codes.NotFound, agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, "instance.instance_id"},
	}
	h := start(t, nil, nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkRefusal(t, h, c) })
	}
	if n := h.rec.count(); n != 0 {
		t.Fatalf("%d refused calls reached the driver: %v", n, h.rec.calls)
	}
	// every refusal left one audit line, and no line carries the values that were refused
	refused := h.logs.lines(t, "agent_call")
	n := 0
	for _, l := range refused {
		if l["outcome"] == "refused" {
			n++
			if l["peer_uid"] == nil || l["reason"] == nil || l["method"] == nil {
				t.Errorf("incomplete audit line %v", l)
			}
		}
	}
	if n != len(cases)-1 { // the oversize message is refused by gRPC before the interceptor
		t.Errorf("%d refused audit lines, want %d", n, len(cases)-1)
	}
	for _, leak := range []string{"--privileged", "../../../etc", "docker.sock", "mg-data", "alpine:latest"} {
		if strings.Contains(h.logs.String(), leak) {
			t.Errorf("a refused value reached the log: %q", leak)
		}
	}
	t.Logf("%d refusals over the socket", len(cases))
}

func checkRefusal(t *testing.T, h *harness, c refusalCase) {
	t.Helper()
	err := c.call(tctx(t), h.client)
	if status.Code(err) != c.code {
		t.Fatalf("code %v (%v), want %v", status.Code(err), err, c.code)
	}
	r, ok := agentclient.RefusalOf(err)
	if c.reason == 0 {
		if ok {
			t.Fatalf("unexpected refusal detail %v", r)
		}
		return
	}
	if !ok || r.GetReason() != c.reason || r.GetField() != c.field {
		t.Fatalf("refusal %v, want %s %q", r, c.reason, c.field)
	}
	if agentclient.Retryable(err) {
		t.Fatalf("a refusal of the request must not be retryable: %v", err)
	}
}

// TestGuardBeforeTouching: an existing directory or Docker object of another instance is refused (never adopted).
func TestGuardBeforeTouching(t *testing.T) {
	foreignNet := &fakeInventory{nets: []agentspec.NetworkInfo{{Name: "mg-t-acme", Internal: true,
		Labels:  map[string]string{agentspec.LabelInstanceID: otherID, agentspec.LabelRole: agentspec.RoleTenant},
		Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.0.8/29")}}}}
	unlabelled := &fakeInventory{ctrs: []agentspec.ContainerInfo{{Name: "mg-hs-acme"}}}
	h := start(t, foreignNet, nil)
	writeInstance(t, h.tenants, instanceID, tenantID, "acme")
	checkRefusal(t, h, refusalCase{"network of another instance", ensure(func(*agentv1.EnsureInstanceRequest) {}),
		codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "spec.instance.slug"})
	checkRefusal(t, h, refusalCase{"network of another instance (start)", func(ctx context.Context, c *agentclient.Client) error {
		_, err := c.StartInstance(ctx, &agentv1.StartInstanceRequest{Instance: goodRef(), JobId: jobID})
		return err
	}, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "instance.slug"})
	h2 := start(t, unlabelled, nil)
	checkRefusal(t, h2, refusalCase{"unlabelled container", ensure(func(*agentv1.EnsureInstanceRequest) {}),
		codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "spec.instance.slug"})
	h3 := start(t, &fakeInventory{}, nil)
	writeInstance(t, h3.tenants, instanceID, otherID, "acme")
	checkRefusal(t, h3, refusalCase{"directory of another tenant", ensure(func(*agentv1.EnsureInstanceRequest) {}),
		codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, "spec.instance.tenant_id"})
	checkRefusal(t, h3, refusalCase{"remove an instance of another tenant", func(ctx context.Context, c *agentclient.Client) error {
		_, err := c.RemoveInstance(ctx, &agentv1.RemoveInstanceRequest{Instance: goodRef(), JobId: jobID, Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED})
		return err
	}, codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, "instance.tenant_id"})
	if n := h.rec.count() + h2.rec.count() + h3.rec.count(); n != 0 {
		t.Fatalf("%d guarded calls reached the driver", n)
	}
}

func TestTokenRequired(t *testing.T) {
	h := start(t, nil, nil)
	wrong := filepath.Join(h.dir, "wrong")
	if err := os.WriteFile(wrong, []byte(strings.Repeat("f", 64)), 0o400); err != nil {
		t.Fatal(err)
	}
	c := h.dial(t, wrong)
	for _, call := range []func() error{
		func() error { _, err := c.Health(tctx(t), &agentv1.HealthRequest{}); return err },
		func() error { _, err := c.EnsureInstance(tctx(t), goodEnsure()); return err },
	} {
		err := call()
		if r, ok := agentclient.RefusalOf(err); status.Code(err) != codes.Unauthenticated || !ok ||
			r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_UNAUTHENTICATED {
			t.Fatalf("wrong token: %v", err)
		}
	}
	if h.rec.count() != 0 || strings.Contains(h.logs.String(), token) || strings.Contains(h.logs.String(), "ffffffff") {
		t.Fatal("wrong token reached the driver, or a token reached the log")
	}
}

// TestOwnUIDIsHealthOnly: a peer with the agent's own UID (the container healthcheck) may call Health only.
func TestOwnUIDIsHealthOnly(t *testing.T) {
	h := start(t, nil, []uint32{4242})
	if _, err := h.client.Health(tctx(t), &agentv1.HealthRequest{}); err != nil {
		t.Fatalf("Health as own UID: %v", err)
	}
	_, err := h.client.EnsureInstance(tctx(t), goodEnsure())
	if r, ok := agentclient.RefusalOf(err); status.Code(err) != codes.PermissionDenied || !ok ||
		r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_PERMISSION_DENIED {
		t.Fatalf("EnsureInstance as own UID: %v", err)
	}
	if h.rec.count() != 0 {
		t.Fatal("reached the driver")
	}
}

// TestPeerCredRefused: a UID that is neither an allowed worker UID nor the agent's own is refused at connection
// time (SO_PEERCRED): no RPC runs, the attempt is logged with the kernel-attested UID.
func TestPeerCredRefused(t *testing.T) {
	h := start(t, nil, []uint32{4242})
	h.cfg.selfUID = 4343 // the test process is now a stranger
	h.stop()
	h.restart(t)
	_, err := h.dial(t, h.cfg.TokenFile).Health(tctx(t), &agentv1.HealthRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("stranger: %v, want UNAVAILABLE", err)
	}
	lines := h.logs.lines(t, "agent_peer_refused")
	if len(lines) == 0 || lines[0]["peer_uid"] != float64(os.Getuid()) {
		t.Fatalf("peer refusal not logged: %v", lines)
	}
	if !agentclient.Retryable(err) {
		t.Fatal("UNAVAILABLE is retryable for the client (it cannot tell a refusal from a restart)")
	}
}

// restart serves the harness's socket again with its (modified) configuration.
func (h *harness) restart(t *testing.T) {
	t.Helper()
	tok := []byte(token)
	srv := newServer(h.cfg, tok, h.drv, nil, h.logger())
	l, err := listenUnix(context.Background(), h.cfg.Socket, -1)
	if err != nil {
		t.Fatal(err)
	}
	gs := srv.grpcServer(h.cfg) // local: see start() — the Serve goroutine never reads h.gs
	served := make(chan struct{})
	h.gs, h.served = gs, served
	go func() { _ = gs.Serve(l); close(served) }()
	t.Cleanup(gs.Stop)
}

func TestBusyInstanceLock(t *testing.T) {
	h := start(t, nil, nil)
	writeInstance(t, h.tenants, instanceID, tenantID, "acme")
	h.rec.block = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	var first error
	go func() {
		defer wg.Done()
		_, first = h.client.StartInstance(tctx(t), &agentv1.StartInstanceRequest{Instance: goodRef(), JobId: jobID})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for h.rec.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_, err := h.client.StartInstance(tctx(t), &agentv1.StartInstanceRequest{Instance: goodRef(), JobId: jobID})
	r, ok := agentclient.RefusalOf(err)
	if status.Code(err) != codes.Aborted || !ok || r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_BUSY || !agentclient.Retryable(err) {
		t.Fatalf("second call: %v", err)
	}
	close(h.rec.block)
	wg.Wait()
	if first != nil {
		t.Fatalf("first call: %v", first)
	}
	// the lock is released: a third call goes through
	if _, err := h.client.StartInstance(tctx(t), &agentv1.StartInstanceRequest{Instance: goodRef(), JobId: jobID}); err != nil {
		t.Fatal(err)
	}
}

// TestSecretsStayOutOfTheLog: a key returned by the driver crosses the socket but no log line (the audit line
// never carries a request or a response).
func TestSecretsStayOutOfTheLog(t *testing.T) {
	h := start(t, nil, nil)
	writeInstance(t, h.tenants, instanceID, tenantID, "acme")
	r, err := h.client.BootstrapApiKey(tctx(t), &agentv1.BootstrapApiKeyRequest{Instance: goodRef(), JobId: jobID, Ttl: durationpb.New(2160 * time.Hour)})
	if err != nil || !strings.HasPrefix(r.GetApiKey(), "hskey-api-") {
		t.Fatalf("BootstrapApiKey = %v", err)
	}
	if strings.Contains(h.logs.String(), "sssssssss") || strings.Contains(h.logs.String(), "hskey-") {
		t.Fatal("the API key reached the log")
	}
}

func TestSocketPermissions(t *testing.T) {
	h := start(t, nil, nil)
	fi, err := os.Lstat(h.sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 || !ownedBy(fi, os.Geteuid()) {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	dir := testDir(t)
	sock := filepath.Join(dir, "run", "agent.sock")
	// something that is not a socket at the path is never removed
	if err := os.WriteFile(sock, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(context.Background(), sock, -1); err == nil {
		t.Fatal("listened over a regular file")
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatal("the regular file was removed")
	}
	_ = os.Remove(sock)
	// a directory others can write to is refused (someone could swap the socket)
	if err := os.Chmod(filepath.Join(dir, "run"), 0o777); err != nil { //nolint:gosec // G302: the unsafe mode under test
		t.Fatal(err)
	}
	if _, err := listenUnix(context.Background(), sock, -1); err == nil {
		t.Fatal("listened in a world-writable directory")
	}
	// a stale socket of a previous run is replaced
	_ = os.Chmod(filepath.Join(dir, "run"), 0o750) //nolint:gosec // G302: the layout of the agent (directories 0750) under test
	l, err := listenUnix(context.Background(), sock, -1)
	if err != nil {
		t.Fatal(err)
	}
	l.(interface{ SetUnlinkOnClose(bool) }).SetUnlinkOnClose(false)
	_ = l.Close()
	l, err = listenUnix(context.Background(), sock, -1)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	_ = l.Close()
}

func TestDispatch(t *testing.T) {
	var out, errb strings.Builder
	if code := dispatch(context.Background(), []string{"version"}, getenv(nil), nil, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "meshguard-agent ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	if code := dispatch(context.Background(), []string{"--listen=tcp://0.0.0.0:1"}, getenv(nil), nil, &out, &errb); code != 2 ||
		strings.Contains(errb.String(), "tcp://") {
		t.Fatalf("unknown subcommand: %d %q", code, errb.String())
	}
	errb.Reset()
	env := map[string]string{"MG_AGENT_TOKEN": "s3cr3t-value"}
	if code := dispatch(context.Background(), nil, getenv(env), environ(env), &out, &errb); code != 2 || strings.Contains(errb.String(), "s3cr3t") {
		t.Fatalf("bad configuration: %d %q", code, errb.String())
	}
}

func TestHealthcheckSubcommand(t *testing.T) {
	h := start(t, nil, nil)
	env := map[string]string{"MG_AGENT_SOCKET": h.sock, "MG_AGENT_TOKEN_FILE": h.cfg.TokenFile}
	var out, errb strings.Builder
	if code := healthcheck(context.Background(), getenv(env), &out, &errb); code != 0 || !strings.Contains(out.String(), "SERVING") {
		t.Fatalf("healthcheck: %d %q %q", code, out.String(), errb.String())
	}
	h.stop()
	if code := healthcheck(context.Background(), getenv(env), &out, &errb); code != 1 {
		t.Fatalf("healthcheck of a stopped agent: %d", code)
	}
}
