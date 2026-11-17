package reconcile

// Fakes of the unit and DB tests: the Host Agent as an in-process gRPC server (bufconn) behind the real generated
// client, with an interceptor that records EVERY method called — reads and writes alike —, and a Headscale instance
// that records every method of headscale.Instance. A test then asserts that reconcile called nothing but
// GetInstanceStatus / ListInstances and ListAPIKeys.

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// ---------------------------------------------------------------------------------------------------- fake agent

type fakeAgent struct {
	agentv1.UnimplementedAgentServiceServer // every other method: UNIMPLEMENTED — but still recorded by the interceptor

	mu        sync.Mutex
	status    map[string]*agentv1.InstanceStatus // instance id → status
	statusErr map[string]error
	inventory *agentv1.ListInstancesResponse
	listErr   error
	methods   []string // every method called, in order
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{status: map[string]*agentv1.InstanceStatus{}, statusErr: map[string]error{},
		inventory: &agentv1.ListInstancesResponse{}}
}

func (f *fakeAgent) GetInstanceStatus(_ context.Context, r *agentv1.GetInstanceStatusRequest) (*agentv1.GetInstanceStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := r.GetInstance().GetInstanceId()
	if err := f.statusErr[id]; err != nil {
		return nil, err
	}
	st, ok := f.status[id]
	if !ok {
		return nil, refusal(codes.NotFound, agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, "instance.instance_id")
	}
	return &agentv1.GetInstanceStatusResponse{Status: st}, nil
}

func (f *fakeAgent) ListInstances(context.Context, *agentv1.ListInstancesRequest) (*agentv1.ListInstancesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.inventory, nil
}

func (f *fakeAgent) record(m string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, m)
}

func (f *fakeAgent) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.methods)
}

func (f *fakeAgent) set(id uuid.UUID, st *agentv1.InstanceStatus, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id.String()], f.statusErr[id.String()] = st, err
}

// refusal is an agent refusal as the agent sends it (status + typed Refusal detail).
func refusal(c codes.Code, r agentv1.RefusalReason, field string) error {
	st, err := status.New(c, "refused").WithDetails(&agentv1.Refusal{Reason: r, Field: field, Message: "network mg-t-acme is not labelled for this instance"})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

// serve runs the fake agent on an in-memory listener and returns the real generated client.
func (f *fakeAgent) serve(t *testing.T) agentv1.AgentServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		f.record(path.Base(info.FullMethod))
		return h(ctx, req)
	}))
	agentv1.RegisterAgentServiceServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentv1.NewAgentServiceClient(conn)
}

// ---------------------------------------------------------------------------------------------------- fake Headscale

// fakeHS is a headscale.Instance that records every call; reconcile may only list API keys.
type fakeHS struct {
	mu    sync.Mutex
	keys  []headscale.APIKey
	err   error
	calls []string
}

var _ headscale.Instance = (*fakeHS)(nil)

func (f *fakeHS) rec(op string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op)
}

func (f *fakeHS) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeHS) setKeys(k ...headscale.APIKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = k
}

var errWrite = status.Error(codes.PermissionDenied, "reconcile must not write")

func (f *fakeHS) Health(context.Context) (headscale.Health, error) {
	f.rec("Health")
	return headscale.Health{}, nil
}
func (f *fakeHS) Version(context.Context) (string, error) { f.rec("Version"); return "v0.29.7", nil }
func (f *fakeHS) ListUsers(context.Context, headscale.UserFilter) ([]headscale.User, error) {
	f.rec("ListUsers")
	return nil, nil
}
func (f *fakeHS) CreateUser(context.Context, headscale.CreateUser) (headscale.User, error) {
	f.rec("CreateUser")
	return headscale.User{}, errWrite
}
func (f *fakeHS) RenameUser(context.Context, uint64, string) (headscale.User, error) {
	f.rec("RenameUser")
	return headscale.User{}, errWrite
}
func (f *fakeHS) DeleteUser(context.Context, uint64) error { f.rec("DeleteUser"); return errWrite }
func (f *fakeHS) ListNodes(context.Context, string) ([]headscale.Node, error) {
	f.rec("ListNodes")
	return nil, nil
}
func (f *fakeHS) GetNode(context.Context, uint64) (headscale.Node, error) {
	f.rec("GetNode")
	return headscale.Node{}, nil
}
func (f *fakeHS) RenameNode(context.Context, uint64, string) (headscale.Node, error) {
	f.rec("RenameNode")
	return headscale.Node{}, errWrite
}
func (f *fakeHS) SetTags(context.Context, uint64, []string) (headscale.Node, error) {
	f.rec("SetTags")
	return headscale.Node{}, errWrite
}
func (f *fakeHS) SetApprovedRoutes(context.Context, uint64, []netip.Prefix) (headscale.Node, error) {
	f.rec("SetApprovedRoutes")
	return headscale.Node{}, errWrite
}
func (f *fakeHS) ExpireNode(context.Context, uint64, *time.Time) (headscale.Node, error) {
	f.rec("ExpireNode")
	return headscale.Node{}, errWrite
}
func (f *fakeHS) DeleteNode(context.Context, uint64) error { f.rec("DeleteNode"); return errWrite }
func (f *fakeHS) CreatePreAuthKey(context.Context, headscale.PreAuthKeyOpts) (headscale.PreAuthKey, error) {
	f.rec("CreatePreAuthKey")
	return headscale.PreAuthKey{}, errWrite
}
func (f *fakeHS) ListPreAuthKeys(context.Context) ([]headscale.PreAuthKey, error) {
	f.rec("ListPreAuthKeys")
	return nil, nil
}
func (f *fakeHS) ExpirePreAuthKey(context.Context, uint64) error {
	f.rec("ExpirePreAuthKey")
	return errWrite
}
func (f *fakeHS) DeletePreAuthKey(context.Context, uint64) error {
	f.rec("DeletePreAuthKey")
	return errWrite
}
func (f *fakeHS) AuthRegister(context.Context, string, string) (headscale.Node, error) {
	f.rec("AuthRegister")
	return headscale.Node{}, errWrite
}
func (f *fakeHS) AuthApprove(context.Context, string) error { f.rec("AuthApprove"); return errWrite }
func (f *fakeHS) AuthReject(context.Context, string) error  { f.rec("AuthReject"); return errWrite }
func (f *fakeHS) GetPolicy(context.Context) (headscale.Policy, error) {
	f.rec("GetPolicy")
	return headscale.Policy{}, nil
}
func (f *fakeHS) CheckPolicy(context.Context, string) error { f.rec("CheckPolicy"); return nil }
func (f *fakeHS) SetPolicy(context.Context, string) (headscale.Policy, error) {
	f.rec("SetPolicy")
	return headscale.Policy{}, errWrite
}
func (f *fakeHS) CreateAPIKey(context.Context, time.Time) (headscale.Secret, error) {
	f.rec("CreateAPIKey")
	return headscale.Secret{}, errWrite
}
func (f *fakeHS) ListAPIKeys(context.Context) ([]headscale.APIKey, error) {
	f.rec("ListAPIKeys")
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.keys), f.err
}
func (f *fakeHS) ExpireAPIKey(context.Context, string) error { f.rec("ExpireAPIKey"); return errWrite }

// fakeRegistry is a headscale.Registry over fake instances.
type fakeRegistry map[uuid.UUID]*fakeHS

func (r fakeRegistry) ForTenant(_ context.Context, t uuid.UUID) (headscale.Instance, error) {
	if hs, ok := r[t]; ok {
		return hs, nil
	}
	return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1, Err: headscale.ErrNoInstance}
}

// assertReadOnly: the agent saw only the two reads, every Headscale only ListAPIKeys.
func assertReadOnly(t *testing.T, a *fakeAgent, hs ...*fakeHS) {
	t.Helper()
	for _, m := range a.calls() {
		if m != "GetInstanceStatus" && m != "ListInstances" {
			t.Errorf("reconcile called the agent's %s", m)
		}
	}
	for _, h := range hs {
		for _, m := range h.called() {
			if m != "ListAPIKeys" {
				t.Errorf("reconcile called Headscale's %s", m)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------------- fixtures

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
	cfgSum  = strings.Repeat("c", 64)
)

const agentUID, agentGID, runUID = 0, 0, 30001

func desired() Desired {
	return Desired{InstanceID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		TenantID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), Slug: "acme", Status: "running", ImageDigest: digestA,
		NetCIDR: netip.MustParsePrefix("10.250.0.8/29"), RunUID: runUID, APIKeyPrefix: "curKEY000001", ConfigSHA256: cfgSum}
}

// goodPaths are the owner/mode the compose driver writes (§14.2).
func goodPaths() []*agentv1.PathState {
	p := func(k agentv1.PathKind, uid, gid, mode uint32) *agentv1.PathState {
		return &agentv1.PathState{Kind: k, Exists: true, Uid: uid, Gid: gid, Mode: mode}
	}
	return []*agentv1.PathState{
		p(agentv1.PathKind_PATH_KIND_INSTANCE_DIR, agentUID, runUID, 0o750), p(agentv1.PathKind_PATH_KIND_CONFIG_DIR, agentUID, runUID, 0o750),
		p(agentv1.PathKind_PATH_KIND_RECORDS_DIR, agentUID, runUID, 0o750), p(agentv1.PathKind_PATH_KIND_DATA_DIR, runUID, runUID, 0o700),
		p(agentv1.PathKind_PATH_KIND_META_DIR, agentUID, agentGID, 0o700), p(agentv1.PathKind_PATH_KIND_COMPOSE_FILE, agentUID, agentGID, 0o440),
		p(agentv1.PathKind_PATH_KIND_CONFIG_FILE, agentUID, runUID, 0o440), p(agentv1.PathKind_PATH_KIND_POLICY_FILE, agentUID, runUID, 0o440),
		p(agentv1.PathKind_PATH_KIND_RECORDS_FILE, agentUID, runUID, 0o440), p(agentv1.PathKind_PATH_KIND_META_FILE, agentUID, agentGID, 0o400),
	}
}

// goodStatus is the actual state of a healthy, attached instance that matches d.
func goodStatus(d Desired) *agentv1.InstanceStatus {
	return &agentv1.InstanceStatus{
		Instance:       &agentv1.InstanceRef{InstanceId: d.InstanceID.String(), TenantId: d.TenantID.String(), Slug: d.Slug},
		ContainerState: agentv1.ContainerState_CONTAINER_STATE_RUNNING, Health: agentv1.HealthState_HEALTH_STATE_HEALTHY,
		ContainerId: strings.Repeat("f", 64), ImageDigest: d.ImageDigest, ConfigSha256: d.ConfigSHA256, TemplateVersion: 1,
		Network: &agentv1.NetworkState{Exists: true, Subnet: d.NetCIDR.String(), Internal: true,
			Members: []string{"mg-edge", "mg-hs-" + d.Slug}, EdgeAttached: true},
		Paths: goodPaths(),
	}
}

var now0 = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

// currentKey is the recorded key, created 30 days ago, valid 60 more days; old is an expired predecessor.
func currentKey() headscale.APIKey {
	return headscale.APIKey{ID: 7, Prefix: "curKEY000001", CreatedAt: now0.Add(-30 * 24 * time.Hour), Expiration: now0.Add(60 * 24 * time.Hour)}
}

func expiredKey() headscale.APIKey {
	return headscale.APIKey{ID: 3, Prefix: "oldKEY000001", CreatedAt: now0.Add(-120 * 24 * time.Hour), Expiration: now0.Add(-30 * 24 * time.Hour)}
}
