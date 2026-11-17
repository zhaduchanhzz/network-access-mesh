package agentclient

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

var testToken = strings.Repeat("t0k3n-", 8)

// fakeAgent is an in-process stand-in for the agent: it checks the token like the agent and returns canned answers.
type fakeAgent struct {
	agentv1.UnimplementedAgentServiceServer
	sawAuth []string
}

func (f *fakeAgent) auth(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	f.sawAuth = md.Get("authorization")
	if len(f.sawAuth) != 1 || f.sawAuth[0] != "Bearer "+testToken {
		return status.Error(codes.Unauthenticated, "wrong token")
	}
	return nil
}

func (f *fakeAgent) Health(ctx context.Context, _ *agentv1.HealthRequest) (*agentv1.HealthResponse, error) {
	if err := f.auth(ctx); err != nil {
		return nil, err
	}
	return &agentv1.HealthResponse{Status: agentv1.ServingStatus_SERVING_STATUS_SERVING, Driver: "fake"}, nil
}

func (f *fakeAgent) EnsureInstance(ctx context.Context, _ *agentv1.EnsureInstanceRequest) (*agentv1.EnsureInstanceResponse, error) {
	if err := f.auth(ctx); err != nil {
		return nil, err
	}
	st, _ := status.New(codes.InvalidArgument, "refused").WithDetails(&agentv1.Refusal{
		Reason: agentv1.RefusalReason_REFUSAL_REASON_IMAGE_NOT_ALLOWED, Field: "spec.image_digest"})
	return nil, st.Err()
}

func (f *fakeAgent) StartInstance(context.Context, *agentv1.StartInstanceRequest) (*agentv1.StartInstanceResponse, error) {
	st, _ := status.New(codes.Aborted, "busy").WithDetails(&agentv1.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_BUSY})
	return nil, st.Err()
}

func (f *fakeAgent) BootstrapApiKey(context.Context, *agentv1.BootstrapApiKeyRequest) (*agentv1.BootstrapApiKeyResponse, error) {
	return &agentv1.BootstrapApiKeyResponse{ApiKey: "hskey-api-abcdefghijkl-" + strings.Repeat("s", 64), Prefix: "abcdefghijkl", Created: true}, nil
}

func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mgc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func serve(t *testing.T, dir string) (*fakeAgent, string) {
	t.Helper()
	sock := filepath.Join(dir, "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAgent{}
	gs := grpc.NewServer(grpc.Creds(local.NewCredentials()))
	agentv1.RegisterAgentServiceServer(gs, f)
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	return f, sock
}

func writeToken(t *testing.T, dir, value string) string {
	t.Helper()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(value+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}

func callCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestClientOverUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent runs on Linux")
	}
	dir := socketDir(t)
	f, sock := serve(t, dir)
	c, err := New(Config{Socket: sock, TokenFile: writeToken(t, dir, testToken)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	h, err := c.Health(callCtx(t), &agentv1.HealthRequest{})
	if err != nil || h.GetDriver() != "fake" || len(f.sawAuth) != 1 {
		t.Fatalf("Health = %v, %v (auth %v)", h, err, f.sawAuth)
	}
	// a typed refusal: detail extracted, not retryable
	_, err = c.EnsureInstance(callCtx(t), &agentv1.EnsureInstanceRequest{})
	r, ok := RefusalOf(err)
	if !ok || r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_IMAGE_NOT_ALLOWED || r.GetField() != "spec.image_digest" || Retryable(err) {
		t.Fatalf("refusal = %v %v (%v)", r, ok, err)
	}
	// BUSY: retryable
	_, err = c.StartInstance(callCtx(t), &agentv1.StartInstanceRequest{})
	if r, ok := RefusalOf(err); !ok || r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_BUSY || !Retryable(err) {
		t.Fatalf("busy = %v (%v)", r, err)
	}
	// a secret in a response crosses the socket intact
	k, err := c.BootstrapApiKey(callCtx(t), &agentv1.BootstrapApiKeyRequest{})
	if err != nil || k.GetApiKey() != "hskey-api-abcdefghijkl-"+strings.Repeat("s", 64) {
		t.Fatalf("api key response: %v", err)
	}
	// UNIMPLEMENTED is permanent
	_, err = c.Backup(callCtx(t), &agentv1.BackupRequest{})
	if status.Code(err) != codes.Unimplemented || Retryable(err) {
		t.Fatalf("unimplemented: %v", err)
	}
}

func TestWrongTokenAndNoAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent runs on Linux")
	}
	dir := socketDir(t)
	_, sock := serve(t, dir)
	c, err := New(Config{Socket: sock, TokenFile: writeToken(t, dir, strings.Repeat("x", 40))})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Health(callCtx(t), &agentv1.HealthRequest{}); status.Code(err) != codes.Unauthenticated || Retryable(err) {
		t.Fatalf("wrong token: %v", err)
	}
	// no agent listening: UNAVAILABLE, retryable
	d := socketDir(t)
	c2, err := New(Config{Socket: filepath.Join(d, "missing.sock"), TokenFile: writeToken(t, d, testToken)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if _, err := c2.Health(callCtx(t), &agentv1.HealthRequest{}); status.Code(err) != codes.Unavailable || !Retryable(err) {
		t.Fatalf("no agent: %v", err)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	dir := socketDir(t)
	good := writeToken(t, dir, testToken)
	cases := map[string]Config{
		"relative socket":   {Socket: "agent.sock", TokenFile: good},
		"tcp address":       {Socket: "127.0.0.1:9000", TokenFile: good},
		"missing token":     {Socket: "/run/meshguard/agent.sock", TokenFile: filepath.Join(dir, "absent")},
		"short token":       {Socket: "/run/meshguard/agent.sock", TokenFile: writeTokenAs(t, dir, "short", "abc")},
		"token with spaces": {Socket: "/run/meshguard/agent.sock", TokenFile: writeTokenAs(t, dir, "space", strings.Repeat("a b ", 10))},
		"two-line token":    {Socket: "/run/meshguard/agent.sock", TokenFile: writeTokenAs(t, dir, "lines", testToken+"\n"+testToken)},
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "a b a b") {
			t.Errorf("%s: the error leaks the token: %v", name, err)
		}
	}
	if Retryable(nil) || Retryable(errors.New("plain")) {
		t.Error("Retryable of a non-status error")
	}
}

func writeTokenAs(t *testing.T, dir, name, value string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(value), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}
