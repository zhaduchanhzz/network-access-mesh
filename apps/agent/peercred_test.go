//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
)

// TestPeerCredAcrossUIDs connects from a real process running under another UID, so the agent sees that UID through
// SO_PEERCRED (kernel-attested — the client cannot claim another). Needs root to switch UID (CI runs Go tests as
// root in the pinned golang container); skipped otherwise — TestPeerCredRefused covers the logic.
func TestPeerCredAcrossUIDs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the client under another UID")
	}
	const stranger, worker = 65534, 65533
	h := start(t, nil, []uint32{worker})
	// the client process must reach the socket and its token: open the directory and the socket to everyone for
	// this test only (the agent checks the peer, not the file mode, here)
	if err := os.Chmod(filepath.Dir(h.sock), 0o755); err != nil { //nolint:gosec // G302: reachable by the client under another UID
		t.Fatal(err)
	}
	if err := os.Chmod(h.sock, 0o666); err != nil { //nolint:gosec // G302: reachable by the client under another UID
		t.Fatal(err)
	}
	bin := filepath.Join(h.dir, "agent.test")
	copyExecutable(t, bin)
	tok := filepath.Join(h.dir, "client-token")
	if err := os.WriteFile(tok, []byte(token), 0o444); err != nil { //nolint:gosec // G306: readable by the client process under another UID
		t.Fatal(err)
	}
	if err := os.Chmod(h.dir, 0o755); err != nil { //nolint:gosec // G302: reachable by the client under another UID
		t.Fatal(err)
	}
	runAs := func(uid uint32) int {
		cmd := exec.CommandContext(tctx(t), bin, "-test.run=^TestHelperPeerClient$", "-test.count=1") //nolint:gosec // the test binary itself
		cmd.Env = []string{"MG_AGENT_TEST_PEER_SOCKET=" + h.sock, "MG_AGENT_TEST_PEER_TOKEN=" + tok}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("run as %d: %v\n%s", uid, err, out)
		}
		return 0
	}
	if code := runAs(stranger); code != 3 {
		t.Fatalf("stranger UID %d: exit %d, want 3 (refused at connection)", stranger, code)
	}
	if code := runAs(worker); code != 0 {
		t.Fatalf("worker UID %d: exit %d, want 0", worker, code)
	}
	refused := h.logs.lines(t, "agent_peer_refused")
	if len(refused) == 0 || refused[0]["peer_uid"] != float64(stranger) {
		t.Fatalf("refusal of UID %d not logged with the kernel-attested UID: %v", stranger, refused)
	}
	calls := h.logs.lines(t, "agent_call")
	if len(calls) == 0 || calls[len(calls)-1]["peer_uid"] != float64(worker) {
		t.Fatalf("Health of the worker UID not logged with its UID: %v", calls)
	}
}

// TestHelperPeerClient is the client process of TestPeerCredAcrossUIDs (exit 0 = served, 3 = refused, 4 = other).
func TestHelperPeerClient(t *testing.T) {
	sock := os.Getenv("MG_AGENT_TEST_PEER_SOCKET")
	if sock == "" {
		t.Skip("helper process of TestPeerCredAcrossUIDs")
	}
	c, err := agentclient.New(agentclient.Config{Socket: sock, TokenFile: os.Getenv("MG_AGENT_TEST_PEER_TOKEN")})
	if err != nil {
		os.Exit(4)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.Health(ctx, &agentv1.HealthRequest{})
	switch status.Code(err) {
	case codes.OK:
		os.Exit(0)
	case codes.Unavailable:
		os.Exit(3)
	}
	os.Exit(4)
}

func copyExecutable(t *testing.T, dst string) {
	t.Helper()
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src) //nolint:gosec // the running test binary
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
