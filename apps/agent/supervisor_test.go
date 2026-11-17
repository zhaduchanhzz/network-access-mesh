//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)

// fakeSupervisor counts cycles, records which instances it could lock, and lets the test signal edge starts.
type fakeSupervisor struct {
	mu     sync.Mutex
	cycles int
	locked []bool
	ids    []uuid.UUID
	edgeID string
	starts chan struct{}
	subs   int
	cycled chan struct{}
}

func (f *fakeSupervisor) EdgeCycle(_ context.Context, tryLock func(uuid.UUID) (func(), bool)) (compose.EdgeReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cycles++
	f.locked = f.locked[:0]
	for _, id := range f.ids {
		unlock, ok := tryLock(id)
		f.locked = append(f.locked, ok)
		if ok {
			unlock()
		}
	}
	select {
	case f.cycled <- struct{}{}:
	default:
	}
	return compose.EdgeReport{EdgeID: f.edgeID, Instances: len(f.ids)}, nil
}

func (f *fakeSupervisor) EdgeStarts(ctx context.Context) <-chan struct{} {
	f.mu.Lock()
	f.subs++
	f.mu.Unlock()
	out := make(chan struct{})
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-f.starts:
				if !ok {
					return
				}
				out <- struct{}{}
			}
		}
	}()
	return out
}

func (f *fakeSupervisor) state() (int, []bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cycles, append([]bool(nil), f.locked...), f.subs
}

func waitCycle(t *testing.T, f *fakeSupervisor) {
	t.Helper()
	select {
	case <-f.cycled:
	case <-time.After(10 * time.Second):
		t.Fatal("no supervisor cycle")
	}
}

// TestSupervisorLoop: a cycle at start, on every tick and at once on an edge start; an instance whose lock is held by
// an operation is skipped (not waited for); a recreated edge (new ID) is logged; the loop ends with its context.
func TestSupervisorLoop(t *testing.T) {
	h := start(t, nil, nil)
	srv := newServer(h.cfg, []byte(token), h.drv, nil, h.logger())
	busy := uuid.New()
	f := &fakeSupervisor{ids: []uuid.UUID{uuid.New(), busy}, edgeID: strings.Repeat("a", 64), starts: make(chan struct{}), cycled: make(chan struct{}, 8)}
	unlock, err := srv.locks.lock(context.Background(), busy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.superviseEdge(ctx, f, time.Hour); close(done) }()
	waitCycle(t, f)
	if n, locked, _ := f.state(); n != 1 || !locked[0] || locked[1] {
		t.Fatalf("first cycle: %d %v", n, locked)
	}
	unlock()
	// the edge is recreated: its start triggers a cycle at once (the ticker is an hour away)
	f.mu.Lock()
	f.edgeID = strings.Repeat("b", 64)
	f.mu.Unlock()
	f.starts <- struct{}{}
	waitCycle(t, f)
	if n, locked, _ := f.state(); n != 2 || !locked[1] {
		t.Fatalf("after the edge start: %d %v", n, locked)
	}
	// the cycle is logged once EdgeCycle returned
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(h.logs.String(), `"msg":"edge_recreated"`); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no edge_recreated line:\n%s", h.logs.String())
		}
	}
	if !strings.Contains(h.logs.String(), `"msg":"edge_started"`) {
		t.Fatalf("no edge_started line:\n%s", h.logs.String())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not stop with its context")
	}
	// the event stream ending does not stop the loop: the ticker goes on
	f2 := &fakeSupervisor{starts: make(chan struct{}), cycled: make(chan struct{}, 8)}
	close(f2.starts)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go srv.superviseEdge(ctx2, f2, time.Second)
	waitCycle(t, f2)
	waitCycle(t, f2)
	if n, _, _ := f2.state(); n < 2 {
		t.Fatalf("%d cycles", n)
	}
}

// TestTryLock: the supervisor never waits for an instance's lock.
func TestTryLock(t *testing.T) {
	l := &instanceLocks{held: map[uuid.UUID]chan struct{}{}, wait: time.Second}
	id := uuid.New()
	unlock, ok := l.tryLock(id)
	if !ok {
		t.Fatal("free lock refused")
	}
	if _, ok := l.tryLock(id); ok {
		t.Fatal("held lock taken")
	}
	start := time.Now()
	if _, err := l.lock(context.Background(), id); err == nil || time.Since(start) < time.Second {
		t.Fatalf("lock while held: %v", err)
	}
	unlock()
	if u, ok := l.tryLock(id); !ok {
		t.Fatal("released lock refused")
	} else {
		u()
	}
}

// TestNoiseFingerprintSubcommand: the helper prints the fingerprint (and nothing of the key), exit 3 when the file is
// absent, 4 when it is not a key; the dispatcher knows the subcommand.
func TestNoiseFingerprintSubcommand(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "noise_private.key")
	const priv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	if err := os.WriteFile(key, []byte("privkey:"+priv), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := noiseFingerprint(key, &out, &errb); code != 0 || out.String() != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a\n" {
		t.Fatalf("ok: %d %q %q", code, out.String(), errb.String())
	}
	if strings.Contains(out.String()+errb.String(), priv) {
		t.Fatal("the private key was printed")
	}
	if code := noiseFingerprint(filepath.Join(dir, "absent"), &out, &errb); code != compose.FingerprintExitAbsent {
		t.Fatalf("absent: %d", code)
	}
	if err := os.WriteFile(key, []byte("privkey:"+strings.Repeat("z", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := noiseFingerprint(key, &out, &errb); code != compose.FingerprintExitInvalid {
		t.Fatalf("invalid: %d", code)
	}
	// the dispatcher runs it on the fixed path (absent outside the helper container ⇒ 3)
	if _, err := os.Stat(compose.NoiseKeyPath); err != nil {
		if code := dispatch(context.Background(), []string{"noise-fingerprint"}, func(string) string { return "" }, nil, &out, &errb); code != compose.FingerprintExitAbsent {
			t.Fatalf("dispatch: %d", code)
		}
	}
	if code := dispatch(context.Background(), []string{"noise-fingerprint", "/etc/shadow"}, func(string) string { return "" }, nil, &out, &errb); code != 2 {
		t.Fatalf("an argument is refused: %d", code)
	}
}
