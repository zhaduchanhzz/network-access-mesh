package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// fakeWorker counts the starts and stops of the job worker.
type fakeWorker struct {
	mu            sync.Mutex
	starts, stops int
	failStart     bool
}

func (f *fakeWorker) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStart {
		return errors.New("start refused")
	}
	f.starts++
	return nil
}

func (f *fakeWorker) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	return nil
}

func (f *fakeWorker) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.stops
}

type boolGate struct{ on atomic.Bool }

func (g *boolGate) On() bool { return g.on.Load() }

// TestWorkControl (P3-T17): the job worker and the schedules run only while the gate is off — not started in
// maintenance, started when it ends, stopped (schedules cancelled first) when it starts again, a failed start retried,
// everything stopped when the process stops.
func TestWorkControl(t *testing.T) {
	gate := &boolGate{}
	gate.on.Store(true)
	w := &fakeWorker{}
	var scheduled atomic.Int32
	sched := func(ctx context.Context) error {
		scheduled.Add(1)
		<-ctx.Done()
		scheduled.Add(-1)
		return ctx.Err()
	}
	c := &workControl{gate: gate, w: w, log: slog.New(slog.DiscardHandler), check: 10 * time.Millisecond,
		stopWait: time.Second, schedules: map[string]func(context.Context) error{"a": sched, "b": sched}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if s, _ := w.counts(); s != 0 || c.Running() || scheduled.Load() != 0 {
		t.Fatalf("in maintenance: %d starts, running %v, %d schedules", s, c.Running(), scheduled.Load())
	}
	gate.on.Store(false)
	waitFor("start when maintenance ends", func() bool { return c.Running() && scheduled.Load() == 2 })
	gate.on.Store(true)
	waitFor("stop when maintenance starts", func() bool { _, st := w.counts(); return !c.Running() && st == 1 })
	if n := scheduled.Load(); n != 0 {
		t.Fatalf("%d schedules still running in maintenance", n)
	}
	w.mu.Lock()
	w.failStart = true
	w.mu.Unlock()
	gate.on.Store(false)
	time.Sleep(50 * time.Millisecond)
	if c.Running() {
		t.Fatal("running although the start failed")
	}
	w.mu.Lock()
	w.failStart = false
	w.mu.Unlock()
	waitFor("start retried", func() bool { return c.Running() })
	cancel()
	<-done
	if s, st := w.counts(); c.Running() || s != 2 || st != 2 || scheduled.Load() != 0 {
		t.Fatalf("after the process stopped: running %v, %d starts, %d stops, %d schedules", c.Running(), s, st, scheduled.Load())
	}
}

// TestMaintenanceModeWired (P3-T17): the api started with MG_MAINTENANCE=1 answers 503 maintenance (problem+json,
// Retry-After) to a tenant route while it still serves the platform sign-in on admin.<domain>; a second api without the
// switch follows the persisted flag system_settings `maintenance` (polled): ON ⇒ 503 within one poll, OFF ⇒ served
// again; the worker started while the flag is ON logs that its job worker is not started and exports
// meshguard_maintenance_mode 1.
func TestMaintenanceModeWired(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	token := randomToken()
	tokenFile := writeFile(t, t.TempDir(), "edge_admin_token", token+"\n")
	edge := fakeEdgeAdmin(t, token)
	call := func(base, host, path string) (int, string, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		var p struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(b, &p)
		return resp.StatusCode, p.Code, resp.Header.Get("Retry-After")
	}

	forced := wiredEnv(t, "api", pg.URL(db), pg, edge.URL, tokenFile)
	forced["MG_MAINTENANCE"] = "1"
	_, public, _ := startProcess(t, "api", forced)
	if s, code, ra := call(public, "app.mg.test", "/api/v1/tenants"); s != http.StatusServiceUnavailable ||
		code != "maintenance" || ra != "60" {
		t.Fatalf("forced maintenance, GET /tenants: %d %s Retry-After %q", s, code, ra)
	}
	if s, code, _ := call(public, "admin.mg.test", "/api/v1/auth/session"); s != http.StatusUnauthorized {
		t.Fatalf("forced maintenance, platform GET /auth/session: %d %s (want the sign-in served: 401)", s, code)
	}

	_, plain, _ := startProcess(t, "api", wiredEnv(t, "api", pg.URL(db), pg, edge.URL, tokenFile))
	if s, _, _ := call(plain, "app.mg.test", "/api/v1/tenants"); s != http.StatusUnauthorized {
		t.Fatalf("no maintenance, GET /tenants without a session: %d, want 401", s)
	}
	pg.Exec(t, db, `INSERT INTO system_settings (key, value) VALUES ('maintenance', '{"enabled": true, "reason": "test"}')`)
	deadline := time.Now().Add(15 * time.Second)
	for {
		s, code, _ := call(plain, "app.mg.test", "/api/v1/tenants")
		if s == http.StatusServiceUnavailable && code == "maintenance" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("persisted flag ON: still %d %s", s, code)
		}
		time.Sleep(200 * time.Millisecond)
	}
	workerInternal, _, logs := startProcess(t, "worker", wiredEnv(t, "worker", pg.URL(db), pg, edge.URL, tokenFile))
	if !strings.Contains(logs.String(), "the job worker and the schedules are not started") {
		t.Errorf("worker in maintenance: log lacks the notice\n%s", logs.String())
	}
	if r, err := get(t, workerInternal+"/metrics"); err != nil || !strings.Contains(r.body, "meshguard_maintenance_mode 1") {
		t.Errorf("worker metrics: %v %v", err, r.status)
	}
	pg.Exec(t, db, `UPDATE system_settings SET value = '{"enabled": false}' WHERE key = 'maintenance'`)
	deadline = time.Now().Add(15 * time.Second)
	for {
		if s, _, _ := call(plain, "app.mg.test", "/api/v1/tenants"); s == http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("persisted flag OFF: still in maintenance")
		}
		time.Sleep(200 * time.Millisecond)
	}
	deadline = time.Now().Add(15 * time.Second)
	for !strings.Contains(logs.String(), "job worker and schedules started") {
		if time.Now().After(deadline) {
			t.Fatalf("worker did not start its job worker after maintenance\n%s", logs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
