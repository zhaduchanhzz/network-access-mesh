package jobs

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestRegisterPeriodicRefusals: only a known platform-scope kind, with a function and an interval of at least a
// minute, before Start, once.
func TestRegisterPeriodicRefusals(t *testing.T) {
	w, err := NewWorker(nil, testConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	fn := func(context.Context) error { return nil }
	for name, c := range map[string]struct {
		kind  string
		every time.Duration
		fn    func(context.Context) error
	}{
		"unknown kind":      {"session.nope", time.Hour, fn},
		"tenant-scope kind": {"inventory.sync", time.Hour, fn},
		"too frequent":      {"session.gc", time.Second, fn},
		"no function":       {"session.gc", time.Hour, nil},
	} {
		if err := w.RegisterPeriodic(c.kind, c.every, c.fn); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := w.RegisterPeriodic("session.nope", time.Hour, fn); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: %v, want ErrUnknownKind", err)
	}
	if err := w.RegisterPeriodic("session.gc", time.Hour, fn); err != nil {
		t.Fatal(err)
	}
	if err := w.RegisterPeriodic("session.gc", time.Hour, fn); err == nil {
		t.Error("second registration of session.gc accepted")
	}
	if len(w.periodics) != 1 || w.periodics[0] != (periodic{kind: "session.gc", every: time.Hour}) {
		t.Errorf("periodics = %+v", w.periodics)
	}
}

// TestRegisterPeriodicRuns: a module's periodic job (session.gc, as apps/internal/runner registers it) runs when the
// worker starts and records its run like the built-in ones — a platform job, dedupe key <kind>:<slot>, succeeded.
func TestRegisterPeriodicRuns(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	cfg := testConfig()
	cfg.periodicOff = false
	w, _ := newWorker(t, st, cfg, Options{})
	var calls atomic.Int32
	if err := w.RegisterPeriodic("session.gc", time.Hour, func(context.Context) error {
		calls.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start(t, w)
	eventually(t, 30*time.Second, "session.gc run", func() bool {
		return scalar[int64](t, f, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'session.gc' AND status = 'succeeded'
			AND tenant_id IS NULL AND dedupe_key LIKE 'session.gc:%'`) == 1
	})
	if calls.Load() != 1 {
		t.Errorf("function called %d times, want 1", calls.Load())
	}
	if err := w.RegisterPeriodic("session.gc", time.Hour, func(context.Context) error { return nil }); err == nil {
		t.Error("RegisterPeriodic after Start accepted")
	}
}
