package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)

func at(d time.Duration) time.Time { return t0.Add(d) }

// TestBucket walks one key through burst, denial, partial and full refill with exact header values.
func TestBucket(t *testing.T) {
	l := New(Limit{Every: time.Second, Burst: 3}, 0)
	steps := []struct {
		at                time.Duration
		allowed           bool
		remaining         int64
		reset, retryAfter time.Duration
	}{
		{0, true, 2, 1 * time.Second, 0},
		{0, true, 1, 2 * time.Second, 0},
		{0, true, 0, 3 * time.Second, 0},
		{0, false, 0, 3 * time.Second, 1 * time.Second}, // empty: next token in 1 s
		{500 * time.Millisecond, false, 0, 2500 * time.Millisecond, 500 * time.Millisecond},
		{1 * time.Second, true, 0, 3 * time.Second, 0},  // one token refilled, taken
		{10 * time.Second, true, 2, 1 * time.Second, 0}, // idle long enough: full again (never above Burst)
	}
	for i, s := range steps {
		d := l.Allow("k", at(s.at))
		if d.Allowed != s.allowed || d.Limit != 3 || d.Remaining != s.remaining || d.Reset != s.reset || d.RetryAfter != s.retryAfter {
			t.Fatalf("step %d at %v: got %+v; want allowed=%v remaining=%d reset=%v retryAfter=%v",
				i, s.at, d, s.allowed, s.remaining, s.reset, s.retryAfter)
		}
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(Limit{Every: time.Minute, Burst: 1}, 0)
	if !l.Allow("a", t0).Allowed || l.Allow("a", t0).Allowed {
		t.Fatal("key a: want allow then deny")
	}
	if !l.Allow("b", t0).Allowed {
		t.Fatal("key b must have its own bucket")
	}
}

// TestDeniedRequestsTakeNoToken: hammering an empty bucket does not push the next allowed request further away.
func TestDeniedRequestsTakeNoToken(t *testing.T) {
	l := New(Limit{Every: 10 * time.Second, Burst: 1}, 0)
	l.Allow("k", t0)
	for i := range 100 {
		if l.Allow("k", at(time.Duration(i)*time.Millisecond)).Allowed {
			t.Fatal("allowed while empty")
		}
	}
	if !l.Allow("k", at(10*time.Second)).Allowed {
		t.Fatal("denied requests delayed the refill")
	}
}

// TestFractionalRate: one token every 5 s (0.2/s) — integer arithmetic, no drift after many periods.
func TestFractionalRate(t *testing.T) {
	l := New(Limit{Every: 5 * time.Second, Burst: 1}, 0)
	for i := range 1000 {
		now := at(time.Duration(i) * 5 * time.Second)
		if d := l.Allow("k", now); !d.Allowed {
			t.Fatalf("period %d: denied %+v", i, d)
		}
		if d := l.Allow("k", now.Add(4999*time.Millisecond)); d.Allowed || d.RetryAfter != time.Millisecond {
			t.Fatalf("period %d: early request %+v", i, d)
		}
	}
}

func TestClockGoingBackwards(t *testing.T) {
	l := New(Limit{Every: time.Second, Burst: 2}, 0)
	l.Allow("k", at(time.Hour))
	l.Allow("k", at(time.Hour))
	d := l.Allow("k", t0) // an hour earlier: no refill, no panic, sane values
	if d.Allowed || d.Remaining != 0 || d.RetryAfter <= 0 {
		t.Fatalf("got %+v", d)
	}
}

// TestMemoryIsBounded: full buckets are swept and the key count never exceeds MaxKeys.
func TestMemoryIsBounded(t *testing.T) {
	l := New(Limit{Every: time.Second, Burst: 5}, 100)
	for i := range 10_000 {
		l.Allow(fmt.Sprintf("ip-%d", i), at(time.Duration(i)*time.Millisecond))
		if n := l.Len(); n > 100 {
			t.Fatalf("after %d keys: %d tracked, cap 100", i+1, n)
		}
	}
	// One second after the last request every bucket is full again; the next sweep (≥ 1 min later) drops them.
	l.Allow("late", at(time.Hour))
	if n := l.Len(); n != 1 {
		t.Fatalf("after sweep: %d keys tracked, want 1", n)
	}
}

func TestInvalidLimit(t *testing.T) {
	for _, lim := range []Limit{{0, 1}, {time.Second, 0}, {-time.Second, 5}} {
		if lim.Validate() == nil {
			t.Errorf("%+v: Validate accepted it", lim)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("New accepted an invalid limit")
		}
	}()
	New(Limit{}, 0)
}

// TestConcurrentUse: exactly Burst requests win when many goroutines race on one key (run with -race).
func TestConcurrentUse(t *testing.T) {
	l := New(Limit{Every: time.Hour, Burst: 50}, 0)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("shared", t0).Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 50 {
		t.Fatalf("allowed %d, want 50", allowed)
	}
}
