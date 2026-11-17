package headscale

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	b := NewBreaker(BreakerConfig{FailureThreshold: 3, OpenFor: 10 * time.Second}, clk.now)

	for i := 0; i < 2; i++ {
		if !b.Allow() {
			t.Fatal("closed breaker refused a call")
		}
		b.Failure()
	}
	if b.State() != BreakerClosed {
		t.Fatal("opened before the threshold")
	}
	// An answer from the instance resets the count: failures must be consecutive.
	b.Allow()
	b.Success()
	for i := 0; i < 3; i++ {
		b.Allow()
		b.Failure()
	}
	if b.State() != BreakerOpen || b.Allow() {
		t.Fatalf("breaker should be open and refuse calls, state %s", b.State())
	}

	// After OpenFor exactly one trial call is let through.
	clk.advance(10 * time.Second)
	if !b.Allow() {
		t.Fatal("no trial call after OpenFor")
	}
	if b.State() != BreakerHalfOpen || b.Allow() {
		t.Fatal("half-open breaker must allow a single trial call")
	}
	// A failed trial re-opens for another OpenFor.
	b.Failure()
	if b.State() != BreakerOpen || b.Allow() {
		t.Fatal("failed trial must re-open the breaker")
	}
	clk.advance(10 * time.Second)
	if !b.Allow() {
		t.Fatal("no second trial")
	}
	b.Success()
	if b.State() != BreakerClosed || !b.Allow() {
		t.Fatal("successful trial must close the breaker")
	}
}

func TestBreakerAbandonReleasesTrial(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	b := NewBreaker(BreakerConfig{FailureThreshold: 1, OpenFor: time.Second}, clk.now)
	b.Allow()
	b.Failure()
	clk.advance(time.Second)
	if !b.Allow() {
		t.Fatal("no trial")
	}
	b.Abandon() // the caller cancelled: no verdict, but the next call may probe
	if !b.Allow() {
		t.Fatal("abandoned trial kept the breaker blocked")
	}
}

func TestBreakerDefaults(t *testing.T) {
	c := BreakerConfig{}.withDefaults()
	if c.FailureThreshold != 5 || c.OpenFor != 30*time.Second {
		t.Fatalf("defaults = %+v", c)
	}
}
