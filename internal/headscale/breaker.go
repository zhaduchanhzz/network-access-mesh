package headscale

import (
	"sync"
	"time"
)

// BreakerConfig configures the per-instance circuit breaker (§13.4 rule 2).
type BreakerConfig struct {
	// FailureThreshold is the number of consecutive counted failures that opens the circuit (default 5).
	FailureThreshold int
	// OpenFor is how long the circuit stays open before one trial call is let through (default 30s).
	OpenFor time.Duration
}

func (c BreakerConfig) withDefaults() BreakerConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.OpenFor <= 0 {
		c.OpenFor = 30 * time.Second
	}
	return c
}

// BreakerState is the state of a circuit breaker.
type BreakerState string

// Breaker states.
const (
	BreakerClosed   BreakerState = "closed"
	BreakerOpen     BreakerState = "open"
	BreakerHalfOpen BreakerState = "half_open"
)

// Breaker is a small consecutive-failure circuit breaker. Only failures that say "the instance is not answering"
// are counted (transport error, timeout, 503/504, the edge cannot route); any other answer — including a business
// error such as not_found — proves the instance is alive and resets the count. A call cancelled by its caller
// counts as neither.
type Breaker struct {
	cfg BreakerConfig
	now func() time.Time

	mu       sync.Mutex
	state    BreakerState
	failures int
	openedAt time.Time
	probing  bool // a half-open trial call is in flight
}

// NewBreaker returns a closed breaker.
func NewBreaker(cfg BreakerConfig, now func() time.Time) *Breaker {
	if now == nil {
		now = time.Now
	}
	return &Breaker{cfg: cfg.withDefaults(), now: now, state: BreakerClosed}
}

// Allow reports whether a call may proceed. When it returns true the caller must report the outcome with
// Success, Failure or Abandon.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case BreakerOpen:
		if b.now().Sub(b.openedAt) < b.cfg.OpenFor {
			return false
		}
		b.state, b.probing = BreakerHalfOpen, true
		return true
	case BreakerHalfOpen:
		if b.probing {
			return false
		}
		b.probing = true
		return true
	default:
		return true
	}
}

// Success records an answer from the instance.
func (b *Breaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state, b.failures, b.probing = BreakerClosed, 0, false
}

// Failure records a counted failure.
func (b *Breaker) Failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.state == BreakerHalfOpen || b.failures >= b.cfg.FailureThreshold {
		b.state, b.openedAt, b.probing = BreakerOpen, b.now(), false
	}
}

// Abandon records a call that ended without a verdict (cancelled by its caller).
func (b *Breaker) Abandon() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
}

// State returns the current state (open turns into half-open only when a call is allowed).
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
