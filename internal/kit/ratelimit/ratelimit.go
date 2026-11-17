// Package ratelimit is a keyed token bucket ("token bucket theo identity và theo IP", §13.1) with an explicit clock:
// every call passes `now`, so tests are deterministic and the limiter never reads the wall clock itself. It holds no
// HTTP code — internal/httpapi maps a Decision to RateLimit-*, Retry-After and 429.
//
// The bucket is kept in its GCRA form (one "theoretical arrival time" per key, integer durations): exactly a token
// bucket of capacity Burst refilled with one token every Every, without floating-point drift. A key whose bucket is
// full again carries no state and is dropped by a periodic sweep; the number of keys is capped (MaxKeys), and when the
// cap is reached an arbitrary key is evicted — its bucket simply starts full again — so a flood of new keys (spoofed
// sources, IPv6 rotation) costs bounded memory and CPU.
package ratelimit

import (
	"errors"
	"sync"
	"time"
)

// Limit is the bucket of one key: capacity Burst, one token added every Every.
type Limit struct {
	Every time.Duration
	Burst int
}

// Validate reports a limit that cannot work.
func (l Limit) Validate() error {
	if l.Every <= 0 || l.Burst < 1 {
		return errors.New("ratelimit: Every must be > 0 and Burst ≥ 1")
	}
	return nil
}

// Decision is the outcome of one Allow call, with the values of the RateLimit-* response headers.
type Decision struct {
	Allowed    bool
	Limit      int           // bucket capacity (RateLimit-Limit)
	Remaining  int64         // whole requests still allowed right now (RateLimit-Remaining)
	Reset      time.Duration // until the bucket is full again (RateLimit-Reset)
	RetryAfter time.Duration // until the next request is allowed; set only when !Allowed (Retry-After)
}

// DefaultMaxKeys caps the keys tracked by one Limiter.
const DefaultMaxKeys = 100_000

// sweepEvery is how often full buckets are dropped.
const sweepEvery = time.Minute

// Limiter applies one Limit to any number of keys. It is safe for concurrent use.
type Limiter struct {
	limit   Limit
	maxKeys int

	mu    sync.Mutex
	tat   map[string]time.Time // theoretical arrival time: the bucket of the key is full again at tat
	swept time.Time
}

// New returns a limiter; maxKeys ≤ 0 means DefaultMaxKeys. It panics on an invalid limit (validate it first).
func New(l Limit, maxKeys int) *Limiter {
	if err := l.Validate(); err != nil {
		panic(err)
	}
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	return &Limiter{limit: l, maxKeys: maxKeys, tat: map[string]time.Time{}}
}

// Limit returns the limit the limiter applies.
func (l *Limiter) Limit() Limit { return l.limit }

// Allow takes one token from the bucket of key at time now.
func (l *Limiter) Allow(key string, now time.Time) Decision {
	every := l.limit.Every
	capacity := every * time.Duration(l.limit.Burst)

	l.mu.Lock()
	defer l.mu.Unlock()
	tat, tracked := l.tat[key]
	if !tracked {
		l.makeRoom(now)
	}
	if tat.Before(now) {
		tat = now // the bucket is full; a clock that went backwards never refills it
	}
	d := Decision{Limit: l.limit.Burst}
	if wait := tat.Add(every).Sub(now) - capacity; wait > 0 {
		d.RetryAfter = wait // denied requests take no token
	} else {
		tat = tat.Add(every)
		l.tat[key] = tat
		d.Allowed = true
	}
	d.Reset = tat.Sub(now)
	d.Remaining = max(0, int64((capacity-d.Reset)/every))
	return d
}

// Len returns the number of keys whose bucket is not full (or not yet swept).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tat)
}

// makeRoom runs the periodic sweep, then evicts arbitrary keys while the cap is reached. Called with mu held.
func (l *Limiter) makeRoom(now time.Time) {
	full := len(l.tat) >= l.maxKeys
	if now.Sub(l.swept) >= sweepEvery || (full && now.Sub(l.swept) >= time.Second) {
		for k, tat := range l.tat {
			if !tat.After(now) {
				delete(l.tat, k)
			}
		}
		l.swept = now
	}
	for k := range l.tat { // map iteration order is randomized: this evicts an arbitrary key
		if len(l.tat) < l.maxKeys {
			break
		}
		delete(l.tat, k)
	}
}
