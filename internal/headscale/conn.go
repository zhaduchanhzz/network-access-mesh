package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Header names of the edge admin listener (§14.6). The edge strips both X-MG-* headers before Headscale.
const (
	HeaderEdgeToken = "X-MG-Token" //nolint:gosec // G101: a header name, not a credential
	HeaderInstance  = "X-MG-Instance"
)

// maxResponseBytes bounds every response body read by the adapter.
const maxResponseBytes = 8 << 20

// RetryPolicy is the backoff for safe GETs (§13.4 rule 3). Writes are never retried by the adapter.
type RetryPolicy struct {
	Attempts  int           // total attempts for a safe GET (default 3)
	BaseDelay time.Duration // first backoff (default 200ms), doubled per attempt, with full jitter
	MaxDelay  time.Duration // cap (default 2s)
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.Attempts <= 0 {
		p.Attempts = 3
	}
	if p.BaseDelay <= 0 {
		p.BaseDelay = 200 * time.Millisecond
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = 2 * time.Second
	}
	return p
}

// delay returns the backoff before attempt n+1 (n ≥ 1): full jitter in [d/2, d], d = min(Base·2^(n-1), Max).
func (p RetryPolicy) delay(n int, jitter func(int64) int64) time.Duration {
	d := p.MaxDelay
	if n >= 1 && n <= 30 {
		if x := p.BaseDelay << (n - 1); x > 0 && x < p.MaxDelay {
			d = x
		}
	}
	half := int64(d / 2)
	return time.Duration(half + jitter(half+1))
}

// call describes one HTTP exchange. path is a constant template whose variable segments were validated and
// escaped by the caller; nothing from a request ever becomes part of the base URL.
type call struct {
	op     Op
	method string
	path   string
	query  url.Values
	body   any // JSON-encoded when non-nil
	out    any // JSON-decoded from a 2xx body when non-nil
	auth   bool
}

// conn is the per-instance transport shared by the version-specific implementations.
type conn struct {
	reg      *CachingRegistry
	tenantID uuid.UUID
	breaker  *Breaker

	mu     sync.Mutex
	target Target
	base   string
}

func (c *conn) current() (Target, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.target, c.base
}

// do runs the call, retrying safe GETs with backoff and replaying once after reloading credentials when the edge
// (403) or the instance (401) rejected them — such a request was not processed, so the replay is safe for writes.
func (c *conn) do(ctx context.Context, cl call) error {
	attempts := 1
	if cl.method == http.MethodGet && cl.op.RetryClass() == RetrySafe {
		attempts = c.reg.retry.Attempts
	}
	reloaded := false
	for attempt := 1; ; attempt++ {
		e := c.once(ctx, cl, attempt)
		if e == nil {
			return nil
		}
		if (e.Kind == KindAPIKeyRejected || e.Kind == KindEdgeRejected) && !reloaded {
			reloaded = true
			if c.reloadCredentials(ctx) {
				attempt--
				continue
			}
			if e.Kind == KindAPIKeyRejected {
				// §13.4: a key the registry still considers valid was refused — the instance's DB may have been
				// replaced. The caller raises the Critical alert; never re-run apikey.bootstrap automatically.
				c.reg.log.Error("headscale instance rejected the platform API key after reload",
					"op", string(cl.op), "tenant_id", c.tenantID.String())
			}
			return e
		}
		if attempt >= attempts || !transient(e) || ctx.Err() != nil {
			return e
		}
		if !c.reg.sleep(ctx, c.reg.retry.delay(attempt, c.reg.jitter)) {
			return e
		}
	}
}

// transient reports whether the error says "the instance did not answer" (counted by the breaker, retried for GETs).
func transient(e *Error) bool {
	if e.Kind != KindUnavailable || errors.Is(e.Err, context.Canceled) {
		return false
	}
	switch {
	case e.Status == 0: // transport error or timeout
		return true
	case e.Status == http.StatusServiceUnavailable, e.Status == http.StatusGatewayTimeout:
		return true
	case e.Code < 0 && (e.Status == http.StatusNotFound || e.Status == http.StatusBadGateway):
		return true // the edge could not route (instance stopped, unreachable or unknown)
	}
	return false
}

func (c *conn) once(ctx context.Context, cl call, attempt int) *Error {
	if !c.breaker.Allow() {
		return &Error{Op: cl.op, Kind: KindCircuitOpen, Code: -1, Outcome: OutcomeNotApplied, Err: ErrCircuitOpen}
	}
	target, base := c.current()
	timeout := c.reg.timeout
	if target.Timeout > 0 {
		timeout = target.Timeout
	}
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := newRequest(actx, cl, target, base)
	if err != nil {
		c.breaker.Abandon()
		return localError(cl.op, KindInternal, err.Error())
	}
	start := c.reg.now()
	resp, err := c.reg.client.Do(req)
	if err != nil {
		e := c.transportError(ctx, actx, cl, target, err)
		c.logResult(cl, target, attempt, start, e)
		return e
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		e := c.transportError(ctx, actx, cl, target, err)
		c.logResult(cl, target, attempt, start, e)
		return e
	}
	if len(body) > maxResponseBytes {
		c.breaker.Success()
		e := &Error{Op: cl.op, Kind: KindUpstreamRejected, Status: resp.StatusCode, Code: -1,
			Upstream: "response larger than the adapter limit", Outcome: writeOutcome(cl)}
		c.logResult(cl, target, attempt, start, e)
		return e
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.breaker.Success()
		if cl.out != nil {
			if err := json.Unmarshal(body, cl.out); err != nil {
				e := &Error{Op: cl.op, Kind: KindUpstreamRejected, Status: resp.StatusCode, Code: -1,
					Upstream: "undecodable response: " + err.Error(), Outcome: writeOutcome(cl)}
				c.logResult(cl, target, attempt, start, e)
				return e
			}
		}
		c.logResult(cl, target, attempt, start, nil)
		return nil
	}
	e := classify(cl.op, resp.StatusCode, body)
	e.Upstream = scrub(e.Upstream, target)
	if transient(e) {
		c.breaker.Failure()
		if e.Code < 0 {
			// The edge answers the same bare 404/502/504 whether it could not reach the instance or lost it in the
			// middle of the request (observed: AuthRegister with an SSH-check Auth ID crashes Headscale — V-26), so
			// a write may or may not have happened.
			e.Outcome = writeOutcome(cl)
		}
	} else {
		c.breaker.Success()
	}
	c.logResult(cl, target, attempt, start, e)
	return e
}

// writeOutcome is the outcome of a write whose request reached the instance but whose answer is unusable.
func writeOutcome(cl call) Outcome {
	if cl.method == http.MethodGet || cl.op.RetryClass() == RetrySafe {
		return OutcomeNotApplied
	}
	return OutcomeUnknown
}

func (c *conn) transportError(parent, attemptCtx context.Context, cl call, t Target, err error) *Error {
	e := &Error{Op: cl.op, Kind: KindUnavailable, Code: -1, Outcome: writeOutcome(cl)}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		e.Outcome = OutcomeNotApplied // the request never left
	}
	switch {
	case parent.Err() != nil: // cancelled or timed out by the caller: no verdict about the instance
		c.breaker.Abandon()
		e.Err = parent.Err()
	case errors.Is(attemptCtx.Err(), context.DeadlineExceeded):
		c.breaker.Failure()
		e.Err = fmt.Errorf("no answer within the per-call timeout: %w", context.DeadlineExceeded)
	default:
		c.breaker.Failure()
		e.Err = errors.New(scrub(err.Error(), t))
	}
	return e
}

// reloadCredentials asks the registry for a fresh target (bypassing its cache) and reports whether the API key or
// the edge token changed, in which case the request is replayed once.
func (c *conn) reloadCredentials(ctx context.Context) bool {
	fresh, base, err := c.reg.reload(ctx, c.tenantID)
	if err != nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if fresh.InstanceID != c.target.InstanceID || base != c.base {
		return false // the instance itself changed: the caller must ask the registry again
	}
	if fresh.APIKey.Reveal() == c.target.APIKey.Reveal() && fresh.EdgeToken.Reveal() == c.target.EdgeToken.Reveal() {
		return false
	}
	c.target = fresh
	return true
}

func newRequest(ctx context.Context, cl call, t Target, base string) (*http.Request, error) {
	u := base + cl.path
	if len(cl.query) > 0 {
		u += "?" + cl.query.Encode()
	}
	var body io.Reader = http.NoBody
	if cl.body != nil {
		b, err := json.Marshal(cl.body)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, cl.method, u, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set(HeaderEdgeToken, t.EdgeToken.Reveal())
	req.Header.Set(HeaderInstance, t.Slug)
	if cl.auth {
		req.Header.Set("Authorization", "Bearer "+t.APIKey.Reveal())
	}
	req.Header.Set("Accept", "application/json")
	if cl.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "meshguard-headscale-adapter")
	return req, nil
}

// scrub removes the target's credentials and every hskey-… credential from a message before it is stored.
func scrub(msg string, t Target) string {
	return logx.RedactString(t.EdgeToken.scrub(t.APIKey.scrub(msg)))
}

func (c *conn) logResult(cl call, t Target, attempt int, start time.Time, e *Error) {
	attrs := []any{
		"op", string(cl.op), "tenant_id", c.tenantID.String(), "instance_id", t.InstanceID.String(),
		"method", cl.method, "path", cl.path, "attempt", attempt,
		"duration_ms", c.reg.now().Sub(start).Milliseconds(),
	}
	if e == nil {
		c.reg.log.Debug("headscale call", attrs...)
		return
	}
	attrs = append(attrs, "kind", string(e.Kind), "status", e.Status, "code", e.Code, "outcome", e.Outcome.String(),
		"upstream", e.Upstream)
	if e.Err != nil {
		attrs = append(attrs, "cause", e.Err.Error())
	}
	level := slog.LevelWarn
	if e.Kind == KindValidation || e.Kind == KindNotFound || e.Kind == KindConflict {
		level = slog.LevelInfo
	}
	c.reg.log.Log(context.Background(), level, "headscale call failed", attrs...)
}

// defaultJitter returns a value in [0, n).
func defaultJitter(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return rand.Int64N(n) //nolint:gosec // jitter, not security
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
