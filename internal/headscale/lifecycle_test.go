package headscale

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// checkingLocator is a mutableLocator whose tenant can be taken out of service: CheckTarget (the cheap re-check of a
// cached target) and Locate then report it.
type checkingLocator struct {
	*mutableLocator
	cmu    sync.Mutex
	down   error
	checks int
}

func (c *checkingLocator) CheckTarget(_ context.Context, _ uuid.UUID, _ Target) error {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	c.checks++
	return c.down
}

func (c *checkingLocator) Locate(ctx context.Context, id uuid.UUID) (Target, error) {
	c.cmu.Lock()
	down := c.down
	c.cmu.Unlock()
	if errors.Is(down, ErrNoInstance) {
		return Target{}, down
	}
	return c.mutableLocator.Locate(ctx, id)
}

func (c *checkingLocator) set(err error) {
	c.cmu.Lock()
	c.down = err
	c.cmu.Unlock()
}

func (c *checkingLocator) checkCount() int {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	return c.checks
}

// TestLifecycleChangeSeenWithinTTL — G2 L1: a cached target is re-checked on every ForTenant when the Locator can do it
// cheaply (StatusChecker — the production locator reads the tenant and instance status, no secret). A tenant suspended
// or an instance quarantined while its target is cached is refused at once (instance_unavailable wrapping
// ErrNoInstance), without any call to the instance and without waiting for the TTL or for an Invalidate from the
// lifecycle code; a check that cannot be made fails closed.
func TestLifecycleChangeSeenWithinTTL(t *testing.T) {
	h := newHarness(t, Options{})
	cl := &checkingLocator{mutableLocator: h.loc}
	h.reg = NewRegistry(cl, Options{CacheTTL: time.Hour, Now: h.clk.now})
	h.reg.sleep = func(context.Context, time.Duration) bool { return true }
	h.edge.on("GET", "/api/v1/user", 200, `{"users":[]}`)
	ctx := context.Background()

	inst, err := h.reg.ForTenant(ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.ListUsers(ctx, UserFilter{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.ForTenant(ctx, testTenant); err != nil {
		t.Fatal(err)
	}
	if h.loc.count() != 1 || cl.checkCount() != 1 {
		t.Fatalf("cache hit: %d locates, %d checks — want the cached target re-checked, not located again", h.loc.count(),
			cl.checkCount())
	}

	// A check that cannot be made (database unreachable) fails closed.
	cl.set(errors.New("registry unreachable"))
	if _, err := h.reg.ForTenant(ctx, testTenant); !errors.Is(err, ErrInternal) || errors.Is(err, ErrNoInstance) {
		t.Fatalf("failed check: %v, want an internal error", err)
	}
	cl.set(nil)
	if _, err := h.reg.ForTenant(ctx, testTenant); err != nil {
		t.Fatalf("after a failed check: %v", err)
	}

	// The tenant is suspended — nobody calls Invalidate — one second into a one-hour TTL.
	cl.set(fmt.Errorf("tenant %s is suspended: %w", testTenant, ErrNoInstance))
	h.clk.advance(time.Second)
	calls := len(h.edge.requests())
	for range 2 {
		_, err := h.reg.ForTenant(ctx, testTenant)
		var he *Error
		if !errors.Is(err, ErrNoInstance) || !errors.As(err, &he) || he.Kind != KindUnavailable {
			t.Fatalf("suspended tenant within the TTL: %v, want instance_unavailable wrapping ErrNoInstance", err)
		}
	}
	if n := len(h.edge.requests()); n != calls {
		t.Fatalf("%d calls reached the instance of a suspended tenant", n-calls)
	}
	if _, ok := h.reg.CachedVersion(testTenant); ok {
		t.Fatal("the target of a suspended tenant is still cached")
	}

	// Resumed: located again, no restart.
	cl.set(nil)
	if _, err := h.reg.ForTenant(ctx, testTenant); err != nil {
		t.Fatalf("resumed tenant: %v", err)
	}
}

// TestReplacedInstanceLocatedAgain — G2 L1: when the re-check reports that the tenant's live instance is not the cached
// one any more (re-provisioned, adopted again), the stale target is dropped and the new one located in the same call.
func TestReplacedInstanceLocatedAgain(t *testing.T) {
	h := newHarness(t, Options{})
	cl := &checkingLocator{mutableLocator: h.loc}
	h.reg = NewRegistry(cl, Options{CacheTTL: time.Hour, Now: h.clk.now})
	ctx := context.Background()
	if _, err := h.reg.ForTenant(ctx, testTenant); err != nil {
		t.Fatal(err)
	}
	cl.set(fmt.Errorf("live instance replaced: %w", ErrTargetStale))
	if _, err := h.reg.ForTenant(ctx, testTenant); err != nil {
		t.Fatalf("replaced instance: %v", err)
	}
	if h.loc.count() != 2 {
		t.Fatalf("replaced instance: %d locates, want 2 (the stale target located again)", h.loc.count())
	}
}
