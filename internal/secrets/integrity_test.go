package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// TestIntegrityHook — Options.OnIntegrity (P2-T16, G2 wiring hazard 10): an operation refused with ErrIntegrity is
// reported once, with its operation and reference, AFTER its transaction ended (the hook can use the store in a
// transaction of its own — where the processes write the security event); other errors and successes are not
// reported, and nothing in the report carries the value.
func TestIntegrityHook(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	var (
		mu      sync.Mutex
		reports []IntegrityFailure
		inner   []error
	)
	var s *Store
	s = f.newStore(t, f.workerDB, Options{App: f.app.kr, Ops: f.ops.kr, OnIntegrity: func(ctx context.Context, x IntegrityFailure) {
		_, err := s.Latest(ctx, x.Ref.Tenant, x.Ref.Name) // a new transaction: the failed one has ended
		mu.Lock()
		reports, inner = append(reports, x), append(inner, err)
		mu.Unlock()
	}})
	ref, other := TenantRef(f.a, "hooked", 1), TenantRef(f.a, "unhooked", 1)
	mustPut(t, s, ref, "hook value")
	mustPut(t, s, other, "other value")
	if _, err := s.Get(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, TenantRef(f.a, "missing", 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	f.exec(t, `UPDATE secrets SET aad = convert_to('mgsec/v1|platform|hooked|1', 'UTF8') WHERE tenant_id = $1 AND name = $2`,
		f.a, ref.Name)
	if _, err := s.Get(ctx, ref); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 || reports[0].Op != "get" || reports[0].Ref != ref {
		t.Fatalf("reports = %+v, want one get of %s", reports, ref)
	}
	if inner[0] != nil {
		t.Errorf("the hook could not use the store in a transaction of its own: %v", inner[0])
	}
}
