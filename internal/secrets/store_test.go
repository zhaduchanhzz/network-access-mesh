package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

const privilegeErr = "42501" // insufficient_privilege — also a row refused by a WITH CHECK policy

func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Errorf("%s: err = %v, want %v", what, err, target)
	}
}

func wantSQLState(t *testing.T, what string, err error, code string) {
	t.Helper()
	if got := store.SQLState(err); got != code {
		t.Errorf("%s: SQLSTATE %q (err = %v), want %s", what, got, err, code)
	}
}

// TestPutGetAllScopes: tenant secrets (each through its tenant's transaction), a platform secret (api) and a
// platform_ops secret (worker); what lands in the database is ciphertext bound to its reference.
func TestPutGetAllScopes(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	refA := TenantRef(f.a, "headscale.apikey", 1)
	refB := TenantRef(f.b, "headscale.apikey", 1) // same name and version, other tenant
	plat := PlatformRef("oidc.portal.client-secret", 1)
	ops := PlatformRef("smtp.password", 1)
	mustPut(t, f.api, refA, "value of tenant A")
	mustPut(t, f.api, refB, "value of tenant B")
	mustPut(t, f.api, plat, "platform value")
	mustPut(t, f.worker, ops, "ops value", WithPlatformOps())

	for _, s := range []*Store{f.api, f.worker} {
		wantValue(t, s, refA, "value of tenant A")
		wantValue(t, s, refB, "value of tenant B")
		wantValue(t, s, plat, "platform value")
	}
	wantValue(t, f.worker, ops, "ops value")
	_, err := f.api.Get(ctx, ops)
	wantErr(t, "api reading a platform_ops secret", err, ErrNotFound)

	// one active DEK v1 per owner, wrapped by the right keyring
	for o, kek := range map[Owner]string{
		TenantOwner(f.a): f.app.kr.Active(), TenantOwner(f.b): f.app.kr.Active(),
		PlatformOwner: f.app.kr.Active(), PlatformOpsOwner: f.ops.kr.Active(),
	} {
		d := f.deks(t, o)
		if len(d) != 1 || d[0].version != 1 || d[0].state != "active" || d[0].kekID != kek ||
			len(d[0].wrapped) != keySize+16 || len(d[0].nonce) != nonceSize {
			t.Errorf("%s: DEKs %+v, want one active v1 wrapped by %s", o, d, kek)
		}
	}
	// rows: AAD = reference binding, ciphertext ≠ plaintext
	for ref, value := range map[Ref]string{refA: "value of tenant A", plat: "platform value", ops: "ops value"} {
		var aad, ct, nonce []byte
		var scope string
		if err := f.su.QueryRow(ctx, `SELECT aad, ciphertext, nonce, scope FROM secrets WHERE tenant_id IS NOT DISTINCT FROM $1
			AND name = $2 AND version = $3`, tenantArg(ref), ref.Name, ref.Version).Scan(&aad, &ct, &nonce, &scope); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(aad, secretAAD(ref)) || bytes.Contains(ct, []byte(value)) || len(nonce) != nonceSize {
			t.Errorf("%s: aad %q, ciphertext contains plaintext=%v, nonce %d bytes", ref, aad, bytes.Contains(ct, []byte(value)), len(nonce))
		}
		if ref == ops && scope != string(ScopePlatformOps) {
			t.Errorf("%s stored with scope %s", ref, scope)
		}
	}

	// argument checks
	wantErr(t, "put an existing version", f.api.Put(ctx, refA, []byte("x")), ErrExists)
	wantErr(t, "put version 2", f.api.Put(ctx, TenantRef(f.a, "new", 2), []byte("x")), ErrInvalid)
	wantErr(t, "platform_ops option on a tenant secret", f.api.Put(ctx, TenantRef(f.a, "y", 1), []byte("x"), WithPlatformOps()), ErrInvalid)
	wantErr(t, "empty value", f.api.Put(ctx, TenantRef(f.a, "y", 1), nil), ErrInvalid)
	wantErr(t, "oversized value", f.api.Put(ctx, TenantRef(f.a, "y", 1), make([]byte, MaxValueSize+1)), ErrInvalid)
	wantErr(t, "invalid name", f.api.Put(ctx, TenantRef(f.a, "Bad Name", 1), []byte("x")), ErrInvalid)
	_, err = f.api.Get(ctx, TenantRef(f.a, "missing", 1))
	wantErr(t, "missing secret", err, ErrNotFound)
	_, err = f.api.Get(ctx, TenantRef(f.a, refA.Name, 2))
	wantErr(t, "missing version", err, ErrNotFound)
	err = f.api.Put(ctx, TenantRef(uuid.New(), "x", 1), []byte("x")) // no such tenant: the DEK insert breaks the FK
	wantSQLState(t, "secret of an unknown tenant", err, "23503")
}

// swapTenantDEKs swaps wrapped_dek and wrap_nonce of the version-1 DEKs of tenants a and b (superuser, as an
// attacker with write access to the database but without any KEK).
func (f *fixture) swapTenantDEKs(t *testing.T, a, b uuid.UUID) {
	t.Helper()
	n := f.exec(t, `UPDATE tenant_keys t SET wrapped_dek = o.wrapped_dek, wrap_nonce = o.wrap_nonce
		FROM tenant_keys o
		WHERE t.scope = 'tenant' AND o.scope = 'tenant' AND t.version = 1 AND o.version = 1
		  AND ((t.tenant_id = $1 AND o.tenant_id = $2) OR (t.tenant_id = $2 AND o.tenant_id = $1))`, a, b)
	if n != 2 {
		t.Fatalf("swap touched %d rows, want 2", n)
	}
}

// TestWrappedDEKSwapBetweenTenantsRejected is the P2-T04 check "hoán đổi wrapped DEK giữa hai tenant bị từ chối":
// the wrap AAD (scope|tenant_id|version) makes a swapped wrapped DEK fail to unwrap, so the store neither decrypts
// with it nor encrypts new secrets with it.
func TestWrappedDEKSwapBetweenTenantsRejected(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	refA, refB := TenantRef(f.a, "client-secret", 1), TenantRef(f.b, "client-secret", 1)
	mustPut(t, f.api, refA, "secret of A")
	mustPut(t, f.api, refB, "secret of B")

	f.swapTenantDEKs(t, f.a, f.b)
	for _, ref := range []Ref{refA, refB} {
		for _, s := range []*Store{f.api, f.worker} {
			_, err := s.Get(ctx, ref)
			wantErr(t, "get "+ref.String()+" after the swap", err, ErrIntegrity)
		}
		// the store refuses to encrypt a new secret with a DEK whose identity does not verify
		err := f.api.Put(ctx, TenantRef(ref.Tenant, "new-after-swap", 1), []byte("x"))
		wantErr(t, "put for "+ref.Tenant.String()+" after the swap", err, ErrIntegrity)
		_, err = f.worker.EnsureDEK(ctx, TenantOwner(ref.Tenant))
		wantErr(t, "EnsureDEK after the swap", err, ErrIntegrity)
	}
	wantErr(t, "probe after the swap", f.worker.Probe(ctx), ErrIntegrity)
	if !bytes.Contains([]byte(f.log.String()), []byte("DEK cannot be unwrapped")) {
		t.Error("the failed unwrap was not logged")
	}

	// a copy (not a swap) of B's wrapped DEK into A's row fails the same way, and B stays readable
	f.swapTenantDEKs(t, f.a, f.b) // restore
	wantValue(t, f.api, refA, "secret of A")
	wantValue(t, f.api, refB, "secret of B")
	f.exec(t, `UPDATE tenant_keys t SET wrapped_dek = o.wrapped_dek, wrap_nonce = o.wrap_nonce FROM tenant_keys o
		WHERE t.tenant_id = $1 AND o.tenant_id = $2 AND t.version = 1 AND o.version = 1`, f.a, f.b)
	_, err := f.api.Get(ctx, refA)
	wantErr(t, "A with a copy of B's wrapped DEK", err, ErrIntegrity)
	_, err = f.worker.EnsureDEK(ctx, TenantOwner(f.a))
	wantErr(t, "EnsureDEK of A with a copy of B's wrapped DEK", err, ErrIntegrity)
	wantValue(t, f.api, refB, "secret of B")
	// (Probe opens one DEK per (scope, kek_id): it proves the keyring matches the database, not every row.)
}

// TestCiphertextSwapRejected: the secret AAD (tenant_id|name|version) stops a ciphertext from being replayed under
// another name, an older value from being replayed into a newer version, and a ciphertext from moving between
// tenants (also refused by the composite FK and, when that is bypassed, by RLS on the DEK).
func TestCiphertextSwapRejected(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	copyCT := func(dst, src Ref, withAAD bool) {
		t.Helper()
		set := "ciphertext = s.ciphertext, nonce = s.nonce"
		if withAAD {
			set += ", aad = s.aad"
		}
		n := f.exec(t, `UPDATE secrets d SET `+set+` FROM secrets s
			WHERE d.tenant_id IS NOT DISTINCT FROM $1 AND d.name = $2 AND d.version = $3
			  AND s.tenant_id IS NOT DISTINCT FROM $4 AND s.name = $5 AND s.version = $6`,
			tenantArg(dst), dst.Name, dst.Version, tenantArg(src), src.Name, src.Version)
		if n != 1 {
			t.Fatalf("copy %s → %s touched %d rows", src, dst, n)
		}
	}

	t.Run("other name, same tenant and DEK", func(t *testing.T) {
		alpha, beta := TenantRef(f.a, "alpha", 1), TenantRef(f.a, "beta", 1)
		mustPut(t, f.api, alpha, "alpha value")
		mustPut(t, f.api, beta, "beta value")
		copyCT(alpha, beta, false)
		_, err := f.api.Get(ctx, alpha)
		wantErr(t, "beta's ciphertext under alpha", err, ErrIntegrity)
		copyCT(beta, beta, false) // no-op sanity
		wantValue(t, f.api, beta, "beta value")
	})
	t.Run("older version replayed into a newer one", func(t *testing.T) {
		v1 := TenantRef(f.a, "rollback", 1)
		mustPut(t, f.api, v1, "old value")
		v2, err := f.api.Rotate(ctx, v1, []byte("new value"))
		if err != nil {
			t.Fatal(err)
		}
		if f.secretDEK(t, v1) != f.secretDEK(t, v2) {
			t.Fatal("both versions should share the DEK for this case")
		}
		copyCT(v2, v1, false)
		_, err = f.api.Get(ctx, v2)
		wantErr(t, "v1 ciphertext in v2", err, ErrIntegrity)
		copyCT(v2, v1, true) // with v1's stored AAD too: AAD is recomputed from the reference
		_, err = f.api.Get(ctx, v2)
		wantErr(t, "v1 ciphertext and AAD in v2", err, ErrIntegrity)
	})
	t.Run("between tenants", func(t *testing.T) {
		refA, refB := TenantRef(f.a, "shared-name", 1), TenantRef(f.b, "shared-name", 1)
		mustPut(t, f.api, refA, "A")
		mustPut(t, f.api, refB, "B")
		copyCT(refA, refB, true)
		_, err := f.api.Get(ctx, refA)
		wantErr(t, "B's ciphertext in A's row", err, ErrIntegrity)
		// moving B's DEK reference along: the composite FK (tenant_id, dek_id) refuses it, even for the superuser
		_, err = f.su.Exec(ctx, `UPDATE secrets SET dek_id = $1 WHERE tenant_id = $2 AND name = $3`,
			f.secretDEK(t, refB), f.a, refA.Name)
		wantSQLState(t, "dek_id of another tenant", err, "23503")
		// with FK triggers disabled (session_replication_role = replica): RLS hides B's DEK from A's transaction
		f.exec(t, `SET session_replication_role = replica`)
		f.exec(t, `UPDATE secrets SET dek_id = $1 WHERE tenant_id = $2 AND name = $3`, f.secretDEK(t, refB), f.a, refA.Name)
		f.exec(t, `SET session_replication_role = origin`)
		_, err = f.api.Get(ctx, refA)
		wantErr(t, "A's row pointing at B's DEK", err, ErrIntegrity)
		wantValue(t, f.api, refB, "B")
	})
	t.Run("stored AAD tampered", func(t *testing.T) {
		ref := TenantRef(f.a, "aad-only", 1)
		mustPut(t, f.api, ref, "v")
		f.exec(t, `UPDATE secrets SET aad = convert_to('mgsec/v1|platform|aad-only|1', 'UTF8') WHERE tenant_id = $1 AND name = $2`,
			f.a, ref.Name)
		_, err := f.api.Get(ctx, ref)
		wantErr(t, "tampered aad column", err, ErrIntegrity)
	})
	if !bytes.Contains([]byte(f.log.String()), []byte("integrity check failed")) {
		t.Error("integrity failures were not logged")
	}
}

// TestWrongKEK: a keyring with another key under the same kek_id fails authentication; a keyring without the kek_id
// reports it as not loaded; neither ever yields a value.
func TestWrongKEK(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	refA, plat := TenantRef(f.a, "s", 1), PlatformRef("p", 1)
	mustPut(t, f.api, refA, "A")
	mustPut(t, f.api, plat, "P")

	wrong := newTestKeyring(t, KEKApp, f.app.kr.Active()) // same kek_id, different bytes
	s := f.storeWith(t, "mg_api_tenant", "mg_api_platform", Options{App: wrong.kr})
	for _, ref := range []Ref{refA, plat} {
		_, err := s.Get(ctx, ref)
		wantErr(t, "get with the wrong KEK", err, ErrIntegrity)
	}
	wantErr(t, "put with the wrong KEK", s.Put(ctx, TenantRef(f.a, "t", 1), []byte("x")), ErrIntegrity)
	wantErr(t, "probe with the wrong KEK", s.Probe(ctx), ErrIntegrity)

	other := newTestKeyring(t, KEKApp, "app-other")
	s2 := f.storeWith(t, "mg_api_tenant", "mg_api_platform", Options{App: other.kr})
	_, err := s2.Get(ctx, refA)
	wantErr(t, "get without the KEK", err, ErrUnknownKEK)
	wantErr(t, "probe without the KEK", s2.Probe(ctx), ErrUnknownKEK)
	wantErr(t, "probe with the right keyring", f.api.Probe(ctx), nil)
	wantErr(t, "worker probe", f.worker.Probe(ctx), nil)

	// keyring roles are not interchangeable
	if _, err := New(f.workerDB, Options{App: f.ops.kr}); err == nil {
		t.Error("kek-ops accepted as the kek-app keyring")
	}
	if _, err := New(f.workerDB, Options{App: f.app.kr, Ops: f.app.kr}); err == nil {
		t.Error("kek-app accepted as the kek-ops keyring")
	}
	if _, err := New(f.workerDB, Options{}); err == nil {
		t.Error("a store without kek-app accepted")
	}
}

// TestSecretRotation: Rotate writes the next version; older versions stay readable until destroyed; only the latest
// version can be rotated, and of two concurrent rotations exactly one wins.
func TestSecretRotation(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	v1 := TenantRef(f.a, "headscale.apikey", 1)
	mustPut(t, f.api, v1, "key one")
	v2, err := f.api.Rotate(ctx, v1, []byte("key two"))
	if err != nil || v2 != TenantRef(f.a, "headscale.apikey", 2) {
		t.Fatalf("rotate: %s, %v", v2, err)
	}
	wantValue(t, f.api, v1, "key one")
	wantValue(t, f.api, v2, "key two")
	_, err = f.api.Rotate(ctx, v1, []byte("stale"))
	wantErr(t, "rotate from a stale version", err, ErrConflict)
	_, err = f.api.Rotate(ctx, TenantRef(f.b, "headscale.apikey", 1), []byte("x"))
	wantErr(t, "rotate a secret tenant B does not have", err, ErrNotFound)

	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.api.Rotate(ctx, v2, fmt.Appendf(nil, "key three/%d", i))
		}()
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrConflict):
			t.Errorf("concurrent rotate: %v", err)
		}
	}
	if wins != 1 {
		t.Errorf("%d concurrent rotations succeeded, want exactly 1", wins)
	}

	if err := f.api.Destroy(ctx, v1); err != nil {
		t.Fatal(err)
	}
	_, err = f.api.Get(ctx, v1)
	wantErr(t, "get a destroyed version", err, ErrDestroyed)
	wantValue(t, f.api, v2, "key two")
	wantErr(t, "destroy twice", f.api.Destroy(ctx, v1), nil)
	wantErr(t, "destroy a missing version", f.api.Destroy(ctx, TenantRef(f.a, "nope", 1)), ErrNotFound)
	var ct, nonce []byte
	if err := f.su.QueryRow(ctx, `SELECT ciphertext, nonce FROM secrets WHERE tenant_id = $1 AND name = $2 AND version = 1`,
		f.a, v1.Name).Scan(&ct, &nonce); err != nil || ct != nil || nonce != nil {
		t.Errorf("destroyed version still holds ciphertext (%d bytes) / nonce, err %v", len(ct), err)
	}

	// platform_ops keeps its scope across versions; the api cannot see it to rotate it
	ops := PlatformRef("idp.admin", 1)
	mustPut(t, f.worker, ops, "admin password 1", WithPlatformOps())
	ops2, err := f.worker.Rotate(ctx, ops, []byte("admin password 2"))
	if err != nil {
		t.Fatal(err)
	}
	wantValue(t, f.worker, ops2, "admin password 2")
	if d := f.secretDEK(t, ops2); d != f.deks(t, PlatformOpsOwner)[0].id {
		t.Error("the rotated platform_ops version is not under the platform_ops DEK")
	}
	_, err = f.api.Rotate(ctx, ops2, []byte("x"))
	wantErr(t, "api rotating a platform_ops secret", err, ErrNotFound)
	plat := PlatformRef("portal.client", 1)
	mustPut(t, f.api, plat, "p1")
	_, err = f.worker.Rotate(ctx, plat, []byte("p2"), WithPlatformOps())
	wantErr(t, "moving a platform secret to platform_ops", err, ErrInvalid)
}

// TestDEKRotation: a new DEK version becomes active, the old one is retired and still decrypts what it encrypted;
// only the worker roles may rotate.
func TestDEKRotation(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	old := TenantRef(f.a, "before", 1)
	mustPut(t, f.api, old, "written under DEK v1")
	v, err := f.worker.RotateDEK(ctx, TenantOwner(f.a))
	if err != nil || v != 2 {
		t.Fatalf("RotateDEK = %d, %v; want 2", v, err)
	}
	d := f.deks(t, TenantOwner(f.a))
	if len(d) != 2 || d[0].state != "retired" || d[1].state != "active" || d[1].version != 2 {
		t.Fatalf("DEKs after rotation: %+v", d)
	}
	wantValue(t, f.api, old, "written under DEK v1")
	newer := TenantRef(f.a, "after", 1)
	mustPut(t, f.api, newer, "written under DEK v2")
	if f.secretDEK(t, newer) != d[1].id || f.secretDEK(t, old) != d[0].id {
		t.Error("new versions must use the active DEK, old ones keep theirs")
	}
	old2, err := f.api.Rotate(ctx, old, []byte("rotated after the DEK"))
	if err != nil || f.secretDEK(t, old2) != d[1].id {
		t.Errorf("rotated secret not under DEK v2 (%v)", err)
	}
	wantValue(t, f.api, old, "written under DEK v1")

	// the api roles cannot lock/update tenant_keys
	_, err = f.api.RotateDEK(ctx, TenantOwner(f.a))
	wantSQLState(t, "api RotateDEK", err, privilegeErr)
	if d := f.deks(t, TenantOwner(f.a)); len(d) != 2 {
		t.Errorf("api rotation changed the DEKs: %+v", d)
	}
	// platform series rotate the same way
	mustPut(t, f.api, PlatformRef("p", 1), "platform")
	mustPut(t, f.worker, PlatformRef("o", 1), "ops", WithPlatformOps())
	for _, o := range []Owner{PlatformOwner, PlatformOpsOwner} {
		if v, err := f.worker.RotateDEK(ctx, o); err != nil || v != 2 {
			t.Errorf("RotateDEK(%s) = %d, %v", o, v, err)
		}
	}
	wantValue(t, f.api, PlatformRef("p", 1), "platform")
	wantValue(t, f.worker, PlatformRef("o", 1), "ops")
	// an owner without a DEK gets version 1
	c := f.newTenant(t)
	if v, err := f.worker.RotateDEK(ctx, TenantOwner(c)); err != nil || v != 1 {
		t.Errorf("RotateDEK of a tenant without DEK = %d, %v", v, err)
	}
	if v, err := f.api.EnsureDEK(ctx, TenantOwner(c)); err != nil || v != 1 {
		t.Errorf("EnsureDEK = %d, %v", v, err)
	}
	_, err = f.worker.RotateDEK(ctx, TenantOwner(uuid.Nil))
	wantErr(t, "RotateDEK of the nil tenant", err, ErrInvalid)
}

// TestKEKRotationRewrap: the operator adds a new KEK to each keyring and points ACTIVE at it; Rewrap rewraps every
// DEK (active and retired, tenant, platform and platform_ops); afterwards the old KEK file can go and every secret
// version — including those under retired DEKs — is still readable with the new KEK alone.
func TestKEKRotationRewrap(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	refs := map[Ref]string{
		TenantRef(f.a, "s", 1): "A1", TenantRef(f.b, "s", 1): "B1", PlatformRef("p", 1): "P1",
	}
	for ref, v := range refs {
		mustPut(t, f.api, ref, v)
	}
	ops := PlatformRef("o", 1)
	mustPut(t, f.worker, ops, "O1", WithPlatformOps())
	if _, err := f.worker.RotateDEK(ctx, TenantOwner(f.a)); err != nil { // A has a retired DEK too
		t.Fatal(err)
	}
	a2 := TenantRef(f.a, "s2", 1)
	mustPut(t, f.api, a2, "A2")
	refs[a2] = "A2"

	oldApp, oldOps := f.app.kr.Active(), f.ops.kr.Active()
	f.app.add(t, "app-2027-11", randomKey(t), true)
	f.ops.add(t, "ops-2027-11", randomKey(t), true)
	worker := f.storeWith(t, "mg_worker_tenant", "mg_worker_platform", Options{App: f.app.kr, Ops: f.ops.kr})
	for ref, v := range refs { // both KEKs loaded: still readable before the rewrap
		wantValue(t, worker, ref, v)
	}

	// the api cannot rewrap (no UPDATE on tenant_keys)
	api := f.storeWith(t, "mg_api_tenant", "mg_api_platform", Options{App: f.app.kr})
	_, err := api.Rewrap(ctx)
	wantSQLState(t, "api Rewrap", err, privilegeErr)

	reports, err := worker.Rewrap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []RewrapReport{{KEKApp, "app-2027-11", 4}, {KEKOps, "ops-2027-11", 1}} // A v1 (retired), A v2, B v1, platform v1
	if fmt.Sprint(reports) != fmt.Sprint(want) {
		t.Errorf("Rewrap = %+v, want %+v", reports, want)
	}
	if reports, err := worker.Rewrap(ctx); err != nil || reports[0].Rewrapped+reports[1].Rewrapped != 0 {
		t.Errorf("second Rewrap = %+v, %v; want nothing to do", reports, err)
	}
	use, err := worker.KEKUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range use {
		if u.KEKID == oldApp || u.KEKID == oldOps {
			t.Errorf("KEK %s still used by %d DEKs of %s", u.KEKID, u.DEKs, u.Scope)
		}
	}
	if len(use) != 3 { // tenant + platform under the new kek-app KEK, platform_ops under the new kek-ops KEK
		t.Errorf("KEKUsage = %+v", use)
	}

	// remove the old KEK files: the new KEKs alone read every version, including those under the retired DEK
	f.app.remove(t, oldApp)
	f.ops.remove(t, oldOps)
	fresh := f.storeWith(t, "mg_worker_tenant", "mg_worker_platform", Options{App: f.app.kr, Ops: f.ops.kr})
	for ref, v := range refs {
		wantValue(t, fresh, ref, v)
	}
	wantValue(t, fresh, ops, "O1")
	wantErr(t, "probe with the new keyrings", fresh.Probe(ctx), nil)
	// a process still on the old keyring (f.worker) can no longer unwrap
	_, err = f.worker.Get(ctx, TenantRef(f.a, "s", 1))
	wantErr(t, "old keyring after the rewrap", err, ErrUnknownKEK)
	// new DEKs are wrapped by the new KEK
	c := f.newTenant(t)
	mustPut(t, fresh, TenantRef(c, "s", 1), "C1")
	if d := f.deks(t, TenantOwner(c)); len(d) != 1 || d[0].kekID != "app-2027-11" {
		t.Errorf("new DEK: %+v", d)
	}
}

// TestCryptoShredding: destroying a tenant's DEKs (tenant deletion — §6.1, §11.4) makes every secret of the tenant
// unrecoverable, even if a copy of its ciphertext is put back, and leaves other tenants untouched.
func TestCryptoShredding(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	a1 := TenantRef(f.a, "s1", 1)
	mustPut(t, f.api, a1, "A1")
	if _, err := f.worker.RotateDEK(ctx, TenantOwner(f.a)); err != nil {
		t.Fatal(err)
	}
	a2 := TenantRef(f.a, "s2", 1)
	mustPut(t, f.api, a2, "A2")
	b1 := TenantRef(f.b, "s1", 1)
	mustPut(t, f.api, b1, "B1")
	var savedCT, savedNonce []byte // what a backup (or an attacker) kept of A's ciphertext
	if err := f.su.QueryRow(ctx, `SELECT ciphertext, nonce FROM secrets WHERE tenant_id = $1 AND name = 's1'`, f.a).
		Scan(&savedCT, &savedNonce); err != nil {
		t.Fatal(err)
	}

	_, err := f.api.DestroyTenantKeys(ctx, f.a)
	wantSQLState(t, "api DestroyTenantKeys", err, privilegeErr)
	wantValue(t, f.api, a1, "A1")

	r, err := f.worker.DestroyTenantKeys(ctx, f.a)
	if err != nil || r != (ShredReport{DEKs: 2, Secrets: 2}) {
		t.Fatalf("DestroyTenantKeys = %+v, %v; want 2 DEKs, 2 secret versions", r, err)
	}
	for _, d := range f.deks(t, TenantOwner(f.a)) {
		if d.state != "destroyed" || d.wrapped != nil || d.nonce != nil {
			t.Errorf("DEK v%d after shredding: state %s, wrapped %d bytes", d.version, d.state, len(d.wrapped))
		}
	}
	for _, ref := range []Ref{a1, a2} {
		_, err := f.worker.Get(ctx, ref)
		wantErr(t, "get after shredding", err, ErrDestroyed)
	}
	// the saved ciphertext put back is useless without the DEK
	f.exec(t, `UPDATE secrets SET ciphertext = $1, nonce = $2, destroyed_at = NULL WHERE tenant_id = $3 AND name = 's1'`,
		savedCT, savedNonce, f.a)
	_, err = f.worker.Get(ctx, a1)
	wantErr(t, "restored ciphertext after shredding", err, ErrKeyDestroyed)
	// a shredded tenant gets no new DEK
	wantErr(t, "put after shredding", f.api.Put(ctx, TenantRef(f.a, "new", 1), []byte("x")), ErrKeyDestroyed)
	_, err = f.worker.EnsureDEK(ctx, TenantOwner(f.a))
	wantErr(t, "EnsureDEK after shredding", err, ErrKeyDestroyed)
	_, err = f.worker.RotateDEK(ctx, TenantOwner(f.a))
	wantErr(t, "RotateDEK after shredding", err, ErrKeyDestroyed)
	// tenant B is untouched; shredding again is a no-op
	wantValue(t, f.api, b1, "B1")
	if r, err := f.worker.DestroyTenantKeys(ctx, f.a); err != nil || r.DEKs != 0 {
		t.Errorf("second DestroyTenantKeys = %+v, %v", r, err)
	}
	if err := f.worker.Probe(ctx); err != nil {
		t.Errorf("probe after shredding: %v", err)
	}
	_, err = f.worker.DestroyTenantKeys(ctx, uuid.Nil)
	wantErr(t, "DestroyTenantKeys of the nil tenant", err, ErrInvalid)
}

// TestExpiry: an expired version is refused at once and erased by DestroyExpired (TTL of show-once secrets — §13.1).
func TestExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	clock := &fixedClock{t: time.Now()}
	s := f.newStore(t, f.workerDB, Options{App: f.app.kr, Ops: f.ops.kr, Now: clock.now})
	ref := TenantRef(f.a, "idem.preauth", 1)
	mustPut(t, s, ref, "pre-auth key shown once", WithExpiry(clock.now().Add(15*time.Minute)))
	wantValue(t, s, ref, "pre-auth key shown once")
	clock.advance(16 * time.Minute)
	_, err := s.Get(ctx, ref)
	wantErr(t, "get after expiry", err, ErrExpired)
	wantErr(t, "expiry in the past", s.Put(ctx, TenantRef(f.a, "x", 1), []byte("x"), WithExpiry(clock.now().Add(-time.Second))), ErrInvalid)

	keep := TenantRef(f.b, "long-lived", 1)
	mustPut(t, s, keep, "stays")
	f.exec(t, `UPDATE secrets SET expires_at = now() - interval '1 minute' WHERE tenant_id = $1 AND name = $2`, f.a, ref.Name)
	n, err := f.worker.DestroyExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("DestroyExpired = %d, %v; want 1", n, err)
	}
	_, err = f.worker.Get(ctx, ref)
	wantErr(t, "get after the sweep", err, ErrDestroyed)
	wantValue(t, f.worker, keep, "stays")
	if n, err := f.worker.DestroyExpired(ctx); err != nil || n != 0 {
		t.Errorf("second sweep = %d, %v", n, err)
	}
}

// TestConcurrentFirstPut: many first secrets of a new tenant at once create exactly one DEK (ON CONFLICT path).
func TestConcurrentFirstPut(t *testing.T) {
	f := newFixture(t)
	c := f.newTenant(t)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f.api.Put(t.Context(), TenantRef(c, fmt.Sprintf("n%d", i), 1), []byte("v"))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("put %d: %v", i, err)
		}
	}
	if d := f.deks(t, TenantOwner(c)); len(d) != 1 || d[0].version != 1 || d[0].state != "active" {
		t.Errorf("DEKs = %+v, want exactly one active v1", d)
	}
	for i := range errs {
		wantValue(t, f.worker, TenantRef(c, fmt.Sprintf("n%d", i), 1), "v")
	}
}
