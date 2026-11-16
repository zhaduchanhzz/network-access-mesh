package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestCanaryNeverLogged is the "canary secret" test of §25.1 rule 9 for the SecretStore: canary values go through
// every operation — success paths, integrity failures, wrong keys, KEK rotation, crypto-shredding — with the logger
// at debug level, and neither the log output nor any returned error contains a secret value, a KEK or a DEK, in raw,
// hex or base64 form.
func TestCanaryNeverLogged(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	canary := func(tag string) string { return "CANARY-" + tag + "-" + randomHex(8) }
	values := map[Ref]string{
		TenantRef(f.a, "headscale.apikey", 1): canary("a"),
		TenantRef(f.b, "headscale.apikey", 1): canary("b"),
		PlatformRef("oidc.portal", 1):         canary("platform"),
	}
	opsRef, opsValue := PlatformRef("smtp.password", 1), canary("ops")
	var errs []error
	keep := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	for ref, v := range values {
		keep(f.api.Put(ctx, ref, []byte(v)))
		got, err := f.api.Get(ctx, ref)
		keep(err)
		f.logger.Info("a caller logging a decrypted value by mistake", "value", got, "secret_ref", ref.String())
	}
	keep(f.worker.Put(ctx, opsRef, []byte(opsValue), WithPlatformOps()))
	_, err := f.api.Get(ctx, opsRef)
	keep(err)
	refA := TenantRef(f.a, "headscale.apikey", 1)
	refA2, err := f.api.Rotate(ctx, refA, []byte(canary("a2")))
	keep(err)
	values[refA2] = "" // value checked through the log/err scan only
	keep(f.api.Destroy(ctx, refA))
	_, err = f.api.Get(ctx, refA)
	keep(err)
	_, err = f.worker.RotateDEK(ctx, TenantOwner(f.a))
	keep(err)
	_, err = f.api.Rotate(ctx, refA, []byte(canary("stale")))
	keep(err)
	keep(f.api.Put(ctx, TenantRef(f.a, "Bad Name", 1), []byte(canary("badname"))))
	keep(f.api.Put(ctx, TenantRef(f.a, "x", 2), []byte(canary("badversion"))))
	_, err = ParseRef(canary("asref"))
	keep(err)

	// integrity failures: swapped wrapped DEKs, wrong KEK, unknown KEK
	f.swapTenantDEKs(t, f.a, f.b)
	_, err = f.api.Get(ctx, TenantRef(f.b, "headscale.apikey", 1))
	keep(err)
	keep(f.worker.Probe(ctx))
	f.swapTenantDEKs(t, f.a, f.b)
	wrong := newTestKeyring(t, KEKApp, f.app.kr.Active())
	s := f.storeWith(t, "mg_api_tenant", "mg_api_platform", Options{App: wrong.kr})
	_, err = s.Get(ctx, TenantRef(f.b, "headscale.apikey", 1))
	keep(err)

	// KEK rotation
	f.app.add(t, "app-2027-11", randomKey(t), true)
	f.ops.add(t, "ops-2027-11", randomKey(t), true)
	w2 := f.storeWith(t, "mg_worker_tenant", "mg_worker_platform", Options{App: f.app.kr, Ops: f.ops.kr})
	_, err = w2.Rewrap(ctx)
	keep(err)
	keep(w2.Probe(ctx))
	_, err = f.worker.Get(ctx, TenantRef(f.b, "headscale.apikey", 1)) // old keyring: unknown KEK
	keep(err)

	// every DEK in plain form, before shredding erases some of them
	dekMaterial := f.dekMaterial(t, w2)

	// crypto-shredding and the expiry sweep
	_, err = w2.DestroyTenantKeys(ctx, f.b)
	keep(err)
	_, err = w2.Get(ctx, TenantRef(f.b, "headscale.apikey", 1))
	keep(err)
	keep(w2.Put(ctx, TenantRef(f.b, "again", 1), []byte(canary("shredded"))))
	_, err = w2.DestroyExpired(ctx)
	keep(err)

	// a keyring file broken in a way that tempts an error message to quote it
	bad := t.TempDir()
	broken := strings.Repeat("ab", 31) + "zz"
	if err := os.WriteFile(filepath.Join(bad, "kek-1"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, ActiveFile), []byte("kek-1"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadKeyring(KEKApp, bad)
	keep(err)

	// what must never appear
	var forbidden []string
	for _, v := range values {
		if v != "" {
			forbidden = append(forbidden, v)
		}
	}
	forbidden = append(forbidden, opsValue, "CANARY-", broken)
	forbidden = append(forbidden, f.app.material()...)
	forbidden = append(forbidden, f.ops.material()...)
	forbidden = append(forbidden, wrong.material()...)
	forbidden = append(forbidden, dekMaterial...)

	out := f.log.String()
	var texts []string
	for _, e := range errs {
		texts = append(texts, e.Error())
	}
	for _, s := range forbidden {
		if s == "" {
			continue
		}
		if strings.Contains(out, s) {
			t.Errorf("secret material leaked into the log (%d bytes)", len(s))
		}
		for _, e := range texts {
			if strings.Contains(e, s) {
				t.Errorf("secret material leaked into an error: %s", e)
			}
		}
	}
	if len(errs) < 12 {
		t.Errorf("only %d error paths exercised", len(errs))
	}
	for _, event := range []string{"secrets: DEK created", "secrets: secret rotated", "secrets: DEK rotated",
		"secrets: DEK cannot be unwrapped", "secrets: DEKs rewrapped", "secrets: tenant keys destroyed",
		"secrets: secret version destroyed", `"value":"[REDACTED]"`} {
		if !strings.Contains(out, event) {
			t.Errorf("log has no %q event", event)
		}
	}
}

// dekMaterial unwraps every live DEK (superuser view + the test's keyrings) and returns its encodings.
func (f *fixture) dekMaterial(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := f.su.Query(t.Context(), `SELECT id, scope, tenant_id, version, wrapped_dek, wrap_nonce, kek_id
		FROM tenant_keys WHERE state <> 'destroyed'`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id             uuid.UUID
		scope          string
		tenant         *uuid.UUID
		version        int32
		wrapped, nonce []byte
		kek            string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.id, &x.scope, &x.tenant, &x.version, &x.wrapped, &x.nonce, &x.kek)
		return x, err
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, x := range list {
		kr, err := s.keyring(Scope(x.scope))
		if err != nil {
			t.Fatal(err)
		}
		dek, err := kr.unwrap(x.kek, x.nonce, x.wrapped, wrapAAD(x.scope, x.tenant, x.version))
		if err != nil {
			t.Fatalf("unwrap DEK %s: %v", x.id, err)
		}
		out = append(out, keyEncodings(dek)...)
	}
	if len(out) == 0 {
		t.Fatal("no DEK to check")
	}
	return out
}
