package secrets

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The two role checks of P2-T04 (§20), on rows written by the SecretStore itself. The roles are used directly —
// the same login roles, hence the same RLS, as the pools of store.WithTenantTx / store.WithPlatformTx — so the test
// can set app.* the way a compromised or buggy caller would.

// fillAllScopes writes secrets for tenants A and B (A with two DEK versions), the platform and platform_ops.
func (f *fixture) fillAllScopes(t *testing.T) {
	t.Helper()
	mustPut(t, f.api, TenantRef(f.a, "s", 1), "A")
	if _, err := f.worker.RotateDEK(t.Context(), TenantOwner(f.a)); err != nil {
		t.Fatal(err)
	}
	mustPut(t, f.api, TenantRef(f.a, "s2", 1), "A2")
	mustPut(t, f.api, TenantRef(f.b, "s", 1), "B")
	mustPut(t, f.api, PlatformRef("p", 1), "P")
	mustPut(t, f.worker, PlatformRef("o", 1), "O", WithPlatformOps())
}

// inTx runs fn in a transaction of a raw connection as role, after setting app.* like WithTenantTx would for tenant
// (uuid.Nil: like WithPlatformTx) and then applying the caller's own set_config statements.
func inTx(t *testing.T, c *pgx.Conn, tenant uuid.UUID, extra []string, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := t.Context()
	return pgx.BeginTxFunc(ctx, c, pgx.TxOptions{}, func(tx pgx.Tx) error {
		set := `SELECT set_config('app.scope', 'platform', true), set_config('app.tenant_id', '', true)`
		var args []any
		if tenant != uuid.Nil {
			set, args = `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`, []any{tenant.String()}
		}
		if _, err := tx.Exec(ctx, set, args...); err != nil {
			return err
		}
		for _, s := range extra {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

// TestTenantPoolClaimingPlatformScope is the P2-T04 check "kết nối pool tenant đặt app.scope='platform' vẫn không thấy
// hàng của tenant khác": a connection of either tenant-pool role that sets app.scope='platform' itself still sees
// only its own tenant's DEKs and secrets (no other tenant, no platform row), sees nothing once app.tenant_id is
// cleared, cannot write rows of another tenant, and cannot touch another tenant's DEKs.
func TestTenantPoolClaimingPlatformScope(t *testing.T) {
	f := newFixture(t)
	f.fillAllScopes(t)
	ctx := t.Context()
	claim := []string{`SELECT set_config('app.scope', 'platform', true)`}
	claimAll := []string{`SELECT set_config('app.scope', 'platform', true)`, `SELECT set_config('app.tenant_id', '', true)`}
	for _, role := range []string{"mg_api_tenant", "mg_worker_tenant"} {
		t.Run(role, func(t *testing.T) {
			c := f.e.connectAs(t, f.db, role)
			for _, table := range []string{"tenant_keys", "secrets"} {
				var total, own, platform int64
				err := inTx(t, c, f.a, claim, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, fmt.Sprintf(`SELECT count(*), count(*) FILTER (WHERE tenant_id = $1),
						count(*) FILTER (WHERE tenant_id IS NULL) FROM %s`, table), f.a).Scan(&total, &own, &platform)
				})
				if err != nil || total != own || own < 2 || platform != 0 {
					t.Errorf("%s with app.scope=platform: %d rows, %d of A, %d platform (err %v); want only A's rows (≥ 2)",
						table, total, own, platform, err)
				}
				var n int64
				err = inTx(t, c, f.a, claimAll, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n)
				})
				if err != nil || n != 0 {
					t.Errorf("%s with app.scope=platform and no tenant: %d rows (err %v), want 0", table, n, err)
				}
			}
			// writing a row of tenant B from A's transaction claiming platform scope: WITH CHECK refuses it
			err := inTx(t, c, f.a, claim, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO tenant_keys (scope, tenant_id, version, wrapped_dek, wrap_nonce, kek_id)
					VALUES ('tenant', $1, 99, '\x00', '\x00', 'kek-x')`, f.b)
				return err
			})
			wantSQLState(t, role+" inserting a DEK of tenant B", err, privilegeErr)
			err = inTx(t, c, f.a, claim, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO secrets (tenant_id, scope, name, version, ciphertext, nonce, aad, dek_id)
					SELECT $1, 'tenant', 'planted', 1, '\x00', '\x00', '\x00', id FROM tenant_keys LIMIT 1`, f.b)
				return err
			})
			if err == nil {
				t.Errorf("%s planted a secret for tenant B", role)
			}
			// another tenant's DEKs: invisible to the worker role (0 rows updated), not even updatable for the api role
			var updated int64
			err = inTx(t, c, f.a, claim, func(tx pgx.Tx) error {
				tag, err := tx.Exec(ctx, `UPDATE tenant_keys SET state = 'retired' WHERE tenant_id = $1 OR tenant_id IS NULL`, f.b)
				updated = tag.RowsAffected()
				return err
			})
			if role == "mg_api_tenant" {
				wantSQLState(t, role+" updating tenant_keys", err, privilegeErr)
			} else if err != nil || updated != 0 {
				t.Errorf("%s updated %d DEKs of tenant B / the platform (err %v), want 0", role, updated, err)
			}
		})
	}
	// and the SecretStore still reads everything afterwards
	wantValue(t, f.worker, TenantRef(f.b, "s", 1), "B")
	wantValue(t, f.worker, PlatformRef("p", 1), "P")
}

// TestAPIRolesCannotReadPlatformOps is the P2-T04 check "các role mg_api_* không đọc được DEK platform_ops": whatever
// scope they claim, mg_api_tenant and mg_api_platform see no platform_ops DEK and no secret under it, and even an api
// process that had kek-ops could neither read, create nor rotate one. The worker sees them.
func TestAPIRolesCannotReadPlatformOps(t *testing.T) {
	f := newFixture(t)
	f.fillAllScopes(t)
	ctx := t.Context()
	const probe = `SELECT (SELECT count(*) FROM tenant_keys WHERE scope = 'platform_ops'),
		(SELECT count(*) FROM secrets WHERE scope = 'platform_ops'),
		(SELECT count(*) FROM tenant_keys WHERE scope = 'platform')`
	type seen struct{ opsDEKs, opsSecrets, platformDEKs int64 }
	look := func(role string, tenant uuid.UUID, extra []string) (seen, error) {
		var s seen
		c := f.e.connectAs(t, f.db, role)
		err := inTx(t, c, tenant, extra, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, probe).Scan(&s.opsDEKs, &s.opsSecrets, &s.platformDEKs)
		})
		return s, err
	}
	for _, c := range []struct {
		role   string
		tenant uuid.UUID
		extra  []string
		want   seen
	}{
		{"mg_api_platform", uuid.Nil, nil, seen{0, 0, 1}},
		{"mg_api_platform", f.a, []string{`SELECT set_config('app.scope', 'platform', true)`}, seen{0, 0, 1}},
		{"mg_api_tenant", f.a, []string{`SELECT set_config('app.scope', 'platform', true)`}, seen{0, 0, 0}},
		{"mg_api_tenant", f.a, []string{`SELECT set_config('app.scope', 'platform', true)`, `SELECT set_config('app.tenant_id', '', true)`}, seen{0, 0, 0}},
		{"mg_worker_platform", uuid.Nil, nil, seen{1, 1, 1}}, // control: the worker does see them
	} {
		got, err := look(c.role, c.tenant, c.extra)
		if err != nil || got != c.want {
			t.Errorf("%s (tenant %v, %v): %+v, err %v; want %+v", c.role, c.tenant, c.extra, got, err, c.want)
		}
	}
	// the api roles cannot write platform_ops rows either: they are invisible to UPDATE
	var touched int64
	err := inTx(t, f.e.connectAs(t, f.db, "mg_api_platform"), uuid.Nil, nil, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE secrets SET expires_at = now() WHERE scope = 'platform_ops'`)
		touched = tag.RowsAffected()
		return err
	})
	if err != nil || touched != 0 {
		t.Errorf("mg_api_platform updated %d platform_ops secrets (err %v), want 0", touched, err)
	}
	wantValue(t, f.worker, PlatformRef("o", 1), "O")

	// SecretStore level: an api process that (wrongly) held kek-ops still cannot use platform_ops
	apiOps := f.storeWith(t, "mg_api_tenant", "mg_api_platform", Options{App: f.app.kr, Ops: f.ops.kr})
	_, err = apiOps.Get(ctx, PlatformRef("o", 1))
	wantErr(t, "api+kek-ops Get", err, ErrNotFound)
	_, err = apiOps.Rotate(ctx, PlatformRef("o", 1), []byte("x"))
	wantErr(t, "api+kek-ops Rotate", err, ErrNotFound)
	err = apiOps.Put(ctx, PlatformRef("o-new", 1), []byte("x"), WithPlatformOps())
	wantSQLState(t, "api+kek-ops Put platform_ops", err, privilegeErr)
	_, err = apiOps.EnsureDEK(ctx, PlatformOpsOwner)
	wantSQLState(t, "api+kek-ops EnsureDEK platform_ops", err, privilegeErr)
	// the real api (no kek-ops) cannot even wrap a platform_ops DEK
	wantErr(t, "api Put platform_ops", f.api.Put(ctx, PlatformRef("o-new", 1), []byte("x"), WithPlatformOps()), ErrNoKeyring)
	if err := f.api.Probe(ctx); err != nil {
		t.Errorf("api probe: %v", err)
	}
	use, err := f.api.KEKUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range use {
		if u.Scope == ScopePlatformOps {
			t.Errorf("api KEKUsage lists platform_ops: %+v", u)
		}
	}
}
