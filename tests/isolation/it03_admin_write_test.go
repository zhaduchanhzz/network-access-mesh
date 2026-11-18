//go:build mgtestfixture

package isolation_test

// IT-03, write side of the tenant-pool grants of P4-T03a (migration 0025): the api's tenant role writes the settings of
// a tenant row and the claim columns of an identity provider row — of ITS tenant only. Scoped to A exactly as
// WithTenantTx, an UPDATE aimed at B's tenant row, B's IdP or the platform IdP matches no row (RLS), the immutable
// columns are refused (42501), and the worker's tenant role has none of these grants; through the API, B's Owner on A's
// settings, security settings and IdP reads 404 (tests/security/authzmatrix covers every role and operation).

import (
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestIT03TenantAdminWritesStayInTheTenant(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	env := storetest.Require(t)
	w.Exec(t, `UPDATE tenants SET settings = '{"policy":{"four_eyes":true}}' WHERE id = $1`, w.B.ID)
	before := func() (string, string) {
		var s, c string
		w.Scan(t, `SELECT settings::text, claim_mapping::text FROM tenants t JOIN identity_providers p ON p.tenant_id = t.id
			WHERE t.id = $1`, []any{w.B.ID}, &s, &c)
		return s, c
	}
	bSettings, bClaims := before()
	for _, role := range []string{"mg_api_tenant", "mg_worker_tenant"} {
		cfg, err := pgx.ParseConfig(env.URL(w.DB))
		if err != nil {
			t.Fatal(err)
		}
		cfg.User, cfg.Password = role, env.Password(role)
		c, err := pgx.ConnectConfig(t.Context(), cfg)
		if err != nil {
			t.Fatalf("connect as %s: %v", role, err)
		}
		for _, tc := range []struct {
			name, sql string
			args      []any
		}{
			{"B's settings", `UPDATE tenants SET settings = '{}' WHERE id = $1`, []any{w.B.ID}},
			{"every tenant's settings", `UPDATE tenants SET settings = '{}'`, nil},
			{"B's IdP claims", `UPDATE identity_providers SET claim_mapping = '{"name":"x"}' WHERE id = $1`, []any{w.B.IdP}},
			{"the platform IdP", `UPDATE identity_providers SET claim_mapping = '{"name":"x"}' WHERE id = $1`, []any{w.PlatformIdP}},
			{"A's IdP issuer", `UPDATE identity_providers SET issuer = 'https://evil.test' WHERE id = $1`, []any{w.A.IdP}},
		} {
			tx, err := c.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`,
				w.A.ID.String()); err != nil {
				t.Fatal(err)
			}
			tag, err := tx.Exec(t.Context(), tc.sql, tc.args...)
			switch {
			case role == "mg_worker_tenant" || tc.name == "A's IdP issuer":
				if store.SQLState(err) != "42501" {
					t.Errorf("%s, %s: err %v, want 42501", role, tc.name, err)
				}
			case err != nil:
				t.Errorf("%s, %s: %v", role, tc.name, err)
			case tc.name == "every tenant's settings" && tag.RowsAffected() != 1:
				t.Errorf("%s, %s: %d rows, want only A's", role, tc.name, tag.RowsAffected())
			case tc.name != "every tenant's settings" && tag.RowsAffected() != 0:
				t.Errorf("%s, %s: %d rows, want 0 (RLS)", role, tc.name, tag.RowsAffected())
			}
			_ = tx.Rollback(t.Context())
		}
		_ = c.Close(t.Context())
	}
	if s, c := before(); s != bSettings || c != bClaims {
		t.Errorf("B changed: %s %s → %s %s", bSettings, bClaims, s, c)
	}
}
