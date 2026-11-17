//go:build mgtestfixture

package isolation_test

// IT-03 (§5.2 boundary 3), completeness over the catalog: the tests of P2-T03 (internal/store: TestRLSTenantScope,
// TestCrossTenantWritesRejected, TestRLSUnsetOrEmptyGUC, TestCatalogRLSOnEveryTable) prove RLS and the cross-tenant
// references of the tables they know; this one walks every foreign key of the database and requires that a reference
// between two tenant-owned tables is bound to the tenant (a composite (tenant_id, …) key, §6.1 "FK ghép"), so a
// migration that adds a plain foreign key between tenant tables fails here before any data can cross tenants.

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

type foreignKey struct {
	Name string   `json:"name"`
	Src  string   `json:"src"`
	Dst  string   `json:"dst"`
	Cols []string `json:"cols"`
}

// tenantForeignKeys lists the foreign keys between two tables that both have a tenant_id column.
func tenantForeignKeys(t *testing.T, w *sessionfixture.World) []foreignKey {
	t.Helper()
	var raw string
	w.Scan(t, `WITH tenant_tables AS (
			SELECT c.oid, c.relname FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
			WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition)
		SELECT coalesce(json_agg(json_build_object('name', con.conname, 'src', src.relname, 'dst', dst.relname,
			'cols', (SELECT json_agg(att.attname ORDER BY k.ord) FROM unnest(con.conkey) WITH ORDINALITY k(attnum, ord)
			         JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = k.attnum))
			ORDER BY src.relname, con.conname), '[]')::text
		FROM pg_constraint con
		JOIN tenant_tables src ON src.oid = con.conrelid
		JOIN tenant_tables dst ON dst.oid = con.confrelid
		WHERE con.contype = 'f'`, nil, &raw)
	var fks []foreignKey
	if err := json.Unmarshal([]byte(raw), &fks); err != nil {
		t.Fatal(err)
	}
	return fks
}

// unboundForeignKeys returns the foreign keys between tenant tables that do not carry tenant_id and are not doubled
// by a composite key that binds the same reference to the tenant (provisioning_job_steps: job_id → jobs (id) for the
// cascade, plus (tenant_id, job_id) → jobs (tenant_id, id)).
func unboundForeignKeys(fks []foreignKey) []string {
	var out []string
	for _, f := range fks {
		if slices.Contains(f.Cols, "tenant_id") {
			continue
		}
		bound := false
		for _, g := range fks {
			if g.Src != f.Src || g.Dst != f.Dst || !slices.Contains(g.Cols, "tenant_id") {
				continue
			}
			rest := slices.DeleteFunc(slices.Clone(g.Cols), func(c string) bool { return c == "tenant_id" })
			if len(rest) > 0 && !slices.ContainsFunc(rest, func(c string) bool { return !slices.Contains(f.Cols, c) }) {
				bound = true
			}
		}
		if !bound {
			out = append(out, f.Src+"."+f.Name+" ("+strings.Join(f.Cols, ", ")+") → "+f.Dst)
		}
	}
	sort.Strings(out)
	return out
}

// rlsTenantTables lists the RLS-enabled tables of public that carry a tenant column (tenant_id, or id for tenants).
func rlsTenantTables(t *testing.T, w *sessionfixture.World) map[string]string {
	t.Helper()
	var raw string
	w.Scan(t, `SELECT coalesce(json_object_agg(c.relname, CASE WHEN c.relname = 'tenants' THEN 'id' ELSE 'tenant_id' END), '{}')::text
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition AND c.relrowsecurity
		  AND (c.relname = 'tenants' OR EXISTS (SELECT 1 FROM pg_attribute a
		       WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))`, nil, &raw)
	out := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestIT03TenantPoolSeesOnlyItsTenant — IT-03 read side and IT-17 "GUC rỗng ⇒ 0 hàng" over the catalog: as each
// tenant login role (api, worker), a transaction scoped like WithTenantTx(A) sees no row of another tenant (nor a
// platform row) in any RLS table that has a tenant column, and a connection that never set the variables sees no row
// at all — without error. Tables the fixture fills for B (tenants, IdPs, identities, memberships, instances, devices,
// jobs, audit events) make the check non-vacuous; the others are listed.
func TestIT03TenantPoolSeesOnlyItsTenant(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	seedTenantRows(t, w)
	env := storetest.Require(t)
	tables := rlsTenantTables(t, w)
	var withB []string
	for table, col := range tables {
		var n int64
		w.Scan(t, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()+" WHERE "+col+" = $1", []any{w.B.ID}, &n)
		if n > 0 {
			withB = append(withB, table)
		}
	}
	sort.Strings(withB)
	if len(withB) < 8 {
		t.Fatalf("only %d tables hold rows of B (%v) — the check would be vacuous", len(withB), withB)
	}
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
		readable := func(table string) bool {
			var ok bool
			if err := c.QueryRow(t.Context(), "SELECT has_table_privilege(current_user, $1, 'SELECT')", "public."+table).Scan(&ok); err != nil {
				t.Fatal(err)
			}
			return ok
		}
		// never set: 0 rows, no error (IT-17)
		for table := range tables {
			if !readable(table) {
				continue
			}
			var n int64
			if err := c.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil || n != 0 {
				t.Errorf("IT-17: %s without app.* on %s: %d rows, err %v — want 0 rows, no error", role, table, n, err)
			}
		}
		// scoped to A exactly as WithTenantTx: only A's rows
		tx, err := c.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`,
			w.A.ID.String()); err != nil {
			t.Fatal(err)
		}
		for table, col := range tables {
			if !readable(table) {
				continue
			}
			var foreign, own int64
			err := tx.QueryRow(t.Context(), "SELECT count(*) FILTER (WHERE "+col+" IS DISTINCT FROM $1), count(*) FILTER (WHERE "+
				col+" = $1) FROM "+pgx.Identifier{table}.Sanitize(), w.A.ID).Scan(&foreign, &own)
			if err != nil || foreign != 0 {
				t.Errorf("IT-03: %s scoped to A sees %d rows of another tenant (or platform) in %s (err %v)", role, foreign, table, err)
			}
		}
		_ = tx.Rollback(t.Context())
		_ = c.Close(t.Context())
	}
	t.Logf("IT-03/IT-17: %d RLS tables with a tenant column; rows of B present in %d: %v", len(tables), len(withB), withB)
}

// seedTenantRows adds, as superuser, rows of A and B to the tenant tables the fixture leaves empty: one host, an
// instance per tenant, a device, a job with a step, an audit event.
func seedTenantRows(t *testing.T, w *sessionfixture.World) {
	t.Helper()
	host := uuid.Must(uuid.NewV7())
	w.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-it03', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	for i, ten := range []*sessionfixture.Tenant{w.A, w.B} {
		inst, job := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		w.Exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
			inst, ten.ID, host, ten.Slug+".it03.test", ten.Slug+".ts.test", "hs-"+ten.Slug+":8080", 30101+i,
			fmt.Sprintf("10.250.%d.0/29", 100+i), "/opt/meshguard/tenants/"+inst.String())
		w.Exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key)
			VALUES ($1, $2, 1, 'mkey:it03')`, ten.ID, inst)
		w.Exec(t, `INSERT INTO provisioning_jobs (id, tenant_id, instance_id, kind, status) VALUES ($1, $2, $3, 'inventory.sync', 'queued')`,
			job, ten.ID, inst)
		w.Exec(t, `INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status) VALUES ($1, $2, 0, 'sync', 'succeeded')`, ten.ID, job)
		w.Exec(t, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome)
			VALUES ($1, 'system', 'device.sync', 'device', 'success')`, ten.ID)
	}
}

func TestIT03TenantForeignKeysAreComposite(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	fks := tenantForeignKeys(t, w)
	if len(fks) < 8 {
		t.Fatalf("only %d foreign keys between tenant tables — the catalog query is broken", len(fks))
	}
	for _, v := range unboundForeignKeys(fks) {
		t.Errorf("IT-03: foreign key %s between tenant tables is not bound to tenant_id (composite key, §6.1)", v)
	}
	// The check itself: a plain key between tenant tables is reported, a doubled one is not.
	probe := []foreignKey{
		{Name: "plain", Src: "x", Dst: "y", Cols: []string{"y_id"}},
		{Name: "doubled", Src: "x", Dst: "z", Cols: []string{"z_id"}},
		{Name: "doubled_tenant", Src: "x", Dst: "z", Cols: []string{"tenant_id", "z_id"}},
	}
	if got := unboundForeignKeys(probe); !slices.Equal(got, []string{"x.plain (y_id) → y"}) {
		t.Errorf("the check reports %v on the probe", got)
	}
	t.Logf("IT-03: %d foreign keys between tenant tables, all bound to tenant_id", len(fks))
}
