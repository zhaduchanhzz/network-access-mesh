package store

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// rlsTables classifies every RLS table of migrations 0001–0006 by its §6.3 symbol: T (app.tenant_id only),
// T+P (tenant or platform scope), P (platform scope only), T/P (audit: tenant events / platform events).
// col is the column compared with app_tenant_id(). A new table must be added here (TestCatalogRLSOnEveryTable).
var rlsTables = []struct{ name, kind, col string }{
	{"tenants", "T+P", "id"},
	{"hosts", "P", ""},
	{"tenant_instances", "T+P", "tenant_id"},
	{"instance_config_versions", "T+P", "tenant_id"},
	{"system_settings", "P", ""},
	{"identity_providers", "T+P", "tenant_id"},
	{"identities", "T+P", "tenant_id"},
	{"platform_users", "P", ""},
	{"tenant_memberships", "T", "tenant_id"},
	{"tenant_keys", "T+P", "tenant_id"},
	{"secrets", "T+P", "tenant_id"},
	{"audit_events", "T/P", "tenant_id"},
	{"security_events", "T+P", "tenant_id"},
	{"device_inventory_cache", "T", "tenant_id"},
	{"provisioning_jobs", "T+P", "tenant_id"},
	{"provisioning_job_steps", "T+P", "tenant_id"},
	{"idempotency_keys", "T+P", "tenant_id"},
}

// noRLSTables are the tables §6.3 marks "—": global reference data, or identity-module tables used only through the
// platform pool (sessions, auth_requests). goose_db_version belongs to the migrator alone.
var noRLSTables = map[string]bool{
	"roles": true, "permissions": true, "role_permissions": true, "sessions": true, "auth_requests": true,
	"goose_db_version": true,
}

const privilegeErr = "42501" // insufficient_privilege — also raised for a row that fails a WITH CHECK policy

func q(table string) string { return pgx.Identifier{table}.Sanitize() }

// canSelect asks the superuser whether role holds SELECT on table.
func canSelect(t *testing.T, su *pgx.Conn, role, table string) bool {
	t.Helper()
	var ok bool
	if err := su.QueryRow(ctxT(t), "SELECT has_table_privilege($1, $2, 'SELECT')", role, "public."+table).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// fixtureDB returns the shared database with a fresh fixture and a superuser connection to it.
func fixtureDB(t *testing.T) (*pgEnv, string, *fixture, *pgx.Conn) {
	t.Helper()
	e := requireDB(t)
	db := e.sharedDB(t)
	su := e.connectAdmin(t, db)
	f := newFixture()
	f.insertAll(t, su)
	return e, db, f, su
}

func TestCatalogRLSOnEveryTable(t *testing.T) {
	_, _, _, su := fixtureDB(t)
	rows, err := su.Query(ctxT(t), `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
			(SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition`)
	if err != nil {
		t.Fatal(err)
	}
	type info struct {
		enabled, forced bool
		policies        int64
	}
	got := map[string]info{}
	for rows.Next() {
		var n string
		var i info
		if err := rows.Scan(&n, &i.enabled, &i.forced, &i.policies); err != nil {
			t.Fatal(err)
		}
		got[n] = i
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, r := range rlsTables {
		want[r.name] = true
		i, ok := got[r.name]
		switch {
		case !ok:
			t.Errorf("%s: table missing", r.name)
		case !i.enabled || !i.forced:
			t.Errorf("%s: RLS enabled=%v forced=%v, want ENABLE + FORCE (§6.1)", r.name, i.enabled, i.forced)
		case i.policies == 0:
			t.Errorf("%s: RLS without any policy", r.name)
		}
	}
	for n, i := range got {
		switch {
		case want[n]:
		case noRLSTables[n]:
			if i.enabled {
				t.Errorf("%s: §6.3 marks it \"—\" but RLS is enabled", n)
			}
		default:
			t.Errorf("%s: table not classified (add it to rlsTables or noRLSTables with its §6.3 symbol)", n)
		}
	}
}

// TestRLSUnsetOrEmptyGUC is IT-17 (and IT-03): a pool connection whose app.* variables were never set, or were set
// with SET LOCAL by an earlier transaction (the value left behind is ”), sees 0 rows in every RLS table — no error.
func TestRLSUnsetOrEmptyGUC(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	for _, roles := range [][2]string{{"mg_api_tenant", "mg_api_platform"}, {"mg_worker_tenant", "mg_worker_platform"}} {
		s := e.openStore(t, db, roles[0], roles[1], 1) // one connection per pool ⇒ the same connection is reused
		check := func(stage, role string, run func(sql string, dst ...any) error) {
			for _, r := range rlsTables {
				if !canSelect(t, su, role, r.name) {
					continue
				}
				var n int64
				if err := run("SELECT count(*) FROM "+q(r.name), &n); err != nil {
					t.Errorf("%s/%s/%s: error %v, want 0 rows without error", role, stage, r.name, err)
				} else if n != 0 {
					t.Errorf("%s/%s/%s: %d rows visible, want 0", role, stage, r.name, n)
				}
			}
		}
		tenantRun := func(sql string, dst ...any) error { return s.tenant.QueryRow(ctx, sql).Scan(dst...) }
		platformRun := func(sql string, dst ...any) error { return s.platform.QueryRow(ctx, sql).Scan(dst...) }

		// never set
		var scope, tid *string
		if err := s.tenant.QueryRow(ctx, "SELECT current_setting('app.scope', true), current_setting('app.tenant_id', true)").Scan(&scope, &tid); err != nil {
			t.Fatal(err)
		}
		if scope != nil || tid != nil {
			t.Fatalf("fresh connection: app.scope=%v app.tenant_id=%v, want unset", scope, tid)
		}
		check("unset", roles[0], tenantRun)
		check("unset", roles[1], platformRun)

		// set by an earlier transaction on the same connection, then left empty
		var pidIn, pidAfter int32
		if err := s.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pidIn)
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.platformTx(ctx, func(tx pgx.Tx) error { return nil }); err != nil {
			t.Fatal(err)
		}
		var sScope, sTid string
		if err := s.tenant.QueryRow(ctx, "SELECT pg_backend_pid(), current_setting('app.scope', true), current_setting('app.tenant_id', true)").
			Scan(&pidAfter, &sScope, &sTid); err != nil {
			t.Fatal(err)
		}
		if pidIn != pidAfter || sScope != "" || sTid != "" {
			t.Fatalf("reused connection: pid %d→%d, app.scope=%q app.tenant_id=%q; want same pid and empty strings", pidIn, pidAfter, sScope, sTid)
		}
		check("empty", roles[0], tenantRun)
		check("empty", roles[1], platformRun)
	}
}

// tenantView checks, inside WithTenantTx(own), that every table the tenant role may read shows only own's rows
// (at least one) and that tables of scope P are not even readable.
func tenantView(t *testing.T, s *Store, su *pgx.Conn, role string, own uuid.UUID, extra string) {
	t.Helper()
	ctx := ctxT(t)
	for _, r := range rlsTables {
		var total, mine int64
		err := s.tenantTx(ctx, own, func(tx pgx.Tx) error {
			if extra != "" {
				if _, err := tx.Exec(ctx, extra); err != nil {
					return err
				}
			}
			if r.kind == "P" {
				_, err := tx.Exec(ctx, "SELECT 1 FROM "+q(r.name)+" LIMIT 1")
				return err
			}
			return tx.QueryRow(ctx, fmt.Sprintf("SELECT count(*), count(*) FILTER (WHERE %s = $1) FROM %s", q(r.col), q(r.name)), own).
				Scan(&total, &mine)
		})
		switch {
		case r.kind == "P" || !canSelect(t, su, role, r.name):
			wantSQLState(t, role+"/"+r.name+" (not granted)", err, privilegeErr)
		case err != nil:
			t.Errorf("%s/%s: %v", role, r.name, err)
		case total != mine || mine == 0:
			t.Errorf("%s/%s: %d rows visible, %d of the own tenant; want only own rows (≥ 1)", role, r.name, total, mine)
		}
	}
}

// TestRLSTenantScope is IT-03 for the tables of P2-T03: with app.tenant_id = A a tenant role sees only A's rows —
// including identities of A's IdP only — and cannot read tables of scope P.
func TestRLSTenantScope(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	for _, roles := range [][2]string{{"mg_api_tenant", "mg_api_platform"}, {"mg_worker_tenant", "mg_worker_platform"}} {
		s := e.openStore(t, db, roles[0], roles[1], 2)
		tenantView(t, s, su, roles[0], f.a.id, "")
		tenantView(t, s, su, roles[0], f.b.id, "")
	}
}

// TestRLSTenantPoolCannotBecomePlatform is IT-17: a tenant-pool connection that sets app.scope='platform' itself
// still sees only its own tenant, still cannot read tables of scope P, and with app.tenant_id cleared sees nothing.
func TestRLSTenantPoolCannotBecomePlatform(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	s := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	tenantView(t, s, su, "mg_api_tenant", f.a.id, "SELECT set_config('app.scope', 'platform', true)")

	for _, r := range rlsTables {
		var n int64
		err := s.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.scope', 'platform', true), set_config('app.tenant_id', '', true)"); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+q(r.name)).Scan(&n)
		})
		switch {
		case r.kind == "P" || !canSelect(t, su, "mg_api_tenant", r.name):
			wantSQLState(t, "platform scope on tenant pool/"+r.name, err, privilegeErr)
		case err != nil || n != 0:
			t.Errorf("platform scope on tenant pool/%s: %d rows, err %v; want 0 rows", r.name, n, err)
		}
	}
	for _, table := range []string{"sessions", "auth_requests"} { // identity module only, platform pool
		err := s.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT 1 FROM "+q(table))
			return err
		})
		wantSQLState(t, "tenant pool/"+table, err, privilegeErr)
	}
}

// TestRLSPlatformScope: the platform pool sees every tenant in T+P tables and the P tables, never the tenant-internal
// tables (T), and only platform events in audit_events.
func TestRLSPlatformScope(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	for _, roles := range [][2]string{{"mg_api_tenant", "mg_api_platform"}, {"mg_worker_tenant", "mg_worker_platform"}} {
		s := e.openStore(t, db, roles[0], roles[1], 2)
		role := roles[1]
		for _, r := range rlsTables {
			var both, platformRows int64
			err := s.platformTx(ctx, func(tx pgx.Tx) error {
				switch r.kind {
				case "P":
					_, err := tx.Exec(ctx, "SELECT 1 FROM "+q(r.name)+" LIMIT 1")
					return err
				case "T":
					_, err := tx.Exec(ctx, "SELECT 1 FROM "+q(r.name)+" LIMIT 1")
					return err
				}
				return tx.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FILTER (WHERE %[1]s IN ($1, $2)), count(*) FILTER (WHERE %[1]s IS NULL) FROM %[2]s",
					q(r.col), q(r.name)), f.a.id, f.b.id).Scan(&both, &platformRows)
			})
			switch {
			case r.kind == "T" || !canSelect(t, su, role, r.name):
				wantSQLState(t, role+"/"+r.name, err, privilegeErr)
			case err != nil:
				t.Errorf("%s/%s: %v", role, r.name, err)
			case r.kind == "T/P" && (both != 0 || platformRows == 0):
				t.Errorf("%s/%s: %d tenant events, %d platform events; want 0 and ≥ 1", role, r.name, both, platformRows)
			case r.kind == "T+P" && both < 2:
				t.Errorf("%s/%s: %d rows of tenants A and B, want ≥ 2", role, r.name, both)
			}
		}
		var hosts, settings, pusers int64
		if err := s.platformTx(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM hosts WHERE id = $1), (SELECT count(*) FROM system_settings WHERE key = $2),
				(SELECT count(*) FROM platform_users WHERE identity_id = $3)`, f.host, f.setting, f.platformUser).Scan(&hosts, &settings, &pusers)
		}); err != nil || hosts != 1 || settings != 1 || pusers != 1 {
			t.Errorf("%s: P tables hosts=%d system_settings=%d platform_users=%d err=%v, want 1 each", role, hosts, settings, pusers, err)
		}
	}
}

// TestRLSPlatformOpsHiddenFromAPI: policy by role (§6.1, §7.6) — the mg_api_* roles never see the platform_ops DEK
// nor the secrets encrypted with it, and cannot create them; the worker does see them.
func TestRLSPlatformOpsHiddenFromAPI(t *testing.T) {
	e, db, f, _ := fixtureDB(t)
	ctx := ctxT(t)
	count := func(s *Store, table string, id uuid.UUID) int64 {
		var n int64
		col := "id"
		if table == "secrets" {
			col = "dek_id"
		}
		if err := s.platformTx(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE %s = $1", q(table), col), id).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	api := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	for _, table := range []string{"tenant_keys", "secrets"} {
		if n := count(api, table, f.opsDEK); n != 0 {
			t.Errorf("mg_api_platform sees %d %s rows of the platform_ops DEK, want 0", n, table)
		}
		if n := count(api, table, f.platformDEK); n != 1 {
			t.Errorf("mg_api_platform sees %d %s rows of the platform DEK, want 1", n, table)
		}
		if n := count(worker, table, f.opsDEK); n != 1 {
			t.Errorf("mg_worker_platform sees %d %s rows of the platform_ops DEK, want 1", n, table)
		}
	}
	err := api.platformTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant_keys (scope, version, wrapped_dek, wrap_nonce, kek_id, state)
			VALUES ('platform_ops', $1, '\x01', '\x02', 'kek-ops', 'retired')`, 1+randInt(1<<30))
		return err
	})
	wantSQLState(t, "mg_api_platform inserting a platform_ops DEK", err, privilegeErr)
}

// TestCrossTenantWritesRejected is IT-03 (write side): inside tenant A's transaction a row for tenant B violates the
// WITH CHECK policy, and a row of A that references B's identity or instance violates the composite foreign key.
func TestCrossTenantWritesRejected(t *testing.T) {
	e, db, f, _ := fixtureDB(t)
	ctx := ctxT(t)
	s := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	err := s.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
		_, err := q.CreateTenantMembership(ctx, sqlcdb.CreateTenantMembershipParams{TenantID: f.a.id, IdentityID: f.b.identity, RoleID: f.tenantRole})
		return err
	})
	wantSQLState(t, "membership of A with B's identity", err, "23503")
	err = s.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
		_, err := q.CreateDevice(ctx, sqlcdb.CreateDeviceParams{TenantID: f.a.id, InstanceID: f.b.instance, HeadscaleNodeID: 99, MachineKey: "mkey:x"})
		return err
	})
	wantSQLState(t, "device of A on B's instance", err, "23503")
	err = s.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
		_, err := q.CreateDevice(ctx, sqlcdb.CreateDeviceParams{TenantID: f.b.id, InstanceID: f.b.instance, HeadscaleNodeID: 98, MachineKey: "mkey:y"})
		return err
	})
	wantSQLState(t, "device of B written in A's scope", err, privilegeErr)
	// the platform pool has no privilege at all on tenant-internal tables
	err = s.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.ListTenantMemberships(ctx, f.a.id)
		return err
	})
	wantSQLState(t, "platform pool reading tenant_memberships", err, privilegeErr)
}

// TestWithTxScopeAndRole is IT-17 "two pools by role": WithTenantTx runs on a member of mg_app_tenant with
// app.scope='tenant' and the tenant's ID; WithPlatformTx on a member of mg_app_platform with app.scope='platform'
// and no tenant. Queries through sqlc see only what RLS allows.
func TestWithTxScopeAndRole(t *testing.T) {
	e, db, f, _ := fixtureDB(t)
	ctx := ctxT(t)
	s := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	type state struct {
		user, scope, tenant  string
		inTenant, inPlatform bool
	}
	const probe = `SELECT current_user::text, current_setting('app.scope', true), current_setting('app.tenant_id', true),
		pg_has_role(current_user, 'mg_app_tenant', 'MEMBER'), pg_has_role(current_user, 'mg_app_platform', 'MEMBER')`
	var in state
	if err := s.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, probe).Scan(&in.user, &in.scope, &in.tenant, &in.inTenant, &in.inPlatform)
	}); err != nil {
		t.Fatal(err)
	}
	if want := (state{"mg_api_tenant", "tenant", f.a.id.String(), true, false}); in != want {
		t.Errorf("WithTenantTx state = %+v, want %+v", in, want)
	}
	if err := s.platformTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, probe).Scan(&in.user, &in.scope, &in.tenant, &in.inTenant, &in.inPlatform)
	}); err != nil {
		t.Fatal(err)
	}
	if want := (state{"mg_api_platform", "platform", "", false, true}); in != want {
		t.Errorf("WithPlatformTx state = %+v, want %+v", in, want)
	}

	if err := s.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
		if tn, err := q.GetTenant(ctx, f.a.id); err != nil || tn.Slug != f.a.slug {
			return fmt.Errorf("own tenant %+v: %w", tn, err)
		}
		if _, err := q.GetTenant(ctx, f.b.id); !errors.Is(err, ErrNoRows) {
			return fmt.Errorf("other tenant: want ErrNoRows, got %w", err)
		}
		inst, err := q.GetLiveInstanceForTenant(ctx, f.a.id)
		if err != nil || inst.ID != f.a.instance {
			return fmt.Errorf("instance %s: %w", inst.ID, err)
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
	if err := s.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		for _, id := range []uuid.UUID{f.a.id, f.b.id} {
			if _, err := q.GetTenant(ctx, id); err != nil {
				return fmt.Errorf("platform reading tenant %s: %w", id, err)
			}
		}
		_, err := q.GetHost(ctx, f.host)
		return err
	}); err != nil {
		t.Error(err)
	}
	// the transaction rolls back when fn fails
	sentinel := errors.New("boom")
	if err := s.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if _, err := q.UpsertSystemSetting(ctx, sqlcdb.UpsertSystemSettingParams{Key: "test.rollback_" + f.sfx, Value: []byte(`1`)}); err != nil {
			return err
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
	if err := s.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.GetSystemSetting(ctx, "test.rollback_"+f.sfx)
		return err
	}); !errors.Is(err, ErrNoRows) {
		t.Errorf("setting written by a failed transaction: err = %v, want ErrNoRows", err)
	}
}

func TestOpenRejectsWrongRoles(t *testing.T) {
	e := requireDB(t)
	db := e.sharedDB(t)
	ctx := ctxT(t)
	for _, c := range [][2]string{
		{"mg_api_platform", "mg_api_tenant"}, // swapped
		{"mg_api_tenant", "mg_api_tenant"},   // platform pool on a tenant role
		{"mg_readonly", "mg_api_platform"},   // not in an application group
		{"mg_api_tenant", "mg_backup"},       // BYPASSRLS
	} {
		s, err := Open(ctx, Config{URL: e.storeURL(db), Tenant: e.creds(t, c[0]), Platform: e.creds(t, c[1])})
		if err == nil {
			s.Close()
			t.Errorf("Open(tenant=%s, platform=%s) succeeded, want an error", c[0], c[1])
		}
	}
	if _, err := Open(ctx, Config{URL: e.storeURL(db), Tenant: Credentials{User: "mg_api_tenant", PasswordFile: "/nonexistent"},
		Platform: e.creds(t, "mg_api_platform")}); err == nil {
		t.Error("Open with a missing password file succeeded")
	}
	s := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 0)
	if err := s.Ping(ctx); err != nil {
		t.Error(err)
	}
}

// TestReadonlyCannotReadRLSTables: mg_readonly sets app.scope and app.tenant_id itself and still reads no table with
// RLS (§6.1 — any role can set app.*, so RLS only means something for roles the application controls).
func TestReadonlyCannotReadRLSTables(t *testing.T) {
	e, db, f, _ := fixtureDB(t)
	ctx := ctxT(t)
	ro := e.connectAs(t, db, "mg_readonly")
	if _, err := ro.Exec(ctx, "SELECT set_config('app.scope', 'platform', false), set_config('app.tenant_id', $1, false)", f.a.id.String()); err != nil {
		t.Fatal(err)
	}
	for _, r := range rlsTables {
		_, err := ro.Exec(ctx, "SELECT 1 FROM public."+q(r.name)+" LIMIT 1")
		wantSQLState(t, "mg_readonly/"+r.name, err, privilegeErr)
	}
	for _, table := range []string{"sessions", "auth_requests", "roles"} {
		_, err := ro.Exec(ctx, "SELECT 1 FROM public."+q(table)+" LIMIT 1")
		wantSQLState(t, "mg_readonly/"+table, err, privilegeErr)
	}
	var report, public bool
	if err := ro.QueryRow(ctx, "SELECT has_schema_privilege('report', 'USAGE'), has_schema_privilege('public', 'USAGE')").Scan(&report, &public); err != nil {
		t.Fatal(err)
	}
	if !report || public {
		t.Errorf("mg_readonly USAGE: report=%v public=%v, want true/false", report, public)
	}
}

// TestBackupRoleReadsEverything: mg_backup (BYPASSRLS + pg_read_all_data, P2-T03a) reads every row of the FORCE RLS
// tables and of the partitions without setting app.*, and cannot write.
func TestBackupRoleReadsEverything(t *testing.T) {
	e, db, f, _ := fixtureDB(t)
	ctx := ctxT(t)
	bk := e.connectAs(t, db, "mg_backup")
	var tenants, audit, defaultRows int64
	if err := bk.QueryRow(ctx, `SELECT (SELECT count(*) FROM tenants WHERE id IN ($1, $2)),
			(SELECT count(*) FROM audit_events WHERE tenant_id IN ($1, $2) OR tenant_id IS NULL),
			(SELECT count(*) FROM partitions.audit_events_default)`, f.a.id, f.b.id).Scan(&tenants, &audit, &defaultRows); err != nil {
		t.Fatal(err)
	}
	if tenants != 2 || audit < 3 {
		t.Errorf("mg_backup sees %d tenants and %d audit events of the fixture, want 2 and ≥ 3", tenants, audit)
	}
	_, err := bk.Exec(ctx, "INSERT INTO system_settings (key, value) VALUES ('test.backup_write', '1')")
	if code := SQLState(err); code != "25006" && code != privilegeErr {
		t.Errorf("mg_backup write: SQLSTATE %q (%v), want read_only_sql_transaction or insufficient_privilege", code, err)
	}
}

// TestAuditWriterInsertOnly: the detached audit path (mg_audit_writer, §6.1) inserts events of any tenant without
// app.* and can read nothing back.
func TestAuditWriterInsertOnly(t *testing.T) {
	e, db, f, _ := fixtureDB(t)
	ctx := ctxT(t)
	w := e.connectAs(t, db, "mg_audit_writer")
	for _, tenant := range []*uuid.UUID{&f.a.id, nil} {
		if _, err := w.Exec(ctx, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome)
			VALUES ($1, 'identity', 'tenant.read', 'tenant', 'denied')`, tenant); err != nil {
			t.Errorf("detached insert (tenant %v): %v", tenant, err)
		}
	}
	_, err := w.Exec(ctx, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome)
		VALUES ($1, 'identity', 'x', 'y', 'denied') RETURNING id`, f.a.id)
	wantSQLState(t, "mg_audit_writer INSERT … RETURNING", err, privilegeErr)
	for _, sql := range []string{
		"SELECT 1 FROM audit_events LIMIT 1",
		"UPDATE audit_events SET outcome = 'success'",
		"DELETE FROM audit_events",
		"TRUNCATE audit_events",
		"INSERT INTO security_events (kind, severity, source) VALUES ('x', 'low', 'y')",
	} {
		_, err := w.Exec(ctx, sql)
		wantSQLState(t, "mg_audit_writer: "+sql, err, privilegeErr)
	}
}

// TestCatalogRoles checks the role model of §6.1 in the catalog.
func TestCatalogRoles(t *testing.T) {
	_, _, _, su := fixtureDB(t)
	ctx := ctxT(t)
	// USAGE = the privileges (and therefore the RLS policies) of the group apply to the role (§6.1). mg_migrator holds
	// ADMIN on the roles it created but neither inherits nor can SET to the application groups.
	rows, err := su.Query(ctx, `SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication,
			pg_has_role(rolname, 'mg_app_tenant', 'USAGE') OR pg_has_role(rolname, 'mg_app_tenant', 'SET'),
			pg_has_role(rolname, 'mg_app_platform', 'USAGE') OR pg_has_role(rolname, 'mg_app_platform', 'SET')
		FROM pg_roles WHERE rolname LIKE 'mg\_%' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	type attrs struct {
		login, super, bypass, createrole, createdb, repl, inTenant, inPlatform bool
	}
	got := map[string]attrs{}
	for rows.Next() {
		var n string
		var a attrs
		if err := rows.Scan(&n, &a.login, &a.super, &a.bypass, &a.createrole, &a.createdb, &a.repl, &a.inTenant, &a.inPlatform); err != nil {
			t.Fatal(err)
		}
		got[n] = a
	}
	want := map[string]attrs{
		"mg_app_tenant":      {inTenant: true},
		"mg_app_platform":    {inPlatform: true},
		"mg_api_tenant":      {login: true, inTenant: true},
		"mg_worker_tenant":   {login: true, inTenant: true},
		"mg_api_platform":    {login: true, inPlatform: true},
		"mg_worker_platform": {login: true, inPlatform: true},
		"mg_readonly":        {login: true},
		"mg_audit_writer":    {login: true},
		"mg_partition_maint": {login: true},
		"mg_migrator":        {login: true, createrole: true},
		"mg_backup":          {login: true, bypass: true},
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("role %s = %+v, want %+v", n, got[n], w)
		}
	}
	for n := range got {
		if _, ok := want[n]; !ok {
			t.Errorf("unexpected role %s", n)
		}
	}

	var violations []string
	rows, err = su.Query(ctx, `
		SELECT format('%s owns %s', r.rolname, c.oid::regclass) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
		 WHERE r.rolname = ANY($1)
		UNION ALL
		SELECT format('%s has TRUNCATE on %s', a.grantee::regrole, c.oid::regclass)
		  FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
		 WHERE a.privilege_type = 'TRUNCATE' AND a.grantee <> c.relowner
		UNION ALL
		SELECT format('PUBLIC has %s on %s', a.privilege_type, c.oid::regclass)
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a
		 WHERE n.nspname IN ('public', 'partitions', 'report') AND a.grantee = 0
		UNION ALL
		SELECT format('mg_readonly has %s on %s', a.privilege_type, c.oid::regclass)
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a
		 WHERE n.nspname <> 'report' AND a.grantee = 'mg_readonly'::regrole
		UNION ALL
		SELECT format('PUBLIC may run %s', p.oid::regprocedure)
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'public' AND p.proname LIKE ANY (ARRAY['app\_%', 'mg\_%'])
		   AND has_function_privilege('public', p.oid, 'EXECUTE')`, appRoles)
	if err != nil {
		t.Fatal(err)
	}
	violations, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}
