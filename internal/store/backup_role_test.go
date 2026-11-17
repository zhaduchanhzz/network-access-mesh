package store

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// mg_backup (P2-T03a, §6.1) — the role of the pg-backup service: it must read every row (pg_dump sets
// row_security = off, which only a BYPASSRLS role may do on FORCE ROW LEVEL SECURITY tables) and must not be able to
// do anything else. default_transaction_read_only is only a default the role can switch off itself, so these tests
// switch it off first and check that the privileges alone refuse every write and every escalation.

// backupConn opens a mg_backup connection with the session switched to read-write.
func backupConn(t *testing.T, e *pgEnv, db string) *pgx.Conn {
	t.Helper()
	bk := e.connectAs(t, db, "mg_backup")
	var ro string
	if err := bk.QueryRow(ctxT(t), "SHOW default_transaction_read_only").Scan(&ro); err != nil {
		t.Fatal(err)
	}
	if ro != "on" {
		t.Errorf("mg_backup: default_transaction_read_only = %s, want on (bootstrap ALTER ROLE … SET)", ro)
	}
	if _, err := bk.Exec(ctxT(t), "INSERT INTO system_settings (key, value) VALUES ('test.bk_default', '1')"); SQLState(err) != "25006" {
		t.Errorf("mg_backup write with the default session: SQLSTATE %q (%v), want 25006 read_only_sql_transaction", SQLState(err), err)
	}
	if _, err := bk.Exec(ctxT(t), "SET default_transaction_read_only = off"); err != nil {
		t.Fatal(err)
	}
	return bk
}

// TestBackupRoleCatalog: what the catalog grants mg_backup — attributes, memberships, and per object type.
func TestBackupRoleCatalog(t *testing.T) {
	_, _, _, su := fixtureDB(t)
	ctx := ctxT(t)
	var super, createrole, createdb, repl, bypass, login bool
	var config []string
	if err := su.QueryRow(ctx, `SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolcanlogin,
			COALESCE(rolconfig, '{}') FROM pg_roles WHERE rolname = 'mg_backup'`).
		Scan(&super, &createrole, &createdb, &repl, &bypass, &login, &config); err != nil {
		t.Fatal(err)
	}
	if super || createrole || createdb || repl || !bypass || !login {
		t.Errorf("mg_backup attributes: super=%v createrole=%v createdb=%v replication=%v bypassrls=%v login=%v",
			super, createrole, createdb, repl, bypass, login)
	}
	if strings.Join(config, ",") != "default_transaction_read_only=on" {
		t.Errorf("mg_backup role settings = %v, want [default_transaction_read_only=on]", config)
	}

	violations := func(what, sql string) {
		t.Helper()
		rows, err := su.Query(ctx, sql)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		for _, v := range got {
			t.Errorf("%s: %s", what, v)
		}
	}
	// exactly one membership (pg_read_all_data, without ADMIN), nobody is a member of mg_backup, and through
	// pg_read_all_data it reaches no other role (pg_write_all_data, pg_*_server_*, pg_signal_backend, application roles…)
	violations("membership", `
		SELECT format('member of %s (admin=%s)', roleid::regrole, admin_option) FROM pg_auth_members
		 WHERE member = 'mg_backup'::regrole AND (roleid <> 'pg_read_all_data'::regrole OR admin_option)
		UNION ALL
		SELECT format('%s is a member of mg_backup', member::regrole) FROM pg_auth_members WHERE roleid = 'mg_backup'::regrole
		UNION ALL
		SELECT format('reaches role %s', rolname) FROM pg_roles
		 WHERE rolname NOT IN ('mg_backup', 'pg_read_all_data') AND pg_has_role('mg_backup', oid, 'MEMBER')
		UNION ALL
		SELECT 'not a member of pg_read_all_data' WHERE NOT pg_has_role('mg_backup', 'pg_read_all_data', 'USAGE')`)
	// relations of every schema of the database: SELECT (pg_dump) and nothing else
	violations("relation privilege", `
		SELECT format('%s on %s', p, c.oid::regclass)
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 CROSS JOIN unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']) AS p
		 WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		   AND has_table_privilege('mg_backup', c.oid, p)
		UNION ALL
		SELECT format('cannot SELECT %s', c.oid::regclass)
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		   AND NOT has_table_privilege('mg_backup', c.oid, 'SELECT')
		UNION ALL
		SELECT format('%s on sequence %s', p, c.oid::regclass)
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN unnest(ARRAY['USAGE', 'UPDATE']) AS p
		 WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		   AND has_sequence_privilege('mg_backup', c.oid, p)`)
	violations("schema/database privilege", `
		SELECT format('CREATE on schema %s', nspname) FROM pg_namespace
		 WHERE has_schema_privilege('mg_backup', oid, 'CREATE')
		UNION ALL
		SELECT format('%s on database %s', p, current_database()) FROM unnest(ARRAY['CREATE', 'TEMPORARY']) AS p
		 WHERE has_database_privilege('mg_backup', current_database(), p)
		UNION ALL
		SELECT 'no CONNECT on the database' WHERE NOT has_database_privilege('mg_backup', current_database(), 'CONNECT')`)
	// no function that runs with another role's rights, and none of the platform's maintenance functions
	violations("function", `
		SELECT format('EXECUTE on %s%s', p.oid::regprocedure, CASE WHEN p.prosecdef THEN ' (SECURITY DEFINER)' ELSE '' END)
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		   AND has_function_privilege('mg_backup', p.oid, 'EXECUTE')
		   AND (p.prosecdef OR p.proname LIKE 'mg\_%' OR p.proname LIKE 'app\_%')`)
}

// TestBackupRoleCannotWriteOrEscalate: with its read-only default switched off, mg_backup still cannot change data,
// create objects, take an exclusive lock, become another role, reach the server's files or programs, or signal
// another session. Each statement runs in its own transaction.
func TestBackupRoleCannotWriteOrEscalate(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	bk := backupConn(t, e, db)
	var seq, partition string
	if err := su.QueryRow(ctx, `SELECT c.oid::regclass::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'S' AND n.nspname = 'river' ORDER BY 1 LIMIT 1`).Scan(&seq); err != nil {
		t.Fatalf("a sequence of the river schema: %v", err)
	}
	if err := su.QueryRow(ctx, `SELECT c.oid::regclass::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'audit_events'::regclass ORDER BY 1 LIMIT 1`).Scan(&partition); err != nil {
		t.Fatal(err)
	}
	var suPID int
	if err := su.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&suPID); err != nil {
		t.Fatal(err)
	}
	denied := []string{
		"INSERT INTO system_settings (key, value) VALUES ('test.bk_rw', '1')",
		fmt.Sprintf("UPDATE tenants SET name = name WHERE id = '%s'", f.a.id),
		"DELETE FROM sessions",
		"DELETE FROM audit_events",
		"TRUNCATE security_events",
		"UPDATE secrets SET ciphertext = ciphertext",
		"INSERT INTO " + partition + " (tenant_id, actor_type, action, resource_type, outcome) VALUES (NULL, 'system', 'x', 'y', 'success')",
		"INSERT INTO river.river_job (args, kind, max_attempts) VALUES ('{}', 'backup.test', 1)",
		"SELECT nextval('" + seq + "')",
		"SELECT setval('" + seq + "', 1)",
		"CREATE TABLE public.bk_test (i int)",
		"CREATE TEMP TABLE bk_test (i int)",
		"CREATE SCHEMA bk_test",
		"CREATE FUNCTION public.bk_test() RETURNS int LANGUAGE sql RETURN 1",
		"CREATE ROLE bk_test",
		"CREATE DATABASE bk_test",
		"ALTER ROLE mg_backup NOBYPASSRLS",
		"ALTER ROLE mg_backup CREATEDB",
		"ALTER ROLE mg_api_platform PASSWORD NULL",
		"ALTER TABLE tenants DISABLE ROW LEVEL SECURITY",
		"DROP TABLE security_events",
		"SET ROLE mg_migrator",
		"SET ROLE mg_api_platform",
		"SET ROLE postgres",
		"SET SESSION AUTHORIZATION mg_migrator",
		"LOCK TABLE tenants IN ACCESS EXCLUSIVE MODE",
		"LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE",
		"COPY tenants TO '/tmp/mg_backup_test'",
		"COPY (SELECT 1) TO PROGRAM 'true'",
		"SELECT pg_read_file('/etc/passwd')",
		fmt.Sprintf("SELECT pg_terminate_backend(%d)", suPID),
		"SELECT mg_partition_maintain('audit_events', 3)",
		"SELECT app_tenant_id()",
	}
	for _, sql := range denied {
		if strings.HasPrefix(sql, "CREATE DATABASE") { // not allowed inside a transaction block
			_, err := bk.Exec(ctx, sql)
			wantSQLState(t, "mg_backup: "+sql, err, privilegeErr)
			continue
		}
		tx, err := bk.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, sql)
		_ = tx.Rollback(ctx)
		wantSQLState(t, "mg_backup: "+sql, err, privilegeErr)
	}

	// GRANT without the grant option is a warning, not an error: check that nothing was granted
	if _, err := bk.Exec(ctx, "GRANT SELECT ON tenants TO mg_readonly"); err != nil && SQLState(err) != privilegeErr {
		t.Errorf("GRANT by mg_backup: %v", err)
	}
	if canSelect(t, su, "mg_readonly", "tenants") {
		t.Error("mg_backup granted SELECT on tenants to mg_readonly")
	}

	// what pg_dump does: ACCESS SHARE locks and reads with row_security = off, every row of the FORCE RLS tables
	tx, err := bk.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var n int64
	if _, err := tx.Exec(ctx, "SET LOCAL row_security = off; LOCK TABLE tenants, audit_events IN ACCESS SHARE MODE"); err != nil {
		t.Fatalf("pg_dump's session settings as mg_backup: %v", err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM tenants WHERE id IN ($1, $2)", f.a.id, f.b.id).Scan(&n); err != nil || n != 2 {
		t.Errorf("mg_backup with row_security = off sees %d fixture tenants (%v), want 2", n, err)
	}
	_ = tx.Rollback(ctx)

	// Known residual, asserted so that a change is noticed: like every role, mg_backup may change its OWN session
	// defaults (ALTER ROLE … SET) — the read-only default is defence in depth; the privileges above are the control.
	// The role setting is a cluster-wide catalog row that the bootstrap of every other test package (superuser.sql)
	// rewrites too: without the cluster lock, a package starting meanwhile makes this fail with "tuple concurrently
	// updated" (XX000) instead of the privilege outcome the test pins.
	unlock := e.lockCluster(t)
	defer unlock()
	tx, err = bk.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "ALTER ROLE mg_backup SET default_transaction_read_only = off"); err != nil {
		t.Errorf("ALTER ROLE mg_backup SET … by itself: %v (PostgreSQL behaviour changed — update the evidence of P2-T03a)", err)
	}
	_ = tx.Rollback(ctx)
}

// TestRowSecurityOffNeedsBypassRLS is the negative control of the §6.1 assumption checked by P2-T03a: without
// BYPASSRLS, pg_dump's row_security = off fails on the FORCE RLS tables — for the owner (mg_migrator) and for an
// application role alike — instead of silently dumping a filtered subset.
func TestRowSecurityOffNeedsBypassRLS(t *testing.T) {
	e, db, _, _ := fixtureDB(t)
	ctx := ctxT(t)
	for _, role := range []string{"mg_migrator", "mg_api_platform"} {
		c := e.connectAs(t, db, role)
		if _, err := c.Exec(ctx, "SET row_security = off"); err != nil {
			t.Fatal(err)
		}
		_, err := c.Exec(ctx, "SELECT count(*) FROM tenants")
		wantSQLState(t, role+" with row_security = off", err, privilegeErr)
	}
}
