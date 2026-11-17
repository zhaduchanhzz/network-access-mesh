package store

// Migration 0014 (P3-T04, §6.3, §11.3 step 3): CHECK/DEFAULT of the hosts columns placement reads (status, capacity,
// public_entry, run_uid_range, tenant_net_pool, stun_port_range) and of tenant_instances (net_cidr is one IPv4 /29,
// run_uid within the host bounds). Up on data of schema 13 (staging), the constraints case by case, and what the
// application roles may not do to keep "UID never reused" (no DELETE on tenant_instances).

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestMigration0014OnSchema13Data — expand-only: a database at schema 13 holding the fixture of 0001–0013 and a host
// registered by adopt-instance before 0014 (capacity '{}', public_entry '{}') migrates to 14; the host gets the
// provisional capacity of P1-T20 (max_instances 100), every other row stays as it was (same count, same hosts statuses,
// pools and instance subnets). A database holding an instance subnet that is not a /29 refuses 0014 as a whole (goose:
// one transaction — schema stays at 13) and migrates once the row is repaired; a host whose capacity already holds a key
// of its own is refused too, never silently rewritten.
func TestMigration0014OnSchema13Data(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 13)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	f := newFixture()
	for v := int64(1); v <= 13; v++ {
		fixtureSteps[v](f, t, su)
	}
	adopted := newID()
	exec(t, su, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, capacity, public_entry)
		VALUES ($1, 'adopted-'||$2, 'lab', int4range(30000, 40000), '10.250.0.0/16', '{}', '{}')`, adopted, f.sfx)
	odd := newID()
	exec(t, su, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, capacity)
		VALUES ($1, 'odd-'||$2, 'lab', int4range(30000, 40000), '10.251.0.0/16', '{"cpu": 8}')`, odd, f.sfx)
	exec(t, su, `UPDATE tenant_instances SET net_cidr = '10.250.0.0/28' WHERE id = $1`, f.a.instance)
	before := publicRowCounts(t, su)
	snapshot := func() string {
		var s string
		if err := su.QueryRow(ctx, `SELECT string_agg(x, ';' ORDER BY x) FROM (
				SELECT concat_ws('|', h.id, h.status, h.run_uid_range, h.tenant_net_pool, h.public_entry::text) AS x FROM hosts h
				UNION ALL SELECT concat_ws('|', i.id, i.status, i.run_uid, i.net_cidr) FROM tenant_instances i) s`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// 1. refused while a row breaks a new constraint
	if err := MigrateTo(ctx, mig, 14); err == nil {
		t.Fatal("0014 applied on a database holding a /28 instance subnet and a host capacity with a foreign key")
	}
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 13 {
		t.Fatalf("schema version after the refused 0014 = %d (%v), want 13", v, err)
	}
	exec(t, su, `UPDATE tenant_instances SET net_cidr = '10.250.0.0/29' WHERE id = $1`, f.a.instance)
	if err := MigrateTo(ctx, mig, 14); err == nil {
		t.Fatal("0014 applied on a host capacity holding a key of its own")
	}
	exec(t, su, `UPDATE hosts SET capacity = '{}' WHERE id = $1`, odd)
	want := snapshot()

	// 2. applied once repaired
	if err := MigrateTo(ctx, mig, 14); err != nil {
		t.Fatalf("0014 on repaired data: %v", err)
	}
	after := publicRowCounts(t, su)
	if got := after["goose_db_version"] - before["goose_db_version"]; got != 1 {
		t.Errorf("goose_db_version: %d new rows, want 1", got)
	}
	delete(before, "goose_db_version")
	for n, c := range before {
		if after[n] != c {
			t.Errorf("%s: %d rows at schema 13, %d at schema 14", n, c, after[n])
		}
	}
	if got := snapshot(); got != want {
		t.Errorf("hosts/instances changed by 0014:\n%s\nwant\n%s", got, want)
	}
	rows, err := su.Query(ctx, `SELECT capacity::text FROM hosts WHERE id IN ($1, $2, $3)`, f.host, adopted, odd)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(caps) != 3 {
		t.Fatalf("capacities %v, %v", caps, err)
	}
	for _, c := range caps {
		if c != `{"max_instances": 100}` {
			t.Errorf("capacity after 0014 = %s, want the provisional max_instances 100 (P1-T20)", c)
		}
	}
	// the default of a host registered from now on, and the fixture step of 0014 passes the new checks
	var def string
	if err := su.QueryRow(ctx, `INSERT INTO hosts (name, region, run_uid_range, tenant_net_pool)
		VALUES ('new-'||$1, 'lab', int4range(30000, 40000), '10.250.0.0/16') RETURNING capacity::text`, f.sfx).Scan(&def); err != nil ||
		def != `{"max_instances": 100}` {
		t.Errorf("default capacity = %s (%v)", def, err)
	}
	fixtureSteps[14](f, t, su)
	var forced bool
	if err := su.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid = 'hosts'::regclass`).Scan(&forced); err != nil || !forced {
		t.Errorf("hosts FORCE ROW LEVEL SECURITY after 0014 = %v (%v)", forced, err)
	}
}

// TestPlacementCheckConstraints — the constraints of 0014, one deviation at a time from a valid host / instance row
// (superuser, rolled back: only the constraints play a part).
func TestPlacementCheckConstraints(t *testing.T) {
	_, _, f, su := fixtureDB(t)
	ctx := ctxT(t)
	h := row{"name": "'h-" + f.sfx + "'", "region": "'lab'", "run_uid_range": "int4range(30000, 40000)",
		"tenant_net_pool": "'10.250.0.0/16'"}
	set := func(col, val string) string {
		return "UPDATE hosts SET " + col + " = " + val + " WHERE id = " + lit(f.host)
	}
	inst := func(col, val string) string {
		return "UPDATE tenant_instances SET " + col + " = " + val + " WHERE id = " + lit(f.a.instance)
	}
	cases := []struct{ name, sql, want string }{
		{"host: valid with defaults", h.insert("hosts"), ""},
		{"host: valid draining", h.with("status", "'draining'").insert("hosts"), ""},
		{"host: valid disabled", h.with("status", "'disabled'").insert("hosts"), ""},
		{"host: unknown status", h.with("status", "'maintenance'").insert("hosts"), "23514"},
		// capacity
		{"capacity: valid 0", set("capacity", `'{"max_instances": 0}'`), ""},
		{"capacity: valid 2147483647", set("capacity", `'{"max_instances": 2147483647}'`), ""},
		{"capacity: integral value with a fraction", set("capacity", `'{"max_instances": 10.0}'`), "23514"},
		{"capacity: exponent", set("capacity", `'{"max_instances": 1e2}'`), ""}, // jsonb stores it as 100
		{"capacity: empty", set("capacity", `'{}'`), "23514"},
		{"capacity: negative", set("capacity", `'{"max_instances": -1}'`), "23514"},
		{"capacity: fraction", set("capacity", `'{"max_instances": 1.5}'`), "23514"},
		{"capacity: too large", set("capacity", `'{"max_instances": 2147483648}'`), "23514"},
		{"capacity: string", set("capacity", `'{"max_instances": "10"}'`), "23514"},
		{"capacity: unknown key", set("capacity", `'{"max_instances": 10, "cpu": 8}'`), "23514"},
		{"capacity: not an object", set("capacity", `'[10]'`), "23514"},
		// public_entry
		{"entry: valid empty", set("public_entry", `'{}'`), ""},
		{"entry: valid vps_gateway", set("public_entry", `'{"ipv4": "203.0.113.7", "mode": "vps_gateway"}'`), ""},
		{"entry: valid private LAN address, direct", set("public_entry", `'{"ipv4": "192.168.1.8", "mode": "direct"}'`), ""},
		{"entry: valid without mode", set("public_entry", `'{"ipv4": "198.51.100.1"}'`), ""},
		{"entry: unknown mode", set("public_entry", `'{"ipv4": "203.0.113.7", "mode": "tunnel"}'`), "23514"},
		{"entry: ipv6 key (MVP: IPv4 only)", set("public_entry", `'{"ipv4": "203.0.113.7", "ipv6": "2001:db8::1"}'`), "23514"},
		{"entry: unknown key", set("public_entry", `'{"ipv4": "203.0.113.7", "port": 443}'`), "23514"},
		{"entry: ipv4 not canonical (leading zero)", set("public_entry", `'{"ipv4": "203.0.113.07"}'`), "23514"},
		{"entry: ipv4 with prefix", set("public_entry", `'{"ipv4": "203.0.113.0/24"}'`), "23514"},
		{"entry: ipv4 is IPv6", set("public_entry", `'{"ipv4": "2001:db8::1"}'`), "23514"},
		{"entry: ipv4 a name", set("public_entry", `'{"ipv4": "gw.example.com"}'`), "23514"},
		{"entry: ipv4 a number", set("public_entry", `'{"ipv4": 3405803783}'`), "23514"},
		{"entry: loopback", set("public_entry", `'{"ipv4": "127.0.0.1"}'`), "23514"},
		{"entry: unspecified", set("public_entry", `'{"ipv4": "0.0.0.0"}'`), "23514"},
		{"entry: link-local", set("public_entry", `'{"ipv4": "169.254.10.1"}'`), "23514"},
		{"entry: multicast", set("public_entry", `'{"ipv4": "224.0.0.1"}'`), "23514"},
		{"entry: broadcast", set("public_entry", `'{"ipv4": "255.255.255.255"}'`), "23514"},
		{"entry: inside the tenant pool", set("public_entry", `'{"ipv4": "10.250.3.4"}'`), "23514"},
		// pools
		{"pool: valid /29", h.with("tenant_net_pool", "'10.250.0.0/29'").insert("hosts"), ""},
		{"pool: valid /8", h.with("tenant_net_pool", "'10.0.0.0/8'").insert("hosts"), ""},
		{"pool: IPv6", h.with("tenant_net_pool", "'fd00::/64'").insert("hosts"), "23514"},
		{"pool: /30", h.with("tenant_net_pool", "'10.250.0.0/30'").insert("hosts"), "23514"},
		{"pool: /7", h.with("tenant_net_pool", "'10.0.0.0/7'").insert("hosts"), "23514"},
		{"pool: inside 100.64.0.0/10", h.with("tenant_net_pool", "'100.100.0.0/16'").insert("hosts"), "23514"},
		{"pool: containing 100.64.0.0/10", h.with("tenant_net_pool", "'100.0.0.0/8'").insert("hosts"), "23514"},
		{"uid range: valid lower bound 1000", h.with("run_uid_range", "int4range(1000, 2000)").insert("hosts"), ""},
		{"uid range: valid upper bound", h.with("run_uid_range", "int4range(2147483000, 2147483646, '[]')").insert("hosts"), ""},
		{"uid range: below 1000", h.with("run_uid_range", "int4range(999, 2000)").insert("hosts"), "23514"},
		{"uid range: up to 2147483647", h.with("run_uid_range", "int4range(2147483000, 2147483647)").insert("hosts"), ""},
		{"uid range: unbounded above", h.with("run_uid_range", "int4range(30000, NULL)").insert("hosts"), "23514"},
		{"uid range: unbounded below", h.with("run_uid_range", "int4range(NULL, 30000)").insert("hosts"), "23514"},
		{"stun range: valid", h.with("stun_port_range", "int4range(40000, 40100)").insert("hosts"), ""},
		{"stun range: valid up to 65535", h.with("stun_port_range", "int4range(65000, 65535, '[]')").insert("hosts"), ""},
		{"stun range: below 1024", h.with("stun_port_range", "int4range(1000, 2000)").insert("hosts"), "23514"},
		{"stun range: empty", h.with("stun_port_range", "'empty'::int4range").insert("hosts"), "23514"},
		{"stun range: unbounded", h.with("stun_port_range", "int4range(40000, NULL)").insert("hosts"), "23514"},
		// tenant_instances
		{"instance: valid /29", inst("net_cidr", "'10.250.9.8/29'"), ""},
		{"instance: /28", inst("net_cidr", "'10.250.9.0/28'"), "23514"},
		{"instance: /30", inst("net_cidr", "'10.250.9.8/30'"), "23514"},
		{"instance: IPv6 /125", inst("net_cidr", "'fd00::/125'"), "23514"},
		{"instance: run_uid 999", inst("run_uid", "999"), "23514"},
		{"instance: run_uid 2147483647", inst("run_uid", "2147483647"), "23514"},
		{"instance: valid run_uid 1000", inst("run_uid", "1000"), ""},
	}
	for _, c := range cases {
		tx, err := su.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, c.sql)
		_ = tx.Rollback(ctx)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v\n%s", c.name, err, c.sql)
			}
			continue
		}
		if got := SQLState(err); got != c.want {
			t.Errorf("%s: SQLSTATE %q (%v), want %s\n%s", c.name, got, err, c.want, c.sql)
		}
	}
}

// TestPlacementPrivileges — what "UID never reused" rests on besides UNIQUE(host_id, run_uid): no application role can
// delete or truncate a tenant_instances row; only the platform roles may lock host rows (SELECT … FOR UPDATE needs
// UPDATE on a column) and insert/update instances; the tenant roles see no host at all.
func TestPlacementPrivileges(t *testing.T) {
	_, _, _, su := fixtureDB(t)
	ctx := ctxT(t)
	for _, role := range []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_readonly",
		"mg_audit_writer", "mg_partition_maint"} {
		var del, trunc, hostSel, hostUpd, instIns bool
		if err := su.QueryRow(ctx, `SELECT has_table_privilege($1, 'tenant_instances', 'DELETE'),
				has_table_privilege($1, 'tenant_instances', 'TRUNCATE'), has_table_privilege($1, 'hosts', 'SELECT'),
				has_any_column_privilege($1, 'hosts', 'UPDATE'), has_table_privilege($1, 'tenant_instances', 'INSERT')`,
			role).Scan(&del, &trunc, &hostSel, &hostUpd, &instIns); err != nil {
			t.Fatal(err)
		}
		platform := role == "mg_api_platform" || role == "mg_worker_platform"
		if del || trunc {
			t.Errorf("%s may delete/truncate tenant_instances (DELETE %v, TRUNCATE %v): a UID could be handed out again", role,
				del, trunc)
		}
		if hostSel != platform || hostUpd != platform || instIns != platform {
			t.Errorf("%s: hosts SELECT %v, UPDATE %v, tenant_instances INSERT %v; want %v", role, hostSel, hostUpd, instIns,
				platform)
		}
	}
}
