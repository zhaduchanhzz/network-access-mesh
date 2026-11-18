package store

// Migrations 0020–0023 (P4-T05, §6.3): enrollment_requests + FK device_inventory_cache.enrollment_request_id (0020),
// groups, group_members, tenant_tags (0021), network_resources, dns_records (0022), support_access_grants + trigger
// mg_support_grant_guard, identity_links (0023). The generic tests of rls_test.go (RLS classes, unset GUC, tenant/platform
// scope, read-only role, catalog) cover the new tables through rlsTables and the fixture steps 20–23, and IT-03 of
// tests/isolation walks their foreign keys; the tests here cover what is specific to them: up on a database holding data
// of schema 19 (staging), cross-tenant writes (WITH CHECK, composite FK), the grant matrix, the policy classes, the CHECK
// constraints, the platform-managed tags and the decision rules of a support grant.

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// p4Tables are the tables created by 0020–0023, in migration order.
var p4Tables = []string{"enrollment_requests", "groups", "group_members", "tenant_tags", "network_resources", "dns_records",
	"support_access_grants", "identity_links"}

// TestMigrations0020To0023OnSchema19Data — the verification of P4-T05 "up trên bản sao có dữ liệu": a database at schema
// 19 (the state of staging) holding rows of every table of 0001–0019. An orphan device_inventory_cache.enrollment_request_id
// (no module wrote that column before 0020) makes 0020 fail as a whole — the schema stays at 19 —, and once repaired
// 0020 → 0023 apply one step at a time: every existing row survives, the new tables start empty, the device links stay
// NULL; the seeds then run, the new tables take data, the application reads old and new rows through RLS, and no
// partition carries a privilege.
func TestMigrations0020To0023OnSchema19Data(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 19)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	f := newFixture()
	for v := int64(1); v <= 19; v++ {
		fixtureSteps[v](f, t, su)
	}

	exec(t, su, `UPDATE device_inventory_cache SET enrollment_request_id = $1 WHERE id = $2`, newID(), f.b.device)
	err = MigrateTo(ctx, mig, 20)
	if err == nil || !strings.Contains(err.Error(), "device_inventory_cache_enrollment_request_fkey") {
		t.Fatalf("0020 on a database holding an orphan enrollment link: err = %v, want the FK violation", err)
	}
	var table *string
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 19 {
		t.Fatalf("schema version after the refused 0020 = %d (%v), want 19", v, err)
	}
	if err := su.QueryRow(ctx, `SELECT to_regclass('public.enrollment_requests')::text`).Scan(&table); err != nil || table != nil {
		t.Fatalf("enrollment_requests after the refused 0020: %v (%v), want no table", table, err)
	}
	exec(t, su, `UPDATE device_inventory_cache SET enrollment_request_id = NULL WHERE id = $1`, f.b.device)

	before := publicRowCounts(t, su)
	for _, n := range p4Tables {
		if _, ok := before[n]; ok {
			t.Fatalf("%s exists at schema 19", n)
		}
	}
	for v := int64(20); v <= 23; v++ {
		if err := MigrateTo(ctx, mig, v); err != nil {
			t.Fatalf("migration %04d on a database of schema %d with data: %v", v, v-1, err)
		}
		if got, err := SchemaVersion(ctx, mig); err != nil || got != v {
			t.Fatalf("schema version = %d (%v), want %d", got, err, v)
		}
	}
	after := publicRowCounts(t, su)
	if got := after["goose_db_version"] - before["goose_db_version"]; got != 4 {
		t.Errorf("goose_db_version: %d new rows, want 4 (0020–0023)", got)
	}
	delete(before, "goose_db_version")
	for n, c := range before {
		if after[n] != c {
			t.Errorf("%s: %d rows at schema 19, %d at schema 23", n, c, after[n])
		}
	}
	for _, n := range p4Tables {
		if c, ok := after[n]; !ok || c != 0 {
			t.Errorf("%s at schema 23: present=%v, %d rows; want an empty table", n, ok, c)
		}
	}
	var linked int64
	if err := su.QueryRow(ctx, `SELECT count(enrollment_request_id) FROM device_inventory_cache`).Scan(&linked); err != nil || linked != 0 {
		t.Errorf("after 0020: %d devices linked to an enrollment request (%v), want 0", linked, err)
	}
	if err := Migrate(ctx, mig); err != nil { // nothing pending, then the seeds
		t.Fatalf("Migrate: %v", err)
	}

	for v := int64(20); v <= 23; v++ { // data of the new tables, written after the migration
		fixtureSteps[v](f, t, su)
	}
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	var slug string
	var requests, groups, members, tags, resources, records, grants, devLinked int64
	if err := worker.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT slug::text FROM tenants WHERE id = $1), (SELECT count(*) FROM enrollment_requests),
				(SELECT count(*) FROM groups), (SELECT count(*) FROM group_members), (SELECT count(*) FROM tenant_tags),
				(SELECT count(*) FROM network_resources), (SELECT count(*) FROM dns_records), (SELECT count(*) FROM support_access_grants),
				(SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = $2)`, f.a.id, f.a.enrollment).
			Scan(&slug, &requests, &groups, &members, &tags, &resources, &records, &grants, &devLinked)
	}); err != nil {
		t.Fatal(err)
	}
	if slug != f.a.slug || requests != 1 || groups != 1 || members != 1 || tags != 1 || resources != 1 || records != 1 || grants != 1 || devLinked != 1 {
		t.Errorf("worker tenant pool, tenant A: slug %q, %d requests, %d groups, %d members, %d tags, %d resources, %d records, %d grants, "+
			"%d linked devices; want %q and 1 each", slug, requests, groups, members, tags, resources, records, grants, devLinked, f.a.slug)
	}
	var platformGrants int64
	if err := worker.platformTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM support_access_grants WHERE tenant_id IN ($1, $2)`, f.a.id, f.b.id).Scan(&platformGrants)
	}); err != nil || platformGrants != 2 {
		t.Errorf("worker platform pool: %d support grants of A and B (%v), want 2", platformGrants, err)
	}
	if v, err := PartitionGrantViolations(ctx, su); err != nil || len(v) != 0 {
		t.Errorf("partition grant violations at schema 23: %v (%v)", v, err)
	}
}

// p4People adds, as superuser, what the decision rules need beyond the fixture — in tenant A: a second membership of the
// fixture role (approver ≠ requester of an enrollment request), memberships with the seeded tenant_owner and
// tenant_viewer roles, a locked owner and an owner whose identity is disabled; on the platform: two Super Admins and a
// Platform Support user (seeded roles — the shared database is migrated with its seeds).
type p4People struct {
	a2, owner, viewer, lockedOwner, disabledOwner uuid.UUID // tenant_memberships.id in tenant A
	bOwner                                        uuid.UUID // tenant_memberships.id in tenant B (tenant_owner)
	sa1, sa2, support                             uuid.UUID // platform_users.id
}

func newP4People(t *testing.T, su *pgx.Conn, f *fixture) p4People {
	t.Helper()
	p := p4People{}
	member := func(tr *tenantRows, roleSQL, status, identityStatus string) uuid.UUID {
		identity, m := newID(), newID()
		exec(t, su, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, status)
			VALUES ($1, $2, $3, 'tenant', 'p4-'||$4, 'p4-'||$4||'@example.test', $5)`, identity, tr.idp, tr.id, randomHex(6), identityStatus)
		exec(t, su, `INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status) VALUES ($1, $2, $3, (`+roleSQL+`), $4)`,
			m, tr.id, identity, status)
		return m
	}
	seeded := func(key string) string { return "SELECT id FROM roles WHERE scope = 'tenant' AND key = '" + key + "'" }
	p.a2 = member(&f.a, "SELECT '"+f.tenantRole.String()+"'::uuid", "active", "active")
	p.owner = member(&f.a, seeded("tenant_owner"), "active", "active")
	p.viewer = member(&f.a, seeded("tenant_viewer"), "active", "active")
	p.lockedOwner = member(&f.a, seeded("tenant_owner"), "locked", "active")
	p.disabledOwner = member(&f.a, seeded("tenant_owner"), "active", "disabled")
	p.bOwner = member(&f.b, seeded("tenant_owner"), "active", "active")
	staff := func(key string) uuid.UUID {
		identity, pu := newID(), newID()
		exec(t, su, `INSERT INTO identities (id, idp_id, scope, subject, email) VALUES ($1, $2, 'platform', 'staff-'||$3, 'staff@example.test')`,
			identity, f.platformIdP, randomHex(6))
		exec(t, su, `INSERT INTO platform_users (id, identity_id, role_id) VALUES ($1, $2, (SELECT id FROM roles WHERE scope = 'platform' AND key = $3))`,
			pu, identity, key)
		return pu
	}
	p.sa1, p.sa2, p.support = staff("super_admin"), staff("super_admin"), staff("platform_support")
	return p
}

// TestP4CrossTenantWritesRejected is IT-03 (write side) for 0020–0023, through the application roles: inside tenant A's
// transaction a row of tenant B violates the WITH CHECK policy; a row of A that references an object of B — instance,
// membership, group, enrollment request — violates the composite foreign key; B's rows are invisible to UPDATE and DELETE;
// a decision on A's support grant by B's owner is refused by the trigger; the platform pool cannot touch the
// tenant-internal tables. Positive controls show the same statements succeed on A's own objects.
func TestP4CrossTenantWritesRejected(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	p := newP4People(t, su, f)
	api := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	const (
		insRequest = `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id, method, target_membership_id)
			VALUES ($1, $2, $3, 'preauth_key', $4)`
		insGroup    = `INSERT INTO groups (tenant_id, name) VALUES ($1, 'g-'||$2)`
		insMember   = `INSERT INTO group_members (tenant_id, group_id, membership_id) VALUES ($1, $2, $3)`
		insTag      = `INSERT INTO tenant_tags (tenant_id, name) VALUES ($1, 'tag:t-'||$2)`
		insResource = `INSERT INTO network_resources (tenant_id, name, kind, address, owner_group_id) VALUES ($1, 'r-'||$2, 'host', '10.9.9.9/32', $3)`
		insRecord   = `INSERT INTO dns_records (tenant_id, name, type, value) VALUES ($1, 'x-'||$2||'.ts.test', 'A', '100.64.1.1')`
		insGrant    = `INSERT INTO support_access_grants (tenant_id, grantee_platform_user_id, requested_by_platform_user_id, effective_role_key,
			reason, ticket_ref, expires_at) VALUES ($1, $2, $2, $3, 'check', 'T-1', now() + interval '1 hour')`
		approveTenant = `UPDATE support_access_grants SET status = 'approved', approval_kind = 'tenant', approved_by_membership_id = $1,
			decided_at = now() WHERE id = $2`
	)
	n := func() string { return randomHex(4) }
	A, B, platform := f.a.id, f.b.id, uuid.Nil
	cases := []struct {
		name   string
		s      *Store
		scope  uuid.UUID
		sql    string
		args   []any
		want   string // SQLSTATE, "" = must succeed
		rows   int64  // rows affected when want == ""
		update bool   // check rows
	}{
		// WITH CHECK of the tenant policy: a row of B written in A's scope
		{"enrollment request of B in A's scope", api, A, insRequest, []any{B, f.b.instance, f.b.membership, f.b.membership}, privilegeErr, 0, false},
		{"group of B in A's scope", api, A, insGroup, []any{B, n()}, privilegeErr, 0, false},
		{"group member of B in A's scope", api, A, insMember, []any{B, f.b.group, p.bOwner}, privilegeErr, 0, false},
		{"tag of B in A's scope", api, A, insTag, []any{B, n()}, privilegeErr, 0, false},
		{"resource of B in A's scope", api, A, insResource, []any{B, n(), nil}, privilegeErr, 0, false},
		{"DNS record of B in A's scope", api, A, insRecord, []any{B, n()}, privilegeErr, 0, false},
		{"tenant pool inserts a support grant", api, A, insGrant, []any{A, f.platformUserRow, f.supportRole}, privilegeErr, 0, false},
		// composite foreign keys: a row of A referencing an object of B
		{"request of A on B's instance", api, A, insRequest, []any{A, f.b.instance, f.a.membership, f.a.membership}, "23503", 0, false},
		{"request of A by B's membership", api, A, insRequest, []any{A, f.a.instance, f.b.membership, f.b.membership}, "23503", 0, false},
		{"request of A for B's membership", api, A, `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id,
			method, target_membership_id) VALUES ($1, $2, $3, 'preauth_key', $4)`, []any{A, f.a.instance, f.a.membership, f.b.membership}, "23503", 0, false},
		{"request of A decided by B's membership", api, A, `UPDATE enrollment_requests SET approver_membership_id = $1 WHERE id = $2`,
			[]any{f.b.membership, f.a.enrollment}, "23503", 0, false},
		{"device of A linked to B's request", worker, A, `UPDATE device_inventory_cache SET enrollment_request_id = $1 WHERE id = $2`,
			[]any{f.b.enrollment, f.a.device}, "23503", 0, false},
		{"A's group gets B's membership", api, A, insMember, []any{A, f.a.group, f.b.membership}, "23503", 0, false},
		{"A's membership into B's group", api, A, insMember, []any{A, f.b.group, p.owner}, "23503", 0, false},
		{"resource of A owned by B's group", api, A, insResource, []any{A, n(), f.b.group}, "23503", 0, false},
		{"A's resource re-owned by B's group", api, A, `UPDATE network_resources SET owner_group_id = $1 WHERE id = $2`,
			[]any{f.b.group, f.a.resource}, "23503", 0, false},
		// the grant trigger: a decision on A's grant by B's owner is refused (the membership is not one of A)
		{"A's grant approved by B's owner", api, A, approveTenant, []any{p.bOwner, f.a.grant}, privilegeErr, 0, false},
		// RLS hides B's rows from A's scope: UPDATE/DELETE affect nothing
		{"A renames B's group", api, A, `UPDATE groups SET name = 'stolen' WHERE id = $1`, []any{f.b.group}, "", 0, true},
		{"A deletes B's tag", api, A, `DELETE FROM tenant_tags WHERE id = $1`, []any{f.b.tag}, "", 0, true},
		{"A deletes B's DNS record", api, A, `DELETE FROM dns_records WHERE id = $1`, []any{f.b.record}, "", 0, true},
		{"A revokes B's grant", api, A, `UPDATE support_access_grants SET status = 'revoked', revoked_at = now() WHERE id = $1`,
			[]any{f.b.grant}, "", 0, true},
		{"A expires B's enrollment request", worker, A, `UPDATE enrollment_requests SET status = 'expired' WHERE id = $1`,
			[]any{f.b.enrollment}, "", 0, true},
		{"A removes B's group members", api, A, `DELETE FROM group_members WHERE group_id = $1`, []any{f.b.group}, "", 0, true},
		// the platform pool has no privilege on the tenant-internal tables (T)
		{"platform pool reads enrollment requests", api, platform, `SELECT 1 FROM enrollment_requests`, nil, privilegeErr, 0, false},
		{"platform pool reads groups", worker, platform, `SELECT 1 FROM groups`, nil, privilegeErr, 0, false},
		{"platform pool reads group members", api, platform, `SELECT 1 FROM group_members`, nil, privilegeErr, 0, false},
		{"platform pool reads tags", worker, platform, `SELECT 1 FROM tenant_tags`, nil, privilegeErr, 0, false},
		{"platform pool reads resources", api, platform, `SELECT 1 FROM network_resources`, nil, privilegeErr, 0, false},
		{"platform pool reads DNS records", worker, platform, `SELECT 1 FROM dns_records`, nil, privilegeErr, 0, false},
		{"platform pool reads identity links", worker, platform, `SELECT 1 FROM identity_links`, nil, privilegeErr, 0, false},
		// positive controls: the same statements on A's own objects
		{"request of A by A's membership", api, A, insRequest, []any{A, f.a.instance, f.a.membership, f.a.membership}, "", 1, true},
		{"group of A", api, A, insGroup, []any{A, n()}, "", 1, true},
		{"A's group gets A's owner", api, A, insMember, []any{A, f.a.group, p.owner}, "", 1, true},
		{"tag of A", api, A, insTag, []any{A, n()}, "", 1, true},
		{"resource of A owned by A's group", api, A, insResource, []any{A, n(), f.a.group}, "", 1, true},
		{"DNS record of A", api, A, insRecord, []any{A, n()}, "", 1, true},
		{"support grant of A requested by the platform", api, platform, insGrant, []any{A, f.platformUserRow, f.supportRole}, "", 1, true},
		{"A's grant approved by A's owner", api, A, approveTenant, []any{p.owner, f.a.grant}, "", 1, true},
	}
	for _, c := range cases {
		n, err := execIn(ctx, c.s, c.scope, c.sql, c.args...)
		if c.want == "" {
			if err != nil || (c.update && n != c.rows) {
				t.Errorf("%s: %d rows, err %v; want %d rows, no error", c.name, n, err, c.rows)
			}
			continue
		}
		wantSQLState(t, c.name, err, c.want)
	}
}

// TestP4GrantMatrix — least privilege (§6.1) of 0020–0023 read from the catalog: for every new table, exactly these
// privileges per role — no TRUNCATE, no table-level UPDATE, immutable columns (the approved content of an enrollment
// request, tag names, the request of a support grant…) without UPDATE, nothing on identity_links before P7-T06, nothing
// for mg_audit_writer, mg_readonly, mg_partition_maint; mg_backup reads every table (pg_read_all_data). Then statements
// prove the matrix holds at execution time.
func TestP4GrantMatrix(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	roles := []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_audit_writer", "mg_readonly",
		"mg_partition_maint", "mg_backup"}
	S, SID := []string{"SELECT"}, []string{"SELECT", "INSERT", "DELETE"}
	with := func(m map[string]grantSpec) map[string]grantSpec {
		m["mg_backup"] = grantSpec{table: S}
		return m
	}
	grantDecide := "decided_at,expires_at,revoked_at,starts_at,status,updated_at,version,approval_kind"
	want := map[string]map[string]grantSpec{
		"enrollment_requests": with(map[string]grantSpec{
			"mg_api_tenant": {[]string{"SELECT", "INSERT"}, cols("approved_at,approver_membership_id,auth_id_hash,claimed_at,claimed_from_ip," +
				"consumed_node_id,credential_expires_at,enroll_code_hash,failure_code,headscale_preauthkey_id,issued_at,registered_machine_key," +
				"reported_hostname,session_id_hash,status,updated_at,version")},
			"mg_worker_tenant": {[]string{"SELECT", "DELETE"}, cols("consumed_node_id,failure_code,registered_machine_key,reported_hostname,status,updated_at,version")},
		}),
		"groups": with(map[string]grantSpec{
			"mg_api_tenant": {SID, cols("description,name,updated_at,version")}, "mg_worker_tenant": {S, nil},
		}),
		"group_members": with(map[string]grantSpec{"mg_api_tenant": {SID, nil}, "mg_worker_tenant": {S, nil}}),
		"tenant_tags": with(map[string]grantSpec{
			"mg_api_tenant": {SID, cols("description,updated_at,version")}, "mg_worker_tenant": {S, nil},
		}),
		"network_resources": with(map[string]grantSpec{
			"mg_api_tenant":    {SID, cols("address,description,kind,name,owner_group_id,ports,protocol,tags,updated_at,version")},
			"mg_worker_tenant": {S, nil},
		}),
		"dns_records": with(map[string]grantSpec{"mg_api_tenant": {SID, nil}, "mg_worker_tenant": {S, nil}}),
		"support_access_grants": with(map[string]grantSpec{
			"mg_api_tenant":      {S, cols(grantDecide + ",approved_by_membership_id")},
			"mg_worker_tenant":   {S, nil},
			"mg_api_platform":    {[]string{"SELECT", "INSERT"}, cols(grantDecide + ",approved_by_platform_user_id")},
			"mg_worker_platform": {S, cols("revoked_at,status,updated_at,version")},
		}),
		"identity_links": with(map[string]grantSpec{}),
	}
	if len(want) != len(p4Tables) {
		t.Fatalf("grant matrix covers %d tables, 0020–0023 created %d", len(want), len(p4Tables))
	}
	for table, byRole := range want {
		for _, role := range roles {
			var got grantSpec
			rows, err := su.Query(ctx, `SELECT p FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES',
				'TRIGGER', 'MAINTAIN']) WITH ORDINALITY AS u(p, o) WHERE has_table_privilege($1, $2::regclass, p) ORDER BY o`, role, "public."+table)
			if err != nil {
				t.Fatal(err)
			}
			if got.table, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
				t.Fatal(err)
			}
			rows, err = su.Query(ctx, `SELECT attname::text FROM pg_attribute WHERE attrelid = $2::regclass AND attnum > 0 AND NOT attisdropped
				AND has_column_privilege($1, $2::regclass, attnum, 'UPDATE')`, role, "public."+table)
			if err != nil {
				t.Fatal(err)
			}
			if got.columns, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
				t.Fatal(err)
			}
			w := byRole[role]
			sort.Strings(got.columns)
			if !slices.Equal(got.table, w.table) || !slices.Equal(got.columns, slices.Sorted(slices.Values(w.columns))) {
				t.Errorf("%s on %s: table %v, UPDATE columns %v; want %v, %v", role, table, got.table, got.columns, w.table, w.columns)
			}
		}
	}
	// The trigger function of support_access_grants: nobody runs it directly (a trigger needs no EXECUTE).
	for _, role := range roles {
		var ok bool
		if err := su.QueryRow(ctx, `SELECT has_function_privilege($1, 'mg_support_grant_guard()', 'EXECUTE')`, role).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("%s holds EXECUTE on mg_support_grant_guard()", role)
		}
	}

	// At execution time.
	api := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	A, platform := f.a.id, uuid.Nil
	req, grant := lit(f.a.enrollment), lit(f.a.grant)
	denied := []struct {
		name  string
		s     *Store
		scope uuid.UUID
		sql   string
	}{
		{"api tenant rewrites the tags of a request", api, A, `UPDATE enrollment_requests SET requested_tags = '{tag:admin}' WHERE id = ` + req},
		{"api tenant renames the device of a request", api, A, `UPDATE enrollment_requests SET device_label = 'x' WHERE id = ` + req},
		{"api tenant makes a request reusable", api, A, `UPDATE enrollment_requests SET reusable = true WHERE id = ` + req},
		{"api tenant moves a request to another member", api, A, `UPDATE enrollment_requests SET target_membership_id = NULL WHERE id = ` + req},
		{"worker tenant creates a request", worker, A, `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id,
			method, target_membership_id) VALUES (` + lit(A) + `, ` + lit(f.a.instance) + `, ` + lit(f.a.membership) + `, 'preauth_key', ` + lit(f.a.membership) + `)`},
		{"worker tenant records an approval", worker, A, `UPDATE enrollment_requests SET approved_at = now() WHERE id = ` + req},
		{"api tenant deletes a request", api, A, `DELETE FROM enrollment_requests WHERE id = ` + req},
		{"api tenant renames a tag", api, A, `UPDATE tenant_tags SET name = 'tag:other'`},
		{"api tenant changes the purpose of a tag", api, A, `UPDATE tenant_tags SET purpose = 'exit'`},
		{"api tenant marks a tag platform-managed", api, A, `UPDATE tenant_tags SET platform_managed = true`},
		{"api tenant changes the source of a group", api, A, `UPDATE groups SET source = 'idp'`},
		{"api tenant edits a DNS record", api, A, `UPDATE dns_records SET value = '100.64.9.9'`},
		{"worker tenant deletes a group", worker, A, `DELETE FROM groups`},
		{"worker tenant writes a resource", worker, A, `UPDATE network_resources SET description = 'x'`},
		{"worker tenant truncates groups", worker, A, `TRUNCATE groups`},
		{"api tenant rewrites the reason of a grant", api, A, `UPDATE support_access_grants SET reason = 'x' WHERE id = ` + grant},
		{"api tenant re-targets a grant", api, A, `UPDATE support_access_grants SET grantee_platform_user_id = grantee_platform_user_id WHERE id = ` + grant},
		{"api tenant records a break-glass approver", api, A, `UPDATE support_access_grants SET approved_by_platform_user_id = NULL WHERE id = ` + grant},
		{"api platform records a tenant approver", api, platform, `UPDATE support_access_grants SET approved_by_membership_id = NULL WHERE id = ` + grant},
		{"api platform changes the role of a grant", api, platform, `UPDATE support_access_grants SET effective_role_key = effective_role_key WHERE id = ` + grant},
		{"worker platform decides a grant", worker, platform, `UPDATE support_access_grants SET approval_kind = NULL WHERE id = ` + grant},
		{"api platform deletes a grant", api, platform, `DELETE FROM support_access_grants WHERE id = ` + grant},
		{"worker platform creates a grant", worker, platform, `INSERT INTO support_access_grants (tenant_id, grantee_platform_user_id,
			requested_by_platform_user_id, effective_role_key, reason, ticket_ref, expires_at) SELECT tenant_id, grantee_platform_user_id,
			requested_by_platform_user_id, effective_role_key, reason, ticket_ref, expires_at FROM support_access_grants WHERE id = ` + grant},
		{"api tenant reads identity links", api, A, `SELECT 1 FROM identity_links`},
		{"worker tenant links identities", worker, A, `INSERT INTO identity_links (tenant_id, old_identity_id, old_idp_id, new_identity_id, new_idp_id)
			VALUES (` + lit(A) + `, gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid())`},
	}
	for _, c := range denied {
		_, err := execIn(ctx, c.s, c.scope, c.sql)
		wantSQLState(t, c.name, err, privilegeErr)
	}
	// granted: the worker reconciles a request, the worker platform pool expires a grant, the api tenant pool edits
	for _, c := range []struct {
		name  string
		s     *Store
		scope uuid.UUID
		sql   string
	}{
		{"worker tenant marks a request failed", worker, A, `UPDATE enrollment_requests SET status = 'failed', failure_code = 'reconcile_lost',
			updated_at = now(), version = version + 1 WHERE id = ` + req},
		{"api tenant edits a group", api, A, `UPDATE groups SET name = 'eng2', description = 'x', version = version + 1 WHERE id = ` + lit(f.a.group)},
		{"worker platform expires a grant", worker, platform, `UPDATE support_access_grants SET status = 'expired', version = version + 1 WHERE id = ` + grant},
	} {
		if n, err := execIn(ctx, c.s, c.scope, c.sql); err != nil || n != 1 {
			t.Errorf("%s: %d rows, %v; want 1 row", c.name, n, err)
		}
	}
}

// TestP4PolicyClasses: the RLS policies of the new tables follow their §6.3 symbol exactly — T: one policy, to
// mg_app_tenant only, without a platform branch; T+P: one policy per group role, the tenant one without a platform
// branch; tenant_tags adds three RESTRICTIVE policies of mg_api_tenant (platform-managed tags).
func TestP4PolicyClasses(t *testing.T) {
	_, _, _, su := fixtureDB(t)
	tenantOnly := []string{"mg_app_tenant|ALL|PERMISSIVE|false"}
	want := map[string][]string{
		"enrollment_requests": tenantOnly, "groups": tenantOnly, "group_members": tenantOnly, "network_resources": tenantOnly,
		"dns_records": tenantOnly, "identity_links": tenantOnly,
		"tenant_tags": {"mg_api_tenant|DELETE|RESTRICTIVE|false", "mg_api_tenant|INSERT|RESTRICTIVE|false",
			"mg_api_tenant|UPDATE|RESTRICTIVE|false", "mg_app_tenant|ALL|PERMISSIVE|false"},
		"support_access_grants": {"mg_app_platform|ALL|PERMISSIVE|true", "mg_app_tenant|ALL|PERMISSIVE|false"},
	}
	kinds := map[string]string{}
	for _, r := range rlsTables {
		kinds[r.name] = r.kind
	}
	for _, table := range p4Tables {
		if k := kinds[table]; (k == "T+P") != (table == "support_access_grants") || k == "" {
			t.Errorf("%s: rlsTables class %q", table, k)
		}
		rows, err := su.Query(ctxT(t), `SELECT array_to_string(roles, ',') || '|' || cmd || '|' || permissive || '|' ||
				(COALESCE(qual, '') || COALESCE(with_check, '') LIKE '%app_is_platform%')::text
			FROM pg_policies WHERE schemaname = 'public' AND tablename = $1`, table)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(got)
		if !slices.Equal(got, want[table]) {
			t.Errorf("%s: policies %v, want %v", table, got, want[table])
		}
	}
}

// TestP4CheckConstraints — the CHECK constraints, unique indexes, composite keys and FK actions of 0020–0023: from a
// valid row of each table (a positive control), one deviation at a time is refused with check_violation (23514),
// unique_violation (23505) or foreign_key_violation (23503); the valid variants of each state pass. Each statement runs
// as superuser in its own rolled-back transaction, so RLS and privileges play no part — only the constraints (and, for
// support_access_grants, its trigger) do.
func TestP4CheckConstraints(t *testing.T) {
	_, _, f, su := fixtureDB(t)
	ctx := ctxT(t)
	p := newP4People(t, su, f)
	A, a := lit(f.a.id), &f.a
	sha := func(s string) string { return "sha256(convert_to('" + s + "', 'UTF8'))" }
	rnd := "sha256(convert_to(gen_random_uuid()::text, 'UTF8'))"
	// enrollment_requests
	er := row{"tenant_id": A, "instance_id": lit(a.instance), "requested_by_membership_id": lit(a.membership), "method": "'preauth_key'",
		"target_membership_id": lit(a.membership)}
	window := []string{"issued_at", "now()", "credential_expires_at", "now() + interval '10 minutes'"}
	issued := er.with(append([]string{"status", "'credential_issued'", "headscale_preauthkey_id", "42"}, window...)...)
	web := er.with("method", "'web_auth'")
	webIssued := web.with(append([]string{"status", "'awaiting_device'", "enroll_code_hash", rnd, "session_id_hash", rnd}, window...)...)
	claimed := webIssued.with("status", "'claimed'", "claimed_at", "now()", "auth_id_hash", rnd)
	tagOnly := er.with("target_membership_id", "-", "requested_tags", "'{tag:ci}'")
	decided := er.with("status", "'approved'", "approver_membership_id", lit(p.a2), "approved_at", "now()")
	// groups / tags / resources / records
	group := row{"tenant_id": A, "name": "'ops-" + f.sfx + "'"}
	tag := row{"tenant_id": A, "name": "'tag:check'"}
	res := row{"tenant_id": A, "name": "'svc'", "kind": "'host'", "address": "'10.0.0.9/32'"}
	rec := row{"tenant_id": A, "name": "'svc." + f.a.slug + ".ts.test'", "type": "'A'", "value": "'100.64.0.9'"}
	// support grants and identity links
	grant := row{"tenant_id": A, "grantee_platform_user_id": lit(f.platformUserRow), "requested_by_platform_user_id": lit(f.platformUserRow),
		"effective_role_key": "'" + f.supportRole + "'", "reason": "'check'", "ticket_ref": "'T-2'", "expires_at": "now() + interval '1 hour'"}
	noGuard := "ALTER TABLE support_access_grants DISABLE TRIGGER support_access_grants_guard; "
	link := row{"tenant_id": A, "old_identity_id": lit(a.identity), "old_idp_id": lit(a.idp), "new_identity_id": lit(a.oldIdentity),
		"new_idp_id": lit(a.oldIdP)}
	relink := "DELETE FROM identity_links WHERE tenant_id = " + A + "; "
	type tc struct{ name, sql, want string }
	cases := []tc{
		// enrollment_requests — valid states
		{"request: valid requested key", er.insert("enrollment_requests"), ""},
		{"request: valid pending approval", er.with("status", "'pending_approval'").insert("enrollment_requests"), ""},
		{"request: valid approved", decided.insert("enrollment_requests"), ""},
		{"request: valid rejected", er.with("status", "'rejected'", "approver_membership_id", lit(p.a2)).insert("enrollment_requests"), ""},
		{"request: valid credential issued", issued.insert("enrollment_requests"), ""},
		{"request: valid approved then issued", issued.with("approver_membership_id", lit(p.a2), "approved_at", "now()").insert("enrollment_requests"), ""},
		{"request: valid consumed", issued.with("status", "'consumed'", "consumed_node_id", "9").insert("enrollment_requests"), ""},
		{"request: valid tag-only reusable ephemeral key", tagOnly.with("ephemeral", "true", "reusable", "true").insert("enrollment_requests"), ""},
		{"request: valid web-auth awaiting device", webIssued.insert("enrollment_requests"), ""},
		{"request: valid claimed", claimed.insert("enrollment_requests"), ""},
		{"request: valid verified", claimed.with("status", "'verified'", "consumed_node_id", "3", "registered_machine_key", "'mkey:x'",
			"reported_hostname", "'mg-abc'").insert("enrollment_requests"), ""},
		{"request: valid expired after issue", webIssued.with("status", "'expired'").insert("enrollment_requests"), ""},
		{"request: valid failed", claimed.with("status", "'failed'", "failure_code", "'node_mismatch'").insert("enrollment_requests"), ""},
		{"request: valid native OIDC registered", er.with("method", "'oidc'", "status", "'registered'", "consumed_node_id", "4").insert("enrollment_requests"), ""},
		{"request: valid 15-minute window", issued.with("credential_expires_at", "now() + interval '15 minutes'").insert("enrollment_requests"), ""},
		// enrollment_requests — refused
		{"request: unknown method", er.with("method", "'ssh'").insert("enrollment_requests"), "23514"},
		{"request: unknown status (API term issued)", er.with("status", "'issued'").insert("enrollment_requests"), "23514"},
		{"request: tag without prefix", tagOnly.with("requested_tags", "'{server}'").insert("enrollment_requests"), "23514"},
		{"request: tag in capitals", tagOnly.with("requested_tags", "'{tag:Server}'").insert("enrollment_requests"), "23514"},
		{"request: NULL tag", tagOnly.with("requested_tags", "ARRAY['tag:ci', NULL]").insert("enrollment_requests"), "23514"},
		{"request: tag smuggling a comma", tagOnly.with("requested_tags", `'{"tag:a,tag:b"}'`).insert("enrollment_requests"), "23514"},
		{"request: 65 tags", tagOnly.with("requested_tags", "(SELECT array_agg('tag:t'||g) FROM generate_series(1, 65) g)").insert("enrollment_requests"), "23514"},
		{"request: key without owner nor tag", er.with("target_membership_id", "-").insert("enrollment_requests"), "23514"},
		{"request: web-auth for another member", web.with("target_membership_id", lit(p.a2)).insert("enrollment_requests"), "23514"},
		{"request: web-auth without owner", web.with("target_membership_id", "-", "requested_tags", "'{tag:ci}'").insert("enrollment_requests"), "23514"},
		{"request: web-auth with tags", web.with("requested_tags", "'{tag:ci}'").insert("enrollment_requests"), "23514"},
		{"request: reusable web-auth", web.with("reusable", "true").insert("enrollment_requests"), "23514"},
		{"request: ephemeral native OIDC", er.with("method", "'oidc'", "ephemeral", "true").insert("enrollment_requests"), "23514"},
		{"request: key awaiting a device", issued.with("status", "'awaiting_device'").insert("enrollment_requests"), "23514"},
		{"request: web-auth credential issued", webIssued.with("status", "'credential_issued'").insert("enrollment_requests"), "23514"},
		{"request: key registered", issued.with("status", "'registered'", "consumed_node_id", "5").insert("enrollment_requests"), "23514"},
		{"request: self-approval", decided.with("approver_membership_id", lit(a.membership)).insert("enrollment_requests"), "23514"},
		{"request: approved without approved_at", decided.with("approved_at", "-").insert("enrollment_requests"), "23514"},
		{"request: approved_at without approver", er.with("approved_at", "now()", "status", "'expired'").insert("enrollment_requests"), "23514"},
		{"request: pending approval already decided", decided.with("status", "'pending_approval'").insert("enrollment_requests"), "23514"},
		{"request: rejected without decider", er.with("status", "'rejected'").insert("enrollment_requests"), "23514"},
		{"request: rejected with approved_at", decided.with("status", "'rejected'").insert("enrollment_requests"), "23514"},
		{"request: credential before approval", decided.with(window...).insert("enrollment_requests"), "23514"},
		{"request: credential on pending approval", er.with(append([]string{"status", "'pending_approval'"}, window...)...).insert("enrollment_requests"), "23514"},
		{"request: issued without expiry", issued.with("credential_expires_at", "-").insert("enrollment_requests"), "23514"},
		{"request: expiry without issue", er.with("credential_expires_at", "now() + interval '5 minutes'").insert("enrollment_requests"), "23514"},
		{"request: 16-minute window (T-06)", issued.with("credential_expires_at", "now() + interval '16 minutes'").insert("enrollment_requests"), "23514"},
		{"request: expiry before issue", issued.with("credential_expires_at", "now() - interval '1 minute'").insert("enrollment_requests"), "23514"},
		{"request: credential issued without credential", issued.with("issued_at", "-", "credential_expires_at", "-").insert("enrollment_requests"), "23514"},
		{"request: web-auth awaiting without credential", webIssued.with("issued_at", "-", "credential_expires_at", "-").insert("enrollment_requests"), "23514"},
		{"request: Auth ID on a key", issued.with("auth_id_hash", rnd).insert("enrollment_requests"), "23514"},
		{"request: enrollment code on a key", issued.with("enroll_code_hash", rnd).insert("enrollment_requests"), "23514"},
		{"request: pre-auth key id on web-auth", webIssued.with("headscale_preauthkey_id", "1").insert("enrollment_requests"), "23514"},
		{"request: web-auth issued without code", webIssued.with("enroll_code_hash", "-").insert("enrollment_requests"), "23514"},
		{"request: web-auth issued without session", webIssued.with("session_id_hash", "-").insert("enrollment_requests"), "23514"},
		{"request: claimed without Auth ID", claimed.with("auth_id_hash", "-").insert("enrollment_requests"), "23514"},
		{"request: claimed without claimed_at", claimed.with("claimed_at", "-").insert("enrollment_requests"), "23514"},
		{"request: key issued without its id", issued.with("headscale_preauthkey_id", "-").insert("enrollment_requests"), "23514"},
		{"request: consumed without node", issued.with("status", "'consumed'").insert("enrollment_requests"), "23514"},
		{"request: verified without node", claimed.with("status", "'verified'").insert("enrollment_requests"), "23514"},
		{"request: failed without code", er.with("status", "'failed'").insert("enrollment_requests"), "23514"},
		{"request: failure code format", er.with("status", "'failed'", "failure_code", "'Node Mismatch'").insert("enrollment_requests"), "23514"},
		{"request: Auth ID hash of 16 bytes", claimed.with("auth_id_hash", "decode(repeat('00', 16), 'hex')").insert("enrollment_requests"), "23514"},
		{"request: empty device label", er.with("device_label", "''").insert("enrollment_requests"), "23514"},
		{"request: node id 0", issued.with("status", "'consumed'", "consumed_node_id", "0").insert("enrollment_requests"), "23514"},
		{"request: same enrollment code twice", webIssued.with("enroll_code_hash", sha("dup-"+f.sfx)).insert("enrollment_requests") + "; " +
			webIssued.with("enroll_code_hash", sha("dup-"+f.sfx)).insert("enrollment_requests"), "23505"},
		{"request: same Auth ID twice", claimed.with("auth_id_hash", sha("auth-"+f.sfx)).insert("enrollment_requests") + "; " +
			claimed.with("auth_id_hash", sha("auth-"+f.sfx)).insert("enrollment_requests"), "23505"},
		{"request: same Auth ID in two tenants", claimed.with("auth_id_hash", sha("auth2-"+f.sfx)).insert("enrollment_requests") + "; " +
			claimed.with("auth_id_hash", sha("auth2-"+f.sfx), "tenant_id", lit(f.b.id), "instance_id", lit(f.b.instance),
				"requested_by_membership_id", lit(f.b.membership), "target_membership_id", lit(f.b.membership)).insert("enrollment_requests"), ""},
		// the device link (0020): composite, and a linked request is never deleted (§6.4)
		{"device link: A's device to B's request", "UPDATE device_inventory_cache SET enrollment_request_id = " + lit(f.b.enrollment) +
			" WHERE id = " + lit(a.device), "23503"},
		{"device link: deleting a linked request", "DELETE FROM enrollment_requests WHERE id = " + lit(a.enrollment), "23503"},
		{"device link: deleting it once unlinked", "UPDATE device_inventory_cache SET enrollment_request_id = NULL WHERE id = " + lit(a.device) +
			"; DELETE FROM enrollment_requests WHERE id = " + lit(a.enrollment), ""},
		// groups / group_members
		{"group: valid", group.insert("groups"), ""},
		{"group: valid IdP-synced", group.with("source", "'idp'").insert("groups"), ""},
		{"group: name in capitals", group.with("name", "'Ops'").insert("groups"), "23514"},
		{"group: name with a space", group.with("name", "'ops team'").insert("groups"), "23514"},
		{"group: name with the policy prefix", group.with("name", "'group:ops'").insert("groups"), "23514"},
		{"group: name of 51 characters", group.with("name", "'a'||repeat('b', 50)").insert("groups"), "23514"},
		{"group: unknown source", group.with("source", "'ldap'").insert("groups"), "23514"},
		{"group: name of A's group twice", group.with("name", "'eng'").insert("groups"), "23505"},
		{"group member: same member twice", "INSERT INTO group_members (tenant_id, group_id, membership_id) VALUES (" + A + ", " +
			lit(a.group) + ", " + lit(a.membership) + ")", "23505"},
		{"group member: membership deleted while in a group", "INSERT INTO group_members (tenant_id, group_id, membership_id) VALUES (" + A +
			", " + lit(a.group) + ", " + lit(p.viewer) + "); DELETE FROM tenant_memberships WHERE id = " + lit(p.viewer), "23503"},
		{"group: deleting a group that owns a resource", "DELETE FROM groups WHERE id = " + lit(a.group), "23503"},
		{"group: deleting a group drops its members", "DELETE FROM network_resources WHERE owner_group_id = " + lit(a.group) +
			"; DELETE FROM groups WHERE id = " + lit(a.group) + "; DO $$ BEGIN IF EXISTS (SELECT 1 FROM group_members WHERE group_id = " +
			lit(a.group) + ") THEN RAISE EXCEPTION 'members left' USING ERRCODE = 'P0001'; END IF; END $$", ""},
		// tenant_tags
		{"tag: valid", tag.insert("tenant_tags"), ""},
		{"tag: valid platform-managed router", tag.with("name", "'tag:router'", "purpose", "'router'", "platform_managed", "true").insert("tenant_tags"), ""},
		{"tag: name without prefix", tag.with("name", "'check'").insert("tenant_tags"), "23514"},
		{"tag: name in capitals", tag.with("name", "'tag:Check'").insert("tenant_tags"), "23514"},
		{"tag: name starting with a dash", tag.with("name", "'tag:-x'").insert("tenant_tags"), "23514"},
		{"tag: name of 51 characters", tag.with("name", "'tag:a'||repeat('b', 50)").insert("tenant_tags"), "23514"},
		{"tag: unknown purpose", tag.with("purpose", "'admin'").insert("tenant_tags"), "23514"},
		{"tag: name of A's tag twice", tag.with("name", "'tag:server'").insert("tenant_tags"), "23505"},
		// network_resources
		{"resource: valid host", res.insert("network_resources"), ""},
		{"resource: valid IPv6 host", res.with("address", "'2001:db8::1/128'").insert("network_resources"), ""},
		{"resource: valid subnet", res.with("kind", "'subnet'", "address", "'10.1.0.0/16'").insert("network_resources"), ""},
		{"resource: valid service", res.with("kind", "'service'", "ports", "'{443,8000-8100}'", "protocol", "'tcp'", "tags", "'{tag:server}'").insert("network_resources"), ""},
		{"resource: valid ports for any protocol", res.with("ports", "'{53}'").insert("network_resources"), ""},
		{"resource: valid ICMP host", res.with("protocol", "'icmp'").insert("network_resources"), ""},
		{"resource: unknown kind", res.with("kind", "'url'").insert("network_resources"), "23514"},
		{"resource: subnet of one address", res.with("kind", "'subnet'").insert("network_resources"), "23514"},
		{"resource: host of a prefix", res.with("address", "'10.0.0.0/24'").insert("network_resources"), "23514"},
		{"resource: the whole Internet", res.with("kind", "'subnet'", "address", "'0.0.0.0/0'").insert("network_resources"), "23514"},
		{"resource: the whole IPv6 Internet", res.with("kind", "'subnet'", "address", "'::/0'").insert("network_resources"), "23514"},
		{"resource: service without ports", res.with("kind", "'service'").insert("network_resources"), "23514"},
		{"resource: ports with ICMP", res.with("ports", "'{443}'", "protocol", "'icmp'").insert("network_resources"), "23514"},
		{"resource: unknown protocol", res.with("protocol", "'sctp'").insert("network_resources"), "23514"},
		{"resource: port with protocol suffix", res.with("ports", "'{443/tcp}'").insert("network_resources"), "23514"},
		{"resource: port wildcard", res.with("ports", "'{*}'").insert("network_resources"), "23514"},
		{"resource: NULL port", res.with("ports", "ARRAY['443', NULL]").insert("network_resources"), "23514"},
		{"resource: tag without prefix", res.with("tags", "'{server}'").insert("network_resources"), "23514"},
		{"resource: name in capitals", res.with("name", "'DB'").insert("network_resources"), "23514"},
		{"resource: name with a dot", res.with("name", "'db.internal'").insert("network_resources"), "23514"},
		{"resource: name of A's resource twice", res.with("name", "'db'").insert("network_resources"), "23505"},
		{"resource: owner group of B", res.with("owner_group_id", lit(f.b.group)).insert("network_resources"), "23503"},
		// dns_records
		{"record: valid A", rec.insert("dns_records"), ""},
		{"record: valid AAAA", rec.with("type", "'AAAA'", "value", "'fd7a:115c:a1e0::9'").insert("dns_records"), ""},
		{"record: valid second address of a name", rec.with("value", "'100.64.0.10'").insert("dns_records") + "; " + rec.insert("dns_records"), ""},
		{"record: CNAME", rec.with("type", "'CNAME'").insert("dns_records"), "23514"},
		{"record: A with IPv6", rec.with("value", "'fd7a:115c:a1e0::9'").insert("dns_records"), "23514"},
		{"record: AAAA with IPv4", rec.with("type", "'AAAA'").insert("dns_records"), "23514"},
		{"record: A of a network", rec.with("value", "'100.64.0.0/24'").insert("dns_records"), "23514"},
		{"record: single label", rec.with("name", "'svc'").insert("dns_records"), "23514"},
		{"record: name in capitals", rec.with("name", "'Svc.example.test'").insert("dns_records"), "23514"},
		{"record: wildcard", rec.with("name", "'*.example.test'").insert("dns_records"), "23514"},
		{"record: trailing dot", rec.with("name", "'svc.example.test.'").insert("dns_records"), "23514"},
		{"record: label starting with a dash", rec.with("name", "'-svc.example.test'").insert("dns_records"), "23514"},
		{"record: label of 64 characters", rec.with("name", "repeat('a', 64)||'.example.test'").insert("dns_records"), "23514"},
		{"record: name of 254 characters", rec.with("name", "repeat(repeat('a', 62)||'.', 4)||'example'").insert("dns_records"), "23514"},
		{"record: A's record twice", "INSERT INTO dns_records (tenant_id, name, type, value) VALUES (" + A + ", 'db." + f.a.slug +
			".ts.test', 'A', '100.64.0.5')", "23505"},
		// support_access_grants (constraints; the decision rules are TestSupportGrantDecisions)
		{"grant: valid pending", grant.insert("support_access_grants"), ""},
		{"grant: valid 8-hour window", grant.with("starts_at", "now() + interval '1 hour'", "expires_at", "now() + interval '9 hours'").insert("support_access_grants"), ""},
		{"grant: created approved (trigger)", grant.with("status", "'approved'", "approval_kind", "'tenant'", "approved_by_membership_id",
			lit(p.owner), "decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: window of 8 hours and 1 second", grant.with("expires_at", "now() + interval '8 hours 1 second'").insert("support_access_grants"), "23514"},
		{"grant: window ends before it starts", grant.with("expires_at", "now() - interval '1 minute'").insert("support_access_grants"), "23514"},
		{"grant: empty reason", grant.with("reason", "''").insert("support_access_grants"), "23514"},
		{"grant: empty ticket", grant.with("ticket_ref", "''").insert("support_access_grants"), "23514"},
		{"grant: unknown status", noGuard + grant.with("status", "'active'").insert("support_access_grants"), "23514"},
		{"grant: tenant role as effective role", grant.with("effective_role_scope", "'tenant'", "effective_role_key", "'tenant_owner'").insert("support_access_grants"), "23514"},
		{"grant: unknown support role", grant.with("effective_role_key", "'support_nobody'").insert("support_access_grants"), "23503"},
		{"grant: unknown grantee", grant.with("grantee_platform_user_id", "gen_random_uuid()").insert("support_access_grants"), "23503"},
		{"grant: pending with revoked_at", grant.with("revoked_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: revoked without revoked_at", noGuard + grant.with("status", "'revoked'").insert("support_access_grants"), "23514"},
		{"grant: approved without kind", noGuard + grant.with("status", "'approved'").insert("support_access_grants"), "23514"},
		{"grant: decided_at without kind", noGuard + grant.with("status", "'expired'", "decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: tenant kind without membership", noGuard + grant.with("status", "'approved'", "approval_kind", "'tenant'",
			"decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: tenant kind with a platform approver", noGuard + grant.with("status", "'approved'", "approval_kind", "'tenant'",
			"approved_by_membership_id", lit(p.owner), "approved_by_platform_user_id", lit(p.sa1), "decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: break-glass with a membership", noGuard + grant.with("status", "'approved'", "approval_kind", "'breakglass'",
			"approved_by_membership_id", lit(p.owner), "decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: break-glass rejection", noGuard + grant.with("status", "'rejected'", "approval_kind", "'breakglass'",
			"approved_by_platform_user_id", lit(p.sa1), "decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: break-glass approved by its requester", noGuard + grant.with("status", "'approved'", "approval_kind", "'breakglass'",
			"approved_by_platform_user_id", lit(f.platformUserRow), "grantee_platform_user_id", lit(p.support), "decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: break-glass approved by its grantee", noGuard + grant.with("status", "'approved'", "approval_kind", "'breakglass'",
			"approved_by_platform_user_id", lit(f.platformUserRow), "requested_by_platform_user_id", lit(p.sa1), "decided_at", "now()").insert("support_access_grants"), "23514"},
		{"grant: tenant approval by B's membership (FK)", noGuard + grant.with("status", "'approved'", "approval_kind", "'tenant'",
			"approved_by_membership_id", lit(p.bOwner), "decided_at", "now()").insert("support_access_grants"), "23503"},
		// identity_links
		{"link: valid (A's old identity → its identity on the new IdP)", relink + link.insert("identity_links"), ""},
		{"link: identity linked to itself", relink + link.with("new_identity_id", lit(a.identity), "new_idp_id", lit(a.idp)).insert("identity_links"), "23514"},
		{"link: same IdP on both sides", relink + link.with("new_identity_id", lit(p4Identity(t, su, p.owner)), "new_idp_id", lit(a.idp)).insert("identity_links"), "23514"},
		{"link: new identity of B", relink + link.with("new_identity_id", lit(f.b.identity), "new_idp_id", lit(f.b.idp)).insert("identity_links"), "23503"},
		{"link: IdP that is not the identity's", relink + link.with("old_idp_id", lit(a.oldIdP), "new_idp_id", lit(a.idp)).insert("identity_links"), "23503"},
		{"link: old identity linked twice", link.with("old_identity_id", lit(a.oldIdentity), "old_idp_id", lit(a.oldIdP),
			"new_identity_id", lit(p4Identity(t, su, p.viewer)), "new_idp_id", lit(a.idp)).insert("identity_links"), "23505"},
	}
	for _, c := range cases {
		tx, err := su.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, c.sql) // no arguments ⇒ simple protocol: "a; b" runs both statements
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

// p4Identity returns the identity of a membership.
func p4Identity(t *testing.T, su *pgx.Conn, membership uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := su.QueryRow(ctxT(t), `SELECT identity_id FROM tenant_memberships WHERE id = $1`, membership).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestTenantTagsPlatformManaged: a tag created by the platform (platform_managed) is read by the tenant pools but the api
// tenant pool cannot create, edit or delete one (RESTRICTIVE policies — UPDATE/DELETE see no such row, INSERT fails the
// WITH CHECK); the same statements on an ordinary tag succeed.
func TestTenantTagsPlatformManaged(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	managed := newID()
	exec(t, su, `INSERT INTO tenant_tags (id, tenant_id, name, purpose, platform_managed) VALUES ($1, $2, 'tag:router', 'router', true)`,
		managed, f.a.id)
	api := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	A := f.a.id
	for _, c := range []struct {
		name string
		s    *Store
		sql  string
		want string
		rows int64
	}{
		{"api tenant reads the managed tag", api, `SELECT 1 FROM tenant_tags WHERE id = '` + managed.String() + `'`, "", 1},
		{"worker tenant reads the managed tag", worker, `SELECT 1 FROM tenant_tags WHERE id = '` + managed.String() + `'`, "", 1},
		{"api tenant edits the managed tag", api, `UPDATE tenant_tags SET description = 'x' WHERE id = '` + managed.String() + `'`, "", 0},
		{"api tenant deletes the managed tag", api, `DELETE FROM tenant_tags WHERE id = '` + managed.String() + `'`, "", 0},
		{"api tenant creates a managed tag", api, `INSERT INTO tenant_tags (tenant_id, name, purpose, platform_managed)
			VALUES ('` + A.String() + `', 'tag:exit', 'exit', true)`, privilegeErr, 0},
		{"api tenant creates an ordinary tag", api, `INSERT INTO tenant_tags (tenant_id, name) VALUES ('` + A.String() + `', 'tag:mine')`, "", 1},
		{"api tenant edits an ordinary tag", api, `UPDATE tenant_tags SET description = 'x' WHERE id = '` + f.a.tag.String() + `'`, "", 1},
		{"api tenant deletes an ordinary tag", api, `DELETE FROM tenant_tags WHERE name = 'tag:mine'`, "", 1},
	} {
		n, err := execIn(ctx, c.s, A, c.sql)
		if c.want != "" {
			wantSQLState(t, c.name, err, c.want)
			continue
		}
		if err != nil || n != c.rows {
			t.Errorf("%s: %d rows, %v; want %d rows", c.name, n, err, c.rows)
		}
	}
	var still int64
	if err := su.QueryRow(ctx, `SELECT count(*) FROM tenant_tags WHERE id = $1 AND description IS NULL`, managed).Scan(&still); err != nil || still != 1 {
		t.Errorf("managed tag after the api attempts: %d unchanged rows (%v), want 1", still, err)
	}
}

// TestSupportGrantDecisions — the decision rules of §8.7 enforced by the trigger of 0023, through the application roles:
// a tenant approval (api tenant pool) needs an active membership of that tenant whose role holds
// tenant.support_grant:decide (seeded tenant_owner: yes; tenant_viewer, the fixture role, a locked membership or a
// disabled identity: 42501); a break-glass approval (api platform pool) needs two different active Super Admins as
// requester and approver (42501 otherwise, also when approver = requester; approver = grantee: 23514); each pool can only record its own kind
// of decider (column privileges); once decided, the decision and the window are frozen, terminal states stay terminal,
// a revocation or expiry carries no decision, and an already-ended window cannot be approved (23514).
func TestSupportGrantDecisions(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	p := newP4People(t, su, f)
	api := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	A, platform := f.a.id, uuid.Nil
	// newGrant inserts a pending grant into tenant A (superuser) and returns its id.
	newGrant := func(requester, grantee uuid.UUID, window string) uuid.UUID {
		id := newID()
		if window == "" {
			window = "now(), now() + interval '2 hours'"
		}
		exec(t, su, `INSERT INTO support_access_grants (id, tenant_id, grantee_platform_user_id, requested_by_platform_user_id,
				effective_role_key, reason, ticket_ref, starts_at, expires_at)
			VALUES ($1, $2, $3, $4, 'support_operator', 'decision test', 'T-3', `+window+`)`, id, A, grantee, requester)
		return id
	}
	tenantDecision := func(status string, m uuid.UUID) string {
		return fmt.Sprintf(`UPDATE support_access_grants SET status = '%s', approval_kind = 'tenant', approved_by_membership_id = '%s',
			decided_at = now(), version = version + 1 WHERE id = $1`, status, m)
	}
	breakglass := func(approver uuid.UUID) string {
		return fmt.Sprintf(`UPDATE support_access_grants SET status = 'approved', approval_kind = 'breakglass',
			approved_by_platform_user_id = '%s', decided_at = now(), version = version + 1 WHERE id = $1`, approver)
	}
	const (
		revoke = `UPDATE support_access_grants SET status = 'revoked', revoked_at = now() WHERE id = $1`
		expire = `UPDATE support_access_grants SET status = 'expired' WHERE id = $1`
		extend = `UPDATE support_access_grants SET expires_at = expires_at + interval '1 hour' WHERE id = $1`
		reopen = `UPDATE support_access_grants SET status = 'pending', approval_kind = NULL, approved_by_platform_user_id = NULL,
			decided_at = NULL WHERE id = $1`
		approve = `UPDATE support_access_grants SET status = 'approved' WHERE id = $1`
	)
	approved := newGrant(f.platformUserRow, f.platformUserRow, "")
	rejected := newGrant(f.platformUserRow, f.platformUserRow, "")
	glass := newGrant(p.sa1, p.support, "")
	revoked := newGrant(f.platformUserRow, f.platformUserRow, "")
	expired := newGrant(f.platformUserRow, f.platformUserRow, "")
	fresh := func() uuid.UUID { return newGrant(f.platformUserRow, f.platformUserRow, "") }
	cases := []struct {
		name  string
		s     *Store
		scope uuid.UUID
		sql   string
		id    uuid.UUID
		want  string // SQLSTATE, "" = exactly one row updated
	}{
		// tenant approvals (api tenant pool)
		{"owner approves", api, A, tenantDecision("approved", p.owner), approved, ""},
		{"owner approves (revoked below)", api, A, tenantDecision("approved", p.owner), revoked, ""},
		{"owner approves (expired below)", api, A, tenantDecision("approved", p.owner), expired, ""},
		{"owner rejects", api, A, tenantDecision("rejected", p.owner), rejected, ""},
		{"viewer approves", api, A, tenantDecision("approved", p.viewer), fresh(), privilegeErr},
		{"fixture role (no decide) approves", api, A, tenantDecision("approved", f.a.membership), fresh(), privilegeErr},
		{"locked owner approves", api, A, tenantDecision("approved", p.lockedOwner), fresh(), privilegeErr},
		{"owner with a disabled identity approves", api, A, tenantDecision("approved", p.disabledOwner), fresh(), privilegeErr},
		{"viewer rejects", api, A, tenantDecision("rejected", p.viewer), fresh(), privilegeErr},
		{"platform pool records a tenant approval", api, platform, tenantDecision("approved", p.owner), fresh(), privilegeErr},
		{"tenant pool records a break-glass approval", api, A, breakglass(p.sa2), fresh(), privilegeErr},
		{"worker tenant pool approves", worker, A, tenantDecision("approved", p.owner), fresh(), privilegeErr},
		{"approval of an ended window", api, A, tenantDecision("approved", p.owner),
			newGrant(f.platformUserRow, f.platformUserRow, "now() - interval '2 hours', now() - interval '1 hour'"), "23514"},
		// break-glass (api platform pool)
		{"second Super Admin approves break-glass", api, platform, breakglass(p.sa2), glass, ""},
		{"break-glass requested by Platform Support", api, platform, breakglass(p.sa1), newGrant(p.support, p.support, ""), privilegeErr},
		{"break-glass approved by Platform Support", api, platform, breakglass(p.support), newGrant(p.sa1, p.sa1, ""), privilegeErr},
		{"break-glass approved by the fixture's platform user", api, platform, breakglass(f.platformUserRow), newGrant(p.sa1, p.support, ""), privilegeErr},
		// approver = requester: one Super Admin, not two (the CHECK approver ≠ requester is TestP4CheckConstraints)
		{"break-glass approved by its requester", api, platform, breakglass(p.sa1), newGrant(p.sa1, p.support, ""), privilegeErr},
		{"break-glass approved by its grantee", api, platform, breakglass(p.sa2), newGrant(p.sa1, p.sa2, ""), "23514"},
		// after the decision
		{"decision frozen: window extended", api, A, extend, approved, "23514"},
		{"decision frozen: approver changed", api, A, tenantDecision("approved", p.owner), approved, "23514"},
		{"approved back to pending", api, platform, reopen, glass, "23514"},
		{"rejected then approved", api, A, approve, rejected, "23514"},
		{"tenant revokes an approved grant", api, A, revoke, revoked, ""},
		{"revoked then approved", api, A, approve, revoked, "23514"},
		{"revoked then expired", worker, platform, expire, revoked, "23514"},
		{"worker expires an approved grant", worker, platform, expire, expired, ""},
		{"tenant revokes the break-glass grant", api, A, revoke, glass, ""},
		{"expired then revoked", api, A, revoke, expired, "23514"},
		{"pending revoked with a decision", api, A, `UPDATE support_access_grants SET status = 'revoked', revoked_at = now(),
			approval_kind = 'tenant', approved_by_membership_id = '` + p.owner.String() + `', decided_at = now() WHERE id = $1`, fresh(), "23514"},
		{"pending window adjusted before the decision", api, A, extend, fresh(), ""},
		{"requester withdraws a pending grant", api, platform, revoke, fresh(), ""},
	}
	for _, c := range cases {
		n, err := execIn(ctx, c.s, c.scope, c.sql, c.id)
		if c.want == "" {
			if err != nil || n != 1 {
				t.Errorf("%s: %d rows, err %v; want 1 row", c.name, n, err)
			}
			continue
		}
		wantSQLState(t, c.name, err, c.want)
	}
	// the outcome as the tenant sees it (transparency — §8.7)
	var states []string
	if err := api.tenantTx(ctx, A, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT status || '/' || COALESCE(approval_kind, '-') FROM support_access_grants WHERE id IN ($1, $2, $3, $4, $5)`,
			approved, rejected, glass, revoked, expired)
		if err != nil {
			return err
		}
		states, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(states)
	if want := []string{"approved/tenant", "expired/tenant", "rejected/tenant", "revoked/breakglass", "revoked/tenant"}; !slices.Equal(states, want) {
		t.Errorf("grants as tenant A sees them: %v, want %v", states, want)
	}
}
