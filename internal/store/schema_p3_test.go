package store

// Migrations 0009–0013 (P3-T06, §6.3): approval_requests, tenant_invitations, notification_outbox (0009), relay_regions,
// relay_assignments (0010), backups (0011), subscription_plans, subscriptions + quota.max_tenants (0012), policy_versions,
// policy_applications + FK tenants.desired_policy_version_id (0013), and the minimal plan of database/seeds/plans.sql.
// The generic tests of rls_test.go (RLS classes, unset GUC, tenant/platform scope, read-only role, catalog) cover the new
// tables through rlsTables and the fixture steps 9–13; the tests here cover what is specific to them: up on a database
// holding data of schema 8 (staging), cross-tenant writes (WITH CHECK, composite FK), the grant matrix, the CHECK
// constraints and the seed.

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// p3Tables are the tables created by 0009–0013, in migration order.
var p3Tables = []string{"approval_requests", "tenant_invitations", "notification_outbox", "relay_regions", "relay_assignments",
	"backups", "subscription_plans", "subscriptions", "policy_versions", "policy_applications"}

// TestLatestMigrationIs13: the embedded migrations end at 0013 (latestMigration of the fixture) — the version
// `meshguard-api migrate status` reports as latest_migration (current = schema_version == latest_migration,
// ReadDeployState) — and the fixture has a step for every migration.
func TestLatestMigrationIs13(t *testing.T) {
	v, err := LatestMigration()
	if err != nil || v != latestMigration {
		t.Fatalf("LatestMigration() = %d (%v), want latestMigration = %d", v, err, latestMigration)
	}
	for i := int64(1); i <= latestMigration; i++ {
		if fixtureSteps[i] == nil {
			t.Errorf("no fixture step for migration %04d", i)
		}
	}
}

// publicRowCounts counts the rows of every table of schema public (superuser: no RLS).
func publicRowCounts(t *testing.T, su *pgx.Conn) map[string]int64 {
	t.Helper()
	rows, err := su.Query(ctxT(t), `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, n := range names {
		var c int64
		if err := su.QueryRow(ctxT(t), "SELECT count(*) FROM "+q(n)).Scan(&c); err != nil {
			t.Fatal(err)
		}
		out[n] = c
	}
	return out
}

// TestMigrations0009To0013OnSchema8Data — the verification of P3-T06 "up trên bản sao có dữ liệu": a database at schema 8
// holding rows of every table of 0001–0008 (the state of staging) and an owner-tuned tenant cap migrates 0009 → 0013 one
// step at a time; every existing row survives, the new tables start empty, tenants keep desired_policy_version_id NULL,
// the tuned cap is not overwritten; the seed then adds the plan `standard`, a second run changes nothing, the new tables
// take data, the application reads old and new rows through RLS, and no partition carries a privilege.
func TestMigrations0009To0013OnSchema8Data(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 8)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	f := newFixture()
	for v := int64(1); v <= 8; v++ {
		fixtureSteps[v](f, t, su)
	}
	exec(t, su, `INSERT INTO system_settings (key, value) VALUES ('quota.max_tenants', '25')`) // tuned before 0012 ran
	before := publicRowCounts(t, su)
	for _, n := range p3Tables {
		if _, ok := before[n]; ok {
			t.Fatalf("%s exists at schema 8", n)
		}
	}
	for v := int64(9); v <= 13; v++ {
		if err := MigrateTo(ctx, mig, v); err != nil {
			t.Fatalf("migration %04d on a database of schema %d with data: %v", v, v-1, err)
		}
		if got, err := SchemaVersion(ctx, mig); err != nil || got != v {
			t.Fatalf("schema version = %d (%v), want %d", got, err, v)
		}
	}
	after := publicRowCounts(t, su)
	if got := after["goose_db_version"] - before["goose_db_version"]; got != 5 {
		t.Errorf("goose_db_version: %d new rows, want 5 (0009–0013)", got)
	}
	delete(before, "goose_db_version")
	for n, c := range before {
		if after[n] != c {
			t.Errorf("%s: %d rows at schema 8, %d at schema 13", n, c, after[n])
		}
	}
	for _, n := range p3Tables {
		if c, ok := after[n]; !ok || c != 0 {
			t.Errorf("%s at schema 13: present=%v, %d rows; want an empty table", n, ok, c)
		}
	}
	var desired int64
	var tenantCap string
	if err := su.QueryRow(ctx, `SELECT (SELECT count(desired_policy_version_id) FROM tenants),
			(SELECT value::text FROM system_settings WHERE key = 'quota.max_tenants')`).Scan(&desired, &tenantCap); err != nil {
		t.Fatal(err)
	}
	if desired != 0 || tenantCap != "25" {
		t.Errorf("after 0013: %d tenants with a desired policy (want 0), quota.max_tenants = %s (want the tuned 25)", desired, tenantCap)
	}

	// store.Migrate: nothing pending, then the seeds — the plan `standard`; a second run is a no-op.
	for i := range 2 {
		if err := Migrate(ctx, mig); err != nil {
			t.Fatalf("Migrate #%d: %v", i+1, err)
		}
		var plans int64
		if err := su.QueryRow(ctx, `SELECT count(*) FROM subscription_plans WHERE key = 'standard'`).Scan(&plans); err != nil || plans != 1 {
			t.Fatalf("Migrate #%d: %d plans `standard` (%v), want 1", i+1, plans, err)
		}
	}

	for v := int64(9); v <= 13; v++ { // data of the new tables, written after the migration
		fixtureSteps[v](f, t, su)
	}
	s := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	var slug string
	var policies, applications, invitations int64
	if err := s.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT slug::text FROM tenants WHERE id = $1), (SELECT count(*) FROM policy_versions),
				(SELECT count(*) FROM policy_applications), (SELECT count(*) FROM tenant_invitations)`, f.a.id).
			Scan(&slug, &policies, &applications, &invitations)
	}); err != nil {
		t.Fatal(err)
	}
	if slug != f.a.slug || policies != 1 || applications != 1 || invitations != 1 {
		t.Errorf("worker tenant pool, tenant A: slug %q, %d policy versions, %d applications, %d invitations; want %q, 1, 1, 1",
			slug, policies, applications, invitations, f.a.slug)
	}
	if v, err := PartitionGrantViolations(ctx, su); err != nil || len(v) != 0 {
		t.Errorf("partition grant violations at schema 13: %v (%v)", v, err)
	}
}

// execIn runs one statement in a transaction of s scoped like WithTenantTx(tenant) — or WithPlatformTx when tenant is
// uuid.Nil — and returns the rows it affected. The transaction commits only when the statement succeeds.
func execIn(ctx context.Context, s *Store, tenant uuid.UUID, sql string, args ...any) (int64, error) {
	var n int64
	run := func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		n = tag.RowsAffected()
		return err
	}
	if tenant == uuid.Nil {
		return n, s.platformTx(ctx, run)
	}
	return n, s.tenantTx(ctx, tenant, run)
}

// extraIdentities adds, as superuser, a second identity of tenant A on A's IdP, an identity of tenant A on a second
// (retiring) IdP of A, and a second platform identity — what the 2P and invitation checks need beyond the fixture.
type extraIdentities struct{ a2, aOtherIdP, platform2 uuid.UUID }

func newExtraIdentities(t *testing.T, su *pgx.Conn, f *fixture) extraIdentities {
	t.Helper()
	x := extraIdentities{a2: newID(), aOtherIdP: newID(), platform2: newID()}
	otherIdP := newID()
	exec(t, su, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email)
		VALUES ($1, $2, $3, 'tenant', 'user2-'||$4, 'user2@'||$4||'.test')`, x.a2, f.a.idp, f.a.id, f.a.slug)
	exec(t, su, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, 'https://idp.test/realms/old-'||$3, 'portal', 'keycloak', 'retiring')`, otherIdP, f.a.id, f.a.slug)
	exec(t, su, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email)
		VALUES ($1, $2, $3, 'tenant', 'user-'||$4, 'user@'||$4||'.test')`, x.aOtherIdP, otherIdP, f.a.id, f.a.slug)
	exec(t, su, `INSERT INTO identities (id, idp_id, scope, subject, email) VALUES ($1, $2, 'platform', 'po-'||$3, 'po@example.test')`,
		x.platform2, f.platformIdP, f.sfx)
	return x
}

// TestP3CrossTenantWritesRejected is IT-03 (write side) for 0009–0013, through the application roles: inside tenant A's
// transaction a row of tenant B violates the WITH CHECK policy (or the role holds no INSERT at all); a row of A that
// references an object of B — identity, IdP, membership, instance, relay region, job, policy version — violates the
// composite foreign key; an identity of the wrong scope or of another IdP of A is refused by the (id, scope) and
// (id, idp_id) keys; B's rows are invisible to UPDATE; the platform pool cannot touch the tenant-internal tables.
// Positive controls show the same statements succeed on A's own objects.
func TestP3CrossTenantWritesRejected(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	x := newExtraIdentities(t, su, f)
	api := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	const (
		insApproval = `INSERT INTO approval_requests (scope, tenant_id, action, resource_type, payload, payload_sha256,
			requested_by_identity_id, expires_at) VALUES ($1, $2, 'tenant.settings.disable_four_eyes', 'tenant_settings', '{}',
			repeat('a', 64), $3, now() + interval '1 hour')`
		insInvitation = `INSERT INTO tenant_invitations (tenant_id, idp_id, email, role_id, token_hash, expires_at)
			VALUES ($1, $2, 'cross-'||$4||'@example.test', $3, sha256(convert_to($4, 'UTF8')), now() + interval '1 day')`
		insNotification = `INSERT INTO notification_outbox (tenant_id, recipient_membership_id, kind) VALUES ($1, $2, 'device.new')`
		insPolicy       = `INSERT INTO policy_versions (tenant_id, version, source, content_sha256, parent_version_id)
			VALUES ($1, $2, '{"grants": []}', repeat('e', 64), $3)`
		insApplication = `INSERT INTO policy_applications (tenant_id, instance_id, policy_version_id, trigger, applied_hujson, applied_sha256)
			VALUES ($1, $2, $3, 'manual', $4, $5)`
		insAssignment = `INSERT INTO relay_assignments (tenant_id, instance_id, relay_region_id, priority) VALUES ($1, $2, $3, 9)`
		insBackup     = `INSERT INTO backups (tenant_id, instance_id, kind, storage_uri, key_ref, headscale_version, job_id)
			VALUES ($1, $2, 'instance', 'file:///opt/meshguard/backups/x.age', 'mgsec://'||$4||'/backup-key#1', '0.29.7', $3)`
	)
	tok := func() string { return "tok-" + randomHex(8) }
	ver := func() int64 { return 100 + randInt(1<<30) }
	hj := `{"grants": []}`
	A, B, platform := f.a.id, f.b.id, uuid.Nil
	cases := []struct {
		name   string
		s      *Store
		scope  uuid.UUID
		sql    string
		args   []any
		want   string // SQLSTATE, "" = must succeed
		rows   int64  // rows affected when want == ""
		update bool   // check rows (UPDATE statements)
	}{
		// WITH CHECK of the tenant policy (or no INSERT privilege at all): a row of B written in A's scope
		{"approval of B in A's scope", api, A, insApproval, []any{"tenant", B, f.b.identity}, privilegeErr, 0, false},
		{"invitation of B in A's scope", api, A, insInvitation, []any{B, f.b.idp, f.tenantRole, tok()}, privilegeErr, 0, false},
		{"notification of B in A's scope", api, A, insNotification, []any{B, f.b.membership}, privilegeErr, 0, false},
		{"policy version of B in A's scope", worker, A, insPolicy, []any{B, ver(), nil}, privilegeErr, 0, false},
		{"policy application of B in A's scope", worker, A, insApplication, []any{B, f.b.instance, f.b.policy, hj, sha256Hex(hj)}, privilegeErr, 0, false},
		{"tenant pool inserts a relay assignment", worker, A, insAssignment, []any{A, f.a.instance, f.a.region}, privilegeErr, 0, false},
		{"tenant api inserts a backup", api, A, insBackup, []any{A, f.a.instance, f.a.job, A.String()}, privilegeErr, 0, false},
		{"tenant api inserts a subscription", api, A, `INSERT INTO subscriptions (tenant_id, plan_id, status) VALUES ($1, $2, 'cancelled')`,
			[]any{A, f.plan}, privilegeErr, 0, false},
		// composite foreign keys: a row of A referencing an object of B
		{"approval of A requested by B's identity", api, A, insApproval, []any{"tenant", A, f.b.identity}, "23503", 0, false},
		{"approval of A approved by B's identity", api, platform, `UPDATE approval_requests SET status = 'approved',
			approved_by_identity_id = $1, decided_at = now() WHERE id = $2`, []any{f.b.identity, f.a.approval}, "23503", 0, false},
		{"approval of A approved by a platform identity", api, platform, `UPDATE approval_requests SET status = 'approved',
			approved_by_identity_id = $1, decided_at = now() WHERE id = $2`, []any{x.platform2, f.a.approval}, "23503", 0, false},
		{"platform approval requested by a tenant identity", api, platform, insApproval, []any{"platform", nil, f.a.identity}, "23503", 0, false},
		{"platform approval approved by a tenant identity", api, platform, `UPDATE approval_requests SET status = 'approved',
			approved_by_identity_id = $1, decided_at = now() WHERE id = $2`, []any{f.a.identity, f.platformApproval}, "23503", 0, false},
		{"invitation of A on B's IdP", api, A, insInvitation, []any{A, f.b.idp, f.tenantRole, tok()}, "23503", 0, false},
		{"invitation of A with a platform role", api, A, insInvitation, []any{A, f.a.idp, f.platformRole, tok()}, "23503", 0, false},
		{"invitation of A accepted by B's identity", api, A, `UPDATE tenant_invitations SET status = 'accepted', accepted_identity_id = $1,
			accepted_at = now() WHERE id = $2`, []any{f.b.identity, f.a.invitation}, "23503", 0, false},
		{"invitation of A accepted by A's identity of another IdP", api, A, `UPDATE tenant_invitations SET status = 'accepted',
			accepted_identity_id = $1, accepted_at = now() WHERE id = $2`, []any{x.aOtherIdP, f.a.invitation}, "23503", 0, false},
		{"notification of A to B's membership", api, A, insNotification, []any{A, f.b.membership}, "23503", 0, false},
		{"policy version of A with B's parent", api, A, insPolicy, []any{A, ver(), f.b.policy}, "23503", 0, false},
		{"policy application of A with B's version", worker, A, insApplication, []any{A, f.a.instance, f.b.policy, hj, sha256Hex(hj)}, "23503", 0, false},
		{"policy application of A on B's instance", worker, A, insApplication, []any{A, f.b.instance, f.a.policy, hj, sha256Hex(hj)}, "23503", 0, false},
		{"desired policy of A = B's version", api, A, `UPDATE tenants SET desired_policy_version_id = $1 WHERE id = $2`,
			[]any{f.b.policy, A}, "23503", 0, false},
		{"relay assignment of A on B's instance", worker, platform, insAssignment, []any{A, f.b.instance, f.a.region}, "23503", 0, false},
		{"relay assignment of A to B's region", worker, platform, insAssignment, []any{A, f.a.instance, f.b.region}, "23503", 0, false},
		{"relay assignment of A to a shared region (MVP)", worker, platform, insAssignment, []any{A, f.a.instance, f.sharedRegion}, "23503", 0, false},
		{"backup of A of B's instance", worker, platform, insBackup, []any{A, f.b.instance, f.a.job, A.String()}, "23503", 0, false},
		{"backup of A linked to B's job", worker, platform, insBackup, []any{A, f.a.instance, f.b.job, A.String()}, "23503", 0, false},
		// RLS hides B's rows (and the platform rows) from A's scope: UPDATE affects nothing
		{"A updates B's invitation", api, A, `UPDATE tenant_invitations SET status = 'revoked' WHERE id = $1`, []any{f.b.invitation}, "", 0, true},
		{"A marks B's notification read", api, A, `UPDATE notification_outbox SET read_at = now() WHERE id = $1`, []any{f.b.notification}, "", 0, true},
		{"A rejects B's and the platform's approvals", api, A, `UPDATE approval_requests SET status = 'rejected', decided_at = now()
			WHERE id IN ($1, $2)`, []any{f.b.approval, f.platformApproval}, "", 0, true},
		{"A clears B's desired policy", api, A, `UPDATE tenants SET desired_policy_version_id = NULL WHERE id = $1`, []any{B}, "", 0, true},
		{"A supersedes B's application", worker, A, `UPDATE policy_applications SET superseded_at = now() WHERE id = $1`,
			[]any{f.b.application}, "", 0, true},
		// the platform pool has no privilege on the tenant-internal tables (T)
		{"platform pool reads policy versions", worker, platform, `SELECT 1 FROM policy_versions`, nil, privilegeErr, 0, false},
		{"platform pool reads policy applications", worker, platform, `SELECT 1 FROM policy_applications`, nil, privilegeErr, 0, false},
		{"platform pool reads invitations", api, platform, `SELECT 1 FROM tenant_invitations`, nil, privilegeErr, 0, false},
		// positive controls: the same statements on A's own objects
		{"approval of A by A's identity", api, A, insApproval, []any{"tenant", A, f.a.identity}, "", 1, true},
		{"approval of A approved by A's second identity", api, A, `UPDATE approval_requests SET status = 'approved',
			approved_by_identity_id = $1, decided_at = now() WHERE id = $2`, []any{x.a2, f.a.approval}, "", 1, true},
		{"platform approval approved by a second platform identity", api, platform, `UPDATE approval_requests SET status = 'approved',
			approved_by_identity_id = $1, decided_at = now() WHERE id = $2`, []any{x.platform2, f.platformApproval}, "", 1, true},
		{"invitation of A on A's IdP", api, A, insInvitation, []any{A, f.a.idp, f.tenantRole, tok()}, "", 1, true},
		{"invitation of A accepted by A's identity", api, A, `UPDATE tenant_invitations SET status = 'accepted', accepted_identity_id = $1,
			accepted_at = now() WHERE id = $2`, []any{f.a.identity, f.a.invitation}, "", 1, true},
		{"notification of A to A's membership", worker, A, insNotification, []any{A, f.a.membership}, "", 1, true},
		{"policy version of A with A's parent", api, A, insPolicy, []any{A, ver(), f.a.policy}, "", 1, true},
		{"desired policy of A = A's version", api, A, `UPDATE tenants SET desired_policy_version_id = $1 WHERE id = $2`,
			[]any{f.a.policy, A}, "", 1, true},
		{"backup of A of A's instance and job", worker, platform, insBackup, []any{A, f.a.instance, f.a.job, A.String()}, "", 1, true},
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

// grantSpec is the expected privilege set of one role on one table: table-level privileges, and the columns it may
// UPDATE when UPDATE is granted per column.
type grantSpec struct {
	table   []string
	columns []string
}

func cols(s string) []string { return strings.Split(s, ",") }

// TestP3GrantMatrix — least privilege (§6.1) of 0009–0013 read from the catalog: for every new table (and the column of
// tenants that 0013 opens to the tenant roles), exactly these privileges per role — no TRUNCATE, no table-level UPDATE,
// immutable columns without UPDATE, nothing for mg_audit_writer, mg_readonly, mg_partition_maint; mg_backup reads every
// table (pg_read_all_data). Then a few statements prove the matrix holds at execution time.
func TestP3GrantMatrix(t *testing.T) {
	e, db, f, su := fixtureDB(t)
	ctx := ctxT(t)
	roles := []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_audit_writer", "mg_readonly",
		"mg_partition_maint", "mg_backup"}
	S, SI, SID := []string{"SELECT"}, []string{"SELECT", "INSERT"}, []string{"SELECT", "INSERT", "DELETE"}
	backup := map[string]grantSpec{"mg_backup": {table: S}}
	with := func(m map[string]grantSpec) map[string]grantSpec {
		out := maps.Clone(m)
		maps.Copy(out, backup)
		return out
	}
	approvalDecide := cols("approved_by_identity_id,decided_at,job_id,status")
	backupUpdate := cols("expires_at,finished_at,sha256,size_bytes,status,verified_at")
	want := map[string]map[string]grantSpec{
		"approval_requests": with(map[string]grantSpec{
			"mg_api_tenant": {SI, approvalDecide}, "mg_api_platform": {SI, approvalDecide},
			"mg_worker_tenant": {S, nil}, "mg_worker_platform": {[]string{"SELECT", "DELETE"}, cols("status")},
		}),
		"tenant_invitations": with(map[string]grantSpec{
			"mg_api_tenant":    {SI, cols("accepted_at,accepted_identity_id,expires_at,status,token_hash,updated_at,version")},
			"mg_worker_tenant": {SID, cols("status,updated_at,version")},
		}),
		"notification_outbox": with(map[string]grantSpec{
			"mg_api_tenant": {SI, cols("read_at")}, "mg_worker_tenant": {SI, cols("attempts,sent_at,status")},
			"mg_api_platform": {SI, nil}, "mg_worker_platform": {SID, cols("attempts,sent_at,status")},
		}),
		"relay_regions": with(map[string]grantSpec{
			"mg_api_tenant": {S, nil}, "mg_worker_tenant": {S, nil}, "mg_api_platform": {S, nil},
			"mg_worker_platform": {SID, cols("derp_port,hostname,ipv4,ipv6,name,status,stun_port,updated_at,version")},
		}),
		"relay_assignments": with(map[string]grantSpec{
			"mg_api_tenant": {S, nil}, "mg_worker_tenant": {S, nil}, "mg_api_platform": {S, nil},
			"mg_worker_platform": {SID, cols("priority,status,updated_at")},
		}),
		"backups": with(map[string]grantSpec{
			"mg_worker_tenant": {SI, backupUpdate}, "mg_api_platform": {S, nil}, "mg_worker_platform": {SID, backupUpdate},
		}),
		"subscription_plans": with(map[string]grantSpec{
			"mg_api_tenant": {S, nil}, "mg_worker_tenant": {S, nil}, "mg_worker_platform": {S, nil},
			"mg_api_platform": {SI, cols("is_active,limits,name,updated_at,version")},
		}),
		"subscriptions": with(map[string]grantSpec{
			"mg_api_tenant": {S, cols("updated_at")}, "mg_worker_tenant": {S, cols("updated_at")},
			"mg_api_platform":    {SI, cols("overrides,period_end,period_start,plan_id,status,updated_at,version")},
			"mg_worker_platform": {S, cols("period_end,status,updated_at,version")},
		}),
		"policy_versions": with(map[string]grantSpec{
			"mg_api_tenant": {SI, cols("approved_at,approved_by,approved_content_sha256,content_sha256,rejected_at,rejected_by," +
				"rejected_reason,review_mode,revision,source,source_hujson,state,submitted_at,submitted_by,updated_at,validation_report")},
			"mg_worker_tenant": {SI, cols("revision,state,updated_at,validation_report")},
		}),
		"policy_applications": with(map[string]grantSpec{
			"mg_api_tenant": {S, nil}, "mg_worker_tenant": {SI, cols("error_code,finished_at,headscale_updated_at,state,superseded_at")},
		}),
		"tenants": with(map[string]grantSpec{
			"mg_api_tenant": {S, cols("desired_policy_version_id")}, "mg_worker_tenant": {S, cols("desired_policy_version_id")},
			"mg_api_platform":    {SI, cols("deleted_at,deployment_region,desired_policy_version_id,name,settings,status,updated_at,version")},
			"mg_worker_platform": {SI, cols("deleted_at,deployment_region,desired_policy_version_id,name,settings,status,updated_at,version")},
		}),
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
				AND has_column_privilege($1, $2::regclass, attnum, 'UPDATE') ORDER BY 1`, role, "public."+table)
			if err != nil {
				t.Fatal(err)
			}
			if got.columns, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
				t.Fatal(err)
			}
			w := byRole[role]
			sort.Strings(got.columns) // byte order, whatever the collation of the database
			if !slices.Equal(got.table, w.table) || !slices.Equal(got.columns, slices.Sorted(slices.Values(w.columns))) {
				t.Errorf("%s on %s: table %v, UPDATE columns %v; want %v, %v", role, table, got.table, got.columns, w.table, w.columns)
			}
		}
	}
	// The CHECK function of PlanLimits: EXECUTE only for the roles that write plans/subscriptions.
	for _, role := range roles {
		var ok bool
		if err := su.QueryRow(ctx, `SELECT has_function_privilege($1, 'mg_plan_limits_valid(jsonb, boolean)', 'EXECUTE')`, role).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if want := role == "mg_api_platform" || role == "mg_worker_platform"; ok != want {
			t.Errorf("%s EXECUTE on mg_plan_limits_valid = %v, want %v", role, ok, want)
		}
	}

	// At execution time.
	api := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	worker := e.openStore(t, db, "mg_worker_tenant", "mg_worker_platform", 2)
	A, platform := f.a.id, uuid.Nil
	denied := []struct {
		name  string
		s     *Store
		scope uuid.UUID
		sql   string
	}{
		{"api tenant rewrites an approval payload", api, A, `UPDATE approval_requests SET payload = '{"x": 1}' WHERE id = '` + f.a.approval.String() + `'`},
		{"api platform rewrites a payload hash", api, platform, `UPDATE approval_requests SET payload_sha256 = repeat('f', 64)`},
		{"api tenant updates its subscription", api, A, `UPDATE subscriptions SET updated_at = now()`},
		{"worker platform changes a plan of a subscription", worker, platform, `UPDATE subscriptions SET plan_id = plan_id`},
		{"api tenant renames its tenant", api, A, `UPDATE tenants SET name = 'x'`},
		{"worker tenant deletes policy versions", worker, A, `DELETE FROM policy_versions`},
		{"api tenant writes a policy application", api, A, `UPDATE policy_applications SET state = 'failed'`},
		{"api tenant reads backups", api, A, `SELECT 1 FROM backups`},
		{"api platform writes a relay region", api, platform, `UPDATE relay_regions SET status = 'disabled'`},
		{"api platform deletes a plan", api, platform, `DELETE FROM subscription_plans WHERE key = 'none'`},
		{"worker tenant truncates the outbox", worker, A, `TRUNCATE notification_outbox`},
	}
	for _, c := range denied {
		_, err := execIn(ctx, c.s, c.scope, c.sql)
		wantSQLState(t, c.name, err, privilegeErr)
	}
	// QuotaChecker's lock (§7.4 step 3): the tenant pool locks its own live subscription row, never B's.
	for _, role := range []*Store{api, worker} {
		var own, other int64
		if err := role.tenantTx(ctx, A, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM subscriptions WHERE tenant_id = $1
					AND status IN ('trialing', 'active', 'past_due') FOR UPDATE) s`, A).Scan(&own); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM subscriptions WHERE tenant_id = $1 FOR UPDATE) s`, f.b.id).Scan(&other)
		}); err != nil || own != 1 || other != 0 {
			t.Errorf("tenant pool SELECT … FOR UPDATE: own %d, B %d (%v); want 1, 0", own, other, err)
		}
	}
	if n, err := execIn(ctx, api, platform, `UPDATE subscriptions SET overrides = '{"max_devices": 9}', version = version + 1 WHERE id = $1`,
		f.a.subscription); err != nil || n != 1 {
		t.Errorf("api platform changes an override: %d rows, %v", n, err)
	}
}

// TestP3PolicyClasses: the RLS policies of the new tables follow their §6.3 symbol exactly — T: one policy, to
// mg_app_tenant only; T+P: one policy per group role, and the tenant one has no platform branch.
func TestP3PolicyClasses(t *testing.T) {
	_, _, _, su := fixtureDB(t)
	kinds := map[string]string{}
	for _, r := range rlsTables {
		kinds[r.name] = r.kind
	}
	for _, table := range p3Tables {
		rows, err := su.Query(ctxT(t), `SELECT array_to_string(roles, ',') || '|' || cmd || '|' || permissive || '|' ||
				(COALESCE(qual, '') || COALESCE(with_check, '') LIKE '%app_is_platform%')::text
			FROM pg_policies WHERE schemaname = 'public' AND tablename = $1 ORDER BY 1`, table)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		switch kinds[table] {
		case "T":
			want = []string{"mg_app_tenant|ALL|PERMISSIVE|false"}
		case "T+P":
			want = []string{"mg_app_platform|ALL|PERMISSIVE|true", "mg_app_tenant|ALL|PERMISSIVE|false"}
		case "":
			want = nil // subscription_plans: "—"
		default:
			t.Fatalf("%s: unexpected class %s", table, kinds[table])
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s (%s): policies %v, want %v", table, kinds[table], got, want)
		}
	}
}

// row is an INSERT under construction: column → SQL expression.
type row map[string]string

// with returns a copy with the given column/expression pairs set ("-" drops the column: its default applies).
func (r row) with(kv ...string) row {
	out := maps.Clone(r)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "-" {
			delete(out, kv[i])
		} else {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

func (r row) insert(table string) string {
	names := slices.Sorted(maps.Keys(r))
	vals := make([]string, len(names))
	for i, n := range names {
		vals[i] = r[n]
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(names, ", "), strings.Join(vals, ", "))
}

func lit(u uuid.UUID) string { return "'" + u.String() + "'" }

// shaOf is the SQL expression of the hex SHA-256 of a SQL string expression.
func shaOf(expr string) string { return "encode(sha256(convert_to(" + expr + ", 'UTF8')), 'hex')" }

// TestP3CheckConstraints — the CHECK constraints and unique indexes of 0009–0013: from a valid row of each table (a
// positive control), one deviation at a time is refused with check_violation (23514) or unique_violation (23505);
// the valid variants of each state pass. Each statement runs as superuser in its own rolled-back transaction, so RLS and
// privileges play no part — only the constraints do.
func TestP3CheckConstraints(t *testing.T) {
	_, _, f, su := fixtureDB(t)
	ctx := ctxT(t)
	x := newExtraIdentities(t, su, f)
	A, a := lit(f.a.id), &f.a
	region2 := newID()
	exec(t, su, `INSERT INTO relay_regions (id, code, name, kind, derp_region_id, hostname, verify_mode, tenant_id)
		VALUES ($1, 'mg-second-'||$2, 'Second', 'embedded', 902, 'second-'||$2||'.mesh.test', 'in_process', $3)`, region2, f.sfx, f.a.id)
	const hj = `'{"grants": []}'`
	approval := row{"scope": "'tenant'", "tenant_id": A, "action": "'tenant.settings.disable_four_eyes'", "resource_type": "'tenant_settings'",
		"payload": "'{}'", "payload_sha256": "repeat('a', 64)", "requested_by_identity_id": lit(a.identity),
		"expires_at": "now() + interval '1 hour'"}
	decided := approval.with("status", "'approved'", "approved_by_identity_id", lit(x.a2), "decided_at", "now()")
	invitation := row{"tenant_id": A, "idp_id": lit(a.idp), "email": "'new-" + f.sfx + "@example.test'", "role_id": lit(f.tenantRole),
		"token_hash": "sha256(convert_to(gen_random_uuid()::text, 'UTF8'))", "expires_at": "now() + interval '1 day'"}
	outbox := row{"tenant_id": A, "recipient_membership_id": lit(a.membership), "kind": "'device.new'"}
	region := row{"code": "'mg-check-'||substr(md5(random()::text), 1, 8)", "name": "'Check'", "kind": "'embedded'", "derp_region_id": "900",
		"hostname": "'check.mesh.test'", "verify_mode": "'in_process'", "tenant_id": A}
	assignment := row{"tenant_id": A, "instance_id": lit(a.instance), "relay_region_id": lit(region2)}
	bkp := row{"tenant_id": A, "instance_id": lit(a.instance), "kind": "'instance'", "storage_uri": "'file:///opt/meshguard/backups/c.age'",
		"key_ref": "'mgsec://" + f.a.id.String() + "/backup-key#2'", "headscale_version": "'0.29.7'"}
	done := bkp.with("status", "'succeeded'", "finished_at", "now()", "size_bytes", "10", "sha256", "repeat('0', 64)")
	quota := `"max_devices": 10, "max_users": 10, "max_tagged_devices": 2, "max_live_enrollment_credentials": 3`
	plan := row{"key": "'check-'||substr(md5(random()::text), 1, 8)", "name": "'Check'", "limits": "'{" + quota + "}'"}
	limits := func(extra string) string { return "'{" + quota + ", " + extra + "}'" }
	sub := row{"tenant_id": A, "plan_id": lit(f.plan), "status": "'cancelled'"}
	pv := row{"tenant_id": A, "version": "1000 + (random() * 1000000)::int", "source": hj, "content_sha256": "repeat('e', 64)"}
	pvH := pv.with("source", "-", "source_hujson", hj, "content_sha256", shaOf(hj))
	approvedSelf := pv.with("state", "'approved'", "approved_by", lit(a.identity), "approved_at", "now()",
		"approved_content_sha256", "repeat('e', 64)", "review_mode", "'self'")
	pa := row{"tenant_id": A, "instance_id": lit(a.instance), "policy_version_id": lit(a.policy), "trigger": "'manual'",
		"applied_hujson": hj, "applied_sha256": shaOf(hj)}
	type tc struct{ name, sql, want string }
	cases := []tc{
		// approval_requests
		{"approval: valid pending", approval.insert("approval_requests"), ""},
		{"approval: valid approved", decided.insert("approval_requests"), ""},
		{"approval: valid executed with the tenant's job", decided.with("status", "'executed'", "job_id", lit(a.job)).insert("approval_requests"), ""},
		{"approval: valid rejected", approval.with("status", "'rejected'", "decided_at", "now()").insert("approval_requests"), ""},
		{"approval: valid platform request about tenant A", approval.with("scope", "'platform'", "tenant_id", "-", "resource_type", "'tenant'",
			"resource_id", "'"+f.a.id.String()+"'", "requested_by_identity_id", lit(f.platformUser)).insert("approval_requests"), ""},
		{"approval: unknown status", approval.with("status", "'cancelled'").insert("approval_requests"), "23514"},
		{"approval: self-approval", decided.with("approved_by_identity_id", lit(a.identity)).insert("approval_requests"), "23514"},
		{"approval: approved without decided_at", decided.with("decided_at", "-").insert("approval_requests"), "23514"},
		{"approval: approved without approver", decided.with("approved_by_identity_id", "-").insert("approval_requests"), "23514"},
		{"approval: pending with a decision", approval.with("decided_at", "now()").insert("approval_requests"), "23514"},
		{"approval: rejected without decided_at", approval.with("status", "'rejected'").insert("approval_requests"), "23514"},
		{"approval: job before execution", decided.with("job_id", lit(a.job)).insert("approval_requests"), "23514"},
		{"approval: platform scope with a tenant", approval.with("scope", "'platform'", "requested_by_identity_id", lit(f.platformUser)).insert("approval_requests"), "23514"},
		{"approval: tenant scope without tenant", approval.with("tenant_id", "-").insert("approval_requests"), "23514"},
		{"approval: already expired at creation", approval.with("expires_at", "now() - interval '1 second'").insert("approval_requests"), "23514"},
		{"approval: payload not an object", approval.with("payload", "'[]'").insert("approval_requests"), "23514"},
		{"approval: payload hash not hex", approval.with("payload_sha256", "'xyz'").insert("approval_requests"), "23514"},
		{"approval: action format", approval.with("action", "'Delete'").insert("approval_requests"), "23514"},
		// tenant_invitations
		{"invitation: valid pending", invitation.insert("tenant_invitations"), ""},
		{"invitation: valid accepted", invitation.with("status", "'accepted'", "accepted_identity_id", lit(a.identity), "accepted_at", "now()").insert("tenant_invitations"), ""},
		{"invitation: valid pending after the earlier one was revoked", "UPDATE tenant_invitations SET status = 'revoked' WHERE id = " +
			lit(a.invitation) + "; " + invitation.with("email", "'invitee@"+f.a.slug+".test'").insert("tenant_invitations"), ""},
		{"invitation: unknown status", invitation.with("status", "'declined'").insert("tenant_invitations"), "23514"},
		{"invitation: accepted without identity", invitation.with("status", "'accepted'", "accepted_at", "now()").insert("tenant_invitations"), "23514"},
		{"invitation: pending with an accepting identity", invitation.with("accepted_identity_id", lit(a.identity)).insert("tenant_invitations"), "23514"},
		{"invitation: token hash of 16 bytes", invitation.with("token_hash", "decode(repeat('00', 16), 'hex')").insert("tenant_invitations"), "23514"},
		{"invitation: not an e-mail address", invitation.with("email", "'nobody'").insert("tenant_invitations"), "23514"},
		{"invitation: already expired at creation", invitation.with("expires_at", "now() - interval '1 second'").insert("tenant_invitations"), "23514"},
		{"invitation: second pending for the same e-mail", invitation.with("email", "'INVITEE@"+f.a.slug+".test'").insert("tenant_invitations"), "23505"},
		// notification_outbox
		{"outbox: valid in-portal", outbox.insert("notification_outbox"), ""},
		{"outbox: valid platform e-mail", outbox.with("tenant_id", "-", "recipient_membership_id", "-", "recipient_email", "'ops@example.test'").insert("notification_outbox"), ""},
		{"outbox: valid sent and read", outbox.with("status", "'sent'", "sent_at", "now()", "read_at", "now()").insert("notification_outbox"), ""},
		{"outbox: no recipient", outbox.with("recipient_membership_id", "-").insert("notification_outbox"), "23514"},
		{"outbox: platform row to a membership", outbox.with("tenant_id", "-").insert("notification_outbox"), "23514"},
		{"outbox: read_at without a membership", outbox.with("recipient_membership_id", "-", "recipient_email", "'x@example.test'", "read_at", "now()").insert("notification_outbox"), "23514"},
		{"outbox: sent without sent_at", outbox.with("status", "'sent'").insert("notification_outbox"), "23514"},
		{"outbox: sent_at while pending", outbox.with("sent_at", "now()").insert("notification_outbox"), "23514"},
		{"outbox: unknown status", outbox.with("status", "'queued'").insert("notification_outbox"), "23514"},
		{"outbox: negative attempts", outbox.with("attempts", "-1").insert("notification_outbox"), "23514"},
		{"outbox: kind format", outbox.with("kind", "'Device New'").insert("notification_outbox"), "23514"},
		// relay_regions / relay_assignments
		{"region: valid embedded", region.insert("relay_regions"), ""},
		{"region: valid shared", region.with("kind", "'shared'", "tenant_id", "-", "verify_mode", "'verify_url'").insert("relay_regions"), ""},
		{"region: embedded without tenant", region.with("tenant_id", "-").insert("relay_regions"), "23514"},
		{"region: standalone without tenant", region.with("kind", "'standalone'", "tenant_id", "-").insert("relay_regions"), "23514"},
		{"region: shared owned by a tenant", region.with("kind", "'shared'").insert("relay_regions"), "23514"},
		{"region: embedded verified by URL", region.with("verify_mode", "'verify_url'").insert("relay_regions"), "23514"},
		{"region: no verification", region.with("verify_mode", "'none'").insert("relay_regions"), "23514"},
		{"region: region id outside 900–999", region.with("derp_region_id", "1").insert("relay_regions"), "23514"},
		{"region: IPv6 in ipv4", region.with("ipv4", "'2001:db8::1'").insert("relay_regions"), "23514"},
		{"region: ipv4 network", region.with("ipv4", "'192.0.2.0/24'").insert("relay_regions"), "23514"},
		{"region: hostname format", region.with("hostname", "'Bad_Host'").insert("relay_regions"), "23514"},
		{"region: unknown status", region.with("status", "'up'").insert("relay_regions"), "23514"},
		{"region: code of A used twice", region.with("code", "'mg-"+f.a.slug+"'").insert("relay_regions"), "23505"},
		{"assignment: valid", assignment.insert("relay_assignments"), ""},
		{"assignment: negative priority", assignment.with("priority", "-1").insert("relay_assignments"), "23514"},
		{"assignment: unknown status", assignment.with("status", "'up'").insert("relay_assignments"), "23514"},
		{"assignment: same instance and region twice", assignment.with("relay_region_id", lit(a.region)).insert("relay_assignments"), "23505"},
		// backups
		{"backup: valid running", bkp.insert("backups"), ""},
		{"backup: valid succeeded and verified", done.with("verified_at", "now()").insert("backups"), ""},
		{"backup: valid platform dump without key", bkp.with("tenant_id", "-", "instance_id", "-", "kind", "'postgres'", "key_ref", "-",
			"headscale_version", "-").insert("backups"), ""},
		{"backup: instance archive without instance", bkp.with("instance_id", "-").insert("backups"), "23514"},
		{"backup: platform dump bound to a tenant", bkp.with("kind", "'postgres'").insert("backups"), "23514"},
		{"backup: instance archive without key", bkp.with("key_ref", "-").insert("backups"), "23514"},
		{"backup: key of tenant B", bkp.with("key_ref", "'mgsec://"+f.b.id.String()+"/backup-key#1'").insert("backups"), "23514"},
		{"backup: platform key on a tenant archive", bkp.with("key_ref", "'mgsec://platform/backup-key#1'").insert("backups"), "23514"},
		{"backup: credentials in storage_uri", bkp.with("storage_uri", "'sftp://backup:hunter2@store.example/x.age'").insert("backups"), "23514"},
		{"backup: storage_uri without scheme", bkp.with("storage_uri", "'/opt/meshguard/backups/c.age'").insert("backups"), "23514"},
		{"backup: succeeded without sha256", done.with("sha256", "-").insert("backups"), "23514"},
		{"backup: succeeded without finished_at", done.with("finished_at", "-").insert("backups"), "23514"},
		{"backup: running with finished_at", bkp.with("finished_at", "now()").insert("backups"), "23514"},
		{"backup: verified while failed", bkp.with("status", "'failed'", "finished_at", "now()", "verified_at", "now()").insert("backups"), "23514"},
		{"backup: unknown kind", bkp.with("kind", "'sqlite'").insert("backups"), "23514"},
		{"backup: unknown status", bkp.with("status", "'done'").insert("backups"), "23514"},
		// subscription_plans (PlanLimits — mg_plan_limits_valid)
		{"plan: valid quota keys only", plan.insert("subscription_plans"), ""},
		{"plan: valid every key", plan.with("limits", limits(`"backup_interval_minutes": 15, "instance": {"cpus": 0.5, "memory_mb": 256, "pids": 128}`)).insert("subscription_plans"), ""},
		{"plan: missing a quota key", plan.with("limits", `'{"max_devices": 10, "max_users": 10, "max_tagged_devices": 2}'`).insert("subscription_plans"), "23514"},
		{"plan: unknown key", plan.with("limits", limits(`"max_relays": 1`)).insert("subscription_plans"), "23514"},
		{"plan: negative quota", plan.with("limits", `'{"max_devices": -1, "max_users": 10, "max_tagged_devices": 2, "max_live_enrollment_credentials": 3}'`).insert("subscription_plans"), "23514"},
		{"plan: fractional quota", plan.with("limits", `'{"max_devices": 1.5, "max_users": 10, "max_tagged_devices": 2, "max_live_enrollment_credentials": 3}'`).insert("subscription_plans"), "23514"},
		{"plan: quota as a string", plan.with("limits", `'{"max_devices": "10", "max_users": 10, "max_tagged_devices": 2, "max_live_enrollment_credentials": 3}'`).insert("subscription_plans"), "23514"},
		{"plan: quota as null", plan.with("limits", `'{"max_devices": null, "max_users": 10, "max_tagged_devices": 2, "max_live_enrollment_credentials": 3}'`).insert("subscription_plans"), "23514"},
		{"plan: quota beyond int32", plan.with("limits", `'{"max_devices": 3000000000, "max_users": 10, "max_tagged_devices": 2, "max_live_enrollment_credentials": 3}'`).insert("subscription_plans"), "23514"},
		{"plan: backup interval 0", plan.with("limits", limits(`"backup_interval_minutes": 0`)).insert("subscription_plans"), "23514"},
		{"plan: instance cpus 0", plan.with("limits", limits(`"instance": {"cpus": 0}`)).insert("subscription_plans"), "23514"},
		{"plan: instance unknown key", plan.with("limits", limits(`"instance": {"disk_mb": 10}`)).insert("subscription_plans"), "23514"},
		{"plan: instance memory fractional", plan.with("limits", limits(`"instance": {"memory_mb": 1.5}`)).insert("subscription_plans"), "23514"},
		{"plan: instance not an object", plan.with("limits", limits(`"instance": 1`)).insert("subscription_plans"), "23514"},
		{"plan: limits not an object", plan.with("limits", "'[]'").insert("subscription_plans"), "23514"},
		{"plan: key format", plan.with("key", "'Bad Key'").insert("subscription_plans"), "23514"},
		{"plan: key of the fixture plan twice", plan.with("key", "'fixture-"+f.sfx+"'").insert("subscription_plans"), "23505"},
		// subscriptions
		{"subscription: valid cancelled with an override", sub.with("overrides", `'{"max_devices": 9, "instance": {"pids": 64}}'`).insert("subscriptions"), ""},
		{"subscription: valid new live one after cancelling the old", "UPDATE subscriptions SET status = 'cancelled' WHERE id = " + lit(a.subscription) + "; " +
			sub.with("status", "'trialing'").insert("subscriptions"), ""},
		{"subscription: second live one", sub.with("status", "'past_due'").insert("subscriptions"), "23505"},
		{"subscription: override of an unknown key", sub.with("overrides", `'{"max_tenants": 1}'`).insert("subscriptions"), "23514"},
		{"subscription: negative override", sub.with("overrides", `'{"max_users": -5}'`).insert("subscriptions"), "23514"},
		{"subscription: unknown status", sub.with("status", "'canceled'").insert("subscriptions"), "23514"},
		{"subscription: period ends before it starts", sub.with("period_end", "now() - interval '1 day'").insert("subscriptions"), "23514"},
		// policy_versions
		{"policy: valid draft from a typed source", pv.insert("policy_versions"), ""},
		{"policy: valid draft from HuJSON", pvH.insert("policy_versions"), ""},
		{"policy: valid self-reviewed approval", approvedSelf.insert("policy_versions"), ""},
		{"policy: valid peer-reviewed approval", approvedSelf.with("review_mode", "'peer'", "submitted_by", lit(x.a2), "submitted_at", "now()").insert("policy_versions"), ""},
		{"policy: valid system-approved baseline", pvH.with("kind", "'suspension'", "state", "'approved'", "approved_at", "now()",
			"approved_content_sha256", shaOf(hj)).insert("policy_versions"), ""},
		{"policy: valid child of A's baseline", pv.with("parent_version_id", lit(a.policy), "rollback_of", lit(a.policy)).insert("policy_versions"), ""},
		{"policy: unknown state", pv.with("state", "'applied'").insert("policy_versions"), "23514"},
		{"policy: unknown kind", pv.with("kind", "'fixture'").insert("policy_versions"), "23514"},
		{"policy: both a source and HuJSON", pvH.with("source", hj).insert("policy_versions"), "23514"},
		{"policy: no content", pv.with("source", "-").insert("policy_versions"), "23514"},
		{"policy: HuJSON hash mismatch", pvH.with("content_sha256", "repeat('e', 64)").insert("policy_versions"), "23514"},
		{"policy: empty HuJSON (L2)", pvH.with("source_hujson", "E' \\n\\t'", "content_sha256", shaOf("E' \\n\\t'")).insert("policy_versions"), "23514"},
		{"policy: approved without approved_at", approvedSelf.with("approved_at", "-").insert("policy_versions"), "23514"},
		{"policy: approved content differs", approvedSelf.with("approved_content_sha256", "repeat('f', 64)").insert("policy_versions"), "23514"},
		{"policy: user policy approved without reviewer", approvedSelf.with("approved_by", "-").insert("policy_versions"), "23514"},
		{"policy: user policy approved without review mode", approvedSelf.with("review_mode", "-").insert("policy_versions"), "23514"},
		{"policy: peer review by the submitter", approvedSelf.with("review_mode", "'peer'", "submitted_by", lit(a.identity), "submitted_at", "now()").insert("policy_versions"), "23514"},
		{"policy: draft keeping an approval", pv.with("approved_by", lit(a.identity)).insert("policy_versions"), "23514"},
		{"policy: validated keeping an approval", pv.with("state", "'validated'", "review_mode", "'self'").insert("policy_versions"), "23514"},
		{"policy: pending approval never submitted", pv.with("state", "'pending_approval'").insert("policy_versions"), "23514"},
		{"policy: rejected without rejected_at", pv.with("state", "'rejected'").insert("policy_versions"), "23514"},
		{"policy: version number of A's baseline", pv.with("version", "1").insert("policy_versions"), "23505"},
		// policy_applications
		{"application: valid pending", pa.insert("policy_applications"), ""},
		{"application: valid unknown", pa.with("state", "'unknown'").insert("policy_applications"), ""},
		{"application: valid failed", pa.with("state", "'failed'", "finished_at", "now()", "error_code", "'upstream_rejected'").insert("policy_applications"), ""},
		{"application: valid new current after superseding the old", "UPDATE policy_applications SET superseded_at = now() WHERE id = " +
			lit(a.application) + "; " + pa.with("state", "'applied'", "finished_at", "now()").insert("policy_applications"), ""},
		{"application: second current for one instance", pa.with("state", "'applied'", "finished_at", "now()").insert("policy_applications"), "23505"},
		{"application: hash of other bytes", pa.with("applied_sha256", "repeat('a', 64)").insert("policy_applications"), "23514"},
		{"application: empty HuJSON", pa.with("applied_hujson", "' '", "applied_sha256", shaOf("' '")).insert("policy_applications"), "23514"},
		{"application: unknown trigger", pa.with("trigger", "'cron'").insert("policy_applications"), "23514"},
		{"application: unknown state", pa.with("state", "'superseded'").insert("policy_applications"), "23514"},
		{"application: applied without finished_at", pa.with("state", "'applied'").insert("policy_applications"), "23514"},
		{"application: pending with finished_at", pa.with("finished_at", "now()").insert("policy_applications"), "23514"},
		{"application: failed without error code", pa.with("state", "'failed'", "finished_at", "now()").insert("policy_applications"), "23514"},
		{"application: superseded while pending", pa.with("superseded_at", "now()").insert("policy_applications"), "23514"},
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

// standardLimits is the content of the plan `standard` of database/seeds/plans.sql.
const standardLimits = `{"max_devices": 100, "max_users": 100, "max_tagged_devices": 25, "max_live_enrollment_credentials": 25,
	"backup_interval_minutes": 60, "instance": {"cpus": 1, "memory_mb": 512, "pids": 256}}`

// TestPlanSeedAndTenantCap — "plan tối thiểu": after store.Migrate the plan `standard` holds exactly the limits of the
// seed and quota.max_tenants is 10; the seed only inserts — limits, name and is_active tuned by the owner survive every
// later run, a plan deleted by hand comes back; the effective limits of a tenant (plan ⊕ overrides) are read in the
// tenant pool under the subscription row lock, as QuotaChecker will (P3-T06a); the tenant cap is readable by the platform
// pool only.
func TestPlanSeedAndTenantCap(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 0) // own database: the test changes the seeded plan
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	plan := func() (name string, limits map[string]any, active bool) {
		var raw []byte
		if err := su.QueryRow(ctx, `SELECT name, limits, is_active FROM subscription_plans WHERE key = 'standard'`).Scan(&name, &raw, &active); err != nil {
			t.Fatalf("plan standard: %v", err)
		}
		if err := json.Unmarshal(raw, &limits); err != nil {
			t.Fatal(err)
		}
		return name, limits, active
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(standardLimits), &want); err != nil {
		t.Fatal(err)
	}
	if name, limits, active := plan(); name != "Standard (MVP)" || !reflect.DeepEqual(limits, want) || !active {
		t.Fatalf("seeded plan: %q %v active=%v; want %q %v true", name, limits, active, "Standard (MVP)", want)
	}
	var plans int64
	if err := su.QueryRow(ctx, `SELECT count(*) FROM subscription_plans`).Scan(&plans); err != nil || plans != 1 {
		t.Errorf("%d plans after the seed (%v), want only `standard`", plans, err)
	}

	exec(t, su, `UPDATE subscription_plans SET limits = jsonb_set(limits, '{max_devices}', '250'), name = 'Tuned', is_active = false
		WHERE key = 'standard'`)
	if err := Seed(ctx, mig); err != nil {
		t.Fatal(err)
	}
	if name, limits, active := plan(); name != "Tuned" || limits["max_devices"] != float64(250) || active {
		t.Errorf("after a re-seed the owner's tuning is gone: %q %v active=%v", name, limits, active)
	}
	exec(t, su, `DELETE FROM subscription_plans WHERE key = 'standard'`)
	if err := Seed(ctx, mig); err != nil {
		t.Fatal(err)
	}
	if name, limits, _ := plan(); name != "Standard (MVP)" || !reflect.DeepEqual(limits, want) {
		t.Errorf("a deleted plan comes back with the seed's content: %q %v", name, limits)
	}

	f := newFixture()
	f.insertAll(t, su)
	exec(t, su, `UPDATE subscriptions SET plan_id = (SELECT id FROM subscription_plans WHERE key = 'standard'),
		overrides = '{"max_devices": 150}' WHERE id = $1`, f.a.subscription)
	s := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	var effective []byte
	if err := s.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT p.limits || s.overrides FROM subscriptions s JOIN subscription_plans p ON p.id = s.plan_id
			WHERE s.tenant_id = $1 AND s.status IN ('trialing', 'active', 'past_due') FOR UPDATE OF s`, f.a.id).Scan(&effective)
	}); err != nil {
		t.Fatalf("effective limits in the tenant pool: %v", err)
	}
	var eff map[string]any
	if err := json.Unmarshal(effective, &eff); err != nil {
		t.Fatal(err)
	}
	if eff["max_devices"] != float64(150) || eff["max_users"] != float64(100) || eff["max_live_enrollment_credentials"] != float64(25) {
		t.Errorf("effective limits of A = %v, want max_devices 150 (override) and the plan's other keys", eff)
	}

	var tenantCap string
	if err := s.platformTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value::text FROM system_settings WHERE key = 'quota.max_tenants'`).Scan(&tenantCap)
	}); err != nil || tenantCap != "10" {
		t.Errorf("quota.max_tenants through the platform pool = %q (%v), want 10", tenantCap, err)
	}
	err = s.tenantTx(ctx, f.a.id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT 1 FROM system_settings`)
		return err
	})
	wantSQLState(t, "tenant pool reading system_settings", err, privilegeErr)

	// Every key of the seeded plan is one of PlanLimits, in a stable order for the evidence.
	keys := slices.Collect(maps.Keys(want))
	sort.Strings(keys)
	t.Logf("plan standard: keys %v", keys)
}
