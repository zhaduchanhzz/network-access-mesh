package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fixture holds one row per scope (tenant A, tenant B, platform) in every table of migrations 0001–0014, inserted
// by the superuser (bypassing RLS) so the tests can check what each role and scope sees. Every identifier is random,
// so fixtures of parallel tests share a database without colliding.
type fixture struct {
	sfx          string
	host         uuid.UUID
	a, b         tenantRows
	tenantRole   uuid.UUID
	platformRole uuid.UUID
	permission   string
	platformIdP  uuid.UUID
	platformUser uuid.UUID // identities.id of a platform identity
	platformDEK  uuid.UUID
	opsDEK       uuid.UUID
	setting      string
	// 0009–0013 (P3-T06): rows of the platform scope and the plan of this fixture
	platformApproval, platformNotification, sharedRegion, platformBackup, plan uuid.UUID
}

type tenantRows struct {
	id, instance, config, idp, identity, membership, dek, secret, device, job uuid.UUID
	// 0009–0013 (P3-T06)
	approval, invitation, notification, region, assignment, backup, subscription, policy, application uuid.UUID
	slug                                                                                              string
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func randInt(n int64) int64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(n))
	return v.Int64()
}

func newFixture() *fixture {
	f := &fixture{sfx: randomHex(4), host: newID(), tenantRole: newID(), platformRole: newID(), platformIdP: newID(),
		platformUser: newID(), platformDEK: newID(), opsDEK: newID(), platformApproval: newID(), platformNotification: newID(),
		sharedRegion: newID(), platformBackup: newID(), plan: newID()}
	f.permission = "tenant.fixture_" + f.sfx + ":read" // permissions.key: <scope>.<resource>:<action>, prefix = scope
	f.setting = "test.setting_" + f.sfx
	for _, tr := range []*tenantRows{&f.a, &f.b} {
		*tr = tenantRows{id: newID(), instance: newID(), config: newID(), idp: newID(), identity: newID(),
			membership: newID(), dek: newID(), secret: newID(), device: newID(), job: newID(), approval: newID(), invitation: newID(),
			notification: newID(), region: newID(), assignment: newID(), backup: newID(), subscription: newID(), policy: newID(),
			application: newID()}
		tr.slug = "t" + randomHex(5)
	}
	return f
}

// fixtureSteps[v] inserts the rows of the tables created by migration v (the migration test runs them between
// migrations; insertAll runs them all on a fully migrated database).
var fixtureSteps = map[int64]func(f *fixture, t *testing.T, c *pgx.Conn){
	1: (*fixture).step1, 2: (*fixture).step2, 3: (*fixture).step3, 4: (*fixture).step4, 5: (*fixture).step5, 6: (*fixture).step6,
	7: (*fixture).step7, 8: (*fixture).step8, 9: (*fixture).step9, 10: (*fixture).step10, 11: (*fixture).step11,
	12: (*fixture).step12, 13: (*fixture).step13, 14: (*fixture).step14, 15: (*fixture).step15,
	16: (*fixture).step16,
	17: (*fixture).step17,
	18: (*fixture).step18,
}

// latestMigration is the number of the last migration of database/migrations (TestMigrationsUpWithData,
// TestMigrationsShareClusterRoles).
const latestMigration = 18

// migrationVersions are the versions that have a migration, ascending. Tasks written in parallel use provisional
// numbers; the coordinator renumbers at merge so that the numbers stay contiguous (goose refuses a migration numbered
// below one already applied) — P3-T05c was written as 0019 and merged as 0016. TestLatestMigration keeps it equal to
// the embedded migrations.
func migrationVersions() []int64 {
	out := make([]int64, 0, len(fixtureSteps))
	for v := range fixtureSteps {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

func (f *fixture) insertAll(t *testing.T, c *pgx.Conn) {
	t.Helper()
	for _, v := range migrationVersions() {
		fixtureSteps[v](f, t, c)
	}
}

func exec(t *testing.T, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(ctxT(t), sql, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

func (f *fixture) tenants() []*tenantRows { return []*tenantRows{&f.a, &f.b} }

// 0001: hosts, tenants, tenant_instances, instance_config_versions, system_settings.
func (f *fixture) step1(t *testing.T, c *pgx.Conn) {
	exec(t, c, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-'||$2, 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host, f.sfx)
	for i, tr := range f.tenants() {
		exec(t, c, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`,
			tr.id, tr.slug, "Tenant "+tr.slug)
		exec(t, c, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
			tr.instance, tr.id, f.host, tr.slug+".mesh.test", tr.slug+".ts.test", "hs-"+tr.slug+":8080", 30001+i,
			fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+tr.instance.String())
		exec(t, c, `INSERT INTO instance_config_versions (id, tenant_id, instance_id, version, template_version,
				rendered_config, config_sha256)
			VALUES ($1, $2, $3, 1, 'v4', 'server_url: https://example', repeat('b', 64))`, tr.config, tr.id, tr.instance)
		exec(t, c, `UPDATE tenant_instances SET config_version_id = $1 WHERE id = $2`, tr.config, tr.instance)
	}
	exec(t, c, `INSERT INTO system_settings (key, value) VALUES ($1, '{"max_tenants": 10}')`, f.setting)
}

// 0002: roles/permissions, identity_providers, identities, platform_users, tenant_memberships, sessions, auth_requests.
func (f *fixture) step2(t *testing.T, c *pgx.Conn) {
	exec(t, c, `INSERT INTO roles (id, scope, key, name) VALUES ($1, 'tenant', 'owner_'||$3, 'Owner'),
		($2, 'platform', 'super_admin_'||$3, 'Super Admin')`, f.tenantRole, f.platformRole, f.sfx)
	exec(t, c, `INSERT INTO permissions (key, scope) VALUES ($1, 'tenant')`, f.permission)
	exec(t, c, `INSERT INTO role_permissions (role_id, role_scope, permission_key, permission_scope)
		VALUES ($1, 'tenant', $2, 'tenant')`, f.tenantRole, f.permission)
	// client secrets: the platform IdP's under the name of `meshguard admin set-idp-client-secret`, tenant A's under the
	// drivers' name, tenant B a public client — the three forms 0007 (owner CHECK) must keep
	exec(t, c, `INSERT INTO identity_providers (id, scope, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'platform', 'https://idp.test/realms/platform-'||$2, 'portal', $3, 'keycloak', 'active')`,
		f.platformIdP, f.sfx, "mgsec://platform/idp-client-secret."+f.platformIdP.String()+"#1")
	exec(t, c, `INSERT INTO identities (id, idp_id, scope, subject, email) VALUES ($1, $2, 'platform', 'sa-'||$3, 'sa@example.test')`,
		f.platformUser, f.platformIdP, f.sfx)
	exec(t, c, `INSERT INTO platform_users (identity_id, role_id) VALUES ($1, $2)`, f.platformUser, f.platformRole)
	for i, tr := range f.tenants() {
		var ref *string
		if i == 0 {
			r := "mgsec://" + tr.id.String() + "/idp." + tr.idp.String() + ".client#1"
			ref = &r
		}
		exec(t, c, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
			VALUES ($1, 'tenant', $2, 'https://idp.test/realms/'||$3, 'portal', $4, 'keycloak', 'active')`, tr.idp, tr.id, tr.slug, ref)
		exec(t, c, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email)
			VALUES ($1, $2, $3, 'tenant', 'user-'||$4, 'user@'||$4||'.test')`, tr.identity, tr.idp, tr.id, tr.slug)
		exec(t, c, `INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id) VALUES ($1, $2, $3, $4)`,
			tr.membership, tr.id, tr.identity, f.tenantRole)
	}
	exec(t, c, `INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at)
		VALUES (sha256(convert_to($1, 'UTF8')), $2, $3, 'admin', now(), now() + interval '30 minutes', now() + interval '8 hours')`,
		"session-"+f.sfx, f.platformUser, f.platformIdP)
	exec(t, c, `INSERT INTO auth_requests (state_hash, idp_id, scope, origin, nonce, pkce_verifier_enc, browser_binding_hash,
			expires_at)
		VALUES (sha256(convert_to($1, 'UTF8')), $2, 'platform', 'admin', 'n', '\x00', sha256('\x01'), now() + interval '5 minutes')`,
		"state-"+f.sfx, f.platformIdP)
}

// 0003: tenant_keys, secrets — one tenant DEK per tenant, one platform and one platform_ops DEK (retired, random
// version: only one active DEK per scope is allowed and parallel fixtures share the database).
func (f *fixture) step3(t *testing.T, c *pgx.Conn) {
	keys := []struct {
		id     uuid.UUID
		scope  string
		tenant *uuid.UUID
		secret uuid.UUID
		state  string
	}{
		{f.a.dek, "tenant", &f.a.id, f.a.secret, "active"},
		{f.b.dek, "tenant", &f.b.id, f.b.secret, "active"},
		{f.platformDEK, "platform", nil, newID(), "retired"},
		{f.opsDEK, "platform_ops", nil, newID(), "retired"},
	}
	for _, k := range keys {
		v := 1 + randInt(1<<30)
		exec(t, c, `INSERT INTO tenant_keys (id, scope, tenant_id, version, wrapped_dek, wrap_nonce, kek_id, state)
			VALUES ($1, $2, $3, $4, '\xdead', '\xbeef', 'kek-test', $5)`, k.id, k.scope, k.tenant, v, k.state)
		exec(t, c, `INSERT INTO secrets (id, tenant_id, scope, name, version, ciphertext, nonce, aad, dek_id)
			VALUES ($1, $2, $3, 'secret-'||$4, 1, '\xc0ffee', '\x00', '\x00', $5)`, k.secret, k.tenant, k.scope, randomHex(4), k.id)
	}
}

// 0004: audit_events (tenant A, tenant B, platform), security_events (same).
func (f *fixture) step4(t *testing.T, c *pgx.Conn) {
	for _, tenant := range []*uuid.UUID{&f.a.id, &f.b.id, nil} {
		exec(t, c, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome)
			VALUES ($1, 'system', 'fixture.created', 'fixture', 'success')`, tenant)
		exec(t, c, `INSERT INTO security_events (tenant_id, kind, severity, source) VALUES ($1, 'fixture', 'low', 'test')`, tenant)
	}
}

// 0005: device_inventory_cache, device_inventory_sync_state.
func (f *fixture) step5(t *testing.T, c *pgx.Conn) {
	for i, tr := range f.tenants() {
		exec(t, c, `INSERT INTO device_inventory_cache (id, tenant_id, instance_id, headscale_node_id, machine_key, name,
				owner_membership_id, ip_addresses)
			VALUES ($1, $2, $3, $4, 'mkey:'||$5, 'laptop', $6, ARRAY['100.64.0.1'::inet])`,
			tr.device, tr.id, tr.instance, i+1, randomHex(8), tr.membership)
		exec(t, c, `INSERT INTO device_inventory_sync_state (instance_id, tenant_id, generation, synced_at, node_count)
			VALUES ($1, $2, 1, now(), 1)`, tr.instance, tr.id)
	}
}

// 0007: no table — the owner CHECK of identity_providers.client_secret_ref; the references written by step2 must pass.
func (f *fixture) step7(*testing.T, *pgx.Conn) {}

// 0008: no table — sessions.id_token_hint_enc (G2 round 2, A-1): a session of tenant A's identity carrying a sealed
// hint (opaque bytes for the database), next to the 0002 session without one.
func (f *fixture) step8(t *testing.T, c *pgx.Conn) {
	exec(t, c, `INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at,
			id_token_hint_enc)
		VALUES (sha256(convert_to($1, 'UTF8')), $2, $3, 'app', now(), now() + interval '30 minutes', now() + interval '12 hours',
			sha256(convert_to($1, 'UTF8')) || sha256(convert_to($1 || '-x', 'UTF8')))`, "session-hint-"+f.sfx, f.a.identity, f.a.idp)
}

// 0006: provisioning_jobs (+steps), idempotency_keys; links device A to its revocation job (FK added by 0006).
func (f *fixture) step6(t *testing.T, c *pgx.Conn) {
	for _, tr := range f.tenants() {
		exec(t, c, `INSERT INTO provisioning_jobs (id, tenant_id, instance_id, kind, status) VALUES ($1, $2, $3, 'device.revoke', 'succeeded')`,
			tr.job, tr.id, tr.instance)
		exec(t, c, `INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status) VALUES ($1, $2, 0, 'expire', 'succeeded')`,
			tr.id, tr.job)
		exec(t, c, `INSERT INTO idempotency_keys (tenant_id, identity_id, operation_id, key, request_hash, expires_at)
			VALUES ($1, $2, 'expireDevice', $3, sha256(convert_to($3, 'UTF8')), now() + interval '1 day')`, tr.id, tr.identity, randomHex(8))
	}
	platformJob := newID()
	exec(t, c, `INSERT INTO provisioning_jobs (id, kind, status) VALUES ($1, 'partition.maintain', 'succeeded')`, platformJob)
	exec(t, c, `INSERT INTO provisioning_job_steps (job_id, seq, name, status) VALUES ($1, 0, 'create', 'succeeded')`, platformJob)
	exec(t, c, `INSERT INTO idempotency_keys (identity_id, operation_id, key, request_hash, expires_at)
		VALUES ($1, 'createTenant', $2, sha256(convert_to($2, 'UTF8')), now() + interval '1 day')`, f.platformUser, randomHex(8))
	exec(t, c, `UPDATE device_inventory_cache SET revocation_state = 'applied', revocation_kind = 'expire', revocation_job_id = $1
		WHERE id = $2`, f.a.job, f.a.device)
}

// sha256Hex is the lowercase hex SHA-256 of s (payload_sha256, content_sha256, applied_sha256).
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// baselinePolicy is the deny-all HuJSON of the fixture's baseline version (§11.3 step 15): a comment and a trailing
// comma keep it HuJSON rather than JSON.
const baselinePolicy = "{\n  // baseline: deny-all (fixture)\n  \"grants\": [],\n}\n"

// 0009: approval_requests (tenant A, tenant B: pending requests of the tenant's identity; platform: a pending 2P request
// about tenant A, its target in resource_type/resource_id), tenant_invitations (A, B), notification_outbox (in-portal
// to the tenant's membership for A and B, an e-mail of the platform scope).
func (f *fixture) step9(t *testing.T, c *pgx.Conn) {
	const payload = `{"four_eyes": false}`
	for _, tr := range f.tenants() {
		exec(t, c, `INSERT INTO approval_requests (id, scope, tenant_id, action, resource_type, resource_id, payload, payload_sha256,
				requested_by_identity_id, reason, expires_at)
			VALUES ($1, 'tenant', $2, 'tenant.settings.disable_four_eyes', 'tenant_settings', $3, $4, $5, $6, 'fixture',
				now() + interval '24 hours')`,
			tr.approval, tr.id, tr.id.String(), payload, sha256Hex(payload), tr.identity)
		exec(t, c, `INSERT INTO tenant_invitations (id, tenant_id, idp_id, email, role_id, token_hash, expires_at)
			VALUES ($1, $2, $3, 'invitee@'||$4||'.test', $5, sha256(convert_to($6, 'UTF8')), now() + interval '7 days')`,
			tr.invitation, tr.id, tr.idp, tr.slug, f.tenantRole, "invitation-token-"+randomHex(8))
		exec(t, c, `INSERT INTO notification_outbox (id, tenant_id, recipient_membership_id, kind, payload)
			VALUES ($1, $2, $3, 'tenant.activated', '{"slug": "x"}')`, tr.notification, tr.id, tr.membership)
	}
	exec(t, c, `INSERT INTO approval_requests (id, scope, action, resource_type, resource_id, payload, payload_sha256,
			requested_by_identity_id, expires_at)
		VALUES ($1, 'platform', 'tenant.delete', 'tenant', $2, '{}', $3, $4, now() + interval '24 hours')`,
		f.platformApproval, f.a.id.String(), sha256Hex("{}"), f.platformUser)
	exec(t, c, `INSERT INTO notification_outbox (id, recipient_email, kind) VALUES ($1, 'ops@example.test', 'platform.backup_overdue')`,
		f.platformNotification)
}

// 0010: relay_regions (an embedded region per tenant on the fixture host, a shared region of the platform scope),
// relay_assignments (each tenant's instance to its own region).
func (f *fixture) step10(t *testing.T, c *pgx.Conn) {
	for _, tr := range f.tenants() {
		exec(t, c, `INSERT INTO relay_regions (id, code, name, kind, derp_region_id, hostname, ipv4, stun_port, verify_mode, host_id,
				tenant_id, status)
			VALUES ($1, 'mg-'||$2, 'Relay '||$2, 'embedded', 900, $2||'.mesh.test', '192.0.2.10', 3478, 'in_process', $3, $4, 'active')`,
			tr.region, tr.slug, f.host, tr.id)
		exec(t, c, `INSERT INTO relay_assignments (id, tenant_id, instance_id, relay_region_id, status) VALUES ($1, $2, $3, $4, 'active')`,
			tr.assignment, tr.id, tr.instance, tr.region)
	}
	exec(t, c, `INSERT INTO relay_regions (id, code, name, kind, derp_region_id, hostname, verify_mode)
		VALUES ($1, 'shared-'||$2, 'Shared '||$2, 'shared', 901, 'derp-'||$2||'.relay.test', 'verify_url')`, f.sharedRegion, f.sfx)
}

// 0011: backups (a finished instance archive per tenant, keyed by the tenant's own backup key and linked to the
// tenant's job; a PostgreSQL dump of the platform scope).
func (f *fixture) step11(t *testing.T, c *pgx.Conn) {
	// on a schema with P3-T11's backup columns (insertAll), an instance backup carries its sequence, wrapped data key
	// and signed manifest (CHECK backups_instance_key / _manifest); before them (the migration test) step17 adds them
	full := hasColumn(t, c, "backups", "sequence")
	for i, tr := range f.tenants() {
		if full {
			exec(t, c, `INSERT INTO backups (id, tenant_id, instance_id, kind, status, storage_uri, size_bytes, sha256, key_ref,
					headscale_version, finished_at, expires_at, job_id, sequence, wrapped_data_key, manifest, manifest_signature,
					manifest_sha256, method)
				VALUES ($1, $2, $3, 'instance', 'succeeded', $4, 4096, repeat('c', 64), $5, '0.29.7', now(), now() + interval '30 days', $6,
					$7, decode(repeat('ab', 60), 'hex'), convert_to('{"fixture":true}', 'UTF8'), decode(repeat('cd', 64), 'hex'),
					repeat('e', 64), 'vacuum_into')`,
				tr.backup, tr.id, tr.instance, "file:///opt/meshguard/backups/tenants/"+tr.instance.String()+"/fixture.age",
				"mgsec://"+tr.id.String()+"/backup-key#1", tr.job, 1000+i)
			continue
		}
		exec(t, c, `INSERT INTO backups (id, tenant_id, instance_id, kind, status, storage_uri, size_bytes, sha256, key_ref,
				headscale_version, finished_at, expires_at, job_id)
			VALUES ($1, $2, $3, 'instance', 'succeeded', $4, 4096, repeat('c', 64), $5, '0.29.7', now(), now() + interval '30 days', $6)`,
			tr.backup, tr.id, tr.instance, "file:///opt/meshguard/backups/tenants/"+tr.instance.String()+"/fixture.age",
			"mgsec://"+tr.id.String()+"/backup-key#1", tr.job)
	}
	exec(t, c, `INSERT INTO backups (id, kind, status, storage_uri, size_bytes, sha256, finished_at)
		VALUES ($1, 'postgres', 'succeeded', 'file:///opt/meshguard/backups/postgres/fixture-'||$2||'.age', 1024, repeat('d', 64), now())`,
		f.platformBackup, f.sfx)
}

// 0012: subscription_plans (a plan of this fixture), subscriptions (one live subscription per tenant with an override).
func (f *fixture) step12(t *testing.T, c *pgx.Conn) {
	exec(t, c, `INSERT INTO subscription_plans (id, key, name, limits)
		VALUES ($1, 'fixture-'||$2, 'Fixture', '{"max_devices": 5, "max_users": 5, "max_tagged_devices": 1, "max_live_enrollment_credentials": 2}')`,
		f.plan, f.sfx)
	for _, tr := range f.tenants() {
		exec(t, c, `INSERT INTO subscriptions (id, tenant_id, plan_id, overrides) VALUES ($1, $2, $3, '{"max_devices": 7}')`,
			tr.subscription, tr.id, f.plan)
	}
}

// 0013: policy_versions (the baseline v1 of each tenant, approved by the system), tenants.desired_policy_version_id,
// policy_applications (the bootstrap application of that baseline on the tenant's instance — the current one).
func (f *fixture) step13(t *testing.T, c *pgx.Conn) {
	for _, tr := range f.tenants() {
		exec(t, c, `INSERT INTO policy_versions (id, tenant_id, version, kind, source_hujson, content_sha256, state, approved_at,
				approved_content_sha256)
			VALUES ($1, $2, 1, 'baseline', $3, $4, 'approved', now(), $4)`, tr.policy, tr.id, baselinePolicy, sha256Hex(baselinePolicy))
		exec(t, c, `UPDATE tenants SET desired_policy_version_id = $1 WHERE id = $2`, tr.policy, tr.id)
		exec(t, c, `INSERT INTO policy_applications (id, tenant_id, instance_id, policy_version_id, trigger, applied_hujson,
				applied_sha256, state, finished_at)
			VALUES ($1, $2, $3, $4, 'bootstrap', $5, $6, 'applied', now())`,
			tr.application, tr.id, tr.instance, tr.policy, baselinePolicy, sha256Hex(baselinePolicy))
	}
}

// 0014 (P3-T04): no new table — the host of the fixture declares its public entry and capacity (shapes checked by 0014),
// so it is a host placement could choose.
func (f *fixture) step14(t *testing.T, c *pgx.Conn) {
	exec(t, c, `UPDATE hosts SET public_entry = '{"ipv4": "192.0.2.10", "mode": "direct"}',
		capacity = '{"max_instances": 50}' WHERE id = $1`, f.host)
}

// step15 (0015, P3-T05): a job that took a /cancel request (provisioning_jobs.cancel_requested_at).
func (f *fixture) step15(t *testing.T, c *pgx.Conn) {
	exec(t, c, `UPDATE provisioning_jobs SET cancel_requested_at = now() WHERE id = $1`, f.a.job)
}

// step16 (0016, P3-T05c — renumbered from the provisional 0019 at merge): the last relay probe of tenant A's region (relay_regions.last_probe /
// last_probe_at, as relay.probe records it); B's region was never probed.
func (f *fixture) step16(t *testing.T, c *pgx.Conn) {
	exec(t, c, `UPDATE relay_regions SET last_probe = '{"schema":1,"status":"healthy","derp":{"ok":true,"status":200,"duration_ms":12},
			"stun":{"ok":true,"duration_ms":3}}', last_probe_at = now() WHERE id = $1`, f.a.region)
}

// step17 (P3-T11, backup_manifest — provisional number): the instance backups inserted before the migration get their
// sequence, wrapped data key and signed manifest (a row inserted after it has them from its insertion — step11).
func (f *fixture) step17(t *testing.T, c *pgx.Conn) {
	for i, tr := range f.tenants() {
		exec(t, c, `UPDATE backups SET sequence = $2, wrapped_data_key = decode(repeat('ab', 60), 'hex'),
				manifest = convert_to('{"fixture":true}', 'UTF8'), manifest_signature = decode(repeat('cd', 64), 'hex'),
				manifest_sha256 = repeat('e', 64), method = 'vacuum_into'
			WHERE id = $1 AND sequence IS NULL`, tr.backup, 1000+i)
	}
}

// hasColumn reports whether the fixture's database has table.column (the fixture runs on every schema version).
func hasColumn(t *testing.T, c *pgx.Conn, table, column string) bool {
	t.Helper()
	var ok bool
	if err := c.QueryRow(ctxT(t), `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)`, table, column).Scan(&ok); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return ok
}

// step18 (0018, P3-T17 — renumbered from the provisional 0020 at merge): no table, no column — a grant (UPDATE
// (revoked_at, id_token_hint_enc) ON sessions TO mg_worker_platform), exercised by TestMigration0018WorkerRevokesSessions.
func (f *fixture) step18(*testing.T, *pgx.Conn) {}
