package store

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fixture holds one row per scope (tenant A, tenant B, platform) in every table of migrations 0001–0006, inserted
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
}

type tenantRows struct {
	id, instance, config, idp, identity, membership, dek, secret, device, job uuid.UUID
	slug                                                                      string
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func randInt(n int64) int64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(n))
	return v.Int64()
}

func newFixture() *fixture {
	f := &fixture{sfx: randomHex(4), host: newID(), tenantRole: newID(), platformRole: newID(), platformIdP: newID(),
		platformUser: newID(), platformDEK: newID(), opsDEK: newID()}
	f.permission = "tenant.fixture_" + f.sfx + ":read" // permissions.key: <scope>.<resource>:<action>, prefix = scope
	f.setting = "test.setting_" + f.sfx
	for _, tr := range []*tenantRows{&f.a, &f.b} {
		*tr = tenantRows{id: newID(), instance: newID(), config: newID(), idp: newID(), identity: newID(),
			membership: newID(), dek: newID(), secret: newID(), device: newID(), job: newID()}
		tr.slug = "t" + randomHex(5)
	}
	return f
}

// fixtureSteps[v] inserts the rows of the tables created by migration v (the migration test runs them between
// migrations; insertAll runs them all on a fully migrated database).
var fixtureSteps = map[int64]func(f *fixture, t *testing.T, c *pgx.Conn){
	1: (*fixture).step1, 2: (*fixture).step2, 3: (*fixture).step3, 4: (*fixture).step4, 5: (*fixture).step5, 6: (*fixture).step6,
}

func (f *fixture) insertAll(t *testing.T, c *pgx.Conn) {
	t.Helper()
	for v := int64(1); v <= 6; v++ {
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
	exec(t, c, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.test/realms/platform-'||$2, 'portal', 'keycloak', 'active')`, f.platformIdP, f.sfx)
	exec(t, c, `INSERT INTO identities (id, idp_id, scope, subject, email) VALUES ($1, $2, 'platform', 'sa-'||$3, 'sa@example.test')`,
		f.platformUser, f.platformIdP, f.sfx)
	exec(t, c, `INSERT INTO platform_users (identity_id, role_id) VALUES ($1, $2)`, f.platformUser, f.platformRole)
	for _, tr := range f.tenants() {
		exec(t, c, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
			VALUES ($1, 'tenant', $2, 'https://idp.test/realms/'||$3, 'portal', 'keycloak', 'active')`, tr.idp, tr.id, tr.slug)
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
