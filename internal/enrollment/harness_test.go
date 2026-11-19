package enrollment

// PostgreSQL integration harness of internal/enrollment: one database per test (storetest), two tenants with a running
// instance each behind its own fake Headscale (devicestest, reached through the real adapter), members of every tenant
// role, a live subscription of the standard plan, the tag catalog's real RequireTags as TagGate and an in-memory Vault
// with expiry; the api service runs on the api roles, the worker service (reconcile) on the worker roles, both on a
// clock the test moves.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// clock is the time of both services; tests move it.
type clock struct {
	mu sync.Mutex
	d  time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.d)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.d += d
}

// memVault is a Vault in memory with the expiry semantics of the SecretStore.
type memVault struct {
	mu   sync.Mutex
	clk  *clock
	vals map[string]struct {
		tenant uuid.UUID
		v      []byte
		exp    time.Time
	}
}

func (v *memVault) Keep(_ context.Context, tenantID uuid.UUID, value []byte, expires time.Time) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	ref := "mgsec://" + tenantID.String() + "/enrollment-credential." + uuid.NewString() + "#1"
	v.vals[ref] = struct {
		tenant uuid.UUID
		v      []byte
		exp    time.Time
	}{tenantID, append([]byte(nil), value...), expires}
	return ref, nil
}

func (v *memVault) Recall(_ context.Context, tenantID uuid.UUID, ref string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	x, ok := v.vals[ref]
	if !ok || x.tenant != tenantID || !v.clk.now().Before(x.exp) {
		return nil, ErrSecretGone
	}
	return append([]byte(nil), x.v...), nil
}

type person struct {
	membership, identity uuid.UUID
	role                 string
}

func (p person) username() string { return "mg-" + p.membership.String() }

type tenantFx struct {
	id, instance, idp uuid.UUID
	slug              string
	hs                *devicestest.Fake
	people            map[string]person
}

type fixture struct {
	env      *storetest.Env
	db       string
	su       *pgx.Conn
	mu       sync.Mutex
	a, b     *tenantFx
	host     uuid.UUID
	clk      *clock
	vault    *memVault
	api, wrk *Service
	apiSt    *store.Store
	wrkSt    *store.Store
	n        int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	clk := &clock{}
	f := &fixture{env: env, db: env.NewDatabase(t), host: uuid.New(), clk: clk}
	f.vault = &memVault{clk: clk, vals: map[string]struct {
		tenant uuid.UUID
		v      []byte
		exp    time.Time
	}{}}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.exec(t, `INSERT INTO subscription_plans (key, name, limits) VALUES ('standard', 'Standard',
		'{"max_devices": 100, "max_users": 100, "max_tagged_devices": 25, "max_live_enrollment_credentials": 25}')
		ON CONFLICT (key) DO NOTHING`)
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	reg := devicestest.Registry(map[uuid.UUID]headscale.Target{
		f.a.id: f.a.hs.Target(f.a.instance), f.b.id: f.b.hs.Target(f.b.instance)})
	f.apiSt = env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 8)
	f.wrkSt = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 6)
	var err error
	if f.api, err = New(f.apiSt, Config{Registry: reg, Vault: f.vault, Tags: policies.RequireTags, Now: clk.now,
		ClaimsPerMinute: 100}); err != nil {
		t.Fatal(err)
	}
	if f.wrk, err = New(f.wrkSt, Config{Registry: reg, Now: clk.now}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	f.n++
	i := f.n
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), idp: uuid.New(), slug: fmt.Sprintf("tenant%02d", i),
		people: map[string]person{}}
	ten.hs = devicestest.New(t, ten.slug)
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		ten.instance, ten.id, f.host, ten.slug+".mesh.test", ten.slug+".ts.test", "hs-"+ten.slug+":8080", 30000+i,
		fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+ten.instance.String())
	f.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, driver_ref, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', $4, 'active')`, ten.idp, ten.id,
		"https://idp.invalid/realms/"+ten.slug, ten.slug)
	f.exec(t, `INSERT INTO subscriptions (tenant_id, plan_id) SELECT $1, id FROM subscription_plans WHERE key = 'standard'`, ten.id)
	f.exec(t, `INSERT INTO tenant_tags (tenant_id, name, purpose) VALUES ($1, 'tag:server', 'server')`, ten.id)
	for _, who := range []struct{ name, role string }{{"owner", "tenant_owner"}, {"admin", "tenant_admin"},
		{"operator", "tenant_operator"}, {"viewer", "tenant_viewer"}, {"user", "end_user"}, {"user2", "end_user"}} {
		p := person{identity: uuid.New(), role: who.role}
		f.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, p.identity, ten.idp, ten.id, uuid.NewString(),
			who.name+"@"+ten.slug+".test", who.name)
		f.scan(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
			SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3 RETURNING id`,
			[]any{ten.id, p.identity, who.role}, &p.membership)
		ten.people[who.name] = p
	}
	return ten
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.su.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (f *fixture) scan(t *testing.T, sql string, args []any, dest ...any) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(dest...); err != nil {
		t.Fatalf("superuser query: %v\n%s", err, sql)
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	f.scan(t, sql, args, &n)
	return n
}

func (f *fixture) str(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	f.scan(t, sql, args, &s)
	return s
}

// setting writes one key of TenantSettings.enrollment (or a top-level path) directly (PUT /settings/security is
// P4-T03a's; this module only reads it).
func (f *fixture) setting(t *testing.T, ten *tenantFx, path string, value string) {
	t.Helper()
	f.exec(t, `UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb) ||
		jsonb_build_object('enrollment', COALESCE(settings->'enrollment', '{}'::jsonb)), $2::text[], $3::jsonb, true)
		WHERE id = $1`, ten.id, "{"+path+"}", value)
}

// actor is a caller of the tenant: session s; own-only and self-enroll obligations as the authorizer decides them for
// the role (End User: own on read/revoke, conditional on request); TO/TA/TP may approve.
func (ten *tenantFx) actor(name string, session uuid.UUID) Actor {
	p := ten.people[name]
	a := Actor{IdentityID: p.identity, MembershipID: p.membership, Display: name, SessionID: session}
	switch p.role {
	case "end_user":
		a.OwnOnly, a.SelfEnrollOnly = true, true
	case "tenant_owner", "tenant_admin", "tenant_operator":
		a.CanApprove = true
	}
	return a
}

// ctxOf is the audit scope of a request of the actor (what the audit middleware sets).
func ctxOf(a Actor, tenant uuid.UUID, action string) context.Context {
	id, ten := a.IdentityID, tenant
	return audit.WithRequest(context.Background(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &id, ActorTenantID: &ten, TenantID: &ten, ResourceType: "enrollment_request",
		RequestID: "req-" + action})
}

func codeOf(err error) string {
	if e, ok := AsError(err); ok {
		return e.Code
	}
	var q interface{ QuotaResource() string }
	if errors.As(err, &q) {
		return "quota_exceeded:" + q.QuotaResource()
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func reasonOf(err error) string {
	if e, ok := AsError(err); ok {
		return e.Reason
	}
	return ""
}

// auditOf lists action/outcome of the events of a resource, oldest first.
func (f *fixture) auditOf(t *testing.T, resource string) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	rows, err := f.su.Query(context.Background(), `SELECT action || '/' || outcome FROM audit_events WHERE resource_id = $1
		ORDER BY occurred_at, id`, resource)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// noKeyMaterial fails when a table of the platform holds the shape of a Headscale key (§13.1, P4-T06 §20: no hskey- in
// the tables after the operations).
func (f *fixture) noKeyMaterial(t *testing.T) {
	t.Helper()
	for _, tbl := range []string{"enrollment_requests", "idempotency_keys", "audit_events", "security_events",
		"provisioning_jobs", "notification_outbox", "device_inventory_cache"} {
		if n := f.count(t, `SELECT count(*) FROM `+tbl+` x WHERE x::text LIKE '%hskey-%'`); n != 0 {
			t.Errorf("%s: %d row(s) hold hskey- material", tbl, n)
		}
	}
}

func joined(s []string) string { return strings.Join(s, ",") }
