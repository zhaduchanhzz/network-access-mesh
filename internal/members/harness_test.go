package members

// PostgreSQL integration harness of internal/members: one database per test (storetest), two tenants with a running
// instance each behind its own fake Headscale (devicestest, reached through the real adapter), members of every
// tenant role, the real membership guard (authz.GuardMembershipChange) and IdP drivers that record their calls.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// fakeIdP is an IdP driver recording DisableUser and InviteUser; err makes the next calls fail.
type fakeIdP struct {
	name              string
	mu                sync.Mutex
	disabled, invited []string
	err               error
}

func (d *fakeIdP) Name() string { return d.name }
func (*fakeIdP) EnsureIssuer(context.Context, idp.IssuerSpec) (idp.IssuerResult, error) {
	return idp.IssuerResult{}, nil
}
func (*fakeIdP) EnsureClient(context.Context, idp.ClientSpec) (idp.ClientResult, error) {
	return idp.ClientResult{}, nil
}
func (d *fakeIdP) InviteUser(_ context.Context, _ idp.Registration, inv idp.Invite) (idp.InviteResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.name == idp.DriverExternal {
		return idp.InviteResult{}, idp.NewError(idp.CodeUnsupported, "external.InviteUser", "tenant_managed_idp", nil)
	}
	if d.err != nil {
		return idp.InviteResult{Created: true}, d.err
	}
	d.invited = append(d.invited, inv.Email)
	return idp.InviteResult{Subject: uuid.NewString(), Created: true, EmailSent: inv.SendEmail}, nil
}
func (d *fakeIdP) DisableUser(_ context.Context, _ idp.Registration, subject string) (idp.DisableResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.name == idp.DriverExternal {
		return idp.DisableResult{}, idp.NewError(idp.CodeUnsupported, "external.DisableUser", "tenant_managed_idp", nil)
	}
	if d.err != nil {
		return idp.DisableResult{}, d.err
	}
	d.disabled = append(d.disabled, subject)
	return idp.DisableResult{Subject: subject, Found: true, SessionsRevoked: true}, nil
}
func (*fakeIdP) RemoveIssuer(context.Context, idp.Registration, idp.RemoveMode) (idp.RemoveResult, error) {
	return idp.RemoveResult{}, nil
}
func (*fakeIdP) CheckDiscovery(context.Context, idp.Registration) (idp.Discovery, error) {
	return idp.Discovery{}, nil
}

// person is a member of a fixture tenant.
type person struct {
	membership, identity uuid.UUID
	subject, role        string
	hsUser               uint64
}

func (p person) username() string { return "mg-" + p.membership.String() }

type tenantFx struct {
	id, instance, idp uuid.UUID
	slug              string
	hs                *devicestest.Fake
	people            map[string]person // "owner", "admin", "admin2", "operator", "viewer", "user", "user2"
}

type fixture struct {
	env      *storetest.Env
	db       string
	su       *pgx.Conn
	mu       sync.Mutex
	a, b     *tenantFx
	host     uuid.UUID
	kc, ext  *fakeIdP
	api, wrk *Service
	apiSt    *store.Store
	wrkSt    *store.Store
	n        int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	f := &fixture{env: env, db: env.NewDatabase(t), host: uuid.New(), kc: &fakeIdP{name: idp.DriverKeycloak},
		ext: &fakeIdP{name: idp.DriverExternal}}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	reg := devicestest.Registry(map[uuid.UUID]headscale.Target{
		f.a.id: f.a.hs.Target(f.a.instance), f.b.id: f.b.hs.Target(f.b.instance)})
	drivers, err := idp.NewRegistry(f.kc, f.ext)
	if err != nil {
		t.Fatal(err)
	}
	f.apiSt = env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 6)
	f.wrkSt = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 6)
	guard := func(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, c Change) error {
		return authz.GuardMembershipChange(ctx, q, tenantID, authz.MembershipChange{Actor: c.Actor, Target: c.Target,
			NewRole: c.NewRole, Deactivate: c.Deactivate, OwnershipTransfer: c.OwnershipTransfer})
	}
	if f.api, err = New(f.apiSt, Config{Tenants: tenants.New(f.apiSt, tenants.Options{}), Guard: guard}); err != nil {
		t.Fatal(err)
	}
	if f.wrk, err = New(f.wrkSt, Config{Tenants: tenants.New(f.wrkSt, tenants.Options{}), Headscale: reg, IdP: drivers}); err != nil {
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
	for n, who := range []struct{ name, role string }{{"owner", RoleOwner}, {"admin", RoleAdmin}, {"admin2", RoleAdmin},
		{"operator", RoleOperator}, {"viewer", RoleViewer}, {"user", RoleEndUser}, {"user2", RoleEndUser}} {
		p := person{identity: uuid.New(), subject: uuid.NewString(), role: who.role, hsUser: uint64(10 + n)} //nolint:gosec // small
		f.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, p.identity, ten.idp, ten.id, p.subject,
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

// session inserts a live Portal session of an identity.
func (f *fixture) session(t *testing.T, ten *tenantFx, p person) {
	t.Helper()
	h := make([]byte, 32)
	_, _ = rand.Read(h)
	f.exec(t, `INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, 'app', now(), now() + interval '30 minutes', now() + interval '12 hours')`, h, p.identity, ten.idp)
}

func (f *fixture) liveSessions(t *testing.T, p person) int {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM sessions WHERE identity_id = $1 AND revoked_at IS NULL`, p.identity)
}

// actor is the caller of an operation (its session was a fresh login: auth_time now).
func (ten *tenantFx) actor(name string) Actor {
	p := ten.people[name]
	return Actor{IdentityID: p.identity, MembershipID: p.membership, Display: name, AuthTime: time.Now()}
}

// ctxOf is the audit scope of a request of the actor (what the audit middleware sets).
func ctxOf(a Actor, tenant uuid.UUID, action string) context.Context {
	id, ten := a.IdentityID, tenant
	return audit.WithRequest(context.Background(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &id, ActorTenantID: &ten, TenantID: &ten, ResourceType: "membership", RequestID: "req-" + action})
}

// run is the jobs.Run a worker hands to a handler for one attempt of job id.
func (f *fixture) run(t *testing.T, id uuid.UUID, attempt, maxAttempts int) *jobs.Run {
	t.Helper()
	var j sqlcdb.ProvisioningJob
	if err := f.wrkSt.WithPlatformTx(context.Background(), func(q *sqlcdb.Queries) error {
		var err error
		j, err = q.GetJob(context.Background(), id)
		return err
	}); err != nil {
		t.Fatalf("job %s: %v", id, err)
	}
	return &jobs.Run{ID: j.ID, Kind: j.Kind, TenantID: j.TenantID, InstanceID: j.InstanceID, Input: json.RawMessage(j.Input),
		Attempt: attempt, MaxAttempts: maxAttempts, Deadline: time.Now().Add(time.Minute), Store: f.wrkSt}
}

func (f *fixture) finishJob(t *testing.T, id uuid.UUID, status string) {
	t.Helper()
	f.exec(t, `UPDATE provisioning_jobs SET status = $2, finished_at = now() WHERE id = $1`, id, status)
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

// denialReason is the reason of an authz denial (the guard's refusals), "" for anything else.
func denialReason(err error) string {
	var d *authz.Denial
	if errors.As(err, &d) {
		return d.Reason
	}
	return ""
}

func reasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return denialReason(err)
}
