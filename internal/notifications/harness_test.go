package notifications

// PostgreSQL integration harness of internal/notifications: the tests of the package share ONE database
// (internal/store/storetest — database creation is serialised across every package of the run); every test gets two
// fresh tenants (A, B) — each with an Owner, an Admin, a Viewer, an End User (verified addresses) and an Admin whose
// address is NOT verified — and two fresh platform users (Super Admin with a verified address, Platform Viewer; the
// platform users of earlier tests are disabled); the api and worker stores; the real job framework delivering
// notification.send to the fake SMTP relay (smtptest) — River jobs left by earlier tests are deleted before a worker
// starts, so a test's relay only ever sees its own mail. Every assertion is scoped to the test's own tenants/addresses.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications/smtptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

type tenantFx struct {
	id, idp                                   uuid.UUID
	slug, name                                string
	owner, admin, viewer, endUser, unverified uuid.UUID
	email                                     map[uuid.UUID]string
}

type fixture struct {
	env   *storetest.Env
	db    string
	su    *pgx.Conn
	mu    sync.Mutex
	a, b  *tenantFx
	api   *store.Store
	wrk   *store.Store
	super string // the Super Admin's address
	n     int
}

// shared is the database of the package (created by the first test that needs it, dropped by storetest.Cleanup).
var shared struct {
	mu sync.Mutex
	db string
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	shared.mu.Lock()
	if shared.db == "" {
		shared.db = env.NewDatabase(t)
	}
	f := &fixture{env: env, db: shared.db}
	shared.mu.Unlock()
	f.su = env.Admin(t, f.db)
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	run := randomHex(5)
	pidp := uuid.New()
	f.exec(t, `UPDATE platform_users SET status = 'disabled'`) // only this test's platform staff receive platform mail
	f.exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', $2, 'mg-admin', 'keycloak', 'active')`, pidp, "https://idp.invalid/realms/platform-"+run)
	f.super = "super-" + run + "@platform.test"
	for _, p := range []struct{ sub, email, role string }{{"super", f.super, "super_admin"}, {"pv", "viewer-" + run + "@platform.test", "platform_viewer"}} {
		ident := uuid.New()
		f.exec(t, `INSERT INTO identities (id, idp_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, 'platform', $3, $4, true, $3)`, ident, pidp, p.sub, p.email)
		f.exec(t, `INSERT INTO platform_users (identity_id, role_id, status)
			SELECT $1, id, 'active' FROM roles WHERE scope = 'platform' AND key = $2`, ident, p.role)
	}
	f.api = env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 4)
	f.wrk = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 6)
	return f
}

func (f *fixture) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	f.n++
	ten := &tenantFx{id: uuid.New(), idp: uuid.New(), slug: "t" + randomHex(5) + fmt.Sprintf("%02d", f.n),
		email: map[uuid.UUID]string{}}
	ten.name = "Tenant " + ten.slug
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, ten.name)
	f.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, ten.idp, ten.id, "https://idp.invalid/realms/"+ten.slug)
	ten.owner = f.member(t, ten, "owner", "tenant_owner", true)
	ten.admin = f.member(t, ten, "admin", "tenant_admin", true)
	ten.viewer = f.member(t, ten, "viewer", "tenant_viewer", true)
	ten.endUser = f.member(t, ten, "eu", "end_user", true)
	ten.unverified = f.member(t, ten, "admin2", "tenant_admin", false)
	return ten
}

func (f *fixture) member(t *testing.T, ten *tenantFx, name, role string, verified bool) uuid.UUID {
	t.Helper()
	ident, m := uuid.New(), uuid.Nil
	email := name + "@" + ten.slug + ".test"
	f.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, $3, 'tenant', $4, $5, $6, $4)`, ident, ten.idp, ten.id, name+"-"+ten.slug, email, verified)
	f.scan(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
		SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3 RETURNING id`, []any{ten.id, ident, role}, &m)
	ten.email[m] = email
	return m
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

// enqueue runs Enqueue in a transaction of st: the tenant's for a tenant event, the platform's otherwise.
func (f *fixture) enqueue(t *testing.T, st *store.Store, ev Event) (Result, error) {
	t.Helper()
	var res Result
	fn := func(tx *store.Tx) error {
		var err error
		res, err = Enqueue(context.Background(), tx, ev)
		return err
	}
	var err error
	if ev.TenantID != nil {
		err = st.WithTenantJobTx(context.Background(), *ev.TenantID, fn)
	} else {
		err = st.WithPlatformJobTx(context.Background(), fn)
	}
	return res, err
}

// worker starts the job framework with the notification.send handler over mailer (nil = no relay), fast retries.
func (f *fixture) worker(t *testing.T, mailer Mailer, attempts int) {
	t.Helper()
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 50*time.Millisecond, 200*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	k := cfg.Kinds[JobKind]
	k.MaxAttempts = attempts
	cfg.Kinds[JobKind] = k
	f.exec(t, `DELETE FROM river.river_job`) // jobs left queued by earlier tests of the shared database never reach this relay
	w, err := jobs.NewWorker(f.wrk, cfg, jobs.Options{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(f.wrk, SenderConfig{Mailer: mailer, PortalURL: "https://app.mesh.test",
		ConsoleURL: "https://admin.mesh.test", MessageIDDomain: "mesh.test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(c)
	})
}

// relay is a STARTTLS fake relay and the mailer that trusts it.
func relay(t *testing.T) (*smtptest.Server, *SMTPMailer) {
	t.Helper()
	srv := smtptest.New(t, smtptest.Options{StartTLS: true})
	m, err := NewSMTPMailer(SMTPConfig{Addr: srv.Addr(), RootCAs: srv.Roots, From: "MeshGuard <no-reply@mesh.test>",
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return srv, m
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
