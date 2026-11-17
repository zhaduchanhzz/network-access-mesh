package auditsync

// PostgreSQL integration tests of idp.audit_sync: the worker's store (mg_worker_tenant / mg_worker_platform) on a
// migrated database, a fake Keycloak (fakeSource) — the real Keycloak is exercised by the E2E cases E2E-40…43.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

const base = "https://auth.mg.test/realms/"

// fakeSource is the Keycloak of the tests: events per realm, oldest first, paged like the Admin API.
type fakeSource struct {
	mu        sync.Mutex
	admin     map[string][]keycloak.AdminEvent
	user      map[string][]keycloak.UserEvent
	config    map[string]keycloak.EventsConfig
	fail      map[string]error
	provErr   error
	adminRead int
}

func newSource() *fakeSource {
	return &fakeSource{admin: map[string][]keycloak.AdminEvent{}, user: map[string][]keycloak.UserEvent{},
		config: map[string]keycloak.EventsConfig{}, fail: map[string]error{}}
}

func page[T any](all []T, ms func(T) int64, q keycloak.EventQuery, keep func(T) bool) []T {
	var sel []T
	for _, e := range all {
		if ms(e) >= q.FromMillis && keep(e) {
			sel = append(sel, e)
		}
	}
	if q.First >= len(sel) {
		return nil
	}
	end := min(q.First+q.Max, len(sel))
	return sel[q.First:end]
}

func (f *fakeSource) AdminEvents(_ context.Context, realm string, q keycloak.EventQuery) ([]keycloak.AdminEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail[realm]; err != nil {
		return nil, err
	}
	f.adminRead++
	return page(f.admin[realm], func(e keycloak.AdminEvent) int64 { return e.Time }, q,
		func(keycloak.AdminEvent) bool { return true }), nil
}

func (f *fakeSource) UserEvents(_ context.Context, realm string, q keycloak.EventQuery) ([]keycloak.UserEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	types := map[string]bool{}
	for _, t := range q.Types {
		types[t] = true
	}
	return page(f.user[realm], func(e keycloak.UserEvent) int64 { return e.Time }, q,
		func(e keycloak.UserEvent) bool { return types[e.Type] }), nil
}

func (f *fakeSource) EventsConfig(_ context.Context, realm string) (keycloak.EventsConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail[realm]; err != nil {
		return keycloak.EventsConfig{}, err
	}
	if c, ok := f.config[realm]; ok {
		return c, nil
	}
	return keycloak.EventsConfig{EventsEnabled: true, AdminEventsEnabled: true, AdminEventsDetailsEnabled: true}, nil
}

func (f *fakeSource) ClientUUID(_ context.Context, _, _ string) (string, error) { return drvUUID, nil }

func (f *fakeSource) ProvisionerUserID(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return provUID, f.provErr
}

func (f *fakeSource) ProvisionerClientID() string { return "mg-provisioner" }

func (f *fakeSource) RealmOfIssuer(issuer string) (string, bool) {
	r, ok := strings.CutPrefix(issuer, base)
	return r, ok && r != "" && r != "master"
}

type fx struct {
	t       *testing.T
	su      *pgx.Conn
	st      *store.Store
	tenant  uuid.UUID
	tenantB uuid.UUID
	realm   string
	realmB  string
	plat    string
	target  uuid.UUID // identity of the member whose credential is reset
	now     time.Time
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newFx(t *testing.T) *fx {
	t.Helper()
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	f := &fx{t: t, su: env.Admin(t, db), tenant: uuid.New(), tenantB: uuid.New(), now: time.Now().UTC()}
	run := randomHex(4)
	f.realm, f.realmB, f.plat = "ta-"+run, "tb-"+run, "platform-"+run
	idpA, idpB, pidp := uuid.New(), uuid.New(), uuid.New()
	f.exec(`UPDATE platform_users SET status = 'disabled'`)
	for _, x := range []struct {
		id, idp uuid.UUID
		realm   string
	}{{f.tenant, idpA, f.realm}, {f.tenantB, idpB, f.realmB}} {
		f.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, x.id, x.realm, "Tenant "+x.realm)
		f.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
			VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, x.idp, x.id, base+x.realm)
		owner := uuid.New()
		f.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, $3, 'tenant', $4, $5, true, 'Owner')`, owner, x.idp, x.id, "owner-"+x.realm, "owner@"+x.realm+".test")
		f.exec(`INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
			SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'tenant_owner'`, x.id, owner)
	}
	f.target = uuid.New()
	f.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, $3, 'tenant', $4, 'alice@a.test', true, 'Alice Target')`, f.target, idpA, f.tenant, userID)
	f.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', $2, 'mg-portal', 'keycloak', 'active')`, pidp, base+f.plat)
	sa := uuid.New()
	f.exec(`INSERT INTO identities (id, idp_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, 'platform', 'sa', $3, true, 'SA')`, sa, pidp, "sa-"+run+"@platform.test")
	f.exec(`INSERT INTO platform_users (identity_id, role_id, status)
		SELECT $1, id, 'active' FROM roles WHERE scope = 'platform' AND key = 'super_admin'`, sa)
	f.st = env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 6)
	return f
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.su.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return n
}

func (f *fx) syncer(src Source, pageSize int) *Syncer {
	f.t.Helper()
	s, err := New(f.st, Config{Source: src, PageSize: pageSize, Now: func() time.Time { return f.now }})
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// at is an event time (ms) a few minutes ago.
func (f *fx) at(minutesAgo int) int64 {
	return f.now.Add(-time.Duration(minutesAgo) * time.Minute).UnixMilli()
}

func (f *fx) events(src *fakeSource) {
	ev := func(id string, ms int64, op, typ, path, rep string, by keycloak.AuthDetails) keycloak.AdminEvent {
		return keycloak.AdminEvent{ID: id, Time: ms, RealmID: realmID, AuthDetails: by, OperationType: op,
			ResourceType: typ, ResourcePath: path, Representation: rep}
	}
	src.admin[f.realm] = []keycloak.AdminEvent{
		ev("a1", f.at(10), "CREATE", "USER", "users/"+userID, `{"username":"alice"}`, byDriver),
		ev("a2", f.at(9), "ACTION", "USER", "users/"+userID+"/reset-password", "", byMaster),
		ev("a3", f.at(9), "UPDATE", "CLIENT", "clients/"+drvUUID, `{"clientId":"mg-portal","secret":"`+canary+`"}`, byProv),
		ev("a4", f.at(8), "CREATE", "CLIENT_ROLE_MAPPING", "users/"+userID+"/role-mappings/clients/x", `[{"name":"manage-users"}]`, byMaster),
		ev("a5", f.at(7), "ACTION", "USER", "users/"+userID+"/logout", "", byDriver),
	}
	src.user[f.realm] = []keycloak.UserEvent{{ID: "i1", Time: f.at(6), Type: "IMPERSONATE", RealmID: realmID, UserID: userID,
		Details: map[string]string{"impersonator": "admin"}}}
	src.admin[f.plat] = []keycloak.AdminEvent{
		ev("p1", f.at(5), "ACTION", "USER", "users/"+adminUID+"/reset-password", "", byMaster)}
	src.user["master"] = []keycloak.UserEvent{
		{ID: "m1", Time: f.at(4), Type: "CLIENT_LOGIN", ClientID: "mg-provisioner", UserID: provUID},
		{ID: "m2", Time: f.at(3), Type: "LOGIN_ERROR", ClientID: "security-admin-console", UserID: adminUID,
			IPAddress: "10.230.0.1", Error: "invalid_user_credentials", Details: map[string]string{"username": "mg-bootstrap-admin"}},
		{ID: "m3", Time: f.at(2), Type: "LOGIN", ClientID: "security-admin-console", UserID: adminUID, IPAddress: "10.230.0.1",
			Details: map[string]string{"username": "mg-bootstrap-admin", "code_id": canary}},
	}
}

// TestSyncImportsOnce: a tenant realm's admin events become the tenant's audit rows (credential reset with the member
// it concerns), its Owners' notifications (not for the driver's routine invitation/logout) and tenant security events;
// the platform realm and the master realm become platform rows; a console login is a high security event and a
// notification to the platform staff; nothing holds the client secret; a second run — and a run with the cursors
// erased — imports nothing again.
func TestSyncImportsOnce(t *testing.T) {
	f := newFx(t)
	src := newSource()
	f.events(src)
	s := f.syncer(src, 2) // pages of 2: the paging of the Admin API is exercised
	sum, err := s.RunOnce(t.Context())
	if err != nil || sum.Skipped || len(sum.Failed) != 0 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	// 5 admin events + 1 impersonation of tenant A, 1 of the platform realm, 2 console logins (m1 skipped)
	if sum.Imported != 9 {
		t.Errorf("imported %d, want 9", sum.Imported)
	}
	tenantRows := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action LIKE 'idp.%' AND actor_type = 'system'`, f.tenant)
	if tenantRows != 6 {
		t.Errorf("tenant audit rows %d, want 6", tenantRows)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'idp.user.credential_reset'
		AND resource_id = $2 AND details ->> 'identity_id' = $3 AND details ->> 'idp_actor_kind' = 'idp_admin'
		AND actor_ip = '10.0.0.7' AND occurred_at = $4`, f.tenant, userID, f.target.String(),
		time.UnixMilli(f.at(9)).UTC()); n != 1 {
		t.Errorf("credential reset row: %d", n)
	}
	// Owners: credential reset, client update, role grant, impersonation (sensitive) — not the driver's create/logout
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'idp.admin_change'`, f.tenant); n != 4 {
		t.Errorf("owner notifications %d, want 4", n)
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'idp.admin_change'
		AND payload ->> 'action' = 'idp.user.credential_reset' AND payload ->> 'user' = 'Alice Target'
		AND recipient_email = $2`, f.tenant, "owner@"+f.realm+".test"); n != 1 {
		t.Errorf("credential reset notification to the Owner: %d", n)
	}
	for kind, want := range map[string]string{KindCredentialReset: "high", KindImpersonation: "critical"} {
		if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2 AND severity = $3`,
			f.tenant, kind, want); n != 1 {
			t.Errorf("tenant security event %s: %d", kind, n)
		}
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action LIKE 'idp.%'`); n != 3 {
		t.Errorf("platform audit rows %d, want 3 (platform realm reset, 2 console logins)", n)
	}
	for kind, want := range map[string]string{KindConsoleLogin: "high", KindConsoleLoginFailed: "medium", KindCredentialReset: "high"} {
		if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id IS NULL AND kind = $1 AND severity = $2`,
			kind, want); n != 1 {
			t.Errorf("platform security event %s: %d", kind, n)
		}
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id IS NULL AND kind = 'idp.console_login'
		AND payload ->> 'client' = 'security-admin-console' AND payload ->> 'ip' = '10.230.0.1'`); n != 1 {
		t.Errorf("console login notification: %d", n)
	}
	leaks := f.count(`SELECT count(*) FROM (SELECT details::text x FROM audit_events UNION ALL SELECT details::text FROM
		security_events UNION ALL SELECT payload::text FROM notification_outbox) t WHERE strpos(x, $1) > 0`, canary)
	if leaks != 0 {
		t.Errorf("the representation's secret reached %d rows", leaks)
	}
	if n := f.count(`SELECT count(*) FROM system_settings WHERE key LIKE 'idp.audit_sync.%'`); n == 0 {
		t.Error("no cursor saved")
	}
	total := func() int {
		return f.count(`SELECT (SELECT count(*) FROM audit_events WHERE action LIKE 'idp.%') +
			(SELECT count(*) FROM security_events WHERE source = 'idp.audit_sync') +
			(SELECT count(*) FROM notification_outbox WHERE kind LIKE 'idp.%')`)
	}
	before := total()
	if sum, err := s.RunOnce(t.Context()); err != nil || sum.Imported != 0 {
		t.Errorf("second run: %+v %v", sum, err)
	}
	f.exec(`DELETE FROM system_settings WHERE key LIKE 'idp.audit_sync.%'`) // a lost cursor never duplicates an event
	if sum, err := s.RunOnce(t.Context()); err != nil || sum.Imported != 0 {
		t.Errorf("run without cursor: %+v %v", sum, err)
	}
	if after := total(); after != before {
		t.Errorf("rows %d → %d after re-runs", before, after)
	}
	// a new event after the cursor is imported
	src.mu.Lock()
	src.admin[f.realm] = append(src.admin[f.realm], keycloak.AdminEvent{ID: "a6", Time: f.at(1), RealmID: realmID,
		AuthDetails: byMaster, OperationType: "DELETE", ResourceType: "USER", ResourcePath: "users/" + userID})
	src.mu.Unlock()
	if sum, err := s.RunOnce(t.Context()); err != nil || sum.Imported != 1 {
		t.Errorf("new event: %+v %v", sum, err)
	}
}

// TestSyncConcurrentRuns: the periodic job and `admin idp-audit-sync` may overlap (two processes): each event is
// imported once.
func TestSyncConcurrentRuns(t *testing.T) {
	f := newFx(t)
	src := newSource()
	f.events(src)
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.syncer(src, 1).RunOnce(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action LIKE 'idp.%'`); n != 9 {
		t.Errorf("audit rows %d after concurrent runs, want 9", n)
	}
	if n := f.count(`SELECT count(*) FROM (SELECT details ->> 'idp_event_id' FROM audit_events WHERE action LIKE 'idp.%'
		GROUP BY 1 HAVING count(*) > 1) d`); n != 0 {
		t.Errorf("%d events imported twice", n)
	}
}

// TestSyncFailuresAndGaps: a realm that cannot be read is skipped with a security event, the others are read; a realm
// whose events are off raises idp.audit_events_disabled; nothing happens before the provisioning identity exists.
func TestSyncFailuresAndGaps(t *testing.T) {
	f := newFx(t)
	src := newSource()
	f.events(src)
	src.fail[f.realmB] = idp.NewError(idp.CodeForbidden, "keycloak.EventsConfig", "http_403", nil)
	src.config[f.realm] = keycloak.EventsConfig{EventsEnabled: true, AdminEventsEnabled: false}
	s := f.syncer(src, 100)
	sum, err := s.RunOnce(t.Context())
	if err != nil || len(sum.Failed) != 1 || sum.Failed[0] != f.realmB || sum.Imported != 9 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id IS NULL AND kind = $1 AND details ->> 'realm' = $2`,
		KindAuditSyncFailed, f.realmB); n != 1 {
		t.Errorf("sync failure event: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2 AND severity = 'high'`,
		f.tenant, KindAuditDisabled); n != 1 {
		t.Errorf("audit disabled event: %d", n)
	}
	if _, err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE kind IN ($1, $2)`, KindAuditSyncFailed, KindAuditDisabled); n != 2 {
		t.Errorf("gap events not deduplicated: %d", n)
	}
	// not bootstrapped: nothing read, nothing written
	g := newSource()
	f.events(g)
	g.provErr = idp.NewError(idp.CodeCredentials, "keycloak.ProvisionerUserID", "secret_store", nil)
	sum, err = f.syncer(g, 100).RunOnce(t.Context())
	if err != nil || !sum.Skipped || g.adminRead != 0 {
		t.Errorf("not bootstrapped: %+v %v (admin reads %d)", sum, err, g.adminRead)
	}
}
