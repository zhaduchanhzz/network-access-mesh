package platform_test

// Integration tests of the platform administration of P4-T03a on a database of their own with the api roles: plan
// limits validated exactly as the CHECK of 0012, the system settings (closed set, ETag "0" for an absent key), and the
// execution of an approved Super Admin role change (the bootstrap lock, the approved version only, never zero Super
// Admins, sessions revoked).

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

type adminWorld struct {
	*world
	api *store.Store
	svc *platform.Service
	idp uuid.UUID
}

func newAdminWorld(t *testing.T) *adminWorld {
	t.Helper()
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	w := openWorld(t, pg, db, 4, platform.PlacerOptions{}, true)
	api := pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8)
	aw := &adminWorld{world: w, api: api, svc: platform.New(api), idp: uuid.Must(uuid.NewV7())}
	aw.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.invalid/realms/platform', 'mg-portal', 'keycloak', 'active')`, aw.idp)
	return aw
}

func (w *adminWorld) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.su.Exec(w.t.Context(), sql, args...); err != nil {
		w.t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

// staff inserts a platform identity with role and a live session; it returns identity and platform user.
func (w *adminWorld) staff(role string) (uuid.UUID, uuid.UUID) {
	w.t.Helper()
	ident, pu := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO identities (id, idp_id, scope, subject) VALUES ($1, $2, 'platform', $3)`, ident, w.idp, ident.String())
	w.exec(`INSERT INTO platform_users (id, identity_id, role_id) SELECT $1, $2, id FROM roles WHERE scope = 'platform' AND key = $3`,
		pu, ident, role)
	w.exec(`INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at)
		VALUES (sha256(uuid_send($1)), $2, $3, 'admin', now(), now() + interval '1 hour', now() + interval '8 hours')`,
		uuid.Must(uuid.NewV7()), ident, w.idp)
	return ident, pu
}

func (w *adminWorld) liveSessions(ident uuid.UUID) int {
	var n int
	if err := w.su.QueryRow(w.t.Context(), `SELECT count(*) FROM sessions WHERE identity_id = $1 AND revoked_at IS NULL`,
		ident).Scan(&n); err != nil {
		w.t.Fatal(err)
	}
	return n
}

// TestPlanLimitsParity — CheckPlanLimits is the mirror of mg_plan_limits_valid (0012), full and partial.
func TestPlanLimitsParity(t *testing.T) {
	w := newAdminWorld(t)
	quota := `"max_devices":1,"max_users":2,"max_tagged_devices":0,"max_live_enrollment_credentials":3`
	for _, doc := range []string{
		`{` + quota + `}`, `{` + quota + `,"backup_interval_minutes":60,"instance":{"cpus":0.5,"memory_mb":512,"pids":64}}`,
		`{"max_devices":1}`, `{}`, `[]`, `1`, `{` + quota + `,"extra":1}`, `{` + quota + `,"max_devices":-1}`,
		`{` + quota + `,"max_devices":2147483648}`, `{` + quota + `,"max_devices":1.5}`, `{` + quota + `,"max_devices":"1"}`,
		`{` + quota + `,"backup_interval_minutes":0}`, `{` + quota + `,"instance":{"cpus":0}}`,
		`{` + quota + `,"instance":{"cpus":1025}}`, `{` + quota + `,"instance":{"pids":0}}`, `{` + quota + `,"instance":{"gpu":1}}`,
		`{` + quota + `,"instance":[]}`, `{"max_users":0,"instance":{"memory_mb":1}}`, `{` + quota + `,"max_devices":null}`,
	} {
		for _, partial := range []bool{false, true} {
			var db bool
			if err := w.su.QueryRow(t.Context(), `SELECT mg_plan_limits_valid($1::jsonb, $2)`, doc, partial).Scan(&db); err != nil {
				t.Fatalf("%s: %v", doc, err)
			}
			if code := platform.CheckPlanLimits([]byte(doc), partial) == ""; code != db {
				t.Errorf("%s (partial %v): CheckPlanLimits valid=%v, CHECK valid=%v", doc, partial, code, db)
			}
		}
	}
}

// TestSystemSettings — the closed set, an absent key at ETag "0", stale ETag 412, read-only and cursor keys.
func TestSystemSettings(t *testing.T) {
	w := newAdminWorld(t)
	sa, _ := w.staff(platform.RoleSuperAdmin)
	ctx := audit.WithRequest(t.Context(), &audit.Request{Action: platform.ActionSettingUpdate, ActorType: audit.ActorIdentity,
		ActorIdentityID: &sa, RequestID: "t"})
	a := platform.Actor{IdentityID: sa, AuthTime: time.Now()}
	w.exec(`DELETE FROM system_settings WHERE key = 'approval.ttl_hours'`)
	s, err := w.svc.GetSetting(ctx, "approval.ttl_hours")
	if err != nil || s.Value != nil || s.ETag != `"0"` || string(s.Default) != "24" || !s.Writable {
		t.Fatalf("absent key: %+v, %v", s, err)
	}
	if _, err := w.svc.PutSetting(ctx, a, "approval.ttl_hours", []byte(`12`), `"1"`); !errors.Is(err, platform.ErrPreconditionFailed) {
		t.Fatalf("absent key with ETag 1: %v", err)
	}
	s, err = w.svc.PutSetting(ctx, a, "approval.ttl_hours", []byte(` 12 `), `"0"`)
	if err != nil || string(s.Value) != "12" || s.Version != 1 || s.UpdatedBy == nil || *s.UpdatedBy != sa {
		t.Fatalf("create: %+v, %v", s, err)
	}
	if _, err := w.svc.PutSetting(ctx, a, "approval.ttl_hours", []byte(`13`), `"0"`); !errors.Is(err, platform.ErrPreconditionFailed) {
		t.Fatalf("stale ETag: %v", err)
	}
	for _, bad := range []string{`0`, `169`, `"12"`, `12.0`, `1e1`, `null`} {
		if _, err := w.svc.PutSetting(ctx, a, "approval.ttl_hours", []byte(bad), s.ETag); !errors.Is(err, platform.ErrInvalid) {
			t.Errorf("value %s: %v", bad, err)
		}
	}
	if _, err := w.svc.PutSetting(ctx, a, "maintenance", []byte(`{}`), `"0"`); !errors.Is(err, platform.ErrInvalid) {
		t.Fatalf("read-only key: %v", err)
	}
	for _, k := range []string{"idp.audit_sync.admin.platform", "no.such"} {
		if _, err := w.svc.GetSetting(ctx, k); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("GET %s: %v", k, err)
		}
		if _, err := w.svc.PutSetting(ctx, a, k, []byte(`1`), `"0"`); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("PUT %s: %v", k, err)
		}
	}
	if _, err := w.svc.PutSetting(ctx, platform.Actor{IdentityID: sa, AuthTime: time.Now().Add(-time.Hour)}, "approval.ttl_hours",
		[]byte(`12`), s.ETag); !errors.Is(err, platform.ErrReauthRequired) {
		t.Fatalf("without step-up: %v", err)
	}
	l, err := w.svc.ListSettings(ctx)
	if err != nil || len(l) != 3 || l[0].Key != "approval.ttl_hours" {
		t.Fatalf("list: %+v, %v", l, err)
	}
}

// TestSuperAdminExecution — an approved Super Admin role change: the approved version only, never zero Super Admins,
// sessions revoked, and concurrent executions serialized by the bootstrap lock.
func TestSuperAdminExecution(t *testing.T) {
	w := newAdminWorld(t)
	sa1, pu1 := w.staff(platform.RoleSuperAdmin)
	v1, pv1 := w.staff(platform.RolePlatformViewer)
	ctx := audit.WithRequest(t.Context(), &audit.Request{Action: "platform.approval.approve", ActorType: audit.ActorIdentity,
		ActorIdentityID: &sa1, RequestID: "t"})
	run := func(p platform.SuperAdminPayload) error {
		return w.api.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			return w.svc.ExecuteSuperAdmin(ctx, q, platform.SuperAdminExecution{ApprovalID: uuid.New(), RequestedBy: sa1,
				DecidedBy: uuid.New()}, p)
		})
	}
	// the only Super Admin is never revoked
	p, err := w.svc.SuperAdminRequest(ctx, pu1, false, platform.RolePlatformViewer)
	if err != nil {
		t.Fatal(err)
	}
	var ae *platform.AdminError
	if err := run(p); !errors.As(err, &ae) || ae.Reason != platform.ReasonLastSuperAdmin {
		t.Fatalf("revoking the last Super Admin: %v", err)
	}
	// grant: refused at a stale version, then applied with the sessions revoked
	g, err := w.svc.SuperAdminRequest(ctx, pv1, true, "")
	if err != nil || g.RoleBefore != platform.RolePlatformViewer || g.IdentityID != v1 {
		t.Fatalf("grant payload: %+v, %v", g, err)
	}
	if _, err := w.svc.SuperAdminRequest(ctx, pv1, true, "x"); !errors.Is(err, platform.ErrInvalid) {
		t.Fatalf("role_after on a grant: %v", err)
	}
	stale := g
	stale.Version++
	if err := run(stale); !errors.As(err, &ae) || ae.Reason != platform.ReasonStale {
		t.Fatalf("stale grant: %v", err)
	}
	if err := run(g); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if n := w.liveSessions(v1); n != 0 {
		t.Fatalf("%d sessions of the new Super Admin survived", n)
	}
	if err := run(g); !errors.As(err, &ae) || ae.Reason != platform.ReasonStale {
		t.Fatalf("the same grant twice: %v", err)
	}
	if _, err := w.svc.SuperAdminRequest(ctx, pv1, true, ""); !errors.As(err, &ae) || ae.Reason != platform.ReasonState {
		t.Fatalf("grant to a Super Admin: %v", err)
	}
	// two revocations racing for the last two Super Admins: one applies, the other finds no Super Admin left
	r1, _ := w.svc.SuperAdminRequest(ctx, pu1, false, platform.RolePlatformViewer)
	r2, _ := w.svc.SuperAdminRequest(ctx, pv1, false, platform.RolePlatformOperator)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, p := range []platform.SuperAdminPayload{r1, r2} {
		wg.Go(func() { errs[i] = run(p) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if !errors.As(err, &ae) || ae.Reason != platform.ReasonLastSuperAdmin {
			t.Errorf("race: %v", err)
		}
	}
	var active int
	if err := w.su.QueryRow(t.Context(), `SELECT count(*) FROM platform_users pu JOIN roles r ON r.id = pu.role_id
		WHERE r.key = 'super_admin' AND pu.status = 'active'`).Scan(&active); err != nil || ok != 1 || active != 1 {
		t.Fatalf("race: %d applied, %d Super Admins left (%v)", ok, active, err)
	}
}
