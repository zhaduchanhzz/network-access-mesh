package approvals_test

// PostgreSQL tests of dual control (P3-T04a) on a migrated database (internal/store/storetest: MG_TEST_PG_ADMIN_URL,
// MG_TEST_PG_REQUIRED=1 in CI), the api roles, the real Authorizer and real jobs. Verification of §20: self-approval
// ⇒ 403; expired ⇒ not executed; payload changed after approval ⇒ refused; the approver sees exactly the payload that
// runs (backup_id of a restore); an executed request is not reused; the audit names both persons; tenant scope:
// another tenant's request is not found.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// clock is the service clock of a test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// execLog records what the test actions received; failNext makes the next execution fail (transient error).
type execLog struct {
	mu       sync.Mutex
	payloads []json.RawMessage
	failNext bool
}

func (l *execLog) record(p json.RawMessage) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.payloads = append(l.payloads, append(json.RawMessage(nil), p...))
	if l.failNext {
		l.failNext = false
		return errors.New("test: transient failure of the action")
	}
	return nil
}

func (l *execLog) count() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.payloads) }

// Test actions: a restore-like action of the platform (Platform Operators decide it — restore_only), a delete-like
// one (Super Admins only) and a tenant action needing tenant.settings:update_security (Tenant Owners only).
type restorePayload struct {
	BackupID   string `json:"backup_id"`
	InstanceID string `json:"instance_id"`
}

func (p restorePayload) Validate() error {
	if _, err := uuid.Parse(p.BackupID); err != nil {
		return err
	}
	_, err := uuid.Parse(p.InstanceID)
	return err
}

type deletePayload struct {
	TenantID string `json:"tenant_id"`
}

type fourEyesPayload struct {
	Setting string `json:"setting"`
}

const (
	actRestore  = "platform.test_restore"
	actDelete   = "platform.test_delete"
	actFourEyes = "tenant.test_four_eyes_off"
)

func registry(t *testing.T, log *execLog) *approvals.Registry {
	t.Helper()
	platformJob := func(ctx context.Context, tx *store.Tx, e approvals.Execution) (*uuid.UUID, error) {
		if err := log.record(e.Payload); err != nil {
			return nil, err
		}
		enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: "partition.maintain", Slot: e.Request.ID.String(),
			Input: map[string]any{"approval_id": e.Request.ID.String()}})
		if err != nil {
			return nil, err
		}
		return &enq.Job.ID, nil
	}
	r, err := approvals.NewRegistry(
		approvals.Typed(approvals.Spec{Name: actRestore, Scope: authz.ScopePlatform, ResourceType: "instance",
			Permission: "platform.instance:restore", DecideConditions: []string{authz.CondRestoreOnly}},
			func(ctx context.Context, tx *store.Tx, e approvals.Execution, _ restorePayload) (*uuid.UUID, error) {
				return platformJob(ctx, tx, e)
			}),
		approvals.Typed(approvals.Spec{Name: actDelete, Scope: authz.ScopePlatform, ResourceType: "tenant",
			Permission: "platform.tenant:delete"},
			func(ctx context.Context, tx *store.Tx, e approvals.Execution, _ deletePayload) (*uuid.UUID, error) {
				return platformJob(ctx, tx, e)
			}),
		approvals.Typed(approvals.Spec{Name: actFourEyes, Scope: authz.ScopeTenant, ResourceType: "settings",
			Permission: "tenant.settings:update_security"},
			func(ctx context.Context, tx *store.Tx, e approvals.Execution, _ fourEyesPayload) (*uuid.UUID, error) {
				if err := log.record(e.Payload); err != nil {
					return nil, err
				}
				enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: "policy.apply", TenantID: e.Request.TenantID})
				if err != nil {
					return nil, err
				}
				return &enq.Job.ID, nil
			}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// world is a migrated database with a platform IdP, platform users and tenants.
type world struct {
	t     *testing.T
	pg    *storetest.Env
	db    string
	su    *pgx.Conn
	st    *store.Store
	clock *clock
	log   *execLog
	svc   *approvals.Service
	pidp  uuid.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	w := &world{t: t, pg: pg, db: db, su: pg.Admin(t, db), st: pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8),
		clock: &clock{t: time.Now().UTC().Truncate(time.Second)}, log: &execLog{}, pidp: uuid.Must(uuid.NewV7())}
	w.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.invalid/realms/platform', 'mg-portal', 'keycloak', 'active')`, w.pidp)
	logger, err := audit.New(w.st, pg.OpenAuditWriter(t, db), audit.Config{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	w.svc, err = approvals.New(w.st, approvals.Config{Approvers: authz.New(w.st), Registry: registry(t, w.log),
		Security: logger, Now: w.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.su.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatalf("%v\n%s", err, sql)
	}
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		w.t.Fatalf("%v\n%s", err, sql)
	}
	return n
}

func (w *world) roleID(scope, key string) uuid.UUID {
	w.t.Helper()
	var id uuid.UUID
	if err := w.su.QueryRow(context.Background(), `SELECT id FROM roles WHERE scope = $1 AND key = $2`, scope, key).Scan(&id); err != nil {
		w.t.Fatal(err)
	}
	return id
}

// staff creates a platform identity holding role; the actor is freshly stepped up.
func (w *world) staff(role string) approvals.Actor {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO identities (id, idp_id, scope, subject, display_name) VALUES ($1, $2, 'platform', $3, $4)`,
		id, w.pidp, "sub-"+id.String(), role+" "+id.String()[:8])
	w.exec(`INSERT INTO platform_users (identity_id, role_id) VALUES ($1, $2)`, id, w.roleID("platform", role))
	a := approvals.Actor{IdentityID: id, Scope: authz.ScopePlatform, AuthTime: w.clock.Now()}
	if role == authz.RolePlatformOperator {
		a.Condition = authz.CondRestoreOnly // the condition of the PO's :decide grant, as layer 1 hands it over
	}
	return a
}

type tenantFix struct{ id, idp uuid.UUID }

func (w *world) tenant() tenantFix {
	w.t.Helper()
	f := tenantFix{id: uuid.Must(uuid.NewV7()), idp: uuid.Must(uuid.NewV7())}
	w.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, 'T', 'active')`, f.id, "t-"+f.id.String()[24:])
	w.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, f.idp, f.id, "https://idp.invalid/realms/"+f.id.String())
	return f
}

// member creates an identity of the tenant holding role.
func (w *world) member(f tenantFix, role string) approvals.Actor {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', $4)`,
		id, f.idp, f.id, "sub-"+id.String())
	w.exec(`INSERT INTO tenant_memberships (tenant_id, identity_id, role_id) VALUES ($1, $2, $3)`, f.id, id, w.roleID("tenant", role))
	return approvals.Actor{IdentityID: id, Scope: authz.ScopeTenant, AuthTime: w.clock.Now()}
}

func fresh(a approvals.Actor, now time.Time) approvals.Actor { a.AuthTime = now; return a }

func wantErr(t *testing.T, what string, err, kind error, reason string) {
	t.Helper()
	var e *approvals.Error
	if !errors.As(err, &e) || !errors.Is(err, kind) || (reason != "" && e.Reason != reason) {
		t.Fatalf("%s: %v, want %v (%s)", what, err, kind, reason)
	}
}

func platformRef(id uuid.UUID) approvals.Ref {
	return approvals.Ref{Scope: authz.ScopePlatform, ID: id}
}

func (w *world) status(id uuid.UUID) string {
	w.t.Helper()
	var s string
	if err := w.su.QueryRow(context.Background(), `SELECT status FROM approval_requests WHERE id = $1`, id).Scan(&s); err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *world) restoreRequest(by approvals.Actor) approvals.Request {
	w.t.Helper()
	r, err := w.svc.Request(context.Background(), by, approvals.NewRequest{Action: actRestore, ResourceID: uuid.NewString(),
		Payload: restorePayload{BackupID: uuid.NewString(), InstanceID: uuid.NewString()}, Reason: "drill <restore> & check"})
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

// TestPlatformApprovalLifecycle — request (step-up), review (exact payload + hash), self-approval refused, stale
// step-up and a stale reviewed hash refused, approval by a second Super Admin executes once (job in the same
// transaction), the executed request cannot be used again, the audit names both persons.
func TestPlatformApprovalLifecycle(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sa1, sa2 := w.staff(authz.RoleSuperAdmin), w.staff(authz.RoleSuperAdmin)

	stale := sa1
	stale.AuthTime = w.clock.Now().Add(-16 * time.Minute)
	_, err := w.svc.Request(ctx, stale, approvals.NewRequest{Action: actRestore, Payload: restorePayload{}})
	wantErr(t, "request without step-up", err, approvals.ErrReauthRequired, approvals.ReasonStepUp)

	backup, instance := uuid.NewString(), uuid.NewString()
	req, err := w.svc.Request(ctx, sa1, approvals.NewRequest{Action: actRestore, ResourceID: instance,
		Payload: restorePayload{BackupID: backup, InstanceID: instance}, Reason: "restore after incident"})
	if err != nil {
		t.Fatal(err)
	}
	wantPayload := `{"backup_id":"` + backup + `","instance_id":"` + instance + `"}`
	if req.Status != approvals.StatusPending || string(req.Payload) != wantPayload ||
		req.PayloadSHA256 != approvals.Hash([]byte(wantPayload)) || !req.ExpiresAt.Equal(w.clock.Now().Add(24*time.Hour)) ||
		req.RequestedBy.IdentityID != sa1.IdentityID || approvals.Location(req) != "/api/v1/platform/approvals/"+req.ID.String() {
		t.Fatalf("request %+v", req)
	}
	_, err = w.svc.Request(ctx, sa1, approvals.NewRequest{Action: actRestore, ResourceID: instance,
		Payload: restorePayload{BackupID: uuid.NewString(), InstanceID: instance}})
	var open *approvals.Error
	if !errors.As(err, &open) || open.Reason != approvals.ReasonOpenRequest || open.Existing != req.ID {
		t.Fatalf("second open request: %v", err)
	}
	_, err = w.svc.Request(ctx, sa1, approvals.NewRequest{Action: actRestore, Payload: map[string]any{"backup_id": 1}})
	wantErr(t, "invalid payload", err, approvals.ErrInvalid, approvals.ReasonInvalidPayload)

	// the approver reviews: the payload that will run, as stored
	seen, err := w.svc.Get(ctx, platformRef(req.ID))
	if err != nil || string(seen.Payload) != wantPayload || seen.PayloadSHA256 != req.PayloadSHA256 {
		t.Fatalf("review %+v %v", seen, err)
	}

	_, err = w.svc.Approve(ctx, sa1, platformRef(req.ID), req.PayloadSHA256)
	wantErr(t, "self-approval", err, approvals.ErrForbidden, approvals.ReasonSelfDecision)
	if n := w.count(`SELECT count(*) FROM security_events WHERE kind = $1 AND details ->> 'approval_id' = $2`,
		approvals.KindSelfApproval, req.ID.String()); n != 1 {
		t.Fatalf("%d self-approval security events", n)
	}
	_, err = w.svc.Reject(ctx, sa1, platformRef(req.ID))
	wantErr(t, "self-rejection", err, approvals.ErrForbidden, approvals.ReasonSelfDecision)

	w.clock.Advance(20 * time.Minute) // sa2's session (auth_time at creation) is no longer a step-up
	_, err = w.svc.Approve(ctx, sa2, platformRef(req.ID), req.PayloadSHA256)
	wantErr(t, "approval without step-up", err, approvals.ErrReauthRequired, approvals.ReasonStepUp)
	sa2 = fresh(sa2, w.clock.Now())
	_, err = w.svc.Approve(ctx, sa2, platformRef(req.ID), approvals.Hash([]byte(`{"backup_id":"other"}`)))
	wantErr(t, "stale reviewed hash", err, approvals.ErrPayloadChanged, approvals.ReasonPayloadChanged)
	if w.status(req.ID) != approvals.StatusPending || w.log.count() != 0 {
		t.Fatal("a refused approval changed the request or ran the action")
	}

	done, err := w.svc.Approve(ctx, sa2, platformRef(req.ID), req.PayloadSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != approvals.StatusExecuted || done.JobID == nil || done.DecidedBy == nil ||
		done.DecidedBy.IdentityID != sa2.IdentityID || done.DecidedAt == nil {
		t.Fatalf("executed %+v", done)
	}
	if w.log.count() != 1 || string(w.log.payloads[0]) != wantPayload {
		t.Fatalf("the action ran %d times with %s, want once with the reviewed payload %s", w.log.count(),
			w.log.payloads, wantPayload)
	}
	if n := w.count(`SELECT count(*) FROM provisioning_jobs WHERE id = $1 AND kind = 'partition.maintain'`, *done.JobID); n != 1 {
		t.Fatalf("job of the execution: %d rows", n)
	}

	// executed is terminal: neither approve nor execute nor reject runs it again
	_, err = w.svc.Approve(ctx, sa2, platformRef(req.ID), req.PayloadSHA256)
	wantErr(t, "approve again", err, approvals.ErrConflict, approvals.ReasonExecuted)
	_, err = w.svc.Execute(ctx, sa2, platformRef(req.ID), req.PayloadSHA256)
	wantErr(t, "execute again", err, approvals.ErrConflict, approvals.ReasonExecuted)
	_, err = w.svc.Reject(ctx, w.staff(authz.RoleSuperAdmin), platformRef(req.ID))
	wantErr(t, "reject executed", err, approvals.ErrConflict, approvals.ReasonExecuted)
	if w.log.count() != 1 || w.count(`SELECT count(*) FROM provisioning_jobs WHERE kind = 'partition.maintain'`) != 1 {
		t.Fatal("an executed request ran again")
	}

	// audit: request by sa1; approval and execution by sa2 naming both persons
	for action, actor := range map[string]uuid.UUID{"platform.approval.request": sa1.IdentityID,
		"platform.approval.approve": sa2.IdentityID, "platform.approval.execute": sa2.IdentityID} {
		if n := w.count(`SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = $1 AND outcome = 'success'
			AND actor_identity_id = $2 AND resource_id = $3 AND details ->> 'requested_by_identity_id' = $4
			AND details ->> 'payload_sha256' = $5`, action, actor, req.ID.String(), sa1.IdentityID.String(),
			req.PayloadSHA256); n != 1 {
			t.Errorf("audit %s by %s: %d events", action, actor, n)
		}
	}
	if n := w.count(`SELECT count(*) FROM audit_events WHERE action = 'platform.approval.execute'
		AND details ->> 'decided_by_identity_id' = $1 AND details ->> 'job_id' = $2`, sa2.IdentityID.String(),
		done.JobID.String()); n != 1 {
		t.Errorf("execute event: %d with the approver and the job", n)
	}
}

// TestDeciderRules — the :decide condition of a Platform Operator ("chỉ cho restore"), the permission of the action
// itself, an action this process cannot execute, and the tenant rule (an Owner, not an Admin, approves an action
// that needs tenant.settings:update_security).
func TestDeciderRules(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sa1, sa2, po := w.staff(authz.RoleSuperAdmin), w.staff(authz.RoleSuperAdmin), w.staff(authz.RolePlatformOperator)

	del, err := w.svc.Request(ctx, sa1, approvals.NewRequest{Action: actDelete, ResourceID: uuid.NewString(),
		Payload: deletePayload{TenantID: uuid.NewString()}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.svc.Approve(ctx, po, platformRef(del.ID), del.PayloadSHA256)
	wantErr(t, "PO approves a deletion", err, approvals.ErrForbidden, approvals.ReasonDecideCondition)
	_, err = w.svc.Reject(ctx, po, platformRef(del.ID))
	wantErr(t, "PO rejects a deletion", err, approvals.ErrForbidden, approvals.ReasonDecideCondition)
	noCond := po
	noCond.Condition = "" // even without the condition the PO lacks platform.tenant:delete
	_, err = w.svc.Approve(ctx, noCond, platformRef(del.ID), del.PayloadSHA256)
	var den *authz.Denial
	if !errors.As(err, &den) || !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("PO without platform.tenant:delete: %v", err)
	}
	if r, err := w.svc.Approve(ctx, sa2, platformRef(del.ID), del.PayloadSHA256); err != nil || r.Status != approvals.StatusExecuted {
		t.Fatalf("SA approves the deletion: %+v %v", r, err)
	}

	res := w.restoreRequest(sa1)
	if r, err := w.svc.Approve(ctx, po, platformRef(res.ID), res.PayloadSHA256); err != nil || r.Status != approvals.StatusExecuted {
		t.Fatalf("PO approves a restore: %+v %v", r, err)
	}

	// a request whose action this build cannot run: readable, rejectable, never approved
	unknown := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO approval_requests (id, scope, action, resource_type, payload, payload_sha256, requested_by_identity_id,
			expires_at) VALUES ($1, 'platform', 'platform.future_action', 'tenant', '{"x":1}', $2, $3, now() + interval '1 day')`,
		unknown, approvals.Hash([]byte(`{"x":1}`)), sa1.IdentityID)
	_, err = w.svc.Approve(ctx, sa2, platformRef(unknown), approvals.Hash([]byte(`{"x":1}`)))
	wantErr(t, "approve an unknown action", err, approvals.ErrUnavailable, approvals.ReasonActionUnavailable)
	if r, err := w.svc.Reject(ctx, sa2, platformRef(unknown)); err != nil || r.Status != approvals.StatusRejected ||
		r.DecidedBy == nil || r.DecidedBy.IdentityID != sa2.IdentityID {
		t.Fatalf("reject an unknown action: %+v %v", r, err)
	}

	// tenant scope: the second person also needs the action's permission
	ten := w.tenant()
	to1, to2, ta := w.member(ten, authz.RoleTenantOwner), w.member(ten, authz.RoleTenantOwner), w.member(ten, authz.RoleTenantAdmin)
	req, err := w.svc.Request(ctx, to1, approvals.NewRequest{Action: actFourEyes, TenantID: ten.id, ResourceID: "policy",
		Payload: fourEyesPayload{Setting: "policy.four_eyes"}})
	if err != nil {
		t.Fatal(err)
	}
	tref := approvals.Ref{Scope: authz.ScopeTenant, TenantID: ten.id, ID: req.ID}
	_, err = w.svc.Approve(ctx, ta, tref, req.PayloadSHA256)
	if !errors.As(err, &den) || den.Reason != "no_grant" {
		t.Fatalf("TA without tenant.settings:update_security: %v", err)
	}
	r, err := w.svc.Approve(ctx, to2, tref, req.PayloadSHA256)
	if err != nil || r.Status != approvals.StatusExecuted || r.JobID == nil || r.TenantID == nil || *r.TenantID != ten.id {
		t.Fatalf("second Owner approves: %+v %v", r, err)
	}
	if n := w.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'approval.execute'
		AND actor_identity_id = $2 AND details ->> 'requested_by_identity_id' = $3`, ten.id, to2.IdentityID,
		to1.IdentityID.String()); n != 1 {
		t.Fatalf("tenant execute event: %d", n)
	}
	if n := w.count(`SELECT count(*) FROM provisioning_jobs WHERE id = $1 AND tenant_id = $2 AND kind = 'policy.apply'`,
		*r.JobID, ten.id); n != 1 {
		t.Fatalf("tenant job: %d", n)
	}
}

// TestExpiry — an expired request is never executed: neither a pending one nor an approved one whose execution
// failed and is retried after the expiry. The default lifetime comes from system_settings when set.
func TestExpiry(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sa1, sa2 := w.staff(authz.RoleSuperAdmin), w.staff(authz.RoleSuperAdmin)

	req := w.restoreRequest(sa1)
	w.clock.Advance(25 * time.Hour)
	_, err := w.svc.Approve(ctx, fresh(sa2, w.clock.Now()), platformRef(req.ID), req.PayloadSHA256)
	wantErr(t, "approve an expired request", err, approvals.ErrConflict, approvals.ReasonExpired)
	if w.status(req.ID) != approvals.StatusExpired || w.log.count() != 0 {
		t.Fatalf("expired request: status %s, %d executions", w.status(req.ID), w.log.count())
	}
	if got, _ := w.svc.Get(ctx, platformRef(req.ID)); got.Status != approvals.StatusExpired {
		t.Fatalf("view status %s", got.Status)
	}

	sa1, sa2 = fresh(sa1, w.clock.Now()), fresh(sa2, w.clock.Now())
	req = w.restoreRequest(sa1)
	w.log.failNext = true
	if _, err := w.svc.Approve(ctx, sa2, platformRef(req.ID), req.PayloadSHA256); err == nil {
		t.Fatal("the failing action succeeded")
	}
	if w.status(req.ID) != approvals.StatusApproved || w.count(`SELECT count(*) FROM provisioning_jobs`) != 0 {
		t.Fatal("a failed execution must leave the request approved and no job")
	}
	w.clock.Advance(25 * time.Hour)
	_, err = w.svc.Approve(ctx, fresh(sa2, w.clock.Now()), platformRef(req.ID), req.PayloadSHA256)
	wantErr(t, "retry after the expiry", err, approvals.ErrConflict, approvals.ReasonExpired)
	if w.status(req.ID) != approvals.StatusExpired || w.count(`SELECT count(*) FROM provisioning_jobs`) != 0 {
		t.Fatal("an approved request past its expiry ran")
	}

	w.exec(`INSERT INTO system_settings (key, value) VALUES ($1, '2')`, approvals.TTLSetting)
	sa1 = fresh(sa1, w.clock.Now())
	req = w.restoreRequest(sa1)
	if !req.ExpiresAt.Equal(w.clock.Now().Add(2 * time.Hour)) {
		t.Fatalf("expires_at %s with %s = 2", req.ExpiresAt, approvals.TTLSetting)
	}
}

// TestPayloadBinding — the request runs only with the payload that was approved: a payload changed in the database
// before the decision or after the approval (the columns are immutable for the application; only a privileged writer
// could do it) is refused with a security event and never runs; a changed hash makes the reviewed hash stale.
func TestPayloadBinding(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sa1, sa2 := w.staff(authz.RoleSuperAdmin), w.staff(authz.RoleSuperAdmin)
	tamper := func(id uuid.UUID) {
		w.exec(`UPDATE approval_requests SET payload = jsonb_set(payload, '{backup_id}', to_jsonb($2::text)) WHERE id = $1`,
			id, uuid.NewString())
	}

	before := w.restoreRequest(sa1)
	tamper(before.ID)
	_, err := w.svc.Approve(ctx, sa2, platformRef(before.ID), before.PayloadSHA256)
	wantErr(t, "changed before the decision", err, approvals.ErrConflict, approvals.ReasonPayloadIntegrity)
	if w.status(before.ID) != approvals.StatusPending {
		t.Fatal("a tampered request was approved")
	}

	after := w.restoreRequest(sa1)
	w.log.failNext = true
	if _, err := w.svc.Approve(ctx, sa2, platformRef(after.ID), after.PayloadSHA256); err == nil {
		t.Fatal("the failing action succeeded")
	}
	tamper(after.ID) // changed after the approval, before the execution
	_, err = w.svc.Approve(ctx, sa2, platformRef(after.ID), after.PayloadSHA256)
	wantErr(t, "changed after the approval", err, approvals.ErrConflict, approvals.ReasonPayloadIntegrity)
	_, err = w.svc.Execute(ctx, sa2, platformRef(after.ID), after.PayloadSHA256)
	wantErr(t, "execute a tampered request", err, approvals.ErrConflict, approvals.ReasonPayloadIntegrity)
	if w.status(after.ID) != approvals.StatusApproved || w.log.count() != 1 || w.count(`SELECT count(*) FROM provisioning_jobs`) != 0 {
		t.Fatalf("tampered request: status %s, %d executions", w.status(after.ID), w.log.count())
	}
	if n := w.count(`SELECT count(*) FROM security_events WHERE kind = $1 AND tenant_id IS NULL`,
		approvals.KindPayloadIntegrity); n < 2 {
		t.Fatalf("%d payload integrity security events", n)
	}

	// payload and hash rewritten together: the hash the approver reviewed no longer matches ⇒ precondition failed
	both := w.restoreRequest(sa1)
	w.log.failNext = true
	_, _ = w.svc.Approve(ctx, sa2, platformRef(both.ID), both.PayloadSHA256)
	forged := `{"backup_id":"` + uuid.NewString() + `","instance_id":"` + uuid.NewString() + `"}`
	w.exec(`UPDATE approval_requests SET payload = $2::jsonb, payload_sha256 = $3 WHERE id = $1`, both.ID, forged,
		approvals.Hash([]byte(forged)))
	_, err = w.svc.Approve(ctx, sa2, platformRef(both.ID), both.PayloadSHA256)
	wantErr(t, "payload and hash rewritten", err, approvals.ErrPayloadChanged, approvals.ReasonPayloadChanged)
	_, err = w.svc.Execute(ctx, sa2, platformRef(both.ID), both.PayloadSHA256)
	wantErr(t, "execute with the approved hash", err, approvals.ErrPayloadChanged, approvals.ReasonPayloadChanged)
	if w.status(both.ID) != approvals.StatusApproved {
		t.Fatal("rewritten request executed")
	}
}

// TestScopes — a tenant request lives in its tenant only: another tenant's scope and the platform scope read it as
// missing (RLS + scope filter), lists are per scope; the platform list never shows tenant requests.
func TestScopes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a, b := w.tenant(), w.tenant()
	toA1, toA2, toB := w.member(a, authz.RoleTenantOwner), w.member(a, authz.RoleTenantOwner), w.member(b, authz.RoleTenantOwner)
	sa := w.staff(authz.RoleSuperAdmin)
	req, err := w.svc.Request(ctx, toA1, approvals.NewRequest{Action: actFourEyes, TenantID: a.id,
		Payload: fourEyesPayload{Setting: "routes.four_eyes"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]approvals.Ref{
		"tenant B":       {Scope: authz.ScopeTenant, TenantID: b.id, ID: req.ID},
		"platform":       {Scope: authz.ScopePlatform, ID: req.ID},
		"no tenant":      {Scope: authz.ScopeTenant, ID: req.ID},
		"tenant on plat": {Scope: authz.ScopePlatform, TenantID: a.id, ID: req.ID},
	} {
		if _, err := w.svc.Get(ctx, ref); !errors.Is(err, approvals.ErrNotFound) {
			t.Errorf("get from %s: %v, want not found", name, err)
		}
	}
	_, err = w.svc.Approve(ctx, toB, approvals.Ref{Scope: authz.ScopeTenant, TenantID: b.id, ID: req.ID}, req.PayloadSHA256)
	wantErr(t, "B's Owner approves A's request", err, approvals.ErrNotFound, approvals.ReasonNotFound)
	_, err = w.svc.Approve(ctx, sa, platformRef(req.ID), req.PayloadSHA256)
	wantErr(t, "staff approves A's request on the platform scope", err, approvals.ErrNotFound, approvals.ReasonNotFound)
	_, err = w.svc.Request(ctx, toA1, approvals.NewRequest{Action: actFourEyes, Payload: fourEyesPayload{}})
	wantErr(t, "tenant action without tenant", err, approvals.ErrInvalid, approvals.ReasonScopeMismatch)
	_, err = w.svc.Request(ctx, toA1, approvals.NewRequest{Action: actRestore, Payload: restorePayload{}})
	wantErr(t, "platform action by a tenant identity", err, approvals.ErrInvalid, approvals.ReasonScopeMismatch)

	pa, err := w.svc.List(ctx, approvals.Ref{Scope: authz.ScopeTenant, TenantID: a.id}, approvals.Filter{})
	pb, err2 := w.svc.List(ctx, approvals.Ref{Scope: authz.ScopeTenant, TenantID: b.id}, approvals.Filter{})
	pp, err3 := w.svc.List(ctx, approvals.Ref{Scope: authz.ScopePlatform}, approvals.Filter{})
	if err != nil || err2 != nil || err3 != nil || len(pa.Items) != 1 || pa.Items[0].ID != req.ID || len(pb.Items) != 0 ||
		len(pp.Items) != 0 {
		t.Fatalf("lists A %d B %d platform %d (%v %v %v)", len(pa.Items), len(pb.Items), len(pp.Items), err, err2, err3)
	}

	// the second Owner of A rejects; the decision is final and audited with both persons
	r, err := w.svc.Reject(ctx, toA2, approvals.Ref{Scope: authz.ScopeTenant, TenantID: a.id, ID: req.ID})
	if err != nil || r.Status != approvals.StatusRejected {
		t.Fatalf("reject %+v %v", r, err)
	}
	_, err = w.svc.Approve(ctx, toA2, approvals.Ref{Scope: authz.ScopeTenant, TenantID: a.id, ID: req.ID}, req.PayloadSHA256)
	wantErr(t, "approve a rejected request", err, approvals.ErrConflict, approvals.ReasonNotPending)
	if n := w.count(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'approval.reject'
		AND actor_identity_id = $2 AND details ->> 'requested_by_identity_id' = $3`, a.id, toA2.IdentityID,
		toA1.IdentityID.String()); n != 1 {
		t.Fatalf("reject event: %d", n)
	}
	if w.log.count() != 0 {
		t.Fatal("a rejected request ran")
	}
}

// TestListPages — pagination (newest first, stable cursor), status (effective) and action filters, invalid input.
func TestListPages(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sa1, sa2 := w.staff(authz.RoleSuperAdmin), w.staff(authz.RoleSuperAdmin)
	var ids []uuid.UUID
	for range 5 {
		ids = append(ids, w.restoreRequest(sa1).ID)
		w.clock.Advance(time.Second)
	}
	if _, err := w.svc.Reject(ctx, fresh(sa2, w.clock.Now()), platformRef(ids[0])); err != nil {
		t.Fatal(err)
	}
	var got []uuid.UUID
	f := approvals.Filter{Limit: 2}
	for page := 0; page < 5; page++ {
		p, err := w.svc.List(ctx, approvals.Ref{Scope: authz.ScopePlatform}, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range p.Items {
			got = append(got, it.ID)
		}
		if p.NextCursor == "" {
			break
		}
		f.Cursor = p.NextCursor
	}
	if len(got) != 5 || got[0] != ids[4] || got[4] != ids[0] {
		t.Fatalf("pages %v, want newest first %v", got, ids)
	}
	p, err := w.svc.List(ctx, approvals.Ref{Scope: authz.ScopePlatform}, approvals.Filter{Status: approvals.StatusRejected})
	if err != nil || len(p.Items) != 1 || p.Items[0].ID != ids[0] {
		t.Fatalf("rejected filter %v %v", p.Items, err)
	}
	w.clock.Advance(25 * time.Hour)
	p, err = w.svc.List(ctx, approvals.Ref{Scope: authz.ScopePlatform}, approvals.Filter{Status: approvals.StatusExpired, Action: actRestore})
	if err != nil || len(p.Items) != 4 {
		t.Fatalf("expired (effective) %d %v", len(p.Items), err)
	}
	for _, bad := range []approvals.Filter{{Limit: -1}, {Limit: 201}, {Status: "open"}, {Action: "Bad Action"}, {Cursor: "zz"}} {
		if _, err := w.svc.List(ctx, approvals.Ref{Scope: authz.ScopePlatform}, bad); !errors.Is(err, approvals.ErrInvalid) {
			t.Errorf("filter %+v: %v", bad, err)
		}
	}
}
