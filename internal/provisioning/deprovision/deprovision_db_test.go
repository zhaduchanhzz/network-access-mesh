package deprovision

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
)

// allSucceeded is the step list of a deprovision of a tenant with a live instance, every step succeeded.
func allSucceeded() string {
	out := make([]string, 0, len(Steps))
	for _, s := range Steps {
		out = append(out, s+":succeeded")
	}
	return strings.Join(out, " ")
}

// assertGone checks everything a deprovision removes or closes for ten.
func (g *rig) assertGone(t *testing.T, ten *tenantFx) {
	t.Helper()
	if st := g.status(t, ten); st != tenants.StatusDeleted {
		t.Fatalf("tenant %s", st)
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM tenant_instances WHERE tenant_id = $1 AND status <> 'removed'`:                                        0,
		`SELECT count(*) FROM sessions s JOIN identities i ON i.id = s.identity_id WHERE i.tenant_id = $1 AND s.revoked_at IS NULL`: 0,
		`SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'`:                                       0,
		`SELECT count(*) FROM relay_assignments WHERE tenant_id = $1`:                                                               0,
		`SELECT count(*) FROM relay_regions WHERE tenant_id = $1`:                                                                   0,
		`SELECT count(*) FROM identity_providers WHERE tenant_id = $1 AND status <> 'disabled'`:                                     0,
		`SELECT count(*) FROM subscriptions WHERE tenant_id = $1 AND status IN ('trialing', 'active', 'past_due')`:                  0,
		`SELECT count(*) FROM secrets WHERE tenant_id = $1 AND name = 'headscale-api-key' AND destroyed_at IS NULL`:                 0,
		`SELECT count(*) FROM tenants WHERE id = $1 AND deleted_at IS NOT NULL AND keys_destroy_after IS NOT NULL`:                  1,
	} {
		if got := g.count(t, q, ten.id); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	if st := g.str(t, `SELECT status FROM approval_requests WHERE id = $1`, ten.approval); st != approvals.StatusExpired {
		t.Errorf("the open restore request on the instance is %s, want expired", st)
	}
	// the keys are scheduled exactly deleted_at + grace
	if d := g.str(t, `SELECT (keys_destroy_after - deleted_at)::text FROM tenants WHERE id = $1`, ten.id); d != pgInterval(g.grace) {
		t.Errorf("keys_destroy_after - deleted_at = %s, want %s", d, pgInterval(g.grace))
	}
	// no schedule target names the tenant any more ("service discovery" of the platform's periodic work)
	if l, err := Listed(t.Context(), g.wrk, ten.id); err != nil || len(l) != 0 {
		t.Errorf("target lists still naming the tenant: %v (%v)", l, err)
	}
	if n := ten.hs.validNodes(time.Now()); n != 0 {
		t.Errorf("%d node(s) still valid", n)
	}
	if left := ten.hs.keys; len(validKeys(ten.hs)) != 0 {
		t.Errorf("pre-auth keys still valid: %+v", left)
	}
	if ten.hs.Stored() != canonical(t, templates.SuspensionPolicy) {
		t.Errorf("Headscale holds %q, want the suspension policy", ten.hs.Stored())
	}
	m := g.agent.model(ten.instance)
	if m.edge || m.container || m.network || m.dir {
		t.Errorf("host left behind: %+v", m)
	}
	// the slug stays reserved (§11.4): a new tenant with the same slug ⇒ 409 slug_not_reusable
	if _, err := g.creator(t).Create(g.reqCtx(t, g.staff[0].IdentityID, orchestrator.ActionTenantCreate), g.staff[0].IdentityID,
		orchestrator.CreateRequest{Slug: ten.slug, Name: "Again", PlanKey: "standard", OwnerEmail: "o@again.test",
			IdP: orchestrator.IdPRequest{Driver: orchestrator.DriverKeycloak}}, nil); !isReason(err, "slug_not_reusable") {
		t.Errorf("create with the slug of the deleted tenant: %v, want 409 slug_not_reusable", err)
	}
	// authorization: the tenant does not exist any more for its members (404, invariant 6)
	if _, err := authz.New(g.api).Require(authz.WithPrincipal(t.Context(), authz.Principal{IdentityID: ten.admin,
		Scope: authz.ScopeTenant, Origin: authz.OriginApp}), ten.id, authz.Requirement{Permission: "tenant.device:read",
		ReadOnly: true}); !errors.Is(err, authz.ErrNotFound) {
		t.Errorf("a member of the deleted tenant reads it: %v, want not_found", err)
	}
	audit := g.str(t, `SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events
		WHERE action LIKE 'platform.tenant.delete%' AND resource_id = $1::text`, ten.id.String())
	if audit != "platform.tenant.delete.requested,platform.tenant.delete.succeeded" {
		t.Errorf("audit %s", audit)
	}
	if n := g.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'tenant.deleted'`, ten.id); n != 2 {
		t.Errorf("%d tenant.deleted notification(s), want 2 (Owner, Admin)", n)
	}
}

// canonical is the form the policy core sets (Lint's Applied — what Headscale stores).
func canonical(t *testing.T, text string) string {
	t.Helper()
	d, err := policies.Lint(text)
	if err != nil {
		t.Fatal(err)
	}
	return d.Applied
}

func validKeys(f *fakeHS) []headscale.PreAuthKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []headscale.PreAuthKey
	for _, k := range f.keys {
		if (k.Expiration.IsZero() || k.Expiration.After(time.Now())) && (k.Reusable || !k.Used) {
			out = append(out, k)
		}
	}
	return out
}

func pgInterval(d time.Duration) string {
	days := int(d / (24 * time.Hour))
	rest := d - time.Duration(days)*24*time.Hour
	h, m, s := int(rest/time.Hour), int(rest%time.Hour/time.Minute), int(rest%time.Minute/time.Second)
	if days == 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	if rest == 0 {
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d days %02d:%02d:%02d", days, h, m, s)
}

func isReason(err error, reason string) bool {
	var ce *orchestrator.CreateError
	return errors.As(err, &ce) && ce.Reason == reason
}

func (g *rig) creator(t *testing.T) *orchestrator.Creator {
	t.Helper()
	c, err := orchestrator.NewCreator(orchestrator.CreatorConfig{Store: g.api, Quota: usage.NewChecker(g.api),
		QuotaTx: usage.TenantCreationTx, BaseDomain: "mesh.test"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDeprovisionDB — §11.4 end to end over the real 2P path, job framework, registry, SecretStore and policy core:
// every step in order, every resource gone, the slug reserved, the sessions revoked, no target left; then the
// crypto-shredding after the grace period: the SecretStore cannot decrypt anything of the tenant any more.
func TestDeprovisionDB(t *testing.T) {
	g := newRig(t, rigOptions{grace: 48 * time.Hour})
	ten := g.newTenant(t)
	other := g.newTenant(t)
	ctx := t.Context()
	usedBefore, err := usage.NewChecker(g.api).CheckTenantCreation(ctx)
	if err != nil {
		t.Fatal(err)
	}

	job := g.request(t, ten, false)
	g.wait(t, job, jobs.StatusSucceeded)
	if got := g.steps(t, job); got != allSucceeded() {
		t.Fatalf("steps\n got %s\nwant %s", got, allSucceeded())
	}
	g.assertGone(t, ten)
	// order on the host (§11.4): edge (flag, detach) → compose down + network → the directory against the final backup
	seq := g.str(t, `SELECT sequence::text FROM backups WHERE job_id = $1 AND status = 'succeeded'`, job)
	want := []string{"RemoveEdgeAttachment:EDGE_DETACH_REASON_DEPROVISION", "RemoveInstance:DATA_DISPOSITION_KEEP",
		"RemoveInstance:DATA_DISPOSITION_DELETE_ARCHIVED:" + seq}
	if got := g.agent.Calls(); !slices.Equal(got, want) {
		t.Fatalf("agent calls %v, want %v", got, want)
	}
	// the final backup is in the book, kept at least the grace period
	if n := g.count(t, `SELECT count(*) FROM backups WHERE job_id = $1 AND status = 'succeeded' AND expires_at >= now() + interval '47 hours'`, job); n != 1 {
		t.Fatalf("%d final backup(s) kept ≥ the grace period", n)
	}
	if got := g.kc.Removes(); !slices.Equal(got, []string{ten.slug + ":disable"}) {
		t.Fatalf("IdP calls %v", got)
	}
	// the other tenant is untouched
	if g.status(t, other) != tenants.StatusActive || other.hs.validNodes(time.Now()) != 2 || len(validKeys(other.hs)) != 2 {
		t.Fatalf("the other tenant changed")
	}
	if m := g.agent.model(other.instance); !m.edge || !m.container || !m.network || !m.dir {
		t.Fatalf("the other tenant's host changed: %+v", m)
	}
	// quota: the deleted tenant no longer counts
	usedAfter, err := usage.NewChecker(g.api).CheckTenantCreation(ctx)
	if err != nil || usedAfter.Used != usedBefore.Used-1 {
		t.Fatalf("quota used %d → %d (%v)", usedBefore.Used, usedAfter.Used, err)
	}
	// the backup key and the IdP client secret wait for the crypto-shredding: still readable within the grace period
	for _, ref := range []secrets.Ref{ten.backupKey, ten.idpC} {
		if pt, err := g.sec.Get(ctx, ref); err != nil {
			t.Fatalf("%s within the grace period: %v", ref, err)
		} else {
			pt.Wipe()
		}
	}

	// tenant.keys_destroy: nothing before the grace period, then everything of the tenant (not of the other one)
	sh, err := NewShredder(ShredderConfig{Store: g.wrk, Secrets: g.sec, IdP: drivers{"keycloak": g.kc}})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := sh.Sweep(ctx); err != nil || len(r.Tenants) != 0 {
		t.Fatalf("sweep before the grace period: %+v %v", r, err)
	}
	sh.cfg.Now = func() time.Time { return time.Now().Add(g.grace + time.Minute) }
	r, err := sh.Sweep(ctx)
	if err != nil || !slices.Contains(r.Tenants, ten.id) || r.Failed != 0 || r.DEKs < 1 || r.Secrets < 2 {
		t.Fatalf("sweep after the grace period: %+v %v", r, err)
	}
	for _, ref := range []secrets.Ref{ten.backupKey, ten.idpC, ten.apiKey} {
		if pt, err := g.sec.Get(ctx, ref); err == nil {
			pt.Wipe()
			t.Fatalf("%s decrypted after the crypto-shredding", ref)
		} else if !errors.Is(err, secrets.ErrDestroyed) && !errors.Is(err, secrets.ErrKeyDestroyed) {
			t.Fatalf("%s after the crypto-shredding: %v, want destroyed", ref, err)
		}
	}
	if err := g.sec.Put(ctx, secrets.TenantRef(ten.id, "late", 1), []byte("x")); !errors.Is(err, secrets.ErrKeyDestroyed) {
		t.Fatalf("a new secret of the shredded tenant: %v, want ErrKeyDestroyed", err)
	}
	// the calls on this tenant's realm only: with -count=N the sweep also shreds the deleted tenants that the other tests
	// of an earlier iteration left in the package's database (their grace period is over at the shifted clock)
	var got []string
	for _, c := range g.kc.Removes() {
		if strings.HasPrefix(c, ten.slug+":") {
			got = append(got, c)
		}
	}
	if !slices.Equal(got, []string{ten.slug + ":disable", ten.slug + ":purge"}) {
		t.Fatalf("IdP calls on the realm %s: %v (the realm purged before the keys)", ten.slug, got)
	}
	if n := g.count(t, `SELECT count(*) FROM audit_events WHERE action = $1 AND resource_id = $2::text`, AuditKeysDestroyed, ten.id.String()); n != 1 {
		t.Fatalf("%d keys_destroyed audit event(s)", n)
	}
	if pt, err := g.sec.Get(ctx, other.backupKey); err != nil {
		t.Fatalf("the other tenant's secret: %v", err)
	} else {
		pt.Wipe()
	}
	if r, err := sh.Sweep(ctx); err != nil || len(r.Tenants) != 0 {
		t.Fatalf("second sweep: %+v %v (idempotent)", r, err)
	}
	// the slug: still held by the final backup in the book; free once the backup is purged (P6-T04)
	held := func() bool {
		var b bool
		g.scan(t, `SELECT EXISTS (SELECT 1 FROM tenants t WHERE t.slug = $1 AND t.status = 'deleted'
			AND (EXISTS (SELECT 1 FROM backups b WHERE b.tenant_id = t.id AND b.status <> 'purged')
			     OR EXISTS (SELECT 1 FROM tenant_keys k WHERE k.tenant_id = t.id AND k.state <> 'destroyed')))`, []any{ten.slug}, &b)
		return b
	}
	if !held() {
		t.Fatal("slug free while the final backup is in the book")
	}
	g.exec(t, `UPDATE backups SET status = 'purged' WHERE tenant_id = $1`, ten.id)
	if _, err := g.creator(t).Create(g.reqCtx(t, g.staff[0].IdentityID, orchestrator.ActionTenantCreate), g.staff[0].IdentityID,
		orchestrator.CreateRequest{Slug: ten.slug, Name: "Again", PlanKey: "standard", OwnerEmail: "o@again.test",
			IdP: orchestrator.IdPRequest{Driver: orchestrator.DriverKeycloak}}, nil); err != nil {
		t.Fatalf("the slug once nothing of the deleted tenant remains: %v", err)
	}
}

// TestDeprovisionRequestRefusals — the API side: unknown tenant 404, a typed slug that is not the tenant's 422, states
// that cannot be deprovisioned 409, an unfinished lifecycle job 409, a quarantined instance without skipping the final
// backup 409; the approval itself: never by the requester (self-approval refused), one open request per tenant.
func TestDeprovisionRequestRefusals(t *testing.T) {
	g := newRig(t, rigOptions{noWorker: true})
	ctx := t.Context()
	ten := g.newTenant(t)
	reason := func(err error) string {
		var re *RequestError
		if errors.As(err, &re) {
			return re.Reason
		}
		return fmt.Sprint(err)
	}
	if _, err := g.req.Check(ctx, uuid.New(), "x", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
	if _, err := g.req.Check(ctx, ten.id, ten.slug+"x", false); !errors.Is(err, ErrInvalid) || reason(err) != ReasonSlugMismatch {
		t.Fatalf("typed slug: %v", err)
	}
	for st, want := range map[string]string{"deleted": ReasonDeleted, "deprovisioning": ReasonInProgress,
		"provisioning": ReasonNotDeprovisioned, "pending": ReasonNotDeprovisioned} {
		g.exec(t, `UPDATE tenants SET status = $2::text, deleted_at = CASE WHEN $2::text = 'deleted' THEN now() END WHERE id = $1`, ten.id, st)
		if _, err := g.req.Check(ctx, ten.id, ten.slug, false); !errors.Is(err, ErrConflict) || reason(err) != want {
			t.Errorf("tenant %s: %v, want %s", st, err, want)
		}
	}
	g.exec(t, `UPDATE tenants SET status = 'active', deleted_at = NULL WHERE id = $1`, ten.id)
	g.exec(t, `UPDATE tenant_instances SET status = 'quarantined' WHERE id = $1`, ten.instance)
	if _, err := g.req.Check(ctx, ten.id, ten.slug, false); reason(err) != ReasonQuarantined {
		t.Fatalf("quarantined instance: %v", err)
	}
	if p, err := g.req.Check(ctx, ten.id, ten.slug, true); err != nil || !p.SkipFinalBackup || p.Slug != ten.slug {
		t.Fatalf("quarantined instance, final backup skipped: %+v %v", p, err)
	}
	g.exec(t, `UPDATE tenant_instances SET status = 'running' WHERE id = $1`, ten.instance)
	// an unfinished lifecycle job of the tenant (a suspend queued) ⇒ 409, at the check and at the execution
	var susp uuid.UUID
	g.scan(t, `INSERT INTO provisioning_jobs (tenant_id, kind, dedupe_key, lock_key, max_attempts, input)
		VALUES ($1::uuid, 'tenant.suspend', 'tenant:'||$1::uuid::text||':lifecycle', NULL, 6, '{}') RETURNING id`, []any{ten.id}, &susp)
	if _, err := g.req.Check(ctx, ten.id, ten.slug, false); reason(err) != ReasonLifecycleJob {
		t.Fatalf("lifecycle job: %v", err)
	}
	g.exec(t, `UPDATE provisioning_jobs SET status = 'cancelled', finished_at = now() WHERE id = $1`, susp)

	// 2P: the requester cannot approve; the second Super Admin does; a second request while one is open ⇒ 409
	a, b := g.staff[0], g.staff[1]
	p, err := g.req.Check(ctx, ten.id, ten.slug, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := g.appr.Request(g.reqCtx(t, a.IdentityID, Action+".request"), a, approvals.NewRequest{Action: Action,
		ResourceID: ten.id.String(), Payload: p, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.appr.Request(g.reqCtx(t, b.IdentityID, Action+".request"), b, approvals.NewRequest{Action: Action,
		ResourceID: ten.id.String(), Payload: p, Reason: "test"}); !errors.Is(err, approvals.ErrConflict) {
		t.Fatalf("second open request: %v", err)
	}
	if _, err := g.appr.Approve(g.reqCtx(t, a.IdentityID, "platform.approval.approve"), a,
		approvals.Ref{Scope: authz.ScopePlatform, ID: r.ID}, r.PayloadSHA256); !errors.Is(err, approvals.ErrForbidden) {
		t.Fatalf("self-approval: %v", err)
	}
	if n := g.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = $2`, ten.id, Kind); n != 0 {
		t.Fatalf("%d deprovision job(s) before the approval", n)
	}
	stale := b
	stale.AuthTime = time.Now().Add(-time.Hour)
	if _, err := g.appr.Approve(g.reqCtx(t, b.IdentityID, "platform.approval.approve"), stale,
		approvals.Ref{Scope: authz.ScopePlatform, ID: r.ID}, r.PayloadSHA256); !errors.Is(err, approvals.ErrReauthRequired) {
		t.Fatalf("approval without step-up: %v", err)
	}
	done, err := g.appr.Approve(g.reqCtx(t, b.IdentityID, "platform.approval.approve"), b,
		approvals.Ref{Scope: authz.ScopePlatform, ID: r.ID}, r.PayloadSHA256)
	if err != nil || done.JobID == nil || done.Status != approvals.StatusExecuted {
		t.Fatalf("approval: %+v %v", done, err)
	}
	if got := g.steps(t, *done.JobID); got != "validate:succeeded" {
		t.Fatalf("steps of the new job %s", got)
	}
	in := g.str(t, `SELECT input::text FROM provisioning_jobs WHERE id = $1`, *done.JobID)
	for _, w := range []string{`"from_status": "active"`, `"instance_id": "` + ten.instance.String(), `"approval_id": "` + r.ID.String(),
		`"requested_by": "` + a.IdentityID.String(), `"restore_version_id": "` + ten.desired.String()} {
		if !strings.Contains(in, w) {
			t.Errorf("job input %s lacks %s", in, w)
		}
	}
	// the job holds the lifecycle lock: a deprovision cannot be asked again
	if _, err := g.req.Check(ctx, ten.id, ten.slug, false); reason(err) != ReasonLifecycleJob {
		t.Fatalf("while the job is queued: %v", err)
	}
	if n := g.count(t, `SELECT count(*) FROM audit_events WHERE action = 'platform.tenant.delete.requested' AND resource_id = $1::text`, ten.id.String()); n != 1 {
		t.Fatalf("%d .requested event(s)", n)
	}
}

// TestDeprovisionFinalBackupFailure — the final backup fails ⇒ the job stops failed_resumable at backup.final, nothing
// else ran, the tenant is still active and serving; /rollback (before the point of no return) ⇒ rolled_back, audit
// .failed; a new request whose approved payload skips the final backup ⇒ succeeded with the data directory kept and a
// security event.
func TestDeprovisionFinalBackupFailure(t *testing.T) {
	g := newRig(t, rigOptions{})
	ten := g.newTenant(t)
	g.backups.set(func(b *fakeBackups) {
		b.err = jobs.Permanent("agent_integrity", errors.New("the database does not verify (test)"))
	})
	job := g.request(t, ten, false)
	g.wait(t, job, jobs.StatusFailedResumable)
	if got := g.steps(t, job); got != "validate:succeeded backup.final:failed:agent_integrity" {
		t.Fatalf("steps %s", got)
	}
	if g.status(t, ten) != tenants.StatusActive || len(g.agent.Calls()) != 0 || ten.hs.validNodes(time.Now()) != 2 {
		t.Fatalf("the tenant changed without a final backup")
	}
	if _, err := g.control(t, jobs.Rollback, job); err != nil {
		t.Fatalf("/rollback before the point of no return: %v", err)
	}
	g.wait(t, job, jobs.StatusRolledBack)
	if g.status(t, ten) != tenants.StatusActive {
		t.Fatalf("tenant %s after rollback", g.status(t, ten))
	}
	if a := g.str(t, `SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events WHERE action LIKE 'platform.tenant.delete%'
		AND resource_id = $1::text`, ten.id.String()); a != "platform.tenant.delete.requested,platform.tenant.delete.failed" {
		t.Fatalf("audit %s", a)
	}

	// the operator override: approved with skip_final_backup ⇒ no backup, the directory kept, a security event
	g.backups.set(func(b *fakeBackups) { b.err = nil })
	job2 := g.request(t, ten, true)
	g.wait(t, job2, jobs.StatusSucceeded)
	if g.backups.Calls() != 1 {
		t.Fatalf("%d backup call(s), want only the failed one", g.backups.Calls())
	}
	m := g.agent.model(ten.instance)
	if m.edge || m.container || m.network || !m.dir {
		t.Fatalf("host %+v: the directory (the only copy) must stay", m)
	}
	for _, c := range g.agent.Calls() {
		if strings.Contains(c, "DELETE") {
			t.Fatalf("the directory was deleted without a final backup: %v", g.agent.Calls())
		}
	}
	if n := g.count(t, `SELECT count(*) FROM security_events WHERE kind = $1 AND details->>'tenant_id' = $2::text`,
		EventNoFinalBackup, ten.id.String()); n != 1 {
		t.Fatalf("%d security event(s) %s", n, EventNoFinalBackup)
	}
	if fb := g.str(t, `SELECT payload->>'final_backup' FROM notification_outbox WHERE tenant_id = $1 AND kind = 'tenant.deleted' LIMIT 1`,
		ten.id); fb != "skipped" {
		t.Fatalf("notification final_backup %s", fb)
	}
	if g.status(t, ten) != tenants.StatusDeleted {
		t.Fatalf("tenant %s", g.status(t, ten))
	}
}

// TestDeprovisionQuarantinedInstance — P3-T18 × P3-T09: an instance quarantined after the approval stops the job at
// backup.final (no backup of a suspect instance), before the point of no return: /rollback restores the tenant. The
// approved override (skip_final_backup — the only way the API accepts a quarantined instance) then deletes the tenant
// without reaching the quarantined Headscale (the locator refuses it; the quarantine stopped it and detached the edge):
// edge detach + compose down/network with the data KEPT for the investigation, never a DELETE of it.
func TestDeprovisionQuarantinedInstance(t *testing.T) {
	g := newRig(t, rigOptions{})
	ten := g.newTenant(t)
	quarantine := func() error {
		return g.backups.exec(`UPDATE tenant_instances SET status = 'quarantined' WHERE id = $1`, ten.instance)
	}
	g.backups.set(func(b *fakeBackups) {
		b.before = func() error {
			if err := quarantine(); err != nil {
				return jobs.Transient("registry_unavailable", err)
			}
			return jobs.Transient("agent_unavailable", errors.New("the quarantine took the instance meanwhile (test)"))
		}
	})
	job := g.request(t, ten, false)
	g.wait(t, job, jobs.StatusFailedResumable)
	if got := g.steps(t, job); got != "validate:succeeded backup.final:failed:"+ReasonQuarantined {
		t.Fatalf("steps %s", got)
	}
	if n := g.count(t, `SELECT count(*) FROM backups WHERE tenant_id = $1`, ten.id); n != 0 {
		t.Fatalf("%d backup(s) of a quarantined instance", n)
	}
	if _, err := g.control(t, jobs.Rollback, job); err != nil {
		t.Fatalf("/rollback before the point of no return: %v", err)
	}
	g.wait(t, job, jobs.StatusRolledBack)
	if g.status(t, ten) != tenants.StatusActive || len(g.agent.Calls()) != 0 {
		t.Fatalf("tenant %s, agent calls %v after the rollback", g.status(t, ten), g.agent.Calls())
	}

	// the API refuses the quarantined instance without the override, accepts it with it
	var re *RequestError
	if _, err := g.req.Check(t.Context(), ten.id, ten.slug, false); !errors.As(err, &re) || re.Reason != ReasonQuarantined {
		t.Fatalf("quarantined instance without the override: %v", err)
	}
	g.backups.set(func(b *fakeBackups) { b.before = nil })
	calls := g.backups.Calls()
	job2 := g.request(t, ten, true)
	g.wait(t, job2, jobs.StatusSucceeded)
	if got := g.steps(t, job2); got != allSucceeded() {
		t.Fatalf("steps\n got %s\nwant %s", got, allSucceeded())
	}
	if d := g.str(t, `SELECT detail->>'skipped' FROM provisioning_job_steps WHERE job_id = $1 AND name = $2`, job2,
		StepNodesExpire); d != "instance_quarantined" {
		t.Fatalf("nodes.expire detail %q", d)
	}
	if d := g.str(t, `SELECT detail->>'reason' FROM provisioning_job_steps WHERE job_id = $1 AND name = $2`, job2,
		StepStorage); d != "instance_quarantined" {
		t.Fatalf("storage.remove detail %q", d)
	}
	if g.backups.Calls() != calls {
		t.Fatalf("a backup of the quarantined instance was attempted")
	}
	for _, c := range ten.hs.Calls() {
		if strings.HasPrefix(c, "ExpireNode") || strings.HasPrefix(c, "ListNodes") {
			t.Fatalf("the job reached the quarantined Headscale: %v", ten.hs.Calls())
		}
	}
	wantAgent := []string{"RemoveEdgeAttachment:EDGE_DETACH_REASON_DEPROVISION", "RemoveInstance:DATA_DISPOSITION_KEEP"}
	if got := g.agent.Calls(); !slices.Equal(got, wantAgent) {
		t.Fatalf("agent calls %v, want %v", got, wantAgent)
	}
	if m := g.agent.model(ten.instance); m.edge || m.container || m.network || !m.dir {
		t.Fatalf("host %+v: the data of the quarantined instance must stay", m)
	}
	if g.status(t, ten) != tenants.StatusDeleted {
		t.Fatalf("tenant %s", g.status(t, ten))
	}
	if st := g.str(t, `SELECT status FROM tenant_instances WHERE id = $1`, ten.instance); st != tenants.InstanceRemoved {
		t.Fatalf("instance %s", st)
	}
}

// TestDeprovisionRollbackBeforeTheNodes — the instance cannot be reached at nodes.expire (before it records anything):
// failed_resumable with the tenant deprovisioning behind the suspension policy; /rollback ⇒ compensation in reverse
// order: active again, the desired policy applied again, nothing on the host touched.
func TestDeprovisionRollbackBeforeTheNodes(t *testing.T) {
	// the handler's registry never reaches the instance (the policy core's does): nodes.expire fails before it records
	// anything (transient ⇒ in-place retries ⇒ failed_resumable)
	g := newRig(t, rigOptions{unreachable: true})
	ten := g.newTenant(t)
	allow := ten.hs.Stored()
	job := g.request(t, ten, false)
	g.wait(t, job, jobs.StatusFailedResumable)
	if got := g.steps(t, job); !strings.HasSuffix(got, "registry.deprovision:succeeded nodes.expire:failed:instance_unavailable") {
		t.Fatalf("steps %s", got)
	}
	if g.status(t, ten) != tenants.StatusDeprovisioning || ten.hs.Stored() != canonical(t, templates.SuspensionPolicy) {
		t.Fatalf("tenant %s behind %q", g.status(t, ten), ten.hs.Stored())
	}
	if _, err := g.control(t, jobs.Rollback, job); err != nil {
		t.Fatalf("/rollback: %v", err)
	}
	g.wait(t, job, jobs.StatusRolledBack)
	if got := g.compensation(t, job); got != "validate:skipped backup.final:skipped policy.suspend:succeeded registry.deprovision:succeeded nodes.expire:skipped" {
		t.Fatalf("compensation %s", got)
	}
	if g.status(t, ten) != tenants.StatusActive || ten.hs.Stored() != allow {
		t.Fatalf("after rollback: tenant %s behind %q", g.status(t, ten), ten.hs.Stored())
	}
	if m := g.agent.model(ten.instance); !m.edge || !m.container || !m.network || !m.dir || ten.hs.validNodes(time.Now()) != 2 {
		t.Fatalf("rollback touched the host or the nodes: %+v", m)
	}
	// the final backup stays in the book (a normal backup of the instance)
	if n := g.count(t, `SELECT count(*) FROM backups WHERE job_id = $1 AND status = 'succeeded'`, job); n != 1 {
		t.Fatalf("%d final backup(s)", n)
	}
}

// unreachable is a registry that never reaches the instance.
type unreachable struct{}

func (unreachable) ForTenant(context.Context, uuid.UUID) (headscale.Instance, error) {
	return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1, Err: headscale.ErrNoInstance}
}

// TestDeprovisionPointOfNoReturn — a permanent failure after nodes.expire recorded its point of no return: the job
// stops failed_resumable (never an automatic compensation); /rollback is refused (point_of_no_return) and the
// compensation itself would refuse; /retry resumes at the failed step and converges.
func TestDeprovisionPointOfNoReturn(t *testing.T) {
	g := newRig(t, rigOptions{})
	ten := g.newTenant(t)
	ten.hs.set(func(f *fakeHS) {
		f.expireErr = &headscale.Error{Op: headscale.OpExpireNode, Kind: headscale.KindUpstreamRejected}
	})
	job := g.request(t, ten, false)
	g.wait(t, job, jobs.StatusFailedResumable)
	if got := g.steps(t, job); !strings.HasSuffix(got, "nodes.expire:failed:headscale_upstream_rejected") {
		t.Fatalf("steps %s", got)
	}
	_, err := g.control(t, jobs.Rollback, job)
	var se *jobs.StateError
	if !errors.As(err, &se) || se.Reason != jobs.ReasonPointOfNoReturn {
		t.Fatalf("/rollback past the point of no return: %v", err)
	}
	if st := g.str(t, `SELECT status FROM provisioning_jobs WHERE id = $1`, job); st != jobs.StatusFailedResumable {
		t.Fatalf("job %s after a refused rollback", st)
	}
	ten.hs.set(func(f *fakeHS) { f.expireErr = nil })
	if _, err := g.control(t, jobs.Retry, job); err != nil {
		t.Fatalf("/retry: %v", err)
	}
	g.wait(t, job, jobs.StatusSucceeded)
	g.assertGone(t, ten)
}

// TestDeprovisionRetryConverges — every external call of the job fails once AFTER its effect (the answer lost, as when
// the worker dies mid-step): each step is retried in place and the end state is exactly the one of a clean run — one
// final backup (the backup recorded by the lost attempt is reused), each host object removed once.
func TestDeprovisionRetryConverges(t *testing.T) {
	g := newRig(t, rigOptions{})
	ten := g.newTenant(t)
	g.backups.set(func(b *fakeBackups) { b.after = 1 })
	ten.hs.set(func(f *fakeHS) { f.expireAfter = 1 })
	g.agent.mu.Lock()
	for _, c := range []string{"RemoveEdgeAttachment", "RemoveInstance:DATA_DISPOSITION_KEEP", "RemoveInstance:DATA_DISPOSITION_DELETE_ARCHIVED"} {
		g.agent.after[c] = 1
	}
	g.agent.mu.Unlock()
	g.kc.mu.Lock()
	g.kc.after = 1
	g.kc.mu.Unlock()
	job := g.request(t, ten, false)
	g.wait(t, job, jobs.StatusSucceeded)
	if got := g.steps(t, job); got != allSucceeded() {
		t.Fatalf("steps %s", got)
	}
	att := g.attempts(t, job)
	for _, s := range []string{StepFinalBackup, StepNodesExpire, StepEdgeDetach, StepInstance, StepStorage, StepIdP} {
		if !strings.Contains(att, s+":2") {
			t.Errorf("step %s not retried once: %s", s, att)
		}
	}
	if n := g.count(t, `SELECT count(*) FROM backups WHERE tenant_id = $1`, ten.id); n != 1 || g.backups.Calls() != 1 {
		t.Fatalf("%d backup row(s), %d backup call(s): the lost answer's backup must be reused", n, g.backups.Calls())
	}
	g.assertGone(t, ten)
}

// TestDeprovisionFailedTenant — a tenant whose provisioning was rolled back (failed, no live instance) is deleted for
// good without touching any host: the steps that need an instance are skipped.
func TestDeprovisionFailedTenant(t *testing.T) {
	g := newRig(t, rigOptions{noAgent: true})
	ten := g.newTenant(t)
	g.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, ten.instance)
	g.exec(t, `UPDATE tenants SET status = 'failed' WHERE id = $1`, ten.id)
	job := g.request(t, ten, false)
	g.wait(t, job, jobs.StatusSucceeded)
	if g.status(t, ten) != tenants.StatusDeleted || len(g.agent.Calls()) != 0 || g.backups.Calls() != 0 {
		t.Fatalf("tenant %s, agent %v, backups %d", g.status(t, ten), g.agent.Calls(), g.backups.Calls())
	}
	for _, s := range []string{StepFinalBackup, StepPolicy, StepNodesExpire, StepEdgeDetach, StepInstance, StepStorage} {
		if d := g.str(t, `SELECT coalesce(detail->>'skipped', '') FROM provisioning_job_steps WHERE job_id = $1 AND name = $2`, job, s); d == "" {
			t.Errorf("step %s not skipped", s)
		}
	}
	if n := g.count(t, `SELECT count(*) FROM sessions s JOIN identities i ON i.id = s.identity_id WHERE i.tenant_id = $1
		AND s.revoked_at IS NULL`, ten.id); n != 0 {
		t.Fatalf("%d live session(s)", n)
	}
}

// TestJobKind: tenant.deprovision is a compensable lifecycle kind whose point of no return is nodes.expire; the steps
// are those of §11.4 in order; tenant.keys_destroy is a platform maintenance kind.
func TestJobKind(t *testing.T) {
	k, ok := jobs.KindOf(Kind)
	if !ok || !k.Compensable || k.PointOfNoReturn != PointOfNoReturn || k.Lock != jobs.LockHold {
		t.Fatalf("kind %+v", k)
	}
	if i := slices.Index(Steps, PointOfNoReturn); i != 4 || Steps[i-1] != StepDeprovision {
		t.Fatalf("point of no return at %d", i)
	}
	s, ok := jobs.KindOf(KindKeysDestroy)
	if !ok || s.Scope != jobs.ScopePlatform || s.Queue != jobs.QueueMaintenance {
		t.Fatalf("kind %+v", s)
	}
	if !slices.Equal(ReachableStatuses, []string{"active", "suspended", "deprovisioning"}) {
		t.Fatalf("reachable statuses %v", ReachableStatuses)
	}
}
