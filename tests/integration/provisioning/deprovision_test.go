//go:build linux && dockerintegration

package provisioning

// The deprovision cases of P3-T09 (E2E-73…E2E-75) on the real stack of the harness: the real tenant.deprovision
// (internal/provisioning/deprovision) with the real backup service (the final backup: the agent's helper, VACUUM INTO,
// age, the signed manifest), the real Host Agent (RemoveEdgeAttachment, RemoveInstance KEEP then DELETE_ARCHIVED
// against the signed archive), the real Headscale (nodes and pre-auth keys expired through the edge), the real
// SecretStore, and the 2P path of DELETE /platform/tenants/{id} through the real approvals service.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/deprovision"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/faultinject"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/orphans"
)

// hsExec runs a headscale CLI command inside the tenant's container (test data only: nodes registered as a client would).
func (h *harness) hsExec(t *testing.T, slug string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	ec, err := h.docker.ExecCreate(ctx, "mg-hs-"+slug, client.ExecCreateOptions{AttachStdout: true, AttachStderr: true,
		Cmd: append([]string{"headscale"}, args...)})
	if err != nil {
		t.Fatalf("exec %v: %v", args, err)
	}
	att, err := h.docker.ExecAttach(ctx, ec.ID, client.ExecAttachOptions{})
	if err != nil {
		t.Fatalf("exec attach %v: %v", args, err)
	}
	defer att.Close()
	var out, errb bytes.Buffer
	if _, err := stdcopy.StdCopy(&out, &errb, io.LimitReader(att.Reader, 1<<20)); err != nil {
		t.Fatalf("exec output %v: %v", args, err)
	}
	for range 100 {
		in, err := h.docker.ExecInspect(ctx, ec.ID, client.ExecInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !in.Running {
			if in.ExitCode != 0 {
				t.Fatalf("headscale %v: exit %d: %s", args, in.ExitCode, errb.String())
			}
			return out.String()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("headscale %v: no exit code", args)
	return ""
}

// devices registers n nodes of a user "pit" and a reusable pre-auth key in the tenant's Headscale, the way clients
// would (the deprovision must expire them all).
func (h *harness) devices(t *testing.T, slug string, n int) {
	t.Helper()
	h.hsExec(t, slug, "users", "create", "pit")
	for i := range n {
		var b [12]byte
		_, _ = rand.Read(b[:])
		id := "hskey-authreq-" + hex.EncodeToString(b[:])
		h.hsExec(t, slug, "debug", "create-node", "--user", "pit", "--name", fmt.Sprintf("n%d", i+1), "--key", id, "-o", "json")
		h.hsExec(t, slug, "auth", "register", "--auth-id", id, "--user", "pit", "-o", "json")
	}
}

// hsNode is a node as `headscale nodes list -o json` prints it.
type hsNode struct {
	ID     uint64 `json:"id"`
	Expiry *struct {
		Seconds int64 `json:"seconds"`
	} `json:"expiry"`
}

// nodesValid counts the nodes of the tenant's Headscale whose key is still valid (no expiry, or one in the future).
func (h *harness) nodesValid(t *testing.T, slug string) (valid, total int) {
	t.Helper()
	var l []hsNode
	if err := json.Unmarshal(bytes.TrimSpace([]byte(h.hsExec(t, slug, "nodes", "list", "-o", "json"))), &l); err != nil {
		t.Fatalf("nodes list: %v", err)
	}
	for _, n := range l {
		if n.Expiry == nil || n.Expiry.Seconds <= 0 || time.Unix(n.Expiry.Seconds, 0).After(time.Now()) {
			valid++
		}
	}
	return valid, len(l)
}

// seedSessions gives the tenant a member with two live Portal sessions (identities of the tenant's IdP).
func (h *harness) seedSessions(t *testing.T, tenant uuid.UUID) int {
	t.Helper()
	ident := uuid.New()
	h.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified)
		SELECT $1, i.id, $2, 'tenant', 'member-'||$1::uuid::text, 'member@'||$1::uuid::text||'.test', true
		FROM identity_providers i WHERE i.tenant_id = $2 ORDER BY i.created_at LIMIT 1`, ident, tenant)
	h.exec(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
		SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'tenant_admin'`, tenant, ident)
	for range 2 {
		h.exec(t, `INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at)
			SELECT sha256(convert_to(gen_random_uuid()::text, 'UTF8')), $1, idp_id, 'app', now(), now() + interval '1 hour',
				now() + interval '8 hours' FROM identities WHERE id = $1`, ident)
	}
	return scalar[int](t, h, `SELECT count(*)::int FROM sessions s JOIN identities i ON i.id = s.identity_id
		WHERE i.tenant_id = $1 AND s.revoked_at IS NULL`, tenant)
}

// shredDue waits until the grace period of every deleted tenant of the run has passed and runs tenant.keys_destroy
// (the shredder the worker schedules every hour), so that the detector's "keys live after the grace period" never fires
// on timing. It returns the tenants it shredded.
func (h *harness) shredDue(t *testing.T) []uuid.UUID {
	t.Helper()
	var due time.Time
	if err := h.su.QueryRow(t.Context(), `SELECT COALESCE(max(keys_destroy_after), now()) FROM tenants
		WHERE status = 'deleted' AND slug LIKE $1 AND EXISTS (SELECT 1 FROM tenant_keys k WHERE k.tenant_id = tenants.id
		AND k.state <> 'destroyed')`, h.e.prefix+"-%").Scan(&due); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(due); d > 0 {
		time.Sleep(d + time.Second)
	}
	sh, err := deprovision.NewShredder(deprovision.ShredderConfig{Store: h.wrk, Secrets: h.sec, Batch: 100,
		IdP: drivers{idp.DriverKeycloak: &keycloakDriver{sec: h.sec, realms: map[string]string{}}}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := sh.Sweep(t.Context())
	if err != nil || r.Failed != 0 {
		t.Fatalf("tenant.keys_destroy: %+v %v", r, err)
	}
	return r.Tenants
}

// assertDeleted checks the end state of a deprovisioned tenant: deleted, every instance removed, its live sessions
// revoked, no schedule target, the slug reserved; it returns the final backup (book row verified against the signed
// manifest: tenant, instance, slug, sequence).
func (h *harness) assertDeleted(t *testing.T, tenant uuid.UUID, slug string, job uuid.UUID) string {
	t.Helper()
	if st := scalar[string](t, h, `SELECT status FROM tenants WHERE id = $1`, tenant); st != "deleted" {
		t.Fatalf("tenant %s", st)
	}
	if n := scalar[int64](t, h, `SELECT count(*) FROM tenant_instances WHERE tenant_id = $1 AND status <> 'removed'`, tenant); n != 0 {
		t.Fatalf("%d live instance(s)", n)
	}
	if n := scalar[int64](t, h, `SELECT count(*) FROM sessions s JOIN identities i ON i.id = s.identity_id
		WHERE i.tenant_id = $1 AND s.revoked_at IS NULL`, tenant); n != 0 {
		t.Fatalf("%d live session(s)", n)
	}
	if l, err := deprovision.Listed(t.Context(), h.wrk, tenant); err != nil || len(l) != 0 {
		t.Fatalf("schedule targets still naming the tenant: %v %v", l, err)
	}
	_, err := h.creator.Create(h.reqCtx(t, orchestrator.ActionTenantCreate), h.actor, orchestrator.CreateRequest{Slug: slug,
		Name: "Again " + slug, PlanKey: "standard", OwnerEmail: "owner@again.example",
		IdP: orchestrator.IdPRequest{Driver: orchestrator.DriverKeycloak}}, nil)
	var ce *orchestrator.CreateError
	if !errors.As(err, &ce) || ce.Reason != "slug_not_reusable" {
		t.Fatalf("a new tenant with the slug of the deleted one: %v, want 409 slug_not_reusable", err)
	}
	var (
		inst          uuid.UUID
		seq           int64
		manifest, sig []byte
	)
	if err := h.su.QueryRow(t.Context(), `SELECT instance_id, sequence, manifest, manifest_signature FROM backups
		WHERE job_id = $1 AND status = 'succeeded'`, job).Scan(&inst, &seq, &manifest, &sig); err != nil {
		t.Fatalf("the final backup of job %s: %v", job, err)
	}
	m, err := backupfmt.Parse(manifest, sig, h.e.manifestKeys)
	if err == nil {
		err = m.Check(backupfmt.Identity{TenantID: tenant, InstanceID: inst, Slug: slug, Sequence: uint64(seq)}) //nolint:gosec // > 0
	}
	if err != nil {
		t.Fatalf("the final backup's manifest: %v", err)
	}
	return fmt.Sprintf("final backup seq %d (%s, %d bytes, manifest signed)", seq, m.Method, m.Archive.Size)
}

func allSucceeded(t *testing.T, steps []stepRow) {
	t.Helper()
	names := make([]string, 0, len(steps))
	for _, s := range steps {
		names = append(names, s.Name)
		if s.Status != jobs.StepSucceeded {
			t.Fatalf("step %s %s; steps:%s", s.Name, s.Status, describeSteps(steps))
		}
	}
	if !slices.Equal(names, deprovision.Steps) {
		t.Fatalf("steps %v, want %v", names, deprovision.Steps)
	}
}

// deprovisionEndToEnd is E2E-73.
func (h *harness) deprovisionEndToEnd(t *testing.T) string {
	start := time.Now()
	slug := h.slugFor("dep73")
	w := h.startWorker(t, slug, nil)
	cr := h.create(t, slug)
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusSucceeded)
	inst, _, _ := h.instanceOf(t, cr.TenantID)
	h.devices(t, slug, 2)
	sessions := h.seedSessions(t, cr.TenantID)
	before, err := deprovision.Listed(t.Context(), h.wrk, cr.TenantID)
	if err != nil || len(before) == 0 {
		t.Fatalf("an active tenant is a target of %v (%v)", before, err)
	}
	pending := scalar[int64](t, h, `SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'`, cr.TenantID)
	backupKey := secrets.TenantRef(cr.TenantID, backupfmt.BackupKeySecretName, 1)

	job := h.deprovision(t, cr.TenantID, slug, false)
	h.waitJob(t, job, 5*time.Minute, jobs.StatusSucceeded)
	w.stop(t)
	allSucceeded(t, h.steps(t, job))
	fb := h.assertDeleted(t, cr.TenantID, slug, job)
	if n := scalar[int64](t, h, `SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'`, cr.TenantID); n != 0 {
		t.Fatalf("%d pending invitation(s)", n)
	}
	expired := scalar[string](t, h, `SELECT detail->>'expired_ids' FROM provisioning_job_steps WHERE job_id = $1 AND name = $2`,
		job, deprovision.StepNodesExpire)
	// the instance and its directory are gone; the backup key still decrypts within the grace period
	h.noOrphans(t)
	if pt, err := h.sec.Get(t.Context(), backupKey); err != nil {
		t.Fatalf("the backup key within the grace period: %v", err)
	} else {
		pt.Wipe()
	}

	// crypto-shredding after the (shortened) grace period: nothing of the tenant decrypts any more
	shredded := h.shredDue(t)
	if !slices.Contains(shredded, cr.TenantID) {
		t.Fatalf("tenant not shredded: %v", shredded)
	}
	for _, ref := range []secrets.Ref{backupKey, secrets.TenantRef(cr.TenantID, orphans.APIKeySecretName, 1)} {
		if pt, err := h.sec.Get(t.Context(), ref); err == nil {
			pt.Wipe()
			t.Fatalf("%s decrypted after the crypto-shredding", ref)
		} else if !errors.Is(err, secrets.ErrDestroyed) && !errors.Is(err, secrets.ErrKeyDestroyed) {
			t.Fatalf("%s after the crypto-shredding: %v", ref, err)
		}
	}
	if n := scalar[int64](t, h, `SELECT count(*) FROM tenant_keys WHERE tenant_id = $1 AND state <> 'destroyed'`, cr.TenantID); n != 0 {
		t.Fatalf("%d DEK(s) left", n)
	}
	inv := h.noOrphans(t)
	return fmt.Sprintf("E2E-73 provision → 2P deprovision %s: 15 steps succeeded, nodes expired %s, %d session(s) revoked, "+
		"%d invitation(s) revoked, targets %v → [], slug reserved, %s; instance %s and its directory gone; after the grace "+
		"period (%s) DEK + secrets destroyed, the SecretStore refuses; detector: %s; %5.1fs", slug, expired, sessions, pending,
		before, fb, short(inst), h.e.keyGrace, inv.Summary(), time.Since(start).Seconds())
}

// deprovisionCrash is E2E-74.
func (h *harness) deprovisionCrash(t *testing.T) string {
	start := time.Now()
	slug := h.slugFor("dep74")
	w0 := h.startWorker(t, slug, nil)
	cr := h.create(t, slug)
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusSucceeded)
	w0.stop(t)
	h.devices(t, slug, 2)
	// nodes.expire answers lost (the node expired) once; the worker dies right after compose down + network removal
	nodes, _ := h.nodesValid(t, slug)
	w1 := h.startWorker(t, slug+"-killed", faultinject.Plan{
		{Call: "headscale.ExpireNode", Mode: faultinject.Transient, After: true, Times: 1},
		{Call: "agent.RemoveInstance", Mode: faultinject.Kill, Times: 1},
	})
	job := h.deprovision(t, cr.TenantID, slug, false)
	w1.waitKilled(t, 5*time.Minute)
	ri, _ := stepByName(h.steps(t, job), deprovision.StepInstance)
	if ri.Status != jobs.StepRunning {
		t.Fatalf("instance.remove after the kill: %+v", ri)
	}
	if m := h.agentModelGone(t, slug); !m {
		t.Fatalf("compose down did not happen before the kill")
	}
	w2 := h.startWorker(t, slug+"-restarted", nil)
	h.reap(t, job)
	if _, err := h.control.Rollback(h.reqCtx(t, orchestrator.ActionJobRollback), h.actor, job, nil); !errors.Is(err, jobs.ErrJobState) {
		t.Fatalf("/rollback past the point of no return: %v", err)
	}
	h.retry(t, job)
	h.waitJob(t, job, 5*time.Minute, jobs.StatusSucceeded)
	w2.stop(t)
	steps := h.steps(t, job)
	allSucceeded(t, steps)
	ne, _ := stepByName(steps, deprovision.StepNodesExpire)
	in, _ := stepByName(steps, deprovision.StepInstance)
	if ne.Attempt != 2 || in.Attempt != 2 {
		t.Fatalf("attempts nodes.expire %d, instance.remove %d; want 2, 2", ne.Attempt, in.Attempt)
	}
	fb := h.assertDeleted(t, cr.TenantID, slug, job)
	h.shredDue(t)
	inv := h.noOrphans(t)
	return fmt.Sprintf("E2E-74 %d node(s): ExpireNode answer lost ×1 ⇒ retried in place; SIGKILL after RemoveInstance(KEEP) ⇒ "+
		"reaper worker_lost ⇒ /rollback refused (point of no return) ⇒ /retry ⇒ instance.remove attempt 2 ⇒ succeeded; %s; "+
		"detector: %s; %5.1fs", nodes, fb, inv.Summary(), time.Since(start).Seconds())
}

// agentModelGone: the tenant's container and network no longer exist (Docker).
func (h *harness) agentModelGone(t *testing.T, slug string) bool {
	t.Helper()
	_, inv := h.findings(t, false)
	for _, c := range inv.Host.Containers {
		if c.Name == "mg-hs-"+slug {
			return false
		}
	}
	for _, n := range inv.Host.Networks {
		if n.Name == "mg-t-"+slug {
			return false
		}
	}
	return true
}

// deprovisionBackupRefused is E2E-75.
func (h *harness) deprovisionBackupRefused(t *testing.T) string {
	start := time.Now()
	slug := h.slugFor("dep75")
	w0 := h.startWorker(t, slug, nil)
	cr := h.create(t, slug)
	h.waitJob(t, cr.Job.ID, 5*time.Minute, jobs.StatusSucceeded)
	w0.stop(t)
	h.devices(t, slug, 1)

	// 1. the agent refuses the final backup ⇒ failed_resumable at backup.final, nothing else done
	w1 := h.startWorker(t, slug+"-norbackup", faultinject.Plan{{Call: "agent.Backup", Mode: faultinject.Permanent, Times: 1}})
	job := h.deprovision(t, cr.TenantID, slug, false)
	h.waitJob(t, job, 5*time.Minute, jobs.StatusFailedResumable)
	steps := h.steps(t, job)
	if len(steps) != 2 || steps[1].Name != deprovision.StepFinalBackup || steps[1].ErrorCode != "agent_state" {
		t.Fatalf("steps:%s", describeSteps(steps))
	}
	if st := scalar[string](t, h, `SELECT status FROM tenants WHERE id = $1`, cr.TenantID); st != "active" {
		t.Fatalf("tenant %s without a final backup", st)
	}
	valid, total := h.nodesValid(t, slug)
	if valid != total || total == 0 {
		t.Fatalf("nodes %d valid of %d: the deprovision went past the backup", valid, total)
	}
	h.noOrphans(t) // the instance serves as before (container, edge, key)
	// 2. /rollback before the point of no return ⇒ rolled_back, the tenant active and serving
	r := h.rollback(t, job)
	if r.Job.Status != jobs.StatusCompensating {
		t.Fatalf("/rollback: %+v", r)
	}
	h.waitJob(t, job, 5*time.Minute, jobs.StatusRolledBack)
	w1.stop(t)
	if st := scalar[string](t, h, `SELECT status FROM tenants WHERE id = $1`, cr.TenantID); st != "active" {
		t.Fatalf("tenant %s after the rollback", st)
	}
	h.noOrphans(t)

	// 3. a permanent failure past the point of no return: /rollback refused, /retry converges
	w2 := h.startWorker(t, slug+"-pnr", faultinject.Plan{{Call: "headscale.ExpireNode", Mode: faultinject.Permanent, Times: 1}})
	job2 := h.deprovision(t, cr.TenantID, slug, false)
	h.waitJob(t, job2, 5*time.Minute, jobs.StatusFailedResumable)
	w2.stop(t)
	_, err := h.control.Rollback(h.reqCtx(t, orchestrator.ActionJobRollback), h.actor, job2, nil)
	var se *jobs.StateError
	if !errors.As(err, &se) || se.Reason != jobs.ReasonPointOfNoReturn {
		t.Fatalf("/rollback past the point of no return: %v", err)
	}
	w3 := h.startWorker(t, slug+"-retry", nil)
	h.retry(t, job2)
	h.waitJob(t, job2, 5*time.Minute, jobs.StatusSucceeded)
	w3.stop(t)
	allSucceeded(t, h.steps(t, job2))
	fb := h.assertDeleted(t, cr.TenantID, slug, job2)
	h.shredDue(t)
	inv := h.noOrphans(t)
	return fmt.Sprintf("E2E-75 agent.Backup refused ⇒ failed_resumable at backup.final (tenant active, %d node(s) valid) ⇒ "+
		"/rollback ⇒ rolled_back, serving; ExpireNode refused ⇒ failed_resumable past the point of no return ⇒ /rollback "+
		"refused (%s) ⇒ /retry ⇒ succeeded; %s; detector: %s; %5.1fs", valid, se.Reason, fb, inv.Summary(),
		time.Since(start).Seconds())
}

// deprovisionAll deprovisions every tenant of the run still active, suspended or failed (rolled back), concurrently
// (one lifecycle lock per tenant), then shreds them after the grace period: the end of the run leaves nothing.
func (h *harness) deprovisionAll(t *testing.T) int {
	t.Helper()
	rows, err := h.su.Query(t.Context(), `SELECT id, slug FROM tenants WHERE slug LIKE $1 AND status IN ('active', 'suspended', 'failed')
		ORDER BY created_at`, h.e.prefix+"-%")
	if err != nil {
		t.Fatal(err)
	}
	type ten struct {
		id   uuid.UUID
		slug string
	}
	var list []ten
	for rows.Next() {
		var x ten
		if err := rows.Scan(&x.id, &x.slug); err != nil {
			t.Fatal(err)
		}
		list = append(list, x)
	}
	rows.Close()
	w := h.startWorker(t, "final-deprovision", nil)
	jobsOf := make([]uuid.UUID, 0, len(list))
	for _, x := range list {
		jobsOf = append(jobsOf, h.deprovision(t, x.id, x.slug, false))
	}
	for i, j := range jobsOf {
		h.waitJob(t, j, 10*time.Minute, jobs.StatusSucceeded)
		if st := scalar[string](t, h, `SELECT status FROM tenants WHERE id = $1`, list[i].id); st != "deleted" {
			t.Fatalf("tenant %s is %s", list[i].slug, st)
		}
	}
	w.stop(t)
	h.shredDue(t)
	return len(list)
}
