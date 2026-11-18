//go:build linux && dockerintegration

package provisioning

// E2E-72 (P3-T17, master §17.2 "Đối soát sau khi restore PostgreSQL về thời điểm cũ hơn", §20 P3-T17): the reconcile
// after PostgreSQL was restored to an OLDER point, against the real world of this harness — the Host Agent driving
// Docker, the Headscale instances it provisioned ([images.mg-headscale]), the test edge, PostgreSQL:
//
//  1. tenant P provisioned by the real orchestrator; a platform session and a pending approval request; P's Owner
//     invitation is pending (step 16);
//  2. pg_dump of the database (inside the PostgreSQL container — a real dump, custom format);
//  3. after the dump: tenant Q provisioned (it exists on the host only once the dump is restored); P's API key rotated
//     (apikey.rotate, forced — the key of the dump expired); a NEWER policy applied to P (policy core); the session
//     logged out, the approval rejected, the invitation revoked (revocations of the gap);
//  4. pg_restore of the dump into a new database — the restored registry is older than the host;
//  5. post-restore-reconcile (internal/provisioning/postrestore with the production collaborators: the agent client,
//     the rotation of P3-T10, the policy core, a registry through the edge) in a dry run, then for real.
//
// Verified: the dry run changes nothing (database, keys, policy); then no session nor approval of the dump is valid,
// the invitation is revoked; Q is reported as an orphan and is neither deleted (its container runs, its directory
// stays) nor adopted (no registry row); P's key — refused, it was rotated in the gap — is re-issued through the agent's
// BootstrapApiKey and is the ONLY valid key of the instance, usable from the restored registry; the newer policy on
// Headscale is NOT overwritten (GetPolicy unchanged, recorded as the current application, imported as a validated
// desired version, tenant flagged); inventory.sync is queued for P; audit.gap is recorded; a second run is idempotent.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/postrestore"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/faultinject"
)

// pgContainer is the PostgreSQL container of the run (PIT_PG_CONTAINER, else the host of the admin URL).
func pgContainer(t *testing.T) string {
	if c := os.Getenv("PIT_PG_CONTAINER"); c != "" {
		return c
	}
	u, err := url.Parse(os.Getenv("MG_TEST_PG_ADMIN_URL"))
	if err != nil || u.Hostname() == "" {
		t.Fatal("PIT_PG_CONTAINER or MG_TEST_PG_ADMIN_URL is required")
	}
	return u.Hostname()
}

// pgExec runs a PostgreSQL client tool as the postgres user inside the PostgreSQL container (its local socket).
func (h *harness) pgExec(t *testing.T, cmd ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	ex, err := h.docker.ExecCreate(ctx, pgContainer(t), client.ExecCreateOptions{User: "postgres", Cmd: cmd, AttachStdout: true,
		AttachStderr: true})
	if err != nil {
		t.Fatalf("exec %v: %v", cmd[0], err)
	}
	at, err := h.docker.ExecAttach(ctx, ex.ID, client.ExecAttachOptions{})
	if err != nil {
		t.Fatalf("attach %v: %v", cmd[0], err)
	}
	var out bytes.Buffer
	_, _ = io.Copy(&out, at.Reader)
	at.Close()
	for {
		r, err := h.docker.ExecInspect(ctx, ex.ID, client.ExecInspectOptions{})
		if err != nil {
			t.Fatalf("inspect %v: %v", cmd[0], err)
		}
		if !r.Running {
			if r.ExitCode != 0 {
				t.Fatalf("%v: exit %d\n%s", cmd, r.ExitCode, strings.ToValidUTF8(out.String(), "?"))
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// restoredWorld is what the post-restore reconcile runs on: the worker's roles on the restored database.
type restoredWorld struct {
	db  string
	su  *pgx.Conn
	st  *store.Store
	sec *secrets.Store
	reg *headscale.CachingRegistry
	svc *postrestore.Service
}

func (h *harness) openRestored(t *testing.T, db string) *restoredWorld {
	t.Helper()
	w := &restoredWorld{db: db, su: h.pg.Admin(t, db), st: h.pg.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 6)}
	kr, err := secrets.LoadKeyring(secrets.KEKApp, h.keyring)
	if err != nil {
		t.Fatal(err)
	}
	if w.sec, err = secrets.New(w.st, secrets.Options{App: kr}); err != nil {
		t.Fatal(err)
	}
	loc, err := locator.New(tenants.New(w.st, tenants.Options{BaseDomain: h.e.baseDomain}), w.sec,
		locator.Options{AdminURL: h.e.edgeAdmin, EdgeTokenFile: h.e.edgeTokenFile(), TenantStatuses: apikey.TenantStatuses})
	if err != nil {
		t.Fatal(err)
	}
	w.reg = headscale.NewRegistry(loc, headscale.Options{})
	sec := securityRecorder{st: w.st}
	keys, err := apikey.New(w.st, apikey.Config{Locator: loc, Secrets: w.sec, Security: sec, Agent: h.agent,
		Invalidate: []apikey.Invalidator{w.reg}})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policies.New(w.st, policies.Config{Registry: w.reg})
	if err != nil {
		t.Fatal(err)
	}
	if w.svc, err = postrestore.New(w.st, postrestore.Config{Agent: h.agent, Headscale: w.reg, Keys: keys, Policies: pol,
		Security: sec, Actor: "E2E-72"}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *restoredWorld) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.su.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("restored database: %v\n%s", err, sql)
	}
	return n
}

// registryPolicySHA is the sha256 of the policy the instance stores, read through a registry (GetPolicy).
func registryPolicySHA(t *testing.T, reg headscale.Registry, tenant uuid.UUID) string {
	t.Helper()
	inst, err := reg.ForTenant(t.Context(), tenant)
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	p, err := inst.GetPolicy(t.Context())
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return policies.SHA256Hex(p.Data)
}

func TestPostRestoreReconcile(t *testing.T) {
	h := newHarness(t)
	w := h.startWorker(t, "pr", faultinject.Plan{})
	ctx := t.Context()

	// 1. before the dump
	slugP, slugQ := h.slugFor("prp"), h.slugFor("prq")
	p := h.create(t, slugP)
	h.waitJob(t, p.Job.ID, 6*time.Minute, jobs.StatusSucceeded)
	instP, _, prefixP := h.instanceOf(t, p.TenantID)
	idp, sa1, sa2 := uuid.New(), uuid.New(), uuid.New()
	h.exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.test/realms/platform-pr', 'mg-portal', 'keycloak', 'active')`, idp)
	for i, id := range []uuid.UUID{sa1, sa2} {
		h.exec(t, `INSERT INTO identities (id, idp_id, scope, subject, email) VALUES ($1, $2, 'platform', $3, $4)`, id, idp,
			fmt.Sprintf("pr-sa-%d", i), fmt.Sprintf("pr-sa-%d@example.test", i))
	}
	session := uuid.NewString()
	h.exec(t, `INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at)
		VALUES (sha256(convert_to($1::text, 'UTF8')), $2, $3, 'admin', now(), now() + interval '8 hours', now() + interval '12 hours')`,
		session, sa1, idp)
	approval := uuid.New()
	h.exec(t, `INSERT INTO approval_requests (id, scope, action, resource_type, resource_id, payload, payload_sha256,
		requested_by_identity_id, expires_at) VALUES ($1, 'platform', 'tenant.delete', 'tenant', $2, '{}', $3, $4,
		now() + interval '24 hours')`, approval, p.TenantID.String(), policies.SHA256Hex("{}"), sa1)
	if n := scalar[int64](t, h, `SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'`, p.TenantID); n != 1 {
		t.Fatalf("P's Owner invitation: %d pending", n)
	}
	bootstrapSHA := scalar[string](t, h, `SELECT applied_sha256 FROM policy_applications WHERE tenant_id = $1 AND state = 'applied'
		AND superseded_at IS NULL`, p.TenantID)

	// 2. the dump (custom format, inside the PostgreSQL container)
	restorePoint := scalar[time.Time](t, h, `SELECT now()`).UTC().Truncate(time.Second)
	dumpFile := "/tmp/" + h.db + ".dump"
	h.pgExec(t, "pg_dump", "-U", "postgres", "-Fc", "-d", h.db, "-f", dumpFile)
	t.Logf("E2E-72 dump of %s at %s", h.db, restorePoint.Format(time.RFC3339))

	// 3. after the dump: Q provisioned, P's key rotated, a newer policy on P, the revocations of the gap
	q := h.create(t, slugQ)
	h.waitJob(t, q.Job.ID, 6*time.Minute, jobs.StatusSucceeded)
	instQ, _, _ := h.instanceOf(t, q.TenantID)
	loc, err := locator.New(tenants.New(h.wrk, tenants.Options{BaseDomain: h.e.baseDomain}), h.sec,
		locator.Options{AdminURL: h.e.edgeAdmin, EdgeTokenFile: h.e.edgeTokenFile(), TenantStatuses: apikey.TenantStatuses})
	if err != nil {
		t.Fatal(err)
	}
	liveReg := headscale.NewRegistry(loc, headscale.Options{})
	rot, err := apikey.New(h.wrk, apikey.Config{Locator: loc, Secrets: h.sec, Security: securityRecorder{st: h.wrk}, Agent: h.agent,
		Invalidate: []apikey.Invalidator{liveReg}})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := rot.Rotate(ctx, apikey.Request{TenantID: p.TenantID, InstanceID: instP, Force: true, Trigger: apikey.TriggerAdmin})
	if err != nil || rotated.Outcome != apikey.OutcomeRotated || rotated.KeyPrefix == prefixP {
		t.Fatalf("rotation in the gap: %+v %v", rotated, err)
	}
	pol, err := policies.New(h.wrk, policies.Config{Registry: liveReg})
	if err != nil {
		t.Fatal(err)
	}
	newer := "// applied after the dump (E2E-72)\n{\"grants\": [{\"src\": [\"autogroup:member\"], \"dst\": [\"autogroup:member\"], " +
		"\"ip\": [\"tcp:9443\"]}], \"ssh\": []}\n"
	applied, err := pol.Apply(ctx, policies.ApplyRequest{TenantID: p.TenantID, HuJSON: newer, Actor: "E2E-72"})
	if err != nil || applied.State != policies.StateApplied {
		t.Fatalf("newer policy: %+v %v", applied, err)
	}
	newerSHA := applied.AppliedSHA256
	h.exec(t, `UPDATE sessions SET revoked_at = now() WHERE id_hash = sha256(convert_to($1::text, 'UTF8'))`, session)
	h.exec(t, `UPDATE approval_requests SET status = 'rejected', decided_at = now(), approved_by_identity_id = $2 WHERE id = $1`,
		approval, sa2)
	h.exec(t, `UPDATE tenant_invitations SET status = 'revoked' WHERE tenant_id = $1 AND status = 'pending'`, p.TenantID)
	w.stop(t)

	// 4. the restore into a new database (the cluster's roles exist; ownership and grants come with the dump)
	restored := h.db + "_r"
	adm := h.pg.Admin(t, "postgres")
	if _, err := adm.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{restored}.Sanitize()+" TEMPLATE template0 OWNER mg_migrator"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adm.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{restored}.Sanitize()+" WITH (FORCE)")
	})
	h.pgExec(t, "pg_restore", "-U", "postgres", "-d", restored, "--exit-on-error", dumpFile)
	h.pgExec(t, "rm", "-f", dumpFile)
	r := h.openRestored(t, restored)
	if n := r.count(t, `SELECT count(*) FROM tenants WHERE id = $1`, q.TenantID); n != 0 {
		t.Fatal("the restored database knows Q")
	}
	if n := r.count(t, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL`); n == 0 {
		t.Fatal("the dump holds no live session: the case would prove nothing")
	}

	// 5a. dry run: nothing changes
	digest := func() string {
		return fmt.Sprintf("%d|%d|%d|%d|%d|%s", r.count(t, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL`),
			r.count(t, `SELECT count(*) FROM approval_requests WHERE status IN ('pending', 'approved')`),
			r.count(t, `SELECT count(*) FROM tenant_invitations WHERE status = 'pending'`),
			r.count(t, `SELECT count(*) FROM audit_events`), r.count(t, `SELECT count(*) FROM provisioning_jobs`),
			validPrefixes(h.keys(t, p.TenantID, instP, slugP)))
	}
	before := digest()
	dry, err := r.svc.Run(ctx, postrestore.Request{RestorePoint: restorePoint, DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if after := digest(); after != before || registryPolicySHA(t, liveReg, p.TenantID) != newerSHA {
		t.Fatalf("the dry run changed something: %s → %s", before, after)
	}
	dryKey := ""
	for _, k := range dry.APIKeys {
		if k.TenantID == p.TenantID {
			dryKey = k.Outcome + "/" + k.Reason
		}
	}
	if dryKey != postrestore.KeyWouldReissue+"/"+apikey.ReasonKeyRejected {
		t.Fatalf("dry run, P's key: %q", dryKey)
	}

	// 5b. the reconcile
	rep, err := r.svc.Run(ctx, postrestore.Request{RestorePoint: restorePoint})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var summary []string
	note := func(s string, a ...any) { summary = append(summary, fmt.Sprintf(s, a...)) }

	// no session or grant of the dump is valid; the invitation of the gap stays revoked
	if n := r.count(t, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL`); n != 0 || rep.Sessions.Revoked == 0 {
		t.Fatalf("sessions: %d still valid (report %+v)", n, rep.Sessions)
	}
	if n := r.count(t, `SELECT count(*) FROM approval_requests WHERE status IN ('pending', 'approved')`); n != 0 ||
		r.count(t, `SELECT count(*) FROM approval_requests WHERE id = $1 AND status = 'expired'`, approval) != 1 {
		t.Fatalf("approvals: %d still open", n)
	}
	if n := r.count(t, `SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'revoked'`, p.TenantID); n != 1 {
		t.Fatalf("P's invitation: %d revoked", n)
	}
	note("sessions revoked %d, approvals expired %d, invitations revoked %d", rep.Sessions.Revoked, rep.Approvals.Expired,
		rep.Invitations.Revoked)

	// Q: an orphan — reported, not deleted, not adopted
	orphan := slices.IndexFunc(rep.Instances.Orphans, func(o postrestore.OrphanInstance) bool { return o.InstanceID == instQ.String() })
	if rep.Instances.Inventory != "checked" || orphan < 0 || rep.Instances.Orphans[orphan].Slug != slugQ ||
		rep.Instances.Orphans[orphan].TenantLabel != q.TenantID.String() {
		t.Fatalf("Q is not reported as an orphan: %+v", rep.Instances)
	}
	ci, err := h.docker.ContainerInspect(ctx, "mg-hs-"+slugQ, client.ContainerInspectOptions{})
	if err != nil || ci.Container.State == nil || !ci.Container.State.Running {
		t.Fatalf("Q's container after the reconcile: %v", err)
	}
	if n := r.count(t, `SELECT count(*) FROM tenant_instances WHERE id = $1`, instQ) +
		r.count(t, `SELECT count(*) FROM tenants WHERE id = $1 OR slug = $2`, q.TenantID, slugQ); n != 0 {
		t.Fatal("Q was adopted into the restored registry")
	}
	if !slices.ContainsFunc(rep.ReviewRequired, func(it postrestore.ReviewItem) bool {
		return it.InstanceID != nil && *it.InstanceID == instQ && slices.Contains(it.Reasons, postrestore.ReviewOrphan)
	}) {
		t.Fatalf("Q is not in review_required: %+v", rep.ReviewRequired)
	}
	if n := r.count(t, `SELECT count(*) FROM security_events WHERE kind = 'reconcile.unknown_instance'
		AND details->>'instance_id' = $1`, instQ.String()); n != 1 {
		t.Fatalf("security event of the orphan: %d", n)
	}
	note("orphan Q %s reported (container running, no registry row); %d orphan(s) on the host in all", short(instQ),
		len(rep.Instances.Orphans))

	// P's key: rotated in the gap ⇒ refused ⇒ re-issued by the agent, the only valid key, usable from the restored registry
	var keyRes postrestore.APIKeyResult
	for _, k := range rep.APIKeys {
		if k.TenantID == p.TenantID {
			keyRes = k
		}
	}
	keys := h.keys(t, p.TenantID, instP, slugP)
	recorded := ""
	if err := r.su.QueryRow(ctx, `SELECT api_key_prefix FROM tenant_instances WHERE id = $1`, instP).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if keyRes.Outcome != postrestore.KeyReissued || keyRes.Reason != apikey.ReasonKeyRejected || keyRes.PreviousPrefix != prefixP ||
		!slices.Equal(validPrefixes(keys), []string{keyRes.KeyPrefix}) || recorded != keyRes.KeyPrefix ||
		keys[rotated.KeyPrefix] || keys[prefixP] {
		t.Fatalf("P's key: report %+v, valid %v, recorded %s (gap key %s, dump key %s)", keyRes, validPrefixes(keys), recorded,
			rotated.KeyPrefix, prefixP)
	}
	r.reg.Invalidate(p.TenantID)
	inst, err := r.reg.ForTenant(ctx, p.TenantID)
	if err == nil {
		_, err = inst.ListAPIKeys(ctx)
	}
	if err != nil {
		t.Fatalf("the restored registry cannot use the re-issued key: %v", err)
	}
	note("P's key %s (dump) → rotated %s in the gap → re-issued %s by BootstrapApiKey: the only valid key", prefixP,
		rotated.KeyPrefix, keyRes.KeyPrefix)

	// the newer policy on Headscale is not overwritten
	if got := registryPolicySHA(t, r.reg, p.TenantID); got != newerSHA {
		t.Fatalf("Headscale's policy changed: %s, want the newer %s", got, newerSHA)
	}
	var polRes policies.RunningResult
	for _, x := range rep.Policies {
		if x.TenantID == p.TenantID {
			polRes = x
		}
	}
	if polRes.Outcome != policies.RunningAdopted || polRes.RecordedSHA != bootstrapSHA || polRes.RunningSHA256 != newerSHA ||
		polRes.VersionStatus != "validated" ||
		r.count(t, `SELECT count(*) FROM policy_applications a JOIN tenants t ON t.id = a.tenant_id
			JOIN policy_versions v ON v.id = t.desired_policy_version_id WHERE a.tenant_id = $1 AND a.state = 'applied'
			AND a.superseded_at IS NULL AND a.trigger = 'restore' AND a.applied_sha256 = $2 AND v.state = 'validated'
			AND v.kind = 'user'`, p.TenantID, newerSHA) != 1 ||
		r.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2`, p.TenantID,
			policies.SecurityRestoreReview) != 1 {
		t.Fatalf("policy step: %+v", polRes)
	}
	note("policy: Headscale keeps the newer %s… (the restored database had %s…): recorded, validated version desired, flagged",
		newerSHA[:12], bootstrapSHA[:12])

	// inventory.sync, audit.gap, maintenance, the audit pair
	if rep.InventorySync.Enqueued < 1 || r.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'inventory.sync'
		AND instance_id = $1 AND status = 'queued'`, instP) != 1 {
		t.Fatalf("inventory.sync: %+v", rep.InventorySync)
	}
	if n := r.count(t, `SELECT count(*) FROM audit_events WHERE action = $1 AND details->>'restore_point_unix' = $2`,
		postrestore.ActionGap, fmt.Sprint(restorePoint.Unix())); n < 2 || !rep.AuditGap.Platform {
		t.Fatalf("audit.gap: %d", n)
	}
	if rep.Status != postrestore.StatusCompleted || len(rep.Incomplete) != 0 ||
		r.count(t, `SELECT count(*) FROM system_settings WHERE key = 'maintenance' AND (value->>'enabled')::boolean
			AND value->'post_restore'->>'status' = 'reconciled'`) != 1 {
		t.Fatalf("status %s, incomplete %v", rep.Status, rep.Incomplete)
	}

	// a second run: idempotent
	again, err := r.svc.Run(ctx, postrestore.Request{RestorePoint: restorePoint})
	if err != nil || again.Sessions.Revoked != 0 || again.Approvals.Expired != 0 || again.AuditGap.Written != 0 ||
		again.InventorySync.Existing < 1 {
		t.Fatalf("second run: %+v %v", again, err)
	}
	for _, k := range again.APIKeys {
		if k.TenantID == p.TenantID && k.Outcome != postrestore.KeyOK {
			t.Fatalf("second run, P's key: %+v", k)
		}
	}
	for _, x := range again.Policies {
		if x.TenantID == p.TenantID && x.Outcome != policies.RunningMatch {
			t.Fatalf("second run, P's policy: %+v", x)
		}
	}
	if got := validPrefixes(h.keys(t, p.TenantID, instP, slugP)); !slices.Equal(got, []string{keyRes.KeyPrefix}) {
		t.Fatalf("second run changed the keys: %v", got)
	}
	note("second run: nothing revoked, no key or policy change, audit.gap not repeated, sync already queued")
	if l := h.leaks(t); len(l) != 0 {
		t.Fatalf("an API key reached a worker log: %v", l)
	}
	t.Logf("E2E-72 summary:\n  %s", strings.Join(summary, "\n  "))

	// the original database still describes the host (P and Q live): the harness tears them down from it
	if n := h.teardown(t); n != 2 {
		t.Errorf("teardown: %d instance(s), want 2", n)
	}
}
