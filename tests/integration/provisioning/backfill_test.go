//go:build linux && dockerintegration

package provisioning

// E2E-84 (P3-T14b): an instance built the Phase-1 way and adopted (tenant-a/b of staging) is brought under the
// orchestrator by the backfill — on the real stack of the harness: the real Host Agent and Docker, the real Headscale
// image, PostgreSQL, the test edge, the orphan detector and reconcile.
//
//  1. "Phase 1": the instance is built through the agent's typed RPCs without the activation of step 14 (storage,
//     config, network, container — the files render_instance.py renders, byte for byte: P3-T02 parity), the baseline
//     policy set, the edge attached BY HAND (reattach-edge.sh: no edge_attach flag, no meta/activated), an API key created
//     inside the container (the runbook's `headscale apikeys create`) and given to the real Adopter (P2-T11); two
//     client nodes registered.
//  2. Before: reconcile's config and noise_key checks are not_applicable; reconfigure/upgrade refuse it; the edge
//     supervisor does not re-attach it; the orphan detector over ANOTHER slug scope does not report it (the staging
//     G3 baseline finding, fixed in the detector).
//  3. Backfill: refused while the parameters do not render config.yaml on the host (no override) — nothing written;
//     dry run; run — activation without restart (same container, same start, same Noise key), version, fingerprint,
//     relay; a second run changes nothing.
//  4. After: reconcile clean on every check; detector 0 findings (both scopes); nodes unchanged (same node keys);
//     the edge supervisor re-attaches the edge after a detach; instance.reconfigure (no change ⇒ no restart) and
//     instance.restart (restart, health, post-start gate, edge.verify with the backfilled fingerprint) succeed after the
//     policy in force was recorded through the policy core (`admin policy-apply`); instance.backup then instance.restore
//     (P3-T11 — the agent restores only an activated instance with a recorded fingerprint) succeed with the same Noise
//     key; the nodes are still the same; the tenant is deprovisioned the production way (final backup, DELETE_ARCHIVED).

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/client"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/orphans"
)

// bfNode is a node as `headscale nodes list -o json` prints it (the identity a client keeps).
type bfNode struct {
	ID         uint64 `json:"id"`
	NodeKey    string `json:"node_key"`
	MachineKey string `json:"machine_key"`
}

func (h *harness) nodeKeys(t *testing.T, slug string) []bfNode {
	t.Helper()
	var l []bfNode
	if err := json.Unmarshal(bytes.TrimSpace([]byte(h.hsExec(t, slug, "nodes", "list", "-o", "json"))), &l); err != nil {
		t.Fatalf("nodes list: %v", err)
	}
	slices.SortFunc(l, func(a, b bfNode) int { return cmp.Compare(a.ID, b.ID) })
	return l
}

func (h *harness) status(t *testing.T, ref *agentv1.InstanceRef) *agentv1.InstanceStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	r, err := h.agent.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return r.GetStatus()
}

// edgeOn waits until the edge's membership of the network is `want` (or the timeout passes) and reports it.
func (h *harness) edgeOn(t *testing.T, ref *agentv1.InstanceRef, want bool, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := h.status(t, ref).GetNetwork().GetEdgeAttached()
		if got == want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(time.Second)
	}
}

func checksOf(r reconcile.Report) map[string]string {
	out := map[string]string{}
	for _, c := range r.Checks {
		out[c.Name] = c.Outcome
		if c.Reason != "" {
			out[c.Name] += "/" + c.Reason
		}
	}
	return out
}

func TestBackfillAdoptedInstance(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	e := h.e
	slug := h.slugFor("bf")
	tenantID, instanceID := uuid.New(), uuid.New()
	ref := &agentv1.InstanceRef{InstanceId: instanceID.String(), TenantId: tenantID.String(), Slug: slug}
	// far from the values the fresh databases of the other tests hand out first (their placers start at the bottom of
	// the run's range and pool, TestPostRestoreReconcile at the very top)
	runUID := int32(e.runUIDs[1] - 20) //nolint:gosec // a test range
	netCIDR := netip.PrefixFrom(lastSubnet(e.pool, 26).Addr(), 29)
	nameservers := []netip.Addr{netip.MustParseAddr("192.0.2.53")} // = the worker processes' MG_PROVISION_NAMESERVERS

	// ---------------------------------------------------------------------------------------- 1. "Phase 1"
	spec := &agentv1.InstanceSpec{Instance: ref, ImageDigest: e.hsDigest, RunUid: uint32(runUID), NetCidr: netCIDR.String(), //nolint:gosec // > 0
		Limits: &agentv1.ResourceLimits{MemoryMib: 512, CpuMillis: 1000, Pids: 256},
		// node expiry 30 days: the instance's own parameter file differs from tenant.provision's default (90)
		Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 30, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 901,
			PublicEntryIpv4: e.publicIPv4, LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}
	for _, phase := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
		agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		_, err := h.agent.EnsureInstance(cctx, &agentv1.EnsureInstanceRequest{Spec: spec, TargetPhase: phase, JobId: uuid.NewString()})
		cancel()
		if err != nil {
			t.Fatalf("EnsureInstance(%s): %v", phase, err)
		}
	}
	var st *agentv1.InstanceStatus
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		st = h.status(t, ref)
		if st.GetHealth() == agentv1.HealthState_HEALTH_STATE_HEALTHY {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("instance not healthy: %s %s", st.GetContainerState(), st.GetHealth())
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	if _, err := h.agent.BootstrapPolicy(cctx, &agentv1.BootstrapPolicyRequest{Instance: ref, JobId: uuid.NewString(),
		Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL}); err != nil {
		t.Fatalf("baseline policy: %v", err)
	}
	cancel()
	// reattach-edge.sh: the edge joins the tenant network by hand — no flag, no activation
	if _, err := h.docker.NetworkConnect(ctx, "mg-t-"+slug, client.NetworkConnectOptions{Container: e.edge}); err != nil {
		t.Fatalf("attach the edge by hand: %v", err)
	}
	if !h.edgeOn(t, ref, true, 10*time.Second) {
		t.Fatal("edge not attached")
	}
	key := strings.TrimSpace(h.hsExec(t, slug, "apikeys", "create", "--expiration", "2160h"))
	if !provisioning.ValidAPIKey(key) {
		t.Fatal("apikeys create did not print a key")
	}
	h.adopt(t, provisioning.Meta{TenantID: tenantID, InstanceID: instanceID, Slug: slug, RunUID: runUID, NetCIDR: netCIDR,
		Image: "mg-headscale@" + e.hsDigest, ImageDigest: e.hsDigest, TemplateVersion: "1", ConfigSHA256: st.GetConfigSha256()},
		headscale.NewSecret(key))
	h.devices(t, slug, 2)
	nodes := h.nodeKeys(t, slug)
	if len(nodes) != 2 || nodes[0].NodeKey == "" {
		t.Fatalf("nodes: %+v", nodes)
	}

	// ---------------------------------------------------------------------------------------- 2. before
	src := h.sources(t)
	rec, err := reconcile.New(h.wrk, reconcile.Config{Agent: h.agent, Headscale: src.Headscale, Security: securityRecorder{st: h.wrk}})
	if err != nil {
		t.Fatal(err)
	}
	rep, _, err := rec.ReconcileInstance(ctx, tenantID, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	before := checksOf(rep)
	if before[reconcile.CheckConfig] != "not_applicable/not_recorded" || before[reconcile.CheckNoiseKey] != "not_applicable/not_recorded" ||
		len(rep.Findings) != 0 {
		t.Fatalf("reconcile before: %v %+v", before, rep.Findings)
	}
	st = h.status(t, ref)
	if st.GetActivated() || st.GetEdgeAttachFlag() {
		t.Fatalf("Phase-1 instance activated=%t flag=%t", st.GetActivated(), st.GetEdgeAttachFlag())
	}
	enqueue := func(kind string) error {
		return h.api.WithPlatformJobTx(h.reqCtx(t, "platform.instance."+strings.TrimPrefix(kind, "instance.")), func(tx *store.Tx) error {
			var err error
			switch kind {
			case orchestrator.ReconfigureKind:
				_, _, err = orchestrator.EnqueueReconfigure(ctx, tx, orchestrator.ReconfigureRequest{InstanceID: instanceID, RequestedBy: &h.actor})
			case orchestrator.RestartKind:
				_, _, err = orchestrator.EnqueueRestart(ctx, tx, orchestrator.OpsRequest{InstanceID: instanceID, RequestedBy: &h.actor})
			}
			return err
		})
	}
	if err := enqueue(orchestrator.ReconfigureKind); err == nil || !strings.Contains(err.Error(), "no_config_version") {
		t.Fatalf("reconfigure before the backfill: %v", err)
	}
	// the edge supervisor does not re-attach an instance it never activated
	if _, err := h.docker.NetworkDisconnect(ctx, "mg-t-"+slug, client.NetworkDisconnectOptions{Container: e.edge}); err != nil {
		t.Fatal(err)
	}
	if h.edgeOn(t, ref, true, 15*time.Second) {
		t.Fatal("the supervisor re-attached an unflagged instance")
	}
	if _, err := h.docker.NetworkConnect(ctx, "mg-t-"+slug, client.NetworkConnectOptions{Container: e.edge}); err != nil {
		t.Fatal(err)
	}
	// the orphan detector, scope of this tenant and a scope that excludes it (the G3 run on staging: g3-* beside A/B)
	other := h.scope(true)
	other.SlugPrefix = e.prefix + "-zz-"
	for name, sc := range map[string]orphans.Scope{"own": h.scope(true), "other": other} {
		inv, err := orphans.Collect(ctx, src, sc)
		if err != nil {
			t.Fatal(err)
		}
		if fs := orphans.Check(inv); len(fs) != 0 {
			t.Fatalf("detector (%s scope) before the backfill: %v", name, fs)
		}
	}

	// a worker of the run (instance.backup/restore, reconfigure, restart, deprovision)
	w := h.startWorker(t, "bf", nil)
	jobOf := func(kind string) uuid.UUID {
		return scalar[uuid.UUID](t, h, `SELECT id FROM provisioning_jobs WHERE kind = $1 AND instance_id = $2 ORDER BY created_at DESC LIMIT 1`,
			kind, instanceID)
	}
	// the scheduled backup of a hand-built instance works (staging: A/B are backed up since P3-T11) — its restore does
	// not: the agent restores only an activated instance with a recorded Noise key fingerprint (the refusal seen on
	// staging). Older-point branch: the tenant has no applied policy yet.
	bsvc := backup.New(h.api, backup.Config{})
	bj, _, err := bsvc.RequestBackup(h.reqCtx(t, backup.AuditBackup), h.actor, instanceID, nil)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	h.waitJob(t, bj.ID, 5*time.Minute, jobs.StatusSucceeded)
	preBackup := scalar[uuid.UUID](t, h, `SELECT id FROM backups WHERE instance_id = $1 AND status = 'succeeded' ORDER BY started_at DESC LIMIT 1`, instanceID)
	if err := h.api.WithPlatformJobTx(h.reqCtx(t, backup.AuditRestore), func(tx *store.Tx) error {
		_, err := bsvc.EnqueueRestore(ctx, tx, h.actor, uuid.New(), backup.RestorePayload{BackupID: preBackup, InstanceID: instanceID,
			RestorePointOlderThanBackup: true})
		return err
	}); err != nil {
		t.Fatalf("restore before the backfill: %v", err)
	}
	refused := jobOf(backup.KindRestore)
	h.waitJob(t, refused, 3*time.Minute, jobs.StatusFailedResumable)
	if code := h.jobErrorCode(t, refused); code != "agent_state" {
		t.Fatalf("restore before the backfill: %s, want agent_state", code)
	}
	// the refused job keeps the instance's restore slot (failed_resumable: neither /cancel nor /rollback apply to
	// instance.restore) — after the backfill, /retry runs it again (the staging drill's path, procedure §6)
	if s := h.status(t, ref); !s.GetStartedAt().AsTime().Equal(st.GetStartedAt().AsTime()) || s.GetActivated() {
		t.Fatal("the refused restore touched the instance")
	}
	t.Logf("E2E-84 restore before the backfill refused: %s", h.jobErrorCode(t, refused))

	// ---------------------------------------------------------------------------------------- 3. backfill
	b := &orchestrator.Backfiller{Store: orchestrator.NewDBStore(h.wrk, nil), Agent: h.agent,
		Defaults: orchestrator.BackfillDefaults{Nameservers: nameservers}, Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	auditN := func() int64 {
		return scalar[int64](t, h, `SELECT count(*) FROM audit_events WHERE action LIKE 'platform.instance.backfill%'`)
	}
	plan, err := b.Backfill(ctx, orchestrator.BackfillRequest{TenantID: tenantID, Actor: "E2E-84"})
	var be *orchestrator.BackfillError
	if !errors.As(err, &be) || be.Code != orchestrator.BackfillConfigDiffers || plan.OperationID != nil || auditN() != 0 {
		t.Fatalf("defaults (90 days) against a 30-day instance: %+v %v", plan, err)
	}
	t.Logf("E2E-84 refused without the instance's parameters: %v", err)
	thirty := uint32(30)
	req := orchestrator.BackfillRequest{TenantID: tenantID, Actor: "E2E-84", DryRun: true,
		Overrides: orchestrator.BackfillOverrides{NodeExpiryDays: &thirty, MemoryMiB: new(uint32(512)), CPUMillis: new(uint32(1000)), PIDs: new(uint32(256))}}
	plan, err = b.Backfill(ctx, req)
	if err != nil || !plan.Changed || plan.RenderedSHA256 != plan.ConfigSHA256 || auditN() != 0 || h.status(t, ref).GetActivated() {
		t.Fatalf("dry run: %+v %v", plan, err)
	}
	raw, _ := json.Marshal(plan)
	t.Logf("E2E-84 dry run: %s", raw)
	req.DryRun = false
	plan, err = b.Backfill(ctx, req)
	if err != nil || !plan.Changed || plan.OperationID == nil {
		t.Fatalf("backfill: %+v %v", plan, err)
	}
	raw, _ = json.Marshal(plan)
	t.Logf("E2E-84 backfill: %s", raw)
	after := h.status(t, ref)
	if !after.GetActivated() || !after.GetEdgeAttachFlag() || after.GetContainerId() != st.GetContainerId() ||
		!after.GetStartedAt().AsTime().Equal(st.GetStartedAt().AsTime()) || after.GetNoiseKeyFingerprint() != st.GetNoiseKeyFingerprint() ||
		after.GetConfigSha256() != st.GetConfigSha256() {
		t.Fatalf("host after the backfill: %+v (before %+v)", after, st)
	}
	fp := scalar[string](t, h, `SELECT COALESCE(noise_key_fingerprint, '') FROM tenant_instances WHERE id = $1`, instanceID)
	cfgSHA := scalar[string](t, h, `SELECT v.config_sha256 FROM tenant_instances i JOIN instance_config_versions v ON v.id = i.config_version_id
		WHERE i.id = $1`, instanceID)
	relays := scalar[int64](t, h, `SELECT count(*) FROM relay_assignments WHERE instance_id = $1`, instanceID)
	if fp != after.GetNoiseKeyFingerprint() || cfgSHA != after.GetConfigSha256() || relays != 1 || auditN() != 2 {
		t.Fatalf("registry: fp %s cfg %s relays %d audit %d", fp, cfgSHA, relays, auditN())
	}
	rowVersion := scalar[int64](t, h, `SELECT version FROM tenant_instances WHERE id = $1`, instanceID)
	plan, err = b.Backfill(ctx, req)
	if err != nil || plan.Changed || auditN() != 2 || scalar[int64](t, h, `SELECT version FROM tenant_instances WHERE id = $1`, instanceID) != rowVersion {
		t.Fatalf("second backfill: %+v %v", plan, err)
	}

	// /retry of the refused instance.restore (P3-T11, AC-19) — the backup taken BEFORE the backfill, the staging case: its
	// manifest carries the Noise key the helper computed, which the backfill recorded since. The device inventory holds
	// the two nodes, as inventory.sync records them.
	for _, n := range nodes {
		h.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name)
			VALUES ($1, $2, $3, $4, $5)`, tenantID, instanceID, int64(n.ID), n.MachineKey, "node-"+strconv.FormatUint(n.ID, 10)) //nolint:gosec // a node id
	}
	h.retry(t, refused)
	restoreJob := &refused
	h.waitJob(t, *restoreJob, 8*time.Minute, jobs.StatusSucceeded)
	restored := h.status(t, ref)
	if !restored.GetStartedAt().AsTime().After(st.GetStartedAt().AsTime()) || restored.GetNoiseKeyFingerprint() != fp ||
		!restored.GetActivated() || !restored.GetNetwork().GetEdgeAttached() {
		t.Fatalf("after the restore: %+v", restored)
	}
	if got := h.nodeKeys(t, slug); !slices.Equal(got, nodes) {
		t.Fatalf("nodes changed by the restore: %+v → %+v", nodes, got)
	}
	rep, _, err = rec.ReconcileInstance(ctx, tenantID, instanceID)
	if err != nil || rep.Status != reconcile.StatusClean {
		t.Fatalf("reconcile after the restore: %+v %v", rep, err)
	}
	t.Logf("E2E-84 restore of the pre-backfill backup %s: job %s succeeded; fingerprint unchanged %t; nodes unchanged; reconcile %s", preBackup,
		*restoreJob, restored.GetNoiseKeyFingerprint() == fp, rep.Status)

	// ---------------------------------------------------------------------------------------- 4. after
	rep, _, err = rec.ReconcileInstance(ctx, tenantID, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	afterChecks := checksOf(rep)
	for name, outcome := range afterChecks {
		if outcome != reconcile.OutcomeOK {
			t.Errorf("reconcile after: %s %s", name, outcome)
		}
	}
	if rep.Status != reconcile.StatusClean || len(rep.Findings) != 0 {
		t.Fatalf("reconcile after: %s %v %+v", rep.Status, afterChecks, rep.Findings)
	}
	host, err := rec.ReconcileHost(ctx)
	if err != nil || host.Status != reconcile.StatusClean {
		t.Fatalf("host reconcile: %+v %v", host, err)
	}
	for name, sc := range map[string]orphans.Scope{"own": h.scope(true), "other": other} {
		inv, err := orphans.Collect(ctx, src, sc)
		if err != nil {
			t.Fatal(err)
		}
		if fs := orphans.Check(inv); len(fs) != 0 {
			t.Fatalf("detector (%s scope) after the backfill: %v", name, fs)
		}
	}
	if got := h.nodeKeys(t, slug); !slices.Equal(got, nodes) {
		t.Fatalf("nodes changed: %+v → %+v", nodes, got)
	}
	// the supervisor now re-attaches it (edge recreated, host rebooted — §11.4, G3)
	if _, err := h.docker.NetworkDisconnect(ctx, "mg-t-"+slug, client.NetworkDisconnectOptions{Container: e.edge}); err != nil {
		t.Fatal(err)
	}
	if !h.edgeOn(t, ref, true, 30*time.Second) {
		t.Fatal("the supervisor did not re-attach the backfilled instance")
	}

	// the policy in force recorded through the policy core (`admin policy-apply`, P3-T08a — step 7 of the staging procedure):
	// the post-start gate of restart and the normal branch of the restore compare against it
	core, err := policies.New(h.wrk, policies.Config{Registry: src.Headscale})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := core.Apply(ctx, policies.ApplyRequest{TenantID: tenantID, HuJSON: templates.BootstrapPolicy, Actor: "E2E-84"}); err != nil ||
		res.State != policies.StateApplied {
		t.Fatalf("policy-apply: %+v %v", res, err)
	}

	// instance.reconfigure (no change: the recorded parameters render the configuration in force) and instance.restart
	if err := enqueue(orchestrator.ReconfigureKind); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	rj := jobOf(orchestrator.ReconfigureKind)
	h.waitJob(t, rj, 3*time.Minute, jobs.StatusSucceeded)
	if s := h.status(t, ref); !s.GetStartedAt().AsTime().Equal(restored.GetStartedAt().AsTime()) {
		t.Fatal("a reconfiguration without change restarted the instance")
	}
	if err := enqueue(orchestrator.RestartKind); err != nil {
		t.Fatalf("restart: %v", err)
	}
	sj := jobOf(orchestrator.RestartKind)
	h.waitJob(t, sj, 4*time.Minute, jobs.StatusSucceeded)
	edgeStep, _ := stepByName(h.steps(t, sj), "edge.verify")
	restarted := h.status(t, ref)
	if !restarted.GetStartedAt().AsTime().After(restored.GetStartedAt().AsTime()) || restarted.GetNoiseKeyFingerprint() != fp ||
		!restarted.GetNetwork().GetEdgeAttached() {
		t.Fatalf("after the restart: %+v", restarted)
	}
	if got := h.nodeKeys(t, slug); !slices.Equal(got, nodes) {
		t.Fatalf("nodes changed by the restart: %+v → %+v", nodes, got)
	}
	rep, _, err = rec.ReconcileInstance(ctx, tenantID, instanceID)
	if err != nil || rep.Status != reconcile.StatusClean {
		t.Fatalf("reconcile after the restart: %+v %v", rep, err)
	}
	t.Logf("E2E-84 summary: refused without overrides (%s); second run: changed=false, %s; reconcile before %v, after %v; "+
		"nodes %d unchanged (node keys) through backfill + restart + restore; supervisor re-attached; reconfigure %s (no restart), restart %s "+
		"(edge.verify %s); container %s started %s → %s",
		orchestrator.BackfillConfigDiffers, itemsOf(plan), before, afterChecks, len(nodes), rj, sj, edgeStep.Status,
		st.GetContainerId()[:12], st.GetStartedAt().AsTime().Format(time.RFC3339), restarted.GetStartedAt().AsTime().Format(time.RFC3339))

	// the tenant leaves the production way (final backup, DELETE_ARCHIVED) — nothing is left for the other tests
	dj := h.deprovision(t, tenantID, slug, false)
	h.waitJob(t, dj, 10*time.Minute, jobs.StatusSucceeded)
	w.stop(t)
	if st := scalar[string](t, h, `SELECT status FROM tenant_instances WHERE id = $1`, instanceID); st != "removed" {
		t.Fatalf("instance %s after the deprovision", st)
	}
	inv := h.noOrphans(t)
	if slices.Contains(inv.Host.Dirs, instanceID.String()) {
		t.Fatal("the instance directory is left")
	}
}

func itemsOf(p orchestrator.BackfillPlan) string {
	var s []string
	for _, it := range p.Items {
		s = append(s, it.Name+"="+it.State)
	}
	return strings.Join(s, ",")
}

// adopt is `meshguard admin adopt-instance` (P2-T11) with the api's roles: the real Adopter (pre-flight of the key
// through the edge admin listener, registry, SecretStore, verification through Registry.ForTenant, other keys expired,
// activation).
func (h *harness) adopt(t *testing.T, m provisioning.Meta, key headscale.Secret) {
	t.Helper()
	kr, err := secrets.LoadKeyring(secrets.KEKApp, h.keyring)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(h.api, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	dir := tenants.New(h.api, tenants.Options{BaseDomain: h.e.baseDomain})
	loc, err := locator.New(dir, sec, locator.Options{AdminURL: h.e.edgeAdmin, EdgeTokenFile: h.e.edgeTokenFile()})
	if err != nil {
		t.Fatal(err)
	}
	ad := &provisioning.Adopter{Tenants: dir, Platform: platform.New(h.api), Secrets: sec, Locator: loc}
	res, err := ad.Adopt(t.Context(), provisioning.AdoptRequest{Meta: m, APIKey: key, HostName: "pit-host",
		BaseDomain: h.e.baseDomain, IdP: provisioning.KeycloakRealmIdP(uuid.New(), &m.TenantID, m.Slug, h.e.baseDomain)})
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if !res.TenantCreated || !res.InstanceCreated || res.ValidKeys != 1 {
		t.Fatalf("adopt: %+v", res)
	}
	t.Logf("E2E-84 adopted %s (instance %s, key %s, %s)", m.Slug, m.InstanceID, res.KeyPrefix, res.HeadscaleVersion)
}
