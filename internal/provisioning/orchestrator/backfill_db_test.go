package orchestrator

// The backfill of an adopted instance against PostgreSQL 18 (storetest): the registry rows written by the adopt path
// (tenants.Service Register + Activate with the api's roles, as `admin adopt-instance` writes them), the real DBStore
// on the worker's roles, a fake host (bfAgent). Checks the rows written, the audit pair, idempotence (a second run
// changes no row: version columns unchanged, no audit event) and that the instance becomes eligible for
// instance.reconfigure (P3-T13), instance.restart and instance.upgrade (P3-T13a) — they refused it with
// no_config_version before.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestBackfillDB(t *testing.T) {
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	su := env.Admin(t, db)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := su.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := su.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
		return n
	}
	host := uuid.New()
	exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry)
		VALUES ($1, 'mg-staging', 'lab', int4range(30000, 30100), '10.250.0.0/24', '{"ipv4": "192.0.2.10", "mode": "vps_gateway"}')`, host)
	api := env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 4)
	wrk := env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 4)

	// tenant-a as adopt-instance registers it (P2-T11)
	b, _, ag := bfWorld(t)
	img := ag.st.GetImageDigest()
	tid, iid := uuid.New(), uuid.New()
	reg := tenants.New(api, tenants.Options{BaseDomain: "mg.test"})
	ad := tenants.Adoption{TenantID: tid, Slug: "tenant-a", Name: "tenant-a", Region: "lab",
		Instance: tenants.InstanceSpec{ID: iid, HostID: host, HeadscaleVersion: "v0.29.7", ImageDigest: img,
			ControlHostname: "tenant-a.mesh.mg.test", ServerURL: "https://tenant-a.mesh.mg.test",
			BaseDomain: "tenant-a.tail.mg.test", InternalAddress: "hs-tenant-a:8080", RunUID: 30001,
			NetCIDR: netip.MustParsePrefix("10.250.0.0/29"), DataPath: "/opt/meshguard/tenants/" + iid.String() + "/data"},
		IdP: tenants.IdPSpec{ID: uuid.New(), Scope: "tenant", TenantID: &tid, Issuer: "https://auth.mg.test/realms/tenant-a",
			ClientID: "mg-portal", Driver: "keycloak", DriverRef: "tenant-a"}}
	if _, err := reg.Register(ctx, ad); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Activate(ctx, tid, iid); err != nil {
		t.Fatal(err)
	}
	enqueue := func(kind string) error {
		return api.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
			var err error
			switch kind {
			case ReconfigureKind:
				_, _, err = EnqueueReconfigure(ctx, tx, ReconfigureRequest{InstanceID: iid})
			case UpgradeKind:
				_, _, err = EnqueueUpgrade(ctx, tx, OpsRequest{InstanceID: iid, ImageDigest: "sha256:" + strings.Repeat("9", 64)})
			case RestartKind:
				_, _, err = EnqueueRestart(ctx, tx, OpsRequest{InstanceID: iid})
			}
			return err
		})
	}
	var ce *CreateError
	for _, k := range []string{ReconfigureKind, UpgradeKind} {
		if err := enqueue(k); !errors.As(err, &ce) || ce.Reason != "no_config_version" {
			t.Fatalf("%s before the backfill: %v, want no_config_version", k, err)
		}
	}

	b.Store = NewDBStore(wrk, nil)
	req := BackfillRequest{TenantID: tid, DryRun: true, Actor: "test"}
	plan, err := b.Backfill(ctx, req)
	if err != nil || !plan.Changed || plan.InstanceID != iid {
		t.Fatalf("dry run: %+v, %v", plan, err)
	}
	for k, s := range items(plan) {
		if s != ItemWouldWrite {
			t.Errorf("dry run: %s %s", k, s)
		}
	}
	if n := count(`SELECT count(*)::int FROM instance_config_versions`) + count(`SELECT count(*)::int FROM relay_regions WHERE tenant_id IS NOT NULL`) +
		count(`SELECT count(*)::int FROM audit_events WHERE action LIKE 'platform.instance.backfill%'`); n != 0 {
		t.Fatalf("the dry run wrote %d rows", n)
	}

	req.DryRun = false
	plan, err = b.Backfill(ctx, req)
	if err != nil || !plan.Changed || plan.OperationID == nil {
		t.Fatalf("run: %+v, %v", plan, err)
	}
	var (
		cfgID, verID              uuid.UUID
		sha, status, tv, params   string
		fp                        string
		derp, rowVersion, version int
		appliedAt                 bool
	)
	if err := su.QueryRow(ctx, `SELECT i.config_version_id, v.id, v.config_sha256, v.status, v.template_version, v.params::text,
			v.applied_at IS NOT NULL, i.noise_key_fingerprint, i.derp_region_id, i.version, v.version
		FROM tenant_instances i JOIN instance_config_versions v ON v.id = i.config_version_id WHERE i.id = $1`, iid).Scan(
		&cfgID, &verID, &sha, &status, &tv, &params, &appliedAt, &fp, &derp, &rowVersion, &version); err != nil {
		t.Fatal(err)
	}
	if cfgID != verID || sha != ag.onDisk || status != "applied" || tv != "1" || !appliedAt || fp != bfFP || derp != 901 || version != 1 ||
		!strings.Contains(params, `"memory_mib": 512`) || !strings.Contains(params, `"log_level": "LOG_LEVEL_INFO"`) {
		t.Fatalf("version row: %s %s %s %s %v %s %d v%d %s", sha, status, tv, fp, appliedAt, params, derp, version, cfgID)
	}
	if n := count(`SELECT count(*)::int FROM relay_regions r JOIN relay_assignments a ON a.relay_region_id = r.id
		WHERE r.tenant_id = $1 AND r.code = 'mg-tenant-a' AND r.kind = 'embedded' AND r.derp_region_id = 901
		AND r.hostname = 'tenant-a.mesh.mg.test' AND r.stun_port = 3478 AND a.instance_id = $2 AND a.status = 'active'`, tid, iid); n != 1 {
		t.Fatalf("relay rows: %d", n)
	}
	if n := count(`SELECT count(*)::int FROM audit_events WHERE operation_id = $1 AND tenant_id IS NULL AND actor_type = 'system'
		AND resource_id = $2 AND action IN ('platform.instance.backfill.requested', 'platform.instance.backfill.succeeded')`,
		*plan.OperationID, iid.String()); n != 2 {
		t.Fatalf("audit pair: %d", n)
	}

	// a second run changes no row
	plan, err = b.Backfill(ctx, req)
	if err != nil || plan.Changed || plan.OperationID != nil {
		t.Fatalf("second run: %+v, %v", plan, err)
	}
	if n := count(`SELECT version::int FROM tenant_instances WHERE id = $1`, iid); n != rowVersion {
		t.Fatalf("tenant_instances.version %d → %d", rowVersion, n)
	}
	if n := count(`SELECT count(*)::int FROM audit_events WHERE action LIKE 'platform.instance.backfill%'`) +
		count(`SELECT count(*)::int FROM instance_config_versions`); n != 3 {
		t.Fatalf("second run wrote: %d audit events + versions", n)
	}
	if n := count(`SELECT version::int FROM relay_regions WHERE tenant_id = $1`, tid); n != 1 {
		t.Fatalf("relay region version %d", n)
	}

	// eligible for the operations of P3-T13 and P3-T13a now
	for _, k := range []string{ReconfigureKind, RestartKind, UpgradeKind} {
		if err := enqueue(k); err != nil {
			t.Fatalf("%s after the backfill: %v", k, err)
		}
	}

	// the registry write re-checks under its transaction: a version recorded meanwhile is not overwritten
	exec(`UPDATE tenant_instances SET config_version_id = NULL, noise_key_fingerprint = $2 WHERE id = $1`, iid, strings.Repeat("3", 64))
	err = b.Store.RecordBackfill(ctx, BackfillRecord{TenantID: tid, InstanceID: iid, Fingerprint: bfFP})
	if !errors.Is(err, ErrState) {
		t.Fatalf("fingerprint recorded meanwhile: %v", err)
	}

	// a lifecycle job holding the tenant's lock refuses the backfill (read from provisioning_jobs)
	exec(`UPDATE tenant_instances SET config_version_id = $2, noise_key_fingerprint = $3 WHERE id = $1`, iid, verID, bfFP)
	held := count(`SELECT count(*)::int FROM provisioning_jobs WHERE lock_key = $1 AND status IN ('running', 'compensating', 'failed_resumable')`,
		"tenant:"+tid.String()+":lifecycle")
	if held != 0 {
		t.Fatalf("unexpected lock holders: %d", held)
	}
	exec(`UPDATE provisioning_jobs SET status = 'running', lock_key = $1, started_at = now() WHERE kind = 'instance.restart' AND instance_id = $2`,
		"tenant:"+tid.String()+":lifecycle", iid)
	_, err = b.Backfill(context.WithoutCancel(ctx), BackfillRequest{TenantID: tid, DryRun: true})
	var be *BackfillError
	if !errors.As(err, &be) || be.Code != BackfillLifecycleBusy {
		t.Fatalf("lock held: %v", err)
	}
}
