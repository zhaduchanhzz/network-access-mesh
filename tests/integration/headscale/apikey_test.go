package contract

// Phase 13 (P3-T10): the rotation of the instance API key (internal/provisioning/apikey) against the real Headscale of
// the contract run (the patched build), through the real admin listener of the edge, with the register database of
// phases 8–12 (worker roles, RLS), the real SecretStore and the production locator. The verification of the task:
// "Key cũ bị expire; adapter dùng key mới":
//
//   - the run's key (run.sh: `headscale apikeys create --expiration 3h`) is stored as version 1 and recorded on the
//     instance row — it expires within 21 days, so it is due; it is the only valid key of the instance;
//   - a registry of "another process" (the production locator) caches the old key before the rotation;
//   - apikey.rotate: CreateAPIKey with the old key and an explicit 90-day expiration (V-06), verified with the new key,
//     version 2 stored, row + audit pair in one transaction, the old key expired, version 1 destroyed;
//   - afterwards the old key gets 401 through the edge; ListAPIKeys with the new key shows exactly ONE valid key — the
//     new one, with the requested expiration; a fresh registry and the cached one (401 ⇒ reload ⇒ replay) work;
//   - instance.reconcile of P3-T12 (report only): API key check ok, valid=1, no finding, no security event;
//   - a second run is skipped (not_due); a forced one rotates again and leaves one valid key;
//   - no key in the audit, the security events, the adapter log or the observations.
//
// This phase changes the instance's API key: it is the LAST phase of run.sh.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// platformSecurity is the security recorder of apps/worker (a platform transaction of the worker's store).
type platformSecurity struct{ st *store.Store }

func (p platformSecurity) RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error) {
	var wrote bool
	err := p.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		wrote, err = audit.RecordSecurityEvent(ctx, q, ev)
		return err
	})
	return wrote, err
}

func validKeys(t *testing.T, inst headscale.Instance) (all []headscale.APIKey, valid []string) {
	t.Helper()
	keys, err := inst.ListAPIKeys(ctx(t))
	if err != nil {
		t.Fatalf("ListAPIKeys: %s", describe(err))
	}
	now := time.Now()
	for _, k := range keys {
		if k.Expiration.IsZero() || k.Expiration.After(now) {
			valid = append(valid, k.Prefix)
		}
	}
	slices.Sort(valid)
	return keys, valid
}

// current reads a version of the instance's key (to look for it in the logs afterwards).
func current(t *testing.T, ss *secrets.Store, v int32) string {
	t.Helper()
	pt, err := ss.Get(ctx(t), secrets.TenantRef(tenantID, apikey.SecretName, v))
	if err != nil {
		t.Fatalf("version %d: %v", v, err)
	}
	defer pt.Wipe()
	return string(pt.Bytes())
}

func TestP13_APIKeyRotation(t *testing.T) {
	d := devSetup(t)
	c := ctx(t)
	lf, err := os.OpenFile(filepath.Join(d.stateDir, "adapter.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304/G703: run.sh's state directory
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lf.Close() })
	log := logx.New(lf, slog.LevelDebug, "apikey")
	dir := t.TempDir()
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	for name, content := range map[string]string{"kek-1": hex.EncodeToString(kek) + "\n", secrets.ActiveFile: "kek-1\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := secrets.New(d.wrkSt, secrets.Options{App: kr, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	reg := tenants.New(d.wrkSt, tenants.Options{BaseDomain: "contract.test"})
	tokenFile := filepath.Join(os.Getenv("HSCT_SECRETS_DIR"), "edge_token")
	rotLoc, err := locator.New(reg, ss, locator.Options{AdminURL: d.adminURL, EdgeTokenFile: tokenFile, Logger: log,
		TenantStatuses: apikey.TenantStatuses})
	if err != nil {
		t.Fatal(err)
	}
	prodLoc, err := locator.New(reg, ss, locator.Options{AdminURL: d.adminURL, EdgeTokenFile: tokenFile, Logger: log})
	if err != nil {
		t.Fatal(err)
	}

	// 1. the run's key becomes the registered key of the instance (version 1)
	oldKey := headscale.NewSecret(d.apiKey)
	oldPrefix := headscale.APIKeyPrefix(oldKey)
	all, valid := validKeys(t, d.inst(t))
	if !slices.Equal(valid, []string{oldPrefix}) {
		t.Fatalf("before the rotation the run's key must be the only valid key: %v", valid)
	}
	var oldExp time.Time
	for _, k := range all {
		if k.Prefix == oldPrefix {
			oldExp = k.Expiration
		}
	}
	ref1 := secrets.TenantRef(tenantID, apikey.SecretName, 1)
	if err := ss.Put(c, ref1, []byte(d.apiKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.su.Exec(context.Background(), `UPDATE tenant_instances SET api_key_secret_ref = $1, api_key_prefix = $2,
		api_key_expires_at = $3 WHERE id = $4`, ref1.String(), oldPrefix, oldExp, instanceID); err != nil {
		t.Fatal(err)
	}
	// 2. another process caches the old key
	other := headscale.NewRegistry(prodLoc, headscale.Options{Logger: log, Timeout: 15 * time.Second})
	cached, err := other.ForTenant(c, tenantID)
	if err != nil {
		t.Fatalf("ForTenant before: %s", describe(err))
	}
	if _, err := cached.ListAPIKeys(c); err != nil {
		t.Fatalf("cached before: %s", describe(err))
	}

	// 3. the rotation
	svc, err := apikey.New(d.wrkSt, apikey.Config{Locator: rotLoc, Secrets: ss, Security: platformSecurity{st: d.wrkSt},
		Headscale: headscale.Options{Logger: log, Timeout: 15 * time.Second}, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := svc.Rotate(c, apikey.Request{TenantID: tenantID, InstanceID: instanceID, Trigger: apikey.TriggerJob})
	took := time.Since(start)
	if err != nil || res.Outcome != apikey.OutcomeRotated || res.Mode != apikey.ModeAPI || res.PreviousPrefix != oldPrefix ||
		res.KeyPrefix == oldPrefix || res.RefVersion != 2 || res.ValidKeys != 1 {
		t.Fatalf("rotation: %+v %v", res, err)
	}

	// 4. the old key is refused, the new key is the only valid one, with the requested expiration
	status, _ := d.raw(t, rawReq{method: "GET", path: "/api/v1/apikey"}) // raw requests carry the run's (old) key
	if status != 401 {
		t.Fatalf("old key: HTTP %d, want 401", status)
	}
	fresh := headscale.NewRegistry(prodLoc, headscale.Options{Logger: log, Timeout: 15 * time.Second})
	inst, err := fresh.ForTenant(c, tenantID)
	if err != nil {
		t.Fatalf("ForTenant after: %s", describe(err))
	}
	all, valid = validKeys(t, inst)
	if !slices.Equal(valid, []string{res.KeyPrefix}) {
		t.Fatalf("valid keys after the rotation: %v (new %s)", valid, res.KeyPrefix)
	}
	var newExp, oldExpired time.Time
	for _, k := range all {
		switch k.Prefix {
		case res.KeyPrefix:
			newExp = k.Expiration
		case oldPrefix:
			oldExpired = k.Expiration
		}
	}
	if diff := newExp.Sub(start.Add(apikey.MaxTTL)); diff > time.Minute || diff < -time.Minute || !newExp.Equal(res.ExpiresAt.UTC()) {
		t.Fatalf("new key expires %s (recorded %s)", newExp, res.ExpiresAt)
	}
	if _, err := cached.ListAPIKeys(c); err != nil {
		t.Fatalf("cached registry after the rotation (expected 401 ⇒ reload ⇒ replay): %s", describe(err))
	}
	keys := []string{d.apiKey, current(t, ss, 2)}
	var rowRef, rowPrefix string
	var rowExp time.Time
	if err := d.su.QueryRow(context.Background(), `SELECT api_key_secret_ref, api_key_prefix, api_key_expires_at
		FROM tenant_instances WHERE id = $1`, instanceID).Scan(&rowRef, &rowPrefix, &rowExp); err != nil {
		t.Fatal(err)
	}
	if rowRef != secrets.TenantRef(tenantID, apikey.SecretName, 2).String() || rowPrefix != res.KeyPrefix || !rowExp.Equal(newExp) {
		t.Fatalf("registry row: %s %s %s", rowRef, rowPrefix, rowExp)
	}
	if n := d.count(t, `SELECT count(*) FROM secrets WHERE tenant_id = $1 AND name = $2 AND version = 1 AND destroyed_at IS NOT NULL`,
		tenantID, apikey.SecretName); n != 1 {
		t.Fatal("version 1 not destroyed")
	}
	if n := d.count(t, `SELECT count(*) FROM audit_events r JOIN audit_events s ON s.operation_id = r.operation_id
		WHERE r.action = 'instance.apikey.rotate.requested' AND s.action = 'instance.apikey.rotate.succeeded'
		AND r.tenant_id IS NULL AND s.details->>'key_prefix' = $1`, res.KeyPrefix); n != 1 {
		t.Fatalf("audit pair: %d", n)
	}
	d.record(t, "P3-T10", "xoay API key qua adapter (key hiện hành → key mới)",
		fmt.Sprintf("trong %d ms: key cũ %s (hạn %s) ⇒ HTTP 401 qua edge, ListAPIKeys: %d key, đúng 1 còn hạn = %s, hạn %s (yêu cầu now+2160h, khớp từng giây); key cũ expiration = %s; version secret 1 → 2 (bản 1 đã hủy); registry khác đang cache key cũ vẫn gọi được (401 ⇒ nạp lại ⇒ phát lại)",
			took.Milliseconds(), oldPrefix, oldExp.UTC().Format(time.RFC3339), len(all), res.KeyPrefix,
			newExp.UTC().Format(time.RFC3339), oldExpired.UTC().Format(time.RFC3339)),
		"CreateAPIKey(key cũ) → ListAPIKeys(key mới) → SecretStore v2 → swap có điều kiện + audit → ExpireAPIKey(cũ, bằng key mới) → ListAPIKeys")

	// 5. reconcile (P3-T12): nothing to report
	rec, err := reconcile.New(d.wrkSt, reconcile.Config{Headscale: fresh, Security: platformSecurity{st: d.wrkSt}})
	if err != nil {
		t.Fatal(err)
	}
	rep, skipped, err := rec.ReconcileInstance(c, tenantID, instanceID)
	if err != nil || skipped != "" {
		t.Fatalf("reconcile: %q %v", skipped, err)
	}
	var check reconcile.Check
	for _, x := range rep.Checks {
		if x.Name == reconcile.CheckAPIKeys {
			check = x
		}
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Kind, "api_key") {
			t.Fatalf("reconcile finding after the rotation: %+v", f)
		}
	}
	if check.Outcome != reconcile.OutcomeOK || check.Note != "valid=1" {
		t.Fatalf("reconcile api_keys check: %+v", check)
	}
	if n := d.count(t, `SELECT count(*) FROM security_events WHERE kind LIKE 'apikey.%' OR kind LIKE 'reconcile.api_key%'`); n != 0 {
		t.Fatalf("security events: %d", n)
	}
	d.record(t, "P3-T10", "reconcile (P3-T12) sau khi xoay",
		fmt.Sprintf("kiểm api_keys: %s (%s), 0 finding api_key_*, 0 security_event apikey.*/reconcile.api_key*", check.Outcome, check.Note),
		"khóa API key của instance (store.WithTenantLock, apikey.LockName) bao quanh việc đọc lại prefix + ListAPIKeys")

	// 6. not due any more; forced once more
	if again, err := svc.Rotate(c, apikey.Request{TenantID: tenantID, InstanceID: instanceID}); err != nil ||
		again.Outcome != apikey.OutcomeSkipped || again.SkipReason != apikey.SkipNotDue {
		t.Fatalf("second run: %+v %v", again, err)
	}
	forced, err := svc.Rotate(c, apikey.Request{TenantID: tenantID, InstanceID: instanceID, Force: true, Trigger: apikey.TriggerAdmin})
	if err != nil || forced.Outcome != apikey.OutcomeRotated || forced.PreviousPrefix != res.KeyPrefix {
		t.Fatalf("forced: %+v %v", forced, err)
	}
	if _, valid = validKeys(t, inst); !slices.Equal(valid, []string{forced.KeyPrefix}) {
		t.Fatalf("valid keys after the forced rotation: %v", valid)
	}
	d.record(t, "P3-T10", "chạy lại", fmt.Sprintf("lần 2: skipped %s; --force: %s → %s, còn đúng 1 key hợp lệ",
		apikey.SkipNotDue, res.KeyPrefix, forced.KeyPrefix), "")

	// 7. no key anywhere (version 2 was destroyed by the forced rotation)
	keys = append(keys, current(t, ss, 3))
	if _, err := ss.Get(c, secrets.TenantRef(tenantID, apikey.SecretName, 2)); err == nil {
		t.Fatal("version 2 still readable after the forced rotation")
	}
	logText, _ := os.ReadFile(filepath.Join(d.stateDir, "adapter.log")) //nolint:gosec // G304: run.sh's state directory
	obsText, _ := os.ReadFile(d.obsFile)
	var dbText string
	if err := d.su.QueryRow(context.Background(), `SELECT coalesce(string_agg(details::text, ' '), '') FROM (
		SELECT details FROM audit_events UNION ALL SELECT details FROM security_events) x`).Scan(&dbText); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"adapter log": string(logText), "observations": string(obsText), "audit/security": dbText} {
		for _, k := range keys {
			if strings.Contains(text, k) || strings.Contains(text, k[23:]) {
				t.Fatalf("a key appears in the %s", name)
			}
		}
	}
}
