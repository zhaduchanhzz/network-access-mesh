package platform_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// TestMaintenanceFlag (P3-T17) — the persisted maintenance flag through the api's platform role: absent = off; on and
// off are audited platform.maintenance.enable / .disable (actor_type system, the command and request id) in the same
// transaction; setting the state it already has writes and audits nothing; a bad reason is refused before anything is
// written; off is refused while the post-restore reconcile is recorded running or failed (ErrPostRestorePending, nothing
// written) unless forced — the event says so — and allowed once it is reconciled; an unreadable value counts as ON.
func TestMaintenanceFlag(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	su := pg.Admin(t, db)
	st := pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 4)
	svc := platform.New(st)
	ctx := t.Context()
	actor := func(cmd string) platform.SystemActor {
		return platform.SystemActor{Command: cmd, RequestID: "admin-" + uuid.NewString()}
	}
	audits := func(action string) int {
		var n int
		if err := su.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = $1 AND tenant_id IS NULL
			AND actor_type = 'system' AND resource_id = 'maintenance'`, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if m, err := svc.Maintenance(ctx); err != nil || m.Enabled {
		t.Fatalf("absent flag: %+v %v", m, err)
	}
	if _, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Enable: true, Reason: "Not A Code!", Actor: actor("x")}); !errors.Is(err, platform.ErrInvalid) {
		t.Fatalf("bad reason: %v", err)
	}
	res, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Enable: true, Reason: "pg-restore", Actor: actor("meshguard admin maintenance on")})
	if err != nil || !res.Changed || !res.After.Enabled || res.After.Reason != "pg-restore" || res.After.Since == nil ||
		res.After.By != "meshguard admin maintenance on" || audits(platform.ActionMaintenanceEnable) != 1 {
		t.Fatalf("on: %+v %v (audits %d)", res, err, audits(platform.ActionMaintenanceEnable))
	}
	if res, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Enable: true, Actor: actor("again")}); err != nil ||
		res.Changed || audits(platform.ActionMaintenanceEnable) != 1 {
		t.Fatalf("on again: %+v %v", res, err)
	}

	// a post-restore reconcile recorded running: off is refused, nothing written
	if err := st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		m, err := platform.ReadMaintenance(ctx, q)
		if err != nil {
			return err
		}
		m.PostRestore = &platform.PostRestore{RestorePoint: time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
			RunID: uuid.New(), Status: platform.PostRestoreRunning, Runs: 1, StartedAt: time.Now().UTC()}
		return platform.WriteMaintenance(ctx, q, m)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Actor: actor("off")}); !errors.Is(err, platform.ErrPostRestorePending) {
		t.Fatalf("off while running: %v", err)
	}
	if m, _ := svc.Maintenance(ctx); !m.Enabled || audits(platform.ActionMaintenanceDisable) != 0 {
		t.Fatalf("refused off changed something: %+v", m)
	}
	res, err = svc.SetMaintenance(ctx, platform.MaintenanceChange{Force: true, Actor: actor("meshguard admin maintenance off")})
	if err != nil || !res.Changed || res.After.Enabled || res.After.PostRestore == nil ||
		audits(platform.ActionMaintenanceDisable) != 1 {
		t.Fatalf("forced off: %+v %v", res, err)
	}
	var forced string
	if err := su.QueryRow(ctx, `SELECT details->>'forced' FROM audit_events WHERE action = $1`,
		platform.ActionMaintenanceDisable).Scan(&forced); err != nil || forced != "true" {
		t.Fatalf("forced off audit: %q %v", forced, err)
	}
	// reconciled: on then off without force
	if _, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Enable: true, Actor: actor("on")}); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `UPDATE system_settings SET value = jsonb_set(value, '{post_restore,status}', '"reconciled"')
		WHERE key = 'maintenance'`); err != nil {
		t.Fatal(err)
	}
	if res, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Actor: actor("off")}); err != nil || !res.Changed || res.After.Enabled {
		t.Fatalf("off after reconcile: %+v %v", res, err)
	}
	if res, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Actor: actor("off again")}); err != nil || res.Changed {
		t.Fatalf("off again: %+v %v", res, err)
	}

	// the gate: the startup switch alone, the flag alone, an unreadable value (ON), a change seen by Refresh
	g := platform.NewMaintenanceGate(st, platform.MaintenanceGateOptions{Forced: true})
	if on, err := g.Refresh(ctx); err != nil || !on {
		t.Fatalf("forced gate: %v %v", on, err)
	}
	g = platform.NewMaintenanceGate(st, platform.MaintenanceGateOptions{})
	if !g.On() {
		t.Fatal("a gate is ON before its first read")
	}
	changes := 0
	g.OnChange(func(bool) { changes++ })
	if on, err := g.Refresh(ctx); err != nil || on || changes != 1 {
		t.Fatalf("gate, flag off: %v %v (%d changes)", on, err, changes)
	}
	if _, err := su.Exec(ctx, `UPDATE system_settings SET value = '"garbage"' WHERE key = 'maintenance'`); err != nil {
		t.Fatal(err)
	}
	if on, err := g.Refresh(ctx); err == nil || !on || changes != 2 {
		t.Fatalf("gate, unreadable flag: %v %v (%d changes)", on, err, changes)
	}
	if _, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Actor: actor("off unreadable")}); err == nil {
		t.Fatal("off over an unreadable flag must fail")
	}
}
