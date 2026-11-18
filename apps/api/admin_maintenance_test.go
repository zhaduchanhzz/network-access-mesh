package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMaintenanceCommand — `meshguard admin maintenance` end to end on a migrated database with the api's roles (dev:
// the events go through audit.Record in the command's transaction): usage errors (2) before anything is opened; status
// of an absent flag (off); on (audited, reason kept), on again (unchanged); off refused while the post-restore
// reconcile is recorded running (1, nothing changed), forced off (audited forced); the JSON output on every success.
func TestMaintenanceCommand(t *testing.T) {
	c := newCLIEnv(t, "", "")
	out := func() maintenanceOutput {
		t.Helper()
		var o maintenanceOutput
		if err := json.Unmarshal([]byte(strings.TrimSpace(c.stdout.String())), &o); err != nil {
			t.Fatalf("output %q: %v", c.stdout.String(), err)
		}
		return o
	}
	for _, args := range [][]string{{"maintenance"}, {"maintenance", "pause"}, {"maintenance", "off", "--reason", "x"},
		{"maintenance", "on", "--force"}, {"maintenance", "status", "extra"}} {
		if code := c.run(nil, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := c.run(nil, "maintenance", "status"); code != 0 || out().Enabled {
		t.Fatalf("status of an absent flag: %d %s", code, c.out.String())
	}
	if code := c.run(nil, "maintenance", "on", "--reason", "pg-restore"); code != 0 {
		t.Fatalf("on: %d %s", code, c.out.String())
	}
	if o := out(); !o.Enabled || !o.Changed || o.Reason != "pg-restore" || o.By != "meshguard admin maintenance on" {
		t.Fatalf("on: %+v", o)
	}
	if code := c.run(nil, "maintenance", "on"); code != 0 || out().Changed {
		t.Fatalf("on again: %d %s", code, c.out.String())
	}
	if _, err := c.su.Exec(t.Context(), `UPDATE system_settings SET value = value || jsonb_build_object('post_restore',
		jsonb_build_object('restore_point', '2026-11-18T02:30:00Z', 'run_id', gen_random_uuid(), 'status', 'running',
		'runs', 1, 'started_at', '2026-11-18T05:00:00Z')) WHERE key = 'maintenance'`); err != nil {
		t.Fatal(err)
	}
	if code := c.run(nil, "maintenance", "off"); code != 1 || !strings.Contains(c.stderr.String(), "post-restore reconcile has not completed") {
		t.Fatalf("off while the reconcile runs: %d %s", code, c.out.String())
	}
	if code := c.run(nil, "maintenance", "status"); code != 0 || !out().Enabled {
		t.Fatalf("status after the refusal: %s", c.out.String())
	}
	if code := c.run(nil, "maintenance", "off", "--force"); code != 0 {
		t.Fatalf("forced off: %d %s", code, c.out.String())
	}
	if o := out(); o.Enabled || !o.Changed || o.PostRestore == nil || o.Note == "" {
		t.Fatalf("forced off: %+v", o)
	}
	var n int
	if err := c.su.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE resource_id = 'maintenance'
		AND actor_type = 'system' AND ((action = 'platform.maintenance.enable' AND details->>'reason' = 'pg-restore')
		OR (action = 'platform.maintenance.disable' AND details->>'forced' = 'true'))`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit: %d (%v)", n, err)
	}
}
