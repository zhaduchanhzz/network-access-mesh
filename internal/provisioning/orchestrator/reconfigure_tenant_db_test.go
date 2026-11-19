package orchestrator

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// TestReconfigureTenantScope: the internal entry point EnqueueReconfigure called in a TENANT transaction (PUT
// /tenants/{t}/dns/settings — P4-T12): the operation is the tenant's (requested in its audit), the job applies the new
// nameservers with a restart, and closes the operation in a transaction of the tenant (a platform transaction cannot
// write a tenant's event — RLS of 0004); an unchanged request closes it the same way.
func TestReconfigureTenantScope(t *testing.T) {
	g := newReconfigureDBRig(t)
	ctx := context.Background()
	enqueue := func(ns []string) jobs.Job {
		t.Helper()
		var j jobs.Job
		if err := g.api.WithTenantJobTx(ctx, g.tid, func(tx *store.Tx) error {
			var err error
			j, _, err = EnqueueReconfigure(ctx, tx, ReconfigureRequest{TenantID: g.tid, InstanceID: g.inst,
				Change: ConfigChange{Nameservers: ns}, RequestedBy: &g.actor, Source: "tenant_dns_settings",
				Action: "dns.settings.update"})
			return err
		}); err != nil {
			t.Fatalf("enqueue in the tenant's transaction: %v", err)
		}
		return j
	}
	j := enqueue([]string{"9.9.9.9", "2620:fe::fe"})
	g.waitJob(t, j.ID, jobs.StatusSucceeded)
	if got := dbScalar[string](t, g.dbRig, `SELECT c.params->>'nameservers' FROM tenant_instances i
		JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`, g.inst); got != `["9.9.9.9", "2620:fe::fe"]` {
		t.Fatalf("nameservers in force: %s", got)
	}
	if _, _, restarts := g.cfg.host(); restarts != 1 {
		t.Fatalf("restarts %d", restarts)
	}
	j2 := enqueue([]string{"9.9.9.9", "2620:fe::fe"}) // the same: no new version, no restart
	g.waitJob(t, j2.ID, jobs.StatusSucceeded)
	got := dbScalar[string](t, g.dbRig, `SELECT string_agg(action, ',' ORDER BY occurred_at, id) FROM audit_events
		WHERE tenant_id = $1 AND action LIKE 'dns.settings.update.%'`, g.tid)
	want := "dns.settings.update.requested,dns.settings.update.succeeded,dns.settings.update.requested,dns.settings.update.succeeded"
	if got != want {
		t.Fatalf("tenant audit %q, want %q", got, want)
	}
	if n := dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action LIKE 'dns.settings.%'`); n != 0 {
		t.Fatalf("%d platform events of a tenant operation", n)
	}
	_ = uuid.Nil
}
