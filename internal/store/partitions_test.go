package store

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// monthStart returns the first instant (UTC) of the month offset months after now.
func monthStart(offset int) time.Time {
	n := time.Now().UTC()
	return time.Date(n.Year(), n.Month()+time.Month(offset), 1, 0, 0, 0, 0, time.UTC)
}

func partitionName(table string, offset int) string {
	return fmt.Sprintf("partitions.%s_p%s", table, monthStart(offset).Format("200601"))
}

// TestPartitionsRouteByMonth: an audit event of the current month and one of next month, written by the application
// through WithTenantTx, land in their monthly partitions — not in DEFAULT (partitions created by migration 0004).
func TestPartitionsRouteByMonth(t *testing.T) {
	e, db, f, _ := fixtureDB(t)
	ctx := ctxT(t)
	s := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	for _, offset := range []int{0, 1, 3} {
		at := monthStart(offset).Add(36 * time.Hour)
		if offset == 0 {
			at = time.Now().UTC()
		}
		err := s.WithTenantTx(ctx, f.a.id, func(q *sqlcdb.Queries) error {
			row, err := q.InsertAuditEvent(ctx, sqlcdb.InsertAuditEventParams{
				OccurredAt: &at, TenantID: &f.a.id, ActorType: "system", Action: "partition.routing_test",
				ResourceType: "audit_event", Outcome: "success", Details: []byte(`{}`),
			})
			if err != nil {
				return err
			}
			got, err := q.AuditEventPartition(ctx, sqlcdb.AuditEventPartitionParams{OccurredAt: row.OccurredAt, ID: row.ID})
			if err != nil {
				return err
			}
			if want := partitionName("audit_events", offset); got != want {
				return fmt.Errorf("event at %s stored in %s, want %s", at.Format(time.RFC3339), got, want)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	}
}

// TestPartitionsDirectAccessDenied: no application role may read or write a partition of audit_events directly —
// RLS of the parent would not apply there (§6.1).
func TestPartitionsDirectAccessDenied(t *testing.T) {
	e, db, _, _ := fixtureDB(t)
	ctx := ctxT(t)
	parts := []string{partitionName("audit_events", 0), partitionName("audit_events", 1), "partitions.audit_events_default"}
	for _, role := range appRoles {
		c := e.connectAs(t, db, role)
		for _, p := range parts {
			for _, sql := range []string{
				"SELECT * FROM " + p + " LIMIT 1",
				"INSERT INTO " + p + " (tenant_id, actor_type, action, resource_type, outcome) VALUES (NULL, 'system', 'x', 'y', 'success')",
				"UPDATE " + p + " SET outcome = 'failure'",
				"DELETE FROM " + p,
				"TRUNCATE " + p,
			} {
				_, err := c.Exec(ctx, sql)
				wantSQLState(t, role+": "+sql, err, privilegeErr)
			}
		}
	}
}

// TestPartitionMaintain: the partition.maintain job (mg_partition_maint) creates the missing months idempotently,
// leaves no privilege on any partition (the CI check), reports rows that fell into DEFAULT, and cannot erase audit
// rows except by dropping a partition.
func TestPartitionMaintain(t *testing.T) {
	e := requireDB(t)
	db := e.newDatabase(t, 0) // own database: this test changes the partition set
	ctx := ctxT(t)
	su := e.connectAdmin(t, db)

	if v, err := PartitionGrantViolations(ctx, su); err != nil || len(v) != 0 {
		t.Fatalf("after migration: violations %v, err %v", v, err)
	}
	m, err := OpenPartitionMaintainer(ctx, e.storeURL(db), e.creds(t, "mg_partition_maint"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := OpenPartitionMaintainer(ctx, e.storeURL(db), e.creds(t, "mg_api_platform")); err == nil {
		t.Error("OpenPartitionMaintainer accepted a role that does not own audit_events")
	}

	rep, err := m.Maintain(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"audit_events_p" + monthStart(4).Format("200601"), "audit_events_p" + monthStart(5).Format("200601")}
	if len(rep) != 1 || !slices.Equal(rep[0].Created, want) || rep[0].DefaultRows != 0 {
		t.Fatalf("first run = %+v, want created %v and 0 default rows", rep, want)
	}
	if rep, err = m.Maintain(ctx, PartitionMonthsAhead); err != nil || len(rep[0].Created) != 0 {
		t.Fatalf("second run = %+v, err %v; want nothing created", rep, err)
	}
	var bounds string
	if err := su.QueryRow(ctx, "SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE oid = $1::regclass",
		partitionName("audit_events", 5)).Scan(&bounds); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("FOR VALUES FROM ('%s') TO ('%s')", monthStart(5).Format("2006-01-02 15:04:05-07"),
		monthStart(6).Format("2006-01-02 15:04:05-07")); bounds != want {
		t.Errorf("bounds = %s, want %s (UTC month)", bounds, want)
	}
	if v, err := PartitionGrantViolations(ctx, su); err != nil || len(v) != 0 {
		t.Fatalf("after partition.maintain: violations %v, err %v", v, err)
	}

	// A row beyond the prepared months falls into DEFAULT and is reported (alert — §6.1).
	far := monthStart(30)
	if _, err := su.Exec(ctx, `INSERT INTO audit_events (occurred_at, actor_type, action, resource_type, outcome)
		VALUES ($1, 'system', 'far.future', 'test', 'success'), (now(), 'system', 'now', 'test', 'success')`, far); err != nil {
		t.Fatal(err)
	}
	if rep, err = m.Maintain(ctx, PartitionMonthsAhead); err != nil || rep[0].DefaultRows != 1 {
		t.Fatalf("report = %+v, err %v; want DefaultRows = 1", rep, err)
	}

	// Append-only, even for the owner: UPDATE/DELETE/TRUNCATE are stopped by the triggers (TRUNCATE also on a
	// partition, where partition.maintain copied the trigger).
	owner := e.connectAs(t, db, "mg_partition_maint")
	for _, sql := range []string{
		"UPDATE " + partitionName("audit_events", 0) + " SET outcome = 'failure'",
		"DELETE FROM " + partitionName("audit_events", 0),
		"DELETE FROM partitions.audit_events_default",
		"TRUNCATE audit_events",
		"TRUNCATE " + partitionName("audit_events", 0),
		"TRUNCATE " + partitionName("audit_events", 5),
		"TRUNCATE partitions.audit_events_default",
	} {
		_, err := owner.Exec(ctx, sql)
		wantSQLState(t, "owner: "+sql, err, "23001")
	}
	var rows int64
	if err := su.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&rows); err != nil || rows != 2 {
		t.Errorf("audit rows after the attempts = %d (err %v), want 2", rows, err)
	}

	// Negative control for the CI check: a grant on a partition, a partition without RLS and a default privilege are
	// all reported — and even with the stray grant RLS on the partition still returns no row.
	p := partitionName("audit_events", 0)
	for _, sql := range []string{
		"GRANT SELECT ON " + p + " TO mg_api_tenant",
		"ALTER TABLE " + partitionName("audit_events", 1) + " DISABLE ROW LEVEL SECURITY",
		"ALTER DEFAULT PRIVILEGES FOR ROLE mg_partition_maint IN SCHEMA partitions GRANT SELECT ON TABLES TO mg_api_tenant",
		"GRANT USAGE ON SCHEMA partitions TO mg_api_tenant",
	} {
		if _, err := su.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	v, err := PartitionGrantViolations(ctx, su)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"partition_grant: " + p, "mg_api_tenant", "partition_without_rls: " + partitionName("audit_events", 1), "default_privileges: partitions"} {
		if !anyContains(v, w) {
			t.Errorf("CI check missed %q; violations:\n%v", w, v)
		}
	}
	var leaked int64
	if err := e.connectAs(t, db, "mg_api_tenant").QueryRow(ctx, "SELECT count(*) FROM "+p).Scan(&leaked); err != nil || leaked != 0 {
		t.Errorf("stray grant: mg_api_tenant reads %d rows of %s (err %v), want 0 (RLS on the partition)", leaked, p, err)
	}
}

// TestPartitionMaintainRejectsOtherTables: the maintenance function only accepts range partitioned parents.
func TestPartitionMaintainRejectsOtherTables(t *testing.T) {
	e, db, _, _ := fixtureDB(t)
	ctx := ctxT(t)
	c := e.connectAs(t, db, "mg_partition_maint")
	for _, sql := range []string{
		"SELECT mg_partition_maintain('tenants'::regclass, 3)",
		"SELECT mg_partition_maintain('audit_events'::regclass, 25)",
	} {
		_, err := c.Exec(ctx, sql)
		wantSQLState(t, sql, err, "22023")
	}
	for _, role := range appRoles {
		_, err := e.connectAs(t, db, role).Exec(ctx, "SELECT public.mg_partition_maintain('public.audit_events'::regclass, 3)")
		// mg_readonly has no USAGE on schema public at all: the name does not even resolve (42P01).
		if code := SQLState(err); code != privilegeErr && (role != "mg_readonly" || code != "42P01") {
			t.Errorf("%s calling mg_partition_maintain: SQLSTATE %q (%v), want %s", role, code, err, privilegeErr)
		}
	}
}
