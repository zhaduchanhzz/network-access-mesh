package store

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/riverqueue/river"
)

// queueTables classifies every table of the River schema (database/river/grants.sql). A River release that adds a
// table fails TestMigrateQueue until the table is classified here and granted there.
var queueTables = map[string]bool{ // true = used by the worker's River client
	"river_job": true, "river_leader": true, "river_queue": true, "river_notification": true,
	"river_migration": false, // mg_migrator only
}

type queueTestArgs struct{}

func (queueTestArgs) Kind() string { return "store.queue_test" }

// TestMigrateQueue: River's own migrator creates its tables in schema river (owned by mg_migrator) right after goose; a
// second run applies nothing; the privileges of database/river/grants.sql are exactly the ones each role needs —
// enqueue for the application roles, everything for the worker's platform role, nothing for the others, TRUNCATE for
// nobody — and the application roles enqueue inside their RLS transaction.
func TestMigrateQueue(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.sharedDB(t)
	su := e.connectAdmin(t, db)

	var versions []int64
	rows, err := su.Query(ctx, "SELECT version FROM river.river_migration WHERE line = 'main' ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, v)
	}
	if len(versions) == 0 || versions[0] != 1 || versions[len(versions)-1] != int64(len(versions)) {
		t.Fatalf("river migrations = %v, want 1…N", versions)
	}
	applied, err := MigrateQueue(ctx, e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil || len(applied) != 0 {
		t.Fatalf("second MigrateQueue: applied %v, err %v; want nothing", applied, err)
	}

	// every table classified, every object owned by mg_migrator
	rows, err = su.Query(ctx, `SELECT c.relname, c.relkind::text, r.rolname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
		WHERE n.nspname = 'river' AND c.relkind IN ('r', 'p', 'S', 'v', 'm')`)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name, kind, owner string
		if err := rows.Scan(&name, &kind, &owner); err != nil {
			t.Fatal(err)
		}
		if owner != "mg_migrator" {
			t.Errorf("river.%s is owned by %s, want mg_migrator", name, owner)
		}
		if kind == "S" {
			continue
		}
		seen[name] = true
		if _, ok := queueTables[name]; !ok {
			t.Errorf("river.%s: table not classified (add it to queueTables and database/river/grants.sql)", name)
		}
	}
	for name := range queueTables {
		if !seen[name] {
			t.Errorf("river.%s missing", name)
		}
	}

	privs := func(role, table string) string {
		var got []string
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			var ok bool
			if err := su.QueryRow(ctx, "SELECT has_table_privilege($1, $2, $3)", role, "river."+table, p).Scan(&ok); err != nil {
				t.Fatal(err)
			}
			if ok {
				got = append(got, p)
			}
		}
		sort.Strings(got)
		return strings.Join(got, ",")
	}
	enqueue := []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform"}
	for table, worker := range queueTables {
		for _, role := range []string{"mg_worker_platform", "mg_api_tenant", "mg_worker_tenant", "mg_api_platform",
			"mg_readonly", "mg_audit_writer", "mg_partition_maint"} {
			want := ""
			switch {
			case role == "mg_worker_platform" && worker:
				want = "DELETE,INSERT,SELECT,UPDATE"
			case table == "river_job" && slices.Contains(enqueue, role):
				want = "INSERT,SELECT" // + UPDATE (kind) only, checked below
			}
			if got := privs(role, table); got != want {
				t.Errorf("%s on river.%s: privileges %q, want %q", role, table, got, want)
			}
		}
	}
	for _, role := range enqueue {
		var kind, other bool
		if err := su.QueryRow(ctx, `SELECT has_column_privilege($1, 'river.river_job', 'kind', 'UPDATE'),
				has_column_privilege($1, 'river.river_job', 'state', 'UPDATE')`, role).Scan(&kind, &other); err != nil {
			t.Fatal(err)
		}
		if !kind || other {
			t.Errorf("%s: UPDATE on river_job.kind=%v state=%v, want only kind", role, kind, other)
		}
	}
	for _, role := range []string{"mg_readonly", "mg_audit_writer", "mg_partition_maint"} {
		var usage bool
		if err := su.QueryRow(ctx, "SELECT has_schema_privilege($1, 'river', 'USAGE')", role).Scan(&usage); err != nil {
			t.Fatal(err)
		}
		if usage {
			t.Errorf("%s has USAGE on schema river", role)
		}
	}

	// enqueue in the same transaction as the business change, rolled back with it
	s := e.openStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	f := newFixture()
	f.insertAll(t, su)
	var id int64
	sentinel := errors.New("rollback")
	err = s.WithTenantJobTx(ctx, f.a.id, func(tx *Tx) error {
		var err error
		if id, err = tx.InsertQueueJob(ctx, queueTestArgs{}, &river.InsertOpts{Queue: "default", MaxAttempts: 1}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) || id == 0 {
		t.Fatalf("enqueue in a tenant transaction: id %d, err %v", id, err)
	}
	var n int64
	if err := su.QueryRow(ctx, "SELECT count(*) FROM river.river_job WHERE id = $1", id).Scan(&n); err != nil || n != 0 {
		t.Errorf("River job of a rolled-back transaction: %d rows (err %v), want 0", n, err)
	}
	err = s.WithPlatformJobTx(ctx, func(tx *Tx) error {
		if id, err = tx.InsertQueueJob(ctx, queueTestArgs{}, &river.InsertOpts{Queue: "default", MaxAttempts: 1}); err != nil {
			return err
		}
		states, err := tx.QueueJobStates(ctx, []int64{id, -1})
		if err != nil || len(states) != 1 || states[id] != "available" {
			t.Errorf("QueueJobStates = %v (err %v), want only %d: available", states, err, id)
		}
		_, err = tx.tx.Exec(ctx, "DELETE FROM river.river_job WHERE id = $1", id)
		return err
	})
	wantSQLState(t, "mg_api_platform deleting a River job", err, privilegeErr)

	if _, err := s.NewQueueClient(ctx, &river.Config{Schema: "public"}, 2); err == nil {
		t.Error("NewQueueClient accepted a schema other than river")
	}
}
