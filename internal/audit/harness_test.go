package audit

// PostgreSQL integration harness of internal/audit (P2-T08): every test gets its own database migrated like a
// deployment (internal/store/storetest: bootstrap, goose, RBAC seed, River, role passwords — the cluster lock and the
// role passwords come from storetest/pgcluster) with two tenants, the api process's two pools and the detached pool.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// syncBuffer collects log lines written concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fixture is one test database with tenants A and B, the api's store (mg_api_tenant / mg_api_platform), the detached
// writer (mg_audit_writer) and a Logger on them.
type fixture struct {
	env  *storetest.Env
	db   string
	su   *pgx.Conn // superuser: fixtures and checks (test goroutine only)
	a, b uuid.UUID
	st   *store.Store
	w    *store.AuditWriter
	log  *Logger
	logs *syncBuffer
	reg  *prometheus.Registry
}

func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	env := storetest.Require(t)
	f := &fixture{env: env, db: env.NewDatabase(t), a: uuid.Must(uuid.NewV7()), b: uuid.Must(uuid.NewV7()),
		logs: &syncBuffer{}, reg: prometheus.NewRegistry()}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-a', 'A', 'active'), ($2, 'tenant-b', 'B', 'active')`,
		f.a, f.b)
	f.st = env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 8)
	f.w = env.OpenAuditWriter(t, f.db)
	cfg.Log = slog.New(slog.NewJSONHandler(f.logs, nil))
	cfg.Registerer = f.reg
	l, err := New(f.st, f.w, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.log = l
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.su.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

// row is an audit event as the superuser reads it.
type row struct {
	ID          uuid.UUID
	Tenant      *uuid.UUID
	Target      *uuid.UUID
	Actor       *uuid.UUID
	ActorType   string
	Action      string
	Outcome     string
	Resource    string
	ResourceID  string
	RequestID   string
	OperationID *uuid.UUID
	Details     map[string]any
}

// events returns the audit events matching where (SQL on audit_events, args), oldest first.
func (f *fixture) events(t *testing.T, where string, args ...any) []row {
	t.Helper()
	rows, err := f.su.Query(t.Context(), `SELECT id, tenant_id, target_tenant_id, actor_identity_id, actor_type, action,
			outcome, resource_type, coalesce(resource_id, ''), coalesce(request_id, ''), operation_id, details
		FROM audit_events WHERE `+where+` ORDER BY occurred_at, id`, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var (
			r   row
			raw []byte
		)
		if err := rows.Scan(&r.ID, &r.Tenant, &r.Target, &r.Actor, &r.ActorType, &r.Action, &r.Outcome, &r.Resource,
			&r.ResourceID, &r.RequestID, &r.OperationID, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &r.Details); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// count returns a single integer computed by the superuser.
func (f *fixture) count(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := f.su.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// connectAs opens a connection to the test database as role (derived test password).
func (f *fixture) connectAs(t *testing.T, role string) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(f.env.URL(f.db))
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = role, f.env.Password(role)
	c, err := pgx.ConnectConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// counter reads one series of a counter of the Logger's registry (0 when absent).
func (f *fixture) counter(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := f.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if matches(m, labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func matches(m *dto.Metric, labels map[string]string) bool {
	n := 0
	for _, lp := range m.GetLabel() {
		if v, ok := labels[lp.GetName()]; ok {
			if v != lp.GetValue() {
				return false
			}
			n++
		}
	}
	return n == len(labels)
}

// newID returns a fresh UUIDv7 (an identity, a request…).
func newID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// sqlState returns the SQLSTATE of err.
func sqlState(err error) string { return store.SQLState(err) }

// logged reports whether the Logger wrote a JSON line with msg and every key=value of kv.
func (f *fixture) logged(msg string, kv ...string) bool {
	for _, ln := range strings.Split(f.logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) != nil || m["msg"] != msg {
			continue
		}
		ok := true
		for i := 0; i+1 < len(kv); i += 2 {
			if fmt.Sprint(m[kv[i]]) != kv[i+1] {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}
