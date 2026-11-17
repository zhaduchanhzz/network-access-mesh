package audit

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ids returns the ids of the audit events matching where, as the superuser sees them (no RLS), sorted.
func (f *fixture) ids(t *testing.T, where string, args ...any) []uuid.UUID {
	t.Helper()
	var out []uuid.UUID
	for _, e := range f.events(t, where, args...) {
		out = append(out, e.ID)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return out
}

func entryIDs(items []Entry) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(items))
	for _, e := range items {
		out = append(out, e.ID)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return out
}

// seedScopes writes events of A, of B and of the platform, a denial of a user of A on B and of staff on A.
func seedScopes(t *testing.T, f *fixture) {
	t.Helper()
	ctx := t.Context()
	for tenant, n := range map[uuid.UUID]int{f.a: 3, f.b: 2} {
		for range n {
			if err := f.st.WithTenantTx(ctx, tenant, func(q *sqlcdb.Queries) error {
				return Record(ctx, q, Event{TenantID: &tenant, Action: "device.rename", ResourceType: "device"})
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for range 2 {
		if err := f.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			return Record(ctx, q, Event{Action: "platform.tenant.read", ResourceType: "tenant"})
		}); err != nil {
			t.Fatal(err)
		}
	}
	userA, staff := newID(t), newID(t)
	for _, ev := range []Event{
		{TenantID: &f.a, TargetTenantID: &f.b, ActorIdentityID: &userA, Action: "device.list", ResourceType: "device", Outcome: OutcomeDenied},
		{TargetTenantID: &f.a, ActorIdentityID: &staff, Action: "device.list", ResourceType: "device", Outcome: OutcomeDenied},
	} {
		if err := f.log.RecordDetached(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
}

// TestReaderScopes — T-01/IT-03 for audit: tenant A never reads B's events and B never lists the denial of A's user on
// B (§20 P2-T08); the platform list holds only platform events (P2-T03 open item 7, §8.5 "sự kiện platform"). Each
// of the two layers is checked on its own: RLS with the raw table under the application roles, and the queries of
// the reader run by the superuser (no RLS).
func TestReaderScopes(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	seedScopes(t, f)
	r := NewReader(f.st)
	for _, c := range []struct {
		name string
		list func() (Page, error)
		want []uuid.UUID
	}{
		{"tenant A", func() (Page, error) { return r.ListTenant(ctx, f.a, Query{}) }, f.ids(t, "tenant_id = $1", f.a)},
		{"tenant B", func() (Page, error) { return r.ListTenant(ctx, f.b, Query{}) }, f.ids(t, "tenant_id = $1", f.b)},
		{"platform", func() (Page, error) { return r.ListPlatform(ctx, Query{}) }, f.ids(t, "tenant_id IS NULL")},
	} {
		page, err := c.list()
		if err != nil {
			t.Fatal(err)
		}
		if got := entryIDs(page.Items); !slices.Equal(got, c.want) || len(got) == 0 {
			t.Errorf("%s lists %d events %v, want exactly %v", c.name, len(got), got, c.want)
		}
	}
	if n := len(f.ids(t, "tenant_id = $1", f.a)); n != 4 { // 3 + the cross-tenant denial of A's user
		t.Errorf("tenant A holds %d events, want 4", n)
	}
	if n := len(f.ids(t, "tenant_id IS NULL")); n != 3 { // 2 + the denial of staff on A
		t.Errorf("platform holds %d events, want 3", n)
	}

	// Layer RLS alone: raw SELECT under each application role, in its scope (and trying to widen it).
	scope := func(role, sc, tenant string) []*uuid.UUID {
		t.Helper()
		c := f.connectAs(t, role)
		if _, err := c.Exec(ctx, "SELECT set_config('app.scope', $1, false), set_config('app.tenant_id', $2, false)", sc, tenant); err != nil {
			t.Fatal(err)
		}
		rows, err := c.Query(ctx, "SELECT tenant_id FROM audit_events")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []*uuid.UUID
		for rows.Next() {
			var id *uuid.UUID
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		return out
	}
	only := func(what string, got []*uuid.UUID, want *uuid.UUID, n int) {
		t.Helper()
		if len(got) != n {
			t.Errorf("%s: %d rows, want %d", what, len(got), n)
		}
		for _, g := range got {
			if !sameID(g, want) {
				t.Errorf("%s: row of tenant %v", what, g)
			}
		}
	}
	only("mg_api_tenant in A", scope("mg_api_tenant", "tenant", f.a.String()), &f.a, 4)
	only("mg_worker_tenant in B", scope("mg_worker_tenant", "tenant", f.b.String()), &f.b, 2)
	only("mg_api_tenant in A claiming the platform scope", scope("mg_api_tenant", "platform", f.a.String()), &f.a, 4)
	only("mg_api_tenant claiming the platform scope without tenant", scope("mg_api_tenant", "platform", ""), nil, 0)
	only("mg_api_platform", scope("mg_api_platform", "platform", ""), nil, 3)
	only("mg_api_platform with a tenant set", scope("mg_api_platform", "platform", f.a.String()), nil, 3)

	// Layer query alone: the reader's statements as the superuser.
	q := sqlcdb.New(f.su)
	rows, err := q.ListTenantAuditEvents(ctx, sqlcdb.ListTenantAuditEventsParams{TenantID: f.a, FromAt: farPast,
		ToAt: farFuture, BeforeAt: farFuture, BeforeID: maxUUID, RowLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rows {
		if e.TenantID == nil || *e.TenantID != f.a {
			t.Errorf("ListTenantAuditEvents(A) without RLS returned an event of %v", e.TenantID)
		}
	}
	if len(rows) != 4 {
		t.Errorf("ListTenantAuditEvents(A) without RLS: %d rows, want 4", len(rows))
	}
	prows, err := q.ListPlatformAuditEvents(ctx, sqlcdb.ListPlatformAuditEventsParams{FromAt: farPast, ToAt: farFuture,
		BeforeAt: farFuture, BeforeID: maxUUID, RowLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range prows {
		if e.TenantID != nil {
			t.Errorf("ListPlatformAuditEvents without RLS returned an event of tenant %s", *e.TenantID)
		}
	}
	if len(prows) != 3 {
		t.Errorf("ListPlatformAuditEvents without RLS: %d rows, want 3", len(prows))
	}
}

// TestPaginationStable — §13.1 cursor pagination on (occurred_at, id), newest first: pages of 5 over 23 events with
// ties reproduce the full order exactly once; events written meanwhile (newer) do not shift later pages; filters
// apply; a cursor is bound to its list and filters; bad parameters are QueryErrors naming the field.
func TestPaginationStable(t *testing.T) {
	f := newFixture(t, Config{})
	ctx := t.Context()
	actors := []uuid.UUID{newID(t), newID(t)}
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for i := range 23 {
		outcome := OutcomeSuccess
		if i%3 == 0 {
			outcome = OutcomeDenied
		}
		action := "device.rename"
		if i%2 == 0 {
			action = "device.list"
		}
		f.exec(t, `INSERT INTO audit_events (occurred_at, tenant_id, actor_type, actor_identity_id, action, resource_type, outcome)
			VALUES ($1, $2, 'identity', $3, $4, 'device', $5)`, base.Add(time.Duration(i/5)*time.Second), f.a, actors[i%2],
			action, outcome) // five events per instant: ties broken by id
	}
	for range 4 {
		f.exec(t, `INSERT INTO audit_events (occurred_at, tenant_id, actor_type, action, resource_type, outcome)
			VALUES ($1, $2, 'system', 'device.list', 'device', 'success')`, base, f.b)
	}
	var want []uuid.UUID
	rows, err := f.su.Query(ctx, "SELECT id FROM audit_events WHERE tenant_id = $1 ORDER BY occurred_at DESC, id DESC", f.a)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		want = append(want, id)
	}
	rows.Close()

	r := NewReader(f.st)
	var (
		got    []uuid.UUID
		cursor string
		pages  int
	)
	for {
		page, err := r.ListTenant(ctx, f.a, Query{Limit: 5, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Items {
			got = append(got, e.ID)
		}
		pages++
		if pages == 1 { // newer events arrive while the client pages: later pages must not move
			for range 3 {
				f.exec(t, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome)
					VALUES ($1, 'system', 'device.sync', 'device', 'success')`, f.a)
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("pagination does not end")
		}
	}
	if !slices.Equal(got, want) || pages != 5 {
		t.Fatalf("paged %d events in %d pages, want the %d events in order in 5 pages", len(got), pages, len(want))
	}

	// filters: each page set equals the superuser's selection
	from, to := base.Add(time.Second), base.Add(3*time.Second)
	for name, c := range map[string]struct {
		q     Query
		where string
		args  []any
	}{
		"outcome": {Query{Outcome: OutcomeDenied}, "tenant_id = $1 AND outcome = 'denied'", []any{f.a}},
		"action":  {Query{Action: "device.list"}, "tenant_id = $1 AND action = 'device.list'", []any{f.a}},
		"actor":   {Query{Actor: &actors[1]}, "tenant_id = $1 AND actor_identity_id = $2", []any{f.a, actors[1]}},
		"window":  {Query{From: &from, To: &to}, "tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3", []any{f.a, from, to}},
	} {
		page, err := r.ListTenant(ctx, f.a, c.q)
		if err != nil {
			t.Fatal(err)
		}
		if w := f.ids(t, c.where, c.args...); !slices.Equal(entryIDs(page.Items), w) || len(w) == 0 {
			t.Errorf("filter %s: %d events, want %d", name, len(page.Items), len(w))
		}
	}

	// cursor binding and bad parameters
	first, err := r.ListTenant(ctx, f.a, Query{Limit: 2})
	if err != nil || first.NextCursor == "" {
		t.Fatal(err)
	}
	tampered := []byte(first.NextCursor)
	tampered[len(tampered)-1] ^= 1 // the binding (a forged position with a valid binding only moves within the same list)
	for name, c := range map[string]struct {
		run   func() (Page, error)
		field string
	}{
		"cursor of A on B":       {func() (Page, error) { return r.ListTenant(ctx, f.b, Query{Cursor: first.NextCursor}) }, "cursor"},
		"cursor on the platform": {func() (Page, error) { return r.ListPlatform(ctx, Query{Cursor: first.NextCursor}) }, "cursor"},
		"cursor with another filter": {func() (Page, error) {
			return r.ListTenant(ctx, f.a, Query{Cursor: first.NextCursor, Outcome: OutcomeDenied})
		}, "cursor"},
		"tampered cursor": {func() (Page, error) { return r.ListTenant(ctx, f.a, Query{Cursor: string(tampered)}) }, "cursor"},
		"limit 201":       {func() (Page, error) { return r.ListTenant(ctx, f.a, Query{Limit: 201}) }, "limit"},
		"negative limit":  {func() (Page, error) { return r.ListTenant(ctx, f.a, Query{Limit: -1}) }, "limit"},
		"bad action":      {func() (Page, error) { return r.ListTenant(ctx, f.a, Query{Action: "Device List"}) }, "action"},
		"bad outcome":     {func() (Page, error) { return r.ListTenant(ctx, f.a, Query{Outcome: "maybe"}) }, "outcome"},
		"empty window":    {func() (Page, error) { return r.ListTenant(ctx, f.a, Query{From: &to, To: &from}) }, "to"},
	} {
		_, err := c.run()
		var qe *QueryError
		if !errors.As(err, &qe) || qe.Field != c.field {
			t.Errorf("%s: %v, want a QueryError on %s", name, err, c.field)
		}
	}
	if page, err := r.ListTenant(ctx, f.a, Query{Cursor: first.NextCursor, Limit: 3}); err != nil || len(page.Items) != 3 {
		t.Errorf("the page size may change between pages: %v, %d items", err, len(page.Items))
	}
	if page, err := r.ListTenant(ctx, f.a, Query{}); err != nil || len(page.Items) != 26 || page.NextCursor != "" {
		t.Errorf("default page: %v, %d items (want all 26 ≤ %d)", err, len(page.Items), DefaultLimit)
	}
}
