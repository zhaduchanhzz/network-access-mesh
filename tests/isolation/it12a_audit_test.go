//go:build mgtestfixture

package isolation_test

// IT-12a (§5.2 boundary 12): the audit API of tenant A never returns an event of tenant B — for every role that may
// read it, through every page, with filters naming B's actors, with an extra tenant parameter, with B's cursor — and
// the platform audit holds platform events only. Through the composed API of the api process (identity, authz, audit
// middleware and handlers of P2-T08) with minted sessions of the 9 roles. P2-T08 proved it for one admin per tenant
// (internal/httpapi/auditapi TestAuditThroughTheAPI, internal/audit TestReaderScopes); this is the per-role version.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// auditWorld is a fixture world with the audit trail mounted as in the api process (P2-T16).
func auditWorld(t *testing.T, opts sessionfixture.Options) *sessionfixture.World {
	t.Helper()
	opts.Mount = func(w *sessionfixture.World) sessionfixture.Mount {
		l, err := audit.New(w.Store, storetest.Require(t).OpenAuditWriter(t, w.DB), audit.Config{})
		if err != nil {
			t.Fatal(err)
		}
		return sessionfixture.Mount{
			Handlers: httpapi.Handlers{Audit: auditapi.New(audit.NewReader(w.Store))},
			Audit:    auditapi.Middleware(l),
		}
	}
	return sessionfixture.New(t, opts)
}

// listAudit pages through an audit list (limit 4) and returns the items; a refusal fails the test.
func listAudit(t *testing.T, w *sessionfixture.World, s *sessionfixture.Session, path string, q url.Values) ([]gen.AuditEvent, []string) {
	t.Helper()
	var items []gen.AuditEvent
	var bodies []string
	q = cloneValues(q)
	q.Set("limit", "4")
	for range 200 {
		rec := w.Do(t, s, http.MethodGet, path+"?"+q.Encode(), nil, nil)
		var page gen.AuditEventList
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
			t.Fatalf("GET %s as %s: HTTP %d %s", path, s, rec.Code, rec.Body.String())
		}
		items = append(items, page.Items...)
		bodies = append(bodies, rec.Body.String())
		if page.NextCursor == nil {
			return items, bodies
		}
		q.Set("cursor", *page.NextCursor)
	}
	t.Fatalf("GET %s: pagination does not end", path)
	return nil, nil
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = slices.Clone(vs)
	}
	return out
}

func idsOf(items []gen.AuditEvent) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		out = append(out, it.Id)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// dbEvents returns the ids of the audit events of a tenant (nil: platform events), read as superuser.
func dbEvents(t *testing.T, w *sessionfixture.World, tenant *uuid.UUID) []uuid.UUID {
	t.Helper()
	var raw string
	if tenant == nil {
		w.Scan(t, `SELECT coalesce(json_agg(id ORDER BY id::text), '[]')::text FROM audit_events WHERE tenant_id IS NULL`, nil, &raw)
	} else {
		w.Scan(t, `SELECT coalesce(json_agg(id ORDER BY id::text), '[]')::text FROM audit_events WHERE tenant_id = $1`,
			[]any{*tenant}, &raw)
	}
	var out []uuid.UUID
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIT12aAuditIsolation(t *testing.T) {
	w := auditWorld(t, sessionfixture.Options{})
	ctx := t.Context()
	sessions := map[string]*sessionfixture.Session{}
	session := func(role string, ten *sessionfixture.Tenant) *sessionfixture.Session {
		a := w.Actor(t, role, ten)
		if s, ok := sessions[a.String()]; ok {
			return s
		}
		s := w.Login(t, a)
		sessions[a.String()] = s
		return s
	}

	// 1. Events in both tenants (business events written in the tenant's transaction, as handlers do) and on the
	// platform; denials through the API: in-tenant (A's operator reads A's audit ⇒ 403, under A), cross-tenant (B's
	// viewer reads A's audit ⇒ 404, under B with target A) and by staff (the viewer of the platform ⇒ 403, platform).
	for _, ten := range []*sessionfixture.Tenant{w.A, w.B} {
		owner := w.Actor(t, authz.RoleTenantOwner, ten)
		for i := range 7 {
			if err := w.Store.WithTenantTx(ctx, ten.ID, func(q *sqlcdb.Queries) error {
				return audit.Record(ctx, q, audit.Event{TenantID: &ten.ID, ActorIdentityID: &owner.IdentityID,
					ActorDisplay: "Owner " + ten.Name, Action: "device.rename", ResourceType: "device",
					ResourceID: fmt.Sprintf("device-%s-%d", ten.Name, i), Details: audit.Details{"tenant_name": ten.Name}})
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		sa := w.Actor(t, authz.RoleSuperAdmin, nil)
		return audit.Record(ctx, q, audit.Event{ActorIdentityID: &sa.IdentityID, Action: "platform.tenant.update",
			ResourceType: "tenant", ResourceID: w.A.ID.String()})
	}); err != nil {
		t.Fatal(err)
	}
	pathA, pathB := "/tenants/"+w.A.ID.String()+"/audit", "/tenants/"+w.B.ID.String()+"/audit"
	denials := map[string]struct {
		s      *sessionfixture.Session
		path   string
		status int
	}{
		"operator of A on A": {session(authz.RoleTenantOperator, w.A), pathA, http.StatusForbidden},
		"viewer of B on A":   {session(authz.RoleTenantViewer, w.B), pathA, http.StatusNotFound},
		"owner of A on B":    {session(authz.RoleTenantOwner, w.A), pathB, http.StatusNotFound},
		"platform viewer":    {session(authz.RolePlatformViewer, nil), pathA, http.StatusForbidden},
	}
	requestOf := map[string]string{}
	for name, d := range denials {
		rec := w.Do(t, d.s, http.MethodGet, d.path, nil, nil)
		if rec.Code != d.status {
			t.Fatalf("%s: HTTP %d, want %d", name, rec.Code, d.status)
		}
		requestOf[name] = rec.Header().Get("X-Request-Id")
	}

	// 2. Every role that may read a tenant's audit sees exactly that tenant's events, page after page — and nothing
	// that names the other tenant.
	for _, tc := range []struct {
		ten, oth *sessionfixture.Tenant
		path     string
	}{{w.A, w.B, pathA}, {w.B, w.A, pathB}} {
		if n := len(dbEvents(t, w, &tc.ten.ID)); n < 8 { // 7 business events + the denials of the tenant's actors
			t.Fatalf("tenant %s has only %d events — the fixture is broken", tc.ten.Name, n)
		}
		foreign := []string{tc.oth.ID.String(), tc.oth.Slug, "device-" + tc.oth.Name + "-", `"tenant_name":"` + tc.oth.Name + `"`}
		for _, role := range sessionfixture.TenantRoles {
			s := session(role, tc.ten)
			if cellAllowsAudit(role) {
				want := dbEvents(t, w, &tc.ten.ID) // the probes below add denials of the tenant's own actors
				items, bodies := listAudit(t, w, s, tc.path, nil)
				if got := idsOf(items); !slices.Equal(got, want) {
					t.Errorf("IT-12a: %s lists %d events of %s, the database holds %d", s, len(got), tc.ten.Name, len(want))
				}
				for _, b := range bodies {
					for _, f := range foreign {
						if strings.Contains(b, f) {
							t.Errorf("IT-12a: the audit of %s read by %s contains %q of tenant %s", tc.ten.Name, s, f, tc.oth.Name)
						}
					}
				}
			} else {
				rec := w.Do(t, s, http.MethodGet, tc.path, nil, nil)
				if rec.Code != http.StatusForbidden {
					t.Errorf("IT-12a: %s reads the audit of its tenant: HTTP %d, want 403", s, rec.Code)
				}
			}
			// …and never the other tenant's: 404, as if it did not exist.
			other := "/tenants/" + tc.oth.ID.String() + "/audit"
			if rec := w.Do(t, s, http.MethodGet, other, nil, nil); rec.Code != http.StatusNotFound {
				t.Errorf("IT-12a: %s reads the audit of %s: HTTP %d, want 404", s, tc.oth.Name, rec.Code)
			}
		}
	}

	// 3. Filters and parameters cannot reach the other tenant: an actor of B as filter ⇒ nothing; an extra tenant
	// parameter is ignored; B's cursor on A ⇒ 422 naming cursor.
	ownerA := session(authz.RoleTenantOwner, w.A)
	ownerB := w.Actor(t, authz.RoleTenantOwner, w.B)
	if items, _ := listAudit(t, w, ownerA, pathA, url.Values{"actor": {ownerB.IdentityID.String()}}); len(items) != 0 {
		t.Errorf("IT-12a: filter actor=<owner of B> on A's audit returned %d events", len(items))
	}
	viewerB := w.Actor(t, authz.RoleTenantViewer, w.B)
	if items, _ := listAudit(t, w, ownerA, pathA, url.Values{"actor": {viewerB.IdentityID.String()}}); len(items) != 0 {
		t.Errorf("IT-12a: the cross-tenant denial of B's viewer appears in A's audit (%d events)", len(items))
	}
	all, _ := listAudit(t, w, ownerA, pathA, nil)
	injected, _ := listAudit(t, w, ownerA, pathA, url.Values{"tenant_id": {w.B.ID.String()}, "tenantId": {w.B.ID.String()}})
	if !slices.Equal(idsOf(all), idsOf(injected)) {
		t.Errorf("IT-12a: an extra tenant parameter changed A's audit (%d → %d events)", len(all), len(injected))
	}
	rec := w.Do(t, session(authz.RoleTenantOwner, w.B), http.MethodGet, pathB+"?limit=1", nil, nil)
	var pageB gen.AuditEventList
	if json.Unmarshal(rec.Body.Bytes(), &pageB) != nil || pageB.NextCursor == nil {
		t.Fatalf("B's first page: HTTP %d %s", rec.Code, rec.Body.String())
	}
	rec = w.Do(t, ownerA, http.MethodGet, pathA+"?limit=1&cursor="+url.QueryEscape(*pageB.NextCursor), nil, nil)
	var p gen.Problem
	if rec.Code != http.StatusUnprocessableEntity || json.Unmarshal(rec.Body.Bytes(), &p) != nil ||
		p.Code != gen.ProblemCodeValidationFailed || p.Errors == nil || len(*p.Errors) != 1 || (*p.Errors)[0].Field != "cursor" {
		t.Errorf("IT-12a: B's cursor on A's audit: HTTP %d %s, want 422 naming cursor", rec.Code, rec.Body.String())
	}

	// 4. Where the denials went: each in the actor's scope (B's viewer probing A ⇒ B's audit, never A's).
	where := map[string][]gen.AuditEvent{}
	where["A"], _ = listAudit(t, w, ownerA, pathA, nil)
	where["B"], _ = listAudit(t, w, session(authz.RoleTenantOwner, w.B), pathB, nil)
	where["platform"], _ = listAudit(t, w, session(authz.RoleSuperAdmin, nil), "/platform/audit", nil)
	for name, scope := range map[string]string{
		"operator of A on A": "A", "viewer of B on A": "B", "owner of A on B": "A", "platform viewer": "platform",
	} {
		for s, items := range where {
			found := slices.ContainsFunc(items, func(e gen.AuditEvent) bool {
				return e.RequestId == requestOf[name] && e.Outcome == gen.AuditOutcomeDenied
			})
			if found != (s == scope) {
				t.Errorf("IT-12a: denial %q in the audit of %s: %v (it belongs to %s only)", name, s, found, scope)
			}
		}
	}

	// 5. The platform audit lists platform events only, for every platform role that may read it.
	var wantP []uuid.UUID
	for _, role := range sessionfixture.PlatformRoles {
		s := session(role, nil)
		if role == authz.RolePlatformSupport { // §8.5: platform.audit:read — PS —
			if rec := w.Do(t, s, http.MethodGet, "/platform/audit", nil, nil); rec.Code != http.StatusForbidden {
				t.Errorf("IT-12a: %s reads the platform audit: HTTP %d, want 403", s, rec.Code)
			}
			continue
		}
		wantP = dbEvents(t, w, nil) // the refusal of the support role above is itself a platform event
		items, bodies := listAudit(t, w, s, "/platform/audit", nil)
		if got := idsOf(items); !slices.Equal(got, wantP) {
			t.Errorf("IT-12a: %s lists %d platform events, the database holds %d", s, len(got), len(wantP))
		}
		for _, b := range bodies {
			if strings.Contains(b, "device-A-") || strings.Contains(b, "device-B-") {
				t.Errorf("IT-12a: the platform audit read by %s contains a tenant event", s)
			}
		}
	}
	t.Logf("IT-12a: A %d events, B %d events, platform %d events; denials in the actor's scope only",
		len(where["A"]), len(where["B"]), len(wantP))
}

// cellAllowsAudit is §8.6 tenant.audit:read: TO ✔, TA ✔, TP —, TV ✔, EU —.
func cellAllowsAudit(role string) bool {
	return role == authz.RoleTenantOwner || role == authz.RoleTenantAdmin || role == authz.RoleTenantViewer
}
