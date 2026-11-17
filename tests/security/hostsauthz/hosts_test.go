//go:build mgtestfixture

// Package hostsauthz drives the host operations of P3-T04 (GET/POST/PATCH /platform/hosts) through the composed API —
// identity session layer, authorization (authz), audit middleware, hostsapi over platform.Service on the api's pools —
// with sessions minted by the fixture of P2-T15a: the permission matrix of §8.5 (platform.host:read SA, PO, PS, PV;
// :manage SA, PO; every tenant role refused), the conventions of §13.1 (Idempotency-Key replay and reuse, ETag and
// If-Match with 412/428, 422 with field errors that never echo the value, 409), and the audit trail — successes with
// before/after in the platform scope, refusals and failures of every write.
package hostsauthz

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/hostsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

type answer struct {
	rec     *httptest.ResponseRecorder
	problem gen.Problem
	host    gen.Host
}

type client struct {
	t *testing.T
	w *sessionfixture.World
	s *sessionfixture.Session
}

func (c client) do(method, path, body string, hdr map[string]string) answer {
	c.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	rec := c.w.Do(c.t, c.s, method, path, rd, h)
	a := answer{rec: rec}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
		_ = json.Unmarshal(rec.Body.Bytes(), &a.problem)
	} else {
		_ = json.Unmarshal(rec.Body.Bytes(), &a.host)
	}
	return a
}

func key() map[string]string {
	return map[string]string{"Idempotency-Key": "hosts-" + uuid.NewString()}
}

const createBody = `{"name":"api-host","region":"api-lab","capacity":{"max_instances":4},` +
	`"run_uid_range":{"first":30000,"last":30099},"tenant_net_pool":"10.250.0.0/24"}`

func TestHostsThroughTheAPI(t *testing.T) {
	pg := storetest.Require(t)
	w := sessionfixture.New(t, sessionfixture.Options{Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		logger, err := audit.New(w.Store, pg.OpenAuditWriter(t, w.DB), audit.Config{Registerer: prometheus.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		return sessionfixture.Mount{Handlers: httpapi.Handlers{Hosts: hostsapi.New(platform.New(w.Store))},
			Audit: auditapi.Middleware(logger)}
	}})
	as := func(role string, ten *sessionfixture.Tenant) client {
		return client{t: t, w: w, s: w.Login(t, w.Actor(t, role, ten))}
	}
	sa, po := as(authz.RoleSuperAdmin, nil), as(authz.RolePlatformOperator, nil)
	ps, pv := as(authz.RolePlatformSupport, nil), as(authz.RolePlatformViewer, nil)

	// create, replay, reuse, conflict
	k := key()
	created := sa.do(http.MethodPost, "/platform/hosts", createBody, k)
	h := created.host
	if created.rec.Code != http.StatusCreated || h.Name != "api-host" || h.Status != "active" || h.Capacity.MaxInstances != 4 ||
		h.Etag == "" || created.rec.Header().Get("ETag") != h.Etag || h.PublicEntry.Ipv4 != nil || h.Usage.RunUidsFree != 100 ||
		h.Usage.NetSlotsFree != 32 {
		t.Fatalf("create: %d %s", created.rec.Code, created.rec.Body)
	}
	path := "/platform/hosts/" + h.Id.String()
	if again := sa.do(http.MethodPost, "/platform/hosts", createBody, k); again.rec.Code != http.StatusCreated || again.host.Id != h.Id {
		t.Errorf("replay: %d %s", again.rec.Code, again.rec.Body)
	}
	if reuse := sa.do(http.MethodPost, "/platform/hosts", strings.Replace(createBody, `"api-lab"`, `"api-lab2"`, 1), k); reuse.rec.Code != http.StatusUnprocessableEntity ||
		reuse.problem.Code != gen.ProblemCodeIdempotencyKeyReuse {
		t.Errorf("key reuse: %d %s", reuse.rec.Code, reuse.rec.Body)
	}
	if dup := po.do(http.MethodPost, "/platform/hosts", createBody, key()); dup.rec.Code != http.StatusConflict || dup.problem.Code != gen.ProblemCodeConflict {
		t.Errorf("same name: %d %s", dup.rec.Code, dup.rec.Body)
	}
	var hosts int
	w.Scan(t, `SELECT count(*) FROM hosts WHERE name = 'api-host'`, nil, &hosts)
	if hosts != 1 {
		t.Errorf("%d hosts named api-host", hosts)
	}

	// 422: every invalid field named, no value echoed
	bad := sa.do(http.MethodPost, "/platform/hosts", `{"name":"Bad_Name","region":"api-lab","capacity":{"max_instances":-1},`+
		`"public_entry":{"ipv4":"127.0.0.1","mode":"tunnel"},"run_uid_range":{"first":20000,"last":20010},`+
		`"stun_port_range":{"first":80,"last":90},"tenant_net_pool":"10.250.0.0/30"}`, key())
	var fields []string
	if bad.problem.Errors != nil {
		for _, f := range *bad.problem.Errors {
			fields = append(fields, f.Field)
		}
	}
	slices.Sort(fields)
	want := []string{"capacity.max_instances", "name", "public_entry.ipv4", "public_entry.mode", "run_uid_range",
		"stun_port_range.first", "stun_port_range.last", "tenant_net_pool"}
	if bad.rec.Code != http.StatusUnprocessableEntity || bad.problem.Code != gen.ProblemCodeValidationFailed || !slices.Equal(fields, want) {
		t.Errorf("invalid host: %d fields %v, want %v: %s", bad.rec.Code, fields, want, bad.rec.Body)
	}
	for _, v := range []string{"Bad_Name", "127.0.0.1", "tunnel", "10.250.0.0/30"} {
		if strings.Contains(bad.rec.Body.String(), v) {
			t.Errorf("the 422 echoes %q: %s", v, bad.rec.Body)
		}
	}

	// reads: every platform role; writes: SA and PO only; tenant roles: nothing (§8.5)
	for _, c := range []client{sa, po, ps, pv} {
		if a := c.do(http.MethodGet, path, "", nil); a.rec.Code != http.StatusOK || a.host.Id != h.Id || a.rec.Header().Get("ETag") != h.Etag {
			t.Errorf("%s: get %d", c.s, a.rec.Code)
		}
		if a := c.do(http.MethodGet, "/platform/hosts?region=api-lab", "", nil); a.rec.Code != http.StatusOK ||
			!strings.Contains(a.rec.Body.String(), h.Id.String()) {
			t.Errorf("%s: list %d %s", c.s, a.rec.Code, a.rec.Body)
		}
	}
	for _, c := range []client{ps, pv} {
		if a := c.do(http.MethodPost, "/platform/hosts", strings.Replace(createBody, "api-host", "api-host-2", 1), key()); a.rec.Code != http.StatusForbidden {
			t.Errorf("%s: create %d", c.s, a.rec.Code)
		}
		if a := c.do(http.MethodPatch, path, `{"status":"disabled"}`, map[string]string{"If-Match": h.Etag}); a.rec.Code != http.StatusForbidden {
			t.Errorf("%s: patch %d", c.s, a.rec.Code)
		}
	}
	for _, role := range sessionfixture.TenantRoles {
		c := as(role, w.A)
		for _, r := range []struct{ method, path, body string }{{http.MethodGet, "/platform/hosts", ""}, {http.MethodGet, path, ""},
			{http.MethodPost, "/platform/hosts", strings.Replace(createBody, "api-host", "api-host-3", 1)},
			{http.MethodPatch, path, `{"status":"disabled"}`}} {
			hdr := key()
			hdr["If-Match"] = h.Etag
			if a := c.do(r.method, r.path, r.body, hdr); a.rec.Code != http.StatusForbidden || a.problem.Code != gen.ProblemCodeForbidden {
				t.Errorf("%s: %s %s: %d", role, r.method, r.path, a.rec.Code)
			}
		}
	}
	w.Scan(t, `SELECT count(*) FROM hosts WHERE name LIKE 'api-host%'`, nil, &hosts)
	if hosts != 1 {
		t.Errorf("refused creates wrote %d hosts", hosts-1)
	}

	// PATCH: If-Match, then a change by the Platform Operator
	patch := `{"status":"draining","capacity":{"max_instances":2},"public_entry":{"ipv4":"203.0.113.50","mode":"vps_gateway"}}`
	for name, c := range map[string]struct {
		ifMatch string
		status  int
		code    gen.ProblemCode
	}{
		"missing": {"", http.StatusPreconditionRequired, gen.ProblemCodePreconditionRequired},
		"star":    {"*", http.StatusPreconditionRequired, gen.ProblemCodePreconditionRequired},
		"weak":    {"W/" + h.Etag, http.StatusPreconditionFailed, gen.ProblemCodePreconditionFailed},
		"other":   {`"00000000000000000000000000000000"`, http.StatusPreconditionFailed, gen.ProblemCodePreconditionFailed},
	} {
		hdr := map[string]string{}
		if c.ifMatch != "" {
			hdr["If-Match"] = c.ifMatch
		}
		if a := po.do(http.MethodPatch, path, patch, hdr); a.rec.Code != c.status || a.problem.Code != c.code {
			t.Errorf("If-Match %s: %d %s", name, a.rec.Code, a.rec.Body)
		}
	}
	if a := sa.do(http.MethodPatch, "/platform/hosts/"+uuid.NewString(), patch, map[string]string{"If-Match": h.Etag}); a.rec.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", a.rec.Code)
	}
	if a := sa.do(http.MethodGet, "/platform/hosts/"+uuid.NewString(), "", nil); a.rec.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", a.rec.Code)
	}
	if a := po.do(http.MethodPatch, path, `{"tenant_net_pool":"203.0.113.0/24","public_entry":{"ipv4":"203.0.113.50"}}`,
		map[string]string{"If-Match": h.Etag}); a.rec.Code != http.StatusUnprocessableEntity || a.problem.Errors == nil ||
		(*a.problem.Errors)[0].Field != "public_entry.ipv4" {
		t.Errorf("entry inside the new pool: %d %s", a.rec.Code, a.rec.Body)
	}
	upd := po.do(http.MethodPatch, path, patch, map[string]string{"If-Match": h.Etag})
	if upd.rec.Code != http.StatusOK || upd.host.Status != "draining" || upd.host.Capacity.MaxInstances != 2 || upd.host.PublicEntry.Ipv4 == nil ||
		*upd.host.PublicEntry.Ipv4 != "203.0.113.50" || upd.host.Etag == h.Etag || upd.rec.Header().Get("ETag") != upd.host.Etag {
		t.Fatalf("patch: %d %s", upd.rec.Code, upd.rec.Body)
	}
	if a := sa.do(http.MethodPatch, path, `{"status":"active"}`, map[string]string{"If-Match": h.Etag}); a.rec.Code != http.StatusPreconditionFailed {
		t.Errorf("the ETag read before the change: %d", a.rec.Code)
	}
	if a := sa.do(http.MethodGet, "/platform/hosts?status=draining&region=api-lab", "", nil); a.rec.Code != http.StatusOK ||
		!strings.Contains(a.rec.Body.String(), `"id":"`+h.Id.String()+`"`) {
		t.Errorf("list draining: %d %s", a.rec.Code, a.rec.Body)
	}

	// the audit trail of the host (platform scope)
	type event struct {
		Action, Outcome string
		Actor           *uuid.UUID
		Tenant          *uuid.UUID
		Reason          *string
	}
	var raw string
	w.Scan(t, `SELECT coalesce(json_agg(json_build_object('Action', action, 'Outcome', outcome, 'Actor', actor_identity_id,
			'Tenant', tenant_id, 'Reason', details ->> 'reason') ORDER BY occurred_at, id), '[]')::text
		FROM audit_events WHERE action IN ('platform.host.create', 'platform.host.update')`, nil, &raw)
	var evs []event
	if err := json.Unmarshal([]byte(raw), &evs); err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, e := range evs {
		count[e.Action+"/"+e.Outcome]++
		if e.Outcome == audit.OutcomeSuccess && (e.Tenant != nil || e.Actor == nil) {
			t.Errorf("success event outside the platform scope or without actor: %+v", e)
		}
	}
	// create: 2 successes (the create, its replay — marked replay, nothing changed), refusals PS/PV + every tenant role,
	// failures 409 + 422 (key reuse) + 422 (invalid); update: 1 success, refusals PS/PV + every tenant role + the 404 of
	// an unknown host (layer 2), failures 428 ×2, 412 ×3, 422
	for k, n := range map[string]int{
		"platform.host.create/success": 2, "platform.host.create/denied": 2 + len(sessionfixture.TenantRoles), "platform.host.create/failure": 3,
		"platform.host.update/success": 1, "platform.host.update/denied": 3 + len(sessionfixture.TenantRoles), "platform.host.update/failure": 6,
	} {
		if count[k] != n {
			t.Errorf("audit %s: %d events, want %d (all: %v)", k, count[k], n, count)
		}
	}
	var details string
	w.Scan(t, `SELECT details::text FROM audit_events WHERE action = 'platform.host.update' AND outcome = 'success'`, nil, &details)
	for _, s := range []string{`"after_status": "draining"`, `"before_status": "active"`, `"after_public_ipv4": "203.0.113.50"`,
		`"before_public_ipv4": null`, `"after_max_instances": 2`, `"before_max_instances": 4`} {
		if !strings.Contains(details, s) {
			t.Errorf("update details lack %s: %s", s, details)
		}
	}
}
