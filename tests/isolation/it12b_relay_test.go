//go:build mgtestfixture

package isolation_test

// IT-12b, relay part (§5.2 boundary 12; §20 P3-T05c "relay của A không xuất hiện ở B"): the relay figures of tenant A
// never contain tenant B's, through the composed API of the api process (identity session layer, authz, audit
// middleware, relayapi over internal/relay) with minted sessions of the 9 roles of §8.4. Both tenants have the relay
// rows step 17 writes (embedded region mg-<slug>, DERP 901, assignment of the instance) and a probe recorded by the
// worker-side RelayService (A healthy, B unhealthy — so a leak of B's figures into A's view would show). Every role of A
// that may read the relay sees exactly A's assignment, region and health with checked_at = the recorded probe time,
// whatever tenant a query parameter or a header names; B's tenant id on A's session ⇒ 404 (IDs of another tenant are
// not found, as for every tenant route); the End User ⇒ 403; staff without a Support Access Grant ⇒ 403 on the tenant
// route (AC-05a) and the platform list holds both tenants' regions for the four platform roles, refused to tenant roles.
// Successful reads are not audited, refusals are (P2-T08).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/relayapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// relayFixture is what the IT-12b relay test seeded for one tenant.
type relayFixture struct {
	instance, region, assignment uuid.UUID
	host                         string
	checkedAt                    time.Time
	status                       gen.HealthStatus
	reason                       string
}

func TestIT12bRelayIsolation(t *testing.T) {
	pg := storetest.Require(t)
	w := sessionfixture.New(t, sessionfixture.Options{Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		l, err := audit.New(w.Store, pg.OpenAuditWriter(t, w.DB), audit.Config{Registerer: prometheus.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		svc, err := relay.New(w.Store, relay.Config{Registerer: prometheus.NewRegistry()}) // the api side: reads only
		if err != nil {
			t.Fatal(err)
		}
		return sessionfixture.Mount{Handlers: httpapi.Handlers{Relay: relayapi.New(svc)}, Audit: auditapi.Middleware(l)}
	}})
	ctx := context.Background()

	// The rows of step 17 for A and B, then one probe each through the worker's RelayService (worker pools).
	host := uuid.New()
	w.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	fx := map[*sessionfixture.Tenant]*relayFixture{}
	for i, ten := range []*sessionfixture.Tenant{w.A, w.B} {
		f := &relayFixture{instance: uuid.New(), region: uuid.New(), assignment: uuid.New(), host: ten.Slug + ".mesh.test"}
		fx[ten] = f
		w.Exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path, derp_region_id)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9, 901)`,
			f.instance, ten.ID, host, f.host, ten.Slug+".ts.test", "hs-"+ten.Slug+":8080", 30001+i,
			fmt.Sprintf("10.250.%d.0/29", i+1), "/opt/meshguard/tenants/"+f.instance.String())
		w.Exec(t, `INSERT INTO relay_regions (id, tenant_id, code, name, kind, derp_region_id, hostname, ipv4, stun_port, derp_port,
				verify_mode, host_id, status)
			VALUES ($1, $2, 'mg-'||$3, 'MeshGuard '||$3, 'embedded', 901, $4, '192.0.2.10', 3478, 443, 'in_process', $5, 'active')`,
			f.region, ten.ID, ten.Slug, f.host, host)
		w.Exec(t, `INSERT INTO relay_assignments (id, tenant_id, instance_id, relay_region_id, priority, status)
			VALUES ($1, $2, $3, $4, 0, 'active')`, f.assignment, ten.ID, f.instance, f.region)
	}
	fx[w.A].status, fx[w.B].status, fx[w.B].reason = gen.HealthStatusHealthy, gen.HealthStatusUnhealthy, relay.ReasonDERPProbeFailed
	prober := relay.ProberFunc(func(_ context.Context, p relay.ProbeRequest) (relay.ProbeResult, error) {
		if p.Host == fx[w.B].host {
			return relay.ProbeResult{DERP: relay.Check{Status: 502, Code: "expectation_failed"}, STUN: relay.Check{OK: true}}, nil
		}
		return relay.ProbeResult{DERP: relay.Check{OK: true, Status: 200}, STUN: relay.Check{OK: true}}, nil
	})
	wrk, err := relay.New(pg.OpenStore(t, w.DB, "mg_worker_tenant", "mg_worker_platform", 4),
		relay.Config{Prober: prober, EdgeAddress: "10.249.0.2:443", Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	for ten, f := range fx {
		if res, err := wrk.Probe(ctx, ten.ID, f.region); err != nil || !res.Recorded {
			t.Fatalf("probe of %s: %+v %v", ten.Name, res, err)
		}
		w.Scan(t, `SELECT last_probe_at FROM relay_regions WHERE id = $1`, []any{f.region}, &f.checkedAt)
	}

	relayOf := func(ten *sessionfixture.Tenant) string { return "/tenants/" + ten.ID.String() + "/relay" }
	other := func(ten *sessionfixture.Tenant) *sessionfixture.Tenant {
		if ten == w.A {
			return w.B
		}
		return w.A
	}
	check := func(who, body string, code int, ten *sessionfixture.Tenant) {
		t.Helper()
		f, o := fx[ten], fx[other(ten)]
		var r gen.TenantRelay
		if code != http.StatusOK || json.Unmarshal([]byte(body), &r) != nil {
			t.Errorf("IT-12b: %s reads the relay of %s: HTTP %d %s", who, ten.Name, code, body)
			return
		}
		if len(r.Assignments) != 1 {
			t.Errorf("IT-12b: %s sees %d relays of %s, want its own 1", who, len(r.Assignments), ten.Name)
			return
		}
		a := r.Assignments[0]
		reason := ""
		if a.Health.Reason != nil {
			reason = *a.Health.Reason
		}
		if a.Id != f.assignment || a.Region.Id != f.region || a.Region.Hostname != f.host || a.Region.Code != "mg-"+ten.Slug ||
			a.Health.Status != f.status || reason != f.reason || a.Health.CheckedAt == nil || !a.Health.CheckedAt.Equal(f.checkedAt) {
			t.Errorf("IT-12b: %s reads %s's relay as %+v (health %s/%q at %v), want its own %s/%q at %v", who, ten.Name, a,
				a.Health.Status, reason, a.Health.CheckedAt, f.status, f.reason, f.checkedAt)
		}
		for _, leak := range []string{other(ten).ID.String(), other(ten).Slug, o.region.String(), o.assignment.String(),
			o.instance.String(), o.host} {
			if strings.Contains(body, leak) {
				t.Errorf("IT-12b: the relay of %s read by %s contains %q of tenant %s", ten.Name, who, leak, other(ten).Name)
			}
		}
		if len(r.Unavailable) != len(relay.Unmeasured()) {
			t.Errorf("IT-12b: %s: unavailable figures %v", who, r.Unavailable)
		}
	}
	inject := http.Header{"X-Tenant-Id": {w.B.ID.String()}, "X-Mg-Tenant": {w.B.ID.String()}}
	injectQuery := "?tenant_id=" + w.B.ID.String() + "&tenant=" + w.B.Slug + "&tenantId=" + w.B.ID.String()

	// §8.6 tenant.relay:read: TO TA TP TV ✔, EU — (written from the master, independently of the seed).
	allowed := map[string]bool{authz.RoleTenantOwner: true, authz.RoleTenantAdmin: true, authz.RoleTenantOperator: true,
		authz.RoleTenantViewer: true, authz.RoleEndUser: false}
	requests := 0
	for _, ten := range []*sessionfixture.Tenant{w.A, w.B} {
		for _, role := range sessionfixture.TenantRoles {
			a := w.Actor(t, role, ten)
			s := w.Login(t, a)
			for _, path := range []string{relayOf(ten), relayOf(ten) + injectQuery} {
				rec := w.Do(t, s, http.MethodGet, path, nil, inject)
				requests++
				if allowed[role] {
					check(a.String()+" "+path, rec.Body.String(), rec.Code, ten)
				} else if rec.Code != http.StatusForbidden {
					t.Errorf("IT-12b: %s on %s: HTTP %d, want 403", a, path, rec.Code)
				}
			}
			// The other tenant's id in the path: not found, as if it did not exist — whatever the role.
			if rec := w.Do(t, s, http.MethodGet, relayOf(other(ten)), nil, nil); rec.Code != http.StatusNotFound {
				t.Errorf("IT-12b: %s reads the relay of %s: HTTP %d, want 404", a, other(ten).Name, rec.Code)
			}
			if rec := w.Do(t, s, http.MethodGet, "/platform/relay-regions", nil, nil); rec.Code != http.StatusForbidden {
				t.Errorf("IT-12b: %s lists the platform's relay regions: HTTP %d, want 403", a, rec.Code)
			}
			requests += 2
		}
	}

	// §8.5 platform.relay:read: SA PO PS PV ✔ — every region of every tenant; a tenant's relay without a Support Access
	// Grant: 403 (AC-05a).
	for _, role := range sessionfixture.PlatformRoles {
		a := w.Actor(t, role, nil)
		s := w.Login(t, a)
		if rec := w.Do(t, s, http.MethodGet, relayOf(w.A), nil, nil); rec.Code != http.StatusForbidden {
			t.Errorf("IT-12b: %s reads A's relay without a grant: HTTP %d, want 403", a, rec.Code)
		}
		rec := w.Do(t, s, http.MethodGet, "/platform/relay-regions?limit=200", nil, nil)
		requests += 2
		var page gen.RelayRegionList
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
			t.Errorf("IT-12b: %s lists the relay regions: HTTP %d %s", a, rec.Code, rec.Body.String())
			continue
		}
		seen := map[uuid.UUID]gen.PlatformRelayRegion{}
		for _, it := range page.Items {
			seen[it.Region.Id] = it
		}
		for ten, f := range fx {
			it, ok := seen[f.region]
			if !ok || it.TenantId == nil || *it.TenantId != ten.ID || len(it.Assignments) != 1 || it.Assignments[0].TenantId != ten.ID ||
				it.Assignments[0].InstanceId != f.instance || it.Health.Status != f.status || it.Health.CheckedAt == nil ||
				!it.Health.CheckedAt.Equal(f.checkedAt) {
				t.Errorf("IT-12b: %s: region of %s in the platform list: %+v (present %v)", a, ten.Name, it, ok)
			}
		}
	}

	// Audit: successful reads leave no event; the refusals are recorded under the read actions.
	n := func(sql string, args ...any) int {
		var v int
		w.Scan(t, sql, args, &v)
		return v
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE action IN ('relay.read', 'platform.relay_region.list') AND outcome <> 'denied'`); v != 0 {
		t.Errorf("%d audit events for successful reads (reads are not audited — P2-T08)", v)
	}
	eu := w.Actor(t, authz.RoleEndUser, w.A)
	if v := n(`SELECT count(*) FROM audit_events WHERE action = 'relay.read' AND outcome = 'denied' AND actor_identity_id = $1`,
		eu.IdentityID); v < 2 {
		t.Errorf("denials of A's End User on the relay: %d, want ≥ 2", v)
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE action = 'platform.relay_region.list' AND outcome = 'denied'`); v < 2*len(sessionfixture.TenantRoles) {
		t.Errorf("denials of tenant roles on the platform list: %d, want ≥ %d", v, 2*len(sessionfixture.TenantRoles))
	}
	t.Logf("IT-12b relay: %d requests; A %s at %s, B %s/%s at %s; no figure of the other tenant in any view", requests,
		fx[w.A].status, fx[w.A].checkedAt.UTC().Format(time.RFC3339Nano), fx[w.B].status, fx[w.B].reason,
		fx[w.B].checkedAt.UTC().Format(time.RFC3339Nano))
}
