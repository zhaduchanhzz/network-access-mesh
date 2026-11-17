//go:build mgtestfixture

package authzmatrix_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// handlerSets are the production handler sets of the composed API under test: every set that exists today. The
// identity handlers (Auth) are added by the fixture. AFTER THE MERGE OF P2-T11 (Tenants), P2-T13 (Devices), the jobs
// handlers and P2-T13a (Monitoring), add their sets here — mountedOps then switches the expectations of their
// operations from 501 to real answers (own object accepted; another member's object for an own-only grant, another
// tenant's object and a missing one ⇒ 404), with nothing else to change.
func handlerSets(w *sessionfixture.World) httpapi.Handlers {
	return httpapi.Handlers{Audit: auditapi.New(audit.NewReader(w.Store))}
}

// mountedOps lists the Go names of the operations whose handler set is mounted (Auth always is: the fixture mounts
// identityapi when the set is nil).
func mountedOps(h httpapi.Handlers) map[string]bool {
	out := map[string]bool{}
	v := reflect.ValueOf(h)
	for i := range v.NumField() {
		f := v.Type().Field(i)
		if v.Field(i).IsNil() && f.Name != "Auth" {
			continue
		}
		for j := range f.Type.NumMethod() {
			out[f.Type.Method(j).Name] = true
		}
	}
	return out
}

// decisionRecord is what the authorizer decided for one request.
type decisionRecord struct {
	operation string
	tenant    uuid.UUID
	decision  authz.Decision
	err       error
}

// recorder wraps the authorizer of the authz hook and keeps its decision per request id: the matrix checks what layer 1
// decided (grant with its obligations, or the kind and reason of the refusal) as well as what the client received.
type recorder struct {
	next authzhook.Authorizer
	mu   sync.Mutex
	recs map[string]decisionRecord
}

func (r *recorder) RequireOperation(ctx context.Context, operation string, tenantID uuid.UUID) (authz.Decision, error) {
	d, err := r.next.RequireOperation(ctx, operation, tenantID)
	r.mu.Lock()
	r.recs[requestid.From(ctx)] = decisionRecord{operation: operation, tenant: tenantID, decision: d, err: err}
	r.mu.Unlock()
	return d, err
}

func (r *recorder) get(id string) (decisionRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.recs[id]
	return d, ok
}

// objects are the fixture rows the object parameters of the paths designate, per tenant ("A", "B").
type objects struct {
	instance                     map[string]uuid.UUID
	devEU, devEUTagged, devOther map[string]uuid.UUID // EU's untagged device, EU's tagged device, TA's device
	job                          map[string]uuid.UUID // a job of the tenant
	platformJob                  uuid.UUID            // a job of scope platform
	canaries                     []string             // secret values planted in the SecretStore (never in a response)
}

// matrixWorld is the world of the matrix: the fixture world with the real audit trail, the recorder, the objects.
type matrixWorld struct {
	*sessionfixture.World
	rec     *recorder
	mounted map[string]bool
	obj     objects
}

func newMatrixWorld(t *testing.T) *matrixWorld {
	t.Helper()
	m := &matrixWorld{rec: &recorder{recs: map[string]decisionRecord{}}}
	m.World = sessionfixture.New(t, sessionfixture.Options{MaxConns: 8, Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		logger, err := audit.New(w.Store, storetest.Require(t).OpenAuditWriter(t, w.DB), audit.Config{})
		if err != nil {
			t.Fatal(err)
		}
		h := handlerSets(w)
		m.mounted = mountedOps(h)
		return sessionfixture.Mount{
			Handlers: h,
			Audit:    auditapi.Middleware(logger), // as the api process (P2-T16): every denial is audited
			Authorizer: func(a authzhook.Authorizer) authzhook.Authorizer {
				m.rec.next = a
				return m.rec
			},
		}
	}})
	m.obj = m.createObjects(t)
	return m
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// createObjects inserts (as superuser) one host, one running instance per tenant whose API key and IdP client secret
// are real SecretStore secrets holding canary values, three devices per tenant (the End User's untagged and tagged
// devices, the Tenant Admin's device), one job per tenant and one platform job.
func (m *matrixWorld) createObjects(t *testing.T) objects {
	t.Helper()
	o := objects{
		instance: map[string]uuid.UUID{}, devEU: map[string]uuid.UUID{}, devEUTagged: map[string]uuid.UUID{},
		devOther: map[string]uuid.UUID{}, job: map[string]uuid.UUID{}, platformJob: uuid.Must(uuid.NewV7()),
	}
	// A throwaway kek-app keyring: the SecretStore writes the canaries as the api process would.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kek-matrix-1"), []byte(randomHex(32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, secrets.ActiveFile), []byte("kek-matrix-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(m.Store, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	host := uuid.Must(uuid.NewV7())
	m.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-matrix', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	for i, ten := range []*sessionfixture.Tenant{m.A, m.B} {
		apiKey := secrets.TenantRef(ten.ID, "headscale-api-key", 1)
		clientSecret := secrets.TenantRef(ten.ID, "idp-client-secret", 1)
		for ref, value := range map[secrets.Ref]string{
			apiKey:       "hskey-api-" + randomHex(6) + "-" + randomHex(24), // the shape of a Headscale API key
			clientSecret: "mg-canary-client-secret-" + randomHex(16),
		} {
			if err := sec.Put(t.Context(), ref, []byte(value)); err != nil {
				t.Fatal(err)
			}
			o.canaries = append(o.canaries, value)
		}
		m.Exec(t, `UPDATE identity_providers SET client_secret_ref = $1 WHERE id = $2`, clientSecret.String(), ten.IdP)
		inst := uuid.Must(uuid.NewV7())
		o.instance[ten.Name] = inst
		m.Exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path,
				api_key_secret_ref, api_key_prefix, api_key_expires_at)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7,
				$8::cidr, $9, $10, $11, now() + interval '90 days')`,
			inst, ten.ID, host, ten.Slug+".mesh.test", ten.Slug+".ts.test", "hs-"+ten.Slug+":8080", 30001+i,
			"10.250."+string(rune('0'+i))+".0/29", "/opt/meshguard/tenants/"+inst.String(), apiKey.String(), randomHex(6))
		eu := m.Actor(t, authz.RoleEndUser, ten)
		ta := m.Actor(t, authz.RoleTenantAdmin, ten)
		for j, d := range []struct {
			dst   map[string]uuid.UUID
			owner uuid.UUID
			tags  []string
		}{
			{o.devEU, eu.MembershipID, []string{}},
			{o.devEUTagged, eu.MembershipID, []string{"tag:server"}},
			{o.devOther, ta.MembershipID, []string{}},
		} {
			id := uuid.Must(uuid.NewV7())
			d.dst[ten.Name] = id
			m.Exec(t, `INSERT INTO device_inventory_cache (id, tenant_id, instance_id, headscale_node_id, machine_key,
					name, given_name, owner_membership_id, tags)
				VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8)`,
				id, ten.ID, inst, 100+j, "mkey:"+randomHex(32), "matrix-"+ten.Name+"-"+string(rune('a'+j)), d.owner, d.tags)
		}
		job := uuid.Must(uuid.NewV7())
		o.job[ten.Name] = job
		m.Exec(t, `INSERT INTO provisioning_jobs (id, tenant_id, instance_id, kind, status, created_at, finished_at)
			VALUES ($1, $2, $3, 'inventory.sync', 'succeeded', now(), now())`, job, ten.ID, inst)
	}
	m.Exec(t, `INSERT INTO provisioning_jobs (id, kind, status, created_at, finished_at)
		VALUES ($1, 'partition.maintain', 'succeeded', now(), now())`, o.platformJob)
	return o
}
