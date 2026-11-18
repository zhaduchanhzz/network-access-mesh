//go:build mgtestfixture

package authzmatrix_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/devicesapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/hostsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/idpconsoleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/invitationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/monitoringapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/notificationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/provisioningapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/relayapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// unreachableEdge is the edge admin listener the Locator hands out: nothing listens there, so a handler that calls
// Headscale for an own object answers 503 instance_unavailable — and an answer of 404 for any other object proves the
// object was refused BEFORE any Headscale call.
const unreachableEdge = "http://127.0.0.1:1"

// handlerSets are the production handler sets of the composed API under test — every set that exists on main, wired
// as the api process wires them (P2-T16): Tenants (P2-T11, tenantsapi over internal/tenants + internal/platform),
// Devices (P2-T13, devicesapi over internal/devices), Audit (P2-T08) and Monitoring (P2-T13a, monitoringapi over
// internal/monitoring — the api side: reads only, no Prober; device counts through devices.Service.Summary as in
// apps/*); the identity handlers (Auth, P2-T06) are added by the fixture. The device service reaches Headscale only
// through the production registry — headscale.NewRegistry over the real Locator of P2-T11 (tenant_instances read in the
// tenant's own scope, API key from the SecretStore that holds the canaries) — pointed at unreachableEdge. mountedOps
// switches the expectations of the mounted operations from 501 to real answers (own object accepted; another member's
// object under an own-only grant, another tenant's object and a missing one ⇒ 404). Jobs (P2-T16, jobsapi over
// jobs.Service on the api's store — the HTTP handlers deferred by P2-T12) is mounted like every other set: no
// operation of the spec answers 501 any more. Hosts (P3-T04, hostsapi over platform.Service) too: PS/PV and every
// tenant role are refused the writes before the handler.
func (m *matrixWorld) handlerSets(t *testing.T, w *sessionfixture.World) httpapi.Handlers {
	t.Helper()
	log := logx.New(m.svcLog, slog.LevelDebug, "matrix")
	dir := tenants.New(w.Store, tenants.Options{BaseDomain: "mesh.test"})
	tokenFile := filepath.Join(t.TempDir(), "edge_admin_token")
	if err := os.WriteFile(tokenFile, []byte(m.edgeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loc, err := locator.New(dir, m.sec, locator.Options{AdminURL: unreachableEdge, EdgeTokenFile: tokenFile,
		Timeout: 2 * time.Second, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	reg := headscale.NewRegistry(loc, headscale.Options{Logger: log, Retry: headscale.RetryPolicy{Attempts: 1}})
	dev, err := devices.New(w.Store, devices.Config{Registry: reg, Logger: log, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	counts := monitoring.DeviceCounterFunc(func(ctx context.Context, tenant uuid.UUID) (monitoring.DeviceCounts, error) {
		s, err := dev.Summary(ctx, tenant)
		return monitoring.DeviceCounts(s), err // same fields: checked by the compiler
	})
	mon, err := monitoring.New(w.Store, monitoring.Config{Devices: counts, Logger: log, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	actions, err := approvals.NewRegistry(
		approvals.Typed(approvals.Spec{Name: matrixPlatformAction, Scope: authz.ScopePlatform, ResourceType: "instance",
			Permission: "platform.instance:restore", DecideConditions: []string{authz.CondRestoreOnly}},
			func(context.Context, *store.Tx, approvals.Execution, matrixRestore) (*uuid.UUID, error) {
				return nil, nil
			}),
		approvals.Typed(approvals.Spec{Name: matrixTenantAction, Scope: authz.ScopeTenant, ResourceType: "device",
			Permission: "tenant.route:approve"},
			func(context.Context, *store.Tx, approvals.Execution, matrixRoute) (*uuid.UUID, error) {
				return nil, nil
			}),
		approvals.Typed(approvals.Spec{Name: console.Action, Scope: authz.ScopePlatform, ResourceType: console.ResourceType,
			Permission: console.Permission},
			func(context.Context, *store.Tx, approvals.Execution, console.Payload) (*uuid.UUID, error) {
				return nil, nil
			}),
	)
	if err != nil {
		t.Fatal(err)
	}
	appr, err := approvals.New(w.Store, approvals.Config{Approvers: authz.New(w.Store), Registry: actions, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	// Provisioning (P3-T05): the api side of the Tenant Orchestrator — tenant creation (steps 1–2, no worker here: the
	// job stays queued) and the job controls, with the api's quota checks as apps/* wires them.
	// Relay (P3-T05c): the api side of the RelayService — reads only (no Prober), as apps/* wires it.
	relays, err := relay.New(w.Store, relay.Config{Logger: log, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	creator, err := orchestrator.NewCreator(orchestrator.CreatorConfig{Store: w.Store, Secrets: m.sec,
		Quota: usage.NewChecker(w.Store), QuotaTx: usage.TenantCreationTx, BaseDomain: "mesh.test"})
	if err != nil {
		t.Fatal(err)
	}
	return httpapi.Handlers{
		Tenants:     tenantsapi.New(dir, platform.New(w.Store)),
		Devices:     devicesapi.New(dev),
		Audit:       auditapi.New(audit.NewReader(w.Store)),
		Jobs:        jobsapi.New(jobs.NewService(w.Store)),
		Monitoring:  monitoringapi.New(mon),
		Approvals:   approvalsapi.New(appr),
		Invitations: invitationsapi.New(dir, authz.GuardInvitationRole),
		IdPConsole:  idpconsoleapi.New(appr), // P3-T15: the Keycloak console session (always 2P)

		// Notifications (P3-T05b, notificationsapi over notifications.Reader — reads the caller's own rows only).
		Notifications: notificationsapi.New(notifications.NewReader(w.Store)),
		Hosts:         hostsapi.New(platform.New(w.Store)),
		Provisioning:  provisioningapi.New(creator, orchestrator.NewControl(w.Store)),
		Relay:         relayapi.New(relays),
	}
}

// The approval objects of the matrix (P3-T04a): a restore-like request of the platform — Super Admins and Platform
// Operators (restore_only) decide it — and a route-approval request per tenant (tenant.route:approve: TO and TA),
// each made by an identity that is not an actor of the matrix (no caller is its requester). The payloads are stored in
// canonical form, so the recipes approve with their constant hash.
const (
	matrixPlatformAction  = "platform.matrix_restore"
	matrixTenantAction    = "tenant.matrix_route_approval"
	matrixPlatformPayload = `{"backup_id":"0190a000-0000-7000-8000-000000000001","instance_id":"0190a000-0000-7000-8000-000000000002"}`
	matrixTenantPayload   = `{"device_id":"0190a000-0000-7000-8000-000000000003","prefixes":["10.0.0.0/24"]}`
)

var (
	matrixPlatformHash = approvals.Hash([]byte(matrixPlatformPayload))
	matrixTenantHash   = approvals.Hash([]byte(matrixTenantPayload))
)

type matrixRestore struct {
	BackupID   string `json:"backup_id"`
	InstanceID string `json:"instance_id"`
}

type matrixRoute struct {
	DeviceID string   `json:"device_id"`
	Prefixes []string `json:"prefixes"`
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
	approval, invitation         map[string]uuid.UUID // a pending approval request and invitation of the tenant
	platformApproval             uuid.UUID            // a pending approval request of scope platform
	host                         uuid.UUID            // the host of the instances (P3-T04: /platform/hosts/{hostId})
	canaries                     []string             // secret values planted in the SecretStore (never in a response)
}

// matrixWorld is the world of the matrix: the fixture world with the real audit trail, the recorder, the objects.
type matrixWorld struct {
	*sessionfixture.World
	rec       *recorder
	mounted   map[string]bool
	obj       objects
	sec       *secrets.Store // the SecretStore of the api process (throwaway kek-app keyring)
	edgeToken string         // the edge admin token the Locator reads from its file (a canary too)
	svcLog    *syncBuffer    // log of the services behind the handlers: devices, Locator, Headscale adapter (scanned)
}

// syncBuffer collects the log lines written by concurrent requests.
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

// newSecretStore opens the SecretStore of the api process over a throwaway kek-app keyring.
func newSecretStore(t *testing.T, w *sessionfixture.World) *secrets.Store {
	t.Helper()
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
	sec, err := secrets.New(w.Store, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

func newMatrixWorld(t *testing.T) *matrixWorld {
	t.Helper()
	m := &matrixWorld{rec: &recorder{recs: map[string]decisionRecord{}}, svcLog: &syncBuffer{}, edgeToken: randomHex(20)}
	m.World = sessionfixture.New(t, sessionfixture.Options{MaxConns: 8, Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		logger, err := audit.New(w.Store, storetest.Require(t).OpenAuditWriter(t, w.DB), audit.Config{})
		if err != nil {
			t.Fatal(err)
		}
		m.sec = newSecretStore(t, w)
		h := m.handlerSets(t, w)
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
// are real SecretStore secrets holding canary values (the API key is what the Locator hands the device service),
// three devices per tenant (the End User's untagged and tagged devices, the Tenant Admin's device), one job per tenant
// and one platform job.
func (m *matrixWorld) createObjects(t *testing.T) objects {
	t.Helper()
	o := objects{
		instance: map[string]uuid.UUID{}, devEU: map[string]uuid.UUID{}, devEUTagged: map[string]uuid.UUID{},
		devOther: map[string]uuid.UUID{}, job: map[string]uuid.UUID{}, platformJob: uuid.Must(uuid.NewV7()),
		approval: map[string]uuid.UUID{}, invitation: map[string]uuid.UUID{}, platformApproval: uuid.Must(uuid.NewV7()),
		canaries: []string{m.edgeToken},
	}
	sec := m.sec
	host := uuid.Must(uuid.NewV7())
	o.host = host
	m.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-matrix', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	for i, ten := range []*sessionfixture.Tenant{m.A, m.B} {
		apiKey := secrets.TenantRef(ten.ID, "headscale-api-key", 1)
		clientSecret := secrets.TenantRef(ten.ID, "idp-client-secret."+ten.IdP.String(), 1) // the IdP's own name (G2 F3)
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
		appr := uuid.Must(uuid.NewV7())
		o.approval[ten.Name] = appr
		m.Exec(t, `INSERT INTO approval_requests (id, scope, tenant_id, action, resource_type, resource_id, payload,
				payload_sha256, requested_by_identity_id, expires_at)
			VALUES ($1, 'tenant', $2, $3, 'device', 'matrix', $4::jsonb, $5, $6, now() + interval '1 day')`,
			appr, ten.ID, matrixTenantAction, matrixTenantPayload, matrixTenantHash, m.NewActor(t, authz.RoleTenantOwner, ten).IdentityID)
		inv := uuid.Must(uuid.NewV7())
		o.invitation[ten.Name] = inv
		m.Exec(t, `INSERT INTO tenant_invitations (id, tenant_id, idp_id, email, role_id, token_hash, expires_at)
			SELECT $1::uuid, $2, $3, $4, id, sha256(uuid_send($1::uuid)), now() + interval '1 day'
			FROM roles WHERE scope = 'tenant' AND key = 'tenant_viewer'`, inv, ten.ID, ten.IdP, "matrix-object-"+ten.Name+"@example.test")
	}
	m.Exec(t, `INSERT INTO approval_requests (id, scope, action, resource_type, resource_id, payload, payload_sha256,
			requested_by_identity_id, expires_at)
		VALUES ($1, 'platform', $2, 'instance', 'matrix', $3::jsonb, $4, $5, now() + interval '1 day')`,
		o.platformApproval, matrixPlatformAction, matrixPlatformPayload, matrixPlatformHash,
		m.NewActor(t, authz.RoleSuperAdmin, nil).IdentityID)
	m.Exec(t, `INSERT INTO provisioning_jobs (id, kind, status, created_at, finished_at)
		VALUES ($1, 'partition.maintain', 'succeeded', now(), now())`, o.platformJob)
	return o
}
