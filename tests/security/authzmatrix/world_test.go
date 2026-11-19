//go:build mgtestfixture

package authzmatrix_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/adminapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/backupapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/deprovisionapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/devicesapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/hostsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/idpconsoleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/instanceopsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/invitationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/jobsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/lifecycleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/membersapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/monitoringapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/networkapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/notificationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/policiesapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/provisioningapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/quarantineapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/reconfigureapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/relayapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tagsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
	"github.com/zhaduchanhzz/network-access-mesh/internal/members"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/network"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/deprovision"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/quarantine"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
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
	// P4-T15: the tag catalog of the api — CRUD (tagsapi) and the catalog check of PUT /devices/{id}/tags
	tagSvc, err := policies.NewTags(w.Store, policies.TagsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := devices.New(w.Store, devices.Config{Registry: reg, Logger: log, Registerer: prometheus.NewRegistry(),
		Tags: tagSvc})
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
		// the restore of P3-T11 (apps/internal/runner registers the executing action — here a no-op)
		approvals.Typed(approvals.Spec{Name: backup.ActionRestore, Scope: authz.ScopePlatform, ResourceType: "instance",
			Permission: "platform.instance:restore", DecideConditions: []string{authz.CondRestoreOnly}},
			func(context.Context, *store.Tx, approvals.Execution, backup.RestorePayload) (*uuid.UUID, error) {
				return nil, nil
			}),
		// the deprovision of P3-T09 (apps/internal/runner registers the executing action — here a no-op)
		approvals.Typed(approvals.Spec{Name: deprovision.Action, Scope: authz.ScopePlatform, ResourceType: "tenant",
			Permission: deprovision.Permission},
			func(context.Context, *store.Tx, approvals.Execution, deprovision.Payload) (*uuid.UUID, error) {
				return nil, nil
			}),
		// the actions of P4-T03a (apps/internal/runner registers the executing ones — here no-ops): the Super Admin role,
		// a platform change of a tenant IdP (the approver holds platform.idp:manage under tenant_idp_dual_control), the
		// tenant's security settings
		approvals.Typed(approvals.Spec{Name: platform.SuperAdminAction, Scope: authz.ScopePlatform,
			ResourceType: platform.SuperAdminResourceType, Permission: platform.SuperAdminPermission},
			func(context.Context, *store.Tx, approvals.Execution, platform.SuperAdminPayload) (*uuid.UUID, error) {
				return nil, nil
			}),
		approvals.Typed(approvals.Spec{Name: tenants.PlatformIdPChangeApprovalAction, Scope: authz.ScopePlatform,
			ResourceType: "identity_provider", Permission: "platform.idp:manage",
			ApproverConditions: []string{authz.CondTenantIdPDualControl}},
			func(context.Context, *store.Tx, approvals.Execution, tenants.PlatformIdPChange) (*uuid.UUID, error) {
				return nil, nil
			}),
		approvals.Typed(approvals.Spec{Name: tenants.SecuritySettingsApprovalAction, Scope: authz.ScopeTenant,
			ResourceType: "settings", Permission: "tenant.approval:decide"},
			func(context.Context, *store.Tx, approvals.Execution, tenants.SecuritySettingsPayload) (*uuid.UUID, error) {
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
	netw, err := network.New(w.Store, network.Config{Registry: reg, Devices: devices.RouteRegister{}, Tags: policies.RequireTags,
		ResourceRefs: policies.ResourceReferences, BaseDomain: "mesh.test", Logger: log,
		Reconfigure: func(context.Context, *store.Tx, network.ReconfigureRequest) (jobs.Job, bool, error) {
			return jobs.Job{}, false, errors.New("matrix: no reconfiguration")
		}})
	if err != nil {
		t.Fatal(err)
	}
	versions, err := policies.NewVersions(w.Store, policies.VersionsConfig{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	mem, err := members.New(w.Store, members.Config{Tenants: dir, Logger: log,
		Guard: func(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, c members.Change) error {
			return authz.GuardMembershipChange(ctx, q, tenantID, authz.MembershipChange{Actor: c.Actor, Target: c.Target,
				NewRole: c.NewRole, Deactivate: c.Deactivate, OwnershipTransfer: c.OwnershipTransfer})
		}})
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
	registry, jobsH, relayH := tenantsapi.New(dir, platform.New(w.Store)), jobsapi.New(jobs.NewService(w.Store)), relayapi.New(relays)
	inbox := notificationsapi.New(notifications.NewReader(w.Store))
	return httpapi.Handlers{
		Tenants:     registry,
		Devices:     devicesapi.New(dev),
		Audit:       auditapi.New(audit.NewReader(w.Store)),
		Jobs:        jobsH,
		Monitoring:  monitoringapi.New(mon),
		Approvals:   approvalsapi.New(appr),
		Invitations: invitationsapi.New(dir, authz.GuardInvitationRole),
		IdPConsole:  idpconsoleapi.New(appr), // P3-T15: the Keycloak console session (always 2P)
		// Backup/restore (P3-T11): the api side — enqueue a backup, a 2P restore request, the backup book
		Backups: backupapi.New(backup.New(w.Store, backup.Config{Logger: log}), appr),

		// Notifications (P3-T05b, notificationsapi over notifications.Reader — reads the caller's own rows only) and
		// the read state of the caller's own notifications (P4-T04 — the same handlers as PortalHandlers).
		Notifications: inbox,
		Portal:        inbox,
		Hosts:         hostsapi.New(platform.New(w.Store)),
		Provisioning:  provisioningapi.New(creator, orchestrator.NewControl(w.Store)),
		// Lifecycle (P3-T08): suspend/resume requests of the api (no worker here: a job would stay queued)
		Lifecycle: lifecycleapi.New(lifecycle.NewRequester(w.Store)),
		// Relay (P3-T05c): the tenant's relays and the platform's regions, reads only
		Relay: relayH,
		// Reconfigure (P3-T13): instance.reconfigure requests of the api
		Reconfigure: reconfigureapi.New(orchestrator.NewReconfigureService(w.Store)),
		// InstanceOps (P3-T13a): instance.restart and instance.upgrade requests of the api (no worker: jobs stay queued)
		InstanceOps: instanceopsapi.New(orchestrator.NewInstanceOpsService(w.Store)),
		// Deprovision (P3-T09): the 2P request of DELETE /platform/tenants/{id} (no worker here)
		Deprovision: deprovisionapi.New(deprovision.NewRequester(w.Store), appr),
		// Quarantine (P3-T18): quarantine requests of the api; a release becomes an approval request
		Quarantine: quarantineapi.New(quarantine.NewRequester(w.Store), appr),
		// Tenant detail of the Platform Console (P4-T02): jobs, instances and relay regions of one tenant, reads only
		TenantView: httpapi.PlatformTenantView{Jobs: jobsH, Instances: registry, Relay: relayH},
		// Tags (P4-T15): the tag catalog and PUT /devices/{id}/tags (delegated to the device handlers)
		Tags: tagsapi.New(tagSvc, devicesapi.New(dev)),
		// Members (P4-T09): membership writes under authz.GuardMembershipChange, groups (no worker: jobs stay queued)
		Members: membersapi.New(mem, appr),
		// Admin (P4-T03a): platform users, settings, IdPs, plans, PATCH of a tenant; the tenant's settings, IdP and
		// deletion request — with the approval actions of P4-T03a in the registry above
		Admin: adminapi.New(platform.New(w.Store), dir, appr),
		// Policies (P4-T10): the policy lifecycle over the production registry (validate's dry run — unreachable)
		Policies: policiesapi.New(versions),
		// Network (P4-T12): routes over the register (Headscale unreachable — every write is refused 428 first), DNS,
		// the resource catalog with the catalog check of P4-T15 (no worker: jobs stay queued)
		Network: networkapi.New(netw, appr),
	}
}

// The approval objects of the matrix (P3-T04a): a restore-like request of the platform — Super Admins and Platform
// Operators (restore_only) decide it — and a route-approval request per tenant (tenant.route:approve: TO and TA),
// each made by an identity that is not an actor of the matrix (no caller is its requester). The payloads are stored in
// canonical form, so the recipes approve with their constant hash.
// matrixPolicySource is the content of the matrix's draft policy version (P4-T10) and its sha256.
const (
	matrixPolicySource = `{"grants":[],"ssh":[]}`
	matrixPolicySHA    = "d0eb6d21884cf2aabd42491db0e65dcb307cc14a51ac8c41698602f274e164c4"
)

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
	devEU, devEUTagged, devOther map[string]uuid.UUID    // EU's untagged device, EU's tagged device, TA's device
	job                          map[string]uuid.UUID    // a job of the tenant
	platformJob                  uuid.UUID               // a job of scope platform
	approval, invitation         map[string]uuid.UUID    // a pending approval request and invitation of the tenant
	tag                          map[string]uuid.UUID    // the tenant's catalog tag tag:server (carried by devEUTagged)
	target, group                map[string]uuid.UUID    // P4-T09: an end-user member no actor is (membership writes), a group
	policy                       map[string]uuid.UUID    // P4-T10: a typed draft policy version of the tenant (never approved)
	dnsRecord, resource          map[string]uuid.UUID    // P4-T12: an extra DNS record and a catalog resource of the tenant
	platformApproval             uuid.UUID               // a pending approval request of scope platform
	platformUser, plan           uuid.UUID               // P4-T03a: a platform user no actor is, the standard plan
	host                         uuid.UUID               // the host of the instances (P3-T04: /platform/hosts/{hostId})
	notifOwn                     map[uuid.UUID]uuid.UUID // P4-T04: membership of a tenant actor → a notification addressed to it
	notifOther                   map[string]uuid.UUID    // P4-T04: a notification of the tenant addressed to a non-actor member
	canaries                     []string                // secret values planted in the SecretStore (never in a response)
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
		tag:    map[string]uuid.UUID{},
		target: map[string]uuid.UUID{}, group: map[string]uuid.UUID{}, policy: map[string]uuid.UUID{},
		dnsRecord: map[string]uuid.UUID{}, resource: map[string]uuid.UUID{},
		notifOwn: map[uuid.UUID]uuid.UUID{}, notifOther: map[string]uuid.UUID{},
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
		tag := uuid.Must(uuid.NewV7())
		o.tag[ten.Name] = tag
		m.Exec(t, `INSERT INTO tenant_tags (id, tenant_id, name, purpose) VALUES ($1, $2, 'tag:server', 'server')`, tag, ten.ID)
		target, ident := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		o.target[ten.Name] = target
		m.Exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email) VALUES ($1, $2, $3, 'tenant', $4, $5)`,
			ident, ten.IdP, ten.ID, "matrix-target-"+ten.Name, "matrix-target-"+ten.Name+"@example.test")
		m.Exec(t, `INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id)
			SELECT $1, $2, $3, id FROM roles WHERE scope = 'tenant' AND key = 'end_user'`, target, ten.ID, ident)
		group := uuid.Must(uuid.NewV7())
		o.group[ten.Name] = group
		m.Exec(t, `INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, 'matrix-group')`, group, ten.ID)
		pol := uuid.Must(uuid.NewV7())
		o.policy[ten.Name] = pol
		m.Exec(t, `INSERT INTO policy_versions (id, tenant_id, version, kind, source, content_sha256, state)
			VALUES ($1, $2, 1, 'user', '`+matrixPolicySource+`', '`+matrixPolicySHA+`', 'draft')`, pol, ten.ID)
		rec, res := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		o.dnsRecord[ten.Name], o.resource[ten.Name] = rec, res
		m.Exec(t, `INSERT INTO dns_records (id, tenant_id, name, type, value) VALUES ($1, $2, 'matrix.corp.example', 'A', '100.64.0.9')`,
			rec, ten.ID)
		m.Exec(t, `INSERT INTO network_resources (id, tenant_id, name, kind, address) VALUES ($1, $2, 'matrix-db', 'host', '10.9.0.5/32')`,
			res, ten.ID)
		inv := uuid.Must(uuid.NewV7())
		o.invitation[ten.Name] = inv
		m.Exec(t, `INSERT INTO tenant_invitations (id, tenant_id, idp_id, email, role_id, token_hash, expires_at)
			SELECT $1::uuid, $2, $3, $4, id, sha256(uuid_send($1::uuid)), now() + interval '1 day'
			FROM roles WHERE scope = 'tenant' AND key = 'tenant_viewer'`, inv, ten.ID, ten.IdP, "matrix-object-"+ten.Name+"@example.test")
		// Portal notifications (P4-T04): one per tenant actor, addressed to it, and one addressed to a member that is not
		// an actor of the matrix (another member's for every caller)
		notify := func(member uuid.UUID) uuid.UUID {
			id := uuid.Must(uuid.NewV7())
			m.Exec(t, `INSERT INTO notification_outbox (id, tenant_id, recipient_membership_id, kind, payload, status, sent_at)
				VALUES ($1, $2, $3, 'tenant.resumed', '{"job_id":"0190a000-0000-7000-8000-000000000004"}', 'sent', now())`,
				id, ten.ID, member)
			return id
		}
		for _, role := range []string{authz.RoleTenantOwner, authz.RoleTenantAdmin, authz.RoleTenantOperator,
			authz.RoleTenantViewer, authz.RoleEndUser} {
			a := m.Actor(t, role, ten)
			o.notifOwn[a.MembershipID] = notify(a.MembershipID)
		}
		o.notifOther[ten.Name] = notify(m.NewActor(t, authz.RoleTenantViewer, ten).MembershipID)
	}
	m.Exec(t, `INSERT INTO approval_requests (id, scope, action, resource_type, resource_id, payload, payload_sha256,
			requested_by_identity_id, expires_at)
		VALUES ($1, 'platform', $2, 'instance', 'matrix', $3::jsonb, $4, $5, now() + interval '1 day')`,
		o.platformApproval, matrixPlatformAction, matrixPlatformPayload, matrixPlatformHash,
		m.NewActor(t, authz.RoleSuperAdmin, nil).IdentityID)
	m.Exec(t, `INSERT INTO provisioning_jobs (id, kind, status, created_at, finished_at)
		VALUES ($1, 'partition.maintain', 'succeeded', now(), now())`, o.platformJob)
	// P4-T03a: the platform user the writes of /platform/users target (never an actor: a role change revokes its
	// sessions) and the seeded standard plan
	o.platformUser = m.NewActor(t, authz.RolePlatformViewer, nil).PlatformUserID
	m.Scan(t, `SELECT id FROM subscription_plans WHERE key = 'standard'`, nil, &o.plan)
	return o
}
