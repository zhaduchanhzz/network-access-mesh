package orphans

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// Querier reads the registry: a superuser connection of the test database (RLS does not hide other tenants' rows).
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// SecretReader reads a stored secret (*secrets.Store).
type SecretReader interface {
	Get(ctx context.Context, ref secrets.Ref) (secrets.Plaintext, error)
}

// Sources are the real sources of a test host. Agent is the Host Agent client (*agentclient.Client — read calls only:
// ListInstances, GetInstanceStatus); Headscale reaches an instance through the edge with the key the registry
// references (a fresh registry: no cached target).
type Sources struct {
	DB        Querier
	Docker    *client.Client
	Agent     reconcile.Agent
	Secrets   SecretReader
	Headscale headscale.Registry
	Now       func() time.Time
	// Timeout bounds every call to the agent and to Headscale (default 30 s).
	Timeout time.Duration
}

// Collect observes a run. It fails only when a source cannot be read at all; a per-instance failure (keys not
// listable, key not readable) becomes part of the inventory and so a finding.
func Collect(ctx context.Context, src Sources, scope Scope) (Inventory, error) {
	if src.Now == nil {
		src.Now = time.Now
	}
	if src.Timeout <= 0 {
		src.Timeout = 30 * time.Second
	}
	inv := Inventory{Scope: scope, Now: src.Now()}
	var err error
	if inv.Registry, err = readRegistry(ctx, src.DB); err != nil {
		return inv, fmt.Errorf("orphans: registry: %w", err)
	}
	if inv.Host, err = readHost(ctx, src.Docker, scope); err != nil {
		return inv, fmt.Errorf("orphans: host: %w", err)
	}
	inScope := scopeInstances(inv)
	if src.Agent != nil {
		inv.Keys = readKeys(ctx, src, inScope)
		rep, _ := (&reconcile.Inspector{Agent: scopedAgent{next: src.Agent, scope: scope, ids: inScope},
			AgentTimeout: src.Timeout, Now: src.Now}).Host(ctx, registered(inScope))
		inv.Reconcile = []HostFinding{}
		for _, f := range rep.Findings {
			inv.Reconcile = append(inv.Reconcile, HostFinding{Kind: f.Kind, Subject: f.Subject})
		}
		for _, ch := range rep.Checks {
			if ch.Outcome == reconcile.OutcomeUnavailable {
				inv.Reconcile = append(inv.Reconcile, HostFinding{Kind: "check_unavailable", Subject: ch.Name + ":" + ch.Reason})
			}
		}
	}
	return inv, nil
}

// scopeInstances are the instances of the scope's tenants, by id.
func scopeInstances(inv Inventory) map[uuid.UUID]Instance {
	tenants := map[uuid.UUID]bool{}
	for _, t := range inv.Registry.Tenants {
		if inv.Scope.inScope(t.Slug) {
			tenants[t.ID] = true
		}
	}
	out := map[uuid.UUID]Instance{}
	for _, i := range inv.Registry.Instances {
		if tenants[i.TenantID] {
			out[i.ID] = i
		}
	}
	return out
}

func registered(m map[uuid.UUID]Instance) []reconcile.Registered {
	out := make([]reconcile.Registered, 0, len(m))
	for _, i := range m {
		out = append(out, reconcile.Registered{InstanceID: i.ID, TenantID: i.TenantID, Slug: i.Slug, Status: i.Status})
	}
	return out
}

func readRegistry(ctx context.Context, db Querier) (Registry, error) {
	var r Registry
	if err := query(ctx, db, `SELECT id, slug, status FROM tenants`, func(rows pgx.Rows) error {
		var t Tenant
		err := rows.Scan(&t.ID, &t.Slug, &t.Status)
		r.Tenants = append(r.Tenants, t)
		return err
	}); err != nil {
		return r, err
	}
	if err := query(ctx, db, `SELECT i.id, i.tenant_id, t.slug, i.status, COALESCE(i.api_key_secret_ref, ''),
		COALESCE(i.api_key_prefix, '') FROM tenant_instances i JOIN tenants t ON t.id = i.tenant_id`, func(rows pgx.Rows) error {
		var i Instance
		err := rows.Scan(&i.ID, &i.TenantID, &i.Slug, &i.Status, &i.APIKeyRef, &i.APIKeyPrefix)
		r.Instances = append(r.Instances, i)
		return err
	}); err != nil {
		return r, err
	}
	if err := query(ctx, db, `SELECT id, tenant_id, status, COALESCE(client_secret_ref, '') FROM identity_providers
		WHERE tenant_id IS NOT NULL`, func(rows pgx.Rows) error {
		var p IdP
		err := rows.Scan(&p.ID, &p.TenantID, &p.Status, &p.ClientSecretRef)
		r.IdPs = append(r.IdPs, p)
		return err
	}); err != nil {
		return r, err
	}
	if err := query(ctx, db, `SELECT COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), name, version,
		destroyed_at IS NOT NULL FROM secrets WHERE scope IN ('tenant', 'platform')`, func(rows pgx.Rows) error {
		var s Secret
		err := rows.Scan(&s.TenantID, &s.Name, &s.Version, &s.Destroyed)
		r.Secrets = append(r.Secrets, s)
		return err
	}); err != nil {
		return r, err
	}
	if err := query(ctx, db, `SELECT id, tenant_id, status FROM tenant_invitations`, func(rows pgx.Rows) error {
		var i Invitation
		err := rows.Scan(&i.ID, &i.TenantID, &i.Status)
		r.Invitations = append(r.Invitations, i)
		return err
	}); err != nil {
		return r, err
	}
	err := query(ctx, db, `SELECT tenant_id, 'region', code FROM relay_regions WHERE tenant_id IS NOT NULL
		UNION ALL SELECT tenant_id, 'assignment', id::text FROM relay_assignments`, func(rows pgx.Rows) error {
		var x Relay
		err := rows.Scan(&x.TenantID, &x.Kind, &x.Name)
		r.Relays = append(r.Relays, x)
		return err
	})
	return r, err
}

func query(ctx context.Context, db Querier, sql string, scan func(pgx.Rows) error) error {
	rows, err := db.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// meshguardish: a derived name or a MeshGuard label.
func meshguardish(name string, labels map[string]string) bool {
	if strings.HasPrefix(name, containerPrefix) || strings.HasPrefix(name, helperPrefix) || strings.HasPrefix(name, networkPrefix) {
		return true
	}
	for k := range labels {
		if strings.HasPrefix(k, "meshguard.") {
			return true
		}
	}
	return false
}

func readHost(ctx context.Context, dc *client.Client, scope Scope) (Host, error) {
	var h Host
	cl, err := dc.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return h, err
	}
	for _, c := range cl.Items {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		if meshguardish(name, c.Labels) {
			h.Containers = append(h.Containers, Container{ID: c.ID, Name: name, State: string(c.State), Labels: c.Labels})
		}
	}
	nl, err := dc.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return h, err
	}
	for _, n := range nl.Items {
		if meshguardish(n.Name, n.Labels) {
			h.Networks = append(h.Networks, Network{ID: n.ID, Name: n.Name, Labels: n.Labels})
		}
	}
	if scope.Edge != "" {
		ci, err := dc.ContainerInspect(ctx, scope.Edge, client.ContainerInspectOptions{})
		if err != nil {
			return h, fmt.Errorf("edge %s: %w", scope.Edge, err)
		}
		for nw := range ci.Container.NetworkSettings.Networks {
			h.EdgeNetworks = append(h.EdgeNetworks, nw)
		}
	}
	if scope.TenantsDir != "" {
		entries, err := os.ReadDir(scope.TenantsDir)
		if err != nil {
			return h, err
		}
		for _, e := range entries {
			h.Dirs = append(h.Dirs, e.Name())
		}
	}
	return h, nil
}

// readKeys: for every starting/running instance of the scope, the keys Headscale holds (through the agent — it works
// even when the registry's key does not), the prefix of the key the SecretStore holds under the registry's reference,
// and one authenticated call through the edge with that key.
func readKeys(ctx context.Context, src Sources, m map[uuid.UUID]Instance) []Keys {
	var out []Keys
	for _, i := range m {
		if i.Status != StatusStarting && i.Status != StatusRunning {
			continue
		}
		k := Keys{InstanceID: i.ID}
		actx, cancel := context.WithTimeout(ctx, src.Timeout)
		resp, err := src.Agent.GetInstanceStatus(actx, &agentv1.GetInstanceStatusRequest{IncludeApiKeys: true,
			Instance: &agentv1.InstanceRef{InstanceId: i.ID.String(), TenantId: i.TenantID.String(), Slug: i.Slug}})
		cancel()
		if err != nil {
			k.ListErr = err.Error()
		}
		for _, key := range resp.GetStatus().GetApiKeys() {
			ak := APIKey{Prefix: strings.TrimSuffix(strings.TrimPrefix(key.GetPrefix(), "hskey-api-"), "-***")}
			if e := key.GetExpiration(); e != nil && e.IsValid() && !e.AsTime().IsZero() && e.AsTime().Unix() > 0 {
				ak.Expiration = e.AsTime()
			}
			k.Listed = append(k.Listed, ak)
		}
		if i.APIKeyRef != "" {
			k.StoredPrefix, k.StoredErr = storedPrefix(ctx, src.Secrets, i.APIKeyRef)
			k.APIOK, k.APIErr = apiCall(ctx, src, i.TenantID)
		}
		out = append(out, k)
	}
	return out
}

func storedPrefix(ctx context.Context, sec SecretReader, ref string) (string, string) {
	if sec == nil {
		return "", "no SecretStore"
	}
	r, err := secrets.ParseRef(ref)
	if err != nil {
		return "", err.Error()
	}
	pt, err := sec.Get(ctx, r)
	if err != nil {
		return "", err.Error()
	}
	defer pt.Wipe()
	p := headscale.APIKeyPrefix(headscale.NewSecret(string(pt.Bytes())))
	if p == "" {
		return "", "the stored value is not an API key"
	}
	return p, ""
}

func apiCall(ctx context.Context, src Sources, tenantID uuid.UUID) (bool, string) {
	if src.Headscale == nil {
		return false, "no Headscale registry"
	}
	cctx, cancel := context.WithTimeout(ctx, src.Timeout)
	defer cancel()
	inst, err := src.Headscale.ForTenant(cctx, tenantID)
	if err != nil {
		return false, err.Error()
	}
	if _, err := inst.ListAPIKeys(cctx); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// scopedAgent hides from reconcile's host check what belongs to other runs on a shared host: inventory entries and edge
// aliases outside the scope.
type scopedAgent struct {
	next  reconcile.Agent
	scope Scope
	ids   map[uuid.UUID]Instance
}

func (s scopedAgent) GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, o ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	return s.next.GetInstanceStatus(ctx, in, o...)
}

func (s scopedAgent) ListInstances(ctx context.Context, in *agentv1.ListInstancesRequest, o ...grpc.CallOption) (*agentv1.ListInstancesResponse, error) {
	resp, err := s.next.ListInstances(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	out := &agentv1.ListInstancesResponse{}
	for _, e := range resp.GetInstances() {
		id, _ := uuid.Parse(e.GetInstanceId())
		_, known := s.ids[id]
		// every directory is the run's (the tenants directory is); containers and networks only when they name the
		// run's slug or one of its instances
		if e.GetHasDirectory() || known || (e.GetSlug() != "" && s.scope.inScope(e.GetSlug())) {
			out.Instances = append(out.Instances, e)
		}
	}
	for _, a := range resp.GetEdgeAliases() {
		if s.scope.inScope(strings.TrimPrefix(a.GetAlias(), "hs-")) {
			out.EdgeAliases = append(out.EdgeAliases, a)
		}
	}
	return out, nil
}
