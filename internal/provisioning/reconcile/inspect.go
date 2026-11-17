package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Agent is the read-only part of the Host Agent API that reconcile uses — *agentclient.Client satisfies it. Nothing
// else of the agent is reachable from this package: reconcile cannot start, stop, create or remove anything.
type Agent interface {
	GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, opts ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error)
	ListInstances(ctx context.Context, in *agentv1.ListInstancesRequest, opts ...grpc.CallOption) (*agentv1.ListInstancesResponse, error)
}

// Desired is the registry's state of one instance.
type Desired struct {
	InstanceID, TenantID uuid.UUID
	Slug                 string
	Status               string // tenant_instances.status: starting, running or stopped
	ImageDigest          string // sha256:<hex>
	NetCIDR              netip.Prefix
	RunUID               uint32
	APIKeyPrefix         string // "" when not recorded
	NoiseKeyFingerprint  string // "" when not recorded
	ConfigSHA256         string // config version in force; "" when none is recorded (instances built by hand, Phase 1)
}

// Registered is one row of the registry for the host check.
type Registered struct {
	InstanceID, TenantID uuid.UUID
	Slug, Status         string
}

// Inspector reads the actual state and compares it with a desired state. It has no database: Service feeds it.
type Inspector struct {
	// Agent is the host's agent; nil = no agent configured (every agent check: unavailable, agent_not_configured).
	Agent Agent
	// Headscale reaches a tenant's instance (headscale.Registry — the worker's CachingRegistry); nil = the API key
	// check is unavailable.
	Headscale headscale.Registry
	// AgentUID and AgentGID own the agent's paths ("root" of §14.2 — 0 in production).
	AgentUID, AgentGID uint32
	// RotationGrace: while the current key is younger than this, the key created just before it may still be valid
	// (§11.4 API key rotation: create → verify → store → expire the old one).
	RotationGrace time.Duration
	// AgentTimeout bounds one call to the agent.
	AgentTimeout time.Duration
	// EventWindow deduplicates the security events of one subject.
	EventWindow time.Duration
	Now         func() time.Time
}

func (in *Inspector) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// names derived from the slug (agentspec.Host.Names — the agent's own derivation, checked by a test).
func networkName(slug string) string   { return "mg-t-" + slug }
func containerName(slug string) string { return "mg-hs-" + slug }
func aliasName(slug string) string     { return "hs-" + slug }

// Reasons a check could not run.
const (
	ReasonAgentNotConfigured  = "agent_not_configured"
	ReasonAgentUnreachable    = "agent_unreachable"
	ReasonAgentBusy           = "agent_busy"
	ReasonAgentNoDriver       = "agent_no_driver"
	ReasonAgentUnauthorized   = "agent_unauthorized"
	ReasonAgentRefused        = "agent_refused"
	ReasonAgentError          = "agent_error"
	ReasonNotRecorded         = "not_recorded"
	ReasonNotReported         = "not_reported"
	ReasonNotExpected         = "not_expected"
	ReasonHeadscaleNoRegistry = "headscale_not_configured"
)

// Instance compares one instance; the security events are platform-scope (tenant_id NULL) and name the instance.
func (in *Inspector) Instance(ctx context.Context, d Desired) (Report, []audit.SecurityEvent) {
	start := time.Now()
	t, i := d.TenantID, d.InstanceID
	r := Report{Schema: ReportSchema, Scope: ScopeInstance, TenantID: &t, InstanceID: &i, CheckedAt: in.now().UTC()}
	ev := &events{in: in, d: &d}
	in.agentChecks(ctx, d, &r, ev)
	in.keyChecks(ctx, d, &r, ev)
	r.finish()
	r.DurationMS = time.Since(start).Milliseconds()
	return r, ev.list
}

// agentChecks: GetInstanceStatus and everything derived from it.
func (in *Inspector) agentChecks(ctx context.Context, d Desired, r *Report, ev *events) {
	agentNames := []string{CheckContainer, CheckImage, CheckConfig, CheckNetwork, CheckPaths, CheckNoiseKey}
	unavailable := func(reason string) {
		r.check(CheckAgent, OutcomeUnavailable, reason, "")
		for _, n := range agentNames {
			r.check(n, OutcomeUnavailable, reason, "")
		}
	}
	if in.Agent == nil {
		unavailable(ReasonAgentNotConfigured)
		return
	}
	actx, cancel := in.agentContext(ctx)
	resp, err := in.Agent.GetInstanceStatus(actx, &agentv1.GetInstanceStatusRequest{
		Instance: &agentv1.InstanceRef{InstanceId: d.InstanceID.String(), TenantId: d.TenantID.String(), Slug: d.Slug}})
	cancel()
	if err != nil {
		reason, refusal := classify(err)
		switch {
		case refusal != nil && refusal.GetReason() == agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND:
			r.check(CheckAgent, OutcomeDrift, "", "")
			r.add(Finding{Kind: DriftInstanceMissing, Expected: "directory with meta/instance.json", Actual: "absent"})
		case reason == "" && refusal != nil:
			// the guard refused to report: an object with a derived name, or the instance's meta, is not this instance's
			code := strings.ToLower(strings.TrimPrefix(refusal.GetReason().String(), "REFUSAL_REASON_"))
			r.check(CheckAgent, OutcomeDrift, "", "")
			r.add(Finding{Kind: DriftGuardRefused, Actual: code, Items: nonEmpty(refusal.GetField())})
			ev.add(DriftGuardRefused, code, audit.Details{"refusal": code, "field": refusal.GetField(),
				"message": clip(refusal.GetMessage())})
		default:
			unavailable(reason)
			return
		}
		for _, n := range agentNames {
			r.check(n, OutcomeUnavailable, ReasonAgentRefused, "")
		}
		return
	}
	r.check(CheckAgent, OutcomeOK, "", "")
	st := resp.GetStatus()
	running := in.containerCheck(d, st, r)
	in.imageCheck(d, st, r, ev)
	in.configCheck(d, st, r)
	in.networkCheck(d, st, running, r, ev)
	in.pathCheck(d, st, r)
	in.noiseCheck(d, st, r, ev)
}

func (in *Inspector) agentContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if in.AgentTimeout > 0 {
		return context.WithTimeout(ctx, in.AgentTimeout)
	}
	return context.WithCancel(ctx)
}

// classify maps an agent error: reason "" with a refusal means the agent's guard refused (FOREIGN_OBJECT, CONFLICT,
// IDENTITY_MISMATCH, UNSAFE_PATH, STATE — drift), otherwise reason says why the check could not run.
func classify(err error) (string, *agentv1.Refusal) {
	refusal, _ := agentclient.RefusalOf(err)
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return ReasonAgentUnreachable, refusal
	case codes.Aborted:
		return ReasonAgentBusy, refusal
	case codes.Unimplemented:
		return ReasonAgentNoDriver, refusal
	case codes.Unauthenticated, codes.PermissionDenied:
		return ReasonAgentUnauthorized, refusal
	case codes.NotFound:
		if refusal != nil {
			return "", refusal
		}
	case codes.FailedPrecondition:
		if refusal != nil {
			return "", refusal
		}
	case codes.InvalidArgument:
		return ReasonAgentRefused, refusal
	}
	return ReasonAgentError, refusal
}

func stateName(s agentv1.ContainerState) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "CONTAINER_STATE_"))
}

// containerCheck reports whether the container runs.
func (in *Inspector) containerCheck(d Desired, st *agentv1.InstanceStatus, r *Report) bool {
	wantRunning := d.Status != tenants.InstanceStopped
	cs := st.GetContainerState()
	before := len(r.Findings)
	switch {
	case cs == agentv1.ContainerState_CONTAINER_STATE_ABSENT:
		r.add(Finding{Kind: DriftContainerAbsent, Expected: containerName(d.Slug), Actual: "absent"})
	case cs == agentv1.ContainerState_CONTAINER_STATE_RUNNING && !wantRunning:
		r.add(Finding{Kind: DriftContainerRunning, Expected: "not running", Actual: stateName(cs)})
	case cs == agentv1.ContainerState_CONTAINER_STATE_RUNNING && st.GetHealth() == agentv1.HealthState_HEALTH_STATE_UNHEALTHY:
		r.add(Finding{Kind: DriftContainerUnhealthy, Expected: "healthy", Actual: "unhealthy"})
	case cs != agentv1.ContainerState_CONTAINER_STATE_RUNNING && wantRunning:
		r.add(Finding{Kind: DriftContainerNotRunning, Expected: "running", Actual: stateName(cs)})
	}
	r.check(CheckContainer, outcome(r, before), "", stateName(cs))
	return cs == agentv1.ContainerState_CONTAINER_STATE_RUNNING
}

func outcome(r *Report, before int) string {
	if len(r.Findings) > before {
		return OutcomeDrift
	}
	return OutcomeOK
}

func (in *Inspector) imageCheck(d Desired, st *agentv1.InstanceStatus, r *Report, ev *events) {
	if st.GetContainerState() == agentv1.ContainerState_CONTAINER_STATE_ABSENT {
		r.check(CheckImage, OutcomeNotApplicable, ReasonNotExpected, "")
		return
	}
	actual := st.GetImageDigest()
	if actual == d.ImageDigest {
		r.check(CheckImage, OutcomeOK, "", "")
		return
	}
	if actual == "" {
		actual = "unpinned"
	}
	r.add(Finding{Kind: DriftImageDigest, Expected: d.ImageDigest, Actual: actual})
	r.check(CheckImage, OutcomeDrift, "", "")
	ev.add(DriftImageDigest, actual, audit.Details{"expected": d.ImageDigest, "actual": actual})
}

func (in *Inspector) configCheck(d Desired, st *agentv1.InstanceStatus, r *Report) {
	switch actual := st.GetConfigSha256(); {
	case d.ConfigSHA256 == "":
		r.check(CheckConfig, OutcomeNotApplicable, ReasonNotRecorded, "")
	case actual == "":
		r.add(Finding{Kind: DriftConfigMissing, Expected: d.ConfigSHA256, Actual: "absent"})
		r.check(CheckConfig, OutcomeDrift, "", "")
	case !strings.EqualFold(actual, d.ConfigSHA256):
		r.add(Finding{Kind: DriftConfigHash, Expected: d.ConfigSHA256, Actual: actual})
		r.check(CheckConfig, OutcomeDrift, "", "")
	default:
		r.check(CheckConfig, OutcomeOK, "", "")
	}
}

// networkCheck: mg-t-<slug> exists with net_cidr, is internal, and holds exactly the instance's container and the edge
// (§14.3). Docker lists running members only: the instance's own container is required while it runs.
func (in *Inspector) networkCheck(d Desired, st *agentv1.InstanceStatus, running bool, r *Report, ev *events) {
	nw := st.GetNetwork()
	before := len(r.Findings)
	if !nw.GetExists() {
		r.add(Finding{Kind: DriftNetworkAbsent, Expected: networkName(d.Slug), Actual: "absent"})
		r.check(CheckNetwork, OutcomeDrift, "", "")
		return
	}
	if nw.GetSubnet() != d.NetCIDR.String() {
		r.add(Finding{Kind: DriftNetworkSubnet, Expected: d.NetCIDR.String(), Actual: nw.GetSubnet()})
	}
	if !nw.GetInternal() {
		r.add(Finding{Kind: DriftNetworkNotInternal, Expected: "internal", Actual: "not internal"})
		ev.add(DriftNetworkNotInternal, "", audit.Details{"network": networkName(d.Slug)})
	}
	own := false
	for _, m := range nw.GetMembers() {
		if m == containerName(d.Slug) {
			own = true
		}
	}
	extra := len(nw.GetMembers())
	if own {
		extra--
	}
	if nw.GetEdgeAttached() {
		extra--
	}
	if extra > 0 {
		// counts only in the report (a member may be another tenant's container); the names go to the platform event
		r.add(Finding{Kind: DriftNetworkExtraMember, Expected: "2", Actual: strconv.Itoa(len(nw.GetMembers())), Count: extra})
		members := append([]string(nil), nw.GetMembers()...)
		sort.Strings(members)
		ev.add(DriftNetworkExtraMember, digest(strings.Join(members, ",")), audit.Details{"network": networkName(d.Slug),
			"members": capList(members), "extra": extra, "edge_attached": nw.GetEdgeAttached()})
	}
	if running && !own {
		r.add(Finding{Kind: DriftContainerDetached, Expected: containerName(d.Slug), Actual: "not a member"})
	}
	if d.Status == tenants.InstanceRunning && !nw.GetEdgeAttached() {
		r.add(Finding{Kind: DriftEdgeDetached, Expected: "attached", Actual: "detached"})
	}
	r.check(CheckNetwork, outcome(r, before), "", fmt.Sprintf("members=%d", len(nw.GetMembers())))
}

// pathRule is the owner/mode of one agent-managed path (§14.2, the compose driver's storage.go).
type pathRule struct {
	tenantUID, tenantGID bool // owner / group is run_uid (otherwise the agent's)
	mode                 uint32
}

var pathRules = map[agentv1.PathKind]pathRule{
	agentv1.PathKind_PATH_KIND_INSTANCE_DIR: {false, true, 0o750},
	agentv1.PathKind_PATH_KIND_CONFIG_DIR:   {false, true, 0o750},
	agentv1.PathKind_PATH_KIND_RECORDS_DIR:  {false, true, 0o750},
	agentv1.PathKind_PATH_KIND_DATA_DIR:     {true, true, 0o700},
	agentv1.PathKind_PATH_KIND_META_DIR:     {false, false, 0o700},
	agentv1.PathKind_PATH_KIND_COMPOSE_FILE: {false, false, 0o440},
	agentv1.PathKind_PATH_KIND_CONFIG_FILE:  {false, true, 0o440},
	agentv1.PathKind_PATH_KIND_POLICY_FILE:  {false, true, 0o440},
	agentv1.PathKind_PATH_KIND_RECORDS_FILE: {false, true, 0o440},
	agentv1.PathKind_PATH_KIND_META_FILE:    {false, false, 0o400},
}

func pathName(k agentv1.PathKind) string {
	return strings.ToLower(strings.TrimPrefix(k.String(), "PATH_KIND_"))
}

// pathCheck compares the owner/mode of every reported path with §14.2 (setuid/setgid/sticky bits and a symlink are a
// mismatch: the agent reports them in mode).
func (in *Inspector) pathCheck(d Desired, st *agentv1.InstanceStatus, r *Report) {
	var items []string
	seen := 0
	for _, p := range st.GetPaths() {
		rule, ok := pathRules[p.GetKind()]
		if !ok {
			continue
		}
		seen++
		name := pathName(p.GetKind())
		if !p.GetExists() {
			items = append(items, name+":missing")
			continue
		}
		uid, gid := in.AgentUID, in.AgentGID
		if rule.tenantUID {
			uid = d.RunUID
		}
		if rule.tenantGID {
			gid = d.RunUID // run_gid = run_uid (§6.3)
		}
		if p.GetUid() != uid || p.GetGid() != gid {
			items = append(items, fmt.Sprintf("%s:owner=%d:%d,want=%d:%d", name, p.GetUid(), p.GetGid(), uid, gid))
		}
		if p.GetMode() != rule.mode {
			m := fmt.Sprintf("%s:mode=%04o", name, p.GetMode()&0o7777)
			if p.GetMode()&uint32(fs.ModeSymlink) != 0 {
				m += ",symlink"
			}
			items = append(items, fmt.Sprintf("%s,want=%04o", m, rule.mode))
		}
	}
	switch {
	case seen == 0:
		r.check(CheckPaths, OutcomeNotApplicable, ReasonNotReported, "")
	case len(items) > 0:
		sort.Strings(items)
		r.add(Finding{Kind: DriftPathPermissions, Items: capList(items), Count: len(items)})
		r.check(CheckPaths, OutcomeDrift, "", fmt.Sprintf("paths=%d", seen))
	default:
		r.check(CheckPaths, OutcomeOK, "", fmt.Sprintf("paths=%d", seen))
	}
}

func (in *Inspector) noiseCheck(d Desired, st *agentv1.InstanceStatus, r *Report, ev *events) {
	actual := st.GetNoiseKeyFingerprint()
	switch {
	case actual == "":
		r.check(CheckNoiseKey, OutcomeNotApplicable, ReasonNotReported, "")
	case d.NoiseKeyFingerprint == "":
		r.check(CheckNoiseKey, OutcomeNotApplicable, ReasonNotRecorded, "")
	case !strings.EqualFold(actual, d.NoiseKeyFingerprint):
		r.add(Finding{Kind: DriftNoiseKey, Expected: d.NoiseKeyFingerprint, Actual: actual})
		r.check(CheckNoiseKey, OutcomeDrift, "", "")
		ev.add(DriftNoiseKey, actual, audit.Details{"expected": d.NoiseKeyFingerprint, "actual": actual})
	default:
		r.check(CheckNoiseKey, OutcomeOK, "", "")
	}
}

// keyChecks: ListAPIKeys of the instance (§11.4 API key rotation, T-05). Valid = no expiration (Headscale keeps such a
// key forever) or an expiration in the future.
func (in *Inspector) keyChecks(ctx context.Context, d Desired, r *Report, ev *events) {
	switch {
	case d.Status == tenants.InstanceStopped:
		r.check(CheckAPIKeys, OutcomeNotApplicable, ReasonNotExpected, "")
		return
	case in.Headscale == nil:
		r.check(CheckAPIKeys, OutcomeUnavailable, ReasonHeadscaleNoRegistry, "")
		return
	case d.APIKeyPrefix == "":
		r.check(CheckAPIKeys, OutcomeNotApplicable, ReasonNotRecorded, "")
		return
	}
	inst, err := in.Headscale.ForTenant(ctx, d.TenantID)
	var keys []headscale.APIKey
	if err == nil {
		keys, err = inst.ListAPIKeys(ctx)
	}
	if err != nil {
		r.check(CheckAPIKeys, OutcomeUnavailable, headscaleReason(err), "")
		return
	}
	now := in.now()
	valid := func(k headscale.APIKey) bool { return k.Expiration.IsZero() || k.Expiration.After(now) }
	var cur *headscale.APIKey
	for i := range keys {
		if keys[i].Prefix == d.APIKeyPrefix && keys[i].Prefix != "" {
			cur = &keys[i]
		}
	}
	before := len(r.Findings)
	switch {
	case cur == nil:
		r.add(Finding{Kind: DriftAPIKeyCurrent, Expected: d.APIKeyPrefix, Actual: "absent"})
	case !valid(*cur):
		r.add(Finding{Kind: DriftAPIKeyCurrent, Expected: d.APIKeyPrefix, Actual: "expired"})
	}
	// the previous key: while the current one is younger than RotationGrace, the newest valid key created before it
	var prev *headscale.APIKey
	if cur != nil && now.Sub(cur.CreatedAt) < in.RotationGrace {
		for i := range keys {
			k := &keys[i]
			if k == cur || !valid(*k) || !k.CreatedAt.Before(cur.CreatedAt) {
				continue
			}
			if prev == nil || k.CreatedAt.After(prev.CreatedAt) {
				prev = k
			}
		}
	}
	nValid := 0
	for i := range keys {
		k := &keys[i]
		if !valid(*k) {
			continue
		}
		nValid++
		if k == cur || k == prev {
			continue
		}
		subject := k.Prefix
		if subject == "" {
			subject = "id:" + strconv.FormatUint(k.ID, 10)
		}
		expires := "never"
		if !k.Expiration.IsZero() {
			expires = k.Expiration.UTC().Format(time.RFC3339)
		}
		r.add(Finding{Kind: DriftAPIKeyForeign, Subject: subject, Expected: "expired", Actual: "valid until " + expires})
		details := audit.Details{"prefix": subject, "key_id": strconv.FormatUint(k.ID, 10), "expires": expires,
			"created_at": k.CreatedAt.UTC().Format(time.RFC3339)}
		if k.LastSeen != nil {
			details["last_seen"] = k.LastSeen.UTC().Format(time.RFC3339)
		}
		ev.add(DriftAPIKeyForeign, subject, details)
	}
	note := "valid=" + strconv.Itoa(nValid)
	if prev != nil {
		note += ",rotation_previous=" + prev.Prefix
	}
	r.check(CheckAPIKeys, outcome(r, before), "", note)
}

// headscaleReason is the stable code of an adapter error (never its text).
func headscaleReason(err error) string {
	var he *headscale.Error
	if errors.As(err, &he) && he.Kind != "" {
		return "headscale_" + string(he.Kind)
	}
	return "headscale_error"
}

// Host compares the host's inventory with the registry; the security events are platform-scope.
func (in *Inspector) Host(ctx context.Context, regs []Registered) (Report, []audit.SecurityEvent) {
	start := time.Now()
	r := Report{Schema: ReportSchema, Scope: ScopeHost, CheckedAt: in.now().UTC()}
	ev := &events{in: in}
	if in.Agent == nil {
		for _, n := range []string{CheckAgent, CheckInventory, CheckAliases} {
			r.check(n, OutcomeUnavailable, ReasonAgentNotConfigured, "")
		}
		r.finish()
		return r, nil
	}
	actx, cancel := in.agentContext(ctx)
	resp, err := in.Agent.ListInstances(actx, &agentv1.ListInstancesRequest{})
	cancel()
	if err != nil {
		reason, _ := classify(err)
		if reason == "" {
			reason = ReasonAgentRefused
		}
		for _, n := range []string{CheckAgent, CheckInventory, CheckAliases} {
			r.check(n, OutcomeUnavailable, reason, "")
		}
		r.finish()
		r.DurationMS = time.Since(start).Milliseconds()
		return r, nil
	}
	r.check(CheckAgent, OutcomeOK, "", "")
	in.inventoryCheck(resp.GetInstances(), regs, &r, ev)
	in.aliasCheck(resp.GetEdgeAliases(), regs, &r, ev)
	r.finish()
	r.DurationMS = time.Since(start).Milliseconds()
	return r, ev.list
}

func flags(e *agentv1.InventoryEntry) []string {
	var out []string
	if e.GetHasDirectory() {
		out = append(out, "directory")
	}
	if e.GetHasContainer() {
		out = append(out, "container")
	}
	if e.GetHasNetwork() {
		out = append(out, "network")
	}
	return out
}

func (in *Inspector) inventoryCheck(entries []*agentv1.InventoryEntry, regs []Registered, r *Report, ev *events) {
	byID := make(map[string]Registered, len(regs))
	for _, g := range regs {
		byID[g.InstanceID.String()] = g
	}
	before := len(r.Findings)
	seen := map[string]bool{}
	for _, e := range entries {
		id := e.GetInstanceId()
		seen[id] = true
		g, known := byID[id]
		details := audit.Details{"instance_id": id, "tenant_label": e.GetTenantId(), "slug": e.GetSlug(),
			"directory": e.GetHasDirectory(), "container": e.GetHasContainer(), "network": e.GetHasNetwork()}
		switch {
		case !known:
			r.add(Finding{Kind: DriftUnknownInstance, Subject: id, Items: flags(e)})
			ev.addHost(DriftUnknownInstance, id, details)
		case g.Status == tenants.InstanceRemoved:
			r.add(Finding{Kind: DriftRemovedLeftover, Subject: id, Items: flags(e)})
		case (e.GetTenantId() != "" && e.GetTenantId() != g.TenantID.String()) || (e.GetSlug() != "" && e.GetSlug() != g.Slug):
			r.add(Finding{Kind: DriftIdentityMismatch, Subject: id, Expected: g.TenantID.String() + "/" + g.Slug,
				Actual: e.GetTenantId() + "/" + e.GetSlug()})
			details["tenant_id"], details["registry_slug"] = g.TenantID.String(), g.Slug
			ev.addHost(DriftIdentityMismatch, id, details)
		}
	}
	for _, g := range regs {
		if targeted(g.Status) && !seen[g.InstanceID.String()] {
			r.add(Finding{Kind: DriftRegisteredMissing, Subject: g.InstanceID.String(), Expected: "directory, container, network",
				Actual: "absent"})
		}
	}
	r.check(CheckInventory, outcome(r, before), "", fmt.Sprintf("host=%d,registry=%d", len(entries), len(regs)))
}

// targeted: the statuses reconcile checks (ListReconcileTargets).
func targeted(status string) bool {
	return status == tenants.InstanceStarting || status == tenants.InstanceRunning || status == tenants.InstanceStopped
}

// aliasCheck: every hs-<slug> on the edge's networks belongs to a live instance and is held only by mg-hs-<slug> on
// mg-t-<slug> (§11.4; the edge resolves the name over all of its networks).
func (in *Inspector) aliasCheck(aliases []*agentv1.EdgeAlias, regs []Registered, r *Report, ev *events) {
	live := map[string]bool{}
	for _, g := range regs {
		if g.Status != tenants.InstanceRemoved {
			live[g.Slug] = true
		}
	}
	holders := map[string][]string{}
	foreign := map[string]bool{}
	for _, a := range aliases {
		slug := strings.TrimPrefix(a.GetAlias(), "hs-")
		holders[a.GetAlias()] = append(holders[a.GetAlias()], a.GetNetwork()+"/"+a.GetContainer())
		if a.GetNetwork() != networkName(slug) || a.GetContainer() != containerName(slug) {
			foreign[a.GetAlias()] = true
		}
	}
	names := make([]string, 0, len(holders))
	for n := range holders {
		names = append(names, n)
	}
	sort.Strings(names)
	before := len(r.Findings)
	for _, alias := range names {
		h := holders[alias]
		sort.Strings(h)
		slug := strings.TrimPrefix(alias, "hs-")
		details := audit.Details{"alias": alias, "holders": capList(h)}
		switch {
		case !live[slug]:
			r.add(Finding{Kind: DriftUnknownAlias, Subject: alias, Items: capList(h), Count: len(h)})
			ev.addHost(DriftUnknownAlias, alias+":"+digest(strings.Join(h, ",")), details)
		case foreign[alias]:
			r.add(Finding{Kind: DriftAliasCollision, Subject: alias, Expected: networkName(slug) + "/" + containerName(slug),
				Items: capList(h), Count: len(h)})
			ev.addHost(DriftAliasCollision, alias+":"+digest(strings.Join(h, ",")), details)
		}
	}
	r.check(CheckAliases, outcome(r, before), "", fmt.Sprintf("names=%d", len(aliases)))
}

// events builds the security events of one run.
type events struct {
	in   *Inspector
	d    *Desired // nil for the host
	list []audit.SecurityEvent
}

// add records an event of the instance: subject distinguishes several events of one kind (a key prefix, a digest).
func (e *events) add(kind, subject string, details audit.Details) {
	details["tenant_id"] = e.d.TenantID.String()
	details["instance_id"] = e.d.InstanceID.String()
	details["slug"] = e.d.Slug
	e.push(kind, e.d.InstanceID.String()+":"+subject, details)
}

func (e *events) addHost(kind, subject string, details audit.Details) {
	e.push(kind, "host:"+subject, details)
}

func (e *events) push(kind, subject string, details audit.Details) {
	if !securityKinds[kind] {
		return
	}
	details["drift"] = kind
	window := e.in.EventWindow
	if window <= 0 {
		window = DefaultEventWindow
	}
	e.list = append(e.list, audit.SecurityEvent{Kind: "reconcile." + kind, Severity: severities[kind], Source: SecuritySource,
		Details: details, DedupeKey: clip("reconcile." + kind + ":" + subject), DedupeWindow: window})
}

// digest is a short stable hash of a list (dedupe keys of sets of names).
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// clip bounds a text to what security_events details keep (256 bytes per value).
func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// capList bounds a list (details keep at most 32 elements).
func capList(s []string) []string {
	if len(s) > 32 {
		return s[:32]
	}
	return s
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
