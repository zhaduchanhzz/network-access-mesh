package orchestrator

// In-memory fakes of every collaborator of the state machine: the job attempt (fakeRunner — steps, created_resources,
// compensation status, like internal/jobs), the registry (memStore), the Host Agent (fakeAgent — a model of the host:
// directory, config, network, container, policy, API keys, edge), placement, SecretStore, IdP driver, Headscale,
// prober. Each records what it was asked so the tests can assert order, idempotency and the absence of secrets.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ---------------------------------------------------------------------------------------------------- runner

type fakeStep struct {
	name, status, comp string
	attempt            int
	resources, detail  []byte
}

type fakeRunner struct {
	id        uuid.UUID
	input     []byte
	steps     []*fakeStep
	cancelled bool
	output    any
	resource  [2]string
}

func newRunner(in Input) *fakeRunner {
	b, _ := json.Marshal(in)
	return &fakeRunner{id: uuid.New(), input: b}
}

func (r *fakeRunner) step(name string) *fakeStep {
	for _, s := range r.steps {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (r *fakeRunner) JobID() uuid.UUID           { return r.id }
func (r *fakeRunner) Input(v any) error          { return json.Unmarshal(r.input, v) }
func (r *fakeRunner) SetOutput(v any) error      { r.output = v; return nil }
func (r *fakeRunner) SetResource(typ, id string) { r.resource = [2]string{typ, id} }

func (r *fakeRunner) Step(ctx context.Context, name string, fn func(ctx context.Context, s stepCtx) error) error {
	if r.cancelled {
		return jobs.Resumable(jobs.CodeCancelled, errors.New("cancelled"))
	}
	s := r.step(name)
	if s == nil {
		s = &fakeStep{name: name}
		r.steps = append(r.steps, s)
	}
	if s.status == jobs.StepSucceeded {
		return nil
	}
	s.status, s.attempt, s.detail = jobs.StepRunning, s.attempt+1, nil
	sc := &fakeStepCtx{s: s}
	err := fn(ctx, sc)
	s.detail = sc.detail
	if err != nil {
		s.status = jobs.StepFailed
		return err
	}
	s.status = jobs.StepSucceeded
	return nil
}

func (r *fakeRunner) StepResources(_ context.Context, name string, v any) (bool, error) {
	s := r.step(name)
	if s == nil || len(s.resources) == 0 {
		return false, nil
	}
	return true, json.Unmarshal(s.resources, v)
}

func (r *fakeRunner) CompensateSteps(ctx context.Context, fns map[string]jobs.CompensateFunc) error {
	for i := len(r.steps) - 1; i >= 0; i-- {
		s := r.steps[i]
		if s.comp == jobs.StepSucceeded || s.comp == jobs.StepSkipped {
			continue
		}
		fn := fns[s.name]
		acted := s.status == jobs.StepSucceeded || (len(s.resources) > 0 && s.status != jobs.StepSkipped)
		if fn == nil || !acted {
			s.comp = jobs.StepSkipped
			continue
		}
		if err := fn(ctx, jobs.CompensationStep{Name: s.name, Status: s.status, Resources: s.resources}); err != nil {
			s.comp = jobs.StepFailed
			return err
		}
		s.comp = jobs.StepSucceeded
	}
	return nil
}

// reset marks a succeeded step as not run, so the next run executes it again (idempotent re-execution).
func (r *fakeRunner) reset(name string) {
	if s := r.step(name); s != nil {
		s.status = jobs.StepFailed
	}
}

// texts is everything the job stored: details, created_resources, output.
func (r *fakeRunner) texts() string {
	var b strings.Builder
	for _, s := range r.steps {
		b.Write(s.resources)
		b.Write(s.detail)
	}
	o, _ := json.Marshal(r.output)
	b.Write(o)
	return b.String()
}

type fakeStepCtx struct {
	s      *fakeStep
	detail []byte
}

func (c *fakeStepCtx) RecordCreated(_ context.Context, v any) error {
	b, err := json.Marshal(v)
	c.s.resources = b
	return err
}

func (c *fakeStepCtx) SetDetail(v any) error {
	b, err := json.Marshal(v)
	c.detail = b
	return err
}

func (c *fakeStepCtx) Previous(v any) (bool, error) {
	if len(c.s.resources) == 0 {
		return false, nil
	}
	return true, json.Unmarshal(c.s.resources, v)
}

// ---------------------------------------------------------------------------------------------------- registry

type memStore struct {
	mu           sync.Mutex
	tenant       TenantRecord
	instances    map[uuid.UUID]*InstanceRecord
	configs      map[string]uuid.UUID // config sha → version id
	idps         map[uuid.UUID]*IdPRecord
	policy       []string // recorded baseline policies (one per RecordBaselinePolicy that wrote)
	invitations  map[uuid.UUID]string
	settings     json.RawMessage
	relays       map[string]bool
	activations  int
	audit        []string // "<action>.<suffix> <reason>"
	failErr      map[string]error
	notification []string
	apiKeyLocks  int // WithAPIKeyLock calls
}

func newMemStore(t TenantRecord) *memStore {
	return &memStore{tenant: t, instances: map[uuid.UUID]*InstanceRecord{}, configs: map[string]uuid.UUID{},
		idps: map[uuid.UUID]*IdPRecord{}, invitations: map[uuid.UUID]string{}, relays: map[string]bool{},
		failErr: map[string]error{}}
}

func (m *memStore) err(op string) error {
	if e := m.failErr[op]; e != nil {
		return e
	}
	return nil
}

func (m *memStore) Tenant(context.Context, uuid.UUID) (TenantRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tenant, m.err("Tenant")
}

func (m *memStore) Instance(_ context.Context, _, id uuid.UUID) (InstanceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.instances[id]
	if !ok {
		return InstanceRecord{}, ErrNotFound
	}
	return *i, nil
}

func (m *memStore) TransitionInstance(_ context.Context, _, id uuid.UUID, from []string, to string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.instances[id]
	if !ok {
		return "", ErrNotFound
	}
	prev := i.Status
	if slices.Contains(from, i.Status) {
		i.Status = to
	}
	return prev, nil
}

func (m *memStore) SetFingerprint(_ context.Context, _, id uuid.UUID, fp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.instances[id].NoiseFingerprint = fp
	return nil
}

func (m *memStore) SetRuntime(_ context.Context, _, id uuid.UUID, v, d string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.instances[id].HeadscaleVersion, m.instances[id].ImageDigest = v, d
	return nil
}

func (m *memStore) RecordConfig(_ context.Context, _, id uuid.UUID, c ConfigRecord) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.configs[c.ConfigSHA256]; ok {
		return v, nil
	}
	v := uuid.New()
	m.configs[c.ConfigSHA256] = v
	m.instances[id].DERPRegionID = c.DERPRegionID
	return v, nil
}

func (m *memStore) SetAPIKey(_ context.Context, _, id uuid.UUID, ref, prefix string, exp *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.err("SetAPIKey"); err != nil {
		return err
	}
	i := m.instances[id]
	i.APIKeyRef, i.APIKeyPrefix, i.APIKeyExpiresAt = ref, prefix, exp
	return nil
}

func (m *memStore) IdP(_ context.Context, _, id uuid.UUID) (IdPRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.idps[id]
	if !ok {
		return IdPRecord{}, false, nil
	}
	return *r, true, nil
}

func (m *memStore) SaveIdP(_ context.Context, r IdPRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.idps[r.ID]; ok {
		cur.DriverRef, cur.ClientSecretRef = r.DriverRef, r.ClientSecretRef
		return nil
	}
	r.Status = "pending"
	m.idps[r.ID] = &r
	return nil
}

func (m *memStore) SetIdPStatus(_ context.Context, _, id uuid.UUID, from, to string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.idps[id]
	if !ok || r.Status != from {
		return false, nil
	}
	r.Status = to
	return true, nil
}

func (m *memStore) RecordBaselinePolicy(_ context.Context, _, _ uuid.UUID, hujson string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.policy) == 0 {
		m.policy = append(m.policy, hujson)
	}
	return nil
}

func (m *memStore) Configure(_ context.Context, r ConfigureRequest) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.err("Configure"); err != nil {
		return uuid.Nil, err
	}
	m.settings = r.Settings
	if i := m.idps[r.IdPID]; i != nil && i.Status == "pending" {
		i.Status = tenants.IdPStatusActive
	}
	for id, st := range m.invitations {
		if st == "pending" {
			return id, nil
		}
	}
	id := uuid.New()
	m.invitations[id] = "pending"
	m.notification = append(m.notification, "tenant.invitation "+r.OwnerEmail)
	return id, nil
}

func (m *memStore) RevokeInvitation(_ context.Context, _, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invitations[id] == "pending" {
		m.invitations[id] = "revoked"
	}
	return nil
}

func (m *memStore) AssignRelay(_ context.Context, r RelayRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relays[r.Code] = true
	return nil
}

func (m *memStore) RemoveRelay(_ context.Context, _, _ uuid.UUID, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.relays, code)
	return nil
}

func (m *memStore) Activate(_ context.Context, r ActivateRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.err("Activate"); err != nil {
		return err
	}
	i := m.instances[r.InstanceID]
	if i.Status == tenants.InstanceStarting {
		i.Status = tenants.InstanceRunning
	}
	if m.tenant.Status == tenants.StatusProvisioning {
		m.tenant.Status = tenants.StatusActive
		m.activations++
		m.audit = append(m.audit, r.Operation.Action+".succeeded")
		m.notification = append(m.notification, "tenant.activated "+r.OwnerEmail)
	}
	return nil
}

func (m *memStore) Fail(_ context.Context, _ uuid.UUID, op audit.Operation, reason string, _ audit.Details) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tenant.Status == tenants.StatusProvisioning {
		m.tenant.Status = tenants.StatusFailed
		m.audit = append(m.audit, op.Action+".failed "+reason)
	}
	return nil
}

func (m *memStore) WithAPIKeyLock(ctx context.Context, _ uuid.UUID, fn func(ctx context.Context) error) error {
	m.mu.Lock()
	m.apiKeyLocks++
	m.mu.Unlock()
	return fn(ctx)
}

// snapshot is the registry state compared across re-executions.
func (m *memStore) snapshot() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var parts []string
	for id, i := range m.instances {
		parts = append(parts, fmt.Sprintf("inst %s %s %s fp=%s key=%s/%s derp=%d", id, i.Status, i.HeadscaleVersion,
			i.NoiseFingerprint, i.APIKeyRef, i.APIKeyPrefix, i.DERPRegionID))
	}
	for _, c := range m.configs {
		parts = append(parts, "config "+c.String())
	}
	for id, r := range m.idps {
		parts = append(parts, fmt.Sprintf("idp %s %s %s %s", id, r.Status, r.DriverRef, r.ClientSecretRef))
	}
	for id, s := range m.invitations {
		parts = append(parts, "invitation "+id.String()+" "+s)
	}
	for c := range m.relays {
		parts = append(parts, "relay "+c)
	}
	parts = append(parts, fmt.Sprintf("tenant %s policies=%d activations=%d audit=%v notes=%v", m.tenant.Status,
		len(m.policy), m.activations, m.audit, m.notification))
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// ---------------------------------------------------------------------------------------------------- placement

type fakePlacer struct {
	m      *memStore
	host   uuid.UUID
	err    error
	allocs int
}

func (p *fakePlacer) Allocate(_ context.Context, req platform.AllocationRequest) (platform.Allocation, error) {
	if p.err != nil {
		return platform.Allocation{}, p.err
	}
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	if i, ok := p.m.instances[req.InstanceID]; ok {
		if i.Status == tenants.InstanceRemoved {
			return platform.Allocation{}, platform.ErrInstanceRemoved
		}
		return platform.Allocation{InstanceID: i.ID, Existing: true, NetCIDR: i.NetCIDR}, nil
	}
	for _, i := range p.m.instances {
		if i.Status != tenants.InstanceRemoved {
			return platform.Allocation{}, platform.ErrTenantHasInstance
		}
	}
	p.allocs++
	p.m.instances[req.InstanceID] = &InstanceRecord{ID: req.InstanceID, TenantID: req.TenantID, HostID: p.host,
		HostName: "host-1", Status: tenants.InstanceAllocated, ImageDigest: req.ImageDigest,
		HeadscaleVersion: req.HeadscaleVersion, ControlHostname: p.m.tenant.Slug + ".mesh.example.test",
		BaseDomain: p.m.tenant.Slug + ".tail.example.test", RunUID: int32(30000 + p.allocs), //nolint:gosec // test
		NetCIDR: netip.MustParsePrefix(fmt.Sprintf("10.250.%d.0/29", p.allocs)), PublicEntryIPv4: netip.MustParseAddr("192.0.2.10")}
	return platform.Allocation{InstanceID: req.InstanceID, HostName: "host-1",
		NetCIDR: p.m.instances[req.InstanceID].NetCIDR, ControlHostname: p.m.instances[req.InstanceID].ControlHostname}, nil
}

func (p *fakePlacer) Release(_ context.Context, _, id uuid.UUID) (bool, error) {
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	i, ok := p.m.instances[id]
	switch {
	case !ok:
		return false, platform.ErrNotFound
	case i.Status == tenants.InstanceRemoved:
		return false, nil
	case i.Status != tenants.InstanceAllocated && i.Status != tenants.InstanceFailed:
		return false, fmt.Errorf("%w: %s", platform.ErrConflict, i.Status)
	}
	i.Status = tenants.InstanceRemoved
	return true, nil
}

// ---------------------------------------------------------------------------------------------------- secrets

type memSecrets struct {
	mu       sync.Mutex
	versions map[string][]byte // ref → value (nil = destroyed)
	deks     int
	err      error
}

func newMemSecrets() *memSecrets { return &memSecrets{versions: map[string][]byte{}} }

func (s *memSecrets) EnsureDEK(context.Context, secrets.Owner) (int32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deks == 0 {
		s.deks = 1
	}
	return 1, s.err
}

func (s *memSecrets) Put(_ context.Context, ref secrets.Ref, v []byte, _ ...secrets.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if _, ok := s.versions[ref.String()]; ok {
		return secrets.ErrExists
	}
	s.versions[ref.String()] = slices.Clone(v)
	return nil
}

func (s *memSecrets) Get(_ context.Context, ref secrets.Ref) (secrets.Plaintext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[ref.String()]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	if v == nil {
		return nil, secrets.ErrDestroyed
	}
	return secrets.Plaintext(slices.Clone(v)), nil
}

func (s *memSecrets) Rotate(_ context.Context, ref secrets.Ref, v []byte, _ ...secrets.Option) (secrets.Ref, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := ref
	next.Version++
	if _, ok := s.versions[next.String()]; ok {
		return secrets.Ref{}, secrets.ErrConflict
	}
	s.versions[next.String()] = slices.Clone(v)
	return next, nil
}

func (s *memSecrets) Destroy(_ context.Context, ref secrets.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[ref.String()]; !ok {
		return secrets.ErrNotFound
	}
	s.versions[ref.String()] = nil
	return nil
}

func (s *memSecrets) Latest(_ context.Context, tenant uuid.UUID, name string) (secrets.Ref, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best secrets.Ref
	for k := range s.versions {
		r, err := secrets.ParseRef(k)
		if err == nil && r.Tenant == tenant && r.Name == name && r.Version > best.Version {
			best = r
		}
	}
	if best.Version == 0 {
		return best, secrets.ErrNotFound
	}
	return best, nil
}

// live are the references that still hold a value.
func (s *memSecrets) live() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k, v := range s.versions {
		if v != nil {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (s *memSecrets) values() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, v := range s.versions {
		b.Write(v)
	}
	return b.String()
}

// ---------------------------------------------------------------------------------------------------- IdP

type fakeIdP struct {
	name     string
	mu       sync.Mutex
	realms   map[string]string // realm → state (enabled/disabled)
	clients  int
	err      error
	removeOK int
}

func (d *fakeIdP) Name() string { return d.name }

func (d *fakeIdP) EnsureIssuer(_ context.Context, spec idp.IssuerSpec) (idp.IssuerResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return idp.IssuerResult{}, d.err
	}
	if d.name == DriverExternal {
		return idp.IssuerResult{Issuer: spec.Issuer}, nil
	}
	_, existed := d.realms[spec.Realm]
	d.realms[spec.Realm] = "enabled"
	return idp.IssuerResult{Issuer: "https://auth.example.test/realms/" + spec.Realm, DriverRef: spec.Realm, Created: !existed}, nil
}

func (d *fakeIdP) EnsureClient(_ context.Context, spec idp.ClientSpec) (idp.ClientResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ref := spec.ClientSecretRef
	created := ref == ""
	if ref == "" && d.name == DriverKeycloak {
		ref = secrets.TenantRef(spec.TenantID, idp.ClientSecretName(spec.IdPID), 1).String()
		d.clients++
	}
	return idp.ClientResult{ClientID: spec.ClientID, ClientSecretRef: ref, Created: created}, nil
}

func (d *fakeIdP) InviteUser(context.Context, idp.Registration, idp.Invite) (idp.InviteResult, error) {
	return idp.InviteResult{}, errors.New("unused")
}

func (d *fakeIdP) DisableUser(context.Context, idp.Registration, string) (idp.DisableResult, error) {
	return idp.DisableResult{}, errors.New("unused")
}

func (d *fakeIdP) RemoveIssuer(_ context.Context, reg idp.Registration, mode idp.RemoveMode) (idp.RemoveResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeOK++
	if _, ok := d.realms[reg.DriverRef]; ok {
		d.realms[reg.DriverRef] = string(mode)
	}
	return idp.RemoveResult{Mode: mode}, nil
}

func (d *fakeIdP) CheckDiscovery(context.Context, idp.Registration) (idp.Discovery, error) {
	return idp.Discovery{}, nil
}

type fakeDrivers map[string]idp.IdPDriver

func (f fakeDrivers) Driver(name string) (idp.IdPDriver, error) {
	if d, ok := f[name]; ok {
		return d, nil
	}
	return nil, idp.NewError(idp.CodeUnknownDriver, "registry", "", nil)
}

// ---------------------------------------------------------------------------------------------------- Headscale

type fakeHS struct {
	headscale.Instance // methods the state machine never calls panic
	policy             string
	noPolicy           bool
	err                error
	healthy            bool
}

func (h *fakeHS) GetPolicy(context.Context) (headscale.Policy, error) {
	if h.err != nil {
		return headscale.Policy{}, h.err
	}
	if h.noPolicy {
		return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy, Err: headscale.ErrNoPolicy}
	}
	return headscale.Policy{Data: h.policy}, nil
}

func (h *fakeHS) Version(context.Context) (string, error) { return "v0.29.7", h.err }

func (h *fakeHS) Health(context.Context) (headscale.Health, error) {
	return headscale.Health{DatabaseConnectivity: h.healthy}, h.err
}

type fakeRegistry struct{ hs *fakeHS }

func (r fakeRegistry) ForTenant(context.Context, uuid.UUID) (headscale.Instance, error) {
	return r.hs, nil
}

// ---------------------------------------------------------------------------------------------------- prober

type fakeProber struct {
	mu        sync.Mutex
	relay     ProbeResult
	edge      ProbeResult
	relayErrs []error
	edgeErrs  []error
	calls     []string
}

func (p *fakeProber) Relay(_ context.Context, r RelayProbe) (ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, "relay "+r.Host+" "+r.STUN)
	if len(p.relayErrs) > 0 {
		e := p.relayErrs[0]
		p.relayErrs = p.relayErrs[1:]
		return ProbeResult{}, e
	}
	return p.relay, nil
}

func (p *fakeProber) Edge(_ context.Context, r EdgeProbe) (ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, "edge "+r.Host+" "+r.PublicKey)
	if len(p.edgeErrs) > 0 {
		e := p.edgeErrs[0]
		p.edgeErrs = p.edgeErrs[1:]
		return ProbeResult{}, e
	}
	return p.edge, nil
}

// ---------------------------------------------------------------------------------------------------- agent

// hostModel is what the fake agent keeps of one instance on the host.
type hostModel struct {
	dir, config, network, container bool
	configSHA                       string
	policy                          bool
	keys                            map[string]bool // prefix → valid
	edge, flag                      bool
	activatedBy                     string
}

type fakeAgent struct {
	mu        sync.Mutex
	host      map[string]*hostModel
	calls     []string
	errs      map[string][]error // method → errors returned by successive calls
	unhealthy bool
	keyN      int
	lastKey   string // the last key handed out (the canary of the leak checks)
	fp        string
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{host: map[string]*hostModel{}, errs: map[string][]error{}, fp: strings.Repeat("ab", 32)}
}

// enter records the call and returns with a.mu held (the caller unlocks).
func (a *fakeAgent) enter(method, id string) (*hostModel, error) {
	a.mu.Lock()
	a.calls = append(a.calls, method)
	if q := a.errs[method]; len(q) > 0 {
		a.errs[method] = q[1:]
		return nil, q[0]
	}
	h := a.host[id]
	if h == nil {
		h = &hostModel{keys: map[string]bool{}}
		a.host[id] = h
	}
	return h, nil
}

func refused(c codes.Code, r agentv1.RefusalReason, msg string) error {
	st, _ := status.New(c, "refused").WithDetails(&agentv1.Refusal{Reason: r, Field: "instance", Message: msg})
	return st.Err()
}

func (a *fakeAgent) ValidateConfig(_ context.Context, in *agentv1.ValidateConfigRequest, _ ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	h, err := a.enter("ValidateConfig", in.GetSpec().GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !h.dir {
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "no instance directory")
	}
	return &agentv1.ValidateConfigResponse{Valid: true, ConfigSha256: strings.Repeat("c", 64)}, nil
}

func (a *fakeAgent) EnsureInstance(_ context.Context, in *agentv1.EnsureInstanceRequest, _ ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	h, err := a.enter("EnsureInstance:"+in.GetTargetPhase().String(), in.GetSpec().GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	resp := &agentv1.EnsureInstanceResponse{TemplateVersion: 1, Status: &agentv1.InstanceStatus{}}
	switch in.GetTargetPhase() {
	case agentv1.TargetPhase_TARGET_PHASE_STORAGE:
		h.dir = true
	case agentv1.TargetPhase_TARGET_PHASE_CONFIG:
		h.config, h.configSHA = true, strings.Repeat("c", 64)
		resp.ConfigSha256 = h.configSHA
	case agentv1.TargetPhase_TARGET_PHASE_NETWORK:
		h.network = true
		resp.Status.Network = &agentv1.NetworkState{Exists: true, Subnet: in.GetSpec().GetNetCidr(), Internal: true}
	case agentv1.TargetPhase_TARGET_PHASE_CONTAINER:
		if !h.network || !h.config {
			return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "network or config missing")
		}
		h.container = true
		resp.Status.ContainerState = agentv1.ContainerState_CONTAINER_STATE_RUNNING
	}
	return resp, nil
}

func (a *fakeAgent) GetInstanceStatus(_ context.Context, in *agentv1.GetInstanceStatusRequest, _ ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	h, err := a.enter("GetInstanceStatus", in.GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	st := &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_ABSENT}
	if h.container {
		st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_RUNNING, agentv1.HealthState_HEALTH_STATE_HEALTHY
		if a.unhealthy {
			st.Health = agentv1.HealthState_HEALTH_STATE_UNHEALTHY
		}
		st.NoiseKeyFingerprint = a.fp
	}
	return &agentv1.GetInstanceStatusResponse{Status: st}, nil
}

func (a *fakeAgent) RemoveInstance(_ context.Context, in *agentv1.RemoveInstanceRequest, _ ...grpc.CallOption) (*agentv1.RemoveInstanceResponse, error) {
	h, err := a.enter("RemoveInstance:"+in.GetData().String(), in.GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if h.edge {
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "edge still attached")
	}
	resp := &agentv1.RemoveInstanceResponse{ContainerRemoved: h.container, NetworkRemoved: h.network}
	h.container, h.network = false, false
	if in.GetData() == agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED {
		if h.activatedBy != "" {
			return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "activated")
		}
		resp.DirectoryRemoved = h.dir
		h.dir, h.config, h.policy, h.keys = false, false, false, map[string]bool{}
	}
	return resp, nil
}

func (a *fakeAgent) BootstrapPolicy(_ context.Context, in *agentv1.BootstrapPolicyRequest, _ ...grpc.CallOption) (*agentv1.BootstrapPolicyResponse, error) {
	h, err := a.enter("BootstrapPolicy", in.GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !h.container {
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "not running")
	}
	h.policy = true
	return &agentv1.BootstrapPolicyResponse{PolicySha256: BaselineSHA256}, nil
}

func (a *fakeAgent) BootstrapApiKey(_ context.Context, in *agentv1.BootstrapApiKeyRequest, _ ...grpc.CallOption) (*agentv1.BootstrapApiKeyResponse, error) { //nolint:revive // generated name
	h, err := a.enter("BootstrapApiKey", in.GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var expired uint32
	for p, valid := range h.keys {
		if valid && p != in.GetKeepPrefix() {
			h.keys[p] = false
			expired++
		}
	}
	exp := timestamppb.New(time.Now().Add(in.GetTtl().AsDuration()))
	if in.GetKeepPrefix() != "" && h.keys[in.GetKeepPrefix()] {
		return &agentv1.BootstrapApiKeyResponse{Prefix: in.GetKeepPrefix(), ExpiresAt: exp, ExpiredKeys: expired}, nil
	}
	a.keyN++
	prefix := fmt.Sprintf("pfx%09d", a.keyN)
	key := "hskey-api-" + prefix + "-" + strings.Repeat("S", 63) + fmt.Sprint(a.keyN%10)
	h.keys[prefix] = true
	a.lastKey = key
	return &agentv1.BootstrapApiKeyResponse{ApiKey: key, Prefix: prefix, ExpiresAt: exp, Created: true, ExpiredKeys: expired}, nil
}

func (a *fakeAgent) EnsureEdgeAttachment(_ context.Context, in *agentv1.EnsureEdgeAttachmentRequest, _ ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	h, err := a.enter("EnsureEdgeAttachment", in.GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !h.policy {
		// the real agent's rule (P3-T03): never attach the edge in the allow-all window (PL-02)
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "no policy yet")
	}
	already := h.edge
	h.edge, h.flag = true, true
	if h.activatedBy == "" {
		h.activatedBy = in.GetJobId()
	}
	return &agentv1.EnsureEdgeAttachmentResponse{Attached: !already, AlreadyAttached: already, NetworkMembers: 2}, nil
}

func (a *fakeAgent) RemoveEdgeAttachment(_ context.Context, in *agentv1.RemoveEdgeAttachmentRequest, _ ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	h, err := a.enter("RemoveEdgeAttachment", in.GetInstance().GetInstanceId())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	was := h.edge
	h.edge, h.flag = false, false
	if in.GetReason() == agentv1.EdgeDetachReason_EDGE_DETACH_REASON_COMPENSATION && h.activatedBy == in.GetJobId() {
		h.activatedBy = ""
	}
	return &agentv1.RemoveEdgeAttachmentResponse{Detached: was, WasAttached: was}, nil
}

func (a *fakeAgent) callList() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.calls)
}

// model is the host state of the only instance (zero model when none).
func (a *fakeAgent) model() hostModel {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, h := range a.host {
		m := *h
		m.keys = map[string]bool{}
		for k, v := range h.keys {
			m.keys[k] = v
		}
		return m
	}
	return hostModel{}
}

func (a *fakeAgent) fail(method string, errs ...error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.errs[method] = append(a.errs[method], errs...)
}

var _ = templates.BootstrapPolicy
