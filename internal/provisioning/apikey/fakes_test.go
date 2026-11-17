package apikey

// Fakes of the unit tests: the database side (fakeBackend), the SecretStore, the locator, the Host Agent, the security
// recorder, and a proxy in front of the fake edge admin listener of internal/headscale/headscaletest that can refuse,
// lose the answer of, or pause a request — the failure steps of a rotation. The proxy also records every API key that
// Headscale handed out (from the answers of CreateApiKey), so a test can assert that none of them ever reaches a log,
// an error, an audit or security event, or a job output.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

const day = 24 * time.Hour

// ---------------------------------------------------------------------------------------------------- backend

type auditRec struct {
	Action  string
	Details string // JSON
}

type fakeBackend struct {
	mu      sync.Mutex
	sem     chan struct{}
	st      instanceState
	missing bool
	audits  []auditRec

	swapErr   error // returned by swap
	swapApply bool  // apply the change before returning swapErr (a commit whose answer was lost)
	refErr    error // currentRef fails
	locked    int   // lock acquisitions
	jobs      []string
}

func newFakeBackend(st instanceState) *fakeBackend {
	return &fakeBackend{sem: make(chan struct{}, 1), st: st}
}

func (b *fakeBackend) snapshot() instanceState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st
}

func (b *fakeBackend) set(fn func(*instanceState)) {
	b.mu.Lock()
	fn(&b.st)
	b.mu.Unlock()
}

func (b *fakeBackend) actions() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, a := range b.audits {
		out = append(out, a.Action)
	}
	return out
}

func (b *fakeBackend) lock(ctx context.Context, _ uuid.UUID, wait time.Duration, fn func(context.Context) error) error {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case b.sem <- struct{}{}:
	case <-t.C:
		return store.ErrLockTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-b.sem }()
	b.mu.Lock()
	b.locked++
	b.mu.Unlock()
	return fn(ctx)
}

func (b *fakeBackend) load(_ context.Context, tenantID, instanceID uuid.UUID) (instanceState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.missing || b.st.TenantID != tenantID || b.st.InstanceID != instanceID {
		return instanceState{}, errNotFound
	}
	return b.st, nil
}

func (b *fakeBackend) record(action string, d audit.Details) {
	raw, _ := json.Marshal(d)
	b.mu.Lock()
	b.audits = append(b.audits, auditRec{Action: action, Details: string(raw)})
	b.mu.Unlock()
}

func (b *fakeBackend) requested(_ context.Context, ev audit.Event) (audit.Operation, error) {
	b.record(ev.Action+audit.SuffixRequested, ev.Details)
	return audit.Operation{ID: uuid.New(), Action: ev.Action, ActorType: ev.ActorType, ResourceType: ev.ResourceType,
		ResourceID: ev.ResourceID}, nil
}

func (b *fakeBackend) swap(_ context.Context, sw swapSpec, op audit.Operation, d audit.Details) error {
	b.mu.Lock()
	if b.swapErr != nil && !b.swapApply {
		err := b.swapErr
		b.mu.Unlock()
		return err
	}
	if b.st.Ref != sw.OldRef {
		b.mu.Unlock()
		return errSwapConflict
	}
	exp := sw.NewExpiresAt
	b.st.Ref, b.st.Prefix, b.st.ExpiresAt = sw.NewRef, sw.NewPrefix, &exp
	err := b.swapErr
	b.mu.Unlock()
	b.record(op.Action+audit.SuffixSucceeded, d)
	return err
}

func (b *fakeBackend) currentRef(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refErr != nil {
		return "", b.refErr
	}
	return b.st.Ref, nil
}

func (b *fakeBackend) failed(_ context.Context, op audit.Operation, reason string, d audit.Details) error {
	d["reason"] = reason
	b.record(op.Action+audit.SuffixFailed, d)
	return nil
}

func (b *fakeBackend) expiries(context.Context) ([]expiry, error) {
	st := b.snapshot()
	return []expiry{{TenantID: st.TenantID, InstanceID: st.InstanceID, Prefix: st.Prefix, ExpiresAt: st.ExpiresAt}}, nil
}

func (b *fakeBackend) enqueue(_ context.Context, _, instanceID uuid.UUID, slot int64, in Input) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := fmt.Sprintf("instance:%s:apikey:%d", instanceID, slot)
	if slices.Contains(b.jobs, key) {
		return false, nil
	}
	b.jobs = append(b.jobs, key)
	_ = in
	return true, nil
}

// ---------------------------------------------------------------------------------------------------- SecretStore

type fakeSecrets struct {
	mu        sync.Mutex
	vals      map[string][]byte // ref → value; nil after Destroy
	putErr    error
	rotateErr error
}

func newFakeSecrets() *fakeSecrets { return &fakeSecrets{vals: map[string][]byte{}} }

func (f *fakeSecrets) Put(_ context.Context, ref secrets.Ref, value []byte, _ ...secrets.Option) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	if _, ok := f.vals[ref.String()]; ok {
		return secrets.ErrExists
	}
	f.vals[ref.String()] = bytes.Clone(value)
	return nil
}

func (f *fakeSecrets) latestLocked(tenant uuid.UUID, name string) (secrets.Ref, bool) {
	var best secrets.Ref
	for raw := range f.vals {
		r, err := secrets.ParseRef(raw)
		if err == nil && r.Tenant == tenant && r.Name == name && r.Version > best.Version {
			best = r
		}
	}
	return best, best.Version > 0
}

func (f *fakeSecrets) Rotate(_ context.Context, ref secrets.Ref, value []byte, _ ...secrets.Option) (secrets.Ref, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rotateErr != nil {
		return secrets.Ref{}, f.rotateErr
	}
	latest, ok := f.latestLocked(ref.Tenant, ref.Name)
	if !ok || latest.Version != ref.Version {
		return secrets.Ref{}, secrets.ErrConflict
	}
	next := ref
	next.Version++
	f.vals[next.String()] = bytes.Clone(value)
	return next, nil
}

func (f *fakeSecrets) Destroy(_ context.Context, ref secrets.Ref) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vals[ref.String()]
	if !ok {
		return secrets.ErrNotFound
	}
	clear(v)
	f.vals[ref.String()] = nil
	return nil
}

func (f *fakeSecrets) Latest(_ context.Context, tenant uuid.UUID, name string) (secrets.Ref, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.latestLocked(tenant, name)
	if !ok {
		return secrets.Ref{}, secrets.ErrNotFound
	}
	return r, nil
}

func (f *fakeSecrets) get(raw string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vals[raw]
	switch {
	case !ok:
		return "", fmt.Errorf("secrets: get %s: %w", raw, secrets.ErrNotFound)
	case v == nil:
		return "", fmt.Errorf("secrets: get %s: %w", raw, secrets.ErrDestroyed)
	}
	return string(v), nil
}

// ---------------------------------------------------------------------------------------------------- locator

// fakeLocator resolves the tenant like the production locator: the reference of the backend's row, the value from the
// SecretStore, the edge URL and token of the configuration.
type fakeLocator struct {
	b     *fakeBackend
	sec   *fakeSecrets
	url   string
	token string
}

func (l *fakeLocator) Locate(_ context.Context, tenantID uuid.UUID) (headscale.Target, error) {
	st := l.b.snapshot()
	if st.TenantID != tenantID || st.Ref == "" {
		return headscale.Target{}, fmt.Errorf("tenant %s: %w", tenantID, headscale.ErrNoInstance)
	}
	v, err := l.sec.get(st.Ref)
	if err != nil {
		return headscale.Target{}, fmt.Errorf("instance %s: API key: %w", st.InstanceID, err)
	}
	return headscale.Target{InstanceID: st.InstanceID, Slug: st.Slug, AdminURL: l.url, APIKey: headscale.NewSecret(v),
		EdgeToken: headscale.NewSecret(l.token)}, nil
}

func (l *fakeLocator) Candidate(instanceID uuid.UUID, slug string, key headscale.Secret) (headscale.Target, error) {
	return headscale.Target{InstanceID: instanceID, Slug: slug, AdminURL: l.url, APIKey: key,
		EdgeToken: headscale.NewSecret(l.token)}, nil
}

// ---------------------------------------------------------------------------------------------------- agent

// fakeAgent is BootstrapApiKey of the compose driver against the fake instance: a new key created "with the CLI"
// (directly on the instance), every other valid key expired, the expiration read back.
type fakeAgent struct {
	mu       sync.Mutex
	inst     *headscaletest.Instance
	edgeURL  string
	token    string
	err      error
	unusable bool // answer created=true with a key of the wrong shape
	calls    []*agentv1.BootstrapApiKeyRequest
	issued   []string
}

func (a *fakeAgent) BootstrapApiKey(ctx context.Context, in *agentv1.BootstrapApiKeyRequest, _ ...grpc.CallOption) (*agentv1.BootstrapApiKeyResponse, error) {
	a.mu.Lock()
	a.calls = append(a.calls, in)
	err := a.err
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	full, prefix := a.inst.NewKey(in.GetTtl().AsDuration())
	a.mu.Lock()
	a.issued = append(a.issued, full)
	a.mu.Unlock()
	tid, _ := uuid.Parse(in.GetInstance().GetTenantId())
	iid, _ := uuid.Parse(in.GetInstance().GetInstanceId())
	reg := headscale.NewRegistry(headscale.StaticLocator{tid: {InstanceID: iid, Slug: in.GetInstance().GetSlug(),
		AdminURL: a.edgeURL, APIKey: headscale.NewSecret(full), EdgeToken: headscale.NewSecret(a.token)}},
		headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1}})
	inst, err := reg.ForTenant(ctx, tid)
	if err != nil {
		return nil, status.Error(codes.Internal, "fake agent: "+err.Error())
	}
	keys, err := inst.ListAPIKeys(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "fake agent: "+err.Error())
	}
	var expired uint32
	var exp time.Time
	for _, k := range keys {
		if k.Prefix == prefix {
			exp = k.Expiration
			continue
		}
		if valid(k, time.Now()) {
			if err := inst.ExpireAPIKey(ctx, k.Prefix); err != nil {
				return nil, status.Error(codes.Internal, "fake agent: "+err.Error())
			}
			expired++
		}
	}
	if a.unusable {
		full = "hskey-api-" + prefix + "-short"
	}
	return &agentv1.BootstrapApiKeyResponse{ApiKey: full, Prefix: prefix, ExpiresAt: timestamppb.New(exp), Created: true,
		ExpiredKeys: expired}, nil
}

// ---------------------------------------------------------------------------------------------------- security, registry

type fakeSecurity struct {
	mu     sync.Mutex
	events []audit.SecurityEvent
	seen   map[string]bool
	err    error
}

func (f *fakeSecurity) RecordSecurityEvent(_ context.Context, ev audit.SecurityEvent) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	if f.seen[ev.DedupeKey] {
		return false, nil
	}
	f.seen[ev.DedupeKey] = true
	f.events = append(f.events, ev)
	return true, nil
}

// prefixes returns the prefixes named by the events of a kind.
func (f *fakeSecurity) prefixes(kind string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, ev := range f.events {
		if ev.Kind == kind {
			out = append(out, fmt.Sprint(ev.Details["prefix"]))
		}
	}
	return out
}

func (f *fakeSecurity) dump() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(f.events)
	return string(b)
}

type recInvalidator struct {
	mu    sync.Mutex
	calls []uuid.UUID
}

func (r *recInvalidator) Invalidate(t uuid.UUID) {
	r.mu.Lock()
	r.calls = append(r.calls, t)
	r.mu.Unlock()
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ---------------------------------------------------------------------------------------------------- proxy

// rule changes what the proxy does with matching requests.
type rule struct {
	method, path string
	bearer       string // only requests whose Bearer prefix is this; "!x" = any prefix but x; "" = any
	action       string // "fail": answer status/body; "lose": forward, then answer a bare 504; "pause": wait, then forward; "rewrite": forward body instead
	status       int
	body         string
	times        int           // matching requests affected (0 = all)
	after        int           // the first `after` matching requests pass untouched
	reached      chan struct{} // pause: closed when the first request arrives
	release      chan struct{} // pause: the request goes on when this is closed
	hits         int
}

type proxyReq struct {
	Method, Path, Bearer string
}

// proxy stands between the adapter and the fake edge.
type proxy struct {
	target string
	srv    *httptest.Server

	mu     sync.Mutex
	rules  []*rule
	issued []string
	reqs   []proxyReq
}

func newProxy(t *testing.T, target string) *proxy {
	p := &proxy{target: target}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *proxy) add(r *rule) *rule {
	if r.action == "pause" {
		r.reached, r.release = make(chan struct{}), make(chan struct{})
	}
	p.mu.Lock()
	p.rules = append(p.rules, r)
	p.mu.Unlock()
	return r
}

func (p *proxy) reset() {
	p.mu.Lock()
	p.rules = nil
	p.mu.Unlock()
}

func bearerPrefix(h string) string {
	rest, ok := strings.CutPrefix(h, "Bearer hskey-api-")
	if !ok || len(rest) < 12 {
		return ""
	}
	return rest[:12]
}

func (p *proxy) match(method, path, bearer string) *rule {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.rules {
		if r.method != method || r.path != path {
			continue
		}
		switch {
		case strings.HasPrefix(r.bearer, "!") && bearer == r.bearer[1:]:
			continue
		case r.bearer != "" && !strings.HasPrefix(r.bearer, "!") && bearer != r.bearer:
			continue
		case r.times > 0 && r.hits >= r.after+r.times:
			continue
		}
		r.hits++
		if r.hits <= r.after {
			return nil
		}
		return r
	}
	return nil
}

func (p *proxy) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	bearer := bearerPrefix(r.Header.Get("Authorization"))
	p.mu.Lock()
	p.reqs = append(p.reqs, proxyReq{Method: r.Method, Path: r.URL.Path, Bearer: bearer})
	p.mu.Unlock()
	ru := p.match(r.Method, r.URL.Path, bearer)
	if ru != nil && ru.action == "fail" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ru.status)
		_, _ = io.WriteString(w, ru.body)
		return
	}
	if ru != nil && ru.action == "pause" {
		select {
		case <-ru.reached:
		default:
			close(ru.reached)
		}
		<-ru.release
	}
	if ru != nil && ru.action == "rewrite" { // Headscale "records" another request body than the one sent
		body = []byte(ru.body)
	}
	req, _ := http.NewRequestWithContext(r.Context(), r.Method, p.target+r.URL.RequestURI(), bytes.NewReader(body)) //nolint:gosec // G704: the fake edge of this test
	req.Header = r.Header.Clone()
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: the fake edge of this test
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/apikey" && resp.StatusCode == http.StatusOK {
		var k struct {
			APIKey string `json:"apiKey"`
		}
		if json.Unmarshal(out, &k) == nil && k.APIKey != "" {
			p.mu.Lock()
			p.issued = append(p.issued, k.APIKey)
			p.mu.Unlock()
		}
	}
	if ru != nil && ru.action == "lose" {
		w.WriteHeader(http.StatusGatewayTimeout)
		return
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

func (p *proxy) keys() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.issued)
}

func (p *proxy) requests() []proxyReq {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reqs)
}

// ---------------------------------------------------------------------------------------------------- fixture

type fixture struct {
	t        *testing.T
	edge     *headscaletest.Edge
	inst     *headscaletest.Instance
	px       *proxy
	be       *fakeBackend
	sec      *fakeSecrets
	loc      *fakeLocator
	agent    *fakeAgent
	secev    *fakeSecurity
	inv      *recInvalidator
	logs     *syncBuffer
	prom     *prometheus.Registry
	svc      *Service
	tenant   uuid.UUID
	instance uuid.UUID
	token    string
	k0, p0   string // the current key at the start, and its prefix
	errs     []string
	results  []string
}

// newFixture: one running instance of an active tenant, its current key K0 created with ttl (≤ 0: no expiration), stored
// as version 1 and recorded with the expiry Headscale holds.
func newFixture(t *testing.T, ttl time.Duration, withAgent bool) *fixture {
	t.Helper()
	f := &fixture{t: t, tenant: uuid.New(), instance: uuid.New(), token: headscaletest.NewToken(), logs: &syncBuffer{},
		secev: &fakeSecurity{}, inv: &recInvalidator{}, sec: newFakeSecrets(), prom: prometheus.NewRegistry()}
	f.edge = headscaletest.NewEdge(t, f.token)
	f.inst = f.edge.AddInstance("tenant-a")
	f.px = newProxy(t, f.edge.URL())
	f.k0, f.p0 = f.inst.NewKey(ttl)
	ref := secrets.TenantRef(f.tenant, SecretName, 1)
	if err := f.sec.Put(context.Background(), ref, []byte(f.k0)); err != nil {
		t.Fatal(err)
	}
	var exp *time.Time
	for _, k := range f.inst.Keys() {
		if k.Prefix == f.p0 && k.Expiration != nil {
			e := k.Expiration.UTC()
			exp = &e
		}
	}
	f.be = newFakeBackend(instanceState{TenantID: f.tenant, InstanceID: f.instance, Slug: "tenant-a", TenantStatus: "active",
		Status: "running", Ref: ref.String(), Prefix: f.p0, ExpiresAt: exp})
	f.loc = &fakeLocator{b: f.be, sec: f.sec, url: f.px.srv.URL, token: f.token}
	cfg := f.config()
	if withAgent {
		f.agent = &fakeAgent{inst: f.inst, edgeURL: f.edge.URL(), token: f.token}
		cfg.Agent = f.agent
	}
	svc, err := newService(f.be, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

func (f *fixture) config() Config {
	log := logx.New(f.logs, slog.LevelDebug, "apikey-test")
	return Config{Locator: f.loc, Secrets: f.sec, Security: f.secev, Invalidate: []Invalidator{f.inv},
		Headscale: headscale.Options{Logger: log, Retry: headscale.RetryPolicy{Attempts: 1}, Timeout: 5 * time.Second},
		Logger:    log, Registerer: f.prom, LockWait: 2 * time.Second}
}

// rotate runs one rotation and keeps its error and result for the secret check.
func (f *fixture) rotate(req Request) (Result, error) {
	f.t.Helper()
	if req.TenantID == uuid.Nil {
		req.TenantID, req.InstanceID = f.tenant, f.instance
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := f.svc.Rotate(ctx, req)
	if err != nil {
		f.errs = append(f.errs, err.Error())
	}
	b, _ := json.Marshal(res)
	f.results = append(f.results, string(b))
	return res, err
}

// valid returns the prefixes of the instance's valid keys, sorted.
func (f *fixture) valid() []string {
	p := f.inst.ValidPrefixes()
	slices.Sort(p)
	return p
}

// working asserts the invariant "a working key": the key the registry records reaches the instance.
func (f *fixture) working() {
	f.t.Helper()
	reg := headscale.NewRegistry(f.loc, headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1}})
	inst, err := reg.ForTenant(context.Background(), f.tenant)
	if err == nil {
		_, err = inst.ListAPIKeys(context.Background())
	}
	if err != nil {
		f.t.Fatalf("the recorded key does not work: %v", err)
	}
}

// noOrphans asserts "no orphan valid key, or a security event naming it": every valid key but the recorded one is
// named by apikey.leftover.
func (f *fixture) noOrphans() {
	f.t.Helper()
	cur := f.be.snapshot().Prefix
	left := f.secev.prefixes(EventLeftover)
	for _, p := range f.valid() {
		if p != cur && !slices.Contains(left, p) {
			f.t.Fatalf("valid key %s is neither the recorded key %s nor reported (leftover events: %v)", p, cur, left)
		}
	}
}

// noSecret asserts that no key ever handed out — K0, every key CreateApiKey answered, every key of the agent — and no
// "hskey-" text appears in the logs, errors, results, audit details or security events.
func (f *fixture) noSecret() {
	f.t.Helper()
	keys := append([]string{f.k0}, f.px.keys()...)
	if f.agent != nil {
		f.agent.mu.Lock()
		keys = append(keys, f.agent.issued...)
		f.agent.mu.Unlock()
	}
	var audits []string
	f.be.mu.Lock()
	for _, a := range f.be.audits {
		audits = append(audits, a.Details)
	}
	f.be.mu.Unlock()
	texts := map[string]string{"logs": f.logs.String(), "errors": strings.Join(f.errs, "\n"),
		"results": strings.Join(f.results, "\n"), "audit": strings.Join(audits, "\n"), "security": f.secev.dump()}
	for name, text := range texts {
		for _, k := range keys {
			if k != "" && strings.Contains(text, k) {
				f.t.Fatalf("a key appears in %s", name)
			}
			if len(k) > 30 && strings.Contains(text, k[23:]) {
				f.t.Fatalf("the secret part of a key appears in %s", name)
			}
		}
		if strings.Contains(text, "hskey-") {
			f.t.Fatalf("%s holds hskey- text: %s", name, text)
		}
	}
}

// refused reports whether the instance refuses a key (401 through the edge).
func (f *fixture) refused(key string) bool {
	f.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, f.edge.URL()+"/api/v1/apikey", nil)
	req.Header.Set(headscale.HeaderEdgeToken, f.token)
	req.Header.Set(headscale.HeaderInstance, "tenant-a")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusUnauthorized
}

// codeOf is the jobs.Error code of err ("" when err is nil or not a jobs.Error) and whether it is permanent.
func codeOf(err error) (string, bool) {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je.Code, je.Permanent
	}
	return "", false
}
