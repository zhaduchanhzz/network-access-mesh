// Package devicestest is a fake Headscale 0.29.7 behind the edge admin listener, for the tests of internal/devices and
// of its HTTP adapter: the real adapter (internal/headscale — version check, error classification, circuit breaker)
// talks to it over HTTP. It keeps nodes and pre-auth keys in memory, answers in the wire format of 0.29.7 — including
// the GetNode/ListNodes difference for tagged nodes (V-28) — and has switches for the failure modes of P2-T13: the
// instance not answering, Headscale refusing a call, a write that is acknowledged but not applied (read-back mismatch).
// It also answers the health checks of the monitoring probe (P2-T13a): GET /version with a settable version and
// GET /api/v1/health with a settable database connectivity. One-shot hooks (Before, After) let a test interleave
// another actor — a revocation job, an operator's CLI — at an exact point of a call, without sleeps.
// Test code only (internal/archtest keeps it out of the binaries).
package devicestest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Node is one node of the fake instance.
type Node struct {
	ID         uint64
	MachineKey string
	NodeKey    string
	Hostname   string
	GivenName  string
	UserID     uint64 // 0 for a node registered with a tag-only key
	UserName   string
	Tags       []string
	IPs        []netip.Addr
	Method     string // authkey, cli, oidc
	Online     bool
	LastSeen   *time.Time
	Expiry     *time.Time
	CreatedAt  time.Time
	PreAuthKey uint64
	Approved   []netip.Prefix
	Available  []netip.Prefix
	Subnet     []netip.Prefix // primary + approved exit routes (ListNodes only — V-28)
}

// Key is one pre-auth key of the fake instance (never the secret).
type Key struct {
	ID         uint64
	UserID     uint64
	UserName   string
	Reusable   bool
	Used       bool
	Expiration time.Time
	Tags       []string
}

// Fake is the fake instance and its admin listener.
type Fake struct {
	Server    *httptest.Server
	Slug      string
	EdgeToken string
	APIKey    string

	mu     sync.Mutex
	nodes  map[uint64]*Node
	keys   map[uint64]*Key
	calls  map[string]int  // "GET /api/v1/node" → count
	down   bool            // every call: 502 without body (the edge cannot route — instance stopped)
	refuse map[string]bool // op → answer 500 {"code":2,"message":"…"} (a refusal the adapter maps to upstream_rejected)
	// ignore makes an acknowledged write a no-op: ExpireNode / DeleteNode / RenameNode answer success, change nothing.
	ignore map[string]bool
	now    func() time.Time
	// version answered by GET /version; noDatabase makes GET /api/v1/health report no database connectivity.
	version    string
	noDatabase bool
	// before/after: one-shot hooks of the next call of an op (Before, After); expiries: the expiry of every ExpireNode
	// call received, per node (ExpireCalls).
	before, after map[string]func(id uint64)
	expiries      map[uint64][]time.Time
	// policyTags: the tags the instance's current policy declares (tagOwners); nil accepts any well-formed tag. SetTags
	// with a tag outside it is refused like 0.29.7 (400 code 3 "requested tags […] are invalid or not permitted").
	policyTags map[string]bool
}

// Operation names used by Refuse, Ignore and Calls.
const (
	OpListNodes        = "ListNodes"
	OpGetNode          = "GetNode"
	OpRenameNode       = "RenameNode"
	OpExpireNode       = "ExpireNode"
	OpSetTags          = "SetTags"
	OpDeleteNode       = "DeleteNode"
	OpListPreAuthKeys  = "ListPreAuthKeys"
	OpExpirePreAuthKey = "ExpirePreAuthKey"
	OpHealth           = "Health"
	OpVersion          = "Version"
)

// New starts a fake instance for slug, closed when the test ends. Its credentials are generated per test.
func New(t testing.TB, slug string) *Fake {
	t.Helper()
	f := &Fake{Slug: slug, EdgeToken: strings.Repeat("E", 20) + strings.ReplaceAll(uuid.NewString(), "-", "")[:20],
		APIKey: "hskey-" + "api-" + "fakeprefix12" + "-" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		nodes:  map[uint64]*Node{}, keys: map[uint64]*Key{}, calls: map[string]int{}, refuse: map[string]bool{},
		ignore: map[string]bool{}, now: time.Now, version: "v0.29.7",
		before: map[string]func(uint64){}, after: map[string]func(uint64){}, expiries: map[uint64][]time.Time{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

// Target is the adapter target of this instance (what the P2-T11 locator returns in production).
func (f *Fake) Target(instanceID uuid.UUID) headscale.Target {
	return headscale.Target{InstanceID: instanceID, Slug: f.Slug, AdminURL: f.Server.URL, APIKey: headscale.NewSecret(f.APIKey),
		EdgeToken: headscale.NewSecret(f.EdgeToken), Timeout: 2 * time.Second}
}

// Registry returns a registry for the given tenant → instance pairs of fakes, without adapter retries (a test decides
// how many calls fail) and with a breaker that never opens during a test.
func Registry(targets map[uuid.UUID]headscale.Target) *headscale.CachingRegistry {
	return headscale.NewRegistry(headscale.StaticLocator(targets), headscale.Options{
		Timeout: 2 * time.Second, CacheTTL: time.Hour, Retry: headscale.RetryPolicy{Attempts: 1},
		Breaker: headscale.BreakerConfig{FailureThreshold: 1 << 20, OpenFor: time.Millisecond},
	})
}

// PutNode adds or replaces a node.
func (f *Fake) PutNode(n Node) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := n
	f.nodes[n.ID] = &c
}

// RemoveNode deletes a node as an operator would with the CLI.
func (f *Fake) RemoveNode(id uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.nodes, id)
}

// Node returns a copy of a node.
func (f *Fake) Node(id uint64) (Node, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok {
		return Node{}, false
	}
	return *n, true
}

// PutKey adds a pre-auth key.
func (f *Fake) PutKey(k Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := k
	f.keys[k.ID] = &c
}

// Key returns a copy of a pre-auth key.
func (f *Fake) Key(id uint64) Key {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.keys[id]
}

// SetDown makes every call fail as when the instance is stopped (the edge answers 502).
func (f *Fake) SetDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// SetPolicyTags sets the tags the instance's policy declares (nil: any).
func (f *Fake) SetPolicyTags(tags ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policyTags = map[string]bool{}
	for _, t := range tags {
		f.policyTags[t] = true
	}
}

// SetVersion sets the version GET /version reports (default v0.29.7).
func (f *Fake) SetVersion(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = v
}

// SetDatabase sets the database connectivity GET /api/v1/health reports (default true).
func (f *Fake) SetDatabase(ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noDatabase = !ok
}

// Refuse makes op answer a refusal (HTTP 500 with a gateway error body).
func (f *Fake) Refuse(op string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse[op] = on
}

// Ignore makes the write op answer success without changing anything.
func (f *Fake) Ignore(op string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ignore[op] = on
}

// Calls returns how many times op was called (failed calls included).
func (f *Fake) Calls(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

// ResetCalls clears the call counters.
func (f *Fake) ResetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = map[string]int{}
}

// Before runs fn once, at the next call of op, before the fake handles it (fn gets the node id of the call, 0 for
// calls without one). The fake is not locked while fn runs: fn may call the instance itself (its own calls of op do
// not run the hook again).
func (f *Fake) Before(op string, fn func(id uint64)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.before[op] = fn
}

// After runs fn once, at the next call of op, after the fake computed its answer and before the answer is sent: the
// caller receives the state as it was before fn — e.g. a ListNodes snapshot that a revocation then makes stale.
func (f *Fake) After(op string, fn func(id uint64)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.after[op] = fn
}

// ExpireCalls returns the expiry of every ExpireNode call the fake handled for node id, in the order it handled them
// (after any Before hook of the call; refused and ignored calls included).
func (f *Fake) ExpireCalls(id uint64) []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.expiries[id])
}

// hook removes and returns the hook of op in hooks.
func (f *Fake) hook(hooks map[string]func(uint64), op string) func(uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn := hooks[op]
	delete(hooks, op)
	return fn
}

func gw(code int, msg string) string {
	b, _ := json.Marshal(map[string]any{"code": code, "message": msg, "details": []any{}})
	return string(b)
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.Header.Get(headscale.HeaderEdgeToken) != f.EdgeToken {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Header.Get(headscale.HeaderInstance) != f.Slug {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	op, id, _ := route(r)
	if fn := f.hook(f.before, op); fn != nil {
		fn(id)
	}
	rec := httptest.NewRecorder()
	f.answer(rec, r, body)
	if fn := f.hook(f.after, op); fn != nil {
		fn(id)
	}
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

// answer handles one call that passed the edge checks, under the fake's lock.
func (f *Fake) answer(w http.ResponseWriter, r *http.Request, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/version" {
		f.calls[OpVersion]++
		if f.down {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"version": f.version, "commit": "c9cf210b8bc84d13177e18b91f555788a44b47b6"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.APIKey {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
		return
	}
	op, id, rest := route(r)
	f.calls[op]++
	if op == OpExpireNode {
		if at, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("expiry")); err == nil {
			f.expiries[id] = append(f.expiries[id], at)
		}
	}
	if f.down {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if f.refuse[op] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(gw(2, "fake headscale refuses "+op)))
		return
	}
	switch op {
	case OpHealth:
		writeJSON(w, map[string]any{"databaseConnectivity": !f.noDatabase})
	case OpListNodes:
		out := make([]any, 0, len(f.nodes))
		ids := make([]uint64, 0, len(f.nodes))
		for nid := range f.nodes {
			ids = append(ids, nid)
		}
		slices.Sort(ids)
		for _, nid := range ids {
			out = append(out, f.nodes[nid].wire(true))
		}
		writeJSON(w, map[string]any{"nodes": out})
	case OpGetNode, OpRenameNode, OpExpireNode:
		n, ok := f.nodes[id]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(gw(5, "node not found")))
			return
		}
		switch {
		case op == OpRenameNode && !f.ignore[op]:
			n.GivenName = rest
		case op == OpExpireNode && !f.ignore[op]:
			at, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("expiry"))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(gw(3, "invalid expiry")))
				return
			}
			n.Expiry = &at
		}
		writeJSON(w, map[string]any{"node": n.wire(false)})
	case OpSetTags:
		n, ok := f.nodes[id]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(gw(5, "node not found")))
			return
		}
		var in struct {
			Tags []string `json:"tags"`
		}
		_ = json.Unmarshal(body, &in)
		var bad []string
		for _, t := range in.Tags {
			if f.policyTags != nil && !f.policyTags[t] {
				bad = append(bad, t)
			}
		}
		if len(bad) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(gw(3, "requested tags ["+strings.Join(bad, " ")+"] are invalid or not permitted")))
			return
		}
		if !f.ignore[op] {
			n.Tags = slices.Clone(in.Tags)
		}
		writeJSON(w, map[string]any{"node": n.wire(false)})
	case OpDeleteNode:
		if _, ok := f.nodes[id]; !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(gw(5, "node not found")))
			return
		}
		if !f.ignore[op] {
			delete(f.nodes, id)
		}
		writeJSON(w, map[string]any{})
	case OpListPreAuthKeys:
		out := make([]any, 0, len(f.keys))
		for _, k := range f.keys {
			out = append(out, k.wire())
		}
		writeJSON(w, map[string]any{"preAuthKeys": out})
	case OpExpirePreAuthKey:
		var in struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &in)
		kid, _ := strconv.ParseUint(in.ID, 10, 64)
		k, ok := f.keys[kid]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(gw(5, "pre auth key not found")))
			return
		}
		k.Expiration = f.now().Add(-time.Second)
		writeJSON(w, map[string]any{})
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(gw(5, "Not Found")))
	}
}

// route names the operation of a request and extracts the node id and the rest of the path.
func route(r *http.Request) (op string, id uint64, rest string) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	switch {
	case r.Method == http.MethodGet && p == "health":
		return OpHealth, 0, ""
	case r.Method == http.MethodGet && p == "node":
		return OpListNodes, 0, ""
	case r.Method == http.MethodGet && p == "preauthkey":
		return OpListPreAuthKeys, 0, ""
	case r.Method == http.MethodPost && p == "preauthkey/expire":
		return OpExpirePreAuthKey, 0, ""
	case strings.HasPrefix(p, "node/"):
		parts := strings.SplitN(strings.TrimPrefix(p, "node/"), "/", 3)
		n, _ := strconv.ParseUint(parts[0], 10, 64)
		switch {
		case r.Method == http.MethodGet && len(parts) == 1:
			return OpGetNode, n, ""
		case r.Method == http.MethodDelete && len(parts) == 1:
			return OpDeleteNode, n, ""
		case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "expire":
			return OpExpireNode, n, ""
		case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "tags":
			return OpSetTags, n, ""
		case r.Method == http.MethodPost && len(parts) == 3 && parts[1] == "rename":
			return OpRenameNode, n, parts[2]
		}
	}
	return "unknown " + r.Method + " " + r.URL.Path, 0, ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func ts(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func strs[T fmt.Stringer](in []T) []string {
	out := make([]string, 0, len(in))
	for _, x := range in {
		out = append(out, x.String())
	}
	return out
}

// wire is the node as 0.29.7 answers it. listView: ListNodes (tagged node owned by "tagged-devices", subnet routes
// filled); otherwise GetNode and the write calls (tagged node: user null, subnet routes empty — V-28).
func (n *Node) wire(listView bool) map[string]any {
	created := n.CreatedAt.UTC().Format(time.RFC3339Nano)
	m := map[string]any{
		"id": strconv.FormatUint(n.ID, 10), "machineKey": n.MachineKey, "nodeKey": n.NodeKey, "discoKey": "discokey:00",
		"ipAddresses": strs(n.IPs), "name": n.Hostname, "givenName": n.GivenName, "lastSeen": ts(n.LastSeen),
		"expiry": ts(n.Expiry), "createdAt": created, "registerMethod": wireMethod(n.Method),
		"online": n.Online, "approvedRoutes": strs(n.Approved), "availableRoutes": strs(n.Available),
		"subnetRoutes": []string{}, "tags": nonNil(n.Tags),
	}
	if n.PreAuthKey != 0 {
		m["preAuthKey"] = map[string]any{"id": strconv.FormatUint(n.PreAuthKey, 10)}
	}
	tagged := len(n.Tags) > 0
	switch {
	case tagged && listView:
		m["user"] = map[string]any{"id": "0", "name": headscale.TaggedDevicesUser}
		m["subnetRoutes"] = strs(n.Subnet)
	case tagged:
		m["user"] = nil
	default:
		m["user"] = map[string]any{"id": strconv.FormatUint(n.UserID, 10), "name": n.UserName, "createdAt": created}
		if listView {
			m["subnetRoutes"] = strs(n.Subnet)
		}
	}
	return m
}

func (k *Key) wire() map[string]any {
	m := map[string]any{"id": strconv.FormatUint(k.ID, 10), "key": "hskey-" + "auth-" + "abcdefghijkl" + "-***",
		"reusable": k.Reusable, "ephemeral": false, "used": k.Used, "expiration": k.Expiration.UTC().Format(time.RFC3339Nano),
		"createdAt": k.Expiration.Add(-time.Hour).UTC().Format(time.RFC3339Nano), "aclTags": nonNil(k.Tags)}
	if k.UserID != 0 {
		m["user"] = map[string]any{"id": strconv.FormatUint(k.UserID, 10), "name": k.UserName}
	}
	return m
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func wireMethod(m string) string {
	switch m {
	case "authkey":
		return "REGISTER_METHOD_AUTH_KEY"
	case "cli":
		return "REGISTER_METHOD_CLI"
	case "oidc":
		return "REGISTER_METHOD_OIDC"
	}
	return "REGISTER_METHOD_UNSPECIFIED"
}
