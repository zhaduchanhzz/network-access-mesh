// Package headscaletest is a fake edge admin listener (§14.6) in front of fake Headscale instances — one per slug, each
// with its own API keys — for the tests of the packages built on internal/headscale (headscale/locator,
// provisioning, apps/api). Only test code imports it. The real edge block and Headscale 0.29.7 are exercised by
// tests/integration/headscale (P2-T10) and tests/integration/adopt (P2-T11).
//
// Behaviour copied from the observations of P2-T10: a wrong X-MG-Token ⇒ bare 403; an unknown X-MG-Instance ⇒ bare
// 404; GET /version needs no API key; /api/v1/* needs a valid Bearer key of THAT instance, else 401 "Unauthorized"
// (text); a key with an expiration in the past is refused, a key without expiration never expires
// (hscontrol/db/api_key.go); list answers the display prefix "hskey-api-<prefix>-***"; expiring an unknown prefix ⇒
// 500 code 2 "record not found". Requests are recorded without credentials: only the public prefix of the key used.
package headscaletest

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const urlSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// randomString returns n characters of the URL-safe base64 alphabet (as Headscale's GenerateRandomStringURLSafe).
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = urlSafe[int(b[i])%len(urlSafe)]
	}
	return string(b)
}

// NewToken returns a random edge admin token (40 characters [A-Za-z0-9], §14.6).
func NewToken() string {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 40)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alnum[int(b[i])%len(alnum)]
	}
	return string(b)
}

// Key is the state of one API key of a fake instance (the full key is returned once, by NewKey).
type Key struct {
	ID         uint64
	Prefix     string
	Expiration *time.Time // nil: never expires
	CreatedAt  time.Time
	secret     string
}

// Valid follows Headscale: no expiration ⇒ valid; expiration in the past ⇒ refused.
func (k Key) Valid(now time.Time) bool { return k.Expiration == nil || k.Expiration.After(now) }

// Instance is one fake Headscale behind the edge.
type Instance struct {
	edge    *Edge
	Slug    string
	Version string
	keys    []*Key
	nextID  uint64
}

// Request is a recorded request (no credential: AuthPrefix is the public prefix of the Bearer key, if any).
type Request struct {
	Slug       string
	Method     string
	Path       string
	TokenOK    bool
	AuthPrefix string
}

// Edge is the fake admin listener.
type Edge struct {
	Server *httptest.Server
	Now    func() time.Time

	mu        sync.Mutex
	token     string
	instances map[string]*Instance
	requests  []Request
	failPfx   map[string]bool                            // ExpireApiKey of these prefixes answers 500 (storage error)
	hook      func(r Request, n int) (int, string, bool) // n = number of earlier requests with the same method+path
}

// NewEdge starts a fake edge with the given admin token; it is closed at the end of the test.
func NewEdge(t testing.TB, token string) *Edge {
	t.Helper()
	e := &Edge{Now: time.Now, token: token, instances: map[string]*Instance{}, failPfx: map[string]bool{}}
	e.Server = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.Server.Close)
	return e
}

// URL is the base URL of the listener (http://127.0.0.1:port).
func (e *Edge) URL() string { return e.Server.URL }

// SetToken replaces the admin token (rotation).
func (e *Edge) SetToken(tok string) { e.mu.Lock(); e.token = tok; e.mu.Unlock() }

// AddInstance adds an instance reachable as X-MG-Instance: slug, reporting version v0.29.7.
func (e *Edge) AddInstance(slug string) *Instance {
	e.mu.Lock()
	defer e.mu.Unlock()
	i := &Instance{edge: e, Slug: slug, Version: "v0.29.7"}
	e.instances[slug] = i
	return i
}

// FailExpire makes ExpireApiKey of prefix answer 500 "database is locked".
func (e *Edge) FailExpire(prefix string) { e.mu.Lock(); e.failPfx[prefix] = true; e.mu.Unlock() }

// HealExpire ends every FailExpire.
func (e *Edge) HealExpire() { e.mu.Lock(); e.failPfx = map[string]bool{}; e.mu.Unlock() }

// SetHook installs a function consulted before routing (after the edge checks); ok = answer status/body instead.
func (e *Edge) SetHook(h func(r Request, n int) (status int, body string, ok bool)) {
	e.mu.Lock()
	e.hook = h
	e.mu.Unlock()
}

// Requests returns the recorded requests.
func (e *Edge) Requests() []Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Request(nil), e.requests...)
}

// NewKey creates an API key like `headscale apikeys create -e <ttl>` (ttl ≤ 0: no expiration — a pre-0.28 style key
// that never expires) and returns the full key (shown once) and its prefix.
func (i *Instance) NewKey(ttl time.Duration) (full, prefix string) {
	i.edge.mu.Lock()
	defer i.edge.mu.Unlock()
	return i.newKeyLocked(ttl)
}

func (i *Instance) newKeyLocked(ttl time.Duration) (string, string) {
	i.nextID++
	k := &Key{ID: i.nextID, Prefix: randomString(12), CreatedAt: i.edge.Now().UTC(), secret: randomString(64)}
	if ttl > 0 {
		exp := i.edge.Now().Add(ttl).UTC()
		k.Expiration = &exp
	}
	i.keys = append(i.keys, k)
	return "hskey-" + "api-" + k.Prefix + "-" + k.secret, k.Prefix
}

// Keys returns a copy of the key states.
func (i *Instance) Keys() []Key {
	i.edge.mu.Lock()
	defer i.edge.mu.Unlock()
	out := make([]Key, 0, len(i.keys))
	for _, k := range i.keys {
		c := *k
		c.secret = ""
		out = append(out, c)
	}
	return out
}

// ValidPrefixes returns the prefixes of the keys valid now.
func (i *Instance) ValidPrefixes() []string {
	now := i.edge.Now()
	var out []string
	for _, k := range i.Keys() {
		if k.Valid(now) {
			out = append(out, k.Prefix)
		}
	}
	return out
}

// authKey returns the key matching a Bearer value of this instance (nil if none — wrong instance or wrong secret).
func (i *Instance) authKey(bearer string) *Key {
	rest, ok := strings.CutPrefix(bearer, "hskey-"+"api-")
	if !ok || len(rest) != 12+1+64 || rest[12] != '-' {
		return nil
	}
	for _, k := range i.keys {
		if k.Prefix == rest[:12] && k.secret == rest[13:] {
			return k
		}
	}
	return nil
}

func prefixOf(bearer string) string {
	rest, ok := strings.CutPrefix(bearer, "hskey-"+"api-")
	if !ok || len(rest) < 12 {
		return ""
	}
	return rest[:12]
}

func (e *Edge) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	e.mu.Lock()
	defer e.mu.Unlock()
	rec := Request{Slug: r.Header.Get("X-MG-Instance"), Method: r.Method, Path: r.URL.Path,
		TokenOK: r.Header.Get("X-MG-Token") == e.token, AuthPrefix: prefixOf(bearer)}
	n := 0
	for _, p := range e.requests {
		if p.Method == rec.Method && p.Path == rec.Path {
			n++
		}
	}
	e.requests = append(e.requests, rec)
	if !rec.TokenOK {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	inst := e.instances[rec.Slug]
	if inst == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if e.hook != nil {
		if status, b, ok := e.hook(rec, n); ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, b)
			return
		}
	}
	if r.Method == http.MethodGet && r.URL.Path == "/version" {
		writeJSON(w, http.StatusOK, map[string]string{"version": inst.Version, "commit": strings.Repeat("c", 40)})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	now := e.Now()
	k := inst.authKey(bearer)
	if k == nil || !k.Valid(now) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "Unauthorized")
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/apikey":
		type wire struct {
			ID         string     `json:"id"`
			Prefix     string     `json:"prefix"`
			Expiration *time.Time `json:"expiration,omitempty"`
			CreatedAt  time.Time  `json:"createdAt"`
		}
		out := struct {
			APIKeys []wire `json:"apiKeys"`
		}{APIKeys: []wire{}}
		for _, k := range inst.keys {
			out.APIKeys = append(out.APIKeys, wire{ID: strconv.FormatUint(k.ID, 10),
				Prefix: "hskey-" + "api-" + k.Prefix + "-***", Expiration: k.Expiration, CreatedAt: k.CreatedAt})
		}
		writeJSON(w, http.StatusOK, out)
	case "POST /api/v1/apikey":
		var in struct {
			Expiration time.Time `json:"expiration"`
		}
		_ = json.Unmarshal(body, &in)
		full, _ := inst.newKeyLocked(in.Expiration.Sub(now))
		writeJSON(w, http.StatusOK, map[string]string{"apiKey": full})
	case "POST /api/v1/apikey/expire":
		var in struct {
			Prefix string `json:"prefix"`
		}
		_ = json.Unmarshal(body, &in)
		if e.failPfx[in.Prefix] {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 2, "message": "database is locked"})
			return
		}
		for _, k := range inst.keys {
			if k.Prefix == in.Prefix {
				t := now.UTC()
				k.Expiration = &t
				writeJSON(w, http.StatusOK, map[string]any{})
				return
			}
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 2, "message": "record not found"})
	case "GET /api/v1/health":
		writeJSON(w, http.StatusOK, map[string]bool{"databaseConnectivity": true})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 5, "message": "Not Found"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
