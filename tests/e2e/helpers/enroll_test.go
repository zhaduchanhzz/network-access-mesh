//go:build mgtestfixture

package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// fakeInstance is the part of a Headscale instance the helper uses, in memory. Any other method of the interface
// panics (nil embedded interface): the helper must not call it.
type fakeInstance struct {
	headscale.Instance

	mu       sync.Mutex
	calls    []string
	users    []headscale.User
	keys     []headscale.PreAuthKey
	nodes    []headscale.Node
	nextID   uint64
	opts     []headscale.PreAuthKeyOpts
	raceUser bool  // CreateUser: another writer created the user first ⇒ conflict
	lie      bool  // ListPreAuthKeys reports the key reusable (read-back must catch it)
	keyErr   error // CreatePreAuthKey stores the key, then fails (outcome unknown)
}

func (f *fakeInstance) call(s string) { f.calls = append(f.calls, s) }

func (f *fakeInstance) ListUsers(_ context.Context, flt headscale.UserFilter) ([]headscale.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ListUsers")
	var out []headscale.User
	for _, u := range f.users {
		if flt.Name == "" || u.Name == flt.Name {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *fakeInstance) CreateUser(_ context.Context, u headscale.CreateUser) (headscale.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("CreateUser")
	f.nextID++
	nu := headscale.User{ID: f.nextID, Name: u.Name, DisplayName: u.DisplayName}
	f.users = append(f.users, nu)
	if f.raceUser {
		return headscale.User{}, &headscale.Error{Op: headscale.OpCreateUser, Kind: headscale.KindConflict, Code: -1}
	}
	return nu, nil
}

func (f *fakeInstance) DeleteUser(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("DeleteUser")
	for _, n := range f.nodes {
		if n.User != nil && n.User.ID == id {
			return &headscale.Error{Op: headscale.OpDeleteUser, Kind: headscale.KindConflict, Code: -1}
		}
	}
	f.users = slices.DeleteFunc(f.users, func(u headscale.User) bool { return u.ID == id })
	return nil
}

func (f *fakeInstance) ListNodes(_ context.Context, user string) ([]headscale.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ListNodes")
	var out []headscale.Node
	for _, n := range f.nodes {
		if user == "" || (n.User != nil && n.User.Name == user) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (f *fakeInstance) DeleteNode(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("DeleteNode")
	f.nodes = slices.DeleteFunc(f.nodes, func(n headscale.Node) bool { return n.ID == id })
	return nil
}

func (f *fakeInstance) CreatePreAuthKey(_ context.Context, o headscale.PreAuthKeyOpts) (headscale.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("CreatePreAuthKey")
	f.opts = append(f.opts, o)
	f.nextID++
	var owner *headscale.User
	for i := range f.users {
		if f.users[i].ID == o.User {
			owner = &f.users[i]
		}
	}
	prefix := fmt.Sprintf("pfx%09d", f.nextID)
	secret := strings.Join([]string{"hskey", "auth", prefix, "S3cretPart" + strings.Repeat("x", 20)}, "-")
	k := headscale.PreAuthKey{ID: f.nextID, User: owner, KeyPrefix: prefix, Reusable: o.Reusable, Ephemeral: o.Ephemeral,
		Expiration: o.Expiration, CreatedAt: time.Now().UTC(), Tags: o.Tags}
	f.keys = append(f.keys, k)
	if f.keyErr != nil {
		return headscale.PreAuthKey{}, f.keyErr
	}
	k.Key = headscale.NewSecret(secret)
	return k, nil
}

func (f *fakeInstance) ListPreAuthKeys(context.Context) ([]headscale.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ListPreAuthKeys")
	out := slices.Clone(f.keys)
	if f.lie {
		for i := range out {
			out[i].Reusable = true
		}
	}
	return out, nil
}

func (f *fakeInstance) ExpirePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call(fmt.Sprintf("ExpirePreAuthKey %d", id))
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys[i].Expiration = time.Now().Add(-time.Second)
		}
	}
	return nil
}

// register simulates a client registering with key id (Headscale marks a one-time key used).
func (f *fakeInstance) register(id uint64, host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys[i].Used = true
			f.nextID++
			f.nodes = append(f.nodes, headscale.Node{ID: f.nextID, Name: host, User: f.keys[i].User, PreAuthKeyID: id,
				RegisterMethod: headscale.RegisterMethodAuthKey})
		}
	}
}

type fakeRegistry struct {
	tenant uuid.UUID
	inst   *fakeInstance
}

func (r fakeRegistry) ForTenant(_ context.Context, id uuid.UUID) (headscale.Instance, error) {
	if id != r.tenant {
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable, Code: -1, Err: headscale.ErrNoInstance}
	}
	return r.inst, nil
}

func newFake() (fakeRegistry, *fakeInstance) {
	inst := &fakeInstance{}
	return fakeRegistry{tenant: uuid.New(), inst: inst}, inst
}

var fixedNow = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)

func TestEnrollCreatesUserAndOneTimeKey(t *testing.T) {
	reg, inst := newFake()
	e, err := Enroll(t.Context(), reg, reg.tenant, Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	if !e.UserCreated || e.User.Name != DefaultUser || e.KeyID == 0 || e.Key().IsZero() || e.TenantID != reg.tenant {
		t.Fatalf("%v", e)
	}
	want := headscale.PreAuthKeyOpts{User: e.User.ID, Reusable: false, Ephemeral: false, Expiration: fixedNow.Add(DefaultKeyTTL)}
	if len(inst.opts) != 1 || inst.opts[0].User != want.User || inst.opts[0].Reusable || inst.opts[0].Ephemeral ||
		!inst.opts[0].Expiration.Equal(want.Expiration) || len(inst.opts[0].Tags) != 0 {
		t.Fatalf("CreatePreAuthKey %+v, want %+v", inst.opts, want)
	}
	if !e.Expiration.Equal(fixedNow.Add(DefaultKeyTTL)) {
		t.Fatalf("expiration %v", e.Expiration)
	}
	// ensure, re-resolve right before the write, create, read back (§13.4)
	if got := strings.Join(inst.calls, ","); got != "ListUsers,CreateUser,ListUsers,CreatePreAuthKey,ListPreAuthKeys" {
		t.Fatalf("calls %s", got)
	}
}

func TestEnrollReusesUserAndBoundsTTL(t *testing.T) {
	reg, inst := newFake()
	inst.users = []headscale.User{{ID: 7, Name: "mg-e2e-x"}}
	inst.nextID = 7
	e, err := Enroll(t.Context(), reg, reg.tenant, Options{User: "mg-e2e-x", TTL: MaxKeyTTL})
	if err != nil || e.UserCreated || e.User.ID != 7 || slices.Contains(inst.calls, "CreateUser") {
		t.Fatalf("%v %v %v", e, err, inst.calls)
	}
	if d := time.Until(e.Expiration); d > MaxKeyTTL || d < MaxKeyTTL-5*time.Second {
		t.Fatalf("expiration in %v", d)
	}
	for _, ttl := range []time.Duration{MaxKeyTTL + time.Second, -time.Minute} {
		if _, err := Enroll(t.Context(), reg, reg.tenant, Options{TTL: ttl}); err == nil {
			t.Errorf("TTL %v accepted", ttl)
		}
	}
	if _, err := Enroll(t.Context(), reg, uuid.New(), Options{}); !errors.Is(err, headscale.ErrNoInstance) {
		t.Fatalf("unknown tenant: %v", err)
	}
}

// A conflict from a concurrent creation is read back, not retried.
func TestEnrollUserCreatedConcurrently(t *testing.T) {
	reg, inst := newFake()
	inst.raceUser = true
	e, err := Enroll(t.Context(), reg, reg.tenant, Options{})
	if err != nil || e.UserCreated || strings.Count(strings.Join(inst.calls, ","), "CreateUser") != 1 {
		t.Fatalf("%v %v %v", e, err, inst.calls)
	}
}

// A key read back reusable (or otherwise different) is refused and expired; a failed create expires a key the
// instance may have stored anyway.
func TestEnrollRefusesAndExpiresBadKeys(t *testing.T) {
	reg, inst := newFake()
	inst.lie = true
	if _, err := Enroll(t.Context(), reg, reg.tenant, Options{}); err == nil || !strings.Contains(err.Error(), "reusable") {
		t.Fatalf("lying read-back: %v", err)
	}
	if !inst.keys[0].Expiration.Before(time.Now()) {
		t.Fatal("refused key not expired")
	}
	reg2, inst2 := newFake()
	inst2.keyErr = &headscale.Error{Op: headscale.OpCreatePreAuthKey, Kind: headscale.KindUnavailable, Code: -1,
		Outcome: headscale.OutcomeUnknown}
	if _, err := Enroll(t.Context(), reg2, reg2.tenant, Options{}); !errors.Is(err, headscale.ErrUnavailable) {
		t.Fatalf("create failure: %v", err)
	}
	if len(inst2.keys) != 1 || !inst2.keys[0].Expiration.Before(time.Now()) {
		t.Fatalf("key stored by a failed create not expired: %+v", inst2.keys)
	}
}

// The key never appears when the enrollment, its state or its key are printed, logged or marshalled.
func TestKeyNeverPrinted(t *testing.T) {
	reg, _ := newFake()
	e, err := Enroll(t.Context(), reg, reg.tenant, Options{})
	if err != nil {
		t.Fatal(err)
	}
	secret := e.Key().Reveal()
	if !strings.HasPrefix(secret, "hskey-auth-") {
		t.Fatalf("fake key %q", e.KeyPrefix)
	}
	var buf bytes.Buffer
	for _, v := range []any{e, *e, e.Key(), e.State()} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			fmt.Fprintf(&buf, verb+"\n", v)
		}
		js, _ := json.Marshal(v)
		buf.Write(js)
	}
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "e", e, "v", *e, "k", e.Key(), "s", e.State())
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "e", e, "v", *e, "k", e.Key(), "s", e.State())
	if strings.Contains(buf.String(), secret) || strings.Contains(buf.String(), "S3cretPart") {
		t.Fatalf("key printed:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), e.KeyPrefix) {
		t.Fatal("the public prefix should be printed")
	}
}

func TestKeyFile(t *testing.T) {
	reg, _ := newFake()
	e, err := Enroll(t.Context(), reg, reg.tenant, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "keys")
	path, err := e.WriteKeyFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the file this test just wrote
	if err != nil || string(raw) != e.Key().Reveal() {
		t.Fatalf("content mismatch (%v)", err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		di, _ := os.Stat(dir)
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Fatalf("modes file %v dir %v", fi.Mode().Perm(), di.Mode().Perm())
		}
	}
	second, err := e.WriteKeyFile(dir)
	if err != nil || second == path || len(e.KeyFiles()) != 2 || !slices.Contains(e.State().KeyFiles, second) {
		t.Fatalf("second file %q %v %v", second, err, e.KeyFiles())
	}
	if err := e.RemoveKeyFiles(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, second} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists", p)
		}
	}
	if _, err := Resume(e.State()).WriteKeyFile(dir); err == nil {
		t.Fatal("a resumed enrollment has no key to write")
	}
}

// After a client registered with the key: Nodes finds its node, KeyState reports it used, Cleanup expires the key,
// deletes the node and the user it created — also from a resumed State (another process).
func TestNodesKeyStateCleanup(t *testing.T) {
	reg, inst := newFake()
	e, err := Enroll(t.Context(), reg, reg.tenant, Options{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := Enroll(t.Context(), reg, reg.tenant, Options{})
	if err != nil {
		t.Fatal(err)
	}
	inst.register(e.KeyID, "client-1")
	inst.register(other.KeyID, "client-2")
	path, _ := e.WriteKeyFile(t.TempDir())
	raw, _ := json.Marshal(e.State())
	var st State
	if err := json.Unmarshal(raw, &st); err != nil || strings.Contains(string(raw), e.Key().Reveal()) {
		t.Fatalf("state %s %v", raw, err)
	}
	r := Resume(st)
	nodes, err := r.Nodes(t.Context(), reg)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "client-1" || nodes[0].PreAuthKeyID != e.KeyID {
		t.Fatalf("nodes %+v %v", nodes, err)
	}
	k, err := r.KeyState(t.Context(), reg)
	if err != nil || !k.Used || k.Reusable {
		t.Fatalf("key state %+v %v", k, err)
	}
	// the user still has the other client's node: deleting it is refused, the error is reported
	if err := r.Cleanup(t.Context(), reg, CleanupOptions{DeleteNodes: true, DeleteUser: true}); !errors.Is(err, headscale.ErrConflict) {
		t.Fatalf("cleanup with another node left: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cleanup kept the key file")
	}
	if err := other.Cleanup(t.Context(), reg, CleanupOptions{DeleteNodes: true, DeleteUser: true}); err != nil {
		t.Fatal(err)
	}
	if len(inst.nodes) != 0 || len(inst.users) != 0 {
		t.Fatalf("left: nodes %+v users %+v", inst.nodes, inst.users)
	}
	if _, err := r.KeyState(t.Context(), reg); err != nil {
		t.Fatal(err) // keys stay listed (expired), as on Headscale
	}
}
