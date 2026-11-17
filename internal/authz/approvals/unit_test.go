package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// TestCanonical — the canonical form does not depend on key order, whitespace, HTML escaping or the way PostgreSQL
// prints jsonb (a space after ':' and ','); non-objects, floats, deep nesting and oversized payloads are refused.
func TestCanonical(t *testing.T) {
	type nested struct {
		Z string         `json:"z"`
		A map[string]int `json:"a"`
	}
	c1, err := Canonical(map[string]any{"b": 2, "a": "<x>&y", "c": nested{Z: "é", A: map[string]int{"y": 1, "x": -3}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"<x>&y","b":2,"c":{"a":{"x":-3,"y":1},"z":"é"}}`
	if string(c1) != want {
		t.Fatalf("canonical %s, want %s", c1, want)
	}
	// the jsonb text of the same value (keys reordered by length, spaces) re-canonicalizes to the same bytes
	c2, err := CanonicalJSON([]byte(`{"b": 2, "a": "<x>&y", "c": {"z": "é", "a": {"y": 1, "x": -3}}}`))
	if err != nil || string(c2) != want || Hash(c1) != Hash(c2) {
		t.Fatalf("re-canonicalized %s (%v), hashes %s / %s", c2, err, Hash(c1), Hash(c2))
	}
	if !ValidHash(Hash(c1)) || ValidHash("ABC") || ValidHash(strings.Repeat("g", 64)) {
		t.Fatal("ValidHash")
	}
	for name, raw := range map[string]string{
		"array": `[1]`, "string": `"x"`, "float": `{"a": 1.5}`, "exponent": `{"a": 1e3}`, "trailing": `{"a":1} {}`,
		"invalid": `{"a":`, "deep": strings.Repeat(`{"a":`, 20) + `1` + strings.Repeat(`}`, 20),
		"large": `{"a":"` + strings.Repeat("x", MaxPayloadBytes) + `"}`, "huge int": `{"a": 12345678901234567890}`,
	} {
		if _, err := CanonicalJSON([]byte(raw)); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: %v, want ErrPayload", name, err)
		}
	}
	if _, err := Canonical(1.5); !errors.Is(err, ErrPayload) {
		t.Errorf("Canonical(float): %v", err)
	}
}

type testPayload struct {
	BackupID string `json:"backup_id"`
}

func (p testPayload) Validate() error {
	if _, err := uuid.Parse(p.BackupID); err != nil {
		return errors.New("backup_id is not a UUID")
	}
	return nil
}

func noop(context.Context, *store.Tx, Execution, testPayload) (*uuid.UUID, error) { return nil, nil }

// TestTyped — strict decoding of the typed payload (unknown fields refused) and its Validate.
func TestTyped(t *testing.T) {
	a := Typed(Spec{Name: "platform.test_restore", Scope: authz.ScopePlatform, ResourceType: "instance",
		Permission: "platform.instance:restore"}, noop)
	ok := json.RawMessage(`{"backup_id":"` + uuid.NewString() + `"}`)
	if err := a.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"backup_id":"x"}`, `{"backup_id":"` + uuid.NewString() + `","extra":1}`, `{}`, `[`} {
		if err := a.Validate(json.RawMessage(bad)); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: %v, want ErrPayload", bad, err)
		}
	}
}

// TestRegistry — the specs of the executors are checked once, at start.
func TestRegistry(t *testing.T) {
	good := Spec{Name: "platform.test_restore", Scope: authz.ScopePlatform, ResourceType: "instance",
		Permission: "platform.instance:restore", DecideConditions: []string{authz.CondRestoreOnly}}
	r, err := NewRegistry(Typed(good, noop))
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := r.Lookup(good.Name); !ok || a.Spec().Name != good.Name || len(r.Names()) != 1 {
		t.Fatal("lookup")
	}
	if _, ok := (*Registry)(nil).Lookup(good.Name); ok {
		t.Fatal("nil registry finds an action")
	}
	bad := map[string]Spec{
		"name":       {Name: "Restore", Scope: authz.ScopePlatform, ResourceType: "instance", Permission: "platform.instance:restore"},
		"scope":      {Name: "x.y", Scope: authz.ScopeSupport, ResourceType: "instance", Permission: "platform.instance:restore"},
		"resource":   {Name: "x.y", Scope: authz.ScopePlatform, ResourceType: "Instance!", Permission: "platform.instance:restore"},
		"permission": {Name: "x.y", Scope: authz.ScopeTenant, ResourceType: "settings", Permission: "platform.instance:restore"},
		"condition":  {Name: "x.y", Scope: authz.ScopePlatform, ResourceType: "instance", Permission: "platform.instance:restore", DecideConditions: []string{"sometimes"}},
	}
	for name, s := range bad {
		if _, err := NewRegistry(Typed(s, noop)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewRegistry(Typed(good, noop), Typed(good, noop)); err == nil {
		t.Error("duplicate accepted")
	}
}

// TestLocationAndCursor — the Location of a 2P answer names the scope of the request; the cursor round-trips.
func TestLocationAndCursor(t *testing.T) {
	id, ten := uuid.New(), uuid.New()
	if got := Location(Request{ID: id, Scope: authz.ScopePlatform}); got != "/api/v1/platform/approvals/"+id.String() {
		t.Fatal(got)
	}
	if got := Location(Request{ID: id, Scope: authz.ScopeTenant, TenantID: &ten}); got != "/api/v1/tenants/"+ten.String()+"/approvals/"+id.String() {
		t.Fatal(got)
	}
	at := time.Date(2026, 11, 17, 10, 20, 30, 123456000, time.UTC)
	ts, cid, ok := decodeCursor(encodeCursor(at, id))
	if !ok || cid != id || !ts.Equal(at) {
		t.Fatal("cursor")
	}
	if _, _, ok := decodeCursor("not-a-cursor"); ok {
		t.Fatal("bad cursor accepted")
	}
}
