package audit

// Tests that need no database: event checks, the details filter, the request defaults and the cursor.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

func TestNormalize(t *testing.T) {
	op := uuid.New()
	a, b := uuid.New(), uuid.New()
	for _, c := range []struct {
		name string
		ev   Event
		ok   bool
	}{
		{"minimal", Event{Action: "device.rename", ResourceType: "device"}, true},
		{"one segment", Event{Action: "rename", ResourceType: "device"}, false},
		{"upper case", Event{Action: "Device.rename", ResourceType: "device"}, false},
		{"too long", Event{Action: "a." + strings.Repeat("b", 199), ResourceType: "device"}, false},
		{"actor type", Event{Action: "device.rename", ResourceType: "device", ActorType: "robot"}, false},
		{"outcome", Event{Action: "device.rename", ResourceType: "device", Outcome: "partial"}, false},
		{"resource type", Event{Action: "device.rename", ResourceType: "Device!"}, false},
		{"no resource type", Event{Action: "device.rename"}, false},
		{"requested without operation", Event{Action: "device.expire.requested", ResourceType: "device"}, false},
		{"requested", Event{Action: "device.expire.requested", ResourceType: "device", OperationID: &op}, true},
		{"failed as success", Event{Action: "device.expire.failed", ResourceType: "device", OperationID: &op}, false},
		{"failed", Event{Action: "device.expire.failed", ResourceType: "device", OperationID: &op, Outcome: OutcomeFailure}, true},
		{"succeeded as denied", Event{Action: "device.expire.succeeded", ResourceType: "device", OperationID: &op,
			Outcome: OutcomeDenied}, false},
		{"operation on a plain event", Event{Action: "device.rename", ResourceType: "device", OperationID: &op}, false},
	} {
		err := c.ev.normalize()
		if c.ok != (err == nil) || err != nil && !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	ev := Event{Action: "device.list", ResourceType: "device", TenantID: &a, TargetTenantID: &a,
		ActorDisplay: strings.Repeat("é", 150), ResourceID: strings.Repeat("x", 300)}
	if err := ev.normalize(); err != nil {
		t.Fatal(err)
	}
	if ev.TargetTenantID != nil || ev.ActorType != ActorIdentity || ev.Outcome != OutcomeSuccess {
		t.Errorf("defaults/target: %+v", ev)
	}
	if len(ev.ActorDisplay) > maxText || !strings.HasPrefix(strings.Repeat("é", 150), ev.ActorDisplay) || len(ev.ResourceID) != maxText {
		t.Errorf("clipped display %d bytes, resource id %d bytes", len(ev.ActorDisplay), len(ev.ResourceID))
	}
	ev = Event{Action: "device.list", ResourceType: "device", TenantID: &a, TargetTenantID: &b, Outcome: OutcomeDenied}
	if err := ev.normalize(); err != nil || ev.TargetTenantID == nil || *ev.TargetTenantID != b {
		t.Errorf("cross-tenant target dropped: %+v %v", ev, err)
	}
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDetailsFilter(t *testing.T) {
	id := uuid.New()
	at := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	raw, dropped, err := encodeDetails(Details{
		"reason": "no_grant", "status": 403, "ok": true, "ratio": 0.5, "idp_id": id, "maybe": (*uuid.UUID)(nil),
		"at": at, "ip": netip.MustParseAddr("192.0.2.7"), "tags": []string{"tag:a"}, "ids": []uuid.UUID{id},
		"big": uint64(math.MaxUint64), "nan": math.NaN(), "err": errors.New("x"), "Upper": "x", "_x": "y",
		"api_key": "k", "preauth_key": "k", "nonce": "n", "verifier": "v", "headers": "h", "private_key": "p",
		"id_token": "eyJ", "refresh_token": "r",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, raw)
	want := map[string]any{
		"reason": "no_grant", "status": float64(403), "ok": true, "ratio": 0.5, "idp_id": id.String(), "maybe": nil,
		"at": "2026-11-17T01:02:03Z", "ip": "192.0.2.7", "tags": []any{"tag:a"}, "ids": []any{id.String()},
		"_redacted": float64(dropped),
	}
	if dropped != 13 || fmt.Sprint(m) != fmt.Sprint(want) {
		t.Errorf("filtered details %v (dropped %d), want %v (13)", m, dropped, want)
	}

	many := Details{}
	for i := range 40 {
		many[fmt.Sprintf("k%02d", i)] = i
	}
	raw, dropped, _ = encodeDetails(many)
	if m := decode(t, raw); dropped != 8 || len(m) != maxDetailKeys+1 || m["k00"] != float64(0) {
		t.Errorf("40 keys: dropped %d, kept %d", dropped, len(m))
	}
	huge := Details{}
	for i := range 32 {
		huge[fmt.Sprintf("k%02d", i)] = strings.Repeat("v", maxDetailText)
	}
	if raw, _, _ = encodeDetails(huge); string(raw) != `{"_truncated":true}` {
		t.Errorf("an object above %d bytes: %d bytes", maxDetailsSize, len(raw))
	}
	if raw, dropped, _ = encodeDetails(nil); string(raw) != `{}` || dropped != 0 {
		t.Errorf("nil details: %s", raw)
	}
}

func TestFillFromRequest(t *testing.T) {
	a, actor, grant := uuid.New(), uuid.New(), uuid.New()
	r := &Request{Action: "device.rename", ActorType: ActorSupport, ActorIdentityID: &actor, ActorDisplay: "Bob",
		SupportGrantID: &grant, TenantID: &a, ResourceType: "device", ResourceID: "dev-1", RequestID: "req-1",
		ClientIP: netip.MustParseAddr("2001:db8::1")}
	var ev Event
	fill(t.Context(), &ev, r, true)
	if ev.Action != "device.rename" || ev.ActorType != ActorSupport || *ev.ActorIdentityID != actor || ev.ActorDisplay != "Bob" ||
		*ev.SupportGrantID != grant || *ev.TenantID != a || ev.ResourceType != "device" || ev.ResourceID != "dev-1" ||
		ev.RequestID != "req-1" || ev.ActorIP != r.ClientIP {
		t.Errorf("defaults: %+v", ev)
	}
	ev = Event{}
	fill(t.Context(), &ev, r, false)
	if ev.TenantID != nil {
		t.Error("a detached event inherited the tenant of the path")
	}
	ev = Event{ResourceType: "session"}
	fill(t.Context(), &ev, r, true)
	if ev.ResourceID != "" {
		t.Error("the resource id of another resource type was inherited")
	}
	ev = Event{}
	fill(requestid.With(context.Background(), "req-ctx"), &ev, nil, true)
	if ev.RequestID != "req-ctx" || ev.TenantID != nil {
		t.Errorf("without a request scope: %+v", ev)
	}
	var nilReq *Request
	nilReq.markRecorded()
	nilReq.track(Operation{})
	nilReq.handOff(uuid.New())
	if RequestFrom(context.Background()) != nil {
		t.Error("RequestFrom outside a request")
	}
}

func TestCursor(t *testing.T) {
	at := time.Date(2026, 11, 17, 8, 30, 0, 123456000, time.UTC)
	id := uuid.New()
	q := Query{Outcome: OutcomeDenied}
	bind := cursorBinding("tenant", id, q)
	c := encodeCursor(at, id, bind)
	gotAt, gotID, ok := decodeCursor(c, bind)
	if !ok || !gotAt.Equal(at) || gotID != id {
		t.Fatalf("round trip: %v %v %v", gotAt, gotID, ok)
	}
	for name, other := range map[string][8]byte{
		"other tenant":   cursorBinding("tenant", uuid.New(), q),
		"platform":       cursorBinding("platform", id, q),
		"other filter":   cursorBinding("tenant", id, Query{}),
		"other window":   cursorBinding("tenant", id, Query{Outcome: OutcomeDenied, From: &at}),
		"other actor":    cursorBinding("tenant", id, Query{Outcome: OutcomeDenied, Actor: &id}),
		"other action":   cursorBinding("tenant", id, Query{Outcome: OutcomeDenied, Action: "device.list"}),
		"page size only": cursorBinding("tenant", id, Query{Outcome: OutcomeDenied, Limit: 7}),
	} {
		_, _, ok := decodeCursor(c, other)
		if want := name == "page size only"; ok != want {
			t.Errorf("%s: accepted %v, want %v", name, ok, want)
		}
	}
	for _, bad := range []string{"", "!!", c + "A", c[:len(c)-2], strings.Repeat("A", 600),
		encodeCursor(time.Date(9999, 12, 31, 1, 0, 0, 0, time.UTC), id, bind)} {
		if _, _, ok := decodeCursor(bad, bind); ok {
			t.Errorf("cursor %q accepted", bad)
		}
	}
}
