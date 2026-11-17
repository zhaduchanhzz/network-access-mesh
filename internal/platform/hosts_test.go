package platform_test

// Integration tests of host management (P3-T04, GET/POST/PATCH /platform/hosts and `meshguard admin host-set`) on a
// real PostgreSQL migrated like a deployment: the service on the api's pools (mg_api_tenant / mg_api_platform), the
// Placer on the worker's (the world of placement_test.go, same shared database). Validation parity with the CHECKs of
// 0001/0014, the 409 rules, the ETag, Idempotency-Key, the audit rows, and placement following what the API changes.

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
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// hostWorld is the shared database seen by the api (the host Service) and by the worker (the Placer).
type hostWorld struct {
	*world
	svc *platform.Service
}

func newHostWorld(t *testing.T) *hostWorld {
	t.Helper()
	w := newWorld(t, 8, platform.PlacerOptions{})
	pg := storetest.Require(t)
	shared.Lock()
	db := shared.db
	shared.Unlock()
	return &hostWorld{world: w, svc: platform.New(pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8))}
}

func i64(v int64) *int64 { return &v }

// apiCtx is the context of an API request of identity id: the audit scope the audit middleware sets (auditapi).
func apiCtx(ctx context.Context, id uuid.UUID, requestID string) context.Context {
	return audit.WithRequest(ctx, &audit.Request{Action: "platform.host.update", ActorType: audit.ActorIdentity,
		ActorIdentityID: &id, ActorDisplay: "operator " + id.String()[:8], ResourceType: "host", RequestID: requestID})
}

// TestHostConfigParity — the validation of the service is the exact mirror of the CHECKs of hosts: every case is
// validated by HostConfig.Check and written straight into the table as superuser (in a transaction rolled back), and
// both must agree — except the rules the database leaves to code (codeOnly: the database accepts, the service refuses).
func TestHostConfigParity(t *testing.T) {
	w := newWorld(t, 2, platform.PlacerOptions{})
	ctx := t.Context()
	base := func() platform.HostConfig {
		return platform.HostConfig{Name: "parity-" + w.sfx, Region: "lab", Status: platform.HostActive, MaxInstances: i64(100),
			PublicEntry: platform.PublicEntry{IPv4: ptr("203.0.113.7"), Mode: ptr(platform.EntryVPSGateway)},
			RunUIDRange: platform.IntRange{First: 30000, Last: 39999}, TenantNetPool: "10.250.0.0/16"}
	}
	type pc struct {
		name     string
		mut      func(*platform.HostConfig)
		field    string // "" ⇒ valid; otherwise the field the service names
		codeOnly bool
	}
	cases := []pc{
		{name: "base", mut: func(*platform.HostConfig) {}},
		{name: "draining", mut: func(c *platform.HostConfig) { c.Status = platform.HostDraining }},
		{name: "disabled", mut: func(c *platform.HostConfig) { c.Status = platform.HostDisabled }},
		{name: "status upper", mut: func(c *platform.HostConfig) { c.Status = "Active" }, field: "status"},
		{name: "status maintenance", mut: func(c *platform.HostConfig) { c.Status = "maintenance" }, field: "status"},
		{name: "capacity 0", mut: func(c *platform.HostConfig) { c.MaxInstances = i64(0) }},
		{name: "capacity max", mut: func(c *platform.HostConfig) { c.MaxInstances = i64(2147483647) }},
		{name: "capacity -1", mut: func(c *platform.HostConfig) { c.MaxInstances = i64(-1) }, field: "capacity.max_instances"},
		{name: "capacity 2^31", mut: func(c *platform.HostConfig) { c.MaxInstances = i64(2147483648) }, field: "capacity.max_instances"},
		{name: "entry empty", mut: func(c *platform.HostConfig) { c.PublicEntry = platform.PublicEntry{} }},
		{name: "entry ipv4 only", mut: func(c *platform.HostConfig) { c.PublicEntry.Mode = nil }},
		{name: "entry mode only", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = nil }},
		{name: "mode direct", mut: func(c *platform.HostConfig) { c.PublicEntry.Mode = ptr(platform.EntryDirect) }},
		{name: "mode upper", mut: func(c *platform.HostConfig) { c.PublicEntry.Mode = ptr("DIRECT") }, field: "public_entry.mode"},
		{name: "mode empty", mut: func(c *platform.HostConfig) { c.PublicEntry.Mode = ptr("") }, field: "public_entry.mode"},
		{name: "mode other", mut: func(c *platform.HostConfig) { c.PublicEntry.Mode = ptr("gateway") }, field: "public_entry.mode"},
		{name: "ipv4 empty", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("") }, field: "public_entry.ipv4"},
		{name: "ipv4 leading zero", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("203.0.113.07") }, field: "public_entry.ipv4"},
		{name: "ipv4 octet 256", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("256.0.113.7") }, field: "public_entry.ipv4"},
		{name: "ipv4 three octets", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("203.0.113") }, field: "public_entry.ipv4"},
		{name: "ipv4 prefix", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("203.0.113.7/32") }, field: "public_entry.ipv4"},
		{name: "ipv4 ipv6", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("2001:db8::7") }, field: "public_entry.ipv4"},
		{name: "ipv4 mapped", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("::ffff:203.0.113.7") }, field: "public_entry.ipv4"},
		{name: "ipv4 name", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("vps.example.test") }, field: "public_entry.ipv4"},
		{name: "ipv4 space", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr(" 203.0.113.7") }, field: "public_entry.ipv4"},
		{name: "ipv4 0.0.0.0", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("0.0.0.0") }, field: "public_entry.ipv4"},
		{name: "ipv4 0/8", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("0.1.2.3") }, field: "public_entry.ipv4"},
		{name: "ipv4 loopback", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("127.0.0.1") }, field: "public_entry.ipv4"},
		{name: "ipv4 link-local", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("169.254.10.1") }, field: "public_entry.ipv4"},
		{name: "ipv4 multicast", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("224.0.0.1") }, field: "public_entry.ipv4"},
		{name: "ipv4 class E", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("240.0.0.1") }, field: "public_entry.ipv4"},
		{name: "ipv4 broadcast", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("255.255.255.255") }, field: "public_entry.ipv4"},
		{name: "ipv4 223.255.255.255", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("223.255.255.255") }},
		{name: "ipv4 1.0.0.0", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("1.0.0.0") }},
		{name: "ipv4 LAN direct", mut: func(c *platform.HostConfig) {
			c.PublicEntry = platform.PublicEntry{IPv4: ptr("192.168.50.10"), Mode: ptr(platform.EntryDirect)}
		}},
		{name: "ipv4 shared space", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("100.64.0.1") }},
		{name: "ipv4 in pool", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("10.250.3.4") }, field: "public_entry.ipv4"},
		{name: "ipv4 = pool network", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("10.250.0.0") }, field: "public_entry.ipv4"},
		{name: "ipv4 = pool broadcast", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("10.250.255.255") }, field: "public_entry.ipv4"},
		{name: "ipv4 next to pool", mut: func(c *platform.HostConfig) { c.PublicEntry.IPv4 = ptr("10.251.0.0") }},
		{name: "pool /8", mut: func(c *platform.HostConfig) { c.TenantNetPool = "10.0.0.0/8"; c.PublicEntry.IPv4 = ptr("203.0.113.7") }},
		{name: "pool /29", mut: func(c *platform.HostConfig) { c.TenantNetPool = "10.250.0.0/29" }},
		{name: "pool /30", mut: func(c *platform.HostConfig) { c.TenantNetPool = "10.250.0.0/30" }, field: "tenant_net_pool"},
		{name: "pool /7", mut: func(c *platform.HostConfig) { c.TenantNetPool = "10.0.0.0/7" }, field: "tenant_net_pool"},
		{name: "pool host bits", mut: func(c *platform.HostConfig) { c.TenantNetPool = "10.250.0.1/16" }, field: "tenant_net_pool"},
		{name: "pool no mask", mut: func(c *platform.HostConfig) { c.TenantNetPool = "10.250.0.0" }, field: "tenant_net_pool"},
		{name: "pool in tailnet", mut: func(c *platform.HostConfig) { c.TenantNetPool = "100.100.0.0/16" }, field: "tenant_net_pool"},
		{name: "pool over tailnet", mut: func(c *platform.HostConfig) { c.TenantNetPool = "100.0.0.0/8" }, field: "tenant_net_pool"},
		{name: "pool after tailnet", mut: func(c *platform.HostConfig) { c.TenantNetPool = "100.128.0.0/16" }},
		{name: "pool ipv6", mut: func(c *platform.HostConfig) { c.TenantNetPool = "fd00::/64" }, field: "tenant_net_pool"},
		{name: "uid single", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 30000, Last: 30000} }},
		{name: "uid 1001", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 1001, Last: 1001} }},
		{name: "uid top", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 70000, Last: 2147483646} }},
		{name: "uid above top", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 70000, Last: 2147483647} }, field: "run_uid_range.last"},
		{name: "uid 999", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 999, Last: 2000} }, field: "run_uid_range.first"},
		{name: "uid zero", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 0, Last: 2000} }, field: "run_uid_range.first"},
		{name: "uid negative", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: -5, Last: 2000} }, field: "run_uid_range.first"},
		{name: "uid reversed", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 40000, Last: 30000} }, field: "run_uid_range"},
		{name: "stun 3478-3479", mut: func(c *platform.HostConfig) { c.STUNPortRange = &platform.IntRange{First: 3478, Last: 3479} }},
		{name: "stun full", mut: func(c *platform.HostConfig) { c.STUNPortRange = &platform.IntRange{First: 1024, Last: 65535} }},
		{name: "stun 1023", mut: func(c *platform.HostConfig) { c.STUNPortRange = &platform.IntRange{First: 1023, Last: 2000} }, field: "stun_port_range.first"},
		{name: "stun 65536", mut: func(c *platform.HostConfig) { c.STUNPortRange = &platform.IntRange{First: 2000, Last: 65536} }, field: "stun_port_range.last"},
		{name: "stun reversed", mut: func(c *platform.HostConfig) { c.STUNPortRange = &platform.IntRange{First: 2000, Last: 1999} }, field: "stun_port_range"},
		// rules the database leaves to code
		{name: "uid Keycloak 1000", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 1000, Last: 1000} }, field: "run_uid_range", codeOnly: true},
		{name: "uid core services", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 20000, Last: 20010} }, field: "run_uid_range", codeOnly: true},
		{name: "uid nobody", mut: func(c *platform.HostConfig) { c.RunUIDRange = platform.IntRange{First: 60000, Last: 70000} }, field: "run_uid_range", codeOnly: true},
		{name: "name not a label", mut: func(c *platform.HostConfig) { c.Name = "Not_A_Label" }, field: "name", codeOnly: true},
		{name: "region with space", mut: func(c *platform.HostConfig) { c.Region = "two words" }, field: "region", codeOnly: true},
		{name: "region empty", mut: func(c *platform.HostConfig) { c.Region = "" }, field: "region", codeOnly: true},
	}
	var valid, refused, codeOnly int
	for _, c := range cases {
		cfg := base()
		c.mut(&cfg)
		fe := cfg.Check()
		dbErr := insertRaw(ctx, w, cfg)
		switch {
		case c.field == "" && (len(fe) != 0 || dbErr != nil):
			t.Errorf("%s: want valid — service %+v, database %v", c.name, fe, dbErr)
		case c.field != "" && (len(fe) != 1 || fe[0].Field != c.field):
			t.Errorf("%s: service %+v, want one error on %s", c.name, fe, c.field)
		case c.field != "" && !c.codeOnly && dbErr == nil:
			t.Errorf("%s: the service refuses it (%s) but the database accepts it — the mirror is wrong", c.name, fe[0].Code)
		case c.codeOnly && dbErr != nil:
			t.Errorf("%s: a code-only rule, but the database refuses it too: %v", c.name, dbErr)
		case c.codeOnly:
			codeOnly++
		case c.field != "":
			refused++
		default:
			valid++
		}
	}
	t.Logf("parity: %d cases — %d valid in both, %d refused by both, %d refused by code only", len(cases), valid, refused, codeOnly)
}

// insertRaw writes cfg (with the defaults of HostConfig) straight into hosts as superuser, in a transaction that is
// rolled back; nil = the database accepts the row.
func insertRaw(ctx context.Context, w *world, c platform.HostConfig) error {
	status := c.Status
	if status == "" {
		status = platform.HostActive
	}
	maxInstances := int64(platform.DefaultMaxInstances)
	if c.MaxInstances != nil {
		maxInstances = *c.MaxInstances
	}
	entry, err := json.Marshal(c.PublicEntry)
	if err != nil {
		return err
	}
	var stunFirst, stunLast *int64
	if c.STUNPortRange != nil {
		stunFirst, stunLast = &c.STUNPortRange.First, &c.STUNPortRange.Last
	}
	tx, err := w.su.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	_, err = tx.Exec(ctx, `INSERT INTO hosts (name, region, status, capacity, public_entry, run_uid_range, stun_port_range,
			tenant_net_pool)
		VALUES ($1, $2, $3, jsonb_build_object('max_instances', $4::bigint), $5::jsonb, int4range($6::int, $7::int, '[]'),
			CASE WHEN $8::int IS NULL THEN NULL ELSE int4range($8::int, $9::int, '[]') END, $10::text::cidr)`,
		c.Name, c.Region, status, maxInstances, string(entry), c.RunUIDRange.First, c.RunUIDRange.Last, stunFirst, stunLast,
		c.TenantNetPool)
	return err
}

// TestHostWrites — create (defaults, Idempotency-Key replay and reuse, name conflict, validation), read, list (filters,
// pagination), the If-Match rules, the 409 rules with live and removed instances, and the audit rows.
func TestHostWrites(t *testing.T) {
	w := newHostWorld(t)
	actor := uuid.Must(uuid.NewV7())
	ctx := apiCtx(t.Context(), actor, "req-"+w.sfx)
	region := w.region("hosts")
	name := "hw-" + w.sfx
	in := platform.HostConfig{Name: name, Region: region, RunUIDRange: platform.IntRange{First: 30000, Last: 30009},
		TenantNetPool: "10.250.0.0/28"}
	body, _ := json.Marshal(map[string]any{"name": name, "region": region})
	key := &platform.Idempotency{IdentityID: actor, Key: "create-" + w.sfx, Hash: jobs.RequestHash("POST", "/platform/hosts", body)}

	h, err := w.svc.CreateHost(ctx, in, platform.HostWrite{Idempotency: key})
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != name || h.Status != platform.HostActive || h.MaxInstances != platform.DefaultMaxInstances ||
		h.PublicEntry.IsValid() || h.EntryMode != "" || h.STUNPortFirst != 0 || h.RunUIDFirst != 30000 || h.RunUIDLast != 30009 ||
		h.TenantNetPool.String() != "10.250.0.0/28" || h.ETag == "" || h.Usage.LiveInstances != 0 || h.Usage.RunUIDsFree != 10 ||
		h.Usage.NetSlotsFree != 2 || h.LastHeartbeatAt != nil {
		t.Fatalf("created %+v", h)
	}
	// the same request again: the stored answer, no second row; the key with another request: refused
	if again, err := w.svc.CreateHost(ctx, in, platform.HostWrite{Idempotency: key}); err != nil || again.ID != h.ID || again.ETag != h.ETag {
		t.Errorf("replay: %+v %v", again, err)
	}
	other := *key
	other.Hash = jobs.RequestHash("POST", "/platform/hosts", []byte(`{"name":"else"}`))
	if _, err := w.svc.CreateHost(ctx, in, platform.HostWrite{Idempotency: &other}); !errors.Is(err, platform.ErrIdempotencyKeyReuse) {
		t.Errorf("key reuse: %v", err)
	}
	var conf *platform.HostConflictError
	if _, err := w.svc.CreateHost(ctx, in, platform.HostWrite{}); !errors.As(err, &conf) || conf.Reason != platform.ConflictNameTaken ||
		!errors.Is(err, platform.ErrConflict) {
		t.Errorf("same name: %v", err)
	}
	bad := in
	bad.Name, bad.PublicEntry.IPv4 = "hw2-"+w.sfx, ptr("10.250.0.3")
	var inv *platform.ValidationError
	if _, err := w.svc.CreateHost(ctx, bad, platform.HostWrite{}); !errors.As(err, &inv) || len(inv.Fields) != 1 ||
		inv.Fields[0].Field != "public_entry.ipv4" || !errors.Is(err, platform.ErrInvalid) {
		t.Errorf("ipv4 inside the pool: %v", err)
	}
	var rows int
	if err := w.su.QueryRow(ctx, `SELECT count(*) FROM hosts WHERE region = $1`, region).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("%d hosts in the region after the refusals (%v)", rows, err)
	}
	got, err := w.svc.GetHost(ctx, h.ID)
	if err != nil || got.ETag != h.ETag || got.ID != h.ID {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := w.svc.GetHost(ctx, uuid.New()); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown host: %v", err)
	}

	// If-Match
	draining := platform.HostPatch{Status: ptr(platform.HostDraining)}
	for ifMatch, want := range map[string]error{"": platform.ErrPreconditionRequired, "*": platform.ErrPreconditionRequired,
		`"0000"`: platform.ErrPreconditionFailed} {
		if _, err := w.svc.UpdateHost(ctx, h.ID, draining, platform.HostWrite{IfMatch: ifMatch}); !errors.Is(err, want) {
			t.Errorf("If-Match %q: %v, want %v", ifMatch, err, want)
		}
	}
	if _, err := w.svc.UpdateHost(ctx, uuid.New(), draining, platform.HostWrite{IfMatch: h.ETag}); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	if _, err := w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{}, platform.HostWrite{IfMatch: h.ETag}); !errors.As(err, &inv) ||
		inv.Fields[0].Field != "body" {
		t.Errorf("empty patch: %v", err)
	}
	// public entry + capacity
	h2, err := w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{MaxInstances: i64(2), PublicEntry: &platform.PublicEntry{
		IPv4: ptr("203.0.113.9"), Mode: ptr(platform.EntryVPSGateway)}}, platform.HostWrite{IfMatch: h.ETag})
	if err != nil || h2.MaxInstances != 2 || h2.PublicEntry != netip.MustParseAddr("203.0.113.9") ||
		h2.EntryMode != platform.EntryVPSGateway || h2.ETag == h.ETag {
		t.Fatalf("set public entry: %+v %v", h2, err)
	}
	if _, err := w.svc.UpdateHost(ctx, h.ID, draining, platform.HostWrite{IfMatch: h.ETag}); !errors.Is(err, platform.ErrPreconditionFailed) {
		t.Errorf("stale ETag after a change: %v", err)
	}
	// the patched configuration is validated as a whole: a pool that now holds the public entry is refused
	if _, err := w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{TenantNetPool: ptr("203.0.113.0/28")},
		platform.HostWrite{IfMatch: h2.ETag}); !errors.As(err, &inv) || inv.Fields[0].Field != "public_entry.ipv4" ||
		inv.Fields[0].Code != "inside_pool" {
		t.Errorf("pool around the public entry: %v", err)
	}

	// two live instances on the host
	t1, t2 := w.tenantIn("hw-a", region), w.tenantIn("hw-b", region)
	a1, a2 := w.mustAllocate(t1), w.mustAllocate(t2)
	if a1.HostID != h.ID || a2.HostID != h.ID {
		t.Fatalf("allocated on %s, %s; want %s", a1.HostID, a2.HostID, h.ID)
	}
	cur, err := w.svc.GetHost(ctx, h.ID)
	if err != nil || cur.ETag != h2.ETag || cur.Usage.LiveInstances != 2 || cur.Usage.ByStatus["allocated"] != 2 ||
		cur.Usage.RunUIDsFree != 8 || cur.Usage.NetSlotsFree != 0 {
		t.Fatalf("usage with 2 instances (the ETag must not change): %+v %v", cur, err)
	}
	if _, err := w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{MaxInstances: i64(1)}, platform.HostWrite{IfMatch: cur.ETag}); !errors.As(err, &conf) ||
		conf.Reason != platform.ConflictCapacityBelowLive || conf.Live != 2 {
		t.Errorf("capacity below live: %v", err)
	}
	for field, p := range map[string]platform.HostPatch{
		"region":          {Region: ptr(w.region("elsewhere"))},
		"run_uid_range":   {RunUIDRange: &platform.IntRange{First: 30000, Last: 30019}},
		"tenant_net_pool": {TenantNetPool: ptr("10.250.0.0/27")},
		"stun_port_range": {STUNPortRange: &platform.IntRange{First: 4000, Last: 4010}},
	} {
		if _, err := w.svc.UpdateHost(ctx, h.ID, p, platform.HostWrite{IfMatch: cur.ETag}); !errors.As(err, &conf) ||
			conf.Reason != platform.ConflictAllocationInUse || !slices.Equal(conf.Fields, []string{field}) || conf.Live != 2 {
			t.Errorf("%s with live instances: %v", field, err)
		}
	}
	// what may change with live instances: capacity down to the live count, status, the public entry (same values: a
	// no-op change is still written and audited)
	h3, err := w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{MaxInstances: i64(2), Status: ptr(platform.HostDraining),
		PublicEntry: &platform.PublicEntry{IPv4: ptr("203.0.113.10"), Mode: ptr(platform.EntryDirect)}},
		platform.HostWrite{IfMatch: cur.ETag})
	if err != nil || h3.Status != platform.HostDraining || h3.EntryMode != platform.EntryDirect {
		t.Fatalf("status and entry with live instances: %+v %v", h3, err)
	}
	// once the instances are removed, the ranges may change (their UIDs stay consumed)
	for _, a := range []platform.Allocation{a1, a2} {
		if _, err := w.placer.Release(ctx, a.TenantID, a.InstanceID); err != nil {
			t.Fatal(err)
		}
	}
	h4, err := w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{RunUIDRange: &platform.IntRange{First: 30000, Last: 30019},
		TenantNetPool: ptr("10.250.0.0/27"), Region: ptr(w.region("hosts2")), MaxInstances: i64(0)},
		platform.HostWrite{IfMatch: h3.ETag})
	if err != nil || h4.RunUIDLast != 30019 || h4.Usage.LiveInstances != 0 || h4.Usage.RunUIDsFree != 18 || h4.Usage.NetSlotsFree != 4 ||
		h4.MaxInstances != 0 {
		t.Fatalf("ranges after removal: %+v %v", h4, err)
	}

	// the audit trail: the create, its replay (marked, nothing changed), three updates — in the platform scope, with the
	// actor of the request and the values before/after
	type ev struct {
		Action, ActorType, RequestID string
		Actor                        *uuid.UUID
		Tenant                       *uuid.UUID
		Details                      map[string]any
	}
	var evs []ev
	r, err := w.su.Query(ctx, `SELECT action, actor_type, actor_identity_id, request_id, tenant_id, details FROM audit_events
		WHERE resource_type = 'host' AND resource_id = $1 ORDER BY occurred_at, id`, h.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var e ev
		var raw []byte
		if err := r.Scan(&e.Action, &e.ActorType, &e.Actor, &e.RequestID, &e.Tenant, &raw); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &e.Details)
		evs = append(evs, e)
	}
	r.Close()
	actions := make([]string, len(evs))
	for i, e := range evs {
		actions[i] = e.Action
		if e.ActorType != audit.ActorIdentity || e.Actor == nil || *e.Actor != actor || e.Tenant != nil || e.RequestID != "req-"+w.sfx {
			t.Errorf("event %d: %+v", i, e)
		}
		if _, redacted := e.Details["_redacted"]; redacted {
			t.Errorf("event %d: details dropped: %v", i, e.Details)
		}
	}
	if !slices.Equal(actions, []string{platform.ActionHostCreate, platform.ActionHostCreate, platform.ActionHostUpdate,
		platform.ActionHostUpdate, platform.ActionHostUpdate}) {
		t.Fatalf("audit actions %v", actions)
	}
	c := evs[0].Details
	if c["name"] != name || c["status"] != "active" || c["max_instances"] != float64(100) || c["public_ipv4"] != nil ||
		c["run_uid_range"] != "30000-30009" || c["tenant_net_pool"] != "10.250.0.0/28" || c["stun_port_range"] != nil {
		t.Errorf("create details %v", c)
	}
	if r := evs[1].Details; r["replay"] != true || r["name"] != name || len(r) != 2 {
		t.Errorf("replay details %v", r)
	}
	u := evs[2].Details
	if u["before_public_ipv4"] != nil || u["after_public_ipv4"] != "203.0.113.9" || u["before_max_instances"] != float64(100) ||
		u["after_max_instances"] != float64(2) || u["after_entry_mode"] != "vps_gateway" || u["live_instances"] != float64(0) ||
		fmt.Sprint(u["changed"]) != "[capacity public_entry]" {
		t.Errorf("update details %v", u)
	}
	if d := evs[3].Details; d["before_status"] != "active" || d["after_status"] != "draining" || d["live_instances"] != float64(2) ||
		d["before_public_ipv4"] != "203.0.113.9" || d["after_public_ipv4"] != "203.0.113.10" {
		t.Errorf("update with live instances %v", d)
	}
	if d := evs[4].Details; fmt.Sprint(d["changed"]) != "[region capacity run_uid_range tenant_net_pool]" ||
		d["after_run_uid_range"] != "30000-30019" {
		t.Errorf("update of the ranges %v", d)
	}
}

// tenantIn registers a tenant <slug>-<sfx> in status provisioning in an exact region.
func (w *world) tenantIn(slug, region string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO tenants (id, slug, name, status, deployment_region) VALUES ($1, $2::text, $2::text, 'provisioning', $3)`,
		id, slug+"-"+w.sfx, region)
	return id
}

// TestHostListAndSystemActor — list filters and pagination on hosts of one region, the refused parameters, and the host
// command's update path (by name, actor_type system).
func TestHostListAndSystemActor(t *testing.T) {
	w := newHostWorld(t)
	ctx := apiCtx(t.Context(), uuid.Must(uuid.NewV7()), "req-list-"+w.sfx)
	region := w.region("list")
	var ids []uuid.UUID
	for i, st := range []string{platform.HostActive, platform.HostDraining, platform.HostActive, platform.HostDisabled, platform.HostActive} {
		v, err := w.svc.CreateHost(ctx, platform.HostConfig{Name: fmt.Sprintf("hl%d-%s", i, w.sfx), Region: region, Status: st,
			RunUIDRange: platform.IntRange{First: 30000, Last: 30099}, TenantNetPool: "10.250.0.0/24"}, platform.HostWrite{})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, v.ID)
	}
	var seen []uuid.UUID
	cursor := ""
	for page := 0; page < 10; page++ {
		p, err := w.svc.ListHosts(ctx, platform.HostFilter{Limit: 2, Cursor: cursor, Region: region})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range p.Items {
			seen = append(seen, v.ID)
			if v.ETag == "" || v.Region != region {
				t.Errorf("listed %+v", v)
			}
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if !slices.Equal(seen, ids) {
		t.Errorf("pages %v, want %v (creation order)", seen, ids)
	}
	act, err := w.svc.ListHosts(ctx, platform.HostFilter{Region: region, Status: platform.HostActive})
	if err != nil || len(act.Items) != 3 || act.NextCursor != "" {
		t.Errorf("active hosts of the region: %d %v", len(act.Items), err)
	}
	for name, f := range map[string]platform.HostFilter{
		"status": {Status: "gone"}, "limit": {Limit: 201}, "negative": {Limit: -1}, "cursor": {Cursor: "not-a-cursor"},
	} {
		if _, err := w.svc.ListHosts(ctx, f); !errors.Is(err, platform.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the host command: by name, system actor, its own request id
	name := fmt.Sprintf("hl0-%s", w.sfx)
	cur, err := w.svc.GetHostByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.GetHostByName(ctx, "missing-"+w.sfx); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown name: %v", err)
	}
	reqID := "admin-" + uuid.NewString()
	sys := platform.HostWrite{IfMatch: cur.ETag, System: &platform.SystemActor{Command: "meshguard admin host-set", RequestID: reqID}}
	v, err := w.svc.UpdateHostByName(t.Context(), name, platform.HostPatch{PublicEntry: &platform.PublicEntry{IPv4: ptr("203.0.113.20"),
		Mode: ptr(platform.EntryVPSGateway)}}, sys)
	if err != nil || v.PublicEntry.String() != "203.0.113.20" {
		t.Fatalf("host command: %+v %v", v, err)
	}
	if _, err := w.svc.UpdateHostByName(t.Context(), name, platform.HostPatch{Status: ptr(platform.HostDraining)}, sys); !errors.Is(err, platform.ErrPreconditionFailed) {
		t.Errorf("host command with the ETag read before its own change: %v", err)
	}
	if _, err := w.svc.UpdateHostByName(t.Context(), "missing-"+w.sfx, platform.HostPatch{Status: ptr(platform.HostDraining)}, sys); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("host command, unknown host: %v", err)
	}
	var actorType, display string
	var actorID *uuid.UUID
	if err := w.su.QueryRow(ctx, `SELECT actor_type, actor_identity_id, actor_display FROM audit_events WHERE request_id = $1
		AND action = 'platform.host.update' AND resource_id = $2`, reqID, v.ID.String()).Scan(&actorType, &actorID, &display); err != nil ||
		actorType != audit.ActorSystem || actorID != nil || display != "meshguard admin host-set" {
		t.Errorf("audit of the host command: %s %v %q %v", actorType, actorID, display, err)
	}
}

// TestPlacementFollowsHosts — what the API changes is what placement sees: draining and disabled hosts take no new
// instance (the existing one stays), capacity and the public entry decide the rest, and the active host takes again.
func TestPlacementFollowsHosts(t *testing.T) {
	w := newHostWorld(t)
	ctx := apiCtx(t.Context(), uuid.Must(uuid.NewV7()), "req-place-"+w.sfx)
	region := w.region("place")
	h, err := w.svc.CreateHost(ctx, platform.HostConfig{Name: "hp-" + w.sfx, Region: region, MaxInstances: i64(5),
		PublicEntry: platform.PublicEntry{IPv4: ptr("203.0.113.30"), Mode: ptr(platform.EntryVPSGateway)},
		RunUIDRange: platform.IntRange{First: 30000, Last: 30099}, TenantNetPool: "10.250.0.0/24"}, platform.HostWrite{})
	if err != nil {
		t.Fatal(err)
	}
	first := w.mustAllocate(w.tenantIn("hp-first", region))
	if first.HostID != h.ID || first.PublicEntryIPv4.String() != "203.0.113.30" {
		t.Fatalf("first allocation %+v", first)
	}
	etag := h.ETag
	set := func(p platform.HostPatch) {
		t.Helper()
		v, err := w.svc.UpdateHost(ctx, h.ID, p, platform.HostWrite{IfMatch: etag})
		if err != nil {
			t.Fatal(err)
		}
		etag = v.ETag
	}
	tn := w.tenantIn("hp-next", region)
	var nc *platform.NoCapacityError
	for _, st := range []string{platform.HostDraining, platform.HostDisabled} {
		set(platform.HostPatch{Status: ptr(st)})
		if _, err := w.allocate(tn); !errors.As(err, &nc) || len(nc.Rejected) != 0 {
			t.Errorf("host %s: %v (want no active host in the region)", st, err)
		}
	}
	var status string
	if err := w.su.QueryRow(ctx, `SELECT status FROM tenant_instances WHERE id = $1`, first.InstanceID).Scan(&status); err != nil ||
		status != "allocated" {
		t.Errorf("the existing instance on a disabled host: %s %v", status, err)
	}
	set(platform.HostPatch{Status: ptr(platform.HostActive), MaxInstances: i64(1)})
	if _, err := w.allocate(tn); !errors.As(err, &nc) || len(nc.Rejected) != 1 || nc.Rejected[0].Reason != platform.RejectFull {
		t.Errorf("full host: %v", err)
	}
	set(platform.HostPatch{MaxInstances: i64(2), PublicEntry: &platform.PublicEntry{}})
	if _, err := w.allocate(tn); !errors.As(err, &nc) || len(nc.Rejected) != 1 || nc.Rejected[0].Reason != platform.RejectNoPublicEntry {
		t.Errorf("host without public entry: %v", err)
	}
	set(platform.HostPatch{PublicEntry: &platform.PublicEntry{IPv4: ptr("203.0.113.31")}})
	if a, err := w.allocate(tn); err != nil || a.HostID != h.ID || a.PublicEntryIPv4.String() != "203.0.113.31" {
		t.Errorf("active again: %+v %v", a, err)
	}
}

// TestCapacityShrinkRace — PATCH capacity takes the host row lock placement takes: allocations racing a capacity cut
// never leave more live instances than the capacity, and a refused cut was refused because the instances were there.
func TestCapacityShrinkRace(t *testing.T) {
	w := newHostWorld(t)
	ctx := apiCtx(t.Context(), uuid.Must(uuid.NewV7()), "req-race-"+w.sfx)
	const rounds, tenants, cut = 8, 6, 2
	var applied, refused int
	for round := range rounds {
		region := w.region(fmt.Sprintf("race%d", round))
		h, err := w.svc.CreateHost(ctx, platform.HostConfig{Name: fmt.Sprintf("hr%d-%s", round, w.sfx), Region: region,
			MaxInstances: i64(tenants), PublicEntry: platform.PublicEntry{IPv4: ptr("203.0.113.40")},
			RunUIDRange: platform.IntRange{First: 30000, Last: 30099}, TenantNetPool: "10.250.0.0/24"}, platform.HostWrite{})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]uuid.UUID, tenants)
		for i := range ids {
			ids[i] = w.tenantIn(fmt.Sprintf("r%d-%d", round, i), region)
		}
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			placed   int
			patchErr error
		)
		start := make(chan struct{})
		for i := range tenants {
			wg.Go(func() {
				<-start
				if _, err := w.allocate(ids[i]); err == nil {
					mu.Lock()
					placed++
					mu.Unlock()
				}
			})
		}
		wg.Go(func() {
			<-start
			time.Sleep(time.Duration(round) * 3 * time.Millisecond) // later and later: both orders occur
			_, patchErr = w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{MaxInstances: i64(cut)}, platform.HostWrite{IfMatch: h.ETag})
		})
		close(start)
		wg.Wait()
		v, err := w.svc.GetHost(ctx, h.ID)
		if err != nil {
			t.Fatal(err)
		}
		var conf *platform.HostConflictError
		switch {
		case patchErr == nil && (v.MaxInstances != cut || v.Usage.LiveInstances > cut):
			t.Errorf("round %d: cut applied, %d live instances for a capacity of %d", round, v.Usage.LiveInstances, v.MaxInstances)
		case patchErr != nil && (!errors.As(patchErr, &conf) || conf.Reason != platform.ConflictCapacityBelowLive || conf.Live <= cut):
			t.Errorf("round %d: cut refused with %v", round, patchErr)
		case v.Usage.LiveInstances != placed:
			t.Errorf("round %d: %d allocations succeeded, %d live", round, placed, v.Usage.LiveInstances)
		}
		if patchErr == nil {
			applied++
		} else {
			refused++
		}
	}
	t.Logf("%d rounds: capacity cut applied in %d (then at most %d placed), refused in %d (more than %d already live)",
		rounds, applied, cut, refused, cut)
}

// TestHostConcurrentPatches — two PATCH with the same ETag: exactly one wins, the other gets 412 (no lost update).
func TestHostConcurrentPatches(t *testing.T) {
	w := newHostWorld(t)
	ctx := apiCtx(t.Context(), uuid.Must(uuid.NewV7()), "req-cc-"+w.sfx)
	h, err := w.svc.CreateHost(ctx, platform.HostConfig{Name: "hc-" + w.sfx, Region: w.region("cc"),
		RunUIDRange: platform.IntRange{First: 30000, Last: 30099}, TenantNetPool: "10.250.0.0/24"}, platform.HostWrite{})
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			_, errs[i] = w.svc.UpdateHost(ctx, h.ID, platform.HostPatch{MaxInstances: i64(int64(10 + i))}, platform.HostWrite{IfMatch: h.ETag})
		})
	}
	close(start)
	wg.Wait()
	var ok, stale []int
	for i, err := range errs {
		switch {
		case err == nil:
			ok = append(ok, i)
		case errors.Is(err, platform.ErrPreconditionFailed):
			stale = append(stale, i)
		default:
			t.Errorf("patch %d: %v", i, err)
		}
	}
	sort.Ints(ok)
	v, err := w.svc.GetHost(ctx, h.ID)
	if len(ok) != 1 || len(stale) != n-1 || err != nil || int64(v.MaxInstances) != int64(10+ok[0]) {
		t.Errorf("%d won, %d stale; capacity %d (%v)", len(ok), len(stale), v.MaxInstances, err)
	}
	if strings.Count(fmt.Sprint(errs), "changed since") != n-1 {
		t.Logf("errors %v", errs)
	}
}

// TestHostJSONParity — the two jsonb objects of the API body are read the way the CHECKs read the columns: each raw
// document is parsed by ParseCapacity / ParsePublicEntry (then validated with a valid rest of the host) and written as
// is into hosts as superuser (rolled back); both must agree on every case.
func TestHostJSONParity(t *testing.T) {
	w := newWorld(t, 2, platform.PlacerOptions{})
	ctx := t.Context()
	insert := func(capacity, entry string) error {
		tx, err := w.su.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		_, err = tx.Exec(ctx, `INSERT INTO hosts (name, region, capacity, public_entry, run_uid_range, tenant_net_pool)
			VALUES ($1, 'lab', $2::text::jsonb, $3::text::jsonb, int4range(30000, 40000), '10.250.0.0/16')`,
			"json-"+w.sfx, capacity, entry)
		return err
	}
	base := func() platform.HostConfig {
		return platform.HostConfig{Name: "json-" + w.sfx, Region: "lab", RunUIDRange: platform.IntRange{First: 30000, Last: 39999},
			TenantNetPool: "10.250.0.0/16"}
	}
	var agree int
	for _, c := range []struct {
		capacity string
		valid    bool
	}{
		{`{"max_instances": 0}`, true}, {`{"max_instances": 100}`, true}, {`{"max_instances": 2147483647}`, true},
		{`{"max_instances": 1e2}`, true}, {`{"max_instances": 1.5e1}`, true}, {`{"max_instances": -0}`, true},
		{`{"max_instances": 0e5}`, true}, {`{"max_instances": 2.147483647e9}`, true},
		{`{"max_instances": 10.0}`, false}, {`{"max_instances": 1.5}`, false}, {`{"max_instances": 1.50e1}`, false},
		{`{"max_instances": 100e-1}`, false}, {`{"max_instances": -1}`, false}, {`{"max_instances": -0.0}`, false},
		{`{"max_instances": 2147483648}`, false}, {`{"max_instances": 1e10}`, false}, {`{"max_instances": 99999999999}`, false},
		{`{"max_instances": "100"}`, false}, {`{"max_instances": null}`, false}, {`{"max_instances": true}`, false},
		{`{"max_instances": [1]}`, false}, {`{}`, false}, {`{"max_instances": 1, "cpus": 2}`, false}, {`[]`, false},
		{`100`, false}, {`"x"`, false},
	} {
		n, fe := platform.ParseCapacity([]byte(c.capacity))
		if len(fe) == 0 {
			cfg := base()
			cfg.MaxInstances = &n
			fe = cfg.Check()
		}
		dbErr := insert(c.capacity, `{}`)
		switch {
		case (len(fe) == 0) != c.valid || (dbErr == nil) != c.valid:
			t.Errorf("capacity %s: want valid=%v — service %+v, database %v", c.capacity, c.valid, fe, dbErr)
		default:
			agree++
		}
	}
	for _, c := range []struct {
		entry string
		valid bool
	}{
		{`{}`, true}, {`{"ipv4": "203.0.113.7"}`, true}, {`{"mode": "direct"}`, true},
		{`{"ipv4": "203.0.113.7", "mode": "vps_gateway"}`, true}, {`{"mode": "direct", "mode": "vps_gateway"}`, true},
		{`{"ipv4": "\u0032\u0030\u0033.0.113.7"}`, true},
		{`{"ipv6": "2001:db8::1"}`, false}, {`{"ipv4": "203.0.113.7", "ipv6": "2001:db8::1"}`, false},
		{`{"ipv4": "203.0.113.7", "port": 443}`, false}, {`{"ipv4": null}`, false}, {`{"mode": null}`, false},
		{`{"ipv4": 3405803783}`, false}, {`{"mode": 1}`, false}, {`{"mode": "VPS_GATEWAY"}`, false},
		{`{"ipv4": ["203.0.113.7"]}`, false}, {`{"ipv4": "10.250.0.9"}`, false}, {`{"ipv4": "203.0.113.007"}`, false},
		{`[]`, false}, {`"203.0.113.7"`, false},
	} {
		e, fe := platform.ParsePublicEntry([]byte(c.entry))
		if len(fe) == 0 {
			cfg := base()
			cfg.PublicEntry = e
			fe = cfg.Check()
		}
		dbErr := insert(`{"max_instances": 100}`, c.entry)
		switch {
		case (len(fe) == 0) != c.valid || (dbErr == nil) != c.valid:
			t.Errorf("public_entry %s: want valid=%v — service %+v, database %v", c.entry, c.valid, fe, dbErr)
		default:
			agree++
		}
	}
	t.Logf("jsonb parity: %d documents, service and database agree on every one", agree)
}
