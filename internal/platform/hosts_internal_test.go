package platform

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

func sp(s string) *string { return &s }

func i64(v int64) *int64 { return &v }

func validConfig() HostConfig {
	m := int64(100)
	return HostConfig{Name: "mg-staging", Region: "lab", Status: HostActive, MaxInstances: &m,
		PublicEntry: PublicEntry{IPv4: sp("203.0.113.7"), Mode: sp(EntryVPSGateway)},
		RunUIDRange: IntRange{First: 30000, Last: 39999}, TenantNetPool: "10.250.0.0/16"}
}

// TestCheckConfigFields — each rule names its field and a stable code; the messages never quote the value. The
// complete comparison with the CHECKs of the database is TestHostConfigParity (hosts_test.go, PostgreSQL).
func TestCheckConfigFields(t *testing.T) {
	if fe := validConfig().Check(); len(fe) != 0 {
		t.Fatalf("valid config refused: %+v", fe)
	}
	defaults := HostConfig{Name: "h1", Region: "lab", RunUIDRange: IntRange{First: 30000, Last: 30010}, TenantNetPool: "10.250.0.0/16"}
	if c := defaults.config(); c.status != HostActive || c.maxInstances != DefaultMaxInstances || c.ipv4 != nil || c.mode != nil || c.stun != nil {
		t.Fatalf("defaults: %+v", c)
	}
	for _, c := range []struct {
		name  string
		mut   func(*HostConfig)
		field string
		code  string
	}{
		{"name not a label", func(c *HostConfig) { c.Name = "Bad_Name" }, "name", "invalid_format"},
		{"region with space", func(c *HostConfig) { c.Region = "two words" }, "region", "invalid_format"},
		{"region empty", func(c *HostConfig) { c.Region = "" }, "region", "invalid_format"},
		{"status", func(c *HostConfig) { c.Status = "maintenance" }, "status", "invalid_value"},
		{"capacity negative", func(c *HostConfig) { c.MaxInstances = i64(-1) }, "capacity.max_instances", "out_of_range"},
		{"capacity above int4", func(c *HostConfig) { c.MaxInstances = i64(1 << 31) }, "capacity.max_instances", "out_of_range"},
		{"mode", func(c *HostConfig) { c.PublicEntry.Mode = sp("gateway") }, "public_entry.mode", "invalid_value"},
		{"mode empty", func(c *HostConfig) { c.PublicEntry.Mode = sp("") }, "public_entry.mode", "invalid_value"},
		{"ipv4 empty", func(c *HostConfig) { c.PublicEntry.IPv4 = sp("") }, "public_entry.ipv4", "invalid_format"},
		{"ipv4 leading zero", func(c *HostConfig) { c.PublicEntry.IPv4 = sp("203.0.113.07") }, "public_entry.ipv4", "invalid_format"},
		{"ipv4 with prefix", func(c *HostConfig) { c.PublicEntry.IPv4 = sp("203.0.113.7/32") }, "public_entry.ipv4", "invalid_format"},
		{"ipv6", func(c *HostConfig) { c.PublicEntry.IPv4 = sp("2001:db8::1") }, "public_entry.ipv4", "invalid_format"},
		{"loopback", func(c *HostConfig) { c.PublicEntry.IPv4 = sp("127.0.0.1") }, "public_entry.ipv4", "not_unicast"},
		{"multicast", func(c *HostConfig) { c.PublicEntry.IPv4 = sp("239.1.2.3") }, "public_entry.ipv4", "not_unicast"},
		{"inside pool", func(c *HostConfig) { c.PublicEntry.IPv4 = sp("10.250.3.4") }, "public_entry.ipv4", "inside_pool"},
		{"pool host bits", func(c *HostConfig) { c.TenantNetPool = "10.250.0.1/16" }, "tenant_net_pool", "invalid_value"},
		{"pool /30", func(c *HostConfig) { c.TenantNetPool = "10.250.0.0/30" }, "tenant_net_pool", "invalid_value"},
		{"pool tailnet", func(c *HostConfig) { c.TenantNetPool = "100.100.0.0/16" }, "tenant_net_pool", "invalid_value"},
		{"pool abbreviated", func(c *HostConfig) { c.TenantNetPool = "10.250/16" }, "tenant_net_pool", "invalid_value"},
		{"uid first", func(c *HostConfig) { c.RunUIDRange.First = 999 }, "run_uid_range.first", "out_of_range"},
		{"uid last", func(c *HostConfig) { c.RunUIDRange.Last = 1 << 31 }, "run_uid_range.last", "out_of_range"},
		{"uid empty", func(c *HostConfig) { c.RunUIDRange = IntRange{First: 40000, Last: 30000} }, "run_uid_range", "empty_range"},
		{"uid reserved", func(c *HostConfig) { c.RunUIDRange = IntRange{First: 20000, Last: 20010} }, "run_uid_range", "reserved_id"},
		{"stun low", func(c *HostConfig) { c.STUNPortRange = &IntRange{First: 1023, Last: 2000} }, "stun_port_range.first", "out_of_range"},
		{"stun high", func(c *HostConfig) { c.STUNPortRange = &IntRange{First: 2000, Last: 65536} }, "stun_port_range.last", "out_of_range"},
		{"stun empty", func(c *HostConfig) { c.STUNPortRange = &IntRange{First: 3000, Last: 2999} }, "stun_port_range", "empty_range"},
	} {
		cfg := validConfig()
		c.mut(&cfg)
		fe := cfg.Check()
		if len(fe) != 1 || fe[0].Field != c.field || fe[0].Code != c.code {
			t.Errorf("%s: %+v, want one error %s/%s", c.name, fe, c.field, c.code)
			continue
		}
		for _, v := range []string{"203.0.113.07", "10.250.3.4", "Bad_Name", "two words", "2001:db8::1"} {
			if strings.Contains(fe[0].Message, v) {
				t.Errorf("%s: the message quotes the value: %q", c.name, fe[0].Message)
			}
		}
	}
	// a PATCH applies the rules left to code to the fields it changes only
	after := configOf(Host{Region: "old region", Status: HostActive, MaxInstances: 1, RunUIDFirst: 20000, RunUIDLast: 20010,
		TenantNetPool: netip.MustParsePrefix("10.250.0.0/16")})
	if fe := checkConfig(nil, after, codeRules{}); len(fe) != 0 {
		t.Errorf("unchanged legacy fields refused: %+v", fe)
	}
	if fe := checkConfig(nil, after, allCodeRules); len(fe) != 2 {
		t.Errorf("legacy fields under every rule: %+v", fe)
	}
}

// TestHostETag — the ETag covers every managed field and the host id, and nothing else (no heartbeat, no timestamps).
func TestHostETag(t *testing.T) {
	base := Host{ID: uuid.MustParse("0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f51"), Name: "h", Region: "lab", Status: HostActive,
		RunUIDFirst: 30000, RunUIDLast: 39999, TenantNetPool: netip.MustParsePrefix("10.250.0.0/16"), MaxInstances: 100,
		PublicEntry: netip.MustParseAddr("203.0.113.7"), EntryMode: EntryVPSGateway}
	e := hostETag(base)
	if len(e) != 34 || e[0] != '"' || e[33] != '"' || hostETag(base) != e {
		t.Fatalf("etag %q", e)
	}
	seen := map[string]string{e: "base"}
	for name, mut := range map[string]func(*Host){
		"id":       func(h *Host) { h.ID = uuid.New() },
		"region":   func(h *Host) { h.Region = "lab2" },
		"status":   func(h *Host) { h.Status = HostDraining },
		"capacity": func(h *Host) { h.MaxInstances = 99 },
		"ipv4":     func(h *Host) { h.PublicEntry = netip.MustParseAddr("203.0.113.8") },
		"no ipv4":  func(h *Host) { h.PublicEntry = netip.Addr{} },
		"mode":     func(h *Host) { h.EntryMode = EntryDirect },
		"uid":      func(h *Host) { h.RunUIDLast = 39998 },
		"stun":     func(h *Host) { h.STUNPortFirst, h.STUNPortLast = 3479, 3500 },
		"pool":     func(h *Host) { h.TenantNetPool = netip.MustParsePrefix("10.251.0.0/16") },
	} {
		h := base
		mut(&h)
		got := hostETag(h)
		if prev, dup := seen[got]; dup {
			t.Errorf("%s: same etag as %s", name, prev)
		}
		seen[got] = name
	}
	if h := base; hostETag(Host{ID: h.ID, Name: "other name", Region: h.Region, Status: h.Status, RunUIDFirst: h.RunUIDFirst,
		RunUIDLast: h.RunUIDLast, TenantNetPool: h.TenantNetPool, MaxInstances: h.MaxInstances, PublicEntry: h.PublicEntry,
		EntryMode: h.EntryMode}) != e {
		t.Error("the immutable name changes the etag")
	}
}

func TestIfMatchState(t *testing.T) {
	cur := `"0123456789abcdef0123456789abcdef"`
	for in, want := range map[string]error{
		"":                       ErrPreconditionRequired,
		"  ":                     ErrPreconditionRequired,
		"*":                      ErrPreconditionRequired,
		cur:                      nil,
		" " + cur + " ":          nil,
		`"other", ` + cur:        nil,
		`"other"`:                ErrPreconditionFailed,
		"W/" + cur:               ErrPreconditionFailed, // weak tags never match strongly
		strings.Trim(cur, `"`):   ErrPreconditionFailed, // unquoted
		`"other", "and another"`: ErrPreconditionFailed,
	} {
		if got := ifMatchState(in, cur); !errors.Is(got, want) || (want == nil && got != nil) {
			t.Errorf("If-Match %q: %v, want %v", in, got, want)
		}
	}
}

func TestPatchApplyAndChanged(t *testing.T) {
	cur := configOf(Host{Region: "lab", Status: HostActive, MaxInstances: 100, RunUIDFirst: 30000, RunUIDLast: 39999,
		TenantNetPool: netip.MustParsePrefix("10.250.0.0/16"), PublicEntry: netip.MustParseAddr("203.0.113.7"),
		EntryMode: EntryDirect})
	if d := changed(cur, HostPatch{}.apply(cur)); len(d) != 0 {
		t.Fatalf("empty patch changes %v", d)
	}
	if !(HostPatch{}).empty() || (HostPatch{Status: sp(HostActive)}).empty() {
		t.Error("empty()")
	}
	same := HostPatch{Status: sp(HostActive), PublicEntry: &PublicEntry{IPv4: sp("203.0.113.7"), Mode: sp(EntryDirect)}}
	if d := changed(cur, same.apply(cur)); len(d) != 0 {
		t.Errorf("patch to the same values changes %v", d)
	}
	m := int64(5)
	all := HostPatch{Region: sp("hn1"), Status: sp(HostDraining), MaxInstances: &m, PublicEntry: &PublicEntry{},
		RunUIDRange: &IntRange{First: 30000, Last: 30099}, STUNPortRange: &IntRange{First: 4000, Last: 4010},
		TenantNetPool: sp("10.251.0.0/16")}
	after := all.apply(cur)
	want := []string{"region", "status", "capacity", "public_entry", "run_uid_range", "stun_port_range", "tenant_net_pool"}
	if d := changed(cur, after); !slices.Equal(d, want) {
		t.Errorf("changed %v, want %v", d, want)
	}
	if after.ipv4 != nil || after.mode != nil || string(after.publicEntryJSON()) != "{}" {
		t.Errorf("public_entry {} must clear it: %s", after.publicEntryJSON())
	}
	if string(after.capacityJSON()) != `{"max_instances":5}` {
		t.Errorf("capacity %s", after.capacityJSON())
	}
	if d := changed(cur, (HostPatch{PublicEntry: &PublicEntry{IPv4: sp("203.0.113.7")}}).apply(cur)); !slices.Equal(d, []string{"public_entry"}) {
		t.Errorf("dropping the mode: %v", d)
	}
	if cur.stunRange().Valid || !after.stunRange().Valid {
		t.Error("stun range NULL / set")
	}
}

func TestUsageOf(t *testing.T) {
	h := Host{RunUIDFirst: 19999, RunUIDLast: 20010, TenantNetPool: netip.MustParsePrefix("10.250.0.0/27")}
	// 12 UIDs, 8 of them reserved (20001…20008) ⇒ 4 usable; /27 ⇒ 4 slots
	rows := []sqlcdb.ListHostAllocationsRow{
		{Status: "running", RunUid: 19999, NetCidr: netip.MustParsePrefix("10.250.0.0/29")},
		{Status: "removed", RunUid: 20000, NetCidr: netip.MustParsePrefix("10.250.0.8/29")}, // UID consumed, slot free
		{Status: "allocated", RunUid: 20009, NetCidr: netip.MustParsePrefix("10.250.0.8/29")},
		{Status: "failed", RunUid: 30000, NetCidr: netip.MustParsePrefix("10.99.0.0/29")}, // outside both ranges
	}
	u := usageOf(h, rows)
	if u.LiveInstances != 3 || u.ByStatus["running"] != 1 || u.ByStatus["allocated"] != 1 || u.ByStatus["failed"] != 1 ||
		u.ByStatus["removed"] != 0 {
		t.Errorf("live %d by status %v", u.LiveInstances, u.ByStatus)
	}
	if u.RunUIDsFree != 1 || u.NetSlotsFree != 2 {
		t.Errorf("free UIDs %d (want 1), free /29 %d (want 2)", u.RunUIDsFree, u.NetSlotsFree)
	}
	if u := usageOf(Host{RunUIDFirst: 30000, RunUIDLast: 39999, TenantNetPool: netip.MustParsePrefix("10.250.0.0/16")}, nil); u.RunUIDsFree != 10000 || u.NetSlotsFree != 8192 || u.LiveInstances != 0 {
		t.Errorf("empty host: %+v", u)
	}
}

func TestHostErrors(t *testing.T) {
	v := &ValidationError{Fields: []FieldError{{Field: "status", Code: "invalid_value"}}}
	if !errors.Is(v, ErrInvalid) || errors.Is(v, ErrConflict) || !strings.Contains(v.Error(), "status (invalid_value)") {
		t.Errorf("validation error: %v", v)
	}
	for _, c := range []*HostConflictError{{Reason: ConflictNameTaken}, {Reason: ConflictCapacityBelowLive, Live: 3},
		{Reason: ConflictAllocationInUse, Fields: []string{"run_uid_range"}, Live: 1}} {
		if !errors.Is(c, ErrConflict) || errors.Is(c, ErrInvalid) || c.Error() == "" {
			t.Errorf("conflict %+v: %v", c, c)
		}
	}
	if b := (&IdempotencyBusyError{}); !errors.Is(b, ErrIdempotencyInProgress) {
		t.Error("busy")
	}
}

// TestNumericInteger — the PostgreSQL reading of a JSON number (display scale = max(0, fraction digits - exponent)).
func TestNumericInteger(t *testing.T) {
	for s, want := range map[string]int64{"0": 0, "100": 100, "1e2": 100, "1E+2": 100, "1.5e1": 15, "15e0": 15, "-0": 0,
		"0e9": 0, "0.0e1": 0, "2147483647": 2147483647, "2.147483647e9": 2147483647, "1000000000": 1000000000} {
		if n, ok := numericInteger(s, 2147483647); !ok || n != want {
			t.Errorf("%s: %d %v, want %d", s, n, ok, want)
		}
	}
	for _, s := range []string{"10.0", "1.5", "1.50e1", "100e-1", "-1", "-0.0", "2147483648", "1e10", "99999999999", "1e1001",
		"", "abc", "1e", "+1", "0x10", "1_000"} {
		if n, ok := numericInteger(s, 2147483647); ok {
			t.Errorf("%s accepted as %d", s, n)
		}
	}
}

func TestParseCapacityAndPublicEntry(t *testing.T) {
	if n, fe := ParseCapacity([]byte(`{"max_instances": 1e2}`)); n != 100 || fe != nil {
		t.Errorf("1e2: %d %v", n, fe)
	}
	for raw, field := range map[string]string{
		`{}`: "capacity.max_instances", `{"max_instances": null}`: "capacity.max_instances",
		`{"max_instances": "10"}`: "capacity.max_instances", `{"max_instances": 10.0}`: "capacity.max_instances",
		`{"max_instances": 1, "cpu": 2}`: "capacity", `[]`: "capacity", `10`: "capacity", `null`: "capacity",
		`{"max_instances": 1} {}`: "capacity",
	} {
		if _, fe := ParseCapacity([]byte(raw)); len(fe) != 1 || fe[0].Field != field {
			t.Errorf("capacity %s: %+v, want %s", raw, fe, field)
		}
	}
	e, fe := ParsePublicEntry([]byte(`{"mode": "direct", "ipv4": "203.0.113.7", "mode": "vps_gateway"}`)) // the last duplicate wins, as in jsonb
	if fe != nil || e.IPv4 == nil || *e.IPv4 != "203.0.113.7" || e.Mode == nil || *e.Mode != "vps_gateway" {
		t.Errorf("entry: %+v %v", e, fe)
	}
	if e, fe := ParsePublicEntry([]byte(`{}`)); fe != nil || e.IPv4 != nil || e.Mode != nil {
		t.Errorf("empty entry: %+v %v", e, fe)
	}
	for raw, fields := range map[string]string{
		`{"ipv6": "2001:db8::1"}`: "public_entry", `{"ipv4": null}`: "public_entry.ipv4", `{"mode": 1}`: "public_entry.mode",
		`{"ipv4": "203.0.113.7", "x": 1, "y": 2}`: "public_entry", `{"ipv4": 1, "mode": null}`: "public_entry.ipv4 public_entry.mode",
		`"203.0.113.7"`: "public_entry", `[]`: "public_entry",
	} {
		_, fe := ParsePublicEntry([]byte(raw))
		got := make([]string, len(fe))
		for i, f := range fe {
			got[i] = f.Field
		}
		if strings.Join(got, " ") != fields {
			t.Errorf("entry %s: %v, want %s", raw, got, fields)
		}
	}
}
