package platform

// Unit tests of the allocation rules of placement.go (no database): smallest free UID / port, lowest free /29, the
// decision for one host, the order among hosts, the parsing of the jsonb columns, the reserved IDs against
// versions.lock, and the mapping of constraint violations to retries and typed errors.

import (
	"bufio"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestSmallestFree(t *testing.T) {
	used := map[int32]bool{30000: true, 30001: true, 30003: true}
	taken := func(v int32) bool { return used[v] }
	for _, c := range []struct {
		first, last, want int32
		ok                bool
	}{
		{30000, 39999, 30002, true},
		{30003, 30003, 0, false},
		{30000, 30001, 0, false},
		{30004, 30004, 30004, true},
		{5, 4, 0, false},
		{2147483646, 2147483647, 2147483646, true}, // no overflow at the top of int32
	} {
		if got, ok := smallestFree(c.first, c.last, taken); got != c.want || ok != c.ok {
			t.Errorf("smallestFree(%d, %d) = %d, %v; want %d, %v", c.first, c.last, got, ok, c.want, c.ok)
		}
	}
	if _, ok := smallestFree(2147483647, 2147483647, func(int32) bool { return true }); ok {
		t.Error("full range at the top of int32")
	}
}

func TestSmallestFreeNet(t *testing.T) {
	for _, c := range []struct {
		name string
		pool string
		used []string
		want string // "" = none
	}{
		{"empty pool", "10.250.0.0/16", nil, "10.250.0.0/29"},
		{"first two taken", "10.250.0.0/16", []string{"10.250.0.8/29", "10.250.0.0/29"}, "10.250.0.16/29"},
		{"gap reused", "10.250.0.0/16", []string{"10.250.0.0/29", "10.250.0.16/29"}, "10.250.0.8/29"},
		{"a /28 blocks two", "10.250.0.0/16", []string{"10.250.0.0/28"}, "10.250.0.16/29"},
		{"unaligned foreign net", "10.250.0.0/16", []string{"10.250.0.4/30"}, "10.250.0.8/29"},
		{"nets outside the pool ignored", "10.250.0.0/16", []string{"10.251.0.0/29", "192.168.0.0/16"}, "10.250.0.0/29"},
		{"a supernet blocks the pool", "10.250.0.0/16", []string{"10.0.0.0/8"}, ""},
		{"pool /29 free", "10.250.7.8/29", nil, "10.250.7.8/29"},
		{"pool /29 full", "10.250.7.8/29", []string{"10.250.7.8/29"}, ""},
		{"pool /28 one left", "10.250.7.0/28", []string{"10.250.7.0/29"}, "10.250.7.8/29"},
		{"pool /28 full", "10.250.7.0/28", []string{"10.250.7.8/29", "10.250.7.0/29"}, ""},
		{"top of the address space", "255.255.255.0/29", nil, "255.255.255.0/29"},
		{"top of the address space full", "255.255.255.248/29", []string{"255.255.255.248/29"}, ""},
		{"IPv6 pool refused", "fd00::/64", nil, ""},
		{"pool /30 refused", "10.250.0.0/30", nil, ""},
	} {
		var used []netip.Prefix
		for _, u := range c.used {
			used = append(used, pfx(u))
		}
		got, ok := smallestFreeNet(pfx(c.pool), used)
		if c.want == "" {
			if ok {
				t.Errorf("%s: got %s, want none", c.name, got)
			}
			continue
		}
		if !ok || got != pfx(c.want) {
			t.Errorf("%s: got %s (%v), want %s", c.name, got, ok, c.want)
		}
	}
	// a /22 pool holds exactly 128 subnets, handed out in order, all distinct and inside the pool
	pool := pfx("10.250.4.0/22")
	var used []netip.Prefix
	for i := range 128 {
		n, ok := smallestFreeNet(pool, used)
		if !ok || n.Bits() != 29 || !pool.Contains(n.Addr()) || slices.Contains(used, n) {
			t.Fatalf("subnet %d: %s %v", i, n, ok)
		}
		used = append(used, n)
	}
	if n, ok := smallestFreeNet(pool, used); ok {
		t.Errorf("129th subnet of a /22: %s", n)
	}
}

func testHost() Host {
	return Host{Name: "h1", Status: HostActive, RunUIDFirst: 30000, RunUIDLast: 30009, TenantNetPool: pfx("10.250.0.0/28"),
		MaxInstances: 5, PublicEntry: netip.MustParseAddr("203.0.113.7")}
}

func TestPlanHost(t *testing.T) {
	p32 := func(v int32) *int32 { return &v }
	h := testHost()
	plan, reason := planHost(h, nil, false)
	if reason != "" || plan.runUID != 30000 || plan.net != pfx("10.250.0.0/29") || plan.stunPort != 0 || plan.live != 0 {
		t.Fatalf("empty host: %+v %q", plan, reason)
	}
	// removed rows keep their UID but free their subnet and port
	rows := []allocRow{{removed: true, runUID: 30000, net: pfx("10.250.0.0/29"), stunPort: p32(40000)},
		{runUID: 30001, net: pfx("10.250.0.8/29")}}
	if plan, reason = planHost(h, rows, false); reason != "" || plan.runUID != 30002 || plan.net != pfx("10.250.0.0/29") ||
		plan.live != 1 {
		t.Errorf("after a removed instance: %+v %q", plan, reason)
	}
	// reserved IDs are skipped
	r := h
	r.RunUIDFirst, r.RunUIDLast = 10000, 10002
	if plan, reason = planHost(r, []allocRow{{runUID: 10000, net: pfx("10.250.0.0/29")}}, false); reason != "" || plan.runUID != 10002 {
		t.Errorf("reserved 10001 not skipped: %+v %q", plan, reason)
	}
	for name, c := range map[string]struct {
		mod  func(*Host)
		rows []allocRow
		stun bool
		want string
	}{
		"no public entry": {func(h *Host) { h.PublicEntry = netip.Addr{} }, nil, false, RejectNoPublicEntry},
		"capacity 0":      {func(h *Host) { h.MaxInstances = 0 }, nil, false, RejectFull},
		"full":            {func(h *Host) { h.MaxInstances = 1 }, []allocRow{{runUID: 30000, net: pfx("10.250.0.0/29")}}, false, RejectFull},
		"removed rows do not fill": {func(h *Host) { h.MaxInstances = 1 },
			[]allocRow{{removed: true, runUID: 30000, net: pfx("10.250.0.0/29")}}, false, ""},
		"UIDs used by removed rows": {func(h *Host) { h.RunUIDLast = 30001 },
			[]allocRow{{removed: true, runUID: 30000}, {removed: true, runUID: 30001}}, false, RejectRunUIDExhausted},
		"pool full": {nil, []allocRow{{runUID: 30000, net: pfx("10.250.0.0/29")}, {runUID: 30001, net: pfx("10.250.0.8/29")}},
			false, RejectNetPoolExhausted},
		"STUN without range": {nil, nil, true, RejectSTUNRangeMissing},
		"STUN ports in use": {func(h *Host) { h.STUNPortFirst, h.STUNPortLast = 3478, 3479 },
			[]allocRow{{runUID: 30000, net: pfx("10.250.0.0/29"), stunPort: p32(3479)}}, true, RejectSTUNExhausted},
	} {
		hh := testHost()
		if c.mod != nil {
			c.mod(&hh)
		}
		if _, got := planHost(hh, c.rows, c.stun); got != c.want {
			t.Errorf("%s: reason %q, want %q", name, got, c.want)
		}
	}
	s := testHost()
	s.STUNPortFirst, s.STUNPortLast = 3478, 3481
	rows = []allocRow{{runUID: 30000, net: pfx("10.250.0.0/29"), stunPort: p32(3479)}, {removed: true, runUID: 30001, stunPort: p32(3480)}}
	if plan, reason = planHost(s, rows, true); reason != "" || plan.stunPort != 3480 {
		t.Errorf("STUN: %+v %q — want 3480 (3478 is the shared STUN, 3479 in use, 3480 freed by a removed instance)", plan, reason)
	}
}

func TestLessUsed(t *testing.T) {
	mk := func(name string, live int64, maxInst int32) hostPlan {
		return hostPlan{host: Host{Name: name, MaxInstances: maxInst}, live: live}
	}
	plans := []hostPlan{mk("c", 5, 10), mk("b", 1, 10), mk("a", 1, 10), mk("d", 1, 2), mk("e", 0, 1)}
	slices.SortStableFunc(plans, func(x, y hostPlan) int {
		switch {
		case lessUsed(x, y):
			return -1
		case lessUsed(y, x):
			return 1
		}
		return 0
	})
	var got []string
	for _, p := range plans {
		got = append(got, p.host.Name)
	}
	if want := []string{"e", "a", "b", "c", "d"}; !slices.Equal(got, want) { // 0, 0.1, 0.1, 0.5, 0.5 — ties by name
		t.Errorf("order %v, want %v", got, want)
	}
}

func TestParseHostSettings(t *testing.T) {
	maxInst, entry, mode, err := parseHostSettings([]byte(`{"max_instances": 100}`), []byte(`{"ipv4": "203.0.113.7", "mode": "vps_gateway"}`))
	if err != nil || maxInst != 100 || entry != netip.MustParseAddr("203.0.113.7") || mode != "vps_gateway" {
		t.Fatalf("= %d %s %q %v", maxInst, entry, mode, err)
	}
	if maxInst, entry, _, err = parseHostSettings([]byte(`{}`), []byte(`{}`)); err != nil || maxInst != 0 || entry.IsValid() {
		t.Errorf("empty: %d %s %v (undeclared ⇒ capacity 0, no entry: the host takes nothing)", maxInst, entry, err)
	}
	for name, c := range map[string][2]string{
		"capacity fraction":   {`{"max_instances": 1.5}`, `{}`},
		"capacity too large":  {`{"max_instances": 2147483648}`, `{}`},
		"capacity negative":   {`{"max_instances": -1}`, `{}`},
		"capacity string":     {`{"max_instances": "10"}`, `{}`},
		"entry not canonical": {`{"max_instances": 1}`, `{"ipv4": "203.0.113.07"}`},
		"entry IPv6":          {`{"max_instances": 1}`, `{"ipv4": "2001:db8::1"}`},
		"entry not JSON":      {`{"max_instances": 1}`, `[`},
	} {
		if _, _, _, err := parseHostSettings([]byte(c[0]), []byte(c[1])); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestReservedIDsCoverVersionsLock keeps ReservedIDs in step with versions.lock [ids] (as the agent's list).
func TestReservedIDsCoverVersionsLock(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "versions.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	num := regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*(\d+)\s*(#.*)?$`)
	in, n := false, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			in = strings.HasPrefix(line, "[ids]")
			continue
		}
		if m := num.FindStringSubmatch(line); in && m != nil {
			v, _ := strconv.ParseInt(m[2], 10, 32)
			n++
			if !slices.Contains(ReservedIDs, int32(v)) {
				t.Errorf("versions.lock [ids] %s = %d is not in ReservedIDs", m[1], v)
			}
		}
	}
	if n < 10 {
		t.Fatalf("read only %d numeric ids from versions.lock [ids]", n)
	}
	// the host registration refuses a range holding one of them
	spec := HostSpec{Name: "h", Region: "lab", RunUIDFirst: 20000, RunUIDLast: 20010, TenantNetPool: pfx("10.250.0.0/16")}
	if err := spec.validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("range holding 20001..20008: %v", err)
	}
}

func TestRetryAndClassify(t *testing.T) {
	pg := func(code, constraint string) error { return &pgconn.PgError{Code: code, ConstraintName: constraint} }
	for _, c := range []string{"tenant_instances_host_id_run_uid_key", "tenant_instances_net_live_key",
		"tenant_instances_stun_port_live_key"} {
		if !retryable(pg("23505", c)) {
			t.Errorf("%s not retried", c)
		}
	}
	for _, err := range []error{nil, errors.New("x"), pg("23505", "tenant_instances_hostname_live_key"), pg("23514", "tenant_instances_net_cidr_slash29")} {
		if retryable(err) {
			t.Errorf("%v retried", err)
		}
	}
	for c, want := range map[string]error{
		"tenant_instances_hostname_live_key":   ErrHostnameInUse,
		"tenant_instances_one_live_per_tenant": ErrTenantHasInstance,
		"tenant_instances_pkey":                ErrConflict,
		"tenant_instances_host_id_run_uid_key": ErrConflict, // after the last retry
	} {
		if err := classify(pg("23505", c)); !errors.Is(err, want) || !errors.Is(err, ErrConflict) {
			t.Errorf("%s ⇒ %v, want %v", c, err, want)
		}
	}
	other := errors.New("boom")
	if got := classify(other); !errors.Is(got, other) || got.Error() != "boom" || classify(nil) != nil {
		t.Error("classify changed a non-unique error")
	}
}

func TestNoCapacityError(t *testing.T) {
	e := &NoCapacityError{Region: "lab", Rejected: []HostRejection{{Host: "h1", Reason: RejectFull},
		{Host: "h2", Reason: RejectRunUIDExhausted}}}
	var err error = e
	if !errors.Is(err, ErrNoCapacity) || errors.Is(err, ErrConflict) ||
		err.Error() != "platform: no host in region lab can take the instance (h1: capacity_full, h2: run_uid_exhausted)" {
		t.Errorf("%v", err)
	}
	if got := (&NoCapacityError{}).Error(); got != "platform: no active host in any region" {
		t.Errorf("%q", got)
	}
}
