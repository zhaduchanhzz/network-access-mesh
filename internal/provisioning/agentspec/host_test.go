package agentspec

import (
	"bufio"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

func mustUUID(s string) uuid.UUID { return uuid.MustParse(s) }

func TestAllowlist(t *testing.T) {
	good := "# generated from versions.lock\n\n" + repo + "@" + digestA + "   # mg-headscale\n" +
		"docker.io/headscale/headscale@" + digestB + "\n"
	a, err := ParseAllowlist(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if img, ok := a.Lookup(digestA); !ok || img.Reference() != repo+"@"+digestA || a.Len() != 2 {
		t.Fatalf("lookup = %+v %v", img, ok)
	}
	if all := a.All(); len(all) != 2 || all[0].Repository != "docker.io/headscale/headscale" {
		t.Fatalf("All = %+v", all)
	}
	for name, bad := range map[string]string{
		"tag":                 repo + ":v0.29.7\n",
		"tag and digest":      repo + ":v0.29.7@" + digestA + "\n",
		"upper-case digest":   repo + "@" + strings.ToUpper(digestA) + "\n",
		"no registry":         "headscale@" + digestA + "\n",
		"upper-case repo":     "ghcr.io/Org/headscale@" + digestA + "\n",
		"duplicate digest":    repo + "@" + digestA + "\n" + "docker.io/x/y@" + digestA + "\n",
		"trailing garbage":    repo + "@" + digestA + " extra\n",
		"shell metacharacter": "ghcr.io/x/y;rm@" + digestA + "\n",
	} {
		if _, err := ParseAllowlist(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHostCheck(t *testing.T) {
	if err := testHost(t).Check(); err != nil {
		t.Fatalf("good host: %v", err)
	}
	cases := map[string]func(h *Host){
		"relative tenants dir":     func(h *Host) { h.TenantsDir = "tenants" },
		"root as tenants dir":      func(h *Host) { h.TenantsDir = "/" },
		"unclean backups dir":      func(h *Host) { h.BackupsDir = "/opt/meshguard/../backups" },
		"uid range below 1000":     func(h *Host) { h.RunUIDs = Range{Min: 500, Max: 39999} },
		"uid range with 20003":     func(h *Host) { h.RunUIDs = Range{Min: 20000, Max: 29999} },
		"uid range with 65532":     func(h *Host) { h.RunUIDs = Range{Min: 60000, Max: 70000} },
		"uid range with edge":      func(h *Host) { h.RunUIDs = Range{Min: 10000, Max: 10005} },
		"pool not canonical":       func(h *Host) { h.TenantPool = netip.MustParsePrefix("10.250.1.0/16") },
		"pool IPv6":                func(h *Host) { h.TenantPool = netip.MustParsePrefix("fd00::/64") },
		"pool smaller than /29":    func(h *Host) { h.TenantPool = netip.MustParsePrefix("10.250.0.0/30") },
		"public entry in the pool": func(h *Host) { h.PublicEntry = netip.MustParseAddr("10.250.3.4") },
		"public entry loopback":    func(h *Host) { h.PublicEntry = netip.MustParseAddr("127.0.0.1") },
		"STUN range with 3478":     func(h *Host) { h.STUNPorts = &Range{Min: 3000, Max: 4000} },
		"STUN range privileged":    func(h *Host) { h.STUNPorts = &Range{Min: 53, Max: 2000} },
		"bad base domain":          func(h *Host) { h.BaseDomain = "Example.COM" },
		"empty allowlist":          func(h *Host) { h.Images = &Allowlist{} },
	}
	for name, mut := range cases {
		h := testHost(t)
		mut(h)
		if err := h.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestReservedIDsCoverVersionsLock: every numeric UID/GID of versions.lock [ids] is reserved (never a run_uid).
func TestReservedIDsCoverVersionsLock(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "..", "versions.lock"))
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
			in = line == "[ids]" || strings.HasPrefix(line, "[ids]")
			continue
		}
		if m := num.FindStringSubmatch(line); in && m != nil {
			v, _ := strconv.ParseUint(m[2], 10, 32)
			n++
			if !slices.Contains(reservedIDs, uint32(v)) {
				t.Errorf("versions.lock [ids] %s = %d is not in reservedIDs", m[1], v)
			}
		}
	}
	if n < 10 {
		t.Fatalf("read only %d numeric ids from versions.lock [ids]", n)
	}
}

func TestNamesMatchThePhase1Scripts(t *testing.T) {
	h := testHost(t)
	n := h.Names(Ref{InstanceID: mustUUID(instanceID), TenantID: mustUUID(tenantID), Slug: "tenant-a"})
	want := map[string]string{
		n.Dir: filepath.Join(h.TenantsDir, instanceID), n.DataDir: filepath.Join(h.TenantsDir, instanceID, "data"),
		n.MetaFile: filepath.Join(h.TenantsDir, instanceID, "meta", "instance.json"), n.BackupDir: filepath.Join(h.BackupsDir, instanceID),
		n.Network: "mg-t-tenant-a", n.Project: "mg-t-tenant-a", n.Container: "mg-hs-tenant-a", n.Alias: "hs-tenant-a", n.Service: "hs-tenant-a",
		n.RecordsFile: filepath.Join(h.TenantsDir, instanceID, "records", "extra-records.json"),
	}
	for got, w := range want {
		if got != w {
			t.Errorf("name %q, want %q", got, w)
		}
	}
}

func TestPlan(t *testing.T) {
	h := testHost(t)
	s := validSpec(t, h)
	n := h.Names(s.Ref)
	storage := h.Plan(s, agentv1.TargetPhase_TARGET_PHASE_STORAGE)
	all := h.Plan(s, agentv1.TargetPhase_TARGET_PHASE_CONTAINER)
	if len(storage) != 6 || len(all) != 14 {
		t.Fatalf("plan sizes %d/%d", len(storage), len(all))
	}
	for _, a := range all {
		if !strings.HasPrefix(a.Target, n.Dir) && a.Target != n.Network && a.Target != n.Project {
			t.Errorf("target %q outside the instance", a.Target)
		}
		if a.Target == n.DataDir && (a.Uid != 30001 || a.Gid != 30001 || a.Mode != 0o700) {
			t.Errorf("data/ = %d:%d %o", a.Uid, a.Gid, a.Mode)
		}
		if a.Target == n.ConfigFile && (a.Uid != uint32(h.OwnerUID) || a.Mode != 0o440) { //nolint:gosec // test
			t.Errorf("config.yaml = %d %o", a.Uid, a.Mode)
		}
	}
	if storage[0].Target != n.Dir || storage[2].Target != n.MetaFile {
		t.Errorf("meta/instance.json must be written right after the directory: %v", storage)
	}
	if last := all[len(all)-1]; last.Kind != agentv1.PlannedActionKind_PLANNED_ACTION_KIND_COMPOSE_UP || !strings.Contains(last.Detail, "no published port") {
		t.Errorf("last action %v", last)
	}
}
