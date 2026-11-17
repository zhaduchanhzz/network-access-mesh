package compose

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// repoRoot is the repository root seen from this package.
var repoRoot = filepath.Join("..", "..", "..", "..")

// lockImages reads versions.lock [images.<name>] → image@index (a line parser: no TOML library in the module).
func lockImages(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(repoRoot, "versions.lock")) //nolint:gosec // G304: the repository's versions.lock
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	section := regexp.MustCompile(`^\[images\.([a-z0-9-]+)\]`)
	kv := regexp.MustCompile(`^(image|index) = "([^"]+)"`)
	out, cur, image := map[string]string{}, "", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := section.FindStringSubmatch(line); m != nil {
			cur, image = m[1], ""
			continue
		}
		if strings.HasPrefix(line, "[") {
			cur = ""
		}
		if m := kv.FindStringSubmatch(line); m != nil && cur != "" {
			if m[1] == "image" {
				image = m[2]
			} else if image != "" {
				out[cur] = image + "@" + m[2]
			}
		}
	}
	return out
}

// pyParams are the parameters of tools/render_instance.py (after ${MG_*} expansion).
type pyParams struct {
	TenantID     string   `json:"tenant_id"`
	InstanceID   string   `json:"instance_id"`
	Slug         string   `json:"slug"`
	BaseDomain   string   `json:"base_domain"`
	NetCIDR      string   `json:"net_cidr"`
	RunUID       uint32   `json:"run_uid"`
	DERPRegionID uint32   `json:"derp_region_id"`
	DERPIPv4     string   `json:"derp_ipv4"`
	NodeExpiry   string   `json:"node_expiry"`
	Nameservers  []string `json:"nameservers"`
	MemLimit     string   `json:"mem_limit"`
	CPUs         string   `json:"cpus"`
	PIDsLimit    uint32   `json:"pids_limit"`
	LogLevel     string   `json:"log_level"`
}

// typed converts the parameters of a Python parameter file into the typed values the worker sends to the agent
// (agentspec.InstanceSpec) — image is the reference render_instance.py chose (its meta/instance.json).
func typed(t *testing.T, p pyParams, image string) (*agentspec.Host, agentspec.InstanceSpec) {
	t.Helper()
	repo, digest, _ := strings.Cut(image, "@")
	allow, err := agentspec.ParseAllowlist(strings.NewReader(image + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := &agentspec.Host{TenantsDir: "/opt/meshguard/tenants", BackupsDir: "/opt/meshguard/backups/tenants",
		RunUIDs: agentspec.Range{Min: 30000, Max: 39999}, TenantPool: netip.MustParsePrefix("10.250.0.0/16"),
		PublicEntry: netip.MustParseAddr(p.DERPIPv4), BaseDomain: p.BaseDomain, Images: allow}
	hours, err := strconv.Atoi(strings.TrimSuffix(p.NodeExpiry, "h"))
	if err != nil || hours%24 != 0 {
		t.Fatalf("node_expiry %q is not whole days", p.NodeExpiry)
	}
	mem, err := strconv.Atoi(strings.TrimSuffix(p.MemLimit, "m"))
	if err != nil {
		t.Fatalf("mem_limit %q", p.MemLimit)
	}
	whole, frac, _ := strings.Cut(p.CPUs, ".")
	w, _ := strconv.Atoi(whole)
	f, _ := strconv.Atoi((frac + "000")[:3])
	s := agentspec.InstanceSpec{
		Ref:     agentspec.Ref{InstanceID: uuid.MustParse(p.InstanceID), TenantID: uuid.MustParse(p.TenantID), Slug: p.Slug},
		Image:   agentspec.AllowedImage{Repository: repo, Digest: digest},
		RunUID:  p.RunUID,
		NetCIDR: netip.MustParsePrefix(p.NetCIDR),
		Limits:  agentspec.Limits{MemoryMiB: uint32(mem), CPUMillis: uint32(w*1000 + f), PIDs: p.PIDsLimit}, //nolint:gosec // G115: test values
		Headscale: agentspec.HeadscaleParams{NodeExpiryDays: uint32(hours / 24), DERPRegionID: p.DERPRegionID, //nolint:gosec // G115: test values
			PublicEntry: netip.MustParseAddr(p.DERPIPv4), LogLevel: "info"},
	}
	if p.LogLevel != "" {
		s.Headscale.LogLevel = p.LogLevel
	}
	for _, ns := range p.Nameservers {
		s.Headscale.Nameservers = append(s.Headscale.Nameservers, netip.MustParseAddr(ns))
	}
	return h, s
}

// files is what the Go renderer produces, keyed like render_instance.py's output directory.
func files(t *testing.T, h *agentspec.Host, s agentspec.InstanceSpec) map[string][]byte {
	t.Helper()
	r, err := Render(h, s)
	if err != nil {
		t.Fatal(err)
	}
	m := identityMeta(s)
	configMeta(m, r)
	meta, err := encodeMeta(m)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"compose.yaml": r.Compose, "config/config.yaml": r.Config, "config/bootstrap-policy.hujson": r.Policy,
		"records/extra-records.json": []byte(InitialRecords), "meta/instance.json": meta,
	}
}

func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
		out[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func compareTrees(t *testing.T, name string, want, got map[string][]byte) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("%s: %d files, want %d", name, len(got), len(want))
	}
	for rel, w := range want {
		if g, ok := got[rel]; !ok || !bytes.Equal(g, w) {
			t.Errorf("%s: %s differs from render_instance.py (byte-identical required)\n--- want\n%s\n--- got\n%s", name, rel, w, g)
		}
	}
}

// TestGoldenTenantA: the Go renderer reproduces tests/golden/headscale/tenant-a/expected — the golden files of
// tools/render_instance.py — byte for byte, meta/instance.json (template_version, config_sha256) included.
func TestGoldenTenantA(t *testing.T) {
	dir := filepath.Join(repoRoot, "tests", "golden", "headscale", "tenant-a")
	raw, err := os.ReadFile(filepath.Join(dir, "params.json")) //nolint:gosec // G304: golden parameters of the repository
	if err != nil {
		t.Fatal(err)
	}
	var p pyParams
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	official := lockImages(t)["headscale"] // params: headscale_build = official
	h, s := typed(t, p, official)
	compareTrees(t, "golden tenant-a", readTree(t, filepath.Join(dir, "expected")), files(t, h, s))
}

// TestRepositoriesMatchVersionsLock: the two repositories that choose the "Headscale: …" note are the ones of
// versions.lock.
func TestRepositoriesMatchVersionsLock(t *testing.T) {
	imgs := lockImages(t)
	for name, repo := range map[string]string{"mg-headscale": PatchedRepository, "headscale": OfficialRepository} {
		if r, _, _ := strings.Cut(imgs[name], "@"); r != repo {
			t.Errorf("versions.lock [images.%s] = %q, the renderer knows %q", name, r, repo)
		}
	}
}

func python(t *testing.T) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("MG_TEST_PYTHON_REQUIRED") == "1" {
			t.Fatal("python3 is required for the parity test (the golang image has it)")
		}
		t.Skip("python3 not found: the parity test with tools/render_instance.py is skipped")
	}
	return py
}

func runPy(t *testing.T, py string, args ...string) []byte {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), py, args...) //nolint:gosec // G204: test runs the repository's own tools
	cmd.Dir = repoRoot
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "PYTHONDONTWRITEBYTECODE=1"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python3 %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// TestParityWithRenderInstancePy runs tools/render_instance.py itself on the parameter files of the repository — the
// golden case, the three staging tenants (expanded from staging.env by tools/mgenv.py, as on the host), the test
// instances of the contract, isolation and adopt suites — plus variants of every typed parameter, and requires the
// Go renderer to produce the same five files byte for byte. A parameter file without image/headscale_build gets
// headscale_build = "patched" explicitly: the agent always receives an explicit, allowlisted image (the "mặc định"
// suffix of the note marks only render_instance.py's implicit default).
func TestParityWithRenderInstancePy(t *testing.T) {
	py := python(t)
	cases := map[string]string{
		"golden tenant-a":          "tests/golden/headscale/tenant-a/params.json",
		"staging tenant-a":         "infrastructure/environments/staging/tenants/tenant-a.json",
		"staging tenant-b":         "infrastructure/environments/staging/tenants/tenant-b.json",
		"staging tenant-c":         "infrastructure/environments/staging/tenants/tenant-c.json",
		"contract hsct":            "tests/integration/headscale/testdata/params.json",
		"isolation iso-a":          "tests/isolation/headscale/testdata/params-a.json",
		"isolation iso-b":          "tests/isolation/headscale/testdata/params-b.json",
		"adopt tenant-e2e (image)": "tests/integration/adopt/testdata/params.json",
	}
	variants := map[string]map[string]any{
		"log_level warn":       {"log_level": "warn"},
		"log_level error":      {"log_level": "error"},
		"cpus 0.5, 256m, 64":   {"cpus": "0.5", "mem_limit": "256m", "pids_limit": 64},
		"cpus 2.25":            {"cpus": "2.25"},
		"cpus 16.0, 16384m":    {"cpus": "16.0", "mem_limit": "16384m", "pids_limit": 4096},
		"expiry 1 day":         {"node_expiry": "24h"},
		"three nameservers v6": {"nameservers": []string{"2606:4700:4700::1111", "9.9.9.9", "2001:db8::53"}},
		"region 999":           {"derp_region_id": 999},
		"long slug":            {"slug": "a2345678901234567890123456789012"},
		"official build":       {"headscale_build": "official"},
	}
	n := 0
	for name, file := range cases {
		expanded := runPy(t, py, "tools/mgenv.py", "json", file)
		var base map[string]any
		if err := json.Unmarshal(expanded, &base); err != nil {
			t.Fatal(err)
		}
		_, hasImage := base["image"]
		if _, ok := base["headscale_build"]; !ok && !hasImage {
			base["headscale_build"] = "patched"
		}
		run := map[string]map[string]any{name: base}
		if name == "golden tenant-a" || name == "staging tenant-b" {
			for v, over := range variants {
				p := map[string]any{}
				for k, x := range base {
					p[k] = x
				}
				for k, x := range over {
					p[k] = x
				}
				run[name+" / "+v] = p
			}
		}
		for cname, params := range run {
			t.Run(cname, func(t *testing.T) {
				dir := t.TempDir()
				pf := filepath.Join(dir, "params.json")
				raw, _ := json.Marshal(params)
				if err := os.WriteFile(pf, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(dir, "out")
				runPy(t, py, "tools/render_instance.py", pf, out)
				want := readTree(t, out)
				var meta struct {
					Image string `json:"image"`
				}
				if err := json.Unmarshal(want["meta/instance.json"], &meta); err != nil {
					t.Fatal(err)
				}
				var p pyParams
				if err := json.Unmarshal(raw, &p); err != nil {
					t.Fatal(err)
				}
				h, s := typed(t, p, meta.Image)
				compareTrees(t, cname, want, files(t, h, s))
			})
			n++
		}
	}
	t.Logf("%d parameter sets rendered byte-identically by render_instance.py and the agent", n)
}

func TestCPUs(t *testing.T) {
	for millis, want := range map[uint32]string{100: "0.1", 500: "0.5", 1000: "1.0", 1250: "1.25", 2005: "2.005", 16000: "16.0"} {
		if got := cpus(millis); got != want {
			t.Errorf("cpus(%d) = %q, want %q", millis, got, want)
		}
	}
}

func TestSubstitute(t *testing.T) {
	got, err := substitute("a ${x} $y $$ ${X}", map[string]string{"x": "1", "y": "2", "X": "3"})
	if err != nil || got != "a 1 2 $ 3" {
		t.Fatalf("substitute = %q, %v", got, err)
	}
	// values are inserted once, never expanded again
	if got, _ := substitute("${x}", map[string]string{"x": "${y}", "y": "no"}); got != "${y}" {
		t.Fatalf("re-expanded: %q", got)
	}
	for _, bad := range []string{"${missing}", "$ alone", "${not closed", "$1"} {
		if _, err := substitute(bad, map[string]string{"x": "1"}); err == nil {
			t.Errorf("substitute(%q) accepted", bad)
		}
	}
}

// testSpec is a valid instance for the unit tests (tenants directory dir).
func testSpec(t *testing.T, dir string) (*agentspec.Host, agentspec.InstanceSpec) {
	t.Helper()
	img := PatchedRepository + "@sha256:" + strings.Repeat("a", 64)
	h, s := typed(t, pyParams{TenantID: "11111111-1111-4111-8111-111111111111", InstanceID: "22222222-2222-4222-8222-222222222222",
		Slug: "acme", BaseDomain: "example.com", NetCIDR: "10.250.0.8/29", RunUID: 30001, DERPRegionID: 901,
		DERPIPv4: "203.0.113.10", NodeExpiry: "2160h", Nameservers: []string{"1.1.1.1"}, MemLimit: "512m", CPUs: "1.0",
		PIDsLimit: 256}, img)
	h.TenantsDir, h.BackupsDir = dir, dir+"-backups"
	h.OwnerUID = os.Geteuid()
	return h, s
}

// TestInvariantsRefuseFailOpenConfigurations: every isolation invariant of §11.1 / §11.3 step 8 is enforced on the
// rendered bytes — a template that drifted into any of these would be refused before anything is written.
func TestInvariantsRefuseFailOpenConfigurations(t *testing.T) {
	h, s := testSpec(t, "/opt/meshguard/tenants")
	r, err := Render(h, s)
	if err != nil {
		t.Fatal(err)
	}
	cfg, cmp := string(r.Config), string(r.Compose)
	configCases := map[string][2]string{
		"verify_clients false":        {"verify_clients: true", "verify_clients: false"},
		"policy mode file":            {"  mode: database", "  mode: file"},
		"derp urls":                   {"  urls: []", "  urls: [https://controlplane.tailscale.com/derpmap/default]"},
		"derp paths":                  {"  paths: []", "  paths: [/etc/derp.yaml]"},
		"grpc insecure":               {"grpc_allow_insecure: false", "grpc_allow_insecure: true"},
		"grpc listen all":             {"grpc_listen_addr: 127.0.0.1:50443", "grpc_listen_addr: 0.0.0.0:50443"},
		"tls cert":                    {`tls_cert_path: ""`, `tls_cert_path: "/x.pem"`},
		"tls letsencrypt":             {`tls_letsencrypt_hostname: ""`, `tls_letsencrypt_hostname: "acme.example.com"`},
		"trusted proxies widened":     {"  - 10.250.0.8/29", "  - 0.0.0.0/0"},
		"node expiry zero":            {"expiry: 2160h", "expiry: 0h"},
		"node expiry days":            {"expiry: 2160h", "expiry: 90d"},
		"log level debug":             {"  level: info", "  level: debug"},
		"log format text":             {"  format: json", "  format: text"},
		"prefix v4 outside":           {"v4: 100.64.0.0/10", "v4: 10.0.0.0/8"},
		"prefix v6 outside":           {"v6: fd7a:115c:a1e0::/48", "v6: fd00::/8"},
		"magic dns base = server":     {"base_domain: acme.tail.example.com", "base_domain: acme.mesh.example.com"},
		"no nameserver":               {"      - 1.1.1.1\n", ""},
		"extra records elsewhere":     {"/etc/headscale-records/extra-records.json", "/var/lib/headscale/records.json"},
		"logtail on":                  {"logtail:\n  enabled: false", "logtail:\n  enabled: true"},
		"check updates":               {"disable_check_updates: true", "disable_check_updates: false"},
		"derp ipv4 other":             {"ipv4: 203.0.113.10", "ipv4: 198.51.100.1"},
		"server_url of another slug":  {"server_url: https://acme.", "server_url: https://other."},
		"oidc block":                  {"logtail:", "oidc:\n  issuer: https://idp.example\nlogtail:"},
		"database postgres":           {"  type: sqlite", "  type: postgres"},
		"noise key outside data":      {"/var/lib/headscale/noise_private.key", "/etc/headscale/noise_private.key"},
		"unix socket on a mount":      {"unix_socket: /var/run/headscale/headscale.sock", "unix_socket: /var/lib/headscale/headscale.sock"},
		"verify clients not a bool":   {"verify_clients: true", "verify_clients: yes please"},
		"derp disabled":               {"    enabled: true\n    region_id", "    enabled: false\n    region_id"},
		"not yaml":                    {"server_url:", "server_url: [unclosed"},
		"policy path":                 {"  path: \"\"\n\ndns", "  path: \"/etc/policy.hujson\"\n\ndns"},
		"override local dns disabled": {"override_local_dns: true", "override_local_dns: false"},
	}
	composeCases := map[string][2]string{
		"published port":            {"    read_only: true\n", "    read_only: true\n    ports: [\"8080:8080\"]\n"},
		"privileged":                {"    read_only: true\n", "    read_only: true\n    privileged: true\n"},
		"cap_add NET_ADMIN":         {"    read_only: true\n", "    read_only: true\n    cap_add: [NET_ADMIN]\n"},
		"TS_ variable":              {"    read_only: true\n", "    read_only: true\n    environment: {TS_DEBUG_KEY_PATH: /x}\n"},
		"interpolation":             {"    read_only: true\n", "    read_only: true\n    hostname: ${HOST}\n"},
		"host network":              {"    read_only: true\n", "    read_only: true\n    network_mode: host\n"},
		"writable rootfs":           {"    read_only: true\n", "    read_only: false\n"},
		"root user":                 {`user: "30001:30001"`, `user: "0:0"`},
		"no cap_drop":               {"    cap_drop: [ALL]\n", "    cap_drop: [CHOWN]\n"},
		"new privileges":            {`security_opt: ["no-new-privileges:true"]`, `security_opt: ["apparmor:unconfined"]`},
		"image by tag":              {"image: " + s.Image.Reference(), "image: headscale/headscale:latest"},
		"other container name":      {"container_name: mg-hs-acme", "container_name: mg-edge"},
		"bind of another instance":  {"/22222222-2222-4222-8222-222222222222/data", "/33333333-3333-4333-8333-333333333333/data"},
		"bind of the docker socket": {"source: /opt/meshguard/tenants/22222222-2222-4222-8222-222222222222/records", "source: /var/run"},
		"config mounted writable":   {"target: /etc/headscale\n        read_only: true", "target: /etc/headscale\n        read_only: false"},
		"create host path":          {"create_host_path: false", "create_host_path: true"},
		"extra volume":              {"    networks:\n      mg-t-acme:", "      - /:/host\n    networks:\n      mg-t-acme:"},
		"network of another tenant": {"    networks:\n      mg-t-acme:\n        aliases", "    networks:\n      mg-t-other:\n        aliases"},
		"network not external":      {"external: true", "external: false"},
		"edge network":              {"networks:\n  mg-t-acme:\n    external: true", "networks:\n  mg-t-acme:\n    external: true\n  mg-edge:\n    external: true"},
		"label of another instance": {`meshguard.instance_id: "22222222`, `meshguard.instance_id: "33333333`},
		"project name":              {"name: mg-t-acme", "name: mg-t-other"},
		"second service":            {"\nnetworks:\n  mg-t-acme:", "  spy:\n    image: busybox\n\nnetworks:\n  mg-t-acme:"},
	}
	n := 0
	for name, c := range configCases {
		mut := strings.Replace(cfg, c[0], c[1], 1)
		if mut == cfg {
			t.Errorf("config case %q: pattern not found", name)
			continue
		}
		if err := checkConfig([]byte(mut), h, s); !errors.Is(err, ErrInvariant) {
			t.Errorf("config case %q accepted: %v", name, err)
		}
		n++
	}
	for name, c := range composeCases {
		mut := strings.Replace(cmp, c[0], c[1], 1)
		if mut == cmp {
			t.Errorf("compose case %q: pattern not found", name)
			continue
		}
		if err := checkCompose([]byte(mut), h, s); !errors.Is(err, ErrInvariant) {
			t.Errorf("compose case %q accepted: %v", name, err)
		}
		n++
	}
	t.Logf("%d fail-open configurations refused", n)
}

func TestRenderRefusesPerTenantSTUNPort(t *testing.T) {
	h, s := testSpec(t, "/opt/meshguard/tenants")
	s.Headscale.STUNPort = 40000
	_, err := Render(h, s)
	if r, ok := agentspec.AsRefusal(err); !ok || r.Reason != agentv1.RefusalReason_REFUSAL_REASON_PORT_OUT_OF_RANGE {
		t.Fatalf("Render with a STUN port: %v", err)
	}
}

func TestMetaEncodingIsPythons(t *testing.T) {
	m := map[string]any{"b": "x", "a": json.Number("1"), "c": true}
	got, err := encodeMeta(m)
	if err != nil || string(got) != "{\n  \"a\": 1,\n  \"b\": \"x\",\n  \"c\": true\n}\n" {
		t.Fatalf("encodeMeta = %q, %v", got, err)
	}
	back, err := decodeMeta(got)
	if err != nil || fmt.Sprint(back["a"]) != "1" {
		t.Fatalf("decodeMeta: %v %v", back, err)
	}
	for _, bad := range []string{"[]", "null", "{} {}", "{"} {
		if _, err := decodeMeta([]byte(bad)); err == nil {
			t.Errorf("decodeMeta(%q) accepted", bad)
		}
	}
}
