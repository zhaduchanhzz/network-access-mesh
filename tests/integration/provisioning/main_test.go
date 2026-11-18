//go:build linux && dockerintegration

package provisioning

// Roles of this binary (PIT_ROLE): "" — the harness (the tests of cases_test.go); "edge" — the test edge (TestMain,
// edge_test.go); "worker" — one worker process (TestWorkerProcess, worker_test.go), started by the harness.

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// env is the configuration run.sh hands to every role.
type env struct {
	prefix      string       // PIT_PREFIX: slug prefix of the run's tenants
	root        string       // PIT_ROOT: the test host's /opt/meshguard (tenants/, run/, cfg/) — same path everywhere
	pool        netip.Prefix // PIT_POOL: hosts.tenant_net_pool = MG_AGENT_TENANT_NET_POOL
	runUIDs     [2]int       // PIT_RUN_UIDS lo-hi (inclusive) = MG_AGENT_RUN_UID_RANGE
	publicIPv4  string       // PIT_PUBLIC_IPV4 = MG_AGENT_PUBLIC_ENTRY_IPV4
	baseDomain  string       // PIT_BASE_DOMAIN = MG_BASE_DOMAIN
	hsDigest    string       // PIT_HS_DIGEST: [images.mg-headscale] index digest
	hsVersion   string       // PIT_HS_VERSION: [images.headscale] tag
	edge        string       // PIT_EDGE: container name of the test edge
	edgeNetwork string       // PIT_EDGE_NETWORK: the edge's platform network
	edgeAdmin   string       // PIT_EDGE_ADMIN: http://<edge>:8081
	edgePublic  string       // PIT_EDGE_PUBLIC: <edge>:8080 (the prober's address)
}

func (e env) tenantsDir() string     { return filepath.Join(e.root, "tenants") }
func (e env) socket() string         { return filepath.Join(e.root, "run", "agent.sock") }
func (e env) agentTokenFile() string { return filepath.Join(e.root, "cfg", "agent_token") }
func (e env) edgeTokenFile() string  { return filepath.Join(e.root, "cfg", "edge_token") }

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func loadEnv() (env, error) {
	e := env{prefix: os.Getenv("PIT_PREFIX"), root: os.Getenv("PIT_ROOT"), publicIPv4: os.Getenv("PIT_PUBLIC_IPV4"),
		baseDomain: os.Getenv("PIT_BASE_DOMAIN"), hsDigest: os.Getenv("PIT_HS_DIGEST"), hsVersion: os.Getenv("PIT_HS_VERSION"),
		edge: os.Getenv("PIT_EDGE"), edgeNetwork: os.Getenv("PIT_EDGE_NETWORK"), edgeAdmin: os.Getenv("PIT_EDGE_ADMIN"),
		edgePublic: os.Getenv("PIT_EDGE_PUBLIC")}
	var err error
	if e.pool, err = netip.ParsePrefix(os.Getenv("PIT_POOL")); err != nil {
		return e, fmt.Errorf("PIT_POOL: %w", err)
	}
	if _, err := fmt.Sscanf(os.Getenv("PIT_RUN_UIDS"), "%d-%d", &e.runUIDs[0], &e.runUIDs[1]); err != nil || e.runUIDs[0] >= e.runUIDs[1] {
		return e, fmt.Errorf("PIT_RUN_UIDS: lo-hi required")
	}
	switch {
	case e.prefix == "" || strings.ContainsAny(e.prefix, "_ ."), !filepath.IsAbs(e.root), e.publicIPv4 == "",
		e.baseDomain == "", !digestRE.MatchString(e.hsDigest), e.hsVersion == "", e.edge == "", e.edgeNetwork == "",
		e.edgeAdmin == "", e.edgePublic == "":
		return e, fmt.Errorf("PIT_PREFIX, PIT_ROOT, PIT_PUBLIC_IPV4, PIT_BASE_DOMAIN, PIT_HS_DIGEST, PIT_HS_VERSION, " +
			"PIT_EDGE, PIT_EDGE_NETWORK, PIT_EDGE_ADMIN and PIT_EDGE_PUBLIC are required (tests/integration/provisioning/run.sh)")
	}
	return e, nil
}

func mustEnv(t testing.TB) env {
	t.Helper()
	e, err := loadEnv()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMain(m *testing.M) {
	if os.Getenv("PIT_ROLE") == "edge" {
		os.Exit(runEdge())
	}
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}
