//go:build linux && dockerintegration

package provisioning

// Roles of this binary (PIT_ROLE): "" — the harness (the tests of cases_test.go); "edge" — the test edge (TestMain,
// edge_test.go); "worker" — one worker process (TestWorkerProcess, worker_test.go), started by the harness; "keygen" —
// the key ceremony of the test host for the final backups of the deprovision (P3-T09): writes the manifest signing key
// (PKCS#8 PEM), its public key (SubjectPublicKeyInfo, base64) and an age recovery recipient into PIT_KEYGEN_OUT.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
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
	// manifestKeys verify the final backups (PIT_MANIFEST_PUBKEY = the agent's MG_BACKUP_MANIFEST_PUBKEY — keygen).
	manifestKeys []ed25519.PublicKey
	// keyGrace is the deprovision's grace before the keys are destroyed (PIT_KEY_GRACE, test-shortened).
	keyGrace time.Duration
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
	if v := os.Getenv("PIT_MANIFEST_PUBKEY"); v != "" {
		b, errs := config.LoadBackup("worker", func(k string) string {
			if k == "MG_BACKUP_MANIFEST_PUBKEY" {
				return v
			}
			return ""
		})
		if len(errs) > 0 {
			return e, fmt.Errorf("PIT_MANIFEST_PUBKEY: %v", errs)
		}
		e.manifestKeys = b.ManifestKeys
	}
	e.keyGrace = 20 * time.Second
	if v := os.Getenv("PIT_KEY_GRACE"); v != "" {
		if e.keyGrace, err = time.ParseDuration(v); err != nil || e.keyGrace <= 0 {
			return e, fmt.Errorf("PIT_KEY_GRACE: a positive duration")
		}
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
	switch os.Getenv("PIT_ROLE") {
	case "edge":
		os.Exit(runEdge())
	case "keygen":
		if err := keygen(os.Getenv("PIT_KEYGEN_OUT")); err != nil {
			fmt.Fprintln(os.Stderr, "keygen:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// keygen is the key ceremony of the test host (P2-T04a in production): the manifest signing key of the agent, its
// public key for the worker, and an age recovery recipient (the identity is not kept — the run never opens an archive
// offline). Files: manifest_signing_key (PEM, 0400), manifest_pubkey, recovery_recipient.
func keygen(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("PIT_KEYGEN_OUT: an absolute directory is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	rk, err := backupfmt.NewDataKey()
	if err != nil {
		return err
	}
	defer clear(rk)
	rp, err := backupfmt.DataRecipient(rk)
	if err != nil {
		return err
	}
	recipient, err := backupfmt.RecipientString(rp)
	if err != nil {
		return err
	}
	for name, v := range map[string]string{
		"manifest_signing_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"manifest_pubkey":      backupfmt.PublicKeySPKI(pub),
		"recovery_recipient":   recipient,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o400); err != nil { //nolint:gosec // G703: the run's own key directory (run.sh)
			return err
		}
	}
	return nil
}
