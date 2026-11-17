package main

// End-to-end adoption against Headscale 0.29.7 behind the REAL admin listener block of the edge
// (tests/integration/adopt/run.sh): the runner pipes `headscale apikeys create -e 2160h -o json` straight into this
// test process (its stdin — never a file), which hands the key to `meshguard admin adopt-instance` through a pipe, as
// the runbook does on the host. Skipped without the runner's environment.
//
//	MG_TEST_ADOPT_E2E=1, MG_TEST_PG_ADMIN_URL (storetest), ADOPT_E2E_ADMIN_URL, ADOPT_E2E_TOKEN_FILE, ADOPT_E2E_META,
//	ADOPT_E2E_PHASE1_DIR (files phase1_* holding the keys created before the adoption), ADOPT_E2E_STATE_DIR

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func validPrefixes(keys []headscale.APIKey, now time.Time) []string {
	var out []string
	for _, k := range keys {
		if k.Expiration.IsZero() || k.Expiration.After(now) {
			out = append(out, k.Prefix)
		}
	}
	return out
}

func TestAdoptE2E(t *testing.T) {
	if os.Getenv("MG_TEST_ADOPT_E2E") != "1" {
		t.Skip("end-to-end adoption: run tests/integration/adopt/run.sh")
	}
	adminURL, tokenFile := os.Getenv("ADOPT_E2E_ADMIN_URL"), os.Getenv("ADOPT_E2E_TOKEN_FILE")
	metaPath, phase1Dir, stateDir := os.Getenv("ADOPT_E2E_META"), os.Getenv("ADOPT_E2E_PHASE1_DIR"), os.Getenv("ADOPT_E2E_STATE_DIR")
	ctx := t.Context()

	// 1. the new key arrives on this process's stdin from `docker exec … headscale apikeys create -e 2160h -o json`:
	// the same pipe check as the command (a terminal or a file would be refused); it stays in memory
	raw, err := readStdin(os.Stdin)
	if err != nil {
		t.Fatalf("stdin of the test process: %v", err)
	}
	key, err := parseAPIKey(raw)
	clear(raw)
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	prefix := headscale.APIKeyPrefix(key)
	var phase1 []string
	entries, err := os.ReadDir(phase1Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "phase1_") {
			b, err := os.ReadFile(filepath.Join(phase1Dir, e.Name())) //nolint:gosec // test runner's 0600 file
			if err != nil {
				t.Fatal(err)
			}
			phase1 = append(phase1, strings.TrimSpace(string(b)))
		}
	}
	if len(phase1) < 2 {
		t.Fatalf("the runner created %d Phase 1 keys, want ≥ 2", len(phase1))
	}
	mf, err := os.Open(metaPath) //nolint:gosec // test input
	if err != nil {
		t.Fatal(err)
	}
	m, err := provisioning.ParseMeta(mf)
	_ = mf.Close()
	if err != nil {
		t.Fatal(err)
	}

	c := newCLIEnv(t, adminURL, tokenFile)
	c.vars[idpEnvName(m.Slug)] = uuid.Must(uuid.NewV7()).String()
	code := c.run(pipeWith(t, cliOutput(key.Reveal())), "adopt-instance", "--host", "e2e-host", "--host-region", "lab",
		"--run-uid-range", "30000-39999", "--tenant-net-pool", "10.250.0.0/16", "--name", "Tenant E2E", metaPath)
	t.Logf("adopt-instance (exit %d):\n%s", code, c.stdout.String())
	if code != 0 {
		t.Fatalf("adopt-instance failed:\n%s", c.stderr.String())
	}

	// 2. the production path, opened like the api will open it: registry + SecretStore + edge
	st, err := store.Open(ctx, store.Config{URL: c.vars["MG_DB_URL"],
		Tenant:   store.Credentials{User: c.vars["MG_DB_TENANT_USER"], PasswordFile: c.vars["MG_DB_TENANT_PASSWORD_FILE"]},
		Platform: store.Credentials{User: c.vars["MG_DB_PLATFORM_USER"], PasswordFile: c.vars["MG_DB_PLATFORM_PASSWORD_FILE"]}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kr, err := secrets.LoadKeyring(secrets.KEKApp, c.vars["MG_KEK_APP_DIR"])
	if err != nil {
		t.Fatal(err)
	}
	ss, err := secrets.New(st, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	loc, err := locator.New(tenants.New(st, tenants.Options{}), ss, locator.Options{AdminURL: adminURL, EdgeTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := headscale.NewRegistry(loc, headscale.Options{}).ForTenant(ctx, m.TenantID)
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	keys, err := inst.ListAPIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := validPrefixes(keys, time.Now()); !slices.Equal(v, []string{prefix}) {
		t.Fatalf("valid keys after adoption: %v, want only the new key %s", v, prefix)
	}
	t.Logf("after adoption: %d API keys on the instance, valid: %v (the new key)", len(keys), []string{prefix})

	// 3. every Phase 1 key is expired and refused by the instance (401 through the edge)
	for i, k := range phase1 {
		cand, err := loc.Candidate(m.InstanceID, m.Slug, headscale.NewSecret(k))
		if err != nil {
			t.Fatal(err)
		}
		old, err := headscale.NewRegistry(headscale.StaticLocator{m.TenantID: cand}, headscale.Options{}).ForTenant(ctx, m.TenantID)
		if err != nil {
			t.Fatal(err)
		}
		var he *headscale.Error
		if _, err := old.ListAPIKeys(ctx); !errors.As(err, &he) || he.Kind != headscale.KindAPIKeyRejected {
			t.Errorf("Phase 1 key %d after adoption: %v, want api_key_rejected", i, err)
		}
	}

	// 4. a second run (another new key, created through the adapter with the platform's key — still only in memory)
	key2, err := inst.CreateAPIKey(ctx, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	prefix2 := headscale.APIKeyPrefix(key2)
	code = c.run(pipeWith(t, cliOutput(key2.Reveal())), "adopt-instance", "--host", "e2e-host", metaPath)
	t.Logf("adopt-instance again (exit %d):\n%s", code, c.stdout.String())
	if code != 0 || !strings.Contains(c.stdout.String(), "/headscale-api-key#2 (previous: mgsec://") ||
		!strings.Contains(c.stdout.String(), "expired: 1 other API key(s) ("+prefix+")") {
		t.Fatalf("second run:\n%s%s", c.stdout.String(), c.stderr.String())
	}
	inst2, err := headscale.NewRegistry(loc, headscale.Options{}).ForTenant(ctx, m.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	keys, err = inst2.ListAPIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := validPrefixes(keys, time.Now()); !slices.Equal(v, []string{prefix2}) {
		t.Fatalf("valid keys after the second run: %v, want only %s", v, prefix2)
	}

	// 5. canary: no key in the output of the command (debug logs included) or in the database
	all := c.out.String()
	for i, s := range append([]string{key.Reveal(), key2.Reveal()}, phase1...) {
		if strings.Contains(all, s) || strings.Contains(all, s[len(s)-24:]) {
			t.Errorf("key %d reached stdout/stderr", i)
		}
		if leaks := c.dbLeaks(s); len(leaks) > 0 {
			t.Errorf("key %d found in clear or hex in %v", i, leaks)
		}
	}
	state := filepath.Join(stateDir, "platform_key_prefix")
	if err := os.WriteFile(state, []byte(prefix2+"\n"), 0o600); err != nil { //nolint:gosec // the runner's state directory
		t.Fatal(err)
	}
}
