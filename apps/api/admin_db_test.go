package main

// The admin commands end to end below the process boundary: configuration from the environment exactly as the
// container gets it, a real PostgreSQL migrated like a deployment (storetest), the real SecretStore, a fake edge admin
// listener with fake Headscale instances (headscaletest). Canary rule (§25.1 rule 9): the API keys and the client
// secret read from stdin never appear in stdout, stderr (debug logs), errors or any database column in clear or hex.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// cliEnv runs admin commands with the environment of the api container.
type cliEnv struct {
	t      *testing.T
	su     *pgx.Conn
	vars   map[string]string
	stdout bytes.Buffer
	stderr bytes.Buffer
	out    strings.Builder // every stdout and stderr of the test, for the canary check
}

func newCLIEnv(t *testing.T, adminURL, tokenFile string) *cliEnv {
	t.Helper()
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	kek := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	writeTestFile(t, filepath.Join(kek, "kek-1"), hex.EncodeToString(k)+"\n")
	writeTestFile(t, filepath.Join(kek, secrets.ActiveFile), "kek-1\n")
	tc, pc := pg.Creds(t, "mg_api_tenant"), pg.Creds(t, "mg_api_platform")
	return &cliEnv{t: t, su: pg.Admin(t, db), vars: map[string]string{
		"MG_ENV": "dev", "MG_LOG_LEVEL": "debug", "MG_BASE_DOMAIN": "mg.test", "MG_KEK_APP_DIR": kek,
		"MG_DB_URL": pg.URL(db), "MG_DB_TENANT_USER": tc.User, "MG_DB_TENANT_PASSWORD_FILE": tc.PasswordFile,
		"MG_DB_PLATFORM_USER": pc.User, "MG_DB_PLATFORM_PASSWORD_FILE": pc.PasswordFile,
		"MG_EDGE_ADMIN_URL": adminURL, "MG_EDGE_ADMIN_TOKEN_FILE": tokenFile,
	}}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (c *cliEnv) run(stdin stdinFile, args ...string) int {
	c.t.Helper()
	c.stdout.Reset()
	c.stderr.Reset()
	environ := make([]string, 0, len(c.vars))
	for k, v := range c.vars {
		environ = append(environ, k+"="+v)
	}
	code := admin(c.t.Context(), args, adminIO{stdin: stdin, stdout: &c.stdout, stderr: &c.stderr,
		getenv: func(k string) string { return c.vars[k] }, environ: environ})
	c.out.WriteString(c.stdout.String())
	c.out.WriteString(c.stderr.String())
	return code
}

// metaFile writes meta/instance.json as tools/render_instance.py does (sorted keys, indent 2) and returns its path.
func metaFile(t *testing.T, tenantID, instanceID uuid.UUID, slug string, runUID int, net string) string {
	t.Helper()
	b, _ := json.MarshalIndent(map[string]any{
		"config_sha256": strings.Repeat("c", 64), "image": "docker.io/headscale/headscale@sha256:" + strings.Repeat("1", 64),
		"instance_id": instanceID.String(), "net_cidr": net, "run_uid": runUID, "slug": slug, "template_version": "1",
		"tenant_id": tenantID.String(),
	}, "", "  ")
	dir := filepath.Join(t.TempDir(), "meta")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "instance.json")
	writeTestFile(t, p, string(b)+"\n")
	return p
}

// cliOutput is what `headscale apikeys create -o json` prints: json.MarshalIndent of the key + fmt.Println.
func cliOutput(key string) string {
	b, _ := json.MarshalIndent(key, "", "\t")
	return string(b) + "\n"
}

// dbLeaks returns the tables holding needle in some row (row-to-text cast: text columns in clear, bytea in hex).
func (c *cliEnv) dbLeaks(needle string) []string {
	c.t.Helper()
	ctx := context.Background()
	rows, err := c.su.Query(ctx, `SELECT format('%I.%I', table_schema, table_name) FROM information_schema.tables
		WHERE table_schema IN ('public', 'river') AND table_type = 'BASE TABLE'`)
	if err != nil {
		c.t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		c.t.Fatal(err)
	}
	var out []string
	for _, tb := range tables {
		for _, n := range []string{needle, hex.EncodeToString([]byte(needle))} {
			var cnt int
			if err := c.su.QueryRow(ctx, "SELECT count(*) FROM "+tb+" AS x WHERE x::text ILIKE '%'||$1||'%'", n).
				Scan(&cnt); err != nil {
				c.t.Fatalf("scan %s: %v", tb, err)
			}
			if cnt > 0 {
				out = append(out, tb)
			}
		}
	}
	return out
}

func TestAdminCommands(t *testing.T) {
	tok := headscaletest.NewToken()
	edge := headscaletest.NewEdge(t, tok)
	tokenFile := filepath.Join(t.TempDir(), "edge_admin_token")
	writeTestFile(t, tokenFile, tok+"\n")
	c := newCLIEnv(t, edge.URL(), tokenFile)
	fa, fb, fc := edge.AddInstance("tenant-a"), edge.AddInstance("tenant-b"), edge.AddInstance("tenant-c")
	_, phase1A := fa.NewKey(time.Hour)
	fb.NewKey(time.Hour)
	fc.NewKey(time.Hour)
	tenantA, instA, tenantB, instB, tenantC := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	idpA, idpB, idpP := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	c.vars["MG_IDP_ID_TENANT_A"], c.vars["MG_IDP_ID_TENANT_B"] = idpA.String(), idpB.String()
	c.vars["MG_IDP_ID_PLATFORM"] = idpP.String()
	metaA := metaFile(t, tenantA, instA, "tenant-a", 30001, "10.250.0.0/29")
	metaB := metaFile(t, tenantB, instB, "tenant-b", 30002, "10.250.0.8/29")
	metaC := metaFile(t, tenantC, uuid.New(), "tenant-c", 30003, "10.250.0.16/29")
	newHost := []string{"adopt-instance", "--host", "mg-staging", "--host-region", "lab", "--run-uid-range",
		"30000-39999", "--tenant-net-pool", "10.250.0.0/16"}
	var secretsSeen []string

	// register-platform-idp
	if code := c.run(nil, "register-platform-idp"); code != 0 || !strings.Contains(c.stdout.String(), "created") ||
		!strings.Contains(c.stdout.String(), "https://auth.mg.test/realms/platform") {
		t.Fatalf("register-platform-idp: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	if code := c.run(nil, "register-platform-idp"); code != 0 || !strings.Contains(c.stdout.String(), "already registered") {
		t.Fatalf("register-platform-idp again: %d %s", code, c.stdout.String())
	}

	// adopt tenant-a (new host), then tenant-b (host registered: no pools needed)
	keyA, prefixA := fa.NewKey(90 * 24 * time.Hour)
	secretsSeen = append(secretsSeen, keyA)
	if code := c.run(pipeWith(t, cliOutput(keyA)), append(newHost, "--name", "Tenant A", metaA)...); code != 0 {
		t.Fatalf("adopt A: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	out := c.stdout.String()
	for _, want := range []string{"tenant tenant-a", "registry: host created, tenant created, instance created",
		"secret: mgsec://" + tenantA.String() + "/headscale-api-key#1", "expired: 1 other API key(s) (" + phase1A + ")",
		"valid keys now: 1", "activated: tenant provisioning→active, instance starting→running", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("adopt A output lacks %q:\n%s", want, out)
		}
	}
	keyB, prefixB := fb.NewKey(90 * 24 * time.Hour)
	secretsSeen = append(secretsSeen, keyB)
	if code := c.run(pipeWith(t, keyB+"\n"), "--host", "mg-staging", metaB); code == 0 {
		t.Fatal("adopt-instance without the command name succeeded")
	}
	if code := c.run(pipeWith(t, keyB+"\n"), "adopt-instance", "--host", "mg-staging", metaB); code != 0 {
		t.Fatalf("adopt B: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	if !slices.Equal(fa.ValidPrefixes(), []string{prefixA}) || !slices.Equal(fb.ValidPrefixes(), []string{prefixB}) {
		t.Fatalf("valid keys A %v, B %v", fa.ValidPrefixes(), fb.ValidPrefixes())
	}

	// tenant-c is not adopted: it has no identity provider in the environment, nothing is called or written
	keyC, _ := fc.NewKey(90 * 24 * time.Hour)
	secretsSeen = append(secretsSeen, keyC)
	if code := c.run(pipeWith(t, cliOutput(keyC)), "adopt-instance", "--host", "mg-staging", metaC); code != 1 ||
		!strings.Contains(c.stderr.String(), "MG_IDP_ID_TENANT_C") {
		t.Fatalf("adopt C: %d %s", code, c.stderr.String())
	}
	for _, r := range edge.Requests() {
		if r.Slug == "tenant-c" {
			t.Fatalf("a request reached tenant-c: %+v", r)
		}
	}
	if len(fc.ValidPrefixes()) != 2 {
		t.Fatalf("tenant-c keys changed: %v", fc.ValidPrefixes())
	}

	// idempotent re-run with another new key: rotation
	keyA2, prefixA2 := fa.NewKey(90 * 24 * time.Hour)
	secretsSeen = append(secretsSeen, keyA2)
	if code := c.run(pipeWith(t, cliOutput(keyA2)), "adopt-instance", "--host", "mg-staging", metaA); code != 0 ||
		!strings.Contains(c.stdout.String(), "registry: host existing, tenant existing, instance existing") ||
		!strings.Contains(c.stdout.String(), "#2 (previous: mgsec://"+tenantA.String()+"/headscale-api-key#1)") {
		t.Fatalf("adopt A again: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	if !slices.Equal(fa.ValidPrefixes(), []string{prefixA2}) {
		t.Fatalf("after rotation: %v", fa.ValidPrefixes())
	}

	// set-idp-client-secret for the platform IdP and tenant-a's IdP
	for _, id := range []uuid.UUID{idpP, idpA} {
		s := "CANARY" + strings.Repeat("z", 24) + id.String()[:8]
		secretsSeen = append(secretsSeen, s)
		if code := c.run(pipeWith(t, s+"\n"), "set-idp-client-secret", id.String()); code != 0 ||
			!strings.Contains(c.stdout.String(), "idp-client-secret."+id.String()+"#1") {
			t.Fatalf("set-idp-client-secret %s: %d\n%s%s", id, code, c.stdout.String(), c.stderr.String())
		}
	}

	// refusals of the input channel
	keyX, _ := fa.NewKey(90 * 24 * time.Hour)
	secretsSeen = append(secretsSeen, keyX)
	p := filepath.Join(t.TempDir(), "key.json")
	writeTestFile(t, p, cliOutput(keyX))
	f, _ := os.Open(p) //nolint:gosec // a file this test created
	defer func() { _ = f.Close() }()
	if code := c.run(f, "adopt-instance", "--host", "mg-staging", metaA); code != 1 ||
		!strings.Contains(c.stderr.String(), "stdin is a file") {
		t.Errorf("key from a file: %d %s", code, c.stderr.String())
	}
	dev, _ := os.Open(os.DevNull)
	defer func() { _ = dev.Close() }()
	if code := c.run(dev, "adopt-instance", "--host", "mg-staging", metaA); code != 1 ||
		!strings.Contains(c.stderr.String(), "terminal") {
		t.Errorf("terminal: %d %s", code, c.stderr.String())
	}
	if code := c.run(pipeWith(t, ""), "adopt-instance", "--host", "mg-staging", metaA, keyX); code != 2 ||
		!strings.Contains(c.stderr.String(), "never an argument") {
		t.Errorf("key as an argument: %d %s", code, c.stderr.String())
	}
	if code := c.run(pipeWith(t, ""), "adopt-instance", "--host="+keyX, metaA); code != 2 {
		t.Errorf("key as a flag value: %d %s", code, c.stderr.String())
	}
	if code := c.run(pipeWith(t, cliOutput(keyX)), "adopt-instance", metaA); code != 2 ||
		!strings.Contains(c.stderr.String(), "--host is required") {
		t.Errorf("no --host: %d %s", code, c.stderr.String())
	}
	if code := c.run(pipeWith(t, "short\n"), "set-idp-client-secret", idpA.String()); code != 1 {
		t.Errorf("short client secret: %d", code)
	}
	c.vars["MG_DB_PASSWORD"] = keyX // a secret value in the environment is refused, and not repeated
	if code := c.run(pipeWith(t, cliOutput(keyX)), "adopt-instance", "--host", "mg-staging", metaA); code != 1 ||
		!strings.Contains(c.stderr.String(), "MG_DB_PASSWORD: secret values must be passed as a file") {
		t.Errorf("secret in the environment: %d %s", code, c.stderr.String())
	}
	delete(c.vars, "MG_DB_PASSWORD")
	if !slices.Equal(fa.ValidPrefixes(), []string{prefixA2, prefixOf(keyX)}) {
		t.Errorf("a refused run changed the keys of A: %v", fa.ValidPrefixes())
	}

	// canary: no credential in any output (debug logs included) or in the database
	all := c.out.String()
	if !strings.Contains(all, `"level":"DEBUG"`) || !strings.Contains(all, prefixA) {
		t.Fatal("the debug log or the public key prefix is missing from the output: the canary check would prove nothing")
	}
	if leaks := c.dbLeaks("tenant-a"); !slices.Contains(leaks, "public.tenants") { // positive control of the scan
		t.Fatalf("the database scan does not find a known value (%v)", leaks)
	}
	for i, s := range secretsSeen {
		if strings.Contains(all, s) || strings.Contains(all, s[len(s)-24:]) {
			t.Errorf("credential %d reached stdout/stderr", i)
		}
		if leaks := c.dbLeaks(s); len(leaks) > 0 {
			t.Errorf("credential %d found in clear or hex in %v", i, leaks)
		}
	}
}

func prefixOf(key string) string { return strings.TrimPrefix(key, "hskey-"+"api-")[:12] }
