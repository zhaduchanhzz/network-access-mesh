//go:build mgtestfixture

// Package hostside is the host-side part of the G3 tool (P3-T14, tests/g3/g3.py): one test binary
// (`go test -c -tags mgtestfixture`) that the tool runs in a throwaway container WITH THE WORKER'S IDENTITY — the
// worker's image, environment, mounts (--volumes-from, read-only: role passwords, keyrings, edge admin token, Host Agent
// socket and token), network namespace (--network container:<worker>: the edge admin listener and the Host Agent see
// the worker) and UID/groups (65532 + 20001/20003). It reuses, never re-implements:
//
//   - the orphan-resource detector of P3-T07 (tests/integration/provisioning/orphans: Collect + Check over PostgreSQL,
//     Docker, the tenants directory, the Host Agent, the SecretStore and the Headscale adapter) — phase "orphans";
//   - the enrollment helper of P3-T14a (tests/e2e/helpers: user + one-time pre-auth key through the adapter, key only in
//     a 0600 file) over the WORKER'S registry (Locator: tenant_instances + SecretStore + edge admin listener — P3-T14a
//     §2.4) — phases "enroll-issue", "enroll-verify", "enroll-cleanup";
//   - the test key ceremony of the dev stack (manifest signing key, its public key, an age recovery recipient — like the
//     keygen role of the provisioning harness) — phase "keygen" (dev only).
//
// Inputs (environment; never a secret value — only paths): the worker's own variables (config.Load("worker")) plus
// MG_G3_PHASE and the phase's MG_G3_* variables (see each phase). Output: one line `G3JSON {…}` on stdout with public
// identifiers only (finding kinds/subjects, user/key/node IDs, key prefixes) — never a key, a password or a token.
// Without MG_G3_PHASE the test is skipped (go test ./... in CI).
package hostside

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/e2e/helpers"
	"github.com/zhaduchanhzz/network-access-mesh/tests/integration/provisioning/orphans"
)

const marker = "G3JSON "

func env(t *testing.T, name string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv("MG_G3_" + name))
	if v == "" {
		t.Fatalf("MG_G3_%s is not set", name)
	}
	return v
}

// emit writes the phase's result: one marker line (public identifiers only).
func emit(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, marker+string(raw)); err != nil {
		t.Fatal(err)
	}
}

// worker opens what the worker opens (apps/internal/runner/deps.go): its two pools, the SecretStore with kek-app and
// kek-ops, the Tenant Registry. Read-only use: the detector and the helper only read the registry and the secrets.
type worker struct {
	cfg config.Config
	st  *store.Store
	sec *secrets.Store
}

func openWorker(t *testing.T) *worker {
	t.Helper()
	cfg, err := config.Load("worker", os.Getenv, os.Environ())
	if err != nil {
		t.Fatalf("worker configuration: %v", err)
	}
	app, err := secrets.LoadKeyring(secrets.KEKApp, cfg.KEKAppDir)
	if err != nil {
		t.Fatal(err)
	}
	var ops *secrets.Keyring
	if cfg.KEKOpsDir != "" {
		if ops, err = secrets.LoadKeyring(secrets.KEKOps, cfg.KEKOpsDir); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(t.Context(), store.Config{URL: cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile}, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	sec, err := secrets.New(st, secrets.Options{App: app, Ops: ops})
	if err != nil {
		t.Fatal(err)
	}
	return &worker{cfg: cfg, st: st, sec: sec}
}

// registry is a fresh Headscale registry over the worker's Locator (no cached target), quiet (the adapter logs to a
// buffer that is checked for the key and discarded).
func (w *worker) registry(t *testing.T, out io.Writer) headscale.Registry {
	t.Helper()
	loc, err := locator.New(tenants.New(w.st, tenants.Options{BaseDomain: w.cfg.BaseDomain}), w.sec,
		locator.Options{AdminURL: w.cfg.Edge.URL, EdgeTokenFile: w.cfg.Edge.TokenFile})
	if err != nil {
		t.Fatal(err)
	}
	return headscale.NewRegistry(loc, headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1},
		Logger: logx.New(out, slog.LevelWarn, "g3-hostside")})
}

func TestG3HostSide(t *testing.T) {
	phase := os.Getenv("MG_G3_PHASE")
	if phase == "" {
		t.Skip("G3 tool only: tests/g3/g3.py runs this binary with MG_G3_PHASE in a container of the worker's identity")
	}
	switch phase {
	case "orphans":
		phaseOrphans(t)
	case "enroll-issue":
		phaseIssue(t)
	case "enroll-verify":
		phaseVerify(t)
	case "enroll-cleanup":
		phaseCleanup(t)
	case "keygen":
		phaseKeygen(t)
	default:
		t.Fatalf("MG_G3_PHASE %q: want orphans, enroll-issue, enroll-verify, enroll-cleanup or keygen", phase)
	}
}

// ---------------------------------------------------------------------------------------------------- orphans

// phaseOrphans runs the P3-T07 detector over the run's scope. MG_G3_SLUG_PREFIX (tenants judged), MG_G3_TENANTS_DIR
// (the agent's tenants directory, mounted read-only at the same path), MG_G3_EDGE / MG_G3_EDGE_NETWORK (the edge
// container and its platform network), MG_G3_DB_USER (a read-only role that sees every tenant: mg_backup — BYPASSRLS +
// pg_read_all_data) with MG_G3_DB_PASSWORD_FILE, MG_G3_SETTLED (1: no job of the run in flight). The Docker Engine is
// read through /var/run/docker.sock (mounted by the tool; the detector only lists and inspects).
func phaseOrphans(t *testing.T) {
	w := openWorker(t)
	ctx := t.Context()
	u, err := url.Parse(w.cfg.DB.URL)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := os.ReadFile(env(t, "DB_PASSWORD_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(env(t, "DB_USER"), strings.TrimSpace(string(pw)))
	clear(pw)
	db, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatalf("database (%s): %v", env(t, "DB_USER"), redactURL(err, u))
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	if _, err := db.Exec(ctx, "SET default_transaction_read_only = on"); err != nil {
		t.Fatal(err)
	}
	dc, err := client.New(client.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dc.Close() })
	var agent *agentclient.Client
	if w.cfg.Agent.Configured() {
		if agent, err = agentclient.New(agentclient.Config{Socket: w.cfg.Agent.Socket, TokenFile: w.cfg.Agent.TokenFile}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = agent.Close() })
	}
	var logs strings.Builder
	src := orphans.Sources{DB: db, Docker: dc, Secrets: w.sec, Headscale: w.registry(t, &logs)}
	if agent != nil {
		src.Agent = agent
	}
	scope := orphans.Scope{SlugPrefix: env(t, "SLUG_PREFIX"), TenantsDir: env(t, "TENANTS_DIR"), Edge: env(t, "EDGE"),
		EdgeNetwork: env(t, "EDGE_NETWORK"), Settled: os.Getenv("MG_G3_SETTLED") == "1",
		// the data key of the tenant's backups (P3-T11) — kept with the final backup of a deprovision until the key
		// grace period ends (then keys_live_after_grace on p3-t09's detector), as the provisioning harness allows it
		AllowSecrets: []string{backupfmt.BackupKeySecretName}}
	inv, err := orphans.Collect(ctx, src, scope)
	if err != nil {
		t.Fatalf("orphan detector: %v", err)
	}
	fs := orphans.Check(inv)
	if fs == nil {
		fs = []orphans.Finding{}
	}
	emit(t, map[string]any{"findings": fs, "summary": inv.Summary(), "agent": agent != nil, "scope": scope.SlugPrefix})
}

func redactURL(err error, u *url.URL) string {
	s := err.Error()
	if p, ok := u.User.Password(); ok && p != "" {
		s = strings.ReplaceAll(s, p, "[REDACTED]")
	}
	return s
}

// ---------------------------------------------------------------------------------------------------- enrollment

// enrollEnv: MG_G3_TENANT (uuid), MG_G3_ENROLL_USER, MG_G3_STATE_DIR (public State of each key: state-<i>.json).
func enrollEnv(t *testing.T) (uuid.UUID, string, string) {
	t.Helper()
	id, err := uuid.Parse(env(t, "TENANT"))
	if err != nil {
		t.Fatal(err)
	}
	return id, env(t, "ENROLL_USER"), env(t, "STATE_DIR")
}

func states(t *testing.T, dir string) []helpers.State {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "state-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	out := make([]helpers.State, 0, len(files))
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // the tool's own state directory
		if err != nil {
			t.Fatal(err)
		}
		var s helpers.State
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// phaseIssue issues MG_G3_ENROLL_COUNT one-time keys (P3-T14a Enroll — one per client, same user) and writes each to
// a 0600 file in MG_G3_KEY_DIR (keys/authkey-…); the public State of each goes to MG_G3_STATE_DIR.
func phaseIssue(t *testing.T) {
	w := openWorker(t)
	tenantID, user, stateDir := enrollEnv(t)
	n, err := strconv.Atoi(env(t, "ENROLL_COUNT"))
	if err != nil || n < 1 || n > 8 {
		t.Fatalf("MG_G3_ENROLL_COUNT: 1–8")
	}
	var logs strings.Builder
	reg := w.registry(t, &logs)
	type issued struct {
		Index      int       `json:"index"`
		UserID     uint64    `json:"user_id"`
		KeyID      uint64    `json:"key_id"`
		KeyPrefix  string    `json:"key_prefix"`
		Expiration time.Time `json:"expiration"`
		File       string    `json:"file"`
	}
	out := []issued{}
	keys := []string{}
	for i := range n {
		e, err := helpers.Enroll(t.Context(), reg, tenantID, helpers.Options{User: user, DisplayName: "G3 tenant C (P3-T14)"})
		if err != nil {
			t.Fatalf("enroll %d: %v", i, err)
		}
		path, err := e.WriteKeyFile(env(t, "KEY_DIR"))
		if err != nil {
			t.Fatal(err)
		}
		st := e.State()
		raw, _ := json.Marshal(st)
		if err := os.WriteFile(filepath.Join(stateDir, fmt.Sprintf("state-%d.json", i)), raw, 0o644); err != nil { //nolint:gosec // public identifiers only
			t.Fatal(err)
		}
		keys = append(keys, e.Key().Reveal())
		out = append(out, issued{Index: i, UserID: st.UserID, KeyID: st.KeyID, KeyPrefix: st.KeyPrefix,
			Expiration: st.Expiration, File: filepath.Base(path)})
	}
	raw, _ := json.Marshal(out)
	for _, k := range keys {
		if strings.Contains(logs.String(), k) || strings.Contains(string(raw), k) {
			t.Fatal("a key reached a log line or the output")
		}
	}
	emit(t, map[string]any{"issued": out})
}

// phaseVerify checks that each key registered exactly one node (MG_G3_HOSTS, comma-separated, in key order), by the
// key (register method authkey), and reads back used / one-time; then removes the key files (they were only for the
// clients). Output: the nodes.
func phaseVerify(t *testing.T) {
	w := openWorker(t)
	_, _, stateDir := enrollEnv(t)
	hosts := strings.Split(env(t, "HOSTS"), ",")
	var logs strings.Builder
	reg := w.registry(t, &logs)
	sts := states(t, stateDir)
	if len(sts) != len(hosts) {
		t.Fatalf("%d states for %d hosts", len(sts), len(hosts))
	}
	type node struct {
		Host   string `json:"host"`
		NodeID uint64 `json:"node_id"`
		KeyID  uint64 `json:"key_id"`
		Method string `json:"register_method"`
		Used   bool   `json:"key_used"`
		OneUse bool   `json:"key_one_time"`
	}
	out := []node{}
	var errs []error
	for i, s := range sts {
		e := helpers.Resume(s)
		nodes, err := e.Nodes(t.Context(), reg)
		if err != nil {
			t.Fatal(err)
		}
		k, err := e.KeyState(t.Context(), reg)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 || (nodes[0].Name != hosts[i] && nodes[0].GivenName != hosts[i]) ||
			nodes[0].RegisterMethod != headscale.RegisterMethodAuthKey {
			errs = append(errs, fmt.Errorf("key #%d: %d node(s) %+v, want one %s by authkey", s.KeyID, len(nodes), nodes, hosts[i]))
			continue
		}
		if !k.Used || k.Reusable || k.Ephemeral {
			errs = append(errs, fmt.Errorf("key #%d: used %v reusable %v ephemeral %v", s.KeyID, k.Used, k.Reusable, k.Ephemeral))
		}
		if err := e.RemoveKeyFiles(); err != nil {
			errs = append(errs, err)
		}
		out = append(out, node{Host: hosts[i], NodeID: nodes[0].ID, KeyID: s.KeyID, Method: string(nodes[0].RegisterMethod),
			Used: k.Used, OneUse: !k.Reusable})
	}
	emit(t, map[string]any{"nodes": out, "errors": fmt.Sprint(errors.Join(errs...))})
	if len(errs) > 0 {
		t.Fatal(errors.Join(errs...))
	}
}

// phaseCleanup (failure path or a tenant kept alive): key files removed, keys expired, nodes and user deleted.
func phaseCleanup(t *testing.T) {
	w := openWorker(t)
	_, _, stateDir := enrollEnv(t)
	var logs strings.Builder
	reg := w.registry(t, &logs)
	var errs []error
	for _, s := range states(t, stateDir) {
		e := helpers.Resume(s)
		_ = e.RemoveKeyFiles()
		if err := e.Cleanup(t.Context(), reg, helpers.CleanupOptions{DeleteNodes: true, DeleteUser: true}); err != nil {
			errs = append(errs, err)
		}
	}
	emit(t, map[string]any{"cleaned": len(states(t, stateDir)), "errors": fmt.Sprint(errors.Join(errs...))})
}

// ---------------------------------------------------------------------------------------------------- keygen (dev)

// phaseKeygen is the key ceremony of the dev stack's Host Agent (P2-T04a in production): manifest signing key (PKCS#8
// PEM), its public key (SPKI base64) and an age recovery recipient (identity not kept) into MG_G3_KEYGEN_OUT.
func phaseKeygen(t *testing.T) {
	dir := env(t, "KEYGEN_OUT")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := backupfmt.NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rk)
	rp, err := backupfmt.DataRecipient(rk)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := backupfmt.RecipientString(rp)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{
		"manifest_signing_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"manifest_pubkey":      backupfmt.PublicKeySPKI(pub),
		"recovery_recipient":   recipient,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o400); err != nil { //nolint:gosec // G703: the tool's own key directory
			t.Fatal(err)
		}
	}
	emit(t, map[string]any{"keygen": "ok"})
}
