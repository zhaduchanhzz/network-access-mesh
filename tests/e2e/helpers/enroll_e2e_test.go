//go:build mgtestfixture

package helpers

// TestEnrollE2E — case E2E-32 of the dev/CI stack (tests/e2e/harness/phase3.py): the helper against a real Headscale
// 0.29.7 behind the real admin listener of the edge, through the adapter (headscale.NewRegistry over a StaticLocator —
// the dev stack has no platform record for this; P3-T14 passes the worker's registry instead). The harness compiles
// this test (`go test -c -tags mgtestfixture`) and runs it twice in a container on the stack's admin network, with a
// tailscale client container started by the harness in between:
//
//	MG_E2E_ENROLL_PHASE=issue   ensure the user, issue the one-time key, write it to a 0600 file in MG_E2E_ENROLL_DIR,
//	                            write the public State to MG_E2E_ENROLL_STATE
//	(harness)                   client 1 joins with the key file; client 2 tries the same key — must fail
//	MG_E2E_ENROLL_PHASE=verify  client 1's node is listed with the key's ID, client 2 has no node, the key reads back
//	                            used / one-time / ≤ 15 min; the key file (0600) is deleted; Cleanup leaves no node,
//	                            no user, no valid key
//
// Inputs (environment, none secret): MG_E2E_ENROLL_ADMIN_URL, _TENANT_ID, _INSTANCE_ID, _SLUG, _USER, _HOST (client 1),
// _REUSE_HOST (client 2), _DIR, _STATE; and MG_E2E_ENROLL_SECRETS, a read-only directory holding `apikey` (a
// short-lived instance API key) and `edge_token` (the admin listener's token). Without MG_E2E_ENROLL_PHASE the test is
// skipped. Output: only public identifiers (user and key IDs, key prefix, node IDs) — never the key.

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

func e2eEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv("MG_E2E_ENROLL_" + name)
	if v == "" {
		t.Fatalf("MG_E2E_ENROLL_%s is not set", name)
	}
	return v
}

func readSecret(t *testing.T, dir, name string) headscale.Secret {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the harness's read-only secret directory
	if err != nil {
		t.Fatalf("secret %s: %v", name, err)
	}
	return headscale.NewSecret(strings.TrimSpace(string(b)))
}

func TestEnrollE2E(t *testing.T) {
	phase := os.Getenv("MG_E2E_ENROLL_PHASE")
	if phase == "" {
		t.Skip("dev/CI stack only: tests/e2e/harness (E2E-32) sets MG_E2E_ENROLL_PHASE")
	}
	tenantID, err := uuid.Parse(e2eEnv(t, "TENANT_ID"))
	if err != nil {
		t.Fatal(err)
	}
	instanceID, err := uuid.Parse(e2eEnv(t, "INSTANCE_ID"))
	if err != nil {
		t.Fatal(err)
	}
	secrets := e2eEnv(t, "SECRETS")
	var logs bytes.Buffer // the adapter's log lines: checked for the key below
	log := logx.New(&logs, slog.LevelDebug, "e2e-enroll")
	reg := headscale.NewRegistry(headscale.StaticLocator{tenantID: {InstanceID: instanceID, Slug: e2eEnv(t, "SLUG"),
		AdminURL: e2eEnv(t, "ADMIN_URL"), APIKey: readSecret(t, secrets, "apikey"), EdgeToken: readSecret(t, secrets, "edge_token")}},
		headscale.Options{Logger: log})
	statePath, user := e2eEnv(t, "STATE"), e2eEnv(t, "USER")
	ctx := t.Context()

	switch phase {
	case "issue":
		e, err := Enroll(ctx, reg, tenantID, Options{User: user, DisplayName: "E2E enrollment helper (P3-T14a)"})
		if err != nil {
			t.Fatal(err)
		}
		path, err := e.WriteKeyFile(e2eEnv(t, "DIR"))
		if err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %v (%v)", fi.Mode().Perm(), err)
		}
		if ttl := time.Until(e.Expiration); ttl <= 0 || ttl > MaxKeyTTL {
			t.Fatalf("expires in %v", ttl)
		}
		raw, _ := json.Marshal(e.State())
		if err := os.WriteFile(statePath, raw, 0o644); err != nil { //nolint:gosec // public identifiers only
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), e.Key().Reveal()) || strings.Contains(string(raw), e.Key().Reveal()) {
			t.Fatal("the key reached a log line or the state")
		}
		t.Logf("issued: user %s#%d created=%v, key #%d %s… expires %s, file %s 0600",
			e.User.Name, e.User.ID, e.UserCreated, e.KeyID, e.KeyPrefix, e.Expiration.Format("15:04:05Z"), filepath.Base(path))

	case "verify":
		raw, err := os.ReadFile(statePath) //nolint:gosec // the harness's state file
		if err != nil {
			t.Fatal(err)
		}
		var st State
		if err := json.Unmarshal(raw, &st); err != nil || st.TenantID != tenantID || st.UserName != user {
			t.Fatalf("state %s: %v", raw, err)
		}
		e := Resume(st)
		host, reuse := e2eEnv(t, "HOST"), e2eEnv(t, "REUSE_HOST")
		nodes, err := e.Nodes(ctx, reg)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 || nodes[0].Name != host || nodes[0].User == nil || nodes[0].User.ID != st.UserID ||
			nodes[0].IsTagged() || nodes[0].RegisterMethod != headscale.RegisterMethodAuthKey {
			t.Fatalf("nodes registered with key %d: %+v", st.KeyID, nodes)
		}
		inst, err := reg.ForTenant(ctx, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		all, err := inst.ListNodes(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range all {
			if n.Name == reuse || n.GivenName == reuse {
				t.Fatalf("the reused key registered a second node: %+v", n)
			}
		}
		k, err := e.KeyState(ctx, reg)
		if err != nil {
			t.Fatal(err)
		}
		if !k.Used || k.Reusable || k.Ephemeral || len(k.Tags) != 0 || k.Expiration.Sub(st.Expiration).Abs() > expiryTolerance ||
			k.Expiration.Sub(k.CreatedAt) > MaxKeyTTL {
			t.Fatalf("key read back: used %v reusable %v ephemeral %v tags %v expires %s created %s", k.Used, k.Reusable,
				k.Ephemeral, k.Tags, k.Expiration, k.CreatedAt)
		}
		for _, p := range st.KeyFiles {
			fi, err := os.Stat(p)
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("key file %s: %v", filepath.Base(p), err)
			}
		}
		if err := e.RemoveKeyFiles(); err != nil {
			t.Fatal(err)
		}
		for _, p := range st.KeyFiles {
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("key file %s still exists", filepath.Base(p))
			}
		}
		if err := e.Cleanup(ctx, reg, CleanupOptions{DeleteNodes: true, DeleteUser: true}); err != nil {
			t.Fatal(err)
		}
		if left, _ := inst.ListUsers(ctx, headscale.UserFilter{Name: user}); len(left) != 0 {
			t.Fatalf("user %q still exists", user)
		}
		if k, err := e.KeyState(ctx, reg); err == nil && k.Expiration.After(time.Now()) {
			t.Fatal("the key is still valid after cleanup")
		}
		t.Logf("verified: node #%d %s user #%d %s key #%d; no node %s; key used, one-time, lifetime %v; file removed; "+
			"node+user deleted", nodes[0].ID, nodes[0].Name, st.UserID, nodes[0].RegisterMethod, st.KeyID, reuse,
			k.Expiration.Sub(k.CreatedAt).Round(time.Second))

	default:
		t.Fatalf("MG_E2E_ENROLL_PHASE %q: want issue or verify", phase)
	}
}
