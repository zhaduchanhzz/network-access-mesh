package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDispatchRunPathUnchanged: without arguments the worker runs exactly as before (runner.Main); a subcommand never
// starts it.
func TestDispatchRunPathUnchanged(t *testing.T) {
	ran := 0
	run := func() int { ran++; return 7 }
	if code := dispatch(nil, io.Discard, io.Discard, run); code != 7 || ran != 1 {
		t.Fatalf("no arguments: exit %d, run called %d times", code, ran)
	}
	if code := dispatch([]string{}, io.Discard, io.Discard, run); code != 7 || ran != 2 {
		t.Fatalf("empty arguments: exit %d, run called %d times", code, ran)
	}
	var stderr bytes.Buffer
	for _, args := range [][]string{{"kek-drill"}, {"kek-drill", "--help"}, {"run"}, {"secret-looking-argument"}, {"--live", "/x"}} {
		stderr.Reset()
		if code := dispatch(args, io.Discard, &stderr, run); code != 2 || ran != 2 {
			t.Errorf("%q: exit %d (want 2), run called %d times", args, code, ran)
		}
		if !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("%q: no usage on stderr: %q", args, stderr.String())
		}
		if strings.Contains(stderr.String(), "secret-looking-argument") {
			t.Errorf("an unknown argument is repeated: %q", stderr.String())
		}
	}
}

// setMode sets the mode of a test file (the host mode 0440, or a refused one, is a parameter).
func setMode(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

// keyringRoot writes <root>/kek-app and <root>/kek-ops, one KEK each (64 hex characters, mode 0440 as on the host),
// and returns the root (test keys are random per run and never printed).
func keyringRoot(t *testing.T, ids map[string]string, keys map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	for name, id := range ids {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		for file, content := range map[string]string{id: hex.EncodeToString(keys[name]) + "\n", "ACTIVE": id + "\n"} {
			p := filepath.Join(dir, file)
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			setMode(t, p, 0o440)
		}
	}
	return root
}

func randomKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// TestKEKDrill runs the subcommand through dispatch on keyring directories laid out like the ceremony's mounts.
func TestKEKDrill(t *testing.T) {
	ids := map[string]string{"kek-app": "staging-app-20261117-0900", "kek-ops": "staging-ops-20261117-0900"}
	keys := map[string][]byte{"kek-app": randomKEK(t), "kek-ops": randomKEK(t)}
	live := keyringRoot(t, ids, keys)
	leaks := func(out string) bool {
		for _, k := range keys {
			for _, enc := range []string{hex.EncodeToString(k), strings.ToUpper(hex.EncodeToString(k)), base64.StdEncoding.EncodeToString(k)} {
				if strings.Contains(out, enc) {
					return true
				}
			}
		}
		return false
	}
	drill := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := dispatch(append([]string{"kek-drill"}, args...), &stdout, &stderr, func() int { t.Fatal("run called"); return 0 })
		out := stdout.String() + stderr.String()
		if leaks(out) {
			t.Fatalf("key material in the output of %q", args)
		}
		return code, out
	}

	// faithful copies of both keyrings ⇒ PASS, with kek_ids and KCVs
	code, out := drill("--live", live, "--recovered", keyringRoot(t, ids, keys))
	if code != 0 || !strings.HasSuffix(out, "kek-drill: PASS (2 keyrings, 2 kek_ids)\n") ||
		!strings.Contains(out, "kek-drill: kek-app: kek_id=staging-app-20261117-0900 kcv live=") ||
		!strings.Contains(out, "wrap live->recovered=ok recovered->live=ok") || !strings.Contains(out, "kek-drill: process uid=") {
		t.Fatalf("faithful copy: exit %d\n%s", code, out)
	}

	// one bit of kek-ops differs ⇒ FAIL, kek-app still PASS
	bad := map[string][]byte{"kek-app": keys["kek-app"], "kek-ops": append([]byte(nil), keys["kek-ops"]...)}
	bad["kek-ops"][0] ^= 0x80
	code, out = drill("--live", live, "--recovered", keyringRoot(t, ids, bad))
	if code != 1 || !strings.Contains(out, "kek-drill: kek-app: PASS") || !strings.Contains(out, `kek-drill: kek-ops: FAIL — kek_id "staging-ops-20261117-0900": KCV differs`) ||
		!strings.HasSuffix(out, "kek-drill: FAIL (3 problems)\n") {
		t.Fatalf("one bit differs: exit %d\n%s", code, out)
	}
	// only kek-app requested ⇒ the bad kek-ops copy is not looked at
	if code, out = drill("--live", live, "--recovered", keyringRoot(t, ids, bad), "--keyring", "kek-app"); code != 0 ||
		!strings.HasSuffix(out, "PASS (1 keyrings, 1 kek_ids)\n") {
		t.Fatalf("--keyring kek-app: exit %d\n%s", code, out)
	}

	// the same key in both keyrings (live and recovered) ⇒ FAIL even though each copy matches its live keyring
	same := map[string][]byte{"kek-app": keys["kek-app"], "kek-ops": keys["kek-app"]}
	sameLive := keyringRoot(t, ids, same)
	if code, out = drill("--live", sameLive, "--recovered", keyringRoot(t, ids, same)); code != 1 ||
		!strings.Contains(out, "kek-app and kek-ops hold the same key") {
		t.Fatalf("shared key: exit %d\n%s", code, out)
	}

	// a recovered keyring that LoadKeyring refuses (world-readable file) ⇒ FAIL naming the file
	loose := keyringRoot(t, ids, keys)
	setMode(t, filepath.Join(loose, "kek-app", ids["kek-app"]), 0o644)
	if code, out = drill("--live", live, "--recovered", loose); code != 1 ||
		!strings.Contains(out, "kek-drill: kek-app: FAIL — recovered keyring:") || !strings.Contains(out, "lets other users access it") {
		t.Fatalf("world-readable recovered key: exit %d\n%s", code, out)
	}
	// a missing recovered keyring ⇒ FAIL
	if code, _ = drill("--live", live, "--recovered", t.TempDir()); code != 1 {
		t.Fatalf("missing recovered keyrings: exit %d", code)
	}

	// usage errors ⇒ 2
	for _, args := range [][]string{
		{"--live", live},
		{"--recovered", live},
		{"--live", "relative", "--recovered", live},
		{"--live", live, "--recovered", live},
		{"--live", live, "--recovered", live + "/"},
		{"--live", live, "--recovered", t.TempDir(), "--keyring", "kek-other"},
		{"--live", live, "--recovered", t.TempDir(), "--keyring", "kek-app,kek-app"},
		{"--live", live, "--recovered", t.TempDir(), "extra"},
		{"--unknown-flag"},
	} {
		if code, out := drill(args...); code != 2 || !strings.Contains(out, "usage: meshguard-worker kek-drill") {
			t.Errorf("%q: exit %d\n%s", args, code, out)
		}
	}
}
