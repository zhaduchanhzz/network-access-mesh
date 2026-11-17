package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pipeWith returns the read end of a pipe holding content (what `… | meshguard admin …` gives the command).
func pipeWith(t *testing.T, content string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func testKey() string {
	return "hskey-" + "api-" + "AbC_12-xyZ09" + "-" + strings.Repeat("S", 32) + strings.Repeat("s", 32)
}

// TestDispatch — no argument runs the api (unchanged); admin runs a command; anything else is a usage error that
// does not repeat the argument.
func TestDispatch(t *testing.T) {
	ran := false
	if code := dispatch(nil, nil, &bytes.Buffer{}, &bytes.Buffer{}, func() int { ran = true; return 7 }); code != 7 || !ran {
		t.Fatalf("no argument: code %d, ran %v", code, ran)
	}
	var errb bytes.Buffer
	if code := dispatch([]string{testKey()}, nil, &bytes.Buffer{}, &errb, func() int { return 0 }); code != 2 ||
		strings.Contains(errb.String(), testKey()) || !strings.Contains(errb.String(), "unknown subcommand") {
		t.Fatalf("unknown subcommand: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := admin(context.Background(), nil, adminIO{stderr: &errb}); code != 2 ||
		!strings.Contains(errb.String(), "adopt-instance") || !strings.Contains(errb.String(), "set-idp-client-secret") {
		t.Fatalf("admin without command: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := admin(context.Background(), []string{"drop-database"}, adminIO{stderr: &errb}); code != 2 ||
		strings.Contains(errb.String(), "drop-database") {
		t.Fatalf("unknown admin command: %d %q", code, errb.String())
	}
}

// TestStdinMustBeAPipe — a terminal (echo, scrollback) and a file (disk) are refused before anything is read.
func TestStdinMustBeAPipe(t *testing.T) {
	if b, err := readStdin(pipeWith(t, "value\n")); err != nil || string(b) != "value\n" {
		t.Fatalf("pipe: %q %v", b, err)
	}
	dev, err := os.Open(os.DevNull) // a character device, like a terminal
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dev.Close() }()
	if _, err := readStdin(dev); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("character device: %v", err)
	}
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(testKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p) //nolint:gosec // a file this test created
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := readStdin(f); err == nil || !strings.Contains(err.Error(), "file") {
		t.Fatalf("regular file: %v", err)
	}
	dir, _ := os.Open(t.TempDir())
	defer func() { _ = dir.Close() }()
	if _, err := readStdin(dir); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := readStdin(pipeWith(t, strings.Repeat("x", maxStdin+1))); err == nil {
		t.Fatal("oversized stdin accepted")
	}
	if _, err := readStdin(nil); err == nil {
		t.Fatal("nil stdin accepted")
	}
}

// TestParseAPIKey — the JSON string of `headscale apikeys create -o json` (with the newline of fmt.Println) and the
// bare key are accepted; anything else is refused without repeating the input.
func TestParseAPIKey(t *testing.T) {
	k := testKey()
	j, _ := json.MarshalIndent(k, "", "\t")
	for name, in := range map[string]string{"json": string(j) + "\n", "bare": k, "bare with newline": k + "\n"} {
		s, err := parseAPIKey([]byte(in))
		if err != nil || s.Reveal() != k {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, in := range map[string]string{
		"pre-auth key": "hskey-" + "auth-" + "AbC_12-xyZ09-" + strings.Repeat("s", 64),
		"two keys":     k + "\n" + k,
		"json object":  `{"apiKey": "` + k + `"}`,
		"broken json":  `"` + k,
		"empty":        "",
		"legacy key":   "abcdefg." + strings.Repeat("s", 32),
	} {
		_, err := parseAPIKey([]byte(in))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "xyZ09") || strings.Contains(err.Error(), "sss") {
			t.Errorf("%s: the error repeats the input: %v", name, err)
		}
	}
}

func TestHostSpecAndNames(t *testing.T) {
	s, err := hostSpec("mg-staging", "lab", "30000-39999", "10.250.0.0/16")
	if err != nil || s.RunUIDFirst != 30000 || s.RunUIDLast != 39999 || s.TenantNetPool.String() != "10.250.0.0/16" {
		t.Fatalf("hostSpec = %+v, %v", s, err)
	}
	for _, c := range [][3]string{{"", "30000-39999", "10.250.0.0/16"}, {"lab", "39999-30000", "10.250.0.0/16"},
		{"lab", "30000", "10.250.0.0/16"}, {"lab", "30000-39999", "10.250.0.1/16"}, {"lab", "a-b", "10.250.0.0/16"}} {
		if _, err := hostSpec("h", c[0], c[1], c[2]); err == nil {
			t.Errorf("hostSpec %v accepted", c)
		}
	}
	if n := idpEnvName("tenant-a"); n != "MG_IDP_ID_TENANT_A" {
		t.Errorf("idpEnvName = %s", n)
	}
	if !looksLikeCredential([]string{"--host", "x", testKey()}) || looksLikeCredential([]string{"--host", "x"}) {
		t.Error("looksLikeCredential")
	}
	if !clientSecretOK([]byte(strings.Repeat("a", 32))) || clientSecretOK([]byte("short")) ||
		clientSecretOK([]byte(strings.Repeat("a", 20)+" "+strings.Repeat("b", 20))) {
		t.Error("clientSecretOK")
	}
}
