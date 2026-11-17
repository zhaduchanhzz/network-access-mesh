package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// exampleRecipient is the recipient of the age README (public example key, not a platform key).
const exampleRecipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

// fakeIdentity has the shape of an age identity, built at run time so that no key-shaped literal sits in the
// repository for the secret scanner; it is not the key of anything.
var fakeIdentity = "AGE-SECRET-KEY-1" + strings.Repeat("GFPYYSJZ", 7) + "GFPQ"

// encodeRecipient bech32-encodes a 32-byte key as an age X25519 recipient (test helper: fresh valid recipients).
func encodeRecipient(key [32]byte) string {
	var data []byte
	acc, bits := 0, 0
	for _, b := range key {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data = append(data, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		data = append(data, byte(acc<<(5-bits)&31))
	}
	values := []byte{3, 3, 3, 0, 1, 7, 5} // hrp "age" expanded: high bits 3,3,3 · 0 · low bits a=1 g=7 e=5
	values = append(values, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range gen {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	chk ^= 1
	out := "age1"
	for _, v := range data {
		out += string(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		out += string(bech32Charset[(chk>>uint(5*(5-i)))&31])
	}
	return out
}

func TestValidRecipient(t *testing.T) {
	fresh := encodeRecipient([32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	for _, ok := range []string{exampleRecipient, fresh} {
		if err := ValidRecipient(ok); err != nil {
			t.Errorf("ValidRecipient(%s) = %v, want nil", ok, err)
		}
	}
	flipped := []byte(exampleRecipient)
	flipped[20] = map[bool]byte{true: 'q', false: 'p'}[flipped[20] != 'q']
	secret := fakeIdentity
	for name, bad := range map[string]string{
		"empty":            "",
		"private key":      secret,
		"private key (lc)": strings.ToLower(secret),
		"one char changed": string(flipped),
		"upper case":       strings.ToUpper(exampleRecipient),
		"two recipients":   exampleRecipient + " " + fresh,
		"plugin recipient": "age1yubikey1q2w3e4r5t6y7u8i9o0p",
		"ssh key":          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6",
		"truncated":        exampleRecipient[:len(exampleRecipient)-1],
		"post-quantum":     "age1pq1" + strings.Repeat("q", 100),
	} {
		err := ValidRecipient(bad)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "GFPYY") || (bad != "" && strings.Contains(err.Error(), bad)) {
			t.Errorf("%s: the error echoes the value: %v", name, err)
		}
		if strings.HasPrefix(name, "private key") && !strings.Contains(err.Error(), "private key") {
			t.Errorf("%s: the error does not say a private key was pasted: %v", name, err)
		}
	}
}

func baseEnv(target string) map[string]string {
	e := map[string]string{"MG_BACKUP_TARGET": target, "MG_BACKUP_RECIPIENT": exampleRecipient}
	if target != TargetEdge {
		e["MG_BACKUP_PG_HOST"], e["MG_BACKUP_PG_DATABASE"], e["MG_BACKUP_PG_USER"] = "postgres", "meshguard", "mg_backup"
		e["MG_BACKUP_PG_PASSWORD_FILE"] = "/run/secrets/pg_backup_password"
	}
	return e
}

func getenvOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfig(t *testing.T) {
	for _, target := range []string{TargetPostgres, TargetIdP, TargetEdge} {
		c, err := LoadConfig(getenvOf(baseEnv(target)))
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if c.DailyAtString() != "02:30" || c.KeepDays != 14 || c.KeepMin != 7 || c.KeepOnDemand != 5 ||
			c.MaxAge != 26*time.Hour || c.Dest != "/backups" || c.IsPG() != (target != TargetEdge) {
			t.Errorf("%s: defaults = %+v", target, c)
		}
	}
	bad := map[string]map[string]string{
		"no target":            {"MG_BACKUP_TARGET": ""},
		"unknown target":       {"MG_BACKUP_TARGET": "tenants"},
		"empty recipient":      {"MG_BACKUP_RECIPIENT": ""},
		"secret as recipient":  {"MG_BACKUP_RECIPIENT": "AGE-SECRET-KEY-1XYZ"},
		"bad daily time":       {"MG_BACKUP_DAILY_AT": "24:00"},
		"relative dest":        {"MG_BACKUP_DEST": "backups"},
		"no pg host":           {"MG_BACKUP_PG_HOST": ""},
		"pg host with options": {"MG_BACKUP_PG_HOST": "postgres password=x"},
		"database injection":   {"MG_BACKUP_PG_DATABASE": "meshguard password=x"},
		"bad port":             {"MG_BACKUP_PG_PORT": "70000"},
		"bad sslmode":          {"MG_BACKUP_PG_SSLMODE": "maybe"},
		"relative password":    {"MG_BACKUP_PG_PASSWORD_FILE": "pw"},
		"zero retention":       {"MG_BACKUP_KEEP_MIN": "0"},
		"bad duration":         {"MG_BACKUP_RETRY_AFTER": "soon"},
		"bad log level":        {"MG_LOG_LEVEL": "loud"},
		"relative recip. file": {"MG_BACKUP_RECIPIENT_FILE": "recipient.txt"},
	}
	for name, over := range bad {
		env := baseEnv(TargetPostgres)
		for k, v := range over {
			env[k] = v
		}
		if _, err := LoadConfig(getenvOf(env)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "AGE-SECRET-KEY-1XYZ") || strings.Contains(err.Error(), "password=x") {
			t.Errorf("%s: the error echoes the value: %v", name, err)
		}
	}
	env := baseEnv(TargetEdge)
	env["MG_BACKUP_SOURCE"], env["MG_BACKUP_DEST"] = "/data", "/data/backups"
	if _, err := LoadConfig(getenvOf(env)); err == nil {
		t.Error("edge: a destination inside the source was accepted")
	}
}

func TestRecipientFromFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ceremony := write("ok", "# MeshGuard staging — recipient của khóa khôi phục backup. Công khai.\n\n"+exampleRecipient+"\n")
	if r, err := recipientFromFile(ceremony); err != nil || r != exampleRecipient {
		t.Errorf("ceremony file: %q, %v", r, err)
	}
	for name, content := range map[string]string{
		"empty":       "# nothing\n",
		"two":         exampleRecipient + "\n" + encodeRecipient([32]byte{7}) + "\n",
		"private key": fakeIdentity + "\n",
		"garbage":     "hello\n",
	} {
		_, err := recipientFromFile(write(name, content))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "GFPYY") {
			t.Errorf("%s: the error echoes the key: %v", name, err)
		} else if name == "private key" && !strings.Contains(err.Error(), "private key") {
			t.Errorf("private key: the error does not say so: %v", err)
		}
	}
	if _, err := recipientFromFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestNextDaily(t *testing.T) {
	at := 2*time.Hour + 30*time.Minute
	for _, c := range []struct{ now, want string }{
		{"2026-11-17T01:00:00Z", "2026-11-17T02:30:00Z"},
		{"2026-11-17T02:30:00Z", "2026-11-18T02:30:00Z"},
		{"2026-11-17T23:59:59Z", "2026-11-18T02:30:00Z"},
		{"2026-12-31T03:00:00Z", "2027-01-01T02:30:00Z"},
	} {
		now, _ := time.Parse(time.RFC3339, c.now)
		if got := nextDaily(now, at).Format(time.RFC3339); got != c.want {
			t.Errorf("nextDaily(%s) = %s, want %s", c.now, got, c.want)
		}
	}
}

func TestErrConfigWrapping(t *testing.T) {
	c, err := LoadConfig(getenvOf(baseEnv(TargetEdge)))
	if err != nil {
		t.Fatal(err)
	}
	c.AgeBin, c.Source, c.Dest = "/nonexistent/age", t.TempDir(), t.TempDir()
	if _, err := c.Preflight(t.Context()); !errors.Is(err, ErrConfig) {
		t.Errorf("Preflight with a missing age = %v, want ErrConfig", err)
	}
}
