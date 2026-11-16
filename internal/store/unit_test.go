package store

// Tests that need no database.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestScramVerifierRFC7677 checks scramVerifier against the SCRAM-SHA-256 example exchange of RFC 7677 §3
// (user "user", password "pencil"): the StoredKey must validate the client proof and the ServerKey must produce the
// server signature of that exchange.
func TestScramVerifierRFC7677(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	v, err := scramVerifier("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !verifierRE.MatchString(v) {
		t.Fatalf("verifier %q has the wrong format", v)
	}
	parts := strings.Split(strings.TrimPrefix(v, "SCRAM-SHA-256$"), "$")
	keys := strings.Split(parts[1], ":")
	storedKey, _ := base64.StdEncoding.DecodeString(keys[0])
	serverKey, _ := base64.StdEncoding.DecodeString(keys[1])

	const authMessage = "n=user,r=rOprNGfwEbeRWgbNEkqO," +
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," +
		"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	proof, _ := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	wantServerSig, _ := base64.StdEncoding.DecodeString("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")

	if sig := hmacSHA256(serverKey, authMessage); !hmac.Equal(sig, wantServerSig) {
		t.Errorf("server signature = %x, want %x", sig, wantServerSig)
	}
	clientSig := hmacSHA256(storedKey, authMessage)
	clientKey := make([]byte, len(proof))
	for i := range proof {
		clientKey[i] = proof[i] ^ clientSig[i]
	}
	if got := sha256.Sum256(clientKey); !bytes.Equal(got[:], storedKey) {
		t.Errorf("StoredKey does not validate the RFC 7677 client proof")
	}
}

func TestReadPasswordFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const good = "0123456789abcdefXYZ!#%"
	for name, content := range map[string]string{"lf": good + "\n", "crlf": good + "\r\n", "bare": good} {
		if pw, err := ReadPasswordFile(write(name, content)); err != nil || pw != good {
			t.Errorf("%s: %q, %v", name, pw, err)
		}
	}
	for name, content := range map[string]string{
		"short": "tooshort\n", "space": "0123456789 abcdefg\n", "two-lines": good + "\n\n", "utf8": "0123456789abcdéfgh",
		"empty": "",
	} {
		_, err := ReadPasswordFile(write(name, content))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), strings.TrimSpace(content)) && content != "" {
			t.Errorf("%s: the error leaks the file content: %v", name, err)
		}
	}
	if _, err := ReadPasswordFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}

type recordExec struct{ sql []string }

func (r *recordExec) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	r.sql = append(r.sql, sql)
	return pgconn.CommandTag{}, nil
}

func TestSetRolePasswordSendsOnlyAVerifier(t *testing.T) {
	rec := &recordExec{}
	ex := Execer(rec)
	const pw = "correct-horse-battery-staple"
	if err := SetRolePassword(t.Context(), ex, "mg_api_tenant", pw); err != nil {
		t.Fatal(err)
	}
	if len(rec.sql) != 1 || strings.Contains(rec.sql[0], pw) ||
		!strings.HasPrefix(rec.sql[0], `ALTER ROLE "mg_api_tenant" PASSWORD 'SCRAM-SHA-256$4096:`) {
		t.Fatalf("statement = %q", rec.sql)
	}
	for _, c := range []struct{ role, pw string }{
		{"postgres", pw}, {"mg_api_tenant; DROP TABLE x", pw}, {`mg_x"`, pw}, {"mg_api_tenant", "short"},
		{"mg_api_tenant", "has a space in it!!"},
	} {
		if err := SetRolePassword(t.Context(), ex, c.role, c.pw); err == nil {
			t.Errorf("SetRolePassword(%q, %q) accepted", c.role, c.pw)
		}
	}
}

func TestPoolConfigRejectsCredentialsInURL(t *testing.T) {
	cred := Credentials{User: "mg_api_tenant", PasswordFile: "/run/secrets/x"}
	for _, u := range []string{
		"postgres://user:pw@db:5432/meshguard",
		"postgres://user@db:5432/meshguard",
		"postgres://db:5432/meshguard?password=pw",
		"postgres://db:5432/meshguard?user=x",
		"host=db password=pw",
		"mysql://db/meshguard",
	} {
		if _, err := poolConfig(u, cred); err == nil {
			t.Errorf("poolConfig(%q) accepted", u)
		} else if strings.Contains(err.Error(), "pw") {
			t.Errorf("poolConfig(%q) error leaks the URL: %v", u, err)
		}
	}
	if _, err := poolConfig("postgres://db:5432/meshguard?sslmode=disable", Credentials{User: "x"}); err == nil {
		t.Error("missing password file accepted")
	}
	cfg, err := poolConfig("postgres://db:5432/meshguard?sslmode=disable", cred)
	if err != nil || cfg.ConnConfig.User != "mg_api_tenant" || cfg.ConnConfig.Password != "" || cfg.BeforeConnect == nil {
		t.Fatalf("poolConfig = %+v, %v", cfg, err)
	}
}

func TestWithTenantTxRequiresTenant(t *testing.T) {
	var s Store // no pool: the check happens before any connection is used
	if err := s.WithTenantTx(t.Context(), uuid.Nil, nil); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("err = %v, want ErrNoTenant", err)
	}
}
