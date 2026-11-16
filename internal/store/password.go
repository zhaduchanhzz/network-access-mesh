package store

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is satisfied by *pgx.Conn, *pgxpool.Pool and pgx.Tx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const (
	minPasswordLen = 16
	maxPasswordLen = 1024
	// scramIterations matches PostgreSQL's default scram_iterations; the client repeats this work on every login.
	scramIterations = 4096
)

var (
	roleNameRE = regexp.MustCompile(`^mg_[a-z][a-z_]{0,39}$`)
	verifierRE = regexp.MustCompile(`^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$`)
)

// ReadPasswordFile reads a role password from a file secret (§7.6, §14.2): one line of printable ASCII without
// spaces, at least 16 characters; a single trailing newline is ignored. Errors name the file, never its content.
func ReadPasswordFile(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the path comes from deployment configuration, not from a request
	if err != nil {
		return "", fmt.Errorf("read password file %s: %w", path, err)
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if err := checkPassword(pw); err != nil {
		return "", fmt.Errorf("password file %s: %w", path, err)
	}
	return pw, nil
}

// checkPassword restricts passwords to printable ASCII so that SASLprep (applied by PostgreSQL and by the pgx
// SCRAM client) is the identity function and the verifier computed here is the one the server expects.
func checkPassword(pw string) error {
	if len(pw) < minPasswordLen || len(pw) > maxPasswordLen {
		return fmt.Errorf("password must be %d–%d characters", minPasswordLen, maxPasswordLen)
	}
	for i := 0; i < len(pw); i++ {
		if pw[i] <= ' ' || pw[i] > '~' {
			return errors.New("password must be printable ASCII without spaces")
		}
	}
	return nil
}

// SetRolePassword sets the password of an mg_* login role to a SCRAM-SHA-256 verifier computed here, so the
// plaintext never reaches the server, its logs or pg_stat_activity. The caller needs the right to alter the role:
// the superuser for mg_migrator and mg_backup, mg_migrator (CREATEROLE, ADMIN on the roles it created) for the rest.
func SetRolePassword(ctx context.Context, db Execer, role, password string) error {
	if !roleNameRE.MatchString(role) {
		return fmt.Errorf("refusing to set the password of role %q (only mg_* login roles)", role)
	}
	if err := checkPassword(password); err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	v, err := scramVerifier(password, salt, scramIterations)
	if err != nil {
		return err
	}
	if !verifierRE.MatchString(v) { // the literal below can then never contain a quote
		return errors.New("internal error: malformed SCRAM verifier")
	}
	_, err = db.Exec(ctx, "ALTER ROLE "+pgx.Identifier{role}.Sanitize()+" PASSWORD '"+v+"'")
	if err != nil {
		return fmt.Errorf("set password of role %s: %w", role, err)
	}
	return nil
}

// scramVerifier returns the PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677):
// SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>.
func scramVerifier(password string, salt []byte, iterations int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
