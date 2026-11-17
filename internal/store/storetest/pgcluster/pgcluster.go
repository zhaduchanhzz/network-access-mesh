// Package pgcluster holds the two cluster-wide rules that every PostgreSQL test harness of the repository must share
// when several test packages run against one throwaway cluster (CI service container, build VM): the advisory lock
// that serialises the cluster-wide part of their setup, and the derivation of the role passwords. Only test code
// imports it — the harness of internal/store/storetest, and the harnesses of internal/store, internal/secrets,
// internal/authz and internal/identity, which keep their own fixtures but take the lock and derive the passwords here
// (internal/store's own tests cannot import storetest — import cycle —, hence this leaf package).
//
// Why: roles, role memberships and role settings are cluster-wide objects, and `go test ./...` runs test packages in
// parallel. Two packages bootstrapping (CREATE/ALTER ROLE), migrating (CREATE ROLE, GRANT role) or setting role
// passwords (ALTER ROLE … PASSWORD) at the same time fail with `duplicate key value violates unique constraint
// "pg_authid_rolname_index"` or `tuple concurrently updated` (reproduced in the evidence of P2-T04 and P2-T06).
package pgcluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5"
)

// LockKey is the session-level advisory lock ("mg_test") a harness holds, in database "postgres" (advisory locks are
// per database), from CREATE DATABASE until the role passwords are set: bootstrap, migrations and SetRolePassword all
// run under it. It is the only key for this purpose — a harness taking another key would race the others again.
const LockKey int64 = 0x6d675f74657374 // "mg_test"

// RolePassword derives the test password of a login role from the superuser password of the throwaway cluster. Roles
// are cluster-wide: every harness sets exactly this value, so one package re-setting a password never breaks the
// logins of another package running at the same time.
func RolePassword(superuserPassword, role string) string {
	sum := sha256.Sum256([]byte("meshguard-test|" + superuserPassword + "|" + role))
	return hex.EncodeToString(sum[:])
}

// Lock opens a dedicated superuser session on database "postgres" of the cluster that adminURL (the superuser URL of
// MG_TEST_PG_ADMIN_URL, any database) points at, waits for LockKey and returns the function that releases the lock
// and closes the session. A test process that dies while holding the lock releases it with its session.
func Lock(ctx context.Context, adminURL string) (release func(), err error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return nil, errors.New("pgcluster: the admin URL does not parse") // never echo the URL: it holds a password
	}
	u.Path = "/postgres"
	c, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("pgcluster: connect to database postgres: %w", err)
	}
	if _, err := c.Exec(ctx, "SELECT pg_advisory_lock($1)", LockKey); err != nil {
		_ = c.Close(context.Background())
		return nil, fmt.Errorf("pgcluster: cluster lock: %w", err)
	}
	return func() {
		_, _ = c.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", LockKey)
		_ = c.Close(context.Background())
	}, nil
}
