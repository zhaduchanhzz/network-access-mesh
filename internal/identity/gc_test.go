package identity_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

type registrar struct {
	kind     string
	interval time.Duration
	fn       func(context.Context) error
}

func (r *registrar) RegisterPeriodic(kind string, interval time.Duration, fn func(context.Context) error) error {
	r.kind, r.interval, r.fn = kind, interval, fn
	return nil
}

// TestSessionGC — §6.4: sessions deleted 30 days after expiry/revocation, auth requests 1 hour after expires_at; the
// job runs with the worker's platform role; the api role cannot delete.
func TestSessionGC(t *testing.T) {
	t.Parallel()
	pg := identity.RequirePG(t)
	db := pg.Admin(t)
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour

	tenantID, idpID, identityID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	slug := "gc" + identity.RandomHex(4)
	identity.Exec(t, db, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, 'GC', 'active')`, tenantID, slug)
	identity.Exec(t, db, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, 'https://gc.example/'||$3, 'portal', 'external', 'active')`, idpID, tenantID, slug)
	identity.Exec(t, db, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', 'gc-user')`,
		identityID, idpID, tenantID)

	type sess struct {
		name               string
		created, idle, abs time.Time
		revoked            *time.Time
		deleted            bool
	}
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	sessions := []sess{
		{name: "live", created: now, idle: now.Add(30 * time.Minute), abs: now.Add(12 * time.Hour)},
		{name: "revoked 31 days ago", created: now.Add(-32 * day), idle: now.Add(-32*day + 30*time.Minute),
			abs: now.Add(-32*day + 12*time.Hour), revoked: at(-31 * day), deleted: true},
		{name: "revoked 29 days ago", created: now.Add(-29 * day), idle: now.Add(-29*day + 30*time.Minute),
			abs: now.Add(-29*day + 12*time.Hour), revoked: at(-29*day + time.Minute)},
		{name: "idle-expired 31 days ago", created: now.Add(-31*day - time.Hour), idle: now.Add(-31 * day),
			abs: now.Add(-31*day + 11*time.Hour), deleted: true},
		{name: "absolute-expired 40 days ago", created: now.Add(-40*day - 12*time.Hour), idle: now.Add(-40 * day),
			abs: now.Add(-40 * day), deleted: true},
		{name: "expired 10 days ago", created: now.Add(-10*day - time.Hour), idle: now.Add(-10 * day),
			abs: now.Add(-10*day + 11*time.Hour)},
	}
	hashes := map[string][]byte{}
	for _, s := range sessions {
		h := []byte(identity.RandomHex(16))
		hashes[s.name] = h
		identity.Exec(t, db, `INSERT INTO sessions (id_hash, identity_id, idp_id, origin, created_at, last_seen_at, auth_time,
				idle_expires_at, absolute_expires_at, revoked_at)
			VALUES ($1, $2, $3, 'app', $4, $4, $4, $5, $6, $7)`, h, identityID, idpID, s.created, s.idle, s.abs, s.revoked)
	}
	type areq struct {
		name    string
		expires time.Time
		deleted bool
	}
	areqs := []areq{
		{"expired 2 hours ago", now.Add(-2 * time.Hour), true},
		{"expired 30 minutes ago", now.Add(-30 * time.Minute), false},
		{"pending", now.Add(5 * time.Minute), false},
	}
	for _, a := range areqs {
		h := []byte(identity.RandomHex(16))
		hashes[a.name] = h
		identity.Exec(t, db, `INSERT INTO auth_requests (state_hash, idp_id, tenant_id, scope, origin, nonce, pkce_verifier_enc,
				browser_binding_hash, created_at, expires_at)
			VALUES ($1, $2, $3, 'tenant', 'app', 'n', '\x00', $1, $4, $5)`, h, idpID, tenantID, a.expires.Add(-10*time.Minute), a.expires)
	}

	// The api role has no DELETE on sessions/auth_requests: the job only works with the worker store.
	apiGC := identity.NewSessionGC(pg.Store(t), slog.New(slog.DiscardHandler), func() time.Time { return now })
	_, err := apiGC.Run(context.Background())
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("session.gc with the api role: %v, want 42501", err)
	}

	gc := identity.NewSessionGC(pg.WorkerStore(t), slog.New(slog.DiscardHandler), func() time.Time { return now })
	gc.Batch = 1 // force several batches
	reg := &registrar{}
	if err := gc.Register(reg); err != nil || reg.kind != identity.SessionGCKind || reg.interval != time.Hour {
		t.Fatalf("registration %q %v %v", reg.kind, reg.interval, err)
	}
	if err := reg.fn(context.Background()); err != nil {
		t.Fatalf("registered run: %v", err)
	}
	for _, s := range sessions {
		n := countAs(t, db, `SELECT count(*) FROM sessions WHERE id_hash = $1`, hashes[s.name])
		if (n == 0) != s.deleted {
			t.Errorf("session %q: present=%v, want deleted=%v", s.name, n == 1, s.deleted)
		}
	}
	for _, a := range areqs {
		n := countAs(t, db, `SELECT count(*) FROM auth_requests WHERE state_hash = $1`, hashes[a.name])
		if (n == 0) != a.deleted {
			t.Errorf("auth request %q: present=%v, want deleted=%v", a.name, n == 1, a.deleted)
		}
	}
	// Idempotent: a second run deletes nothing of ours and does not fail.
	if _, err := gc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func countAs(t *testing.T, db *pgx.Conn, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
