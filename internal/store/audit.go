package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// AuditWriterRole is the login role of the detached audit path (§6.1, migration 0004).
const AuditWriterRole = "mg_audit_writer"

// auditWriterConns caps the detached pool: one short INSERT per denied or failed request.
const auditWriterConns = 4

// AuditWriter is the detached audit path of §6.1 ("AuditLogger.RecordDetached()"): its own pool, logged in as
// mg_audit_writer, whose only privilege is INSERT on audit_events (policy WITH CHECK (true), no app.* setting needed).
// Each append is a single autocommitted statement, so a denied or failed event is written outside — and survives —
// any business transaction; the role cannot read the table back (not even through RETURNING), update or delete it.
type AuditWriter struct {
	pool *pgxpool.Pool
}

// auditWriterQuery reads what the login role may do: it must be able to insert audit events and nothing else.
const auditWriterQuery = `SELECT current_user::text, r.rolsuper, r.rolbypassrls,
       pg_has_role(current_user, 'mg_app_tenant', 'MEMBER') OR pg_has_role(current_user, 'mg_app_platform', 'MEMBER'),
       has_table_privilege(current_user, 'public.audit_events', 'INSERT'),
       has_table_privilege(current_user, 'public.audit_events', 'SELECT, UPDATE, DELETE, TRUNCATE'),
       has_table_privilege(current_user, 'public.security_events', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
FROM pg_roles r WHERE r.rolname = current_user`

// OpenAuditWriter creates the detached pool and checks its login role: neither superuser nor BYPASSRLS, member of
// no application group, INSERT on audit_events and no other privilege on audit_events or security_events — so a
// swapped credential (an application role, which could read, or the owner) fails at start-up.
func OpenAuditWriter(ctx context.Context, rawURL string, cred Credentials) (*AuditWriter, error) {
	pool, err := newPool(ctx, rawURL, cred, auditWriterConns)
	if err != nil {
		return nil, fmt.Errorf("store: audit writer: %w", err)
	}
	var (
		user                                      string
		superuser, bypassesRLS, appMember, insert bool
		otherAudit, anySecurity                   bool
	)
	err = pool.QueryRow(ctx, auditWriterQuery).Scan(&user, &superuser, &bypassesRLS, &appMember, &insert, &otherAudit,
		&anySecurity)
	switch {
	case err != nil:
		err = fmt.Errorf("check login role: %w", err)
	case superuser || bypassesRLS:
		err = fmt.Errorf("login role %s must be neither superuser nor BYPASSRLS", user)
	case appMember:
		err = fmt.Errorf("login role %s must not belong to an application group", user)
	case !insert || otherAudit || anySecurity:
		err = fmt.Errorf("login role %s must have INSERT on audit_events and no other privilege on the audit tables", user)
	}
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: audit writer: %w", err)
	}
	return &AuditWriter{pool: pool}, nil
}

// Close closes the pool.
func (w *AuditWriter) Close() { w.pool.Close() }

// Append inserts one audit event in its own (autocommitted) statement.
func (w *AuditWriter) Append(ctx context.Context, p sqlcdb.AppendAuditEventParams) error {
	if w == nil {
		return errors.New("store: audit writer is not open")
	}
	return sqlcdb.New(w.pool).AppendAuditEvent(ctx, p)
}
