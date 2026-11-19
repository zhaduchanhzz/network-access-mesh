package store

// Migration 0028 (P4-T06/C4 — the project owner's decision of 2026-11-19): the decider of an enrollment request may be
// platform staff acting through a Support Access Grant (§8.6 cell G of tenant.enrollment:approve, §8.7):
// enrollment_requests.approver_support_grant_id, a composite FK to support_access_grants (tenant_id, id), and the two
// unnamed CHECKs of 0020 that required a membership of every decision replaced by "exactly one of the two". The shape
// of the new constraints (one decider, none before the decision, the tenant of the grant) is in TestP4CheckConstraints,
// the column privilege in TestP4GrantMatrix, the cross-tenant write in TestP4CrossTenantWritesRejected; this test is the
// migration itself on a database at schema 27 holding rows of every table (staging is below it — deploy-backend o).

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestMigration0028EnrollmentSupportDecider: on a database at schema 27 with data — requests approved and rejected by
// a member among them —, a schema whose unnamed CHECK does not hold the definition 0028 expects (here: renamed) makes
// 0028 fail as a whole (schema stays 27, no column, the constraint untouched) instead of dropping another constraint;
// repaired, 0028 applies: every row survives with a NULL grant decider and stays valid, the two CHECKs of 0020 are gone
// and the five constraints of 0028 exist; afterwards the api's tenant role records a decision through the tenant's own
// grant (and not through another tenant's — FK), the worker's role cannot write the column.
func TestMigration0028EnrollmentSupportDecider(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 27)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	f := newFixture()
	for v := int64(1); v <= 27; v++ {
		fixtureSteps[v](f, t, su)
	}
	// decisions of members, written before 0028 (the decider of 0020)
	approver, approverIdentity := newID(), newID()
	exec(t, su, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email) VALUES ($1, $2, $3, 'tenant', 'approver-'||$4, 'approver@'||$4||'.test')`,
		approverIdentity, f.a.idp, f.a.id, f.a.slug)
	exec(t, su, `INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status) VALUES ($1, $2, $3, $4, 'active')`,
		approver, f.a.id, approverIdentity, f.tenantRole)
	approved, rejected, pending := newID(), newID(), newID()
	exec(t, su, `INSERT INTO enrollment_requests (id, tenant_id, instance_id, requested_by_membership_id, method, target_membership_id,
			status, approver_membership_id, approved_at) VALUES ($1, $2, $3, $4, 'web_auth', $4, 'approved', $5, now())`,
		approved, f.a.id, f.a.instance, f.a.membership, approver)
	exec(t, su, `INSERT INTO enrollment_requests (id, tenant_id, instance_id, requested_by_membership_id, method, target_membership_id,
			status, approver_membership_id) VALUES ($1, $2, $3, $4, 'preauth_key', $4, 'rejected', $5)`,
		rejected, f.a.id, f.a.instance, f.a.membership, approver)
	exec(t, su, `INSERT INTO enrollment_requests (id, tenant_id, instance_id, requested_by_membership_id, method, target_membership_id,
			status) VALUES ($1, $2, $3, $4, 'web_auth', $4, 'pending_approval')`, pending, f.a.id, f.a.instance, f.a.membership)

	hasCol := func() bool { return hasColumn(t, su, "enrollment_requests", "approver_support_grant_id") }
	constraints := func() map[string]bool {
		rows, err := su.Query(ctx, `SELECT conname::text FROM pg_constraint WHERE conrelid = 'public.enrollment_requests'::regclass`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[n] = true
		}
		return out
	}
	// a schema that drifted from 0020 (the constraint 0028 drops is not where it expects it): refused as a whole
	exec(t, su, `ALTER TABLE enrollment_requests RENAME CONSTRAINT enrollment_requests_check7 TO enrollment_requests_check7_moved`)
	err = MigrateTo(ctx, mig, 28)
	if err == nil || !strings.Contains(err.Error(), "enrollment_requests_check7") {
		t.Fatalf("0028 on a schema without the expected CHECK: err = %v, want the refusal of the guard", err)
	}
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 27 || hasCol() || !constraints()["enrollment_requests_check7_moved"] ||
		!constraints()["enrollment_requests_check10"] {
		t.Fatalf("after the refused 0028: schema %d (%v), column %v, constraints %v — want 27, no column, nothing dropped",
			v, err, hasCol(), constraints())
	}
	exec(t, su, `ALTER TABLE enrollment_requests RENAME CONSTRAINT enrollment_requests_check7_moved TO enrollment_requests_check7`)

	before := publicRowCounts(t, su)
	if err := MigrateTo(ctx, mig, 28); err != nil {
		t.Fatalf("0028 on schema 27 with data: %v", err)
	}
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 28 {
		t.Fatalf("schema version = %d (%v), want 28", v, err)
	}
	after := publicRowCounts(t, su)
	for n, c := range before {
		if n != "goose_db_version" && after[n] != c {
			t.Errorf("%s: %d rows at schema 27, %d at schema 28", n, c, after[n])
		}
	}
	var withGrant, decidedByMember int64
	if err := su.QueryRow(ctx, `SELECT count(approver_support_grant_id), count(*) FILTER (WHERE approver_membership_id IS NOT NULL)
		FROM enrollment_requests`).Scan(&withGrant, &decidedByMember); err != nil || withGrant != 0 || decidedByMember != 2 {
		t.Fatalf("after 0028: %d requests with a grant decider, %d decided by a member (%v); want 0 and 2", withGrant, decidedByMember, err)
	}
	cs := constraints()
	for _, gone := range []string{"enrollment_requests_check7", "enrollment_requests_check10"} {
		if cs[gone] {
			t.Errorf("%s still exists", gone)
		}
	}
	for _, n := range []string{"enrollment_requests_one_decider_check", "enrollment_requests_approved_decider_check",
		"enrollment_requests_rejected_decider_check", "enrollment_requests_undecided_grant_check",
		"enrollment_requests_approver_support_grant_fkey", "enrollment_requests_check6", "enrollment_requests_check8",
		"enrollment_requests_check9"} {
		if !cs[n] {
			t.Errorf("constraint %s missing after 0028", n)
		}
	}
	fixtureSteps[28](f, t, su)

	// The api's tenant role, in tenant A's scope (as WithTenantTx): a decision through A's own grant is written; through
	// B's grant the composite FK refuses it; the worker's role holds no privilege on the column.
	inTenant := func(role string, sql string, args ...any) (int64, error) {
		c := e.connectAs(t, db, role)
		tx, err := c.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`,
			f.a.id.String()); err != nil {
			t.Fatal(err)
		}
		tag, err := tx.Exec(ctx, sql, args...)
		return tag.RowsAffected(), err
	}
	decide := `UPDATE enrollment_requests SET status = 'approved', approved_at = now(), approver_support_grant_id = $1,
		version = version + 1 WHERE id = $2`
	for _, c := range []struct {
		name, role string
		grant      uuid.UUID
		state      string
	}{
		{"api approves through A's grant", "mg_api_tenant", f.a.grant, ""},
		{"api approves through B's grant", "mg_api_tenant", f.b.grant, "23503"},
		{"worker records a decider", "mg_worker_tenant", f.a.grant, privilegeErr},
	} {
		n, err := inTenant(c.role, decide, c.grant, pending)
		if c.state != "" {
			wantSQLState(t, c.name, err, c.state)
			continue
		}
		if err != nil || n != 1 {
			t.Errorf("%s: %d rows (%v), want 1", c.name, n, err)
		}
	}
	// a decision of a member and of staff at once, on a request decided before 0028
	_, err = su.Exec(ctx, `UPDATE enrollment_requests SET approver_support_grant_id = $1 WHERE id = $2`, f.a.grant, approved)
	wantSQLState(t, "second decider on a member's approval", err, "23514")
	_, err = su.Exec(ctx, `UPDATE enrollment_requests SET approver_membership_id = NULL, approver_support_grant_id = $1 WHERE id = $2`,
		f.a.grant, rejected)
	if err != nil {
		t.Errorf("moving a rejection's decider to a grant (superuser): %v", err)
	}
}
