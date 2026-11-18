package store

// Migration 0025 (P4-T03a): platform_users.status pinned to {active, disabled}; the tenant pool may write the settings
// of ITS OWN tenant row and the claim columns of ITS OWN identity provider row — and nothing else of them. Run on a
// database at schema 24 holding rows of every table: a platform user with another status makes 0025 fail as a whole;
// repaired, 0025 applies, every row survives; afterwards the grants hold through the api's own roles (RLS keeps another
// tenant's rows out of reach, the immutable columns refuse 42501).

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMigration0025AdminSettings(t *testing.T) {
	e := requireDB(t)
	ctx := ctxT(t)
	db := e.newDatabase(t, 24)
	su := e.connectAdmin(t, db)
	mig, err := OpenMigrator(e.storeURL(db), e.creds(t, "mg_migrator"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close() }()
	f := newFixture()
	for v := int64(1); v <= 24; v++ {
		fixtureSteps[v](f, t, su)
	}
	exec(t, su, `UPDATE platform_users SET status = 'locked' WHERE id = $1`, f.platformUserRow)
	err = MigrateTo(ctx, mig, 25)
	if err == nil || !strings.Contains(err.Error(), "platform_users_status_check") {
		t.Fatalf("0025 over a platform user 'locked': err = %v, want the CHECK violation", err)
	}
	if v, err := SchemaVersion(ctx, mig); err != nil || v != 24 {
		t.Fatalf("schema version after the refused 0025 = %d (%v), want 24", v, err)
	}
	exec(t, su, `UPDATE platform_users SET status = 'active' WHERE id = $1`, f.platformUserRow)
	before := publicRowCounts(t, su)
	if err := MigrateTo(ctx, mig, 25); err != nil {
		t.Fatalf("0025 on schema 24 with data: %v", err)
	}
	after := publicRowCounts(t, su)
	for n, c := range before {
		if n != "goose_db_version" && after[n] != c {
			t.Errorf("%s: %d rows at schema 24, %d at schema 25", n, c, after[n])
		}
	}
	fixtureSteps[25](f, t, su)
	for _, st := range []string{"active", "disabled"} {
		if _, err := su.Exec(ctx, `UPDATE platform_users SET status = $1 WHERE id = $2`, st, f.platformUserRow); err != nil {
			t.Errorf("status %s refused: %v", st, err)
		}
	}
	for _, st := range []string{"locked", "removed", "Active", ""} {
		_, err := su.Exec(ctx, `UPDATE platform_users SET status = $1 WHERE id = $2`, st, f.platformUserRow)
		wantSQLState(t, "platform user status "+st, err, "23514")
	}

	// The grants of 0025 through the api's tenant role, in tenant A's scope.
	tc := e.connectAs(t, db, "mg_api_tenant")
	inTenant := func(tenant uuid.UUID, sql string, args ...any) (int64, error) {
		tx, err := tc.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`,
			tenant.String()); err != nil {
			t.Fatal(err)
		}
		tag, err := tx.Exec(ctx, sql, args...)
		return tag.RowsAffected(), err
	}
	a, b := f.a, f.b
	for _, c := range []struct {
		name, sql string
		args      []any
		rows      int64
		state     string
	}{
		{"own settings", `UPDATE tenants SET settings = '{"policy":{"four_eyes":true}}', version = version + 1 WHERE id = $1`, []any{a.id}, 1, ""},
		{"other tenant's settings (RLS)", `UPDATE tenants SET settings = '{}' WHERE id = $1`, []any{b.id}, 0, ""},
		{"own name (not granted)", `UPDATE tenants SET name = 'x' WHERE id = $1`, []any{a.id}, 0, "42501"},
		{"own status (not granted)", `UPDATE tenants SET status = 'active' WHERE id = $1`, []any{a.id}, 0, "42501"},
		{"own IdP claims", `UPDATE identity_providers SET required_claims = '{"hd":"a.test"}', allowed_email_domains = '{a.test}',
			claim_mapping = '{}', version = version + 1 WHERE id = $1`, []any{a.idp}, 1, ""},
		{"other tenant's IdP (RLS)", `UPDATE identity_providers SET claim_mapping = '{}' WHERE id = $1`, []any{b.idp}, 0, ""},
		{"own IdP issuer (immutable)", `UPDATE identity_providers SET issuer = 'https://evil.test' WHERE id = $1`, []any{a.idp}, 0, "42501"},
		{"own IdP client_id (immutable)", `UPDATE identity_providers SET client_id = 'x' WHERE id = $1`, []any{a.idp}, 0, "42501"},
		{"own IdP status (not granted)", `UPDATE identity_providers SET status = 'disabled' WHERE id = $1`, []any{a.idp}, 0, "42501"},
		{"own IdP require_email_verified (not granted)", `UPDATE identity_providers SET require_email_verified = false WHERE id = $1`, []any{a.idp}, 0, "42501"},
		{"platform IdP (RLS)", `UPDATE identity_providers SET claim_mapping = '{}' WHERE id = $1`, []any{f.platformIdP}, 0, ""},
		{"own IdP secret ref of another owner (CHECK 0007)", `UPDATE identity_providers SET client_secret_ref = 'mgsec://platform/x#1' WHERE id = $1`, []any{a.idp}, 0, "23514"},
	} {
		n, err := inTenant(a.id, c.sql, c.args...)
		if c.state != "" {
			wantSQLState(t, c.name, err, c.state)
			continue
		}
		if err != nil || n != c.rows {
			t.Errorf("%s: %d rows (%v), want %d", c.name, n, err, c.rows)
		}
	}
	// the worker's tenant role got nothing
	wc := e.connectAs(t, db, "mg_worker_tenant")
	tx, err := wc.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`, a.id.String()); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `UPDATE tenants SET settings = '{}' WHERE id = $1`, a.id)
	wantSQLState(t, "worker tenant settings", err, "42501")
}
