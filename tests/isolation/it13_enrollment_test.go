//go:build mgtestfixture

package isolation_test

// IT-13 (AC-14), the platform side of enrollment (P4-T06): an enrollment request — the record a web-auth claim and a
// pre-auth key are bound to — never crosses tenants at the database. Scoped to tenant A exactly as WithTenantTx, the
// api's and the worker's tenant roles see none of B's requests, update none of them (RLS — the claim of an Auth ID issued
// through B, the expiry or consumption of B's key), and cannot write a request of B (WITH CHECK). The write is tried by
// a role that HOLDS the INSERT privilege, next to a request of A that the same role in the same scope may write, so
// the refusal can only be the policy's WITH CHECK — never a missing privilege (A6): the api role as it logs in (0020
// grants it INSERT), the worker role with INSERT granted inside a transaction that is rolled back (0020 grants it
// none, which is asserted too: the worker never creates a request). The service level — an Auth ID of A's instance
// sent to B's claim endpoint is refused before Headscale and no node appears in either — is internal/enrollment
// TestEnrollment/CrossTenantClaim; the real Headscale side (A's key refused by B's instance) is E2E-101 and
// tests/isolation/it13_preauth_cross_tenant.sh.

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// refusal classifies a refused write: "rls" (42501 new row violates row-level security policy), "privilege" (42501
// permission denied), "" for anything else (no error, another SQLSTATE).
func refusal(err error) string {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "42501" {
		return ""
	}
	switch {
	case strings.Contains(pg.Message, "row-level security"):
		return "rls"
	case strings.Contains(pg.Message, "permission denied"):
		return "privilege"
	}
	return ""
}

func TestIT13EnrollmentRequestsStayInTheTenant(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	env := storetest.Require(t)
	host := uuid.Must(uuid.NewV7())
	w.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-it13', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	inst := map[string]uuid.UUID{}
	req := map[string]uuid.UUID{}
	member := map[string]uuid.UUID{}
	tenants := map[string]*sessionfixture.Tenant{"A": w.A, "B": w.B}
	for i, ten := range []*sessionfixture.Tenant{w.A, w.B} {
		id := uuid.Must(uuid.NewV7())
		inst[ten.Name] = id
		w.Exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
			id, ten.ID, host, ten.Slug+".mesh.test", ten.Slug+".ts.test", "hs-"+ten.Slug+":8080", 31001+i,
			"10.250."+string(rune('0'+i))+".0/29", "/opt/meshguard/tenants/"+id.String())
		member[ten.Name] = w.Actor(t, authz.RoleEndUser, ten).MembershipID
		r := uuid.Must(uuid.NewV7())
		req[ten.Name] = r
		w.Exec(t, `INSERT INTO enrollment_requests (id, tenant_id, instance_id, requested_by_membership_id, method,
				target_membership_id, status, issued_at, credential_expires_at, enroll_code_hash, session_id_hash)
			VALUES ($1, $2, $3, $4, 'web_auth', $4, 'awaiting_device', now(), now() + interval '10 minutes',
				sha256($5::bytea), sha256($6::bytea))`, r, ten.ID, id, member[ten.Name], []byte("code-"+ten.Name),
			[]byte("session-"+ten.Name))
	}
	// insert writes a new request of tenant name (its instance, its End User) in tx.
	insert := func(tx pgx.Tx, name string) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id,
				method, target_membership_id) VALUES ($1, $2, $3, 'web_auth', $3)`, tenants[name].ID, inst[name], member[name])
		return err
	}
	// scopeA scopes tx to tenant A exactly as WithTenantTx does.
	scopeA := func(tx pgx.Tx) {
		if _, err := tx.Exec(t.Context(), `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`,
			w.A.ID.String()); err != nil {
			t.Fatal(err)
		}
	}
	// granted runs fn as role with INSERT on enrollment_requests granted for the duration of one superuser transaction
	// (SET LOCAL ROLE: the role's own privileges and policies apply; GRANT and every row are rolled back with it).
	su := env.Admin(t, w.DB)
	granted := func(role string, fn func(tx pgx.Tx)) {
		tx, err := su.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if _, err := tx.Exec(t.Context(), `GRANT INSERT ON enrollment_requests TO `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SET LOCAL ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		scopeA(tx)
		fn(tx)
	}
	for _, tc := range []struct {
		role     string
		mayWrite bool // 0020 grants the role INSERT on enrollment_requests
	}{{"mg_api_tenant", true}, {"mg_worker_tenant", false}} {
		role := tc.role
		cfg, err := pgx.ParseConfig(env.URL(w.DB))
		if err != nil {
			t.Fatal(err)
		}
		cfg.User, cfg.Password = role, env.Password(role)
		c, err := pgx.ConnectConfig(t.Context(), cfg)
		if err != nil {
			t.Fatalf("connect as %s: %v", role, err)
		}
		scoped := func(fn func(tx pgx.Tx)) {
			tx, err := c.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			scopeA(tx)
			fn(tx)
		}
		scoped(func(tx pgx.Tx) {
			var n int
			if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM enrollment_requests`).Scan(&n); err != nil || n != 1 {
				t.Errorf("%s: sees %d request(s) (%v), want only A's", role, n, err)
			}
			if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM enrollment_requests WHERE id = $1`, req["B"]).Scan(&n); err != nil || n != 0 {
				t.Errorf("%s: sees B's request (%d, %v)", role, n, err)
			}
		})
		scoped(func(tx pgx.Tx) {
			tag, err := tx.Exec(t.Context(), `UPDATE enrollment_requests SET status = 'expired' WHERE id = $1`, req["B"])
			if err != nil || tag.RowsAffected() != 0 {
				t.Errorf("%s: update of B's request: %v rows %d, want 0 (RLS)", role, err, tag.RowsAffected())
			}
		})
		// the privilege 0020 gives the role as it logs in
		scoped(func(tx pgx.Tx) {
			err := insert(tx, "A")
			switch {
			case tc.mayWrite && err != nil:
				t.Errorf("%s: insert of a request of A in A's scope: %v, want it written (the role may insert)", role, err)
			case !tc.mayWrite && refusal(err) != "privilege":
				t.Errorf("%s: insert of a request of A: %v, want 42501 permission denied (0020 grants no INSERT)", role, err)
			}
		})
		if tc.mayWrite {
			scoped(func(tx pgx.Tx) {
				if err := insert(tx, "B"); refusal(err) != "rls" {
					t.Errorf("%s: insert of a request of B in A's scope: %v, want 42501 from the row-level security "+
						"policy (WITH CHECK) — the role may insert", role, err)
				}
			})
		}
		_ = c.Close(t.Context())
		// WITH CHECK for the role even where 0020 grants no INSERT: with the privilege, A's request is written and B's
		// is refused by the policy — never by a missing privilege
		granted(role, func(tx pgx.Tx) {
			if err := insert(tx, "A"); err != nil {
				t.Errorf("%s with INSERT: insert of a request of A in A's scope: %v, want it written", role, err)
			}
		})
		granted(role, func(tx pgx.Tx) {
			if err := insert(tx, "B"); refusal(err) != "rls" {
				t.Errorf("%s with INSERT: insert of a request of B in A's scope: %v, want 42501 from the row-level "+
					"security policy (WITH CHECK)", role, err)
			}
		})
	}
	var st string
	var n int
	w.Scan(t, `SELECT status FROM enrollment_requests WHERE id = $1`, []any{req["B"]}, &st)
	w.Scan(t, `SELECT count(*) FROM enrollment_requests`, nil, &n)
	if st != "awaiting_device" || n != 2 {
		t.Errorf("B's request changed (%s) or a write was kept (%d requests, want 2)", st, n)
	}
	var grants string
	w.Scan(t, `SELECT coalesce(string_agg(grantee || ':' || privilege_type, ',' ORDER BY grantee, privilege_type), '')
		FROM information_schema.role_table_grants
		WHERE table_name = 'enrollment_requests' AND grantee = 'mg_worker_tenant' AND privilege_type = 'INSERT'`, nil, &grants)
	if grants != "" {
		t.Errorf("the test's INSERT grant to the worker outlived its transaction: %s", grants)
	}
}
