//go:build mgtestfixture

package isolation_test

// IT-13 (AC-14), the platform side of enrollment (P4-T06): an enrollment request — the record a web-auth claim and a
// pre-auth key are bound to — never crosses tenants at the database. Scoped to tenant A exactly as WithTenantTx, the
// api's and the worker's tenant roles see none of B's requests, update none of them (RLS — the claim of an Auth ID issued
// through B, the expiry or consumption of B's key), and cannot write a request of B (WITH CHECK). The service level —
// an Auth ID of A's instance sent to B's claim endpoint is refused before Headscale and no node appears in either — is
// internal/enrollment TestEnrollment/CrossTenantClaim; the real Headscale side (A's key refused by B's instance) is
// E2E-101 and tests/isolation/it13_preauth_cross_tenant.sh.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestIT13EnrollmentRequestsStayInTheTenant(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	env := storetest.Require(t)
	host := uuid.Must(uuid.NewV7())
	w.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-it13', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	inst := map[string]uuid.UUID{}
	req := map[string]uuid.UUID{}
	member := map[string]uuid.UUID{}
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
	for _, role := range []string{"mg_api_tenant", "mg_worker_tenant"} {
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
			if _, err := tx.Exec(t.Context(), `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`,
				w.A.ID.String()); err != nil {
				t.Fatal(err)
			}
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
		scoped(func(tx pgx.Tx) {
			_, err := tx.Exec(t.Context(), `INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id,
					method, target_membership_id) VALUES ($1, $2, $3, 'web_auth', $3)`, w.B.ID, inst["B"], member["B"])
			if st := store.SQLState(err); st != "42501" {
				t.Errorf("%s: insert of a request of B: %v (sqlstate %s), want 42501", role, err, st)
			}
		})
		_ = c.Close(t.Context())
	}
	var st string
	w.Scan(t, `SELECT status FROM enrollment_requests WHERE id = $1`, []any{req["B"]}, &st)
	if st != "awaiting_device" {
		t.Errorf("B's request changed: %s", st)
	}
}
