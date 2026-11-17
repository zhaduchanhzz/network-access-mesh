package main

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// TestAdminAuditToDatabase — G2 wiring hazard 7 (P2-T16): with the detached audit writer configured (always outside
// dev — config.LoadAdmin), the admin commands of P2-T11 write their audit events to audit_events through
// internal/audit — actor_type system, the request id of the run (admin-<uuid>) — instead of the process log; a client
// secret given on stdin never reaches the events. Outside dev the writer is required.
func TestAdminAuditToDatabase(t *testing.T) {
	tok := headscaletest.NewToken()
	edge := headscaletest.NewEdge(t, tok)
	tokenFile := t.TempDir() + "/edge_admin_token"
	writeTestFile(t, tokenFile, tok+"\n")
	c := newCLIEnv(t, edge.URL(), tokenFile)
	pg := storetest.Require(t)
	c.vars["MG_DB_AUDIT_WRITER_PASSWORD_FILE"] = pg.Creds(t, "mg_audit_writer").PasswordFile
	idp := uuid.Must(uuid.NewV7())
	c.vars["MG_IDP_ID_PLATFORM"] = idp.String()

	if code := c.run(nil, "register-platform-idp"); code != 0 {
		t.Fatalf("register-platform-idp: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	secret := "mg-canary-client-secret-" + uuid.NewString()
	if code := c.run(pipeWith(t, secret+"\n"), "set-idp-client-secret", idp.String()); code != 0 {
		t.Fatalf("set-idp-client-secret: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	if strings.Contains(c.out.String(), `"actor_type":"system"`) && strings.Contains(c.out.String(), "platform.idp.register") {
		t.Error("the audit events still go to the process log")
	}
	rows, err := c.su.Query(context.Background(), `SELECT action, actor_type, outcome, request_id, tenant_id IS NULL, details::text
		FROM audit_events WHERE action LIKE 'platform.idp.%' ORDER BY occurred_at`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, actor, outcome, rid, details string
		var platform bool
		if err := rows.Scan(&action, &actor, &outcome, &rid, &platform, &details); err != nil {
			t.Fatal(err)
		}
		if actor != "system" || outcome != "success" || !strings.HasPrefix(rid, "admin-") || !platform ||
			strings.Contains(details, secret) {
			t.Errorf("%s: actor %s outcome %s request %s platform %v details %s", action, actor, outcome, rid, platform, details)
		}
		got = append(got, action)
	}
	if strings.Join(got, ",") != "platform.idp.register,platform.idp.client_secret.update" {
		t.Fatalf("audit events %v", got)
	}

	// outside dev the detached writer is required
	delete(c.vars, "MG_DB_AUDIT_WRITER_PASSWORD_FILE")
	c.vars["MG_ENV"] = "staging"
	if code := c.run(nil, "register-platform-idp"); code != 2 && code != 1 ||
		!strings.Contains(c.stderr.String(), "MG_DB_AUDIT_WRITER_PASSWORD_FILE") {
		t.Fatalf("staging without the audit writer: %d %s", code, c.stderr.String())
	}
}
