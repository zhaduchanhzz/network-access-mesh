package enrollment

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// supportStaff is a Platform Support member holding a Support Access Grant (support_operator) into a tenant.
type supportStaff struct {
	identity, platformUser, grant uuid.UUID
}

// supportGrant creates a Platform Support member and its grant into ten, approved by the tenant's owner (§8.7).
func (f *fixture) supportGrant(t *testing.T, ten *tenantFx) supportStaff {
	t.Helper()
	idp, s := uuid.New(), supportStaff{identity: uuid.New(), platformUser: uuid.New(), grant: uuid.New()}
	f.exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', $2, 'admin', 'external', 'active')`, idp, "https://idp.invalid/platform-"+idp.String())
	f.exec(t, `INSERT INTO identities (id, idp_id, scope, subject, display_name) VALUES ($1, $2, 'platform', $3, 'Support')`,
		s.identity, idp, uuid.NewString())
	f.exec(t, `INSERT INTO platform_users (id, identity_id, role_id)
		SELECT $1, $2, id FROM roles WHERE scope = 'platform' AND key = 'platform_support'`, s.platformUser, s.identity)
	f.exec(t, `INSERT INTO support_access_grants (id, tenant_id, grantee_platform_user_id, requested_by_platform_user_id,
			effective_role_key, reason, ticket_ref, starts_at, expires_at)
		VALUES ($1, $2, $3, $3, 'support_operator', 'leaked key', 'T-C4', now() - interval '1 minute', now() + interval '1 hour')`,
		s.grant, ten.id, s.platformUser)
	f.exec(t, `UPDATE support_access_grants SET status = 'approved', approval_kind = 'tenant', approved_by_membership_id = $2,
		decided_at = now() WHERE id = $1`, s.grant, ten.people["owner"].membership)
	return s
}

// ctx is the scope of a request of s decided through its grant into tenant (what authz and authzhook set): the
// support actor every tenant transaction re-checks, and the audit scope of a support actor.
func (s supportStaff) ctx(tenant uuid.UUID, action string) context.Context {
	id, g, ten := s.identity, s.grant, tenant
	ctx := audit.WithRequest(context.Background(), &audit.Request{Action: action, ActorType: audit.ActorSupport,
		ActorIdentityID: &id, ActorTenantID: &ten, ActorDisplay: "Support", SupportGrantID: &g, TenantID: &ten,
		ResourceType: "enrollment_request", RequestID: "req-support-" + uuid.NewString()})
	return store.WithSupportActor(ctx, store.SupportActor{GrantID: s.grant, PlatformUserID: s.platformUser})
}

// TestSupportActorRevokesLiveKey (C4): platform staff with a live Support Access Grant into the tenant (§8.6 cell G of
// tenant.enrollment:revoke — enrollmentapi hands the service an actor of scope any, without a membership) revoke a
// leaked pre-auth key that may still register a node. It is the remote branch of revoke: the operation's requested
// event, the key expired at Headscale, then a second transaction (re-checking the grant) marks the request revoked and
// closes the operation succeeded — both events in the tenant's trail as the support actor of the grant, with the key
// id. Once the grant is revoked, the same call is refused before any statement (store.ErrSupportGrantNotLive): the key
// stays live at Headscale and the request unchanged, nothing audited by the service.
func TestSupportActorRevokesLiveKey(t *testing.T) {
	f := newFixture(t)
	a := f.a
	admin := a.actor("admin", uuid.New())
	issue := func(key string) (uuid.UUID, uint64) {
		t.Helper()
		out, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin, NewKey{Tags: []string{"tag:server"}},
			idem(key, key))
		if err != nil || out.Request.Status != StatusIssued {
			t.Fatalf("key: %+v %v", out.Request, err)
		}
		keys := a.hs.Keys()
		return out.Request.ID, keys[len(keys)-1].ID
	}
	staff := f.supportGrant(t, a)
	support := Actor{IdentityID: staff.identity, Display: "Support"}
	id, kid := issue("k-support-1")
	r, err := f.api.Revoke(staff.ctx(a.id, ActionRevoke), a.id, id, support)
	if err != nil || r.Status != StatusRevoked {
		t.Fatalf("revoke by the support actor: %+v %v", r, err)
	}
	if k := a.hs.Key(kid); k.Expiration.After(time.Now().Add(time.Second)) {
		t.Fatalf("key not expired at Headscale: %+v", k)
	}
	if got := joined(revokeEvents(f.auditOf(t, id.String()))); got !=
		"enrollment.revoke.requested/success,enrollment.revoke.succeeded/success" {
		t.Fatalf("revoke events %s", got)
	}
	if n := f.count(t, `SELECT count(DISTINCT operation_id) FROM audit_events WHERE resource_id = $1 AND tenant_id = $2
		AND action IN ('enrollment.revoke.requested', 'enrollment.revoke.succeeded') AND actor_type = 'support'
		AND support_grant_id = $3 AND actor_identity_id = $4 AND operation_id IS NOT NULL
		AND (details ->> 'key_id')::bigint = $5`, id.String(), a.id, staff.grant, staff.identity, int64(kid)); n != 1 { //nolint:gosec // a Headscale id
		t.Errorf("revoke events as the support actor (one operation, the key id): %d", n)
	}
	// the grant ends: the revoke of another live key is refused before anything is written or called
	id2, kid2 := issue("k-support-2")
	f.exec(t, `UPDATE support_access_grants SET status = 'revoked', revoked_at = now() WHERE id = $1`, staff.grant)
	if _, err := f.api.Revoke(staff.ctx(a.id, ActionRevoke), a.id, id2, support); !errors.Is(err, store.ErrSupportGrantNotLive) {
		t.Fatalf("revoke after the grant ended: %v", err)
	}
	if k := a.hs.Key(kid2); !k.Expiration.After(time.Now().Add(time.Minute)) {
		t.Errorf("key expired at Headscale by a refused call: %+v", k)
	}
	if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, id2); st != StatusCredentialIssued {
		t.Errorf("request %s after a refused revoke", st)
	}
	if got := revokeEvents(f.auditOf(t, id2.String())); len(got) != 0 {
		t.Errorf("events of the refused revoke %v", got)
	}
	f.noKeyMaterial(t)
}

// revokeEvents keeps the events of enrollment.revoke (action/outcome, as auditOf lists them).
func revokeEvents(events []string) []string {
	var out []string
	for _, e := range events {
		if strings.HasPrefix(e, ActionRevoke+".") || strings.HasPrefix(e, ActionRevoke+"/") {
			out = append(out, e)
		}
	}
	return out
}
