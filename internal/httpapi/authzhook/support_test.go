package authzhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
)

// TestAuthzMarksSupportActors (P4-T13, §8.7 step 3): a request decided through a Support Access Grant — granted, or
// refused by the grant's role — carries actor_type=support, the grant and the tenant of the path in its audit scope (its
// events belong to the tenant's trail); any other request keeps the identity actor and no tenant of its own.
func TestAuthzMarksSupportActors(t *testing.T) {
	tenant, grant := uuid.New(), uuid.New()
	cases := []struct {
		name    string
		d       authz.Decision
		err     error
		support bool
	}{
		{"granted through a grant", authz.Decision{TenantID: tenant, SupportGrantID: grant, PlatformUserID: uuid.New()}, nil, true},
		{"refused by the grant's role", authz.Decision{}, &authz.Denial{Kind: authz.ErrForbidden, Reason: "no_grant", SupportGrantID: grant}, true},
		{"staff without grant", authz.Decision{}, &authz.Denial{Kind: authz.ErrForbidden, Reason: "no_support_grant"}, false},
		{"member", authz.Decision{TenantID: tenant, MembershipID: uuid.New()}, nil, false},
	}
	for _, c := range cases {
		f := &fakeAuthorizer{decide: func(string) (authz.Decision, error) { return c.d, c.err }}
		req := &audit.Request{ActorType: audit.ActorIdentity}
		ctx := audit.WithRequest(context.Background(), req)
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/tenants/"+tenant.String()+"/devices", nil)
		r.SetPathValue("tenantId", tenant.String())
		ran := false
		h := Authz(f)(func(context.Context, http.ResponseWriter, *http.Request, any) (any, error) {
			ran = true
			return nil, nil
		}, "ListDevices")
		_, err := h(ctx, httptest.NewRecorder(), r, nil)
		if (err == nil) != (c.err == nil) || ran != (c.err == nil) {
			t.Errorf("%s: err %v, handler ran %v", c.name, err, ran)
		}
		marked := req.ActorType == audit.ActorSupport && req.SupportGrantID != nil && *req.SupportGrantID == grant &&
			req.ActorTenantID != nil && *req.ActorTenantID == tenant
		untouched := req.ActorType == audit.ActorIdentity && req.SupportGrantID == nil && req.ActorTenantID == nil
		if c.support && !marked || !c.support && !untouched {
			t.Errorf("%s: audit scope %+v", c.name, req)
		}
	}
}
