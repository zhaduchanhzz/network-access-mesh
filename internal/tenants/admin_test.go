package tenants_test

// Integration tests of the tenant administration of P4-T03a (settings, security settings and their approved execution,
// the IdP claim constraints and a platform change of them, the deletion request) on a real PostgreSQL with the api
// roles: every write runs in the tenant's own transaction (0025), refuses another tenant's rows, keeps the keys it does
// not own, and an approved change runs only on the state it was approved on.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func reqCtx(ctx context.Context, actor uuid.UUID, tenant *uuid.UUID, action string) context.Context {
	return audit.WithRequest(ctx, &audit.Request{Action: action, ActorType: audit.ActorIdentity, ActorIdentityID: &actor,
		TenantID: tenant, RequestID: "test-" + uuid.NewString()})
}

func fresh(id, membership uuid.UUID) tenants.Actor {
	return tenants.Actor{IdentityID: id, MembershipID: membership, AuthTime: time.Now(), Display: "Owner"}
}

func TestSettingsAndSecurity(t *testing.T) {
	f := newFixture(t)
	a, idpA := f.tenant("adm-a", "A", "active", false)
	b, _ := f.tenant("adm-b", "B", "active", false)
	f.exec(`UPDATE tenants SET settings = '{"dns":{"magic_dns":true},"future_key":{"x":1},"policy":{"four_eyes":"yes"}}' WHERE id = $1`, a)
	ownerID, ownerM := f.member(a, idpA, "Owner", "o@a.test", "tenant_owner", "active")
	ctx := reqCtx(t.Context(), ownerID, &a, tenants.ActionSecuritySettingsUpdate)

	v, err := f.svc.GetSettings(ctx, a)
	if err != nil || v.Settings.Policy.FourEyes || !v.Settings.Enrollment.WebAuthEnabled || !strings.Contains(string(v.Settings.DNS), "magic_dns") {
		t.Fatalf("defaults over an ill-typed document: %+v, %v", v.Settings, err)
	}
	if _, err := f.svc.GetSettings(ctx, uuid.New()); !errors.Is(err, tenants.ErrNotFound) {
		t.Fatalf("missing tenant: %v", err)
	}
	g := uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, 'finance')`, g, a)
	gb := uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, 'finance')`, gb, b)
	want := v.Settings.Security()
	want.PolicyFourEyes, want.SensitiveGroups = true, []uuid.UUID{gb}
	if _, err := f.svc.PutSecuritySettings(ctx, fresh(ownerID, ownerM), a, want, v.ETag); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("another tenant's group as sensitive: %v", err)
	}
	want.SensitiveGroups = []uuid.UUID{g}
	if _, err := f.svc.PutSecuritySettings(ctx, tenants.Actor{IdentityID: ownerID, AuthTime: time.Now().Add(-time.Hour)}, a, want,
		v.ETag); !errors.Is(err, tenants.ErrReauthRequired) {
		t.Fatalf("without step-up: %v", err)
	}
	if _, err := f.svc.PutSecuritySettings(ctx, fresh(ownerID, ownerM), a, want, ""); !errors.Is(err, tenants.ErrPreconditionRequired) {
		t.Fatalf("without If-Match: %v", err)
	}
	res, err := f.svc.PutSecuritySettings(ctx, fresh(ownerID, ownerM), a, want, v.ETag)
	if err != nil || res.Approval != nil || !res.View.Settings.Policy.FourEyes || res.View.ETag == v.ETag {
		t.Fatalf("tightening: %+v, %v", res, err)
	}
	var raw string
	if err := f.su.QueryRow(t.Context(), `SELECT settings::text FROM tenants WHERE id = $1`, a).Scan(&raw); err != nil ||
		!strings.Contains(raw, "future_key") || !strings.Contains(raw, "magic_dns") {
		t.Fatalf("keys of others lost: %s (%v)", raw, err)
	}
	var notified int
	if err := f.su.QueryRow(t.Context(), `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1
		AND kind = 'tenant.security_settings_changed'`, a).Scan(&notified); err != nil || notified != 1 {
		t.Fatalf("notifications of the write: %d (%v)", notified, err)
	}

	// lifting 4-eyes: the payload of an approval, nothing written; executed on the same ETag only
	lift := res.View.Settings.Security()
	lift.PolicyFourEyes, lift.SensitiveGroups = false, []uuid.UUID{}
	res2, err := f.svc.PutSecuritySettings(ctx, fresh(ownerID, ownerM), a, lift, res.View.ETag)
	if err != nil || res2.Approval == nil || len(res2.Approval.Weakens) != 2 || res2.Approval.IfMatch != res.View.ETag {
		t.Fatalf("lifting: %+v, %v", res2, err)
	}
	exec := func(tenant uuid.UUID, p tenants.SecuritySettingsPayload) error {
		return f.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			return f.svc.ExecuteSecuritySettings(ctx, tx, tenant, tenants.ApprovalExecution{ApprovalID: uuid.New(),
				RequestedBy: ownerID, DecidedBy: uuid.New()}, p)
		})
	}
	if err := exec(b, *res2.Approval); !errors.Is(err, tenants.ErrStale) {
		t.Fatalf("executed on another tenant: %v", err)
	}
	stale := *res2.Approval
	stale.IfMatch = `"0000"`
	if err := exec(a, stale); !errors.Is(err, tenants.ErrStale) {
		t.Fatalf("stale execution: %v", err)
	}
	if err := exec(a, *res2.Approval); err != nil {
		t.Fatalf("execution: %v", err)
	}
	if v, _ := f.svc.GetSettings(ctx, a); v.Settings.Policy.FourEyes || len(v.Settings.Policy.SensitiveGroups) != 0 {
		t.Fatalf("after execution: %+v", v.Settings)
	}
	if err := exec(a, *res2.Approval); !errors.Is(err, tenants.ErrStale) {
		t.Fatalf("second execution of the same payload: %v", err)
	}

	// identity_mode: headscale_oidc unavailable; immutable once a Headscale user exists (ID-08)
	v, _ = f.svc.GetSettings(ctx, a)
	oidc := v.Settings.Security()
	oidc.IdentityMode = config.IdentityModeHeadscaleOIDC
	if _, err := f.svc.PutSecuritySettings(ctx, fresh(ownerID, ownerM), a, oidc, v.ETag); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("headscale_oidc: %v", err)
	}
	f.exec(`UPDATE tenants SET settings = jsonb_set(settings, '{enrollment,identity_mode}', '"headscale_oidc"') WHERE id = $1`, a)
	f.exec(`UPDATE tenant_memberships SET headscale_user_id = 7 WHERE id = $1`, ownerM)
	v, _ = f.svc.GetSettings(ctx, a)
	back := v.Settings.Security()
	back.IdentityMode = config.IdentityModePortal
	if _, err := f.svc.PutSecuritySettings(ctx, fresh(ownerID, ownerM), a, back, v.ETag); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("identity_mode after the first Headscale user: %v", err)
	}

	// PATCH /settings: regular keys only, If-Match
	ttl := "45m"
	if _, err := f.svc.PatchSettings(ctx, a, config.SettingsPatch{PreauthKeyTTLMax: &ttl}, `"stale"`); !errors.Is(err, tenants.ErrPreconditionFailed) {
		t.Fatalf("stale PATCH: %v", err)
	}
	bad := "3s"
	if _, err := f.svc.PatchSettings(ctx, a, config.SettingsPatch{PreauthKeyTTLMax: &bad}, v.ETag); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("invalid TTL: %v", err)
	}
	p, err := f.svc.PatchSettings(ctx, a, config.SettingsPatch{PreauthKeyTTLMax: &ttl}, v.ETag)
	if err != nil || p.Settings.Enrollment.PreauthKeyTTLMax != "45m" || p.Settings.Enrollment.IdentityMode != config.IdentityModeHeadscaleOIDC {
		t.Fatalf("PATCH: %+v, %v", p.Settings, err)
	}
}

func TestIdPConfig(t *testing.T) {
	f := newFixture(t)
	a, idpA := f.tenant("idp-a", "A", "active", false)
	b, idpB := f.tenant("idp-b", "B", "active", false)
	ownerID, ownerM := f.member(a, idpA, "Owner", "o@a.test", "tenant_owner", "active")
	ctx := reqCtx(t.Context(), ownerID, &a, tenants.ActionIdPUpdate)
	cur, err := f.svc.GetActiveIdP(ctx, a)
	if err != nil || cur.ID != idpA || cur.ClientSecretSet {
		t.Fatalf("active IdP: %+v, %v", cur, err)
	}
	domains := []string{"A.test", "a.test", "b.test"}
	got, err := f.svc.UpdateIdP(ctx, fresh(ownerID, ownerM), a, tenants.IdPChange{AllowedEmailDomains: &domains,
		RequiredClaims: []byte(`{"hd":["a.test","b.test"]}`)}, nil, cur.ETag)
	if err != nil || strings.Join(got.AllowedEmailDomains, ",") != "a.test,b.test" || got.Version != cur.Version+1 {
		t.Fatalf("UpdateIdP: %+v, %v", got, err)
	}
	if _, err := f.svc.UpdateIdP(ctx, fresh(ownerID, ownerM), a, tenants.IdPChange{RequiredClaims: []byte(`{"sub":"x"}`)}, nil,
		got.ETag); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("required claim on sub: %v", err)
	}
	if _, err := f.svc.UpdateIdP(ctx, fresh(ownerID, ownerM), a, tenants.IdPChange{}, []byte(strings.Repeat("ab", 10)),
		got.ETag); !errors.Is(err, tenants.ErrUnavailable) {
		t.Fatalf("client secret without a SecretStore: %v", err)
	}

	// a platform change: applied in the tenant's transaction, only on the approved version, never on another tenant
	pctx := reqCtx(t.Context(), uuid.New(), nil, "platform.approval.approve")
	change := tenants.PlatformIdPChange{IdPID: idpA, TenantID: a, Version: got.Version,
		RequiredClaims: map[string]any{"hd": "a.test"}, AllowedEmailDomains: []string{"a.test"},
		ClaimMapping: map[string]string{"name": "preferred_username"}, Changed: []string{"claim_mapping"}}
	exec := tenants.ApprovalExecution{ApprovalID: uuid.New(), RequestedBy: uuid.New(), DecidedBy: uuid.New()}
	wrong := change
	wrong.IdPID = idpB
	if err := f.svc.ApplyPlatformIdPChange(pctx, wrong, exec); !errors.Is(err, tenants.ErrStale) {
		t.Fatalf("B's IdP under A's tenant: %v", err)
	}
	wrongTenant := change
	wrongTenant.TenantID, wrongTenant.IdPID = b, idpA
	if err := f.svc.ApplyPlatformIdPChange(pctx, wrongTenant, exec); !errors.Is(err, tenants.ErrStale) {
		t.Fatalf("A's IdP in B's scope: %v", err)
	}
	if err := f.svc.RecordPlatformIdPChangeRequested(pctx, change, exec.ApprovalID, exec.RequestedBy, "SA", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ApplyPlatformIdPChange(pctx, change, exec); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := f.svc.ApplyPlatformIdPChange(pctx, change, exec); err != nil {
		t.Fatalf("a retry of the same approval after it wrote: %v", err)
	}
	other := change
	other.ClaimMapping = map[string]string{}
	if err := f.svc.ApplyPlatformIdPChange(pctx, other, exec); !errors.Is(err, tenants.ErrStale) {
		t.Fatalf("a different change at the old version: %v", err)
	}
	var n int
	if err := f.su.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE tenant_id = $1
		AND action IN ('identity_provider.platform_change.request', 'identity_provider.platform_change.apply')`, a).Scan(&n); err != nil || n != 2 {
		t.Fatalf("tenant audit of the platform change: %d (%v)", n, err)
	}
	var issuer string
	if err := f.su.QueryRow(t.Context(), `SELECT issuer FROM identity_providers WHERE id = $1`, idpB).Scan(&issuer); err != nil ||
		!strings.HasSuffix(issuer, "idp-b") {
		t.Fatalf("B's IdP: %q (%v)", issuer, err)
	}
}

func TestRequestDeletion(t *testing.T) {
	f := newFixture(t)
	a, idpA := f.tenant("del-a", "A", "active", false)
	ownerID, ownerM := f.member(a, idpA, "Owner", "o@a.test", "tenant_owner", "active")
	ctx := reqCtx(t.Context(), ownerID, &a, tenants.ActionDeletionRequest)
	if _, err := f.svc.RequestDeletion(ctx, fresh(ownerID, ownerM), a, "nope", "x"); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("wrong slug: %v", err)
	}
	d, err := f.svc.RequestDeletion(ctx, fresh(ownerID, ownerM), a, "del-a", "closing")
	if err != nil || !d.PlatformNotified || d.RequestedByName != "Owner" {
		t.Fatalf("request: %+v, %v", d, err)
	}
	var platform, tenant int
	if err := f.su.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = 'platform.tenant.deletion_requested'),
		(SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'tenant.deletion.request')`, a).Scan(&platform, &tenant); err != nil ||
		platform != 1 || tenant != 1 {
		t.Fatalf("audit: platform %d tenant %d (%v)", platform, tenant, err)
	}
}
