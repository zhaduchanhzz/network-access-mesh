package provisioning_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// TestIdPAdmin — register-platform-idp (idempotent, issuer immutable) and set-idp-client-secret for the platform IdP
// (platform DEK, readable by the api) and for a tenant IdP (the tenant's DEK): reference recorded, older versions
// erased, the value never in the log or the audit.
func TestIdPAdmin(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	ia := &provisioning.IdPAdmin{Tenants: f.ten, Secrets: f.ss, Audit: f.audit}

	platformID := uuid.Must(uuid.NewV7())
	spec := provisioning.KeycloakRealmIdP(platformID, nil, provisioning.PlatformRealm, baseDomain)
	p, existed, err := ia.RegisterPlatformIdP(ctx, spec)
	if err != nil || existed || p.Issuer != "https://auth.mg.test/realms/platform" || p.ClientID != "mg-portal" {
		t.Fatalf("RegisterPlatformIdP = %+v, %v, %v", p, existed, err)
	}
	if _, existed, err := ia.RegisterPlatformIdP(ctx, spec); err != nil || !existed {
		t.Fatalf("again: %v %v", existed, err)
	}
	moved := provisioning.KeycloakRealmIdP(platformID, nil, provisioning.PlatformRealm, "other.test")
	if _, _, err := ia.RegisterPlatformIdP(ctx, moved); !errors.Is(err, provisioning.ErrRefused) {
		t.Fatalf("issuer change: %v", err)
	}
	tid := uuid.New()
	if _, _, err := ia.RegisterPlatformIdP(ctx, provisioning.KeycloakRealmIdP(uuid.New(), &tid, "tenant-a", baseDomain)); !errors.Is(err, provisioning.ErrRefused) {
		t.Fatalf("tenant IdP through register-platform-idp: %v", err)
	}

	// the platform client secret, twice: version 2 replaces version 1
	s1 := "CANARY1" + strings.Repeat("p", 25)
	s2 := "CANARY2" + strings.Repeat("q", 25)
	r1, err := ia.SetClientSecret(ctx, platformID, []byte(s1))
	if err != nil || r1.Ref != "mgsec://platform/idp-client-secret."+platformID.String()+"#1" || r1.PreviousRef != "" {
		t.Fatalf("SetClientSecret = %+v, %v", r1, err)
	}
	r2, err := ia.SetClientSecret(ctx, platformID, []byte(s2))
	if err != nil || r2.PreviousRef != r1.Ref || !slices.Equal(r2.DestroyedRefs, []string{r1.Ref}) {
		t.Fatalf("second SetClientSecret = %+v, %v", r2, err)
	}
	ref2, _ := secrets.ParseRef(r2.Ref)
	pt, err := f.ss.Get(ctx, ref2)
	if err != nil || string(pt.Bytes()) != s2 {
		t.Fatalf("stored platform secret: %v", err)
	}
	ref1, _ := secrets.ParseRef(r1.Ref)
	if _, err := f.ss.Get(ctx, ref1); !errors.Is(err, secrets.ErrDestroyed) {
		t.Fatalf("version 1 after rotation: %v", err)
	}
	var scope, recorded string
	if err := f.su.QueryRow(ctx, `SELECT s.scope, p.client_secret_ref FROM secrets s, identity_providers p
		WHERE s.tenant_id IS NULL AND s.version = 2 AND p.id = $1`, platformID).Scan(&scope, &recorded); err != nil ||
		scope != "platform" || recorded != r2.Ref {
		t.Fatalf("platform secret scope %s, recorded %s (%v)", scope, recorded, err)
	}

	// a tenant IdP: adopted with its tenant, secret under the tenant's DEK
	a := newSubject("tenant-a", 0)
	key, _ := f.a.NewKey(90 * day)
	if _, err := f.ad.Adopt(ctx, a.request(key)); err != nil {
		t.Fatal(err)
	}
	s3 := "CANARY3" + strings.Repeat("r", 25)
	r3, err := ia.SetClientSecret(ctx, a.idp, []byte(s3))
	if err != nil || r3.Ref != "mgsec://"+a.meta.TenantID.String()+"/idp-client-secret."+a.idp.String()+"#1" ||
		r3.IdP.Scope != "tenant" {
		t.Fatalf("tenant SetClientSecret = %+v, %v", r3, err)
	}
	if _, err := ia.SetClientSecret(ctx, uuid.New(), []byte(s3)); !errors.Is(err, provisioning.ErrRefused) {
		t.Fatalf("unknown IdP: %v", err)
	}

	// no value in the log, the audit or a plaintext column
	logs := f.logs.String()
	for _, s := range []string{s1, s2, s3} {
		if strings.Contains(logs, s) {
			t.Fatal("a client secret reached the log")
		}
		for _, ev := range f.audit.events {
			for _, v := range ev.Details {
				if strings.Contains(strings.ToLower(toString(v)), strings.ToLower(s)) {
					t.Fatal("a client secret reached an audit event")
				}
			}
		}
		var n int
		if err := f.su.QueryRow(ctx, `SELECT (SELECT count(*) FROM secrets s WHERE s::text LIKE '%'||$1||'%')
			+ (SELECT count(*) FROM identity_providers p WHERE p::text LIKE '%'||$1||'%')`, s).Scan(&n); err != nil || n != 0 {
			t.Fatalf("plaintext found in the database: %d %v", n, err)
		}
	}
	if acts := f.audit.actions(); !slices.Contains(acts, "platform.idp.register") ||
		!slices.Contains(acts, "platform.idp.client_secret.update") {
		t.Errorf("audit %v", acts)
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
