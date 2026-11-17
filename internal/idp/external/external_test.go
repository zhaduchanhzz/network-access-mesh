package external_test

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/external"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/idptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

type resolver struct {
	mu sync.Mutex
	m  map[string][]netip.Addr
}

func (r *resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.m[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r *resolver) set(host string, a ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []netip.Addr
	for _, s := range a {
		out = append(out, netip.MustParseAddr(s))
	}
	r.m[host] = out
}

const issuer = "https://example.com/tenant/v2.0"

// setup: an IdP served by an httptest TLS server under example.com (the name of the test certificate), reached
// through the hardened client (fake resolver: public address; dialler: the test server).
func setup(t *testing.T, doc func(r *http.Request) string) (*external.Driver, *idptest.Secrets, *resolver, *int) {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/jwks") {
			_, _ = io.WriteString(w, `{"keys":[{"kty":"EC","use":"sig","crv":"P-256","x":"a","y":"b"}]}`)
			return
		}
		_, _ = io.WriteString(w, doc(r))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	res := &resolver{m: map[string][]netip.Addr{}}
	res.set("example.com", "93.184.215.14")
	h, err := idp.NewHardened(idp.HardenedConfig{Resolver: res, RootCAs: pool, DenyDomains: []string{"platform.example"},
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		}})
	if err != nil {
		t.Fatal(err)
	}
	st := idptest.NewSecrets()
	d, err := external.New(external.Config{Client: h, Secrets: st})
	if err != nil {
		t.Fatal(err)
	}
	return d, st, res, &calls
}

func goodDoc(r *http.Request) string {
	return `{"issuer":"` + issuer + `","authorization_endpoint":"https://example.com/auth","token_endpoint":"https://example.com/token",` +
		`"jwks_uri":"https://example.com/jwks","userinfo_endpoint":"https://example.com/userinfo","response_types_supported":["code"]}`
}

func reg() idp.Registration {
	return idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: uuid.New(), Driver: idp.DriverExternal}
}

func TestEnsureIssuerAndDiscovery(t *testing.T) {
	d, _, _, _ := setup(t, goodDoc)
	r := reg()
	r.Issuer = issuer
	res, err := d.EnsureIssuer(t.Context(), idp.IssuerSpec{Registration: r})
	if err != nil || res.Issuer != issuer || res.Created || res.DriverRef != "" {
		t.Fatalf("EnsureIssuer = %+v, %v", res, err)
	}
	disc, err := d.CheckDiscovery(t.Context(), r)
	if err != nil || disc.SigningKeys != 1 || disc.JWKSURI != "https://example.com/jwks" {
		t.Fatalf("CheckDiscovery = %+v, %v", disc, err)
	}
	if d.Name() != "external" {
		t.Fatal("name")
	}
}

// TestEnsureIssuerRefusals: tenant-supplied issuers and endpoints that point inside, to the platform, or that do
// not match are refused (T-21).
func TestEnsureIssuerRefusals(t *testing.T) {
	cases := map[string]struct {
		issuer string
		doc    func(*http.Request) string
		setup  func(*resolver)
		code   idp.Code
	}{
		"issuer on the platform IdP host": {"https://auth.platform.example/realms/tenant-b", goodDoc, nil, idp.CodeDestinationRefused},
		"issuer IP literal":               {"https://10.249.2.2/", goodDoc, nil, idp.CodeDestinationRefused},
		"issuer metadata":                 {"https://169.254.169.254/latest", goodDoc, nil, idp.CodeDestinationRefused},
		"issuer with a query":             {issuer + "?x=1", goodDoc, nil, idp.CodeInvalidArgument},
		"issuer on http":                  {"http://example.com/tenant/v2.0", goodDoc, nil, idp.CodeDestinationRefused},
		"issuer name resolving inside": {"https://idp.corp.example.org", goodDoc,
			func(r *resolver) { r.set("idp.corp.example.org", "10.249.1.5") }, idp.CodeDestinationRefused},
		"issuer mismatch": {issuer, func(*http.Request) string {
			return strings.Replace(goodDoc(nil), issuer, "https://example.com/other", 1)
		}, nil, idp.CodeIssuerMismatch},
		"token endpoint on the platform domain": {issuer, func(*http.Request) string {
			return strings.Replace(goodDoc(nil), "https://example.com/token", "https://auth.platform.example/realms/x/token", 1)
		}, nil, idp.CodeDestinationRefused},
		"token endpoint resolving to the tenant pool": {issuer, func(*http.Request) string {
			return strings.Replace(goodDoc(nil), "https://example.com/token", "https://token.example.net/t", 1)
		}, func(r *resolver) { r.set("token.example.net", "::ffff:10.250.0.3") }, idp.CodeDestinationRefused},
		"userinfo endpoint unresolvable": {issuer, func(*http.Request) string {
			return strings.Replace(goodDoc(nil), "https://example.com/userinfo", "https://nowhere.example.net/u", 1)
		}, nil, idp.CodeUnavailable},
	}
	for name, c := range cases {
		d, _, res, _ := setup(t, c.doc)
		if c.setup != nil {
			c.setup(res)
		}
		r := reg()
		r.Issuer = c.issuer
		_, err := d.EnsureIssuer(t.Context(), idp.IssuerSpec{Registration: r})
		if idp.CodeOf(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
}

// TestEnsureClient: the tenant-supplied secret goes to the tenant's SecretStore; the same secret again changes
// nothing; a new secret is a new version; a public client has no reference.
func TestEnsureClient(t *testing.T) {
	d, st, _, _ := setup(t, goodDoc)
	r := reg()
	ctx := t.Context()
	res, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: withClient(r, "tenant-portal"), ClientSecret: secrets.Plaintext("s3cr3t-1")})
	if err != nil || res.ClientID != "tenant-portal" || !res.SecretRotated {
		t.Fatalf("first: %+v, %v", res, err)
	}
	ref, err := secrets.ParseRef(res.ClientSecretRef)
	if err != nil || ref.Tenant != r.TenantID || ref.Version != 1 || st.Value(ref) != "s3cr3t-1" {
		t.Fatalf("stored %v (%v)", res.ClientSecretRef, err)
	}
	again := withClient(r, "tenant-portal")
	again.ClientSecretRef = res.ClientSecretRef
	res2, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: again, ClientSecret: secrets.Plaintext("s3cr3t-1")})
	if err != nil || res2.SecretRotated || res2.ClientSecretRef != res.ClientSecretRef {
		t.Fatalf("same secret: %+v, %v", res2, err)
	}
	res3, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: again, ClientSecret: secrets.Plaintext("s3cr3t-2")})
	if err != nil || !res3.SecretRotated || !strings.HasSuffix(res3.ClientSecretRef, "#2") {
		t.Fatalf("new secret: %+v, %v", res3, err)
	}
	pub, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: withClient(reg(), "spa")})
	if err != nil || pub.ClientSecretRef != "" {
		t.Fatalf("public client: %+v, %v", pub, err)
	}
	for _, bad := range []string{"", "has space", strings.Repeat("x", 256)} {
		if _, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: withClient(r, bad)}); idp.CodeOf(err) != idp.CodeInvalidArgument {
			t.Errorf("client id %q: %v", bad, err)
		}
	}
	// purge destroys every version; disable keeps them; both idempotent
	gone := again
	gone.ClientSecretRef = res3.ClientSecretRef
	for range 2 {
		if _, err := d.RemoveIssuer(ctx, gone, idp.RemoveDisable); err != nil {
			t.Fatal(err)
		}
	}
	r2, _ := secrets.ParseRef(res3.ClientSecretRef)
	if st.Destroyed(r2) {
		t.Fatal("disable destroyed the secret")
	}
	for range 2 {
		if _, err := d.RemoveIssuer(ctx, gone, idp.RemovePurge); err != nil {
			t.Fatal(err)
		}
	}
	if !st.Destroyed(r2) || !st.Destroyed(ref) {
		t.Fatal("purge did not destroy every version")
	}
}

func withClient(r idp.Registration, id string) idp.Registration { r.ClientID = id; return r }

// codeNotOwned is idp.CodeSecretRefNotOwned (G2 F3), spelled out so the test also pins the stable code.
const codeNotOwned = idp.Code("secret_ref_not_owned")

// TestClientSecretRefMustBeTheIdPsOwn — G2 F3: the stored client_secret_ref is only used when it names the IdP's own
// client secret (owner = the IdP's tenant, or platform for the platform IdP; name idp.<id>.client or
// idp-client-secret.<id>). Any other reference — another tenant's Headscale API key, a platform secret on a tenant
// IdP, the tenant's own Headscale key, another IdP's client secret, a tenant secret on the platform IdP — is refused
// with secret_ref_not_owned before the SecretStore is touched: EnsureClient reads nothing and writes nothing,
// RemoveIssuer purge destroys nothing. Disabling (no secret involved) still works; the IdP's own references work.
func TestClientSecretRefMustBeTheIdPsOwn(t *testing.T) {
	st, rec := idptest.NewSecrets(), &idptest.Security{}
	h, err := idp.NewHardened(idp.HardenedConfig{}) // nothing below reaches the network
	if err != nil {
		t.Fatal(err)
	}
	d, err := external.New(external.Config{Client: h, Secrets: st, Security: rec})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	r := withClient(reg(), "tenant-portal")
	other := uuid.New()
	platform := withClient(idp.Registration{IdPID: uuid.New(), Scope: idp.ScopePlatform, Driver: idp.DriverExternal}, "console")
	cases := map[string]struct {
		reg idp.Registration
		ref secrets.Ref
	}{
		"another tenant's Headscale API key":  {r, secrets.TenantRef(other, "headscale-api-key", 1)},
		"a platform secret on a tenant IdP":   {r, secrets.PlatformRef("idp."+r.IdPID.String()+".client", 1)},
		"the tenant's own Headscale API key":  {r, secrets.TenantRef(r.TenantID, "headscale-api-key", 1)},
		"another IdP's client secret":         {r, secrets.TenantRef(r.TenantID, "idp."+uuid.NewString()+".client", 1)},
		"a tenant secret on the platform IdP": {platform, secrets.TenantRef(other, "idp."+platform.IdPID.String()+".client", 1)},
	}
	for name, c := range cases {
		if err := st.Put(ctx, c.ref, []byte("foreign:"+name)); err != nil {
			t.Fatal(err)
		}
		rg := c.reg
		rg.ClientSecretRef = c.ref.String()
		reads := len(st.Reads)
		if _, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: rg, ClientSecret: secrets.Plaintext("new-secret")}); idp.CodeOf(err) != codeNotOwned {
			t.Errorf("%s: EnsureClient = %v, want %s", name, err, codeNotOwned)
		}
		if len(st.Reads) != reads {
			t.Errorf("%s: EnsureClient read %v", name, st.Reads[reads:])
		}
		if st.Latest(rg.ClientSecretOwner(1)) != 0 {
			t.Errorf("%s: EnsureClient stored a client secret despite the refusal", name)
		}
		if _, err := d.RemoveIssuer(ctx, rg, idp.RemovePurge); idp.CodeOf(err) != codeNotOwned {
			t.Errorf("%s: RemoveIssuer purge = %v, want %s", name, err, codeNotOwned)
		}
		if st.Destroyed(c.ref) || st.Value(c.ref) != "foreign:"+name {
			t.Errorf("%s: RemoveIssuer purge destroyed a secret the IdP does not own", name)
		}
		if _, err := d.RemoveIssuer(ctx, rg, idp.RemoveDisable); err != nil {
			t.Errorf("%s: RemoveIssuer disable (no secret involved) = %v", name, err)
		}
		// one security event per refusal (the audit.Logger deduplicates them per IdP and hour)
		evs := rec.Events()
		if len(evs) < 2 {
			t.Fatalf("%s: %d security events", name, len(evs))
		}
		for _, ev := range evs[len(evs)-2:] {
			if ev.Kind != idp.KindClientSecretRefNotOwned || ev.Severity != "high" || ev.Source != "idp" || ev.TenantID != nil ||
				ev.Details["idp_id"] != rg.IdPID || ev.DedupeKey != idp.KindClientSecretRefNotOwned+":"+rg.IdPID.String() {
				t.Errorf("%s: security event %+v", name, ev)
			}
		}
	}
	if n := len(rec.Events()); n != 2*len(cases) {
		t.Errorf("%d security events for %d refusals", n, 2*len(cases))
	}
	// The IdP's own references, under both names in use (drivers: idp.<id>.client; `meshguard admin
	// set-idp-client-secret`: idp-client-secret.<id>), are read and destroyed as before.
	for _, rg := range []idp.Registration{r, platform} {
		for _, own := range []secrets.Ref{rg.ClientSecretOwner(1), {Tenant: rg.TenantID, Name: "idp-client-secret." + rg.IdPID.String(), Version: 1}} {
			if err := st.Put(ctx, own, []byte("same")); err != nil {
				t.Fatal(err)
			}
			x := rg
			x.ClientSecretRef = own.String()
			res, err := d.EnsureClient(ctx, idp.ClientSpec{Registration: x, ClientSecret: secrets.Plaintext("same")})
			if err != nil || res.SecretRotated || res.ClientSecretRef != own.String() {
				t.Errorf("own reference %s: EnsureClient = %+v, %v", own, res, err)
			}
			if _, err := d.RemoveIssuer(ctx, x, idp.RemovePurge); err != nil || !st.Destroyed(own) {
				t.Errorf("own reference %s: RemoveIssuer purge = %v (destroyed %v)", own, err, st.Destroyed(own))
			}
		}
	}
	if n := len(rec.Events()); n != 2*len(cases) {
		t.Errorf("own references raised %d security events", n-2*len(cases))
	}
}

func TestUnsupported(t *testing.T) {
	d, _, _, calls := setup(t, goodDoc)
	if _, err := d.InviteUser(t.Context(), reg(), idp.Invite{Email: "a@example.com"}); idp.CodeOf(err) != idp.CodeUnsupported {
		t.Fatalf("InviteUser: %v", err)
	}
	if _, err := d.DisableUser(t.Context(), reg(), uuid.NewString()); idp.CodeOf(err) != idp.CodeUnsupported {
		t.Fatalf("DisableUser: %v", err)
	}
	if *calls != 0 {
		t.Fatal("an unsupported operation called the IdP")
	}
	if _, err := external.New(external.Config{}); err == nil {
		t.Fatal("a driver without a hardened client")
	}
}
