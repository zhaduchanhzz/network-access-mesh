package keycloak

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/idptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// relaySMTP is the realm relay of staging: the worker's MG_SMTP_* as tools/render_app.py renders them.
func relaySMTP(t *testing.T) SMTPServer {
	t.Helper()
	s, ok, err := SMTPFromConfig("mailrelay:587", "starttls", "", "", "example.test")
	if err != nil || !ok {
		t.Fatalf("SMTPFromConfig: %v %v", ok, err)
	}
	return s
}

// TestSMTPFromConfig (G4b-E1): the realm relay is the worker's own unauthenticated relay, with the representation
// tools/render_idp.py gives the rendered realms (smtp_relay: STARTTLS to mailrelay:587, the one sender, no auth); an
// authenticated relay or none gives no realm SMTP; malformed values are refused.
func TestSMTPFromConfig(t *testing.T) {
	got := relaySMTP(t).rep()
	want := map[string]any{"host": "mailrelay", "port": "587", "from": "no-reply@example.test", "fromDisplayName": "MeshGuard",
		"auth": "false", "ssl": "false", "starttls": "true"}
	if smtpNorm(got) != smtpNorm(want) || len(got) != len(want) {
		t.Fatalf("relay rep = %v, want %v", got, want)
	}
	s, ok, err := SMTPFromConfig("relay.example.test:465", "implicit", `"Ops Team" <ops@example.test>`, "", "example.test")
	if err != nil || !ok || !s.SSL || s.StartTLS || s.From != "ops@example.test" || s.FromDisplayName != "Ops Team" {
		t.Fatalf("implicit: %+v %v %v", s, ok, err)
	}
	if s, ok, err := SMTPFromConfig("mailsink:1025", "none", "noreply@example.test", "", "x"); err != nil || !ok ||
		s.SSL || s.StartTLS || s.FromDisplayName != "" {
		t.Fatalf("none: %+v %v %v", s, ok, err)
	}
	for _, c := range [][2]string{{"", ""}, {"smtp.example.test:587", "user"}} {
		if _, ok, err := SMTPFromConfig(c[0], "starttls", "", c[1], "example.test"); ok || err != nil {
			t.Errorf("addr %q user %q: ok=%v err=%v, want no realm SMTP", c[0], c[1], ok, err)
		}
	}
	for _, c := range [][3]string{{"mailrelay", "starttls", ""}, {"mailrelay:0", "starttls", ""},
		{"mailrelay:587", "tls", ""}, {"mailrelay:587", "starttls", "not an address"}} {
		if _, _, err := SMTPFromConfig(c[0], c[1], c[2], "", "example.test"); err == nil {
			t.Errorf("%v: accepted", c)
		}
	}
	if _, err := New(Config{Route: &idp.PlatformRoute{}, Secrets: idptest.NewSecrets(), AppHost: "app.example.test",
		AdminHost: "admin.example.test", Provisioner: Credentials{ClientID: "p", Secret: secrets.PlatformRef("p", 1)},
		SMTP: &SMTPServer{Host: "mailrelay", Port: 587, From: "a@b.test", StartTLS: true, SSL: true}}); err == nil {
		t.Fatal("STARTTLS + SSL accepted")
	}
}

// TestRealmRepCarriesSMTP: a realm the driver creates gets the relay; without one it has no smtpServer (the template
// has none); Keycloak's answer (strings, masked password, empty values) compares equal to what was sent.
func TestRealmRepCarriesSMTP(t *testing.T) {
	s := relaySMTP(t)
	p := realmParams{Realm: "t-x", Scope: idp.ScopeTenant, IdPID: uuid.New(), RedirectURI: "https://app.example.test/cb", SMTP: &s}
	rep, err := realmRep(p)
	if err != nil {
		t.Fatal(err)
	}
	if smtpNorm(rep["smtpServer"]) != smtpNorm(s.rep()) {
		t.Fatalf("smtpServer = %v", rep["smtpServer"])
	}
	p.SMTP = nil
	if rep, err = realmRep(p); err != nil || rep["smtpServer"] != nil {
		t.Fatalf("no relay: smtpServer = %v, %v", rep["smtpServer"], err)
	}
	live := map[string]any{"host": "mailrelay", "port": "587", "from": "no-reply@example.test", "fromDisplayName": "MeshGuard",
		"auth": "false", "ssl": "false", "starttls": "true", "password": "**********", "replyTo": ""}
	if smtpDiffers(s.rep(), live) || !smtpDiffers(s.rep(), nil) || !smtpDiffers(s.rep(), map[string]any{"host": "mailsink"}) ||
		smtpDiffers(nil, nil) || smtpDiffers(nil, live) {
		t.Fatal("smtpDiffers")
	}
}

// fakeRealmKC answers the provisioner's token and GET/PUT of one realm.
type fakeRealmKC struct {
	mu    sync.Mutex
	realm map[string]any
	puts  []map[string]any
}

func (f *fakeRealmKC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/realms/master/protocol/openid-connect/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 300})
	case r.URL.Path == "/admin/realms/t-new" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(f.realm)
	case r.URL.Path == "/admin/realms/t-new" && r.Method == http.MethodPut:
		var upd map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &upd)
		f.puts = append(f.puts, upd)
		for k, v := range upd {
			f.realm[k] = v
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestEnsureSMTP (G4b-E1, repair of realms created before the fix): a driver-created realm without smtpServer gets
// the relay once — a second run changes nothing; a rendered (adopted) realm, a realm of another IdP and a driver
// without a relay are refused without a write.
func TestEnsureSMTP(t *testing.T) {
	idpID := uuid.New()
	f := &fakeRealmKC{realm: map[string]any{"id": "x", "realm": "t-new",
		"attributes": map[string]any{"meshguard.idp_id": idpID.String(), "meshguard.scope": "tenant"}}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: "example.com", Address: srv.Listener.Addr().String(),
		RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	st := idptest.NewSecrets()
	pref := secrets.PlatformRef(ProvisionerRefName, 1)
	if err := st.Put(t.Context(), pref, []byte("prov-secret")); err != nil {
		t.Fatal(err)
	}
	s := relaySMTP(t)
	cfg := Config{Route: route, Secrets: st, AppHost: "app.example.test", AdminHost: "admin.example.test",
		Provisioner: Credentials{ClientID: DefaultProvisionerClientID, Secret: pref}, SMTP: &s}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reg := idp.Registration{IdPID: idpID, Scope: idp.ScopeTenant, TenantID: uuid.New(), Driver: idp.DriverKeycloak,
		Issuer: "https://example.com/realms/t-new", ClientID: PortalClientID,
		DriverRef: DriverRef{Realm: "t-new", DriverSecret: driverSecretRef(idpID).String()}.Encode()}
	ctx := t.Context()
	if changed, err := d.EnsureSMTP(ctx, reg); err != nil || !changed {
		t.Fatalf("first run: changed=%v err=%v", changed, err)
	}
	if changed, err := d.EnsureSMTP(ctx, reg); err != nil || changed {
		t.Fatalf("second run: changed=%v err=%v", changed, err)
	}
	if len(f.puts) != 1 || len(f.puts[0]) != 1 || smtpNorm(f.puts[0]["smtpServer"]) != smtpNorm(s.rep()) {
		t.Fatalf("PUTs %v", f.puts)
	}
	adopted := reg
	adopted.DriverRef = "t-new"
	if _, err := d.EnsureSMTP(ctx, adopted); idp.CodeOf(err) != idp.CodeUnsupported {
		t.Fatalf("adopted realm: %v", err)
	}
	other := reg
	other.IdPID = uuid.New()
	other.DriverRef = DriverRef{Realm: "t-new", DriverSecret: driverSecretRef(other.IdPID).String()}.Encode()
	if _, err := d.EnsureSMTP(ctx, other); idp.CodeOf(err) != idp.CodeConflict {
		t.Fatalf("realm of another IdP: %v", err)
	}
	cfg.SMTP = nil
	bare, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.EnsureSMTP(ctx, reg); idp.CodeOf(err) != idp.CodeInvalidArgument || !strings.Contains(err.Error(), "smtp") {
		t.Fatalf("no relay: %v", err)
	}
	if len(f.puts) != 1 {
		t.Fatalf("refused runs wrote: %v", f.puts)
	}
}
