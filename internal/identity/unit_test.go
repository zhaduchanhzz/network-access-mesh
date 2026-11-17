package identity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

func TestCSRFTokenIsHMACOfSessionID(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, secretLen)
	m := hmac.New(sha256.New, raw)
	_, _ = m.Write([]byte("csrf-v1"))
	want := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if got := csrfToken(raw); got != want || len(got) != 43 {
		t.Fatalf("csrfToken = %q, want %q", got, want)
	}
	if !validCSRF(raw, want) {
		t.Fatal("valid token refused")
	}
	other := bytes.Repeat([]byte{0x43}, secretLen)
	for _, bad := range []string{"", want[:42], want + "A", csrfToken(other), strings.ToUpper(want)} {
		if bad != want && validCSRF(raw, bad) {
			t.Fatalf("token %q accepted", bad)
		}
	}
}

func TestDecodeSecretIsStrict(t *testing.T) {
	raw := newSecret()
	enc := encodeSecret(raw)
	if len(enc) != 43 {
		t.Fatalf("encoded length %d", len(enc))
	}
	if b, ok := decodeSecret(enc); !ok || !bytes.Equal(b, raw) {
		t.Fatal("round trip")
	}
	last := enc[42]
	nonCanonical := enc[:42] + string(last^1) // flips a low bit that is not part of the 32 bytes
	for _, bad := range []string{"", enc[:42], enc + "A", enc + "=", base64.URLEncoding.EncodeToString(raw),
		strings.Replace(enc, enc[:1], "+", 1), base64.RawURLEncoding.EncodeToString(raw[:31]), nonCanonical} {
		if _, ok := decodeSecret(bad); ok {
			t.Errorf("decodeSecret(%q) accepted", bad)
		}
	}
	if newSecret() == nil || bytes.Equal(newSecret(), newSecret()) {
		t.Fatal("secrets not random")
	}
}

func TestSealedVerifier(t *testing.T) {
	state, binding := newSecret(), newSecret()
	idp := uuid.New()
	aad := authRequestAAD(hashSecret(state), idp, OriginApp)
	verifier := encodeSecret(newSecret())
	sealed, err := sealVerifier(state, binding, aad, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(verifier)) {
		t.Fatal("ciphertext contains the verifier")
	}
	if got, err := openVerifier(state, binding, aad, sealed); err != nil || got != verifier {
		t.Fatalf("open = %q, %v", got, err)
	}
	other := newSecret()
	for name, f := range map[string]func() (string, error){
		"other state":   func() (string, error) { return openVerifier(other, binding, aad, sealed) },
		"other binding": func() (string, error) { return openVerifier(state, other, aad, sealed) },
		"other IdP": func() (string, error) {
			return openVerifier(state, binding, authRequestAAD(hashSecret(state), uuid.New(), OriginApp), sealed)
		},
		"other origin": func() (string, error) {
			return openVerifier(state, binding, authRequestAAD(hashSecret(state), idp, OriginAdmin), sealed)
		},
		"tampered": func() (string, error) {
			s := bytes.Clone(sealed)
			s[len(s)-1] ^= 1
			return openVerifier(state, binding, aad, s)
		},
		"truncated": func() (string, error) { return openVerifier(state, binding, aad, sealed[:10]) },
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestCleanReturnTo(t *testing.T) {
	ok := map[string]string{"": "/", "/": "/", "/devices": "/devices", "/a/b?c=d#e": "/a/b?c=d#e", "/x%2F%2Fy": "/x%2F%2Fy"}
	for in, want := range ok {
		if got, valid := cleanReturnTo(in); !valid || got != want {
			t.Errorf("cleanReturnTo(%q) = %q, %v", in, got, valid)
		}
	}
	for _, in := range []string{"//evil.example", "/\\evil.example", "https://evil.example", "javascript:alert(1)", "devices",
		"/a b", "/a\tb", "/\t/evil.example", "/a\nb", "/ok\x00", "/ok\x7f", "\\\\evil", "/" + strings.Repeat("a", 512)} {
		if got, valid := cleanReturnTo(in); valid {
			t.Errorf("cleanReturnTo(%q) accepted as %q", in, got)
		}
	}
}

func TestRequiredClaims(t *testing.T) {
	parse := func(s string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct {
		required, claims, reason string
	}{
		{`{}`, `{"sub":"a"}`, ""},
		{`{"hd":"x.example"}`, `{"hd":"x.example"}`, ""},
		{`{"hd":"x.example"}`, `{"hd":"y.example"}`, "required_claim_mismatch"},
		{`{"hd":"x.example"}`, `{}`, "required_claim_missing"},
		{`{"hd":"x.example"}`, `{"hd":["y.example","x.example"]}`, ""},
		{`{"tid":["t1","t2"]}`, `{"tid":"t2"}`, ""},
		{`{"tid":["t1","t2"]}`, `{"tid":"t3"}`, "required_claim_mismatch"},
		{`{"tid":["t1","t2"]}`, `{"tid":["t3","t1"]}`, ""},
		{`{"admin":true}`, `{"admin":true}`, ""},
		{`{"admin":true}`, `{"admin":"true"}`, "required_claim_mismatch"},
		{`{"level":2}`, `{"level":2}`, ""},
		{`{"org":{"id":"x"}}`, `{"org":{"id":"x"}}`, "required_claim_misconfigured"},
		{`{"org":null}`, `{"org":null}`, "required_claim_misconfigured"},
		{`{"a":"1","b":"2"}`, `{"a":"1"}`, "required_claim_missing"},
	}
	for _, c := range cases {
		err := checkRequiredClaims(parse(c.required), parse(c.claims))
		got := ""
		if err != nil {
			got = err.Reason
			if err.Kind != KindForbidden {
				t.Errorf("%s/%s: kind %v", c.required, c.claims, err.Kind)
			}
		}
		if got != c.reason {
			t.Errorf("required %s claims %s: reason %q, want %q", c.required, c.claims, got, c.reason)
		}
	}
}

func TestEmailPolicy(t *testing.T) {
	cases := []struct {
		verifiedRequired bool
		domains          []string
		email            string
		verified         bool
		reason           string
	}{
		{true, nil, "a@x.example", true, ""},
		{true, nil, "a@x.example", false, "email_not_verified"},
		{true, nil, "", false, "email_not_verified"},
		{false, nil, "", false, ""},
		{false, nil, "a@x.example", false, ""},
		{false, []string{"x.example"}, "a@x.example", false, "email_not_verified"},
		{false, []string{"x.example"}, "a@X.EXAMPLE", true, ""},
		{false, []string{"x.example"}, "a@sub.x.example", true, "email_domain_not_allowed"},
		{false, []string{"x.example"}, "a@x.example.evil", true, "email_domain_not_allowed"},
		{false, []string{"x.example"}, "a@evil@x.example", true, ""},
	}
	for _, c := range cases {
		p := &idp{RequireEmailVerified: c.verifiedRequired, AllowedEmailDomains: c.domains}
		got := ""
		if err := checkEmail(p, c.email, c.verified); err != nil {
			got = err.Reason
		}
		if got != c.reason {
			t.Errorf("%+v: %q, want %q", c, got, c.reason)
		}
	}
}

func TestProfileFromClaims(t *testing.T) {
	p := &idp{RequireEmailVerified: true, ClaimMapping: map[string]string{"display_name": "nickname"}}
	claims := map[string]any{"sub": "s1", "email": "a@x.example", "email_verified": "true", "nickname": "Nick",
		"name": "Full Name", "acr": "1", "amr": []any{"pwd", "otp", 7}}
	prof, err := profileFromClaims(p, claims)
	if err != nil {
		t.Fatal(err)
	}
	if prof.Subject != "s1" || prof.DisplayName != "Nick" || !prof.EmailVerified || prof.ACR != "1" ||
		strings.Join(prof.AMR, ",") != "pwd,otp" {
		t.Fatalf("profile %+v", prof)
	}
	long := strings.Repeat("é", 300)
	prof, err = profileFromClaims(&idp{}, map[string]any{"sub": "s", "preferred_username": long})
	if err != nil || len(prof.DisplayName) > maxDisplayNameLen || !strings.HasPrefix(long, prof.DisplayName) {
		t.Fatalf("truncation: %q %v", prof.DisplayName, err)
	}
	for _, sub := range []any{nil, "", strings.Repeat("s", 256), 42} {
		if _, err := profileFromClaims(&idp{}, map[string]any{"sub": sub}); err == nil || err.Reason != "subject_invalid" {
			t.Errorf("sub %v accepted", sub)
		}
	}
}

func TestHostsAndOrigins(t *testing.T) {
	h := hosts{app: "app.mg.test", admin: "admin.mg.test"}
	for in, want := range map[string]Origin{"app.mg.test": OriginApp, "APP.MG.TEST:443": OriginApp,
		"admin.mg.test.": OriginAdmin, "admin.mg.test:8443": OriginAdmin} {
		if got, ok := h.origin(in); !ok || got != want {
			t.Errorf("origin(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "evil.test", "app.mg.test.evil", "xapp.mg.test", "mg.test"} {
		if _, ok := h.origin(in); ok {
			t.Errorf("origin(%q) accepted", in)
		}
	}
	if h.baseURL(OriginAdmin) != "https://admin.mg.test" || originForScope(ScopePlatform) != OriginAdmin ||
		originForScope(ScopeTenant) != OriginApp {
		t.Fatal("origin mapping")
	}
}

func TestCookieAttributes(t *testing.T) {
	for name, c := range map[string]*http.Cookie{
		"session": SessionCookie("v"), "authreq": AuthRequestCookie("v", 10*time.Minute),
		"expired": ExpiredCookie(SessionCookieName),
	} {
		s := c.String()
		for _, attr := range []string{"Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
			if !strings.Contains(s, attr) {
				t.Errorf("%s cookie %q lacks %s", name, s, attr)
			}
		}
		if strings.Contains(s, "Domain=") || !strings.HasPrefix(c.Name, "__Host-") {
			t.Errorf("%s cookie %q is not a __Host- cookie", name, s)
		}
	}
	if s := AuthRequestCookie("v", 10*time.Minute).String(); !strings.Contains(s, "Max-Age=600") {
		t.Errorf("authreq %q", s)
	}
	if s := ExpiredCookie(AuthRequestCookieName).String(); !strings.Contains(s, "Max-Age=0") {
		t.Errorf("expired %q", s)
	}
	if s := SessionCookie("v").String(); strings.Contains(s, "Max-Age") || strings.Contains(s, "Expires") {
		t.Errorf("session cookie %q is persistent", s)
	}
}

func TestAuthStyle(t *testing.T) {
	cases := []struct {
		methods []string
		secret  bool
		want    oauth2.AuthStyle
		err     bool
	}{
		{nil, true, oauth2.AuthStyleInHeader, false},
		{[]string{"client_secret_post", "client_secret_basic"}, true, oauth2.AuthStyleInHeader, false},
		{[]string{"client_secret_post"}, true, oauth2.AuthStyleInParams, false},
		{[]string{"private_key_jwt"}, true, 0, true},
		{[]string{"private_key_jwt"}, false, oauth2.AuthStyleInParams, false},
	}
	for _, c := range cases {
		got, err := authStyle(discoveryMeta{TokenEndpointAuthMethods: c.methods}, c.secret)
		if (err != nil) != c.err || (!c.err && got != c.want) {
			t.Errorf("%v secret=%v: %v %v", c.methods, c.secret, got, err)
		}
	}
}

func TestLimitedBody(t *testing.T) {
	read := func(n int, limit int64) error {
		b := &limitedBody{rc: io.NopCloser(bytes.NewReader(make([]byte, n))), left: limit}
		_, err := io.ReadAll(b)
		return err
	}
	if err := read(100, 100); err != nil {
		t.Fatalf("exact size: %v", err)
	}
	if err := read(101, 100); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
}

func TestSessionNeverPrintsTheRawID(t *testing.T) {
	raw := newSecret()
	s := &Session{PublicID: uuid.New(), IdentityID: uuid.New(), raw: raw, idHash: hashSecret(raw)}
	enc := encodeSecret(raw)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "session", s, "value", *s)
	out := fmt.Sprintf("%v %+v %#v %s %v %+v", s, s, s, s, *s, *s) + buf.String()
	for _, leak := range []string{enc, hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), string(raw), s.CSRFToken()} {
		if strings.Contains(out, leak) {
			t.Fatalf("raw session material printed: %s", out)
		}
	}
	if !strings.Contains(out, s.PublicID.String()) {
		t.Fatal("public id missing from the printed form")
	}
}

func TestProblem(t *testing.T) {
	p := NewProblem(invalid("return_to", "pattern"), "req-1", "/api/v1/auth/login")
	if p.Status != 422 || p.Code != "validation_failed" || p.Type != "urn:meshguard:problem:validation_failed" ||
		p.RequestID != "req-1" || p.Instance != "/api/v1/auth/login" || len(p.Errors) != 1 || p.Errors[0].Field != "return_to" {
		t.Fatalf("problem %+v", p)
	}
	p = NewProblem(errors.New("db password=hunter2 refused"), "", "/x")
	if p.Status != 500 || p.Code != "internal_error" || strings.Contains(p.Detail, "hunter2") {
		t.Fatalf("internal problem %+v", p)
	}
	for _, k := range []Kind{KindUnauthenticated, KindReauthRequired, KindForbidden, KindNotFound, KindInvalid, KindUpstream, KindInternal} {
		if k.Status() < 400 || k.Code() == "" || k.title() == "" || k.detail() == "" {
			t.Errorf("kind %d incomplete", k)
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	ok := Config{AppHost: "app.mg.test", AdminHost: "admin.mg.test", HTTPClient: http.DefaultClient}
	st := &store.Store{}
	svc, err := New(st, ok)
	if err != nil {
		t.Fatalf("valid configuration refused: %v", err)
	}
	if svc.cfg.StepUpWindow != 15*time.Minute || svc.cfg.AuthRequestTTL != 10*time.Minute ||
		svc.timeouts(ScopeTenant) != DefaultTenantTimeouts || svc.timeouts(ScopePlatform) != DefaultPlatformTimeouts ||
		svc.maxAge(ScopePlatform) != 8*time.Hour {
		t.Fatalf("defaults %+v", svc.cfg)
	}
	if _, err := New(nil, ok); err == nil {
		t.Error("nil store accepted")
	}
	for name, mutate := range map[string]func(c *Config){
		"same hosts":       func(c *Config) { c.AdminHost = c.AppHost },
		"IP host":          func(c *Config) { c.AppHost = "192.0.2.1" },
		"empty host":       func(c *Config) { c.AdminHost = "" },
		"no http client":   func(c *Config) { c.HTTPClient = nil },
		"auth request ttl": func(c *Config) { c.AuthRequestTTL = 11 * time.Minute },
		"idle > absolute":  func(c *Config) { c.TenantTimeouts = Timeouts{Idle: 2 * time.Hour, Absolute: time.Hour} },
	} {
		c := ok
		mutate(&c)
		if _, err := New(st, c); err == nil || !strings.Contains(err.Error(), "invalid configuration") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
