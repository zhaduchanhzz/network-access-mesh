package idp

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const goodJWKS = `{"keys":[{"kty":"RSA","use":"sig","kid":"k1","alg":"RS256","n":"sXch","e":"AQAB"},
{"kty":"RSA","use":"enc","kid":"k2","n":"x","e":"AQAB"}]}`

func discoveryServer(t *testing.T, doc, jwks string, status int) (*Hardened, *dialLog) {
	t.Helper()
	srv, pool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/jwks") {
			_, _ = io.WriteString(w, jwks)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, doc)
	}))
	h, _, log := hardenedFor(t, srv, pool, HardenedConfig{DenyDomains: []string{"platform.example"}})
	return h, log
}

func docFor(issuer string, mutate func(m map[string]string)) string {
	m := map[string]string{
		"issuer": issuer, "authorization_endpoint": "https://example.com/auth", "token_endpoint": "https://example.com/token",
		"jwks_uri": "https://example.com/jwks", "userinfo_endpoint": "https://example.com/userinfo",
	}
	if mutate != nil {
		mutate(m)
	}
	var b strings.Builder
	b.WriteString(`{"response_types_supported":["code","id_token"],"code_challenge_methods_supported":["plain","S256"],` +
		`"authorization_response_iss_parameter_supported":true`)
	for k, v := range m {
		if v != "" {
			b.WriteString(`,"` + k + `":"` + v + `"`)
		}
	}
	b.WriteString("}")
	return b.String()
}

func staticRule(h *Hardened) EndpointRule {
	return func(_ context.Context, u *url.URL, _ EndpointKind) error { return h.CheckURL(u) }
}

func TestFetchDiscoveryHappyPath(t *testing.T) {
	h, _ := discoveryServer(t, docFor("https://example.com/realms/t1", nil), goodJWKS, 200)
	d, err := FetchDiscovery(t.Context(), h.Client(), "https://example.com/realms/t1", staticRule(h))
	if err != nil {
		t.Fatal(err)
	}
	if d.Issuer != "https://example.com/realms/t1" || d.TokenEndpoint != "https://example.com/token" ||
		d.SigningKeys != 1 || !d.IssParameterSupported {
		t.Fatalf("discovery %+v", d)
	}
	if DiscoveryURL("https://example.com/realms/t1/") != "https://example.com/realms/t1/.well-known/openid-configuration" {
		t.Fatal("DiscoveryURL must drop a terminating slash")
	}
}

// TestFetchDiscoveryRefusals: issuer mismatch, missing/forbidden endpoints, PKCE, JWKS without a signature key,
// non-JSON and HTTP errors are refused — and no error ever carries upstream content.
func TestFetchDiscoveryRefusals(t *testing.T) {
	const canary = "UPSTREAM-CANARY-7f3a"
	iss := "https://example.com/realms/t1"
	cases := []struct {
		name   string
		doc    string
		jwks   string
		status int
		code   Code
		reason string
	}{
		{"issuer mismatch", docFor("https://evil.example.org/"+canary, nil), goodJWKS, 200, CodeIssuerMismatch, "issuer_mismatch"},
		{"issuer trailing slash", docFor(iss+"/", nil), goodJWKS, 200, CodeIssuerMismatch, ""},
		{"token endpoint missing", docFor(iss, func(m map[string]string) { m["token_endpoint"] = "" }), goodJWKS, 200,
			CodeDiscoveryInvalid, "endpoint_missing"},
		{"jwks on http", docFor(iss, func(m map[string]string) { m["jwks_uri"] = "http://example.com/jwks" }), goodJWKS, 200,
			CodeDestinationRefused, "jwks_uri:scheme"},
		{"token endpoint on an internal IP", docFor(iss, func(m map[string]string) {
			m["token_endpoint"] = "https://169.254.169.254/token"
		}), goodJWKS, 200, CodeDestinationRefused, "token_endpoint:host_ip_literal"},
		{"userinfo on the platform domain", docFor(iss, func(m map[string]string) {
			m["userinfo_endpoint"] = "https://auth.platform.example/realms/x/userinfo"
		}), goodJWKS, 200, CodeDestinationRefused, "userinfo_endpoint:host_platform_domain"},
		{"authorization endpoint on another port", docFor(iss, func(m map[string]string) {
			m["authorization_endpoint"] = "https://example.com:8443/auth"
		}), goodJWKS, 200, CodeDestinationRefused, "authorization_endpoint:port"},
		{"no S256", strings.Replace(docFor(iss, nil), `"plain","S256"`, `"plain"`, 1), goodJWKS, 200,
			CodeDiscoveryInvalid, "pkce_s256_unsupported"},
		{"no code flow", strings.Replace(docFor(iss, nil), `["code","id_token"]`, `["id_token"]`, 1), goodJWKS, 200,
			CodeDiscoveryInvalid, "response_type_code_unsupported"},
		{"jwks only encryption keys", docFor(iss, nil), `{"keys":[{"kty":"RSA","use":"enc","n":"x","e":"AQAB"}]}`, 200,
			CodeDiscoveryInvalid, "jwks_no_signing_key"},
		{"jwks not json", docFor(iss, nil), "<html>" + canary, 200, CodeDiscoveryInvalid, "not_json_object"},
		{"not json", "<html>" + canary + "</html>", goodJWKS, 200, CodeDiscoveryInvalid, "not_json_object"},
		{"malformed json", `{"issuer": "` + canary + `", oops}`, goodJWKS, 200, CodeDiscoveryInvalid, "malformed_json"},
		{"server error", `{"error":"` + canary + `"}`, goodJWKS, 500, CodeUnavailable, "http_500"},
		{"not found", canary, goodJWKS, 404, CodeNotFound, "http_404"},
	}
	for _, c := range cases {
		h, _ := discoveryServer(t, c.doc, c.jwks, c.status)
		_, err := FetchDiscovery(t.Context(), h.Client(), iss, staticRule(h))
		wantCode(t, c.name, err, c.code, c.reason)
		if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "evil.example.org") {
			t.Errorf("%s: the error carries upstream content: %v", c.name, err)
		}
	}
	h, _ := discoveryServer(t, docFor(iss, nil), goodJWKS, 200)
	for _, bad := range []string{"http://example.com", "https://example.com/?x=1", "https://u@example.com", "not a url"} {
		_, err := FetchDiscovery(t.Context(), h.Client(), bad, staticRule(h))
		if CodeOf(err) != CodeInvalidArgument && CodeOf(err) != CodeDestinationRefused {
			t.Errorf("issuer %q: %v", bad, err)
		}
	}
}
