package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// EndpointKind tells an EndpointRule how the backend uses an endpoint of the discovery document.
type EndpointKind int

// Endpoint kinds.
const (
	// EndpointBackend: called by the backend (jwks_uri, token, userinfo) — must reach an allowed destination.
	EndpointBackend EndpointKind = iota
	// EndpointBrowser: only visited by the browser (authorization, end_session) — static rules only.
	EndpointBrowser
)

// EndpointRule validates one endpoint URL of a discovery document; it returns an *Error (CodeDiscoveryInvalid or
// CodeDestinationRefused) when the URL is not acceptable.
type EndpointRule func(ctx context.Context, u *url.URL, kind EndpointKind) error

// discoveryDoc holds the discovery fields the module checks (unknown fields are ignored).
type discoveryDoc struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	JWKSURI                     string   `json:"jwks_uri"`
	UserinfoEndpoint            string   `json:"userinfo_endpoint"`
	EndSessionEndpoint          string   `json:"end_session_endpoint"`
	ResponseTypesSupported      []string `json:"response_types_supported"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
	IssParameterSupported       bool     `json:"authorization_response_iss_parameter_supported"`
	IDTokenSigningAlgsSupported []string `json:"id_token_signing_alg_values_supported"`
}

type jwks struct {
	Keys []struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

// DiscoveryURL returns the discovery URL of an issuer (OpenID Connect Discovery 1.0 §4: a terminating "/" of the
// issuer is removed before appending /.well-known/openid-configuration).
func DiscoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

// FetchDiscovery fetches the discovery document of issuer with client and checks it: HTTP 200, a JSON object, an
// issuer exactly equal to the stored one (§8.2: checked at every refresh), authorization/token/jwks endpoints present
// and accepted by rule (as is every other endpoint present), response type "code", S256 among the PKCE methods when
// the list is published; then it fetches the JWKS with the same client and requires at least one usable signature
// key. Errors never carry upstream content.
func FetchDiscovery(ctx context.Context, client *http.Client, issuer string, rule EndpointRule) (Discovery, error) {
	const op = "discovery"
	iu, err := url.Parse(issuer)
	if err != nil || iu.Scheme != "https" || iu.Host == "" || iu.RawQuery != "" || iu.Fragment != "" || iu.User != nil {
		return Discovery{}, NewError(CodeInvalidArgument, op, "issuer_url", nil)
	}
	if err := rule(ctx, iu, EndpointBackend); err != nil {
		return Discovery{}, err
	}
	var doc discoveryDoc
	if err := getJSON(ctx, client, op, DiscoveryURL(issuer), &doc); err != nil {
		return Discovery{}, err
	}
	if doc.Issuer != issuer {
		return Discovery{}, NewError(CodeIssuerMismatch, op, "issuer_mismatch", nil)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return Discovery{}, NewError(CodeDiscoveryInvalid, op, "endpoint_missing", nil)
	}
	if !slices.Contains(doc.ResponseTypesSupported, "code") {
		return Discovery{}, NewError(CodeDiscoveryInvalid, op, "response_type_code_unsupported", nil)
	}
	if len(doc.CodeChallengeMethods) > 0 && !slices.Contains(doc.CodeChallengeMethods, "S256") {
		return Discovery{}, NewError(CodeDiscoveryInvalid, op, "pkce_s256_unsupported", nil)
	}
	endpoints := []struct {
		raw  string
		kind EndpointKind
		name string
	}{
		{doc.AuthorizationEndpoint, EndpointBrowser, "authorization_endpoint"},
		{doc.TokenEndpoint, EndpointBackend, "token_endpoint"},
		{doc.JWKSURI, EndpointBackend, "jwks_uri"},
		{doc.UserinfoEndpoint, EndpointBackend, "userinfo_endpoint"},
		{doc.EndSessionEndpoint, EndpointBrowser, "end_session_endpoint"},
	}
	for _, ep := range endpoints {
		if ep.raw == "" {
			continue
		}
		u, err := url.Parse(ep.raw)
		if err != nil {
			return Discovery{}, NewError(CodeDiscoveryInvalid, op, ep.name+"_unparsable", nil)
		}
		if err := rule(ctx, u, ep.kind); err != nil {
			var e *Error
			if asError(err, &e) && e.Code == CodeDestinationRefused {
				return Discovery{}, &Error{Code: CodeDestinationRefused, Op: op, Reason: ep.name + ":" + e.Reason, err: err}
			}
			return Discovery{}, err
		}
	}
	var keys jwks
	if err := getJSON(ctx, client, op+".jwks", doc.JWKSURI, &keys); err != nil {
		return Discovery{}, err
	}
	n := 0
	for _, k := range keys.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch {
		case k.Kty == "RSA" && k.N != "" && k.E != "",
			k.Kty == "EC" && k.Crv != "" && k.X != "" && k.Y != "",
			k.Kty == "OKP" && k.Crv != "" && k.X != "":
			n++
		}
	}
	if n == 0 {
		return Discovery{}, NewError(CodeDiscoveryInvalid, op, "jwks_no_signing_key", nil)
	}
	return Discovery{
		Issuer: doc.Issuer, AuthorizationEndpoint: doc.AuthorizationEndpoint, TokenEndpoint: doc.TokenEndpoint,
		JWKSURI: doc.JWKSURI, UserinfoEndpoint: doc.UserinfoEndpoint, EndSessionEndpoint: doc.EndSessionEndpoint,
		CodeChallengeMethods: doc.CodeChallengeMethods, IssParameterSupported: doc.IssParameterSupported,
		SigningKeys: n,
	}, nil
}

// getJSON GETs target and decodes a JSON object into out. Any failure is an *Error without upstream content (a
// decoding error of encoding/json can quote a byte of the body, so it is never wrapped).
func getJSON(ctx context.Context, client *http.Client, op, target string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return NewError(CodeInvalidArgument, op, "url", nil)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Classify(op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return StatusError(op, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Classify(op, err)
	}
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' {
		return NewError(CodeDiscoveryInvalid, op, "not_json_object", nil)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return NewError(CodeDiscoveryInvalid, op, "malformed_json", nil)
	}
	return nil
}

func asError(err error, target **Error) bool { return errors.As(err, target) }
