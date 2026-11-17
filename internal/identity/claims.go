package identity

import (
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Size limits of the profile values copied from an ID token.
const (
	maxSubjectLen     = 255
	maxDisplayNameLen = 200
	maxEmailLen       = 320
	maxACRLen         = 200
	maxAMR            = 16
	maxAMRLen         = 64
)

// tokenProfile is what a login keeps from a verified ID token.
type tokenProfile struct {
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	AuthTime      time.Time
	ACR           string
	AMR           []string
}

// claimString returns a string claim, or "" when absent or not a string.
func claimString(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return s
}

// claimTime returns a NumericDate claim (seconds since the epoch).
func claimTime(claims map[string]any, name string) (time.Time, bool) {
	v, ok := claims[name].(float64)
	if !ok || v <= 0 || v > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0), true
}

// claimBool accepts a JSON boolean and, for providers that send it as a string, "true"/"false".
func claimBool(claims map[string]any, name string) bool {
	switch v := claims[name].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// mappedClaim returns the claim name for a profile field: claim_mapping overrides the default.
func (p *idp) mappedClaim(field, def string) string {
	if c, ok := p.ClaimMapping[field]; ok {
		return c
	}
	return def
}

// checkRequiredClaims enforces identity_providers.required_claims before any identity is created (§8.2
// shared-issuer rule; IT-01c). For every entry name → expected:
//   - expected is a string, number or boolean: the claim must equal it, or be an array that contains it;
//   - expected is an array: the claim must equal one of its elements, or be an array sharing an element with it;
//   - anything else (object, null) is a configuration error and rejects the login (fail closed).
func checkRequiredClaims(required map[string]any, claims map[string]any) *Error {
	for name, want := range required {
		got, ok := claims[name]
		if !ok {
			return forbidden("required_claim_missing")
		}
		var accepted []any
		switch w := want.(type) {
		case string, float64, bool:
			accepted = []any{w}
		case []any:
			accepted = w
		default:
			return newErr(KindForbidden, "required_claim_misconfigured", nil)
		}
		if !claimMatches(got, accepted) {
			return forbidden("required_claim_mismatch")
		}
	}
	return nil
}

func claimMatches(got any, accepted []any) bool {
	values := []any{got}
	if arr, ok := got.([]any); ok {
		values = arr
	}
	for _, v := range values {
		for _, a := range accepted {
			switch a.(type) {
			case string, float64, bool:
				if reflect.DeepEqual(v, a) {
					return true
				}
			}
		}
	}
	return false
}

// checkEmail enforces require_email_verified and allowed_email_domains (§8.2): a domain restriction only ever
// trusts a verified address.
func checkEmail(p *idp, email string, verified bool) *Error {
	if p.RequireEmailVerified && (email == "" || !verified) {
		return forbidden("email_not_verified")
	}
	if len(p.AllowedEmailDomains) == 0 {
		return nil
	}
	if email == "" || !verified {
		return forbidden("email_not_verified")
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return forbidden("email_domain_not_allowed")
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range p.AllowedEmailDomains {
		if domain == d {
			return nil
		}
	}
	return forbidden("email_domain_not_allowed")
}

// profileFromClaims extracts the profile of a verified ID token and checks the IdP's claim policy.
func profileFromClaims(p *idp, claims map[string]any) (*tokenProfile, *Error) {
	sub := claimString(claims, "sub")
	if sub == "" || len(sub) > maxSubjectLen || !utf8.ValidString(sub) {
		return nil, unauthenticated("subject_invalid")
	}
	if err := checkRequiredClaims(p.RequiredClaims, claims); err != nil {
		return nil, err
	}
	email := strings.TrimSpace(claimString(claims, p.mappedClaim("email", "email")))
	if len(email) > maxEmailLen || (email != "" && !strings.Contains(email, "@")) || !utf8.ValidString(email) {
		email = ""
	}
	verified := email != "" && claimBool(claims, "email_verified")
	if err := checkEmail(p, email, verified); err != nil {
		return nil, err
	}
	name := claimString(claims, p.mappedClaim("display_name", "name"))
	if name == "" {
		name = claimString(claims, "preferred_username")
	}
	prof := &tokenProfile{
		Subject: sub, Email: email, EmailVerified: verified,
		DisplayName: truncateUTF8(strings.TrimSpace(name), maxDisplayNameLen),
		ACR:         truncateUTF8(claimString(claims, "acr"), maxACRLen),
	}
	if amr, ok := claims["amr"].([]any); ok {
		for _, v := range amr {
			if s, ok := v.(string); ok && s != "" && len(prof.AMR) < maxAMR {
				prof.AMR = append(prof.AMR, truncateUTF8(s, maxAMRLen))
			}
		}
	}
	return prof, nil
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune and drops invalid UTF-8.
func truncateUTF8(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
