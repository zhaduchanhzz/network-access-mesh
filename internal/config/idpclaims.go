package config

// IdP claim constraints — the part of an identity_providers row that PATCH /tenants/{t}/identity-provider and PATCH
// /platform/identity-providers/{id} change (§8.2 MVP: claim_mapping, required_claims, allowed_email_domains; issuer and
// client_id are immutable). The rules are those the login callback reads them with (internal/identity: claim_mapping
// values are claim names, required_claims values are a string/number/boolean or a list of them — anything else rejects
// every login, so it is refused here first; allowed_email_domains are lowercase DNS names).

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Bounds of the claim constraints.
const (
	MaxRequiredClaims   = 16
	MaxClaimValues      = 32
	MaxAllowedDomains   = 32
	MaxClaimNameLength  = 128
	MaxClaimValueLength = 256
)

// MappedFields are the profile fields claim_mapping may redirect (internal/identity mappedClaim).
var MappedFields = []string{"email", "email_verified", "name"}

// IdPClaims are the claim constraints of an IdP, in the form stored (sorted, lowercase domains).
type IdPClaims struct {
	RequiredClaims      map[string]any
	AllowedEmailDomains []string
	ClaimMapping        map[string]string
}

var (
	claimNameRE   = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	emailDomainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// ErrIdPClaims marks invalid claim constraints; the error text names the field ("required_claims", …).
var ErrIdPClaims = errors.New("config: invalid IdP claim constraints")

type claimsError struct{ field, code string }

func (e *claimsError) Error() string   { return "config: " + e.field + ": " + e.code }
func (e *claimsError) Is(t error) bool { return t == ErrIdPClaims }

// ClaimsErrorField returns the field and the code of an invalid constraint.
func ClaimsErrorField(err error) (field, code string) {
	var ce *claimsError
	if errors.As(err, &ce) {
		return ce.field, ce.code
	}
	return "", ""
}

// ParseRequiredClaims decodes and checks a required_claims object (stored or submitted).
func ParseRequiredClaims(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return nil, &claimsError{"required_claims", "not_an_object"}
	}
	if len(m) > MaxRequiredClaims {
		return nil, &claimsError{"required_claims", "too_many"}
	}
	for k, v := range m {
		if !claimNameRE.MatchString(k) || k == "sub" || k == "iss" || k == "aud" {
			return nil, &claimsError{"required_claims", "invalid_claim_name"}
		}
		switch x := v.(type) {
		case string, bool, json.Number:
			if !scalarOK(x) {
				return nil, &claimsError{"required_claims", "invalid_value"}
			}
		case []any:
			if len(x) == 0 || len(x) > MaxClaimValues {
				return nil, &claimsError{"required_claims", "invalid_value"}
			}
			for _, e := range x {
				if !scalarOK(e) {
					return nil, &claimsError{"required_claims", "invalid_value"}
				}
			}
		default:
			return nil, &claimsError{"required_claims", "invalid_value"}
		}
	}
	return m, nil
}

func scalarOK(v any) bool {
	switch x := v.(type) {
	case string:
		return x != "" && len(x) <= MaxClaimValueLength
	case bool:
		return true
	case json.Number:
		_, err := x.Float64()
		return err == nil
	}
	return false
}

// NormalizeEmailDomains lowercases, checks and sorts allowed_email_domains (duplicates removed).
func NormalizeEmailDomains(in []string) ([]string, error) {
	if len(in) > MaxAllowedDomains {
		return nil, &claimsError{"allowed_email_domains", "too_many"}
	}
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if len(d) > 253 || !emailDomainRE.MatchString(d) {
			return nil, &claimsError{"allowed_email_domains", "invalid_domain"}
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out, nil
}

// CheckClaimMapping checks claim_mapping: keys among MappedFields, values claim names.
func CheckClaimMapping(m map[string]string) error {
	for k, v := range m {
		if !slices.Contains(MappedFields, k) {
			return &claimsError{"claim_mapping", "unknown_field"}
		}
		if !claimNameRE.MatchString(v) || len(v) > MaxClaimNameLength {
			return &claimsError{"claim_mapping", "invalid_claim_name"}
		}
	}
	return nil
}

// ParseClaimMapping decodes a stored claim_mapping (non-string values dropped — the login refuses them anyway).
func ParseClaimMapping(raw []byte) map[string]string {
	var m map[string]any
	out := map[string]string{}
	if json.Unmarshal(raw, &m) != nil {
		return out
	}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// RequiredClaimsJSON encodes required claims canonically (sorted keys — encoding/json sorts map keys).
func RequiredClaimsJSON(m map[string]any) []byte {
	if m == nil {
		m = map[string]any{}
	}
	b, _ := json.Marshal(m)
	return b
}

// ClaimMappingJSON encodes a claim mapping.
func ClaimMappingJSON(m map[string]string) []byte {
	if m == nil {
		m = map[string]string{}
	}
	b, _ := json.Marshal(m)
	return b
}

// EqualMapping compares two claim mappings.
func EqualMapping(a, b map[string]string) bool { return maps.Equal(a, b) }
