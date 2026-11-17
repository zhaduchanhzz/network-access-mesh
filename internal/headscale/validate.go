package headscale

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

var (
	authIDPattern    = regexp.MustCompile(`^hskey-authreq-[A-Za-z0-9_-]{24}$`)
	givenNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tagPattern       = regexp.MustCompile(`^tag:[a-z][a-z0-9-]{0,62}$`)
	slugPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	edgeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9]{40}$`)
)

// maxUserNameLength is a platform limit (names are mg-<uuid>, 39 characters); Headscale itself has none.
const maxUserNameLength = 128

// ValidateAuthID checks the format of a web-auth / SSH-check Auth ID (ID-05: hskey-authreq- + 24 characters).
func ValidateAuthID(id string) error {
	if !authIDPattern.MatchString(id) {
		return errors.New("auth ID must be hskey-authreq- followed by 24 characters [A-Za-z0-9_-]")
	}
	return nil
}

// ValidateUserName applies the user-name rules of ID-08 that the REST API does not apply on CreateUser/RenameUser:
// at least 2 characters, starts with a letter, only letters, digits, '-', '.', '_' and at most one '@'. The
// platform additionally restricts names to ASCII and to maxUserNameLength.
func ValidateUserName(name string) error {
	if len(name) < 2 || len(name) > maxUserNameLength {
		return fmt.Errorf("user name must be 2-%d characters", maxUserNameLength)
	}
	if !isASCIILetter(rune(name[0])) {
		return errors.New("user name must start with a letter")
	}
	at := 0
	for _, r := range name {
		switch {
		case isASCIILetter(r), r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		case r == '@':
			at++
			if at > 1 {
				return errors.New("user name may contain at most one '@'")
			}
		default:
			return fmt.Errorf("user name contains an invalid character %q", r)
		}
	}
	return nil
}

func isASCIILetter(r rune) bool { return r < unicode.MaxASCII && unicode.IsLetter(r) }

// ValidateGivenName checks a node name for RenameNode: one lowercase DNS label (the name becomes the MagicDNS host).
func ValidateGivenName(name string) error {
	if !givenNamePattern.MatchString(name) {
		return errors.New("node name must be a lowercase DNS label: 1-63 of [a-z0-9-], not starting or ending with '-'")
	}
	return nil
}

// ValidateTag checks the platform tag format: "tag:" + a lowercase name starting with a letter (Headscale only
// requires the "tag:" prefix, lowercase and no spaces; the policy requires the name to start with a letter).
func ValidateTag(tag string) error {
	if !tagPattern.MatchString(tag) {
		return fmt.Errorf("tag %q must match tag:[a-z][a-z0-9-]{0,62}", tag)
	}
	return nil
}

func validateTags(tags []string) error {
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		if err := ValidateTag(t); err != nil {
			return err
		}
		if seen[t] {
			return fmt.Errorf("duplicate tag %q", t)
		}
		seen[t] = true
	}
	return nil
}

func validateRoutes(routes []netip.Prefix) error {
	for _, p := range routes {
		if !p.IsValid() || p != p.Masked() {
			return fmt.Errorf("route %s must be a canonical prefix (address bits beyond the mask must be zero)", p)
		}
	}
	return nil
}

// policyTopLevelKeys are the only top-level keys Headscale 0.29 accepts (PL-01), in their exact spelling.
var policyTopLevelKeys = map[string]bool{
	"groups": true, "hosts": true, "tagOwners": true, "acls": true, "grants": true, "nodeAttrs": true,
	"autoApprovers": true, "ssh": true, "tests": true, "sshTests": true, "randomizeClientPort": true,
}

// maxPolicyBytes bounds the document size accepted by the adapter.
const maxPolicyBytes = 1 << 20

// ValidatePolicyDocument is the adapter's guard against the leniency of Headscale's policy decoder (V-06), applied
// before CheckPolicy and SetPolicy:
//
//   - the document must not be empty: an empty PUT is stored and becomes "no policy" (allow-all) at the next
//     start while the running policy stays unchanged (PL-06);
//   - it must be plain JSON (the platform renderer emits JSON; HuJSON comments would hide what is checked here);
//   - no member name anywhere may start with '#': Headscale silently drops such members, so "#grants" hides rules;
//   - top-level keys must be exactly one of the 11 known keys (Headscale matches names case-insensitively, so
//     "Grants" would be accepted), and no object may repeat a key, compared case-insensitively;
//   - "grants" must be present and be an array: a missing key or "grants": null means allow-all (PL-02).
func ValidatePolicyDocument(doc string) error {
	if strings.TrimSpace(doc) == "" {
		return errors.New("policy is empty: Headscale would store it and start allow-all at the next restart (PL-06)")
	}
	if len(doc) > maxPolicyBytes {
		return fmt.Errorf("policy is larger than %d bytes", maxPolicyBytes)
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("policy is not valid JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("policy must be a JSON object")
	}
	top, err := walkObject(dec, "", true)
	if err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("policy has data after the top-level object")
	}
	grants, ok := top["grants"]
	if !ok {
		return errors.New(`policy must contain "grants": without it (and without "acls") Headscale allows all traffic (PL-02)`)
	}
	if grants != '[' {
		return errors.New(`"grants" must be an array: "grants": null means allow-all (V-06)`)
	}
	if acls, ok := top["acls"]; ok && acls != '[' {
		return errors.New(`"acls" must be an array when present`)
	}
	return nil
}

// walkObject consumes the members of an object whose '{' was already read. For the top level it returns the
// opening token of each member value ('[' for arrays, '{' for objects, 'n' for null, 'v' for other scalars).
func walkObject(dec *json.Decoder, path string, top bool) (map[string]byte, error) {
	seen := map[string]bool{}
	kinds := map[string]byte{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("policy is not valid JSON: %w", err)
		}
		name, _ := tok.(string)
		where := path + "/" + name
		if strings.HasPrefix(name, "#") {
			return nil, fmt.Errorf("policy member %q starts with '#': Headscale silently ignores it (V-06)", where)
		}
		folded := strings.ToLower(name)
		if seen[folded] {
			return nil, fmt.Errorf("policy member %q is repeated (names are compared case-insensitively)", where)
		}
		seen[folded] = true
		if top && !policyTopLevelKeys[name] {
			return nil, fmt.Errorf("unknown or misspelled top-level policy key %q (Headscale matches keys case-insensitively)", name)
		}
		kind, err := walkValue(dec, where)
		if err != nil {
			return nil, err
		}
		kinds[name] = kind
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, fmt.Errorf("policy is not valid JSON: %w", err)
	}
	return kinds, nil
}

func walkValue(dec *json.Decoder, path string) (byte, error) {
	tok, err := dec.Token()
	if err != nil {
		return 0, fmt.Errorf("policy is not valid JSON: %w", err)
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			if _, err := walkObject(dec, path, false); err != nil {
				return 0, err
			}
			return '{', nil
		case '[':
			for i := 0; dec.More(); i++ {
				if _, err := walkValue(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return 0, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return 0, fmt.Errorf("policy is not valid JSON: %w", err)
			}
			return '[', nil
		}
		return 0, fmt.Errorf("policy is not valid JSON at %q", path)
	case nil:
		return 'n', nil
	default:
		return 'v', nil
	}
}

// equalJSON reports whether two policy documents are byte-identical after trimming surrounding whitespace
// (GetPolicy returns exactly what SetPolicy stored).
func equalJSON(a, b string) bool {
	return bytes.Equal(bytes.TrimSpace([]byte(a)), bytes.TrimSpace([]byte(b)))
}
