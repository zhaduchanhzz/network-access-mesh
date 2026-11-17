package approvals

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// MaxPayloadBytes bounds the canonical payload. PostgreSQL prints jsonb with a space after every ':' and ',', and the
// CHECK of 0009 bounds that text to 16 KiB: half of it leaves room for any expansion.
const MaxPayloadBytes = 8192

// ErrPayload marks a payload that is not a canonicalizable JSON object (not an object, a float, too large, invalid).
var ErrPayload = errors.New("approvals: invalid payload")

var integerRE = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,18})$`)

// Canonical returns the canonical JSON of v — the form stored in approval_requests.payload, shown to the approver and
// hashed into payload_sha256 (§6.3): a JSON object, keys sorted by byte order at every level, no insignificant
// whitespace, no HTML escaping, numbers restricted to integers (a float has no single canonical text). The same value
// always gives the same bytes, so the hash does not depend on how the database prints jsonb.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPayload, err)
	}
	return CanonicalJSON(buf.Bytes())
}

// CanonicalJSON re-encodes JSON text (a request body, the jsonb read back from the database) in canonical form.
func CanonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPayload, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrPayload)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, fmt.Errorf("%w: not a JSON object", ErrPayload)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v, 0); err != nil {
		return nil, err
	}
	if buf.Len() > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrPayload, buf.Len(), MaxPayloadBytes)
	}
	return buf.Bytes(), nil
}

// maxDepth bounds the nesting of a payload (parameters of an operation, not documents).
const maxDepth = 16

func writeCanonical(buf *bytes.Buffer, v any, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: nested deeper than %d", ErrPayload, maxDepth)
	}
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		if !integerRE.MatchString(string(x)) {
			return fmt.Errorf("%w: number %q is not an integer of at most 19 digits", ErrPayload, string(x))
		}
		buf.WriteString(string(x))
	case string:
		writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%w: unexpected JSON value %T", ErrPayload, v)
	}
	return nil
}

// writeString writes s as a JSON string the way encoding/json does without HTML escaping (deterministic for a given
// string: control characters, '"', '\\', U+2028 and U+2029 escaped; invalid UTF-8 replaced).
func writeString(buf *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	buf.Write(bytes.TrimSuffix(tmp.Bytes(), []byte("\n")))
}

// Hash is payload_sha256: the lower-case hex SHA-256 of the canonical payload.
func Hash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// hashRE is the shape of payload_sha256 (CHECK of 0009).
var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidHash reports whether s has the shape of a payload_sha256.
func ValidHash(s string) bool { return hashRE.MatchString(s) }
