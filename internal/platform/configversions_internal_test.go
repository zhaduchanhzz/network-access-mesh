package platform

import (
	"encoding/base64"
	"errors"
	"testing"
)

// TestVersionCursor: the cursor of GET /platform/instances/{id}/config-versions round-trips a version and refuses
// anything that is not one (422, never a database error).
func TestVersionCursor(t *testing.T) {
	for _, v := range []int32{1, 7, 2147483647} {
		got, err := decodeVersionCursor(encodeVersionCursor(v))
		if err != nil || got != v {
			t.Errorf("round trip %d: %d %v", v, got, err)
		}
	}
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, c := range []string{"@@", enc("7"), enc("v0"), enc("v-1"), enc("vx"), enc("v2147483648"), enc("v1|x"),
		enc("v" + string(make([]byte, 70)))} {
		if _, err := decodeVersionCursor(c); !errors.Is(err, ErrInvalid) {
			t.Errorf("cursor %q: %v, want ErrInvalid", c, err)
		}
	}
}
