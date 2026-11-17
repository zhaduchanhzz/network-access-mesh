package requestid

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValid(t *testing.T) {
	for _, id := range []string{
		"0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f50", // UUID (the edge or a client)
		"01JCZ3V1S0YBEK2N5Q8R7T6W4X",           // ULID
		"req_42", "a", "trace:span.1-2",
		strings.Repeat("x", MaxLen),
	} {
		if !Valid(id) {
			t.Errorf("Valid(%q) = false, want true", id)
		}
	}
	for _, id := range []string{
		"", strings.Repeat("x", MaxLen+1), "-leading", ".leading",
		"has space", "line\nbreak", "tab\t", "<script>", `quote"`, "semi;colon", "slash/x", "ünïcode",
		"hskey-api-AbCdEf123", "x-HSKEY-auth-1", // never echo something shaped like a Headscale credential
	} {
		if Valid(id) {
			t.Errorf("Valid(%q) = true, want false", id)
		}
	}
}

func TestNew(t *testing.T) {
	a, b := New(), New()
	if a == b {
		t.Fatalf("New returned the same id twice: %s", a)
	}
	for _, id := range []string{a, b} {
		u, err := uuid.Parse(id)
		if err != nil || u.Version() != 7 {
			t.Errorf("New() = %q: want a UUIDv7 (err %v)", id, err)
		}
		if !Valid(id) {
			t.Errorf("New() = %q is not Valid", id)
		}
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()
	if got := From(ctx); got != "" {
		t.Fatalf("From(empty) = %q", got)
	}
	if got := From(With(ctx, "rid-1")); got != "rid-1" {
		t.Fatalf("From(With(rid-1)) = %q", got)
	}
}
