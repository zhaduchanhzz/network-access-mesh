package policies

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 11, 19, 1, 2, 3, 456000, time.UTC)
}

func mustLint(t *testing.T, text string) Document {
	t.Helper()
	doc, err := Lint(text)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	return doc
}

// TestTagReferences: every string value and member name starting with "tag:" outside "tagOwners" is a reference —
// grants src/dst/via, ACL destinations with ports, SSH, autoApprovers, tests — cut before the port; "tagOwners" (keys
// and owners) is not.
func TestTagReferences(t *testing.T) {
	doc := mustLint(t, `{
		// comments are gone after Lint
		"tagOwners": {"tag:owned-only": ["tag:owner-tag", "group:x"]},
		"grants": [{"src": ["tag:web"], "dst": ["tag:db"], "ip": ["tcp:5432"], "via": ["tag:router"]}],
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:api:443", "tag:api:80"]}],
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:ssh"], "users": ["root"]}],
		"autoApprovers": {"routes": {"10.0.0.0/8": ["tag:subnet"]}, "exitNode": ["tag:exit"]},
		"tests": [{"src": "tag:web", "accept": ["tag:db:5432"]}],
	}`)
	refs, err := TagReferences(doc.Applied)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tag:api", "tag:db", "tag:exit", "tag:router", "tag:ssh", "tag:subnet", "tag:web"}
	if !slices.Equal(refs, want) {
		t.Fatalf("refs %v, want %v", refs, want)
	}
	if _, err := TagReferences(`[1]`); err == nil {
		t.Fatal("an array is not a policy")
	}
}

// TestRenderCatalog: L6 refuses an undeclared reference; "tagOwners" is the catalog with empty owners (replaced in
// place, or appended last); a policy without "tagOwners" and an empty catalog keeps its bytes; the render is
// deterministic, idempotent through Lint (the drift repair re-applies the applied string) and its inputs hash covers the
// catalog.
func TestRenderCatalog(t *testing.T) {
	plain := mustLint(t, `{"grants": [], "ssh": []}`)
	got, err := RenderCatalog(plain, nil)
	if err != nil || got.Applied != plain.Applied || got.InputsSHA256 != plain.ContentSHA256 || got.TagOwners != nil {
		t.Fatalf("empty catalog changed the document: %+v %v", got, err)
	}

	withTag := mustLint(t, `{"grants": [{"src": ["tag:web"], "dst": ["autogroup:member"], "ip": ["*"]}], "ssh": []}`)
	_, err = RenderCatalog(withTag, []string{"tag:db"})
	le, ok := IsLint(err)
	if !ok || le.Rule != RuleL6 || le.Code() != "lint_l6_undeclared_tag" || !slices.Equal(le.Tags, []string{"tag:web"}) ||
		!strings.Contains(le.Detail, "tag:web") {
		t.Fatalf("L6: %v", err)
	}
	// a name that could never be declared is counted, never quoted
	odd := mustLint(t, `{"grants": [{"src": ["tag:Not_Valid"], "dst": ["*"], "ip": ["*"]}]}`)
	_, err = RenderCatalog(odd, nil)
	if le, ok := IsLint(err); !ok || le.Rule != RuleL6 || len(le.Tags) != 0 || strings.Contains(le.Detail, "Not_Valid") {
		t.Fatalf("odd name: %v", err)
	}

	out, err := RenderCatalog(withTag, []string{"tag:web", "tag:db", "tag:web"})
	if err != nil {
		t.Fatal(err)
	}
	wantTail := "\"ssh\": [],\n  \"tagOwners\": {\n    \"tag:db\": [],\n    \"tag:web\": []\n  }\n}"
	if !strings.HasSuffix(out.Applied, wantTail) || out.AppliedSHA256 != SHA256Hex(out.Applied) {
		t.Fatalf("appended render:\n%s", out.Applied)
	}
	if !slices.Equal(out.TagOwners, []string{"tag:db", "tag:web"}) || out.InputsSHA256 == out.ContentSHA256 ||
		out.ContentSHA256 != withTag.ContentSHA256 {
		t.Fatalf("render metadata %+v", out)
	}
	// idempotent: the applied string goes through Lint and the render again (drift repair) ⇒ the same bytes
	again, err := RenderCatalog(mustLint(t, out.Applied), []string{"tag:db", "tag:web"})
	if err != nil || again.Applied != out.Applied {
		t.Fatalf("render not idempotent: %v\n%s", err, again.Applied)
	}
	// another catalog ⇒ other inputs, other bytes
	other, err := RenderCatalog(withTag, []string{"tag:web"})
	if err != nil || other.InputsSHA256 == out.InputsSHA256 || other.Applied == out.Applied {
		t.Fatalf("catalog not in the inputs: %v", err)
	}

	// an existing "tagOwners" is replaced in place, its owners dropped; its keys are not references (a tag deleted from
	// the catalog does not block the re-application of the previously applied string)
	owned := mustLint(t, `{"tagOwners": {"tag:gone": ["alice@"], "tag:web": ["group:x"]}, "grants": [{"src": ["tag:web"], "dst": ["*"], "ip": ["*"]}]}`)
	in, err := RenderCatalog(owned, []string{"tag:web"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(in.Applied, "{\n  \"tagOwners\": {\n    \"tag:web\": []\n  },\n  \"grants\"") ||
		strings.Contains(in.Applied, "alice") || strings.Contains(in.Applied, "tag:gone") {
		t.Fatalf("in-place render:\n%s", in.Applied)
	}
	emptied, err := RenderCatalog(mustLint(t, `{"tagOwners": {"tag:gone": []}, "grants": []}`), nil)
	if err != nil || !strings.Contains(emptied.Applied, "\"tagOwners\": {}") || emptied.TagOwners == nil {
		t.Fatalf("emptied catalog: %v\n%s", err, emptied.Applied)
	}
}

// TestCatalogInputChecks: the format and size checks of the catalog's names (no database).
func TestCatalogInputChecks(t *testing.T) {
	for _, n := range []string{"tag:a", "tag:web-1", "tag:" + strings.Repeat("a", 50)} {
		if !ValidTagName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", "tag:", "tag:A", "tag:1a", "web", "tag:a_b", "tag:a b", "tag:" + strings.Repeat("a", 51), "Tag:a"} {
		if ValidTagName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	if got, err := normalizeTags([]string{"tag:b", "tag:a", "tag:b"}, "tags"); err != nil || !slices.Equal(got, []string{"tag:a", "tag:b"}) {
		t.Errorf("normalize: %v %v", got, err)
	}
	many := make([]string, MaxTagsPerRequest+1)
	for i := range many {
		many[i] = "tag:t" + strings.Repeat("a", i%40)
	}
	for _, c := range []struct {
		in     []string
		reason string
	}{{nil, "tags_empty"}, {[]string{"tag:ok", "nope"}, "invalid_tag_name"}, {many, "too_many_tags"}} {
		_, err := normalizeTags(c.in, "requested_tags")
		te, ok := AsTagError(err)
		if !ok || !errors.Is(err, ErrTagInvalid) || te.Reason != c.reason || te.Field != "requested_tags" {
			t.Errorf("%v: %v", c.in, err)
			continue
		}
		if f, r, _, ok := te.Validation(); !ok || f != "requested_tags" || r != c.reason {
			t.Errorf("validation accessor: %s %s %v", f, r, ok)
		}
	}
	if _, _, _, ok := tagErr(ErrTagConflict, "tag_in_use", "").Validation(); ok {
		t.Error("a conflict is not a validation refusal")
	}
	if d, err := checkDescription(new(string)); err != nil || d != nil {
		t.Errorf("empty description: %v %v", d, err)
	}
	long := strings.Repeat("é", MaxTagDescription+1)
	if _, err := checkDescription(&long); !errors.Is(err, ErrTagInvalid) {
		t.Errorf("long description: %v", err)
	}
	c := encodeTagCursor(mustTime(t), [16]byte{1})
	if at, id, ok := decodeTagCursor(c); !ok || !at.Equal(mustTime(t)) || id[0] != 1 {
		t.Errorf("cursor round trip: %v %v %v", at, id, ok)
	}
	if _, _, ok := decodeTagCursor("nope"); ok {
		t.Error("foreign cursor accepted")
	}
}
