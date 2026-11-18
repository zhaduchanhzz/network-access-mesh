package policies

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Tag references and the tagOwners render of the tag catalog (P4-T15 — §7.2: "tagOwners" is rendered from the tenant's
// catalog, tenant_tags, with EMPTY owner lists — only the platform tags nodes, through the API (PL-09); L6: a tag
// referenced but not declared is refused).

// RuleL6 is the lint rule of §7.2 for undeclared references; the core implements its tag part (the tenant's catalog —
// groups, hosts and memberships come with the typed model of P4-T10).
const RuleL6 = "L6"

// tagOwnersKey is the top-level member rendered from the catalog.
const tagOwnersKey = "tagOwners"

// TagNamePattern is the format of a catalog tag name (CHECK of tenant_tags.name — 0021): the exact string a node
// carries on Headscale.
var TagNamePattern = regexp.MustCompile(`^tag:[a-z][a-z0-9-]{0,49}$`)

// ValidTagName reports whether name has the format of a catalog tag.
func ValidTagName(name string) bool { return TagNamePattern.MatchString(name) }

// tagOf returns the tag a policy string refers to — "tag:web", or "tag:web:443" (an ACL destination with its ports) —
// and whether s is a tag reference at all.
func tagOf(s string) (string, bool) {
	if !strings.HasPrefix(s, "tag:") {
		return "", false
	}
	if i := strings.IndexByte(s[len("tag:"):], ':'); i >= 0 {
		return s[:len("tag:")+i], true
	}
	return s, true
}

// TagReferences returns, sorted and without duplicates, the tags a canonical policy (Document.Applied — plain JSON)
// references OUTSIDE its "tagOwners" member: every string value and every member name that starts with "tag:" — a
// src/dst/via of a grant or an ACL, an SSH rule, an autoApprover, a test — cut before the port of an ACL destination.
// "tagOwners" is left out: it is rendered from the catalog itself, whatever the document holds there.
func TagReferences(applied string) ([]string, error) {
	dec := json.NewDecoder(strings.NewReader(applied))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("policies: tag references: %w", err)
	}
	top, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("policies: tag references: the policy is not an object")
	}
	seen := map[string]bool{}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if tag, ok := tagOf(k); ok {
					seen[tag] = true
				}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case string:
			if tag, ok := tagOf(t); ok {
				seen[tag] = true
			}
		}
	}
	for k, val := range top {
		if k == tagOwnersKey {
			continue
		}
		if tag, ok := tagOf(k); ok {
			seen[tag] = true
		}
		walk(val)
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// undeclared returns the references that are not in the catalog (both sorted).
func undeclared(refs, catalog []string) []string {
	var out []string
	for _, r := range refs {
		if _, found := slices.BinarySearch(catalog, r); !found {
			out = append(out, r)
		}
	}
	return out
}

// l6Error is the L6 refusal: Tags lists the undeclared names that have the format of a catalog tag (a name that could
// never be declared is counted, not quoted — lint errors never quote the document).
func l6Error(missing []string) *LintError {
	var named []string
	for _, m := range missing {
		if ValidTagName(m) {
			named = append(named, m)
		}
	}
	detail := fmt.Sprintf("%d tag(s) referenced by the policy are not in the tenant's tag catalog", len(missing))
	if len(named) > 0 {
		detail += ": " + strings.Join(named, ", ")
	}
	return &LintError{Rule: RuleL6, Detail: detail, Tags: named}
}

// renderTagOwners returns the canonical policy with its "tagOwners" member replaced by the catalog — every tag of the
// catalog, sorted, each with an EMPTY owner list (§7.2, L12: no user may self-tag with --advertise-tags) — and whether
// it rendered anything. A policy without "tagOwners" and an empty catalog is returned unchanged (the documents the
// platform applied before the catalog existed keep their bytes); otherwise the member is replaced in place, or appended
// last. The output is canonical like Document.Applied (encoding/json indentation, two spaces) and rendering it again
// with the same catalog gives the same bytes.
func renderTagOwners(applied string, catalog []string) (string, bool, error) {
	members, err := topMembers(applied)
	if err != nil {
		return "", false, err
	}
	at := -1
	for i, m := range members {
		if m.name == tagOwnersKey {
			at = i
			break
		}
	}
	if at < 0 && len(catalog) == 0 {
		return applied, false, nil
	}
	var owners bytes.Buffer
	owners.WriteByte('{')
	for i, t := range catalog {
		if i > 0 {
			owners.WriteByte(',')
		}
		k, err := json.Marshal(t)
		if err != nil {
			return "", false, err
		}
		owners.Write(k)
		owners.WriteString(":[]")
	}
	owners.WriteByte('}')
	if at >= 0 {
		members[at].value = owners.Bytes()
	} else {
		members = append(members, member{name: tagOwnersKey, value: owners.Bytes()})
	}
	var compact bytes.Buffer
	compact.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			compact.WriteByte(',')
		}
		k, err := json.Marshal(m.name)
		if err != nil {
			return "", false, err
		}
		compact.Write(k)
		compact.WriteByte(':')
		if err := json.Compact(&compact, m.value); err != nil {
			return "", false, err
		}
	}
	compact.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return "", false, err
	}
	return out.String(), true, nil
}

// member is one top-level member of a policy, its value as raw JSON.
type member struct {
	name  string
	value json.RawMessage
}

// topMembers splits a JSON object into its members, in order.
func topMembers(doc string) ([]member, error) {
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("policies: render: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("policies: render: the policy is not an object")
	}
	var out []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("policies: render: %w", err)
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("policies: render: unexpected token")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("policies: render: %w", err)
		}
		out = append(out, member{name: name, value: raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("policies: render: %w", err)
	}
	return out, nil
}

// inputsSHA256 is policy_applications.inputs_sha256 of an application: the version's content_sha256 alone when nothing
// was rendered from the tables (the core of P3-T08a), otherwise the sha256 of the content hash and the rendered catalog
// — the same version applied over a different catalog has different inputs.
func inputsSHA256(contentSHA256 string, rendered bool, catalog []string) string {
	if !rendered {
		return contentSHA256
	}
	return SHA256Hex("content_sha256=" + contentSHA256 + "\ntag_owners=" + strings.Join(catalog, ","))
}

// RenderCatalog applies the tag catalog to a document that passed Lint (§7.2): L6 — every tag the policy references
// outside "tagOwners" must be in the catalog (sorted) — then the "tagOwners" render; Applied, AppliedSHA256 and
// InputsSHA256 describe the result. The catalog is the tenant's tenant_tags names.
func RenderCatalog(doc Document, catalog []string) (Document, error) {
	cat := slices.Clone(catalog)
	sort.Strings(cat)
	cat = slices.Compact(cat)
	refs, err := TagReferences(doc.Applied)
	if err != nil {
		return Document{}, lintErr(RuleSyntax, "the standardized policy is not valid JSON")
	}
	if missing := undeclared(refs, cat); len(missing) > 0 {
		return Document{}, l6Error(missing)
	}
	out, rendered, err := renderTagOwners(doc.Applied, cat)
	if err != nil {
		return Document{}, lintErr(RuleSyntax, "the standardized policy is not valid JSON")
	}
	if len(out) > MaxPolicyBytes {
		return Document{}, lintErr(RuleSyntax, "the rendered policy is larger than %d bytes", MaxPolicyBytes)
	}
	if err := headscale.ValidatePolicyDocument(out); err != nil {
		return Document{}, lintErr(RuleDecoderGuard, "%v", err)
	}
	doc.Applied, doc.AppliedSHA256 = out, SHA256Hex(out)
	doc.InputsSHA256 = inputsSHA256(doc.ContentSHA256, rendered, cat)
	if rendered {
		doc.TagOwners = append([]string{}, cat...) // non-nil: rendered, possibly empty
	}
	return doc, nil
}
