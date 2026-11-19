package policies

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tailscale/hujson"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Lint rules of §7.2 implemented by the core (P3-T08a; L6 for tags — RuleL6, tagref.go, P4-T15). L3–L13 otherwise
// belong to the typed model of P4-T10.
const (
	// RuleL1: no "grants" member (or "grants": null, or not an array) — Headscale would allow all traffic (PL-02, V-06).
	RuleL1 = "L1"
	// RuleL2: the policy text is empty (or only whitespace) — Headscale stores it and starts allow-all at the next
	// restart (PL-06).
	RuleL2 = "L2"
	// RuleSyntax: not HuJSON, not a JSON object at the top level, not UTF-8, or too large.
	RuleSyntax = "syntax"
	// RuleDecoderGuard: the adapter's guard against the leniency of Headscale's decoder (headscale.
	// ValidatePolicyDocument — V-06): "#"-prefixed members, keys repeated case-insensitively, unknown or misspelled
	// top-level keys (PL-01), "acls" that is not an array.
	RuleDecoderGuard = "decoder_guard"
)

// MaxPolicyBytes bounds the HuJSON text (policy_versions.source_hujson ≤ 1 MiB — CHECK of 0013) and the document sent
// to Headscale (the adapter's own bound).
const MaxPolicyBytes = 1 << 20

// LintError is a policy refused by the lint before any database write or Headscale call.
type LintError struct {
	Rule   string // RuleL1, RuleL2, RuleSyntax, RuleDecoderGuard, RuleL6
	Detail string // what is wrong, in terms of the document (never the document itself)
	// Tags lists the undeclared tags of an L6 refusal (names with the format of a catalog tag only).
	Tags []string
}

func (e *LintError) Error() string { return "policy lint " + e.Rule + ": " + e.Detail }

// Code is the stable error code of the rule (audit reason, command output).
func (e *LintError) Code() string {
	switch e.Rule {
	case RuleL1:
		return "lint_l1_missing_grants"
	case RuleL2:
		return "lint_l2_empty"
	case RuleDecoderGuard:
		return "lint_decoder_guard"
	case RuleL6:
		if len(e.Tags) > 0 || strings.Contains(e.Detail, "tag catalog") {
			return "lint_l6_undeclared_tag"
		}
		return "lint_l6_undeclared_reference"
	case RuleSyntax:
		return "lint_syntax"
	}
	return "lint_" + strings.ToLower(e.Rule)
}

// IsLint reports whether err is a lint refusal and returns it.
func IsLint(err error) (*LintError, bool) {
	var le *LintError
	ok := errors.As(err, &le)
	return le, ok
}

func lintErr(rule, format string, args ...any) error {
	return &LintError{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

// Document is a policy that passed the lint: the HuJSON text as given and the canonical JSON sent to Headscale.
type Document struct {
	// HuJSON is the text as given (comments and trailing commas allowed): policy_versions.source_hujson.
	HuJSON string
	// ContentSHA256 is the hex sha256 of HuJSON (UTF-8 bytes): policy_versions.content_sha256 (the DB checks it).
	ContentSHA256 string
	// Applied is the canonical rendering sent to Headscale and stored as policy_applications.applied_hujson: the
	// HuJSON parsed by the parser Headscale itself uses (github.com/tailscale/hujson), comments and trailing commas
	// removed (Standardize), then re-indented by encoding/json with two spaces — no leading or trailing whitespace.
	// Member order, names and literal values are kept byte for byte; the same content always renders the same bytes,
	// whatever its comments or layout.
	Applied string
	// AppliedSHA256 is the hex sha256 of Applied: policy_applications.applied_sha256, the reference of the read-back
	// after SetPolicy (and of the drift check — P4-T10).
	AppliedSHA256 string
	// InputsSHA256 is policy_applications.inputs_sha256: ContentSHA256 after Lint; RenderCatalog adds the catalog.
	InputsSHA256 string
	// TagOwners are the catalog tags RenderCatalog rendered into "tagOwners" (nil: nothing rendered).
	TagOwners []string
}

// Lint checks a HuJSON policy before anything is stored or sent (§7.2 "Guardrail lint (chạy trước mọi lời gọi
// Headscale)") and returns its canonical document:
//
//	L2      the text is empty or only whitespace;
//	syntax  not UTF-8, contains NUL, larger than MaxPolicyBytes, not HuJSON, or not an object at the top level;
//	L1      no member named exactly "grants" whose value is an array ("grants": null and a missing key both mean
//	        allow-all — PL-02, V-06);
//	guard   headscale.ValidatePolicyDocument on the canonical JSON — the adapter runs the same guard again before
//	        CheckPolicy/SetPolicy.
func Lint(text string) (Document, error) {
	if strings.TrimSpace(text) == "" {
		return Document{}, lintErr(RuleL2, "the policy is empty: Headscale would store it and start allow-all at its next restart (PL-06)")
	}
	switch {
	case len(text) > MaxPolicyBytes:
		return Document{}, lintErr(RuleSyntax, "the policy is larger than %d bytes", MaxPolicyBytes)
	case !utf8.ValidString(text):
		return Document{}, lintErr(RuleSyntax, "the policy is not valid UTF-8")
	case strings.ContainsRune(text, 0):
		return Document{}, lintErr(RuleSyntax, "the policy contains a NUL character")
	}
	v, err := hujson.Parse([]byte(text))
	if err != nil {
		return Document{}, lintErr(RuleSyntax, "not valid HuJSON: %s", hujsonMessage(err))
	}
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		return Document{}, lintErr(RuleSyntax, "the policy must be an object at the top level")
	}
	if err := checkGrants(obj); err != nil {
		return Document{}, err
	}
	v.Standardize()
	var applied bytes.Buffer
	if err := json.Indent(&applied, v.Pack(), "", "  "); err != nil {
		return Document{}, lintErr(RuleSyntax, "the standardized policy is not valid JSON")
	}
	out := strings.TrimSpace(applied.String())
	if len(out) > MaxPolicyBytes {
		return Document{}, lintErr(RuleSyntax, "the rendered policy is larger than %d bytes", MaxPolicyBytes)
	}
	if err := headscale.ValidatePolicyDocument(out); err != nil {
		return Document{}, lintErr(RuleDecoderGuard, "%v", err)
	}
	sum := SHA256Hex(text)
	return Document{HuJSON: text, ContentSHA256: sum, Applied: out, AppliedSHA256: SHA256Hex(out), InputsSHA256: sum}, nil
}

// checkGrants is L1: exactly one member spelled "grants", whose value is an array. A differently cased "Grants" is
// left to the decoder guard (it is a misspelled key there); a policy with only "Grants" fails here first.
func checkGrants(obj *hujson.Object) error {
	found := 0
	for _, m := range obj.Members {
		name, ok := m.Name.Value.(hujson.Literal)
		if !ok || name.String() != "grants" {
			continue
		}
		found++
		switch g := m.Value.Value.(type) {
		case *hujson.Array:
		case hujson.Literal:
			if g.Kind() == 'n' {
				return lintErr(RuleL1, `"grants": null means allow-all (V-06): use an explicit array, [] for deny-all`)
			}
			return lintErr(RuleL1, `"grants" must be an array`)
		default:
			return lintErr(RuleL1, `"grants" must be an array`)
		}
	}
	switch found {
	case 0:
		return lintErr(RuleL1, `the policy has no "grants" member: without it (and without "acls") Headscale allows all traffic (PL-02); use "grants": [] for deny-all`)
	case 1:
		return nil
	}
	return lintErr(RuleL1, `"grants" is declared %d times`, found)
}

// hujsonMessage keeps the parser's position information but never quotes the document.
func hujsonMessage(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

// SHA256Hex returns the hex sha256 of the UTF-8 bytes of s.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
