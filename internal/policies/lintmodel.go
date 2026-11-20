package policies

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Lint rules L3–L13 of §7.2 (P4-T10). L1, L2 and the decoder guard are lint.go (P3-T08a), the tag part of L6 is
// tagref.go (P4-T15). They run on the typed model and on the rendered output, always BEFORE any Headscale call.
const (
	RuleL3  = "L3"  // a top-level key outside the 11 Headscale keys, or nodeAttrs (refused in the MVP — HS-22)
	RuleL4  = "L4"  // "*" (or a default route) as a destination — blocked unless an Owner acknowledges it with a reason
	RuleL5  = "L5"  // autogroup:danger-all as a source — blocked
	RuleL7  = "L7"  // autogroup:internet without a via tag; an autoApprover that is not a platform tag — confirm
	RuleL8  = "L8"  // autogroup:self in a large tenant — warning (HS-08)
	RuleL9  = "L9"  // an "acls" section (legacy) — information
	RuleL10 = "L10" // SSH accept (forwarding always on) — confirm; SSH check — blocked (V-26, post-MVP)
	RuleL11 = "L11" // a user token of the output that is not mg-<membership uuid>@ (or a provider identifier) — blocked
	RuleL12 = "L12" // a tagOwners entry with owners — blocked
	RuleL13 = "L13" // autogroup:member in a tenant of identity mode headscale_oidc — confirm
	// RuleCheck is the dry run of the rendered policy on the tenant's instance (CheckPolicy — §7.3 draft → validated).
	RuleCheck = "check"
)

// Severities of a Finding.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// LargeTenantDevices is the size from which autogroup:self costs (L8 — HS-08).
const LargeTenantDevices = 500

// Finding is one result of the lint (validation_report — §13.3).
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
	// Line is the line of the HuJSON text a finding of an import points at (P4-T11); 0 otherwise.
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
	// RequiresAck: the finding needs an acknowledgement of its rule in the source (§7.2 "cần xác nhận"); unacknowledged
	// it is an error. OwnerOnly: the acknowledgement counts only when a Tenant Owner approves the version (L4, L12).
	RequiresAck  bool `json:"requires_ack,omitempty"`
	OwnerOnly    bool `json:"owner_only,omitempty"`
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// Report is policy_versions.validation_report of a typed version (PolicyVersion.validation_report — §13.3): the
// findings of the lint, the sha256 of the rendered policy it judged and the outcome of the dry run on the instance.
// tests[] lists the generated tests of the render and the grants left without one (testgen.go — P5-T01).
type Report struct {
	Engine         string     `json:"engine"`
	Result         string     `json:"result"` // passed | failed
	Errors         []Finding  `json:"errors"`
	Warnings       []Finding  `json:"warnings"`
	Info           []Finding  `json:"info"`
	Tests          []TestCase `json:"tests"`
	RenderedSHA256 string     `json:"rendered_sha256,omitempty"`
	Check          string     `json:"check,omitempty"` // passed | failed | skipped
	Revision       int64      `json:"revision,omitempty"`
	ValidatedAt    *time.Time `json:"validated_at,omitempty"`
}

// Report results.
const (
	ResultPassed = "passed"
	ResultFailed = "failed"
	engineTyped  = "p4-t10"
)

func newReport() Report {
	return Report{Engine: engineTyped, Errors: []Finding{}, Warnings: []Finding{}, Info: []Finding{}, Tests: []TestCase{}}
}

// add files f by its severity; a finding that needs an acknowledgement it does not have becomes an error.
func (r *Report) add(f Finding) {
	switch {
	case f.RequiresAck && !f.Acknowledged:
		f.Severity, f.Code = SeverityError, f.Code+"_ack_required"
		r.Errors = append(r.Errors, f)
	case f.RequiresAck: // acknowledged with a reason: it stays visible to the reviewer
		f.Severity = SeverityWarning
		r.Warnings = append(r.Warnings, f)
	case f.Severity == SeverityError:
		r.Errors = append(r.Errors, f)
	case f.Severity == SeverityWarning:
		r.Warnings = append(r.Warnings, f)
	default:
		r.Info = append(r.Info, f)
	}
}

// finish sets the result.
func (r *Report) finish() {
	r.Result = ResultPassed
	if len(r.Errors) > 0 {
		r.Result = ResultFailed
	}
}

// Blocking reports whether the report holds an error.
func (r Report) Blocking() bool { return len(r.Errors) > 0 }

// OwnerAcknowledged reports whether an acknowledged finding needs a Tenant Owner's approval (L4, L12).
func (r Report) OwnerAcknowledged() bool {
	for _, f := range r.Warnings {
		if f.Acknowledged && f.OwnerOnly {
			return true
		}
	}
	return false
}

// firstError is the LintError of the first blocking finding (the core's refusal shape — audit policy.lint_rejected).
func (r Report) firstError() *LintError {
	if len(r.Errors) == 0 {
		return nil
	}
	f := r.Errors[0]
	return &LintError{Rule: f.Rule, Detail: f.Code + ": " + f.Message + pathSuffix(f.Path)}
}

func pathSuffix(p string) string {
	if p == "" {
		return ""
	}
	return " (" + p + ")"
}

var (
	// userTokenRE is the only user token the renderer emits (§7.2 (1)); providerTokenRE the identifier of the native
	// OIDC mode (<issuer>/<sub>@ — not built in the MVP, accepted so the rule does not have to change with it).
	userTokenRE     = regexp.MustCompile(`^mg-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@$`)
	providerTokenRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)*/[A-Za-z0-9._~|-]{1,255}@$`)
)

// validUserToken reports whether the user part of a policy string (up to its last '@') is a token L11 accepts.
func validUserToken(s string) bool {
	i := strings.LastIndexByte(s, '@')
	if i < 0 {
		return true
	}
	tok := s[:i+1]
	return userTokenRE.MatchString(tok) || providerTokenRE.MatchString(tok)
}

// OutputLint is the lint of a rendered (or platform-given) policy — the canonical JSON sent to Headscale: L3 (unknown
// key, nodeAttrs), L5 (danger-all as a source), L9 (acls — information), L10 (SSH check), L11 (user tokens), L12
// (tagOwners with owners). Every path of the core runs it after the render, before any Headscale call; the typed
// pipeline adds the model rules (lintModel). An unreadable document is an L3 error.
func OutputLint(applied string) []Finding {
	var top map[string]any
	dec := json.NewDecoder(strings.NewReader(applied))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return []Finding{{Rule: RuleL3, Severity: SeverityError, Code: "unreadable", Message: "the rendered policy is not a JSON object"}}
	}
	var out []Finding
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch {
		case k == "nodeAttrs":
			out = append(out, Finding{Rule: RuleL3, Severity: SeverityError, Code: "node_attrs", Path: k,
				Message: "nodeAttrs is not part of the policy model in the MVP (HS-22)"})
		case !topLevelKeys[k]:
			out = append(out, Finding{Rule: RuleL3, Severity: SeverityError, Code: "unknown_key", Path: k,
				Message: "a top-level key outside the 11 keys Headscale accepts"})
		case k == "acls":
			out = append(out, Finding{Rule: RuleL9, Severity: SeverityInfo, Code: "acls_legacy", Path: k,
				Message: "an acls section (legacy — grants-first, HS-07)"})
		}
	}
	rules := func(key string) []map[string]any {
		var rs []map[string]any
		if arr, ok := top[key].([]any); ok {
			for _, e := range arr {
				if m, ok := e.(map[string]any); ok {
					rs = append(rs, m)
				}
			}
		}
		return rs
	}
	strs := func(v any) []string {
		var ss []string
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					ss = append(ss, s)
				}
			}
		case string:
			ss = append(ss, t)
		}
		return ss
	}
	var tokens []string // every string where a user token may stand
	for _, key := range []string{"grants", "acls"} {
		for _, r := range rules(key) {
			for _, s := range strs(r["src"]) {
				if s == "autogroup:danger-all" {
					out = append(out, Finding{Rule: RuleL5, Severity: SeverityError, Code: "danger_all_source", Path: key,
						Message: "autogroup:danger-all as a source"})
				}
				tokens = append(tokens, s)
			}
			tokens = append(tokens, strs(r["dst"])...)
		}
	}
	for _, r := range rules("tests") { // generated (P5-T01): a source or a destination may name a user
		tokens = append(tokens, strs(r["src"])...)
		tokens = append(tokens, strs(r["accept"])...)
		tokens = append(tokens, strs(r["deny"])...)
	}
	for _, r := range rules("ssh") {
		if a, _ := r["action"].(string); a == SSHCheck {
			out = append(out, Finding{Rule: RuleL10, Severity: SeverityError, Code: "ssh_check", Path: "ssh",
				Message: "SSH check mode is not supported (V-26 — post-MVP)"})
		}
		tokens = append(tokens, strs(r["src"])...)
		tokens = append(tokens, strs(r["dst"])...)
	}
	for _, key := range []string{"groups", "tagOwners"} {
		m, _ := top[key].(map[string]any)
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			owners := strs(m[n])
			if key == "tagOwners" && len(owners) > 0 {
				out = append(out, Finding{Rule: RuleL12, Severity: SeverityError, Code: "tag_owners", Path: "tagOwners." + n,
					Message: "a tag with owners lets a user self-tag with --advertise-tags (PL-09)"})
			}
			tokens = append(tokens, owners...)
		}
	}
	if aa, ok := top["autoApprovers"].(map[string]any); ok {
		if routes, ok := aa["routes"].(map[string]any); ok {
			for _, v := range routes {
				tokens = append(tokens, strs(v)...)
			}
		}
		tokens = append(tokens, strs(aa["exitNode"])...)
	}
	bad := 0
	for _, t := range tokens {
		if !validUserToken(t) {
			bad++
		}
	}
	if bad > 0 {
		out = append(out, Finding{Rule: RuleL11, Severity: SeverityError, Code: "user_token",
			Message: "user token(s) that are not mg-<membership uuid>@ (Headscale matches x@ on e-mail and name — HS-09)"})
	}
	return out
}

// topLevelKeys are the 11 keys Headscale 0.29 accepts (PL-01 — the same list as headscale.ValidatePolicyDocument).
var topLevelKeys = map[string]bool{
	"groups": true, "hosts": true, "tagOwners": true, "acls": true, "grants": true, "nodeAttrs": true,
	"autoApprovers": true, "ssh": true, "tests": true, "sshTests": true, "randomizeClientPort": true,
}

// hardLint is the part of OutputLint that refuses: the first error as a LintError (nil when none).
func hardLint(applied string) error {
	r := newReport()
	for _, f := range OutputLint(applied) {
		r.add(f)
	}
	if le := r.firstError(); le != nil {
		return le
	}
	return nil
}
