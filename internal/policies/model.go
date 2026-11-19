package policies

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// The typed policy model of P4-T10 (§7.2 "Tham chiếu principal có kiểu", §13.3 PolicySource): what an administrator
// writes is a structure whose principals are typed references — a membership, a group, a tag, a network resource by
// its id, an autogroup or an address — never a free string. The renderer (render.go) turns it into the HuJSON sent to
// Headscale; the text of a user never reaches Headscale (§7.2 "Không bao giờ gửi nguyên văn văn bản của người dùng").

// Principal types (PolicyPrincipal.type of api/openapi.yaml).
const (
	PrincipalUser      = "user"      // ref = membership id ⇒ "mg-<membership>@"
	PrincipalGroup     = "group"     // ref = group id ⇒ "group:<name>" (+ "groups" rendered from group_members)
	PrincipalTag       = "tag"       // ref = tag id (tenant_tags) ⇒ "tag:<name>"
	PrincipalResource  = "resource"  // ref = network resource id ⇒ its host alias (+ "hosts")
	PrincipalAutogroup = "autogroup" // ref = member | tagged | self | internet | danger-all ⇒ "autogroup:<ref>"
	PrincipalCIDR      = "cidr"      // ref = "*", an IP address or a prefix ⇒ as is (canonical)
)

// Autogroups the model knows (Headscale 0.29 — §7.2).
const (
	AutogroupMember    = "member"
	AutogroupTagged    = "tagged"
	AutogroupSelf      = "self"
	AutogroupInternet  = "internet"
	AutogroupDangerAll = "danger-all"
)

// SSH actions (PolicySSHRule.action).
const (
	SSHAccept = "accept"
	SSHCheck  = "check"
)

// Bounds of the model (a version is at most MaxPolicyBytes once rendered; these keep the structure itself bounded).
const (
	MaxGrants          = 500
	MaxSSHRules        = 200
	MaxPrincipals      = 100 // per list
	MaxIPs             = 50
	MaxSSHUsers        = 20
	MaxAutoApprovers   = 100 // routes
	MaxAcks            = 13
	MaxAckReason       = 500
	MinAckReason       = 5
	MaxAppCapabilities = 20
	maxSourceBytes     = 512 << 10
)

// PolicySource is the typed content of a policy version (policy_versions.source — §13.3): the grants an administrator
// wrote, the SSH rules (default none), the auto approvers (default none) and the acknowledgements of the lint rules
// that need one (§7.2: L4, L12 — the Owner, with a reason; L7, L10 accept, L13 — a confirmation). "groups", "hosts"
// and "tagOwners" are not part of it: they are rendered from the tables when the version is applied.
type PolicySource struct {
	Grants           []Grant           `json:"grants"`
	SSH              []SSHRule         `json:"ssh"`
	AutoApprovers    *AutoApprovers    `json:"auto_approvers,omitempty"`
	Acknowledgements []Acknowledgement `json:"acknowledgements,omitempty"`
}

// Principal is a typed reference (§7.2).
type Principal struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
}

// Grant is one rule of "grants" (grants-first — §7.2, HS-07).
type Grant struct {
	Src []Principal `json:"src"`
	Dst []Principal `json:"dst"`
	IP  []string    `json:"ip,omitempty"`
	// App are application capabilities (Tailscale grants "app"): capability name → list of JSON objects, re-encoded
	// by encoding/json (keys sorted) — never the caller's bytes.
	App map[string][]map[string]any `json:"app,omitempty"`
	Via []Principal                 `json:"via,omitempty"`
}

// SSHRule is one rule of "ssh" (opt-in — §7.2; L10: accept always allows port forwarding, check is refused).
type SSHRule struct {
	Action      string      `json:"action"`
	Src         []Principal `json:"src"`
	Dst         []Principal `json:"dst"`
	Users       []string    `json:"users"`
	CheckPeriod string      `json:"check_period,omitempty"`
}

// AutoApprovers is "autoApprovers" (not rendered by default — §7.2; L7: only the platform's router/exit tags without
// a confirmation).
type AutoApprovers struct {
	Routes   map[string][]Principal `json:"routes,omitempty"`
	ExitNode []Principal            `json:"exit_node,omitempty"`
}

// Acknowledgement is the explicit confirmation of a lint rule that needs one (§7.2), with its reason.
type Acknowledgement struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// AckRules are the rules an acknowledgement may name; OwnerAckRules need a Tenant Owner (§7.2 "trừ khi Owner xác nhận
// tường minh kèm lý do") — enforced when the version is approved.
var (
	AckRules      = []string{RuleL4, RuleL7, RuleL10, RuleL12, RuleL13}
	OwnerAckRules = []string{RuleL4, RuleL12}
)

// SourceError is a structural error of a PolicySource (422 on Field — a JSON path such as grants[0].src[1].ref).
type SourceError struct {
	Field  string
	Reason string
}

func (e *SourceError) Error() string { return "policies: source " + e.Field + ": " + e.Reason }

// AsSourceError returns the *SourceError inside err.
func AsSourceError(err error) (*SourceError, bool) {
	var e *SourceError
	ok := errors.As(err, &e)
	return e, ok
}

func srcErr(field, reason string) error { return &SourceError{Field: field, Reason: reason} }

var (
	ipRE       = regexp.MustCompile(`^(?:(?:tcp|udp|sctp|icmp|ipv6-icmp|igmp|esp|ah|gre|[0-9]{1,3}):)?(?:\*|[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*)$`)
	sshUserRE  = regexp.MustCompile(`^(?:root|autogroup:nonroot|[a-z_][a-z0-9_.-]{0,31})$`)
	capNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_./-]{0,99}$`)
	durationRE = regexp.MustCompile(`^[1-9][0-9]{0,3}[mhd]$`)
)

// ParseSource decodes a PolicySource strictly: unknown members anywhere ⇒ refused, null lists ⇒ refused (a missing
// "grants" is an empty list only when the member is absent — never null), then checks its structure (Check).
func ParseSource(raw []byte) (PolicySource, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return PolicySource{}, srcErr("source", "required")
	}
	if len(raw) > maxSourceBytes {
		return PolicySource{}, srcErr("source", "too_large")
	}
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return PolicySource{}, srcErr("source", "invalid_encoding")
	}
	if err := rejectNullLists(raw); err != nil {
		return PolicySource{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var s PolicySource
	if err := dec.Decode(&s); err != nil {
		return PolicySource{}, srcErr("source", "invalid_json")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return PolicySource{}, srcErr("source", "trailing_data")
	}
	if err := s.Check(); err != nil {
		return PolicySource{}, err
	}
	return s.normalized(), nil
}

// rejectNullLists refuses "grants": null and "ssh": null at the top level (V-06: null grants mean allow-all upstream;
// the model never carries one — the renderer always emits an array).
func rejectNullLists(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&top); err != nil {
		return srcErr("source", "invalid_json")
	}
	for _, k := range []string{"grants", "ssh"} {
		if v, ok := top[k]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return srcErr(k, "null")
		}
	}
	return nil
}

// normalized returns s with nil lists made empty (the canonical form stored and hashed).
func (s PolicySource) normalized() PolicySource {
	if s.Grants == nil {
		s.Grants = []Grant{}
	}
	if s.SSH == nil {
		s.SSH = []SSHRule{}
	}
	for i := range s.SSH {
		if s.SSH[i].Users == nil {
			s.SSH[i].Users = []string{}
		}
	}
	return s
}

// Canonical returns the canonical JSON of the source (encoding/json: struct order, map keys sorted) and its sha256 —
// policy_versions.source and content_sha256.
func (s PolicySource) Canonical() ([]byte, string, error) {
	b, err := json.Marshal(s.normalized())
	if err != nil {
		return nil, "", err
	}
	return b, SHA256Hex(string(b)), nil
}

// position is where a principal stands; each position accepts its own types (§7.2).
type position int

const (
	posGrantSrc position = iota
	posGrantDst
	posVia
	posSSHSrc
	posSSHDst
	posApprover
)

var positionTypes = map[position][]string{
	posGrantSrc: {PrincipalUser, PrincipalGroup, PrincipalTag, PrincipalResource, PrincipalAutogroup, PrincipalCIDR},
	posGrantDst: {PrincipalUser, PrincipalGroup, PrincipalTag, PrincipalResource, PrincipalAutogroup, PrincipalCIDR},
	posVia:      {PrincipalTag},
	posSSHSrc:   {PrincipalUser, PrincipalGroup, PrincipalTag, PrincipalAutogroup},
	posSSHDst:   {PrincipalUser, PrincipalTag, PrincipalAutogroup},
	posApprover: {PrincipalUser, PrincipalGroup, PrincipalTag},
}

var positionAutogroups = map[position][]string{
	posGrantSrc: {AutogroupMember, AutogroupTagged, AutogroupDangerAll}, // danger-all: refused by L5, not here
	posGrantDst: {AutogroupMember, AutogroupTagged, AutogroupSelf, AutogroupInternet},
	posSSHSrc:   {AutogroupMember, AutogroupTagged},
	posSSHDst:   {AutogroupSelf, AutogroupMember, AutogroupTagged},
}

// Check validates the structure of the source (not its references — L6 needs the tables).
func (s PolicySource) Check() error {
	if len(s.Grants) > MaxGrants {
		return srcErr("grants", "too_many")
	}
	for i, g := range s.Grants {
		p := "grants[" + strconv.Itoa(i) + "]"
		if err := checkPrincipals(p+".src", g.Src, posGrantSrc, true); err != nil {
			return err
		}
		if err := checkPrincipals(p+".dst", g.Dst, posGrantDst, true); err != nil {
			return err
		}
		if err := checkPrincipals(p+".via", g.Via, posVia, false); err != nil {
			return err
		}
		if len(g.IP) == 0 && len(g.App) == 0 {
			return srcErr(p+".ip", "required")
		}
		if len(g.IP) > MaxIPs {
			return srcErr(p+".ip", "too_many")
		}
		for j, ip := range g.IP {
			if !ipRE.MatchString(ip) {
				return srcErr(p+".ip["+strconv.Itoa(j)+"]", "invalid_ip_proto")
			}
		}
		if len(g.App) > MaxAppCapabilities {
			return srcErr(p+".app", "too_many")
		}
		for name, objs := range g.App {
			if !capNameRE.MatchString(name) {
				return srcErr(p+".app", "invalid_capability")
			}
			if objs == nil {
				return srcErr(p+".app", "null")
			}
		}
	}
	if len(s.SSH) > MaxSSHRules {
		return srcErr("ssh", "too_many")
	}
	for i, r := range s.SSH {
		p := "ssh[" + strconv.Itoa(i) + "]"
		if r.Action != SSHAccept && r.Action != SSHCheck {
			return srcErr(p+".action", "invalid_action")
		}
		if err := checkPrincipals(p+".src", r.Src, posSSHSrc, true); err != nil {
			return err
		}
		if err := checkPrincipals(p+".dst", r.Dst, posSSHDst, true); err != nil {
			return err
		}
		if len(r.Users) == 0 || len(r.Users) > MaxSSHUsers {
			return srcErr(p+".users", "invalid_count")
		}
		for j, u := range r.Users {
			if !sshUserRE.MatchString(u) {
				return srcErr(p+".users["+strconv.Itoa(j)+"]", "invalid_user")
			}
		}
		if r.CheckPeriod != "" && (r.Action != SSHCheck || !durationRE.MatchString(r.CheckPeriod)) {
			return srcErr(p+".check_period", "invalid_check_period")
		}
	}
	if a := s.AutoApprovers; a != nil {
		if len(a.Routes) > MaxAutoApprovers {
			return srcErr("auto_approvers.routes", "too_many")
		}
		for prefix, ps := range a.Routes {
			pf, err := netip.ParsePrefix(prefix)
			if err != nil || pf.Masked() != pf {
				return srcErr("auto_approvers.routes", "invalid_prefix")
			}
			if err := checkPrincipals("auto_approvers.routes["+prefix+"]", ps, posApprover, true); err != nil {
				return err
			}
		}
		if err := checkPrincipals("auto_approvers.exit_node", a.ExitNode, posApprover, false); err != nil {
			return err
		}
	}
	if len(s.Acknowledgements) > MaxAcks {
		return srcErr("acknowledgements", "too_many")
	}
	seen := map[string]bool{}
	for i, a := range s.Acknowledgements {
		p := "acknowledgements[" + strconv.Itoa(i) + "]"
		if !slices.Contains(AckRules, a.Rule) {
			return srcErr(p+".rule", "not_acknowledgeable")
		}
		if seen[a.Rule] {
			return srcErr(p+".rule", "duplicate")
		}
		seen[a.Rule] = true
		r := strings.TrimSpace(a.Reason)
		if n := utf8.RuneCountInString(r); n < MinAckReason || n > MaxAckReason || strings.ContainsRune(r, 0) {
			return srcErr(p+".reason", "invalid_reason")
		}
	}
	return nil
}

// checkPrincipals checks one list of principals of a position.
func checkPrincipals(field string, ps []Principal, pos position, required bool) error {
	if len(ps) == 0 {
		if required {
			return srcErr(field, "required")
		}
		return nil
	}
	if len(ps) > MaxPrincipals {
		return srcErr(field, "too_many")
	}
	for i, p := range ps {
		f := field + "[" + strconv.Itoa(i) + "]"
		if !slices.Contains(positionTypes[pos], p.Type) {
			return srcErr(f+".type", "type_not_allowed_here")
		}
		switch p.Type {
		case PrincipalUser, PrincipalGroup, PrincipalTag, PrincipalResource:
			if _, err := uuid.Parse(p.Ref); err != nil || len(p.Ref) != 36 {
				return srcErr(f+".ref", "invalid_id")
			}
		case PrincipalAutogroup:
			if !slices.Contains(positionAutogroups[pos], p.Ref) {
				return srcErr(f+".ref", "autogroup_not_allowed_here")
			}
		case PrincipalCIDR:
			if _, err := canonicalCIDR(p.Ref); err != nil {
				return srcErr(f+".ref", "invalid_cidr")
			}
		}
	}
	return nil
}

// canonicalCIDR is the rendered form of a cidr principal: "*", an address, or a masked prefix.
func canonicalCIDR(ref string) (string, error) {
	if ref == "*" {
		return ref, nil
	}
	if a, err := netip.ParseAddr(ref); err == nil && a.Zone() == "" {
		return a.String(), nil
	}
	p, err := netip.ParsePrefix(ref)
	if err != nil {
		return "", err
	}
	if p.Masked() != p {
		return "", fmt.Errorf("prefix %s has host bits", ref)
	}
	return p.String(), nil
}

// acknowledged reports whether rule is acknowledged in the source.
func (s PolicySource) acknowledged(rule string) bool {
	for _, a := range s.Acknowledgements {
		if a.Rule == rule {
			return true
		}
	}
	return false
}

// Refs lists the ids of one principal type the source references (sorted, unique) — L6 and the delete checks.
func (s PolicySource) Refs(kind string) []string {
	seen := map[string]bool{}
	add := func(ps []Principal) {
		for _, p := range ps {
			if p.Type == kind {
				seen[p.Ref] = true
			}
		}
	}
	for _, g := range s.Grants {
		add(g.Src)
		add(g.Dst)
		add(g.Via)
	}
	for _, r := range s.SSH {
		add(r.Src)
		add(r.Dst)
	}
	if a := s.AutoApprovers; a != nil {
		for _, ps := range a.Routes {
			add(ps)
		}
		add(a.ExitNode)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
