package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Deterministic render of a typed version (§7.2): the PolicySource plus the tables read at render time —
//
//	groups      the groups the source references, each "group:<name>": its members that are not offboarded, rendered
//	            "mg-<membership uuid>@" (never an e-mail — HS-09), sorted;
//	hosts       the network resources the source references, "<name>": "<address>";
//	tagOwners   the whole tag catalog of the tenant, each with an EMPTY owner list (PL-09 — P4-T15);
//	grants      always present, an empty array for deny-all (L1);
//	ssh         always present ([] by default);
//	autoApprovers only when the source has some.
//
// encoding/json writes struct members in declaration order and map keys sorted, so the same source over the same
// tables always renders the same bytes — the string sent, stored (applied_hujson) and compared by the drift check.

// RenderInputs are the tables a render reads (one tenant transaction).
type RenderInputs struct {
	Groups       map[uuid.UUID]RenderGroup
	Memberships  map[uuid.UUID]string // membership id → status
	Tags         map[uuid.UUID]RenderTag
	Catalog      []string // every tag name of the tenant, sorted
	Resources    map[uuid.UUID]RenderResource
	IdentityMode string // TenantSettings.enrollment.identity_mode (portal | headscale_oidc)
	Devices      int64  // devices of the tenant not removed (L8)
}

// RenderGroup is a group and its members that are not offboarded.
type RenderGroup struct {
	Name    string
	Members []uuid.UUID
}

// RenderTag is a catalog tag.
type RenderTag struct {
	Name            string
	PlatformManaged bool
}

// RenderResource is a network resource (its host alias).
type RenderResource struct {
	Name    string
	Address string
}

// Identity modes of TenantSettings.enrollment.identity_mode.
const (
	IdentityModePortal        = "portal"
	IdentityModeHeadscaleOIDC = "headscale_oidc"
)

// loadRenderInputs reads the render inputs of a tenant in q (api or worker tenant role).
func loadRenderInputs(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (*RenderInputs, error) {
	in := &RenderInputs{Groups: map[uuid.UUID]RenderGroup{}, Memberships: map[uuid.UUID]string{},
		Tags: map[uuid.UUID]RenderTag{}, Resources: map[uuid.UUID]RenderResource{}}
	groups, err := q.ListPolicyGroups(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		in.Groups[g.ID] = RenderGroup{Name: g.Name, Members: []uuid.UUID{}}
	}
	members, err := q.ListPolicyGroupMembers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if g, ok := in.Groups[m.GroupID]; ok {
			g.Members = append(g.Members, m.MembershipID)
			in.Groups[m.GroupID] = g
		}
	}
	ms, err := q.ListPolicyMemberships(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		in.Memberships[m.ID] = m.Status
	}
	tags, err := q.ListPolicyTags(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, t := range tags {
		in.Tags[t.ID] = RenderTag{Name: t.Name, PlatformManaged: t.PlatformManaged}
		in.Catalog = append(in.Catalog, t.Name)
	}
	sort.Strings(in.Catalog)
	in.Catalog = slices.Compact(in.Catalog)
	res, err := q.ListPolicyResources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, r := range res {
		in.Resources[r.ID] = RenderResource{Name: r.Name, Address: r.Address}
	}
	st, err := q.GetTenantPolicySettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	in.IdentityMode, in.Devices = st.IdentityMode, st.Devices
	return in, nil
}

// renderedPolicy is the output document (member order = the order written).
type renderedPolicy struct {
	Groups        map[string][]string `json:"groups,omitempty"`
	Hosts         map[string]string   `json:"hosts,omitempty"`
	TagOwners     map[string][]string `json:"tagOwners,omitempty"`
	Grants        []renderedGrant     `json:"grants"`
	SSH           []renderedSSH       `json:"ssh"`
	AutoApprovers *renderedApprovers  `json:"autoApprovers,omitempty"`
}

type renderedGrant struct {
	Src []string                    `json:"src"`
	Dst []string                    `json:"dst"`
	IP  []string                    `json:"ip,omitempty"`
	App map[string][]map[string]any `json:"app,omitempty"`
	Via []string                    `json:"via,omitempty"`
}

type renderedSSH struct {
	Action      string   `json:"action"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Users       []string `json:"users"`
	CheckPeriod string   `json:"checkPeriod,omitempty"`
}

type renderedApprovers struct {
	Routes   map[string][]string `json:"routes,omitempty"`
	ExitNode []string            `json:"exitNode,omitempty"`
}

// renderer resolves principals and collects what they need rendered next to them.
type renderer struct {
	src       PolicySource
	in        *RenderInputs
	rep       *Report
	groups    map[uuid.UUID]bool
	resources map[uuid.UUID]bool
	self      bool
	member    bool
}

// Rendered is a typed version rendered and linted.
type Rendered struct {
	Document Document // Applied/AppliedSHA256 = the output; HuJSON = the output too; ContentSHA256 = the version's
	Report   Report
}

// RenderTyped renders src over in and lints the model and the output (L3–L13, L1/L2 and the decoder guard on the
// output). contentSHA256 is the version's content hash. The Document is set only when the report is not blocking on
// a structural problem of the output; a blocking report still carries the rendered sha256 when there is one.
func RenderTyped(src PolicySource, contentSHA256 string, in *RenderInputs) Rendered {
	rep := newReport()
	r := &renderer{src: src, in: in, rep: &rep, groups: map[uuid.UUID]bool{}, resources: map[uuid.UUID]bool{}}
	out := renderedPolicy{Grants: []renderedGrant{}, SSH: []renderedSSH{}}
	for i, g := range src.Grants {
		p := "grants[" + strconv.Itoa(i) + "]"
		rg := renderedGrant{Src: r.list(p+".src", g.Src, posGrantSrc), Dst: r.list(p+".dst", g.Dst, posGrantDst),
			IP: g.IP, App: g.App, Via: r.list(p+".via", g.Via, posVia)}
		for j, d := range g.Dst {
			if d.Type == PrincipalAutogroup && d.Ref == AutogroupInternet && len(g.Via) == 0 {
				rep.add(Finding{Rule: RuleL7, Severity: SeverityWarning, Code: "internet_without_via",
					Path: p + ".dst[" + strconv.Itoa(j) + "]", RequiresAck: true, Acknowledged: src.acknowledged(RuleL7),
					Message: "autogroup:internet without a via tag (exit node)"})
			}
		}
		out.Grants = append(out.Grants, rg)
	}
	for i, s := range src.SSH {
		p := "ssh[" + strconv.Itoa(i) + "]"
		switch s.Action {
		case SSHCheck:
			rep.add(Finding{Rule: RuleL10, Severity: SeverityError, Code: "ssh_check", Path: p + ".action",
				Message: "SSH check mode is not supported (V-26 — post-MVP)"})
		case SSHAccept:
			rep.add(Finding{Rule: RuleL10, Severity: SeverityWarning, Code: "ssh_accept", Path: p + ".action",
				RequiresAck: true, Acknowledged: src.acknowledged(RuleL10),
				Message: "an SSH accept rule always allows port forwarding and is not recorded (PL-13)"})
		}
		out.SSH = append(out.SSH, renderedSSH{Action: s.Action, Src: r.list(p+".src", s.Src, posSSHSrc),
			Dst: r.list(p+".dst", s.Dst, posSSHDst), Users: s.Users, CheckPeriod: s.CheckPeriod})
	}
	if a := src.AutoApprovers; a != nil && (len(a.Routes) > 0 || len(a.ExitNode) > 0) {
		ra := &renderedApprovers{}
		prefixes := make([]string, 0, len(a.Routes))
		for pf := range a.Routes {
			prefixes = append(prefixes, pf)
		}
		sort.Strings(prefixes)
		for _, pf := range prefixes {
			if ra.Routes == nil {
				ra.Routes = map[string][]string{}
			}
			ra.Routes[pf] = r.approvers("auto_approvers.routes["+pf+"]", a.Routes[pf])
		}
		if len(a.ExitNode) > 0 {
			ra.ExitNode = r.approvers("auto_approvers.exit_node", a.ExitNode)
		}
		out.AutoApprovers = ra
	}
	if r.self && in.Devices >= LargeTenantDevices {
		rep.add(Finding{Rule: RuleL8, Severity: SeverityWarning, Code: "self_large_tenant",
			Message: fmt.Sprintf("autogroup:self in a tenant of %d devices costs on every change (HS-08)", in.Devices)})
	}
	if r.member && in.IdentityMode == IdentityModeHeadscaleOIDC {
		rep.add(Finding{Rule: RuleL13, Severity: SeverityWarning, Code: "member_oidc", RequiresAck: true,
			Acknowledged: src.acknowledged(RuleL13),
			Message:      "autogroup:member in identity mode headscale_oidc includes every user of the IdP"})
	}
	if len(r.groups) > 0 {
		out.Groups = map[string][]string{}
		for id := range r.groups {
			g := in.Groups[id]
			toks := make([]string, 0, len(g.Members))
			for _, m := range g.Members {
				toks = append(toks, userToken(m))
			}
			sort.Strings(toks)
			out.Groups["group:"+g.Name] = slices.Compact(toks)
		}
	}
	if len(r.resources) > 0 {
		out.Hosts = map[string]string{}
		for id := range r.resources {
			res := in.Resources[id]
			out.Hosts[res.Name] = res.Address
		}
	}
	if len(in.Catalog) > 0 {
		out.TagOwners = map[string][]string{}
		for _, t := range in.Catalog {
			out.TagOwners[t] = []string{}
		}
	}
	res := Rendered{Report: rep}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		rep.add(Finding{Rule: RuleL3, Severity: SeverityError, Code: "render_failed", Message: "the policy could not be rendered"})
		rep.finish()
		res.Report = rep
		return res
	}
	text := string(b)
	doc, err := Lint(text)
	if err != nil {
		le, _ := IsLint(err)
		f := Finding{Rule: RuleL3, Severity: SeverityError, Code: "output", Message: "the rendered policy is refused"}
		if le != nil {
			f.Rule, f.Code, f.Message = le.Rule, le.Code(), le.Detail
		}
		rep.add(f)
	} else {
		for _, f := range OutputLint(doc.Applied) {
			rep.add(f)
		}
		doc.ContentSHA256 = contentSHA256
		doc.InputsSHA256 = SHA256Hex("content_sha256=" + contentSHA256 + "\napplied_sha256=" + doc.AppliedSHA256)
		doc.TagOwners = append([]string{}, in.Catalog...)
		rep.RenderedSHA256 = doc.AppliedSHA256
		res.Document = doc
	}
	rep.finish()
	res.Report = rep
	return res
}

// userToken is the only form a user is rendered in (§7.2 (1)).
func userToken(membership uuid.UUID) string { return "mg-" + membership.String() + "@" }

// list renders one list of principals; unresolved references are L6 errors, L4 and L5 are judged here.
func (r *renderer) list(field string, ps []Principal, pos position) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, 0, len(ps))
	for i, p := range ps {
		f := field + "[" + strconv.Itoa(i) + "]"
		s, ok := r.one(f, p)
		if !ok {
			continue
		}
		switch {
		case pos == posGrantDst && p.Type == PrincipalCIDR && (s == "*" || s == "0.0.0.0/0" || s == "::/0"):
			r.rep.add(Finding{Rule: RuleL4, Severity: SeverityError, Code: "wildcard_destination", Path: f,
				RequiresAck: true, OwnerOnly: true, Acknowledged: r.src.acknowledged(RuleL4),
				Message: "\"*\" or a default route as a destination (subnet routes and exit nodes included — PL-08)"})
		case pos == posGrantSrc && p.Type == PrincipalAutogroup && p.Ref == AutogroupDangerAll:
			r.rep.add(Finding{Rule: RuleL5, Severity: SeverityError, Code: "danger_all_source", Path: f,
				Message: "autogroup:danger-all as a source"})
		}
		out = append(out, s)
	}
	return out
}

// approvers renders an autoApprover list: anything but a platform router/exit tag needs a confirmation (L7).
func (r *renderer) approvers(field string, ps []Principal) []string {
	for i, p := range ps {
		t, ok := r.tag(p)
		if p.Type != PrincipalTag || !ok || !t.PlatformManaged {
			r.rep.add(Finding{Rule: RuleL7, Severity: SeverityWarning, Code: "auto_approver_not_platform",
				Path: field + "[" + strconv.Itoa(i) + "]", RequiresAck: true, Acknowledged: r.src.acknowledged(RuleL7),
				Message: "an autoApprover that is not a platform router/exit tag (autoApprovers run again on every set — PL-10)"})
		}
	}
	return r.list(field, ps, posApprover)
}

func (r *renderer) tag(p Principal) (RenderTag, bool) {
	id, err := uuid.Parse(p.Ref)
	if err != nil {
		return RenderTag{}, false
	}
	t, ok := r.in.Tags[id]
	return t, ok
}

// one resolves a principal (L6 when its reference does not exist).
func (r *renderer) one(field string, p Principal) (string, bool) {
	missing := func(what string) (string, bool) {
		r.rep.add(Finding{Rule: RuleL6, Severity: SeverityError, Code: "undeclared_" + what, Path: field + ".ref",
			Message: "the " + what + " referenced does not exist in the tenant"})
		return "", false
	}
	switch p.Type {
	case PrincipalCIDR:
		s, err := canonicalCIDR(p.Ref)
		if err != nil {
			return missing("cidr")
		}
		return s, true
	case PrincipalAutogroup:
		switch p.Ref {
		case AutogroupSelf:
			r.self = true
		case AutogroupMember:
			r.member = true
		}
		return "autogroup:" + p.Ref, true
	}
	id, err := uuid.Parse(p.Ref)
	if err != nil {
		return missing(p.Type)
	}
	switch p.Type {
	case PrincipalUser:
		if st, ok := r.in.Memberships[id]; !ok || st == "offboarded" {
			return missing("user")
		}
		return userToken(id), true
	case PrincipalGroup:
		g, ok := r.in.Groups[id]
		if !ok {
			return missing("group")
		}
		r.groups[id] = true
		return "group:" + g.Name, true
	case PrincipalTag:
		t, ok := r.in.Tags[id]
		if !ok {
			return missing("tag")
		}
		return t.Name, true
	case PrincipalResource:
		res, ok := r.in.Resources[id]
		if !ok {
			return missing("resource")
		}
		r.resources[id] = true
		return res.Name, true
	}
	return missing(p.Type)
}
