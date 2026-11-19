package policies

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/tailscale/hujson"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// HuJSON import/export of the Policies editor (P4-T11, §7.2 "import/export HuJSON dịch email ↔ membership ở Portal").
// The translator runs on the SERVER: it is the only side that knows every name (members' e-mails, groups, tags and the
// network resources, which have no list API before P4-T12), it reuses the parser Headscale itself uses
// (github.com/tailscale/hujson) and the strictness rules of §7.2, and its output is only ever a typed PolicySource —
//
//	import  HuJSON text of an administrator ⇒ PolicySource (principals by id) + findings; never stored, never sent to
//	        Headscale: the editor puts the source in its form and saves it through PATCH /policies/{v} like any edit,
//	        so the version is validated, rendered and reviewed exactly like a form-made one (the text of a user never
//	        reaches Headscale — §7.2);
//	export  PolicySource ⇒ HuJSON text with names (a member by its e-mail when it is unique in the tenant, otherwise
//	        "mg-<membership>@"), deterministic.
//
// The dialect is the "grants", "ssh" and "autoApprovers" part of a Headscale policy. "groups", "hosts" and
// "tagOwners" are rendered from the tenant's tables (§7.2) and refused here (L3) rather than dropped; so are "acls"
// (legacy — use grants), "nodeAttrs" (HS-22), "tests"/"sshTests" (generated at apply — PL-04) and
// "randomizeClientPort". Every name is checked in its exact spelling at every level: a "#"-prefixed member, a member
// repeated case-insensitively or spelled in another case is refused (the decoder of Headscale matches names
// case-insensitively and drops "#" members — V-06); "grants" missing, null or not an array is L1; empty text is L2.
// Acknowledgements are not part of the text: the editor keeps them in its form.

// Finding codes of the translator (PolicyFinding.code) next to the rules of lint.go/lintmodel.go.
const (
	RuleSource = "source" // a structural error of the resulting PolicySource (PolicySource.Check)

	maxImportFindings = 50
	maxImportDepth    = 64
	exportHeader      = "// MeshGuard policy (grants, ssh, autoApprovers). \"groups\", \"hosts\" and \"tagOwners\" are rendered\n" +
		"// from the tenant's groups, network resources and tag catalog when the version is applied.\n"
)

// PrincipalName is the name a principal is written with in HuJSON (PolicyPrincipalName of api/openapi.yaml).
type PrincipalName struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
	Name string `json:"name"`
}

// ImportResult is the outcome of an import (PolicyImport): Source only when Result is passed.
type ImportResult struct {
	Result     string          `json:"result"`
	Source     *PolicySource   `json:"source,omitempty"`
	Errors     []Finding       `json:"errors"`
	Warnings   []Finding       `json:"warnings"`
	Principals []PrincipalName `json:"principals"`
}

// ExportResult is the outcome of an export (PolicyExport).
type ExportResult struct {
	HuJSON     string          `json:"hujson"`
	Warnings   []Finding       `json:"warnings"`
	Principals []PrincipalName `json:"principals"`
}

// CatalogUser is a membership of the tenant as the translator sees it.
type CatalogUser struct {
	ID     uuid.UUID
	Email  string
	Status string
}

// NamedID is a group, tag or network resource and its name ("tag:x" for a tag, the bare name otherwise).
type NamedID struct {
	ID   uuid.UUID
	Name string
}

// NameCatalog resolves names ⇄ ids for one tenant (read in one tenant transaction).
type NameCatalog struct {
	users     map[uuid.UUID]CatalogUser
	emails    map[string][]uuid.UUID // lower-cased e-mail → memberships not offboarded
	offboard  map[string]bool        // lower-cased e-mail of an offboarded membership
	groups    map[uuid.UUID]string
	groupIDs  map[string][]uuid.UUID
	tags      map[uuid.UUID]string
	tagIDs    map[string][]uuid.UUID
	resources map[uuid.UUID]string
	resIDs    map[string][]uuid.UUID
}

// NewNameCatalog builds a catalog from the tenant's memberships, groups, tags and network resources.
func NewNameCatalog(users []CatalogUser, groups, tags, resources []NamedID) *NameCatalog {
	c := &NameCatalog{users: map[uuid.UUID]CatalogUser{}, emails: map[string][]uuid.UUID{}, offboard: map[string]bool{},
		groups: map[uuid.UUID]string{}, groupIDs: map[string][]uuid.UUID{}, tags: map[uuid.UUID]string{},
		tagIDs: map[string][]uuid.UUID{}, resources: map[uuid.UUID]string{}, resIDs: map[string][]uuid.UUID{}}
	for _, u := range users {
		c.users[u.ID] = u
		e := strings.ToLower(strings.TrimSpace(u.Email))
		switch {
		case e == "":
		case u.Status == "offboarded":
			c.offboard[e] = true
		default:
			c.emails[e] = append(c.emails[e], u.ID)
		}
	}
	index := func(byID map[uuid.UUID]string, byName map[string][]uuid.UUID, items []NamedID) {
		for _, it := range items {
			byID[it.ID] = it.Name
			byName[it.Name] = append(byName[it.Name], it.ID)
		}
	}
	index(c.groups, c.groupIDs, groups)
	index(c.tags, c.tagIDs, tags)
	index(c.resources, c.resIDs, resources)
	return c
}

// loadNameCatalog reads the catalog of a tenant in q (pool of the api, tenant transaction).
func loadNameCatalog(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (*NameCatalog, error) {
	var users []CatalogUser
	var afterAt *time.Time
	var afterID *uuid.UUID
	for {
		rows, err := q.ListTenantMembersPage(ctx, sqlcdb.ListTenantMembersPageParams{TenantID: tenantID,
			AfterCreatedAt: afterAt, AfterID: afterID, RowLimit: 1000})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			u := CatalogUser{ID: r.ID, Status: r.Status}
			if r.Email != nil {
				u.Email = *r.Email
			}
			users = append(users, u)
		}
		if len(rows) < 1000 {
			break
		}
		last := rows[len(rows)-1]
		afterAt, afterID = &last.CreatedAt, &last.ID
	}
	gs, err := q.ListPolicyGroups(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	groups := make([]NamedID, 0, len(gs))
	for _, g := range gs {
		groups = append(groups, NamedID{ID: g.ID, Name: g.Name})
	}
	ts, err := q.ListPolicyTags(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	tags := make([]NamedID, 0, len(ts))
	for _, t := range ts {
		tags = append(tags, NamedID{ID: t.ID, Name: t.Name})
	}
	rs, err := q.ListPolicyResources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	resources := make([]NamedID, 0, len(rs))
	for _, r := range rs {
		resources = append(resources, NamedID{ID: r.ID, Name: r.Name})
	}
	return NewNameCatalog(users, groups, tags, resources), nil
}

// ---------------------------------------------------------------------------------------------------- export

// token is the HuJSON name of a principal; ok is false when its reference does not resolve (a placeholder that never
// resolves on import is written instead — the administrator fixes it).
func (c *NameCatalog) token(p Principal) (string, bool) {
	switch p.Type {
	case PrincipalAutogroup:
		return "autogroup:" + p.Ref, true
	case PrincipalCIDR:
		if s, err := canonicalCIDR(p.Ref); err == nil {
			return s, true
		}
		return p.Ref, false
	}
	id, err := uuid.Parse(p.Ref)
	if err != nil {
		return "?" + p.Ref, false
	}
	switch p.Type {
	case PrincipalUser:
		u, ok := c.users[id]
		if !ok || u.Status == "offboarded" {
			return userToken(id), false
		}
		if e := strings.ToLower(strings.TrimSpace(u.Email)); e != "" && len(c.emails[e]) == 1 && !c.offboard[e] {
			return strings.TrimSpace(u.Email), true
		}
		return userToken(id), true
	case PrincipalGroup:
		if n, ok := c.groups[id]; ok {
			return "group:" + n, true
		}
		return "group:?" + p.Ref, false
	case PrincipalTag:
		if n, ok := c.tags[id]; ok {
			return n, true
		}
		return "tag:?" + p.Ref, false
	case PrincipalResource:
		if n, ok := c.resources[id]; ok {
			return n, true
		}
		return "?" + p.Ref, false
	}
	return "?" + p.Ref, false
}

type exportGrant struct {
	Src []string                    `json:"src"`
	Dst []string                    `json:"dst"`
	IP  []string                    `json:"ip,omitempty"`
	App map[string][]map[string]any `json:"app,omitempty"`
	Via []string                    `json:"via,omitempty"`
}

type exportSSH struct {
	Action      string   `json:"action"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Users       []string `json:"users"`
	CheckPeriod string   `json:"checkPeriod,omitempty"`
}

type exportApprovers struct {
	Routes   map[string][]string `json:"routes,omitempty"`
	ExitNode []string            `json:"exitNode,omitempty"`
}

type exportDoc struct {
	Grants        []exportGrant    `json:"grants"`
	SSH           []exportSSH      `json:"ssh,omitempty"`
	AutoApprovers *exportApprovers `json:"autoApprovers,omitempty"`
}

// namer writes principals and remembers their names and the unresolved ones.
type namer struct {
	c        *NameCatalog
	names    map[[2]string]string
	warnings []Finding
}

func (n *namer) list(path string, ps []Principal) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, 0, len(ps))
	for i, p := range ps {
		tok, ok := n.c.token(p)
		if !ok {
			n.warnings = append(n.warnings, Finding{Rule: RuleL6, Severity: SeverityWarning, Code: "unresolved_reference",
				Path: path + "[" + strconv.Itoa(i) + "]", Message: "the " + p.Type + " referenced does not exist in the tenant"})
		}
		n.names[[2]string{p.Type, p.Ref}] = tok
		out = append(out, tok)
	}
	return out
}

func (n *namer) principals() []PrincipalName {
	out := make([]PrincipalName, 0, len(n.names))
	for k, v := range n.names {
		out = append(out, PrincipalName{Type: k[0], Ref: k[1], Name: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

// name writes src with names (export) — the same function names the principals of an import.
func (n *namer) document(src PolicySource) exportDoc {
	doc := exportDoc{Grants: []exportGrant{}}
	for i, g := range src.Grants {
		p := "grants[" + strconv.Itoa(i) + "]"
		doc.Grants = append(doc.Grants, exportGrant{Src: n.list(p+".src", g.Src), Dst: n.list(p+".dst", g.Dst), IP: g.IP,
			App: g.App, Via: n.list(p+".via", g.Via)})
	}
	for i, r := range src.SSH {
		p := "ssh[" + strconv.Itoa(i) + "]"
		users := r.Users
		if users == nil {
			users = []string{}
		}
		doc.SSH = append(doc.SSH, exportSSH{Action: r.Action, Src: n.list(p+".src", r.Src), Dst: n.list(p+".dst", r.Dst),
			Users: users, CheckPeriod: r.CheckPeriod})
	}
	if a := src.AutoApprovers; a != nil && (len(a.Routes) > 0 || len(a.ExitNode) > 0) {
		ea := &exportApprovers{}
		prefixes := make([]string, 0, len(a.Routes))
		for pf := range a.Routes {
			prefixes = append(prefixes, pf)
		}
		sort.Strings(prefixes)
		for _, pf := range prefixes {
			if ea.Routes == nil {
				ea.Routes = map[string][]string{}
			}
			ea.Routes[pf] = n.list("auto_approvers.routes["+pf+"]", a.Routes[pf])
		}
		ea.ExitNode = n.list("auto_approvers.exit_node", a.ExitNode)
		doc.AutoApprovers = ea
	}
	return doc
}

// ExportHuJSON writes src as HuJSON with names (deterministic: same source + same catalog ⇒ same text).
func ExportHuJSON(src PolicySource, c *NameCatalog) (ExportResult, error) {
	n := &namer{c: c, names: map[[2]string]string{}}
	doc := n.document(src)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return ExportResult{}, err
	}
	warnings := n.warnings
	if warnings == nil {
		warnings = []Finding{}
	}
	return ExportResult{HuJSON: exportHeader + b.String(), Warnings: warnings, Principals: n.principals()}, nil
}

// ---------------------------------------------------------------------------------------------------- import

// jval is a JSON value with its members in document order (duplicates kept) and its line.
type jval struct {
	kind    byte // '{', '[', 's' string, 'n' number, 'b' bool, 'z' null
	str     string
	num     json.Number
	boolean bool
	members []jmember
	items   []*jval
	line    int
}

type jmember struct {
	name string
	line int
	val  *jval
}

type jparser struct {
	dec   *json.Decoder
	lines []int // byte offsets of the line starts
}

func (p *jparser) lineAt(off int64) int {
	return sort.Search(len(p.lines), func(i int) bool { return int64(p.lines[i]) > off })
}

func (p *jparser) value(depth int) (*jval, error) {
	if depth > maxImportDepth {
		return nil, errors.New("the document is nested too deeply")
	}
	tok, err := p.dec.Token()
	if err != nil {
		return nil, err
	}
	v := &jval{line: p.lineAt(p.dec.InputOffset() - 1)}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			v.kind = '{'
			for p.dec.More() {
				kt, err := p.dec.Token()
				if err != nil {
					return nil, err
				}
				name, _ := kt.(string)
				line := p.lineAt(p.dec.InputOffset() - 1)
				mv, err := p.value(depth + 1)
				if err != nil {
					return nil, err
				}
				v.members = append(v.members, jmember{name: name, line: line, val: mv})
			}
		case '[':
			v.kind = '['
			for p.dec.More() {
				iv, err := p.value(depth + 1)
				if err != nil {
					return nil, err
				}
				v.items = append(v.items, iv)
			}
		default:
			return nil, errors.New("unexpected delimiter")
		}
		if _, err := p.dec.Token(); err != nil { // the closing delimiter
			return nil, err
		}
	case string:
		v.kind, v.str = 's', t
	case json.Number:
		v.kind, v.num = 'n', t
	case bool:
		v.kind, v.boolean = 'b', t
	case nil:
		v.kind = 'z'
	}
	return v, nil
}

// generic is v as encoding/json would decode it with UseNumber (members in a map: callers checked duplicates).
func (v *jval) generic() any {
	switch v.kind {
	case '{':
		m := make(map[string]any, len(v.members))
		for _, mb := range v.members {
			m[mb.name] = mb.val.generic()
		}
		return m
	case '[':
		a := make([]any, 0, len(v.items))
		for _, it := range v.items {
			a = append(a, it.generic())
		}
		return a
	case 's':
		return v.str
	case 'n':
		return v.num
	case 'b':
		return v.boolean
	}
	return nil
}

var (
	mgUserRE = regexp.MustCompile(`^mg-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})@$`)
	// importTopKeys are the Headscale top-level keys (PL-01) — only the first three belong to the model.
	importTopKeys = []string{"grants", "ssh", "autoApprovers", "groups", "hosts", "tagOwners", "acls", "nodeAttrs",
		"tests", "sshTests", "randomizeClientPort"}
	knownAutogroups = []string{AutogroupMember, AutogroupTagged, AutogroupSelf, AutogroupInternet, AutogroupDangerAll}
)

type importer struct {
	c     *NameCatalog
	errs  []Finding
	warns []Finding
}

func (im *importer) fail(rule, code, path string, line int, msg string) {
	if len(im.errs) >= maxImportFindings {
		return
	}
	im.errs = append(im.errs, Finding{Rule: rule, Severity: SeverityError, Code: code, Path: path, Line: line, Message: msg})
}

// members checks the member names of an object against its allowed names (exact spelling) and returns the values;
// a null value is refused too (V-06: null hides a rule).
func (im *importer) members(v *jval, path string, allowed []string) map[string]*jval {
	out := map[string]*jval{}
	seen := map[string]bool{}
	for _, m := range v.members {
		where := joinPath(path, m.name)
		folded := strings.ToLower(m.name)
		switch {
		case strings.HasPrefix(m.name, "#"):
			im.fail(RuleDecoderGuard, "comment_key", where, m.line,
				"a member whose name starts with \"#\" is silently ignored by Headscale (V-06)")
			continue
		case seen[folded]:
			im.fail(RuleDecoderGuard, "duplicate_key", where, m.line,
				"the member is repeated (Headscale compares names case-insensitively)")
			continue
		}
		seen[folded] = true
		if slices.Contains(allowed, m.name) {
			if m.val.kind == 'z' {
				im.fail(RuleDecoderGuard, "null_value", where, m.line, "null is not allowed here (it would hide the rule — V-06)")
				continue
			}
			out[m.name] = m.val
			continue
		}
		if slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, m.name) }) {
			im.fail(RuleDecoderGuard, "misspelled_key", where, m.line,
				"the member must be spelled exactly as documented (Headscale would match it case-insensitively)")
			continue
		}
		im.fail(RuleL3, "unknown_key", where, m.line, "unknown member")
	}
	return out
}

func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func (im *importer) stringList(v *jval, path string) []string {
	if v == nil {
		return nil
	}
	if v.kind != '[' {
		im.fail(RuleSyntax, "not_an_array", path, v.line, "an array of strings is expected")
		return nil
	}
	out := make([]string, 0, len(v.items))
	for i, it := range v.items {
		if it.kind != 's' {
			im.fail(RuleSyntax, "not_a_string", path+"["+strconv.Itoa(i)+"]", it.line, "a string is expected")
			continue
		}
		out = append(out, it.str)
	}
	return out
}

func (im *importer) principals(v *jval, path string) []Principal {
	if v == nil {
		return nil
	}
	if v.kind != '[' {
		im.fail(RuleSyntax, "not_an_array", path, v.line, "an array of principals is expected")
		return nil
	}
	out := make([]Principal, 0, len(v.items))
	for i, it := range v.items {
		where := path + "[" + strconv.Itoa(i) + "]"
		if it.kind != 's' {
			im.fail(RuleSyntax, "not_a_string", where, it.line, "a principal is a string")
			continue
		}
		if p, ok := im.resolve(strings.TrimSpace(it.str), where, it.line); ok {
			out = append(out, p)
		}
	}
	return out
}

// one returns the single id of name in byName (none or several ⇒ false, and how many).
func one(byName map[string][]uuid.UUID, name string) (uuid.UUID, int) {
	ids := byName[name]
	if len(ids) != 1 {
		return uuid.Nil, len(ids)
	}
	return ids[0], 1
}

// resolve turns a HuJSON principal into a typed one (§7.2): "*", an address or a prefix ⇒ cidr; "autogroup:x";
// "group:<name>", "tag:<name>" of the catalog; "mg-<membership>@" or the e-mail of a member ⇒ user; any other name ⇒
// a network resource (host alias). Unresolved ⇒ L6.
func (im *importer) resolve(tok, path string, line int) (Principal, bool) {
	c := im.c
	switch {
	case tok == "":
		im.fail(RuleSyntax, "empty_principal", path, line, "a principal cannot be empty")
	case tok == "*":
		return Principal{Type: PrincipalCIDR, Ref: "*"}, true
	case strings.HasPrefix(tok, "autogroup:"):
		name := strings.TrimPrefix(tok, "autogroup:")
		if slices.Contains(knownAutogroups, name) {
			return Principal{Type: PrincipalAutogroup, Ref: name}, true
		}
		im.fail(RuleSyntax, "unknown_autogroup", path, line, "unknown autogroup")
	case strings.HasPrefix(tok, "group:"):
		if id, n := one(c.groupIDs, strings.TrimPrefix(tok, "group:")); n == 1 {
			return Principal{Type: PrincipalGroup, Ref: id.String()}, true
		}
		im.fail(RuleL6, "undeclared_group", path, line, "no group of the tenant has this name")
	case strings.HasPrefix(tok, "tag:"):
		if id, n := one(c.tagIDs, tok); n == 1 {
			return Principal{Type: PrincipalTag, Ref: id.String()}, true
		}
		im.fail(RuleL6, "undeclared_tag", path, line, "the tag is not in the tenant's tag catalog")
	case mgUserRE.MatchString(tok):
		id := uuid.MustParse(mgUserRE.FindStringSubmatch(tok)[1])
		if u, ok := c.users[id]; ok && u.Status != "offboarded" {
			return Principal{Type: PrincipalUser, Ref: id.String()}, true
		}
		im.fail(RuleL6, "undeclared_user", path, line, "no member of the tenant has this membership (or it is offboarded)")
	case strings.Contains(tok, "@"):
		e := strings.ToLower(tok)
		switch id, n := one(c.emails, e); {
		case n == 1:
			return Principal{Type: PrincipalUser, Ref: id.String()}, true
		case n > 1:
			im.fail(RuleL6, "ambiguous_user", path, line,
				"several members have this e-mail: write the member as mg-<membership id>@")
		case c.offboard[e]:
			im.fail(RuleL6, "undeclared_user", path, line, "the member with this e-mail is offboarded")
		default:
			im.fail(RuleL6, "undeclared_user", path, line, "no member of the tenant has this e-mail")
		}
	default:
		if pf, err := netip.ParsePrefix(tok); err == nil {
			if pf.Masked() != pf {
				im.fail(RuleSyntax, "invalid_cidr", path, line, "the prefix has host bits set")
				return Principal{}, false
			}
			return Principal{Type: PrincipalCIDR, Ref: pf.String()}, true
		}
		if a, err := netip.ParseAddr(tok); err == nil && a.Zone() == "" {
			return Principal{Type: PrincipalCIDR, Ref: a.String()}, true
		}
		switch id, n := one(c.resIDs, tok); {
		case n == 1:
			return Principal{Type: PrincipalResource, Ref: id.String()}, true
		case n > 1:
			im.fail(RuleL6, "ambiguous_resource", path, line, "several network resources have this name")
		default:
			im.fail(RuleL6, "undeclared_resource", path, line, "no network resource of the tenant has this name (host alias)")
		}
	}
	return Principal{}, false
}

func (im *importer) object(v *jval, path string) bool {
	if v.kind != '{' {
		im.fail(RuleSyntax, "not_an_object", path, v.line, "an object is expected")
		return false
	}
	return true
}

func (im *importer) grant(v *jval, path string) Grant {
	var g Grant
	if !im.object(v, path) {
		return g
	}
	m := im.members(v, path, []string{"src", "dst", "ip", "app", "via"})
	g.Src = im.principals(m["src"], path+".src")
	g.Dst = im.principals(m["dst"], path+".dst")
	g.IP = im.stringList(m["ip"], path+".ip")
	g.Via = im.principals(m["via"], path+".via")
	if a := m["app"]; a != nil && im.object(a, path+".app") {
		g.App = map[string][]map[string]any{}
		seen := map[string]bool{}
		for _, cp := range a.members {
			where := path + ".app." + cp.name
			if seen[cp.name] {
				im.fail(RuleDecoderGuard, "duplicate_key", where, cp.line, "the capability is repeated")
				continue
			}
			seen[cp.name] = true
			if cp.val.kind != '[' {
				im.fail(RuleSyntax, "not_an_array", where, cp.line, "an array of objects is expected")
				continue
			}
			objs := make([]map[string]any, 0, len(cp.val.items))
			for i, it := range cp.val.items {
				obj, ok := it.generic().(map[string]any)
				if !ok {
					im.fail(RuleSyntax, "not_an_object", where+"["+strconv.Itoa(i)+"]", it.line, "an object is expected")
					continue
				}
				objs = append(objs, obj)
			}
			g.App[cp.name] = objs
		}
	}
	return g
}

func (im *importer) sshRule(v *jval, path string) SSHRule {
	var r SSHRule
	if !im.object(v, path) {
		return r
	}
	m := im.members(v, path, []string{"action", "src", "dst", "users", "checkPeriod"})
	if a := m["action"]; a != nil {
		if a.kind != 's' {
			im.fail(RuleSyntax, "not_a_string", path+".action", a.line, "a string is expected")
		}
		r.Action = a.str
	}
	r.Src = im.principals(m["src"], path+".src")
	r.Dst = im.principals(m["dst"], path+".dst")
	r.Users = im.stringList(m["users"], path+".users")
	if c := m["checkPeriod"]; c != nil {
		if c.kind != 's' {
			im.fail(RuleSyntax, "not_a_string", path+".checkPeriod", c.line, "a string is expected")
		}
		r.CheckPeriod = c.str
	}
	return r
}

func (im *importer) approvers(v *jval, path string) *AutoApprovers {
	if !im.object(v, path) {
		return nil
	}
	m := im.members(v, path, []string{"routes", "exitNode"})
	a := &AutoApprovers{}
	if rt := m["routes"]; rt != nil && im.object(rt, path+".routes") {
		a.Routes = map[string][]Principal{}
		seen := map[string]bool{}
		for _, mb := range rt.members {
			where := path + ".routes." + mb.name
			pf, err := netip.ParsePrefix(mb.name)
			if err != nil || pf.Masked() != pf {
				im.fail(RuleSyntax, "invalid_prefix", where, mb.line, "a route is a masked IP prefix")
				continue
			}
			if seen[pf.String()] {
				im.fail(RuleDecoderGuard, "duplicate_key", where, mb.line, "the route is repeated")
				continue
			}
			seen[pf.String()] = true
			a.Routes[pf.String()] = im.principals(mb.val, where)
		}
	}
	a.ExitNode = im.principals(m["exitNode"], path+".exitNode")
	return a
}

// sourcePath maps a field of PolicySource.Check (grants[0].src[1].ref) to the HuJSON path (auto_approvers ⇒
// autoApprovers, exit_node ⇒ exitNode, check_period ⇒ checkPeriod).
func sourcePath(field string) string {
	r := strings.NewReplacer("auto_approvers", "autoApprovers", "exit_node", "exitNode", "check_period", "checkPeriod")
	return r.Replace(field)
}

// ImportHuJSON translates the HuJSON text of an administrator into a PolicySource (see the top of this file).
func ImportHuJSON(text string, c *NameCatalog) ImportResult {
	im := &importer{c: c}
	res := ImportResult{Result: ResultFailed, Errors: []Finding{}, Warnings: []Finding{}, Principals: []PrincipalName{}}
	finish := func() ImportResult {
		res.Errors = append(res.Errors, im.errs...)
		res.Warnings = append(res.Warnings, im.warns...)
		return res
	}
	if strings.TrimSpace(text) == "" {
		im.fail(RuleL2, "empty", "", 0, "the policy is empty: Headscale would store it and start allow-all at its next restart (PL-06)")
		return finish()
	}
	switch {
	case len(text) > MaxPolicyBytes:
		im.fail(RuleSyntax, "too_large", "", 0, fmt.Sprintf("the policy is larger than %d bytes", MaxPolicyBytes))
	case !utf8.ValidString(text):
		im.fail(RuleSyntax, "invalid_encoding", "", 0, "the policy is not valid UTF-8")
	case strings.ContainsRune(text, 0):
		im.fail(RuleSyntax, "invalid_encoding", "", 0, "the policy contains a NUL character")
	}
	if len(im.errs) > 0 {
		return finish()
	}
	hv, err := hujson.Parse([]byte(text))
	if err != nil {
		im.fail(RuleSyntax, "invalid_hujson", "", 0, "not valid HuJSON: "+hujsonMessage(err))
		return finish()
	}
	hv.Standardize() // comments and trailing commas become spaces: offsets and lines are kept
	std := hv.Pack()
	lines := []int{0}
	for i, b := range std {
		if b == '\n' {
			lines = append(lines, i+1)
		}
	}
	p := &jparser{dec: json.NewDecoder(bytes.NewReader(std)), lines: lines}
	p.dec.UseNumber()
	top, err := p.value(0)
	if err == nil {
		if _, e := p.dec.Token(); !errors.Is(e, io.EOF) {
			err = errors.New("data after the top-level value")
		}
	}
	if err != nil {
		im.fail(RuleSyntax, "invalid_json", "", 0, "not valid HuJSON: "+hujsonMessage(err))
		return finish()
	}
	if top.kind != '{' {
		im.fail(RuleSyntax, "not_an_object", "", top.line, "the policy must be an object at the top level")
		return finish()
	}
	var grants, ssh, aa *jval
	seen := map[string]bool{}
	grantsSeen := false
	for _, m := range top.members {
		folded := strings.ToLower(m.name)
		switch {
		case strings.HasPrefix(m.name, "#"):
			im.fail(RuleDecoderGuard, "comment_key", m.name, m.line,
				"a top-level member whose name starts with \"#\" is silently ignored by Headscale (V-06)")
			continue
		case seen[folded]:
			im.fail(RuleDecoderGuard, "duplicate_key", m.name, m.line,
				"the member is repeated (Headscale compares names case-insensitively)")
			continue
		}
		seen[folded] = true
		switch m.name {
		case "grants":
			grantsSeen = true
			grants = m.val
		case "ssh":
			ssh = m.val
		case "autoApprovers":
			aa = m.val
		case "groups", "hosts", "tagOwners":
			im.fail(RuleL3, "managed_key", m.name, m.line, "\""+m.name+"\" is rendered from the tenant's tables "+
				"(groups, network resources, tag catalog) — remove it and manage those there")
			continue
		case "acls":
			im.fail(RuleL3, "acls_unsupported", m.name, m.line, "\"acls\" is legacy (L9): write the rules as \"grants\"")
			continue
		case "nodeAttrs":
			im.fail(RuleL3, "node_attrs", m.name, m.line, "\"nodeAttrs\" is refused in the MVP (HS-22)")
			continue
		case "tests", "sshTests":
			im.fail(RuleL3, "tests_generated", m.name, m.line, "tests are generated when a version is applied (PL-04)")
			continue
		case "randomizeClientPort":
			im.fail(RuleL3, "unsupported_key", m.name, m.line, "\"randomizeClientPort\" is not part of a tenant policy")
			continue
		default:
			if slices.ContainsFunc(importTopKeys, func(k string) bool { return strings.EqualFold(k, m.name) }) {
				im.fail(RuleDecoderGuard, "misspelled_key", m.name, m.line,
					"top-level keys must be spelled exactly (Headscale would match \""+m.name+"\" case-insensitively)")
			} else {
				im.fail(RuleL3, "unknown_key", m.name, m.line, "unknown top-level key")
			}
			continue
		}
	}
	src := PolicySource{Grants: []Grant{}, SSH: []SSHRule{}}
	switch {
	case !grantsSeen:
		im.fail(RuleL1, "missing_grants", "grants", 0, "the policy has no \"grants\" member: without it Headscale allows "+
			"all traffic (PL-02); use \"grants\": [] for deny-all")
	case grants.kind == 'z':
		im.fail(RuleL1, "null_grants", "grants", grants.line, "\"grants\": null means allow-all (V-06): use an explicit array")
	case grants.kind != '[':
		im.fail(RuleL1, "grants_not_array", "grants", grants.line, "\"grants\" must be an array")
	default:
		for i, g := range grants.items {
			src.Grants = append(src.Grants, im.grant(g, "grants["+strconv.Itoa(i)+"]"))
		}
	}
	if ssh != nil {
		switch ssh.kind {
		case 'z':
			im.fail(RuleDecoderGuard, "null_value", "ssh", ssh.line, "null is not allowed here (V-06)")
		case '[':
			for i, r := range ssh.items {
				src.SSH = append(src.SSH, im.sshRule(r, "ssh["+strconv.Itoa(i)+"]"))
			}
		default:
			im.fail(RuleSyntax, "not_an_array", "ssh", ssh.line, "\"ssh\" must be an array")
		}
	}
	if aa != nil {
		if aa.kind == 'z' {
			im.fail(RuleDecoderGuard, "null_value", "autoApprovers", aa.line, "null is not allowed here (V-06)")
		} else if a := im.approvers(aa, "autoApprovers"); a != nil && (len(a.Routes) > 0 || len(a.ExitNode) > 0) {
			src.AutoApprovers = a
		}
	}
	if len(im.errs) > 0 {
		return finish()
	}
	if err := src.Check(); err != nil {
		se, ok := AsSourceError(err)
		if !ok {
			im.fail(RuleSource, "invalid", "", 0, "the policy is not a valid source")
		} else {
			im.fail(RuleSource, se.Reason, sourcePath(se.Field), 0, "the policy does not fit the model ("+se.Reason+")")
		}
		return finish()
	}
	src = src.normalized()
	n := &namer{c: c, names: map[[2]string]string{}}
	n.document(src)
	res.Result, res.Source, res.Principals = ResultPassed, &src, n.principals()
	return finish()
}

// ---------------------------------------------------------------------------------------------------- service

// Import is POST /policies/import: the HuJSON of an administrator ⇒ a typed source with the tenant's names resolved
// (nothing stored, nothing sent to Headscale).
func (s *VersionService) Import(ctx context.Context, tenantID uuid.UUID, text string) (ImportResult, error) {
	var cat *NameCatalog
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		cat, err = loadNameCatalog(ctx, q, tenantID)
		return err
	})
	if err != nil {
		return ImportResult{}, err
	}
	return ImportHuJSON(text, cat), nil
}

// Export is POST /policies/export: a typed source (checked like a draft's) ⇒ HuJSON with the tenant's names.
func (s *VersionService) Export(ctx context.Context, tenantID uuid.UUID, source json.RawMessage) (ExportResult, error) {
	src, _, _, err := parseSource(source)
	if err != nil {
		return ExportResult{}, err
	}
	var cat *NameCatalog
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		cat, err = loadNameCatalog(ctx, q, tenantID)
		return err
	})
	if err != nil {
		return ExportResult{}, err
	}
	return ExportHuJSON(src, cat)
}
