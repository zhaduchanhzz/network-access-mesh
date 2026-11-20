package policies

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/tailscale/hujson"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Access evaluation of the applied policy (P5-T08 Connectivity Diagnostics — §9.5, §13.2 "diagnostics"): does the
// policy the tenant's instance holds — policy_applications.applied_hujson of the current application, the very string
// sent to Headscale and read back (T-18) — have a grant that lets a device open a TCP connection to a device or to a
// network resource, on a port or on any port? It answers from the rendered document only (its "groups" and "hosts"
// are part of it), with the Headscale 0.29 semantics of the principals the renderer writes (render.go):
//
//	"*", autogroup:danger-all     every source / destination
//	autogroup:member              an untagged (user-owned) device
//	autogroup:tagged              a tagged device
//	autogroup:self                (destination) an untagged device of the same user as the untagged source
//	autogroup:internet            never a device nor a catalog resource here (exit nodes are not evaluated)
//	tag:<name>                    a device holding the tag
//	group:<name>                  an untagged device whose owner "mg-<membership>@" is a member in "groups"
//	mg-<membership>@              an untagged device of that membership
//	<host alias>, IP, prefix      a device address inside it; a resource whose name is the alias, or whose address
//	                              lies inside the prefix
//
// A grant whose "via" is set applies to subnet routes only: for a resource it needs a router with one of the via tags,
// for a device it does not apply. A grant without "ip" (application capabilities only) opens no connection. A
// principal the evaluator does not understand never matches; it is counted, and a denial that such a principal could
// have turned into an allowance is reported unknown, never denied. This is the control plane's view only: the server
// never observes the path between two devices (direct or relay — §13.2), nor a host firewall behind the destination.

// Access decisions.
const (
	AccessAllowed = "allowed"
	AccessDenied  = "denied"
	AccessUnknown = "unknown"
)

// Reasons of a decision that is not allowed.
const (
	AccessReasonNoGrant        = "no_matching_grant"     // no grant covers source → destination
	AccessReasonPortNotAllowed = "port_not_allowed"      // grants cover the pair, not this TCP port
	AccessReasonNoTCP          = "no_tcp_allowed"        // grants cover the pair, but no TCP port at all
	AccessReasonUnreadable     = "unreadable_policy"     // the applied document does not parse
	AccessReasonUnsupported    = "unsupported_policy"    // legacy "acls" or no "grants" array: not evaluated
	AccessReasonUnresolved     = "unresolved_principals" // a principal not understood could change the answer
	AccessReasonNoPolicy       = "no_applied_policy"     // nothing recorded applied on the live instance
)

// MaxAccessUnresolved bounds the principals listed as not understood.
const MaxAccessUnresolved = 10

// AccessPeer is a device as the control plane knows it.
type AccessPeer struct {
	Owner     uuid.UUID // membership owning an untagged device; uuid.Nil when tagged or unknown
	Tags      []string  // "tag:<name>"
	Addresses []netip.Addr
}

func (p AccessPeer) tagged() bool { return len(p.Tags) > 0 }

// AccessResource is a catalog resource as a destination: its host alias, its address, and the tags of each router
// whose approved subnet routes cover the address (for the grants with "via").
type AccessResource struct {
	Name       string
	Address    netip.Prefix
	RouterTags [][]string
}

// AccessQuery is one question: Src → Dst (a device) or Src → Resource, on TCP Port (0 = any port).
type AccessQuery struct {
	Src      AccessPeer
	Dst      *AccessPeer
	Resource *AccessResource
	Port     int
}

// AccessResult is the answer.
type AccessResult struct {
	Decision   string
	Reason     string   // "" when allowed
	Grants     []int    // indexes in "grants" of the grants covering source → destination (whatever the port)
	Allowed    []string // their "ip" entries, sorted, without duplicates
	Unresolved []string // principals not understood (at most MaxAccessUnresolved)
}

type accessDoc struct {
	Groups map[string][]string `json:"groups"`
	Hosts  map[string]string   `json:"hosts"`
	Grants *[]accessGrant      `json:"grants"`
	ACLs   json.RawMessage     `json:"acls"`
}

type accessGrant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
	Via []string `json:"via"`
}

// evaluator holds one document and the principals it did not understand.
type evaluator struct {
	doc        accessDoc
	unresolved []string
}

func (e *evaluator) unknown(p string) {
	if len(e.unresolved) < MaxAccessUnresolved && !slices.Contains(e.unresolved, p) {
		e.unresolved = append(e.unresolved, p)
	}
}

// EvaluateAccess answers q on the applied policy document (HuJSON or JSON).
func EvaluateAccess(applied []byte, q AccessQuery) AccessResult {
	std, err := hujson.Standardize(bytes.Clone(applied))
	if err != nil {
		return AccessResult{Decision: AccessUnknown, Reason: AccessReasonUnreadable}
	}
	var e evaluator
	if err := json.Unmarshal(std, &e.doc); err != nil {
		return AccessResult{Decision: AccessUnknown, Reason: AccessReasonUnreadable}
	}
	if e.doc.Grants == nil || (len(e.doc.ACLs) > 0 && !bytes.Equal(bytes.TrimSpace(e.doc.ACLs), []byte("null")) &&
		!bytes.Equal(bytes.TrimSpace(e.doc.ACLs), []byte("[]"))) {
		return AccessResult{Decision: AccessUnknown, Reason: AccessReasonUnsupported}
	}
	out := AccessResult{Grants: []int{}, Allowed: []string{}}
	allowed := false
	for i, g := range *e.doc.Grants {
		if len(g.IP) == 0 || !e.grantCovers(g, q) {
			continue
		}
		out.Grants = append(out.Grants, i)
		for _, spec := range g.IP {
			if !slices.Contains(out.Allowed, spec) {
				out.Allowed = append(out.Allowed, spec)
			}
			if portAllowed(spec, q.Port) {
				allowed = true
			}
		}
	}
	slices.Sort(out.Allowed)
	out.Unresolved = e.unresolved
	if out.Unresolved == nil {
		out.Unresolved = []string{}
	}
	switch {
	case allowed:
		out.Decision = AccessAllowed
	case len(out.Unresolved) > 0:
		out.Decision, out.Reason = AccessUnknown, AccessReasonUnresolved
	case len(out.Grants) == 0:
		out.Decision, out.Reason = AccessDenied, AccessReasonNoGrant
	case q.Port > 0:
		out.Decision, out.Reason = AccessDenied, AccessReasonPortNotAllowed
	default:
		out.Decision, out.Reason = AccessDenied, AccessReasonNoTCP
	}
	return out
}

// grantCovers reports whether g covers q's source → destination (ports aside).
func (e *evaluator) grantCovers(g accessGrant, q AccessQuery) bool {
	src := slices.ContainsFunc(g.Src, func(p string) bool { return e.peerMatches(p, q.Src, nil) })
	if !src {
		return false
	}
	switch {
	case q.Dst != nil:
		if len(g.Via) > 0 { // via steers subnet routes and exit traffic, never device-to-device traffic
			return false
		}
		return slices.ContainsFunc(g.Dst, func(p string) bool { return e.peerMatches(p, *q.Dst, &q.Src) })
	case q.Resource != nil:
		if !slices.ContainsFunc(g.Dst, func(p string) bool { return e.resourceMatches(p, *q.Resource) }) {
			return false
		}
		return len(g.Via) == 0 || slices.ContainsFunc(q.Resource.RouterTags, func(tags []string) bool {
			return slices.ContainsFunc(g.Via, func(v string) bool { return slices.Contains(tags, v) })
		})
	}
	return false
}

// peerMatches reports whether principal p designates the device d; src is the source when d is a destination
// (autogroup:self).
func (e *evaluator) peerMatches(p string, d AccessPeer, src *AccessPeer) bool {
	switch {
	case p == "*" || p == "autogroup:danger-all":
		return true
	case p == "autogroup:member":
		return !d.tagged()
	case p == "autogroup:tagged":
		return d.tagged()
	case p == "autogroup:internet":
		return false
	case p == "autogroup:self":
		if src == nil || d.tagged() || src.tagged() {
			return false
		}
		if d.Owner == uuid.Nil || src.Owner == uuid.Nil {
			e.unknown(p)
			return false
		}
		return d.Owner == src.Owner
	case strings.HasPrefix(p, "autogroup:"):
		e.unknown(p)
		return false
	case strings.HasPrefix(p, "tag:"):
		return slices.Contains(d.Tags, p)
	case strings.HasPrefix(p, "group:"):
		members, ok := e.doc.Groups[p]
		if !ok || d.tagged() {
			return false
		}
		return slices.ContainsFunc(members, func(m string) bool { return e.userMatches(m, d) })
	case strings.Contains(p, "@"):
		return !d.tagged() && e.userMatches(p, d)
	}
	if pre, ok := e.prefixOf(p); ok {
		return slices.ContainsFunc(d.Addresses, pre.Contains)
	}
	e.unknown(p)
	return false
}

// userMatches reports whether the user principal u ("mg-<membership>@") owns the untagged device d.
func (e *evaluator) userMatches(u string, d AccessPeer) bool {
	id, ok := membershipOf(u)
	if !ok || d.Owner == uuid.Nil {
		e.unknown(u)
		return false
	}
	return id == d.Owner
}

func membershipOf(u string) (uuid.UUID, bool) {
	rest, ok := strings.CutPrefix(u, "mg-")
	if !ok {
		return uuid.Nil, false
	}
	rest, ok = strings.CutSuffix(rest, "@")
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(rest)
	return id, err == nil
}

// resourceMatches reports whether principal p designates the resource r.
func (e *evaluator) resourceMatches(p string, r AccessResource) bool {
	switch {
	case p == "*" || p == "autogroup:danger-all":
		return true
	case strings.HasPrefix(p, "autogroup:") || strings.HasPrefix(p, "tag:") || strings.HasPrefix(p, "group:") ||
		strings.Contains(p, "@"):
		return false // tailnet devices, not a subnet address (exit nodes / autogroup:internet are not evaluated)
	case p == r.Name && r.Name != "":
		return true
	}
	pre, ok := e.prefixOf(p)
	if !ok {
		e.unknown(p)
		return false
	}
	return r.Address.IsValid() && pre.Bits() <= r.Address.Bits() && pre.Contains(r.Address.Addr())
}

// prefixOf resolves a host alias, an address or a prefix.
func (e *evaluator) prefixOf(p string) (netip.Prefix, bool) {
	if v, ok := e.doc.Hosts[p]; ok {
		p = v
	}
	if a, err := netip.ParseAddr(p); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	if pre, err := netip.ParsePrefix(p); err == nil {
		return pre.Masked(), true
	}
	return netip.Prefix{}, false
}

// portAllowed reports whether the "ip" entry spec lets TCP through to port (0 = to any port).
func portAllowed(spec string, port int) bool {
	proto, ports, found := strings.Cut(spec, ":")
	if !found {
		proto, ports = "", spec
	}
	switch strings.ToLower(proto) {
	case "", "tcp", "6":
	default:
		return false
	}
	if ports == "*" {
		return true
	}
	for _, part := range strings.Split(ports, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if port == 0 || (port >= a && port <= b) {
			return true
		}
	}
	return false
}

// AppliedPolicy is the policy the live instance holds according to the platform's records: its current application
// (applied to Headscale and read back — not "the clients converged", which is not observable, T-18) and the version.
type AppliedPolicy struct {
	Application Application
	Version     int
	Document    string // applied_hujson — the bytes sent and read back
}

// PolicyState is what the diagnostics read of a tenant's policy (P5-T08): the current application of the live
// instance (nil: none recorded), the latest application whatever its state, the desired version.
type PolicyState struct {
	Applied        *AppliedPolicy
	Latest         *Application
	DesiredVersion int // 0: none
}

// State reads the policy state of the tenant on the tenant pool (RLS).
func (s *VersionService) State(ctx context.Context, tenantID uuid.UUID) (PolicyState, error) {
	var out PolicyState
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		if desired != nil {
			r, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *desired})
			if err != nil {
				return err
			}
			out.DesiredVersion = int(r.Version)
		}
		inst, err := q.GetLiveInstanceForTenant(ctx, tenantID)
		switch {
		case errors.Is(err, store.ErrNoRows):
		case err != nil:
			return err
		default:
			cur, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID,
				InstanceID: inst.ID})
			switch {
			case errors.Is(err, store.ErrNoRows):
			case err != nil:
				return err
			default:
				v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: cur.PolicyVersionID})
				if err != nil {
					return err
				}
				out.Applied = &AppliedPolicy{Application: applicationView(cur), Version: int(v.Version), Document: cur.AppliedHujson}
			}
		}
		last, err := q.GetLatestPolicyApplication(ctx, tenantID)
		switch {
		case errors.Is(err, store.ErrNoRows):
		case err != nil:
			return err
		default:
			a := applicationView(last)
			out.Latest = &a
		}
		return nil
	})
	return out, err
}
