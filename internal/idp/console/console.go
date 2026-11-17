// Package console holds the rules of the Keycloak administration console session (P3-T15, §8.2 (3) "Console quản trị
// Keycloak nằm sau cùng lớp 2P + step-up + giới hạn IP như break-glass, có cảnh báo mỗi lần đăng nhập").
//
// The console of the platform-hosted Keycloak (realm master: /admin/*, /realms/master/*, /resources/*) is served only
// on the admin origin of the edge, behind a forward_auth to the api (GET /internal/edge/idp-console): the edge lets a
// request through only while its caller holds a console session —
//
//   - an executed approval request of action platform.idp.console_session (§8.6 2P: requester ≠ approver, both
//     stepped up, the approver holds platform.idp:console too), requested by the caller themselves;
//   - inside its window: from the approval (decided_at) for the approved duration (5–60 minutes);
//   - from the approved source CIDR (by default the requester's own address, /32 or /128);
//   - and the caller still a platform user holding platform.idp:console, on a live Platform Console session of the admin
//     origin (the gate re-checks both at every request).
//
// The payload of the request (Payload) is what the approver sees and what binds the session. Impersonation through
// the console is refused by the gate whatever the session (IsImpersonation) and raised as a critical security event.
package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// The approval action of a console session (approval_requests.action), its resource and the permission of §8.5 the
// requester and the approver must hold.
const (
	Action       = "platform.idp.console_session"
	ResourceType = "identity"
	Permission   = "platform.idp:console"
)

// Bounds of a console session (§8.2 (3): a time-limited session; P3-T15: at most 60 minutes).
const (
	MinDuration     = 5 * time.Minute
	MaxDuration     = 60 * time.Minute
	DefaultDuration = 30 * time.Minute
	// MinIPv4Bits and MinIPv6Bits bound the source CIDR: one office at most (/24, /56), never "anywhere".
	MinIPv4Bits = 24
	MinIPv6Bits = 56
)

// Gate decision reasons (audit details of a refused console request; never sent to the client).
const (
	ReasonAllowed        = "allowed"
	ReasonNoSession      = "no_console_session"    // no executed approval of this person in the window
	ReasonEnded          = "console_session_ended" // the approved window is over
	ReasonSourceIP       = "source_ip_not_allowed" // an approved session exists, not for this address
	ReasonImpersonation  = "impersonation_refused" // POST …/users/{id}/impersonation — never through the console
	ReasonNoPlatformUser = "not_allowed"           // the caller is not (any more) a platform user holding the permission
)

// Payload is the payload of an approval request of Action: the person whose console session it is (the requester),
// the source CIDR and the duration. Canonical JSON; the approver reviews exactly these values.
type Payload struct {
	IdentityID      uuid.UUID `json:"identity_id"`
	SourceCIDR      string    `json:"source_cidr"`
	DurationMinutes int       `json:"duration_minutes"`
}

// Validate implements approvals.Validator.
func (p Payload) Validate() error {
	if p.IdentityID == uuid.Nil {
		return errors.New("identity_id is required")
	}
	if _, err := ParseCIDR(p.SourceCIDR); err != nil {
		return err
	}
	d := time.Duration(p.DurationMinutes) * time.Minute
	if d < MinDuration || d > MaxDuration {
		return fmt.Errorf("duration_minutes must be %d–%d", int(MinDuration.Minutes()), int(MaxDuration.Minutes()))
	}
	return nil
}

// Duration is the approved duration.
func (p Payload) Duration() time.Duration { return time.Duration(p.DurationMinutes) * time.Minute }

// ParseCIDR parses a source CIDR in canonical form (the network address, no host bits): IPv4 /24–/32, IPv6 /56–/128;
// no unspecified, loopback, link-local or multicast network.
func ParseCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || p.String() != s {
		return netip.Prefix{}, errors.New("source_cidr must be a CIDR in canonical form (e.g. 203.0.113.7/32)")
	}
	if p.Masked() != p {
		return netip.Prefix{}, errors.New("source_cidr must not have host bits set")
	}
	a := p.Addr()
	switch {
	case a.Is4() && p.Bits() < MinIPv4Bits, a.Is6() && p.Bits() < MinIPv6Bits:
		return netip.Prefix{}, fmt.Errorf("source_cidr is too wide (IPv4 /%d or longer, IPv6 /%d or longer)", MinIPv4Bits, MinIPv6Bits)
	case a.Is4In6():
		return netip.Prefix{}, errors.New("source_cidr must be IPv4 or IPv6, not IPv4-mapped")
	case a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast():
		return netip.Prefix{}, errors.New("source_cidr is not a usable source network")
	}
	return p, nil
}

// DefaultCIDR is the source CIDR of a request that names none: the requester's own address (/32 or /128).
func DefaultCIDR(ip netip.Addr) (string, error) {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return "", errors.New("the client address is unknown")
	}
	p := netip.PrefixFrom(ip, ip.BitLen())
	if _, err := ParseCIDR(p.String()); err != nil {
		return "", err
	}
	return p.String(), nil
}

// Grant is one executed console session approval of a person.
type Grant struct {
	ApprovalID uuid.UUID
	Payload    Payload
	ApprovedBy uuid.UUID
	StartsAt   time.Time // the approval (decided_at)
	EndsAt     time.Time // StartsAt + Payload.Duration()
}

// Decision is the gate's answer for one console request.
type Decision struct {
	Allowed bool
	Reason  string
	Grant   *Grant // the session that allowed it (or the closest refused one)
}

// Decide returns whether identity, connecting from ip at now, holds a console session among grants (the executed
// approvals of identity, newest first): one whose payload names identity, whose window contains now and whose CIDR
// contains ip.
func Decide(grants []Grant, identity uuid.UUID, ip netip.Addr, now time.Time) Decision {
	ip = ip.Unmap().WithZone("")
	d := Decision{Reason: ReasonNoSession}
	for i := range grants {
		g := grants[i]
		if g.Payload.IdentityID != identity || g.Payload.Validate() != nil {
			continue
		}
		if now.Before(g.StartsAt) || !now.Before(g.EndsAt) {
			if d.Reason == ReasonNoSession {
				d.Reason, d.Grant = ReasonEnded, &g
			}
			continue
		}
		cidr, _ := ParseCIDR(g.Payload.SourceCIDR)
		if !ip.IsValid() || !cidr.Contains(ip) {
			d.Reason, d.Grant = ReasonSourceIP, &g
			continue
		}
		return Decision{Allowed: true, Reason: ReasonAllowed, Grant: &g}
	}
	return d
}

// impersonationRE matches the Admin API call that impersonates a user (POST /admin/realms/{realm}/users/{id}/
// impersonation) — refused at the console gate and by the edge, disabled at the server (P2-T05).
var impersonationRE = regexp.MustCompile(`(?i)^/admin/realms/[^/?#]+/users/[^/?#]+/impersonation/?(?:[?#].*)?$`)

// IsImpersonation reports whether the original request (X-Forwarded-Method, X-Forwarded-Uri of the edge) impersonates
// a user. The method is not required to be POST: any method on that path is refused.
func IsImpersonation(uri string) bool { return impersonationRE.MatchString(uri) }

// Store reads the console grants (approval_requests, platform pool) — the api's store.
type Store struct{ st *store.Store }

// NewStore returns the reader over st.
func NewStore(st *store.Store) *Store { return &Store{st: st} }

// Grants returns the executed console session approvals of identity decided since now − MaxDuration (newest first,
// at most 20): every session that may still be open.
func (s *Store) Grants(ctx context.Context, identity uuid.UUID, now time.Time) ([]Grant, error) {
	var out []Grant
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListIdPConsoleGrants(ctx, sqlcdb.ListIdPConsoleGrantsParams{Action: Action, IdentityID: identity,
			Since: now.Add(-MaxDuration - time.Minute)})
		if err != nil {
			return err
		}
		for _, r := range rows {
			g, ok := grantOf(r.ID, r.Payload, r.DecidedAt, r.ApprovedByIdentityID)
			if ok {
				out = append(out, g)
			}
		}
		return nil
	})
	return out, err
}

// grantOf builds a Grant from a row; a payload that no longer decodes strictly or validates is no grant.
func grantOf(id uuid.UUID, raw []byte, decided *time.Time, approver *uuid.UUID) (Grant, bool) {
	var p Payload
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if decided == nil || approver == nil || dec.Decode(&p) != nil || p.Validate() != nil {
		return Grant{}, false
	}
	return Grant{ApprovalID: id, Payload: p, ApprovedBy: *approver, StartsAt: *decided, EndsAt: decided.Add(p.Duration())}, true
}

// Session statuses (schema IdpConsoleSessionStatus).
const (
	StatusPending  = "pending"
	StatusActive   = "active"
	StatusEnded    = "ended"
	StatusRejected = "rejected"
	StatusExpired  = "expired"
)

// Session is the view of one approval request of Action (GET /platform/idp-console/sessions).
type Session struct {
	Status   string
	Payload  Payload
	StartsAt *time.Time // the approval, when executed
	EndsAt   *time.Time
}

// SessionOf maps an approval request of Action — its effective status (approvals.Statuses), payload and decision time
// — to the console session it is at now. ok is false for a payload that no longer decodes (never a session).
func SessionOf(approvalStatus string, payload []byte, decidedAt *time.Time, now time.Time) (Session, bool) {
	var p Payload
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil {
		return Session{}, false
	}
	out := Session{Payload: p}
	switch approvalStatus {
	case "pending", "approved":
		out.Status = StatusPending
	case "rejected":
		out.Status = StatusRejected
	case "expired":
		out.Status = StatusExpired
	case "executed":
		if decidedAt == nil || p.Validate() != nil {
			return Session{}, false
		}
		start, end := *decidedAt, decidedAt.Add(p.Duration())
		out.StartsAt, out.EndsAt = &start, &end
		out.Status = StatusEnded
		if !now.Before(start) && now.Before(end) {
			out.Status = StatusActive
		}
	default:
		return Session{}, false
	}
	return out, true
}

// Security events of the console gate (security_events.kind).
const (
	// KindImpersonationAttempt: an impersonation call reached the console gate (critical) — refused whatever the session.
	KindImpersonationAttempt = "idp.console_impersonation_attempt"
	// KindSessionOpened: a console session was approved and opened (medium) — every opening is reviewed.
	KindSessionOpened = "idp.console_session_opened"
)
