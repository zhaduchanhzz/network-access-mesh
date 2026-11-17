package devices

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Revocation states and kinds (device_inventory_cache.revocation_*, §6.3; DeviceRevocation of §13.3).
const (
	StateNone    = "none"
	StatePending = "pending"
	StateApplied = "applied"
	StateFailed  = "failed"

	RevokeExpire = "expire"
	RevokeDelete = "delete"
)

// Device is one device of the register as the API shows it (schema Device, §13.3). There is no OS, client version
// or endpoint: the Headscale API does not report them (HS-14, §12.3) and nothing is invented.
type Device struct {
	ID               uuid.UUID
	Name             string // hostname reported by the client
	GivenName        string // DNS label in the tailnet
	IPAddresses      []netip.Addr
	Owner            *Owner // nil for a tagged node or an unknown owner
	Tags             []string
	RegisterMethod   string
	Online           bool
	LastSeen         *time.Time
	Expiry           *time.Time
	AdvertisedRoutes []netip.Prefix
	ApprovedRoutes   []netip.Prefix
	RoutesETag       string
	TagsETag         string
	Revocation       Revocation
	SyncedAt         time.Time
}

// Owner is the membership that owns a user-owned device.
type Owner struct {
	MembershipID uuid.UUID
	DisplayName  string
}

// Revocation is the two-phase revocation state of a device (T-17).
type Revocation struct {
	State       string // StateNone, StatePending, StateApplied, StateFailed
	Kind        string // RevokeExpire, RevokeDelete; "" when never revoked
	RequestedAt *time.Time
	VerifiedAt  *time.Time
}

// Access is what the authorization decision of a request allows on the inventory (§8.4 invariant 3b, §8.8). An
// own-only caller (grant of scope own: the End User) sees and acts on its own untagged devices only; anything else
// is not_found — the same answer as for a device of another tenant. The rule is the one of authz.Decision.CheckOwner,
// applied here because the check needs the device row (internal/devices may not import authz — §13.6).
type Access struct {
	OwnOnly      bool
	MembershipID uuid.UUID // the caller's membership in the tenant
	IdentityID   uuid.UUID // the caller (requested_by of the jobs it starts); uuid.Nil for the system
}

// owns reports whether the access covers the device.
func (a Access) owns(r sqlcdb.DeviceInventoryCache) bool {
	if !a.OwnOnly {
		return true
	}
	return a.MembershipID != uuid.Nil && r.OwnerMembershipID != nil && *r.OwnerMembershipID == a.MembershipID &&
		len(r.Tags) == 0
}

func (a Access) requestedBy() *uuid.UUID {
	if a.IdentityID == uuid.Nil {
		return nil
	}
	id := a.IdentityID
	return &id
}

// deviceOf maps a register row to its API view.
func deviceOf(r sqlcdb.DeviceInventoryCache, ownerDisplay string) Device {
	d := Device{
		ID: r.ID, Name: deref(r.Name), GivenName: deref(r.GivenName), IPAddresses: slices.Clone(r.IpAddresses),
		Tags: slices.Clone(r.Tags), RegisterMethod: deref(r.RegisterMethod), Online: r.Online, LastSeen: r.LastSeen,
		Expiry: r.Expiry, AdvertisedRoutes: slices.Clone(r.AvailableRoutes), ApprovedRoutes: slices.Clone(r.ApprovedRoutes),
		Revocation: Revocation{State: r.RevocationState, Kind: deref(r.RevocationKind), RequestedAt: r.RevocationRequestedAt,
			VerifiedAt: r.RevocationVerifiedAt},
		SyncedAt: r.LastSyncedAt,
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if len(r.Tags) == 0 && r.OwnerMembershipID != nil {
		d.Owner = &Owner{MembershipID: *r.OwnerMembershipID, DisplayName: ownerDisplay}
	}
	d.TagsETag = setETag(r.Tags)
	routes := make([]string, 0, len(r.ApprovedRoutes))
	for _, p := range r.ApprovedRoutes {
		routes = append(routes, p.String())
	}
	d.RoutesETag = setETag(routes)
	return d
}

// setETag is the entity tag of a set (order and duplicates do not matter): a quoted hex prefix of SHA-256.
func setETag(items []string) string {
	s := slices.Clone(items)
	slices.Sort(s)
	s = slices.Compact(s)
	sum := sha256.Sum256([]byte(strings.Join(s, "\n")))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func ptr[T any](v T) *T { return &v }

// ListQuery are the parameters of GET /tenants/{t}/devices (§13.1 explicit filters, cursor pagination).
type ListQuery struct {
	Limit  int        // 1–MaxLimit; 0 ⇒ DefaultLimit
	Cursor string     // next_cursor of the previous page
	Online *bool      // control-plane view at the last sync
	Owner  *uuid.UUID // membership
	Tag    string     // tag:<name>
	Search string     // part of the given name or hostname (1–64 characters)
	Fresh  bool       // run a bounded sync first and answer page 1 (§13.1)
}

// Page is one page of devices.
type Page struct {
	Items      []Device
	NextCursor string // "" on the last page
}

// Pagination bounds (§13.1).
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var tagRE = regexp.MustCompile(`^tag:[a-z][a-z0-9-]{0,49}$`)

// cursor is the position after the last device of a page: (first_seen_at, id), bound to the list it came from.
type cursor struct {
	seen time.Time
	id   uuid.UUID
}

const cursorVersion = 1

// binding ties a cursor to the tenant, the caller's own-only filter and the query filters: a cursor of another list
// is refused instead of silently skipping rows.
func binding(tenant uuid.UUID, a Access, q ListQuery) []byte {
	h := sha256.New()
	h.Write(tenant[:])
	if a.OwnOnly {
		h.Write(a.MembershipID[:])
	}
	if q.Owner != nil {
		h.Write([]byte("owner"))
		h.Write(q.Owner[:])
	}
	if q.Online != nil {
		h.Write([]byte{'o', boolByte(*q.Online)})
	}
	h.Write([]byte("tag\x00" + q.Tag + "\x00q\x00" + q.Search))
	return h.Sum(nil)[:8]
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func encodeCursor(c cursor, bind []byte) string {
	var b bytes.Buffer
	b.WriteByte(cursorVersion)
	_ = binary.Write(&b, binary.BigEndian, c.seen.UnixMicro())
	b.Write(c.id[:])
	b.Write(bind)
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func decodeCursor(s string, bind []byte) (cursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != 1+8+16+8 || raw[0] != cursorVersion || !bytes.Equal(raw[25:], bind) {
		return cursor{}, false
	}
	micros := int64(binary.BigEndian.Uint64(raw[1:9])) //nolint:gosec // round trip of UnixMicro
	id, err := uuid.FromBytes(raw[9:25])
	if err != nil {
		return cursor{}, false
	}
	return cursor{seen: time.UnixMicro(micros).UTC(), id: id}, true
}
