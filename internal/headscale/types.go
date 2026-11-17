package headscale

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// Registry is the ONLY way to obtain an Instance (§13.4 rule 1-2): the tenant is identified by its UUID, never by
// an address taken from a request.
type Registry interface {
	ForTenant(ctx context.Context, tenantID uuid.UUID) (Instance, error)
}

// Instance is the stable adapter interface of §13.4; an implementation is bound to a range of Headscale versions.
//
// Deviations from the sketch in §13.4 (recorded in docs/planning/evidence/P2-T09.md): CreateAPIKey returns a Secret
// instead of a string, and PreAuthKey.Key is a Secret, so a credential cannot reach a log line by accident.
type Instance interface {
	Health(ctx context.Context) (Health, error)
	Version(ctx context.Context) (string, error)

	ListUsers(ctx context.Context, f UserFilter) ([]User, error)
	CreateUser(ctx context.Context, u CreateUser) (User, error)
	RenameUser(ctx context.Context, id uint64, name string) (User, error)
	DeleteUser(ctx context.Context, id uint64) error

	ListNodes(ctx context.Context, user string) ([]Node, error)
	GetNode(ctx context.Context, id uint64) (Node, error)
	RenameNode(ctx context.Context, id uint64, name string) (Node, error)
	SetTags(ctx context.Context, id uint64, tags []string) (Node, error)
	SetApprovedRoutes(ctx context.Context, id uint64, routes []netip.Prefix) (Node, error)
	ExpireNode(ctx context.Context, id uint64, at *time.Time) (Node, error)
	DeleteNode(ctx context.Context, id uint64) error

	CreatePreAuthKey(ctx context.Context, o PreAuthKeyOpts) (PreAuthKey, error)
	ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error)
	ExpirePreAuthKey(ctx context.Context, id uint64) error
	DeletePreAuthKey(ctx context.Context, id uint64) error

	AuthRegister(ctx context.Context, user, authID string) (Node, error)
	AuthApprove(ctx context.Context, authID string) error
	AuthReject(ctx context.Context, authID string) error

	GetPolicy(ctx context.Context) (Policy, error)
	CheckPolicy(ctx context.Context, policy string) error
	SetPolicy(ctx context.Context, policy string) (Policy, error)

	CreateAPIKey(ctx context.Context, expires time.Time) (Secret, error)
	ListAPIKeys(ctx context.Context) ([]APIKey, error)
	ExpireAPIKey(ctx context.Context, prefix string) error
}

// Secret holds a credential. Every formatting path (fmt verbs, slog, JSON) prints logx.Redacted; only Reveal
// returns the value.
type Secret struct{ v string }

// NewSecret wraps a credential.
func NewSecret(s string) Secret { return Secret{v: s} }

// Reveal returns the credential; call it only where the value must leave the process (an HTTP header, SecretStore).
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }

func (Secret) String() string               { return logx.Redacted }
func (Secret) GoString() string             { return logx.Redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(logx.Redacted) }
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(logx.Redacted) }
func (Secret) MarshalText() ([]byte, error) { return []byte(logx.Redacted), nil }
func (Secret) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, logx.Redacted) }

// scrub replaces every occurrence of the secret in text (defence in depth for upstream messages).
func (s Secret) scrub(text string) string {
	if s.v == "" {
		return text
	}
	return strings.ReplaceAll(text, s.v, logx.Redacted)
}

// Health is the result of GET /api/v1/health.
type Health struct {
	DatabaseConnectivity bool
}

// User is a Headscale user.
type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Email       string
	Provider    string // "" for users created over the API/CLI, "oidc" for users created by an OIDC login
	ProviderID  string
	CreatedAt   time.Time
}

// TaggedDevicesUser is the pseudo user ListNodes reports as owner of every tagged node (V-28).
const TaggedDevicesUser = "tagged-devices"

// UserFilter selects users; at most one field may be set (Headscale applies only the first non-empty one).
type UserFilter struct {
	ID    uint64
	Name  string
	Email string
}

// CreateUser is the input of Instance.CreateUser. There is deliberately no Email field: user tokens in the policy
// also match e-mail addresses, so a duplicate e-mail could make the policy invalid at the next start (§13.4).
type CreateUser struct {
	Name        string // mg-<membership_uuid>; checked against the ID-08 rules locally (REST does not check)
	DisplayName string
}

// RegisterMethod is how a node registered (values match Device.register_method of the API: authkey, cli, oidc).
type RegisterMethod string

// Register methods reported by Headscale.
const (
	RegisterMethodUnspecified RegisterMethod = "unspecified"
	RegisterMethodAuthKey     RegisterMethod = "authkey"
	RegisterMethodCLI         RegisterMethod = "cli"
	RegisterMethodOIDC        RegisterMethod = "oidc"
)

// Node is a Headscale node.
//
// Two reads disagree on 0.29.7 (V-28, pinned by the contract tests): ListNodes reports tagged nodes as owned by
// TaggedDevicesUser and fills SubnetRoutes (primary + approved exit routes), GetNode reports the creating user and
// leaves SubnetRoutes empty. Device records must be built from ListNodes; GetNode is only a read-back of the field
// just written.
type Node struct {
	ID              uint64
	MachineKey      string
	NodeKey         string
	DiscoKey        string
	IPAddresses     []netip.Addr
	Name            string // hostname reported by the client
	GivenName       string // DNS label used by MagicDNS (RenameNode)
	User            *User
	Tags            []string
	RegisterMethod  RegisterMethod
	Online          bool
	LastSeen        *time.Time
	Expiry          *time.Time // nil: the node key never expires (tagged nodes, node.expiry 0)
	CreatedAt       time.Time
	PreAuthKeyID    uint64 // 0 unless registered with a pre-auth key
	ApprovedRoutes  []netip.Prefix
	AvailableRoutes []netip.Prefix // announced by the client
	SubnetRoutes    []netip.Prefix // see the type comment (V-28)
}

// IsTagged reports whether the node is owned by tags rather than a user (HS-10).
func (n Node) IsTagged() bool { return len(n.Tags) > 0 }

// PreAuthKeyOpts is the input of Instance.CreatePreAuthKey.
type PreAuthKeyOpts struct {
	User       uint64 // owner; 0 = tag-only key (Tags required)
	Reusable   bool
	Ephemeral  bool
	Expiration time.Time // required and in the future: without it Headscale stores a key that is already expired (V-06)
	Tags       []string
}

// PreAuthKey is a Headscale pre-auth key.
type PreAuthKey struct {
	ID         uint64
	User       *User  // nil for tag-only keys
	Key        Secret // the full key — only in the CreatePreAuthKey result, shown once (x-secret-once)
	KeyPrefix  string // public prefix of the key (ListPreAuthKeys returns only a masked form)
	Reusable   bool
	Ephemeral  bool
	Used       bool
	Expiration time.Time
	CreatedAt  time.Time
	Tags       []string
}

// APIKey is a Headscale API key (never the secret part).
type APIKey struct {
	ID         uint64
	Prefix     string // public prefix (12 characters on 0.29.x)
	Expiration time.Time
	CreatedAt  time.Time
	LastSeen   *time.Time
}

// Policy is the stored policy of an instance. On 0.29.7 GetPolicy reads the DATABASE copy, which can differ from
// the policy the instance is enforcing after a failed SetPolicy (V-26).
type Policy struct {
	Data      string
	UpdatedAt time.Time
}

// ExpiryClampSlack absorbs the few milliseconds between the node's created_at and the default expiry Headscale
// computes at registration (now + node.expiry).
const ExpiryClampSlack = time.Minute

// ExpiryClamp applies the rule "Kẹp hạn node" of §13.4 (HS-19, V-21): a user-owned node whose expiry is empty or
// later than registeredAt + nodeExpiry must be expired at exactly registeredAt + nodeExpiry. It returns that time
// and true when ExpireNode must be called; tagged nodes never expire on Headscale and are reviewed separately.
func ExpiryClamp(n Node, registeredAt time.Time, nodeExpiry time.Duration) (time.Time, bool) {
	if n.IsTagged() || nodeExpiry <= 0 {
		return time.Time{}, false
	}
	limit := registeredAt.Add(nodeExpiry)
	if n.Expiry == nil || n.Expiry.After(limit.Add(ExpiryClampSlack)) {
		return limit.UTC(), true
	}
	return time.Time{}, false
}
