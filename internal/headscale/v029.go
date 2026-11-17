package headscale

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// v029 implements Instance for Headscale 0.29.x (REST v1 through grpc-gateway). Field names are the protojson
// lowerCamelCase names, uint64 values are JSON strings and timestamps are RFC 3339 (null when unset) — as
// observed on 0.29.7 (P2-T10).
//
// Parameter placement on 0.29.7 (pinned by the contract tests): ExpireNode `expiry`, DeletePreAuthKey `id`,
// ListNodes `user` and ListUsers `name|email|id` go in the QUERY string (a body is ignored: an expiry sent in a
// body expires the node immediately); AuthRegister/AuthApprove/AuthReject, SetTags, SetApprovedRoutes,
// CreatePreAuthKey, ExpirePreAuthKey, CreateApiKey, ExpireApiKey, SetPolicy and CheckPolicy take a JSON body;
// RenameUser/RenameNode carry the new name in the PATH.
type v029 struct{ c *conn }

var _ Instance = (*v029)(nil)

// ---------------------------------------------------------------------------------------------- wire types

type flexUint64 uint64

func (f *flexUint64) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("uint64 %q: %w", s, err)
	}
	*f = flexUint64(v)
	return nil
}

type wireUser struct {
	ID          flexUint64 `json:"id"`
	Name        string     `json:"name"`
	CreatedAt   *time.Time `json:"createdAt"`
	DisplayName string     `json:"displayName"`
	Email       string     `json:"email"`
	ProviderID  string     `json:"providerId"`
	Provider    string     `json:"provider"`
}

type wirePreAuthKey struct {
	User       *wireUser  `json:"user"`
	ID         flexUint64 `json:"id"`
	Key        string     `json:"key"`
	Reusable   bool       `json:"reusable"`
	Ephemeral  bool       `json:"ephemeral"`
	Used       bool       `json:"used"`
	Expiration *time.Time `json:"expiration"`
	CreatedAt  *time.Time `json:"createdAt"`
	ACLTags    []string   `json:"aclTags"`
}

type wireNode struct {
	ID              flexUint64      `json:"id"`
	MachineKey      string          `json:"machineKey"`
	NodeKey         string          `json:"nodeKey"`
	DiscoKey        string          `json:"discoKey"`
	IPAddresses     []string        `json:"ipAddresses"`
	Name            string          `json:"name"`
	User            *wireUser       `json:"user"`
	LastSeen        *time.Time      `json:"lastSeen"`
	Expiry          *time.Time      `json:"expiry"`
	PreAuthKey      *wirePreAuthKey `json:"preAuthKey"`
	CreatedAt       *time.Time      `json:"createdAt"`
	RegisterMethod  string          `json:"registerMethod"`
	GivenName       string          `json:"givenName"`
	Online          bool            `json:"online"`
	ApprovedRoutes  []string        `json:"approvedRoutes"`
	AvailableRoutes []string        `json:"availableRoutes"`
	SubnetRoutes    []string        `json:"subnetRoutes"`
	Tags            []string        `json:"tags"`
}

type wireAPIKey struct {
	ID         flexUint64 `json:"id"`
	Prefix     string     `json:"prefix"`
	Expiration *time.Time `json:"expiration"`
	CreatedAt  *time.Time `json:"createdAt"`
	LastSeen   *time.Time `json:"lastSeen"`
}

type wirePolicy struct {
	Policy    string     `json:"policy"`
	UpdatedAt *time.Time `json:"updatedAt"`
}

type nodeEnvelope struct {
	Node *wireNode `json:"node"`
}

type userEnvelope struct {
	User *wireUser `json:"user"`
}

// ---------------------------------------------------------------------------------------------- conversion

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// optionalTime maps null and the zero time (0001-01-01T00:00:00Z) to nil.
func optionalTime(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	v := *t
	return &v
}

func (w *wireUser) toUser() *User {
	if w == nil {
		return nil
	}
	return &User{ID: uint64(w.ID), Name: w.Name, DisplayName: w.DisplayName, Email: w.Email, Provider: w.Provider,
		ProviderID: w.ProviderID, CreatedAt: deref(w.CreatedAt)}
}

func registerMethod(s string) RegisterMethod {
	switch s {
	case "REGISTER_METHOD_AUTH_KEY":
		return RegisterMethodAuthKey
	case "REGISTER_METHOD_CLI":
		return RegisterMethodCLI
	case "REGISTER_METHOD_OIDC":
		return RegisterMethodOIDC
	default:
		return RegisterMethodUnspecified
	}
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func (w *wireNode) toNode() (Node, error) {
	if w == nil {
		return Node{}, fmt.Errorf("response has no node")
	}
	n := Node{
		ID: uint64(w.ID), MachineKey: w.MachineKey, NodeKey: w.NodeKey, DiscoKey: w.DiscoKey, Name: w.Name,
		GivenName: w.GivenName, User: w.User.toUser(), Tags: slices.Clone(w.Tags),
		RegisterMethod: registerMethod(w.RegisterMethod), Online: w.Online, LastSeen: optionalTime(w.LastSeen),
		Expiry: optionalTime(w.Expiry), CreatedAt: deref(w.CreatedAt),
	}
	if w.PreAuthKey != nil {
		n.PreAuthKeyID = uint64(w.PreAuthKey.ID)
	}
	for _, s := range w.IPAddresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return Node{}, fmt.Errorf("ip address %q: %w", s, err)
		}
		n.IPAddresses = append(n.IPAddresses, a)
	}
	var err error
	if n.ApprovedRoutes, err = parsePrefixes(w.ApprovedRoutes); err != nil {
		return Node{}, err
	}
	if n.AvailableRoutes, err = parsePrefixes(w.AvailableRoutes); err != nil {
		return Node{}, err
	}
	if n.SubnetRoutes, err = parsePrefixes(w.SubnetRoutes); err != nil {
		return Node{}, err
	}
	return n, nil
}

// Keys are "hskey-auth-<prefix>-<secret>" / "hskey-api-<prefix>-<secret>" where the prefix is exactly 12 characters
// of the URL-safe base64 alphabet — it may itself contain '-' or '_', so it is cut by length, as Headscale does
// (hscontrol/db/preauth_keys.go, api_key.go). List calls return the display form "hskey-…-<prefix>-***".
var (
	preAuthKeyPrefixPattern = regexp.MustCompile(`^hskey-auth-([A-Za-z0-9_-]{12})-`)
	apiKeyDisplayPattern    = regexp.MustCompile(`^hskey-api-([A-Za-z0-9_-]{12})-`)
	apiKeyPrefixInput       = regexp.MustCompile(`^(?:hskey-api-([A-Za-z0-9_-]{12})(?:-\*\*\*)?|([A-Za-z0-9_-]{12}))$`)
)

func (w *wirePreAuthKey) toPreAuthKey(full bool) PreAuthKey {
	k := PreAuthKey{ID: uint64(w.ID), User: w.User.toUser(), Reusable: w.Reusable, Ephemeral: w.Ephemeral,
		Used: w.Used, Expiration: deref(w.Expiration), CreatedAt: deref(w.CreatedAt), Tags: slices.Clone(w.ACLTags)}
	if m := preAuthKeyPrefixPattern.FindStringSubmatch(w.Key); m != nil {
		k.KeyPrefix = m[1]
	}
	if full {
		k.Key = NewSecret(w.Key)
	}
	return k
}

func (w *wireAPIKey) toAPIKey() APIKey {
	k := APIKey{ID: uint64(w.ID), Expiration: deref(w.Expiration), CreatedAt: deref(w.CreatedAt),
		LastSeen: optionalTime(w.LastSeen)}
	if m := apiKeyDisplayPattern.FindStringSubmatch(w.Prefix); m != nil {
		k.Prefix = m[1]
	}
	return k
}

// APIKeyPrefix returns the public prefix of a full API key (the part ListAPIKeys reports and ExpireAPIKey takes).
func APIKeyPrefix(key Secret) string {
	if m := apiKeyDisplayPattern.FindStringSubmatch(key.Reveal()); m != nil {
		return m[1]
	}
	return ""
}

func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func decodeErr(op Op, outcome Outcome, err error) *Error {
	return &Error{Op: op, Kind: KindUpstreamRejected, Code: -1, Outcome: outcome, Upstream: "unexpected response: " + err.Error()}
}

func validID(op Op, id uint64) *Error {
	if id == 0 {
		return invalid(op, "id must be non-zero")
	}
	return nil
}

func nodePath(id uint64, rest string) string {
	return "/api/v1/node/" + strconv.FormatUint(id, 10) + rest
}

// ---------------------------------------------------------------------------------------------- operations

func (c *conn) version(ctx context.Context) (string, error) {
	var out struct {
		Version string `json:"version"`
	}
	// GET /version is outside /api/v1: the edge routes exactly this path; Headscale needs no API key for it.
	if err := c.do(ctx, call{op: OpVersion, method: http.MethodGet, path: "/version", out: &out}); err != nil {
		return "", err
	}
	if out.Version == "" {
		return "", decodeErr(OpVersion, OutcomeNotApplied, fmt.Errorf("no version field"))
	}
	return out.Version, nil
}

func (a *v029) Version(ctx context.Context) (string, error) { return a.c.version(ctx) }

func (a *v029) Health(ctx context.Context) (Health, error) {
	var out struct {
		DatabaseConnectivity bool `json:"databaseConnectivity"`
	}
	if err := a.c.do(ctx, call{op: OpHealth, method: http.MethodGet, path: "/api/v1/health", auth: true, out: &out}); err != nil {
		return Health{}, err
	}
	return Health{DatabaseConnectivity: out.DatabaseConnectivity}, nil
}

func (a *v029) ListUsers(ctx context.Context, f UserFilter) ([]User, error) {
	q := url.Values{}
	set := 0
	if f.ID != 0 {
		q.Set("id", strconv.FormatUint(f.ID, 10))
		set++
	}
	if f.Name != "" {
		if err := ValidateUserName(f.Name); err != nil {
			return nil, invalid(OpListUsers, "name filter: %v", err)
		}
		q.Set("name", f.Name)
		set++
	}
	if f.Email != "" {
		q.Set("email", f.Email)
		set++
	}
	if set > 1 {
		return nil, invalid(OpListUsers, "at most one filter may be set (Headscale applies only one)")
	}
	var out struct {
		Users []wireUser `json:"users"`
	}
	if err := a.c.do(ctx, call{op: OpListUsers, method: http.MethodGet, path: "/api/v1/user", query: q, auth: true, out: &out}); err != nil {
		return nil, err
	}
	users := make([]User, 0, len(out.Users))
	for i := range out.Users {
		users = append(users, *out.Users[i].toUser())
	}
	return users, nil
}

func (a *v029) CreateUser(ctx context.Context, u CreateUser) (User, error) {
	if err := ValidateUserName(u.Name); err != nil {
		return User{}, invalid(OpCreateUser, "%v", err)
	}
	if len(u.DisplayName) > 256 {
		return User{}, invalid(OpCreateUser, "display name longer than 256 bytes")
	}
	body := struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName,omitempty"`
	}{u.Name, u.DisplayName}
	var out userEnvelope
	if err := a.c.do(ctx, call{op: OpCreateUser, method: http.MethodPost, path: "/api/v1/user", body: body, auth: true, out: &out}); err != nil {
		return User{}, err
	}
	if out.User == nil {
		return User{}, decodeErr(OpCreateUser, OutcomeUnknown, fmt.Errorf("no user in response"))
	}
	return *out.User.toUser(), nil
}

func (a *v029) RenameUser(ctx context.Context, id uint64, name string) (User, error) {
	if err := validID(OpRenameUser, id); err != nil {
		return User{}, err
	}
	if err := ValidateUserName(name); err != nil {
		return User{}, invalid(OpRenameUser, "%v", err)
	}
	path := "/api/v1/user/" + strconv.FormatUint(id, 10) + "/rename/" + url.PathEscape(name)
	var out userEnvelope
	if err := a.c.do(ctx, call{op: OpRenameUser, method: http.MethodPost, path: path, auth: true, out: &out}); err != nil {
		return User{}, err
	}
	if out.User == nil {
		return User{}, decodeErr(OpRenameUser, OutcomeUnknown, fmt.Errorf("no user in response"))
	}
	return *out.User.toUser(), nil
}

func (a *v029) DeleteUser(ctx context.Context, id uint64) error {
	if err := validID(OpDeleteUser, id); err != nil {
		return err
	}
	return a.c.do(ctx, call{op: OpDeleteUser, method: http.MethodDelete, path: "/api/v1/user/" + strconv.FormatUint(id, 10), auth: true})
}

func (a *v029) ListNodes(ctx context.Context, user string) ([]Node, error) {
	q := url.Values{}
	if user != "" {
		if err := ValidateUserName(user); err != nil {
			return nil, invalid(OpListNodes, "user filter: %v", err)
		}
		q.Set("user", user)
	}
	var out struct {
		Nodes []wireNode `json:"nodes"`
	}
	if err := a.c.do(ctx, call{op: OpListNodes, method: http.MethodGet, path: "/api/v1/node", query: q, auth: true, out: &out}); err != nil {
		return nil, err
	}
	nodes := make([]Node, 0, len(out.Nodes))
	for i := range out.Nodes {
		n, err := out.Nodes[i].toNode()
		if err != nil {
			return nil, decodeErr(OpListNodes, OutcomeNotApplied, err)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// nodeCall runs a call whose response is {"node": …}.
func (a *v029) nodeCall(ctx context.Context, cl call) (Node, error) {
	var out nodeEnvelope
	cl.out, cl.auth = &out, true
	if err := a.c.do(ctx, cl); err != nil {
		return Node{}, err
	}
	n, err := out.Node.toNode()
	if err != nil {
		return Node{}, decodeErr(cl.op, writeOutcome(cl), err)
	}
	return n, nil
}

func (a *v029) GetNode(ctx context.Context, id uint64) (Node, error) {
	if err := validID(OpGetNode, id); err != nil {
		return Node{}, err
	}
	return a.nodeCall(ctx, call{op: OpGetNode, method: http.MethodGet, path: nodePath(id, "")})
}

func (a *v029) RenameNode(ctx context.Context, id uint64, name string) (Node, error) {
	if err := validID(OpRenameNode, id); err != nil {
		return Node{}, err
	}
	if err := ValidateGivenName(name); err != nil {
		return Node{}, invalid(OpRenameNode, "%v", err)
	}
	return a.nodeCall(ctx, call{op: OpRenameNode, method: http.MethodPost, path: nodePath(id, "/rename/"+url.PathEscape(name))})
}

func (a *v029) SetTags(ctx context.Context, id uint64, tags []string) (Node, error) {
	if err := validID(OpSetTags, id); err != nil {
		return Node{}, err
	}
	if len(tags) == 0 {
		// Headscale refuses an empty list (V-28), and removing every tag would not return a node to its user
		// anyway (HS-10): PUT /devices/{id}/tags with [] is a 422 at the platform, Headscale is not called.
		return Node{}, invalid(OpSetTags, "tag list must not be empty")
	}
	if err := validateTags(tags); err != nil {
		return Node{}, invalid(OpSetTags, "%v", err)
	}
	body := struct {
		Tags []string `json:"tags"`
	}{tags}
	return a.nodeCall(ctx, call{op: OpSetTags, method: http.MethodPost, path: nodePath(id, "/tags"), body: body})
}

func (a *v029) SetApprovedRoutes(ctx context.Context, id uint64, routes []netip.Prefix) (Node, error) {
	if err := validID(OpSetApprovedRoutes, id); err != nil {
		return Node{}, err
	}
	if err := validateRoutes(routes); err != nil {
		return Node{}, invalid(OpSetApprovedRoutes, "%v", err)
	}
	sorted := slices.Clone(routes)
	slices.SortFunc(sorted, netip.Prefix.Compare)
	sorted = slices.Compact(sorted)
	body := struct {
		Routes []string `json:"routes"`
	}{Routes: make([]string, 0, len(sorted))} // [] (not null): the call REPLACES the whole approved set (PL-10)
	for _, p := range sorted {
		body.Routes = append(body.Routes, p.String())
	}
	return a.nodeCall(ctx, call{op: OpSetApprovedRoutes, method: http.MethodPost, path: nodePath(id, "/approve_routes"), body: body})
}

func (a *v029) ExpireNode(ctx context.Context, id uint64, at *time.Time) (Node, error) {
	if err := validID(OpExpireNode, id); err != nil {
		return Node{}, err
	}
	// Always an explicit time, in the QUERY string: the call is then idempotent, and an expiry sent in a body is
	// ignored by 0.29.7, which then expires the node immediately (P2-T10).
	when := a.c.reg.now()
	if at != nil {
		when = *at
	}
	if y := when.UTC().Year(); y < 1 || y > 9999 {
		return Node{}, invalid(OpExpireNode, "expiry must be within the years 1-9999 UTC")
	}
	q := url.Values{"expiry": {timestamp(when)}}
	return a.nodeCall(ctx, call{op: OpExpireNode, method: http.MethodPost, path: nodePath(id, "/expire"), query: q})
}

func (a *v029) DeleteNode(ctx context.Context, id uint64) error {
	if err := validID(OpDeleteNode, id); err != nil {
		return err
	}
	return a.c.do(ctx, call{op: OpDeleteNode, method: http.MethodDelete, path: nodePath(id, ""), auth: true})
}

func (a *v029) CreatePreAuthKey(ctx context.Context, o PreAuthKeyOpts) (PreAuthKey, error) {
	now := a.c.reg.now()
	switch {
	case o.Expiration.IsZero():
		return PreAuthKey{}, invalid(OpCreatePreAuthKey, "expiration is required: without it the key is stored already expired (V-06)")
	case !o.Expiration.After(now):
		return PreAuthKey{}, invalid(OpCreatePreAuthKey, "expiration must be in the future")
	case o.User == 0 && len(o.Tags) == 0:
		return PreAuthKey{}, invalid(OpCreatePreAuthKey, "a key must have an owner or at least one tag")
	}
	if err := validateTags(o.Tags); err != nil {
		return PreAuthKey{}, invalid(OpCreatePreAuthKey, "%v", err)
	}
	body := struct {
		User       string   `json:"user,omitempty"`
		Reusable   bool     `json:"reusable"`
		Ephemeral  bool     `json:"ephemeral"`
		Expiration string   `json:"expiration"`
		ACLTags    []string `json:"aclTags"`
	}{Reusable: o.Reusable, Ephemeral: o.Ephemeral, Expiration: timestamp(o.Expiration), ACLTags: append([]string{}, o.Tags...)}
	if o.User != 0 {
		body.User = strconv.FormatUint(o.User, 10)
	}
	var out struct {
		PreAuthKey *wirePreAuthKey `json:"preAuthKey"`
	}
	if err := a.c.do(ctx, call{op: OpCreatePreAuthKey, method: http.MethodPost, path: "/api/v1/preauthkey", body: body, auth: true, out: &out}); err != nil {
		return PreAuthKey{}, err
	}
	if out.PreAuthKey == nil || out.PreAuthKey.Key == "" {
		return PreAuthKey{}, decodeErr(OpCreatePreAuthKey, OutcomeUnknown, fmt.Errorf("no key in response"))
	}
	return out.PreAuthKey.toPreAuthKey(true), nil
}

func (a *v029) ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	var out struct {
		PreAuthKeys []wirePreAuthKey `json:"preAuthKeys"`
	}
	if err := a.c.do(ctx, call{op: OpListPreAuthKeys, method: http.MethodGet, path: "/api/v1/preauthkey", auth: true, out: &out}); err != nil {
		return nil, err
	}
	keys := make([]PreAuthKey, 0, len(out.PreAuthKeys))
	for i := range out.PreAuthKeys {
		keys = append(keys, out.PreAuthKeys[i].toPreAuthKey(false))
	}
	return keys, nil
}

func (a *v029) ExpirePreAuthKey(ctx context.Context, id uint64) error {
	if err := validID(OpExpirePreAuthKey, id); err != nil {
		return err
	}
	body := struct {
		ID string `json:"id"`
	}{strconv.FormatUint(id, 10)}
	return a.c.do(ctx, call{op: OpExpirePreAuthKey, method: http.MethodPost, path: "/api/v1/preauthkey/expire", body: body, auth: true})
}

func (a *v029) DeletePreAuthKey(ctx context.Context, id uint64) error {
	if err := validID(OpDeletePreAuthKey, id); err != nil {
		return err
	}
	q := url.Values{"id": {strconv.FormatUint(id, 10)}}
	return a.c.do(ctx, call{op: OpDeletePreAuthKey, method: http.MethodDelete, path: "/api/v1/preauthkey", query: q, auth: true})
}

func (a *v029) AuthRegister(ctx context.Context, user, authID string) (Node, error) {
	if err := ValidateUserName(user); err != nil {
		return Node{}, invalid(OpAuthRegister, "user: %v", err)
	}
	if err := ValidateAuthID(authID); err != nil {
		return Node{}, invalid(OpAuthRegister, "%v", err)
	}
	body := struct {
		User   string `json:"user"`
		AuthID string `json:"authId"`
	}{user, authID}
	return a.nodeCall(ctx, call{op: OpAuthRegister, method: http.MethodPost, path: "/api/v1/auth/register", body: body})
}

func (a *v029) authVerdict(ctx context.Context, op Op, path, authID string) error {
	if err := ValidateAuthID(authID); err != nil {
		return invalid(op, "%v", err)
	}
	body := struct {
		AuthID string `json:"authId"`
	}{authID}
	return a.c.do(ctx, call{op: op, method: http.MethodPost, path: path, body: body, auth: true})
}

func (a *v029) AuthApprove(ctx context.Context, authID string) error {
	return a.authVerdict(ctx, OpAuthApprove, "/api/v1/auth/approve", authID)
}

func (a *v029) AuthReject(ctx context.Context, authID string) error {
	return a.authVerdict(ctx, OpAuthReject, "/api/v1/auth/reject", authID)
}

func (a *v029) GetPolicy(ctx context.Context) (Policy, error) {
	var out wirePolicy
	if err := a.c.do(ctx, call{op: OpGetPolicy, method: http.MethodGet, path: "/api/v1/policy", auth: true, out: &out}); err != nil {
		return Policy{}, err
	}
	if strings.TrimSpace(out.Policy) == "" {
		// An empty stored policy: the running policy is unchanged, but the next start loads "no policy" (PL-06).
		return Policy{}, localError(OpGetPolicy, KindNoPolicy, "stored policy is empty: the instance starts allow-all at its next restart")
	}
	return Policy{Data: out.Policy, UpdatedAt: deref(out.UpdatedAt)}, nil
}

func (a *v029) CheckPolicy(ctx context.Context, policy string) error {
	if err := ValidatePolicyDocument(policy); err != nil {
		return invalid(OpCheckPolicy, "%v", err)
	}
	body := struct {
		Policy string `json:"policy"`
	}{policy}
	return a.c.do(ctx, call{op: OpCheckPolicy, method: http.MethodPost, path: "/api/v1/policy/check", body: body, auth: true})
}

// SetPolicy validates locally, runs CheckPolicy (§13.4: always before SetPolicy), then replaces the policy.
// On an error with Outcome == OutcomeUnknown the instance may be ENFORCING the new policy without having stored it
// (V-26): the caller must re-assert the last applied policy; GetPolicy cannot tell (it reads the database copy).
func (a *v029) SetPolicy(ctx context.Context, policy string) (Policy, error) {
	if err := a.CheckPolicy(ctx, policy); err != nil {
		if e, ok := AsError(err); ok {
			e.Outcome = OutcomeNotApplied
		}
		return Policy{}, err
	}
	body := struct {
		Policy string `json:"policy"`
	}{policy}
	var out wirePolicy
	if err := a.c.do(ctx, call{op: OpSetPolicy, method: http.MethodPut, path: "/api/v1/policy", body: body, auth: true, out: &out}); err != nil {
		return Policy{}, err
	}
	if !equalJSON(out.Policy, policy) {
		return Policy{}, &Error{Op: OpSetPolicy, Kind: KindUpstreamRejected, Code: -1, Outcome: OutcomeUnknown,
			Upstream: "stored policy differs from the document sent"}
	}
	return Policy{Data: out.Policy, UpdatedAt: deref(out.UpdatedAt)}, nil
}

func (a *v029) CreateAPIKey(ctx context.Context, expires time.Time) (Secret, error) {
	if expires.IsZero() {
		return Secret{}, invalid(OpCreateAPIKey, "expiration is required: without it the key is stored already expired (V-06)")
	}
	if !expires.After(a.c.reg.now()) {
		return Secret{}, invalid(OpCreateAPIKey, "expiration must be in the future")
	}
	body := struct {
		Expiration string `json:"expiration"`
	}{timestamp(expires)}
	var out struct {
		APIKey string `json:"apiKey"`
	}
	if err := a.c.do(ctx, call{op: OpCreateAPIKey, method: http.MethodPost, path: "/api/v1/apikey", body: body, auth: true, out: &out}); err != nil {
		return Secret{}, err
	}
	if out.APIKey == "" {
		return Secret{}, decodeErr(OpCreateAPIKey, OutcomeUnknown, fmt.Errorf("no key in response"))
	}
	return NewSecret(out.APIKey), nil
}

func (a *v029) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var out struct {
		APIKeys []wireAPIKey `json:"apiKeys"`
	}
	if err := a.c.do(ctx, call{op: OpListAPIKeys, method: http.MethodGet, path: "/api/v1/apikey", auth: true, out: &out}); err != nil {
		return nil, err
	}
	keys := make([]APIKey, 0, len(out.APIKeys))
	for i := range out.APIKeys {
		keys = append(keys, out.APIKeys[i].toAPIKey())
	}
	return keys, nil
}

// ExpireAPIKey accepts the bare 12-character prefix or the display form "hskey-api-<prefix>-***" returned by
// ListAPIKeys — never a full key (a secret has no business being passed around to expire it).
func (a *v029) ExpireAPIKey(ctx context.Context, prefix string) error {
	m := apiKeyPrefixInput.FindStringSubmatch(prefix)
	if m == nil {
		return invalid(OpExpireAPIKey, "prefix must be the 12-character public prefix of an API key")
	}
	bare := m[1]
	if bare == "" {
		bare = m[2]
	}
	body := struct {
		Prefix string `json:"prefix"`
	}{bare}
	return a.c.do(ctx, call{op: OpExpireAPIKey, method: http.MethodPost, path: "/api/v1/apikey/expire", body: body, auth: true})
}
