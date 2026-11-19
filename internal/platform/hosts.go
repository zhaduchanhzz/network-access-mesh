package platform

// Host management — GET/POST/PATCH /platform/hosts (P3-T04, §13.2; permissions platform.host:read / :manage, §8.5) and
// the host command `meshguard admin host-set`. Every write runs in ONE platform transaction of the api's pool:
//
//   - validation is the exact mirror of the CHECKs of hosts (migrations 0001 and 0014 — checkConfig), plus the rules
//     the database leaves to code (a host name is a DNS label, a region has no space, run_uid_range holds none of the
//     UIDs/GIDs of the core services — ReservedIDs, the list the agent and placement use): a refused value is a
//     *ValidationError naming the field (422), never a constraint violation (TestHostConfigParity compares both on
//     every case). The two jsonb objects of the API body are read the way the CHECKs read the columns
//     (ParseCapacity, ParsePublicEntry — unknown keys, a missing max_instances, a number with a fraction are refused;
//     TestHostJSONParity);
//   - PATCH locks the host row (FOR UPDATE — the lock placement takes on its candidate hosts before it allocates) and
//     only then counts the host's instances that are not removed: capacity.max_instances below that count, or a change
//     of region or of an allocation range (run_uid_range, tenant_net_pool, stun_port_range) while the count is not 0, is
//     a *HostConflictError (409) that no concurrent allocation can slip past;
//   - optimistic concurrency without a version column: the ETag is a hash of the configuration the operator manages
//     (hostETag) — a heartbeat (last_heartbeat_at) does not change it — and a PATCH must name the ETag it read
//     (If-Match: missing ⇒ ErrPreconditionRequired 428, stale ⇒ ErrPreconditionFailed 412);
//   - POST takes its Idempotency-Key in a transaction of its own first (jobs.BeginIdempotent — a duplicate in flight
//     sees in_progress) and stores the response in the business transaction (jobs.CompleteIdempotent);
//   - every write records platform.host.create / platform.host.update in the business transaction (audit.Record):
//     before/after of every managed field, flat (audit details are flat). Within an API request the actor is the
//     caller (the audit scope of the request); the host command records actor_type system.
//
// Placement (placement.go) only ever chooses hosts with status active: draining and disabled take no new instance.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Audit actions of the host writes (x-audit-action of createPlatformHost / updatePlatformHost).
const (
	ActionHostCreate = "platform.host.create"
	ActionHostUpdate = "platform.host.update"
)

// CreateHostOperation is the operationId whose Idempotency-Key CreateHost stores (§13.1).
const CreateHostOperation = "createPlatformHost"

// DefaultMaxInstances is capacity.max_instances of a host created without one (the DEFAULT of 0014 — P1-T20).
const DefaultMaxInstances = 100

// HostStatuses is the value set of hosts.status (CHECK hosts_status_valid, 0014).
var HostStatuses = []string{HostActive, HostDraining, HostDisabled}

// Public entry modes (hosts.public_entry.mode, 0014).
const (
	EntryDirect     = "direct"
	EntryVPSGateway = "vps_gateway"
)

// Reasons of a *HostConflictError.
const (
	ConflictNameTaken         = "name_taken"          // another host has this name (UNIQUE(name))
	ConflictCapacityBelowLive = "capacity_below_live" // capacity.max_instances < instances not removed
	ConflictAllocationInUse   = "allocation_in_use"   // region / allocation range changed while instances are live
)

var (
	// ErrPreconditionRequired: a host change without the ETag the caller read (428 precondition_required).
	ErrPreconditionRequired = errors.New("platform: the ETag of the host is required (If-Match)")
	// ErrPreconditionFailed: the host changed since the caller read it (412 precondition_failed).
	ErrPreconditionFailed = errors.New("platform: the host changed since it was read")
	// ErrIdempotencyInProgress: the same Idempotency-Key is still being served (409 + Retry-After — *IdempotencyBusyError).
	ErrIdempotencyInProgress = errors.New("platform: a request with this Idempotency-Key is in progress")
	// ErrIdempotencyKeyReuse: the Idempotency-Key was used for another request (422 idempotency_key_reuse).
	ErrIdempotencyKeyReuse = errors.New("platform: Idempotency-Key used for another request")
)

// idempotencyLock bounds how long a POST holds its Idempotency-Key while in progress.
const idempotencyLock = 30 * time.Second

// FieldError is one invalid field of a host write: the field path of the API body, a short code and a message that
// never quotes the submitted value.
type FieldError struct {
	Field   string
	Code    string
	Message string
}

// ValidationError lists the invalid fields of a host write (422 validation_failed): errors.Is(err, ErrInvalid).
type ValidationError struct {
	Fields []FieldError
}

func (e *ValidationError) Error() string {
	names := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		names[i] = f.Field + " (" + f.Code + ")"
	}
	return "platform: invalid host: " + strings.Join(names, ", ")
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *ValidationError) Is(target error) bool { return target == ErrInvalid }

// HostConflictError is a host write the registry refuses (409 conflict): errors.Is(err, ErrConflict).
type HostConflictError struct {
	Reason string   // one of the Conflict* constants
	Fields []string // ConflictAllocationInUse: the fields that may not change
	Live   int      // instances of the host that are not removed
}

func (e *HostConflictError) Error() string {
	switch e.Reason {
	case ConflictNameTaken:
		return "platform: a host with this name is already registered"
	case ConflictCapacityBelowLive:
		return fmt.Sprintf("platform: capacity.max_instances is below the %d instances of the host that are not removed", e.Live)
	}
	return fmt.Sprintf("platform: %s cannot change while the host has %d instances that are not removed",
		strings.Join(e.Fields, ", "), e.Live)
}

// Is makes errors.Is(err, ErrConflict) true.
func (e *HostConflictError) Is(target error) bool { return target == ErrConflict }

// IdempotencyBusyError: the request holding the Idempotency-Key has not finished (errors.Is ErrIdempotencyInProgress).
type IdempotencyBusyError struct {
	RetryAfter time.Duration
}

func (e *IdempotencyBusyError) Error() string { return ErrIdempotencyInProgress.Error() }

// Is makes errors.Is(err, ErrIdempotencyInProgress) true.
func (e *IdempotencyBusyError) Is(target error) bool { return target == ErrIdempotencyInProgress }

// IntRange is an inclusive range of integers as the API carries it — int64, so a bound outside int4 is refused by
// validation instead of being truncated.
type IntRange struct {
	First int64 `json:"first"`
	Last  int64 `json:"last"`
}

func (r IntRange) String() string {
	return strconv.FormatInt(r.First, 10) + "-" + strconv.FormatInt(r.Last, 10)
}

// PublicEntry is hosts.public_entry as written: a nil key is absent from the JSON object (an empty string is a value —
// refused, as the CHECK refuses it).
type PublicEntry struct {
	IPv4 *string `json:"ipv4,omitempty"`
	Mode *string `json:"mode,omitempty"`
}

// HostConfig is the body of POST /platform/hosts. Zero Status ⇒ active, nil MaxInstances ⇒ DefaultMaxInstances,
// nil STUNPortRange ⇒ none (shared STUN — MVP).
type HostConfig struct {
	Name          string
	Region        string
	Status        string
	MaxInstances  *int64
	PublicEntry   PublicEntry
	RunUIDRange   IntRange
	STUNPortRange *IntRange
	TenantNetPool string // IPv4 CIDR in canonical form a.b.c.d/n
}

// HostPatch is the body of PATCH /platform/hosts/{hostId}: nil fields are unchanged; PublicEntry replaces the whole
// object (&PublicEntry{} clears it). The name never changes.
type HostPatch struct {
	Region        *string
	Status        *string
	MaxInstances  *int64
	PublicEntry   *PublicEntry
	RunUIDRange   *IntRange
	STUNPortRange *IntRange
	TenantNetPool *string
}

func (p HostPatch) empty() bool {
	return p.Region == nil && p.Status == nil && p.MaxInstances == nil && p.PublicEntry == nil && p.RunUIDRange == nil &&
		p.STUNPortRange == nil && p.TenantNetPool == nil
}

// Idempotency is the Idempotency-Key of POST /platform/hosts: the caller's identity, the key and the SHA-256 of the
// request (jobs.RequestHash).
type Idempotency struct {
	IdentityID uuid.UUID
	Key        string
	Hash       []byte
}

// SystemActor is a host command (`meshguard admin host-set`): its audit event is actor_type system, with the command
// as actor_display and the request id of the run (admin-<uuid>).
type SystemActor struct {
	Command   string
	RequestID string
}

// HostWrite says who writes a host and under which conditions.
type HostWrite struct {
	// IfMatch is the If-Match value of a PATCH: the ETag the caller read (UpdateHost refuses a change without it).
	IfMatch string
	// Idempotency is the Idempotency-Key of a POST (nil: no key — the host command).
	Idempotency *Idempotency
	// System marks a host command; nil ⇒ the actor of the API request (the audit scope of ctx).
	System *SystemActor
}

// HostUsage is what a host holds at the time of the read (schema HostUsage).
type HostUsage struct {
	LiveInstances int            // instances that are not removed
	ByStatus      map[string]int // the same, by status
	RunUIDsFree   int64          // UIDs of run_uid_range never handed out (UIDs are never reused), reserved IDs aside
	NetSlotsFree  int64          // /29 of tenant_net_pool held by no instance that is not removed
	// STUNPortsFree: ports of stun_port_range held by no instance that is not removed (the live UNIQUE(host_id,
	// stun_port) of 0001); nil when the host has no stun_port_range (shared STUN — MVP). P4-T03 (Hosts screen).
	STUNPortsFree *int64
}

// HostView is a host as GET /platform/hosts shows it (schema Host).
type HostView struct {
	Host
	LastHeartbeatAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Usage           HostUsage
	ETag            string
}

// HostFilter holds the query parameters of GET /platform/hosts.
type HostFilter struct {
	Limit  int
	Cursor string
	Status string // one of HostStatuses
	Region string
}

// HostPage is one page of hosts.
type HostPage struct {
	Items      []HostView
	NextCursor string
}

// ---------------------------------------------------------------- validation (mirror of 0001 + 0014)

// hostConfig is a complete configuration: the managed columns of a hosts row, with absent JSON keys as nil.
type hostConfig struct {
	region       string
	status       string
	maxInstances int64
	ipv4, mode   *string
	uid          IntRange
	stun         *IntRange
	pool         string
}

var (
	// ipv4RE is the pattern of hosts_public_entry_valid (0014): dotted decimal, no leading zero.
	ipv4RE = regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$`)
	// notUnicast are the ranges hosts_public_entry_valid refuses as a public entry.
	notUnicast = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/3")}
)

// Bounds of the CHECKs of 0014.
const (
	minRunUID   = 1000
	maxRunUID   = math.MaxInt32 - 1 // upper(run_uid_range) <= 2147483647 (exclusive bound of the canonical range)
	minSTUNPort = 1024
	maxSTUNPort = 65535
)

// Check validates a POST body after its defaults (the same rules as UpdateHost applies to the patched host). Empty
// result = valid.
func (c HostConfig) Check() []FieldError {
	return checkConfig(&c.Name, c.config(), allCodeRules)
}

// config applies the defaults of a new host.
func (c HostConfig) config() hostConfig {
	out := hostConfig{region: c.Region, status: c.Status, maxInstances: DefaultMaxInstances, ipv4: c.PublicEntry.IPv4,
		mode: c.PublicEntry.Mode, uid: c.RunUIDRange, stun: c.STUNPortRange, pool: c.TenantNetPool}
	if out.status == "" {
		out.status = HostActive
	}
	if c.MaxInstances != nil {
		out.maxInstances = *c.MaxInstances
	}
	return out
}

// codeRules selects the rules the database leaves to code (a region without spaces, no core service ID in
// run_uid_range). A PATCH applies them to the fields it changes only: a host registered before a rule existed is not
// stuck (it can still be drained), while every value written through this service follows them.
type codeRules struct{ region, reservedIDs bool }

var allCodeRules = codeRules{region: true, reservedIDs: true}

// checkConfig is the mirror of the CHECKs of hosts (0001: capacity and public_entry are objects, run_uid_range non-empty
// with a positive lower bound; 0014: hosts_status_valid, hosts_capacity_valid, hosts_public_entry_valid,
// hosts_tenant_net_pool_valid, hosts_run_uid_range_bounds, hosts_stun_port_range_valid) plus the rules left to code:
// the name (nil = not checked: it never changes after creation) and those of rules.
func checkConfig(name *string, c hostConfig, rules codeRules) []FieldError {
	var out []FieldError
	add := func(field, code, msg string) { out = append(out, FieldError{Field: field, Code: code, Message: msg}) }
	if name != nil && !hostNameRE.MatchString(*name) {
		add("name", "invalid_format", "must be a DNS label: lower-case letters, digits and '-', at most 63 characters")
	}
	if rules.region && (c.region == "" || len(c.region) > 64 || strings.ContainsAny(c.region, " \t\r\n")) {
		add("region", "invalid_format", "must be 1–64 characters without spaces")
	}
	if !slices.Contains(HostStatuses, c.status) {
		add("status", "invalid_value", "must be active, draining or disabled")
	}
	if c.maxInstances < 0 || c.maxInstances > math.MaxInt32 {
		add("capacity.max_instances", "out_of_range", "must be an integer between 0 and 2147483647")
	}
	pool, poolErr := parsePool(c.pool)
	if poolErr != "" {
		add("tenant_net_pool", "invalid_value", poolErr)
	}
	uidErrs := checkRange("run_uid_range", c.uid, minRunUID, maxRunUID)
	out = append(out, uidErrs...)
	if len(uidErrs) == 0 && rules.reservedIDs { // code only: the list follows versions.lock (placement, agent)
		for _, id := range ReservedIDs {
			if int64(id) >= c.uid.First && int64(id) <= c.uid.Last {
				add("run_uid_range", "reserved_id", fmt.Sprintf("must not contain the UID/GID %d of a core service (versions.lock [ids])", id))
				break
			}
		}
	}
	if c.stun != nil {
		out = append(out, checkRange("stun_port_range", *c.stun, minSTUNPort, maxSTUNPort)...)
	}
	if c.mode != nil && *c.mode != EntryDirect && *c.mode != EntryVPSGateway {
		add("public_entry.mode", "invalid_value", "must be direct or vps_gateway")
	}
	if c.ipv4 != nil {
		switch a, err := netip.ParseAddr(*c.ipv4); {
		case !ipv4RE.MatchString(*c.ipv4) || err != nil:
			add("public_entry.ipv4", "invalid_format", "must be an IPv4 address in dotted decimal without leading zeros")
		case slices.ContainsFunc(notUnicast, func(p netip.Prefix) bool { return p.Contains(a) }):
			add("public_entry.ipv4", "not_unicast", "must not lie in 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 or 224.0.0.0/3")
		case poolErr == "" && pool.Contains(a):
			add("public_entry.ipv4", "inside_pool", "must lie outside tenant_net_pool")
		}
	}
	return out
}

// jsonNumberRE is the grammar of a JSON number: sign, integer part, fraction, exponent.
var jsonNumberRE = regexp.MustCompile(`^-?([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

// ParseCapacity reads a capacity object as the database reads the jsonb column (0001: an object; 0014
// hosts_capacity_valid: exactly the key max_instances, whose PostgreSQL numeric text is 1–10 digits and at most
// 2147483647). A JSON number is a PostgreSQL numeric: 1e2 is 100 and accepted, 10.0 keeps its fraction and is refused,
// -0 is 0. Returns the value in canonical form.
func ParseCapacity(raw []byte) (int64, []FieldError) {
	obj, fe := jsonObject(raw, "capacity")
	if fe != nil {
		return 0, fe
	}
	for k := range obj {
		if k != "max_instances" {
			return 0, []FieldError{{Field: "capacity", Code: "unknown_key", Message: "must hold max_instances only"}}
		}
	}
	v, ok := obj["max_instances"]
	if !ok {
		return 0, []FieldError{{Field: "capacity.max_instances", Code: "required", Message: "is required"}}
	}
	num, isNum := v.(json.Number)
	if !isNum {
		return 0, []FieldError{{Field: "capacity.max_instances", Code: "invalid_type", Message: "must be a number"}}
	}
	n, ok := numericInteger(string(num), math.MaxInt32)
	if !ok {
		return 0, []FieldError{{Field: "capacity.max_instances", Code: "out_of_range",
			Message: "must be an integer between 0 and 2147483647, without a fraction"}}
	}
	return n, nil
}

// ParsePublicEntry reads a public_entry object as hosts_public_entry_valid reads the keys of the jsonb column: an
// object whose keys are ipv4 and mode only (ipv6 is not accepted at the MVP), each a JSON string — null or a number is
// refused like any other value outside the CHECK. The values themselves are checked with the rest of the host.
func ParsePublicEntry(raw []byte) (PublicEntry, []FieldError) {
	obj, fe := jsonObject(raw, "public_entry")
	if fe != nil {
		return PublicEntry{}, fe
	}
	var out PublicEntry
	for k, v := range obj {
		s, isString := v.(string)
		switch {
		case k != "ipv4" && k != "mode":
			fe = append(fe, FieldError{Field: "public_entry", Code: "unknown_key",
				Message: "must hold ipv4 and mode only (ipv6 is not accepted yet)"})
		case !isString:
			fe = append(fe, FieldError{Field: "public_entry." + k, Code: "invalid_type", Message: "must be a string"})
		case k == "ipv4":
			out.IPv4 = &s
		default:
			out.Mode = &s
		}
	}
	slices.SortFunc(fe, func(a, b FieldError) int { return strings.Compare(a.Field, b.Field) })
	return out, slices.CompactFunc(fe, func(a, b FieldError) bool { return a == b })
}

// jsonObject decodes raw as one JSON object, numbers kept as written.
func jsonObject(raw []byte, field string) (map[string]any, []FieldError) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, []FieldError{{Field: field, Code: "invalid_json", Message: "is not valid JSON"}}
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, []FieldError{{Field: field, Code: "invalid_type", Message: "must be an object"}}
	}
	return obj, nil
}

// numericInteger returns the value of a JSON number when PostgreSQL's numeric form of it is an integer in [0, limit]
// written without a fraction: the display scale of a numeric is max(0, fraction digits - exponent), so 1e2 and 1.5e1
// are integers (100, 15), while 10.0 and 1.50e1 keep a fraction (10.0, 15.0).
func numericInteger(s string, limit int64) (int64, bool) {
	m := jsonNumberRE.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	digits, frac := m[1], m[2]
	exp := 0
	if m[3] != "" {
		e, err := strconv.Atoi(m[3])
		if err != nil || e > 1000 || e < -1000 {
			return 0, false
		}
		exp = e
	}
	if len(frac)-exp > 0 {
		return 0, false // a fraction remains in the numeric text
	}
	mantissa := strings.TrimLeft(digits+frac, "0")
	if mantissa == "" {
		return 0, true // zero, whatever its sign or exponent
	}
	if s[0] == '-' {
		return 0, false
	}
	shift := exp - len(frac) // ≥ 0 here
	if len(mantissa)+shift > 10 {
		return 0, false // more than 10 digits
	}
	n, err := strconv.ParseInt(mantissa+strings.Repeat("0", shift), 10, 64)
	if err != nil || n > limit {
		return 0, false
	}
	return n, true
}

// checkRange checks an inclusive range against [lo, hi]: finite (always, here), non-empty, within the bounds.
func checkRange(field string, r IntRange, lo, hi int64) []FieldError {
	var out []FieldError
	if r.First < lo || r.First > hi {
		out = append(out, FieldError{Field: field + ".first", Code: "out_of_range",
			Message: fmt.Sprintf("must be between %d and %d", lo, hi)})
	}
	if r.Last < lo || r.Last > hi {
		out = append(out, FieldError{Field: field + ".last", Code: "out_of_range",
			Message: fmt.Sprintf("must be between %d and %d", lo, hi)})
	}
	if len(out) == 0 && r.First > r.Last {
		out = append(out, FieldError{Field: field, Code: "empty_range", Message: "first must not exceed last"})
	}
	return out
}

// parsePool parses tenant_net_pool as hosts_tenant_net_pool_valid accepts it — in canonical text form a.b.c.d/n (the
// cidr type would also take abbreviations: the API takes one spelling). Returns the reason when it is refused.
func parsePool(s string) (netip.Prefix, string) {
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil || !p.Addr().Is4() || p.String() != s:
		return netip.Prefix{}, "must be an IPv4 network in canonical CIDR form, e.g. 10.250.0.0/16"
	case p != p.Masked():
		return netip.Prefix{}, "must be a network address (no host bits set)"
	case p.Bits() < 8 || p.Bits() > 29:
		return netip.Prefix{}, "must be between /8 and /29"
	case p.Overlaps(tailnetRange):
		return netip.Prefix{}, "must not overlap 100.64.0.0/10 (tailnet addresses)"
	}
	return p, ""
}

// configOf is the configuration of a registered host.
func configOf(h Host) hostConfig {
	c := hostConfig{region: h.Region, status: h.Status, maxInstances: int64(h.MaxInstances),
		uid: IntRange{First: int64(h.RunUIDFirst), Last: int64(h.RunUIDLast)}, pool: h.TenantNetPool.String()}
	if h.PublicEntry.IsValid() {
		s := h.PublicEntry.String()
		c.ipv4 = &s
	}
	if h.EntryMode != "" {
		m := h.EntryMode
		c.mode = &m
	}
	if h.STUNPortFirst != 0 {
		c.stun = &IntRange{First: int64(h.STUNPortFirst), Last: int64(h.STUNPortLast)}
	}
	return c
}

// apply returns the configuration after the patch.
func (p HostPatch) apply(c hostConfig) hostConfig {
	if p.Region != nil {
		c.region = *p.Region
	}
	if p.Status != nil {
		c.status = *p.Status
	}
	if p.MaxInstances != nil {
		c.maxInstances = *p.MaxInstances
	}
	if p.PublicEntry != nil {
		c.ipv4, c.mode = p.PublicEntry.IPv4, p.PublicEntry.Mode
	}
	if p.RunUIDRange != nil {
		c.uid = *p.RunUIDRange
	}
	if p.STUNPortRange != nil {
		s := *p.STUNPortRange
		c.stun = &s
	}
	if p.TenantNetPool != nil {
		c.pool = *p.TenantNetPool
	}
	return c
}

// allocationFields are the fields that may not change while the host has instances that are not removed: what
// placement read when it allocated them (region) and what their UIDs, subnets and ports were taken from.
var allocationFields = []string{"region", "run_uid_range", "stun_port_range", "tenant_net_pool"}

// changed lists the fields that differ between two configurations (API field names).
func changed(a, b hostConfig) []string {
	var out []string
	if a.region != b.region {
		out = append(out, "region")
	}
	if a.status != b.status {
		out = append(out, "status")
	}
	if a.maxInstances != b.maxInstances {
		out = append(out, "capacity")
	}
	if deref(a.ipv4) != deref(b.ipv4) || (a.ipv4 == nil) != (b.ipv4 == nil) || deref(a.mode) != deref(b.mode) ||
		(a.mode == nil) != (b.mode == nil) {
		out = append(out, "public_entry")
	}
	if a.uid != b.uid {
		out = append(out, "run_uid_range")
	}
	if (a.stun == nil) != (b.stun == nil) || (a.stun != nil && *a.stun != *b.stun) {
		out = append(out, "stun_port_range")
	}
	if a.pool != b.pool {
		out = append(out, "tenant_net_pool")
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// optional is s as an audit detail value: JSON null when absent.
func optional(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// row values of a validated configuration.
func (c hostConfig) capacityJSON() []byte {
	b, _ := json.Marshal(map[string]int64{"max_instances": c.maxInstances}) // cannot fail: a map of int64
	return b
}

func (c hostConfig) publicEntryJSON() []byte {
	b, _ := json.Marshal(PublicEntry{IPv4: c.ipv4, Mode: c.mode}) // cannot fail: two optional strings
	return b
}

// int4range is the inclusive range r (validated: both bounds fit int4).
func int4range(r IntRange) pgtype.Range[pgtype.Int4] {
	return pgtype.Range[pgtype.Int4]{
		Lower: pgtype.Int4{Int32: int32(r.First), Valid: true}, LowerType: pgtype.Inclusive, //nolint:gosec // G115: validated bounds
		Upper: pgtype.Int4{Int32: int32(r.Last), Valid: true}, UpperType: pgtype.Inclusive, //nolint:gosec // G115: validated bounds
		Valid: true,
	}
}

func (c hostConfig) stunRange() pgtype.Range[pgtype.Int4] {
	if c.stun == nil {
		return pgtype.Range[pgtype.Int4]{} // NULL
	}
	return int4range(*c.stun)
}

// ---------------------------------------------------------------- ETag, usage

// hostETag is the entity tag of a host's configuration: a quoted hex prefix of the SHA-256 of the managed fields (the
// table has no version column; last_heartbeat_at and updated_at are left out so a heartbeat never invalidates it).
func hostETag(h Host) string {
	stun := ""
	if h.STUNPortFirst != 0 {
		stun = fmt.Sprintf("%d-%d", h.STUNPortFirst, h.STUNPortLast)
	}
	ipv4 := ""
	if h.PublicEntry.IsValid() {
		ipv4 = h.PublicEntry.String()
	}
	s := strings.Join([]string{"host/v1", h.ID.String(), h.Region, h.Status, strconv.Itoa(int(h.MaxInstances)), ipv4,
		h.EntryMode, fmt.Sprintf("%d-%d", h.RunUIDFirst, h.RunUIDLast), stun, h.TenantNetPool.String()}, "\n")
	sum := sha256.Sum256([]byte(s))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// ifMatchState reads an If-Match value against the current ETag: a list of entity tags compared strongly (RFC 9110
// §13.1.1). "*" does not name a version, so it counts as missing.
func ifMatchState(ifMatch, current string) error {
	v := strings.TrimSpace(ifMatch)
	if v == "" || v == "*" {
		return ErrPreconditionRequired
	}
	for _, t := range strings.Split(v, ",") {
		if strings.TrimSpace(t) == current {
			return nil
		}
	}
	return ErrPreconditionFailed
}

// usageOf counts what the instance rows of a host hold (every row: removed ones keep their UID).
func usageOf(h Host, rows []sqlcdb.ListHostAllocationsRow) HostUsage {
	u := HostUsage{ByStatus: map[string]int{}}
	uids := map[int32]bool{}
	nets := map[netip.Prefix]bool{}
	stun := map[int32]bool{}
	for _, r := range rows {
		if r.RunUid >= h.RunUIDFirst && r.RunUid <= h.RunUIDLast && !slices.Contains(ReservedIDs, r.RunUid) {
			uids[r.RunUid] = true
		}
		if r.Status == tenants.InstanceRemoved {
			continue
		}
		u.LiveInstances++
		u.ByStatus[r.Status]++
		if r.NetCidr.Bits() >= h.TenantNetPool.Bits() && h.TenantNetPool.Contains(r.NetCidr.Addr()) {
			nets[r.NetCidr.Masked()] = true
		}
		if r.StunPort != nil && *r.StunPort >= h.STUNPortFirst && *r.StunPort <= h.STUNPortLast {
			stun[*r.StunPort] = true
		}
	}
	total := int64(h.RunUIDLast) - int64(h.RunUIDFirst) + 1
	for _, id := range ReservedIDs {
		if id >= h.RunUIDFirst && id <= h.RunUIDLast {
			total--
		}
	}
	u.RunUIDsFree = max(0, total-int64(len(uids)))
	if b := h.TenantNetPool.Bits(); b >= 8 && b <= 29 {
		u.NetSlotsFree = max(0, int64(1)<<(29-b)-int64(len(nets)))
	}
	if h.STUNPortFirst != 0 {
		free := max(0, int64(h.STUNPortLast)-int64(h.STUNPortFirst)+1-int64(len(stun)))
		u.STUNPortsFree = &free
	}
	return u
}

func view(r sqlcdb.Host, rows []sqlcdb.ListHostAllocationsRow) (HostView, error) {
	h, err := host(r)
	if err != nil {
		return HostView{}, err
	}
	v := HostView{Host: h, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), Usage: usageOf(h, rows),
		ETag: hostETag(h)}
	if r.LastHeartbeatAt != nil {
		t := r.LastHeartbeatAt.UTC()
		v.LastHeartbeatAt = &t
	}
	return v, nil
}

// ---------------------------------------------------------------- reads

// ListHosts is GET /platform/hosts.
func (s *Service) ListHosts(ctx context.Context, f HostFilter) (HostPage, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return HostPage{}, fmt.Errorf("%w: limit must be 1–%d", ErrInvalid, MaxLimit)
	}
	p := sqlcdb.ListHostsPageParams{RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if f.Status != "" {
		if !slices.Contains(HostStatuses, f.Status) {
			return HostPage{}, fmt.Errorf("%w: unknown host status", ErrInvalid)
		}
		p.Status = &f.Status
	}
	if f.Region != "" {
		p.Region = &f.Region
	}
	if f.Cursor != "" {
		t, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return HostPage{}, err
		}
		p.AfterCreatedAt, p.AfterID = &t, &id
	}
	var out HostPage
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListHostsPage(ctx, p)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1]
			out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		}
		ids := make([]uuid.UUID, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		allocs, err := q.ListHostAllocations(ctx, ids)
		if err != nil {
			return err
		}
		byHost := map[uuid.UUID][]sqlcdb.ListHostAllocationsRow{}
		for _, a := range allocs {
			byHost[a.HostID] = append(byHost[a.HostID], a)
		}
		out.Items = make([]HostView, 0, len(rows))
		for _, r := range rows {
			v, err := view(r, byHost[r.ID])
			if err != nil {
				return err
			}
			out.Items = append(out.Items, v)
		}
		return nil
	})
	return out, err
}

// GetHost is GET /platform/hosts/{hostId}.
func (s *Service) GetHost(ctx context.Context, id uuid.UUID) (HostView, error) {
	if id == uuid.Nil {
		return HostView{}, ErrNotFound
	}
	var out HostView
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetHost(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = readView(ctx, q, r)
		return err
	})
	return out, err
}

// GetHostByName reads a host and its usage by name (the host command): ErrNotFound when it is not registered.
func (s *Service) GetHostByName(ctx context.Context, name string) (HostView, error) {
	var out HostView
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetHostByName(ctx, name)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = readView(ctx, q, r)
		return err
	})
	return out, err
}

func readView(ctx context.Context, q *sqlcdb.Queries, r sqlcdb.Host) (HostView, error) {
	rows, err := q.ListHostAllocations(ctx, []uuid.UUID{r.ID})
	if err != nil {
		return HostView{}, err
	}
	return view(r, rows)
}

// ---------------------------------------------------------------- writes

// CreateHost is POST /platform/hosts: validation (*ValidationError), the Idempotency-Key (a replay of the same request
// returns the stored host — as it was created), then one transaction inserts the host and records platform.host.create.
// A name already registered is a *HostConflictError (name_taken).
func (s *Service) CreateHost(ctx context.Context, in HostConfig, w HostWrite) (HostView, error) {
	if fe := in.Check(); len(fe) > 0 {
		return HostView{}, &ValidationError{Fields: fe}
	}
	c := in.config()
	var key *jobs.IdempotencyKey
	if w.Idempotency != nil {
		key = &jobs.IdempotencyKey{IdentityID: w.Idempotency.IdentityID, OperationID: CreateHostOperation,
			Key: w.Idempotency.Key}
		var replay *HostView
		err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			d, err := jobs.BeginIdempotent(ctx, q, *key, w.Idempotency.Hash, idempotencyLock)
			if err != nil {
				return err
			}
			switch d.Outcome {
			case jobs.IdempotencyReplay:
				var v HostView
				if d.Response == nil || json.Unmarshal(d.Response.Body, &v) != nil {
					return errors.New("platform: stored host response unreadable")
				}
				replay = &v
				// the replay changes nothing, but it is a request of the actor like any other (and a write without an
				// event would read as an audit gap)
				return audit.Record(ctx, q, w.event(ActionHostCreate, v.ID, audit.Details{"name": v.Name, "replay": true}))
			case jobs.IdempotencyInProgress:
				return &IdempotencyBusyError{RetryAfter: d.RetryAfter}
			case jobs.IdempotencyKeyReuse:
				return ErrIdempotencyKeyReuse
			}
			return nil
		})
		if err != nil {
			return HostView{}, err
		}
		if replay != nil {
			return *replay, nil
		}
	}
	var out HostView
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		pool, _ := parsePool(c.pool)
		r, err := q.InsertHost(ctx, sqlcdb.InsertHostParams{Name: in.Name, Region: c.region, Status: c.status,
			Capacity: c.capacityJSON(), PublicEntry: c.publicEntryJSON(), RunUidRange: int4range(c.uid),
			StunPortRange: c.stunRange(), TenantNetPool: pool})
		if err != nil {
			return dbRefusal(err)
		}
		if out, err = view(r, nil); err != nil {
			return err
		}
		details := audit.Details{"name": out.Name}
		addConfig(details, "", c)
		if err := audit.Record(ctx, q, w.event(ActionHostCreate, r.ID, details)); err != nil {
			return err
		}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(out)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, q, *key, w.Idempotency.Hash, jobs.StoredResponse{Status: 201, Body: body,
			Resource: &jobs.Resource{Type: "host", ID: r.ID.String()}})
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, w.Idempotency.Hash)
			})
		}
		return HostView{}, err
	}
	return out, nil
}

// UpdateHost is PATCH /platform/hosts/{hostId} (and the host command, through UpdateHostByName). In one transaction:
// lock the row (ErrNotFound), check the If-Match against the current ETag (ErrPreconditionRequired,
// ErrPreconditionFailed), validate the patched configuration (*ValidationError), count the instances that are not
// removed and refuse a capacity below that count or a change of region or allocation range while it is not 0
// (*HostConflictError), write, record platform.host.update with the values before and after.
func (s *Service) UpdateHost(ctx context.Context, id uuid.UUID, p HostPatch, w HostWrite) (HostView, error) {
	if id == uuid.Nil {
		return HostView{}, ErrNotFound
	}
	var out HostView
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.LockHost(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = s.update(ctx, q, r, p, w)
		return err
	})
	return out, err
}

// UpdateHostByName is UpdateHost for a host named by the operator (the host command).
func (s *Service) UpdateHostByName(ctx context.Context, name string, p HostPatch, w HostWrite) (HostView, error) {
	var out HostView
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetHostByName(ctx, name)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if r, err = q.LockHost(ctx, r.ID); err != nil {
			return err
		}
		out, err = s.update(ctx, q, r, p, w)
		return err
	})
	return out, err
}

func (s *Service) update(ctx context.Context, q *sqlcdb.Queries, r sqlcdb.Host, p HostPatch, w HostWrite) (HostView, error) {
	cur, err := host(r)
	if err != nil {
		return HostView{}, err
	}
	if err := ifMatchState(w.IfMatch, hostETag(cur)); err != nil {
		return HostView{}, err
	}
	if p.empty() {
		return HostView{}, &ValidationError{Fields: []FieldError{{Field: "body", Code: "empty",
			Message: "must change at least one field"}}}
	}
	before := configOf(cur)
	after := p.apply(before)
	diff := changed(before, after)
	rules := codeRules{region: slices.Contains(diff, "region"), reservedIDs: slices.Contains(diff, "run_uid_range")}
	if fe := checkConfig(nil, after, rules); len(fe) > 0 {
		return HostView{}, &ValidationError{Fields: fe}
	}
	allocs, err := q.ListHostAllocations(ctx, []uuid.UUID{r.ID}) // under the row lock: no allocation in between
	if err != nil {
		return HostView{}, err
	}
	live := 0
	for _, a := range allocs {
		if a.Status != tenants.InstanceRemoved {
			live++
		}
	}
	if after.maxInstances < int64(live) {
		return HostView{}, &HostConflictError{Reason: ConflictCapacityBelowLive, Live: live}
	}
	if live > 0 {
		var frozen []string
		for _, f := range diff {
			if slices.Contains(allocationFields, f) {
				frozen = append(frozen, f)
			}
		}
		if len(frozen) > 0 {
			return HostView{}, &HostConflictError{Reason: ConflictAllocationInUse, Fields: frozen, Live: live}
		}
	}
	pool, _ := parsePool(after.pool)
	nr, err := q.UpdateHostConfig(ctx, sqlcdb.UpdateHostConfigParams{ID: r.ID, Region: after.region, Status: after.status,
		Capacity: after.capacityJSON(), PublicEntry: after.publicEntryJSON(), RunUidRange: int4range(after.uid),
		StunPortRange: after.stunRange(), TenantNetPool: pool})
	if err != nil {
		return HostView{}, dbRefusal(err)
	}
	out, err := view(nr, allocs)
	if err != nil {
		return HostView{}, err
	}
	if diff == nil {
		diff = []string{}
	}
	details := audit.Details{"name": out.Name, "changed": diff, "live_instances": live}
	addConfig(details, "before_", before)
	addConfig(details, "after_", after)
	if err := audit.Record(ctx, q, w.event(ActionHostUpdate, r.ID, details)); err != nil {
		return HostView{}, err
	}
	return out, nil
}

// addConfig writes the managed fields of c into audit details (flat: audit details hold no nested object). No field of
// a host is a secret.
func addConfig(d audit.Details, prefix string, c hostConfig) {
	d[prefix+"region"] = c.region
	d[prefix+"status"] = c.status
	d[prefix+"max_instances"] = c.maxInstances
	d[prefix+"public_ipv4"] = optional(c.ipv4) // audit.Details takes plain values: a *string would be dropped
	d[prefix+"entry_mode"] = optional(c.mode)
	d[prefix+"run_uid_range"] = c.uid.String()
	if c.stun != nil {
		d[prefix+"stun_port_range"] = c.stun.String()
	} else {
		d[prefix+"stun_port_range"] = nil
	}
	d[prefix+"tenant_net_pool"] = c.pool
}

// event is the audit event of a host write.
func (w HostWrite) event(action string, id uuid.UUID, details audit.Details) audit.Event {
	ev := audit.Event{Action: action, ResourceType: "host", ResourceID: id.String(), Details: details}
	if w.System != nil {
		ev.ActorType, ev.ActorDisplay, ev.RequestID = audit.ActorSystem, w.System.Command, w.System.RequestID
	}
	return ev
}

// dbRefusal maps what the database refused despite validation: the unique name (a concurrent registration) is a
// conflict; a CHECK of 0014 names its field (the validation mirror missed a case — TestHostConfigParity exists so that
// it does not); anything else is returned as is.
func dbRefusal(err error) error {
	switch store.SQLState(err) {
	case "23505":
		if store.SQLConstraint(err) == "hosts_name_key" {
			return &HostConflictError{Reason: ConflictNameTaken}
		}
	case "23514":
		field := map[string]string{
			"hosts_status_valid": "status", "hosts_capacity_valid": "capacity.max_instances",
			"hosts_public_entry_valid": "public_entry", "hosts_tenant_net_pool_valid": "tenant_net_pool",
			"hosts_run_uid_range_bounds": "run_uid_range", "hosts_stun_port_range_valid": "stun_port_range",
		}[store.SQLConstraint(err)]
		if field == "" {
			field = "body"
		}
		return &ValidationError{Fields: []FieldError{{Field: field, Code: "refused", Message: "refused by the registry"}}}
	}
	return err
}
