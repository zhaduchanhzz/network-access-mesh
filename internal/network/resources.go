package network

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Network Resource Catalog (§6.3 network_resources — CHECKs of 0022, mirrored here so a refusal names its field).

// Audit actions of the catalog (x-audit-action of api/openapi.yaml).
const (
	ActionResourceCreate = "resource.create"
	ActionResourceUpdate = "resource.update"
	ActionResourceDelete = "resource.delete"

	resourceType            = "network_resource"
	createResourceOperation = "createTenantResource"
)

// Kinds and protocols of a resource. ProtocolAny is the API's name of "every protocol" (NULL in the table).
const (
	KindHost    = "host"
	KindSubnet  = "subnet"
	KindService = "service"

	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolICMP = "icmp"
	ProtocolAny  = "any"
)

// Limits of the catalog.
const (
	MaxResourceDescription = 1000 // characters (CHECK of 0022)
	MaxResourcePorts       = 64
	MaxResourceTags        = 64
	DefaultResourceLimit   = 50
	MaxResourceLimit       = 200
)

// TriggerResourceChange is the policy.apply trigger of a catalog change (§13.5; the handler of internal/policies).
const (
	kindPolicyApply       = "policy.apply"
	TriggerResourceChange = "resource_change"
)

var (
	resourceNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`) // alias of the policy key `hosts` (§7.2)
	portRE         = regexp.MustCompile(`^([0-9]{1,5})(?:-([0-9]{1,5}))?$`)
)

// Resource is the API view of a catalog entry (schema NetworkResource).
type Resource struct {
	ID           uuid.UUID
	Name         string
	Kind         string
	Address      netip.Prefix
	Ports        []string
	Protocol     string // tcp, udp, icmp or ProtocolAny
	Tags         []string
	OwnerGroupID *uuid.UUID
	Description  string
	Version      int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ETag is the entity tag of the resource (its version — §6.1): the If-Match of PATCH and DELETE.
func (r Resource) ETag() string { return versionETag(r.Version) }

// AddressString is the address as the API shows it: a single address without its prefix length for a host or a
// service, the prefix for a subnet.
func (r Resource) AddressString() string {
	if r.Address.IsSingleIP() {
		return r.Address.Addr().String()
	}
	return r.Address.String()
}

func resourceOf(r sqlcdb.NetworkResource) Resource {
	out := Resource{ID: r.ID, Name: r.Name, Kind: r.Kind, Address: r.Address, Ports: slices.Clone(r.Ports),
		Protocol: ProtocolAny, Tags: slices.Clone(r.Tags), OwnerGroupID: r.OwnerGroupID, Version: r.Version,
		CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC()}
	if r.Protocol != nil {
		out.Protocol = *r.Protocol
	}
	if r.Description != nil {
		out.Description = *r.Description
	}
	if out.Ports == nil {
		out.Ports = []string{}
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	return out
}

// ResourceInput is the body of POST /resources (and the full state a PATCH is checked as).
type ResourceInput struct {
	Name         string
	Kind         string
	Address      string
	Ports        []string
	Protocol     string // "" ⇒ any
	Tags         []string
	OwnerGroupID *uuid.UUID
	Description  string
}

// ResourcePatch is the body of PATCH /resources/{id}: nil fields are unchanged; OwnerGroupID "" removes the owner, an
// empty description clears it, Protocol "any" means every protocol.
type ResourcePatch struct {
	Name         *string
	Kind         *string
	Address      *string
	Ports        *[]string
	Protocol     *string
	Tags         *[]string
	OwnerGroupID *string
	Description  *string
}

// Empty reports a patch that names no field.
func (p ResourcePatch) Empty() bool {
	return p.Name == nil && p.Kind == nil && p.Address == nil && p.Ports == nil && p.Protocol == nil && p.Tags == nil &&
		p.OwnerGroupID == nil && p.Description == nil
}

// ResourcePage is one page of the catalog.
type ResourcePage struct {
	Items      []Resource
	NextCursor string
}

// ResourceChange is the outcome of a catalog change: the resource (the deleted one for a delete) and the policy.apply
// job that carries it (an unfinished job of the tenant is reused — §13.5 dedupe).
type ResourceChange struct {
	Resource    Resource
	PolicyJobID uuid.UUID
}

// normalized is a resource checked against the rules of 0022, ready to be written.
type normalized struct {
	name, kind  string
	address     netip.Prefix
	ports       []string
	protocol    *string
	tags        []string
	owner       *uuid.UUID
	description *string
}

// parseAddress reads an address: a single IPv4/IPv6 address (with or without /32, /128) for a host or a service, a
// masked prefix shorter than the address for a subnet (never /0 — the whole Internet is the exit node's, not the
// catalog's).
func parseAddress(kind, s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, invalid("address", "invalid_address", "address must be an IP address or a prefix")
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, invalid("address", "invalid_address", "address must be an IP address or a prefix")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	a := p.Addr()
	if a.Zone() != "" || a.Is4In6() || a.IsUnspecified() && kind != KindSubnet {
		return netip.Prefix{}, invalid("address", "invalid_address", "address must be a plain IPv4 or IPv6 address or prefix")
	}
	switch kind {
	case KindSubnet:
		if p.Bits() == 0 || p.Bits() >= a.BitLen() {
			return netip.Prefix{}, invalid("address", "subnet_prefix", "a subnet is a prefix shorter than one address and longer than /0")
		}
		if p.Masked() != p {
			return netip.Prefix{}, invalid("address", "address_not_canonical", "the prefix must have no host bits set (e.g. 10.0.0.0/24)")
		}
	default:
		if p.Bits() != a.BitLen() {
			return netip.Prefix{}, invalid("address", "single_address", "a host or a service has exactly one address")
		}
	}
	return p, nil
}

// normalizePorts checks ports and ranges ("443", "8000-8100"), drops duplicates and sorts them.
func normalizePorts(ports []string) ([]string, error) {
	if len(ports) > MaxResourcePorts {
		return nil, invalid("ports", "too_many_ports", fmt.Sprintf("at most %d ports or ranges", MaxResourcePorts))
	}
	type rng struct{ lo, hi int }
	var rs []rng
	for _, s := range ports {
		m := portRE.FindStringSubmatch(strings.TrimSpace(s))
		if m == nil {
			return nil, invalid("ports", "invalid_port", `ports are "443" or ranges "8000-8100"`)
		}
		lo, _ := strconv.Atoi(m[1])
		hi := lo
		if m[2] != "" {
			hi, _ = strconv.Atoi(m[2])
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return nil, invalid("ports", "invalid_port", "ports are between 1 and 65535, a range low-high with low ≤ high")
		}
		rs = append(rs, rng{lo, hi})
	}
	slices.SortFunc(rs, func(a, b rng) int {
		if a.lo != b.lo {
			return a.lo - b.lo
		}
		return a.hi - b.hi
	})
	rs = slices.Compact(rs)
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.lo == r.hi {
			out = append(out, strconv.Itoa(r.lo))
		} else {
			out = append(out, strconv.Itoa(r.lo)+"-"+strconv.Itoa(r.hi))
		}
	}
	return out, nil
}

func normalizeDescription(d string) (*string, error) {
	v := strings.TrimSpace(d)
	switch {
	case v == "":
		return nil, nil
	case !utf8.ValidString(v) || strings.ContainsRune(v, 0) || utf8.RuneCountInString(v) > MaxResourceDescription:
		return nil, invalid("description", "invalid_description", fmt.Sprintf("at most %d characters", MaxResourceDescription))
	}
	return &v, nil
}

// normalizeResource checks a resource (the tags against the catalog are checked in the writing transaction).
func normalizeResource(in ResourceInput) (normalized, error) {
	var n normalized
	if !resourceNameRE.MatchString(in.Name) {
		return n, invalid("name", "invalid_name", "name is lowercase letters, digits and '-', starting with a letter (≤ 63)")
	}
	switch in.Kind {
	case KindHost, KindSubnet, KindService:
	default:
		return n, invalid("kind", "invalid_kind", "kind is host, subnet or service")
	}
	addr, err := parseAddress(in.Kind, in.Address)
	if err != nil {
		return n, err
	}
	ports, err := normalizePorts(in.Ports)
	if err != nil {
		return n, err
	}
	var proto *string
	switch in.Protocol {
	case "", ProtocolAny:
	case ProtocolTCP, ProtocolUDP, ProtocolICMP:
		p := in.Protocol
		proto = &p
	default:
		return n, invalid("protocol", "invalid_protocol", "protocol is tcp, udp, icmp or any")
	}
	switch {
	case len(ports) > 0 && proto != nil && *proto == ProtocolICMP:
		return n, invalid("ports", "ports_with_icmp", "icmp has no ports")
	case in.Kind == KindService && len(ports) == 0:
		return n, invalid("ports", "service_needs_ports", "a service declares at least one port")
	case len(in.Tags) > MaxResourceTags:
		return n, invalid("tags", "too_many_tags", fmt.Sprintf("at most %d tags", MaxResourceTags))
	}
	desc, err := normalizeDescription(in.Description)
	if err != nil {
		return n, err
	}
	if in.OwnerGroupID != nil && *in.OwnerGroupID == uuid.Nil {
		return n, invalid("owner_group_id", "invalid_group", "owner_group_id must be a group of the tenant")
	}
	return normalized{name: in.Name, kind: in.Kind, address: addr, ports: ports, protocol: proto,
		tags: slices.Clone(in.Tags), owner: in.OwnerGroupID, description: desc}, nil
}

// tagValidation is the input refusal of a TagChecker.
type tagValidation interface {
	Validation() (field, reason string, tags []string, ok bool)
}

// checkTags runs the catalog check of the resource's tags in the writing transaction (FOR SHARE: a concurrent delete
// of a tag waits, then counts this resource).
func (s *Service) checkTags(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, tags []string) ([]string, error) {
	if len(tags) == 0 {
		return []string{}, nil
	}
	if s.cfg.Tags == nil {
		return nil, &Error{Code: CodeInternal, Reason: ReasonNotWired, Err: errors.New("network: no tag catalog wired")}
	}
	out, err := s.cfg.Tags(ctx, q, tenantID, tags, "tags")
	if err == nil {
		return out, nil
	}
	var v tagValidation
	if errors.As(err, &v) {
		if _, reason, names, ok := v.Validation(); ok {
			detail := "tags must be names of the form tag:<lowercase name>"
			if len(names) > 0 {
				detail = "these tags are not in the tenant's tag catalog: " + strings.Join(names, ", ")
			}
			return nil, &Error{Code: CodeValidationFailed, Reason: reason, Field: "tags", Detail: detail, Err: err}
		}
	}
	return nil, err
}

// writeError maps the constraint violations of a write (name taken, owner group not of the tenant).
func writeError(err error) error {
	switch store.SQLState(err) {
	case "23505":
		return conflict("resource_exists", "A resource with this name is already in the tenant's catalog.")
	case "23503":
		return invalid("owner_group_id", "unknown_group", "owner_group_id must be a group of the tenant")
	case "23514":
		return invalid("body", "constraint_violation", "The resource does not satisfy the catalog's rules.")
	}
	return err
}

// enqueuePolicyApply enqueues policy.apply (trigger resource_change) in tx — written if and only if the change commits.
func enqueuePolicyApply(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, by *uuid.UUID) (uuid.UUID, error) {
	e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: kindPolicyApply, TenantID: &tenantID,
		Input: map[string]string{"trigger": TriggerResourceChange}, RequestedBy: by})
	if err != nil {
		return uuid.Nil, fmt.Errorf("network: enqueue policy.apply: %w", err)
	}
	return e.Job.ID, nil
}

func resourceEvent(tenantID, id uuid.UUID, action string, d audit.Details) audit.Event {
	t := tenantID
	return audit.Event{Action: action, TenantID: &t, ResourceType: resourceType, ResourceID: id.String(), Details: d}
}

func resourceDetails(r Resource) audit.Details {
	d := audit.Details{"resource_id": r.ID, "name": r.Name, "kind": r.Kind, "address": r.AddressString(),
		"ports": r.Ports, "protocol": r.Protocol, "tags": r.Tags, "version": r.Version}
	if r.OwnerGroupID != nil {
		d["owner_group_id"] = *r.OwnerGroupID
	}
	return d
}

// ListResources is GET /tenants/{t}/resources: the catalog in its stable order (created_at, id). limit 0 ⇒ the
// default; out of [1, MaxResourceLimit] or a cursor that is not ours ⇒ 422.
func (s *Service) ListResources(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) (ResourcePage, error) {
	switch {
	case limit == 0:
		limit = DefaultResourceLimit
	case limit < 1 || limit > MaxResourceLimit:
		return ResourcePage{}, invalid("limit", "invalid_limit", fmt.Sprintf("limit is between 1 and %d", MaxResourceLimit))
	}
	after, afterID := time.Unix(0, 0).UTC(), uuid.Nil
	if cursor != "" {
		t, id, ok := decodeCursor(cursor)
		if !ok {
			return ResourcePage{}, invalid("cursor", "invalid_cursor", "the cursor is not one of this list")
		}
		after, afterID = t, id
	}
	page := ResourcePage{Items: []Resource{}}
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListNetworkResources(ctx, sqlcdb.ListNetworkResourcesParams{TenantID: tenantID, AfterCreatedAt: after,
			AfterID: afterID, PageLimit: int32(limit + 1)}) //nolint:gosec // limit ≤ MaxResourceLimit
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1]
			page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		}
		for _, r := range rows {
			page.Items = append(page.Items, resourceOf(r))
		}
		return nil
	})
	return page, err
}

// GetResource is GET /tenants/{t}/resources/{id} (another tenant's reads not_found — §8.4 invariant 6).
func (s *Service) GetResource(ctx context.Context, tenantID, id uuid.UUID) (Resource, error) {
	var out Resource
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetNetworkResource(ctx, sqlcdb.GetNetworkResourceParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return notFound("resource_not_found")
		}
		if err != nil {
			return err
		}
		out = resourceOf(r)
		return nil
	})
	return out, err
}

// CreateResource is POST /tenants/{t}/resources: a new catalog entry, its audit event and policy.apply
// (resource_change) in one transaction. With an Idempotency-Key, a replay returns the resource the first request
// created (§13.1).
func (s *Service) CreateResource(ctx context.Context, tenantID uuid.UUID, a Actor, in ResourceInput, idem *Idempotency) (ResourceChange, error) {
	n, err := normalizeResource(in)
	if err != nil {
		return ResourceChange{}, err
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{TenantID: &tenantID, IdentityID: a.IdentityID, OperationID: createResourceOperation, Key: idem.Key}
		var stored storedResource
		replayed, err := s.beginIdempotent(ctx, tenantID, *key, idem.Hash, &stored)
		if err != nil {
			return ResourceChange{}, err
		}
		if replayed {
			r, err := s.GetResource(ctx, tenantID, stored.ID)
			if err != nil {
				return ResourceChange{}, err
			}
			return ResourceChange{Resource: r}, nil
		}
	}
	var out ResourceChange
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		tags, err := s.checkTags(ctx, q, tenantID, n.tags)
		if err != nil {
			return err
		}
		row, err := q.InsertNetworkResource(ctx, sqlcdb.InsertNetworkResourceParams{TenantID: tenantID, Name: n.name,
			Kind: n.kind, Address: n.address, Ports: n.ports, Protocol: n.protocol, Tags: tags, OwnerGroupID: n.owner,
			Description: n.description})
		if err != nil {
			return writeError(err)
		}
		jobID, err := enqueuePolicyApply(ctx, tx, tenantID, a.by())
		if err != nil {
			return err
		}
		r := resourceOf(row)
		d := resourceDetails(r)
		d["policy_apply_job_id"] = jobID
		if err := audit.Record(ctx, q, resourceEvent(tenantID, r.ID, ActionResourceCreate, d)); err != nil {
			return err
		}
		out = ResourceChange{Resource: r, PolicyJobID: jobID}
		if key != nil {
			return completeIdempotent(ctx, q, *key, idem.Hash, 201, storedResource{ID: r.ID},
				&jobs.Resource{Type: resourceType, ID: r.ID.String()})
		}
		return nil
	})
	if err != nil {
		if key != nil {
			s.failIdempotent(ctx, tenantID, *key, idem.Hash)
		}
		return ResourceChange{}, err
	}
	return out, nil
}

// storedResource is the replay body of a create (the resource is read again: a later change shows).
type storedResource struct {
	ID uuid.UUID `json:"id"`
}

// lockResource reads and locks a resource, then checks If-Match (required: "" ⇒ 428; stale ⇒ 412).
func lockResource(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID, ifMatch string) (sqlcdb.NetworkResource, error) {
	r, err := q.LockNetworkResource(ctx, sqlcdb.LockNetworkResourceParams{TenantID: tenantID, ID: id})
	if errors.Is(err, store.ErrNoRows) {
		return r, notFound("resource_not_found")
	}
	if err != nil {
		return r, err
	}
	switch m := normalizeIfMatch(ifMatch); {
	case m == "":
		return r, ifMatchRequired("resource's etag")
	case m != versionETag(r.Version):
		return r, stale("stale_etag", "The resource changed since it was read; read it again.")
	}
	return r, nil
}

// UpdateResource is PATCH /tenants/{t}/resources/{id} (If-Match): the named fields change, the result is checked like a
// new resource; resource.update and policy.apply (resource_change) in one transaction.
func (s *Service) UpdateResource(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch string, p ResourcePatch) (ResourceChange, error) {
	if p.Empty() {
		return ResourceChange{}, invalid("body", "empty", "the body names no field to change")
	}
	var out ResourceChange
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		cur, err := lockResource(ctx, q, tenantID, id, ifMatch)
		if err != nil {
			return err
		}
		prev := resourceOf(cur)
		in := ResourceInput{Name: prev.Name, Kind: prev.Kind, Address: prev.AddressString(), Ports: prev.Ports,
			Protocol: prev.Protocol, Tags: prev.Tags, OwnerGroupID: prev.OwnerGroupID, Description: prev.Description}
		if p.Name != nil {
			in.Name = *p.Name
		}
		if p.Kind != nil {
			in.Kind = *p.Kind
		}
		if p.Address != nil {
			in.Address = *p.Address
		}
		if p.Ports != nil {
			in.Ports = *p.Ports
		}
		if p.Protocol != nil {
			in.Protocol = *p.Protocol
		}
		if p.Tags != nil {
			in.Tags = *p.Tags
		}
		if p.Description != nil {
			in.Description = *p.Description
		}
		if p.OwnerGroupID != nil {
			switch g := strings.TrimSpace(*p.OwnerGroupID); g {
			case "":
				in.OwnerGroupID = nil
			default:
				gid, err := uuid.Parse(g)
				if err != nil || gid == uuid.Nil {
					return invalid("owner_group_id", "invalid_group", "owner_group_id must be a group of the tenant")
				}
				in.OwnerGroupID = &gid
			}
		}
		n, err := normalizeResource(in)
		if err != nil {
			return err
		}
		tags, err := s.checkTags(ctx, q, tenantID, n.tags)
		if err != nil {
			return err
		}
		row, err := q.UpdateNetworkResource(ctx, sqlcdb.UpdateNetworkResourceParams{Name: n.name, Kind: n.kind,
			Address: n.address, Ports: n.ports, Protocol: n.protocol, Tags: tags, OwnerGroupID: n.owner,
			Description: n.description, TenantID: tenantID, ID: id})
		if err != nil {
			return writeError(err)
		}
		jobID, err := enqueuePolicyApply(ctx, tx, tenantID, a.by())
		if err != nil {
			return err
		}
		r := resourceOf(row)
		d := resourceDetails(r)
		d["name_before"], d["address_before"], d["version_before"] = prev.Name, prev.AddressString(), prev.Version
		d["policy_apply_job_id"] = jobID
		if err := audit.Record(ctx, q, resourceEvent(tenantID, id, ActionResourceUpdate, d)); err != nil {
			return err
		}
		out = ResourceChange{Resource: r, PolicyJobID: jobID}
		return nil
	})
	return out, err
}

// DeleteResource is DELETE /tenants/{t}/resources/{id} (If-Match): resource.delete and policy.apply (resource_change)
// in one transaction.
func (s *Service) DeleteResource(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch string) (ResourceChange, error) {
	var out ResourceChange
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		cur, err := lockResource(ctx, q, tenantID, id, ifMatch)
		if err != nil {
			return err
		}
		if s.cfg.ResourceRefs != nil {
			refs, err := s.cfg.ResourceRefs(ctx, q, tenantID, id)
			if err != nil {
				return err
			}
			if refs > 0 {
				return conflict("resource_in_use", fmt.Sprintf("The resource is still named by %d policy version(s) that can be applied.", refs))
			}
		}
		n, err := q.DeleteNetworkResource(ctx, sqlcdb.DeleteNetworkResourceParams{TenantID: tenantID, ID: id})
		if err != nil {
			return err
		}
		if n != 1 {
			return notFound("resource_not_found")
		}
		jobID, err := enqueuePolicyApply(ctx, tx, tenantID, a.by())
		if err != nil {
			return err
		}
		r := resourceOf(cur)
		d := resourceDetails(r)
		d["policy_apply_job_id"] = jobID
		if err := audit.Record(ctx, q, resourceEvent(tenantID, id, ActionResourceDelete, d)); err != nil {
			return err
		}
		out = ResourceChange{Resource: r, PolicyJobID: jobID}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------------------------------- cursor

// cursorVersion prefixes the opaque cursor: version | created_at (µs) | id.
const cursorVersion = 1

func encodeCursor(t time.Time, id uuid.UUID) string {
	b := make([]byte, 0, 1+8+16)
	b = append(b, cursorVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(t.UnixMicro())) //nolint:gosec // timestamps after 1970
	b = append(b, id[:]...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (time.Time, uuid.UUID, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 1+8+16 || b[0] != cursorVersion {
		return time.Time{}, uuid.Nil, false
	}
	micros := binary.BigEndian.Uint64(b[1:9])
	if micros > 1<<62 {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.FromBytes(b[9:])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.UnixMicro(int64(micros)).UTC(), id, true
}
