package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// DNS of the tenant (§12.3 DNS/MagicDNS, §13.2 "dns", T-09).

// Audit actions (x-audit-action of api/openapi.yaml).
const (
	ActionDNSRecordCreate   = "dns.record.create"
	ActionDNSRecordDelete   = "dns.record.delete"
	ActionDNSSettingsUpdate = "dns.settings.update" // paired: .requested here, closed by instance.reconfigure

	createDNSRecordOperation = "createTenantDnsRecord"
	resourceDNSRecord        = "dns_record"
	// SourceDNSSettings is the source of the reconfiguration (job input).
	SourceDNSSettings = "tenant_dns_settings"
)

// KindDNSRecordsWrite is the job that writes the tenant's records file through the Host Agent (jobs.DefaultKinds:
// dedupe tenant:{tenant}:dns.records — level-triggered: a queued job carries every later change).
const KindDNSRecordsWrite = "dns.records_write"

// Limits of the DNS.
const (
	MaxDNSRecords  = 1024 // the Host Agent's bound (agentspec.MaxDNSRecords)
	MaxNameservers = 8
	maxDNSName     = 253
)

// Record types.
const (
	TypeA    = "A"
	TypeAAAA = "AAAA"
)

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// DNSView is GET /tenants/{t}/dns (schema DnsView).
type DNSView struct {
	MagicDNS      bool     // always true: the platform renders dns.magic_dns and dns.base_domain (§14.5)
	BaseDomain    string   // <slug>.tail.<domain>
	Nameservers   []string // of the configuration version in force; nil when the instance has none recorded
	ConfigVersion *int32
	ETag          string // If-Match of PUT /dns/settings
	Pending       *PendingDNS
	Records       int
}

// PendingDNS is the unfinished reconfiguration of the instance (whatever asked for it).
type PendingDNS struct {
	JobID       uuid.UUID
	Status      string
	Nameservers []string // the nameservers it asks for; nil when it does not change them
}

// DNSRecord is one extra record (schema DnsRecord).
type DNSRecord struct {
	ID        uuid.UUID
	Name      string
	Type      string
	Value     netip.Addr
	CreatedBy *uuid.UUID
	CreatedAt time.Time
}

// ETag is the entity tag of a record (records are never changed — it names the content): the If-Match of DELETE.
func (r DNSRecord) ETag() string {
	sum := sha256.Sum256([]byte("dns-record/v1\n" + r.ID.String() + "\n" + r.Name + "\n" + r.Type + "\n" + r.Value.String()))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func recordOf(r sqlcdb.DnsRecord) DNSRecord {
	return DNSRecord{ID: r.ID, Name: r.Name, Type: r.Type, Value: r.Value, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt.UTC()}
}

// DNSRecordInput is the body of POST /dns/records.
type DNSRecordInput struct {
	Name  string
	Type  string
	Value string
}

// DNSRecordChange is the outcome of a record change: the record (the deleted one for a delete) and the job that writes
// the records file (an unfinished job of the tenant is reused).
type DNSRecordChange struct {
	Record DNSRecord
	Job    jobs.Job
}

// dnsETag is the entity tag of the DNS settings: the configuration version in force and its nameservers.
func dnsETag(versionID *uuid.UUID, nameservers []string) string {
	v := "none"
	if versionID != nil {
		v = versionID.String()
	}
	sum := sha256.Sum256([]byte("tenant-dns/v1\n" + v + "\n" + strings.Join(nameservers, "\n")))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// instanceOf reads the tenant's live instance with its configuration in force.
func instanceOf(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (sqlcdb.GetNetworkInstanceRow, []string, error) {
	inst, err := q.GetNetworkInstance(ctx, tenantID)
	if errors.Is(err, store.ErrNoRows) {
		return inst, nil, conflict(ReasonNoInstance, "The tenant has no running instance.")
	}
	if err != nil {
		return inst, nil, err
	}
	var ns []string
	if len(inst.Nameservers) > 0 && inst.ConfigVersionID != nil {
		if err := json.Unmarshal(inst.Nameservers, &ns); err != nil {
			ns = nil
		}
	}
	return inst, ns, nil
}

// GetDNS is GET /tenants/{t}/dns.
func (s *Service) GetDNS(ctx context.Context, tenantID uuid.UUID) (DNSView, error) {
	var out DNSView
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		inst, ns, err := instanceOf(ctx, q, tenantID)
		if err != nil {
			return err
		}
		n, err := q.CountDNSRecords(ctx, tenantID)
		if err != nil {
			return err
		}
		out = DNSView{MagicDNS: true, BaseDomain: inst.BaseDomain, Nameservers: ns, ConfigVersion: inst.ConfigVersion,
			ETag: dnsETag(inst.ConfigVersionID, ns), Records: int(n)}
		tid, iid := tenantID, inst.InstanceID
		j, err := q.GetUnfinishedReconfigure(ctx, sqlcdb.GetUnfinishedReconfigureParams{TenantID: &tid, InstanceID: &iid})
		switch {
		case errors.Is(err, store.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		p := &PendingDNS{JobID: j.ID, Status: j.Status}
		var in struct {
			Change struct {
				Nameservers []string `json:"nameservers"`
			} `json:"change"`
		}
		if json.Unmarshal(j.Input, &in) == nil {
			p.Nameservers = in.Change.Nameservers
		}
		out.Pending = p
		return nil
	})
	return out, err
}

// NormalizeNameservers checks the nameservers of PUT /dns/settings: 1..MaxNameservers usable unicast addresses
// without duplicates (the rules of instance.reconfigure — the Host Agent's validation stays the authority).
func NormalizeNameservers(in []string) ([]string, error) {
	if len(in) < 1 || len(in) > MaxNameservers {
		return nil, invalid("nameservers", "invalid_count", fmt.Sprintf("between 1 and %d nameservers", MaxNameservers))
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
			a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
			return nil, invalid("nameservers", "invalid_address", "nameservers are usable unicast IPv4 or IPv6 addresses")
		}
		if slices.Contains(out, a.String()) {
			return nil, invalid("nameservers", "duplicate_address", "a nameserver is listed twice")
		}
		out = append(out, a.String())
	}
	return out, nil
}

// UpdateDNSSettings is PUT /tenants/{t}/dns/settings: If-Match = the DNS view's etag (428/412); the nameservers are
// written into a new configuration version of the instance by instance.reconfigure — a controlled restart behind a
// health gate, rolled back when the instance does not come up (§13.2, R-19: the tenant's relayed sessions drop). It
// returns the job (created = false: the unfinished reconfiguration asking for the same change).
func (s *Service) UpdateDNSSettings(ctx context.Context, tenantID uuid.UUID, a Actor, ifMatch string, nameservers []string) (jobs.Job, bool, error) {
	ns, err := NormalizeNameservers(nameservers)
	if err != nil {
		return jobs.Job{}, false, err
	}
	if normalizeIfMatch(ifMatch) == "" {
		return jobs.Job{}, false, ifMatchRequired("DNS settings' etag")
	}
	if s.cfg.Reconfigure == nil {
		return jobs.Job{}, false, &Error{Code: CodeInternal, Reason: ReasonNotWired, Err: errors.New("network: no reconfigurer wired")}
	}
	var (
		out     jobs.Job
		created bool
	)
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		inst, cur, err := instanceOf(ctx, tx.Q, tenantID)
		if err != nil {
			return err
		}
		switch m := normalizeIfMatch(ifMatch); {
		case m != dnsETag(inst.ConfigVersionID, cur):
			return stale("stale_etag", "The DNS settings changed since they were read; read them again.")
		}
		out, created, err = s.cfg.Reconfigure(ctx, tx, ReconfigureRequest{TenantID: tenantID, InstanceID: inst.InstanceID,
			Nameservers: ns, RequestedBy: a.by(), Action: ActionDNSSettingsUpdate, Source: SourceDNSSettings})
		return err
	})
	return out, created, err
}

// ListDNSRecords is GET /tenants/{t}/dns/records: every record, in the order of the records file.
func (s *Service) ListDNSRecords(ctx context.Context, tenantID uuid.UUID) ([]DNSRecord, error) {
	out := []DNSRecord{}
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListDNSRecords(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, recordOf(r))
		}
		return nil
	})
	return out, err
}

// validDNSName reports a lower-case host name without trailing dot: LDH labels, at least two, ≤ 253 bytes, no wildcard
// (the CHECK of 0022 and the Host Agent's rule).
func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > maxDNSName {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !dnsLabelRE.MatchString(l) {
			return false
		}
	}
	return true
}

func under(name, domain string) bool {
	return domain != "" && (name == domain || strings.HasSuffix(name, "."+domain))
}

// normalizeRecord checks the shape of a record (name, type ⇔ family).
func normalizeRecord(in DNSRecordInput) (string, string, netip.Addr, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Name)), ".")
	if !validDNSName(name) {
		return "", "", netip.Addr{}, invalid("name", "invalid_name",
			"name is a lower-case host name of at least two labels (letters, digits, '-'), no wildcard, ≤ 253 characters")
	}
	if in.Type != TypeA && in.Type != TypeAAAA {
		return "", "", netip.Addr{}, invalid("type", "invalid_type", "type is A or AAAA")
	}
	v, err := netip.ParseAddr(strings.TrimSpace(in.Value))
	if err != nil || v.Zone() != "" || v.Is4In6() || v.IsUnspecified() || v.IsMulticast() || v.IsLoopback() {
		return "", "", netip.Addr{}, invalid("value", "invalid_value", "value is a unicast IP address")
	}
	if (in.Type == TypeA) != v.Is4() {
		return "", "", netip.Addr{}, invalid("value", "type_mismatch", "an A record holds an IPv4 address, an AAAA record an IPv6 address")
	}
	return name, in.Type, v, nil
}

// isExit reports an exit-node route (the whole Internet of one family).
func isExit(p netip.Prefix) bool { return p.Bits() == 0 }

// lintValue is the T-09 rule: the value must be a tailnet address of one of the tenant's devices, or inside a subnet
// route the tenant approved (an exit node's /0 does not count — that would be any address).
func lintValue(devs []sqlcdb.DeviceInventoryCache, v netip.Addr) bool {
	for _, d := range devs {
		if slices.Contains(d.IpAddresses, v) {
			return true
		}
		for _, p := range d.ApprovedRoutes {
			if !isExit(p) && p.Contains(v) {
				return true
			}
		}
	}
	return false
}

// enqueueRecordsWrite enqueues dns.records_write in tx (written if and only if the change commits; an unfinished job of
// the tenant is reused — it reads the records when it runs) and returns its projection.
func enqueueRecordsWrite(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, by *uuid.UUID) (jobs.Job, error) {
	e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindDNSRecordsWrite, TenantID: &tenantID, RequestedBy: by,
		Resource: &jobs.Resource{Type: "dns_records", ID: tenantID.String()}})
	if err != nil {
		return jobs.Job{}, fmt.Errorf("network: enqueue %s: %w", KindDNSRecordsWrite, err)
	}
	return jobs.ProjectTx(ctx, tx.Q, e.Job.ID)
}

// CreateDNSRecord is POST /tenants/{t}/dns/records: the record is checked (shape; a name under the platform's domain
// only inside the tenant's MagicDNS domain; T-09: the value is an address of the tailnet or of an approved route), at
// most MaxDNSRecords, stored with its audit event and the dns.records_write job in one transaction. With an
// Idempotency-Key, a replay returns the record of the first request.
func (s *Service) CreateDNSRecord(ctx context.Context, tenantID uuid.UUID, a Actor, in DNSRecordInput, idem *Idempotency) (DNSRecordChange, error) {
	name, typ, value, err := normalizeRecord(in)
	if err != nil {
		return DNSRecordChange{}, err
	}
	if s.cfg.Devices == nil {
		return DNSRecordChange{}, &Error{Code: CodeInternal, Reason: ReasonNotWired, Err: errors.New("network: no device register wired")}
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{TenantID: &tenantID, IdentityID: a.IdentityID, OperationID: createDNSRecordOperation, Key: idem.Key}
		var stored storedRecord
		replayed, err := s.beginIdempotent(ctx, tenantID, *key, idem.Hash, &stored)
		if err != nil {
			return DNSRecordChange{}, err
		}
		if replayed {
			return s.replayRecord(ctx, tenantID, stored)
		}
	}
	var out DNSRecordChange
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		inst, _, err := instanceOf(ctx, q, tenantID)
		if err != nil {
			return err
		}
		if under(name, s.cfg.BaseDomain) && !under(name, inst.BaseDomain) {
			return invalid("name", "name_platform_domain", "a name under the platform's domain is accepted only inside the tenant's MagicDNS domain "+inst.BaseDomain)
		}
		devs, err := s.cfg.Devices.ListLive(ctx, q, tenantID)
		if err != nil {
			return err
		}
		if !lintValue(devs, value) {
			return invalid("value", "value_not_in_tailnet",
				"value must be the tailnet address of one of the tenant's devices or inside a subnet route the tenant approved")
		}
		if err := q.LockDNSRecordSet(ctx, tenantID); err != nil {
			return err
		}
		n, err := q.CountDNSRecords(ctx, tenantID)
		if err != nil {
			return err
		}
		if n >= MaxDNSRecords {
			return conflict("too_many_records", fmt.Sprintf("The tenant already has %d records, the maximum.", MaxDNSRecords))
		}
		row, err := q.InsertDNSRecord(ctx, sqlcdb.InsertDNSRecordParams{TenantID: tenantID, Name: name, Type: typ, Value: value,
			CreatedBy: a.by()})
		if store.SQLState(err) == "23505" {
			return conflict("record_exists", "The same record (name, type, value) already exists.")
		}
		if err != nil {
			return err
		}
		j, err := enqueueRecordsWrite(ctx, tx, tenantID, a.by())
		if err != nil {
			return err
		}
		t := tenantID
		if err := audit.Record(ctx, q, audit.Event{Action: ActionDNSRecordCreate, TenantID: &t, ResourceType: resourceDNSRecord,
			ResourceID: row.ID.String(), Details: audit.Details{"record_id": row.ID, "name": name, "type": typ,
				"value": value.String(), "job_id": j.ID}}); err != nil {
			return err
		}
		out = DNSRecordChange{Record: recordOf(row), Job: j}
		if key != nil {
			return completeIdempotent(ctx, q, *key, idem.Hash, 201, storedRecord{ID: row.ID, JobID: j.ID},
				&jobs.Resource{Type: resourceDNSRecord, ID: row.ID.String()})
		}
		return nil
	})
	if err != nil {
		if key != nil {
			s.failIdempotent(ctx, tenantID, *key, idem.Hash)
		}
		return DNSRecordChange{}, err
	}
	return out, nil
}

// storedRecord is the replay body of a create.
type storedRecord struct {
	ID    uuid.UUID `json:"id"`
	JobID uuid.UUID `json:"job_id"`
}

func (s *Service) replayRecord(ctx context.Context, tenantID uuid.UUID, st storedRecord) (DNSRecordChange, error) {
	var out DNSRecordChange
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetDNSRecord(ctx, sqlcdb.GetDNSRecordParams{TenantID: tenantID, ID: st.ID})
		if errors.Is(err, store.ErrNoRows) {
			return notFound("record_not_found") // deleted since the first request
		}
		if err != nil {
			return err
		}
		j, err := jobs.ProjectTx(ctx, q, st.JobID)
		if err != nil {
			return err
		}
		out = DNSRecordChange{Record: recordOf(r), Job: j}
		t := tenantID
		return audit.Record(ctx, q, audit.Event{Action: ActionDNSRecordCreate, TenantID: &t, ResourceType: resourceDNSRecord,
			ResourceID: r.ID.String(), Details: audit.Details{"record_id": r.ID, "replay": true}})
	})
	return out, err
}

// DeleteDNSRecord is DELETE /tenants/{t}/dns/records/{id} (If-Match = the record's etag — 428/412): the record, its
// audit event and the dns.records_write job in one transaction (the last record deleted ⇒ the file holds []).
func (s *Service) DeleteDNSRecord(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch string) (DNSRecordChange, error) {
	match := normalizeIfMatch(ifMatch)
	var out DNSRecordChange
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		if err := q.LockDNSRecordSet(ctx, tenantID); err != nil {
			return err
		}
		// the record first: another tenant's or a missing one is 404 whatever the request (§8.4 invariant 6)
		if _, err := q.GetDNSRecord(ctx, sqlcdb.GetDNSRecordParams{TenantID: tenantID, ID: id}); errors.Is(err, store.ErrNoRows) {
			return notFound("record_not_found")
		} else if err != nil {
			return err
		}
		if match == "" {
			return ifMatchRequired("record's etag")
		}
		row, err := q.DeleteDNSRecord(ctx, sqlcdb.DeleteDNSRecordParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return notFound("record_not_found")
		}
		if err != nil {
			return err
		}
		if recordOf(row).ETag() != match {
			return stale("stale_etag", "The record is not the one that was read; read the records again.")
		}
		j, err := enqueueRecordsWrite(ctx, tx, tenantID, a.by())
		if err != nil {
			return err
		}
		t := tenantID
		if err := audit.Record(ctx, q, audit.Event{Action: ActionDNSRecordDelete, TenantID: &t, ResourceType: resourceDNSRecord,
			ResourceID: id.String(), Details: audit.Details{"record_id": id, "name": row.Name, "type": row.Type,
				"value": row.Value.String(), "job_id": j.ID}}); err != nil {
			return err
		}
		out = DNSRecordChange{Record: recordOf(row), Job: j}
		return nil
	})
	return out, err
}
