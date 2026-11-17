package agentspec

import (
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// Bounds of the closed parameter sets. A value outside them is refused (REFUSAL_REASON_OUT_OF_BOUNDS or
// REFUSAL_REASON_TOO_LARGE); the gRPC server also caps a whole message at MaxMessageBytes.
const (
	MaxMessageBytes  = 1 << 20   // gRPC MaxRecvMsgSize of the agent
	MaxPolicyBytes   = 256 << 10 // HuJSON policy set by Restore
	MaxDNSRecords    = 1024
	MaxNameservers   = 8
	MaxListItems     = 10000 // machine keys, nodes, offboarded users of a reconcile plan
	MaxRoutesPerNode = 256
	MaxTagsPerNode   = 64
	DataKeyBytes     = 32
	MinMemoryMiB     = 64
	MaxMemoryMiB     = 16384
	MinCPUMillis     = 100
	MaxCPUMillis     = 16000
	MinPIDs          = 32
	MaxPIDs          = 4096
	MaxNodeExpiry    = 3650 // days
	MinDERPRegionID  = 900
	MaxDERPRegionID  = 999
	MinKeyTTL        = 24 * time.Hour
	MaxKeyTTL        = 8760 * time.Hour
)

var (
	slugRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`) // §11.3 step 1, render_instance.py SLUG_RE
	sha256HexRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyPrefixRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{12}$`) // Headscale API key prefix (URL-safe, 12 — RT-12)
	machineKeyRE = regexp.MustCompile(`^mkey:[0-9a-f]{64}$`)
	tagRE        = regexp.MustCompile(`^tag:[a-z][a-z0-9-]{0,62}$`)
	dnsLabelRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Ref is a validated InstanceRef.
type Ref struct {
	InstanceID uuid.UUID
	TenantID   uuid.UUID
	Slug       string
}

// Limits are validated ResourceLimits.
type Limits struct{ MemoryMiB, CPUMillis, PIDs uint32 }

// HeadscaleParams are validated tenant values of config.yaml.
type HeadscaleParams struct {
	NodeExpiryDays uint32
	Nameservers    []netip.Addr
	DERPRegionID   uint32
	PublicEntry    netip.Addr
	LogLevel       string // info | warn | error
	STUNPort       uint32 // 0: shared STUN (no per-tenant port)
}

// InstanceSpec is a validated InstanceSpec; Image is resolved through the allowlist.
type InstanceSpec struct {
	Ref       Ref
	Image     AllowedImage
	RunUID    uint32
	NetCIDR   netip.Prefix
	Limits    Limits
	Headscale HeadscaleParams
}

// Ensure is a validated EnsureInstanceRequest.
type Ensure struct {
	Spec   InstanceSpec
	Phase  agentv1.TargetPhase
	JobID  uuid.UUID
	DryRun bool
}

// Call is a validated request that names one existing instance (start, stop, restart, edge attachment…).
type Call struct {
	Ref   Ref
	JobID uuid.UUID
}

// Remove is a validated RemoveInstanceRequest.
type Remove struct {
	Call
	Data            agentv1.DataDisposition
	ArchiveSequence uint64
}

// Upgrade is a validated UpgradeInstanceRequest.
type Upgrade struct {
	Call
	From, To AllowedImage
}

// DNSRecord is a validated record.
type DNSRecord struct {
	Name  string
	Type  string // A | AAAA
	Value netip.Addr
}

// DNSRecords is a validated WriteDnsRecordsRequest.
type DNSRecords struct {
	Call
	Records []DNSRecord
}

// APIKey is a validated BootstrapApiKeyRequest.
type APIKey struct {
	Call
	TTL        time.Duration
	KeepPrefix string
}

// Backup is a validated BackupRequest. DataKey is a secret.
type Backup struct {
	Call
	Sequence uint64
	DataKey  []byte
}

// Restore is a validated RestoreRequest. DataKey is a secret; Policy is nil when KeepBackupPolicy.
type Restore struct {
	Call
	Sequence         uint64
	ArchiveSHA256    string
	ManifestSHA256   string
	DataKey          []byte
	Policy           []byte
	KeepBackupPolicy bool
}

// NodeState is a validated NodeDesiredState.
type NodeState struct {
	MachineKey     string
	ApprovedRoutes []netip.Prefix
	Tags           []string
}

// Reconcile is a validated PostRestoreReconcileRequest.
type Reconcile struct {
	Call
	APIKeyTTL           time.Duration
	RevokedMachineKeys  []string
	Nodes               []NodeState
	OffboardedUsers     []string
	RestorePointIsOlder bool
}

// EdgeDetach is a validated RemoveEdgeAttachmentRequest.
type EdgeDetach struct {
	Call
	Reason agentv1.EdgeDetachReason
}

// Validator validates requests against the host configuration.
type Validator struct{ Host *Host }

// ---------------------------------------------------------------------------------------------------- building blocks

// UUID accepts only the canonical lower-case form of a non-nil UUID: "../x", "{…}", "urn:uuid:…" and upper case
// are refused, so an id can be used as a path element.
func UUID(field, s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, missing(field)
	}
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil || id.String() != s {
		return uuid.Nil, refuse(agentv1.RefusalReason_REFUSAL_REASON_INVALID_ID, field, "not a canonical lower-case UUID")
	}
	return id, nil
}

func (v *Validator) slug(field, s string) error {
	switch {
	case s == "":
		return missing(field)
	case !slugRE.MatchString(s), strings.Contains(s, "--"), strings.HasPrefix(s, "xn--"):
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_INVALID_SLUG, field, "must match ^[a-z][a-z0-9-]{1,30}[a-z0-9]$ without -- or xn--")
	case v.Host.slugReserved(s):
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_INVALID_SLUG, field, "reserved name")
	}
	return nil
}

// Ref validates an InstanceRef.
func (v *Validator) Ref(field string, r *agentv1.InstanceRef) (Ref, error) {
	if r == nil {
		return Ref{}, missing(field)
	}
	iid, err := UUID(join(field, "instance_id"), r.GetInstanceId())
	if err != nil {
		return Ref{}, err
	}
	tid, err := UUID(join(field, "tenant_id"), r.GetTenantId())
	if err != nil {
		return Ref{}, err
	}
	if iid == tid {
		return Ref{}, refuse(agentv1.RefusalReason_REFUSAL_REASON_INVALID_ID, join(field, "tenant_id"), "equals instance_id")
	}
	if err := v.slug(join(field, "slug"), r.GetSlug()); err != nil {
		return Ref{}, err
	}
	return Ref{InstanceID: iid, TenantID: tid, Slug: r.GetSlug()}, nil
}

func (v *Validator) call(r *agentv1.InstanceRef, jobID string) (Call, error) {
	ref, err := v.Ref("instance", r)
	if err != nil {
		return Call{}, err
	}
	job, err := UUID("job_id", jobID)
	if err != nil {
		return Call{}, err
	}
	return Call{Ref: ref, JobID: job}, nil
}

// Image resolves a digest through the allowlist.
func (v *Validator) Image(field, digest string) (AllowedImage, error) {
	if digest == "" {
		return AllowedImage{}, missing(field)
	}
	if !digestRE.MatchString(digest) {
		return AllowedImage{}, malformed(field, "want sha256:<64 lower-case hex>")
	}
	img, ok := v.Host.Images.Lookup(digest)
	if !ok {
		return AllowedImage{}, refuse(agentv1.RefusalReason_REFUSAL_REASON_IMAGE_NOT_ALLOWED, field, "digest not in the agent's allowlist")
	}
	return img, nil
}

func (v *Validator) runUID(field string, uid uint32) error {
	if uid == 0 || !v.Host.RunUIDs.Contains(uid) {
		return refuse(agentv1.RefusalReason_REFUSAL_REASON_UID_OUT_OF_RANGE, field, "not in the host's run_uid range %s", v.Host.RunUIDs)
	}
	return nil
}

func (v *Validator) netCIDR(field, s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, missing(field)
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.String() != s {
		return netip.Prefix{}, malformed(field, "want a canonical IPv4 CIDR")
	}
	if p.Bits() != 29 || p != p.Masked() || !v.Host.TenantPool.Contains(p.Addr()) {
		return netip.Prefix{}, refuse(agentv1.RefusalReason_REFUSAL_REASON_NETWORK_OUT_OF_POOL, field,
			"want a /29 network address inside the host's tenant pool %s", v.Host.TenantPool)
	}
	return p, nil
}

func ipAddr(field, s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, missing(field)
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.String() != s {
		return netip.Addr{}, malformed(field, "want a canonical IP address")
	}
	return a, nil
}

func ttl(field string, d *durationpb.Duration) (time.Duration, error) {
	if d == nil {
		return 0, missing(field)
	}
	if err := d.CheckValid(); err != nil {
		return 0, malformed(field, "invalid duration")
	}
	t := d.AsDuration()
	if t%time.Hour != 0 || t < MinKeyTTL || t > MaxKeyTTL {
		return 0, outOfBounds(field, "whole hours between %s and %s", MinKeyTTL, MaxKeyTTL)
	}
	return t, nil
}

func sha256Hex(field, s string) error {
	if s == "" {
		return missing(field)
	}
	if !sha256HexRE.MatchString(s) {
		return malformed(field, "want 64 lower-case hex digits")
	}
	return nil
}

func dataKey(field string, k []byte) ([]byte, error) {
	if len(k) == 0 {
		return nil, missing(field)
	}
	if len(k) != DataKeyBytes {
		return nil, malformed(field, "want exactly %d bytes", DataKeyBytes)
	}
	return append([]byte(nil), k...), nil
}

// ---------------------------------------------------------------------------------------------------- instance spec

// Spec validates an InstanceSpec.
func (v *Validator) Spec(field string, s *agentv1.InstanceSpec) (InstanceSpec, error) {
	if s == nil {
		return InstanceSpec{}, missing(field)
	}
	var out InstanceSpec
	var err error
	if out.Ref, err = v.Ref(join(field, "instance"), s.GetInstance()); err != nil {
		return InstanceSpec{}, err
	}
	if out.Image, err = v.Image(join(field, "image_digest"), s.GetImageDigest()); err != nil {
		return InstanceSpec{}, err
	}
	if err = v.runUID(join(field, "run_uid"), s.GetRunUid()); err != nil {
		return InstanceSpec{}, err
	}
	out.RunUID = s.GetRunUid()
	if out.NetCIDR, err = v.netCIDR(join(field, "net_cidr"), s.GetNetCidr()); err != nil {
		return InstanceSpec{}, err
	}
	if out.Limits, err = limits(join(field, "limits"), s.GetLimits()); err != nil {
		return InstanceSpec{}, err
	}
	if out.Headscale, err = v.headscale(join(field, "headscale"), s.GetHeadscale()); err != nil {
		return InstanceSpec{}, err
	}
	return out, nil
}

func limits(field string, l *agentv1.ResourceLimits) (Limits, error) {
	if l == nil {
		return Limits{}, missing(field)
	}
	for _, c := range []struct {
		name    string
		v, a, b uint32
	}{
		{"memory_mib", l.GetMemoryMib(), MinMemoryMiB, MaxMemoryMiB},
		{"cpu_millis", l.GetCpuMillis(), MinCPUMillis, MaxCPUMillis},
		{"pids", l.GetPids(), MinPIDs, MaxPIDs},
	} {
		if c.v < c.a || c.v > c.b {
			return Limits{}, outOfBounds(join(field, c.name), "must lie within %d..%d", c.a, c.b)
		}
	}
	return Limits{MemoryMiB: l.GetMemoryMib(), CPUMillis: l.GetCpuMillis(), PIDs: l.GetPids()}, nil
}

var logLevels = map[agentv1.LogLevel]string{
	agentv1.LogLevel_LOG_LEVEL_INFO:  "info",
	agentv1.LogLevel_LOG_LEVEL_WARN:  "warn",
	agentv1.LogLevel_LOG_LEVEL_ERROR: "error",
}

func (v *Validator) headscale(field string, p *agentv1.HeadscaleParams) (HeadscaleParams, error) {
	if p == nil {
		return HeadscaleParams{}, missing(field)
	}
	var out HeadscaleParams
	if d := p.GetNodeExpiryDays(); d < 1 || d > MaxNodeExpiry {
		return out, outOfBounds(join(field, "node_expiry_days"), "must lie within 1..%d", MaxNodeExpiry)
	}
	out.NodeExpiryDays = p.GetNodeExpiryDays()
	ns := p.GetNameservers()
	switch {
	case len(ns) == 0:
		return out, missing(join(field, "nameservers"))
	case len(ns) > MaxNameservers:
		return out, tooLarge(join(field, "nameservers"), len(ns), MaxNameservers)
	}
	seen := map[netip.Addr]bool{}
	for i, s := range ns {
		f := index(join(field, "nameservers"), i)
		a, err := ipAddr(f, s)
		if err != nil {
			return out, err
		}
		if !usableUnicast(a) || a.Is4In6() || v.Host.TenantPool.Contains(a) {
			return out, outOfBounds(f, "want a unicast address outside the tenant pool")
		}
		if seen[a] {
			return out, malformed(f, "duplicate")
		}
		seen[a] = true
		out.Nameservers = append(out.Nameservers, a)
	}
	if r := p.GetDerpRegionId(); r < MinDERPRegionID || r > MaxDERPRegionID {
		return out, outOfBounds(join(field, "derp_region_id"), "must lie within %d..%d", MinDERPRegionID, MaxDERPRegionID)
	}
	out.DERPRegionID = p.GetDerpRegionId()
	pe, err := ipAddr(join(field, "public_entry_ipv4"), p.GetPublicEntryIpv4())
	if err != nil {
		return out, err
	}
	if pe != v.Host.PublicEntry {
		return out, refuse(agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, join(field, "public_entry_ipv4"),
			"differs from the public entry configured on this host")
	}
	out.PublicEntry = pe
	lvl, ok := logLevels[p.GetLogLevel()]
	if !ok {
		return out, missing(join(field, "log_level"))
	}
	out.LogLevel = lvl
	if p.StunPort != nil {
		f := join(field, "stun_port")
		if v.Host.STUNPorts == nil || !v.Host.STUNPorts.Contains(p.GetStunPort()) {
			return out, refuse(agentv1.RefusalReason_REFUSAL_REASON_PORT_OUT_OF_RANGE, f, "not in the host's STUN port range (none in the shared-STUN design)")
		}
		out.STUNPort = p.GetStunPort()
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------- requests

// ValidateConfig validates a ValidateConfigRequest.
func (v *Validator) ValidateConfig(r *agentv1.ValidateConfigRequest) (InstanceSpec, uuid.UUID, error) {
	spec, err := v.Spec("spec", r.GetSpec())
	if err != nil {
		return InstanceSpec{}, uuid.Nil, err
	}
	job, err := UUID("job_id", r.GetJobId())
	if err != nil {
		return InstanceSpec{}, uuid.Nil, err
	}
	return spec, job, nil
}

// EnsureInstance validates an EnsureInstanceRequest.
func (v *Validator) EnsureInstance(r *agentv1.EnsureInstanceRequest) (Ensure, error) {
	spec, err := v.Spec("spec", r.GetSpec())
	if err != nil {
		return Ensure{}, err
	}
	if r.GetTargetPhase() == agentv1.TargetPhase_TARGET_PHASE_UNSPECIFIED {
		return Ensure{}, missing("target_phase")
	}
	job, err := UUID("job_id", r.GetJobId())
	if err != nil {
		return Ensure{}, err
	}
	return Ensure{Spec: spec, Phase: r.GetTargetPhase(), JobID: job, DryRun: r.GetDryRun()}, nil
}

// GetInstanceStatus validates a GetInstanceStatusRequest (read-only: no job id).
func (v *Validator) GetInstanceStatus(r *agentv1.GetInstanceStatusRequest) (Ref, error) {
	return v.Ref("instance", r.GetInstance())
}

// Call validates the requests that only name an instance and a job: start, stop, restart, edge attachment.
func (v *Validator) Call(r interface {
	GetInstance() *agentv1.InstanceRef
	GetJobId() string
}) (Call, error) {
	return v.call(r.GetInstance(), r.GetJobId())
}

// RemoveInstance validates a RemoveInstanceRequest.
func (v *Validator) RemoveInstance(r *agentv1.RemoveInstanceRequest) (Remove, error) {
	c, err := v.Call(r)
	if err != nil {
		return Remove{}, err
	}
	switch r.GetData() {
	case agentv1.DataDisposition_DATA_DISPOSITION_UNSPECIFIED:
		return Remove{}, missing("data")
	case agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED:
		if r.GetArchivedBackupSequence() == 0 {
			return Remove{}, missing("archived_backup_sequence")
		}
	default:
		if r.GetArchivedBackupSequence() != 0 {
			return Remove{}, malformed("archived_backup_sequence", "only with DATA_DISPOSITION_DELETE_ARCHIVED")
		}
	}
	return Remove{Call: c, Data: r.GetData(), ArchiveSequence: r.GetArchivedBackupSequence()}, nil
}

// UpgradeInstance validates an UpgradeInstanceRequest: both digests must be allowed (§11.4).
func (v *Validator) UpgradeInstance(r *agentv1.UpgradeInstanceRequest) (Upgrade, error) {
	c, err := v.Call(r)
	if err != nil {
		return Upgrade{}, err
	}
	from, err := v.Image("from_image_digest", r.GetFromImageDigest())
	if err != nil {
		return Upgrade{}, err
	}
	to, err := v.Image("to_image_digest", r.GetToImageDigest())
	if err != nil {
		return Upgrade{}, err
	}
	if from == to {
		return Upgrade{}, malformed("to_image_digest", "equals from_image_digest")
	}
	return Upgrade{Call: c, From: from, To: to}, nil
}

var dnsTypes = map[agentv1.DnsRecordType]string{
	agentv1.DnsRecordType_DNS_RECORD_TYPE_A:    "A",
	agentv1.DnsRecordType_DNS_RECORD_TYPE_AAAA: "AAAA",
}

// WriteDNSRecords validates a WriteDnsRecordsRequest. Names under the platform domain are accepted only inside the
// tenant's own MagicDNS domain <slug>.tail.<domain>.
func (v *Validator) WriteDNSRecords(r *agentv1.WriteDnsRecordsRequest) (DNSRecords, error) {
	c, err := v.Call(r)
	if err != nil {
		return DNSRecords{}, err
	}
	recs := r.GetRecords()
	if len(recs) > MaxDNSRecords {
		return DNSRecords{}, tooLarge("records", len(recs), MaxDNSRecords)
	}
	own := c.Ref.Slug + ".tail." + v.Host.BaseDomain
	type key struct{ name, typ, value string }
	seen := map[key]bool{}
	out := DNSRecords{Call: c, Records: make([]DNSRecord, 0, len(recs))}
	for i, rec := range recs {
		f := index("records", i)
		if rec == nil {
			return DNSRecords{}, missing(f)
		}
		name := rec.GetName()
		if !hostname(name) {
			return DNSRecords{}, malformed(join(f, "name"), "want a lower-case host name (LDH labels, at least two, at most 253 bytes)")
		}
		if under(name, v.Host.BaseDomain) && !under(name, own) {
			return DNSRecords{}, outOfBounds(join(f, "name"), "under the platform domain only inside the tenant's own <slug>.tail.<domain>")
		}
		typ, ok := dnsTypes[rec.GetType()]
		if !ok {
			return DNSRecords{}, missing(join(f, "type"))
		}
		a, err := ipAddr(join(f, "value"), rec.GetValue())
		if err != nil {
			return DNSRecords{}, err
		}
		if (typ == "A") != a.Is4() || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return DNSRecords{}, malformed(join(f, "value"), "want a unicast IPv4 for A, IPv6 for AAAA")
		}
		k := key{name, typ, a.String()}
		if seen[k] {
			return DNSRecords{}, malformed(f, "duplicate record")
		}
		seen[k] = true
		out.Records = append(out.Records, DNSRecord{Name: name, Type: typ, Value: a})
	}
	return out, nil
}

func hostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
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

func under(name, domain string) bool { return name == domain || strings.HasSuffix(name, "."+domain) }

// BootstrapPolicy validates a BootstrapPolicyRequest.
func (v *Validator) BootstrapPolicy(r *agentv1.BootstrapPolicyRequest) (Call, agentv1.PolicyKind, error) {
	c, err := v.Call(r)
	if err != nil {
		return Call{}, 0, err
	}
	if r.GetPolicy() == agentv1.PolicyKind_POLICY_KIND_UNSPECIFIED {
		return Call{}, 0, missing("policy")
	}
	return c, r.GetPolicy(), nil
}

// BootstrapAPIKey validates a BootstrapApiKeyRequest.
func (v *Validator) BootstrapAPIKey(r *agentv1.BootstrapApiKeyRequest) (APIKey, error) {
	c, err := v.Call(r)
	if err != nil {
		return APIKey{}, err
	}
	t, err := ttl("ttl", r.GetTtl())
	if err != nil {
		return APIKey{}, err
	}
	if p := r.GetKeepPrefix(); p != "" && !keyPrefixRE.MatchString(p) {
		return APIKey{}, malformed("keep_prefix", "want the 12-character public prefix of a Headscale API key")
	}
	return APIKey{Call: c, TTL: t, KeepPrefix: r.GetKeepPrefix()}, nil
}

// Backup validates a BackupRequest.
func (v *Validator) Backup(r *agentv1.BackupRequest) (Backup, error) {
	c, err := v.Call(r)
	if err != nil {
		return Backup{}, err
	}
	if r.GetSequence() == 0 {
		return Backup{}, outOfBounds("sequence", "must be at least 1")
	}
	k, err := dataKey("data_key", r.GetDataKey())
	if err != nil {
		return Backup{}, err
	}
	return Backup{Call: c, Sequence: r.GetSequence(), DataKey: k}, nil
}

// Restore validates a RestoreRequest. The archive is always one of the same instance (path derived from the
// instance_id); the agent checks its signed manifest before decrypting (T-15).
func (v *Validator) Restore(r *agentv1.RestoreRequest) (Restore, error) {
	c, err := v.Call(r)
	if err != nil {
		return Restore{}, err
	}
	a := r.GetArtifact()
	if a == nil {
		return Restore{}, missing("artifact")
	}
	if a.GetSequence() == 0 {
		return Restore{}, outOfBounds("artifact.sequence", "must be at least 1")
	}
	if err := sha256Hex("artifact.archive_sha256", a.GetArchiveSha256()); err != nil {
		return Restore{}, err
	}
	if err := sha256Hex("artifact.manifest_sha256", a.GetManifestSha256()); err != nil {
		return Restore{}, err
	}
	k, err := dataKey("data_key", r.GetDataKey())
	if err != nil {
		return Restore{}, err
	}
	out := Restore{Call: c, Sequence: a.GetSequence(), ArchiveSHA256: a.GetArchiveSha256(),
		ManifestSHA256: a.GetManifestSha256(), DataKey: k}
	switch p := r.GetPolicy().(type) {
	case *agentv1.RestoreRequest_AppliedPolicyHujson:
		b := p.AppliedPolicyHujson
		switch {
		case len(b) == 0:
			return Restore{}, missing("applied_policy_hujson")
		case len(b) > MaxPolicyBytes:
			return Restore{}, tooLarge("applied_policy_hujson", len(b), MaxPolicyBytes)
		case !utf8.Valid(b), strings.ContainsRune(string(b), 0):
			return Restore{}, malformed("applied_policy_hujson", "want UTF-8 text without NUL")
		}
		out.Policy = append([]byte(nil), b...)
	case *agentv1.RestoreRequest_KeepBackupPolicy:
		if !p.KeepBackupPolicy {
			return Restore{}, malformed("keep_backup_policy", "must be true when set")
		}
		out.KeepBackupPolicy = true
	default:
		return Restore{}, missing("policy")
	}
	return out, nil
}

// PostRestoreReconcile validates a PostRestoreReconcileRequest.
func (v *Validator) PostRestoreReconcile(r *agentv1.PostRestoreReconcileRequest) (Reconcile, error) {
	c, err := v.Call(r)
	if err != nil {
		return Reconcile{}, err
	}
	p := r.GetPlan()
	if p == nil {
		return Reconcile{}, missing("plan")
	}
	out := Reconcile{Call: c, RestorePointIsOlder: p.GetRestorePointOlderThanBackup()}
	if out.APIKeyTTL, err = ttl("plan.api_key_ttl", p.GetApiKeyTtl()); err != nil {
		return Reconcile{}, err
	}
	if out.RevokedMachineKeys, err = uniqueStrings("plan.revoked_machine_keys", p.GetRevokedMachineKeys(), MaxListItems,
		machineKeyRE, "want mkey:<64 lower-case hex>"); err != nil {
		return Reconcile{}, err
	}
	nodes := p.GetNodes()
	if len(nodes) > MaxListItems {
		return Reconcile{}, tooLarge("plan.nodes", len(nodes), MaxListItems)
	}
	seen := map[string]bool{}
	for i, n := range nodes {
		f := index("plan.nodes", i)
		if n == nil {
			return Reconcile{}, missing(f)
		}
		if !machineKeyRE.MatchString(n.GetMachineKey()) {
			return Reconcile{}, malformed(join(f, "machine_key"), "want mkey:<64 lower-case hex>")
		}
		if seen[n.GetMachineKey()] {
			return Reconcile{}, malformed(join(f, "machine_key"), "duplicate")
		}
		seen[n.GetMachineKey()] = true
		ns := NodeState{MachineKey: n.GetMachineKey()}
		routes := n.GetApprovedRoutes()
		if len(routes) > MaxRoutesPerNode {
			return Reconcile{}, tooLarge(join(f, "approved_routes"), len(routes), MaxRoutesPerNode)
		}
		seenRoute := map[netip.Prefix]bool{}
		for j, s := range routes {
			rf := index(join(f, "approved_routes"), j)
			pfx, err := netip.ParsePrefix(s)
			if err != nil || pfx.String() != s || pfx != pfx.Masked() || seenRoute[pfx] {
				return Reconcile{}, malformed(rf, "want a canonical, distinct CIDR")
			}
			seenRoute[pfx] = true
			ns.ApprovedRoutes = append(ns.ApprovedRoutes, pfx)
		}
		if ns.Tags, err = uniqueStrings(join(f, "tags"), n.GetTags(), MaxTagsPerNode, tagRE, "want tag:<lower-case name>"); err != nil {
			return Reconcile{}, err
		}
		out.Nodes = append(out.Nodes, ns)
	}
	users := p.GetOffboardedUsers()
	if len(users) > MaxListItems {
		return Reconcile{}, tooLarge("plan.offboarded_users", len(users), MaxListItems)
	}
	seenUser := map[string]bool{}
	for i, u := range users {
		f := index("plan.offboarded_users", i)
		rest, ok := strings.CutPrefix(u, "mg-")
		if !ok {
			return Reconcile{}, malformed(f, "want mg-<membership uuid>")
		}
		if _, err := UUID(f, rest); err != nil {
			return Reconcile{}, err
		}
		if seenUser[u] {
			return Reconcile{}, malformed(f, "duplicate")
		}
		seenUser[u] = true
		out.OffboardedUsers = append(out.OffboardedUsers, u)
	}
	return out, nil
}

func uniqueStrings(field string, in []string, max int, re *regexp.Regexp, want string) ([]string, error) {
	if len(in) > max {
		return nil, tooLarge(field, len(in), max)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for i, s := range in {
		f := index(field, i)
		if !re.MatchString(s) {
			return nil, malformed(f, "%s", want)
		}
		if seen[s] {
			return nil, malformed(f, "duplicate")
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// RemoveEdgeAttachment validates a RemoveEdgeAttachmentRequest.
func (v *Validator) RemoveEdgeAttachment(r *agentv1.RemoveEdgeAttachmentRequest) (EdgeDetach, error) {
	c, err := v.Call(r)
	if err != nil {
		return EdgeDetach{}, err
	}
	if r.GetReason() == agentv1.EdgeDetachReason_EDGE_DETACH_REASON_UNSPECIFIED {
		return EdgeDetach{}, missing("reason")
	}
	return EdgeDetach{Call: c, Reason: r.GetReason()}, nil
}
