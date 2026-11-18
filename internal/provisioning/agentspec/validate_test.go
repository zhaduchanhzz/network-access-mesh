package agentspec

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

func timeHours(h int64) time.Duration { return time.Duration(h) * time.Hour }

const (
	rMalformed = agentv1.RefusalReason_REFUSAL_REASON_MALFORMED
	rID        = agentv1.RefusalReason_REFUSAL_REASON_INVALID_ID
	rSlug      = agentv1.RefusalReason_REFUSAL_REASON_INVALID_SLUG
	rImage     = agentv1.RefusalReason_REFUSAL_REASON_IMAGE_NOT_ALLOWED
	rUID       = agentv1.RefusalReason_REFUSAL_REASON_UID_OUT_OF_RANGE
	rNet       = agentv1.RefusalReason_REFUSAL_REASON_NETWORK_OUT_OF_POOL
	rPort      = agentv1.RefusalReason_REFUSAL_REASON_PORT_OUT_OF_RANGE
	rBounds    = agentv1.RefusalReason_REFUSAL_REASON_OUT_OF_BOUNDS
	rLarge     = agentv1.RefusalReason_REFUSAL_REASON_TOO_LARGE
	rConflict  = agentv1.RefusalReason_REFUSAL_REASON_CONFLICT
)

func TestEnsureInstanceAcceptsTheGoodSpec(t *testing.T) {
	v := &Validator{Host: testHost(t)}
	e, err := v.EnsureInstance(goodEnsure())
	if err != nil {
		t.Fatal(err)
	}
	if e.Spec.Image.Reference() != repo+"@"+digestA || e.Spec.Ref.Slug != "acme" || e.Spec.RunUID != 30001 ||
		e.Spec.NetCIDR != netip.MustParsePrefix("10.250.0.8/29") || e.Spec.Headscale.LogLevel != "info" ||
		len(e.Spec.Headscale.Nameservers) != 2 || e.JobID.String() != jobID || e.Spec.Headscale.STUNPort != 0 {
		t.Fatalf("validated spec = %+v", e)
	}
}

// TestEnsureInstanceRefusals is the main negative table (P3-T01 verification): wrong digest, path traversal in ids
// and slugs, out-of-range uid/port, bad networks, bounds, sizes, missing fields. Every refusal names the field.
func TestEnsureInstanceRefusals(t *testing.T) {
	type mut = func(r *agentv1.EnsureInstanceRequest)
	ref := func(f func(r *agentv1.InstanceRef)) mut {
		return func(r *agentv1.EnsureInstanceRequest) { f(r.Spec.Instance) }
	}
	spec := func(f func(s *agentv1.InstanceSpec)) mut { return func(r *agentv1.EnsureInstanceRequest) { f(r.Spec) } }
	hs := func(f func(h *agentv1.HeadscaleParams)) mut {
		return func(r *agentv1.EnsureInstanceRequest) { f(r.Spec.Headscale) }
	}
	lim := func(f func(l *agentv1.ResourceLimits)) mut {
		return func(r *agentv1.EnsureInstanceRequest) { f(r.Spec.Limits) }
	}
	cases := []struct {
		name   string
		mut    mut
		reason agentv1.RefusalReason
		field  string
	}{
		{"no spec", func(r *agentv1.EnsureInstanceRequest) { r.Spec = nil }, rMalformed, "spec"},
		{"no instance", spec(func(s *agentv1.InstanceSpec) { s.Instance = nil }), rMalformed, "spec.instance"},
		{"empty instance_id", ref(func(r *agentv1.InstanceRef) { r.InstanceId = "" }), rMalformed, "spec.instance.instance_id"},
		{"traversal instance_id", ref(func(r *agentv1.InstanceRef) { r.InstanceId = "../../etc/passwd" }), rID, "spec.instance.instance_id"},
		{"uuid then traversal", ref(func(r *agentv1.InstanceRef) { r.InstanceId = instanceID + "/../" + otherID }), rID, "spec.instance.instance_id"},
		{"absolute path as id", ref(func(r *agentv1.InstanceRef) { r.InstanceId = "/opt/meshguard/tenants/" + otherID }), rID, "spec.instance.instance_id"},
		{"upper-case uuid", ref(func(r *agentv1.InstanceRef) { r.InstanceId = "ABCDEF01-2222-4222-8222-222222222222" }), rID, "spec.instance.instance_id"},
		{"braced uuid", ref(func(r *agentv1.InstanceRef) { r.InstanceId = "{" + instanceID + "}" }), rID, "spec.instance.instance_id"},
		{"urn uuid", ref(func(r *agentv1.InstanceRef) { r.InstanceId = "urn:uuid:" + instanceID }), rID, "spec.instance.instance_id"},
		{"uuid without dashes", ref(func(r *agentv1.InstanceRef) { r.InstanceId = strings.ReplaceAll(instanceID, "-", "") }), rID, "spec.instance.instance_id"},
		{"nil uuid", ref(func(r *agentv1.InstanceRef) { r.InstanceId = "00000000-0000-0000-0000-000000000000" }), rID, "spec.instance.instance_id"},
		{"uuid with newline", ref(func(r *agentv1.InstanceRef) { r.InstanceId = instanceID + "\n" }), rID, "spec.instance.instance_id"},
		{"uuid with NUL", ref(func(r *agentv1.InstanceRef) { r.InstanceId = instanceID + "\x00" }), rID, "spec.instance.instance_id"},
		{"traversal tenant_id", ref(func(r *agentv1.InstanceRef) { r.TenantId = "/etc/shadow" }), rID, "spec.instance.tenant_id"},
		{"tenant_id = instance_id", ref(func(r *agentv1.InstanceRef) { r.TenantId = instanceID }), rID, "spec.instance.tenant_id"},
		{"empty slug", ref(func(r *agentv1.InstanceRef) { r.Slug = "" }), rMalformed, "spec.instance.slug"},
		{"traversal slug", ref(func(r *agentv1.InstanceRef) { r.Slug = "../etc" }), rSlug, "spec.instance.slug"},
		{"slash in slug", ref(func(r *agentv1.InstanceRef) { r.Slug = "acme/../x" }), rSlug, "spec.instance.slug"},
		{"upper-case slug", ref(func(r *agentv1.InstanceRef) { r.Slug = "Acme" }), rSlug, "spec.instance.slug"},
		{"double hyphen", ref(func(r *agentv1.InstanceRef) { r.Slug = "acme--corp" }), rSlug, "spec.instance.slug"},
		{"punycode", ref(func(r *agentv1.InstanceRef) { r.Slug = "xn--abc" }), rSlug, "spec.instance.slug"},
		{"reserved slug", ref(func(r *agentv1.InstanceRef) { r.Slug = "admin" }), rSlug, "spec.instance.slug"},
		{"label of the domain", ref(func(r *agentv1.InstanceRef) { r.Slug = "example" }), rSlug, "spec.instance.slug"},
		{"slug too long", ref(func(r *agentv1.InstanceRef) { r.Slug = "a" + strings.Repeat("b", 32) }), rSlug, "spec.instance.slug"},
		{"slug too short", ref(func(r *agentv1.InstanceRef) { r.Slug = "a" }), rSlug, "spec.instance.slug"},
		{"slug ends with hyphen", ref(func(r *agentv1.InstanceRef) { r.Slug = "acme-" }), rSlug, "spec.instance.slug"},
		{"slug with NUL", ref(func(r *agentv1.InstanceRef) { r.Slug = "acme\x00x" }), rSlug, "spec.instance.slug"},
		{"slug with space", ref(func(r *agentv1.InstanceRef) { r.Slug = "ac me" }), rSlug, "spec.instance.slug"},
		{"digest not allowed", spec(func(s *agentv1.InstanceSpec) { s.ImageDigest = digestX }), rImage, "spec.image_digest"},
		{"image by tag", spec(func(s *agentv1.InstanceSpec) { s.ImageDigest = "headscale/headscale:v0.29.7" }), rMalformed, "spec.image_digest"},
		{"image reference instead of digest", spec(func(s *agentv1.InstanceSpec) { s.ImageDigest = repo + "@" + digestA }), rMalformed, "spec.image_digest"},
		{"upper-case digest", spec(func(s *agentv1.InstanceSpec) { s.ImageDigest = strings.ToUpper(digestA) }), rMalformed, "spec.image_digest"},
		{"short digest", spec(func(s *agentv1.InstanceSpec) { s.ImageDigest = digestA[:70] }), rMalformed, "spec.image_digest"},
		{"sha512 digest", spec(func(s *agentv1.InstanceSpec) { s.ImageDigest = "sha512:" + strings.Repeat("a", 128) }), rMalformed, "spec.image_digest"},
		{"empty digest", spec(func(s *agentv1.InstanceSpec) { s.ImageDigest = "" }), rMalformed, "spec.image_digest"},
		{"run_uid 0", spec(func(s *agentv1.InstanceSpec) { s.RunUid = 0 }), rUID, "spec.run_uid"},
		{"run_uid below range", spec(func(s *agentv1.InstanceSpec) { s.RunUid = 29999 }), rUID, "spec.run_uid"},
		{"run_uid above range", spec(func(s *agentv1.InstanceSpec) { s.RunUid = 40000 }), rUID, "spec.run_uid"},
		{"run_uid of api/worker", spec(func(s *agentv1.InstanceSpec) { s.RunUid = 65532 }), rUID, "spec.run_uid"},
		{"run_uid = GID mg-sec-worker", spec(func(s *agentv1.InstanceSpec) { s.RunUid = 20003 }), rUID, "spec.run_uid"},
		{"net outside pool", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "192.168.1.0/29" }), rNet, "spec.net_cidr"},
		{"net of the platform pool", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "10.249.0.0/29" }), rNet, "spec.net_cidr"},
		{"net /28", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "10.250.0.0/28" }), rNet, "spec.net_cidr"},
		{"net /30", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "10.250.0.0/30" }), rNet, "spec.net_cidr"},
		{"net host bits", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "10.250.0.9/29" }), rNet, "spec.net_cidr"},
		{"net IPv6", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "fd00::/125" }), rMalformed, "spec.net_cidr"},
		{"net leading zeros", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "10.250.000.8/29" }), rMalformed, "spec.net_cidr"},
		{"net is an address", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "10.250.0.8" }), rMalformed, "spec.net_cidr"},
		{"net is a docker name", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "mg-edge" }), rMalformed, "spec.net_cidr"},
		{"empty net", spec(func(s *agentv1.InstanceSpec) { s.NetCidr = "" }), rMalformed, "spec.net_cidr"},
		{"no limits", spec(func(s *agentv1.InstanceSpec) { s.Limits = nil }), rMalformed, "spec.limits"},
		{"memory 0", lim(func(l *agentv1.ResourceLimits) { l.MemoryMib = 0 }), rBounds, "spec.limits.memory_mib"},
		{"memory too high", lim(func(l *agentv1.ResourceLimits) { l.MemoryMib = 1 << 20 }), rBounds, "spec.limits.memory_mib"},
		{"cpu too low", lim(func(l *agentv1.ResourceLimits) { l.CpuMillis = 50 }), rBounds, "spec.limits.cpu_millis"},
		{"pids too low", lim(func(l *agentv1.ResourceLimits) { l.Pids = 8 }), rBounds, "spec.limits.pids"},
		{"no headscale params", spec(func(s *agentv1.InstanceSpec) { s.Headscale = nil }), rMalformed, "spec.headscale"},
		{"expiry 0", hs(func(h *agentv1.HeadscaleParams) { h.NodeExpiryDays = 0 }), rBounds, "spec.headscale.node_expiry_days"},
		{"expiry too long", hs(func(h *agentv1.HeadscaleParams) { h.NodeExpiryDays = 4000 }), rBounds, "spec.headscale.node_expiry_days"},
		{"no nameserver", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = nil }), rMalformed, "spec.headscale.nameservers"},
		{"9 nameservers", hs(func(h *agentv1.HeadscaleParams) {
			h.Nameservers = []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9"}
		}), rLarge, "spec.headscale.nameservers"},
		{"nameserver with port", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"1.1.1.1:53"} }), rMalformed, "spec.headscale.nameservers[0]"},
		{"nameserver hostname", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"dns.example.com"} }), rMalformed, "spec.headscale.nameservers[0]"},
		{"loopback nameserver", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"1.1.1.1", "127.0.0.1"} }), rBounds, "spec.headscale.nameservers[1]"},
		{"unspecified nameserver", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"0.0.0.0"} }), rBounds, "spec.headscale.nameservers[0]"},
		{"nameserver in tenant pool", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"10.250.0.10"} }), rBounds, "spec.headscale.nameservers[0]"},
		{"v4-mapped nameserver", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"::ffff:1.1.1.1"} }), rBounds, "spec.headscale.nameservers[0]"},
		{"nameserver with zone", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"fe80::1%eth0"} }), rBounds, "spec.headscale.nameservers[0]"},
		{"duplicate nameserver", hs(func(h *agentv1.HeadscaleParams) { h.Nameservers = []string{"1.1.1.1", "1.1.1.1"} }), rMalformed, "spec.headscale.nameservers[1]"},
		{"region outside 900-999", hs(func(h *agentv1.HeadscaleParams) { h.DerpRegionId = 1 }), rBounds, "spec.headscale.derp_region_id"},
		{"other public entry", hs(func(h *agentv1.HeadscaleParams) { h.PublicEntryIpv4 = "198.51.100.7" }), rConflict, "spec.headscale.public_entry_ipv4"},
		{"public entry not an IP", hs(func(h *agentv1.HeadscaleParams) { h.PublicEntryIpv4 = "gw.example.com" }), rMalformed, "spec.headscale.public_entry_ipv4"},
		{"no log level", hs(func(h *agentv1.HeadscaleParams) { h.LogLevel = agentv1.LogLevel_LOG_LEVEL_UNSPECIFIED }), rMalformed, "spec.headscale.log_level"},
		{"stun port without range", hs(func(h *agentv1.HeadscaleParams) { h.StunPort = proto.Uint32(40001) }), rPort, "spec.headscale.stun_port"},
		{"no target phase", func(r *agentv1.EnsureInstanceRequest) { r.TargetPhase = agentv1.TargetPhase_TARGET_PHASE_UNSPECIFIED }, rMalformed, "target_phase"},
		{"no job id", func(r *agentv1.EnsureInstanceRequest) { r.JobId = "" }, rMalformed, "job_id"},
		{"traversal job id", func(r *agentv1.EnsureInstanceRequest) { r.JobId = "../" + jobID }, rID, "job_id"},
	}
	v := &Validator{Host: testHost(t)}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goodEnsure()
			c.mut(r)
			_, err := v.EnsureInstance(r)
			wantRefusal(t, err, c.reason, c.field)
		})
	}
	t.Logf("%d negative EnsureInstance cases", len(cases))
}

// The fallback per-tenant STUN design: ports only from the host's range.
func TestStunPortRange(t *testing.T) {
	h := testHost(t)
	h.STUNPorts = &Range{Min: 40000, Max: 40999}
	v := &Validator{Host: h}
	for port, ok := range map[uint32]bool{40000: true, 40999: true, 39999: false, 41000: false, 3478: false, 0: false} {
		r := goodEnsure()
		r.Spec.Headscale.StunPort = proto.Uint32(port)
		e, err := v.EnsureInstance(r)
		if ok && (err != nil || e.Spec.Headscale.STUNPort != port) {
			t.Fatalf("port %d: %v", port, err)
		}
		if !ok {
			wantRefusal(t, err, rPort, "spec.headscale.stun_port")
		}
	}
}

// TestOtherRequestRefusals covers the remaining request types.
func TestOtherRequestRefusals(t *testing.T) {
	v := &Validator{Host: testHost(t)}
	ref := goodRef()
	big := strings.Repeat("x", MaxPolicyBytes+1)
	tooManyKeys := make([]string, MaxListItems+1)
	for i := range tooManyKeys {
		tooManyKeys[i] = fmt.Sprintf("mkey:%064x", i)
	}
	tooManyRecords := make([]*agentv1.DnsRecord, MaxDNSRecords+1)
	for i := range tooManyRecords {
		tooManyRecords[i] = &agentv1.DnsRecord{Name: fmt.Sprintf("h%d.acme.tail.example.com", i), Type: agentv1.DnsRecordType_DNS_RECORD_TYPE_A, Value: "100.64.0.1"}
	}
	a := func(name, value string) *agentv1.DnsRecord {
		return &agentv1.DnsRecord{Name: name, Type: agentv1.DnsRecordType_DNS_RECORD_TYPE_A, Value: value}
	}
	aaaa := func(name, value string) *agentv1.DnsRecord {
		return &agentv1.DnsRecord{Name: name, Type: agentv1.DnsRecordType_DNS_RECORD_TYPE_AAAA, Value: value}
	}
	dns := func(recs ...*agentv1.DnsRecord) error {
		_, err := v.WriteDNSRecords(&agentv1.WriteDnsRecordsRequest{Instance: goodRef(), JobId: jobID, Records: recs})
		return err
	}
	key := func(ttl *durationpb.Duration, prefix string) error {
		_, err := v.BootstrapAPIKey(&agentv1.BootstrapApiKeyRequest{Instance: goodRef(), JobId: jobID, Ttl: ttl, KeepPrefix: prefix})
		return err
	}
	goodArtifact := &agentv1.ArtifactRef{Sequence: 3, ArchiveSha256: strings.Repeat("1", 64), ManifestSha256: strings.Repeat("2", 64)}
	restore := func(f func(r *agentv1.RestoreRequest)) error {
		r := &agentv1.RestoreRequest{Instance: goodRef(), JobId: jobID, Artifact: clone(goodArtifact), DataKey: make([]byte, 32),
			Policy: &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: []byte(`{"grants": []}`)}}
		f(r)
		_, err := v.Restore(r)
		return err
	}
	reconcile := func(f func(p *agentv1.ReconcilePlan)) error {
		p := &agentv1.ReconcilePlan{ApiKeyTtl: hours(2160), RevokedMachineKeys: []string{"mkey:" + strings.Repeat("a", 64)},
			Nodes:           []*agentv1.NodeDesiredState{{MachineKey: "mkey:" + strings.Repeat("b", 64), ApprovedRoutes: []string{"10.0.0.0/24"}, Tags: []string{"tag:web"}}},
			OffboardedUsers: []string{"mg-" + otherID}}
		f(p)
		_, err := v.PostRestoreReconcile(&agentv1.PostRestoreReconcileRequest{Instance: goodRef(), JobId: jobID, Plan: p})
		return err
	}
	cases := []struct {
		name   string
		err    error
		reason agentv1.RefusalReason
		field  string
	}{
		{"status: traversal id", func() error {
			_, err := v.GetInstanceStatus(&agentv1.GetInstanceStatusRequest{Instance: &agentv1.InstanceRef{InstanceId: "..", TenantId: tenantID, Slug: "acme"}})
			return err
		}(), rID, "instance.instance_id"},
		{"start: no instance", func() error { _, err := v.Call(&agentv1.StartInstanceRequest{JobId: jobID}); return err }(), rMalformed, "instance"},
		{"stop: no job", func() error { _, err := v.Call(&agentv1.StopInstanceRequest{Instance: ref}); return err }(), rMalformed, "job_id"},
		{"restart: bad slug", func() error {
			_, err := v.Call(&agentv1.RestartInstanceRequest{Instance: &agentv1.InstanceRef{InstanceId: instanceID, TenantId: tenantID, Slug: "mg-edge/.."}, JobId: jobID})
			return err
		}(), rSlug, "instance.slug"},
		{"remove: no disposition", func() error {
			_, err := v.RemoveInstance(&agentv1.RemoveInstanceRequest{Instance: ref, JobId: jobID})
			return err
		}(), rMalformed, "data"},
		{"remove: archived without sequence", func() error {
			_, err := v.RemoveInstance(&agentv1.RemoveInstanceRequest{Instance: ref, JobId: jobID, Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED})
			return err
		}(), rMalformed, "archived_backup_sequence"},
		{"remove: keep with sequence", func() error {
			_, err := v.RemoveInstance(&agentv1.RemoveInstanceRequest{Instance: ref, JobId: jobID, Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP, ArchivedBackupSequence: 4})
			return err
		}(), rMalformed, "archived_backup_sequence"},
		{"upgrade: target not allowed", func() error {
			_, err := v.UpgradeInstance(&agentv1.UpgradeInstanceRequest{Instance: ref, JobId: jobID, FromImageDigest: digestA, ToImageDigest: digestX})
			return err
		}(), rImage, "to_image_digest"},
		{"upgrade: source not allowed", func() error {
			_, err := v.UpgradeInstance(&agentv1.UpgradeInstanceRequest{Instance: ref, JobId: jobID, FromImageDigest: digestX, ToImageDigest: digestA})
			return err
		}(), rImage, "from_image_digest"},
		{"upgrade: same digest", func() error {
			_, err := v.UpgradeInstance(&agentv1.UpgradeInstanceRequest{Instance: ref, JobId: jobID, FromImageDigest: digestA, ToImageDigest: digestA})
			return err
		}(), rMalformed, "to_image_digest"},
		{"upgrade: tag", func() error {
			_, err := v.UpgradeInstance(&agentv1.UpgradeInstanceRequest{Instance: ref, JobId: jobID, FromImageDigest: digestA, ToImageDigest: "latest"})
			return err
		}(), rMalformed, "to_image_digest"},
		{"dns: too many records", dns(tooManyRecords...), rLarge, "records"},
		{"dns: nil record", dns(nil), rMalformed, "records[0]"},
		{"dns: traversal name", dns(a("../../etc/passwd", "100.64.0.1")), rMalformed, "records[0].name"},
		{"dns: single label", dns(a("db", "100.64.0.1")), rMalformed, "records[0].name"},
		{"dns: upper case", dns(a("DB.acme.tail.example.com", "100.64.0.1")), rMalformed, "records[0].name"},
		{"dns: trailing dot", dns(a("db.example.org.", "100.64.0.1")), rMalformed, "records[0].name"},
		{"dns: too long", dns(a(strings.Repeat("a.", 127)+"io", "100.64.0.1")), rMalformed, "records[0].name"},
		{"dns: platform host", dns(a("app.example.com", "100.64.0.1")), rBounds, "records[0].name"},
		{"dns: another tenant's MagicDNS", dns(a("db.other.tail.example.com", "100.64.0.1")), rBounds, "records[0].name"},
		{"dns: no type", dns(&agentv1.DnsRecord{Name: "db.example.org", Value: "100.64.0.1"}), rMalformed, "records[0].type"},
		{"dns: A with IPv6", dns(a("db.example.org", "fd7a:115c:a1e0::1")), rMalformed, "records[0].value"},
		{"dns: AAAA with IPv4", dns(aaaa("db.example.org", "100.64.0.1")), rMalformed, "records[0].value"},
		{"dns: AAAA v4-mapped", dns(aaaa("db.example.org", "::ffff:100.64.0.1")), rMalformed, "records[0].value"},
		{"dns: value not an IP", dns(a("db.example.org", "evil.example.org")), rMalformed, "records[0].value"},
		{"dns: duplicate", dns(a("db.example.org", "100.64.0.1"), a("db.example.org", "100.64.0.1")), rMalformed, "records[1]"},
		{"policy: unspecified", func() error {
			_, _, err := v.BootstrapPolicy(&agentv1.BootstrapPolicyRequest{Instance: ref, JobId: jobID})
			return err
		}(), rMalformed, "policy"},
		{"apikey: no ttl", key(nil, ""), rMalformed, "ttl"},
		{"apikey: 30 minutes", key(durationpb.New(30*time.Minute), ""), rBounds, "ttl"},
		{"apikey: fractional hours", key(durationpb.New(90*time.Minute+24*time.Hour), ""), rBounds, "ttl"},
		{"apikey: more than a year", key(hours(9000), ""), rBounds, "ttl"},
		{"apikey: negative", key(hours(-2160), ""), rBounds, "ttl"},
		{"apikey: invalid duration", key(&durationpb.Duration{Seconds: 1, Nanos: -1}, ""), rMalformed, "ttl"},
		{"apikey: prefix with slash", key(hours(2160), "abc/def/ghij"), rMalformed, "keep_prefix"},
		{"apikey: full key as prefix", key(hours(2160), "hskey-api-abcdefghijkl-secret"), rMalformed, "keep_prefix"},
		{"backup: sequence 0", func() error {
			_, err := v.Backup(&agentv1.BackupRequest{Instance: ref, JobId: jobID, DataRecipient: make([]byte, 32)})
			return err
		}(), rBounds, "sequence"},
		{"backup: short data recipient", func() error {
			_, err := v.Backup(&agentv1.BackupRequest{Instance: ref, JobId: jobID, Sequence: 1, DataRecipient: make([]byte, 31)})
			return err
		}(), rMalformed, "data_recipient"},
		{"backup: no data recipient", func() error {
			_, err := v.Backup(&agentv1.BackupRequest{Instance: ref, JobId: jobID, Sequence: 1})
			return err
		}(), rMalformed, "data_recipient"},
		{"backup: retention above the sequence", func() error {
			_, err := v.Backup(&agentv1.BackupRequest{Instance: ref, JobId: jobID, Sequence: 3, DataRecipient: make([]byte, 32), RetainFromSequence: 4})
			return err
		}(), rBounds, "retain_from_sequence"},
		{"restore: no artifact", restore(func(r *agentv1.RestoreRequest) { r.Artifact = nil }), rMalformed, "artifact"},
		{"restore: sequence 0", restore(func(r *agentv1.RestoreRequest) { r.Artifact.Sequence = 0 }), rBounds, "artifact.sequence"},
		{"restore: archive hash", restore(func(r *agentv1.RestoreRequest) { r.Artifact.ArchiveSha256 = "../" + otherID }), rMalformed, "artifact.archive_sha256"},
		{"restore: manifest hash", restore(func(r *agentv1.RestoreRequest) { r.Artifact.ManifestSha256 = strings.Repeat("G", 64) }), rMalformed, "artifact.manifest_sha256"},
		{"restore: long data key", restore(func(r *agentv1.RestoreRequest) { r.DataKey = make([]byte, 64) }), rMalformed, "data_key"},
		{"restore: no policy", restore(func(r *agentv1.RestoreRequest) { r.Policy = nil }), rMalformed, "policy"},
		{"restore: empty policy", restore(func(r *agentv1.RestoreRequest) {
			r.Policy = &agentv1.RestoreRequest_AppliedPolicyHujson{}
		}), rMalformed, "applied_policy_hujson"},
		{"restore: oversize policy", restore(func(r *agentv1.RestoreRequest) {
			r.Policy = &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: []byte(big)}
		}), rLarge, "applied_policy_hujson"},
		{"restore: binary policy", restore(func(r *agentv1.RestoreRequest) {
			r.Policy = &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: []byte{0xff, 0xfe, '{'}}
		}), rMalformed, "applied_policy_hujson"},
		{"restore: NUL in policy", restore(func(r *agentv1.RestoreRequest) {
			r.Policy = &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: []byte("{}\x00")}
		}), rMalformed, "applied_policy_hujson"},
		{"restore: keep_backup_policy false", restore(func(r *agentv1.RestoreRequest) {
			r.Policy = &agentv1.RestoreRequest_KeepBackupPolicy{}
		}), rMalformed, "keep_backup_policy"},
		{"reconcile: no plan", func() error {
			_, err := v.PostRestoreReconcile(&agentv1.PostRestoreReconcileRequest{Instance: ref, JobId: jobID})
			return err
		}(), rMalformed, "plan"},
		{"reconcile: no ttl", reconcile(func(p *agentv1.ReconcilePlan) { p.ApiKeyTtl = nil }), rMalformed, "plan.api_key_ttl"},
		{"reconcile: numeric node id", reconcile(func(p *agentv1.ReconcilePlan) { p.RevokedMachineKeys = []string{"17"} }), rMalformed, "plan.revoked_machine_keys[0]"},
		{"reconcile: too many keys", reconcile(func(p *agentv1.ReconcilePlan) { p.RevokedMachineKeys = tooManyKeys }), rLarge, "plan.revoked_machine_keys"},
		{"reconcile: duplicate key", reconcile(func(p *agentv1.ReconcilePlan) {
			p.RevokedMachineKeys = append(p.RevokedMachineKeys, p.RevokedMachineKeys[0])
		}), rMalformed, "plan.revoked_machine_keys[1]"},
		{"reconcile: nil node", reconcile(func(p *agentv1.ReconcilePlan) { p.Nodes = []*agentv1.NodeDesiredState{nil} }), rMalformed, "plan.nodes[0]"},
		{"reconcile: node key", reconcile(func(p *agentv1.ReconcilePlan) { p.Nodes[0].MachineKey = "nodekey:" + strings.Repeat("a", 64) }), rMalformed, "plan.nodes[0].machine_key"},
		{"reconcile: route host bits", reconcile(func(p *agentv1.ReconcilePlan) { p.Nodes[0].ApprovedRoutes = []string{"10.0.0.1/24"} }), rMalformed, "plan.nodes[0].approved_routes[0]"},
		{"reconcile: route not a CIDR", reconcile(func(p *agentv1.ReconcilePlan) { p.Nodes[0].ApprovedRoutes = []string{"; rm -rf /"} }), rMalformed, "plan.nodes[0].approved_routes[0]"},
		{"reconcile: bad tag", reconcile(func(p *agentv1.ReconcilePlan) { p.Nodes[0].Tags = []string{"tag:$(id)"} }), rMalformed, "plan.nodes[0].tags[0]"},
		{"reconcile: tag without prefix", reconcile(func(p *agentv1.ReconcilePlan) { p.Nodes[0].Tags = []string{"web"} }), rMalformed, "plan.nodes[0].tags[0]"},
		{"reconcile: user name", reconcile(func(p *agentv1.ReconcilePlan) { p.OffboardedUsers = []string{"alice"} }), rMalformed, "plan.offboarded_users[0]"},
		{"reconcile: user uuid", reconcile(func(p *agentv1.ReconcilePlan) { p.OffboardedUsers = []string{"mg-../" + otherID} }), rID, "plan.offboarded_users[0]"},
		{"edge detach: no reason", func() error {
			_, err := v.RemoveEdgeAttachment(&agentv1.RemoveEdgeAttachmentRequest{Instance: ref, JobId: jobID})
			return err
		}(), rMalformed, "reason"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantRefusal(t, c.err, c.reason, c.field) })
	}
	t.Logf("%d negative cases on the other request types", len(cases))
	// and the good forms pass
	if err := dns(a("db.acme.tail.example.com", "100.64.0.5"), aaaa("db.example.org", "fd7a:115c:a1e0::5"), a("intranet.corp.internal", "10.0.0.5")); err != nil {
		t.Fatal(err)
	}
	if err := key(hours(2160), "a-b_c-d_e-f_"); err != nil {
		t.Fatal(err)
	}
	if err := restore(func(*agentv1.RestoreRequest) {}); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(func(*agentv1.ReconcilePlan) {}); err != nil {
		t.Fatal(err)
	}
}

// TestUnknownFieldsAndEnumsRefused: a field or enum value the agent does not know is refused (fail closed).
func TestUnknownFieldsAndEnumsRefused(t *testing.T) {
	withUnknown := func(m proto.Message) {
		b := protowire.AppendTag(nil, 99, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
		m.ProtoReflect().SetUnknown(b)
	}
	cases := []struct {
		name  string
		msg   func() proto.Message
		field string
	}{
		{"top level", func() proto.Message { r := goodEnsure(); withUnknown(r); return r }, "(request)"},
		{"nested spec.headscale", func() proto.Message { r := goodEnsure(); withUnknown(r.Spec.Headscale); return r }, "spec.headscale"},
		{"nested spec.instance", func() proto.Message { r := goodEnsure(); withUnknown(r.Spec.Instance); return r }, "spec.instance"},
		{"in a list element", func() proto.Message {
			r := &agentv1.WriteDnsRecordsRequest{Instance: goodRef(), JobId: jobID, Records: []*agentv1.DnsRecord{
				{Name: "a.example.org", Type: agentv1.DnsRecordType_DNS_RECORD_TYPE_A, Value: "100.64.0.1"},
				{Name: "b.example.org", Type: agentv1.DnsRecordType_DNS_RECORD_TYPE_A, Value: "100.64.0.2"}}}
			withUnknown(r.Records[1])
			return r
		}, "records[1]"},
		{"unknown enum target_phase", func() proto.Message { r := goodEnsure(); r.TargetPhase = 99; return r }, "target_phase"},
		{"unknown enum log_level", func() proto.Message { r := goodEnsure(); r.Spec.Headscale.LogLevel = 42; return r }, "spec.headscale.log_level"},
		{"unknown enum in list", func() proto.Message {
			return &agentv1.WriteDnsRecordsRequest{Records: []*agentv1.DnsRecord{{Type: 7}}}
		}, "records[0].type"},
		{"unknown enum data disposition", func() proto.Message {
			return &agentv1.RemoveInstanceRequest{Data: 1000}
		}, "data"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// round-trip through the wire format, as the server sees it
			raw, err := proto.Marshal(c.msg())
			if err != nil {
				t.Fatal(err)
			}
			m := c.msg().ProtoReflect().New().Interface()
			if err := proto.Unmarshal(raw, m); err != nil {
				t.Fatal(err)
			}
			wantRefusal(t, UnknownField(m), rMalformed, c.field)
		})
	}
	if err := UnknownField(goodEnsure()); err != nil {
		t.Fatalf("good request: %v", err)
	}
}
