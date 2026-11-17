package agentspec

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

const (
	tenantID   = "11111111-1111-4111-8111-111111111111"
	instanceID = "22222222-2222-4222-8222-222222222222"
	jobID      = "33333333-3333-4333-8333-333333333333"
	otherID    = "44444444-4444-4444-8444-444444444444"
	repo       = "ghcr.io/zhaduchanhzz/network-access-mesh/headscale"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64) // allowed
	digestB = "sha256:" + strings.Repeat("b", 64) // allowed (upgrade target)
	digestX = "sha256:" + strings.Repeat("c", 64) // not allowed
)

func testHost(t *testing.T) *Host {
	t.Helper()
	allow, err := ParseAllowlist(strings.NewReader("# test allowlist\n" + repo + "@" + digestA + "\n" +
		"docker.io/headscale/headscale@" + digestB + "  # official\n"))
	if err != nil {
		t.Fatal(err)
	}
	return &Host{
		TenantsDir:  t.TempDir(),
		BackupsDir:  t.TempDir(),
		RunUIDs:     Range{Min: 30000, Max: 39999},
		TenantPool:  netip.MustParsePrefix("10.250.0.0/16"),
		PublicEntry: netip.MustParseAddr("203.0.113.10"),
		BaseDomain:  "example.com",
		Images:      allow,
		OwnerUID:    os.Geteuid(),
	}
}

func goodRef() *agentv1.InstanceRef {
	return &agentv1.InstanceRef{InstanceId: instanceID, TenantId: tenantID, Slug: "acme"}
}

func goodSpec() *agentv1.InstanceSpec {
	return &agentv1.InstanceSpec{
		Instance:    goodRef(),
		ImageDigest: digestA,
		RunUid:      30001,
		NetCidr:     "10.250.0.8/29",
		Limits:      &agentv1.ResourceLimits{MemoryMib: 512, CpuMillis: 1000, Pids: 256},
		Headscale: &agentv1.HeadscaleParams{
			NodeExpiryDays:  90,
			Nameservers:     []string{"1.1.1.1", "2606:4700:4700::1111"},
			DerpRegionId:    901,
			PublicEntryIpv4: "203.0.113.10",
			LogLevel:        agentv1.LogLevel_LOG_LEVEL_INFO,
		},
	}
}

func goodEnsure() *agentv1.EnsureInstanceRequest {
	return &agentv1.EnsureInstanceRequest{Spec: goodSpec(), TargetPhase: agentv1.TargetPhase_TARGET_PHASE_CONTAINER, JobId: jobID}
}

func hours(h int64) *durationpb.Duration { return durationpb.New(timeHours(h)) }

// wantRefusal asserts err is a refusal with that reason and field.
func wantRefusal(t *testing.T, err error, reason agentv1.RefusalReason, field string) {
	t.Helper()
	r, ok := AsRefusal(err)
	if !ok {
		t.Fatalf("want refusal %s %s, got %v", reason, field, err)
	}
	if r.Reason != reason || (field != "" && r.Field != field) {
		t.Fatalf("want refusal %s %q, got %s %q (%s)", reason, field, r.Reason, r.Field, r.Msg)
	}
}

func clone[T proto.Message](m T) T { return proto.Clone(m).(T) }
