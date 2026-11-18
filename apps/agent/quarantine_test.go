//go:build linux

package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// markedDriver answers Quarantined from its flag; every other operation is noDriver's UNIMPLEMENTED (reaching the
// driver), except QuarantineInstance and ReleaseInstance, which it records.
type markedDriver struct {
	noDriver
	mu     sync.Mutex
	marked bool
	calls  []string
}

func (d *markedDriver) Name() string { return "marked" }
func (d *markedDriver) Quarantined(context.Context, agentspec.Ref) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.marked, nil
}
func (d *markedDriver) QuarantineInstance(_ context.Context, c agentspec.Call) (*agentv1.QuarantineInstanceResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls, d.marked = append(d.calls, "QuarantineInstance"), true
	return &agentv1.QuarantineInstanceResponse{MarkedNow: true}, nil
}
func (d *markedDriver) ReleaseInstance(_ context.Context, r agentspec.Release) (*agentv1.ReleaseInstanceResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls, d.marked = append(d.calls, "ReleaseInstance:"+r.ExpectedPolicySHA256[:4]), false
	return &agentv1.ReleaseInstanceResponse{WasQuarantined: true, PolicySha256: r.ExpectedPolicySHA256}, nil
}

// specOn is goodSpec on another image (the target of an upgrade — P3-T13a).
func specOn(digest string) *agentv1.InstanceSpec {
	s := goodSpec()
	s.ImageDigest = digest
	return s
}

// TestQuarantineRefusals — §11.4 Quarantine on the agent's server (P3-T18): while the instance carries meta/quarantined,
// every call that could make it serve or change it is refused STATE before the driver (start, restart, compose up,
// configtest, upgrade and its preflight (P3-T13a), DNS records, policy and API key bootstrap, restore, post-restore reconcile, edge attachment, the
// compensation that would remove meta/activated, a removal deleting data); stop, a detach, a removal keeping data,
// backup, status, quarantine and release still reach the driver. A release needs a 64-hex policy sha256.
func TestQuarantineRefusals(t *testing.T) {
	d := &markedDriver{}
	h := start(t, nil, nil, withDriver(d))
	c := tctx(t)
	writeInstance(t, h.tenants, instanceID, tenantID, "acme")
	key := make([]byte, 32)
	calls := map[string]func() error{
		"ValidateConfig": func() error {
			_, err := h.client.ValidateConfig(c, &agentv1.ValidateConfigRequest{Spec: goodSpec(), JobId: jobID})
			return err
		},
		"EnsureInstance": func() error { _, err := h.client.EnsureInstance(c, goodEnsure()); return err },
		"StartInstance": func() error {
			_, err := h.client.StartInstance(c, &agentv1.StartInstanceRequest{Instance: goodRef(), JobId: jobID})
			return err
		},
		"RestartInstance": func() error {
			_, err := h.client.RestartInstance(c, &agentv1.RestartInstanceRequest{Instance: goodRef(), JobId: jobID})
			return err
		},
		"UpgradeInstance": func() error {
			_, err := h.client.UpgradeInstance(c, &agentv1.UpgradeInstanceRequest{Instance: goodRef(), JobId: jobID,
				FromImageDigest: digestA, ToImageDigest: digestB, Spec: specOn(digestB)})
			return err
		},
		"PreflightUpgrade": func() error { // P3-T13a
			_, err := h.client.PreflightUpgrade(c, &agentv1.PreflightUpgradeRequest{Spec: specOn(digestB), JobId: jobID,
				FromImageDigest: digestA, DataKey: key,
				Artifact: &agentv1.ArtifactRef{Sequence: 1, ArchiveSha256: strings.Repeat("1", 64), ManifestSha256: strings.Repeat("2", 64)}})
			return err
		},
		"WriteDnsRecords": func() error {
			_, err := h.client.WriteDnsRecords(c, &agentv1.WriteDnsRecordsRequest{Instance: goodRef(), JobId: jobID})
			return err
		},
		"BootstrapPolicy": func() error {
			_, err := h.client.BootstrapPolicy(c, &agentv1.BootstrapPolicyRequest{Instance: goodRef(), JobId: jobID,
				Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL})
			return err
		},
		"BootstrapApiKey": func() error {
			_, err := h.client.BootstrapApiKey(c, &agentv1.BootstrapApiKeyRequest{Instance: goodRef(), JobId: jobID,
				Ttl: durationpb.New(24 * time.Hour)})
			return err
		},
		"Restore": func() error {
			_, err := h.client.Restore(c, &agentv1.RestoreRequest{Instance: goodRef(), JobId: jobID,
				Artifact: &agentv1.ArtifactRef{Sequence: 1, ArchiveSha256: strings.Repeat("1", 64), ManifestSha256: strings.Repeat("2", 64)},
				DataKey:  key, Policy: &agentv1.RestoreRequest_AppliedPolicyHujson{AppliedPolicyHujson: []byte("{}")}})
			return err
		},
		"PostRestoreReconcile": func() error {
			_, err := h.client.PostRestoreReconcile(c, &agentv1.PostRestoreReconcileRequest{Instance: goodRef(), JobId: jobID,
				Plan: &agentv1.ReconcilePlan{ApiKeyTtl: durationpb.New(24 * time.Hour)}})
			return err
		},
		"EnsureEdgeAttachment": func() error {
			_, err := h.client.EnsureEdgeAttachment(c, &agentv1.EnsureEdgeAttachmentRequest{Instance: goodRef(), JobId: jobID})
			return err
		},
		"RemoveEdgeAttachment(COMPENSATION)": func() error {
			_, err := h.client.RemoveEdgeAttachment(c, &agentv1.RemoveEdgeAttachmentRequest{Instance: goodRef(), JobId: jobID,
				Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_COMPENSATION})
			return err
		},
		"RemoveInstance(DELETE_IF_NEVER_ACTIVATED)": func() error {
			_, err := h.client.RemoveInstance(c, &agentv1.RemoveInstanceRequest{Instance: goodRef(), JobId: jobID,
				Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED})
			return err
		},
	}
	allowed := map[string]func() error{
		"StopInstance": func() error {
			_, err := h.client.StopInstance(c, &agentv1.StopInstanceRequest{Instance: goodRef(), JobId: jobID})
			return err
		},
		"RemoveEdgeAttachment(QUARANTINE)": func() error {
			_, err := h.client.RemoveEdgeAttachment(c, &agentv1.RemoveEdgeAttachmentRequest{Instance: goodRef(), JobId: jobID,
				Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_QUARANTINE})
			return err
		},
		"RemoveInstance(KEEP)": func() error {
			_, err := h.client.RemoveInstance(c, &agentv1.RemoveInstanceRequest{Instance: goodRef(), JobId: jobID,
				Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP})
			return err
		},
		"Backup": func() error {
			_, err := h.client.Backup(c, &agentv1.BackupRequest{Instance: goodRef(), JobId: jobID, Sequence: 1, DataRecipient: key})
			return err
		},
		"GetInstanceStatus": func() error {
			_, err := h.client.GetInstanceStatus(c, &agentv1.GetInstanceStatusRequest{Instance: goodRef()})
			return err
		},
	}
	// not quarantined: every call reaches the driver (UNIMPLEMENTED)
	for name, call := range calls {
		if err := call(); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s (not quarantined): %v, want the driver's UNIMPLEMENTED", name, err)
		}
	}
	if _, err := h.client.QuarantineInstance(c, &agentv1.QuarantineInstanceRequest{Instance: goodRef(), JobId: jobID}); err != nil {
		t.Fatal(err)
	}
	for name, call := range calls {
		err := call()
		r, ok := agentclient.RefusalOf(err)
		if status.Code(err) != codes.FailedPrecondition || !ok || r.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_STATE ||
			!strings.Contains(r.GetMessage(), "quarantined") {
			t.Errorf("%s (quarantined): %v, want STATE quarantined", name, err)
		}
		// restore lock fix (P3-T11): a Restore refused before the driver ran is marked unchanged; no other RPC is
		if ok && r.GetUnchanged() != (name == "Restore") {
			t.Errorf("%s (quarantined): unchanged %v", name, r.GetUnchanged())
		}
	}
	for name, call := range allowed {
		if err := call(); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s (quarantined): %v, want it to reach the driver", name, err)
		}
	}
	// a release needs the policy sha256
	for _, bad := range []string{"", "XYZ", strings.Repeat("A", 64)} {
		_, err := h.client.ReleaseInstance(c, &agentv1.ReleaseInstanceRequest{Instance: goodRef(), JobId: jobID, ExpectedPolicySha256: bad})
		if r, ok := agentclient.RefusalOf(err); status.Code(err) != codes.InvalidArgument || !ok || r.GetField() != "expected_policy_sha256" {
			t.Errorf("release with sha %q: %v", bad, err)
		}
	}
	if _, err := h.client.ReleaseInstance(c, &agentv1.ReleaseInstanceRequest{Instance: goodRef(), JobId: jobID,
		ExpectedPolicySha256: strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	if err := calls["StartInstance"](); status.Code(err) != codes.Unimplemented {
		t.Fatalf("start after the release: %v", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.Join(d.calls, ",") != "QuarantineInstance,ReleaseInstance:abab" {
		t.Fatalf("driver calls %v", d.calls)
	}
}
