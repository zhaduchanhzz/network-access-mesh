package main

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Driver performs the operations once they are validated, authorised, locked and guarded. It only ever receives
// agentspec values — never a raw request. The compose driver (P3-T02, internal/provisioning/driver/compose)
// implements it together with agentspec.Inventory; this agent (P3-T01) has none.
type Driver interface {
	Name() string
	ValidateConfig(ctx context.Context, s agentspec.InstanceSpec) (*agentv1.ValidateConfigResponse, error)
	EnsureInstance(ctx context.Context, e agentspec.Ensure) (*agentv1.EnsureInstanceResponse, error)
	InstanceStatus(ctx context.Context, ref agentspec.Ref, includeAPIKeys bool) (*agentv1.InstanceStatus, error)
	ListInstances(ctx context.Context) ([]*agentv1.InventoryEntry, error)
	StartInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error)
	StopInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error)
	RestartInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error)
	RemoveInstance(ctx context.Context, r agentspec.Remove) (*agentv1.RemoveInstanceResponse, error)
	UpgradeInstance(ctx context.Context, u agentspec.Upgrade) (*agentv1.InstanceStatus, error)
	WriteDNSRecords(ctx context.Context, d agentspec.DNSRecords) (*agentv1.WriteDnsRecordsResponse, error)
	BootstrapPolicy(ctx context.Context, c agentspec.Call, kind agentv1.PolicyKind) (*agentv1.BootstrapPolicyResponse, error)
	BootstrapAPIKey(ctx context.Context, k agentspec.APIKey) (*agentv1.BootstrapApiKeyResponse, error)
	Backup(ctx context.Context, b agentspec.Backup) (*agentv1.BackupArtifact, error)
	Restore(ctx context.Context, r agentspec.Restore) (*agentv1.RestoreResponse, error)
	PostRestoreReconcile(ctx context.Context, r agentspec.Reconcile) (*agentv1.PostRestoreReconcileResponse, error)
	EnsureEdgeAttachment(ctx context.Context, c agentspec.Call) (*agentv1.EnsureEdgeAttachmentResponse, error)
	RemoveEdgeAttachment(ctx context.Context, d agentspec.EdgeDetach) (*agentv1.RemoveEdgeAttachmentResponse, error)
}

// noDriver is the driver of P3-T01: every operation answers UNIMPLEMENTED after the request was validated,
// authorised, locked and guarded.
type noDriver struct{}

func unimplemented() error {
	return status.Error(codes.Unimplemented, "no infrastructure driver in this agent yet (compose driver: P3-T02)")
}

func (noDriver) Name() string { return "none" }
func (noDriver) ValidateConfig(context.Context, agentspec.InstanceSpec) (*agentv1.ValidateConfigResponse, error) {
	return nil, unimplemented()
}
func (noDriver) EnsureInstance(context.Context, agentspec.Ensure) (*agentv1.EnsureInstanceResponse, error) {
	return nil, unimplemented()
}
func (noDriver) InstanceStatus(context.Context, agentspec.Ref, bool) (*agentv1.InstanceStatus, error) {
	return nil, unimplemented()
}
func (noDriver) ListInstances(context.Context) ([]*agentv1.InventoryEntry, error) {
	return nil, unimplemented()
}
func (noDriver) StartInstance(context.Context, agentspec.Call) (*agentv1.InstanceStatus, error) {
	return nil, unimplemented()
}
func (noDriver) StopInstance(context.Context, agentspec.Call) (*agentv1.InstanceStatus, error) {
	return nil, unimplemented()
}
func (noDriver) RestartInstance(context.Context, agentspec.Call) (*agentv1.InstanceStatus, error) {
	return nil, unimplemented()
}
func (noDriver) RemoveInstance(context.Context, agentspec.Remove) (*agentv1.RemoveInstanceResponse, error) {
	return nil, unimplemented()
}
func (noDriver) UpgradeInstance(context.Context, agentspec.Upgrade) (*agentv1.InstanceStatus, error) {
	return nil, unimplemented()
}
func (noDriver) WriteDNSRecords(context.Context, agentspec.DNSRecords) (*agentv1.WriteDnsRecordsResponse, error) {
	return nil, unimplemented()
}
func (noDriver) BootstrapPolicy(context.Context, agentspec.Call, agentv1.PolicyKind) (*agentv1.BootstrapPolicyResponse, error) {
	return nil, unimplemented()
}
func (noDriver) BootstrapAPIKey(context.Context, agentspec.APIKey) (*agentv1.BootstrapApiKeyResponse, error) {
	return nil, unimplemented()
}
func (noDriver) Backup(context.Context, agentspec.Backup) (*agentv1.BackupArtifact, error) {
	return nil, unimplemented()
}
func (noDriver) Restore(context.Context, agentspec.Restore) (*agentv1.RestoreResponse, error) {
	return nil, unimplemented()
}
func (noDriver) PostRestoreReconcile(context.Context, agentspec.Reconcile) (*agentv1.PostRestoreReconcileResponse, error) {
	return nil, unimplemented()
}
func (noDriver) EnsureEdgeAttachment(context.Context, agentspec.Call) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	return nil, unimplemented()
}
func (noDriver) RemoveEdgeAttachment(context.Context, agentspec.EdgeDetach) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	return nil, unimplemented()
}
