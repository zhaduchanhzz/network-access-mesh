package main

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose"
)

// Driver performs the operations once they are validated, authorised, locked and guarded. It only ever receives
// agentspec values — never a raw request. The compose driver (internal/provisioning/driver/compose, P3-T02) implements
// it together with agentspec.Inventory.
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
	// Quarantine (§11.4, P3-T18): Quarantined reports meta/quarantined (false when the instance has no directory) —
	// the server refuses with it every call that could make a quarantined instance serve or change it.
	Quarantined(ctx context.Context, ref agentspec.Ref) (bool, error)
	QuarantineInstance(ctx context.Context, c agentspec.Call) (*agentv1.QuarantineInstanceResponse, error)
	ReleaseInstance(ctx context.Context, r agentspec.Release) (*agentv1.ReleaseInstanceResponse, error)
}

// composeDriver is the driver of the agent: the compose driver for EnsureInstance (storage → config → network →
// container), status, inventory, start/stop/restart and remove (P3-T02); ValidateConfig (configtest in a throw-away
// container), BootstrapPolicy, BootstrapApiKey, the edge attachment, the start guard and the edge supervisor (P3-T03).
// Still UNIMPLEMENTED (after validation, authorisation, lock and guard): WriteDnsRecords, Backup/Restore/
// PostRestoreReconcile (P3-T11), UpgradeInstance (P3-T13a).
type composeDriver struct {
	noDriver
	c *compose.Driver
}

func (d composeDriver) Name() string { return d.c.Name() }
func (d composeDriver) ValidateConfig(ctx context.Context, s agentspec.InstanceSpec) (*agentv1.ValidateConfigResponse, error) {
	return d.c.ValidateConfig(ctx, s)
}
func (d composeDriver) EnsureInstance(ctx context.Context, e agentspec.Ensure) (*agentv1.EnsureInstanceResponse, error) {
	return d.c.EnsureInstance(ctx, e)
}
func (d composeDriver) InstanceStatus(ctx context.Context, ref agentspec.Ref, includeAPIKeys bool) (*agentv1.InstanceStatus, error) {
	return d.c.InstanceStatus(ctx, ref, includeAPIKeys)
}
func (d composeDriver) ListInstances(ctx context.Context) ([]*agentv1.InventoryEntry, error) {
	return d.c.ListInstances(ctx)
}
func (d composeDriver) StartInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error) {
	return d.c.StartInstance(ctx, c)
}
func (d composeDriver) StopInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error) {
	return d.c.StopInstance(ctx, c)
}
func (d composeDriver) RestartInstance(ctx context.Context, c agentspec.Call) (*agentv1.InstanceStatus, error) {
	return d.c.RestartInstance(ctx, c)
}
func (d composeDriver) RemoveInstance(ctx context.Context, r agentspec.Remove) (*agentv1.RemoveInstanceResponse, error) {
	return d.c.RemoveInstance(ctx, r)
}
func (d composeDriver) BootstrapPolicy(ctx context.Context, c agentspec.Call, kind agentv1.PolicyKind) (*agentv1.BootstrapPolicyResponse, error) {
	return d.c.BootstrapPolicy(ctx, c, kind)
}
func (d composeDriver) BootstrapAPIKey(ctx context.Context, k agentspec.APIKey) (*agentv1.BootstrapApiKeyResponse, error) {
	return d.c.BootstrapAPIKey(ctx, k)
}
func (d composeDriver) EnsureEdgeAttachment(ctx context.Context, c agentspec.Call) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	return d.c.EnsureEdgeAttachment(ctx, c)
}
func (d composeDriver) RemoveEdgeAttachment(ctx context.Context, r agentspec.EdgeDetach) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	return d.c.RemoveEdgeAttachment(ctx, r)
}
func (d composeDriver) Quarantined(ctx context.Context, ref agentspec.Ref) (bool, error) {
	return d.c.Quarantined(ctx, ref)
}
func (d composeDriver) QuarantineInstance(ctx context.Context, c agentspec.Call) (*agentv1.QuarantineInstanceResponse, error) {
	return d.c.QuarantineInstance(ctx, c)
}
func (d composeDriver) ReleaseInstance(ctx context.Context, r agentspec.Release) (*agentv1.ReleaseInstanceResponse, error) {
	return d.c.ReleaseInstance(ctx, r)
}

// EdgeCycle / EdgeStarts make composeDriver an edgeSupervisor (supervisor.go).
func (d composeDriver) EdgeCycle(ctx context.Context, tryLock func(uuid.UUID) (func(), bool)) (compose.EdgeReport, error) {
	return d.c.EdgeCycle(ctx, tryLock)
}
func (d composeDriver) EdgeStarts(ctx context.Context) <-chan struct{} { return d.c.EdgeStarts(ctx) }

// noDriver answers UNIMPLEMENTED for every operation (MG_AGENT_DRIVER=none, and the operations composeDriver does not
// implement yet) — after the request was validated, authorised, locked and guarded.
type noDriver struct{}

func unimplemented() error {
	return status.Error(codes.Unimplemented, "not implemented by this agent's driver yet")
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

// Quarantined: without a driver there is no instance directory, hence no marker.
func (noDriver) Quarantined(context.Context, agentspec.Ref) (bool, error) { return false, nil }
func (noDriver) QuarantineInstance(context.Context, agentspec.Call) (*agentv1.QuarantineInstanceResponse, error) {
	return nil, unimplemented()
}
func (noDriver) ReleaseInstance(context.Context, agentspec.Release) (*agentv1.ReleaseInstanceResponse, error) {
	return nil, unimplemented()
}
