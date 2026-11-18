package deprovision

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// created_resources of the steps (identifiers only).
type (
	// backupResources: the final backup of step 2 (storage.remove deletes the data directory only against it).
	backupResources struct {
		Skipped  bool      `json:"skipped,omitempty"` // the approved payload skipped it (operator override)
		BackupID uuid.UUID `json:"backup_id,omitzero"`
		Sequence uint64    `json:"sequence,omitempty"`
	}
	// policyResources: what the compensation of policy.suspend applies again.
	policyResources struct {
		FromStatus       string     `json:"from_status"`
		RestoreVersionID *uuid.UUID `json:"restore_version_id,omitempty"`
	}
	// statusResources: the status registry.deprovision moved the tenant from ("" when it found it moved already).
	statusResources struct {
		From string `json:"from"`
	}
	// nodesResources marks the point of no return: recorded just before the first node is expired.
	nodesResources struct {
		PointOfNoReturn bool `json:"point_of_no_return"`
		Nodes           int  `json:"nodes"`
	}
)

func (a *attempt) skip(s *jobs.StepRun, why string) error {
	setDetail(s, map[string]any{"skipped": why})
	return nil
}

func (a *attempt) needAgent() error {
	if a.h.cfg.Agent == nil {
		return jobs.Permanent("agent_not_configured", errors.New("the worker has no Host Agent (MG_AGENT_SOCKET)"))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 2 backup.final

func (a *attempt) finalBackup(ctx context.Context, s *jobs.StepRun) error {
	inst, ok, err := a.instance(ctx)
	if err != nil {
		return err
	}
	if !ok || !liveInstance(inst.Status) {
		a.out("final_backup", "no_instance")
		return a.skip(s, "no_instance")
	}
	if a.in.SkipFinalBackup {
		// the explicit, audited operator override of the approved payload: the data directory is kept (storage.remove)
		if err := record(ctx, s, backupResources{Skipped: true}); err != nil {
			return err
		}
		if err := a.h.security(ctx, audit.SecurityEvent{Kind: EventNoFinalBackup, Severity: audit.SeverityHigh,
			Source: SecuritySource, DedupeKey: EventNoFinalBackup + ":" + a.run.ID.String(), DedupeWindow: 24 * time.Hour,
			Details: audit.Details{"tenant_id": a.in.TenantID, "slug": a.in.Slug, "instance_id": inst.ID, "job_id": a.run.ID,
				"approval_id": a.in.ApprovalID, "requested_by_identity_id": a.in.RequestedBy}}); err != nil {
			return err
		}
		setDetail(s, map[string]any{"skipped": "operator_override", "approval_id": a.in.ApprovalID,
			"data_directory": "kept"})
		a.out("final_backup", "skipped")
		return nil
	}
	if inst.Status == tenants.InstanceQuarantined {
		// quarantined after the approval (the API refuses it without the override): no backup of a suspect instance
		// (P3-T18 — backups skip quarantined instances); failed_resumable before the point of no return: /rollback, then
		// a new request that skips the final backup (its data directory stays for the investigation), or a release
		return jobs.Permanent(ReasonQuarantined, errors.New("the instance was quarantined: no final backup of it"))
	}
	if a.h.cfg.Backups == nil {
		return jobs.Permanent("backup_not_configured", errors.New("the worker takes no backup (agent or manifest key missing)"))
	}
	// a backup this job already recorded (the worker died after it, before the step was recorded succeeded)
	var prev sqlcdb.GetSucceededBackupOfJobRow
	found := false
	if err := a.h.cfg.Store.WithTenantTx(ctx, a.in.TenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetSucceededBackupOfJob(ctx, sqlcdb.GetSucceededBackupOfJobParams{TenantID: a.in.TenantID,
			InstanceID: inst.ID, JobID: a.run.ID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		prev, found = r, err == nil
		return err
	}); err != nil {
		return dbErr("read the backups of the job", err)
	}
	if found && prev.Sequence != nil {
		seq := uint64(*prev.Sequence) //nolint:gosec // G115: sequence > 0 (CHECK)
		if err := record(ctx, s, backupResources{BackupID: prev.ID, Sequence: seq}); err != nil {
			return err
		}
		setDetail(s, map[string]any{"backup_id": prev.ID, "sequence": seq, "reused": true, "expires_at": prev.ExpiresAt})
		a.out("final_backup", prev.ID)
		return nil
	}
	res, err := a.h.cfg.Backups.FinalBackup(ctx, a.run.ID, a.in.TenantID, inst.ID, a.h.cfg.KeyGrace)
	if err != nil {
		var je *jobs.Error
		if errors.As(err, &je) {
			return err
		}
		return jobs.Transient("backup_unavailable", err)
	}
	if res.Skipped != "" {
		return jobs.Permanent("final_backup_"+res.Skipped, fmt.Errorf("the instance cannot be backed up: %s", res.Skipped))
	}
	if err := record(ctx, s, backupResources{BackupID: res.BackupID, Sequence: res.Sequence}); err != nil {
		return err
	}
	setDetail(s, map[string]any{"backup_id": res.BackupID, "sequence": res.Sequence, "method": res.Method,
		"size_bytes": res.SizeBytes, "archive_sha256": res.ArchiveSHA256, "manifest_sha256": res.ManifestSHA256,
		"kept_at_least": a.h.cfg.KeyGrace.String()})
	a.out("final_backup", res.BackupID)
	return nil
}

// ---------------------------------------------------------------------------------------------------- 3 policy.suspend

func (a *attempt) suspendPolicy(ctx context.Context, s *jobs.StepRun) error {
	inst, ok, err := a.instance(ctx)
	if err != nil {
		return err
	}
	if !ok || inst.Status != tenants.InstanceRunning {
		return a.skip(s, "instance_not_running")
	}
	if err := record(ctx, s, policyResources{FromStatus: a.in.FromStatus, RestoreVersionID: a.in.RestoreVersionID}); err != nil {
		return err
	}
	res, err := a.h.cfg.Policies.Apply(ctx, policies.ApplyRequest{TenantID: a.in.TenantID, Kind: policies.KindSuspension,
		HuJSON: a.h.cfg.SuspensionPolicy, Trigger: policies.TriggerSuspend, Actor: Kind})
	d := map[string]any{"application_id": res.ApplicationID, "version_id": res.VersionID, "state": res.State,
		"applied_sha256": res.AppliedSHA256, "readback_sha256": res.ReadbackSHA256, "from_status": a.in.FromStatus}
	if res.ErrorCode != "" {
		d["error_code"] = res.ErrorCode
	}
	setDetail(s, d)
	return applyErr(err)
}

// undoPolicy (rollback): the desired version applied again when the tenant was active; a suspended tenant stays behind
// the suspension policy it had before the job.
func (a *attempt) undoPolicy(ctx context.Context, s jobs.CompensationStep) error {
	var res policyResources
	if found, err := s.Decode(&res); err != nil || !found || res.FromStatus != tenants.StatusActive {
		return err
	}
	if res.RestoreVersionID == nil {
		return jobs.Permanent("no_policy_to_restore", errors.New("the tenant had no desired policy version"))
	}
	var text string
	err := a.h.cfg.Store.WithTenantTx(ctx, a.in.TenantID, func(q *sqlcdb.Queries) error {
		v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: a.in.TenantID, ID: *res.RestoreVersionID})
		if err != nil {
			return err
		}
		if v.SourceHujson == nil {
			return jobs.Permanent("desired_not_hujson", fmt.Errorf("version %s has no HuJSON source", v.ID))
		}
		text = *v.SourceHujson
		return nil
	})
	if errors.Is(err, store.ErrNoRows) {
		return jobs.Permanent("registry_state", errors.New("the desired policy version is gone"))
	}
	if err != nil {
		return dbErr("read the desired policy", err)
	}
	_, err = a.h.cfg.Policies.Apply(ctx, policies.ApplyRequest{TenantID: a.in.TenantID, Kind: policies.KindBaseline,
		HuJSON: text, Trigger: policies.TriggerResume, Actor: Kind + " (rollback)"})
	return applyErr(err)
}

// ---------------------------------------------------------------------------------------------------- 4 registry.deprovision

func (a *attempt) toDeprovisioning(ctx context.Context, s *jobs.StepRun) error {
	var res statusResources
	found, err := s.Previous(&res)
	if err != nil {
		return err
	}
	t, err := a.h.tenant(ctx, a.in.TenantID)
	if err != nil {
		return err
	}
	to := tenants.StatusDeprovisioning
	switch {
	case t.Status == to:
		if !found {
			res.From = "" // not this job's change: nothing to undo
			if err := record(ctx, s, res); err != nil {
				return err
			}
		}
		setDetail(s, map[string]any{"from": res.From, "to": to, "changed": false})
		return nil
	case t.Status != a.in.FromStatus:
		return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s, not %s", t.ID, t.Status, a.in.FromStatus))
	}
	if err := record(ctx, s, statusResources{From: a.in.FromStatus}); err != nil {
		return err
	}
	err = a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: to, ID: t.ID, FromStatus: a.in.FromStatus})
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return jobs.Transient("registry_changed", fmt.Errorf("tenant %s changed status meanwhile", t.ID))
	}
	if err != nil {
		return dbErr("move the tenant to deprovisioning", err)
	}
	setDetail(s, map[string]any{"from": a.in.FromStatus, "to": to, "changed": true})
	return nil
}

// undoDeprovisioning (rollback): deprovisioning → the status this job moved the tenant from.
func (a *attempt) undoDeprovisioning(ctx context.Context, s jobs.CompensationStep) error {
	var res statusResources
	found, err := s.Decode(&res)
	if err != nil || !found || res.From == "" {
		return err
	}
	err = a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: res.From, ID: a.in.TenantID,
			FromStatus: tenants.StatusDeprovisioning})
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		t, terr := a.h.tenant(ctx, a.in.TenantID)
		switch {
		case terr != nil:
			return terr
		case t.Status == res.From:
			return nil // undone by an earlier, interrupted compensation
		}
		return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s, not deprovisioning", a.in.TenantID, t.Status))
	}
	if err != nil {
		return dbErr("restore the tenant status", err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 5 nodes.expire

// expireNodes is the point of no return: every node of the tenant's instance expires (its devices must authenticate
// again — §11.4 "expire toàn bộ node"), every pre-auth key that can still register a node too; both read back.
func (a *attempt) expireNodes(ctx context.Context, s *jobs.StepRun) error {
	inst, ok, err := a.instance(ctx)
	if err != nil {
		return err
	}
	if !ok || !liveInstance(inst.Status) {
		if err := record(ctx, s, nodesResources{PointOfNoReturn: true}); err != nil {
			return err
		}
		return a.skip(s, "no_instance")
	}
	if inst.Status == tenants.InstanceQuarantined {
		// P3-T18: the quarantine stopped the container and detached the edge, and the locator refuses the instance — no
		// client reaches this Headscale and no call of the job can either. The registry marks it removed at step 13, so it
		// is never started again; its database stays in the kept data directory for the investigation.
		if err := record(ctx, s, nodesResources{PointOfNoReturn: true}); err != nil {
			return err
		}
		a.out("nodes_expired", "instance_quarantined")
		return a.skip(s, "instance_quarantined")
	}
	cctx, cancel := a.h.call(ctx)
	defer cancel()
	hs, err := a.h.cfg.Headscale.ForTenant(cctx, a.in.TenantID)
	if err != nil {
		return headscaleErr("ForTenant", err)
	}
	nodes, err := hs.ListNodes(cctx, "")
	if err != nil {
		return headscaleErr("ListNodes", err)
	}
	// recorded BEFORE the first irreversible action: from here /rollback is refused
	if err := record(ctx, s, nodesResources{PointOfNoReturn: true, Nodes: len(nodes)}); err != nil {
		return err
	}
	now := a.h.cfg.Now().UTC()
	var expired []uint64
	for _, n := range nodes {
		if n.Expiry != nil && !n.Expiry.After(now) {
			continue // expired already (an earlier attempt, or by itself)
		}
		at := now
		if _, err := hs.ExpireNode(cctx, n.ID, &at); err != nil {
			setDetail(s, map[string]any{"nodes": len(nodes), "expired_ids": expired})
			return headscaleErr("ExpireNode", err)
		}
		expired = append(expired, n.ID)
	}
	keys, err := hs.ListPreAuthKeys(cctx)
	if err != nil {
		return headscaleErr("ListPreAuthKeys", err)
	}
	var keysExpired []uint64
	for _, k := range lifecycle.ValidPreAuthKeys(keys, now) {
		if err := hs.ExpirePreAuthKey(cctx, k.ID); err != nil {
			return headscaleErr("ExpirePreAuthKey", err)
		}
		keysExpired = append(keysExpired, k.ID)
	}
	again, err := hs.ListNodes(cctx, "")
	if err != nil {
		return headscaleErr("ListNodes", err)
	}
	check := a.h.cfg.Now().UTC()
	valid := 0
	for _, n := range again {
		if n.Expiry == nil || n.Expiry.After(check) {
			valid++
		}
	}
	keysAgain, err := hs.ListPreAuthKeys(cctx)
	if err != nil {
		return headscaleErr("ListPreAuthKeys", err)
	}
	validKeys := len(lifecycle.ValidPreAuthKeys(keysAgain, check))
	setDetail(s, map[string]any{"nodes": len(nodes), "expired_ids": expired, "preauth_keys": len(keys),
		"preauth_keys_expired": keysExpired, "still_valid_nodes": valid, "still_valid_preauth_keys": validKeys})
	a.out("nodes_expired", len(expired))
	if valid > 0 || validKeys > 0 {
		// a node registered meanwhile (writes and logins are already refused) or an expiry not applied: retried
		return jobs.Transient("nodes_still_valid", fmt.Errorf("%d node(s), %d pre-auth key(s) still valid", valid, validKeys))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 6 access.revoke

func (a *attempt) revokeAccess(ctx context.Context, s *jobs.StepRun) error {
	now := a.h.cfg.Now().UTC()
	var sessions, logins, approvals, left int64
	err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if sessions, err = q.RevokeTenantSessions(ctx, sqlcdb.RevokeTenantSessionsParams{Now: now, TenantID: a.in.TenantID}); err != nil {
			return err
		}
		if logins, err = q.DeleteTenantAuthRequests(ctx, a.in.TenantID); err != nil {
			return err
		}
		if approvals, err = q.ExpireTenantApprovals(ctx, a.in.TenantID); err != nil {
			return err
		}
		left, err = q.CountLiveTenantSessions(ctx, a.in.TenantID)
		return err
	})
	if err != nil {
		return dbErr("revoke the sessions, logins and approvals", err)
	}
	var invitations int64
	if err := a.h.cfg.Store.WithTenantTx(ctx, a.in.TenantID, func(q *sqlcdb.Queries) error {
		var err error
		invitations, err = q.RevokeTenantPendingInvitations(ctx, sqlcdb.RevokeTenantPendingInvitationsParams{Now: now,
			TenantID: a.in.TenantID})
		return err
	}); err != nil {
		return dbErr("revoke the pending invitations", err)
	}
	setDetail(s, map[string]any{"sessions_revoked": sessions, "auth_requests_deleted": logins, "approvals_expired": approvals,
		"invitations_revoked": invitations, "sessions_left": left,
		"support_grants": "none — support_access_grants arrives with P4-T13, which revokes them here"})
	a.out("sessions_revoked", sessions)
	if left > 0 {
		return jobs.Transient("sessions_still_live", fmt.Errorf("%d session(s) still live", left))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 7 targets.remove

// TargetLists are the schedule target lists of the registry ("service discovery" of the platform's periodic work):
// the instance of a deprovisioning tenant must be in none of them.
var TargetLists = []string{"health.probe", "relay.probe", "inventory.sync", "instance.backup", "apikey.rotate"}

// listed returns the target lists that still name the tenant (or its instance).
func listed(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) ([]string, error) {
	var out []string
	add := func(name string, ids []uuid.UUID) {
		if slices.Contains(ids, tenantID) {
			out = append(out, name)
		}
	}
	hp, err := q.ListHealthProbeTargets(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(hp))
	for _, r := range hp {
		ids = append(ids, r.TenantID)
	}
	add("health.probe", ids)
	rp, err := q.ListRelayProbeTargets(ctx)
	if err != nil {
		return nil, err
	}
	ids = ids[:0]
	for _, r := range rp {
		ids = append(ids, r.TenantID)
	}
	add("relay.probe", ids)
	ri, err := q.ListRunningInstances(ctx)
	if err != nil {
		return nil, err
	}
	ids = ids[:0]
	for _, r := range ri {
		ids = append(ids, r.TenantID)
	}
	add("inventory.sync", ids)
	bs, err := q.ListBackupSchedule(ctx)
	if err != nil {
		return nil, err
	}
	ids = ids[:0]
	for _, r := range bs {
		ids = append(ids, r.TenantID)
	}
	add("instance.backup", ids)
	ak, err := q.ListAPIKeyExpiries(ctx)
	if err != nil {
		return nil, err
	}
	ids = ids[:0]
	for _, r := range ak {
		ids = append(ids, r.TenantID)
	}
	add("apikey.rotate", ids)
	return out, nil
}

// Listed returns the schedule target lists (TargetLists) that still name the tenant — empty once it is deprovisioning
// or deleted. Platform pool.
func Listed(ctx context.Context, st *store.Store, tenantID uuid.UUID) ([]string, error) {
	var out []string
	err := st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		out, err = listed(ctx, q, tenantID)
		return err
	})
	return out, err
}

func (a *attempt) removeTargets(ctx context.Context, s *jobs.StepRun) error {
	still, err := Listed(ctx, a.h.cfg.Store, a.in.TenantID)
	if err != nil {
		return dbErr("read the target lists", err)
	}
	setDetail(s, map[string]any{"checked": TargetLists, "still_listed": still})
	if len(still) > 0 {
		return jobs.Transient("targets_still_listed", fmt.Errorf("the tenant is still a target of %v", still))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- 8 edge.detach

func (a *attempt) detachEdge(ctx context.Context, s *jobs.StepRun) error {
	inst, ok, err := a.instance(ctx)
	if err != nil {
		return err
	}
	if !ok || !liveInstance(inst.Status) {
		return a.skip(s, "no_instance")
	}
	if err := a.needAgent(); err != nil {
		return err
	}
	cctx, cancel := a.h.call(ctx)
	defer cancel()
	// the agent removes the edge_attach flag first, then detaches the shared edge (§11.4 order)
	r, err := a.h.cfg.Agent.RemoveEdgeAttachment(cctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: a.ref(),
		JobId: a.run.ID.String(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION})
	switch {
	case err != nil && notFoundAtAgent(err):
		return a.skip(s, "absent_at_agent")
	case err != nil:
		return agentErr("RemoveEdgeAttachment", err)
	}
	setDetail(s, map[string]any{"detached": r.GetDetached(), "was_attached": r.GetWasAttached()})
	return nil
}

// ---------------------------------------------------------------------------------------------------- 9 instance.remove

func (a *attempt) removeInstance(ctx context.Context, s *jobs.StepRun) error {
	inst, ok, err := a.instance(ctx)
	if err != nil {
		return err
	}
	if !ok || !liveInstance(inst.Status) {
		return a.skip(s, "no_instance")
	}
	if err := a.needAgent(); err != nil {
		return err
	}
	cctx, cancel := a.h.call(ctx)
	defer cancel()
	// compose down, then the network (the agent refuses while the edge is still attached)
	r, err := a.h.cfg.Agent.RemoveInstance(cctx, &agentv1.RemoveInstanceRequest{Instance: a.ref(), JobId: a.run.ID.String(),
		Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP})
	if err != nil && !notFoundAtAgent(err) {
		return agentErr("RemoveInstance(KEEP)", err)
	}
	var moved bool
	if err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		for _, from := range []string{tenants.InstanceRunning, tenants.InstanceStarting} {
			_, err := q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{
				Status: tenants.InstanceStopped, ID: inst.ID, TenantID: a.in.TenantID, FromStatus: from})
			if err == nil {
				moved = true
				return nil
			}
			if !errors.Is(err, store.ErrNoRows) {
				return err
			}
		}
		return nil
	}); err != nil {
		return dbErr("mark the instance stopped", err)
	}
	setDetail(s, map[string]any{"container_removed": r.GetContainerRemoved(), "network_removed": r.GetNetworkRemoved(),
		"instance_stopped": moved})
	return nil
}

// ---------------------------------------------------------------------------------------------------- 10 storage.remove

func (a *attempt) removeStorage(ctx context.Context, s *jobs.StepRun) error {
	inst, ok, err := a.instance(ctx)
	if err != nil {
		return err
	}
	if !ok || !liveInstance(inst.Status) {
		return a.skip(s, "no_instance")
	}
	if inst.Status == tenants.InstanceQuarantined {
		// P3-T18: the data of a quarantined instance is evidence (the agent refuses to delete it — meta/quarantined)
		setDetail(s, map[string]any{"data_directory": "kept", "reason": "instance_quarantined"})
		a.out("data_directory", "kept")
		return nil
	}
	var b backupResources
	found, err := a.run.StepResources(ctx, StepFinalBackup, &b)
	if err != nil {
		return err
	}
	if !found || b.Skipped || b.Sequence == 0 {
		// no final backup (approved override): the directory — the only copy of the data — is kept in place
		setDetail(s, map[string]any{"data_directory": "kept", "reason": "no_final_backup"})
		a.out("data_directory", "kept")
		return nil
	}
	if err := a.needAgent(); err != nil {
		return err
	}
	cctx, cancel := a.h.call(ctx)
	defer cancel()
	// the agent deletes the directory only when the archive of this sequence exists with a valid signed manifest of
	// this very instance (§11.5 DELETE_ARCHIVED)
	r, err := a.h.cfg.Agent.RemoveInstance(cctx, &agentv1.RemoveInstanceRequest{Instance: a.ref(), JobId: a.run.ID.String(),
		Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED, ArchivedBackupSequence: b.Sequence})
	if err != nil && !notFoundAtAgent(err) {
		return agentErr("RemoveInstance(DELETE_ARCHIVED)", err)
	}
	setDetail(s, map[string]any{"directory_removed": r.GetDirectoryRemoved(), "archived_backup_sequence": b.Sequence,
		"backup_id": b.BackupID})
	a.out("data_directory", "deleted_archived")
	return nil
}

// ---------------------------------------------------------------------------------------------------- 11 idp.disable

func (a *attempt) disableIdP(ctx context.Context, s *jobs.StepRun) error {
	var rows []sqlcdb.ListTenantIdentityProvidersRow
	if err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListTenantIdentityProviders(ctx, a.in.TenantID)
		return err
	}); err != nil {
		return dbErr("list the identity providers", err)
	}
	var disabled []uuid.UUID
	for _, r := range rows {
		if r.Status == "disabled" {
			continue
		}
		reg := registration(a.in.TenantID, r)
		if reg.DriverRef != "" || r.Driver == idp.DriverExternal {
			drv, err := a.h.cfg.IdP.Driver(r.Driver)
			if err != nil {
				return jobs.Permanent("idp_unknown_driver", err)
			}
			cctx, cancel := a.h.call(ctx)
			_, err = drv.RemoveIssuer(cctx, reg, idp.RemoveDisable)
			cancel()
			if err != nil && idp.CodeOf(err) != idp.CodeNotFound {
				return idpErr("RemoveIssuer(disable)", err)
			}
		}
		if err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			_, err := q.TransitionIdentityProviderStatus(ctx, sqlcdb.TransitionIdentityProviderStatusParams{Status: "disabled",
				ID: r.ID, TenantID: &a.in.TenantID, FromStatus: r.Status})
			if errors.Is(err, store.ErrNoRows) {
				return nil // changed meanwhile: the next attempt reads it again
			}
			return err
		}); err != nil {
			return dbErr("disable the identity provider", err)
		}
		disabled = append(disabled, r.ID)
	}
	setDetail(s, map[string]any{"identity_providers": len(rows), "disabled": disabled})
	return nil
}

func registration(tenantID uuid.UUID, r sqlcdb.ListTenantIdentityProvidersRow) idp.Registration {
	reg := idp.Registration{IdPID: r.ID, Scope: idp.ScopeTenant, TenantID: tenantID, Driver: r.Driver, Issuer: r.Issuer,
		ClientID: r.ClientID}
	if r.ClientSecretRef != nil {
		reg.ClientSecretRef = *r.ClientSecretRef
	}
	if r.DriverRef != nil {
		reg.DriverRef = *r.DriverRef
	}
	return reg
}

// ---------------------------------------------------------------------------------------------------- 12 relay.remove

func (a *attempt) removeRelay(ctx context.Context, s *jobs.StepRun) error {
	var assignments, regions int64
	err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if assignments, err = q.DeleteTenantRelayAssignments(ctx, a.in.TenantID); err != nil {
			return err
		}
		if regions, err = q.DeleteTenantEmbeddedRelayRegions(ctx, a.in.TenantID); err != nil {
			return err
		}
		left, err := q.CountTenantRelayRows(ctx, a.in.TenantID)
		if err != nil {
			return err
		}
		if left.Assignments+left.Regions > 0 {
			return jobs.Transient("relay_rows_left", fmt.Errorf("%d assignment(s), %d region(s) left", left.Assignments, left.Regions))
		}
		return nil
	})
	if err != nil {
		return dbErr("delete the relay rows", err)
	}
	setDetail(s, map[string]any{"assignments_deleted": assignments, "regions_deleted": regions})
	return nil
}

// ---------------------------------------------------------------------------------------------------- 13 registry.delete

func (a *attempt) deleteRegistry(ctx context.Context, s *jobs.StepRun) error {
	now := a.h.cfg.Now().UTC()
	var (
		instances, subs int64
		changed         bool
	)
	err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if instances, err = q.RemoveTenantInstances(ctx, a.in.TenantID); err != nil {
			return err
		}
		if subs, err = q.CancelTenantSubscriptions(ctx, a.in.TenantID); err != nil {
			return err
		}
		_, err = q.MarkTenantDeleted(ctx, sqlcdb.MarkTenantDeletedParams{Now: now, ID: a.in.TenantID})
		if errors.Is(err, store.ErrNoRows) {
			t, terr := q.GetTenant(ctx, a.in.TenantID)
			if terr != nil {
				return terr
			}
			if t.Status != tenants.StatusDeleted {
				return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s, not deprovisioning", t.ID, t.Status))
			}
			return nil // deleted by an earlier attempt
		}
		changed = err == nil
		return err
	})
	if err != nil {
		return dbErr("delete the tenant", err)
	}
	// the instance API key dies with the instance: its secret versions are destroyed now (the rest of the tenant's
	// secrets — the backup key of the final backup, the IdP client secret — wait for the crypto-shredding)
	destroyed, err := a.destroyAPIKey(ctx)
	if err != nil {
		return err
	}
	setDetail(s, map[string]any{"instances_removed": instances, "subscriptions_cancelled": subs, "tenant_deleted": changed,
		"apikey_versions_destroyed": destroyed})
	return nil
}

func (a *attempt) destroyAPIKey(ctx context.Context) (int, error) {
	latest, err := a.h.cfg.Secrets.Latest(ctx, a.in.TenantID, provisioning.APIKeySecretName)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		return 0, nil
	case err != nil:
		return 0, jobs.Transient("secret_store_unavailable", err)
	}
	n := 0
	for v := int32(1); v <= latest.Version; v++ {
		err := a.h.cfg.Secrets.Destroy(ctx, secrets.TenantRef(a.in.TenantID, provisioning.APIKeySecretName, v))
		switch {
		case err == nil:
			n++
		case errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrDestroyed):
		default:
			return n, jobs.Transient("secret_store_unavailable", err)
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------------------------------- 14 keys.schedule

func (a *attempt) scheduleKeys(ctx context.Context, s *jobs.StepRun) error {
	var t sqlcdb.Tenant
	err := a.h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if t, err = q.GetTenant(ctx, a.in.TenantID); err != nil {
			return err
		}
		if t.Status != tenants.StatusDeleted || t.DeletedAt == nil {
			return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s", t.ID, t.Status))
		}
		if t.KeysDestroyAfter != nil {
			return nil // scheduled by an earlier attempt
		}
		t, err = q.ScheduleTenantKeysDestruction(ctx, sqlcdb.ScheduleTenantKeysDestructionParams{
			After: t.DeletedAt.Add(a.h.cfg.KeyGrace).UTC(), ID: t.ID})
		return err
	})
	if err != nil {
		return dbErr("schedule the destruction of the keys", err)
	}
	setDetail(s, map[string]any{"deleted_at": t.DeletedAt, "keys_destroy_after": t.KeysDestroyAfter,
		"grace": a.h.cfg.KeyGrace.String()})
	a.out("keys_destroy_after", t.KeysDestroyAfter)
	return nil
}

// ---------------------------------------------------------------------------------------------------- 15 notify

func (a *attempt) notify(ctx context.Context, s *jobs.StepRun) error {
	t, err := a.h.tenant(ctx, a.in.TenantID)
	if err != nil {
		return err
	}
	if t.KeysDestroyAfter == nil {
		return jobs.Permanent("registry_state", errors.New("the destruction of the keys is not scheduled"))
	}
	var b backupResources
	found, err := a.run.StepResources(ctx, StepFinalBackup, &b)
	if err != nil {
		return err
	}
	kept := found && !b.Skipped && b.Sequence > 0
	var notified int
	if err := a.h.cfg.Store.WithTenantJobTx(ctx, a.in.TenantID, func(tx *store.Tx) error {
		r, err := a.h.cfg.Notifier.Enqueue(ctx, tx, notifications.TenantDeleted(a.in.TenantID, a.run.ID, *t.KeysDestroyAfter, kept))
		notified = len(r.Notifications)
		return err
	}); err != nil {
		if errors.Is(err, notifications.ErrInvalidEvent) || errors.Is(err, notifications.ErrNoTenant) {
			return jobs.Permanent("notification_invalid", err)
		}
		return dbErr("write the notification", err)
	}
	if err := a.h.closeOperation(ctx, a.in, func(q *sqlcdb.Queries) error {
		return a.in.Operation.Succeeded(ctx, q, audit.Details{"job_id": a.run.ID, "keys_destroy_after": t.KeysDestroyAfter,
			"final_backup_kept": kept, "approval_id": a.in.ApprovalID})
	}); err != nil {
		return err
	}
	setDetail(s, map[string]any{"notifications": notified, "kind": string(notifications.KindTenantDeleted)})
	a.out("status", tenants.StatusDeleted)
	return nil
}
