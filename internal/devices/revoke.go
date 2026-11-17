package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// RevokeResult is the answer to a revocation request: the device with its revocation state and the job that carries
// the revocation (Location of the 202).
type RevokeResult struct {
	Device Device
	JobID  uuid.UUID
	// Created is false when no new revocation started: the same kind was already pending, or the request replayed
	// an Idempotency-Key.
	Created bool
}

// revokeInput is the input of a device.revoke job. The kind and the explicit expiry time come from the device row at
// run time (revocation_kind, revocation_requested_at); the input names the device and carries the audit operation.
type revokeInput struct {
	DeviceID  uuid.UUID        `json:"device_id"`
	Kind      string           `json:"kind"`
	Operation *audit.Operation `json:"operation,omitempty"`
}

// Revoke starts the two-phase revocation of a device (POST …/expire: kind expire, DELETE …/devices/{id}: kind delete,
// §7.4, T-17): in one transaction the device turns pending, device.<kind>.requested is written and the job
// device.revoke is enqueued (§13.5). The device is applied only once the job read the node back. A device already
// pending for the same kind answers its current state and job; another kind pending is a conflict.
func (s *Service) Revoke(ctx context.Context, tenantID, deviceID uuid.UUID, a Access, kind, requestKey string) (RevokeResult, error) {
	if kind != RevokeExpire && kind != RevokeDelete {
		return RevokeResult{}, invalid("kind", "unknown revocation kind")
	}
	action := ActionExpire
	if kind == RevokeDelete {
		action = ActionDelete
	}
	var (
		res     RevokeResult
		op      audit.Operation
		started bool
	)
	errReplay := errors.New("devices: replayed revocation")
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		row, err := q.LockLiveDevice(ctx, sqlcdb.LockLiveDeviceParams{TenantID: tenantID, ID: deviceID})
		if errors.Is(err, store.ErrNoRows) {
			return notFound(ReasonNoDevice)
		}
		if err != nil {
			return err
		}
		if !a.owns(row) {
			return notFound(ReasonNotOwnResource)
		}
		if row.RevocationState == StatePending {
			if deref(row.RevocationKind) != kind || row.RevocationJobID == nil {
				return conflict(ReasonRevocationInProgress, "Another revocation of this device is in progress.")
			}
			// The same revocation again: nothing new starts; the request is still on record.
			if err := audit.Record(ctx, q, audit.Event{Action: action, TenantID: &tenantID, ResourceType: resourceDevice,
				ResourceID: deviceID.String(), Details: audit.Details{"kind": kind, "state": StatePending, "repeated": true}}); err != nil {
				return err
			}
			res.JobID = *row.RevocationJobID
			return nil
		}
		row, err = q.StartDeviceRevocation(ctx, sqlcdb.StartDeviceRevocationParams{Kind: &kind, TenantID: tenantID, ID: deviceID})
		if err != nil {
			return err
		}
		op, err = audit.Requested(ctx, q, audit.Event{Action: action, TenantID: &tenantID, ResourceType: resourceDevice,
			ResourceID: deviceID.String(), Details: audit.Details{"kind": kind, "node_id": row.HeadscaleNodeID}})
		if err != nil {
			return err
		}
		enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindRevoke, TenantID: &tenantID, Object: deviceID.String(),
			Input: revokeInput{DeviceID: deviceID, Kind: kind, Operation: &op}, RequestKey: requestKey,
			RequestedBy: a.requestedBy(), Resource: &jobs.Resource{Type: resourceDevice, ID: deviceID.String()}})
		switch {
		case errors.Is(err, jobs.ErrRequestKeyReuse) && enq.Job.Kind == KindRevoke && enq.Job.Resource != nil &&
			enq.Job.Resource.ID == deviceID.String():
			// The earlier request with this Idempotency-Key on this device (its input differs only by the new
			// operation id): answer with its job, start nothing.
			res.JobID = enq.Job.ID
			return errReplay
		case errors.Is(err, jobs.ErrRequestKeyReuse):
			return &Error{Code: CodeIdempotencyKeyReuse, Reason: "idempotency_key_reuse", Err: err,
				Detail: "The Idempotency-Key was used for another request."}
		case err != nil:
			return err
		case !enq.Created: // an earlier revocation job of the device is still finishing
			return conflict(ReasonJobInProgress, "A revocation of this device is still finishing; try again shortly.")
		}
		if err := q.SetDeviceRevocationJob(ctx, sqlcdb.SetDeviceRevocationJobParams{JobID: &enq.Job.ID, TenantID: tenantID,
			ID: deviceID}); err != nil {
			return err
		}
		res.JobID, res.Created, started = enq.Job.ID, true, true
		return nil
	})
	if err != nil && !errors.Is(err, errReplay) {
		if e, ok := AsError(err); ok {
			return RevokeResult{}, e
		}
		return RevokeResult{}, fmt.Errorf("devices: revoke: %w", err)
	}
	if started {
		audit.HandOff(ctx, op)
	}
	d, err := s.readDevice(ctx, tenantID, deviceID)
	if err != nil {
		return RevokeResult{}, err
	}
	res.Device = d
	return res, nil
}

// readDevice reads a device for a response (live or not — a revocation may have removed it meanwhile).
func (s *Service) readDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (Device, error) {
	var d Device
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetLiveDevice(ctx, sqlcdb.GetLiveDeviceParams{TenantID: tenantID, ID: deviceID})
		if err == nil {
			d = deviceOf(r.DeviceInventoryCache, r.OwnerDisplay)
			return nil
		}
		if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		row, err := q.LockDevice(ctx, sqlcdb.LockDeviceParams{TenantID: tenantID, ID: deviceID})
		if err != nil {
			return err
		}
		d = deviceOf(row, "")
		return nil
	})
	if err != nil {
		return Device{}, fmt.Errorf("devices: read device: %w", err)
	}
	return d, nil
}

// errReadback: Headscale answered the write but the read-back does not show it yet ⇒ stay pending and retry.
var errReadback = errors.New("devices: read-back does not match the revocation")

// revokeOutcome is what the job verified on the instance.
type revokeOutcome struct {
	gone        bool       // the node no longer exists (deleted, or its id now belongs to another machine)
	expiry      *time.Time // read-back expiry of an expired node
	keysExpired int        // pre-auth keys expired so the device cannot register again by itself (§7.4)
}

// runRevoke is the handler of device.revoke (§13.5): idempotent — every step can run again after a retry.
func (s *Service) runRevoke(ctx context.Context, run *jobs.Run) error {
	var in revokeInput
	if err := run.DecodeInput(&in); err != nil {
		return jobs.Permanent("invalid_input", fmt.Errorf("device.revoke input: %w", err))
	}
	if in.DeviceID == uuid.Nil || run.TenantID == nil {
		return jobs.Permanent("invalid_input", errors.New("device.revoke input: no device or no tenant"))
	}
	tenantID := *run.TenantID
	var row sqlcdb.DeviceInventoryCache
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.LockDevice(ctx, sqlcdb.LockDeviceParams{TenantID: tenantID, ID: in.DeviceID})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows): // deleted by retention: nothing left to revoke
		_ = run.SetOutput(map[string]any{"skipped": "no_device"})
		return nil
	case err != nil:
		return jobs.Transient("internal_error", err)
	}
	if row.RevocationState != StatePending || row.RevocationJobID == nil || *row.RevocationJobID != run.ID {
		// Settled by an earlier attempt, or superseded by a newer request: this job has nothing left to do.
		_ = run.SetOutput(map[string]any{"skipped": "not_pending", "state": row.RevocationState})
		return nil
	}
	kind := deref(row.RevocationKind)
	requestedAt := s.now()
	if row.RevocationRequestedAt != nil {
		requestedAt = *row.RevocationRequestedAt
	}
	out, err := s.revokeNode(ctx, tenantID, row, kind, requestedAt)
	if err != nil {
		code := ReasonReadbackMismatch
		if !errors.Is(err, errReadback) {
			code = fromAdapter(err).Code
		}
		permanent := !errors.Is(err, errReadback) && !transient(err)
		if permanent || run.Attempt >= run.MaxAttempts {
			s.settle(ctx, tenantID, row, run.ID, StateFailed, in.Operation, code, revokeOutcome{})
			if permanent {
				return jobs.Permanent(code, err)
			}
		}
		return jobs.Transient(code, err)
	}
	if !s.settle(ctx, tenantID, row, run.ID, StateApplied, in.Operation, "", out) {
		return jobs.Transient("settle_failed", errors.New("recording the applied revocation failed"))
	}
	_ = run.SetOutput(map[string]any{"state": StateApplied, "kind": kind, "node_gone": out.gone,
		"preauth_keys_expired": out.keysExpired})
	return nil
}

// revokeNode applies the revocation on the instance and reads it back. The node is identified by node id AND machine
// key: a node id handed out again to another machine (restore) is never touched — the device's node is gone.
func (s *Service) revokeNode(ctx context.Context, tenantID uuid.UUID, row sqlcdb.DeviceInventoryCache, kind string,
	requestedAt time.Time,
) (revokeOutcome, error) {
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		return revokeOutcome{}, err
	}
	nodeID := uint64(row.HeadscaleNodeID) //nolint:gosec // CHECK headscale_node_id > 0
	node, err := inst.GetNode(ctx, nodeID)
	switch {
	case isGone(err) || err == nil && node.MachineKey != row.MachineKey:
		return revokeOutcome{gone: true}, nil
	case err != nil:
		return revokeOutcome{}, err
	}
	var out revokeOutcome
	if out.keysExpired, err = s.expireKeys(ctx, inst, node); err != nil {
		return revokeOutcome{}, err
	}
	switch kind {
	case RevokeExpire:
		at := requestedAt // explicit time: replaying the call gives the same state (§13.4 rule 3)
		if _, err := inst.ExpireNode(ctx, nodeID, &at); err != nil && !isGone(err) {
			return revokeOutcome{}, err
		}
	case RevokeDelete:
		if err := inst.DeleteNode(ctx, nodeID); err != nil && !isGone(err) { // not_found on a replay = done (§13.4)
			return revokeOutcome{}, err
		}
	default:
		return revokeOutcome{}, &Error{Code: CodeValidationFailed, Reason: "unknown_kind"}
	}
	back, err := inst.GetNode(ctx, nodeID)
	switch {
	case isGone(err) || err == nil && back.MachineKey != row.MachineKey:
		out.gone = true
		return out, nil
	case err != nil:
		return revokeOutcome{}, err
	case kind == RevokeExpire && back.Expiry != nil && !back.Expiry.After(requestedAt.Add(expiryWindow)):
		out.expiry = back.Expiry
		return out, nil
	}
	return revokeOutcome{}, errReadback
}

// expireKeys expires the pre-auth keys that could register the device again by itself (§7.4): every live key of the
// node's user for a user-owned node, the node's own key for a tagged one. Spent single-use keys are left alone.
func (s *Service) expireKeys(ctx context.Context, inst headscale.Instance, node headscale.Node) (int, error) {
	var userID uint64
	if !node.IsTagged() && node.User != nil && node.User.Name != headscale.TaggedDevicesUser {
		userID = node.User.ID
	}
	if userID == 0 && node.PreAuthKeyID == 0 {
		return 0, nil
	}
	keys, err := inst.ListPreAuthKeys(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now()
	n := 0
	for _, k := range keys {
		mine := userID != 0 && k.User != nil && k.User.ID == userID || node.PreAuthKeyID != 0 && k.ID == node.PreAuthKeyID
		if !mine || !k.Expiration.After(now) || k.Used && !k.Reusable {
			continue
		}
		if err := inst.ExpirePreAuthKey(ctx, k.ID); err != nil && !isGone(err) {
			return n, err
		}
		n++
	}
	return n, nil
}

// settle records the outcome of a revocation (pending → applied or failed) with the outcome event of its audit
// operation, in one transaction on a context detached from the job's. It reports whether it was recorded (false when
// the device was settled or superseded meanwhile, or the write failed).
func (s *Service) settle(ctx context.Context, tenantID uuid.UUID, row sqlcdb.DeviceInventoryCache, jobID uuid.UUID,
	state string, op *audit.Operation, reason string, out revokeOutcome,
) bool {
	wctx, cancel := s.detached(ctx)
	defer cancel()
	kind := deref(row.RevocationKind)
	settled := false
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		p := sqlcdb.SettleDeviceRevocationParams{State: state, TenantID: tenantID, ID: row.ID, JobID: &jobID}
		if state == StateApplied {
			p.Remove = out.gone || kind == RevokeDelete
			p.SetExpiry, p.Expiry = out.expiry != nil, out.expiry
		}
		_, err := q.SettleDeviceRevocation(wctx, p)
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		settled = true
		if op == nil {
			return nil
		}
		if state == StateApplied {
			return op.Succeeded(wctx, q, audit.Details{"kind": kind, "node_gone": out.gone, "preauth_keys_expired": out.keysExpired})
		}
		return op.Failed(wctx, q, reason, audit.Details{"kind": kind})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "devices: recording a revocation outcome failed", "device_id", row.ID, "state", state,
			"sqlstate", store.SQLState(err))
		return false
	}
	if settled {
		s.m.revocations.WithLabelValues(kind, state).Inc()
		if state == StateFailed {
			s.log.ErrorContext(ctx, "devices: revocation failed", "alert", true, "tenant_id", tenantID, "device_id", row.ID,
				"kind", kind, "reason", reason)
		}
	}
	return settled
}

// JobAlert settles the revocation of a device.revoke job that ended without its handler recording it — whole-job
// timeout before an attempt, job.reaper after a lost worker, a panic — and closes the audit pair of an
// inventory.sync asked through the API. Wire it as (part of) the jobs.Worker's Alerter (P2-T16).
func (s *Service) JobAlert(ctx context.Context, a jobs.Alert) {
	if a.TenantID == nil {
		return
	}
	switch a.Kind {
	case KindRevoke:
		if _, err := s.settleOrphans(ctx, *a.TenantID, &a.JobID); err != nil {
			s.log.ErrorContext(ctx, "devices: settling a failed revocation job failed", "job_id", a.JobID, "error", err)
		}
	case KindSync:
		s.closeJobOperation(ctx, *a.TenantID, a.JobID, a.Code)
	}
}

// closeJobOperation closes the audit operation carried by a failed job's input.
func (s *Service) closeJobOperation(ctx context.Context, tenantID, jobID uuid.UUID, code string) {
	wctx, cancel := s.detached(ctx)
	defer cancel()
	var in syncInput
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		j, err := q.GetJob(wctx, jobID)
		if err != nil {
			return err
		}
		return json.Unmarshal(j.Input, &in)
	})
	if err != nil || in.Operation == nil {
		return
	}
	if code == "" {
		code = "job_failed"
	}
	s.closeFailed(ctx, tenantID, in.Operation, code)
}

// settleOrphans settles failed every pending revocation of the tenant (or of one job) whose job ended without success
// or no longer exists, and closes its audit operation. It returns how many it settled.
func (s *Service) settleOrphans(ctx context.Context, tenantID uuid.UUID, jobID *uuid.UUID) (int, error) {
	wctx, cancel := s.detached(ctx)
	defer cancel()
	sctx := systemContext(wctx)
	n := 0
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListOrphanedRevocations(wctx, sqlcdb.ListOrphanedRevocationsParams{TenantID: tenantID, JobID: jobID})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if _, err := q.FailOrphanedRevocation(wctx, sqlcdb.FailOrphanedRevocationParams{TenantID: tenantID, ID: r.ID,
				JobID: r.RevocationJobID}); errors.Is(err, store.ErrNoRows) {
				continue
			} else if err != nil {
				return err
			}
			n++
			s.m.revocations.WithLabelValues(deref(r.RevocationKind), StateFailed).Inc()
			reason := r.JobErrorCode
			switch {
			case r.JobStatus == "":
				reason = "job_missing"
			case reason == "":
				reason = "job_" + r.JobStatus
			}
			s.log.ErrorContext(ctx, "devices: revocation failed", "alert", true, "tenant_id", tenantID, "device_id", r.ID,
				"kind", deref(r.RevocationKind), "reason", reason)
			var in revokeInput
			if json.Unmarshal(r.JobInput, &in) != nil || in.Operation == nil {
				continue
			}
			st, err := q.OperationState(wctx, in.Operation.ID)
			if err != nil {
				return err
			}
			if st.Requested && !st.Finished {
				if err := in.Operation.Failed(sctx, q, reason, audit.Details{"kind": deref(r.RevocationKind)}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("devices: settle orphaned revocations: %w", err)
	}
	return n, nil
}

// Register adds the handlers of inventory.sync and device.revoke to the worker (apps/worker, P2-T16).
func (s *Service) Register(w *jobs.Worker) error {
	if err := w.Register(KindSync, jobs.HandlerFunc(s.runSync)); err != nil {
		return err
	}
	return w.Register(KindRevoke, jobs.HandlerFunc(s.runRevoke))
}
