package members

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// expiryWindow absorbs the clock difference between the request and Headscale's read-back of an expired node.
const expiryWindow = time.Minute

// Error codes of the member.offboard job (provisioning_jobs.error.code, audit reason).
const (
	CodeNotOffboarded     = "not_offboarded"
	CodeNoMember          = "no_membership"
	CodeReadbackMismatch  = "readback_mismatch"
	CodeInstance          = "instance_unavailable"
	CodeHeadscale         = "headscale_rejected"
	CodeIdPDisableFailed  = "idp_disable_failed"
	CodeIdPUnavailable    = "idp_unavailable"
	CodeInvalidInput      = "invalid_input"
	CodeNotConfigured     = "not_configured"
	idpStateDisabled      = "disabled"
	idpStateAlready       = "already_disabled"
	idpStateNoUser        = "no_such_user"
	idpStateNotApplicable = "not_applicable" // the tenant's own IdP (driver external): the platform does not manage it
)

// errReadback: Headscale answered but the read-back does not show the node expired yet ⇒ retry.
var errReadback = errors.New("members: read-back does not show the node expired")

// offboardOutcome is what the job verified.
type offboardOutcome struct {
	nodesExpired int // expired by this run, read back
	nodesAlready int // already expired at or before the request
	nodesGone    int // deleted meanwhile, or the node id now names another machine
	keysExpired  int
	idp          string
}

func (o offboardOutcome) details() audit.Details {
	return audit.Details{"nodes_expired": o.nodesExpired, "nodes_already_expired": o.nodesAlready,
		"nodes_gone": o.nodesGone, "keys_expired": o.keysExpired, "idp": o.idp}
}

// Register adds the handlers of member.offboard and member.idp_invite to the worker (apps/worker).
func (s *Service) Register(w *jobs.Worker) error {
	if s.hs == nil || s.idps == nil {
		return errors.New("members: the worker needs the Headscale registry and the IdP drivers")
	}
	if err := w.Register(KindOffboard, jobs.HandlerFunc(s.runOffboard)); err != nil {
		return err
	}
	return w.Register(KindIdPInvite, jobs.HandlerFunc(s.runIdPInvite))
}

// runOffboard is the handler of member.offboard (§13.5): idempotent — every step converges when run again.
func (s *Service) runOffboard(ctx context.Context, run *jobs.Run) error {
	var in offboardInput
	if err := run.DecodeInput(&in); err != nil || in.MembershipID == uuid.Nil || run.TenantID == nil || in.RequestedAt.IsZero() {
		return jobs.Permanent(CodeInvalidInput, errors.Join(errors.New("member.offboard: invalid input"), err))
	}
	tenantID := *run.TenantID
	var row sqlcdb.GetOffboardSubjectRow
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.GetOffboardSubject(ctx, sqlcdb.GetOffboardSubjectParams{TenantID: tenantID, ID: in.MembershipID})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		s.closeOperation(ctx, tenantID, in.Operation, CodeNoMember, nil)
		return jobs.Permanent(CodeNoMember, errors.New("member.offboard: no such membership"))
	case err != nil:
		return jobs.Transient("internal_error", err)
	case row.Status != tenants.MemberOffboarded:
		s.closeOperation(ctx, tenantID, in.Operation, CodeNotOffboarded, nil)
		return jobs.Permanent(CodeNotOffboarded, fmt.Errorf("member.offboard: membership is %s", row.Status))
	}
	out, err := s.offboardNodes(ctx, tenantID, row, in.RequestedAt)
	if err == nil {
		out.idp, err = s.disableAtIdP(ctx, row)
	}
	if err != nil {
		var je *jobs.Error
		code := "internal_error"
		if errors.As(err, &je) {
			code = je.Code
		}
		if (je != nil && je.Permanent) || run.Attempt >= run.MaxAttempts {
			s.closeOperation(ctx, tenantID, in.Operation, code, out.details())
		}
		return err
	}
	if !s.closeOperation(ctx, tenantID, in.Operation, "", out.details()) {
		return jobs.Transient("record_failed", errors.New("member.offboard: recording the outcome failed"))
	}
	_ = run.SetOutput(map[string]any{"state": tenants.OffboardApplied, "nodes_expired": out.nodesExpired,
		"nodes_already_expired": out.nodesAlready, "nodes_gone": out.nodesGone, "keys_expired": out.keysExpired,
		"idp": out.idp})
	s.log.InfoContext(ctx, "members: offboarding applied", "tenant_id", tenantID, "membership_id", in.MembershipID,
		"nodes_expired", out.nodesExpired, "keys_expired", out.keysExpired, "idp", out.idp)
	return nil
}

// hsErr wraps an adapter error as a job error: unavailable instance ⇒ transient, anything else ⇒ permanent.
func hsErr(err error) error {
	if errors.Is(err, headscale.ErrUnavailable) || errors.Is(err, headscale.ErrCircuitOpen) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errReadback) {
		code := CodeInstance
		if errors.Is(err, errReadback) {
			code = CodeReadbackMismatch
		}
		return jobs.Transient(code, err)
	}
	if he, ok := headscale.AsError(err); ok && he.Kind == headscale.KindInternal {
		return jobs.Transient(CodeInstance, err)
	}
	return jobs.Permanent(CodeHeadscale, err)
}

// offboardNodes expires the member's nodes and pre-auth keys on the tenant's instance. The nodes are those Headscale
// lists for the user mg-<membership> and those the inventory attributes to the membership (it keeps the owner of a
// node tagged after its registration — GetNode reports no user for a tagged node, V-28); a node is identified by id
// AND machine key: a node id handed out again to another machine is never touched.
func (s *Service) offboardNodes(ctx context.Context, tenantID uuid.UUID, row sqlcdb.GetOffboardSubjectRow,
	requestedAt time.Time,
) (offboardOutcome, error) {
	var out offboardOutcome
	var devices []sqlcdb.ListMemberDevicesRow
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		devices, err = q.ListMemberDevices(ctx, sqlcdb.ListMemberDevicesParams{TenantID: tenantID, MembershipID: &row.ID})
		return err
	})
	if err != nil {
		return out, jobs.Transient("internal_error", err)
	}
	inst, err := s.hs.ForTenant(ctx, tenantID)
	if err != nil {
		return out, hsErr(err)
	}
	users, err := inst.ListUsers(ctx, headscale.UserFilter{Name: row.HeadscaleUsername})
	if err != nil {
		return out, hsErr(err)
	}
	var user *headscale.User
	for i := range users {
		if users[i].Name == row.HeadscaleUsername {
			user = &users[i]
		}
	}
	type target struct {
		machineKey string // "" = from ListNodes of the user (no inventory check needed)
		deviceID   uuid.UUID
	}
	targets := map[uint64]target{}
	if user != nil {
		nodes, err := inst.ListNodes(ctx, user.Name)
		if err != nil {
			return out, hsErr(err)
		}
		for _, n := range nodes {
			targets[n.ID] = target{machineKey: n.MachineKey}
		}
	}
	for _, d := range devices {
		id := uint64(d.HeadscaleNodeID) //nolint:gosec // CHECK headscale_node_id > 0
		targets[id] = target{machineKey: d.MachineKey, deviceID: d.ID}
	}
	tagKeys := map[uint64]bool{}
	for id, t := range targets {
		node, err := inst.GetNode(ctx, id)
		switch {
		case errors.Is(err, headscale.ErrNotFound) || err == nil && t.machineKey != "" && node.MachineKey != t.machineKey:
			out.nodesGone++
			continue
		case err != nil:
			return out, hsErr(err)
		}
		if node.PreAuthKeyID != 0 && node.IsTagged() {
			tagKeys[node.PreAuthKeyID] = true // a tagged node's own key (tag-only keys have no user)
		}
		limit := requestedAt.Add(expiryWindow)
		if node.Expiry != nil && !node.Expiry.After(limit) {
			out.nodesAlready++
			s.recordExpiry(ctx, tenantID, t.deviceID, node.Expiry)
			continue
		}
		at := requestedAt // explicit time: a retry sets the same expiry (§13.4 rule 3)
		if _, err := inst.ExpireNode(ctx, id, &at); err != nil {
			if errors.Is(err, headscale.ErrNotFound) {
				out.nodesGone++
				continue
			}
			return out, hsErr(err)
		}
		back, err := inst.GetNode(ctx, id)
		switch {
		case errors.Is(err, headscale.ErrNotFound) || err == nil && back.MachineKey != node.MachineKey:
			out.nodesGone++
			continue
		case err != nil:
			return out, hsErr(err)
		case back.Expiry == nil || back.Expiry.After(limit):
			return out, hsErr(fmt.Errorf("%w: node %d", errReadback, id))
		}
		out.nodesExpired++
		s.recordExpiry(ctx, tenantID, t.deviceID, back.Expiry)
	}
	if user == nil && len(tagKeys) == 0 {
		return out, nil
	}
	keys, err := inst.ListPreAuthKeys(ctx)
	if err != nil {
		return out, hsErr(err)
	}
	now := s.now()
	for _, k := range keys {
		mine := user != nil && k.User != nil && k.User.ID == user.ID || tagKeys[k.ID]
		if !mine || !k.Expiration.After(now) || k.Used && !k.Reusable {
			continue
		}
		if err := inst.ExpirePreAuthKey(ctx, k.ID); err != nil && !errors.Is(err, headscale.ErrNotFound) {
			return out, hsErr(err)
		}
		out.keysExpired++
	}
	return out, nil
}

// recordExpiry writes the read-back expiry into the inventory (the Portal shows the device expired before the next
// inventory.sync); a failure is only logged — the sync converges anyway.
func (s *Service) recordExpiry(ctx context.Context, tenantID, deviceID uuid.UUID, expiry *time.Time) {
	if deviceID == uuid.Nil || expiry == nil {
		return
	}
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		return q.SetDeviceExpiry(ctx, sqlcdb.SetDeviceExpiryParams{Expiry: expiry, TenantID: tenantID, ID: deviceID})
	})
	if err != nil {
		s.log.WarnContext(ctx, "members: recording the expiry of an offboarded member's device failed",
			"device_id", deviceID, "sqlstate", store.SQLState(err))
	}
}

// registration is the IdP registration of a row (identity_providers).
func registration(id uuid.UUID, scope string, tenantID *uuid.UUID, driver string, driverRef *string, issuer, clientID string,
	secretRef *string,
) idp.Registration {
	r := idp.Registration{IdPID: id, Scope: idp.Scope(scope), Driver: driver, Issuer: issuer, ClientID: clientID}
	if tenantID != nil {
		r.TenantID = *tenantID
	}
	if driverRef != nil {
		r.DriverRef = *driverRef
	}
	if secretRef != nil {
		r.ClientSecretRef = *secretRef
	}
	return r
}

// idpErr wraps an IdP driver error as a job error.
func idpErr(code string, err error) error {
	switch idp.CodeOf(err) {
	case idp.CodeUnavailable, idp.CodeTimeout, idp.CodeUpstream, idp.CodeCredentials:
		return jobs.Transient(CodeIdPUnavailable, err)
	}
	return jobs.Permanent(code, err)
}

// disableAtIdP disables the user at a platform-hosted IdP (driver keycloak) and ends its IdP sessions (§8.2, V-23). The
// driver of a tenant-managed IdP does not offer it (unsupported): the platform side — disabled identity, revoked
// sessions, expired nodes — does not depend on it.
func (s *Service) disableAtIdP(ctx context.Context, row sqlcdb.GetOffboardSubjectRow) (string, error) {
	reg := registration(row.IdpID, row.IdpScope, row.IdpTenantID, row.Driver, row.DriverRef, row.Issuer, row.ClientID,
		row.ClientSecretRef)
	drv, err := s.idps.For(reg)
	if err != nil {
		return "", jobs.Permanent(CodeNotConfigured, err)
	}
	res, err := drv.DisableUser(ctx, reg, row.Subject)
	switch {
	case idp.CodeOf(err) == idp.CodeUnsupported:
		return idpStateNotApplicable, nil
	case err != nil:
		return "", idpErr(CodeIdPDisableFailed, err)
	case !res.Found:
		return idpStateNoUser, nil
	case res.AlreadyDisabled:
		return idpStateAlready, nil
	}
	return idpStateDisabled, nil
}

// closeOperation writes the outcome of the audit pair user.offboard (succeeded when code is "", failed otherwise) in
// a transaction on a context detached from the job's. It reports whether it was recorded.
func (s *Service) closeOperation(ctx context.Context, tenantID uuid.UUID, op *audit.Operation, code string, d audit.Details) bool {
	if op == nil {
		return true
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		st, err := q.OperationState(wctx, op.ID)
		if err != nil {
			return err
		}
		if !st.Requested || st.Finished {
			return nil
		}
		if code == "" {
			return op.Succeeded(wctx, q, d)
		}
		return op.Failed(wctx, q, code, d)
	})
	if err != nil {
		s.log.ErrorContext(ctx, "members: closing the audit pair of an offboarding failed", "operation_id", op.ID,
			"sqlstate", store.SQLState(err))
		return false
	}
	return true
}

// JobAlert closes the audit pair of a member.offboard job that ended without its handler recording it (whole-job
// timeout, job.reaper after a lost worker, a panic). Wire it into the jobs.Worker's Alerter (apps/worker).
func (s *Service) JobAlert(ctx context.Context, a jobs.Alert) {
	if a.TenantID == nil || a.Kind != KindOffboard {
		return
	}
	var in offboardInput
	err := s.st.WithTenantTx(ctx, *a.TenantID, func(q *sqlcdb.Queries) error {
		j, err := q.GetJob(ctx, a.JobID)
		if err != nil {
			return err
		}
		return json.Unmarshal(j.Input, &in)
	})
	if err != nil {
		s.log.ErrorContext(ctx, "members: reading a failed offboarding job failed", "job_id", a.JobID, "error", err)
		return
	}
	code := a.Code
	if code == "" {
		code = "job_failed"
	}
	s.closeOperation(audit.WithRequest(ctx, nil), *a.TenantID, in.Operation, code, nil)
}
