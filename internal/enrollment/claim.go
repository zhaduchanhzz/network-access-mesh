package enrollment

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Claim is the input of POST /enrollment/web-auth/claim.
type Claim struct {
	AuthID    string
	RequestID *uuid.UUID
}

// Failure codes of a claim (enrollment_requests.failure_code).
const (
	FailureNodeMismatch    = "node_mismatch" // a new node failed a check of §7.4 step 8: deleted
	FailureForeignNode     = "foreign_node"  // an existing node of someone else: expired, never deleted
	FailureNotPending      = "auth_id_not_pending"
	FailureClaimUnfinished = "claim_unfinished" // reconcile: the claim never reached a verdict
)

// Claim is POST /tenants/{t}/enrollment/web-auth/claim (§7.4 steps 6–8): the only way an Auth ID registers a node.
func (s *Service) Claim(ctx context.Context, tenantID uuid.UUID, a Actor, in Claim) (Request, error) {
	if err := headscale.ValidateAuthID(in.AuthID); err != nil {
		return Request{}, invalid("auth_id", "invalid_auth_id", "auth_id must be the identifier at the end of the sign-in link the client printed")
	}
	if ok, wait := s.allowClaim(a.MembershipID); !ok {
		return Request{}, &Error{Code: CodeRateLimited, Reason: "claim_rate_limited", RetryAfter: wait,
			Detail: "Too many device claims: wait a minute and try again."}
	}
	hash := authIDHash(in.AuthID)
	var (
		r    sqlcdb.EnrollmentRequest
		tc   tenantContext
		user member
		op   audit.Operation
	)
	err := s.inTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		if tc, err = loadContext(ctx, q, tenantID); err != nil {
			return err
		}
		if err := checkSelfEnroll(a, tc); err != nil {
			return err
		}
		if !tc.settings.Enrollment.WebAuthEnabled {
			return invalid("auth_id", "web_auth_disabled", "This tenant does not accept web-auth enrollment.")
		}
		seen, err := q.EnrollmentAuthIDSeen(ctx, sqlcdb.EnrollmentAuthIDSeenParams{TenantID: tenantID, AuthIDHash: hash})
		if err != nil {
			return err
		}
		if seen {
			if _, err := audit.RecordSecurityEvent(ctx, q, s.securityEvent(tenantID, EventClaimReplay, audit.SeverityMedium,
				a, audit.Details{})); err != nil {
				return err
			}
			return errCommitted{conflict("auth_id_already_claimed", "This sign-in link was already used.")}
		}
		pending, err := q.LockPendingWebAuth(ctx, sqlcdb.LockPendingWebAuthParams{TenantID: tenantID,
			Member: a.MembershipID, SessionIDHash: sessionHash(a.SessionID)})
		if err != nil {
			return err
		}
		if in.RequestID != nil {
			var pick []sqlcdb.EnrollmentRequest
			for _, p := range pending {
				if p.ID == *in.RequestID {
					pick = append(pick, p)
				}
			}
			pending = pick
		}
		switch {
		case len(pending) == 0:
			// §7.4 step 6: a claim link without a request of the caller pending in this session is phishing-shaped —
			// refused without any call to Headscale, counted and alerted
			if _, err := audit.RecordSecurityEvent(ctx, q, s.securityEvent(tenantID, EventClaimWithoutRequest,
				audit.SeverityMedium, a, audit.Details{})); err != nil {
				return err
			}
			return errCommitted{conflict("no_pending_request",
				"You have no device request waiting in this session: do not confirm a sign-in link you did not start here.")}
		case len(pending) > 1:
			return invalid("request_id", "request_id_required",
				"You have several device requests waiting: say which one this sign-in belongs to.")
		}
		r = pending[0]
		if user, err = loadMember(ctx, q, tenantID, a.MembershipID, "membership"); err != nil {
			return err
		}
		now := s.now().UTC()
		p := stateOf(r)
		p.Status, p.AuthIDHash, p.ClaimedAt = StatusClaimed, hash, &now
		if a.ClientIP.IsValid() {
			ip := a.ClientIP
			p.ClaimedFromIp = &ip
		}
		if r, err = q.SetEnrollmentRequestState(ctx, p); err != nil {
			return err
		}
		op, err = audit.Requested(ctx, q, audit.Event{Action: ActionClaim, TenantID: &tenantID,
			ResourceType: resourceType, ResourceID: r.ID.String()})
		return err
	})
	if err != nil {
		return Request{}, err
	}
	return s.register(ctx, tenantID, a, r, user, tc, in.AuthID, op)
}

func (s *Service) securityEvent(tenantID uuid.UUID, kind, severity string, a Actor, d audit.Details) audit.SecurityEvent {
	t := tenantID
	d["membership_id"] = a.MembershipID.String()
	if a.ClientIP.IsValid() {
		d["client_ip"] = a.ClientIP.String()
	}
	return audit.SecurityEvent{TenantID: &t, Kind: kind, Severity: severity, Source: securitySource, Details: d}
}

// register calls AuthRegister for a claimed request and checks the node it answers (§7.4 step 8).
func (s *Service) register(ctx context.Context, tenantID uuid.UUID, a Actor, r sqlcdb.EnrollmentRequest, user member,
	tc tenantContext, authID string, op audit.Operation,
) (Request, error) {
	fail := func(err error, code string) (Request, error) {
		e := fromAdapter(err)
		if code == "" {
			code = failureCode(e)
		}
		s.failRequest(ctx, tenantID, r.ID, code, &op)
		return Request{}, e
	}
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		return fail(err, "")
	}
	if _, err := ensureUser(ctx, inst, user.user, user.display); err != nil {
		return fail(err, "")
	}
	node, err := inst.AuthRegister(ctx, user.user, authID)
	if errors.Is(err, headscale.ErrValidation) || errors.Is(err, headscale.ErrNotFound) {
		return fail(&Error{Code: CodeConflict, Reason: FailureNotPending, Err: err,
			Detail: "The control plane has no pending sign-in for this link (it lives 15 minutes): run tailscale up again."},
			FailureNotPending)
	}
	if err != nil {
		return fail(err, "")
	}
	nid := int64(node.ID) //nolint:gosec // Headscale ids are small positive integers
	host := clip(node.Name, 255)
	mkey := clip(node.MachineKey, 200)
	// registered: the node exists — recorded before any corrective call, so a crash leaves a trace for reconcile
	var existing *sqlcdb.DeviceInventoryCache
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		cur, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
		if err != nil {
			return err
		}
		p := stateOf(cur)
		p.Status, p.ConsumedNodeID = StatusRegistered, &nid
		if host != "" {
			p.ReportedHostname = &host
		}
		if mkey != "" {
			p.RegisteredMachineKey = &mkey
		}
		if r, err = q.SetEnrollmentRequestState(ctx, p); err != nil {
			return err
		}
		d, err := q.LiveDeviceByMachineKey(ctx, sqlcdb.LiveDeviceByMachineKeyParams{TenantID: tenantID,
			InstanceID: tc.instance, MachineKey: node.MachineKey})
		if err == nil {
			existing = &d
		} else if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		return nil
	})
	if err != nil {
		return fail(fmt.Errorf("enrollment: record the registered node: %w", err), "record_failed")
	}
	isNew := existing == nil && !node.CreatedAt.Before(r.CreatedAt.Add(-time.Second))
	ownUser := node.User != nil && node.User.Name == user.user
	if !isNew {
		// (b) a node that existed before is never deleted: the member's own device re-authenticates; anything else is
		// expired and left to its owner's decision
		if ownUser && !node.IsTagged() && (existing == nil || (existing.OwnerMembershipID != nil &&
			*existing.OwnerMembershipID == a.MembershipID)) {
			return s.verified(ctx, tenantID, a, r, node, tc, existing, false, op)
		}
		now := s.now().UTC()
		_, xerr := inst.ExpireNode(ctx, node.ID, &now)
		return s.rejected(ctx, tenantID, a, r, EventForeignNode, FailureForeignNode, audit.Details{"node_id": nid,
			"expired": xerr == nil}, op)
	}
	// (a) a new node: name mg-<code> (the code only the requester's session received), the expected user, no tag, CLI
	reasons := []string{}
	code, hasPrefix := strings.CutPrefix(node.Name, HostnamePrefix)
	if !hasPrefix || !bytes.Equal(codeHash(code), r.EnrollCodeHash) {
		reasons = append(reasons, "hostname")
	}
	if !ownUser {
		reasons = append(reasons, "user")
	}
	if node.IsTagged() {
		reasons = append(reasons, "tags")
	}
	if node.RegisterMethod != headscale.RegisterMethodCLI {
		reasons = append(reasons, "register_method")
	}
	if len(reasons) > 0 {
		derr := inst.DeleteNode(ctx, node.ID)
		if errors.Is(derr, headscale.ErrNotFound) {
			derr = nil
		}
		return s.rejected(ctx, tenantID, a, r, EventNodeMismatch, FailureNodeMismatch, audit.Details{"node_id": nid,
			"checks_failed": reasons, "deleted": derr == nil}, op)
	}
	if label := r.DeviceLabel; label != nil && *label != node.GivenName {
		if renamed, rerr := inst.RenameNode(ctx, node.ID, *label); rerr == nil {
			node = renamed
		} else {
			s.log.WarnContext(ctx, "enrollment: renaming the verified node failed", "request_id", r.ID,
				"error", fromAdapter(rerr).Reason)
		}
	}
	return s.verified(ctx, tenantID, a, r, node, tc, nil, true, op)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// rejected ends a claimed request failed after a corrective call (delete or expire), with its security event.
func (s *Service) rejected(ctx context.Context, tenantID uuid.UUID, a Actor, r sqlcdb.EnrollmentRequest, kind, code string,
	d audit.Details, op audit.Operation,
) (Request, error) {
	var out Request
	wctx, cancel := detached(ctx)
	defer cancel()
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		cur, err := q.LockEnrollmentRequest(wctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
		if err != nil {
			return err
		}
		p := stateOf(cur)
		p.Status, p.FailureCode = StatusFailed, &code
		row, err := q.SetEnrollmentRequestState(wctx, p)
		if err != nil {
			return err
		}
		ls, err := loginServerOf(wctx, q, tenantID)
		if err != nil {
			return err
		}
		out = view(row, ls)
		sd := audit.Details{"request_id": r.ID.String()}
		for k, v := range d {
			sd[k] = v
		}
		if _, err := audit.RecordSecurityEvent(wctx, q, s.securityEvent(tenantID, kind, audit.SeverityHigh, a, sd)); err != nil {
			return err
		}
		return op.Failed(wctx, q, code, d)
	})
	return out, err
}

// verified ends a claimed request verified: the device in the inventory with its enrollment link (a new row, or the
// existing row of a re-authentication), the notification device.new for a new device, and inventory.sync — which clamps
// the node's expiry to the tenant's node_expiry (§7.4 "Vòng đời khóa": the client may ask for any expiry).
func (s *Service) verified(ctx context.Context, tenantID uuid.UUID, a Actor, r sqlcdb.EnrollmentRequest,
	node headscale.Node, tc tenantContext, existing *sqlcdb.DeviceInventoryCache, isNew bool, op audit.Operation,
) (Request, error) {
	var out Request
	nid := int64(node.ID) //nolint:gosec // small positive ids
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		cur, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
		if err != nil {
			return err
		}
		p := stateOf(cur)
		p.Status = StatusVerified
		row, err := q.SetEnrollmentRequestState(ctx, p)
		if err != nil {
			return err
		}
		owner := a.MembershipID
		dev, err := q.LockLiveDeviceOfNode(ctx, sqlcdb.LockLiveDeviceOfNodeParams{TenantID: tenantID,
			InstanceID: tc.instance, HeadscaleNodeID: nid})
		switch {
		case err == nil && dev.MachineKey == node.MachineKey:
			if err := q.LinkDeviceEnrollment(ctx, sqlcdb.LinkDeviceEnrollmentParams{EnrollmentRequestID: &r.ID,
				OwnerMembershipID: &owner, TenantID: tenantID, ID: dev.ID}); err != nil {
				return err
			}
		case err == nil:
			// a stale row of a reused node id (another machine key): the inventory.sync enqueued below replaces it and
			// reconcile sets the link of the new row
			dev = sqlcdb.DeviceInventoryCache{}
		case errors.Is(err, store.ErrNoRows):
			// no row yet: the device enters the inventory now
			dev, err = q.InsertEnrolledDevice(ctx, deviceParams(tenantID, tc.instance, node, owner, r.ID))
			if err != nil {
				return err
			}
		default:
			return err
		}
		if isNew && dev.ID != uuid.Nil {
			name := node.GivenName
			if name == "" {
				name = node.Name
			}
			if _, err := notifications.Enqueue(ctx, tx, notifications.DeviceNew(tenantID, dev.ID, &owner, name,
				s.now().UTC())); err != nil {
				return err
			}
		}
		inst := tc.instance
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindSync, TenantID: &tenantID, InstanceID: &inst,
			Slot: slotEnroll}); err != nil {
			return err
		}
		d := audit.Details{"node_id": nid, "reauth": !isNew}
		if existing != nil {
			d["device_id"] = existing.ID.String()
		} else if dev.ID != uuid.Nil {
			d["device_id"] = dev.ID.String()
		}
		if err := op.Succeeded(ctx, q, d); err != nil {
			return err
		}
		out = view(row, tc.loginServer)
		return nil
	})
	if err != nil {
		s.failRequest(ctx, tenantID, r.ID, "record_failed", &op)
		return Request{}, fmt.Errorf("enrollment: record the verified device: %w", err)
	}
	return out, nil
}

func deviceParams(tenantID, instance uuid.UUID, n headscale.Node, owner, request uuid.UUID) sqlcdb.InsertEnrolledDeviceParams {
	p := sqlcdb.InsertEnrolledDeviceParams{TenantID: tenantID, InstanceID: instance,
		HeadscaleNodeID: int64(n.ID), MachineKey: n.MachineKey, IpAddresses: n.IPAddresses, //nolint:gosec // small ids
		OwnerMembershipID: &owner, Tags: n.Tags, Online: n.Online, LastSeen: n.LastSeen, Expiry: n.Expiry,
		EnrollmentRequestID: &request}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	if p.IpAddresses == nil {
		p.IpAddresses = []netip.Addr{}
	}
	if n.NodeKey != "" {
		p.NodeKey = &n.NodeKey
	}
	if n.Name != "" {
		p.Name = &n.Name
	}
	if n.GivenName != "" {
		p.GivenName = &n.GivenName
	}
	if n.User != nil && n.User.ID != 0 {
		uid := int64(n.User.ID) //nolint:gosec // small ids
		p.HeadscaleUserID = &uid
	}
	if n.RegisterMethod != "" {
		m := string(n.RegisterMethod)
		p.RegisterMethod = &m
	}
	if !n.CreatedAt.IsZero() {
		c := n.CreatedAt
		p.HsCreatedAt = &c
	}
	return p
}
