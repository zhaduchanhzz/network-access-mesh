package enrollment

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Failure codes written by reconcile.
const (
	FailureIssueUnfinished = "issue_unfinished" // a key issuance never recorded its key (process died)
	FailureKeyMissing      = "key_missing"      // the issued key is gone from Headscale
	FailureNodeGone        = "node_gone"        // the key was used but its node no longer exists
)

// ReconcileReport is the output of one enrollment.reconcile job.
type ReconcileReport struct {
	Open     int   `json:"open"`
	Expired  int   `json:"expired"`
	Consumed int   `json:"consumed"`
	Failed   int   `json:"failed"`
	Linked   int64 `json:"linked"`
	Skipped  int   `json:"skipped"` // issued keys left for the next run: the instance did not answer
	// NewDevices counts the devices of pre-auth keys that entered the inventory (or got their link) in this run, each
	// notified once (device.new).
	NewDevices int `json:"new_devices"`
	// Revoked counts the consumed reusable keys found ended at Headscale before their expiry (a device revocation
	// expired them): no live credential any more.
	Revoked int `json:"revoked"`
	// Removed counts the nodes of claims that never reached their verdict which failed the checks of step 8 and were
	// deleted (unfinishedClaim — C1).
	Removed int `json:"removed"`
	// Inactive: the tenant is not active (suspended, deprovisioning, deleted — its instance is not reachable): the rows
	// that need Headscale wait for a run after it is active again (counted in Skipped), and the run is not an error.
	Inactive bool `json:"inactive,omitempty"`
}

// reusableGrace is how long after its expiry a consumed reusable key is still looked at: a node it registered before
// expiring may reach the next run late (the schedule runs every 2 minutes).
const reusableGrace = 30 * time.Minute

// endedSlack: a consumed reusable key is taken as ended early (A3) only while its recorded expiry is further away than
// this — Headscale may store the expiration a little earlier than the platform recorded it.
const endedSlack = time.Minute

// Register registers the handler of enrollment.reconcile on the worker.
func (s *Service) Register(w *jobs.Worker) error {
	return w.Register(KindReconcile, jobs.HandlerFunc(s.runReconcile))
}

func (s *Service) runReconcile(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil {
		return jobs.Permanent("invalid_input", errors.New("enrollment.reconcile: no tenant"))
	}
	rep, err := s.Reconcile(ctx, *run.TenantID)
	if oerr := run.SetOutput(rep); oerr != nil && err == nil {
		err = oerr
	}
	if err != nil {
		return jobs.Transient("reconcile_failed", err)
	}
	return nil
}

// Reconcile converges the open enrollment requests of a tenant (§13.5 enrollment.reconcile): expired decisions, codes
// and keys ⇒ expired; used keys ⇒ consumed with their node; unfinished issuances and claims ⇒ failed; device rows of
// consumed/verified requests get their enrollment link. The nodes a pre-auth key registered enter the inventory with
// that link and are notified once (device.new — adoptKeyNodes): at the consumed transition — the device counts against
// max_devices from that transaction on (C9) —, then for a reusable key while it is live (and reusableGrace after); a
// reusable key Headscale ended before its expiry (a device revocation) is revoked (A3). The node of a claim that never
// reached its verdict is checked before the claim is closed (unfinishedClaim — C1). Headscale is asked only when an
// issued or live reusable key or an unfinished claim is open; when it does not answer, those rows wait for the next run
// and the error is returned (the job retries) — unless the tenant is not active (A2: a suspended tenant's instance is
// not reachable by design, the rows wait for its resumption without failing the job every run).
func (s *Service) Reconcile(ctx context.Context, tenantID uuid.UUID) (ReconcileReport, error) {
	var (
		rep      ReconcileReport
		open     []sqlcdb.EnrollmentRequest
		reusable []sqlcdb.EnrollmentRequest
	)
	now := s.now()
	if err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		if open, err = q.ListOpenEnrollmentRequests(ctx, tenantID); err != nil {
			return err
		}
		reusable, err = q.ListLiveReusableEnrollmentKeys(ctx, sqlcdb.ListLiveReusableEnrollmentKeysParams{
			TenantID: tenantID, ExpiredAfter: now.Add(-reusableGrace)})
		return err
	}); err != nil {
		return rep, err
	}
	rep.Open = len(open)
	var (
		inst   headscale.Instance
		keys   map[uint64]headscale.PreAuthKey
		nodes  map[uint64][]headscale.Node // by pre-auth key id, first registered first
		listed []headscale.Node            // every node of the instance
		hsErr  error
		loaded bool
	)
	loadHS := func() {
		if loaded {
			return
		}
		loaded = true
		var err error
		if inst, err = s.reg.ForTenant(ctx, tenantID); err != nil {
			hsErr = err
			return
		}
		ks, err := inst.ListPreAuthKeys(ctx)
		if err != nil {
			hsErr = err
			return
		}
		ns, err := inst.ListNodes(ctx, "")
		if err != nil {
			hsErr = err
			return
		}
		keys, nodes, listed = map[uint64]headscale.PreAuthKey{}, map[uint64][]headscale.Node{}, ns
		for _, k := range ks {
			keys[k.ID] = k
		}
		for _, n := range ns {
			if n.PreAuthKeyID != 0 {
				nodes[n.PreAuthKeyID] = append(nodes[n.PreAuthKeyID], n)
			}
		}
		for _, list := range nodes {
			slices.SortFunc(list, func(a, b headscale.Node) int { // the first node the key registered first
				if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
					return c
				}
				return cmp.Compare(a.ID, b.ID)
			})
		}
	}
	for _, r := range open {
		out := outcome{}
		switch r.Status {
		case StatusRequested:
			if now.Sub(r.CreatedAt) > stuckAfter {
				out = outcome{status: StatusFailed, failure: FailureIssueUnfinished}
			}
		case StatusPendingApproval:
			if now.Sub(r.CreatedAt) >= DecisionWindow {
				out = outcome{status: StatusExpired}
			}
		case StatusApproved:
			since := r.CreatedAt
			if r.ApprovedAt != nil {
				since = *r.ApprovedAt
			}
			if now.Sub(since) >= DecisionWindow {
				out = outcome{status: StatusExpired}
			}
		case StatusAwaitingDevice:
			if r.CredentialExpiresAt != nil && !now.Before(*r.CredentialExpiresAt) {
				out = outcome{status: StatusExpired}
			}
		case StatusClaimed, StatusRegistered:
			if r.ClaimedAt == nil || now.Sub(*r.ClaimedAt) > stuckAfter {
				// the node the claim registered is checked as the claim would have, before the request is closed (C1)
				loadHS()
				if hsErr != nil {
					rep.Skipped++
					continue
				}
				var (
					gone []uint64
					err  error
				)
				if out, gone, err = s.unfinishedClaim(ctx, tenantID, inst, listed, r); err != nil {
					return rep, err
				}
				rep.Removed += len(gone)
				listed = slices.DeleteFunc(listed, func(n headscale.Node) bool { return slices.Contains(gone, n.ID) })
			}
		case StatusCredentialIssued:
			loadHS()
			if hsErr != nil {
				rep.Skipped++
				continue
			}
			out = s.keyOutcome(r, keys, nodes, now)
		}
		if out.status == "" {
			continue
		}
		adopted, err := s.settle(ctx, tenantID, r, out)
		if err != nil {
			return rep, err
		}
		rep.NewDevices += adopted
		switch out.status {
		case StatusExpired:
			rep.Expired++
		case StatusConsumed:
			rep.Consumed++
		case StatusFailed:
			rep.Failed++
		}
	}
	// a live reusable key may register more nodes after its consumed transition: each one enters the inventory once
	for _, r := range reusable {
		loadHS()
		if hsErr != nil {
			rep.Skipped++
			continue
		}
		kid := uint64(*r.HeadscalePreauthkeyID) //nolint:gosec // CHECK > 0; the query selects non-null ids
		// A3: the key ended at Headscale before its own expiry (a device revocation expires the keys that could register
		// the device again — §7.4 "Thu hồi thiết bị"; a restore invalidates them): the request no longer holds a live
		// credential — revoked, so it stops counting against max_live_enrollment_credentials and as a tag reference
		// (only while the recorded expiry is more than endedSlack away: never a key expiring on its own time)
		k, ok := keys[kid]
		keyNodes := nodes[kid]
		if ok && !issuedKey(r, k) { // A4: the id was handed out again (restore): neither that key nor its nodes are r's
			ok, keyNodes = false, nil
		}
		ended := r.CredentialExpiresAt != nil && now.Add(endedSlack).Before(*r.CredentialExpiresAt) &&
			(!ok || !k.Expiration.After(now))
		if len(keyNodes) == 0 && !ended {
			continue
		}
		adopted, revoked := 0, false
		err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
			cur, err := tx.Q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
			switch {
			case errors.Is(err, store.ErrNoRows):
				return nil
			case err != nil:
				return err
			case cur.Status != StatusConsumed:
				return nil // revoked meanwhile
			}
			if adopted, err = s.adoptKeyNodes(ctx, tx, tenantID, cur, keyNodes); err != nil || !ended {
				return err
			}
			if _, err := tx.Q.SetEnrollmentRequestOutcome(ctx, sqlcdb.SetEnrollmentRequestOutcomeParams{
				Status: StatusRevoked, RegisteredMachineKey: cur.RegisteredMachineKey, ReportedHostname: cur.ReportedHostname,
				ConsumedNodeID: cur.ConsumedNodeID, FailureCode: cur.FailureCode, TenantID: tenantID, ID: cur.ID}); err != nil {
				return err
			}
			revoked = true
			t := tenantID
			return audit.Record(ctx, tx.Q, audit.Event{Action: ActionRevoke, ActorType: audit.ActorSystem, TenantID: &t,
				ResourceType: resourceType, ResourceID: cur.ID.String(), Details: audit.Details{"status_before": cur.Status,
					"reason": "key_ended_at_headscale", "key_id": *cur.HeadscalePreauthkeyID, "key_listed": ok}})
		})
		if err != nil {
			return rep, err
		}
		rep.NewDevices += adopted
		if revoked {
			rep.Revoked++
		}
	}
	if err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		rows, err := tx.Q.LinkConsumedEnrollmentDevices(ctx, tenantID)
		if err != nil {
			return err
		}
		rep.Linked = int64(len(rows))
		for _, d := range rows {
			// a device of a pre-auth key whose row inventory.sync wrote after the consumed transition could not adopt it
			// (a reused node id): notified at this link, once; a web-auth device was notified by its claim
			if d.Method != MethodPreauthKey {
				continue
			}
			name := d.ID.String()
			if d.GivenName != nil && *d.GivenName != "" {
				name = *d.GivenName
			} else if d.Name != nil && *d.Name != "" {
				name = *d.Name
			}
			at := now.UTC()
			if d.HsCreatedAt != nil {
				at = d.HsCreatedAt.UTC()
			}
			if _, err := notifications.Enqueue(ctx, tx, notifications.DeviceNew(tenantID, d.ID, d.OwnerMembershipID, name,
				at)); err != nil {
				return err
			}
			rep.NewDevices++
		}
		return nil
	}); err != nil {
		return rep, err
	}
	if hsErr != nil && errors.Is(hsErr, headscale.ErrNoInstance) {
		// A2: a tenant that is not active has no reachable instance by design (the locator refuses it): its rows wait
		// for the resumption — not a failure to retry every run
		var status string
		if err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			tc, err := q.GetEnrollmentContext(ctx, tenantID)
			status = tc.TenantStatus
			return err
		}); err != nil {
			return rep, err
		}
		if status != tenants.StatusActive && status != tenants.StatusProvisioning {
			rep.Inactive = true
			return rep, nil
		}
	}
	return rep, hsErr
}

// outcome is the end reconcile found for a request.
type outcome struct {
	status  string
	failure string
	node    *headscale.Node  // consumed: the first node the key registered; claim_unfinished: the node the claim registered
	nodes   []headscale.Node // consumed: every node of the key (a reusable key registers several)
	// security is recorded with the outcome: the node of an unfinished claim failed the checks and was removed
	security *audit.SecurityEvent
}

// keyOutcome reads the state of an issued key at Headscale.
func (s *Service) keyOutcome(r sqlcdb.EnrollmentRequest, keys map[uint64]headscale.PreAuthKey,
	nodes map[uint64][]headscale.Node, now time.Time,
) outcome {
	if r.HeadscalePreauthkeyID == nil {
		return outcome{status: StatusFailed, failure: FailureKeyMissing}
	}
	kid := uint64(*r.HeadscalePreauthkeyID) //nolint:gosec // CHECK > 0
	k, ok := keys[kid]
	ns := nodes[kid]
	used := len(ns) > 0
	if ok && !issuedKey(r, k) { // the id was handed out again (restore of an older snapshot): r's key is gone
		ok, used = false, false
	}
	switch {
	case used:
		return outcome{status: StatusConsumed, node: &ns[0], nodes: ns}
	case ok && k.Used:
		return outcome{status: StatusFailed, failure: FailureNodeGone} // ephemeral node gone, or deleted at once
	case !ok && (r.CredentialExpiresAt == nil || now.Before(*r.CredentialExpiresAt)):
		return outcome{status: StatusFailed, failure: FailureKeyMissing}
	case !ok, r.CredentialExpiresAt != nil && !now.Before(*r.CredentialExpiresAt), !k.Expiration.After(now):
		return outcome{status: StatusExpired}
	}
	return outcome{}
}

// settle writes the outcome of one request (worker columns of 0020) if it is still open in the same status; a consumed
// key brings its nodes into the inventory in the same transaction (adoptKeyNodes — the devices it reports).
func (s *Service) settle(ctx context.Context, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest, out outcome) (int, error) {
	adopted := 0
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		cur, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if cur.Status != r.Status || cur.Version != r.Version { // moved meanwhile (claim, revoke…): next run
			return nil
		}
		p := sqlcdb.SetEnrollmentRequestOutcomeParams{Status: out.status, RegisteredMachineKey: cur.RegisteredMachineKey,
			ReportedHostname: cur.ReportedHostname, ConsumedNodeID: cur.ConsumedNodeID, FailureCode: cur.FailureCode,
			TenantID: tenantID, ID: r.ID}
		if out.failure != "" {
			p.FailureCode = &out.failure
		}
		if n := out.node; n != nil {
			nid := int64(n.ID) //nolint:gosec // small ids
			p.ConsumedNodeID = &nid
			if n.MachineKey != "" {
				mk := clip(n.MachineKey, 200)
				p.RegisteredMachineKey = &mk
			}
			if n.Name != "" {
				h := clip(n.Name, 255)
				p.ReportedHostname = &h
			}
		}
		row, err := q.SetEnrollmentRequestOutcome(ctx, p)
		if err != nil {
			return err
		}
		if out.security != nil {
			if _, err := audit.RecordSecurityEvent(ctx, q, *out.security); err != nil {
				return err
			}
		}
		if out.status != StatusConsumed {
			return nil
		}
		t := tenantID
		if err := audit.Record(ctx, q, audit.Event{Action: ActionConsume, ActorType: audit.ActorSystem, TenantID: &t,
			ResourceType: resourceType, ResourceID: r.ID.String(), Details: audit.Details{"node_id": *p.ConsumedNodeID,
				"nodes": len(out.nodes)}}); err != nil {
			return err
		}
		adopted, err = s.adoptKeyNodes(ctx, tx, tenantID, row, out.nodes)
		return err
	})
	if err != nil {
		return 0, err
	}
	return adopted, nil
}

// adoptKeyNodes brings the nodes a platform-issued pre-auth key registered into the inventory with the link to their
// enrollment request, and notifies each NEW device once (device.new — §6.3: its owner + the Tenant Owners; T-06 "thông
// báo thiết bị mới"), in the caller's job transaction tx (the consumed transition, or a later run for a live reusable
// key):
//   - a live row of the node with the same machine key and no link yet (inventory.sync came first): linked;
//   - no live row: the device enters the inventory now (InsertEnrolledDevice, as a verified claim does) and inventory.sync
//     is enqueued — it clamps the node's expiry (V-21: a client asks for any expiry with a pre-auth key too);
//   - a row already linked (an earlier run, a claim) or of another machine key (a reused node id — inventory.sync
//     replaces it and the final link step of Reconcile notifies it): nothing.
//
// The owner is the key's target membership, none for a tagged node. Only rows this call links or inserts are notified,
// and the ref device:<id>:new makes a repeated attempt write nothing: one notification per device.
func (s *Service) adoptKeyNodes(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest,
	nodes []headscale.Node,
) (int, error) {
	q := tx.Q
	adopted, inserted := 0, false
	for _, n := range nodes {
		if n.ID == 0 || n.ID > 1<<63-1 || n.MachineKey == "" {
			continue // never written: the CHECK of 0005 and the identity rule need both
		}
		var owner *uuid.UUID
		if !n.IsTagged() && r.TargetMembershipID != nil {
			o := *r.TargetMembershipID
			owner = &o
		}
		dev, err := q.LockLiveDeviceOfNode(ctx, sqlcdb.LockLiveDeviceOfNodeParams{TenantID: tenantID,
			InstanceID: r.InstanceID, HeadscaleNodeID: int64(n.ID)}) //nolint:gosec // bounded just above
		switch {
		case err == nil && (dev.MachineKey != n.MachineKey || dev.EnrollmentRequestID != nil):
			continue
		case err == nil:
			if err := q.LinkDeviceEnrollment(ctx, sqlcdb.LinkDeviceEnrollmentParams{EnrollmentRequestID: &r.ID,
				OwnerMembershipID: owner, TenantID: tenantID, ID: dev.ID}); err != nil {
				return adopted, err
			}
			if dev.OwnerMembershipID != nil {
				owner = dev.OwnerMembershipID // COALESCE of LinkDeviceEnrollment: the row's owner stays
			}
		case errors.Is(err, store.ErrNoRows):
			if dev, err = q.InsertEnrolledDevice(ctx, deviceParams(tenantID, r.InstanceID, n, owner, r.ID)); err != nil {
				return adopted, err
			}
			inserted = true
		default:
			return adopted, err
		}
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		if name == "" {
			name = dev.ID.String()
		}
		at := n.CreatedAt
		if at.IsZero() {
			at = s.now()
		}
		if _, err := notifications.Enqueue(ctx, tx, notifications.DeviceNew(tenantID, dev.ID, owner, name, at.UTC())); err != nil {
			return adopted, err
		}
		adopted++
	}
	if inserted {
		inst := r.InstanceID
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindSync, TenantID: &tenantID, InstanceID: &inst,
			Slot: slotEnroll}); err != nil {
			return adopted, err
		}
	}
	return adopted, nil
}

// unfinishedClaim is the end of a claim stuck in claimed or registered past stuckAfter (the process died, its verdict
// could not be written — C1). Before the request is closed claim_unfinished, the node its AuthRegister registered is
// checked as the claim would have (§7.4 step 8), so that no node stays registered under the member unverified:
//   - registered: the node the claim recorded (consumed_node_id, with its machine key); claimed: the node registeredBy
//     finds among the member's CLI nodes created from claimed_at until the pending registration could no longer be
//     applied (stuckAfter), every other request of the member accounting for its own — recorded on the request;
//   - a new node failing the checks (stepEight, on the hostname it registered with) is deleted — expired when the
//     delete does not go through — with the security event enrollment.node_mismatch; the other unaccounted nodes found
//     with it are removed as well (as a read-back does);
//   - a node that passes is kept: the requester's device (priorVerdicts never refuses it later). A node older than the
//     claim is never deleted (rule b): as for a claim that found nothing new, only a node an earlier claim rejected
//     loses the fresh expiry the AuthRegister may have given it (reprotect).
//
// It returns the outcome to settle and the ids of the nodes deleted.
func (s *Service) unfinishedClaim(ctx context.Context, tenantID uuid.UUID, inst headscale.Instance,
	listed []headscale.Node, r sqlcdb.EnrollmentRequest,
) (outcome, []uint64, error) {
	out := outcome{status: StatusFailed, failure: FailureClaimUnfinished}
	user := memberUserPrefix + r.RequestedByMembershipID.String()
	tc := tenantContext{instance: r.InstanceID}
	claimedAt := r.UpdatedAt
	if r.ClaimedAt != nil {
		claimedAt = *r.ClaimedAt
	}
	var mine []headscale.Node // the member's nodes
	for _, n := range listed {
		if n.User != nil && n.User.Name == user {
			mine = append(mine, n)
		}
	}
	var (
		node *headscale.Node
		host string
		gone []uint64
	)
	switch {
	case r.Status == StatusRegistered && r.ConsumedNodeID != nil:
		for i := range listed {
			n := &listed[i]
			if int64(n.ID) == *r.ConsumedNodeID && //nolint:gosec // small ids
				(r.RegisteredMachineKey == nil || clip(n.MachineKey, 200) == *r.RegisteredMachineKey) {
				node = n
			}
		}
		if node == nil {
			return out, nil, nil // gone (deleted, or its id handed out again to another machine)
		}
		if r.ReportedHostname != nil {
			host = *r.ReportedHostname
		}
		fresh, err := s.newOfClaim(ctx, tenantID, r, *node, claimedAt)
		if err != nil {
			return outcome{}, nil, err
		}
		if !fresh {
			s.reprotect(ctx, tenantID, inst, tc, r, []headscale.Node{*node})
			return out, nil, nil
		}
	case r.Status == StatusClaimed:
		var others []sqlcdb.ListMemberWebAuthClaimsRow
		if err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			var err error
			others, err = q.ListMemberWebAuthClaims(ctx, sqlcdb.ListMemberWebAuthClaimsParams{TenantID: tenantID,
				InstanceID: r.InstanceID, Member: r.RequestedByMembershipID, ID: r.ID, AnyStatus: true})
			return err
		}); err != nil {
			return outcome{}, nil, err
		}
		found, extra := registeredBy(mine, user, r, others, claimedAt, claimedAt.Add(stuckAfter))
		for _, n := range extra {
			deleted, expired := s.removeNode(ctx, inst, n.ID)
			if deleted {
				gone = append(gone, n.ID)
			}
			s.log.ErrorContext(ctx, "enrollment: reconcile removed another unverified node registered under the member during a claim",
				"alert", true, "request_id", r.ID, "node_id", n.ID, "deleted", deleted, "expired", expired)
		}
		if found == nil {
			s.reprotect(ctx, tenantID, inst, tc, r, mine)
			return out, gone, nil
		}
		node, host = found, found.Name
		out.node = found // recorded on the request (consumed_node_id, machine key, hostname)
	default:
		return out, nil, nil
	}
	reasons := stepEight(*node, host, user, r.EnrollCodeHash)
	if len(reasons) == 0 {
		return out, gone, nil // the requester's device
	}
	deleted, expired := s.removeNode(ctx, inst, node.ID)
	if deleted {
		gone = append(gone, node.ID)
	}
	t := tenantID
	out.security = &audit.SecurityEvent{TenantID: &t, Kind: EventNodeMismatch, Severity: audit.SeverityHigh,
		Source: securitySource, Details: audit.Details{"request_id": r.ID.String(),
			"membership_id": r.RequestedByMembershipID.String(), "node_id": int64(node.ID), //nolint:gosec // small ids
			"checks_failed": reasons, "deleted": deleted, "expired": expired, "found_by": "reconcile"}}
	s.log.ErrorContext(ctx, "enrollment: reconcile removed the unverified node of a claim that never reached its verdict",
		"alert", true, "request_id", r.ID, "node_id", node.ID, "checks_failed", reasons, "deleted", deleted,
		"expired", expired)
	return out, gone, nil
}

// newOfClaim reports whether node n, registered by a claim of r that never reached its verdict, is a new node of that
// claim as register decides it: created since the claim began, or since the request was created while the inventory
// had no row of this very node of the member before the claim began. An existing device re-authenticated is never
// deleted (rule b).
func (s *Service) newOfClaim(ctx context.Context, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest, n headscale.Node,
	claimedAt time.Time,
) (bool, error) {
	if createdSince(n, claimedAt) {
		return true, nil
	}
	if !createdSince(n, r.CreatedAt) {
		return false, nil
	}
	known := false
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.LiveDevicesOfMachineKey(ctx, sqlcdb.LiveDevicesOfMachineKeyParams{TenantID: tenantID,
			InstanceID: r.InstanceID, MachineKey: n.MachineKey})
		for _, d := range rows {
			if d.HeadscaleNodeID == int64(n.ID) && d.OwnerMembershipID != nil && //nolint:gosec // small ids
				*d.OwnerMembershipID == r.RequestedByMembershipID && d.FirstSeenAt.Before(claimedAt) {
				known = true
			}
		}
		return err
	})
	return !known, err
}

// ------------------------------------------------------------------------------------------------- schedule

// SchedulerConfig configures the schedule of enrollment.reconcile.
type SchedulerConfig struct {
	Interval time.Duration // between two runs for one tenant; default 2 minutes
	Tick     time.Duration // default 30 s (≤ Interval)
}

// Scheduler enqueues enrollment.reconcile for every tenant with a running instance AND an open enrollment request, a
// live reusable key (its later nodes are adopted — adoptKeyNodes) or an inventory row still waiting for its enrollment
// link (written by inventory.sync after its request ended — B1), once per Interval, each tenant at its own offset (a
// hash of its id). Worker process (workerSchedules in apps/).
type Scheduler struct {
	svc  *Service
	cfg  SchedulerConfig
	mu   sync.Mutex
	last map[uuid.UUID]int64
}

// NewScheduler returns the schedule of enrollment.reconcile (worker: mg_worker_*).
func (s *Service) NewScheduler(cfg SchedulerConfig) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Minute
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Interval {
		cfg.Tick = min(30*time.Second, cfg.Interval)
	}
	return &Scheduler{svc: s, cfg: cfg, last: map[uuid.UUID]int64{}}
}

// Run ticks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.cfg.Tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "enrollment: enrollment.reconcile schedule failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (sc *Scheduler) slot(tenant uuid.UUID, now time.Time) int64 {
	sum := sha256.Sum256(tenant[:])
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Interval)) //nolint:gosec // interval > 0
	return (now.UnixNano() - offset) / int64(sc.cfg.Interval)
}

// Tick enqueues the runs whose period started since the previous tick; it returns how many it enqueued.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	var instances []sqlcdb.ListRunningInstancesRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		instances, err = q.ListRunningInstances(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	seen := map[uuid.UUID]bool{}
	for _, in := range instances {
		tenant := in.TenantID
		if seen[tenant] {
			continue
		}
		seen[tenant] = true
		slot := sc.slot(tenant, now)
		sc.mu.Lock()
		prev, known := sc.last[tenant]
		sc.last[tenant] = slot
		sc.mu.Unlock()
		if !known || slot <= prev {
			continue
		}
		err := sc.svc.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			open, err := tx.Q.ListOpenEnrollmentRequests(ctx, tenant)
			if err != nil {
				return err
			}
			if len(open) == 0 {
				live, err := tx.Q.ListLiveReusableEnrollmentKeys(ctx, sqlcdb.ListLiveReusableEnrollmentKeysParams{
					TenantID: tenant, ExpiredAfter: sc.svc.now().Add(-reusableGrace)})
				if err != nil {
					return err
				}
				if len(live) == 0 {
					// a device row inventory.sync wrote after its request ended still needs its link (B1)
					pending, err := tx.Q.CountPendingEnrollmentLinks(ctx, tenant)
					if err != nil || pending == 0 {
						return err
					}
				}
			}
			_, err = jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindReconcile, TenantID: &tenant,
				Slot: strconv.FormatInt(slot, 10)})
			if err == nil {
				n++
			}
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "enrollment: enqueue enrollment.reconcile failed", "tenant_id", tenant,
				"error", err)
		}
	}
	return n, nil
}
