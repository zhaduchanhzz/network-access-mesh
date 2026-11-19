package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// tenantContext is what every operation reads first: the typed settings and the instance serving the tenant.
type tenantContext struct {
	settings    config.TenantSettings
	instance    uuid.UUID
	loginServer string
}

// loadContext reads the tenant's settings and live instance in q; a tenant without a live instance has nothing to
// enroll into (409 no_instance).
func loadContext(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (tenantContext, error) {
	row, err := q.GetEnrollmentContext(ctx, tenantID)
	if errors.Is(err, store.ErrNoRows) {
		return tenantContext{}, notFound("no_tenant")
	}
	if err != nil {
		return tenantContext{}, err
	}
	tc := tenantContext{settings: settingsOf(row.Settings)}
	if row.InstanceID == nil || row.ServerUrl == nil {
		return tc, conflict("no_instance", "The tenant has no control plane to enroll a device into yet.")
	}
	tc.instance, tc.loginServer = *row.InstanceID, *row.ServerUrl
	return tc, nil
}

// loginServerOf is the --login-server of the tenant ("" when it has no live instance).
func loginServerOf(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (string, error) {
	row, err := q.GetEnrollmentContext(ctx, tenantID)
	if err != nil || row.ServerUrl == nil {
		if errors.Is(err, store.ErrNoRows) {
			err = nil
		}
		return "", err
	}
	return *row.ServerUrl, nil
}

// checkSelfEnroll applies the condition self_enroll of the End User's grant (§8.6).
func checkSelfEnroll(a Actor, tc tenantContext) error {
	if a.SelfEnrollOnly && !tc.settings.Enrollment.SelfEnroll {
		return forbidden("self_enroll_disabled", "This tenant does not let members add devices themselves.")
	}
	return nil
}

// member is a Headscale-user owner of a device: membership, user name mg-<membership>, display name.
type member struct {
	id      uuid.UUID
	user    string
	display string
}

func loadMember(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID, field string) (member, error) {
	m, err := q.GetEnrollmentMember(ctx, sqlcdb.GetEnrollmentMemberParams{TenantID: tenantID, ID: id})
	if errors.Is(err, store.ErrNoRows) {
		return member{}, invalid(field, "member_not_found", field+" is not a member of this tenant")
	}
	if err != nil {
		return member{}, err
	}
	if m.Status != "active" {
		return member{}, invalid(field, "member_not_active", field+" is not an active member of this tenant")
	}
	return member{id: m.ID, user: m.HeadscaleUsername, display: m.DisplayName}, nil
}

// stateOf copies a row into the parameters of SetEnrollmentRequestState (the caller changes what it moves).
func stateOf(r sqlcdb.EnrollmentRequest) sqlcdb.SetEnrollmentRequestStateParams {
	return sqlcdb.SetEnrollmentRequestStateParams{Status: r.Status, ApproverMembershipID: r.ApproverMembershipID,
		ApprovedAt: r.ApprovedAt, IssuedAt: r.IssuedAt, HeadscalePreauthkeyID: r.HeadscalePreauthkeyID,
		AuthIDHash: r.AuthIDHash, SessionIDHash: r.SessionIDHash, EnrollCodeHash: r.EnrollCodeHash, ClaimedAt: r.ClaimedAt,
		ClaimedFromIp: r.ClaimedFromIp, RegisteredMachineKey: r.RegisteredMachineKey, ReportedHostname: r.ReportedHostname,
		CredentialExpiresAt: r.CredentialExpiresAt, ConsumedNodeID: r.ConsumedNodeID, FailureCode: r.FailureCode,
		TenantID: r.TenantID, ID: r.ID}
}

// commands are the `tailscale up` lines of a credential (the key never enters a command: TS_AUTHKEY).
func webAuthCommand(loginServer, hostname string) string {
	return "tailscale up --login-server=" + loginServer + " --hostname=" + hostname
}

func preauthCommand(loginServer string) string {
	return `tailscale up --login-server=` + loginServer + ` --auth-key="$TS_AUTHKEY"`
}

// issueCode moves a web-auth request to awaiting_device in q: a new one-time code (hash stored), bound to the caller's
// Portal session, valid WebAuthWindow.
func (s *Service) issueCode(ctx context.Context, q *sqlcdb.Queries, r sqlcdb.EnrollmentRequest, a Actor,
	loginServer string,
) (sqlcdb.EnrollmentRequest, *Credential, error) {
	if a.SessionID == uuid.Nil {
		return r, nil, errors.New("enrollment: a web-auth code needs the caller's Portal session")
	}
	code, err := newCode()
	if err != nil {
		return r, nil, err
	}
	now := s.now().UTC().Truncate(time.Millisecond) // the column keeps microseconds: the credential shows what is stored
	exp := now.Add(WebAuthWindow)
	p := stateOf(r)
	p.Status, p.IssuedAt, p.CredentialExpiresAt = StatusAwaitingDevice, &now, &exp
	p.EnrollCodeHash, p.SessionIDHash = codeHash(code), sessionHash(a.SessionID)
	row, err := q.SetEnrollmentRequestState(ctx, p)
	if err != nil {
		return r, nil, err
	}
	host := HostnamePrefix + code
	return row, &Credential{Kind: CredentialEnrollCode, EnrollCode: headscale.NewSecret(code), Hostname: host,
		Command: webAuthCommand(loginServer, host), ExpiresAt: exp}, nil
}

// ensureUser returns the id of the Headscale user name, creating it with only its display name (§7.4 step 3: no
// e-mail — user tokens of the policy also match e-mail addresses).
func ensureUser(ctx context.Context, inst headscale.Instance, name, display string) (uint64, error) {
	find := func() (uint64, error) {
		users, err := inst.ListUsers(ctx, headscale.UserFilter{Name: name})
		if err != nil {
			return 0, err
		}
		for _, u := range users {
			if u.Name == name {
				return u.ID, nil
			}
		}
		return 0, nil
	}
	if id, err := find(); err != nil || id != 0 {
		return id, err
	}
	if len(display) > 256 {
		display = display[:256]
	}
	u, err := inst.CreateUser(ctx, headscale.CreateUser{Name: name, DisplayName: display})
	if errors.Is(err, headscale.ErrConflict) { // created concurrently (another request of the same member)
		return find()
	}
	if err != nil {
		return 0, err
	}
	return u.ID, nil
}

// fromAdapter maps an error of internal/headscale (or of the context) to an Error with its Problem code (§13.4 rule 5):
// Headscale's own message stays in the cause, the client only gets the adapter's filtered detail.
func fromAdapter(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := AsError(err); ok {
		return e
	}
	he, ok := headscale.AsError(err)
	if !ok {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return &Error{Code: CodeInstanceUnavailable, Reason: "timeout", Err: err,
				Detail: "The tenant's control plane is not responding; try again later."}
		}
		return &Error{Code: CodeInternal, Reason: "internal", Err: err}
	}
	return &Error{Code: he.ProblemCode(), Reason: string(he.Kind), Err: err, Detail: he.Detail()}
}

// failureCode is the failure_code of a request that failed on an adapter error.
func failureCode(e *Error) string {
	r := strings.ReplaceAll(e.Reason, "-", "_")
	if r == "" || r[0] < 'a' || r[0] > 'z' {
		return "failed"
	}
	return r
}

// keyPlan is the pre-auth key a request issues.
type keyPlan struct {
	owner     *member // nil: tag-only key
	ttl       time.Duration
	tags      []string
	reusable  bool
	ephemeral bool
}

// issueKey creates the pre-auth key of request r at Headscale (explicit expiration — V-06) and records it:
// credential_issued with the key's numeric id, op succeeded. Any failure ends the request failed (op failed); a key
// created but not recorded — or refused at the record (issuable) — is expired at once: no live credential the platform
// does not know.
func (s *Service) issueKey(ctx context.Context, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest, kp keyPlan,
	loginServer string, op audit.Operation,
) (sqlcdb.EnrollmentRequest, *Credential, error) {
	fail := func(err error) (sqlcdb.EnrollmentRequest, *Credential, error) {
		e := fromAdapter(err)
		s.failRequest(ctx, tenantID, r.ID, failureCode(e), &op)
		return r, nil, e
	}
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		return fail(err)
	}
	var uid uint64
	if kp.owner != nil {
		if uid, err = ensureUser(ctx, inst, kp.owner.user, kp.owner.display); err != nil {
			return fail(err)
		}
		if uid == 0 {
			return fail(&Error{Code: CodeUpstreamRejected, Reason: "user_not_created",
				Detail: "The tenant's control plane did not create the device owner's user."})
		}
	}
	issued := s.now().UTC().Truncate(time.Millisecond)
	exp := issued.Add(kp.ttl)
	key, err := inst.CreatePreAuthKey(ctx, headscale.PreAuthKeyOpts{User: uid, Reusable: kp.reusable,
		Ephemeral: kp.ephemeral, Expiration: exp, Tags: kp.tags})
	if err != nil {
		return fail(err)
	}
	if key.ID == 0 || key.Key.IsZero() || key.Expiration.After(exp.Add(time.Second)) || key.Reusable != kp.reusable {
		if key.ID != 0 {
			_ = inst.ExpirePreAuthKey(context.WithoutCancel(ctx), key.ID)
		}
		return fail(&Error{Code: CodeUpstreamRejected, Reason: "readback_mismatch",
			Detail: "The tenant's control plane did not issue the key as requested."})
	}
	kid := int64(key.ID) //nolint:gosec // Headscale ids are small positive integers
	var (
		row     sqlcdb.EnrollmentRequest
		refusal *Error
	)
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		cur, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
		if err != nil {
			return err
		}
		if refusal, err = issuable(ctx, q, tenantID, r, cur); err != nil || refusal != nil {
			if err != nil {
				return err
			}
			if cur.Version == r.Version { // still the row the issuance started from (a moved row keeps its newer state)
				p := stateOf(cur)
				p.Status, p.FailureCode = StatusFailed, &refusal.Reason
				if _, err := q.SetEnrollmentRequestState(ctx, p); err != nil {
					return err
				}
			}
			return s.closeOp(ctx, q, &op, refusal.Reason)
		}
		p := stateOf(cur)
		p.Status, p.IssuedAt, p.CredentialExpiresAt, p.HeadscalePreauthkeyID = StatusCredentialIssued, &issued, &exp, &kid
		if row, err = q.SetEnrollmentRequestState(ctx, p); err != nil {
			return err
		}
		return op.Succeeded(ctx, q, audit.Details{"key_id": kid, "expires_at": exp, "reusable": kp.reusable,
			"ephemeral": kp.ephemeral, "tags": kp.tags, "tag_only": kp.owner == nil})
	})
	if err != nil {
		_ = inst.ExpirePreAuthKey(context.WithoutCancel(ctx), key.ID)
		s.failRequest(ctx, tenantID, r.ID, "record_failed", &op)
		return r, nil, fmt.Errorf("enrollment: record the issued key: %w", err)
	}
	if refusal != nil { // created but never handed out: expired at once (no live credential the platform does not know)
		if err := inst.ExpirePreAuthKey(context.WithoutCancel(ctx), key.ID); err != nil {
			s.log.ErrorContext(ctx, "enrollment: expiring a key that was not handed out failed", "request_id", r.ID,
				"key_id", key.ID, "reason", fromAdapter(err).Reason)
		}
		return r, nil, refusal
	}
	return row, &Credential{Kind: CredentialPreauthKey, PreauthKey: key.Key, Command: preauthCommand(loginServer),
		ExpiresAt: exp}, nil
}

// issuable re-checks, under the lock of the request and after its key was created at Headscale, what the issuance
// started from (cur is the locked row, r the row the issuance read). The request may have moved meanwhile — /revoke of
// a `requested` row does not wait for an issuance it cannot see, reconcile expires an `approved` one —: the newer state
// stays (409 already_final). The tenant may have been suspended after the authorizer let the call through: the
// suspension expires the keys it lists after its status change (P3-T08 step preauthkeys.expire), not a key created after
// that read, and this read follows the creation — so a key is either seen by that step or refused here (403).
func issuable(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, r, cur sqlcdb.EnrollmentRequest) (*Error, error) {
	if cur.Status != r.Status || cur.Version != r.Version {
		return conflict("already_final", "The request was revoked or ended while its key was being issued; no key was handed out."), nil
	}
	tc, err := q.GetEnrollmentContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	switch tc.TenantStatus {
	case tenants.StatusSuspended, tenants.StatusDeprovisioning, tenants.StatusDeleted:
		return &Error{Code: codeTenantSuspended, Reason: codeTenantSuspended,
			Detail: "The tenant was suspended while the key was being issued; no key was handed out."}, nil
	}
	return nil, nil
}

// codeTenantSuspended is the Problem code (403) of a write on a suspended tenant — the one the authorizer answers.
const codeTenantSuspended = "tenant_suspended"

// memberUserPrefix starts the Headscale user name of every membership (tenant_memberships.headscale_username, generated
// column of 0002: 'mg-' || id).
const memberUserPrefix = "mg-"

// issuedKey reports whether k — the key Headscale lists under the id request r recorded — can be the key r issued.
// After a restore of an older snapshot Headscale hands its ids out again (§6.3 device_inventory_cache: VERIFIED on
// 0.29.7 for nodes; pre-auth keys follow the same kind of counter), so the key of a request made after the restore may
// carry the id of r's key, which the restore lost: neither its use nor its expiry is r's. Only what the platform itself
// guarantees about r's key tells them apart — no guess on how Headscale reports the owner of a tagged key:
//   - the reusable flag issueKey asked for (checked on the key Headscale answered);
//   - an expiry no later than r's credential_expires_at (issueKey checked the answered key against it; Headscale
//     never extends a key, an expiry only shortens it) — a key issued after the restore lives later than r's;
//   - an owner that is no other member: a key of another member's Headscale user mg-<membership> is not r's.
func issuedKey(r sqlcdb.EnrollmentRequest, k headscale.PreAuthKey) bool {
	if k.Reusable != r.Reusable {
		return false
	}
	if r.CredentialExpiresAt != nil && k.Expiration.After(r.CredentialExpiresAt.Add(time.Second)) {
		return false
	}
	if u := k.User; u != nil && strings.HasPrefix(u.Name, memberUserPrefix) &&
		(r.TargetMembershipID == nil || u.Name != memberUserPrefix+r.TargetMembershipID.String()) {
		return false
	}
	return true
}

// detached is a context for the closing writes of an operation: not cancelled with the request, bounded.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
}

// failRequest ends a request failed with code (unless it already ended) and closes op failed, in a transaction of its
// own.
func (s *Service) failRequest(ctx context.Context, tenantID, id uuid.UUID, code string, op *audit.Operation) {
	wctx, cancel := detached(ctx)
	defer cancel()
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.LockEnrollmentRequest(wctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: id})
		if err != nil {
			return err
		}
		if !final(r.Status) {
			p := stateOf(r)
			p.Status, p.FailureCode = StatusFailed, &code
			if _, err := q.SetEnrollmentRequestState(wctx, p); err != nil {
				return err
			}
		}
		return s.closeOp(wctx, q, op, code)
	})
	if err != nil {
		s.log.ErrorContext(ctx, "enrollment: recording a failed request failed", "request_id", id, "code", code,
			"sqlstate", store.SQLState(err))
	}
}

// closeOp writes "<action>.failed" for op in q unless the pair is already complete.
func (s *Service) closeOp(ctx context.Context, q *sqlcdb.Queries, op *audit.Operation, code string) error {
	if op == nil || op.ID == uuid.Nil {
		return nil
	}
	st, err := q.OperationState(ctx, op.ID)
	if err != nil || !st.Requested || st.Finished {
		return err
	}
	return op.Failed(ctx, q, code, nil)
}

// ------------------------------------------------------------------------------------------------- idempotency

const idempotencyLock = 60 * time.Second

// storedIssue is the body an Idempotency-Key replays: the issue without its secrets (§13.1) — nor anything derived from
// them: the hostname mg-<code> and the command of a web-auth code carry the code, so they are rebuilt from the Vault at a
// replay; the secrets are in the Vault under the stored reference.
type storedIssue struct {
	Request    Request           `json:"request"`
	Credential *storedCredential `json:"credential,omitempty"`
}

type storedCredential struct {
	Kind      string    `json:"kind"`
	Hostname  string    `json:"hostname,omitempty"`
	Command   string    `json:"command"`
	ExpiresAt time.Time `json:"expires_at"`
}

// secretPayload is what the Vault keeps for a replay.
type secretPayload struct {
	PreauthKey string `json:"preauth_key,omitempty"`
	EnrollCode string `json:"enroll_code,omitempty"`
}

// beginIdempotent takes the key (§13.1); a replay returns the stored issue with its secret recalled from the Vault.
func (s *Service) beginIdempotent(ctx context.Context, tenantID uuid.UUID, a Actor, operation string,
	idem *Idempotency,
) (*jobs.IdempotencyKey, *Issue, error) {
	if idem == nil {
		return nil, nil, nil
	}
	key := &jobs.IdempotencyKey{TenantID: &tenantID, IdentityID: a.IdentityID, OperationID: operation, Key: idem.Key}
	var resp *jobs.StoredResponse
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, idempotencyLock)
		if errors.Is(err, jobs.ErrInvalidIdempotencyKey) {
			return invalid("Idempotency-Key", "invalid_idempotency_key", "Idempotency-Key is invalid")
		}
		if err != nil {
			return err
		}
		switch d.Outcome {
		case jobs.IdempotencyReplay:
			resp = d.Response
		case jobs.IdempotencyInProgress:
			return &Error{Code: CodeConflict, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter,
				Detail: "A request with this Idempotency-Key is still in progress."}
		case jobs.IdempotencyKeyReuse:
			return &Error{Code: CodeIdempotencyReuse, Reason: "idempotency_key_reuse",
				Detail: "The Idempotency-Key was used for another request."}
		}
		return nil
	})
	if err != nil || resp == nil {
		return key, nil, err
	}
	var st storedIssue
	if resp.Body == nil || json.Unmarshal(resp.Body, &st) != nil {
		return nil, nil, errors.New("enrollment: stored response unreadable")
	}
	out := &Issue{Request: st.Request}
	if st.Credential != nil {
		c := &Credential{Kind: st.Credential.Kind, Hostname: st.Credential.Hostname, Command: st.Credential.Command,
			ExpiresAt: st.Credential.ExpiresAt}
		if resp.SecretRef == nil || s.vault == nil {
			return nil, nil, secretGone()
		}
		raw, err := s.vault.Recall(ctx, tenantID, *resp.SecretRef)
		if errors.Is(err, ErrSecretGone) {
			return nil, nil, secretGone()
		}
		if err != nil {
			return nil, nil, err
		}
		var sp secretPayload
		err = json.Unmarshal(raw, &sp)
		clear(raw)
		if err != nil {
			return nil, nil, errors.New("enrollment: kept credential unreadable")
		}
		if (c.Kind == CredentialEnrollCode && sp.EnrollCode == "") || (c.Kind == CredentialPreauthKey && sp.PreauthKey == "") {
			return nil, nil, secretGone() // fail closed: no hostname mg- nor command without the credential they carry
		}
		c.PreauthKey, c.EnrollCode = headscale.NewSecret(sp.PreauthKey), headscale.NewSecret(sp.EnrollCode)
		if c.Kind == CredentialEnrollCode { // never stored: both carry the code (issueCode)
			c.Hostname = HostnamePrefix + sp.EnrollCode
			c.Command = webAuthCommand(st.Request.LoginServer, c.Hostname)
		}
		out.Credential = c
	}
	return nil, out, nil
}

func secretGone() *Error {
	return &Error{Code: CodeSecretGone, Reason: "secret_no_longer_available",
		Detail: "The credential of this request is no longer available: revoke the request and create a new one."}
}

// finishIdempotent stores the response of the request holding key (secrets in the Vault, by reference).
func (s *Service) finishIdempotent(ctx context.Context, tenantID uuid.UUID, key *jobs.IdempotencyKey, idem *Idempotency,
	out Issue,
) error {
	if key == nil {
		return nil
	}
	st := storedIssue{Request: out.Request}
	var ref *string
	if c := out.Credential; c != nil {
		st.Credential = &storedCredential{Kind: c.Kind, ExpiresAt: c.ExpiresAt}
		if c.Kind != CredentialEnrollCode { // the hostname and command of a code hold the code: rebuilt at a replay
			st.Credential.Hostname, st.Credential.Command = c.Hostname, c.Command
		}
		if s.vault != nil {
			raw, err := json.Marshal(secretPayload{PreauthKey: c.PreauthKey.Reveal(), EnrollCode: c.EnrollCode.Reveal()})
			if err != nil {
				return err
			}
			r, err := s.vault.Keep(ctx, tenantID, raw, c.ExpiresAt)
			clear(raw)
			if err != nil {
				return fmt.Errorf("enrollment: keep the credential for replays: %w", err)
			}
			ref = &r
		}
	}
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body, SecretRef: ref,
			Resource: &jobs.Resource{Type: resourceType, ID: out.Request.ID.String()}})
	})
}

// abandonIdempotent releases the key after a failed request (the client may retry with it).
func (s *Service) abandonIdempotent(ctx context.Context, tenantID uuid.UUID, key *jobs.IdempotencyKey, idem *Idempotency) {
	if key == nil {
		return
	}
	wctx, cancel := detached(ctx)
	defer cancel()
	_ = s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		return jobs.FailIdempotent(wctx, q, *key, idem.Hash)
	})
}
