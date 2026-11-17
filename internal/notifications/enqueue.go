package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// JobKind is the job that delivers one outbox row by e-mail (§13.5): dedupe key notification:<row id>.
const JobKind = "notification.send"

// Outbox statuses (notification_outbox.status, 0009).
const (
	StatusPending   = "pending"
	StatusSent      = "sent"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Result is what Enqueue wrote.
type Result struct {
	// Notifications are the outbox rows written, one per recipient (a member with a verified address gets one row that
	// is both the Portal record and the e-mail; a member without one gets a Portal-only row; an address gets an e-mail
	// only).
	Notifications []uuid.UUID
	// Jobs is how many notification.send jobs were enqueued (one per row with an e-mail address).
	Jobs int
	// Duplicate: a notification of the same (tenant, kind, ref) already exists — nothing was written.
	Duplicate bool
	// Suppressed lists the audience parts switched off by TenantSettings.notifications.
	Suppressed bool
}

// Enqueuer is the producer side of the module, for code that takes it as a dependency (tests substitute it). The
// package function Enqueue implements it.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx *store.Tx, ev Event) (Result, error)
}

// EnqueuerFunc adapts a function to Enqueuer.
type EnqueuerFunc func(ctx context.Context, tx *store.Tx, ev Event) (Result, error)

// Enqueue calls f.
func (f EnqueuerFunc) Enqueue(ctx context.Context, tx *store.Tx, ev Event) (Result, error) {
	return f(ctx, tx, ev)
}

// Default is the production Enqueuer (the package function Enqueue).
var Default Enqueuer = EnqueuerFunc(Enqueue)

// recipient is one resolved recipient.
type recipient struct {
	membership *uuid.UUID
	email      *string
}

// Enqueue writes the notifications of ev in tx — the transaction of the event itself (outbox, §6.3): opened by
// store.WithTenantJobTx for a tenant event (RLS: only that tenant's members can be resolved and written), by
// WithPlatformJobTx for a platform event. They commit or roll back with the event.
//
//  1. the event is checked against its kind: payload fields of the kind only, no secret-shaped value or URL;
//  2. TenantSettings.notifications.<setting> = false drops the role part of the audience of kinds that have a setting;
//  3. (tenant, kind, ref) is locked (advisory, transaction scope) and looked up: an existing notification ⇒ nothing
//     is written (Duplicate) — the producer may run again;
//  4. recipients are resolved: active members (active identity) by role, by permission (scope any) or by id, platform
//     staff by platform role, plus explicit addresses; a member's e-mail is used only when the IdP marked it verified
//     (an unverified address could belong to someone else — the member then gets the Portal record only);
//  5. one row per distinct recipient; a row with an address is pending and gets its notification.send job in tx, a
//     row without one is written sent (its Portal record is its delivery).
//
// Zero recipients is not an error (Result.Notifications is empty): a tenant whose Owner has not signed in yet.
func Enqueue(ctx context.Context, tx *store.Tx, ev Event) (Result, error) {
	if tx == nil {
		return Result{}, errors.New("notifications: no transaction")
	}
	payload, err := ev.validate()
	if err != nil {
		return Result{}, err
	}
	q := tx.Q
	var res Result
	audience := ev.To
	if ev.TenantID != nil {
		ts, err := q.GetTenantNotificationSettings(ctx, *ev.TenantID)
		if errors.Is(err, store.ErrNoRows) {
			return Result{}, ErrNoTenant
		}
		if err != nil {
			return Result{}, fmt.Errorf("notifications: tenant settings: %w", err)
		}
		payload["tenant_name"], payload["tenant_slug"] = ts.Name, ts.Slug
		if key := specs[ev.Kind].setting; key != "" && settingOff(ts.Notifications, key) && len(audience.Roles) > 0 {
			audience.Roles = nil
			res.Suppressed = true
		}
	}
	if err := q.LockNotificationRef(ctx, refLockKey(ev)); err != nil {
		return Result{}, fmt.Errorf("notifications: lock: %w", err)
	}
	dup, err := q.NotificationRefExists(ctx, sqlcdb.NotificationRefExistsParams{TenantID: ev.TenantID, Kind: string(ev.Kind), Ref: ev.Ref})
	if err != nil {
		return Result{}, fmt.Errorf("notifications: dedupe: %w", err)
	}
	if dup {
		res.Duplicate = true
		return res, nil
	}
	recips, err := resolve(ctx, q, ev.TenantID, audience)
	if err != nil {
		return Result{}, err
	}
	payload["ref"] = ev.Ref
	payload["locale"] = DefaultLocale
	if ev.Locale != "" {
		payload["locale"] = ev.Locale
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Result{}, fmt.Errorf("notifications: payload: %w", err)
	}
	if len(body) > maxPayloadBytes {
		return Result{}, fmt.Errorf("%w: payload larger than %d bytes", ErrInvalidEvent, maxPayloadBytes)
	}
	for _, r := range recips {
		status := StatusSent
		if r.email != nil {
			status = StatusPending
		}
		row, err := q.InsertNotification(ctx, sqlcdb.InsertNotificationParams{TenantID: ev.TenantID,
			RecipientMembershipID: r.membership, RecipientEmail: r.email, Kind: string(ev.Kind), Payload: body, Status: status})
		if err != nil {
			return Result{}, fmt.Errorf("notifications: insert: %w", err)
		}
		res.Notifications = append(res.Notifications, row.ID)
		if r.email == nil {
			continue
		}
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: JobKind, TenantID: ev.TenantID, Object: row.ID.String(),
			Input: sendInput{NotificationID: row.ID}, Resource: &jobs.Resource{Type: "notification", ID: row.ID.String()},
		}); err != nil {
			return Result{}, fmt.Errorf("notifications: enqueue %s: %w", JobKind, err)
		}
		res.Jobs++
	}
	return res, nil
}

// maxPayloadBytes is the CHECK of notification_outbox.payload (8 KiB).
const maxPayloadBytes = 8192

// sendInput is the input of notification.send (identifiers only — §11.3).
type sendInput struct {
	NotificationID uuid.UUID `json:"notification_id"`
}

// refLockKey is the advisory-lock key of the dedupe check.
func refLockKey(ev Event) string {
	t := "platform"
	if ev.TenantID != nil {
		t = ev.TenantID.String()
	}
	return "meshguard:notification:" + t + ":" + string(ev.Kind) + ":" + ev.Ref
}

// settingOff reports TenantSettings.notifications.<key> == false (absent or anything else ⇒ on).
func settingOff(raw []byte, key string) bool {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	v, ok := m[key].(bool)
	return ok && !v
}

// resolve turns the audience into distinct recipients: members first (by role, permission, id — each once), then
// platform staff, then addresses that are not already a member's.
func resolve(ctx context.Context, q *sqlcdb.Queries, tenantID *uuid.UUID, a Audience) ([]recipient, error) {
	type member struct {
		id       uuid.UUID
		email    *string
		verified bool
	}
	var members []member
	add := func(id uuid.UUID, email *string, verified bool) {
		for _, m := range members {
			if m.id == id {
				return
			}
		}
		members = append(members, member{id: id, email: email, verified: verified})
	}
	if tenantID != nil {
		if len(a.Roles) > 0 {
			rows, err := q.ListNotificationMembersByRole(ctx, sqlcdb.ListNotificationMembersByRoleParams{
				TenantID: *tenantID, RoleKeys: a.Roles})
			if err != nil {
				return nil, fmt.Errorf("notifications: recipients by role: %w", err)
			}
			for _, r := range rows {
				add(r.MembershipID, r.Email, r.EmailVerified)
			}
		}
		if a.Permission != "" {
			rows, err := q.ListNotificationMembersByPermission(ctx, sqlcdb.ListNotificationMembersByPermissionParams{
				TenantID: *tenantID, PermissionKey: a.Permission})
			if err != nil {
				return nil, fmt.Errorf("notifications: recipients by permission: %w", err)
			}
			for _, r := range rows {
				add(r.MembershipID, r.Email, r.EmailVerified)
			}
		}
		if len(a.Members) > 0 {
			rows, err := q.ListNotificationMembersByID(ctx, sqlcdb.ListNotificationMembersByIDParams{
				TenantID: *tenantID, Ids: a.Members})
			if err != nil {
				return nil, fmt.Errorf("notifications: recipients by id: %w", err)
			}
			for _, r := range rows {
				add(r.MembershipID, r.Email, r.EmailVerified)
			}
		}
	}
	var out []recipient
	seen := map[string]bool{}
	for _, m := range members {
		r := recipient{membership: &m.id}
		if m.verified && m.email != nil && *m.email != "" {
			if e, err := normalizeEmail(*m.email); err == nil && !seen[strings.ToLower(e)] {
				seen[strings.ToLower(e)] = true
				r.email = &e
			}
		}
		out = append(out, r)
	}
	if tenantID == nil && len(a.PlatformRoles) > 0 {
		rows, err := q.ListNotificationPlatformStaff(ctx, a.PlatformRoles)
		if err != nil {
			return nil, fmt.Errorf("notifications: platform staff: %w", err)
		}
		for _, r := range rows {
			if !r.EmailVerified || r.Email == nil {
				continue // platform notifications are e-mail only: no verified address, no channel
			}
			if e, err := normalizeEmail(*r.Email); err == nil && !seen[strings.ToLower(e)] {
				seen[strings.ToLower(e)] = true
				out = append(out, recipient{email: &e})
			}
		}
	}
	emails := slices.Clone(a.Emails)
	slices.Sort(emails)
	for _, raw := range emails {
		e, err := normalizeEmail(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
		}
		if seen[strings.ToLower(e)] {
			continue
		}
		seen[strings.ToLower(e)] = true
		out = append(out, recipient{email: &e})
	}
	return out, nil
}
