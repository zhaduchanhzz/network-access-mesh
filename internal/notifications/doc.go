// Package notifications is the notification module of the Management Plane (§4.2 module `notifications`, §6.3
// notification_outbox, §13.5 notification.send; P3-T05b): producers write an outbox row per recipient in the
// transaction of the event, the worker delivers each row by e-mail (SMTP) with the job notification.send, and the
// Portal reads the caller's own rows (GET /tenants/{t}/notifications).
//
// # Producers (Enqueue)
//
// A producer builds an Event with a constructor of this package — TenantActivated, Invitation, TenantSuspended,
// TenantResumed, DeviceNew, DeviceExpiring, APIKeyExpiring (platform), PolicyApplied, SupportGrantRequested,
// BreakGlass, SupportGrantUsed, ApprovalRequested, EnrollmentApproved/EnrollmentRejected (the requester only) … — and
// calls Enqueue(ctx, tx, ev) in its own transaction
// (store.WithTenantJobTx for a tenant event, WithPlatformJobTx for a platform event): the rows and their jobs commit or
// roll back with the event. The constructor fixes the recipient rule of §6.3: security notifications (break-glass,
// support grant used) → every Tenant Owner; a new device → its owner + the Tenant Owners; an approval request → the
// members holding the deciding permission; the rest → Tenant Owners/Admins, which TenantSettings.notifications may
// switch off for the kinds that have a setting (policy_applied; new_device stops the Owners' copies only). Recipients
// are resolved inside the event's tenant (RLS): a member of another tenant cannot be selected. Every event has a ref:
// a second Enqueue of the same (tenant, kind, ref) writes nothing, so a producer that runs again never notifies twice.
//
// # No secret
//
// The payload holds only the fields declared for the kind (ids, names, times), checked at Enqueue: no value shaped
// like a credential and no URL. Templates (vi/en, templates.go) are fixed text plus those fields and the platform's
// own links (https://app.<domain>, https://admin.<domain>). An invitation e-mail points at the tenant's sign-in page
// and never carries a token. Logs carry row ids, kinds and SMTP status codes — never a body or an address list.
//
// # Delivery (notification.send)
//
// One job per row with an address (dedupe notification:<row id>): lock the row, count the attempt, render the
// template in the row's locale (default vi), send through the relay (STARTTLS or implicit TLS, AUTH PLAIN only over
// TLS, password from a file secret), mark sent. 4xx/network errors retry with the framework's backoff; a 5xx or the
// last attempt marks the row failed and fails the job (alert). A row no longer pending is never sent again; the only
// duplicate window (relay accepted, commit lost) re-sends the same Message-ID. Without a relay (MG_SMTP_ADDR unset —
// refused in production by internal/config) e-mail rows are cancelled and the Portal records stay.
//
// A member gets one row that is both the Portal record and the e-mail — the e-mail only when the IdP marked the address
// verified. An address without a membership (an invitation) gets an e-mail only. A platform event goes to the
// platform staff with a verified address (e-mail only; the Platform Console reads audit and alerts).
package notifications
