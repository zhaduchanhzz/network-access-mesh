// Package audit is the audit trail of the Management Plane (§6.1 "Đường ghi audit", §8.8, §16.5; P2-T08): the
// append-only audit_events table (monthly partitions, UPDATE/DELETE/TRUNCATE refused to every role — trigger for the
// owner), the security_events table, and the reader behind GET /tenants/{tenantId}/audit and GET /platform/audit.
//
// # Write paths
//
//   - Record(ctx, q, ev) — in the business transaction q of store.WithTenantTx / WithPlatformTx: the event of a
//     successful operation commits or rolls back with the change it describes; RLS checks its tenant.
//   - Logger.RecordDetached — denied and failure events, written when the business transaction rolled back or was
//     never opened: one autocommitted INSERT on a pool of its own as mg_audit_writer (store.AuditWriter; INSERT only,
//     cannot read back), detached from the request's cancellation and bounded by Config.Timeout — the event survives
//     the rollback of the business transaction.
//   - Logger.RecordCommitted — events reported after their transaction committed (the identity module's Auditor is
//     called after commit), in a transaction of their own with the application role.
//
// # Tenant of an event
//
// An event belongs to the tenant whose audit lists it (Event.TenantID; nil = a platform event, listed only by
// GET /platform/audit). Events of an operation — success, failure, *.requested/*.succeeded/*.failed — belong to the
// tenant of the path (the business transaction's tenant). A denial belongs to the tenant of the ACTOR (nil for platform
// staff) and carries the tenant of the path in target_tenant_id when they differ: a cross-tenant denial is never shown
// to the target tenant, who does not learn who probed it (§6.1).
//
// # Paired events
//
// An operation that calls Headscale or runs as a job writes "<action>.requested" (Requested, committed before the
// external call or in the transaction that enqueues the job), then exactly one "<action>.succeeded" (in the
// transaction applying the outcome) or "<action>.failed" (in a transaction, or detached) with the same operation_id.
// The CHECK audit_events_operation_pair of migration 0004 ties the suffixes to operation_id and outcome. Within an API
// request the HTTP middleware closes the pair: Logger.Finish fails every operation the request started and left open
// when the request fails, and reports a gap when it succeeds; an operation continued by a job is handed off (HandOff)
// and carried in the job input (Operation is plain JSON). Logger.OpenOperations lists the requests a dead process
// left open (reconcile).
//
// # Cross-tenant denial chains (§8.8)
//
// Rule of P2-T08: when an actor (an identity) is denied on a tenant other than its own for the CrossTenantThreshold-th
// time within CrossTenantWindow (defaults 5 in 10 minutes, counted in the actor's own scope from audit_events), one
// platform-scope security event authz.cross_tenant_denials is written — severity high, critical when the denials
// reach 3 distinct target tenants — at most one per actor and window (advisory-lock serialised dedupe). A single
// stale link does not raise it; a probe of other tenants does. Platform staff count like tenant users (their denials
// on tenant routes are cross-tenant: they have no tenant of their own).
//
// # Details
//
// Details are flat, small and filtered on every path: keys naming a credential or raw data (token, secret, cookie,
// password, code, state, body…) and values shaped like one (hskey-…, a JWT, an Authorization value, a PEM block) are
// dropped and only counted; nested values are refused; the encoded object is bounded (8 KiB, also a CHECK).
package audit
