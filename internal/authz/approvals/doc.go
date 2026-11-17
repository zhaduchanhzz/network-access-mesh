// Package approvals is dual control (2P) — the approval_requests of §6.3 and the 2P rule of §8.5/§8.6 (P3-T04a): an
// operation that needs a second person becomes a request (202 + Location of /platform/approvals/{id} or
// /tenants/{tenantId}/approvals/{id}); another person with :decide and the permission of the operation itself approves
// it, and only then does the operation run — from the stored payload, exactly once.
//
// # Payload binding
//
// The parameters of the operation are stored as a canonical JSON object (Canonical: keys sorted, no whitespace, no
// HTML escaping, integers only — never a secret, only secret references) with payload_sha256 = hex SHA-256 of those
// bytes. The approver is shown the payload and its hash (GET …/approvals/{id}) and approves THAT hash (body
// {payload_sha256}): a different hash ⇒ 412 precondition_failed. Before the decision and again before execution the
// stored payload is re-canonicalized and re-hashed: a payload changed outside the application (the columns are
// immutable for the application roles — 0009) no longer matches ⇒ 409 + security event approval.payload_integrity,
// nothing runs. The action receives exactly the bytes that were hashed.
//
// # State machine (approval_requests.status)
//
//	pending ──approve (2nd person, step-up)──▶ approved ──execute (same tx as the job)──▶ executed (terminal)
//	   │                                          │
//	   ├──reject (2nd person, step-up)──▶ rejected (terminal)
//	   └──expires_at reached──▶ expired ◀─────────┘ (an approved request not executed in time)
//
// Approve commits the decision, then Execute runs the action in a job-capable transaction that marks the request
// executed with its job_id: the job exists if and only if the request is executed, and executed is terminal (no
// replay). When execution fails, the request stays approved; the same approver calling approve again retries the
// execution (no second approval, same reviewed hash). Expiry is enforced at the service clock and the row is marked
// expired when touched (the periodic sweep belongs to retention.sweep / P3-T17).
//
// # Rules (§8.3 step 7, §8.4, §8.6)
//
//   - Both persons step up: the requester's and the decider's session auth_time is within StepUpWindow (15 min),
//     else ErrReauthRequired (401 reauth_required).
//   - The decider is never the requester (403, security event approval.self_decision; CHECK of 0009 as backstop) and
//     holds the permission of the action (authz.Authorizer.RequireApprover), besides :decide (layer 1). A conditional
//     :decide grant — "chỉ cho restore" of §8.5 — decides only actions that list the condition (Spec.DecideConditions).
//   - Scope: platform requests (tenant_id NULL) live on /platform/approvals only; tenant requests on
//     /tenants/{tenantId}/approvals of their tenant only (tenant pool, RLS) — another tenant's request reads 404.
//   - Audit: the decision and the execution are written in their transactions with the decider as actor and both
//     persons in the details (requested_by_identity_id, decided_by_identity_id) plus payload_sha256 and the job.
//
// # Executors
//
// Registry is the closed set of actions the process can execute (typed by Typed[P]: strict decoding + Validate).
// Deprovision (P3-T09), restore (P3-T11), release (P3-T18), the 2P operations of P4-T03a/P4-T13 register their action
// and call Service.Request from their handler when the authz decision says NeedsApproval.
package approvals
