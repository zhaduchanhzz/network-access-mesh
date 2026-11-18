// Package backup is the worker side of backup/restore v1 of a tenant's Headscale instance (P3-T11; master plan
// §17.1–§17.2, §13.5 `instance.backup` / `instance.restore`, §6.3 `backups`, T-15, IT-16, AC-19).
//
// instance.backup (schedule — Scheduler, every MG_BACKUP_INTERVAL per instance at an offset of its own — or
// POST /platform/instances/{id}/backup): a random data key per backup; the tenant's backup key (SecretStore secret
// `backup-key`, under the tenant's DEK) wraps it (backupfmt.WrapDataKey — tenant, instance and sequence bound); the
// agent receives only the X25519 public key of the data key, writes the age archive (data key + platform recovery
// recipient) and signs the manifest; the worker verifies signature and identity of the manifest before the `backups`
// row becomes `succeeded`. A hostile data directory or a corrupt database fails the backup closed with a tenant
// security event (IT-15). Local retention: archives older than MG_BACKUP_RETENTION (the newest KeepLatest always
// kept) are removed by the agent with the next backup and their rows become `purged`.
//
// instance.restore (only after a 2P approval — the action platform.instance.restore registered by apps/internal/runner;
// lifecycle job, lock tenant:<id>:lifecycle): the worker verifies the signed manifest and its identity BEFORE it
// unwraps the data key (Worker AND Agent — §17.1), then drives the provisioning order of §17.2: Restore (policy set
// offline before the first start, edge detached, data/ swapped, started without edge) → PostRestoreReconcile with the
// plan built from PostgreSQL (machine keys of revoked and deleted devices, routes/tags of the live devices, offboarded
// members — never numeric ids), a new API key stored in the SecretStore under the API-key lock (apikey.LockName) —
// every key of the archive dead → edge attached again → checks over the API (GetPolicy = applied policy, exactly one
// valid API key, no valid pre-auth key) → membership ids re-resolved by name in one transaction → inventory.sync →
// report, audit, notification. The "PostgreSQL older than the backup" branch (an operator assertion of the request,
// shown verbatim to the approver) keeps the archive's policy — imported as a validated version to review — sends no
// revocation list and resets no route/tag, and flags the tenant for Owner review (security event + notification).
package backup
