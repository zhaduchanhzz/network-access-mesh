// Package apikey rotates the API key of each tenant's Headscale instance (P3-T10; master plan §11.4 "API key
// rotation", §13.5 apikey.rotate, §7.6 "≤ 90 ngày, tự động", §16.3 "API key của instance còn < 14 ngày", T-05).
//
// One rotation is one instance, under the instance's API key lock (store.WithTenantLock, LockName — one live instance
// per tenant): two key operations of an instance never interleave, and the report-only reconcile (P3-T12) takes the
// same lock around its API key check, so it never lists the keys halfway through a rotation.
//
// Flow of Service.Rotate (an apikey.rotate job, or `meshguard-worker admin apikey-rotate`):
//
//  1. read the instance (registry): quarantined, removed, not running, tenant out of reach, a lifecycle job of the
//     tenant running (the skip rule of instance.reconcile), no key recorded ⇒ skipped;
//  2. list the instance's keys WITH THE CURRENT KEY through the registry (production locator: registry + SecretStore
//     + edge admin listener). Not due (the recorded expiry is further than RotateBefore), not forced and no other
//     valid key ⇒ skipped (not_due). Any other valid key ("stray": a leftover of a failed run, or a key the platform
//     never created) ⇒ a security event, and the run rotates whatever the expiry;
//  3. instance.apikey.rotate.requested (platform audit event) — committed before the first change;
//  4. CreateAPIKey with the current key and an explicit expiration (TTL ≤ 90 days, V-06);
//  5. verify the new key with a real call: through the edge admin listener with the NEW key, ListAPIKeys must list it
//     valid with the requested expiration;
//  6. store it as the next SecretStore version of mgsec://<tenant>/headscale-api-key (the scheme of adopt-instance and
//     of §11.3 step 13);
//  7. one platform transaction: tenant_instances.api_key_secret_ref/prefix/expires_at swapped ON CONDITION that the
//     row still holds the reference read in 1, and instance.apikey.rotate.succeeded;
//  8. drop the cached target of the tenant in this process's registries (Config.Invalidate); other processes pick the
//     new key up at their first 401 (headscale.CachingRegistry reloads the target once and replays);
//  9. through the registry again — so with the new key read back from the SecretStore — expire the old key and every
//     stray by prefix, then ListAPIKeys: the new key must be the only valid key;
//  10. erase the older SecretStore versions (their keys are expired).
//
// Failure handling: before step 7 a failure expires the new key with the current key (it never becomes an orphan) and
// writes instance.apikey.rotate.failed; a key the run cannot expire — at any step — is reported by a security event
// apikey.leftover naming its prefix (never the key). After step 7 the new key is the instance's key: a failure of step
// 9 raises apikey.leftover for each key still valid and fails the job, whose retry finds them as strays.
//
// Fallback (§11.4): when the recorded key has expired, or its secret is lost (SecretStore: not found/destroyed), the
// key is re-issued through the Host Agent (BootstrapApiKey: `headscale apikeys create` inside the container, every
// other valid key expired), then verified, stored and swapped the same way. A key that is still valid per the
// registry but refused by the instance is NOT re-issued automatically (§13.4: a replaced database is suspected) — a
// critical security event apikey.rejected is raised and the run fails; the operator verifies the instance and runs
// `meshguard-worker admin apikey-rotate --allow-bootstrap`. Without an agent the fallback fails with
// agent_not_configured (the failed job raises the job alert of §16.3).
//
// Secrets: the key is a headscale.Secret (redacted by every formatting path) from its creation to the SecretStore; it
// is never part of an error, a log line, an audit or security event detail, a job output or a step detail.
package apikey
