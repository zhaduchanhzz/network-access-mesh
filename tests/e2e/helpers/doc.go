//go:build mgtestfixture

// Package helpers holds the test-only helpers of the end-to-end tests (P3-T14a, §20 of the master plan). Enroll
// prepares the enrollment of one test client in a tenant — method B of §7.4 (short-lived pre-auth key) — through the
// Headscale adapter only (headscale.Registry.ForTenant → Instance; never the instance's SQLite, never the CLI):
//
//  1. ensure the Headscale user: ListUsers(name) — re-resolved right before the write that uses its numeric ID
//     (§13.4 "Không dùng headscale_user_id đã cache cho thao tác ghi") — and CreateUser when it does not exist (a
//     conflict from a concurrent creation is read back, not retried);
//  2. CreatePreAuthKey owned by that user: one-time (Reusable false), not ephemeral, no tag, with an EXPLICIT
//     expiration now + TTL, TTL ≤ 15 minutes (§7.4; the adapter refuses a key without expiration — V-06);
//  3. read the key back (ListPreAuthKeys — CreatePreAuthKey is never retried, §13.4 rule 3) and refuse — expiring it —
//     a key that is reusable, ephemeral, tagged, owned by someone else or with another expiration.
//
// The key reaches only the caller: Enrollment.Key returns a headscale.Secret (every fmt verb, slog and JSON print
// [REDACTED]); WriteKeyFile writes it, when a client container needs it, into a new 0600 file of a 0700 directory
// (TS_AUTHKEY=file:… / tailscale up --auth-key=file:…), and RemoveKeyFiles (also called by Cleanup) deletes every file
// written. Nothing in this package logs or returns the key in any other form; State (what a multi-step runner keeps
// between processes) holds only public identifiers.
//
// Verification helpers read through the adapter too: Nodes (the nodes registered with this key — ListNodes of the
// user, PreAuthKeyID), KeyState (the key as Headscale reports it: Used after the registration), Cleanup (expire the
// key, delete its nodes and the user the helper created).
//
// Build tag: every file starts with //go:build mgtestfixture (the repository's test-only tag — the same as the session
// fixture of P2-T15a): no production binary can import this package (internal/archtest checks the constraint and the
// dependencies of apps/*), and CI already vets, lints and tests ./tests/... with that tag.
//
// Use by P3-T14 (G3 E2E, tenant C created by the orchestrator): build the registry the way the worker does —
//
//	loc, _ := locator.New(tenants.New(st, tenants.Options{BaseDomain: …}), secretStore,
//		locator.Options{AdminURL: <edge admin listener>, EdgeTokenFile: <token file>})
//	reg := headscale.NewRegistry(loc, headscale.Options{Logger: logx.New(…)})
//	e := helpers.EnrollT(t, reg, tenantC, helpers.Options{User: "mg-e2e-enroll"}) // t.Cleanup: expire, delete nodes and user
//	path, _ := e.WriteKeyFile(dir)                  // mount at /run/secrets/authkey, TS_AUTHKEY=file:/run/secrets/authkey
//	… start the client, wait until e.Nodes(ctx, reg) has its node …
//	_ = e.RemoveKeyFiles()
//
// or, on the dev/CI stack without the platform database, over headscale.StaticLocator with a short-lived instance API
// key — what TestEnrollE2E (E2E-32 of tests/e2e/harness) does on tenant-a.
package helpers
