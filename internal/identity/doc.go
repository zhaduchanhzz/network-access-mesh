// Package identity is the Portal identity plane of the Management Plane (§8.1–§8.3, P2-T06): a multi-issuer OpenID
// Connect Relying Party behind a Backend-for-Frontend session.
//
// # Login (§8.3 steps 1–4)
//
//   - BeginLogin picks the IdP from the database by tenant (or the platform IdP on the admin origin) — never from the
//     client — and stores an auth_requests row: SHA-256 of the state, the nonce, the PKCE (S256) verifier encrypted
//     with a key derived from the state and the browser-binding cookie (neither is stored), the origin and a ≤ 10 min
//     expiry. The browser gets the __Host-mg_authreq binding cookie and a redirect to the IdP. Every authorization
//     request carries max_age, so a conforming IdP must return auth_time; a login made while a session already exists
//     on the origin is a re-authentication (step-up): prompt=login and max_age=0.
//   - Each IdP has its own redirect URI, https://<origin host>/api/v1/auth/callback/<idpId>. CompleteLogin consumes
//     the auth request (single use) and, BEFORE any call to the token endpoint, rejects an IdP mismatch (mix-up,
//     T-20), a different origin, a missing or wrong binding cookie, an expired request and — RFC 9207 — an iss
//     parameter that is not the stored issuer (or missing when the IdP advertises it). Only then is the code
//     exchanged (PKCE) and the ID token verified: signature, iss, aud/azp, exp, nonce, iat not older than the auth
//     request, auth_time present and plausible, then the IdP's required_claims, verified e-mail and allowed e-mail
//     domains (shared-issuer rule, §8.2). Only when everything passes is identities (idp_id, sub) upserted and a
//     session created; a session presented on the same origin is revoked at the same time (rotation).
//
// # Session (§8.3 steps 4–8)
//
// The session id is 32 random bytes; the browser holds it in __Host-mg_session (Secure; HttpOnly; SameSite=Lax;
// Path=/), the database only its SHA-256. A session carries identity only — never roles: authorization reloads
// memberships, roles and grants on every request. It is bound to the origin it was created on (app or admin) and the
// middleware rejects it on the other origin regardless of cookie scoping. Idle and absolute timeouts follow §8.3 step
// 6 (tenant 30 min / 12 h, platform staff 15 min / 8 h); revocation is effective on the next request. The CSRF token
// is HMAC-SHA256(key = raw session id, msg = "csrf-v1"): recomputed on each request, never stored.
//
// # Step-up (§8.3 steps 7–8)
//
// RequireRecentAuth accepts a session only when its auth_time — the auth_time claim of the fresh ID token that
// created it — is within StepUpWindow (15 min). An ID token without auth_time is rejected at the callback, so a
// step-up cannot be recorded without it.
//
// # Wiring (P2-T14 owns the chain)
//
//	svc, err := identity.New(st, identity.Config{AppHost: "app." + domain, AdminHost: "admin." + domain,
//	        HTTPClient: hardenedIdPClient, ClientSecrets: secretStore, Auditor: auditAdapter, ClientIP: realIP})
//	handler := requestID(recoverer(svc.Middleware(authz(apiRouter))))
//
// Middleware must run after the request-id middleware (it copies X-Request-Id into problems) and before
// authorization (which reads SessionFromContext). The strict-server handlers of the auth operations are in
// internal/httpapi/identityapi; the session.gc job is SessionGC (worker).
package identity
