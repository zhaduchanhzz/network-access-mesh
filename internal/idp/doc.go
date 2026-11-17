// Package idp is the IdP module of the Management Plane (§8.2, P2-T05a): the IdPDriver interface, a registry of
// drivers by identity_providers.driver, and the HTTP clients every call to an IdP goes through.
//
// # Drivers
//
// IdPDriver (EnsureIssuer, EnsureClient, InviteUser, DisableUser, RemoveIssuer, CheckDiscovery) is implemented by
// internal/idp/keycloak (the Keycloak the platform hosts: realm per tenant from the realm template, Admin REST API) and
// internal/idp/external (an IdP the tenant brings: only the issuer and client are recorded, discovery is checked).
// Business code holds an IdPDriver from the Registry and never depends on Keycloak. Methods are context-first,
// return typed results and *Error values with a stable Code, and are idempotent.
//
// # Egress: two clients, never mixed (T-21)
//
// Hardened is the client for every URL a tenant can influence (driver=external: issuer, jwks_uri, token and userinfo
// endpoints): https and port 443 only, no redirect followed, host names only, the platform's own domain refused, the
// name resolved once per connection with every address checked against EgressPolicy (loopback, RFC 1918, link-local
// incl. 169.254.169.254, CGNAT/tailnet 100.64.0.0/10, ULA, multicast, unspecified, reserved and documentation ranges,
// the IPv4-mapped forms of all of them, IPv4-compatible/NAT64/6to4 forms, and the configured Docker pools of the
// platform), the connection made to exactly the checked IP with TLS verified for the original name (no DNS
// rebinding), proxies ignored, body and time bounded, errors free of upstream content.
//
// PlatformRoute is the explicit, narrow path to the IdP the platform hosts (driver=keycloak): in staging
// auth.<domain> resolves to a private LAN address and, inside Docker, to the edge alias on mg-edge — both refused by
// Hardened by design. The route serves one host (auth.<domain>), only /realms/ and /admin/realms paths, dials only
// the configured address (the edge on mg-edge) and verifies TLS for that host. The keycloak driver only receives a
// PlatformRoute, the external driver only a Hardened client, and Hardened refuses every name under the platform's
// domain — a tenant-supplied issuer can never use the platform path.
//
// NewIssuerClient combines both for a Relying Party that keeps a single client for every IdP (internal/identity,
// identity.Config.HTTPClient — wired in P2-T16): the platform IdP host goes through the route restricted to the
// public OIDC endpoints (/realms/), everything else through Hardened.
//
// # Credentials
//
// Drivers read every credential from the SecretStore by reference and write the secrets they generate there first
// (internal/secrets); nothing comes from the environment, files or arguments. idp imports secrets and the base modules
// only (§13.6, archtest).
package idp
