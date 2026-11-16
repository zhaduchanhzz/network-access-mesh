# Research Evidence — F

> Một phần của [nhật ký bằng chứng nghiên cứu](../research-evidence.md) (P0-T08). Chép nguyên từ kết quả của research agent ngày 2026-11-16; nhận định và trích dẫn giữ nguyên tiếng Anh.

## F - Headscale v0.29.7: management API (gRPC + REST gateway) and CLI - complete inventory and semantics

**Tóm tắt của agent:** Headscale v0.29.7 exposes one admin surface: the gRPC service headscale.v1.HeadscaleService (29 unary RPCs) mirrored by a grpc-gateway REST API under /api/v1 (29 operations, Swagger 2.0 at /swagger). It covers users, pre-auth keys, nodes (list, get, expire, delete, rename, tags, approve routes, backfill), API keys, policy (get, set, check), auth (register, approve, reject) and health. That is enough for a central backend to drive tenant onboarding, device lifecycle and policy without patching Headscale, so the planned architecture is feasible. Decisions the API forces: Transport. REST shares the public control-plane listener, so the edge must not forward /api or /swagger; reach tenants over the internal network. Remote gRPC is a separate port that only starts with native TLS or grpc_allow_insecure. The unix socket serves the same API with no authentication and is the bootstrap path for the first key. Recommendation: internal REST with one key per tenant (socket gRPC is an option on a single host). Do not import the Headscale Go module (Go 1.27.3 floor, heavy requirement graph); generate stubs from the eight proto files or write a thin REST client. Authorization. API keys are all-or-nothing admin credentials: no scopes, roles or owners, bcrypt-checked on every request, shown once, no maintained last-used field. All RBAC, tenant isolation and audit must live in our backend. Always send explicit expirations: the server has no default, and an omitted expiration appears to yield an already-expired key (needs a test). State sync. There are no webhooks, streams, pagination, ETags or idempotency keys. The backend must poll and diff, serialise writes per tenant and keep policy history itself. Use ListNodes as the canonical read; GetNode omits subnet routes and the tagged-devices owner. Data gaps. Node objects carry no OS, client version, endpoints, DERP or traffic data. Pending registrations cannot be listed. Nodes cannot be moved between users (removed in 0.28). Tagged-to-personal conversion is client-side only. API-created users cannot be linked to OIDC identities. Policy. SetPolicy only works with policy.mode=database (the default is file). CheckPolicy gives a server-side dry run including policy tests. GetPolicy errors until a first policy is stored. Errors. Many handlers return raw errors that surface as HTTP 500 even for not-found or conflict cases; the client layer must classify by message and pre-validate inputs. Onboarding. Pre-auth keys (user-owned or tag-only, reusable, ephemeral, hashed, shown once) are the cleanest automation path. Interactive approval needs the user to hand the auth ID to the portal, which calls AuthRegister; AuthApprove serves SSH check sessions. Stability. This is a 0.x API with no stability promise. Breaking changes landed inside /api/v1 in 0.28 and 0.29, minor upgrades cannot be skipped, and upstream scopes Headscale to a single tailnet and does not officially support Docker. Pin versions per tenant, isolate Headscale behind an adapter and run contract tests before each upgrade.

## Nhận định

### F-01 · `VERIFIED` — 1 Inventory: overview

- **Nhận định:** At v0.29.7 the management API is a single gRPC service, headscale.v1.HeadscaleService, with 29 unary RPCs. Every RPC carries a google.api.http binding, yielding 29 REST operations on 23 paths, all under /api/v1.
- **Bằng chứng:** headscale.proto: `service HeadscaleService {` with 29 `rpc` definitions, each with `option (google.api.http)`, none using `stream`. Swagger `paths` has 23 keys, from `/api/v1/apikey` to `/api/v1/user/{oldId}/rename/{newName}`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/openapiv2/headscale/v1/headscale.swagger.json

### F-02 · `VERIFIED` — 1 Inventory: users

- **Nhận định:** Users: CreateUser POST /api/v1/user (body name, displayName, email, pictureUrl) returns user; RenameUser POST /api/v1/user/{old_id}/rename/{new_name} returns user; DeleteUser DELETE /api/v1/user/{id} returns empty; ListUsers GET /api/v1/user with optional id, name or email query returns users[].
- **Bằng chứng:** headscale.proto: `post : "/api/v1/user"`, `post : "/api/v1/user/{old_id}/rename/{new_name}"`, `delete : "/api/v1/user/{id}"`, `get : "/api/v1/user"`. user.proto: `message ListUsersRequest { uint64 id = 1; string name = 2; string email = 3; }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/user.proto

### F-03 · `VERIFIED` — 1 Inventory: pre-auth keys

- **Nhận định:** Pre-auth keys: CreatePreAuthKey POST /api/v1/preauthkey (body user, reusable, ephemeral, expiration, aclTags) returns preAuthKey; ExpirePreAuthKey POST /api/v1/preauthkey/expire (body id); DeletePreAuthKey DELETE /api/v1/preauthkey?id=; ListPreAuthKeys GET /api/v1/preauthkey takes no parameters and returns preAuthKeys[] for the whole instance.
- **Bằng chứng:** headscale.proto: `post : "/api/v1/preauthkey"`, `post : "/api/v1/preauthkey/expire"`, `delete : "/api/v1/preauthkey"`, `get : "/api/v1/preauthkey"`. preauthkey.proto: `message ListPreAuthKeysRequest {}`. Swagger DeletePreAuthKey parameter: `"name": "id", "in": "query"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/preauthkey.proto

### F-04 · `VERIFIED` — 1 Inventory: nodes (read and register)

- **Nhận định:** Nodes, read and register: GetNode GET /api/v1/node/{node_id} returns node; ListNodes GET /api/v1/node?user=<username> returns nodes[]; RegisterNode POST /api/v1/node/register?user=&key= returns node (CLI wrapper deprecated in favour of auth register); DebugCreateNode POST /api/v1/debug/node is a test-only helper.
- **Bằng chứng:** headscale.proto: `get : "/api/v1/node/{node_id}"`, `get : "/api/v1/node"`, `post : "/api/v1/node/register"`, `post : "/api/v1/debug/node"`. nodes.go: `Deprecated: "use 'headscale auth register --auth-id <id> --user <user>' instead"`. grpcv1.go: `// The following service calls are for testing and debugging`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/nodes.go

### F-05 · `VERIFIED` — 1 Inventory: nodes (mutations)

- **Nhận định:** Node mutations: DeleteNode DELETE /api/v1/node/{node_id}; ExpireNode POST .../{node_id}/expire?expiry=&disableExpiry=; RenameNode POST .../{node_id}/rename/{new_name}; SetTags POST .../{node_id}/tags (body tags[]); SetApprovedRoutes POST .../{node_id}/approve_routes (body routes[]); BackfillNodeIPs POST /api/v1/node/backfillips?confirmed=true.
- **Bằng chứng:** headscale.proto: `delete : "/api/v1/node/{node_id}"`, `post : "/api/v1/node/{node_id}/expire"`, `post : "/api/v1/node/{node_id}/rename/{new_name}"`, `post : "/api/v1/node/{node_id}/tags"`, `post : "/api/v1/node/{node_id}/approve_routes"`, `post : "/api/v1/node/backfillips"`. Swagger query parameters: `expiry`, `disableExpiry`, `confirmed`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/openapiv2/headscale/v1/headscale.swagger.json

### F-06 · `VERIFIED` — 1 Inventory: API keys

- **Nhận định:** API keys: CreateApiKey POST /api/v1/apikey (body expiration) returns apiKey, the full secret string; ExpireApiKey POST /api/v1/apikey/expire (body prefix or id); ListApiKeys GET /api/v1/apikey returns apiKeys[] with id, prefix, expiration, createdAt, lastSeen; DeleteApiKey DELETE /api/v1/apikey/{prefix}.
- **Bằng chứng:** headscale.proto: `post : "/api/v1/apikey"`, `post : "/api/v1/apikey/expire"`, `get : "/api/v1/apikey"`, `delete : "/api/v1/apikey/{prefix}"`. apikey.proto: `message CreateApiKeyResponse { string api_key = 1; }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/apikey.proto

### F-07 · `VERIFIED` — 1 Inventory: policy

- **Nhận định:** Policy: GetPolicy GET /api/v1/policy returns {policy, updatedAt}; SetPolicy PUT /api/v1/policy (body policy, the HuJSON document as a string) returns {policy, updatedAt}; CheckPolicy POST /api/v1/policy/check (body policy) returns an empty object on success.
- **Bằng chứng:** headscale.proto: `get : "/api/v1/policy"`, `put : "/api/v1/policy"`, `post : "/api/v1/policy/check"`. policy.proto: `message SetPolicyRequest { string policy = 1; }`, `message CheckPolicyResponse {}`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/policy.proto

### F-08 · `VERIFIED` — 1 Inventory: auth

- **Nhận định:** Auth: AuthRegister POST /api/v1/auth/register (JSON body user, authId) returns node; AuthApprove POST /api/v1/auth/approve (body authId) returns empty; AuthReject POST /api/v1/auth/reject (body authId) returns empty.
- **Bằng chứng:** headscale.proto: `post : "/api/v1/auth/register"`, `post : "/api/v1/auth/approve"`, `post : "/api/v1/auth/reject"`, each with `body : "*"`. auth.proto: `message AuthRegisterRequest { string user = 1; string auth_id = 2; }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/auth.proto

### F-09 · `VERIFIED` — 1 Inventory: health and other

- **Nhận định:** Health GET /api/v1/health returns {databaseConnectivity} and requires an API key. The main router also serves unauthenticated GET /health (application/health+json, status pass or fail, HTTP 500 on failure) and GET /version (JSON version info).
- **Bằng chứng:** headscale.proto: `get : "/api/v1/health"`, `message HealthResponse { bool database_connectivity = 1; }`. app.go: `r.Get("/health", h.HealthHandler)`, `r.Get("/version", h.VersionHandler)`. handlers.go: `Status: "pass"` and `res.Status = "fail"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/handlers.go

### F-10 · `VERIFIED` — 2 auth.proto: purpose and semantics

- **Nhận định:** auth.proto (added in 0.29.0 with SSH check-mode) is keyed by an auth_id. AuthRegister delegates to RegisterNode; AuthApprove and AuthReject finish a pending in-memory auth session with an empty or an error verdict and take no user. Unknown IDs return NotFound.
- **Bằng chứng:** grpcv1.go: `resp, err := api.RegisterNode(ctx, &v1.RegisterNodeRequest{Key: request.GetAuthId(), User: request.GetUser()})`; `authReq.FinishAuth(types.AuthVerdict{})`; `"no pending auth session for auth_id %s"`. CHANGELOG 0.29.0: `Add auth related routes`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md

### F-11 · `REQUIRES_VALIDATION` · *critical* — 2 auth.proto: approve on a registration

- **Nhận định:** Calling AuthApprove on a node-registration auth ID does not appear to register the node: the follow-up handler treats an accepted verdict without a node as an expired registration and issues a new AuthURL. Device approval must use AuthRegister with a user.
- **Bằng chứng:** auth.go waitForFollowup: `if !verdict.Node.Valid() { // registration is expired in the cache, instruct the client to try a new registration`. Test: start `tailscale up --login-server`, POST /api/v1/auth/approve with the auth ID, observe the client and the node list.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/auth.go

### F-12 · `UNSUPPORTED` — 2 device.proto

- **Nhận định:** device.proto only defines messages for a possible Tailscale-compatible device API (GetDevice, DeleteDevice, device routes, client connectivity). The RPCs are commented out in headscale.proto and no /api/v1/device route exists.
- **Bằng chứng:** device.proto: `// This is a potential reimplementation of Tailscale's API`. headscale.proto: `// Implement Tailscale API` followed by `// rpc GetDevice(GetDeviceRequest) returns(GetDeviceResponse) {`. Swagger paths contain no device entry.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/device.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto

### F-13 · `VERIFIED` — 3 Authentication: header and failures

- **Nhận định:** Both interfaces use `Authorization: Bearer <API_KEY>` (HTTP header on REST, `authorization` metadata on gRPC). REST failures return HTTP 401 with plain-text `Unauthorized`; remote gRPC returns Unauthenticated for missing or expired keys but codes.Internal ('validating token') for unknown keys.
- **Bằng chứng:** app.go: `AuthPrefix = "Bearer "`; `authHeader, ok := meta["authorization"]`; `writer.Write([]byte("Unauthorized"))`; `if err != nil { return ctx, status.Error(codes.Internal, "validating token") }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go

### F-14 · `VERIFIED` — 3 API key format and storage

- **Nhận định:** API keys have the form `hskey-api-<12-char prefix>-<64-char secret>` using the base64 URL-safe alphabet. Only the prefix (unique index) and a bcrypt hash of the secret are stored; legacy `prefix.secret` keys with a 7-character prefix still validate.
- **Bằng chứng:** db/api_key.go: `apiKeyPrefix = "hskey-api-"`, `apiKeyPrefixLength = 12`, `apiKeyHashLength = 64`; `hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)`; `// Legacy format: prefix.secret`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/api_key.go

### F-15 · `UNSUPPORTED` · *critical* — 3 API key scoping

- **Nhận định:** API keys have no scopes, roles, owner or resource restrictions. The stored model is ID, Prefix, Hash, CreatedAt, Expiration, LastSeen and both auth layers only check validity, so every valid key is a full administrator of that Headscale instance.
- **Bằng chứng:** types/api_key.go: `type APIKey struct { ID uint64 ...; Prefix string ...; Hash []byte; CreatedAt *time.Time; Expiration *time.Time; LastSeen *time.Time }`. app.go interceptor: `valid, err := h.state.ValidateAPIKey(...)` then `return handler(ctx, req)`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/api_key.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go

### F-16 · `VERIFIED` — 3 Expiration defaults and maximum

- **Nhận định:** The documented 90-day API-key default and the 1-hour pre-auth-key default are CLI flag defaults. The server handlers apply no default and no maximum expiration; they store whatever timestamp the request carries.
- **Bằng chứng:** cli/api_key.go: `DefaultAPIKeyExpiry = "90d"`. cli/preauthkeys.go: `DefaultPreAuthKeyExpiry = "1h"`. grpcv1.go: `var expiration time.Time`, `if request.GetExpiration() != nil { expiration = request.GetExpiration().AsTime() }`, `api.h.state.CreateAPIKey(&expiration)`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/api_key.go

### F-17 · `REQUIRES_VALIDATION` · *critical* — 3 and 7 Omitted expiration

- **Nhận định:** A key created through the API without `expiration` is stored with a zero timestamp, and both validators treat any non-nil expiration earlier than now as expired. Such API keys and pre-auth keys are probably unusable immediately; always send an explicit expiration.
- **Bằng chứng:** db/api_key.go: `if key.Expiration != nil && key.Expiration.Before(time.Now()) { return false, nil }`. types/preauth_key.go: `return PAKError("authkey expired")`. Test: POST /api/v1/apikey with `{}` and use the key; POST /api/v1/preauthkey without expiration and register a node.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/api_key.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/preauth_key.go

### F-18 · `VERIFIED` — 3 API key lifecycle

- **Nhận định:** ListApiKeys returns only a masked prefix (`hskey-api-<prefix>-***`). ExpireApiKey sets Expiration to now and keeps the row; DeleteApiKey hard-deletes it. Keys are addressed by exactly one of id or prefix. The validation path never writes last_seen.
- **Bằng chứng:** types/api_key.go: `protoKey.Prefix = "hskey-api-" + key.Prefix + "-***"`. db/api_key.go: `Update("Expiration", time.Now())`, `hsdb.DB.Unscoped().Delete(key)`; ValidateAPIKey contains no update statement. grpcv1.go: `"provide either id or prefix, not both"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/api_key.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/api_key.go

### F-19 · `VERIFIED` · *critical* — 3 First API key bootstrap

- **Nhận định:** The first API key is created over the unix socket: Headscale always serves the full gRPC service on `unix_socket` without TLS or authentication, and the CLI uses that socket whenever cli.address is unset (`headscale apikeys create`, machine-readable with `-o json`).
- **Bằng chứng:** app.go: `// Start the local gRPC server without TLS and without authentication`. utils.go: `HEADSCALE_CLI_ADDRESS environment is not set, connecting to unix socket.` config.go: `viper.SetDefault("unix_socket", "/var/run/headscale/headscale.sock")`, `viper.SetDefault("unix_socket_permission", "0o770")`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/utils.go

### F-20 · `VERIFIED` · *critical* — 3 Per-request authentication cost

- **Nhận định:** Every authenticated REST or remote-gRPC request performs a database lookup by key prefix plus bcrypt.CompareHashAndPassword; the State and DB layers contain no validation cache, so frequent polling pays a bcrypt cost on every call.
- **Bằng chứng:** db/api_key.go validateAPIKey: `err := db.First(&key, "prefix = ?", prefix).Error` then `err = bcrypt.CompareHashAndPassword(key.Hash, []byte(secret))`. state.go: `func (s *State) ValidateAPIKey(keyStr string) (bool, error) { return s.db.ValidateAPIKey(keyStr) }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/api_key.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go

### F-21 · `VERIFIED` — 4 Remote CLI: environment and TLS

- **Nhận định:** Remote CLI mode is enabled by HEADSCALE_CLI_ADDRESS (cli.address) and requires HEADSCALE_CLI_API_KEY (cli.api_key). It always dials TLS with system roots; HEADSCALE_CLI_INSECURE=1 only disables certificate verification. cli.timeout defaults to 5s; HEADSCALE_CONFIG selects a config file.
- **Bằng chứng:** api.md: `export HEADSCALE_CLI_ADDRESS=...`, `export HEADSCALE_CLI_API_KEY=...`, `HEADSCALE_CLI_INSECURE=1`. utils.go: `credentials.NewClientTLSFromCert(nil, "")`, `InsecureSkipVerify: true`, `func (tokenAuth) RequireTransportSecurity() bool { return true }`. config.go: `viper.SetDefault("cli.timeout", "5s")`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/api.md | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/utils.go

### F-22 · `VERIFIED` · *critical* — 4 Remote gRPC listener

- **Nhận định:** The remote gRPC listener (grpc_listen_addr, default :50443) starts only when Headscale itself terminates TLS or grpc_allow_insecure is true. It cannot share the HTTP port, has had no reflection since 0.29.0, and same-port reverse proxying is documented as unsupported.
- **Bằng chứng:** app.go: `if tlsConfig != nil || h.cfg.GRPCAllowInsecure {` and `We are sadly not able to run gRPC and HTTPS (2.0) on the same port`. CHANGELOG 0.29.0: `Remove gRPC reflection from the remote (TCP) server`. api.md: `While this is _not a supported_ feature`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/api.md

### F-23 · `VERIFIED` · *critical* — 5 REST gateway location

- **Nhận định:** The REST gateway is served on the same listener as the Tailscale control plane (listen_addr) at /api/v1/*: the chi router applies API-key middleware and hands requests to a grpc-gateway mux that forwards them to the unauthenticated unix-socket gRPC server.
- **Bằng chứng:** app.go: `r.Route("/api", func(r chi.Router) { r.Use(h.httpAuthenticationMiddleware); r.HandleFunc("/v1/*", grpcMux.ServeHTTP) })`; `// Make the grpc-gateway connect to grpc over socket`; `router := h.createRouter(grpcGatewayMux)` served on `h.cfg.Addr`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go

### F-24 · `VERIFIED` — 5 Swagger endpoint

- **Nhận định:** Swagger UI is served unauthenticated at GET /swagger and the embedded Swagger 2.0 document at GET /swagger/v1/openapiv2.json on the main listener. The UI loads its JS and CSS from unpkg.com; the document declares no API version and no security definitions.
- **Bằng chứng:** app.go: `r.Get("/swagger", headscale.SwaggerUI)`, `r.Get("/swagger/v1/openapiv2.json", headscale.SwaggerAPIv1)`. swagger.go: `https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js`. swagger.json: `"swagger": "2.0"`, `"version": "version not set"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/swagger.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go

### F-25 · `UNSUPPORTED` — 6 Pagination, filtering, sorting

- **Nhận định:** No list RPC supports pagination, sorting or field selection; lists return the complete set ordered by numeric ID. Filtering is limited to ListNodes by username and ListUsers by exactly one of name, email or id; key lists cannot be filtered.
- **Bằng chứng:** Protos: `message ListPreAuthKeysRequest {}`, `message ListApiKeysRequest {}`, `message ListNodesRequest { string user = 1; }`. grpcv1.go: `sort.Slice(response, func(i, j int) bool { return response[i].Id < response[j].Id })`; ListUsers `switch { case request.GetName() != "":`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/node.proto

### F-26 · `UNSUPPORTED` — 6 Rate limiting and timeouts

- **Nhận định:** Headscale applies no rate limiting to the API: the router middleware chain is metrics, request ID, optional real-IP, request logging, panic recovery and security headers, plus API-key authentication on /api. HTTP read and write timeouts are 30 seconds.
- **Bằng chứng:** app.go createRouter: `r.Use(middleware.RequestID)`, `r.Use(middleware.RequestLogger(&zerologRequestLogger{}))`, `r.Use(middleware.Recoverer)`, `r.Use(securityHeaders)`. types/const.go: `HTTPTimeout = 30 * time.Second`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/const.go

### F-27 · `VERIFIED` · *critical* — 6 Error model

- **Nhận định:** REST errors come from grpc-gateway's default handler: JSON {code, message, details} with the HTTP status derived from the gRPC code. Many handlers return plain Go errors (user not found, user still has nodes, rename collisions), which surface as gRPC Unknown and HTTP 500.
- **Bằng chứng:** grpc-gateway v2.29.0 errors.go: `case codes.Unknown: return http.StatusInternalServerError`. grpcv1.go DeleteUser: `if err != nil { return nil, err }` versus GetNode: `status.Errorf(codes.NotFound, "node not found")`. Swagger `rpcStatus` has code, message, details.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v2.29.0/runtime/errors.go

### F-28 · `VERIFIED` — 6 JSON conventions

- **Nhận định:** The gateway uses grpc-gateway's default JSON marshaler (NewServeMux is called without options): responses include unpopulated fields with lowerCamelCase names, uint64 IDs are encoded as JSON strings, and unknown request fields are silently discarded.
- **Bằng chứng:** app.go: `grpcGatewayMux := grpcRuntime.NewServeMux()`. grpc-gateway marshaler_registry.go: `EmitUnpopulated: true` and `DiscardUnknown: true`. Swagger: `"id": { "type": "string", "format": "uint64" }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go | https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v2.29.0/runtime/marshaler_registry.go

### F-29 · `UNSUPPORTED` — 6 Idempotency and concurrency control

- **Nhận định:** There are no idempotency keys, ETags or resource versions. CreatePreAuthKey and CreateApiKey mint a new key on every call, CreateUser maps every failure (including duplicates) to codes.Internal and HTTP 500, and SetPolicy is last-write-wins, inserting a new policy row each time.
- **Bằng chứng:** grpcv1.go: `return nil, status.Errorf(codes.Internal, "creating user: %s", err)`. db/policy.go: `hsdb.DB.Clauses(clause.Returning{}).Create(&p)` and `Order("id DESC").Limit(1)`. No etag or version field exists in any proto message.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/policy.go

### F-30 · `VERIFIED` — 7 Pre-auth key options

- **Nhận định:** CreatePreAuthKey accepts user (numeric ID), reusable, ephemeral, expiration and acl_tags. Tags are only format-checked (`tag:` prefix, lowercase, no spaces), not checked against the policy. `used` is set only for non-reusable keys, so reusable keys expose no usage indicator.
- **Bằng chứng:** preauthkey.proto: `message CreatePreAuthKeyRequest { uint64 user = 1; bool reusable = 2; bool ephemeral = 3; ... repeated string acl_tags = 5; }`. grpcv1.go: `"tag must start with the string 'tag:'"`. state.go: `if params.PreAuthKey != nil && !params.PreAuthKey.Reusable {`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/preauth_keys.go

### F-31 · `VERIFIED` · *critical* — 7 Tag-only pre-auth keys

- **Nhận định:** A pre-auth key can exist without a user when it carries at least one tag; a key with neither is rejected. Tagged keys register tagged nodes (owner shown as `tagged-devices`) with key expiry disabled; registrations combining a pre-auth key with --advertise-tags are rejected.
- **Bằng chứng:** db/preauth_keys.go: `// The uid parameter can be nil for system-created tagged keys.` and `if uid == nil && len(aclTags) == 0 { return nil, ErrPreAuthKeyNotTaggedOrOwned }`. state.go: `// Tagged nodes have key expiry disabled.`, `// Reject advertise-tags for PreAuthKey registrations early`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/preauth_keys.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go

### F-32 · `VERIFIED` · *critical* — 7 Pre-auth key format, storage, retrieval

- **Nhận định:** Pre-auth keys are `hskey-auth-<12-char prefix>-<64-char secret>`, stored as prefix plus bcrypt hash. The full key appears only in the CreatePreAuthKey response; listings show `hskey-auth-<prefix>-***` and there is no get-by-ID RPC, so a lost key cannot be recovered.
- **Bằng chứng:** db/preauth_keys.go: `authKeyPrefix = "hskey-auth-"`, `authKeyPrefixLength = 12`, `authKeyLength = 64`. types/preauth_key.go: `// PreAuthKeyNew is returned once when the key is created.` and `protoKey.Key = "hskey-auth-" + key.Prefix + "-***"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/preauth_keys.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/preauth_key.go

### F-33 · `VERIFIED` — 7 Expire versus delete

- **Nhận định:** ExpirePreAuthKey sets expiration to now and keeps the row; DeletePreAuthKey hard-deletes it and nulls auth_key_id on nodes that used it. Neither evicts nodes: an existing unexpired node re-registering with the same node key skips key validation.
- **Bằng chứng:** db/preauth_keys.go: `Update("expiration", now)`; `Where("auth_key_id = ?", id).Update("auth_key_id", nil)`; `tx.Unscoped().Delete(&types.PreAuthKey{}, id)`. state.go: `skip validation. Pre-auth keys are only needed for initial authentication.`
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/preauth_keys.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go

### F-34 · `VERIFIED` — 8 Registration methods

- **Nhận định:** Docs define two registration methods, web authentication and pre-authenticated key, both usable for personal and tagged nodes. Web-auth approval is done by CLI, by the API, or delegated to OIDC, which completes via /oidc/callback and a confirmation page without an admin API call.
- **Bằng chứng:** registration.md: `There are two main ways to register new nodes, web authentication and registration with a pre authenticated key`; `A node can be approved with: Headscale CLI ... Headscale API ... OpenID Connect`. app.go: `r.Get("/oidc/callback", ...)`, `r.Post("/register/confirm/{auth_id}", ...)`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/registration.md | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go

### F-35 · `VERIFIED` · *critical* — 8 Web-auth approval call

- **Nhận định:** Interactive web auth sends the client to `<server_url>/register/<auth_id>`, which shows `headscale auth register --auth-id ... --user USERNAME`. The API equivalent is AuthRegister with a username that must match exactly one user and an auth ID of `hskey-authreq-` plus 24 characters.
- **Bằng chứng:** handlers.go: `fmt.Sprintf("headscale auth register --auth-id %s --user USERNAME", authId.String())`. types/common.go: `authIDPrefix = "hskey-authreq-"`, `authIDRandomLength = 24`. grpcv1.go: `api.h.state.GetUserByName(request.GetUser())`. db/users.go: `ErrUserNotUnique = errors.New("expected exactly one user")`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/handlers.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/common.go

### F-36 · `UNSUPPORTED` · *critical* — 8 Listing pending registrations

- **Nhận định:** The management API cannot list or inspect pending registrations or auth requests: they live in an in-memory cache keyed by auth ID, and even the debug endpoint reports only cache counts. A portal must obtain the auth ID from the user.
- **Bằng chứng:** headscale.proto Auth section contains only AuthRegister, AuthApprove, AuthReject. state.go: `authCache *expirable.LRU[types.AuthID, *types.AuthRequest]`. state/debug.go DebugRegistrationCache returns `"max_entries"`, `"ssh_reserve"`, `"current_len"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/debug.go

### F-37 · `VERIFIED` — 8 Registration timeouts and limits

- **Nhận định:** Pending auth requests expire after 15 minutes by default (tuning.register_cache_expiration) and are capped at 1024 entries plus 64 reserved for SSH checks; at capacity new requests get HTTP 503 with Retry-After, and a cached registration is limited to 64 KiB.
- **Bằng chứng:** state.go: `registerCacheExpiration = time.Minute * 15`, `defaultRegisterCacheMaxEntries = 1024`, `authCacheSSHReserve = 64`. registration.md: `new requests receive HTTP 503 with Retry-After`. types/registration.go: `MaxRegistrationPayloadBytes = 64 << 10`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/registration.md

### F-38 · `VERIFIED` — 9 Node fields: identity

- **Nhận định:** Node identity fields: id; machine_key, node_key and disco_key (public keys as strings); ip_addresses; name (hostname reported by the client); given_name (unique DNS label used for MagicDNS, set by rename); user (owner); tags (non-empty means the node is tagged).
- **Bằng chứng:** node.proto: `uint64 id = 1; string machine_key = 2; string node_key = 3; string disco_key = 4; repeated string ip_addresses = 5; string name = 6; User user = 7;`, `string given_name = 21;`, `repeated string tags = 26;`. node.go: `Name: node.Hostname`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/node.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/node.go

### F-39 · `VERIFIED` — 9 Node fields: state and routes

- **Nhận định:** Node state fields: last_seen (best effort), expiry (null means never expires), created_at, pre_auth_key (masked key used to register; carries the ephemeral flag), register_method (AUTH_KEY, CLI, OIDC), online, approved_routes, available_routes (announced by the client) and subnet_routes (primary routes actually served).
- **Bằng chứng:** node.proto fields 8, 10 to 13, 22 to 25; `REGISTER_METHOD_AUTH_KEY = 1; REGISTER_METHOD_CLI = 2; REGISTER_METHOD_OIDC = 3;`. node.go: `AvailableRoutes: util.PrefixesToString(node.AnnouncedRoutes())`; `It is best effort and not persisted.`
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/node.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/node.go

### F-40 · `UNSUPPORTED` · *critical* — 9 Node data not available

- **Nhận định:** The Node message exposes no OS, client version, Hostinfo, endpoints, DERP region, latency or traffic counters: field numbers 14 to 20 are reserved with host_info and endpoints commented out, and network flow logs are listed as not implemented.
- **Bằng chứng:** node.proto: `reserved 14 to 20;`, `// bytes host_info = 15;`, `// bytes endpoints = 16;`. docs/about/features.md: `- [ ] Network flow logs` (issue #1687).
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/node.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/features.md

### F-41 · `VERIFIED` — 9 Hostinfo via debug endpoint

- **Nhận định:** Full node records including Hostinfo and Endpoints exist in the in-memory NodeStore and are exposed as JSON only by the debug handler `nodestore` on metrics_listen_addr, which docs say expects localhost traffic or a debug key and must be kept private.
- **Bằng chứng:** state/debug.go: `func (s *State) DebugNodeStoreJSON() map[types.NodeID]types.Node`. types/node.go: `Hostinfo *tailcfg.Hostinfo` and `Endpoints AddrPorts`. debug.md: `The debug endpoint expects traffic from localhost.` and `Keep the metrics and debug endpoint private`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/debug.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/debug.md

### F-42 · `VERIFIED` — 9 GetNode versus ListNodes

- **Nhận định:** GetNode and ListNodes return different shapes: only ListNodes (and SetApprovedRoutes) populate subnet_routes, and only ListNodes substitutes the synthetic `tagged-devices` user for tagged nodes. GetNode returns the raw conversion, so ListNodes is the reliable read.
- **Bằng chứng:** grpcv1.go GetNode: `resp := node.Proto()`. nodesToProto: `if node.IsTagged() { resp.User = types.TaggedDevices.Proto() }` and `resp.SubnetRoutes = util.PrefixesToString(append(state.GetNodePrimaryRoutes(node.ID()), node.ExitRoutes()...))`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go

### F-43 · `VERIFIED` — 10 ExpireNode

- **Nhận định:** ExpireNode sets key expiry to now by default, to a supplied `expiry` time, or to null with `disable_expiry` (the two are mutually exclusive). The node stays in the database, is treated as offline once expired and must re-authenticate; out-of-range times return HTTP 400.
- **Bằng chứng:** grpcv1.go: `expiry := time.Now()`, `if request.GetExpiry() != nil {`, `"cannot set both disable_expiry and expiry"`. nodes.go: `Expiring a node will keep the node in the database and force it to reauthenticate.` CHANGELOG 0.29.7: `POST /api/v1/node/{node_id}/expire (HTTP 400)`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/nodes.go

### F-44 · `VERIFIED` · *critical* — 10 DeleteNode

- **Nhận định:** DeleteNode hard-deletes the row, removes the node from the in-memory store, frees its IPs and immediately enqueues a NodeRemoved change plus a policy refresh to the map batcher (default batch delay 800ms). The deleted client's session is closed; a repeat call returns NotFound.
- **Bằng chứng:** db/node.go: `// Unscoped causes the node to be fully removed from the database.` state.go: `removed := change.NodeRemoved(node.ID())`. grpcv1.go: `api.h.Change(changes...)`. CHANGELOG 0.29.4: `Fix deleting a node leaving its long poll open`. config.go: `"tuning.batch_change_delay", "800ms"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go

### F-45 · `VERIFIED` — 10 RenameNode

- **Nhận định:** RenameNode changes given_name (the MagicDNS label), not the client hostname. The new name must be a valid DNS label whose FQDN fits the length limit, is not auto-sanitised and must be unique; failures are returned as plain errors (HTTP 500).
- **Bằng chứng:** state.go: `The admin supplies the exact DNS label they want; malformed input is rejected (no auto-sanitisation) and collisions error out`; `err := types.ValidateGivenName(newName, s.cfg.BaseDomain)`. grpcv1.go RenameNode: `if err != nil { return nil, err }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go

### F-46 · `VERIFIED` — 10 and 11 SetTags

- **Nhận định:** SetTags replaces the node's tag set; at least one tag is required and each must exist in the policy. Tagging a user-owned node clears its user (one-way through the API); returning to user ownership requires client re-authentication with `--advertise-tags= --force-reauth`.
- **Bằng chứng:** grpcv1.go: `Once tagged, a node cannot be converted back to user-owned.` state.go: `if !strings.HasPrefix(tag, "tag:") || !s.polMan.TagExists(tag) {`. tags.md: `Tagged nodes can return to personal (user-owned) nodes by re-authenticating with` ... `--advertise-tags= --force-reauth`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/tags.md

### F-47 · `VERIFIED` — 1 and 10 Routes and SetApprovedRoutes

- **Nhận định:** There is no standalone routes resource. SetApprovedRoutes replaces a node's whole approved set (empty list clears it), approving either exit route adds both 0.0.0.0/0 and ::/0, routes can be approved before they are announced, and auto-approvers can re-add removed routes.
- **Bằng chứng:** state.go: `node.ApprovedRoutes = routes`. grpcv1.go: `// If the prefix is an exit route, add both.` node.go: `They are not necessarily the routes that the node announces at the moment.` nodes.go list-routes calls `client.ListNodes` and filters client-side.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go

### F-48 · `UNSUPPORTED` · *critical* — 10 Move or reassign node

- **Nhận định:** Nodes cannot be moved or reassigned between users: the MoveNode endpoint and `headscale nodes move` were removed in 0.28.0, and no such RPC exists at v0.29.7. Ownership is fixed at registration, apart from tagging.
- **Bằng chứng:** CHANGELOG 0.28.0: `Remove ability to move nodes between users`, `The MoveNode API endpoint has been removed`, `Nodes are permanently associated with their user or tag at registration time`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md

### F-49 · `VERIFIED` — 10 BackfillNodeIPs

- **Nhận định:** BackfillNodeIPs runs only with confirmed=true, adds or removes node IPs to match the configured prefixes and returns a list of change strings. The handler refreshes the in-memory store but does not enqueue a map change for connected clients.
- **Bằng chứng:** grpcv1.go: `if !request.Confirmed { return nil, errors.New("not confirmed, aborting") }`, then `changes, err := api.h.state.BackfillNodeIPs()` and return, with no `api.h.Change` call. nodes.go: `Backfill IPs can be used to add/remove IPs from nodes`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/nodes.go

### F-50 · `VERIFIED` — 11 Tag ownership model

- **Nhận định:** Headscale follows Tailscale's identity model: a node is either personal (owned by a user) or tagged (owned by its tags, grouped under the special user `tagged-devices`). Tags come from --advertise-tags (authorised by policy tagOwners), a tagged pre-auth key, or admin CLI/API; tagged nodes never expire by default.
- **Bằng chứng:** registration.md: `a personal node is owned by a Headscale user and a tagged node is owned by a tag. Tagged devices are grouped under the special user tagged-devices.` tags.md: `Administrators can manage tags with: Headscale CLI, Headscale API`. config-example.yaml: `Tagged nodes are exempt and never expire.`
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/registration.md | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/tags.md

### F-51 · `VERIFIED` — 12 User fields and uniqueness

- **Nhận định:** User fields: id, name, created_at, display_name, email, provider_id, provider, profile_pic_url. Name is unique only among users without a provider identifier, and provider_id is unique when set, so OIDC users can share a name; name-based lookups then fail.
- **Bằng chứng:** user.proto: `message User { uint64 id = 1; string name = 2; ... string provider_id = 6; string provider = 7; string profile_pic_url = 8; }`. db.go: `CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/user.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/db.go

### F-52 · `REQUIRES_VALIDATION` — 12 User create and rename validation

- **Nhận định:** At v0.29.7 the API paths for CreateUser and RenameUser write through State directly and never reach util.ValidateUsername or the 'cannot edit OIDC user' guard found in the db-layer helpers, so username rules may not be enforced through the API.
- **Bằng chứng:** state.go CreateUser: `if err := s.db.DB.Save(&user).Error`; RenameUser calls UpdateUser with `user.Name = newName`; a grep of state.go finds no ValidateUsername or db.RenameUser. Test: POST /api/v1/user with name `1` or `a b`; rename an OIDC user.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/users.go

### F-53 · `VERIFIED` — 12 User delete constraints

- **Nhận định:** DeleteUser fails with 'user not empty: node(s) found' while the user owns nodes (a plain error, HTTP 500). On success it also deletes every pre-auth key belonging to that user and hard-deletes the user; tagged nodes do not block deletion.
- **Bằng chứng:** db/users.go: `if len(nodes) > 0 { return ErrUserStillHasNodes }`; `for _, key := range keys { err = DestroyPreAuthKey(tx, key.ID)`; `// Tagged nodes have user_id = NULL so they do not block deletion.`
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/users.go

### F-54 · `UNSUPPORTED` — 12 Users and OIDC identities

- **Nhận định:** OIDC logins are matched to users only by provider identifier (iss plus sub). CreateUserRequest has no provider fields, so a user pre-created through the API cannot be linked to an OIDC identity; the first OIDC login creates a separate user row.
- **Bằng chứng:** oidc.go: `user, err = a.h.state.GetUserByOIDCIdentifier(claims.Identifier())`, then `if user == nil { newUser = true; user = &types.User{} }`. user.proto: `message CreateUserRequest { string name = 1; string display_name = 2; string email = 3; string picture_url = 4; }`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/oidc.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/user.proto

### F-55 · `VERIFIED` · *critical* — 13 Policy mode

- **Nhận định:** SetPolicy works only when policy.mode is `database`; in any other mode it returns 'update is disabled for modes other than 'database''. The default mode is `file`, where changes require editing the file and reloading Headscale (SIGHUP).
- **Bằng chứng:** grpcv1.go: `if api.h.cfg.Policy.Mode != types.PolicyModeDB { return nil, types.ErrPolicyUpdateIsDisabled }`. config.go: `viper.SetDefault("policy.mode", "file")`. policy.md: `Headscale needs to be reloaded to pick up changes to the policy file.`
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

### F-56 · `VERIFIED` — 13 SetPolicy validation

- **Nhận định:** SetPolicy validates the HuJSON against live users and nodes (including beta `tests` and `sshTests` blocks), compiles the SSH policy for one node, then stores a new row, reloads the policy and pushes changes to clients. A policy that fails validation is rejected before being stored.
- **Bằng chứng:** grpcv1.go sequence: `api.h.state.SetPolicy([]byte(p))`, `api.h.state.SSHPolicy(nodes.At(0))`, `api.h.state.SetPolicyInDB(p)`, `api.h.state.ReloadPolicy()`. CHANGELOG 0.29.0: `A failing test rejects the write before it is applied`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md

### F-57 · `VERIFIED` — 13 GetPolicy semantics

- **Nhận định:** GetPolicy returns the newest stored policy with updatedAt in database mode, or the raw policy file content without a timestamp in file mode. In database mode with no stored policy it returns the error 'acl policy not found' rather than an empty policy.
- **Bằng chứng:** grpcv1.go file mode: `return &v1.GetPolicyResponse{Policy: string(b)}, nil`. db/policy.go: `if errors.Is(err, gorm.ErrRecordNotFound) { return nil, types.ErrPolicyNotFound }`. types/policy.go: `ErrPolicyNotFound = errors.New("acl policy not found")`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/policy.go

### F-58 · `VERIFIED` — 13 and 16 CheckPolicy

- **Nhận định:** Policy checking is available over the API, not only the CLI: CheckPolicy builds a throwaway policy manager from the submitted policy plus live users and nodes, runs its tests, persists nothing, leaves the live policy untouched, works in either policy mode and returns InvalidArgument on failure.
- **Bằng chứng:** grpcv1.go: `Nothing is persisted and the live PolicyManager is not touched. Works regardless of policy.mode so operators can validate a policy file before storing it.`; `return nil, status.Error(codes.InvalidArgument, err.Error())`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go

### F-59 · `UNSUPPORTED` · *critical* — 14 Events, webhooks, streams

- **Nhận định:** Headscale provides no webhook, event stream or watch API: all 29 RPCs are unary, the protos contain no streaming or subscription constructs, and neither the config loader nor the example config has webhook or event settings.
- **Bằng chứng:** headscale.proto: every entry is `rpc X(XRequest) returns (XResponse)`. A grep of the eight proto files for stream, watch, subscribe and of hscontrol/types/config.go for webhook, event returned no matches.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

### F-60 · `VERIFIED` · *critical* — 15 API stability

- **Nhận định:** No API stability or versioning guarantee is documented. Breaking changes shipped inside /api/v1 in 0.28.0 (Node tag fields replaced, MoveNode removed) and 0.29.0 (auth routes; register body now JSON), and the remote CLI must be the same version as the server.
- **Bằng chứng:** CHANGELOG 0.28.0: `**API**: The Node message in the gRPC/REST API has been simplified - the ForcedTags, InvalidTags, and ValidTags fields have been removed`. api.md: `Make sure to use the same version as on the server.` Swagger: `"version": "version not set"`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/api.md

### F-61 · `VERIFIED` — 15 Upgrade path and upstream scope

- **Nhận định:** Upstream enforces a strict upgrade path (no skipping minor versions, no downgrades), describes Headscale as scoped to a single tailnet for personal or small-organisation use, and states that Docker deployment is not officially supported.
- **Bằng chứng:** CHANGELOG 0.29.0: `Skipping minor versions (e.g. 0.27 → 0.29) is blocked`, `Downgrading to a previous minor version is blocked`. faq.md: `It implements a narrow scope, a _single_ Tailscale network (tailnet)`; `we don't officially support deploying headscale using Docker`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/faq.md

### F-62 · `VERIFIED` — 16 CLI-only capabilities

- **Nhận định:** CLI-only capabilities with no RPC: `--bypass-grpc-and-access-database-directly` on policy get/set/check (direct database access while the server is stopped), `generate private-key`, `configtest`, `serve`, `version`, `mockoidc` and hidden `dumpConfig`. Every other command is a thin wrapper around an RPC.
- **Bằng chứng:** cli/policy.go: `bypassFlag = "bypass-grpc-and-access-database-directly"`. generate.go: `Use: "private-key"`. configtest.go: `Use: "configtest"`. utils.go: `grpcRunE wraps a cobra RunE func, injecting a ready gRPC client and context`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/policy.go | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/utils.go

### F-63 · `VERIFIED` — 17 Go client: paths and generation

- **Nhận định:** The module path is github.com/juanfont/headscale (go 1.27.3). Generated stubs are imported as github.com/juanfont/headscale/gen/go/headscale/v1 although the protos declare go_package .../gen/go/v1; they are produced by `buf generate` with go, go-grpc, grpc-gateway and openapiv2 plugins.
- **Bằng chứng:** go.mod: `module github.com/juanfont/headscale`, `go 1.27.3`. grpcv1.go: `v1 "github.com/juanfont/headscale/gen/go/headscale/v1"` and `//go:generate buf generate --template ../buf.gen.yaml -o .. ../proto`. headscale.proto: `option go_package = "github.com/juanfont/headscale/gen/go/v1";`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/go.mod | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/buf.gen.yaml

### F-64 · `VERIFIED` · *critical* — 17 Go client: weight of the module

- **Nhận định:** The generated package imports only grpc, protobuf, grpc-gateway runtime and genproto annotations, but it belongs to the root module, whose 257-line go.mod requires tailscale.com v1.104.4, gorm, docker, modernc sqlite and gVisor among others; there is no separate lightweight client module.
- **Bằng chứng:** headscale.pb.gw.go imports `github.com/grpc-ecosystem/grpc-gateway/v2/runtime`, `google.golang.org/grpc`, `google.golang.org/protobuf/proto`. go.mod: `tailscale.com v1.104.4`, `gorm.io/gorm v1.31.1`, `github.com/docker/docker v28.5.2+incompatible`, `modernc.org/sqlite v1.52.0`; no require or replace for a nested gen module.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/go.mod | https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/go/headscale/v1/headscale.pb.gw.go

### F-65 · `ASSUMED` — 17 Go client: consequence of importing

- **Nhận định:** Importing the Headscale module would raise our minimum Go toolchain to 1.27.3 and impose its minimum versions of shared dependencies (grpc v1.83.2, protobuf v1.36.12, grpc-gateway v2.29.0); generating our own stubs from the eight proto files (about 14 KB) with buf avoids that coupling.
- **Bằng chứng:** Inference from Go module semantics (the go directive is a minimum; minimal version selection takes the highest required version). go.mod lists `google.golang.org/grpc v1.83.2` and `google.golang.org/protobuf v1.36.12`. Confirm with a scratch module and `go mod graph`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/go.mod

## Hệ quả thiết kế (agent đề xuất)

- Edge: REST and Swagger share the public control-plane listener, so Caddy must not forward /api/* or /swagger* for tenant hostnames; the central backend should call each instance over the internal Docker network (later a private network or mTLS between hosts).
- Backend-to-tenant channel: use internal REST with one API key per tenant as the default. On a single host, gRPC over a mounted unix socket is a keyless alternative, but socket access equals full admin and needs matching socket permissions (default 0770). Remote gRPC needs native TLS in Headscale or grpc_allow_insecure on a private network.
- Provisioning must bootstrap the first API key through the unix socket (CLI `headscale apikeys create -e <duration> -o json` inside the tenant container, or a gRPC CreateApiKey call on the socket), store it encrypted in PostgreSQL, and rotate it: create new, switch, then expire or delete the old key.
- Headscale keys are all-or-nothing: implement RBAC, tenant isolation, per-user authorisation and audit logging entirely in the central backend; never expose a Headscale API key to the browser or to tenant administrators.
- Always send an explicit UTC expiration when creating API keys and pre-auth keys; the server has no default and no maximum.
- No events, pagination or ETags: build a per-tenant poll-and-diff reconciler that treats PostgreSQL as cache and audit trail, uses ListNodes as the canonical node read, serialises writes per tenant and spaces polls, because every call costs a bcrypt check on the tenant instance.
- Wrap all calls in an adapter that normalises errors: map known messages (user not found, node(s) found, node name is not unique, acl policy not found) to typed errors, treat gRPC Internal 'validating token' as an authentication failure, and pre-validate names and tags before calling.
- Set policy.mode=database for every tenant and seed an initial policy at provisioning. Policy pipeline: CheckPolicy, then SetPolicy; keep versions, diffs, rollback and optimistic locking in PostgreSQL. Keep a runbook for the CLI bypass flag when a stored policy prevents startup.
- Onboarding: prefer short-lived single-use pre-auth keys shown once (tag-only keys for servers, user keys for personal devices) and do not combine them with --advertise-tags. For interactive login the portal needs a 'paste auth ID' step that calls AuthRegister with a username, or per-tenant OIDC.
- If OIDC is used, let Headscale create users from the identity provider and map them in our database by providerId; do not pre-create users through the API expecting them to be linked.
- Device views cannot show OS, client version, endpoints, relay or traffic from the management API. Either scope the portal accordingly or add an optional internal collector for the debug nodestore endpoint (debug-grade, unversioned) on the metrics listener.
- There is no node move: 'reassign device' must be implemented as delete plus re-registration. Offboarding should delete the node and expire or delete any reusable pre-auth key it could use to return; deleting a user requires removing its nodes first and also deletes its keys.
- Do not import github.com/juanfont/headscale into the backend; generate stubs from the eight proto files with buf (managed mode to set our own go_package) or write a thin REST client from the Swagger document, and regenerate per pinned Headscale version.
- Pin the Headscale version per tenant, upgrade one minor at a time, and gate upgrades with API contract tests, because /api/v1 has had breaking changes in consecutive minors and upstream gives no stability promise.
- Use unauthenticated GET /health for container health checks and authenticated GET /api/v1/health for backend-side credential and database checks.

## Câu hỏi mở

- Test: does an API key or pre-auth key created over REST without `expiration` work, or is it expired at birth (zero timestamp)?
- Test: what happens when AuthApprove is called for a node-registration auth ID, and what does the client see after AuthReject (new AuthURL or hard failure)?
- Test: are username rules (minimum length, leading letter, allowed characters) enforced by POST /api/v1/user and the rename route at v0.29.7, and can an OIDC user be renamed through the API?
- Measure: CPU and latency cost of bcrypt per API call on a tenant instance, to set polling intervals; compare with gRPC over the unix socket.
- Measure: time from DeleteNode or ExpireNode until peers drop the node and the client is disconnected (batch delay default 800ms); can a deleted device re-register on its own with a still-valid reusable key?
- Test: do ExpirePreAuthKey and DeletePreAuthKey return success for unknown IDs (neither checks rows affected), and does deleting a key change the ephemeral behaviour of nodes that registered with it?
- Test: do connected clients pick up address changes after BackfillNodeIPs without reconnecting (the handler enqueues no map change)?
- Test: exact HTTP status and body of GET /api/v1/policy on a fresh database-mode instance with no stored policy; maximum policy size accepted over REST and gRPC.
- Test: can a custom Go gRPC client use bearer metadata against a grpc_allow_insecure listener (the stock CLI always dials TLS), and can Caddy proxy that listener reliably in a multi-host layout?
- Decision: REST with per-tenant API keys versus unix-socket gRPC in the single-host phase; where and how API keys are stored and rotated.
- Decision: is the debug nodestore endpoint an acceptable source for OS and client version in the portal, or should those fields be dropped?
- Decision: interactive registration UX (paste auth ID, per-tenant OIDC, or pre-auth keys only).
- Check with a scratch module how importing gen/go/headscale/v1 affects go.mod and the toolchain, to confirm the decision to generate our own stubs.

## Nguồn đã đọc

- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/headscale.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/apikey.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/auth.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/device.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/node.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/policy.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/preauthkey.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/headscale/v1/user.proto
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/buf.yaml
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/proto/buf.lock
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/openapiv2/headscale/v1/headscale.swagger.json (all lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/api.md
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/swagger.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1.go (all lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/grpcv1_test.go (test index and one test)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/api_key.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/api_key.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/preauth_keys.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/preauth_key.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/registration.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/registration.md
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/tags.md
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/api_key.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/auth.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/nodes.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/policy.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/preauthkeys.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/users.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/debug.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/health.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/utils.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/root.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/configtest.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/dump_config.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/generate.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/version.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/strings.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/serve.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/mockoidc.go (first 60 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go (identifier grep plus lines 84-130, 400-900, 1046-1200)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/buf.gen.yaml
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/go.mod (all 257 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go (function index plus user, node, policy, API key, auth cache and registration sections)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/debug.go (partial)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/common.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/node.go (struct, Proto, expiry and tag helpers)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/users.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/policy.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/const.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go (grep plus tuning struct and viper defaults)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/users.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/policy.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/node.go (function index)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/db.go (grep for indexes and hooks)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/handlers.go (health, version, web auth handlers)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/auth.go (admission errors and follow-up wait)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/oidc.go (createOrUpdateUserFromClaim and handler index)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/debug.go (handler index and access guard)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/util/dns.go (ValidateUsername)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/util/string.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/util/net.go (first 40 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/go/headscale/v1/headscale_grpc.pb.go (first 45 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/go/headscale/v1/headscale.pb.gw.go (first 45 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/go/headscale/v1/node.pb.go (first 45 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/gen/go/headscale/v1/headscale.pb.go (first 45 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/config-example.yaml (API, node, policy, socket and tuning sections)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md (lines 1-635: 0.29.7 through 0.28.0)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/debug.md
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/policy.md (head and footnotes)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/routes.md (grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/oidc.md (lines 174-256 plus grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/integration/web-ui.md
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/faq.md (lines 1-58 plus grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/features.md
- https://github.com/juanfont/headscale/tree/v0.29.7/cmd/headscale/cli (directory listing via WebFetch)
- https://github.com/juanfont/headscale/tree/v0.29.7/docs/ref (directory listing via WebFetch)
- https://github.com/juanfont/headscale/tree/v0.29.7/hscontrol/types (directory listing via WebFetch)
- https://github.com/juanfont/headscale/tree/v0.29.7/gen/go/headscale/v1 (directory listing via WebFetch)
- https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v2.29.0/runtime/errors.go
- https://raw.githubusercontent.com/grpc-ecosystem/grpc-gateway/v2.29.0/runtime/marshaler_registry.go (first 45 lines)

**Nguồn không đọc được:**

- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/auth.go (HTTP 404; guessed path, not in the task inventory. The AuthID, AuthRequest and AuthVerdict types were found in hscontrol/types/common.go)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/auth_request.go (HTTP 404; guessed path, same content located in hscontrol/types/common.go)
