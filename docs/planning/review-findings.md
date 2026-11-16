# Adversarial Review Findings (bản ghi đầy đủ)

> Bản ghi **nguyên văn** kết quả của 8 reviewer độc lập — là **8 agent AI phản biện tự động, mỗi agent một góc nhìn**, không phải thẩm định của chuyên gia bên ngoài — chạy trên **Rev 1** của Implementation Master Plan (2026-11-16). Số mục/số dòng trong các phát hiện tham chiếu theo Rev 1. Trạng thái xử lý từng phát hiện: xem **Appendix D** của [implementation-master-plan.md](implementation-master-plan.md).
> File này được sinh một lần từ nhật ký phản biện; không sinh lại bằng `tools/split_plan.py`.

## Tổng hợp

| Reviewer (lens) | Critical | High | Medium | Low |
|---|---|---|---|---|
| Completeness against the original brief | 0 | 6 | 15 | 4 |
| UPSTREAM FACT-CHECK (HEADSCALE v0.29.7) | 0 | 2 | 10 | 9 |
| API, data model and authorization design (principal backend engineer / database architect) | 1 | 10 | 14 | 0 |
| Roadmap, task graph and testability (sections 19-25, 5.2, Appendix A/B; cross-checked against deliverables in  | 0 | 10 | 14 | 1 |
| Operations and feasibility (senior SRE / DevOps who has to build and run it) | 0 | 6 | 15 | 3 |
| Tenant-isolation red team (attacker = one tenant's admin account, one tenant's end-user device, or a compromis | 0 | 8 | 12 | 5 |
| Internal consistency and referential integrity (whole plan read end to end: <plan file> | 0 | 5 | 17 | 3 |
| Upstream fact-check: Tailscale client v1.104.7, derper, Caddy 2.11.x, Docker Engine 28/29, CrowdSec, SQLite, P | 0 | 3 | 9 | 4 |
| **Tổng** | **1** | **50** | **106** | **29** |

## Completeness against the original brief

**Verdict:** Revise before approval. Structurally the plan is close to complete: all 25 required sections, 18 tables, 18 threats with eight attributes, 20 acceptance criteria, 24 ADRs, 26 documentation targets, both sequence diagrams, the port matrix and the WebUI A/B/C table are present, and the upstream facts I spot-checked against the pinned tags hold. It is not yet executable without redesign, though: 6 high-severity gaps (identity isolation breaks for shared issuers; backup key custody makes restore and rollback impossible as written; Docker network membership contradicts the connectivity the plan requires; isolation tests IT-07/IT-08 are never scheduled; the IdP driver and invitation flow needed by provisioning have no task; acceptance tests for AC-08/14/18/19 do not prove their criteria), 15 medium gaps and 4 low. No critical issue was found within this lens.

**Strengths noted:**

- All 25 required sections are present in order, with all 18 tables, 18 threats carrying all eight attributes, 20 acceptance criteria, 24 ADRs with the six elements, 26 documentation targets, both sequence diagrams and the WebUI A/B/C comparison on the four requested criteria.
- Upstream facts spot-checked against the pinned tags hold: auth/register and policy/check routes, SetVerifyClientURLFailOpen(false) for embedded DERP, node.expiry 0, allow-all and deny-all policy semantics, pre-auth key defaults, stop-and-copy upgrade guidance.
- Requirement-versus-reality conflicts are stated with alternatives (§2.9, twelve items) and the main unknowns are tied to gates (V-01 to V-15) with a fallback for the DERP-through-Caddy risk.
- Honest about limits: no mock metrics, no SLA or node limits, simulated tests not counted as network E2E, single-host isolation declared non-physical, shared DERP kept as research only.
- Each of the twelve isolation boundaries has a mechanism and a named test, the permission matrix is per API action for all nine roles, and provisioning closes the allow-all window before the edge is attached.

### COMP-01 — HIGH — §8.2 IdP model, §8.4 invariant 1, §6.3 identity_providers, §7.4 method C, §5.2 row 1 (IT-01)

**Problem.** The identity boundary assumes one issuer = one tenant (issuer binding + UNIQUE(issuer)), but the plan also supports tenant-brought IdPs including Google Workspace from MVP and names Keycloak Organizations (one issuer, claim-based) as the fallback. For an issuer shared by several organisations: (a) a second tenant on the same issuer cannot be registered; (b) issuer binding no longer separates organisations, because no organisation rule (hd / tid / verified e-mail domain) exists in the schema or in login step 3; (c) with enrollment method C the rendered Headscale oidc block has no mandatory allowed_domains / allowed_users / allowed_groups, so by the plan's own ID-02 anyone that IdP authenticates for the client becomes a Headscale user of the tenant and matches autogroup:member. IT-01 only tests a different issuer, never 'same issuer, other organisation'.

<details><summary>Evidence</summary>

§8.2: 'IdP do tenant mang tới (Entra ID, Google Workspace, Okta, Keycloak riêng…) | Mạnh nhất (khác tổ chức) | … Hỗ trợ ngay từ MVP'. §6.3 identity_providers: 'UNIQUE(issuer)'. §8.4: 'identity từ IdP của tenant X chỉ có thể có membership ở tenant X'. ID-02: 'Bộ lọc đăng nhập allowed_groups/domains/users rỗng mặc định (ai IdP xác thực cho client đó đều được nhận) … không kiểm tra được claim tùy biến (ví dụ tenant id)'. §7.4 method C control: 'Issuer riêng theo tenant; không có bước admin phê duyệt (UNSUPPORTED)'.

</details>

**Suggested fix.** Add to §8.2 a 'shared-issuer rule': an IdP registration is (issuer, client_id, org_constraint); replace UNIQUE(issuer) with UNIQUE(issuer, client_id) and add column org_constraint jsonb. For issuers that serve more than one organisation the constraint is mandatory (required claim equality such as hd/tid/organization and/or a verified e-mail domain allow-list) and login step 3 rejects the token before upserting identities. Offer method C only when the config renderer can emit a non-empty oidc.allowed_domains/allowed_groups/allowed_users; the config validator blocks an empty filter. Add lint: autogroup:member with identity mode headscale_oidc = warning needing confirmation. Add IT-01b: a user of another organisation on the same issuer is rejected by the Portal and cannot register a node via method C. Update ADR-12 and T-06.

### COMP-02 — HIGH — §7.6 secrets table, §17.1–§17.2, §11.4 Upgrade, §14.3–§14.4 agent, T-14/T-15

**Problem.** Backup encryption is specified three incompatible ways: only a public key is on the host and the operator decrypts offline; archives use a per-tenant key; and the Agent decrypts inside the automated restore job, the upgrade rollback and the periodic restore check. The Agent has network_mode none and no SecretStore access, so it can obtain no decryption key; with the private key offline, AC-19, gate G3, the automatic upgrade rollback and P6-T04 cannot run as designed. Off-site shipping has no owner either: restic is named in §4.3, but the Agent image lists only sqlite3 and age and has no network, and the Worker has no file access. §17.1 also still leaves '.backup or VACUUM INTO' open although ST-06 and ADR-18 chose VACUUM INTO.

<details><summary>Evidence</summary>

§7.6: 'Khóa mã hóa backup | Public key trên host; private key offline | Agent (mã hóa) / người vận hành (giải mã)'. §17.1: 'Archive riêng từng tenant, khóa gắn tenant'. §17.2 step 2: 'Agent giải mã vào thư mục staging của đúng instance'. §11.4 Upgrade rollback: 'dừng → restore backup → image cũ → start'. T-14: 'backup mã hóa bằng khóa không nằm trên host'. §14.3: agent 'network_mode: none'. §14.4 agent image: 'CLI docker/compose + sqlite3 + age'.

</details>

**Suggested fix.** Add §17.1a 'Backup key hierarchy': every archive is encrypted with a random archive key that is wrapped for two recipients: (R1) the offline DR public key, used only for host-loss recovery by an operator; (R2) the tenant DEK in SecretStore. For routine restore, upgrade rollback and restore verification the Worker unwraps through R2 and hands the archive key to the Agent over the Unix socket for the duration of the job (never on disk or in logs). Reword T-14/T-15 accordingly and state the residual risk (KEK + database compromise also opens local archives). Assign off-site shipping to a named service (for example backup-shipper: read-only mount of /opt/meshguard/backups, egress only to the off-site target) and add it to §14.4, §15.1, §15.2 and P6-T03/T04. State VACUUM INTO as the single online method in §17.1.

### COMP-03 — HIGH — §14.3 Docker networks vs §11.3 steps 4/6/17/18, §15.2, §16.1, §14.4

**Problem.** Network membership contradicts the connectivity the plan itself requires. Worker is only on mg-data and mg-admin (both internal) yet must reach the public edge path (step 18), /derp/probe and the STUN port (step 17), DNS resolution or the DNS provider (step 4), the IdP Admin API (step 6; idp is listed on mg-edge) and SMTP. All monitoring is only on internal mg-obs, yet blackbox and the STUN/DERP probe must reach public tenant hostnames and host-published UDP ports, Prometheus must scrape api/worker /metrics and the API service-discovery endpoint, the PostgreSQL exporter must reach postgres on mg-data, and Alertmanager needs webhook egress. Separately, cAdvisor and the log collector must map containers to meshguard.tenant_id labels, which needs the Docker API and contradicts 'only the agent mounts the Docker socket'. Provisioning cannot pass steps 17/18 and Phase 6 monitoring cannot be built without re-deciding segmentation.

<details><summary>Evidence</summary>

§14.3: 'mg-data (internal) | api, worker, postgres'; 'mg-admin (internal, subnet tĩnh) | edge (IP tĩnh), api, worker'; 'mg-obs (internal, subnet tĩnh) | edge (IP tĩnh), prometheus, alertmanager, grafana, log store, collector, exporters'. §11.3 step 18 (Worker): 'qua đường public: GET /key trả 200'. §15.2: 'api / worker | PostgreSQL; edge listener admin; IdP (discovery, token, Admin API); (tùy chọn) SMTP, DNS provider'. §16.1: 'Prometheus HTTP SD đọc GET /internal/prometheus/sd của API'; 'cAdvisor | … Label container meshguard.tenant_id'. §14.4: 'Không service nào ngoài agent được mount Docker socket.'

</details>

**Suggested fix.** Replace the §14.3 table with a service × network matrix and reconcile it row by row with §15.2. Proposal: add mg-egress (not internal, nothing published) for worker, idp, alertmanager and a new prober service (blackbox + STUN/DERP probe); expose api/worker/postgres-exporter metrics on mg-obs or through the edge metrics listener; add /internal/prometheus/sd to the §13.2 internal endpoints and say which network serves it. Define step 18 as a functional check through the edge public listener from prober, and reserve 'external reachability' for an off-host canary (only that may be recorded as Internet-facing). For container-to-tenant mapping choose one mechanism and record it in ADR-05/ADR-19: json-file log option labels=meshguard.tenant_id,meshguard.instance_id with a read-only host-path mount for the collector plus cgroup-id relabelling fed by the SD endpoint for cAdvisor, or an explicitly accepted read-only socket filter limited to GET /containers/json.

### COMP-04 — HIGH — §5.2 (IT-01…IT-13), §19 Phase 2/5, §20 P2-T15, P5-T05, P5-T06, §22.1

**Problem.** The brief requires all twelve boundaries to be designed and tested. The tests are defined, but IT-07 (DNS) and IT-08 (routing) are never referenced by any task, phase, acceptance criterion or gate, and no AC covers DNS or routing isolation. IT-12 is promised as automated in Phase 2 although it needs the usage API (Phase 6) and the tenant relay endpoint (in no phase). The CPU-saturation half of IT-04 exists only as a Phase 6 chaos task, after the MVP gate. §22.1 says IT-01…IT-13 run on every PR, yet IT-05/07/08/09/13 need Tailscale clients and no harness is specified. The claim that tenant A has no network path to instance B is verified only by docker network inspect, not by a reachability test.

<details><summary>Evidence</summary>

IT-07 and IT-08 occur only in the §5.2 table. Phase 2 acceptance: 'IT-01, IT-02, IT-03, IT-06, IT-10, IT-12 tự động'. P5-T05: 'IT-05, IT-13'; P5-T06: '… IT-09'. IT-12: 'API audit/usage/relay của A không trả sự kiện/số liệu của B'; Phase 6 API changes: 'usage/*'. IT-04: 'làm bão hòa CPU của A, đo độ trễ control của B' vs P6-T09 'noisy neighbour'. §22.1: 'IT-01…IT-13 (§5.2) | … | Mỗi PR + trước mỗi gate'. §5.2 (c): 'không có đường mạng tới instance B ngoài các endpoint client công khai'.

</details>

**Suggested fix.** Add to §5.2 a traceability table: IT | harness (API-only / containerised official client = functional / real device = network E2E) | task | first gate | cadence, and correct §22.1 so that only API-level and containerised-client tests run per PR. New tasks: 'P4-T12a IT-07: create an extra record and a MagicDNS name in B; from a client of A the name does not resolve (tailscale dns query or dig @100.100.100.100), and vice versa'; 'P4-T12b IT-08: approve a subnet route and an exit node in B; tailscale status --json on a client of A shows neither'; 'P3-T15 IT-14 network reachability: from a throw-away container attached to tenant A network, connections to hs-<B>:8080 and :9090, the edge admin and metrics listener addresses and postgres:5432 all fail'. Split IT-12 into audit (Phase 2) and usage/relay (the phase that ships those endpoints). Move the saturation half of IT-04 into G5 or mark it Phase 6 explicitly. List IT-01…IT-14 by ID in gate G5.

### COMP-05 — HIGH — §8.2 IdP driver, §11.3 steps 4, 6, 16, §20 Phase 2–4 tasks, §15.2

**Problem.** Components that the provisioning flow depends on have no build task and no interface. The IdP driver (keycloak / external) is needed by step 6 idp.ensure and by the Owner invitation in step 16, but Phase 2 only creates three realm templates by hand and no Phase 3 task builds the driver; P4-T09 then presupposes it. The DNS driver of step 4 appears nowhere else. The invitation flow is undefined: tenant_memberships needs an identity, and identities are keyed by (idp_id, subject), which is unknown before first login with an external IdP. Without this, a tenant created by the Phase 3 orchestrator has no issuer and no user who can log in, so the Phase 3 E2E and the 'provision 20 times' DoD do not yield a usable tenant. In the Keycloak-hosted model invitations also need SMTP, which the plan marks optional.

<details><summary>Evidence</summary>

§8.2: 'IdP driver (bước idp.ensure của orchestrator): keycloak (tạo realm từ template…) và external'. §11.3 step 6: 'IdP driver tạo issuer/client cho tenant'; step 4: 'chế độ per-tenant record: tạo qua DNS driver'; step 16: 'membership Owner (lời mời)'. P2-T05: 'IdP: compose + realm template (platform, tenant-a, tenant-b), MFA'. P4-T09: 'mời qua IdP driver'. §6.3 identities: 'UNIQUE(idp_id, subject)'. §15.2: '(tùy chọn) SMTP'.

</details>

**Suggested fix.** Add tasks before P3-T05: (1) 'IdP driver: interface {EnsureIssuer, EnsureClient, InviteUser, DisableUser, DeleteUser, RemoveIssuer, Health}; keycloak and external implementations; contract tests against a pinned Keycloak'. (2) Decide DNS for MVP: either 'wildcard only; per-record mode and DNS driver are Phase 7' (and delete the per-record branch from step 4) or add a DNS-driver task. (3) Specify invitations: table invitations(id, tenant_id, email, role_id, token_hash, expires_at, accepted_identity_id, invited_by); a membership is created only when a logged-in identity of that tenant IdP redeems the invite token, never by e-mail match alone; add the endpoints and permission rows. (4) Mark SMTP as required for the Keycloak-hosted model in §15.2 and Appendix A.1 item 9.

### COMP-06 — HIGH — §22.2 AC-08, AC-14, AC-18, AC-19; §5.2 IT-11; gate G3; P1-T08, P1-T12

**Problem.** Four acceptance tests do not validly prove their criterion. AC-19 / IT-11 / G3 compare a checksum of tenant B data directory before and after restoring A, but B is a live WAL-mode SQLite whose files change whenever B persists anything, so the test passes or fails for unrelated reasons. AC-18 must show that restarting A does not lose the other tenant's state, but the test checks A's nodes and B's control availability, never B's state. AC-08/09 use 'tailscale status shows each other' while every instance starts with the deny-all baseline and, per the plan's own CL-12, a node only receives peers it may talk to; Phase 1 tasks apply deny-all and then test same-tenant TCP and forced relay without ever defining an allow policy. AC-14 says an Auth ID is used with --login-server, which is not how an Auth ID is consumed.

<details><summary>Evidence</summary>

AC-19: 'Checksum data/ của B trước/sau'; G3: 'restore tenant A không đổi checksum tenant B'. AC-18: 'Restart A: node của A còn nguyên sau khi lên lại; B không gián đoạn control; tunnel direct của A được quan sát trong lúc restart'. AC-08: 'Hai thiết bị thật: tailscale status thấy nhau'; CL-12: 'node chỉ nhận public key của peer nó được phép nói chuyện'; P1-T08: 'policy deny-all qua CLI'; P1-T12: 'TCP cùng tenant, cô lập chéo tenant, ép relay qua Caddy'. AC-14: 'Pre-auth key và Auth ID của A dùng với --login-server của B'.

</details>

**Suggested fix.** AC-19: replace the directory checksum with (i) sha256 of B's noise_private.key, derp_server_private.key and config.yaml, (ii) a logical export of B through the API before and after (node IDs and node keys, users, policy sha256, API-key prefixes, pre-auth key IDs), (iii) the Agent file-operation log for the job showing only paths under tenants/<instance A>/, plus the existing negative test. AC-18: add the same logical export of B before and after, B's container StartedAt unchanged and B's client map session uninterrupted. AC-08/09: evidence = both nodes present in the instance node list; add a named fixture policy 'test-allow-tcp' that P1-T12 and AC-10 apply before any same-tenant traffic, relay or peer-visibility check, and re-apply deny-all for AC-11. AC-14: test the pre-auth key against B's login server, and the Auth ID by submitting A's auth_id through tenant B's /enrollment/web-auth:claim.

### COMP-07 — MEDIUM — §8.5 (2P cells), §8.4 invariant 3, §8.7, §6.3, §13.2, §12.2

**Problem.** Dual control is a headline control (tenant deletion, instance restore, Super Admin assignment; mitigations for T-03 and T-15) but it has no design: no table for pending approvals, no endpoint or permission for the second person to approve or reject, no rule for expiry, payload binding or self-approval, and no UI. Only break-glass has an approve endpoint. There is also no bootstrap procedure for the first Super Admin, and since assigning the SA role itself needs a second SA, a fresh platform (or one with a single SA) deadlocks on every 2P operation.

<details><summary>Evidence</summary>

§8.5: '2P = cho phép nhưng cần người thứ hai phê duyệt (dual control)'; 'platform.tenant:delete | DELETE /tenants/{id} | 2P'; 'platform.instance:restore | … | 2P | 2P'. §8.4: 'gán role SA cần SA thứ hai phê duyệt'. §13.2 platform group: the only approval endpoint is 'POST /platform/support-grants/{id}:approve-breakglass'. §6.3 has no approval table. No task in §20 bootstraps the first platform user.

</details>

**Suggested fix.** Add table approval_requests(id, action, resource_type, resource_id, payload_sha256, requested_by, decided_by, status, reason, expires_at, CHECK (requested_by <> decided_by)); endpoints GET /platform/approvals, POST /platform/approvals/{id}:approve and :reject with permission rows; semantics: a 2P operation returns 202 with an approval id and runs only after approval with step-up, bound to the payload hash, expiring after N hours, fully audited. Add a 'first Super Admin' procedure: one-time host CLI 'meshguard bootstrap-admin --issuer platform --subject <sub>', audited, disabled once two SAs exist; state that 2P operations require at least two active SAs and add a readiness alert. Schedule the bootstrap in Phase 2 and approvals in Phase 3 before P3-T09/P3-T11.

### COMP-08 — MEDIUM — §18.1 T-06 mitigation vs §7.4 flow A; R-22

**Problem.** The T-06 mitigation claims a control that the plan itself says cannot exist in the default enrollment path: the Portal claim page cannot show hostname/OS before approval because Headscale exposes no pending registrations. The only real control in flow A is a user-typed device name compared after the node already exists. The threat model therefore overstates protection against device-code style phishing, and nothing binds a claim to an enrollment request the same user has just opened.

<details><summary>Evidence</summary>

T-06 mitigation: 'trang claim web-auth hiển thị hostname/OS + xác nhận tường minh'. §7.4: 'Headscale API không liệt kê được pending registration (UNSUPPORTED) nên Portal không hiển thị được hostname/OS trước khi phê duyệt — bù bằng bước đối chiếu sau đăng ký ở bước 8'. Step 6: 'user (đã đăng nhập) nhập tên thiết bị mong đợi và xác nhận; backend gọi AuthRegister(user, auth_id)'.

</details>

**Suggested fix.** Rewrite the T-06 row: 'Method A: a claim is accepted only if the same user has an open enrollment_requests row created in this Portal session within the last N minutes; one open request per user; claim rate limit; post-registration name match with immediate delete on mismatch; notification to user and admins. Method C only: the Headscale confirm page shows hostname, OS and machine-key fingerprint.' Add verification: 'claim of an auth_id without an open request is rejected; the mismatch path deletes the node and raises a security event'. Keep R-22 as the stated residual risk and repeat it in §7.4.

### COMP-09 — MEDIUM — §14.5, §14.6, §10.2, §11.3 steps 3 and 9, §6.3 tenant_instances

**Problem.** short_id is used for the compose project, network, container, DNS alias, admin-listener header and metrics path, but it is never defined and is not a column of tenant_instances. Public routing derives the upstream from the host label, which is the tenant slug, while the alias on the tenant network is hs-<short_id>. Unless short_id equals the slug, public routing cannot resolve the upstream; if it does equal the slug, instance-scoped names collide when a replacement instance of the same tenant is created (restore into a new instance, relocation on the same host), which the schema explicitly allows.

<details><summary>Evidence</summary>

§14.5: 'mg-t-<short_id> / mg-hs-<short_id> / alias hs-<short_id> trên network tenant'. §14.6 public listener: 'Nhãn host được kiểm bằng regex slug rồi ghép thành upstream hs-<label>:8080'. §10.2: 'a.<mesh_domain> → edge → hs-a:8080'. §11.3 step 3: 'control_hostname = <slug>.<mesh_domain>'. §6.3 tenant_instances has no short_id column and allows a new instance once the old one has status removed (partial UNIQUE(tenant_id)).

</details>

**Suggested fix.** Define in §6.3: 'tenant_instances.short_id: 12 lowercase base32 characters derived from the instance UUID, UNIQUE, immutable; used for project, network and container names and for the admin and metrics listeners'. For public routing add a second network alias hs-<slug> on the tenant network (uniqueness guaranteed by UNIQUE(control_hostname)), moved atomically to the new instance on relocation or restore. Update §10.2, §14.5, §14.6, the Agent spec validator regexes and the reconcile checks.

### COMP-10 — MEDIUM — §8.4 invariant 4, §8.5–§8.6 vs §13.2

**Problem.** The permission matrix and the endpoint catalogue disagree, and the 'exactly one x-permission per operation' invariant cannot express the matrix. PATCH /users/{id} carries three permissions depending on the body (tenant.user:manage, tenant.membership:assign, tenant.membership:assign_admin); POST /enrollment/requests carries tenant.enrollment:request or :issue_privileged depending on the body; own-resource and 2P variants are also per row. The matrix lists GET /billing, which is not in §13.2. Endpoints without any permission row: GET /enrollment/instructions, GET /policies/current, GET /tenants/{tenantId} for tenant roles, the job Location target /api/v1/jobs/{jobId}, /internal/prometheus/sd, auth/*. The generated authz matrix (IT-02, 100% of operations) therefore cannot be produced from the spec as described.

<details><summary>Evidence</summary>

§8.4: 'mỗi operation trong OpenAPI khai báo đúng một x-permission; … thiếu khai báo ⇒ fail build'. §8.6: 'tenant.membership:assign | PATCH /users/{id} đổi role ≤ Tenant Operator'; 'tenant.enrollment:issue_privileged | key gắn tag / reusable / ephemeral / cho người khác'; 'tenant.billing:read | GET /billing'. §13.1: 'Location: /api/v1/jobs/{jobId}'; §13.2 jobs: 'GET /tenants/{t}/jobs · GET /jobs/{jobId}'.

</details>

**Suggested fix.** Either split body-dependent operations (PUT /users/{id}/role, POST /users/{id}:transfer-ownership, POST /enrollment/keys for tagged, reusable, ephemeral or on-behalf keys) so that one operation = one permission, or define x-permission plus x-permission-rules (field-conditional, own-resource, 2P) and state that the generated matrix iterates over the rules. Add pseudo-permissions 'public' and 'authenticated'. Add the missing rows and endpoints (billing, instructions, policies/current, tenant read of own tenant, GET /platform/jobs/{id} or a tenant-less job read) and a CI check: every operationId appears in §8.5/§8.6 and every matrix row maps to an operationId.

### COMP-11 — MEDIUM — §13.2, §12.2–§12.3 vs §19 'API changes' and §20

**Problem.** Several catalogued endpoints and mapped admin functions are never scheduled, so a coding agent executing §20 in order would not build them. Endpoints in no phase: GET /tenants/{t}/dashboard, GET /tenants/{t}/relay, PUT /devices/{id}/tags, PATCH /tenants/{id}, :request-deletion, users write operations, /settings, /identity-provider, GET /platform/relay-regions, /platform/identity-providers, /platform/plans, /platform/audit. Screens with no task: Relay Regions, Security Events, Backups, tenant relay view. The CrowdSec unban button in the Platform Console has no endpoint, permission or task. Tenant Usage Monitoring is delivered only in Phase 6, after the MVP gate, without §12.3 saying so.

<details><summary>Evidence</summary>

Phase 2 API changes: 'auth/*, tenants (đọc + adopt), devices (đọc, rename, expire, delete, sync), users (đọc), audit, platform/instances, platform/health, jobs'. Phase 4: 'enrollment/*, policies/*, groups/*, routes/*, dns/*, resources/*, support-grants/*, platform/users, platform/settings'. Phase 6: 'usage/*, platform/backups, platform/security-events'. P4-T03: 'instances, hosts, health, jobs, settings, platform users, IdP'. §14.7: 'nút gỡ ban trong Platform Console'.

</details>

**Suggested fix.** Add two columns to the §13.2 table, 'Phase' and 'Task', and a column 'Task' to §12.2 and §12.3; fill every row. Add the missing work to existing or new tasks (for example P2-T13 += tags and dashboard API; P3-T04 += relay-regions read; P4-T03 += Relay Regions, Security Events and Backups screens; P4-T09 += users write, settings, identity-provider; P4-T13 += request-deletion; a new task for the CrowdSec decisions API with a permission row). Mark in §12.3 which Tenant Admin functions are post-MVP. Add a CI rule: every operationId in api/openapi.yaml carries an x-task annotation that exists in the task list.

### COMP-12 — MEDIUM — §6.1, §6.3, §6.4, §13.1 Idempotency, §19 migrations 0001–0016

**Problem.** Schema-to-migration gaps and one plaintext leak. (1) system_settings, one of the 18 required tables, is created by no migration. (2) 0001 'identity & RBAC' precedes 0002 'tenants…' although identity_providers and tenant_memberships reference tenants. (3) Idempotency replay stores the full response in idempotency_keys.response, and Idempotency-Key is mandatory for enrollment creation whose response contains the pre-auth key, so the key is stored in plaintext in a table without tenant_id or RLS, contradicting 'no plaintext pre-auth key'. (4) §6.1 says UUID primary keys, but permissions and system_settings use text keys without stating the exception. (5) Retention is given for jobs, audit and metrics only; usage_records, security_events, sessions, enrollment_requests, backups, idempotency_keys and removed cache rows have none. (6) identities (e-mail of every tenant's users) has no RLS and no stated compensating rule.

<details><summary>Evidence</summary>

Phase 2: '0001 identity & RBAC; 0002 tenants/hosts/instances/config versions; … 0006 jobs/idempotency'; Phase 3: 0007–0011; Phase 4: 0012–0015; Phase 6: 0016 usage_records. No migration names system_settings. §13.1: 'Idempotency-Key bắt buộc cho POST tạo tài nguyên/job (tenant, enrollment, …); lưu ở idempotency_keys, lặp lại trả cùng kết quả'. §6.3: 'idempotency_keys | … request_hash, response jsonb'; enrollment_requests: 'Không lưu plaintext pre-auth key/Auth ID'. §6.3 identities RLS: '— (truy cập qua membership)'.

</details>

**Suggested fix.** Add system_settings to a named migration and publish one table mapping every table of §6.3 to a migration number. Reorder to 0001 tenants/hosts/instances, 0002 identity & RBAC (or keep the order and add the foreign keys in 0002). Idempotency: persist only status code, resource id and a redacted body; fields marked x-secret in OpenAPI are never stored and a replay returns the resource without the secret plus code secret_not_replayable; add tenant_id to idempotency_keys. State the primary-key exceptions in §6.1. Extend §6.4 with a retention value and sweeper for each listed table. For identities either add RLS through a membership join or document the repository rule and a test.

### COMP-13 — MEDIUM — §11.2 flowchart node R, §11.3 step 19, §4.2 modules, §18.1 T-03/T-04/T-06/T-08, R-11, R-22

**Problem.** Notifications are the brief's last provisioning step and a mitigation in at least five threats, but no notification component exists: no module in §4.2, no job kind in §13.5, no table, no template or channel decision, no task in §20, and SMTP is optional. The flowchart ends with 'send enrollment instructions to the Tenant Owner' but the 19-step table ends at activate with a one-word 'thông báo' and no executor, idempotency or failure rule. The flowchart also omits idp.ensure, so the two artefacts disagree.

<details><summary>Evidence</summary>

§11.2: 'Q --> R[gửi hướng dẫn enrollment cho Tenant Owner]'. §11.3 step 19: 'tenants.status=active, tenant_instances.status=running; audit; thông báo'. T-03: 'thông báo node mới cho tenant'; T-04: 'thông báo cho Owner'; T-06: 'thông báo thiết bị mới'; T-08: 'audit + thông báo'. §15.2: '(tùy chọn) SMTP'. §4.2 lists no notification module.

</details>

**Suggested fix.** Add module notifications (interface Notifier; outbox table notification_outbox(id, tenant_id, recipient_membership_id, kind, payload, status, attempts, sent_at) written in the same transaction as the triggering event; channels: e-mail via SMTP and an in-Portal inbox; vi/en templates) and job kind notification.send. Add step 20 owner.onboard to §11.3 (Worker; idempotency key tenant:<id>:onboard; failure does not roll back activation but raises an alert) and add idp.ensure to the flowchart. List the event kinds (device enrolled, policy applied, route approved, support grant requested or used, break-glass, tenant suspended). Add tasks in Phase 3 (outbox + owner onboarding) and Phase 4 (security notifications) and a test for each mitigation that cites a notification.

### COMP-14 — MEDIUM — §17.1, §17.3, §17.4, §7.2

**Problem.** The failure analysis covers SQLite corruption and 'PostgreSQL stopped' but not PostgreSQL corruption or restore to an older point, although the MVP RPO for PostgreSQL is 24 hours and PostgreSQL is the source of truth for policy versions, SecretStore ciphertext (API keys, tenant DEKs), sessions and support grants. After such a restore, tenants provisioned inside the lost window run on disk but are absent from the registry, rotated API keys are gone, the newest policy versions are missing while Headscale holds a newer policy, and revoked support grants or sessions can come back. §17.2 defines post-restore reconciliation only for a tenant restore.

<details><summary>Evidence</summary>

§17.1: 'MVP: logical dump nén mỗi đêm'. §17.3: 'PostgreSQL | 24 giờ (MVP)'. §17.4: 'PostgreSQL ngừng | Portal/API ngừng; Headscale vẫn phục vụ client | … | Restart / restore'. §7.2: 'Nguồn sự thật là PostgreSQL (policy_versions)'. §17.2 step 4 applies only to instance.restore.

</details>

**Suggested fix.** Add a row 'PostgreSQL corrupted / restored to an older point' to §17.4 and a section §17.2b 'Post-restore reconciliation for PostgreSQL': (1) Agent inventory of instances on disk versus registry, adopt or quarantine orphans; (2) per instance compare GetPolicy sha256 with the restored applied version and import the live policy as a new version kind=recovered, never auto-apply an older one; (3) test each stored API key and re-bootstrap through the Agent when it fails; (4) invalidate all sessions and all support grants created before the restore point; (5) full inventory sync; (6) write an audit gap marker. Move WAL archiving from Phase 6 to Phase 3, or record the 24 h window as an accepted risk in §23, and add a DR test for this scenario.

### COMP-15 — MEDIUM — §3.5 SPOF table, §5.3 shared components, §14.6, §17.6, §11.4 Reconcile

**Problem.** Rule XIX.18 requires every single point of failure to be named. §3.5 and §5.3 omit several that the design creates: the single wildcard certificate and private key for all tenants together with the DNS provider and ACME CA it depends on; the KEK file (one key protecting every tenant's secrets); the single Host Agent and single Worker (backups, API-key rotation, reconcile and provisioning stop); the Docker daemon. One failure mode is also unhandled: tenant networks are attached to the running edge container at runtime, so recreating the edge (image upgrade per §17.6) drops every tenant attachment and all tenants stay unreachable until the periodic reconcile re-attaches them one by one.

<details><summary>Evidence</summary>

§3.5 rows: 'Host duy nhất', 'Edge (Caddy)', 'Headscale của từng tenant', 'Một relay mỗi tenant', 'PostgreSQL', 'IdP', 'Một địa chỉ IP công khai'. ADR-09: 'Một chứng chỉ cho mọi tenant'. §7.6: 'KEK | File trên host + bản sao offline'. §14.6: 'Thêm tenant không reload Caddy: chỉ cần attach edge vào network tenant'. §17.6: 'Edge/IdP/monitoring: pin digest, nâng từng thành phần'. §11.4 Reconcile: 'tự sửa … attach lại edge'.

</details>

**Suggested fix.** Add rows to §3.5 and §5.3: 'Wildcard certificate + DNS provider/ACME' (impact: all tenant control URLs; handling: renewal alert at 21 days, backup of ACME data, documented re-issue), 'KEK' (impact: SecretStore of all tenants), 'Host Agent / Worker' (impact: no lifecycle jobs or backups; running tenants unaffected), 'Docker daemon' (handling: live-restore). Add to §11.4 an edge.reattach_all flow: the Agent subscribes to Docker events for the edge container, re-attaches all running tenant networks immediately on start, then runs edge.verify per tenant. Define the edge upgrade runbook in §17.6 with the measured re-attach time for N tenants and an alert 'edge networks < running instances'. Add the measurement to P1-T10.

### COMP-16 — MEDIUM — §14 intro, §15.3 Path C, ADR-24, D-5, §19 Phase 6/7, §5.5

**Problem.** The brief asks for dev/staging before production, but the plan never defines the environments. The LAN host is called dev/staging and 'not for production', production is said to follow Path C or multi-host, yet G6 is the production go-live decision, multi-host starts only in Phase 7 after G6, and no task provisions a production host, cuts over DNS or migrates tenants. Per-environment domains, secrets, config and promotion rules are absent; the root compose.yaml 'local dev environment' is one line. §5.5 also makes multi-host placement and moving PostgreSQL off the tenant host prerequisites for the 100-tenant tier, while P6-T08 load-tests 100 tenants before any multi-host work.

<details><summary>Evidence</summary>

§14: 'dùng cho Development/Staging trước production'. D-5: 'Chấp nhận, không dùng cho production'. ADR-24: 'production đi theo Path C/multi-host'. G6: 'Quyết định go-live production'. P7-T01: 'Multi-host … | G6'. §4.4: 'compose.yaml # môi trường dev cục bộ'. §5.5 100-tenant row: 'Multi-host placement; tách PostgreSQL khỏi host tenant'; P6-T08: 'Load/scale test 10 → 100 tenant'.

</details>

**Suggested fix.** Add §14.0 'Environments': a table of dev (developer machine, root compose.yaml: postgres, one Headscale, real seed data, containerised clients), staging (the LAN host) and production (Path C host), each with domains, secret source, data policy, who may deploy and the promotion rule (same image digests and versions.lock; staging gate evidence required). Add Phase 6 tasks: 'Provision production host with the Phase 1 runbook', 'DNS/TLS for production domains', 'Restore drill onto the production host', 'Go-live cut-over and rollback'. State in G6 on which host production runs and reconcile D-5, ADR-24 and the §5.5 tier prerequisites with the Phase 6/7 ordering.

### COMP-17 — MEDIUM — §18.1 T-10/T-11, §13.1 rate limiting, §14.6, EG-11, §4.3 edge build, P5-T09

**Problem.** Two threats rely on rate and connection limits at the edge, but the plan's own research says Caddy needs an unofficial plugin for rate limiting and the edge build contains only the DNS and CrowdSec modules, so the control has no mechanism. More generally §18.1 does not say which mitigations exist at MVP: UDP rate limiting, host hardening, off-host audit copies, image signing, SBOM and scan gates, chaos and load tests are Phase 6 tasks, yet P5-T09 verifies the T-01…T-18 checklist with 'no High findings' before they exist. Some mitigations have no task at all (admin-origin IP restriction, CAA and registrar lock, DNS record monitoring, tabletop exercise, 'routers must be tagged nodes').

<details><summary>Evidence</summary>

EG-11: 'Rate limiting ở Caddy cần plugin không chính thức'. §4.3: 'Caddy build bằng xcaddy (module DNS provider + CrowdSec bouncer, pin version)'. T-11: 'Rate/connection limit theo IP và theo hostname tenant ở edge'. T-10: 'giới hạn kết nối ở edge; rate-limit UDP STUN bằng nftables'. §13.1: 'cộng thêm giới hạn ở edge'. P6-T07: 'quy tắc DOCKER-USER/nftables'. P5-T09: 'checklist T-01…T-18 | Không lỗi Cao'.

</details>

**Suggested fix.** Decide the mechanism and record it in ADR-08: either add a pinned, reviewed rate-limit module to the xcaddy manifest (with a supply-chain note in T-13) or implement per-source limits in nftables for TCP 443 and UDP STUN, moved from P6-T07 to Phase 1. Add to §18.1 two columns, 'Available from phase' and 'Task', for every mitigation and verification; create tasks for those that have none or delete them. Change P5-T09 to 'verify all mitigations tagged MVP' and add a Phase 6 task 're-verify T-01…T-18 including Phase 6 mitigations' as part of G6.

### COMP-18 — MEDIUM — §22.4 (V-01…V-15), §25.1 item 3, §19 Phase 5 DoD

**Problem.** Build Mode is told to run the §22.4 test for every REQUIRES VALIDATION label, but §22.4 lists only 'key' items, so several labels have no test, task or gate: ID-04 (nodes of a user disabled at the IdP), §10.4 single STUN endpoint and NAT detection, §15.3 Path B source-IP preservation, §7.3 CheckPolicy coverage of via and autogroup:self, §10.6 measurability of concurrent relay connections, EG-10 IPv6 through published ports, CL-13 peer relays. Three listed items have a gate but no task: V-11 (Noise key change / old restore), V-14 (CrowdSec and tenant NAT), V-15 (IdP realm scale). The Phase 5 DoD 'every MVP-relevant REQUIRES VALIDATION has a measured result' cannot be audited without a complete register.

<details><summary>Evidence</summary>

§25.1 item 3: 'Chỗ nào plan ghi REQUIRES VALIDATION thì phải chạy phép thử ở §22.4'. §22.4 title: 'các mục REQUIRES VALIDATION trọng yếu'. ID-04: 'REQUIRES VALIDATION (test offboarding)'. §10.4: 'Một STUN endpoint trên một IP có thể không đủ … — REQUIRES VALIDATION'. V-11: '… | G3/G6'; V-14: '… | G6'; V-15: '… | Trước mốc 100 tenant'; no Phase 3 or Phase 6 task names them.

</details>

**Suggested fix.** Turn §22.4 into the complete register: one row per REQUIRES VALIDATION label in the plan with columns ID | source fact | test | task | gate | MVP-relevant (yes/no) | result. Add rows V-16 ID-04 offboarding (disable the user at the IdP, observe the node until expiry; task next to P4-T09), V-17 single-STUN NAT detection (netcheck from a hard-NAT network; P5-T03), V-18 Path B source IP (only if Path B is chosen), V-19 CheckPolicy with via/autogroup:self (P4-T10), V-20 relay connection counting (P6-T01), V-21 IPv6 STUN (P1-T12). Add tasks for V-11 (P3-T11), V-14 (new Phase 6 task) and V-15 (P6-T08). Add a docs check that fails when a REQUIRES VALIDATION label has no register row.

### COMP-19 — MEDIUM — §2.8 Repository Assessment Matrix

**Problem.** The matrix has the required six columns but does not cover every feature the brief lists, and its Source column is mostly empty. Missing rows: 'Headscale version compatibility' for Repository 1, 'Network ports' for Repository 3, 'Security and maintenance risk' for Repository 4. Features merged into one row with a single verdict: authentication + RBAC; device + user management; relay configuration + custom domain + certificate handling; client verification + verify URL; container security + image update strategy; cluster architecture + cluster_id; load balancing + horizontal scaling; tenant isolation claims + database consistency + failover design (with the combined label 'REQUIRES VALIDATION / UNSUPPORTED'). In 25 of the 40 rows the Source cell holds only the evidence label and no file or document.

<details><summary>Evidence</summary>

Rows such as 'Embedded DERP/STUN (R1) | … | VERIFIED', 'Device / User Management (R2) | … | VERIFIED', 'Fail-open/fail-closed (upstream) | … | VERIFIED', 'Tenant isolation claims / DB consistency / Failover (R4) | Không kiểm chứng được | Không | — | Cao | REQUIRES VALIDATION / UNSUPPORTED'. Version compatibility of Repository 1 appears only in §2.1 ('Pin v0.29.0 …').

</details>

**Suggested fix.** Add the three missing rows, for example: 'Headscale version compatibility (R1) | pinned v0.29.0, config valid on 0.29.7 | Yes after bump | pin digest of 0.29.7 | Medium | VERIFIED [R1:compose.yaml], [HS:CHANGELOG.md]'; 'Network ports (R3/upstream) | TCP 443/80, UDP 3478, DERPPort/STUNPort overrides | Yes (upstream) | per-tenant IP/port plan | Medium | VERIFIED [TS:cmd/derper/derper.go], [TS:tailcfg/derpmap.go]'; 'Security and maintenance risk (R4) | no source, no licence, single commit day, v0.26-based | No | — | Critical | VERIFIED [R4:README.md] + repository metadata'. Split merged rows so each brief feature has its own label. Put a concrete source reference in every Source cell, keeping the evidence label as a prefix.

### COMP-20 — MEDIUM — §13.3 schemas, §6.3 jsonb and status columns, §7.2, §12.2 quota

**Problem.** The brief asks for request/response schemas; the plan gives eight abbreviated ones and defers the rest to a file that does not exist yet. The gaps that force design work onto the builder: the structured policy model (PolicyVersion.source), from which render, form editor, structured diff and lint all derive; the keys of tenants.settings (4-eyes, self-enroll, node expiry, identity mode, allow-list, DNS); the keys of subscription_plans.limits and subscriptions.overrides, that is, which quotas exist for 'manage quota' and QuotaChecker; the list of usage_records.metric values; the status enums and transitions of tenant_instances and enrollment_requests.

<details><summary>Evidence</summary>

§13.3: 'Schema tiêu biểu (rút gọn; bản đầy đủ nằm trong api/openapi.yaml)'; 'PolicyVersion: {id, version, kind, state, sha256, source, rendered_hujson, …}'. §7.2: 'Render tất định từ mô hình có cấu trúc sang HuJSON'. §6.3: 'tenants … settings jsonb'; 'plans(id, key, name, limits jsonb, is_active)'; 'usage_records … metric'; tenant_instances status (only removed and running appear anywhere in the plan); enrollment_requests status.

</details>

**Suggested fix.** Add to §13.3: PolicySource {rules[{id, src{users[], groups[], tags[], autogroups[]}, dst{resources[], hosts[], tags[], autogroups[]}, ip[proto:port], via[]}], tag_catalog[], ssh[]}; TenantSettings {policy_four_eyes, route_four_eyes, self_enroll, node_expiry_days, identity_mode, edge_allowlist_cidrs[], dns{magic_dns, nameservers[], split{}, search_domains[]}}; PlanLimits {max_devices, max_users, max_groups, max_active_preauth_keys, max_subnet_routers, backup_interval_minutes, features[]}; UsageMetric enum (devices_registered, devices_online_peak, users_active, enrollment_keys_issued, relay_bytes_approx). Add status enums with a transition table for tenant_instances and enrollment_requests. Mark each as normative input for P2-T02, P4-T06 and P4-T10.

### COMP-21 — MEDIUM — §11.5 InfrastructureDriver vs §11.3 steps 7–14, §11.4, P3-T03

**Problem.** The driver interface, which the brief singles out as the abstraction for future VM and Kubernetes provisioners, lacks operations that the step table assigns to the Agent: bootstrap policy through the in-container CLI (step 12), detach the edge (compensation of step 14), separate network creation before the instance starts (step 9), image upgrade, and the inspections reconcile needs (network members, file ownership, digests). EnsureInstance bundles storage, files, network and container although steps 7–10 have separate idempotency and compensation rules. P3-T03 already lists 'policy bootstrap via CLI' as an Agent operation that the interface does not contain.

<details><summary>Evidence</summary>

§11.5 methods: HostInfo, ValidateConfig, EnsureInstance ('idempotent: storage, file, network, container'), InstanceStatus, StartInstance, StopInstance, RestartInstance, RemoveInstance, WriteRuntimeFile, BootstrapAPIKey, Backup, Restore, EnsureEdgeAttachment. §11.3 step 12: 'policy.bootstrap | Agent | chạy CLI trong container'; step 14 compensation: 'detach'; step 9: 'network.ensure | Agent'. P3-T03: 'ValidateConfig …, policy bootstrap qua CLI, BootstrapAPIKey, EnsureEdgeAttachment'.

</details>

**Suggested fix.** Extend §11.5 with: BootstrapPolicy(ctx, id, hujson []byte) (sha256 string, err error); RemoveEdgeAttachment(ctx, id); EnsureStorage / EnsureNetwork / EnsureContainer (or keep EnsureInstance but return per-phase status and accept a stop-after-phase option matching steps 7–10); UpgradeInstance(ctx, id, imageDigest); Inspect(ctx, id) returning network members, image digest, config sha256, file owner/mode and Noise key fingerprint. Add a table 'step → driver method → compensation method' and one sentence per method on how a Kubernetes or VM driver would satisfy it.

### COMP-22 — LOW — §4.2, §3.4, §4.4, §13.6

**Problem.** The brief names thirteen backend modules including billing and configuration. §4.2 has usage instead of billing and no configuration module (only an undocumented config directory in §4.4), while the dependency table in §13.6 uses a different vocabulary (tenant, device, policy, billing, configuration) and omits rules for authz, secrets, store, jobs, httpapi, platform and usage. The architecture lint that is supposed to enforce these rules in CI cannot be written from inconsistent names.

<details><summary>Evidence</summary>

§13.6: 'identity | audit, configuration'; 'tenant | identity, audit, billing (quota)'; 'relay, monitoring, billing | tenant'. §4.2 module list: identity, authz, tenants, platform, headscale, provisioning, devices, enrollment, policies, network, relay, usage, audit, secrets, monitoring, store, jobs, httpapi.

</details>

**Suggested fix.** Publish one canonical module table (name, brief module it implements, responsibility, allowed dependencies, forbidden dependencies) and use those names in §3.4, §4.2, §4.4 and §13.6. State explicitly 'usage implements the brief billing module until invoicing in P7-T08' or rename it billing, and define configuration (system_settings, tenant settings, runtime config loading). Add a dependency row for every module.

### COMP-23 — LOW — Conventions (evidence labels), Appendix C, §2.4, CL-15

**Problem.** VERIFIED is defined as read directly in the cited source during this session, but it is also applied to facts relayed by research sub-agents and to Tailscale documentation read through a summarising tool, including the Terms of Service text behind the top business risk R-01. The full evidence log (837 claims with quotes and URLs) lives only in a session log, and the plan carries only the §2 tables into docs, so the builder cannot audit a label. My spot-checks of about ten load-bearing Headscale facts against the pinned tag all held (auth/register and policy/check routes, embedded DERP fail-closed, node.expiry 0, allow-all and deny-all semantics, pre-auth key defaults, upgrade backup guidance), so this is a traceability issue, not an accuracy finding.

<details><summary>Evidence</summary>

Conventions: 'VERIFIED | Đã đọc trực tiếp trong mã nguồn/tài liệu được trích dẫn'. Appendix C: 'đọc ngày 2026-11-16 (qua công cụ tóm lược ⇒ trích dẫn không nguyên văn từng byte)'. §2.4: 'VERIFIED (issue/discussion upstream do agent trích dẫn)'. Appendix C: 'Bản ghi đầy đủ từng nhận định … nằm trong nhật ký phiên nghiên cứu'. CL-15: 'VERIFIED (văn bản)'.

</details>

**Suggested fix.** Add a qualifier to the label table: 'VERIFIED (direct)' versus 'VERIFIED (agent-reported)', and label anything read through a summariser as REQUIRES VALIDATION until re-read verbatim (at least CL-15 and the other [DOC:tailscale.com/docs] facts). Add to P0-T01 the output docs/architecture/research-evidence.md containing the per-claim quote and URL log, and a Phase 0 task 're-read the facts that gates G1–G3 depend on and record file and line for each'.

### COMP-24 — LOW — §7.5 classification, §7.3 state machine, §20 P7-T07

**Problem.** The brief's classification label 'Phase 2' is reused for time-bound access, just-in-time access and SSH check mode, but in this plan Phase 2 is the SaaS Backend phase; the work is actually scheduled in Phase 7 together with Enterprise items (JIT and time-bound) or nowhere (SSH check mode). A builder can read §7.5 as a Phase 2 commitment. Separately, the brief says policies must be reviewed, but review is optional per tenant and off by default: a validated version becomes approved with no reviewer.

<details><summary>Evidence</summary>

§7.5: 'Time-bound access | Phase 2', 'Just-in-time access | Phase 2', 'Tailscale SSH (check mode) | Phase 2 (opt-in)'. P7-T07: 'Application ZTNA extensions: JIT/time-bound; thiết kế gateway'. §7.3: 'validated --> approved: tenant không bật 4-eyes'.

</details>

**Suggested fix.** Rename the middle class to 'Post-MVP (second wave)' and add a column 'Roadmap task' (JIT and time-bound: a dedicated task separate from the gateway design; SSH check mode: add a task or move it to Enterprise Extension). Make review a mandatory step with two modes: 'peer review' (default when the tenant has two or more users holding tenant.policy:approve) and 'self review' (single-admin tenants: explicit acknowledgement of the rendered diff, recorded with review_mode = self); show the mode in the audit event.

### COMP-25 — LOW — §19 Phase 7 and G5, §20 P1-T01/P1-T05, Appendix A, Appendix B, §15.1–§15.2

**Problem.** Smaller completeness defects. (1) Phase 7 merges unit, integration and E2E tests into one row with no content beyond 'per feature', so three of the seventeen attributes are undefined. (2) G5 lets any of the 20 criteria be waived by written exception, including isolation ones. (3) P1-T05 (certificate, verified with openssl s_client) depends only on the edge image but needs the running edge of P1-T06. (4) P1-T01 is done when all 18 checklist items are recorded, but items 13–14 are only allowed after ports are opened, and item 14 probes /health, which the edge allow-list blocks. (5) Appendix A.1 does not list the host LAN address/subnet, default gateway or whether the LAN resolver blocks public names that resolve to private addresses, all needed by §14.1 and §15.3. (6) Appendix B gives no target file for §11, §12, §16, §23 and has no docs/operations entry. (7) The port matrix shows 'TCP nội bộ' instead of port numbers for the edge admin and metrics listeners, api and idp, and §15.2 has no row for crowdsec, postgres, web or build-time egress (registry, module proxy, NTP).

<details><summary>Evidence</summary>

Phase 7: 'Unit / Integration / E2E tests | Theo từng tính năng; scale validation tới 1.000 tenant (mô phỏng)'. G5: '20/20 AC đạt hoặc có ngoại lệ được người dùng chấp nhận bằng văn bản'. P1-T05 depends on 'P1-T04, domain'. P1-T01: 'Đủ 18 hạng mục A.2'; A.2 #14: 'curl -sI https://<host>/health … chỉ thực hiện sau khi được phép mở cổng'; §14.6: 'mọi path khác ⇒ 404 (gồm … /health)'. §15.1: 'edge listener admin | TCP nội bộ'.

</details>

**Suggested fix.** (1) Split the Phase 7 row into three and name at least the tests for P7-T01, T02, T04 and T09. (2) Restrict G5 exceptions to environment-dependent criteria (AC-15 and the Internet part of AC-16) and state that AC-05–07, 12–14, 19 and 20 cannot be waived. (3) Make P1-T05 depend on P1-T06. (4) Change P1-T01 to 'items 1–12 and 15–18; items 13–14 are completed in P1-T14' and probe /key instead of /health. (5) Add A.1 rows for LAN address/subnet/gateway and resolver rebinding behaviour. (6) Map §11 and §12 to system-design.md, §16 to docs/operations/monitoring.md, §23 to docs/planning/risks.md. (7) Assign fixed port numbers and add the missing §15.2 rows.

## UPSTREAM FACT-CHECK (HEADSCALE v0.29.7)

**Verdict:** The Headscale research is mostly accurate: I re-read hscontrol/app.go, noise.go, handlers.go, grpcv1.go, state/state.go, auth.go, oidc.go, debug.go, types/config.go, policy/v2/{policy,types,filter}.go, derp/server/derp_server.go, db/{policy,api_key,preauth_keys,users,versioncheck}.go, cmd/headscale/cli/*, proto/, config-example.yaml, CHANGELOG and the cited docs at tag v0.29.7, and the isolation-critical semantics (allow-all vs deny-all, database-mode SetPolicy and CLI 'policy set', in-process fail-closed DERP verify, STUN port derivation, route surface, version enforcement) hold. No critical finding. Two high findings would bite immediately: every public '/key' probe in the plan returns HTTP 400 as written (provisioning step 18 and the Critical alert), and 'node.expiry' is only a default that a client can override, so the plan's key-lifetime control is not enforced. Beyond that there are ten medium gaps where an upstream behaviour the plan did not use breaks or weakens a designed mechanism (policy-lint bypass through decoder leniency, self-tagging via --advertise-tags, silent fail-open config parsing, a probable panic in AuthRegister, HTTP 500 for domain errors versus the circuit breaker, configtest needing the IdP, no route for adapter Version(), restore version rule, silent fresh-state start, boot-fatal ambiguous user tokens), and several rows labelled VERIFIED that the source does not support (PL-15, the 'no defaults in code' claim in section 10.1, HS-11/HS-12 defaults, ID-08, HS-19 ephemeral timeout, HS-22). Findings marked 'by code reading' could not be executed and must be confirmed in the contract-test suite.

**Strengths noted:**

- Core policy semantics are right and source-backed: no policy or a policy without acls/grants is allow-all, explicit empty arrays are deny-all, SetPolicy works only in database mode, CheckPolicy is a dry run against live users and nodes. PL-06 (empty policy stored, allow-all after restart) is confirmed by db/policy.go and can be relabelled VERIFIED.
- The edge allow-list is protocol-complete: all /machine/* control RPCs (register, map, ssh/action) run inside the Noise tunnel, so only /ts2021, /key, HEAD /machine/ping-response, /derp*, /bootstrap-dns, /register/*, /auth/* and the OIDC paths are needed; blocking /api, /swagger, /verify, /health and /version breaks no client.
- Embedded DERP facts hold: verification is an in-process RoundTripper with SetVerifyClientURLFailOpen(false), so blocking /verify at the edge cannot affect it (V-05 is answered by source), and the advertised STUN port comes from stun_listen_addr (RT-14).
- Runtime-surface rows RT-01, RT-05, RT-08, RT-09 and RT-10 match the code: gRPC TCP only with TLS or allow_insecure, unauthenticated Unix socket behind the REST gateway, ko/distroless root image, capability floor 113 with HTTP 400, enforced one-minor upgrade path.
- The provisioner's CLI commands exist as written (policy set --file, policy get, apikeys create -e, health) and the REST catalogue in HS-13/HS-14 matches the proto, including the query-only parameters of ExpireNode, RegisterNode and DeletePreAuthKey and the expiry/disable_expiry semantics.

### HS-FC-01 — HIGH — §11.3 step 18 (edge.verify); §16.1 blackbox_exporter row; §16.2; §16.3 alert; Appendix A.2 #14

**Problem.** Every public liveness check calls a bare 'GET /key' and expects 200, and A.2 #14 uses 'curl -sI https://<host>/health'. In v0.29.7 '/key' requires the client capability version as query parameter and returns HTTP 400 without it (or below the floor, capver 113). '/health' is registered for GET only (HEAD would be 405) and is 404'd by the plan's own allow-list in §14.6. As written, edge.verify fails for every tenant (the job runs compensation, so no tenant can ever reach 'active') and the Critical alert 'probe /key fail > 2 phút' fires permanently for all tenants.

<details><summary>Evidence</summary>

Plan §11.3 #18: 'qua đường public: `GET /key` trả 200'; §16.1: 'blackbox_exporter | HTTPS `https://<slug>.<mesh_domain>/key`'; §16.3: 'probe `/key` fail > 2 phút | Critical'; A.2 #14: 'curl -sI https://<host>/health'. Upstream hscontrol/handlers.go parseCapabilityVersion: 'if clientCapabilityStr == "" { return 0, NewHTTPError(http.StatusBadRequest, "capability version must be set", nil) }' and KeyHandler: 'if !isSupportedVersion(capVer) { ... http.StatusBadRequest, "unsupported client version" }'; hscontrol/capver/capver_generated.go: 'MinSupportedCapabilityVersion = 113'; CHANGELOG 0.29.3: 'Reject /key requests below the supported capability version floor'; hscontrol/app.go: 'r.Get("/health", h.HealthHandler)'.

</details>

**Suggested fix.** Replace all occurrences with 'GET https://<slug>.<mesh_domain>/key?v=<capver>' and assert 200 plus a JSON body containing 'publicKey'. Keep <capver> in versions.lock (>= 113 for 0.29.x; upstream main raises the floor to v1.84 = capver 116 for 0.30). In step 18 also compare the returned publicKey with tenant_instances.noise_key_fingerprint. blackbox module: add fail_if_body_not_matches_regexp ['publicKey']. Replace A.2 #14 with: curl -s -o /dev/null -w '%{http_code}' 'https://<host>/key?v=113' (no -I). Add to the edge test suite the negative assertion 'bare /key returns 400 and is not an outage'.

### HS-FC-02 — HIGH — §2.5 HS-19; §7.1 (Device-level authorization); §7.4 'Vòng đời khóa'; §25.4 D-4

**Problem.** The plan treats node.expiry as an enforced maximum key lifetime. Upstream it is only a default applied when the client did not request an expiry; a client-supplied RegisterRequest.Expiry wins on every registration path (web auth approved through AuthRegister, pre-auth key, OIDC unless use_expiry_from_token), bounded only by year <= 9999. The official client sends a zero expiry on first login, but a modified or tsnet-based client enrolled through Flow A or B obtains a practically non-expiring node key. This contradicts the plan's claims that key lifetime is controlled and that no long-lived credential exists, and nothing in the design detects it.

<details><summary>Evidence</summary>

Plan §7.1: 'có hạn key (`node.expiry` đặt tường minh)'; §7.4: 'không tồn tại enrollment credential quyền cao vô thời hạn'. Upstream config-example.yaml (node.expiry comment): 'This is the base default. ... If a client explicitly requests a specific expiry, the client value is used.' hscontrol/state/state.go createNewNodeFromAuth: 'Expiry: cmp.Or(expiry, regData.Expiry)'; createAndSaveNewNode: 'needsDefaultExpiry := !nodeToRegister.IsTagged() && (nodeToRegister.Expiry == nil || nodeToRegister.Expiry.IsZero()) && s.cfg.Node.Expiry > 0'; HandleNodeFromPreAuthKey: 'User-owned nodes update expiry from the client request, falling back to the configured default'; hscontrol/auth.go registrationDataFromRequest: 'if !req.Expiry.IsZero() { ... regData.Expiry = &expiry }'; types.ValidateExpiry only rejects years outside 0..9999.

</details>

**Suggested fix.** Add a platform-side clamp to §7.4 and to the acceptance tests: after every registration (the Node returned by AuthRegister, and inventory.sync for pre-auth and OIDC nodes), for user-owned nodes, if expiry is null or greater than registered_at + tenant.node_expiry + 5 min, call POST /api/v1/node/{id}/expire?expiry=<registered_at + tenant.node_expiry> and write security_event(kind=expiry_overridden). Run the same check on every inventory.sync. Add a contract test that registers with a custom RegisterRequest.Expiry against the pinned image and asserts the clamp. Amend HS-19 with the missing upstream sentence, and restrict disable_expiry in ExpireNode to an Owner-only permission.

### HS-FC-03 — MEDIUM — §7.2 guardrail lint L1-L10 (admin-authored HuJSON)

**Problem.** The lints are specified against the policy text, but Headscale's decoder is more lenient than a plain JSON reading: (a) member names are matched case-insensitively; (b) every member whose name starts with '#' is stripped at any depth (except inside 'app') before decoding; (c) by decoder semantics '"grants": null' leaves the slice nil, which is the allow-all condition. Consequences: L1 ('thiếu khóa grants') passes for {"grants": null} while the result is allow-all; L4/L5/L7/L10 can be bypassed with case-variant duplicate members inside a rule, for example '"dst": ["tag:x"], "Dst": ["*"]'. L3 only covers top-level keys.

<details><summary>Evidence</summary>

Upstream hscontrol/policy/v2/types.go: 'var policyJSONOpts = []json.Options{ json.DefaultOptionsV2(), json.MatchCaseInsensitiveNames(true), json.RejectUnknownMembers(true) }'; 'stripMetadataMembers removes every object member whose name starts with '#' from the policy AST'; CHANGELOG 0.29.4: 'Fix `#`-prefixed metadata fields being rejected outside `acls`'; filter.go: 'if pol == nil || (pol.ACLs == nil && pol.Grants == nil) { return tailcfg.FilterAllowAll }'. Plan §7.2: 'L1 | Thiếu khóa `grants` ... | Chặn', 'L3 | Khóa top-level ngoài 11 khóa hợp lệ'. The null case is by decoder semantics and needs the contract test.

</details>

**Suggested fix.** Never send user-supplied text. Pipeline: parse the HuJSON into the typed model, reject (1) any member name that is not the exact canonical spelling at every depth, (2) any '#'-prefixed member, (3) null for grants/acls/ssh/tagOwners, (4) case-variant duplicates; then re-render canonical JSON from the model, run L1-L10 on the model, and send only the re-rendered text (store its sha256). Add one contract test per case against the pinned image ('Grants' vs 'grants', '#grants', 'grants: null') so a decoder change in a later version is detected.

### HS-FC-04 — MEDIUM — §7.4 Flow A step 8; §7.2 row 'tagOwners'; §13.2 users DELETE (offboard)

**Problem.** Web-auth registration honours 'tailscale up --advertise-tags'. When the Headscale user passed to AuthRegister owns the tag (directly or through a group in tagOwners), the result is a tagged node: no owning user, key expiry disabled, and not returned by ListNodes(user). Step 8 only compares the node name, and offboarding expires only 'nodes of the Headscale user', so such nodes survive offboarding indefinitely. The plan says only the platform assigns tags but never states that tagOwners owner lists must be empty and has no lint for it.

<details><summary>Evidence</summary>

Upstream docs/ref/registration.md (Tagged devices, web authentication): 'tailscale up --login-server <URL> --advertise-tags tag:<TAG>' ... 'Headscale checks that <USER> is allowed to register a node with the specified tag(s) and then transfers ownership of the new node to the special user tagged-devices'. hscontrol/state/state.go createAndSaveNewNode: 'Process RequestTags (from tailscale up --advertise-tags) ONLY for non-PreAuthKey registrations' ... 'Tagged nodes have key expiry disabled. nodeToRegister.Expiry = nil'; policy/v2/policy.go NodeCanHaveTag falls back to 'pm.userMatchesOwner(node.User(), owner)'. Plan §7.4 step 8: 'Backend đối chiếu tên node trả về với tên user đã nhập'.

</details>

**Suggested fix.** (1) The renderer emits every tag as '"tag:x": []'; add lint L11: a non-empty owner list in tagOwners is blocked unless the Owner confirms with a reason. (2) Step 8 must verify on the returned Node: user.name equals the expected mg-<id>, tags is empty, register_method is CLI, expiry is within the cap of HS-FC-02; otherwise DeleteNode plus security_event. (3) Offboarding uses device_inventory_cache.enrollment_request_id / owner_membership_id (who enrolled the device) rather than the Headscale user, so tagged nodes enrolled by that member are also expired or flagged.

### HS-FC-05 — MEDIUM — §11.3 step 8 (config.render); §14.5 config table; RT-07

**Problem.** Several config values fail open silently and are not caught by 'headscale configtest': a malformed node.expiry logs a warning and becomes 'no expiry'; an unknown policy.mode loads no policy (allow-all) without error; an invalid log.level becomes debug; prefixes outside the CGNAT/ULA ranges only print a banner. The plan relies on 'validator của ta + configtest' but does not list these, so a renderer bug in the duration format silently removes key expiry for a tenant.

<details><summary>Evidence</summary>

Upstream hscontrol/types/config.go resolveNodeExpiry: 'log.Warn().Str("value", value).Msg("failed to parse node.expiry, defaulting to no expiry"); return 0'; logConfig: 'if err != nil { logLevel = zerolog.DebugLevel }'; 'PolicyModeDB = "database"' with no validation of other values; hscontrol/db/policy.go PolicyBytes ends with 'return nil, nil' for any other mode; prefixV4/prefixV6 only trigger warnBanner. cmd/headscale/cli/configtest.go only calls newHeadscaleServerWithConfig().

</details>

**Suggested fix.** Add explicit validator rules to §11.3 step 8: node.expiry must match the Prometheus duration grammar and be > 0 (render from integer days as '<n>d'); policy.mode must equal exactly 'database'; log.level in {info, warn, error}; prefixes must be subsets of 100.64.0.0/10 and fd7a:115c:a1e0::/48. After start, the Agent scans the container log for 'failed to parse node.expiry' and the warning banner and fails the health gate. Add a contract test: register a pre-auth node on the rendered config and assert expiry is approximately now + TTL.

### HS-FC-06 — MEDIUM — §7.4 fallback ('để user dán Auth ID vào Portal'); §13.2 POST /enrollment/web-auth:claim; §7.5 Tailscale SSH check mode

**Problem.** By code reading (not executed): AuthRegister with an auth ID that belongs to an SSH-check session panics. Registration and SSH-check sessions share one cache; HandleNodeFromAuthPath calls RegistrationData() without an IsRegistration() guard, RegistrationData() panics for non-registration entries, and the local gRPC server behind the REST gateway has no recovery interceptor. Because the Portal forwards user-supplied Auth IDs to AuthRegister, a tenant member covered by an SSH 'check' rule could crash-restart that tenant's Headscale (control plane, embedded DERP and STUN go down, pending registrations are lost). Scope is one tenant, and only when SSH check mode is enabled.

<details><summary>Evidence</summary>

Upstream hscontrol/state/state.go HandleNodeFromAuthPath: 'regEntry, ok := s.GetAuthCacheEntry(authID)' ... 'regData := regEntry.RegistrationData()' (the only IsRegistration checks are in oidc.go lines ~196/843); hscontrol/types/common.go: 'panic("RegistrationData can only be used in registration requests")'; hscontrol/app.go: 'grpcSocket := grpc.NewServer(' with the interceptor commented out; grpcv1.go AuthRegister calls api.RegisterNode. Plan §13.2: '`web-auth:claim` nhận Auth ID của luồng web authentication'.

</details>

**Suggested fix.** Add two contract tests to V-06 before Phase 4: AuthRegister(ssh-check auth id) and AuthApprove(registration auth id). Until proven safe: accept claim IDs only when they arrive through the edge redirect from '/register/<id>' with a short-lived signed state generated server-side, keep the free-text paste fallback disabled for tenants with SSH check enabled, rate-limit web-auth:claim per member, alert on container restart count, and report upstream. Document that AuthApprove on a registration ID returns success but registers nothing (the client is just issued a new auth URL).

### HS-FC-07 — MEDIUM — §13.1 error model; §13.4 rules (2) and (5); V-06

**Problem.** Headscale's REST gateway returns HTTP 500 for most domain errors, because handlers return plain Go errors (gRPC Unknown) or explicitly codes.Internal. Examples: SetPolicy validation or test failure, unknown or expired Auth ID in AuthRegister, user not found, duplicate user name in CreateUser, DeleteUser while the user owns nodes. Only a few paths return 400/404 (CheckPolicy, GetNode, AuthApprove/AuthReject not found, ExpireNode out of range). A per-instance circuit breaker keyed on 5xx would open on ordinary user mistakes such as an expired Auth ID and report the tenant as instance_unavailable; the 502 upstream_rejected versus 503 instance_unavailable split cannot be derived from status codes.

<details><summary>Evidence</summary>

Upstream hscontrol/grpcv1.go: SetPolicy 'return nil, fmt.Errorf("setting policy: %w", err)'; CreateUser 'status.Errorf(codes.Internal, "creating user: %s", err)'; RegisterNode 'return nil, fmt.Errorf("looking up user: %w", err)' and 'return nil, err' for HandleNodeFromAuthPath errors; DeleteUser returns db.ErrUserStillHasNodes unwrapped; by contrast CheckPolicy 'status.Error(codes.InvalidArgument, err.Error())'. Plan §13.4: 'có circuit breaker và timeout theo instance'; §13.1: '`instance_unavailable` (503 ...)', '`upstream_rejected` (502 ...)'.

</details>

**Suggested fix.** Specify in §13.4: classify by the grpc-gateway JSON body {code, message} plus per-operation message patterns; the breaker counts only transport errors, timeouts and 503/504. Add a mapping table (for example 'setting policy:' -> upstream_rejected, registration-cache miss -> validation_failed, 'user not found' -> not_found, UNIQUE violation -> conflict). Pre-validate inputs locally (auth ID regex ^hskey-authreq-[A-Za-z0-9_-]{24}$, user name, tag format) and always call CheckPolicy (returns 400 on rejection) before SetPolicy. Pin every mapping with a contract test.

### HS-FC-08 — MEDIUM — §11.5 ValidateConfig; §11.3 step 8; §11.4 Reconfigure

**Problem.** 'headscale configtest trong container tạm, không network' cannot pass for tenants using Headscale OIDC (enrollment method C). configtest builds the full server object, which performs OIDC discovery against the issuer (30 s budget, fatal while only_start_if_oidc_is_available is true, the default) and reads client_secret_path from disk. In addition configtest never reaches Serve(), so it does not validate the STUN bind, a non-empty DERP map, listen addresses, the Unix socket or the existence of dns.extra_records_path; passing it does not mean the instance will start.

<details><summary>Evidence</summary>

Upstream cmd/headscale/cli/configtest.go: '_, err := newHeadscaleServerWithConfig()'; hscontrol/app.go NewHeadscale: 'if cfg.OIDC.Issuer != "" { ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) ... if err != nil { if cfg.OIDC.OnlyStartIfOIDCIsAvailable { return nil, err }'; hscontrol/oidc.go: 'oidcProvider, err := oidc.NewProvider(ctx, cfg.Issuer)'; types/config.go: 'secretBytes, err := os.ReadFile(os.ExpandEnv(oidcClientSecretPath))'. Plan §11.5: 'ValidateConfig ... // headscale configtest trong container tạm, không network'.

</details>

**Suggested fix.** Run configtest in the scratch container with HEADSCALE_OIDC_ONLY_START_IF_OIDC_IS_AVAILABLE=false (discovery failure becomes a warning; not a secret, so it does not violate the env rule) and mount the client-secret file read-only; validate the issuer separately in the Worker (fetch the discovery document, compare 'issuer'). State in §11.3 that configtest is a syntax gate only and that the post-start health gate is authoritative; add explicit pre-start checks for extra-records.json (exists, parses) and for stun_listen_addr.

### HS-FC-09 — MEDIUM — §13.4 Instance.Version; §14.6 admin listener; §11.4 Upgrade ('contract smoke qua adapter')

**Problem.** The adapter declares Version(ctx) but the design gives it no route. Headscale serves the version only at '/version' on the main router, outside '/api/v1' (there is no Version RPC in the proto). The internal admin listener forwards 'chỉ /api/v1/*' and the public allow-list returns 404 for '/version'. The version layer of ADR-10 and the upgrade smoke test both depend on this call.

<details><summary>Evidence</summary>

Plan §13.4: 'Health(ctx) (Health, error); Version(ctx) (string, error)'; §14.6: 'Admin nội bộ ... chỉ `/api/v1/*`' and public 'mọi path khác => 404 (gồm `/api/*`, `/swagger*`, `/verify`, `/version`, `/health`)'. Upstream hscontrol/app.go createRouter: 'r.Get("/version", h.VersionHandler)' registered outside 'r.Route("/api", ...)'; proto/headscale/v1/headscale.proto contains no version RPC (only Health at get '/api/v1/health').

</details>

**Suggested fix.** Either allow exactly 'GET /version' on the internal admin listener (exact path match, same internal token; keep the public 404), or remove Version() from the interface and derive the version from tenant_instances.image_digest verified by the Agent with docker inspect. In the upgrade flow assert that the reported version equals the expected one before running the contract smoke test.

### HS-FC-10 — MEDIUM — §17.2 step 2 (restore precondition); RT-10

**Problem.** The restore check 'headscale_version <= version đang chạy' is looser than the upstream startup check that the plan itself cites in RT-10. Headscale only starts on a database last used by the same minor (any patch) or by exactly one minor lower; two or more minors behind is refused, as is any minor downgrade. Retained backups (the final backup before deprovision, long-retention archives) will cross that limit after two upgrade waves and the restore job will leave an instance that does not start.

<details><summary>Evidence</summary>

Plan §17.2 step 2: 'kiểm manifest: ... `headscale_version` <= version đang chạy'. Upstream hscontrol/db/versioncheck.go checkVersionUpgradePath: 'Same minor version: always allowed (patch changes in either direction). Single minor version upgrade (stored.minor+1 == current.minor): allowed. Multi-minor upgrade or any minor downgrade: blocked with a fatal error.'

</details>

**Suggested fix.** Replace the rule with: backup.major == running.major and (running.minor - backup.minor) in {0, 1}. Otherwise restore by stepping: start the restored data with the pinned image digest of backup.minor, then each following minor in order, with a health gate per hop; keep one digest per supported minor in versions.lock and the Agent allowlist. Record the database_versions value in the backup manifest and mark older backups 'needs stepping' in the backups table after each upgrade wave.

### HS-FC-11 — MEDIUM — §14.5 volumes; §11.4 Reconcile/Restore/Relocation; RT-06

**Problem.** Headscale self-initialises silently when its data directory is empty: it creates new Noise and DERP keys and a new SQLite database, and with no policy row it is allow-all. Compose short-syntax bind mounts create a missing host path automatically. A wrong or missing data/ (failed restore swap, relocation, operator error) therefore yields a healthy-looking, empty, allow-all tenant with a new identity while the edge stays attached; devices enrolled afterwards land in an allow-all tailnet until the periodic drift job notices.

<details><summary>Evidence</summary>

Upstream hscontrol/app.go readOrCreatePrivateKey: 'log.Info().Str("path", path).Msg("no private key file at path, creating...")'; hscontrol/db/policy.go PolicyBytes: 'if errors.Is(err, types.ErrPolicyNotFound) { return nil, nil }' followed by NewPolicyManager(nil) => FilterAllowAll. Plan RT-06 notes the key auto-generation; §14.5 specifies the mounts without create_host_path; §11.4 Reconcile compares container, digest, config hash, network members and file permissions but not key fingerprint or policy.

</details>

**Suggested fix.** In the tenant compose template use long-syntax bind mounts with 'bind: { create_host_path: false }'. Agent pre-start gate: when tenant_instances.status is not 'provisioning', refuse to start unless data/db.sqlite and both key files exist. Post-start gate on every start path (reconfigure, upgrade, restore, reconcile-detected restart) before the edge is attached or re-attached: Noise public key equals the stored fingerprint and GetPolicy sha256 equals the applied version. Treat a GetPolicy 'not found' error as critical drift and detach the edge automatically.

### HS-FC-12 — MEDIUM — §7.4 step 3 (CreateUser 'kèm display name/email'); §7.3 last bullet (CheckPolicy only before upgrades)

**Problem.** A policy that was accepted can later become boot-fatal. At startup Headscale validates user references in groups, tagOwners, autoApprovers, acls and ssh and aborts if a 'user@' token matches more than one user; tokens match on Email or Name. CreateUser over REST enforces no e-mail uniqueness. If a second Headscale user with the same e-mail appears (two identities sharing an address, or a mixed OIDC/API user), any stored policy that references that address is ambiguous and the instance refuses to start at its next restart. The plan runs CheckPolicy on the stored policy only before upgrades. This is an edge case, but the outcome is a tenant control plane that stays down.

<details><summary>Evidence</summary>

Upstream hscontrol/policy/v2/policy.go NewPolicyManager: 'err = validateUserReferences(policy, users); if err != nil { return nil, fmt.Errorf("validating policy user references: %w", err) }' (called from state.NewState at boot); types.go resolveUser: 'if user.Email == uTrimmed || user.Name == uTrimmed { potentialUsers = append(...) }' ... 'if len(potentialUsers) > 1 { return ... ErrMultipleUsersFound'. docs/about/faq.md: 'Headscale checks if the policy is valid during startup and refuses to start if it detects an error.' Plan §6 'identities': only UNIQUE(idp_id, subject), e-mail not unique.

</details>

**Suggested fix.** (1) In 'portal' identity mode do not populate 'email' on Headscale users, or enforce per-instance uniqueness before CreateUser. (2) Lint: user tokens in policies must be the platform-rendered 'mg-<id>@' form; rewrite e-mail tokens from admin HuJSON into that form or block them. (3) Run CheckPolicy on the currently applied policy after every CreateUser/RenameUser and as a mandatory pre-step of every restart, reconfigure and restore, not only upgrades; block the restart on failure.

### HS-FC-13 — LOW — §2.6 PL-15 (labelled VERIFIED); §14.1 daemon.json

**Problem.** PL-15 is wrong. Only the statsviz handlers are wrapped with protectedDebugHandler (which adds private ranges). '/debug/policy', '/debug/filter', '/debug/ssh', '/debug/routes', '/debug/mapresponses', '/debug/config' and '/debug/ping' are registered through tsweb.Debugger and are limited to loopback, Tailscale address ranges, TS_ALLOW_DEBUG_IP, TS_DEBUG_TRUSTED_CIDRS or a debug key. '/metrics' is open. So a container on a private Docker subnet cannot read '/debug/policy'; but if the tenant Docker pools were carved from 100.64.0.0/10, every debug endpoint would open to the edge container.

<details><summary>Evidence</summary>

Plan PL-15: 'truy cập giới hạn theo địa chỉ nguồn loopback/Tailscale/private => mọi container cùng Docker network đều đọc được'. Upstream hscontrol/debug.go: 'debug := tsweb.Debugger(debugMux)' with 'debug.Handle("policy", ...)'; only 'debugMux.Handle("/debug/statsviz/", protectedDebugHandler(statsvizSrv.Index()))' uses the private-range wrapper. tailscale v1.104.4 tsweb/debug.go: 'd.mux.Handle(href, Protected(debugBrowserHeaderHandler(handler)))'; tsweb.go AllowDebugAccess: 'if tsaddr.IsTailscaleIP(ip) || ip.IsLoopback() || ipStr == envknob.String("TS_ALLOW_DEBUG_IP")'. docs/ref/debug.md: 'The debug endpoint expects traffic from localhost.'

</details>

**Suggested fix.** Correct PL-15 to: '/metrics has no access control; /debug/* is loopback / Tailscale-range / debug-key only; /debug/statsviz additionally allows private ranges'. Add to §14.1: default-address-pools must not overlap 100.64.0.0/10 or fd7a:115c:a1e0::/48, and TS_ALLOW_DEBUG_IP, TS_DEBUG_TRUSTED_CIDRS and TS_DEBUG_KEY_PATH must never be set in tenant containers. Add a Phase 1 check from the edge container: hs:9090/metrics = 200, /debug/policy = 403.

### HS-FC-14 — LOW — §11.4 Suspend ('reject pending auth'); §13.2 enrollment ':reject'

**Problem.** 'reject pending auth' is neither implementable nor effective. There is no API to enumerate pending registrations (the plan states this itself in §7.4), and AuthReject on a registration does not block the device: the waiting client is simply issued a new auth URL. For tenants in headscale_oidc mode Headscale completes registrations by itself during suspension.

<details><summary>Evidence</summary>

Upstream hscontrol/grpcv1.go AuthReject: 'authReq.FinishAuth(types.AuthVerdict{Err: fmt.Errorf("auth request rejected")})'; hscontrol/auth.go waitForFollowup: a non-accepted verdict falls through to 'return h.reqToNewRegisterResponse(regData)' ('instruct the client to try a new registration'). proto/headscale/v1/headscale.proto has no RPC that lists pending auth sessions. Plan §11.4: 'expire mọi pre-auth key còn hiệu lực, reject pending auth'.

</details>

**Suggested fix.** Redefine suspension in §11.4 as: the Portal refuses web-auth:claim and key issuance, all pre-auth keys are expired, and the deny-all policy is applied. Remove 'reject pending auth' or scope it to auth IDs the Portal has recorded (enrollment_requests.auth_id_hash). For method-C tenants add an edge rule that returns 404 for '/register/*', '/oidc/callback' and '/register/confirm/*' while the tenant is suspended, or state explicitly that new OIDC registrations still succeed but are isolated by the deny-all policy.

### HS-FC-15 — LOW — §2.5 HS-11 and HS-12; §22.4 V-06

**Problem.** 'Single use, valid one hour' (pre-auth key) and 'expires after 90 days' (API key) are CLI flag defaults only. Over REST an omitted 'expiration' is stored as the zero time and both validators treat it as already expired, so the key is unusable from creation. V-06 can be answered from source; the tables currently suggest that REST-created keys inherit the CLI defaults.

<details><summary>Evidence</summary>

Upstream hscontrol/grpcv1.go CreateApiKey and CreatePreAuthKey: 'var expiration time.Time; if request.GetExpiration() != nil { ... }' then pass '&expiration'; hscontrol/db/api_key.go ValidateAPIKey: 'if key.Expiration != nil && key.Expiration.Before(time.Now()) { return false, nil }'; hscontrol/types/preauth_key.go Validate: 'if pak.Expiration != nil && pak.Expiration.Before(time.Now()) { return PAKError("authkey expired") }'; cmd/headscale/cli/api_key.go: 'DefaultAPIKeyExpiry = "90d"' is the flag default.

</details>

**Suggested fix.** Reword HS-11/HS-12 ('CLI default; REST without expiration yields a key that is expired at creation'). In the adapter reject zero or past expirations before the call and cap the TTL (pre-auth <= 15 min, API key <= 90 d). Keep a contract test asserting that a key created without expiration is rejected, so an upstream change to 'never expires' is caught at upgrade time.

### HS-FC-16 — LOW — §10.1 row 'Cấu hình' (labelled VERIFIED); §2.5 HS-19

**Problem.** 'Các khóa này không có default trong code' is partly wrong and contradicts HS-17: the code sets defaults for derp.server.enabled (false), derp.server.verify_clients (true), derp.server.automatically_add_embedded_derp_region (true) and derp.update_frequency (3h). There is no code default for region_id, region_code, region_name, stun_listen_addr, private_key_path, ipv4, ipv6 or auto_update_enabled. Conversely HS-19 quotes node.ephemeral.inactivity_timeout as 30m, which is the example file; the code default is 120s. The decision to render everything explicitly still stands.

<details><summary>Evidence</summary>

Upstream hscontrol/types/config.go: 'viper.SetDefault("derp.server.enabled", false)', 'viper.SetDefault("derp.server.verify_clients", true)', 'viper.SetDefault("derp.server.automatically_add_embedded_derp_region", true)', 'viper.SetDefault("node.ephemeral.inactivity_timeout", "120s")', 'viper.SetDefault("taildrop.enabled", true)'. Plan §10.1: 'Các khóa này không có default trong code, chỉ có trong file ví dụ. VERIFIED [HS:hscontrol/types/config.go]'.

</details>

**Suggested fix.** Reword §10.1 to list which keys have no code default, and add node.ephemeral.inactivity_timeout, taildrop.enabled and auto_update.enabled to the explicitly rendered keys in §14.5 so behaviour does not depend on which default applies.

### HS-FC-17 — LOW — §11.3 steps 12 and 13 (CLI in container)

**Problem.** Implementation traps in the two CLI steps: (a) 'headscale policy get' prints with Println, so stdout is the policy plus a newline and its sha256 never equals the file hash; (b) with log.format json (the plan's choice) the CLI redirects its logger to stdout, so any log line contaminates captured output unless a machine-output flag is present; (c) 'apikeys create -o json' prints a quoted JSON string, not an object; (d) '-e' takes Prometheus-style durations.

<details><summary>Evidence</summary>

Upstream cmd/headscale/cli/policy.go: 'fmt.Println(policyData)' with the comment 'This does not pass output format'; cli/root.go: 'if logFormat == types.JSONLogFormat { log.Logger = log.Output(os.Stdout) }' and 'if machineOutput { zerolog.SetGlobalLevel(zerolog.Disabled) }'; cli/api_key.go: 'return printOutput(cmd, response.GetApiKey(), response.GetApiKey())'; cli/utils.go expirationFromFlag uses 'model.ParseDuration'. hscontrol/db/api_key.go: prefix length 12, secret length 64.

</details>

**Suggested fix.** Specify in step 12: run 'headscale policy get -o json' (the flag disables logging; the output is still the raw policy), strip exactly one trailing newline, then compare sha256. Specify in step 13: parse stdout as a JSON string and validate ^hskey-api-[A-Za-z0-9_-]{12}-[A-Za-z0-9_-]{64}$; format the TTL as '<n>d' or '<n>h'.

### HS-FC-18 — LOW — §2.5 HS-22; §7.2 (no lint for nodeAttrs)

**Problem.** 'logtail.enabled: false => client không gửi log về Tailscale Inc.' is over-stated. The instruction is delivered in the netmap, so it applies only after a client has successfully connected; during install and failed logins the client still uploads logs. Separately, granting the node attribute 'https://tailscale.com/cap/data-plane-audit-logs' while logtail is disabled makes clients switch themselves off, and §7.2 has no lint for nodeAttrs although L3 admits the key.

<details><summary>Evidence</summary>

Upstream docs/about/faq.md: 'Headscale, by default, instructs clients to disable log submission ... This configuration is applied by a client once it successfully connected with Headscale.' and 'Do not grant the https://tailscale.com/cap/data-plane-audit-logs node attribute while logtail.enabled is false. A client with log submission disabled treats this attribute as "the tailnet requires logging" and turns itself off'. hscontrol/types/config.go TailcfgDebug returns 'DisableLogTail: true' in map responses.

</details>

**Suggested fix.** Reword HS-22. In enrollment instructions for managed installs add TS_NO_LOGS_NO_SUPPORT=true or --no-logs-no-support where the platform allows, and mention the residual exposure in the privacy notice. Add a lint: nodeAttrs entries are checked against an allow-list and 'data-plane-audit-logs' is blocked.

### HS-FC-19 — LOW — §2.6 ID-08 (labelled VERIFIED); §13.4 adapter contract

**Problem.** Adapter-relevant upstream behaviour is missing or over-stated: (a) the user-name rules of ID-08 are not enforced on REST CreateUser/RenameUser (the state layer saves directly; ValidateUsername is only applied to OIDC claims), so the platform must validate; (b) DeleteUser fails while the user owns nodes and deletes that user's pre-auth keys, and OIDC users cannot be renamed; (c) GetPolicy returns an error, not an empty policy, on a database-mode instance with no policy row; (d) SetPolicy swaps the live policy before the SSH verification and before the DB write, so an error response does not guarantee that nothing changed; (e) rename calls carry the new name in the URL path and need escaping.

<details><summary>Evidence</summary>

Upstream hscontrol/state/state.go CreateUser: 'if err := s.db.DB.Save(&user).Error' (no ValidateUsername call anywhere in state.go; it is called only in db.CreateUser/db.RenameUser and types.User.FromClaim); db/users.go DestroyUser: 'if len(nodes) > 0 { return ErrUserStillHasNodes }'; grpcv1.go GetPolicy: 'return nil, fmt.Errorf("loading ACL from database: %w", err)'; SetPolicy order: 'api.h.state.SetPolicy([]byte(p))' -> 'api.h.state.SSHPolicy(nodes.At(0))' -> 'api.h.state.SetPolicyInDB(p)'; proto: 'post : "/api/v1/user/{old_id}/rename/{new_name}"'.

</details>

**Suggested fix.** Write these into the adapter contract in §13.4 with one contract test each. On any SetPolicy error, re-assert the last applied version and read it back instead of only marking the job failed. Map GetPolicy 'not found' to an explicit ErrNoPolicy that the drift job treats as critical.

### HS-FC-20 — LOW — §2.6 RT-02; §14.6 public allow-list

**Problem.** RT-02 is not the complete outer route list: the main router also serves GET /robots.txt, /favicon.ico and '/'. None is needed by clients, so the allow-list breaks nothing. Two side notes: '/bootstrap-dns' on the allow-list is unauthenticated and makes Headscale perform server-side DNS lookups (up to 60 s) from inside the tenant container, which return an empty map after resolver timeouts once tenant egress is blocked; and '/apple', '/apple/{platform}', '/windows' are blocked although upstream client docs point users to them.

<details><summary>Evidence</summary>

Upstream hscontrol/app.go createRouter: 'r.Get("/robots.txt", h.RobotsHandler)', 'r.Get("/favicon.ico", FaviconHandler)', 'r.Get("/", BlankHandler)', 'r.Get("/apple", ...)', 'r.Get("/windows", ...)'; hscontrol/derp/server/derp_server.go DERPBootstrapDNSHandler: 'resolvCtx, cancel := context.WithTimeout(req.Context(), time.Minute)' ... 'resolver.LookupIP(resolvCtx, "ip", node.HostName())'; docs/about/clients.md: 'see docs and `/apple` on your headscale for more information'.

</details>

**Suggested fix.** Serve '/robots.txt' (Disallow: /) and a static '/bootstrap-dns' JSON for the tenant hostname directly from the edge instead of proxying, or rate-limit the proxied path. Add RT-02 the three missing routes. State in the enrollment docs that the '/apple' and '/windows' helper pages are intentionally replaced by Portal instructions.

### HS-FC-21 — LOW — §14.2 directory layout ('mount read-only, trừ extra-records'); §11.5 WriteRuntimeFile

**Problem.** Upstream constraints on dns.extra_records_path that the layout note leaves ambiguous: the file must exist and be a regular file at startup or Serve() fails; a zero-byte file is ignored (so 'no records' must be written as []); the watcher is on the file path and recovers from rename by re-adding it. If 'trừ extra-records' means a separate single-file bind mount, tmp + rename on the host leaves the container pinned to the old inode and updates are never seen.

<details><summary>Evidence</summary>

Upstream hscontrol/dns/extrarecords.go NewExtraRecordsManager: 'fi, err := os.Stat(path); if err != nil { ... return nil, fmt.Errorf("getting file info: %w", err) }'; readExtraRecordsFromPath: 'if len(b) == 0 { return nil, [32]byte{}, nil }' and updateRecords: 'if records == nil { return }'; Run(): on fsnotify.Remove/Rename it calls waitUntilPathExists and 'e.watcher.Add(e.path)'. hscontrol/app.go Serve: 'return fmt.Errorf("setting up extrarecord manager: %w", err)'.

</details>

**Suggested fix.** Keep extra-records.json inside a directory mount (config/ or a dedicated runtime/ directory mounted read-only) and never bind-mount the single file. Render the initial content as [] in step 8. The Agent writes sorted, stable JSON with tmp + rename in the same directory and confirms pickup after each write.

## API, data model and authorization design (principal backend engineer / database architect)

**Verdict:** Not ready to hand to a coding agent for Phases 2-4 without redesign. 1 critical, 10 high, 14 medium. The critical one: a single shared OIDC callback for all issuers, combined with tenant-supplied IdPs, allows an IdP mix-up that yields a Portal session in another tenant. Four of the high issues are mechanical and cheap to fix before migrations and the OpenAPI file are frozen (colon action paths rejected by the chosen router/generator, the RLS expression, partition DDL and maintenance, content-derived job keys). The other six need design decisions the plan currently leaves to the builder: first Super Admin / first Owner / invitations, how users are named in policy, the policy artefact and apply-state model, IdP uniqueness, the permission matrix, and idempotent issuance of show-once secrets. The Headscale facts the adapter relies on (REST catalogue, query-parameter operations, user-by-name for register/list, explicit expirations, CheckPolicy, node.expiry on API registration) were re-read at tag v0.29.7 and are accurate; the gaps are in the platform's own identity, schema and job design. Not executed here: any database or container; the PostgreSQL GUC behaviour in DB-01 is stated from known behaviour and should be confirmed with the three-line check given.

**Strengths noted:**

- The Headscale facts the adapter depends on hold up against the v0.29.7 tag: REST catalogue including POST /api/v1/policy/check and /api/v1/auth/register, the query-parameter-only operations, user-by-name for register and list, zero-time default when expiration is omitted, and node.expiry applied to API-registered nodes.
- Tenant context taken only from the path, Registry.ForTenant as the single way to reach an instance, and one API key per instance give real defence in depth; composite (tenant_id, id) foreign keys are feasible and are not affected by FORCE row security.
- Lint rules L1/L2 and the deny-all bootstrap through the in-container CLI before the edge is attached correctly close the verified allow-all pitfalls; keeping generated tests out of stored rules is the right instinct, since upstream only warns on failing tests at start-up.
- Secret-handling intent is sound: no plaintext pre-auth key or Auth ID columns, keys shown once, the Headscale API key never reaches the browser, and AAD binds each ciphertext to tenant, name and version.
- Status semantics are honest (applied versus converged, synced_at on cached data, no mock numbers) and jobs are enqueued in the same transaction as the business change.

### AUTH-01 — CRITICAL — 8.3 steps 1-3; 13.2 auth row; 8.2 (tenant-supplied IdP row)

**Problem.** The Portal is a multi-issuer OIDC relying party that (a) accepts issuers supplied by tenants and (b) uses one shared redirect URI, GET /api/v1/auth/callback, for every issuer, with no check of the RFC 9207 iss response parameter. Those are exactly the preconditions of the OAuth IdP mix-up attack. A malicious Tenant Owner registers their own issuer and lures a user of tenant B to /auth/login?scope=tenant&tenant=<attacker-slug>. The attacker's authorization endpoint redirects the browser to tenant B's honest IdP with B's client_id, the shared redirect_uri, the victim's state, and a code_challenge and nonce copied from a second login flow the attacker started for tenant B. The honest IdP (silently, if the victim has an SSO session) returns code_B to the shared callback. The backend looks up state, believes the response belongs to the attacker's IdP and posts code_B to the attacker's token endpoint. The attacker then finishes their own tenant-B flow with code_B: the verifier and nonce match because the attacker planted them, and the backend creates a session for the victim's sub (possibly the Tenant Owner) in the attacker's browser. The iss/aud/nonce checks in step 3 run only after the code has already been sent to the wrong token endpoint, and PKCE does not help because the attacker chose the challenge. Result: cross-tenant account takeover; invariant 1 (issuer binding) and IT-01 are defeated.

<details><summary>Evidence</summary>

Plan 8.3: '`GET /api/v1/auth/callback`: đổi code, kiểm tra chữ ký, `iss`, `aud`, `nonce`, `exp`'. Plan 13.2: '`GET /auth/login` · `GET /auth/callback`'. Plan 8.2: 'IdP do tenant mang tới ... Hỗ trợ ngay từ MVP nhờ cùng code path đa issuer'. RFC 9700 section 2.1: 'When an OAuth client can interact with more than one authorization server, a defense against mix-up attacks (see Section 4.4) is REQUIRED'; section 4.4.1 precondition: 'the client ... uses the same redirection URI for each authorization server'; step 5: 'Since the client still assumes that the code was issued by A-AS, it will try to redeem the code at A-AS's token endpoint.' Google's discovery document advertises authorization_response_iss_parameter_supported: true, so the iss check is cheap where supported.

</details>

**Suggested fix.** 1) One redirect URI per IdP row: GET /api/v1/auth/callback/{idpId}; register exactly that URI at each IdP. 2) New table auth_requests(state_hash PK, idp_id, tenant_id NULL, scope, origin, nonce, pkce_verifier_enc, return_to, browser_binding_hash, created_at, expires_at <= 10 min, consumed_at); set a __Host-mg_authreq cookie and store its hash. 3) In the callback, BEFORE any token request, reject unless auth_requests.idp_id = {idpId}, origin matches, cookie matches and the row is unconsumed; when the IdP metadata advertises authorization_response_iss_parameter_supported, require the iss parameter to equal the stored issuer. 4) Add isolation test IT-01b with a mock malicious IdP that forwards to an honest one, expecting no outbound token call. 5) Add the threat to section 18.

### POL-01 — HIGH — 7.2 (groups row, lint L6); 7.4 flow A step 3; facts PL-07 / ID-08

**Problem.** The plan never defines how a user is referenced in the stored policy model or in admin-written HuJSON; it only says group members render as <headscale_username>@. Headscale resolves a 'x@' token against a user's Email as well as Name, has no notion of a verified email, and rejects the whole policy when a token matches two users. The plan also passes the IdP email to CreateUser. If an email token ever reaches Headscale (hand-written grants, or L6 implemented by email lookup): a member whose IdP email is unverified or self-set matches grants written for someone else; because Headscale users are created lazily at first enrolment, if the legitimate person has not enrolled yet the impostor is the only match and silently receives the access; and a re-invited person (new sub, same email, old Headscale user never deleted) makes every policy write fail with 'multiple users found'. The same validation runs when the policy manager is built at start-up, so it can stop the instance from starting (HS-09). Also undefined: what <id> is in mg-<id>, and the token form for headscale_oidc tenants, where the Headscale name is IdP-controlled and mutable.

<details><summary>Evidence</summary>

Plan 7.4: '`CreateUser` với tên ổn định dạng `mg-<id>`, kèm display name/email'. Plan 7.2: 'Thành viên ghi dạng `<headscale_username>@`' and '`grants` | Rule do admin soạn (form hoặc HuJSON)'. Headscale v0.29.7 hscontrol/policy/v2/types.go, resolveUser: `if user.Email == uTrimmed || user.Name == uTrimmed { potentialUsers = append(potentialUsers, user) }` followed by ErrMultipleUsersFound when more than one matches. hscontrol/policy/v2/policy.go: NewPolicyManager and SetPolicy both call validateUserReferences. hscontrol/db/schema.sql: users.email has no unique index.

</details>

**Suggested fix.** Specify in 7.2: 1) In policy_versions.source a principal is a typed reference, {type:user, membership_id} / {type:group, group_id} / {type:tag, tag_id}, never a free string. 2) The renderer emits users only as mg-<membership_uuid>@ in portal mode (derivable before the Headscale user exists) and as <issuer>/<sub>@ in headscale_oidc mode. 3) HuJSON import/export translates emails to membership ids in the Portal; add lint L11 (block): any user token in rendered output that is not ^mg-[0-9a-f-]{36}@$ or the provider-identifier form. 4) Do not send email to CreateUser (display_name only). 5) Add UNIQUE (tenant_id, headscale_username) and UNIQUE (tenant_id, headscale_user_id) WHERE headscale_user_id IS NOT NULL on tenant_memberships. 6) Contract test: two users with the same email plus an email token is rejected; an mg-...@ token is unaffected.

### IAM-01 — HIGH — 6.3 identities / tenant_memberships / platform_users; 8.4 invariant 3; 11.3 step 16; 13.3 TenantCreate; tasks P2-T07, P4-T09

**Problem.** The identity schema cannot represent anyone who has not logged in yet, and there is no bootstrap path. 1) identities are created at first login (iss+sub) and tenant_memberships requires identity_id, so step 16 'membership Owner (lời mời)' and POST /users (invite) have nowhere to store an invitee whose sub is unknown. That is always the case with the external driver, where the platform cannot create users. There is no invitation table, token, expiry, or rule for binding the first login to the invite. 2) First Super Admin: platform_users needs an identity (exists only after login) and POST /platform/users needs an existing SA; the only CLI named anywhere is adopt-instance. 3) Invariant 3 requires a second SA to approve assigning SA; with one SA the second can never be created, so every 2P operation (tenant delete, restore, break-glass) is permanently unavailable. 4) For a bring-your-own-IdP tenant the Owner must log in through the tenant IdP in order to configure the tenant IdP; TenantCreate has no IdP fields.

<details><summary>Evidence</summary>

Plan 6.3: '`identities` | Danh tính đã đăng nhập (iss+sub)'; '`tenant_memberships` ... `UNIQUE(tenant_id, identity_id)`'. Plan 11.3 step 16: 'membership Owner (lời mời)'. Plan 8.4: 'gán role SA cần SA thứ hai phê duyệt'. Plan 13.3: 'TenantCreate: {slug, name, plan_key, deployment_region?, owner_email, settings?}'. A search of the plan finds no invitation table and no admin bootstrap command.

</details>

**Suggested fix.** Add tenant_invitations(id, tenant_id, idp_id, email citext, role_id, invited_by_identity_id, token_hash, expires_at, status pending|accepted|revoked|expired, accepted_identity_id, accepted_at, version), UNIQUE (tenant_id, email) WHERE status='pending', RLS T. Acceptance rule in the callback: identity comes from the tenant's own idp_id, email_verified is true, email equals the invite (plus required_claims for shared issuers, see IAM-02); then create identity and membership in one transaction. Never link by email outside a pending invitation. Endpoints: GET/POST /tenants/{t}/invitations, DELETE /tenants/{t}/invitations/{id}, POST /tenants/{t}/invitations/{id}/resend. The Keycloak driver may additionally pre-create the user. Extend TenantCreate with identity_provider {driver, issuer?, client_id?, client_secret?} and make step 16 create the Owner invitation. Platform side: host CLI `meshguard admin bootstrap-super-admin --email` writing a platform invitation, audited as actor_type=system. Amend invariant 3: while fewer than two active SAs exist, SA assignment is confirmed by the host CLI instead of a second approver; alert when active SA count < 2.

### DB-01 — HIGH — 6.1 rows 'Row-Level Security' and 'Platform scope'; 5.2 IT-03

**Problem.** The literal policy expression fails on pooled connections. Once a custom setting has been SET LOCAL in a session, after that transaction ends current_setting('app.tenant_id', true) returns the empty string, not NULL, for the rest of the session, and ''::uuid raises 'invalid input syntax for type uuid'. Any later transaction on that connection that does not set app.tenant_id therefore errors instead of returning zero rows: every platform-scope transaction on T+P tables, and the IT-03 check 'unset means 0 rows'. Results differ between a fresh and a reused connection, so the gate test is flaky. In T+P policies the cast sits in the first OR arm and evaluation order is not guaranteed anyway. Also unspecified: how platform transactions are opened (only WithTenantTx is defined), and that the policy on tenants must compare id, not tenant_id.

<details><summary>Evidence</summary>

Plan 6.1: 'policy `tenant_id = current_setting('app.tenant_id', true)::uuid`' and 'policy bổ sung `current_setting('app.scope', true) = 'platform'`'. Plan 5.2 IT-03: 'không đặt `app.tenant_id` ⇒ 0 hàng'. Not executed in this review; confirm on one connection: BEGIN; SET LOCAL app.tenant_id='00000000-0000-0000-0000-000000000001'; COMMIT; SELECT current_setting('app.tenant_id', true) IS NULL;  -- expected: false.

</details>

**Suggested fix.** Define two STABLE SQL helpers in migration 0001 and use them in every policy: app_tenant_id() returns uuid as SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid; app_is_platform() returns boolean as SELECT COALESCE(current_setting('app.scope', true), '') = 'platform'. Policies: T tables USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id()); T+P tables USING (tenant_id = app_tenant_id() OR app_is_platform()); tenants uses id = app_tenant_id() OR app_is_platform(). Add store.WithPlatformTx (sets app.scope='platform' and app.tenant_id='') beside WithTenantTx (sets app.scope='tenant'), forbid raw pool use by lint, and make IT-03 run on a connection that has previously executed a tenant transaction.

### DB-02 — HIGH — 6.1 rows 'Khóa chính', 'DB roles', 'Migrations', 'Audit history'; 6.3 audit_events and usage_records; 13.5 retention.sweep

**Problem.** Monthly partitioning is specified without its mechanics, and the stated rules contradict each other. 1) PostgreSQL requires every PRIMARY KEY or UNIQUE constraint on a partitioned table to include the partition key, so 'primary key = UUID' cannot hold for audit_events, and the usage_records unique key is valid only if the table is partitioned by period_start, which is not stated. 2) Nothing can create next month's partition: mg_app has no DDL, migrations are forward-only files run before a rollout, and no maintenance job exists. On the first day of an unprovisioned month every audit insert fails, and with it every audited write. 3) retention.sweep cannot enforce audit retention: UPDATE/DELETE are revoked and blocked by trigger, and dropping partitions is DDL. 4) Row security on the parent is not applied when a partition is queried directly; a blanket grant or ALTER DEFAULT PRIVILEGES to the application role would open a bypass on every partition. 5) TRUNCATE is not revoked.

<details><summary>Evidence</summary>

Plan 6.1: 'Khóa chính | UUID'; '`audit_events` append-only (REVOKE `UPDATE/DELETE`, trigger chặn), partition theo tháng'; '`mg_app` (API/worker; `NOBYPASSRLS`; không DDL)'; 'File SQL forward-only, đánh số, chạy bằng job `migrate` riêng trước khi rollout'. Plan 13.5: '`grant.expire` / `session.gc` / `retention.sweep`'. PostgreSQL documentation, table partitioning limitations: a unique or primary key constraint on a partitioned table must include all the partition key columns.

</details>

**Suggested fix.** State the DDL: audit_events ... PRIMARY KEY (occurred_at, id) PARTITION BY RANGE (occurred_at); usage_records ... PRIMARY KEY (period_start, id), UNIQUE (tenant_id, metric, period_start) PARTITION BY RANGE (period_start). Add role mg_partition_maint (owner of the two partitioned parents only) and a daily worker job partition.maintain with its own DSN that pre-creates the next three months and, after export, detaches and drops partitions older than the approved retention. Add a DEFAULT partition and an alert when it contains rows. Remove audit from retention.sweep. Grant privileges on parents only, never through default privileges; add to IT-03 'direct SELECT on a partition as the application role is denied'; REVOKE TRUNCATE. Add a test that inserts an audit row dated next month.

### JOB-01 — HIGH — 13.5 column 'Idempotency key'; 6.3 provisioning_jobs UNIQUE(idempotency_key); 11.4 Suspend/Resume; 17.2 step 4(a)

**Problem.** Job keys are derived from content, not from the request, and are enforced by a permanent unique constraint (and, if River unique jobs are used, by a default that also counts completed jobs). Legitimate repeats are silently dropped as duplicates: instance.restart twice with unchanged config; instance.upgrade after an instance.reconfigure with the same config hash (the three kinds share one key template and the kind is not part of the key); reconfigure A to B and back to A; and re-applying the same policy version, which the plan itself requires on resume, after restore and for drift repair. Effect: a resumed tenant stays on the deny-all suspension policy, a restored instance keeps a stale policy, and the API returns the old job as if it were new.

<details><summary>Evidence</summary>

Plan 13.5: '`instance.reconfigure` / `instance.restart` / `instance.upgrade` | API / lịch | `instance:<id>:cfg:<config_sha>`' and '`policy.apply` | API | `tenant:<id>:policy:<version>`'. Plan 6.3: '`UNIQUE(idempotency_key)`'. Plan 11.4: '`resume`: apply lại policy version đã lưu'. Plan 17.2: 'apply lại policy version hiện hành'. River insert_opts.go (master): default ByState is Available, Completed, Pending, Running, Retryable, Scheduled, and 'if a unique job has `completed`, you still can't insert a duplicate, at least not until the job cleaner maintenance process eventually removes the completed job'.

</details>

**Suggested fix.** Separate three concepts. a) API replay protection: request_key = the client's Idempotency-Key, UNIQUE (requested_by_identity_id, kind, request_key). b) In-flight dedupe: dedupe_key that includes the kind, with UNIQUE (dedupe_key) WHERE status IN ('queued','running','compensating'), so a finished job never blocks a new one; do not rely on River uniqueness for this, or set UniqueOpts.ByState explicitly and prove the behaviour in P2-T12. c) Convergence jobs (policy.apply, inventory.sync, reconcile): make them level-triggered. Arguments carry only tenant_id or instance_id; the handler reads the desired state when it runs and records each run in a history table (see POL-02). Scheduled jobs keep their slot keys. Add to gate G3: suspend then resume within five minutes restores traffic; two restart requests produce two restarts.

### API-01 — HIGH — 13.1-13.2; 8.5-8.6 'API action' column; 12.2; stack choice in 4.3 / ST-01

**Problem.** About 25 operations put a path parameter and a literal ':action' suffix in the same path segment: /tenants/{tenantId}:suspend, /devices/{deviceId}:expire, /enrollment/requests/{id}:approve, /policies/{versionId}:apply, /platform/instances/{id}:restart, /platform/jobs/{id}:retry, /support-grants/{id}:approve, and so on. The chosen server stack (standard-library ServeMux with the oapi-codegen std-http strict server) cannot route these; code generation fails, and older generator versions panic at start-up. Literal-only segments such as /devices:sync, /routes:approve and /enrollment/web-auth:claim are fine.

<details><summary>Evidence</summary>

Plan ST-01: '`net/http` ServeMux đủ cho routing, kết hợp `oapi-codegen` v2 strict server'. Go net/http (server.go, pattern docs): 'Wildcards must be full path segments: they must be preceded by a slash and followed by either a slash or the end of the string. For example, "/b_{bucket}" is not a valid pattern.' oapi-codegen pkg/codegen/utils.go, ValidateStdHTTPPath: 'mixed segments such as "{resourceId}:apply" are rejected at codegen time instead of panicking at server startup (see #2488)'.

</details>

**Suggested fix.** Use a sub-resource segment everywhere: POST /tenants/{tenantId}/actions/suspend (or /tenants/{tenantId}/suspend), POST /tenants/{t}/devices/{deviceId}/expire, POST /tenants/{t}/policies/{versionId}/apply, POST /platform/instances/{id}/restart, and so on. Update 8.5, 8.6, 12 and 13.2 consistently, and add a spec-lint rule to P2-T02: no path segment may mix a {param} with literal text. Alternative, not recommended: switch the router in ADR-04 to chi and prove it with a routing test.

### POL-02 — HIGH — 7.2 (rows 'tests' and 'Nguồn sự thật'); 7.3 state diagram; 6.3 policy_versions; 11.4 Suspend; 13.4 rule 3

**Problem.** One row with one rendered_hujson and one sha256, moving through one linear state, cannot carry what the text requires. 1) Bytes sent differ from bytes reviewed: tests are generated at apply time from live inventory and groups/hosts/tagOwners are rendered from tables, yet success is 'GetPolicy sha256 equals stored sha256' and drift uses the same hash. Headscale stores and returns the exact string it was sent, so the hash that matters is of the applied bytes, which did not exist at validation or approval. 2) Group or resource changes create a 'new version': it is undefined whether these need approval under 4-eyes. If not, tenant.group:manage bypasses 4-eyes (add yourself to a privileged group); if so, every onboarding waits for a second admin. 3) No stale-base rule: two drafts from v5, applying the second silently discards the first (parent_version_id exists but no rule uses it). 4) approved -> failed is terminal, and with 'retry only GET' a timed-out SetPolicy is recorded as failed although it may have been applied; the drift job then reports a false out-of-band change. In addition, Headscale's handler swaps the live policy before two later failure points, so an error response can leave the new policy live in memory while GetPolicy (database) still returns the old one; read-back and drift detection cannot see that. 5) Rollback is described as a new draft through the whole pipeline but exposed as a one-shot :rollback under policy:apply, which break-glass staff (no edit or approve permission) are expected to use. 6) During suspension tenants.current_policy_version_id means 'to restore', not 'applied'; nothing enforces a single applied version.

<details><summary>Evidence</summary>

Plan 7.2: '`tests`, `sshTests` | **Sinh lúc apply** từ inventory hiện tại, không lưu cùng rule'. Plan 7.3: 'Apply chỉ được coi là thành công khi đọc lại `GetPolicy` cho sha256 khớp'; 'superseded --> draft: rollback = nhân bản thành version mới rồi đi lại pipeline'. Headscale v0.29.7 hscontrol/grpcv1.go, SetPolicy: `api.h.state.SetPolicy([]byte(p))` (live swap), then `api.h.state.SSHPolicy(nodes.At(0))` returning 'verifying SSH rules', then `api.h.state.SetPolicyInDB(p)`; GetPolicy returns state.GetPolicy(), which reads the database.

</details>

**Suggested fix.** Split the model. policy_versions holds authored and approved content only: add content_sha256 (canonical hash of source), submitted_by/at, approved_by/at, approved_content_sha256, rejected_by/at/reason; states draft|validated|pending_approval|approved|rejected|superseded; any PATCH returns the version to draft and clears approval; apply requires parent_version_id = tenants.desired_policy_version_id, otherwise 409 stale_base. New table policy_applications(id, tenant_id, instance_id, policy_version_id, trigger manual|group_change|resource_change|tag_change|suspend|resume|restore|drift_repair|rollback, inputs_sha256, applied_hujson, applied_sha256, state pending|applied|failed|unknown, headscale_updated_at, error_code, requested_by_identity_id, created_at, finished_at) with one current applied row per instance. Rename tenants.current_policy_version_id to desired_policy_version_id. Drift compares GetPolicy with the latest applied_sha256. The apply job is level-triggered per tenant: render desired version plus current tables plus generated tests, CheckPolicy, SetPolicy, GetPolicy. SetPolicy is retried (a full replacement is idempotent). On any non-2xx or timeout set state unknown, read back, and if the hash differs re-send the last applied bytes before reporting failed. Decide and document whether membership changes of an existing group need re-approval (suggestion: no, but audited and notified, except groups marked sensitive). baseline and suspension kinds never carry tests. Define rollback as 'create version N+1 from an earlier version; approval is inherited only if the content hash equals a previously approved hash'.

### IAM-02 — HIGH — 6.3 identity_providers UNIQUE(issuer); 8.2 'Issuer theo tenant'; 6.2 ERD; 13.2 settings / idp row

**Problem.** 1) UNIQUE(issuer) assumes one issuer equals one tenant. Shared-issuer IdPs break that: every Google Workspace customer has issuer https://accounts.google.com, and one company with two tenants (production and staging, or two subsidiaries) shares one Entra, Okta or Keycloak issuer. The second such tenant cannot be configured, and the conflict response reveals that another tenant uses the issuer. 2) The isolation argument 'different issuer and different signing key' is false for those IdPs; isolation then rests on aud and per-row identities only. There is no per-IdP claim restriction, so for a Google-backed tenant any Google account can complete login and obtain an identities row. 3) The ERD gives a tenant several issuers, the API is singular, and login 'selects the issuer' with no rule when two rows exist. 4) Changing a tenant's IdP gives every user a new (idp_id, sub); memberships stay bound to the old identities, so the whole tenant including the Owner is locked out, and no re-link flow exists.

<details><summary>Evidence</summary>

Plan 6.3: '`UNIQUE(issuer)`'. Plan 8.2: 'token của tenant này vô nghĩa ở tenant khác (khác issuer + khác khóa ký)'; 'IdP do tenant mang tới (Entra ID, Google Workspace, Okta, Keycloak riêng…) ... Hỗ trợ ngay từ MVP'. Plan 6.2: 'tenants ||--o{ identity_providers : "issuer(s)"'. https://accounts.google.com/.well-known/openid-configuration returns "issuer": "https://accounts.google.com".

</details>

**Suggested fix.** UNIQUE (issuer, client_id). Add required_claims jsonb (for example hd or tid), require_email_verified bool and allowed_email_domains text[], enforced in the callback before the identity upsert; make required_claims mandatory for issuers on a maintained shared-issuer list. Add UNIQUE (tenant_id) WHERE status='active' and statuses pending|active|retiring|disabled. Reword invariant 1 as 'an identity is bound to idp_id (issuer + client_id + required claims)'. Make an IdP change an explicit migration: new row pending; members re-link by proving both identities in one session (identity_links(old_identity_id, new_identity_id, linked_at), membership moved), the Owner can bulk re-invite, the old row stays retiring until cut-over; step-up, audit and notification; never match by email automatically.

### AUTHZ-01 — HIGH — 8.4 invariants 3-4; 8.6 matrix; 8.3 step 7; 13.2 tenants row

**Problem.** The matrix cannot be implemented as 'exactly one x-permission per operation', and it leaves escalation paths. 1) Payload-dependent permissions on one operation: PATCH /users/{id} carries tenant.user:manage, tenant.membership:assign (role up to Operator) and tenant.membership:assign_admin (no endpoint given); POST /enrollment/requests carries enrollment:request and enrollment:issue_privileged (no endpoint given). The authz matrix test generated from OpenAPI will be wrong for these. 2) /tenants mixes scopes: GET /tenants and GET /tenants/{id} are platform.tenant:read, yet tenant users must read their own tenant and request-deletion is a tenant permission; no tenant-scope read permission exists. 3) Staff column: 'G = the effective role in the grant, at most Tenant Operator' contradicts the rows. Staff get usage:read and audit:read (Operator has neither), are denied enrollment:request (Operator has it), and even with a break-glass Admin grant are denied policy:edit, route:approve and user:manage. The effective permission set cannot be derived. 4) No target-role rule: a Tenant Admin with user:manage can lock or offboard an Owner or another Admin (only the last Owner is protected) and can invite with any role in the body. 5) tenant.settings:update is granted to Admin and is not a step-up action, but settings hold the 4-eyes switch, the self-enrol switch and the enrolment mode; an Admin can turn 4-eyes off, self-approve, and turn it back on. 6) End User rights on 'own' devices are undefined for devices that were later tagged.

<details><summary>Evidence</summary>

Plan 8.4: 'mỗi operation trong OpenAPI khai báo đúng một `x-permission`'. Plan 8.6 rows: '`tenant.membership:assign` | `PATCH /users/{id}` đổi role ≤ Tenant Operator'; '`tenant.enrollment:issue_privileged` | key gắn tag / reusable / ephemeral / cho người khác'; '`tenant.usage:read` ... TP — ... Staff G'; '`tenant.settings:read` / `:update` | ✔ / ✔ | ✔ / ✔'. Plan 8.6 legend: 'G = hành động với role hiệu lực ghi trong grant (mặc định tối đa Tenant Operator; Tenant Admin chỉ qua break-glass ...)'. Plan 8.3 step 7 list of step-up actions does not include settings.

</details>

**Suggested fix.** Split operations so each has one permission: PATCH /tenants/{t}/users/{id} (status and profile, user:manage); PUT /tenants/{t}/users/{id}/role (membership:assign, with the service rule that the target's current and new role are both strictly below the actor's role unless the actor is Owner); POST /tenants/{t}/ownership-transfer (assign_admin plus step-up); POST /tenants/{t}/enrollment/keys (issue_privileged) separate from POST /tenants/{t}/enrollment/requests (self). Move registry views to GET /platform/tenants[/{id}] and add tenant.tenant:read for GET /tenants/{t}. Seed two system roles, support_operator and support_admin (scope support), whose role_permissions are exactly the Staff column, and make support_access_grants.effective_role_key reference them. Add tenant.settings:update_security (Owner only, step-up, audited, notified; turning 4-eyes off while it is on needs a second approver) and move the three switches under it. State that 'own' means owner_membership_id = caller and the device has no tags. Extend the role property test to the target-role rules.

### API-02 — HIGH — 13.1 row 'Idempotency'; 6.3 idempotency_keys; 13.2 enrollment row; 7.6 closing rule

**Problem.** 'Repeat returns the same result' with a stored response jsonb means the response of POST /enrollment/requests, which contains the plaintext pre-auth key that may be shown once, is persisted in PostgreSQL in clear. That contradicts the plan's own rule against storing plaintext keys and puts them in every database backup. If the builder instead redacts the stored body, a client retry after a timeout can never obtain the key and the already-created Headscale key is orphaned. The table also lacks tenant scope and row security although it caches tenant response bodies (RLS column is '—'), operation scope (the same key reused on another endpoint would return a foreign response), and an in-progress state for concurrent duplicates.

<details><summary>Evidence</summary>

Plan 13.1: '`Idempotency-Key` bắt buộc cho `POST` ... lưu ở `idempotency_keys`, lặp lại trả cùng kết quả'. Plan 6.3: '`idempotency_keys` | ... | `key, identity_id, request_hash, response jsonb, status, expires_at` | `PRIMARY KEY(key, identity_id)` | —'. Plan 13.2: 'Pre-auth key chỉ hiển thị **một lần** trong response tạo'. Plan 6.3 enrollment_requests: 'Không lưu plaintext pre-auth key/Auth ID'.

</details>

**Suggested fix.** Schema: idempotency_keys(tenant_id NULL, identity_id, operation_id, key, request_hash, status in_progress|completed|failed, response_status int, response_body jsonb with secrets removed, secret_ref text NULL, resource_type, resource_id, locked_until, created_at, expires_at), PRIMARY KEY (identity_id, operation_id, key), RLS T+P. Rules: same key with a different request_hash returns 422 idempotency_key_reuse; in_progress returns 409 with Retry-After. For secret-bearing responses store the secret through SecretStore under the tenant key with TTL = min(credential TTL, 15 minutes) and reference it by secret_ref; a replay inside the TTL re-injects it; after the TTL return the stored body with preauth_key null and code secret_no_longer_available so the UI offers revoke and re-issue. A sweeper destroys the secret at expiry. Mark such schemas x-secret-once: true in OpenAPI and add a test that no hskey- pattern exists in idempotency_keys.

### AUTHZ-02 — MEDIUM — 8.5 cells marked 2P; 8.7 step 2; 7.1 'Separation of duties'; 12.2; 6.3 support_access_grants

**Problem.** Dual control is required for tenant deletion, instance restore, Super Admin assignment and break-glass, and optionally for route approval, but there is no entity or endpoint for a pending request: who asked, for exactly what payload, who approved, when it expires, and which job it produced. Only break-glass has an approve endpoint. DELETE /tenants/{id} is '202, dual control' with no way for a second person to act. support_access_grants has a single approved_by_identity_id although break-glass needs a requester and a different approver, both Super Admins. POST /routes:approve executes immediately, so optional 4-eyes for routes has no model.

<details><summary>Evidence</summary>

Plan 8.5: '`platform.tenant:delete` | `DELETE /tenants/{id}` | 2P'; '`platform.instance:restore` ... 2P | 2P'. Plan 8.7: 'break-glass — cần hai Super Admin (người yêu cầu ≠ người duyệt)'. Plan 7.1: 'tùy chọn 4-eyes cho policy/route'. Plan 6.3 support_access_grants columns include only 'approved_by_identity_id, approval_kind (tenant|breakglass)'.

</details>

**Suggested fix.** Add approval_requests(id, scope platform|tenant, tenant_id NULL, action, resource_type, resource_id, payload jsonb, payload_sha256, requested_by_identity_id, requested_at, expires_at, required_approvals smallint, status pending|approved|rejected|expired|executed|cancelled, executed_operation_id) and approval_decisions(request_id, decided_by_identity_id, decision, reason, decided_at, auth_time) with UNIQUE (request_id, decided_by_identity_id) and a trigger that the decider differs from the requester; RLS T+P. Endpoints: GET /platform/approvals, POST /platform/approvals/{id}/approve and /reject, and tenant equivalents under /tenants/{t}/approvals. A 2P operation returns 202 with the Location of the approval; execution happens only from an approved request whose payload_sha256 still matches. Add error code approval_required. Step-up applies to the approver.

### JOB-02 — MEDIUM — 11.3 'Quy tắc chung'; 6.3 provisioning_jobs / provisioning_job_steps; 8.5 platform.job:control

**Problem.** 1) Contradiction: a non-retryable error runs compensation in reverse order (resources torn down, tenant failed), yet :retry is said to continue from the failed step, which would then run against an instance that no longer exists. 2) The one-lifecycle-job lock is 'partial unique index + advisory lock': the index predicate is not defined (if policy.apply or inventory.sync rows share the table they would block a suspend), a session advisory lock is unsafe on a connection pool, and a transaction-level lock would be held across Agent and Headscale calls for up to ten minutes. 3) No reaper: if the worker dies the row stays running and the tenant is locked out of lifecycle operations. River rescues stuck jobs after one hour by default and its default job timeout is one minute, against the plan's ten-minute job. 4) The meaning of :cancel (compensate or stop) and whether a suspend can pre-empt a long upgrade are undefined. 5) Steps do not record what they created, although compensation is conditional on 'created by this job'.

<details><summary>Evidence</summary>

Plan 11.3: 'lỗi không retry được ⇒ chạy compensation ngược thứ tự các step đã hoàn tất; timeout toàn job 10 phút; **một** lifecycle job đang chạy cho mỗi tenant (partial unique index + advisory lock); job `failed` có thể `:retry` (tiếp tục từ step lỗi vì mọi step idempotent)'. Step 7 compensation: 'xóa thư mục **chỉ khi** do job này tạo'. River client.go (master): `JobTimeoutDefault = 1 * time.Minute`; RescueStuckJobsAfter 'Defaults to 1 hour'.

</details>

**Suggested fix.** Statuses queued|running|failed_resumable|compensating|rolled_back|succeeded|cancelled. Rule: retries exhausted on a transient error gives failed_resumable (no compensation; :retry resumes at the failed step; resources kept, edge not attached). An operator rollback or an unrecoverable error runs compensation and ends rolled_back (:retry then creates a new job from step 3). Step columns: tenant_id, started_at, finished_at, created_resources jsonb written before the side effect; the Agent also labels networks and containers with meshguard.job_id and writes a marker file, so ownership is read from reality. The lock is only UNIQUE (tenant_id) WHERE class='lifecycle' AND status IN ('queued','running','compensating','failed_resumable'); drop the advisory lock. Add job.reaper (every minute: timeout_at passed, or the queue job was discarded or cancelled, then mark and alert), set the worker Timeout() to ten minutes and RescueStuckJobsAfter to about fifteen minutes for the lifecycle queue. Define :cancel as 'stop after the current step, status failed_resumable'. The deny-all policy part of suspend runs immediately, outside the lifecycle lock.

### DEV-01 — MEDIUM — 6.3 device_inventory_cache and tenant_memberships; 6.4; 7.4 'Thu hồi thiết bị'; 17.2 steps 3-4; 13.4 CreatePreAuthKey

**Problem.** 1) device_inventory_cache is described as a disposable cache but holds authoritative platform data: the public deviceId, the enrolment link, and ownership that Headscale stops reporting once a node is tagged. Rebuilding it changes every device ID referenced by audit and enrolment records. 2) The two-phase revoke status (pending, applied, failed) has no storage; a revoke issued while the instance is unreachable is just an error and is never retried. 3) After a restore, revocations are replayed by walking the audit log, keyed by Headscale node id. Node and user ids are SQLite AUTOINCREMENT, so after restoring an older file, new nodes and users reuse ids the platform has cached for other objects. CreatePreAuthKey takes the numeric user id, so a cached headscale_user_id can point at a different member's Headscale user and the key enrols the device under that identity. The full unique key on (instance_id, headscale_node_id) also collides with tombstoned rows. 4) Post-restore reconciliation runs after the instance is started with the edge still attached, so revoked nodes and expired keys are valid again until it finishes. 5) Offboarding expires only nodes owned by the user; tagged devices that user enrolled are untouched and never expire.

<details><summary>Evidence</summary>

Plan 17.2: 'khởi động → health gate' then '(b) duyệt audit từ thời điểm backup để expire lại mọi node đã bị expire/delete sau đó'. Headscale v0.29.7 proto: `message CreatePreAuthKeyRequest { uint64 user = 1; ...}` versus `message AuthRegisterRequest { string user = 1; ...}`. hscontrol/db/schema.sql: `CREATE TABLE users( id integer PRIMARY KEY AUTOINCREMENT` and `CREATE TABLE nodes( id integer PRIMARY KEY AUTOINCREMENT`. hscontrol/grpcv1.go nodesToProto: `if node.IsTagged() { resp.User = types.TaggedDevices.Proto() }`.

</details>

**Suggested fix.** Split into devices (authoritative registry: id, tenant_id, instance_id, headscale_node_id, machine_key, enrolled_by_identity_id, owner_membership_id NULL when tagged, enrollment_request_id, first_seen_at, removed_at; UNIQUE (instance_id, headscale_node_id) WHERE removed_at IS NULL; sync rule: same node id with a different machine_key means tombstone and insert) and device_state (volatile: online, last_seen, addresses, routes, tags, expiry, synced_at). Add device_revocations(id, tenant_id, device_id, machine_key, node_key, action expire|delete, requested_by_identity_id, requested_at, state pending|applied|failed, attempts, verified_at, last_error), driven by a retrying job; the UI reads status from it; restore replays this table by machine_key. Never use cached numeric ids for writes: resolve ListUsers(name = mg-<membership_id>) immediately before CreatePreAuthKey, and after any restore re-resolve every headscale_user_id by name. Restore order: start the instance with the edge detached, re-apply policy, replay revocations, expire keys, sync, then re-attach the edge. The offboarding screen lists tagged devices enrolled by the user for an explicit decision.

### ENR-01 — MEDIUM — 7.4 flow A steps 4-8; 6.3 enrollment_requests; 8.6 enrollment rows; 11.4 Suspend; 18.1 T-06

**Problem.** enrollment_requests.status has no listed values and no transition diagram, although three methods plus approval, claim, consumption, expiry, revoke and reconcile all act on it. 1) Approval versus claim: flow A calls AuthRegister immediately at claim, yet tenant.enrollment:approve exists. Approval after the claim is impossible as specified, because the pending registration lives fifteen minutes in Headscale memory and the platform keeps only auth_id_hash. 2) Suspend says 'reject pending auth', but AuthReject needs the plaintext auth id and Headscale has no list call. 3) Step 8 deletes the node when the reported name differs from what the user typed. The name is the client-supplied hostname, so the check is weak against the phishing case and legitimate users will mistype hostnames. Worse, AuthRegister for a machine key that already has a node for that user is a re-authentication of the existing node, so 'delete immediately' destroys an established device (address, tags, approved routes). 4) T-06 lists 'claim page shows hostname/OS' as a mitigation while 7.4 states that this is impossible. 5) Missing columns: claim time and actor, failure reason, uniqueness on auth_id_hash; target_headscale_user_id is a cached numeric id (see DEV-01).

<details><summary>Evidence</summary>

Plan 7.4: 'lệch ⇒ xóa node ngay + `security_event`'; 'Portal không hiển thị được hostname/OS **trước** khi phê duyệt'. Plan 18.1 T-06: 'trang claim web-auth hiển thị hostname/OS + xác nhận tường minh'. Plan 11.4: 'expire mọi pre-auth key còn hiệu lực, reject pending auth'. Headscale v0.29.7 hscontrol/state/state.go HandleNodeFromAuthPath: `if nodeExists && !existingNode.IsTagged() { ... applyAuthNodeUpdate(updateParams)` (log text 'Updating existing node registration via reauth'). proto: `message AuthRejectRequest { string auth_id = 1; }`. hscontrol/auth.go registrationDataFromRequest: `hostname = req.Hostinfo.Hostname`.

</details>

**Suggested fix.** Add a state diagram. Web auth: requested -> (pending_approval -> approved | rejected) -> awaiting_device -> claimed -> registered -> verified, plus expired, revoked, failed. Pre-auth: approved -> credential_issued -> consumed | expired | revoked. Rule: approval, when the tenant requires it, happens before the device step; a claim succeeds only for an awaiting_device request of the same member and calls AuthRegister synchronously. Columns: status with CHECK, approved_at, claimed_at, claimed_from_ip, registered_machine_key, reported_hostname, failure_code, target_membership_id instead of the numeric id, UNIQUE (tenant_id, auth_id_hash). Post-registration check: if the returned node's created_at predates the claim (a re-auth), never delete; on mismatch call ExpireNode, raise a security event and show the reported hostname for an explicit 'this is my device' confirmation; normalise both names before comparing. Suspend: remove 'reject pending auth'; the claim endpoint refuses suspended tenants in portal mode, and the edge blocks /register/* and /oidc/callback for headscale_oidc tenants. Correct T-06.

### HS-01 — MEDIUM — 13.4 rules 2-5 and interface; 13.1 row 'Error model'; 14.6 admin listener row

**Problem.** The adapter contract does not match several verified behaviours. 1) Headscale answers HTTP 500 for ordinary domain errors (unknown or expired auth id, unknown user name in ListNodes or AuthRegister, duplicate user name, policy rejected by SetPolicy, node missing in ExpireNode), while CheckPolicy returns 400 and GetNode/DeleteNode return 404. With a per-instance circuit breaker and only two upstream codes, a user pasting a wrong Auth ID a few times can open the breaker for the whole tenant, and end users get 502 for their own input errors. No mapping table is given. 2) 'Retry only GET' excludes calls that are idempotent by construction (SetPolicy full replace, ExpireNode with an explicit time, SetApprovedRoutes, SetTags, ExpirePreAuthKey), which the two-phase flows need. 3) Instance.Version() has no route: /version is outside /api/v1, the admin listener forwards only /api/v1/*, and the public listener returns 404 for it. 4) GetNode and ListNodes differ: only the list fills subnet_routes and rewrites the user of tagged nodes to tagged-devices, so a cache update from a GetNode read-back would erase routes and ownership. 5) SetTags rejects an empty list; PUT tags with [] must be a 422, not an upstream error.

<details><summary>Evidence</summary>

Headscale v0.29.7 hscontrol/grpcv1.go: CreateUser `status.Errorf(codes.Internal, "creating user: %s", err)`; RegisterNode `return nil, fmt.Errorf("looking up user: %w", err)`; SetPolicy `return nil, fmt.Errorf("setting policy: %w", err)`; CheckPolicy `status.Error(codes.InvalidArgument, err.Error())`; GetNode `resp := node.Proto()` with no SubnetRoutes; SetTags 'cannot remove all tags from a node - tagged nodes must have at least one tag'. hscontrol/state/state.go: `hsdb.ErrNodeNotFoundRegistrationCache` returned as a plain error. hscontrol/app.go: `r.Get("/version", h.VersionHandler)` outside `r.Route("/api", ...)`. Plan 13.4: 'chỉ retry tự động cho lời gọi idempotent (`GET`)'. Plan 14.6: '**chỉ** `/api/v1/*`'.

</details>

**Suggested fix.** Add to 13.4 a mapping table (operation x HTTP status x gateway body code/message pattern -> Problem.code). Examples: AuthRegister 500 with a registration-cache miss -> 410 auth_request_expired; SetPolicy 500 after a successful CheckPolicy -> upstream_rejected plus the 'unknown' handling in POL-02; CreateUser 500 when the name exists -> treat as exists and list by name. The breaker counts only transport errors, timeouts, 502/503/504 from the edge and failures of GET /api/v1/health, never a 500 that carries a gateway JSON body. Retry classes: safe (GET), idempotent-write (the calls listed above; retry with backoff), non-idempotent (CreateUser, CreatePreAuthKey, CreateAPIKey, AuthRegister; reconcile by read instead). Allow GET /version on the admin listener only, or remove Version() and trust the digest in the registry. Normalise node reads through one function that always takes routes and owner from ListNodes. One contract test per row.

### IAM-03 — MEDIUM — 6.3 sessions; 8.3 steps 2, 5, 6, 7; 8.7 step 3; 13.2 platform row; 4.1 api row

**Problem.** Columns and tables needed by the described flows are missing. Step-up tests auth_time <= 15 minutes, but sessions has no auth_time. state, nonce and the PKCE verifier are 'stored server-side', but no table exists and the API is declared stateless. There is no storage or derivation rule for the CSRF token. sessions has no scope, origin or tenant, so nothing server-side stops a platform session being honoured on the tenant origin or the reverse. It is not stated whether roles are cached in the session (then offboarding and role changes lag up to twelve hours) or read on each request. Offboarding does not include revoking sessions, and there is no endpoint to list or revoke sessions although session revocation is a T-04 mitigation. Support staff: tenant endpoints are on the app origin, platform endpoints are 'only on the admin origin', and the staff cookie is bound to the admin host; the plan never says where a staff member with a grant calls /tenants/{t}/... .

<details><summary>Evidence</summary>

Plan 6.3 sessions columns: 'id_hash, identity_id, idp_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, ip, user_agent, acr, amr, revoked_at'. Plan 8.3: '`state` + `nonce` lưu phía server'; 'yêu cầu `auth_time` ≤ 15 phút'. Plan 4.1: 'api ... | Không (stateless)'. Plan 13.2 platform row: 'Chỉ phục vụ trên origin `admin.<domain>`'.

</details>

**Suggested fix.** sessions: add scope, tenant_id NULL, origin, auth_time, csrf_secret_hash, step_up_at, revoked_reason; index (identity_id) WHERE revoked_at IS NULL. Add auth_requests (see AUTH-01). After prompt=login or max_age, verify the auth_time claim of the new ID token and refuse step-up if it is absent or stale. The Authorizer loads membership, role and status on each request (or a cache of at most 30 seconds keyed by identity); sessions carry identity only. Offboard, lock or role change revokes all sessions of that identity in the same transaction. Endpoints: GET /auth/sessions, DELETE /auth/sessions/{id}, DELETE /tenants/{t}/users/{id}/sessions. State explicitly that tenant-scoped routes are also served on the admin origin for principals with scope=platform and an active grant, and that middleware rejects a session whose scope does not match the origin.

### SEC-01 — MEDIUM — 7.6 and its table; 6.3 secrets / tenant_keys; 6.1 row 'Retention'; 17.1; ADR-17; 18.1 T-05

**Problem.** 1) The KEK file is mounted into the Internet-facing api as well as the worker, and both use one database role. A compromise of api can therefore decrypt every tenant's Headscale API key and the platform-scope secrets, including the IdP admin credential that the table says only the worker uses, which allows creating identities in any realm. T-05's residual risk ('keys in use in memory') understates this. 2) Platform secrets (tenant_id NULL) have no data key: tenant_keys is keyed by tenant. 3) No data-key versioning (secrets.key_ref points at nothing versioned), no keyring format for holding old and new KEK during a rewrap, and no nonce or AAD on the wrapped key, so rows can be swapped between tenants. 4) UNIQUE(tenant_id, name, version) does not constrain platform rows, because NULLs are distinct. 5) Crypto-shredding is overstated. Destroying the tenant key makes two small secrets unreadable; the wrapped key survives in every PostgreSQL dump and WAL archive while the KEK lives on; tenant business rows, audit and identities are plaintext; and tenant backups are described both as encrypted with a tenant-bound key and with one host-wide public key whose private key is offline.

<details><summary>Evidence</summary>

Plan 7.6 table: 'KEK | File trên host + bản sao offline | api, worker'; 'Thông tin quản trị IdP (cho driver) | SecretStore | worker'; 'Khóa mã hóa backup | Public key trên host; private key offline'. Plan 17.1: 'Archive riêng từng tenant, khóa gắn tenant'. Plan 6.3: '`tenant_keys(tenant_id, wrapped_dek, kek_id, destroyed_at)`'; '`UNIQUE(tenant_id, name, version)`'. Plan 6.1: 'hủy DEK của tenant (crypto-shredding)'. Plan 6.1: '`mg_app` (API/worker; ...)'.

</details>

**Suggested fix.** data_keys(id, scope platform|tenant, tenant_id NULL, version, wrapped_dek, wrap_nonce, kek_id, alg, state active|retired|destroyed, created_at, destroyed_at) with UNIQUE NULLS NOT DISTINCT (tenant_id, version) and wrap AAD = scope|tenant_id|version; secrets.dek_id as a foreign key; UNIQUE NULLS NOT DISTINCT (tenant_id, name, version). Keyring directory with one file per kek_id and an ACTIVE pointer. Two KEKs: kek-tenant (api and worker) and kek-platform (worker only); separate database roles for api and worker, with a row-security policy on secrets that hides tenant_id IS NULL rows from the api role; the api gets Get only, for the Headscale API key. Data-key cache TTL of at most five minutes; cached API key dropped on a 401. Write down the deletion guarantee: either a per-tenant backup recipient whose private key exists only in SecretStore (shreddable; disaster recovery then needs the PostgreSQL backup and the KEK), or keep the offline recovery key and replace 'crypto-shredding' with 'physical deletion of archives, with a shredding horizon equal to PostgreSQL backup retention'.

### DB-05 — MEDIUM — 6.1 rows 'DB roles' and 'Platform scope'; 6.3 RLS column

**Problem.** Row security is keyed on settings that any role may set. 1) mg_readonly (reporting) can set app.scope to platform, or iterate app.tenant_id, and read every table including the tenant-internal ones the plan says staff may see only with a Support Access Grant. 2) api and worker share one role, so the tenant-facing request path holds the same database rights as the orchestrator. 3) Unscoped tables: identities (email and name of every tenant's users) and idempotency_keys; provisioning_job_steps has no tenant_id although listed as T+P. 4) Role scope is not enforced: tenant_memberships.role_id can reference a platform role and the reverse. 5) Issuer binding is a trigger; it does not fire when identities.idp_id or identity_providers.tenant_id changes, and under FORCE row security its lookup is filtered by the caller's settings.

<details><summary>Evidence</summary>

Plan 6.1: '`mg_readonly` (báo cáo)'; 'nhân sự nền tảng muốn đọc phải có Support Access Grant và đặt đúng `app.tenant_id`'. Plan 6.3: '`identities` ... | — (truy cập qua membership)'; '`steps(id, job_id, seq, name, status, attempt, detail jsonb, compensation_status)`'; '`tenant_memberships` ... trigger: IdP của identity phải thuộc **cùng** tenant'.

</details>

**Suggested fix.** Write policies per role: for the api role USING (tenant_id = app_tenant_id()); for the worker role USING (tenant_id = app_tenant_id() OR app_is_platform()). mg_readonly gets SELECT only on reporting views and aggregates, with no grant on tenant-internal tables. Add tenant_id (NULL for platform) to identities, immutable and copied from the IdP row, with row security T+P, and replace both triggers by declarative keys: identities UNIQUE (tenant_id, id); tenant_memberships FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id); a scope column on identities with UNIQUE (id, scope) and platform_users (identity_id, identity_scope CHECK = 'platform') referencing it; the same pattern for roles (id, scope). Make identity_providers.tenant_id and identities.idp_id immutable. Add tenant_id to provisioning_job_steps. For nullable composite references use ON DELETE SET NULL (child_column) so tenant_id is not set to NULL.

### AUD-01 — MEDIUM — 6.1 rows 'Audit history', 'DB roles', 'Retention'; 6.3 audit_events; 6.4 closing rule; 8.8 last paragraph

**Problem.** 1) mg_audit_writer is defined, but api and worker connect as mg_app. It is not said whether audit is written inside the business transaction (atomic, but then mg_app needs INSERT anyway) or on a second connection (then a crash loses the record, or records an action that was rolled back). 2) Denials must be recorded although the business transaction rolls back, and the tenant under which a cross-tenant denial is stored is undefined; storing it under the target tenant shows tenant B the identity of tenant A's user. 3) Rows are immutable, but writes go to Headscale first and many are asynchronous: one outcome per event cannot express requested, then applied or failed, and if the process dies after the Headscale call nothing is recorded. 4) actor_identity_id referencing identities either blocks deleting identities (retention 'by membership') or needs SET NULL, which the append-only trigger forbids. 5) Tenant deletion 'keeps minimal audit', which needs a per-tenant purge that both the append-only rule and month partitioning prevent. 6) A per-tenant hash chain needs serialised inserts and read access for the writer.

<details><summary>Evidence</summary>

Plan 6.1: '`mg_audit_writer` (chỉ `INSERT` vào `audit_events`)'; 'giữ audit tối thiểu theo chính sách'. Plan 6.4: 'mọi thao tác ghi đi qua Headscale API rồi mới cập nhật cache'; 'Danh tính ... Theo membership'. Plan 6.3 audit_events: 'outcome (success|denied|failure) ... prev_hash, hash'. Plan 8.8: 'Mọi quyết định từ chối đều ghi `audit_events (outcome=denied)`'.

</details>

**Suggested fix.** Decide: audit rows are inserted by the api and worker roles in the same transaction as the state change (INSERT only); keep mg_audit_writer solely for an out-of-transaction path, AuditLogger.RecordDetached(), on a small dedicated pool for denied and failed outcomes. Event model: an intent event (*.requested, committed before the external call) and a result event (*.succeeded or *.failed), correlated by operation_id. Add columns operation_id, target_tenant_id, actor_display (snapshot) and actor_subject_hash; make actor_identity_id a plain uuid without a foreign key. Cross-tenant denials: tenant_id is the actor's tenant, target_tenant_id is set, and the event is mirrored to platform-scope security_events. Purge: a SECURITY DEFINER function audit_purge_tenant(tenant_id, approval_id) owned by a separate role and callable only by the deprovision job, which first writes a platform tombstone event; the trigger exempts that role. Chain (Phase 6): take a per-tenant transaction advisory lock inside the insert function.

### DB-03 — MEDIUM — 6.3 tenant_instances and hosts; 11.3 step 3; 14.5-14.6; 10.2

**Problem.** 1) UNIQUE(control_hostname) and UNIQUE(host_id, stun_port) are full unique keys although rows are kept with status removed. A replacement instance for the same tenant cannot reuse its hostname, and removed rows consume the STUN range for ever (the allocator takes the smallest free port). 2) run_uid is an isolation boundary (IT-10) but has no uniqueness, and hosts has no UID range. 3) short_id names the compose project, network, container alias, admin routing header and metrics path, but is never defined or stored. Meanwhile the public listener builds the upstream from the host label (hs-<label>, that is the slug, as in the hs-a example). If short_id differs from the slug the public route cannot resolve; if it is the slug, that must be stated and the 32-character slug must fit container naming limits.

<details><summary>Evidence</summary>

Plan 6.3 tenant_instances: '`UNIQUE(control_hostname)`; `UNIQUE(host_id, stun_port)`; partial `UNIQUE(tenant_id) WHERE status <> 'removed'`'. hosts columns: 'id, name, region, agent_endpoint, agent_identity, status, capacity jsonb, stun_port_range int4range, last_heartbeat_at'. Plan 14.5: 'alias `hs-<short_id>` trên network tenant'. Plan 14.6: 'ghép thành upstream `hs-<label>:8080`'. Plan 10.2: '`a.<mesh_domain>` → edge → `hs-a:8080`'. A search of the plan finds no definition of short_id.

</details>

**Suggested fix.** tenant_instances: add short_id text NOT NULL (define it as equal to tenants.slug, with a CHECK regex), UNIQUE (short_id) WHERE status <> 'removed', UNIQUE (control_hostname) WHERE status <> 'removed', UNIQUE (host_id, stun_port) WHERE status <> 'removed', UNIQUE (host_id, run_uid) (never reused while data or backups exist). hosts: add run_uid_range int4range. Allocate under SELECT ... FOR UPDATE on the host row and extend the allocation race test in P3-T04 to UIDs.

### DB-04 — MEDIUM — 7.2 tagOwners row; 7.4 first paragraph; 8.6 conditions in cells; 6.3 tenants.settings and subscription_plans; 13.1 quota_exceeded

**Problem.** Features are described without storage. 1) Tag catalogue: tagOwners is rendered from 'the tenant's tag catalogue', lint L6 blocks undeclared tags, and the admin API needs a tag to exist in the applied policy, but there is no table, endpoint or permission; tags are free text arrays in three tables. 2) Security-relevant tenant switches (tailnet identity mode portal or headscale_oidc, self-enrol, policy 4-eyes, route 4-eyes, enrolment approval, node expiry) live implicitly in settings jsonb, with no schema and no immutability rule; switching identity mode after users exist creates duplicate Headscale users (ID-08). 3) Quota: limits jsonb has no defined keys; the check reads a lagging cache without a lock, so concurrent enrolments exceed the limit and unexpired credentials are not counted; platform screens need per-tenant counts but may not read tenant-internal tables. 4) In headscale_oidc mode the instance's own OIDC client (id and secret reference) has no column.

<details><summary>Evidence</summary>

Plan 7.2: '`tagOwners` | Danh mục tag của tenant'. Plan 7.4: 'mỗi tenant chọn **một** chế độ danh tính tailnet (`portal` hoặc `headscale_oidc`)'. Plan 8.6: '✔ (nếu tenant cho phép self-enroll)'; 'khi tenant bật 4-eyes'. Plan 6.3: '`plans(id, key, name, limits jsonb, is_active)`'; tenants column 'settings jsonb'. Plan 7.4 step 3: 'Backend kiểm tra ... quota'.

</details>

**Suggested fix.** tenant_tags(id, tenant_id, name with CHECK (name ~ '^tag:[a-z0-9-]{1,50}$'), purpose router|exit|server|custom, platform_managed bool, description, version), UNIQUE (tenant_id, name); endpoints GET/POST /tenants/{t}/tags and PATCH/DELETE /tenants/{t}/tags/{id} with permission tenant.tag:manage; deletion refused while a device, key or grant references the tag; other tables reference tag ids. Typed columns on tenants (or a 1:1 tenant_security_settings): tailnet_identity_mode (immutable once any Headscale user exists), self_enroll_enabled, enrollment_requires_approval, policy_four_eyes, route_four_eyes, node_expiry_days; keep settings jsonb for cosmetics with a JSON Schema. tenant_usage_counters(tenant_id, metric, value, updated_at), T+P, updated under SELECT ... FOR UPDATE in the enrolment transaction; quota counts registered devices plus live credentials; document limit keys (max_devices, max_users, max_tagged_devices, max_live_enrollment_credentials). tenant_instances.oidc_client_id and oidc_client_secret_ref.

### IAM-04 — MEDIUM — 8.2 'IdP driver' paragraph (external); 13.2 settings / idp row; 15.2 api / worker row; 18 threat table

**Problem.** The backend fetches URLs chosen by a Tenant Owner: the discovery document, the key set, and on every login the token endpoint. api and worker sit on the edge, admin and data networks. No validation rules are given and the threat table has no server-side request forgery entry. A hostile issuer or discovery document can point token_endpoint or jwks_uri at internal addresses (the edge admin listener, the IdP's internal port, PostgreSQL, link-local metadata) or redirect there, and can stall logins with slow responses.

<details><summary>Evidence</summary>

Plan 8.2: '`external` (chỉ ghi nhận issuer/client do tenant cung cấp, kiểm tra discovery)'. Plan 15.2: 'api / worker | PostgreSQL; edge listener admin; IdP (discovery, token, Admin API)'. Plan 15.1: 'api | ... | Chỉ `mg-edge`, `mg-admin`, `mg-data`'. Threats T-01 to T-18 contain no SSRF item.

</details>

**Suggested fix.** Specify one outbound fetcher for all IdP calls: https only; resolve once and connect to the resolved address; reject loopback, RFC 1918, 100.64.0.0/10, link-local, unique-local, the host's own addresses and the platform's own domains; no redirects; five-second total timeout; 1 MiB body limit; the issuer in the document must equal the configured issuer and all endpoint hosts must share its registrable domain unless a Super Admin approves; cache discovery and keys with bounded refresh. Route these calls through an egress-only network that is not the admin or data network. Add threat T-19 and one negative test per rule.

### API-03 — MEDIUM — 13.1 rows 'Thao tác dài' and 'Độ tươi dữ liệu'; 13.2 rows jobs, routes, support grants, platform, internal; 16.1; 14.7

**Problem.** 1) Location: /api/v1/jobs/{jobId} and GET /jobs/{jobId} have no tenant in the path, breaking the rule that tenant context always comes from the path and making object-level authorization implicit. There is no GET /platform/jobs/{id}. Job has no link to the resource it creates (the wizard cannot navigate to the new tenant) and exposes raw step detail to Tenant Viewers. 2) POST /routes:approve and :revoke send deltas, but Headscale replaces the whole approved set: without a per-node lock and a fresh read this is a lost-update race on a stale cache. PUT tags has the same last-write-wins problem; device resources have no version or ETag. 3) ?fresh=true combined with cursor pagination is undefined (Headscale lists are unpaginated). 4) Catalogue gaps: no platform-side list or revoke for support grants although a Super Admin may revoke, no reject on the tenant side, GET /internal/prometheus/sd used in 16.1 is missing from 13.2, no endpoints for the unban button and tenant allowlist promised in 14.7, and no 428 for a missing If-Match.

<details><summary>Evidence</summary>

Plan 13.1: 'Trả `202 Accepted` + `Location: /api/v1/jobs/{jobId}`'; 'Tenant context | **Luôn** là path param `{tenantId}`'. Plan 13.2: '`GET /tenants/{t}/jobs` · `GET /jobs/{jobId}`'; 'Body `{device_id, prefixes[]}`'; platform row lists only `GET /platform/jobs`, `:retry`, `:cancel`. Fact PL-10: 'lời gọi **thay thế** toàn bộ danh sách'. Plan 16.1: '`GET /internal/prometheus/sd`'. Plan 8.7 step 4: 'tenant hoặc Super Admin thu hồi được bất cứ lúc nào'. Plan 14.7: 'nút gỡ ban trong Platform Console'.

</details>

**Suggested fix.** Location is /api/v1/tenants/{t}/operations/{id} or /api/v1/platform/operations/{id}; add GET /platform/operations/{id}; add tenant_id and resource {type, id} to Job, with a tenant-safe step projection (name, status, timestamps, public message). Routes: PUT /tenants/{t}/devices/{id}/approved-routes with the full set, ETag = hash of the approved set read live, If-Match required, executed under a per-instance lock; refuse prefixes not currently advertised. Same ETag rule for tags. fresh=true triggers a bounded sync and then serves page 1 from the registry; reject fresh together with cursor. Add the missing endpoints and precondition_required (428).

### OPS-01 — MEDIUM — 4.2 module list; 6.3; 11.3 steps 16 and 19; 8.7 step 2; 18.1 T-03, T-04, T-06, T-08; 15.2

**Problem.** At least eight controls depend on notifying someone: the Owner invitation, enrolment instructions, the break-glass notice to the Owner, new-device notices, policy and route approval requests, pre-expiry warnings, grant requests and IdP changes. There is no module, table, job, channel configuration or template set. SMTP appears only as optional in the egress table and in Appendix A. Several of these notifications are listed as threat mitigations.

<details><summary>Evidence</summary>

Plan 11.3 step 19: 'audit; thông báo'; flow 11.2: 'gửi hướng dẫn enrollment cho Tenant Owner'. Plan 8.7: 'thông báo cho Tenant Owner'. Plan 18.1 T-03: 'thông báo node mới cho tenant'; T-06: 'thông báo thiết bị mới'. Plan 15.2: '(tùy chọn) SMTP'. The module table in 4.2 and the table catalogue in 6.3 contain nothing for notifications.

</details>

**Suggested fix.** Add module notify and table notification_outbox(id, tenant_id NULL, kind, recipient_identity_id NULL, recipient_email NULL, locale, payload jsonb without secrets, dedupe_key, status pending|sent|failed|suppressed, attempts, next_attempt_at, sent_at), written in the same transaction as the triggering change. Add job notification.deliver with backoff, system_settings keys for SMTP and webhook, per-tenant recipients for security notices, an in-portal inbox endpoint GET /tenants/{t}/notifications, and vi/en templates. Either make SMTP a prerequisite for gate G2 or state which mitigations are inactive without it.

## Roadmap, task graph and testability (sections 19-25, 5.2, Appendix A/B; cross-checked against deliverables in sections 3-18 and against juanfont/headscale@v0.29.7 and tailscale/tailscale@v1.104.7 sources)

**Verdict:** Not ready to hand to a coding agent as written. No architectural decision needs reversing from this lens, and I found no critical issue, but there are 10 high, 14 medium and 1 low findings. Three gates cannot be passed with the deliverables of their own phase: G1 evidence is collected under a deny-all policy (peers are invisible, so the isolation check passes vacuously), G3 needs enrollment and an allow policy that only exist in Phase 4, and G5 needs a public path that no earlier gate requires. G0 admits dead-end states (no domain, no test devices, no privilege-escalation method, a single-issuer IdP). About a dozen cross-cutting deliverables have no task: IdP driver, invitations, first-admin bootstrap, dual control, notifications, PostgreSQL/KEK backup, STUN/HTTPS probes, CI/registry/dev harness. Phase 1 and Phase 3 dependency rows are wrong in ways that would produce invalid Go/No-Go evidence. All findings are fixable by editing gate text and adding roughly 35 task rows; proposed IDs and paste-ready rows are in each issue.

**Strengths noted:**

- Counts and cross-references are internally consistent (98 tasks, 20 AC, 13 IT, 15 V, 19 provisioning steps), and I found no dependency cycle in section 20.
- Every task row carries dependency, output and verification columns, and Phase 4 correctly models its migrations (P4-T05) as an explicit dependency.
- The test strategy separates 'functional' from 'network E2E verified' evidence and records latencies as measured values rather than commitments; I found no invented performance numbers or effort estimates.
- P3-T07 (fault injection at every step plus an orphan-resource detector) and contract tests against a real pinned Headscale are the right verification for the orchestrator and the adapter.
- Upstream facts I spot-checked against the pinned tags match the plan: auth RPCs, CLI flags (`policy set -f`, `apikeys create -e`), in-process fail-closed DERP verification, bcrypt on every API-key validation, and the client test commands named in section 9.5.

### RM-01 — HIGH — §20 P1-T08/T12/T13; §19 Phase 1 (E2E, G1); §22.2 AC-08/09/13/16/18; §5.2 IT-05/07/08

**Problem.** Phase 1 leaves both tenants on the deny-all baseline and no task applies an allow policy before the real-client tests. Under `{"grants": []}` Headscale gives a node no peers at all. Consequences: (a) AC-08/09 evidence (`tailscale status` shows the other client) fails as written; (b) 'TCP cùng tenant', G1(2) 'DERP qua Caddy truyền được dữ liệu' and AC-18 'tunnel direct của A được quan sát' cannot be produced; (c) AC-13/IT-05, and later IT-07/IT-08, pass vacuously: client A shows no key of B because it shows no keys at all. The isolation evidence collected for G1/M1 would prove nothing. AC-08's 'node có trong inventory' also presumes a backend that does not exist in Phase 1.

<details><summary>Evidence</summary>

Plan: P1-T08 'policy deny-all qua CLI … | `policy get` = baseline'; P1-T12 '2 client/tenant (pre-auth key), TCP cùng tenant, cô lập chéo tenant, ép relay qua Caddy' (no policy step); AC-13 '`tailscale status --json` trên client A không chứa node key nào của B'; CL-12 'node chỉ nhận public key của peer nó được phép nói chuyện'. Upstream v0.29.7: hscontrol/policy/v2/policy.go `BuildPeerMap`, global-filter branch (~l.697-775), links two nodes only `if canAccess(srcOf[i], dstOf[j]) || canAccess(srcOf[j], dstOf[i])`; with zero matchers both sets stay nil, so the peer map is empty. hscontrol/state/state.go l.368-373 installs it as the NodeStore peers function, and hscontrol/mapper/mapper.go builds the peer list from `state.ListPeers`.

</details>

**Suggested fix.** 1) Add fixture `infrastructure/headscale/templates/test-allow-intra.hujson`, e.g. `{"grants":[{"src":["autogroup:member"],"dst":["autogroup:member"],"ip":["tcp:5201"]}],"ssh":[]}`.
2) New row: `| P1-T12a | Áp policy thử nghiệm test-allow-intra.hujson lên A và B qua CLI sau khi baseline đã được xác minh; sau P1-T13 trả về baseline | P1-T09 | sha256 trước/sau | policy get khớp fixture; cuối cùng khớp lại baseline |`.
3) P1-T12 deps -> `P1-T09, P1-T10, P1-T12a`; P1-T13 deps -> `P1-T12`.
4) Add to AC-13, IT-05, IT-07, IT-08: 'Tiền điều kiện: mỗi tenant có ≥ 2 node online và mỗi client thấy ≥ 1 peer cùng tenant; nếu danh sách peer rỗng thì phép thử không hợp lệ.'
5) In P1-T12 also check that a port other than 5201 is blocked (early AC-11 smoke).
6) Phase 1 evidence for AC-08/09: `headscale nodes list` instead of 'inventory'.

### RM-02 — HIGH — §19 Phase 3 (E2E, G3); §20 P3-T08, P3-T14; Phase 4 modules enrollment/policies

**Problem.** G3's end-to-end test needs two capabilities that are only built in Phase 4. (a) Enrollment: there is no API or Agent operation that creates a pre-auth key before P4-T06, and the Agent accepts only declared specs, not arbitrary CLI. (b) An allow policy: the policies module is P4-T10, so a freshly provisioned tenant C has only the deny-all baseline. 'Suspend chặn lưu lượng; khôi phục khi resume' therefore has no traffic to block and nothing to restore, because resume re-applies the saved version, which is the same deny-all. Migration 0011 creates the table, but no Phase 3 task builds the code that stores, lints and applies a `user` or `suspension` policy version.

<details><summary>Evidence</summary>

Phase 3 E2E: 'Tạo tenant C qua API → client thật enroll → suspend chặn lưu lượng → resume → deprovision'; P3-T08 verification 'Lưu lượng bị chặn khi suspend; khôi phục khi resume'; Phase 3 migrations '0011 policy_versions (đủ cho baseline/suspension)'; Phase 4 'Files/modules expected: … internal/{enrollment,policies,network}'; §11.1 Agent 'không nhận lệnh tùy ý'.

</details>

**Suggested fix.** Add rows:
`| P3-T08a | Lõi policy tối thiểu (tiền thân internal/policies): lưu policy_versions từ HuJSON thô (kind=user|baseline|suspension), lint L1/L2, advisory lock theo tenant, CheckPolicy → SetPolicy → GetPolicy khớp sha256; lệnh nội bộ để áp fixture | P3-T06, P2-T09 | internal/policies (core) | Integration với Headscale thật: áp fixture allow ⇒ sha khớp; chuỗi rỗng/thiếu grants bị chặn |`
`| P3-T14a | Helper kiểm thử enrollment: tạo Headscale user + pre-auth key (expiration tường minh, dùng 1 lần) qua adapter cho tenant C; chỉ build với tag test | P2-T09 | tests/e2e/helpers | Client (container hoặc thiết bị thật) join được tenant C |`
P3-T08 deps -> `P3-T05, P3-T06, P3-T08a`; P3-T14 deps add `P3-T14a`. P4-T10 text -> 'mở rộng lõi P3-T08a: mô hình có cấu trúc, render, L3–L10, vòng đời, drift'. Rewrite the E2E cell: '… → áp fixture allow → TCP thông → suspend ⇒ TCP bị chặn → resume ⇒ TCP thông lại → deprovision'.

### RM-03 — HIGH — §19 Phase 5 (Dependencies, G5) and G1(4); §22.3 M5; §21.3; §15.3; P6-T07 / TD-12

**Problem.** M5/G5 require the network ACs at 'network E2E verified' level, meaning real devices on different networks. The second network the plan names is LTE/hotspot, which cannot reach a LAN-only host. Yet no gate before G5 requires an exposure path: G1(4) may be left 'pending', D-2 is only 'for the Internet-facing stage', and Phase 5's dependency lists devices and networks but not reachability. Without Path A/B/C, AC-15/16/17 cannot reach the required evidence level and G5 blocks at the very end. Conversely, if the host is exposed for Phase 5, the ingress firewall baseline is still only a proposal (P1-T14); it is implemented in P6-T07, after the exposure.

<details><summary>Evidence</summary>

G1: '(nếu chưa có đường public: ghi "pending" và không được tuyên bố Internet-facing)'; Phase 5 Dependencies: 'G4; có ≥ 4 thiết bị thật và ≥ 2 mạng'; M5: 'AC mạng ở mức "network E2E verified"'; §15.3: 'Phép thử NAT/relay cần thêm mạng thứ hai (hotspot/LTE) và, cho relay qua Internet, cần đường public'; P6-T07: 'Hardening host: quy tắc DOCKER-USER/nftables (ingress + egress pool tenant)'; TD-12.

</details>

**Suggested fix.** 1) Phase 5 Dependencies -> 'G4; ≥ 4 thiết bị thật; và MỘT trong hai: (a) Exposure Path A/B/C đã bật và AC-20 + V-02 đã chạy lại từ Internet; hoặc (b) quyết định bằng văn bản "MVP LAN-only" với mạng thứ hai là một segment NAT nội bộ (router phụ có WAN nằm trên LAN của host) — khi đó AC-15/16 ghi "network E2E verified (LAN NAT)" và phần Internet ghi là ngoại lệ được chấp nhận'.
2) New row: `| P5-T02a | Bật exposure path theo D-2: ingress baseline DOCKER-USER (cho 80/443/dải STUN; SSH chỉ từ mạng quản trị; tách từ P6-T07) → port forwarding/DNS → chạy lại AC-20 và netcheck (V-02) từ mạng ngoài | G4, D-2, người dùng duyệt | Báo cáo | Port scan từ ngoài chỉ thấy 80/443 + dải STUN |`.
3) P6-T07 keeps egress rules and the benchmark only.
4) Add to G5: 'mục G1(4) "pending" phải được đóng hoặc có ngoại lệ bằng văn bản'.

### RM-04 — HIGH — §19 G0; §21.3; §25.4 D-1/D-3; Appendix A.1 (#12, #13, #15); §25.1 rule 4

**Problem.** G0 can be passed in states from which G1 or G2 can never be passed.
(a) 'hoặc quyết định làm lab hạn chế' (no domain): §15.3 says that mode cannot run TLS or embedded DERP, but G1(1) and G1(2) require both, and the serial-gate rule forbids starting Phase 2. The branch is a dead end.
(b) G0 does not require the test clients that G1(1) and P1-T12 need (≥ 2 OS; 2 clients per tenant, outside the host).
(c) Access is 'SSH key, never passwords', but no privilege-escalation method is defined. Discovery rows 6, 10, 16, 18 and all of P1-T02 need root; the word sudo does not appear in the plan.
(d) D-3 is listed as a decision 'trước/ở G0' although its own recommendation says 'xác định ở P1-T01'. Its fallback 'dùng IdP sẵn có' yields one issuer, which cannot satisfy issuer binding, IT-01 or AC-06/07 (a platform issuer plus two tenant issuers are needed).
(e) G0 requires 'cấu hình phần cứng', which P1-T01, a post-G0 task, is the one that measures.

<details><summary>Evidence</summary>

G0: 'domain + DNS provider (hoặc quyết định làm lab hạn chế), cấu hình phần cứng, phương thức truy cập SSH bằng key, xác nhận đã đọc R-01'; §15.3: 'không bật được embedded DERP (cần https) … không dùng để nghiệm thu AC-08…AC-17'; §19: 'không bắt đầu phase kế tiếp khi Go/No-Go gate của phase trước chưa đạt'; §25.1(4): 'Chỉ dùng SSH key; không bao giờ dùng/ghi mật khẩu'; D-3: 'Keycloak nếu host còn đủ RAM … (xác định ở P1-T01); nếu không, dùng IdP sẵn có'; §8.4 invariant 1 (issuer binding).

</details>

**Suggested fix.** Replace the G0 cell with: 'Kiến trúc được duyệt và có đủ: (1) domain + DNS provider có API — bắt buộc; chưa có ⇒ không qua G0 (chỉ làm Phase 0 và các task backend không chạm host); (2) thông số host do người dùng khai, xác minh lại ở P1-T01; (3) SSH key + cơ chế nâng quyền không dùng mật khẩu (sudoers NOPASSWD có phạm vi, hoặc người dùng tự chạy script đặc quyền do agent sinh rồi trả output); (4) danh sách client thử: ≥ 4 client ngoài host trên ≥ 2 hệ điều hành; (5) Git hosting, CI runner, registry (A.1 #15); (6) D-3 sơ bộ: phương án phải cho ≥ 3 issuer tách biệt (Keycloak 3 realm, hoặc 3 IdP nhẹ một-issuer cho lab), chốt sau P1-T01; (7) số người vận hành cho dual control; (8) xác nhận đã đọc R-01.' Add A.1 rows 17 (cơ chế nâng quyền) and 18 (số người vận hành). Delete the 'lab hạn chế' alternative, or define a separate G1-lab with its own reduced criteria.

### RM-05 — HIGH — §5.2; §22.1 (Isolation row); §20 P2-T15, P5-T05, P5-T06; §9.5; §14.3

**Problem.** The isolation suite, which the plan calls 'tiêu chí số một', is only partly executable.
(a) IT-07 (DNS) and IT-08 (routes, exit node) are referenced by no task, no AC and no gate, and the Phase 5 lab (P5-T02) has no subnet router, exit node or extra record.
(b) IT-09 is assigned to P5-T06 with verification '§9.5', but §9.5 has no method for it. An official client cannot be pointed at another tenant's relay, so the test needs a custom DERP client presenting an unregistered or foreign key, which is how upstream tests it. IT-09 covers the only relay isolation boundary, yet it is not run at G1, where the DERP-through-Caddy decision is taken.
(c) §22.1 schedules IT-01…IT-13 'Mỗi PR + trước mỗi gate', but IT-04/05/07/08/09/13 need Tailscale clients and no task builds a client harness.
(d) P2-T15 claims IT-12 in Phase 2, but IT-12 covers 'audit/usage/relay'; usage is P6-T11 and the relay/metrics query has no phase.
(e) The noisy-neighbour half of IT-04 is P6-T09.
(f) No test asserts the §14.3 claim that a container on a tenant network cannot reach the edge admin/metrics listeners or another tenant's Headscale.

<details><summary>Evidence</summary>

P5-T06: 'AC-15 direct P2P; AC-16 ép relay qua relay của tenant; IT-09 | … | §9.5'; §22.1: 'IT-01…IT-13 (§5.2) | Bộ test riêng tests/isolation | Mỗi PR + trước mỗi gate'; P2-T15: 'Isolation suite v1 (IT-01, 02, 03, 06, 10, 12)'; IT-12: 'API audit/usage/relay của A không trả sự kiện/số liệu của B'; §14.3: 'để container của một tenant không gọi được chúng qua network tenant'. Upstream v0.29.7: integration/derp_verify_endpoint_test.go `DERPVerify` builds `derphttp.NewRegionClient(nodeKey, …)` and integration/embedded_derp_test.go l.66-67 calls it with `fakeKey := key.NewNode()`.

</details>

**Suggested fix.** Add to §5.2 a table mapping each IT to owner task, automation level and first gate. New rows:
`| P1-T12b | derpprobe: công cụ Go dùng tailscale.com/derp/derphttp@v1.104.7 — (i) key ngẫu nhiên, (ii) node key của một client lab Linux thuộc B (đọc từ state của client đó) → /derp của A qua edge phải bị từ chối; (iii) node key của A được nhận | P1-T12 | tests/isolation/derpprobe | (i)(ii) bị từ chối, (iii) được nhận ⇒ IT-09 đạt ở G1 |`
`| P1-T12c | IT-14 (mới): từ một container thử gắn vào network của một tenant PoC dùng tạm — không gọi được listener admin/metrics của edge, không tới được hs-<tenant khác>:8080/9090 | P1-T10 | Bằng chứng | Mọi kết nối bị từ chối hoặc timeout |`
`| P5-T05a | IT-07/IT-08: lab thêm 1 subnet router + exit node (Linux, có tag) ở A và 1 extra record ở B; từ client của tenant kia: không thấy route/exit node, tên không phân giải | P5-T02, P4-T12 | Bằng chứng | Đạt cả hai chiều |`
Split IT-12 into IT-12a audit (G2), IT-12b dashboard/relay metrics (phase where built), IT-12c usage (G6). Change the §22.1 row to: 'IT-01/02/03/06/10/11/12a: mỗi PR; IT-05/07/08/09/13/14 ở mức functional bằng client container: hằng đêm; mức network-verified: G1 và G5'.

### RM-06 — HIGH — §11.3 steps 17–18; §14.3; §15.2; §16.1; §20 P3-T05, P6-T01

**Problem.** Two provisioning steps cannot be implemented as specified. Step 18 `edge.verify` is run by the Worker 'qua đường public' and step 17 checks that 'cổng STUN phản hồi'. The Worker is attached only to `mg-data` and `mg-admin`, both marked `internal`; it is not on the tenant network, and the Agent has `network_mode: none`. No network path from the Worker to the public listener or to the host-published UDP port is specified. The STUN prober itself ('Probe STUN/DERP tự viết') is built in P6-T01, three phases after the state machine that calls it. The same gap applies to the monitoring probes on `mg-obs` (`internal`) and to §15.2, which requires Worker egress to the IdP Admin API, SMTP and the DNS provider.

<details><summary>Evidence</summary>

§11.3 step 17: 'kiểm tra /derp/probe và cổng STUN phản hồi'; step 18: 'Worker | qua đường **public**: GET /key trả 200; /api/v1/* … **không** truy cập được'; §14.3: '`mg-data` (`internal`) | api, worker, postgres', '`mg-admin` (`internal`, subnet tĩnh) | edge (IP tĩnh), api, worker', '(không network) | agent'; §15.2: 'api / worker | PostgreSQL; edge listener admin; IdP (discovery, token, Admin API); (tùy chọn) SMTP, DNS provider'; P6-T01: 'Monitoring đầy đủ (HTTP SD, dashboard, alert rule, probe STUN/DERP)'.

</details>

**Suggested fix.** Decide the vantage point and task it:
`| P3-T03a | meshguard probe (chế độ chạy thứ tư hoặc sidecar): STUN binding tới <host>:<stun_port>; HTTPS GET với SNI/Host chỉ định; gắn vào network mg-probe (bridge thường, chỉ egress) + mg-admin; RPC nội bộ cho worker | P2-T01 | apps/probe, compose.core | Cổng đúng trả mapped address; cổng sai ⇒ lỗi; path cấm ⇒ 404 |`
P3-T05 deps add `P3-T03a`; P6-T01 reuses the probe instead of building it. In §11.3 state that steps 17–18 are 'functional (từ trong host)' and that the external check is AC-20 at G1/G5. Correct §14.3 so the Worker (or the API on its behalf) has the egress §15.2 requires. Put the step 4/17/18 checks behind an interface so CI can run the state machine without public DNS.

### RM-07 — HIGH — §8.2; §11.3 steps 6, 16, 19; §8.4; §4.2; §20 P2-T05, P2-T11, P4-T09

**Problem.** Identity plumbing that Phases 2–4 depend on has no task and, in part, no design.
(a) IdP driver (`keycloak` / `external`, step `idp.ensure`): no module in §4.2, no entry in any phase's file list, no task. P2-T05 creates three realms by hand and P4-T09 merely uses 'IdP driver'. A tenant created in Phase 3 therefore has no issuer and nobody can log in to it.
(b) Invitations (step 16 'membership Owner (lời mời)'): an `identities` row only exists after first login, there is no invitations table, and with the `external` driver the platform cannot create the user.
(c) First Super Admin: no bootstrap procedure, while invariant 3 demands a second Super Admin to approve a Super Admin assignment.
(d) Tenant Admin memberships for A and B, needed by the Phase 2 E2E, cannot be created: the Phase 2 `users` API is read-only.
(e) `adopt-instance` has no home (no CLI app in §4.4) and no defined input.

<details><summary>Evidence</summary>

§8.2: 'IdP driver (bước idp.ensure của orchestrator): keycloak … và external'; P2-T05: 'IdP: compose + realm template (platform, tenant-a, tenant-b), MFA'; P4-T09: 'mời qua IdP driver'; §6.3 identities: 'UNIQUE(idp_id, subject)' with §8.3 step 3 'upsert identities (idp_id, sub)'; §8.4(3): 'gán role SA cần SA thứ hai phê duyệt'; Phase 2 API changes: 'users (đọc)'; Phase 2 E2E: 'Tenant Admin A bị 404 ở B'.

</details>

**Suggested fix.** Add rows:
`| P2-T05a | internal/idp: interface IdPDriver {EnsureIssuer, DisableIssuer, InviteUser, DisableUser, CheckDiscovery}; driver keycloak (Admin REST, realm từ template) + driver external | P2-T04, P2-T05 | internal/idp | Integration với Keycloak thật: tạo/xóa realm idempotent; thông tin quản trị chỉ lấy từ SecretStore |`
`| P2-T11a | meshguard admin bootstrap (subcommand, chỉ chạy trên host): tạo 2 Super Admin đầu tiên theo (issuer, sub); seed membership TO/TA cho A và B; audit actor_type=system | P2-T06, P2-T07, P2-T08 | apps/api | Lần chạy thứ hai bị từ chối; E2E Phase 2 dùng các identity này |`
`| P3-T05a | Lời mời: bảng invitations (tenant_id, idp_id, email, role_id, token_hash, expires_at, accepted_identity_id) trong 0007; gắn (idp_id, sub) ở lần đăng nhập đầu; với driver external bắt buộc email_verified | P2-T05a, P3-T06 | internal/tenants | Lời mời hết hạn / sai issuer / sai email bị từ chối |`
P3-T05 deps add `P2-T05a, P3-T05a`. Define `tenant.manifest.yaml` (tenant_id, instance_id, short_id, slug, stun_port, run_uid) as an output of P1-T07 and the input of adopt-instance; add `internal/idp` to §4.2 and to the Phase 2 file list.

### RM-08 — HIGH — §8.5 (2P cells); §13.2; §6.3; §19 Phase 3 Security controls; §20 P3-T09, P3-T11; ADR-13

**Problem.** Dual control is a Phase 3 security control and a G3 prerequisite, since deprovision and restore are both marked 2P, and ADR-13 names 'test 2P' as its validation. The mechanism does not exist in the design. There is no table holding a pending approval, no endpoint for the second person (only break-glass has one), no hook between approval and job enqueue, and no task. `DELETE /tenants/{id}` '(202, dual control)' has nowhere to wait. The plan also never asks whether a second human operator exists; one person holding two accounts defeats the control.

<details><summary>Evidence</summary>

§8.5: '`platform.tenant:delete` | DELETE /tenants/{id} | 2P', '`platform.instance:restore` | … | 2P | 2P', 'platform.user … (SA role: 2P)'; §13.2 platform group contains only 'POST /platform/support-grants/{id}:approve-breakglass' as an approval call; §6.3 has no approval table; Phase 3 Security controls: 'dual control cho xóa/restore'; ADR-13 validation: 'Ma trận authz sinh từ OpenAPI; test 2P'.

</details>

**Suggested fix.** Design: in migration 0007 add `approval_requests(id, tenant_id NULL, action, resource_type, resource_id, payload_sha256, requested_by_identity_id, approved_by_identity_id, status{pending,approved,rejected,expired,executed}, reason, expires_at, job_id)` with `CHECK (approved_by_identity_id <> requested_by_identity_id)`. Endpoints: `GET /platform/approvals`, `POST /platform/approvals/{id}:approve`, `:reject` (step-up required). A 2P operation returns 202 with the approval id and enqueues its job only on approval.
Row: `| P3-T04a | Dual control: approval_requests + API + thực thi sau khi duyệt | P2-T06, P2-T07, P2-T08, P2-T12, P3-T06 | internal/authz/approvals | Tự duyệt ⇒ 403; hết hạn ⇒ không thực thi; payload đổi sau khi duyệt ⇒ từ chối; audit ghi cả hai actor |`
P3-T09 and P3-T11 deps add `P3-T04a`. A.1 new row: 'Số người vận hành nền tảng; nếu chỉ 1 người, người dùng chọn chế độ thay thế (ví dụ trì hoãn có thông báo) và ghi vào ADR-13'.

### RM-09 — HIGH — §17.1; §17.2; §7.6; TD-05; §19 Phase 2 Rollback; §20 P3-T11; ADR-17, ADR-18

**Problem.** Backup duties the plan assigns to the MVP have no task, and the tenant-backup key model contradicts itself.
(a) 'PostgreSQL: MVP logical dump nén mỗi đêm' (TD-05) and the Phase 2 rollback 'restore PostgreSQL từ dump trước migration' have no task before P6-T03. PostgreSQL holds the registry, the policy history and every wrapped Headscale API key.
(b) Offline custody of the KEK and the backup key (ADR-17) has no task, although the KEK is first needed at P2-T04.
(c) IdP database and edge ACME volume backups (§17.1) have no task.
(d) §7.6 says the backup private key is offline and the operator decrypts. §17.1 and T-15 say each archive uses a tenant-bound key. §17.2 says the Agent decrypts inside an automated restore job. P3-T11 cannot be built without choosing one model.
(e) The restore check 'headscale_version ≤ version đang chạy' is too weak: Headscale refuses to start on a database more than one minor version behind.

<details><summary>Evidence</summary>

§17.1: 'MVP: logical dump nén mỗi đêm'; Phase 2 Rollback: 'restore PostgreSQL từ dump trước migration'; §7.6: 'Khóa mã hóa backup | Public key trên host; private key offline | Agent (mã hóa) / người vận hành (giải mã)'; §17.1: 'Archive riêng từng tenant, khóa gắn tenant'; §17.2(2): 'Agent giải mã vào thư mục staging … headscale_version ≤ version đang chạy'. Upstream v0.29.7 hscontrol/db/versioncheck.go l.195-197: 'Single minor version upgrade (stored.minor+1 == current.minor): allowed. Multi-minor upgrade or any minor downgrade: blocked with a fatal error' (case `minorDiff > 1`).

</details>

**Suggested fix.** Add rows:
`| P2-T03a | pg_dump mã hóa (age) hằng đêm và bắt buộc trước mỗi migration; restore thử vào instance tạm | P2-T03 | job + runbook | Số hàng khớp sau restore |`
`| P2-T04a | Nghi thức khóa: sinh KEK và khóa khôi phục backup; người dùng xác nhận 2 bản offline; diễn tập nạp lại KEK | P2-T04 | docs/operations/key-ceremony.md | Giải mã thử một secret bằng KEK khôi phục |`
`| P2-T05b | Dump DB của IdP + sao lưu volume ACME theo lịch | P2-T05 | job | Restore thử |`
Decide the key model in §7.6/§17.1, for example: one age identity per tenant stored in SecretStore at platform scope (usable by the restore job) plus an offline platform recovery recipient on every archive; keep the manifest authenticated outside the ciphertext so the A-into-B refusal happens before decryption. §17.2(2): require `backup.minor ∈ {running.minor, running.minor − 1}`, otherwise restore through the intermediate pinned images; add that case to P6-T10.

### RM-10 — HIGH — §20 Phase 1 table (P1-T01, T05, T10, T11, T13); §19 Phase 1 DoD; P0-T03

**Problem.** Several Phase 1 dependencies are wrong, and running them in the stated order yields invalid Go/No-Go evidence.
(a) P1-T10 contains the V-03 PoC ('thêm tenant không reload', reload behaviour with `stream_close_delay`) but depends only on P1-T08. The first client is enrolled in P1-T12, so there is no open stream to observe.
(b) P1-T13 (AC-18, restart independence) depends on P1-T09, again before any client exists.
(c) P1-T05 issues the wildcard certificate and verifies it with `openssl s_client`, yet depends only on P1-T04. The edge container that runs ACME and listens on 443 is created in P1-T06, and the DNS token file in P1-T03.
(d) P1-T11 (non-root PoC, V-04) runs after A and B are deployed from a template whose `user:` value depends on its result, and after P1-T09 has recorded AC-03's 'UID sở hữu khác nhau'.
(e) The Phase 1 DoD 'runbook dựng lại từ đầu chạy được' has no task.
(f) P0-T03 pins 'Caddy + module' and 'IdP' but depends only on P0-T01; the DNS module follows from D-1 and the IdP from D-3.
(g) P1-T01's verification 'Đủ 18 hạng mục A.2' includes rows 12–14, which cannot be executed at that point.

<details><summary>Evidence</summary>

P1-T10: '… PoC "thêm tenant không reload"; đo hành vi reload với stream_close_delay | P1-T08'; P1-T13: 'Health check cơ bản + test restart độc lập | P1-T09'; P1-T05: '… | P1-T04, domain | Chứng chỉ hợp lệ | openssl s_client thấy chuỗi tin cậy'; P1-T06: 'Compose core tối thiểu: edge, crowdsec, postgres'; P1-T11: 'PoC Headscale non-root + read-only | P1-T08'; V-03 test: 'Thêm tenant khi client tenant khác đang kết nối; không rớt stream'; A.2 row 14: 'chỉ thực hiện sau khi được phép mở cổng'.

</details>

**Suggested fix.** - P1-T05 deps -> `P1-T03, P1-T04, P1-T06, domain`.
- P1-T11 deps -> `P1-T06, P1-T07`; P1-T08 deps add `P1-T11`.
- P1-T10 becomes config only: `| P1-T10 | Cấu hình edge: wildcard + upstream động + allow-list + :80 + listener admin/metrics | P1-T05, P1-T08 | Caddyfile | (giữ nguyên) |`, and add `| P1-T12d | PoC V-03: khi client A/B đang giữ long-poll và phiên DERP, attach một instance thứ ba dùng tạm; đếm stream bị đóng; đo reload với stream_close_delay | P1-T12 | Báo cáo PoC | 0 stream bị đóng khi attach |`.
- P1-T13 deps -> `P1-T12`.
- `| P1-T15 | Diễn tập dựng lại: down → xóa → dựng lại A/B theo runbook | P1-T14 | Runbook đã chạy | Lặp lại được, không chỉnh tay |`.
- P0-T03 deps -> `P0-T01, P0-T05`; move the IdP pin into P2-T05.
- P1-T01 verification -> 'Hạng mục 1–11 và 15–18 đủ; 12–14 ghi "pending" kèm task sẽ hoàn tất (P1-T05, P1-T14 / P5-T02a)'.

### RM-11 — MEDIUM — §19 general rule; §20 Phase 1 order; R-05; R-01 / D-6; Phase 4; Phase 5; §25.2 step 9

**Problem.** The roadmap is fail-late and over-serialised.
(a) R-05 says 'PoC sớm nhất có thể', but the DERP-through-Caddy Go/No-Go is reached at the 12th Phase 1 task, after the custom edge image with SBOM, core compose with CrowdSec and PostgreSQL, two tenants and the non-root PoC.
(b) Client compatibility on five operating systems (V-08) and real-network direct/relay (AC-15/16) need only Phase 1 infrastructure, but are first run in Phase 5, after the whole portal is built.
(c) Legal advice on R-01 is required only 'trước G6', after the MVP is fully built.
(d) 'Chỉ khi G1 đạt: bắt đầu backend' blocks about ten backend tasks that do not depend on G1 (P2-T01–T04, T06–T08, T12, T14) on hardware, domain and devices.
(e) Phase 4 is one gate for 14 tasks, including items no AC exercises (resource catalog, DNS, routes UI, 4-eyes, two languages, axe); the Phase 5 network tests wait for all of it.
(f) PostgreSQL and an enforcing CrowdSec in Phase 1 add nothing to G1, and CrowdSec's 4-hour IP ban (EG-09) can invalidate a PoC run from one NAT.

<details><summary>Evidence</summary>

R-05: 'PoC sớm nhất có thể; phương án lùi (c)'; P1-T12 is the first task that forces a relay; V-08 gate 'G5'; D-6: 'Tư vấn pháp lý R-01 | Bắt buộc trước G6'; §25.2 step 9: 'Chỉ khi G1 đạt: bắt đầu backend theo P2-T01…'; Phase 4 Risks: 'phạm vi UI phình to'; Phase 1 migrations: 'PostgreSQL chỉ được dựng và kiểm tra kết nối'.

</details>

**Suggested fix.** Add rows:
`| P1-T05a | Spike V-01/V-05: 1 Headscale + edge tối thiểu + 2 client, ép relay, truyền TCP | P1-T05 | Báo cáo | Dữ liệu đi qua DERP; thất bại ⇒ dừng trước khi dựng phần còn lại |`
`| P1-T12e | Smoke tương thích sơ bộ (V-08) trên các hệ điều hành sẵn có: enroll + direct + relay | P1-T12 | Ma trận sơ bộ | Mỗi OS có kết quả |`
Rule change in §19 and §25.2: 'Các task P2-T01–T04, T06–T08, T12, T14 được phép chạy song song Phase 1 sau G0; không triển khai lên host trước G1.' D-6 -> 'ý kiến pháp lý sơ bộ bằng văn bản trước G2; đầy đủ trước G6'. Split G4 into G4a (enrollment, policy apply, devices, audit ở mức API + UI tối thiểu; mở P5-T02…T07) and G4b (phần UI còn lại, i18n, a11y). Until G1 run the CrowdSec bouncer in observe-only mode or allowlist the lab egress IPs; move postgres to P2-T16.

### RM-12 — MEDIUM — §19 Phase 2 and 3 migrations; §20 P2-T12, P3-T05, P3-T06, P3-T08, P3-T11; §11.5; P2-T11

**Problem.** Migration and dependency ordering across Phases 2–3 is wrong in several places.
(a) P3-T06 (migrations 0007–0011) is a dependency of no task, although P3-T05 writes provisioning_jobs/steps (0007), step 17 writes the relay tables (0008), P3-T11 writes backups (0009) and P3-T08 needs policy_versions (0011).
(b) Phase 2 exposes a `jobs` API and '0006 jobs/idempotency', but §6.3 has no business job table other than provisioning_jobs (0007, Phase 3). River's tables have no tenant_id or RLS, so tenant-scoped `GET /tenants/{t}/jobs` has no backing table in Phase 2.
(c) Phase 2 migrations hold columns that reference tables of later phases: `tenants.current_policy_version_id` (0011), `audit_events.support_grant_id` (0015), `device_inventory_cache.enrollment_request_id` (0012).
(d) P3-T11 depends only on P3-T02, but its post-restore reconciliation needs the job machinery, audit, inventory sync and policy apply.
(e) `InfrastructureDriver` (§11.5) lacks operations that steps 12 and 14 and P3-T03 require: policy bootstrap, edge detach for compensation, network-membership inspection.
(f) The fate of the hand-built tenants A and B after Phase 3 is undefined. They have no baseline policy_versions row, relay rows, subscription or renderer-produced config version, so reconcile (P3-T12) will flag them.

<details><summary>Evidence</summary>

P3-T05 deps: 'P3-T03, P3-T04, P2-T12'; P3-T06: 'Migration 0007–0011; plan/quota tối thiểu | G2'; Phase 2 migrations: '0006 jobs/idempotency'; §6.3: 'Bảng của job queue (River…) nằm ở schema riêng, không chứa dữ liệu nghiệp vụ ngoài tham chiếu provisioning_jobs.id'; P3-T11 deps: 'P3-T02'; §11.3 step 12 'policy.bootstrap | Agent', step 14 compensation 'detach'; §11.5 interface has neither.

</details>

**Suggested fix.** P3-T05 deps -> `P3-T03, P3-T04, P3-T06, P2-T12`; P3-T08 deps add `P3-T06`; P3-T11 deps -> `P3-T03, P3-T05, P3-T06, P2-T08, P2-T13, P3-T08a`. Move the job read model to Phase 2: create `jobs` / `job_steps` (kind covers every kind in §13.5) in 0006 and drop them from 0007. Add to §19: '0002/0004/0005 tạo các cột này không kèm FK; FK được thêm ở 0011/0015/0012'. Add to §11.5: `BootstrapPolicy(ctx, id) (sha256 string, err error)`, `DetachEdge(ctx, id) error`, `NetworkMembers(ctx, id) ([]string, error)`. New row: `| P3-T14b | Chuẩn hóa A/B: (khuyến nghị) deprovision bản dựng tay và tạo lại qua orchestrator; hoặc backfill + reconfigure | P3-T12 | — | Reconcile không báo drift cho A/B |`.

### RM-13 — MEDIUM — §11.4 Suspend; §20 P3-T08

**Problem.** Suspend includes 'reject pending auth', which cannot be implemented. Headscale can reject a pending registration only when given its auth_id and offers no call that lists pending ones. The platform stores only a hash of the Auth ID, in a table (enrollment_requests, migration 0012) that does not exist until Phase 4.

<details><summary>Evidence</summary>

Plan: §11.4 'expire mọi pre-auth key còn hiệu lực, reject pending auth'; §6.3 enrollment_requests 'Không lưu plaintext pre-auth key/Auth ID'; §7.4 'Headscale API không liệt kê được pending registration (UNSUPPORTED)'. Upstream v0.29.7: proto/headscale/v1/auth.proto `message AuthRejectRequest { string auth_id = 1; }`; hscontrol/grpcv1.go `AuthReject` calls `GetAuthCacheEntry(authID)` and returns NotFound otherwise; headscale.proto has no list RPC in the Auth block.

</details>

**Suggested fix.** Replace the phrase in §11.4 and P3-T08 with: 'Portal từ chối `web-auth:claim` và mọi `enrollment/*` khi tenant ở trạng thái suspended (backend không gọi AuthRegister, pending auth tự hết hạn sau 15 phút); với tenant ở chế độ headscale_oidc: restart instance có kiểm soát để xóa cache pending (ID-05), hoặc chấp nhận node mới chỉ nhận policy deny-all.' Add to P3-T08 verification: 'claim trong lúc suspend ⇒ 403 tenant_suspended'.

### RM-14 — MEDIUM — §22.2 (AC-01, 04, 05, 08, 16, 20); §22.3 M1/M2; §19 Phase 1 and 2 Acceptance; §20 P2-T11

**Problem.** Several acceptance criteria are not reachable in the phase claimed.
- AC-05 is claimed at G2/M2 ('ở mức API'), but its second half needs support grants (migration 0015 and API in Phase 4) and 'vòng đời' needs Phase 3.
- AC-01's evidence 'Registry có 2 tenant active' and AC-08's 'node có trong inventory' are claimed for Phase 1, which has no backend.
- P2-T11 is verified by AC-04 ('API liệt kê thiết bị … qua adapter'), but its dependencies (P2-T04, P2-T07) exclude the adapter (P2-T09) and devices (P2-T13).
- AC-16 is marked Phase 1 and required by G1(2), but is missing from the Phase 1 acceptance list and from M1.
- AC-20 is assigned to Phase 1 only. By G5 the public surface has grown (API `/internal/*` and `/metrics`, the IdP admin console on `auth.`, later Grafana), and Phase 5 would reuse stale evidence.

<details><summary>Evidence</summary>

AC-05: '… có grant thì thao tác được và audit ghi actor_type=support | 2, 4'; Phase 2 Acceptance: 'AC-04, AC-05, AC-06, AC-07, AC-12 ở mức API'; Phase 4 migrations: '0015 support_access_grants'; P2-T11: '… | P2-T04, P2-T07 | Registry có 2 tenant | AC-04'; Phase 1 Acceptance: 'AC-01, AC-02, AC-03, AC-08, AC-09, AC-13, AC-14, AC-18, AC-20 ở mức thủ công'; AC-20 Phase column: '1'.

</details>

**Suggested fix.** - Split AC-05: 'AC-05a (G2): thấy metadata registry của cả hai tenant; mọi operation nội bộ tenant bị từ chối khi không có grant' and 'AC-05b (G4): có grant ⇒ thao tác được, audit ghi actor_type=support'. Alternative: move 0015 and the grant check into Phase 2 (P2-T07) and keep only the UI in Phase 4.
- AC-01 Phase 1 evidence -> 'hai compose project + hai thư mục dữ liệu'; registry evidence from Phase 2.
- AC-08/09 Phase 1 evidence -> '`headscale nodes list`'.
- P2-T11 verification -> 'Registry có 2 tenant; ForTenant trả đúng instance'; move 'AC-04' to P2-T13.
- Add AC-16 to the Phase 1 acceptance cell and to M1.
- AC-20 Phase column -> '1, 5, 6', with the Phase 5 rerun extended to: api `/internal/*`, `/metrics`, `/healthz`; IdP admin console and management endpoints; Caddy admin API; CrowdSec LAPI; Docker TCP.

### RM-15 — MEDIUM — §20 P2-T13, P4-T04; §19 Phase 5 API changes; §6.3 device_inventory_cache; §13.3 Device; ADR-22

**Problem.** The two-phase revoke state ('pending / applied / failed', T-17, AC-17) is assigned to three different phases and has no data model. P2-T13 builds the 'endpoint (trạng thái hai pha)', P4-T04 displays it, yet the Phase 5 table lists 'bổ sung trạng thái hai pha cho revoke/policy' as an API change. Neither `device_inventory_cache` nor the `Device` schema has a field to hold it. The coding agent would have to design it, and AC-17's 'UI hiển thị đúng pending/applied' has no contract to test against.

<details><summary>Evidence</summary>

P2-T13: '`devices`: inventory sync + cache + endpoint (trạng thái hai pha)'; P4-T04: 'devices (trạng thái hai pha, synced_at)'; Phase 5 API changes: '`diagnostics/*`; bổ sung trạng thái hai pha cho revoke/policy'; §13.3: 'Device: {id, name, given_name, ip_addresses[], owner…, tags[], register_method, online, last_seen, expiry, routes{…}, synced_at}'.

</details>

**Suggested fix.** §6.3 device_inventory_cache: add `revocation_state (none|pending|applied|failed), revocation_kind (expire|delete), revocation_requested_at, revocation_verified_at, revocation_job_id`. §13.3: add `Device.revocation{state, requested_at, verified_at}`. Build in P2-T13 with verification 'Headscale API lỗi ⇒ failed; read-back chưa khớp ⇒ pending; khớp ⇒ applied'; show in P4-T04; measure in P5-T07. Alert source: `revocation_state = applied AND online = true`. Change the Phase 5 'API changes' cell to '`diagnostics/*`'.

### RM-16 — MEDIUM — §4.2; §8.5/8.6; §12.2/12.3; §13.2; §13.5; §14.7; §19 'API changes' rows; §20

**Problem.** Deliverables named in sections 3–18 that no task builds, or whose phase is not stated:
- No backend task and no 'API changes' entry: `GET /tenants/{t}/dashboard`, `GET /tenants/{t}/relay`, `/platform/relay-regions` (read), `/platform/identity-providers`, `/platform/plans`, `PATCH /tenants/{id}`, `:request-deletion`, `/tenants/{t}/settings`, `/tenants/{t}/identity-provider`. Phase 4 lists `platform/users` and `platform/settings`, but P4-T03 is a UI task.
- `internal/monitoring` (HealthService, forced tenant label) and the `health.probe` job: in no phase's file list.
- `instance.upgrade`, `instance.restart` and cold backup: the endpoints arrive in Phase 3 (`platform/instances/{id}:*`) with no task; P6-T10 is only a drill.
- `QuotaChecker`: used by provisioning step 1 and P4-T06, while module `usage` is P6-T11.
- Security Events screen (§12.2) and tenant-side security events (§16.4): API in Phase 6, no UI task.
- CrowdSec 'nút gỡ ban trong Platform Console' and tenant allowlist (§14.7, R-16): no endpoint and no task; the api has no route to LAPI.
- Edge rate/connection limiting (T-11): EG-11 says it needs a plugin, but the P1-T04 build has only the DNS module and the bouncer.
- Tagged-node review report (§7.4, ADR-23); jobs `session.gc`, `retention.sweep`.
- Users/Groups screens: P4-T09 names no UI.
- Enrollment method C (native OIDC): schema enum and a per-tenant edge allow-list branch exist, with only an optional validation task (P5-T10).
- `GET /billing` (`tenant.billing:read`): in the matrix and in invariant 5, but absent from §13.2 and from every MVP task.
- `/internal/prometheus/sd` (§16.1) is missing from §13.2.

<details><summary>Evidence</summary>

Phase 2–6 'API changes' cells (none contains dashboard, relay, plans, identity-providers, tenant settings); P4-T03: 'Platform Console: instances, hosts, health, jobs, settings, platform users, IdP'; Phase 3 API changes: 'platform/instances/{id}:*'; P6-T10: 'Diễn tập upgrade/rollback Headscale + job CheckPolicy trước upgrade'; §14.7: 'nút gỡ ban trong Platform Console'; §15.1: 'CrowdSec LAPI | … | Chỉ edge ↔ crowdsec'; P1-T04: 'xcaddy + module DNS + bouncer'; §8.6: '`tenant.billing:read` | GET /billing'.

</details>

**Suggested fix.** Add a 'Phase / Task' column to §13.2 and §13.5, and list every `internal/*` module in exactly one phase's file list. New rows:
`| P2-T13a | internal/monitoring: HealthService + job health.probe + GET /platform/health + GET /tenants/{t}/dashboard | P2-T12, P2-T13 | internal/monitoring | Số liệu kèm checked_at/synced_at; IT-12b |`
`| P3-T06a | QuotaChecker tối thiểu (số tenant, số thiết bị) dùng ở step validate và enrollment | P3-T06 | internal/usage | Vượt quota ⇒ 403 quota_exceeded |`
`| P3-T13a | Job instance.restart và instance.upgrade (preflight, cold backup, health + contract smoke, rollback bằng restore) | P3-T11, P3-T13 | — | Upgrade lỗi ⇒ tự lùi |`
`| P4-T03a | Backend: platform/users, platform/settings, platform/identity-providers, platform/plans, tenants/{t}/settings, identity-provider, PATCH tenant, request-deletion | P4-T05 | — | Ma trận authz phủ đủ |`
`| P4-T09a | UI Users/Groups | P4-T09, P4-T01 | — | E2E |`
`| P6-T02a | Security Events: màn hình platform + mục tenant | P6-T02 | — | E2E |`
Either add `| P6-T07a | Gỡ ban/allowlist CrowdSec qua API | P6-T07 |` or delete the promise from §14.7 and R-16. State explicitly 'không xây ở MVP' for method C, billing, the DNS driver and edge rate limiting (or add the plugin to P1-T04). Add `/internal/prometheus/sd` to §13.2.

### RM-17 — MEDIUM — §4.2; §11.2/11.3 (step 19); §7.4 step 8; §8.7; §18.1 T-04/T-06/T-08; R-11, R-22; ADR-23; Appendix A.1 #9

**Problem.** Notifications are a step or a mitigation in at least ten places: provisioning step 19 and 'gửi hướng dẫn enrollment cho Tenant Owner', §7.4 step 8, break-glass 'thông báo cho Tenant Owner', T-04, T-06, T-08, R-11, R-22 and ADR-23 'Thông báo trước hạn'. T-04's verification is 'test thông báo'. There is no notification module in §4.2, no table, no SMTP configuration task, no job kind and no task. SMTP appears only as an Appendix A question.

<details><summary>Evidence</summary>

§11.3 step 19: 'audit; thông báo'; §8.7(2): 'tạo security_event mức cao và thông báo cho Tenant Owner'; T-04 mitigation 'thông báo cho Owner', verification 'test thông báo'; T-06: 'thông báo thiết bị mới'; R-11: 'thông báo node mới'; A.1 #9: 'SMTP cho thư mời/cảnh báo'. §4.2 module list and §13.5 job list contain no notifier.

</details>

**Suggested fix.** Either add: `| P3-T05b | internal/notify: Notifier (email qua SMTP + bảng notifications cho in-app), template vi/en, không chứa secret; sự kiện: tenant activated / owner invite, thiết bị mới, break-glass, policy applied, yêu cầu duyệt grant, key hoặc node sắp hết hạn | P2-T08, P2-T12, SMTP (A.1 #9) | internal/notify | Với SMTP giả pin digest: mỗi sự kiện đúng 1 thông báo, tới đúng người nhận của đúng tenant |` and add SMTP to §21.3.
Or state once: 'MVP: thông báo = bản ghi in-app + audit; email là hạng mục Phase 6', and edit the ten references and the T-04 verification accordingly.

### RM-18 — MEDIUM — §22.1; §4.4 (`compose.yaml`); §20 P0-T04, P1-T04, P2-T01, P2-T15; Appendix A.1 #15; §21.3

**Problem.** The test strategy assumes infrastructure that no task creates.
- 'Mỗi PR' and 'hằng đêm' runs, 'CI xanh' (P2-T01) and 'action pin theo SHA' presume a Git host and a Docker-capable runner. 'Image + digest' for self-built images presumes a registry. All three are unknowns in A.1 #15 and absent from G0 and §21.3.
- `compose.yaml` ('môi trường dev cục bộ', §4.4) has no task.
- There is no client harness for functional end-to-end runs. Phase 3 'Provision trên Docker thật', Phase 4 'luồng enrollment với client thật' and nightly Playwright need a full stack with IdP, edge TLS and clients.
- The generated authz matrix needs sessions for nine roles, but login is OIDC with MFA and no fixture is defined.
- §22.1 schedules edge allow-list scans per PR, but no automated edge test exists; P1-T10 verifies by hand.

<details><summary>Evidence</summary>

§22.1: 'Isolation … Mỗi PR + trước mỗi gate', 'E2E (UI) … Hằng đêm + trước gate', 'Security … quét allow-list edge trên mọi hostname tenant … Mỗi PR / hằng đêm'; P2-T01 verification: 'CI xanh'; P1-T04 output: 'Image + digest'; A.1 #15: 'Git hosting, CI runner, container registry sẽ dùng'; §4.4: 'compose.yaml # môi trường dev cục bộ'.

</details>

**Suggested fix.** Add rows:
`| P0-T07 | Chốt Git hosting, CI runner có Docker, registry (hoặc registry cục bộ pin digest, không public); quy ước lấy digest cho image tự build | P0-T05 | docs/deployment/ci-and-registry.md | Push/pull thử; digest tra được |`
`| P2-T01a | Stack dev/CI (compose.yaml): postgres, IdP với 3 realm import sẵn, edge dùng CA nội bộ chỉ cho CI, 2 Headscale, 4 client container tailscale pin digest (đã cài CA nội bộ) | P2-T01, P1-T07, P1-T10 | compose.yaml, tests/e2e/harness | make e2e-functional xanh trên runner; kết quả ghi "functional" |`
`| P2-T15a | Fixture phiên kiểm thử (chèn session cho từng role, chỉ build với tag test) + 1 bài đăng nhập OIDC thật có TOTP | P2-T06 | tests/security | Ma trận authz chạy không cần trình duyệt |`
`| P1-T10a | Edge conformance test tự động: path cấm × mọi hostname; fuzz nhãn host và X-MG-Instance; traversal (/derp/../api/v1) | P1-T10 | tests/security/edge | Chạy mỗi khi infrastructure/caddy/** thay đổi |`
Add CI/registry to §21.3.

### RM-19 — MEDIUM — §22.4; §24 'Validation requirements' column; §19 Phase 5 DoD; §13.6

**Problem.** The Phase 5 DoD requires 'mọi mục REQUIRES VALIDATION liên quan MVP đã có kết quả đo', but no complete register exists and several listed validations have no task.
- V-11 (Noise key change / old restore, gate G3/G6), V-14 (CrowdSec NAT replay, G6) and V-15 (IdP realm scale) appear in no task.
- ADR validations with no task or V-ID: ADR-04 'Lint ranh giới module', ADR-23 'Test expiry trên client thật', ADR-24 'Diễn tập dựng lại host', ADR-16 MIT attribution.
- §13.6, the input for the ADR-04 lint, uses module names that differ from §4.2 (`billing`, `configuration`, `tenant`, `device`, `policy`).
- REQUIRES VALIDATION items with no V-ID: ID-04 (node of a user disabled at the IdP), §10.4 (one STUN endpoint and NAT detection), §7.3 (whether tests can assert rights from `via` / `autogroup:self`), §10.6 (stream count at the edge), §15.3 Path B (source IP preserved), §10.1 (region ID reuse).
- V-06 includes 'policy rỗng', but P2-T10's quirk list does not.

<details><summary>Evidence</summary>

V-11: 'Thử trên tenant test | G3/G6' (no task mentions it); V-15 gate: 'Trước mốc 100 tenant'; ADR-04 validation: 'Lint ranh giới module'; ADR-23: 'Test expiry trên client thật'; ADR-24: 'Diễn tập dựng lại host; công bố cho khách'; §10.4: 'Một STUN endpoint trên một IP có thể không đủ … — REQUIRES VALIDATION'; P2-T10: 'gồm các quirk: tham số query, expiration tường minh, lỗi 500'.

</details>

**Suggested fix.** Extend P0-T06's output with `docs/planning/validation-register.md` (ID, claim, label, test, owner task, gate, result) and a docs-check rule: no REQUIRES VALIDATION or ASSUMED label without an ID. Add:
- V-16 node.expiry: `| P5-T07a | Đặt node.expiry = 10 phút trên tenant thử qua instance.reconfigure; quan sát client về NeedsLogin và peer loại bỏ nó; re-auth qua Portal | P5-T02, P3-T13 | Số đo | Ghi giá trị thực |`
- V-17 single-STUN NAT detection -> P5-T06; V-18 IdP-side offboarding -> P4-T09; V-19 tests for via/self -> P5-T01; V-20 Path B -> P5-T02a.
- V-11 -> add a case to P3-T11; V-14 -> new `P6-T07b`; V-15 -> name it in P6-T08.
- ADR-04 -> P2-T01 verification 'depguard/go-arch-lint theo §13.6, tên module thống nhất với §4.2'.
- ADR-24 -> `| P6-T04a | Diễn tập mất host: dựng lại trên máy sạch từ offsite + KEK offline | P6-T03, P6-T04, máy thứ hai | Số đo RTO | Ghi giá trị thực |`.
- P2-T10: add 'PUT policy rỗng'.

### RM-20 — MEDIUM — G2; G4; G6; AC-16; AC-17 / V-09; AC-19 / G3; P6-T08; P6-T09

**Problem.** Several gates and criteria are not objectively decidable.
- G2 'rà soát bảo mật nội bộ … không còn lỗi mức Cao' and G4 'rà soát UX bảo mật' name no reviewer, checklist or evidence. An author reviewing its own code is not a control.
- AC-17, P5-T04 and P5-T07 only require 'Ghi giá trị thực'. A revoke that never takes effect inside the observation window still passes.
- AC-19 and G3 compare a checksum of tenant B's live `data/`. A running instance in WAL mode changes those bytes without any restore, so the test is flaky or forces B to be stopped.
- P6-T08 passes on 'Có số liệu thật' and P6-T09 has no verification; the thresholds A.1 #16 promises are never defined.
- AC-16's evidence `via DERP(<region_code tenant>)` identifies the tenant only if region codes are unique, which §10.1 does not require.

<details><summary>Evidence</summary>

G2: 'rà soát bảo mật nội bộ cho authn/authz không còn lỗi mức Cao'; P5-T07: '… | Số đo | Ghi giá trị thực'; AC-19: 'Checksum data/ của B trước/sau'; §6.5: 'db.sqlite (WAL bật)'; P6-T09 verification: '—'; A.1 #16: 'Ngưỡng Go/No-Go của scale test'; §10.1: 'các tenant dùng lại cùng số được'; CL-12: 'test upstream chấp nhận 30–180 s'.

</details>

**Suggested fix.** - G2 -> 'checklist OWASP ASVS (xác thực, phiên, kiểm soát truy cập) do người không viết phần code đó thực hiện (người dùng hoặc agent review độc lập); kết quả lưu ở evidence/G2-security-review.md; 0 mục Cao còn mở'.
- G4 -> named checklist: key hiển thị một lần; lời nhắc step-up; cách diễn đạt trạng thái hai pha; không secret trong DOM/storage; xác nhận thao tác phá hủy.
- AC-17 -> add 'Không đạt nếu peer online vẫn truyền được TCP sau 180 s kể từ read-back, hoặc peer offline vẫn truyền được sau 60 s kể từ khi nối lại control; ngoài ngưỡng cần ngoại lệ bằng văn bản'.
- AC-19 -> 'so sánh sha256 của noise/derp key của B và hash đã chuẩn hóa của ListNodes/ListUsers/GetPolicy trước và sau; log thao tác của Agent không chứa instance_id của B'.
- P6-T08/T09 -> thresholds derived from A.1 #16 and fixed at G5.
- §10.1 -> `region_code = t-<short_id>`.

### RM-21 — MEDIUM — §19 Phase 5 Security controls; §20 P5-T09; §18.1; T-06 vs §7.4

**Problem.** P5-T09 must close 'checklist T-01…T-18 … Không lỗi Cao' and Phase 5 claims 'Toàn bộ kiểm soát §7; kiểm thử T-01…T-18'. About a third of the §18.1 verification methods depend on Phase 6 work: T-03 (audit pushed off-host, tabletop), T-10 ('test rate-limit UDP' with nftables in P6-T07; relay load test), T-11 (load test, chaos), T-13 (signature and scan gate, P6-T06), T-14 (docker-bench/lynis, restore to a clean host, pen test), T-15 (offsite, periodic restore), T-16 (upgrade drill in CI). G5 would be declared with those rows unverifiable. Separately, T-06's mitigation contradicts §7.4: it promises that the claim page 'hiển thị hostname/OS', while §7.4 states the Portal cannot show them before approval.

<details><summary>Evidence</summary>

P5-T09: 'Đợt security test: authz matrix đầy đủ, quét allow-list edge trên mọi tenant, secret scan, checklist T-01…T-18 | G4 | Báo cáo | Không lỗi Cao'; T-10 verification: 'load test relay; test rate-limit UDP'; T-16: 'Diễn tập upgrade trong CI (N−1 → N với dữ liệu seed)'; T-06 mitigation: 'trang claim web-auth hiển thị hostname/OS + xác nhận tường minh'; §7.4: 'Portal không hiển thị được hostname/OS **trước** khi phê duyệt'.

</details>

**Suggested fix.** Add a column 'Kiểm chứng ở gate' to §18.1. P5-T09 text -> 'checklist T-01, 02, 04–09, 12, 17, 18 đầy đủ; T-03/10/11/13/14/15/16: chỉ phần kiểm được ở MVP, phần còn lại thuộc P6-T12'. Phase 5 Security controls -> 'Các kiểm soát §7 thuộc phạm vi MVP'. T-06 mitigation -> 'trang claim yêu cầu nhập tên thiết bị mong đợi và đối chiếu sau đăng ký (lệch ⇒ xóa node + security_event)'.

### RM-22 — MEDIUM — §21.2 graph vs §20 tables

**Problem.** The critical-path graph does not match the task table.
- Edges in the graph but not in the table: T05→T10; B06→B07 (P2-T07 depends on P2-T02 and P2-T03).
- Table dependencies missing from the graph: T09→T12; P2-T01 and P2-T02 before B03/B07; P3-T04→C05; P4-T05→D06; P4-T05 and P4-T09→D10. The longest Phase 4 chain (T05→T09→T10→T11→T14) is therefore invisible.
- Dead ends: T09, and B10 although G2 requires the contract test.
- Gate tasks P1-T14, P2-T16, P3-T14 and the G1 inputs P1-T11 and P1-T13 are omitted, so the graph shows T12→G1 directly.
- With no durations, the figure is a dependency subset, not a critical path.

<details><summary>Evidence</summary>

Graph: 'T05 --> T10', 'T08 --> T10 --> T12 --> G1', 'B05 --> B06 --> B07', 'G3 --> D06', 'G3 --> D10'. Table: P1-T10 deps 'P1-T08'; P1-T12 deps 'P1-T09, P1-T10'; P1-T14 deps 'P1-T10…T13'; P2-T07 deps 'P2-T02, P2-T03'; P4-T06 deps 'P4-T05'; P4-T10 deps 'P4-T05, P4-T09'.

</details>

**Suggested fix.** Make the table authoritative and generate the graph from it (add to P0-T04: a script, with `make docs-check` failing on drift). Minimal manual patch to the mermaid block: add `T09 --> T12`, `T12 --> T13[P1-T13] --> T14[P1-T14] --> G1`, `T11[P1-T11] --> T14`, `G1 --> B01[P2-T01] --> B03`, `B01 --> B02[P2-T02] --> B07`, replace `B06 --> B07` with `B03 --> B07` and `B06 --> B15`, add `B10 --> B16[P2-T16] --> G2` and `B15 --> B16`, `C04[P3-T04] --> C05`, `C06[P3-T06] --> C05`, `C07 --> C14[P3-T14] --> G3`, `C11 --> C14`, `G3 --> D05[P4-T05] --> D06`, `D05 --> D09[P4-T09] --> D10`. Rename the heading to 'Chuỗi phụ thuộc chính'.

### RM-23 — MEDIUM — §7.5; §8.2; §7.3 / X-4; §23.1; §23.2

**Problem.** Phase labels in the design sections contradict the roadmap, and several debts point at work that is not tasked.
- §7.5 classifies time-bound access, JIT and Tailscale SSH as 'Phase 2', which in this document means 'SaaS Backend'. The only matching task is P7-T07.
- §8.2 puts IdP reconciliation in 'Phase 6'; the task is P7-T06.
- §8.2 says a tenant-brought IdP is 'Hỗ trợ ngay từ MVP', while the Phase 7 scope and P7-T06 list 'IdP của tenant'.
- §7.3 and X-4 promise a policy evaluator or shadow instance in 'Phase 5'; no Phase 5 task exists, and TD-07 says 'Phase 5+'.
- TD-02 (standalone derper, 'Phase 7') has only the research task P7-T04. TD-03 (OpenBao) and TD-10 (DR automation) have no task.
- Risk owners are roles (Tech lead, SRE, Product, Security) never mapped to a person, and no risk has a review trigger. The register omits roadmap risks raised elsewhere in the plan: test devices and second network, a single operator versus dual control, UI scope growth, version drift during the build.

<details><summary>Evidence</summary>

§7.5: 'Time-bound access | Phase 2', 'Just-in-time access | Phase 2', 'Tailscale SSH (check mode) | Phase 2 (opt-in)'; §8.2: 'đối soát định kỳ với IdP (Admin API/SCIM) là hạng mục Phase 6' and 'Hỗ trợ ngay từ MVP nhờ cùng code path đa issuer'; Phase 7 Scope: 'tích hợp danh tính nâng cao (IdP của tenant, SCIM)'; §7.3: 'bộ đánh giá phía nền tảng hoặc shadow instance là hạng mục Phase 5'; TD-07: 'Evaluator/shadow instance (Phase 5+)'.

</details>

**Suggested fix.** - §7.5 column -> 'Post-MVP (P7-T07)'. §8.2 -> 'P7-T06'.
- State once in §8.2: 'driver external (issuer do tenant cung cấp) thuộc MVP; onboarding tự phục vụ và SCIM là P7-T06'.
- §7.3, X-4, TD-07 -> 'backlog sau MVP (chưa có task)', or add an optional P5-T13.
- TD-02, TD-03, TD-10: add a task ID or the word 'backlog'.
- §23.1: add columns 'Người chịu trách nhiệm (tên, chốt ở P0-T02)' and 'Rà lại tại gate'; add R-23 (thiếu thiết bị thử / mạng thứ hai / đường public), R-24 (một người vận hành so với dual control), R-25 (phạm vi UI Phase 4), R-26 (phiên bản pin lỗi thời trong lúc xây).
- Add to every gate: 'rà lại phiên bản pin (bản vá Headscale, client; client di động không pin được ⇒ ghi phiên bản thực tế vào bằng chứng)'.

### RM-24 — MEDIUM — §25.1 rules 1, 7; §25.2 step 5; §6.1 vs P3-T06 / P4-T05; Appendix B

**Problem.** The Build Mode instructions conflict with the tasks in places a coding agent will hit.
- Rule 7 allows the Headscale CLI only 'trong container bằng Agent', but Phase 1 (P1-T08, P1-T12) runs the CLI by hand before the Agent exists.
- §25.2 step 5 says to propose 'chuẩn bị host + firewall' for approval 'rồi thực hiện' under P1-T02/T03. §14.1 says firewall rules are a proposal that is not applied, and the implementing task is P6-T07.
- Rule 1 ('mỗi task một nhánh/PR') presumes a Git host that is still unknown.
- P3-T06 and P4-T05 verify with 'Up/rollback thử', while §6.1 defines migrations as forward-only.
- Evidence is committed to `docs/planning/evidence/`. It will naturally contain pre-auth keys, bearer headers, node keys, public IPs and emails, and there is no redaction rule.
- No rule covers a task blocked by a missing external input, or who triggers the optional tasks (P5-T10, P5-T11).
- After P0-T01 there are two copies of everything: the split files and `implementation-master-plan.md` ('Toàn bộ plan này'). No rule says which is authoritative, and §-number cross-references will not resolve in the split files.
- Appendix B has no target file for §11, §12, §16, §23 or §25.

<details><summary>Evidence</summary>

§25.1(7): 'mọi thao tác qua REST API hoặc CLI trong container bằng Agent'; P1-T08: 'policy deny-all qua CLI → API key qua CLI'; §25.2 step 5: 'Trình đề xuất chuẩn bị host + firewall để duyệt, rồi thực hiện | P1-T02, P1-T03'; §14.1 Firewall: 'đề xuất — không tự áp dụng'; §6.1: 'File SQL forward-only'; P3-T06 verification: 'Up/rollback thử'; Appendix B: 'docs/planning/implementation-master-plan.md | Toàn bộ plan này'.

</details>

**Suggested fix.** - Rule 7 add: 'Ngoại lệ Phase 1–2: chạy `docker exec <container> headscale …` theo runbook đã duyệt; từ Phase 3 chỉ qua Agent.'
- Step 5 -> 'Trình đề xuất chuẩn bị host để duyệt rồi thực hiện (P1-T02, P1-T03); firewall chỉ là đề xuất ở P1-T14, áp dụng ở P5-T02a / P6-T07.'
- P3-T06 and P4-T05 verification -> 'Up trên bản sao có dữ liệu + diễn tập restore từ dump'.
- New rules: '14. Bằng chứng: che `hskey-…`, Authorization, cookie, email, IP public trước khi commit; secret scan có rule cho `hskey-`.' '15. Task bị chặn bởi phụ thuộc ngoài: dừng task, ghi vào evidence/blocked.md, chỉ chuyển sang task không phụ thuộc vào nó; không thay bằng mô phỏng.' '16. Task ghi (Tùy chọn) chỉ chạy khi người dùng yêu cầu.' '17. Sau P0-T01, docs/ là nguồn sự thật; implementation-master-plan.md chỉ là mục lục có link; tham chiếu § được đổi thành link.'
- Appendix B add: `docs/architecture/tenant-orchestrator.md` (§11), `docs/architecture/portal-design.md` (§12), `docs/operations/monitoring.md` (§16), `docs/planning/risks.md` (§23), `docs/planning/build-instructions.md` (§25).

### RM-25 — LOW — Appendix A.2 row 14; §14.5 vs §14.6; §19 Phase 6/7 tables; §20 P6-T04, P7-T09, tasks without verification; §5.5; R-20; Phase 4 Acceptance

**Problem.** Smaller inconsistencies:
1) A.2 row 14 probes `https://<host>/health`, a path §14.6 blocks with 404 on tenant hostnames.
2) §14.5 names the container alias `hs-<short_id>`, while the public route in §14.6 builds `hs-<label>` from the slug label of the hostname. The P1-T07 and P1-T10 golden files need one rule.
3) Phase 7 merges Unit/Integration/E2E into one row (15 attributes, not 17), and Phase 6 'Unit tests: Theo module mới' is filler.
4) P6-T04 depends on P3-T11 rather than G5.
5) §5.5 asks for 'Toàn bộ IT-01…IT-13' at the 2-tenant POC level, which precedes the backend.
6) No checkable verification: P5-T10, P6-T09, P7-T03/05/06/07/08/10 ('—'); P5-T02 'Sẵn sàng'; P0-T06 'Được review'.
7) R-20 cites '§2.6' with no fact ID. The claim itself is correct.
8) Phase 4 Acceptance lists 'AC-12 qua UI', but AC-12 is an API test.

<details><summary>Evidence</summary>

A.2 row 14: '`curl -sI https://<host>/health`'; §14.6: 'mọi path khác ⇒ 404 (gồm /api/*, /swagger*, /verify, /version, /health)'; §14.5: 'alias hs-<short_id>'; §14.6: 'ghép thành upstream hs-<label>:8080'; Phase 7: 'Unit / Integration / E2E tests | Theo từng tính năng'; P6-T04 deps: 'P3-T11'. Upstream v0.29.7 hscontrol/db/api_key.go l.267-268: `bcrypt.CompareHashAndPassword(key.Hash, []byte(secret))` runs on every validation, with no cache.

</details>

**Suggested fix.** 1) Row 14 -> '`curl -sI https://<slug>.<mesh_domain>/key` (mong đợi 200) và `…/api/v1/` (mong đợi 404)'.
2) §14.5 -> 'hai alias: hs-<slug> (route public) và hs-<short_id> (listener admin/metrics)', or derive short_id from the slug and say so.
3) Split the Phase 7 row into three; replace the Phase 6 cell with the modules concerned (hash-chain, usage, KEK rewrap).
4) P6-T04 deps -> 'G5, P3-T11'.
5) §5.5 POC row -> 'IT-04, 05, 09, 13 ở mức thủ công; phần còn lại theo phase'.
6) Give each listed task a checkable verification, e.g. P5-T02 -> 'sơ đồ mạng + danh sách thiết bị/phiên bản client lưu trong evidence; script thu bằng chứng chạy được trên từng thiết bị'.
7) Add fact 'RT-15: mỗi lần xác thực API key chạy bcrypt (hscontrol/db/api_key.go)' and cite it in R-20.
8) Remove AC-12 from the Phase 4 'qua UI' list.

## Operations and feasibility (senior SRE / DevOps who has to build and run it)

**Verdict:** Not ready to build as written, but no finding in this lens invalidates the architecture. I checked the upstream facts this lens depends on against Headscale v0.29.7 and Tailscale v1.104.7 source (CLI flags and bypass mode, configtest side effects, extra-records watcher, DERP region generation, DB version check, peer-map construction, netcheck address selection) and against Docker, Compose and Caddy documentation; nothing was executed. Six high-severity gaps would stall or mislead the builder: (1) Phase 1 cannot exercise G1 under the deny-all baseline because no task applies an allow policy; (2) short_id is undefined and the public route and the container alias use different identifiers; (3) edge network attachments do not survive an edge recreation and recovery depends on PostgreSQL and the worker; (4) the worker sits only on internal networks yet owns steps that need DNS, IdP, public-path and STUN access; (5) the restore procedure exposes the restored instance before reconciliation and can lose API access to it; (6) nothing stops an activated tenant from booting on an empty data directory as a new allow-all control plane. No critical issue (cross-tenant breach or unworkable design) was found; OPS-02 is the closest. Phase 1 (two manual tenants, no backend) is achievable only after re-sequencing its tasks (OPS-11) and adding a lab policy (OPS-01). G1 and G3 are not objectively testable until the criteria in OPS-20 are written down. Docker-behaviour claims marked 'validate' below come from documentation and experience, not from a run.

**Strengths noted:**

- The CLI-over-unix-socket bootstrap through docker exec on the distroless image is valid: `policy set -f`, `apikeys create -e`, `apikeys list/expire` and `health` exist in v0.29.7, and the read-only plus tmpfs socket template matches upstream's container docs.
- The same-number STUN mapping (P:P/udp) is correct: the embedded region takes STUNPort from stun_listen_addr and host and port from server_url, and the client honours DERPNode.STUNPort.
- Blocking /verify at the edge is safe for embedded DERP: verification is in-process through the headscale-derp-verify transport with fail-open disabled, so V-05 should pass.
- An Agent with network_mode none and identical inside/outside bind paths is workable for compose and image pulls (the daemon pulls), and the plan correctly isolates configtest, which does create keys and open the database.
- Restore by whole-directory swap while the instance is stopped avoids stale WAL/SHM files, cold backup before upgrade follows upstream guidance, and the plan is honest about unknowns (REQUIRES VALIDATION list, G1 as a hard gate).

### OPS-01 — HIGH — §19 Phase 1 (E2E tests, G1) · §20 P1-T08, P1-T12 · §22.2 AC-08/AC-16 · §7 baseline policy

**Problem.** Phase 1 leaves both instances on the deny-all baseline and has no task that applies an allow policy, yet P1-T12 and G1 items (1) and (2) need peers to see each other and pass TCP through the relay. With an explicit empty grants array Headscale 0.29.7 compiles an empty filter and builds an empty peer map, so 'tailscale status' shows no peers and nothing can be relayed. A builder following the tasks literally will observe 'relay carries no data' and can wrongly invoke the G1 rule that abandons ADR-11: a false No-Go on the most important gate. Policy templates only appear in P5-T01.

<details><summary>Evidence</summary>

Plan: P1-T08 'policy deny-all qua CLI … `policy get` = baseline'; P1-T12 '2 client/tenant (pre-auth key), TCP cùng tenant, cô lập chéo tenant, ép relay qua Caddy'; G1 'Thất bại (2) ⇒ dừng, chuyển sang phương án (c) ở §10.3 và sửa ADR-11'; §7 'Baseline {"grants": [], "ssh": []}'. Upstream v0.29.7 hscontrol/policy/v2/policy.go, updateLocked: `if pm.pol == nil || (pm.pol.ACLs == nil && pm.pol.Grants == nil) { filter = tailcfg.FilterAllowAll } else { filter = globalFilterRules(pm.compiledGrants) }`; BuildPeerMap appends a peer only when `canAccess(srcOf[i], dstOf[j]) || canAccess(srcOf[j], dstOf[i])`, and canAccess returns false when a node matches no matcher.

</details>

**Suggested fix.** Add task P1-T08b (depends on P1-T08, required by P1-T12): commit infrastructure/headscale/templates/lab-allow.hujson, for example {"grants":[{"src":["autogroup:member"],"dst":["autogroup:member"],"ip":["tcp:5201"]}],"ssh":[]}, apply it with `docker exec mg-hs-<id> headscale policy set -f /etc/headscale/lab-allow.hujson`, verify with `policy get`. In P1-T12 add: (a) precondition 'both clients list each other in tailscale status; otherwise the relay result is INVALID, not FAIL'; (b) negative control: a port outside the grant must be refused; (c) re-apply the baseline at the end and confirm the peers disappear. Reword G1(2) to 'with the lab policy applied'. State in AC-13 that cross-tenant invisibility is checked while an allow policy is active in both tenants.

### OPS-02 — HIGH — §14.5 (project/container/alias) · §14.6 (public and admin listeners) · §10.2 · §6.1/§6.3 (tenant_instances) · §11.3 steps 9-10

**Problem.** short_id names the compose project, container, network and the DNS alias the edge proxies to, but it is never defined: no column in tenant_instances, no derivation rule. Three defects follow. (1) The public route builds the upstream from the Host label, which is the slug (hs-<label>), while the container alias is hs-<short_id>; unless short_id equals the slug the public path resolves nothing. (2) If both a slug alias and a short_id alias exist they share the hs- namespace, so a tenant slug equal to another instance's short_id lets the edge resolve one tenant's hostname, admin call or metrics scrape to the other tenant's instance (Docker answers from whichever attached network knows the name). (3) The natural implementation, a prefix of the instance UUID, collides by construction with the plan's preferred UUIDv7: the first 8 hex digits are the top 32 bits of a millisecond timestamp and stay constant for about 65 seconds, so two tenants created in the same minute get the same project and network name; `docker compose -p` then treats tenant B as an update of tenant A's project and B's compensation tears A down.

<details><summary>Evidence</summary>

§14.6 'Nhãn host được kiểm bằng regex slug rồi ghép thành upstream `hs-<label>:8080`'; §14.5 'alias `hs-<short_id>` trên network tenant'; §10.2 '`a.<mesh_domain>` → edge → `hs-a:8080`'; §14.6 admin listener 'Header `X-MG-Instance: <short_id>` (regex) ⇒ `hs-<short_id>:8080`'; the §6.3 column list of tenant_instances has no short_id; §6.1 'Khóa chính | UUID (ưu tiên UUIDv7 …)'. UUIDv7 starts with a 48-bit Unix-millisecond timestamp (RFC 9562).

</details>

**Suggested fix.** Add `tenant_instances.short_id text NOT NULL UNIQUE`, immutable, 12 base32 characters from a CSPRNG (never derived from the UUID), allocated in step 3. Use two disjoint alias families on the tenant network: `hss-<slug>` for the public wildcard route and `hsi-<short_id>` for the admin and metrics listeners, and state that the slug alias exists only on the tenant's single active instance. Alternative to validate in the P1-T10 PoC: give every instance the same alias `hs` and address it as `hs.<network-name>`, which Docker scopes to the named network. In the Agent, before any compose or network operation on mg-t-<short_id>, require that an existing project, network or container carries label meshguard.instance_id equal to the spec's instance_id, otherwise fail hard. Add a unit test for alias-namespace disjointness and an integration test that provisions two tenants in the same second.

### OPS-03 — HIGH — §14.3 · §14.6 (no-reload attach) · §11.4 Reconcile and Deprovision · §3.5 SPOF table

**Problem.** Tenant reachability depends on runtime `docker network connect` state held only by the edge container. (a) Any recreation of the edge (digest bump, compose config change, force-recreate) starts it with only the networks declared in compose.core.yaml, so every tenant is unreachable until something re-attaches N networks; the only re-attacher is the periodic reconcile in the worker, which needs PostgreSQL, the worker and the agent to be healthy. That contradicts the plan's claim that PostgreSQL loss does not affect running clients. (b) The Deprovision flow removes container and network without detaching the edge first; with the edge running the removal fails on active endpoints, and if the edge is stopped at that moment the network is removed and the edge may then refuse to start because it references a missing network (validate), so one tenant's teardown can take the shared edge down. (c) Reconcile's 'attach lại edge' is not gated on instance state, so a pass during provisioning (between steps 10 and 12) or during a restore can attach an instance that is still allow-all or unreconciled. (d) 'Default gateway … được ghim' names no mechanism, while Docker states the gateway may change whenever connections change.

<details><summary>Evidence</summary>

§14.6 'Thêm tenant không reload Caddy: chỉ cần attach edge vào network tenant'; §11.4 Reconcile 'tự sửa trường hợp an toàn (restart container đã thoát, attach lại edge)'; §11.4 Deprovision '… dừng + xóa container, network → …'; §3.5 PostgreSQL row 'Portal/API (không ảnh hưởng client đang chạy)'; §14.3 'Default gateway của edge được ghim vào network này'. Docker networking docs: 'The default gateway is selected by Docker, and may change whenever a container's network connections change.' and 'When a network should always be the default gateway, it is enough to set its gw-priority to 1.'

</details>

**Suggested fix.** 1) Move the edge to its own compose project so core deploys never recreate it; set `gw_priority: 1` on mg-edge and never pass a gateway priority on tenant attaches. 2) Add an Agent-side edge supervisor that works from Docker state and local files only (no PostgreSQL): on agent start, on the edge container's start event and every 30 s, attach the edge to every network labelled meshguard.role=tenant whose meta/instance.json has edge_attach: true. The flag is written at step 14 (after policy bootstrap) and cleared at the start of deprovision and restore. Worker reconcile only reports drift. 3) Deprovision order: clear flag, detach edge, compose down, network rm. 4) Write an edge-upgrade runbook: pre-pull, announce, recreate, bounded-parallel re-attach, assert attachment count equals active instances. 5) Add to G1 and G3: recreate the edge with N attached tenants while PostgreSQL and the worker are stopped; every tenant answers /key within a stated time.

### OPS-04 — HIGH — §14.3 network table · §15.1/§15.2 · §11.3 steps 4, 6, 17, 18, 19

**Problem.** The network table puts the worker only on mg-data and mg-admin, both internal, yet the orchestrator gives it steps that need other paths: step 4 (DNS resolution check or DNS provider API), step 6 (IdP Admin API, external for a tenant-owned IdP), step 17 (/derp/probe and the STUN port), step 18 (verification over the public path), step 19 (notification). §15.2 itself lists IdP, SMTP and DNS provider as worker egress. As drawn, provisioning cannot get past steps 4, 17 and 18. Separately, every in-cluster caller of a public name (api to auth.<domain> for OIDC discovery and JWKS, worker to <slug>.<mesh_domain>, Headscale in OIDC mode C to its issuer, where the default only_start_if_oidc_is_available makes the instance refuse to start) silently depends on hairpin through the host or the router; under Exposure Path A the records point at the WAN address and this fails unless the router hairpins. The Phase 6 egress block for tenant networks would also cut mode C from its issuer.

<details><summary>Evidence</summary>

§14.3: '`mg-data` (`internal`) | api, worker, postgres …', '`mg-admin` (`internal`, subnet tĩnh) | edge (IP tĩnh), api, worker', '`mg-edge` | edge, web, api, idp, grafana' (no worker). §15.2: 'api / worker | PostgreSQL; edge listener admin; IdP (discovery, token, Admin API); (tùy chọn) SMTP, DNS provider'. §11.3 step 18 'qua đường public: `GET /key` trả 200 …'; step 17 'kiểm tra `/derp/probe` và cổng STUN phản hồi'. Upstream v0.29.7 hscontrol/app.go NewHeadscale: on OIDC init failure `if cfg.OIDC.OnlyStartIfOIDCIsAvailable { return nil, err }`.

</details>

**Suggested fix.** Add a non-internal mg-egress network for the worker, list its allowed destinations for the later egress firewall, and add a worker row to §14.3 and §15.1. Define how in-cluster callers reach public names without hairpin: give the edge the network aliases app.<domain> and auth.<domain> on mg-edge (and auth.<domain> on a tenant network when that tenant uses mode C), and have the worker's check dial the edge's mg-edge address with SNI and Host set to the tenant hostname. Rename step 18 to 'edge allow-list verification (public listener, in-cluster)' and move true outside-in checks (DNS, firewall, port forward, STUN source address) to an external canary or operator checklist that is part of G1 and of the Phase 6 probes. State that the STUN check targets the host address from a non-internal network.

### OPS-05 — HIGH — §17.2 Restore một tenant (steps 2-4) · §17.3 RPO table · P3-T11 · AC-19

**Problem.** §17.2 starts the restored instance on its normal network (edge attached, STUN published) and only afterwards lets the Worker reconcile through the REST API. That leaves a window in which the older policy and every node revoked after the backup are live, and the reconciliation itself is unreliable: (1) the API key in the SecretStore may not exist in the restored database (any rotation after the backup), so the Worker gets 401 and cannot run steps (a) to (d); (2) API keys expired or rotated after the backup become valid again and are not on the list of things to revoke, and route approvals, tags and users changed after the backup are not reconciled; (3) step (a) assumes PostgreSQL is newer than the SQLite copy, but after a host-loss recovery the opposite holds (PostgreSQL RPO 24 h against tenant RPO 1 h), so re-applying 'the current policy version' rolls the tenant back to a day-old policy and the audit needed for (b) is missing; (4) the version test admits backups Headscale will refuse to open.

<details><summary>Evidence</summary>

§17.2 step 3 'Dừng instance → đổi tên `data/` … → hoán đổi staging vào → khởi động → health gate'; step 4 'Worker (a) apply lại policy version hiện hành trong PostgreSQL; (b) duyệt audit từ thời điểm backup để expire lại mọi node …; (c) expire mọi pre-auth key …; (d) chạy `inventory.sync`'; step 2 '`headscale_version` ≤ version đang chạy'; §17.3 PostgreSQL '24 giờ (MVP)', instance '1 giờ'. Upstream v0.29.7 hscontrol/db/versioncheck.go: 'Same minor version: always allowed … Single minor version upgrade (stored.minor+1 == current.minor): allowed. Multi-minor upgrade or any minor downgrade: blocked with a fatal error.' cmd/headscale/cli/policy.go: `policy set` has --bypass-grpc-and-access-database-directly ('does not require the server to be running'); utils.go confirmAction honours --force.

</details>

**Suggested fix.** Reorder: (1) clear the edge-attach flag, detach the edge, stop the instance; (2) swap data/ (chown to run_uid, modes 0700/0600); (3) in a no-network one-shot container run `headscale policy set --bypass-grpc-and-access-database-directly --force -f <policy>` so the restored database never serves a stale policy; (4) start the instance still detached and let the Agent run a declarative PostRestoreReconcile over the unix socket: expire every existing API key, bootstrap a new one into the SecretStore, expire all pre-auth keys, expire or delete the node IDs the Worker lists as revoked after backup.finished_at, reset approved routes and tags to the PostgreSQL view; (5) re-attach, verify policy hash and key through the API, run inventory.sync, emit the diff report. Change the version rule to 'same minor, or exactly one minor behind (migrated forward, irreversible)'. Add a recovery branch: if the manifest time is later than the PostgreSQL recovery point, do not re-apply PostgreSQL's policy; import the instance's policy as a 'recovered' version, mark the tenant 'needs owner review', and expire nodes whose revocation state is unknown for the gap. Add these cases to P3-T11 and AC-19.

### OPS-06 — HIGH — §11.5 EnsureInstance · §11.3 steps 7, 11 · §11.4 API key rotation and Reconcile · §14.5 template · §17.4

**Problem.** Nothing prevents a previously active tenant from being started on an empty data directory. Headscale silently creates a new Noise key and a new database when they are missing, so the result is a brand-new, policy-less (allow-all) control plane on the tenant's hostname. The triggers are ordinary failures: /opt/meshguard on a volume that is not mounted when Docker starts after a reboot (Compose creates missing bind sources by default), a wrong path after a restore swap, or the Agent's own idempotent EnsureInstance and storage.create (mkdir -p plus chown) and the reconcile self-heal of file permissions recreating the directory. The plan then makes it worse: when the stored API key stops working the fallback is to re-run apikey.bootstrap, after which inventory sync would mark every node as gone and new enrollments would land in an allow-all tailnet; existing clients meet an unknown server key, a behaviour the plan itself lists as unknown (RT-06). noise_key_fingerprint is recorded at step 11 and never checked again.

<details><summary>Evidence</summary>

§11.5 'EnsureInstance … // idempotent: storage, file, network, container'; §11.3 step 7 '`mkdir -p` + kiểm tra owner'; §11.4 'nếu key hiện tại mất/hết hạn: chạy lại `apikey.bootstrap` qua Agent'; step 11 'ghi `noise_key_fingerprint`'. Upstream v0.29.7 hscontrol/app.go readOrCreatePrivateKey: util.EnsureDir(dir), then on ErrNotExist only `log.Info()…Msg("no private key file at path, creating...")` and a new key is written; hscontrol/db/db.go creates the SQLite directory with util.EnsureDir(dir). Compose file reference: 'For bind mounts, the short syntax creates a directory at the source path on the host if it doesn't exist' and '`create_host_path` … Defaults to `true`'.

</details>

**Suggested fix.** 1) Tenant template: long-syntax bind mounts with `bind: { create_host_path: false }` for config and data. 2) Agent invariant: once an instance has been activated (marker meta/activated plus registry state), EnsureInstance and StartInstance must refuse to create data/ or to start unless noise_private.key exists and the fingerprint the Agent derives locally from it equals tenant_instances.noise_key_fingerprint; only the first provisioning attempt may create an empty data directory. 3) Health gate, reconcile and health.probe compare the fingerprint on every pass; a mismatch raises a Critical alert, clears the edge-attach flag and blocks apikey.bootstrap, inventory sync and enrollment for that tenant. 4) Host: systemd drop-in `RequiresMountsFor=/opt/meshguard` for docker.service, and add the mount layout to Appendix A.2. 5) Add a fault-injection test: start an activated instance with an empty data directory and expect refusal.

### OPS-07 — MEDIUM — §14.2 directory layout (secrets/) · §7.6 · §14.4 hardening table · P1-T03

**Problem.** The host layout stores every platform secret as root:root 0400 under a root-only directory, while the consumers are non-root containers (api, worker, edge). The plan's own fact ST-05 says Compose file secrets are bind mounts whose uid, gid and mode are ignored, so a non-root process cannot read a root 0400 file: the edge cannot read the DNS token (blocks DNS-01 in P1-T05/T06) and api and worker cannot read the KEK or the DB password. P1-T03's check would certify the broken state, and the usual quick fixes (mode 0444, or running the service as root) undo the hardening in §14.4.

<details><summary>Evidence</summary>

§14.2 'secrets/ # root:root 0700 — KEK, mật khẩu DB, token DNS, khóa bouncer (mỗi secret một file 0400)'; §7.6 'KEK nạp từ file Docker secret (`/opt/meshguard/secrets/`, root `0400`)'; §14.4 'api, worker | Image của ta (distroless, non-root)', edge 'non-root'; ST-05 'thuộc tính `uid/gid/mode` bị bỏ qua ⇒ phải đặt quyền ở phía host'. Compose file reference: 'Compose uses a bind-mount under the hood which doesn't allow `uid` remapping, and these attributes are silently ignored.'

</details>

**Suggested fix.** Fix one numeric UID and GID per service in versions.lock and the compose files (for example user "10001:10001" for api and worker, another pair for edge) and lay secrets out per consumer: /opt/meshguard/secrets/<service>/<name>, owned by that service's UID and GID, mode 0400, parent directories root-owned 0711. Where two services with different UIDs need the same value (bouncer key for crowdsec and edge; DB password for the postgres entrypoint and for api, worker and migrate) store one copy per consumer and rotate them together. Change P1-T03's check script to assert 'readable by the consuming UID and by no other non-root UID', and add a start-up self-test in each service that fails fast naming the secret's path, never its value.

### OPS-08 — MEDIUM — §17.1 (SQLite row, cold backup row) · §14.4 agent image · §14.5 template · ADR-18 · V-12

**Problem.** The online backup is described only as VACUUM INTO run by the Host Agent on the tenant's file. The Agent is a root process in another container opening a live WAL database owned by the tenant's run_uid. Unspecified and risky points: any file root creates in data/ (a fresh -wal or -shm when it is the first or only opener, or an empty db.sqlite on a wrong path) can end up root-owned and make Headscale fail to open its database on the next start, depending on which capabilities the Agent keeps; a WAL reader needs write access to -shm, so a read-only mount is not an option; there is no rule about backups racing lifecycle operations (stop, swap, upgrade) on the same instance; and Headscale runs a full VACUUM on shutdown, which can exceed Docker's 10 s default stop grace period on larger databases and leave a WAL that the cold-backup copy must include. §17.1 and ADR-18 also disagree on the method (.backup or VACUUM INTO).

<details><summary>Evidence</summary>

§17.1 'Online backup qua SQLite backup API (`.backup`) hoặc `VACUUM INTO` do Host Agent thực hiện trên file của tenant'; §14.4 agent image '+ CLI docker/compose + `sqlite3` + `age`'; §14.2 data/ owned by run_uid. Upstream v0.29.7 hscontrol/db/db.go Close(): `if … Sqlite.WriteAheadLog { db.Exec("VACUUM") }`; SetMaxOpenConns(1); sqliteconfig DefaultBusyTimeout = 10000. Compose file reference, stop_grace_period: 'Default value is 10 seconds for the container to exit before sending SIGKILL.'

</details>

**Suggested fix.** Specify the backup as a one-shot helper container started by the Agent with `--network none --read-only --user <run_uid>:<run_gid>`, mounting only this instance's data/ and its staging directory, running `sqlite3 'file:/data/db.sqlite?mode=ro' "VACUUM INTO '/out/db.sqlite'"` followed by PRAGMA integrity_check and PRAGMA foreign_key_check on the copy. Use VACUUM INTO everywhere and delete the .backup alternative. Add an Agent-level per-instance mutex shared by backup, restore, upgrade, reconfigure and restart; if the instance is stopped, take a cold copy instead. Add `stop_grace_period: 60s` to the tenant template and make the cold backup copy db.sqlite, -wal and -shm together. Extend V-12: after 100 online backups under client churn, Headscale restarts cleanly and no file in data/ is owned by a UID other than run_uid.

### OPS-09 — MEDIUM — §17.1 backup table · §14.4 agent row · §4.3 Backup row · §19 Phase 2 rollback strategy · P6-T03

**Problem.** Several backups in §17.1 have no component able to perform them and no task before Phase 6. The Agent mounts only the Docker socket and /opt/meshguard/tenants, but tenant archives are stored under /opt/meshguard/backups/tenants/<instance_id>/; the stack lists restic, yet the Agent has network_mode none and cannot push offsite. The nightly PostgreSQL dump, the Caddy ACME volume copy and the IdP dump have no executor at all: the worker has no filesystem, the Agent has no network and accepts only tenant-scoped specs. Meanwhile Phase 2's rollback strategy already relies on restoring PostgreSQL from a pre-migration dump, and the first task that mentions PostgreSQL backup is P6-T03.

<details><summary>Evidence</summary>

§14.4 agent 'Mount Docker socket và `/opt/meshguard/tenants` cùng đường dẫn trong/ngoài container; `network_mode: none`'; §4.3 'Backup | `VACUUM INTO` + `age` + `restic`'; §17.1 'PostgreSQL (SaaS) | MVP: logical dump nén mỗi đêm', 'Edge (ACME account, chứng chỉ) | Copy volume dữ liệu Caddy | 24 giờ', 'IdP database | Dump theo công cụ của IdP'; Phase 2 rollback 'restore PostgreSQL từ dump trước migration'; P6-T03 'PostgreSQL PITR + offsite; diễn tập restore'.

</details>

**Suggested fix.** Add the mount /opt/meshguard/backups (same path inside and outside) to the Agent and a declarative CoreBackup operation that runs `pg_dump -Fc` through `docker exec` in the postgres container and pipes the stream through age (no network needed), plus the Caddy data and IdP dumps. Add task P2-T03b 'nightly PostgreSQL dump, pre-migration dump, restore rehearsal into a scratch container' before any migration that touches data, and P3-T11b for edge and IdP. Introduce a separate mg-offsite container (egress only to the backup target, read-only mount of the ciphertext directory) that runs restic, and remove restic from the Agent. Put /opt/meshguard/backups on a different filesystem from tenants/ or enforce a quota and an alert, so retention cannot fill the data disk.

### OPS-10 — MEDIUM — §7.6 secrets table (backup key) · §17.1 · §17.2 step 2 · §17.3 · T-15 · §11.4 Deprovision

**Problem.** Key custody for tenant backups is specified three incompatible ways. §7.6 says one backup public key lives on the host and the private key is offline with the operator; §17.1 and T-15 say each archive is encrypted with a key bound to the tenant; §17.2 has the Agent decrypt automatically inside an instance.restore job with a recovery-time target of 15 minutes and an automated AC-19 test. With the private key offline the restore job cannot run unattended; with a single platform key there is no per-tenant binding, and destroying the tenant DEK at deprovision does not make that tenant's backups unreadable.

<details><summary>Evidence</summary>

§7.6 'Khóa mã hóa backup | Public key trên host; private key offline | Agent (mã hóa) / người vận hành (giải mã)'; §17.1 'Archive riêng từng tenant, khóa gắn tenant'; §17.2 step 2 'Agent giải mã vào thư mục staging của đúng instance'; §17.3 'Một Headscale instance | 1 giờ → 15 phút | ≤ 15 phút'; §11.4 Deprovision 'hủy DEK sau grace period'.

</details>

**Suggested fix.** Choose one model and write it in §7.6 and §17. For example: each tenant has an age identity whose private key is stored in the SecretStore under the tenant DEK; archives are encrypted to two recipients, the tenant identity (automated restore: the Worker hands the identity to the Agent over the socket for the duration of the job) and an offline platform recovery recipient (host loss). PostgreSQL dumps are encrypted only to the recovery recipient. Document the consequences: a full recovery restores PostgreSQL first or uses the recovery key; deprovision must delete archives explicitly (restic forget and prune) because the recovery recipient defeats crypto-shredding. Or drop the recovery recipient for tenant archives and accept that losing PostgreSQL plus the KEK loses tenant backups. Update T-15 and the AC-19 wrong-key test to match.

### OPS-11 — MEDIUM — §20 Phase 1 tasks P1-T05…T12 · §21.2 critical path · §22.4 V-03, V-04 · §15.3

**Problem.** Phase 1 task dependencies do not match what the tasks need. (1) P1-T05 must show a trusted wildcard chain with openssl s_client, which needs a running edge with a Caddyfile, the DNS token secret (P1-T03) and the core compose (P1-T06), but it depends only on P1-T04. (2) The edge routing config (P1-T10) depends on P1-T08, yet P1-T08 already attaches the edge and P1-T06 requires 'edge healthy' with no Caddyfile defined. (3) V-03 requires adding a tenant while another tenant's client is connected, but real clients arrive in P1-T12, after both tenants exist; the no-reload PoC in P1-T10 runs before any client is connected. (4) V-04 (non-root) is tested in P1-T11 after tenant A is deployed, although the template and AC-03 depend on its outcome. (5) §15.3 recommends split-horizon DNS on the LAN; DNS-01 propagation checks made from inside the edge will then consult the internal view of the zone and can time out. (6) The API key created in P1-T08 has no storage location before the SecretStore exists (P2-T04).

<details><summary>Evidence</summary>

§20: P1-T05 depends on 'P1-T04, domain', check '`openssl s_client` thấy chuỗi tin cậy'; P1-T06 'Postgres không publish; edge healthy'; P1-T10 depends on 'P1-T08'; P1-T12 depends on 'P1-T09, P1-T10'; P1-T11 depends on 'P1-T08'; §22.4 V-03 'Thêm tenant khi client tenant khác đang kết nối; không rớt stream'; AC-03 'UID sở hữu khác nhau'; §15.3 'dùng DNS nội bộ/split-horizon'; P1-T08 '… API key qua CLI → attach edge'.

</details>

**Suggested fix.** Re-sequence Phase 1 in this order: T04; T06 (core with a minimal Caddyfile: wildcard site answering 404, DNS-01 with the tls `resolvers` option pinned to public resolvers, staging CA); T05 (issue staging, then production certificate); T07 including the non-root PoC (move T11 here); T10a (allow-list, dynamic upstream, admin and metrics listeners, which need no tenant); T08 (tenant A); T08b lab policy; T12a (clients on A with a long-lived relay stream running); T09 (tenant B added while A's streams are observed, which is V-03); T10b reload measurement with stream_close_delay; T12b and T13. Update §21.2 to match. For P1-T08 create only a short-TTL API key for the admin-listener test and state that adopt-instance (P2-T11) bootstraps a fresh key into the SecretStore.

### OPS-12 — MEDIUM — §19 G1 and Phase 6 · P6-T08 · §5.5 growth and measurement tables · §22.4 · Appendix A.1

**Problem.** The properties ADR-08 depends on at scale are first measured in P6-T08, after the orchestrator, portal and MVP acceptance have been built on top of it: edge start and restart time and Docker DNS behaviour with about 100 attached networks, attach and detach time, and recovery after a host reboot or a Docker daemon restart. No gate before G6 includes a host reboot, although cold start (100 Headscale containers plus the edge and its attachments, healthcheck execs, periodic jobs firing on start) is the most likely way a single-host platform fails. §5.5 also says the two-tenant POC measures idle RSS and CPU per instance, but no P1 task or gate records it, and G0 asks for hardware data without a minimum or an admission rule.

<details><summary>Evidence</summary>

P6-T08 'Load/scale test 10 → 100 tenant; baseline tài nguyên/instance; chi phí polling; edge với ~100 network | G5'; §5.5 row '2 tenant — POC … RSS/CPU nhàn rỗi của một instance'; §5.5 'Memory overhead mỗi instance | REQUIRES VALIDATION'; the G1 list has no reboot or daemon-restart item; ST-01 'periodic job bản OSS không bền (cần `RunOnStart`)'.

</details>

**Suggested fix.** Add to Phase 1 (cheap, no backend needed): P1-T15 'edge at N networks': script 100 and 300 dummy tenant networks each with a pause container, attach the edge, record attach time, edge restart time, DNS lookup latency and stream drops on a live tenant. P1-T16 'reboot and daemon restart': with tenants A and B plus the dummies, reboot the host and restart dockerd, record time until every tenant answers /key, confirm no manual step. Make both G1 items with thresholds agreed at G0 (for example edge restart under 60 s at 100 networks, full recovery under 5 minutes). Record idle RSS and CPU of one instance in P1-T13 and derive a provisional hosts.capacity and a reserved-memory admission rule for step 3. Repeat the reboot test at G3 with the orchestrator running.

### OPS-13 — MEDIUM — §11.3 steps 3, 8, 9, 10 · §14.5 (trusted_proxies) · §14.1 daemon.json · §6.3 tenant_instances

**Problem.** Step 8 renders trusted_proxies as the subnet of the tenant network, but the network is created in step 9 and placement in step 3 allocates no subnet, so the value is unknown when the config is rendered and validated. Network ownership is also unspecified: step 9 creates mg-t-<short_id> through the Agent and step 10 runs `docker compose -p mg-t-<short_id> up`; unless the template declares the network external, Compose creates a second network or rejects the pre-existing one, and whether `compose down` in compensation removes it depends on that choice. Sizing of default-address-pools for per-tenant networks is left open.

<details><summary>Evidence</summary>

§11.3 step 3 allocates '`stun_port` …; `run_uid`; `control_hostname = <slug>.<mesh_domain>`; `base_domain`'; step 8 'render `config.yaml` …'; step 9 'tạo network `mg-t-<short_id>` (chưa attach edge)'; §14.5 '`trusted_proxies` | subnet của network tenant (edge)'; §14.1 '`default-address-pools` riêng cho network tenant'; tenant_instances has no subnet column.

</details>

**Suggested fix.** Allocate the tenant network explicitly: add hosts.tenant_net_pool (cidr) and tenant_instances.net_cidr (cidr) with UNIQUE(host_id, net_cidr); allocate a /29 in step 3; have step 9 run `docker network create --subnet <cidr> --label meshguard.instance_id=<id> --label meshguard.role=tenant mg-t-<short_id>`. Declare it `external: true` in the tenant compose template so only the Agent creates and removes it. Attach the edge with a fixed address (`docker network connect --ip`, for example the third host address) and render trusted_proxies as that single /32 instead of the whole subnet. Tenant networks then no longer depend on default-address-pools; keep that setting only for core networks or give those static subnets as well.

### OPS-14 — MEDIUM — §11.3 step table and 'Quy tắc chung' · §13.5 job keys · P3-T05, P3-T07 · G3

**Problem.** The failure model in §11.3 does not close. (1) After step 10 the data directory holds keys and a database, so step 7's compensation (delete only if data/ is empty) never runs; every failure at steps 11 to 18 leaves a directory with key material, contradicting the P3-T07 and G3 criterion of no orphan directories or secrets. (2) 'Non-retryable error: compensate completed steps in reverse' and 'a failed job can :retry from the failed step' cannot both hold: after compensation the DEK is destroyed and the network and instance row are gone. (3) Step 13 returns the API key once; if the worker dies before the SecretStore write, the key is lost but still valid in the instance, and the retry creates another. (4) 'Smallest free port' plus a non-retryable start failure (port held by a host process or by an orphan container) makes every later provisioning pick the same port and fail. (5) §13.5 keys instance.restart and instance.upgrade on config_sha, so a second restart with unchanged config, or an upgrade that only changes the digest, is deduplicated as already done.

<details><summary>Evidence</summary>

§11.3 step 7 compensation 'xóa thư mục chỉ khi do job này tạo và `data/` rỗng'; Quy tắc chung 'lỗi không retry được ⇒ chạy compensation ngược thứ tự các step đã hoàn tất … job `failed` có thể `:retry` (tiếp tục từ step lỗi vì mọi step idempotent)'; P3-T07 'Không còn container/network/thư mục/secret mồ côi'; step 13 'nếu key hiện có còn dùng được ⇒ bỏ qua'; step 3 'cấp `stun_port` trống nhỏ nhất'; §13.5 '`instance.reconfigure` / `instance.restart` / `instance.upgrade` | API / lịch | `instance:<id>:cfg:<config_sha>`'. Upstream CLI v0.29.7 (cmd/headscale/cli/api_key.go) has `apikeys list` and `apikeys expire --prefix|--id`; policy.go has the bypass mode quoted in OPS-05.

</details>

**Suggested fix.** State two terminal outcomes. failed_resumable (transient budget exhausted, nothing compensated): :retry resumes at the failed step. rolled_back (compensation ran): :retry creates a new job from step 3 with fresh placement. For instances that never reached activate, compensation may delete the whole instance directory (it holds only freshly generated keys and an empty database), guarded by the absence of the meta/activated marker. In step 13, before creating a key, list keys and expire every prefix not equal to tenant_instances.api_key_prefix. Have HostInfo report bound UDP ports, let placement skip them, and quarantine a port after a bind failure. Change job keys to instance:<id>:restart:<request-key> and instance:<id>:upgrade:<target_digest>. Seed the baseline before the first start with the bypass CLI in a one-shot container so a running instance is never allow-all, and keep step 12 as verification. Add all of these cases to the fault-injection harness.

### OPS-15 — MEDIUM — §16.1 sources table · §14.3 (mg-obs) · §14.4 monitoring row and socket rule · §15.1/§15.2 · §16.5 · Phase 6 P6-T01

**Problem.** The monitoring design cannot collect or deliver as drawn. All monitoring services are placed only on mg-obs, an internal network whose members are the edge and the monitoring stack. Prometheus therefore cannot reach the API's /internal/prometheus/sd or the api and worker /metrics (api is on mg-edge, mg-admin, mg-data; worker on mg-data, mg-admin), the PostgreSQL exporter cannot reach PostgreSQL, the API cannot query Prometheus for tenant dashboards, Alertmanager has no route out for webhooks or e-mail, and blackbox and STUN probes cannot reach the public hostnames or the host's published UDP ports. CrowdSec appears in no network at all. Per-tenant labels on cAdvisor metrics and on logs come from container labels, which cAdvisor and Alloy obtain from the Docker API, but §14.4 forbids the Docker socket to everything except the Agent.

<details><summary>Evidence</summary>

§14.3 '`mg-obs` (`internal`, subnet tĩnh) | edge (IP tĩnh), prometheus, alertmanager, grafana, log store, collector, exporters'; §14.4 monitoring 'Chỉ `mg-obs`' and 'Không service nào ngoài agent được mount Docker socket'; §16.1 'Prometheus HTTP SD đọc `GET /internal/prometheus/sd` của API', 'cAdvisor | … | Label container `meshguard.tenant_id`', 'blackbox_exporter | HTTPS `https://<slug>.<mesh_domain>/key`'; §16.5 'collector gắn `service`, `tenant_id` (từ label container)'; §15.1 'api | … | Chỉ `mg-edge`, `mg-admin`, `mg-data`'; §15.2 monitoring egress '(tùy chọn) webhook cảnh báo'.

</details>

**Suggested fix.** Publish a complete service-by-network matrix and correct it: api and worker get a metrics and SD listener on mg-obs (bound to that address only); postgres-exporter sits on mg-data and mg-obs; crowdsec on a dedicated network with the edge plus mg-obs for metrics; Alertmanager and the blackbox, STUN and DERP prober additionally join a non-internal network, or the prober runs outside the host, which an Internet-facing check needs anyway. Decide the container-metadata source: either a GET-only Docker socket proxy on an isolated network for cAdvisor and Alloy, with the rule reworded to 'only the Agent can change Docker state', or no socket at all: json-file logging with the `labels` log option for logs and an Agent-written container-id to tenant-id mapping joined in PromQL. Note node_exporter's host-namespace needs and how Prometheus reaches it. Bring a minimal alert set (instance down, disk, certificate expiry, backup age) forward from Phase 6 to Phase 3.

### OPS-16 — MEDIUM — §14.6 edge config (public wildcard listener, bullets) · EG-03 · §16.3 edge 5xx alert

**Problem.** Three behaviours of the no-reload routing are not accounted for. (1) For a hostname whose label matches the slug regex but is not a tenant, the edge asks Docker's embedded DNS for hs-<label>; by default Docker forwards names it does not know to the host's resolvers, so anyone on the Internet can make the edge emit resolver queries per request (subject to the host's search domains), with resolver latency and load. (2) A failed lookup or a stopped instance yields 502 from reverse_proxy, not the uniform 404 the plan specifies; mapping errors to 404 would in turn hide tenant-down from the edge 5xx alert. (3) Caddy treats a placeholder upstream as one static upstream for health-check and load-balancing state, so any passive health check or per-upstream request limit added to implement the plan's connection limit would be shared by all tenants: one tenant's failures or load could eject or throttle everyone.

<details><summary>Evidence</summary>

§14.6 'Nhãn host được kiểm bằng regex slug rồi ghép thành upstream `hs-<label>:8080` (dynamic theo request — EG-03)' and 'Nhãn không khớp regex hoặc không phân giải được ⇒ `404` thống nhất'; protection column 'giới hạn kết nối'. Docker networking docs: 'The embedded DNS server forwards external DNS lookups to the DNS servers configured on the host.' Caddy reverse_proxy docs, on placeholders in upstream addresses: 'potentially many different backends act as a single, static upstream in terms of health checks and load balancing' and 'We recommend using a dynamic upstreams module instead, if possible.'

</details>

**Suggested fix.** Gate the proxy on a local existence check instead of DNS: the Agent maintains a directory of per-slug marker files mounted read-only into the edge (created at step 14 together with the attach flag, removed for deprovision or maintenance); the wildcard site captures the slug with header_regexp and uses a `file` matcher on the marker. No marker gives an immediate 404 with no DNS lookup; marker present goes to reverse_proxy. This also gives a per-tenant public off-switch without reload (restore, suspend, incident isolation). Keep 502 and 504 for existing tenants and alert on them per host. Write into §14.6 that fail_duration, max_fails, unhealthy_request_count and per-upstream limits must not be set on the wildcard proxy; implement per-tenant connection limits elsewhere. Include an unknown-slug flood and a one-tenant-down case in the P1-T10 PoC, where the file-matcher placeholder behaviour is also confirmed.

### OPS-17 — MEDIUM — §14.2 layout (config/ line) · §14.5 Filesystem row · §11.3 step 8 · §11.5 WriteRuntimeFile · P4-T12

**Problem.** The layout says config/ is mounted read-only 'except extra-records', which invites a separate writable single-file bind mount for extra-records.json. Headscale never writes that file; it only reads it and watches the path with inotify. With a single-file bind mount the container stays pinned to the original inode, so the Agent's atomic write (tmp plus rename, as step 8 prescribes) replaces the directory entry on the host and the container never sees the new content: DNS record changes silently stop applying. Two more details are missing: the file must exist before the first start because the watcher is created in Serve() and fails on a missing path, and configtest does not detect that because it only runs NewHeadscale.

<details><summary>Evidence</summary>

§14.2 'config/ # config.yaml, bootstrap-policy.hujson, extra-records.json (mount read-only, trừ extra-records)'; §11.3 step 8 'ghi atomically (tmp + rename)'. Upstream v0.29.7 hscontrol/dns/extrarecords.go: NewExtraRecordsManager calls os.Stat(path) (error 'getting file info') and watcher.Add(path); Run(): 'If a file is removed or renamed, fsnotify will lose track of it and not watch it. We will therefore attempt to re-add it with a backoff.' hscontrol/app.go Serve(): dns.NewExtraRecordsManager(h.cfg.DNSConfig.ExtraRecordsPath), error 'setting up extrarecord manager'. docs/ref/dns.md: 'Headscale uses a checksum to detect changes to the file and a stable output avoids unnecessary processing.'

</details>

**Suggested fix.** Replace the layout line with a dedicated directory: runtime/extra-records.json, bind-mounted as a directory and read-only (runtime/ to /etc/headscale/runtime:ro), with dns.extra_records_path set to /etc/headscale/runtime/extra-records.json. WriteRuntimeFile writes runtime/.extra-records.json.tmp in the same directory, fsyncs, then renames, with stable key order. Step 8 always renders at least an empty array. Never mount the file itself. Add to P4-T12's test: three consecutive updates are each visible from a client (dig on a MagicDNS name) without restart, and writing an empty array removes the last record.

### OPS-18 — MEDIUM — §14.5 template (Healthcheck row) · §11.3 step 11 · §16.3 alert rules · §13.5 periodic jobs

**Problem.** The tenant template defines only the healthcheck command. With Docker defaults the first probe runs 30 s after start and then every 30 s, so step 11's 60 s budget sees at most two probes; every provisioning, restart, restore and upgrade waits at least 30 s; and one slow probe on a loaded host becomes a timeout and a compensation. At 100 instances the defaults also mean a steady stream of `headscale health` execs and, after a host reboot, simultaneous instance-down Critical alerts and every RunOnStart periodic job (backup, inventory sync, health probe) firing against cold instances, each API call costing a bcrypt verification.

<details><summary>Evidence</summary>

§14.5 'Healthcheck | `["CMD", "headscale", "health"]`'; §11.3 step 11 'healthcheck container (`headscale health`); timeout 60 s'; §16.3 'Instance down / healthcheck fail / probe `/key` fail > 2 phút | Critical'; ST-01 '(cần `RunOnStart`)'. Dockerfile reference, HEALTHCHECK: '--interval=DURATION (default: 30s)', '--start-period=DURATION (default: 0s)', 'The health check will first run interval seconds after the container is started'; start-interval 'requires Docker Engine version 25.0 or later'.

</details>

**Suggested fix.** Put explicit values in the template: interval 15s, timeout 5s, retries 3, start_period 45s, start_interval 2s. Define step 11 as 'healthy within 90 s, otherwise store the last 50 redacted log lines in the step detail and fail'. Stagger load: the Agent starts at most K instances concurrently during mass operations; the worker delays periodic jobs by a random 0 to 10 minutes after its own start and spreads per-instance jobs by a hash of the instance id. Add an Alertmanager inhibition for a host-boot window keyed on node_exporter boot time, and set that window from the measured reboot test in OPS-12.

### OPS-19 — MEDIUM — §11.4 Upgrade row · §17.6 · §20 Phase 3 tasks · P6-T10 · §16.6

**Problem.** The Headscale upgrade flow exists only as a table row. No Phase 3 task builds the instance.upgrade job; the first mention is the Phase 6 drill (P6-T10), although upstream ships fixes only on the newest release and the pinned 0.29.7 is itself a security release, so a patch upgrade can become necessary at any time during Phases 2 to 5. The preflight as written checks only the version sequence: nothing validates the re-rendered config, the stored policy or the database migration against the new binary before the instance is stopped, and CheckPolicy on the old version does not exercise the new parser. The edge has the same gap: a Caddy or module security update means recreating the shared edge, which drops every tenant's streams and its runtime attachments, and no procedure is written.

<details><summary>Evidence</summary>

§11.4 Upgrade 'preflight (đích là patch mới nhất của minor kế tiếp — HS-04) → cold backup (dừng → copy …) → đổi image digest → start → health gate → contract smoke qua adapter'; §20 Phase 3 tasks P3-T01…T14 contain no upgrade task; P6-T10 'Diễn tập upgrade/rollback Headscale + job `CheckPolicy` trước upgrade'; RT-12 'bản vá chỉ xuất hiện trên minor mới nhất'; §17.6 'Edge/IdP/monitoring: pin digest, nâng từng thành phần'. Upstream v0.29.7: configtest calls NewHeadscale, whose state.NewState opens and migrates the database and builds the PolicyManager from the stored policy (errors 'initializing database', 'initializing policy manager').

</details>

**Suggested fix.** Add P3-T15 'instance.upgrade (patch level)' to Phase 3 and exercise it in G3. Preflight in a no-network one-shot container with the target digest: mount the re-rendered config read-only and a copy of the cold backup as data, and run `headscale configtest`; it performs the real migration and loads the stored policy, so a failure costs no downtime beyond the cold-backup stop. Only then swap the digest. Require adapter contract tests green for the target version and both digests on the Agent allowlist during the rollout. Roll out canary first, then batches, stopping automatically on the first failed health gate. Record that rollback is restore-only, since minor downgrades are refused by the database version check. Add an edge-upgrade runbook and rehearse it once before G5.

### OPS-20 — MEDIUM — §19 Go/No-Go G1, G2, G3, G4 · §22.2 AC-18, AC-19 · §22.4 V-02, V-03 · Appendix A.2 item 14

**Problem.** Several gates cannot be judged objectively as written. G1(3) says the no-reload mechanism 'works' with no measurement. G1(4) may be recorded as pending when there is no public path, which lets V-02 slip although source-address preservation through Docker's published UDP port can be proven on the LAN. G1(6) and AC-18 ask that B is not interrupted and that A's direct tunnel is 'observed' without saying how. AC-19 and G3 compare a checksum of B's data/ before and after restoring A, but a running instance with connected clients rewrites its database and WAL continuously, so the check is either flaky or forces B to be idle. G2 and G4 end in an internal review with no checklist. Appendix A.2 item 14 probes /health, which the edge blocks by design.

<details><summary>Evidence</summary>

G1 '(3) upstream động theo nhãn + attach network lúc chạy hoạt động (hoặc đã chọn phương án lùi); (4) `tailscale netcheck` đúng qua cổng STUN publish (nếu chưa có đường public: ghi "pending" …); (6) restart A không ảnh hưởng B'; AC-18 'B không gián đoạn control; tunnel direct của A được quan sát trong lúc restart'; AC-19 'Checksum `data/` của B trước/sau'; G2 'rà soát bảo mật nội bộ cho authn/authz không còn lỗi mức Cao'; G4 'rà soát UX bảo mật'; A.2 #14 '`curl -sI https://<host>/health`' against §14.6 'mọi path khác ⇒ `404` (gồm `/api/*`, `/swagger*`, `/verify`, `/version`, `/health`)'.

</details>

**Suggested fix.** Write pass criteria as numbers or observable events. G1(3): during 10 attach and 10 detach cycles the edge access log shows zero closes of tenant A's /ts2021 and /derp streams and a TCP transfer over forced relay shows no reset. G1(4): mandatory on the LAN, with the criterion 'the mapped address in tailscale netcheck equals the client's source address seen by tcpdump on the host's external interface'; only the Internet-facing variant may be pending. G1(6) and AC-18: B's stream-close count is zero and its tailscale status stays connected for the whole window; A's direct flow is a continuous TCP stream with the maximum gap recorded. AC-19: for B compare (i) sha256 of the two key files, (ii) container StartedAt, (iii) a logical dump taken through the API (users, node ids and keys, policy hash, API-key prefixes), and (iv) an inotify or audit record showing no write by the restore job under B's directory. Attach a checklist to the G2 and G4 reviews. Change A.2 item 14 to /key.

### OPS-21 — MEDIUM — §15.3 Exposure Path A · §10.1 (derp.server.* keys) · §14.5 Ports row · §22.4 V-02 · R-06

**Problem.** Three STUN and DERP address details will bite in practice. (1) §15.3 sets derp.server.ipv4 to the WAN address and says LAN clients need hairpin NAT or split DNS. When that field is set the client uses it literally for STUN and DERP and never consults DNS, so split DNS does not help, and a change of a dynamic WAN address requires re-rendering and restarting every tenant instance while control still works through DNS. (2) The template publishes <stun_port>:<stun_port>/udp on all host addresses; on a dual-stack host Docker's userland proxy maps the host's IPv6 address to the container's IPv4 address, so an IPv6 STUN request is answered with a proxy-side address. (3) Nothing tests STUN across a tenant container restart with clients that keep the same source port (stale UDP conntrack entries).

<details><summary>Evidence</summary>

§15.3 Path A '`derp.server.ipv4` = IP WAN; client trong LAN cần hairpin NAT hoặc split DNS'; §14.5 'Ports | Chỉ `<stun_port>:<stun_port>/udp`'; §10.1 lists `ipv4, ipv6` among keys to write explicitly. Upstream: headscale v0.29.7 derp_server.go GenerateRegion sets `IPv4: d.cfg.IPv4, IPv6: d.cfg.IPv6`; tailscale v1.104.7 net/netcheck/netcheck.go nodeAddrPort returns `netip.AddrPortFrom(ip, uint16(port))` from `n.IPv4` when it is non-empty, before any DNS lookup; tailcfg/derpmap.go: 'IPv4 optionally forces an IPv4 address to use, instead of using DNS … the conventional string to disable IPv6 (and not use DNS) is "none"'. Docker port-publishing docs: host IPv6 ports map to the container's IPv4 address when '`--userland-proxy=true` (default)'.

</details>

**Suggested fix.** Default derp.server.ipv4 and ipv6 to empty so clients resolve the hostname (works with split DNS and survives an address change with a DNS update only); set ipv4 only for a static public address and then state that LAN clients require hairpin NAT. Until IPv6 is validated publish STUN on IPv4 only ("0.0.0.0:<p>:<p>/udp"), keep no AAAA records for mesh hostnames and set ipv6 to "none". Extend V-02: (a) the LAN criterion from OPS-20; (b) restart the tenant container while a client runs tailscale netcheck in a loop and require STUN to recover within a stated time; (c) record whether userland-proxy is on and the number of docker-proxy processes at 100 published ports.

### OPS-22 — LOW — §11.5 ValidateConfig · §11.3 step 8 · §11.4 Reconfigure · P3-T03

**Problem.** ValidateConfig is specified as headscale configtest in a throwaway container with no network and a scratch data directory, but the mechanics are not. A builder must get three things right: the scratch directory has to appear at the same container paths the config names (/var/lib/headscale/…) and be writable by the run UID, because configtest creates both private keys and a database; the new config must be validated from a staging directory before it replaces the live config/; and for a tenant using Headscale's native OIDC (mode C) configtest attempts OIDC discovery and fails without network when only_start_if_oidc_is_available is true (the default), so valid configs are rejected.

<details><summary>Evidence</summary>

§11.5 'ValidateConfig … // headscale configtest trong container tạm, không network'; step 8 '`headscale configtest` trong container tạm với thư mục dữ liệu nháp (RT-05)'. Upstream v0.29.7: configtest.go calls newHeadscaleServerWithConfig(); app.go NewHeadscale runs readOrCreatePrivateKey(cfg.NoisePrivateKeyPath), state.NewState(cfg), and for OIDC NewAuthProviderOIDC with a 30 s timeout followed by `if cfg.OIDC.OnlyStartIfOIDCIsAvailable { return nil, err }`; config.go sets the default oidc.only_start_if_oidc_is_available to true.

</details>

**Suggested fix.** Specify the command: `docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user <run_uid>:<run_gid> --tmpfs /var/lib/headscale:uid=<run_uid>,mode=0700 --tmpfs /var/run/headscale -v <instance>/config.next:/etc/headscale:ro <digest> configtest`, with HEADSCALE_OIDC_ONLY_START_IF_OIDC_IS_AVAILABLE=false set only for this run when OIDC is configured (configtest then logs a warning instead of failing), and check issuer reachability separately from the worker. Promote config.next/ into config/ by per-file rename only after a zero exit status, and store the exit code and redacted stderr in the step detail. Reuse the same helper for the upgrade preflight in OPS-19 with a data copy instead of the tmpfs.

### OPS-23 — LOW — §11.1 · §14.2 (run/agent.sock) · §14.4 agent row · §7.6 (token Agent) · §11.3 step 3 (run_uid) · P6-T06

**Problem.** The Agent's own runtime contract is incomplete and inconsistent. The socket path is /run/meshguard/agent.sock in §11.1 and /opt/meshguard/run/agent.sock in §14.2: a host tmpfs path disappears on reboot, a persistent path keeps a stale socket after a crash. The Agent row in §14.4 lists no user, capabilities or read-only setting although the Agent must chown to per-tenant UIDs and traverse 0700 directories they own; with the cap_drop ALL used for the other services it cannot work. The non-root worker must connect to a socket created by the root Agent, and the Agent token in §7.6 is not tied to any check. The run_uid range is not defined, so a tenant UID can coincide with a real host account. Signature verification planned for Phase 6 cannot run in a container without network.

<details><summary>Evidence</summary>

§11.1 'gRPC qua Unix socket `/run/meshguard/agent.sock`'; §14.2 '└── run/agent.sock # Unix socket worker ↔ agent'; §14.4 agent row 'Mount Docker socket và `/opt/meshguard/tenants` cùng đường dẫn trong/ngoài container; `network_mode: none`; allowlist image digest'; §7.6 'Khóa bouncer CrowdSec, token Agent | Docker secret'; §11.3 step 3 lists `run_uid` with no range; P6-T06 'Image không ký bị từ chối'.

</details>

**Suggested fix.** Add an Agent row to the template tables: runs as root with cap_drop ALL plus cap_add CHOWN, FOWNER, DAC_OVERRIDE; read_only true; tmpfs for DOCKER_CONFIG; no-new-privileges; pids and memory limits. Use one socket location: a named volume mounted only into worker and agent; the Agent unlinks a stale socket at start, creates it 0660 with group equal to the worker's GID, and checks peer credentials (SO_PEERCRED uid equals the worker uid) in addition to the token. Define hosts.run_uid_range (for example 200000 to 265535, outside /etc/passwd and subuid ranges) with UNIQUE(host_id, run_uid). State that signature and provenance verification happens in CI and in the worker when it updates the allowlist; the Agent enforces digests only.

### OPS-24 — LOW — §14.6 public wildcard listener · §18.1 T-10/T-11 mitigations · P0-T03, P1-T04 (edge build) · EG-11

**Problem.** Two edge details conflict with the no-reload goal and with the threat mitigations. The mitigations for T-10 and T-11 rely on connection and rate limits at the edge per IP and per tenant hostname, but the edge build contains only the DNS and CrowdSec modules and the plan's own fact EG-11 says Caddy rate limiting needs an unofficial plugin; none is chosen or pinned. The public allow-list adds /oidc/callback and /register/confirm/* only when a tenant uses OIDC, that is per tenant, which on a single wildcard site means a config change and a reload: the event the design is built to avoid.

<details><summary>Evidence</summary>

T-11 'Rate/connection limit theo IP và theo hostname tenant ở edge'; T-10 'giới hạn kết nối ở edge'; P1-T04 'Build image edge (xcaddy + module DNS + bouncer, pin) + SBOM'; EG-11 'Rate limiting ở Caddy cần plugin không chính thức'; §14.6 'và khi tenant dùng OIDC thêm `/oidc/callback`, `/register/confirm/*`'; EG-02 on reload closing every upgraded stream.

</details>

**Suggested fix.** Either add a pinned rate-limit module to the xcaddy manifest in P0-T03 and P1-T04 (limits keyed by client address and by host, with a load test in the P1-T10 PoC) or restate the mitigation as nftables or conntrack limits per source on 443 and remove the edge-limit claim from T-10 and T-11. Make the allow-list a static superset for all tenants, since the two OIDC paths return 404 from Headscale when OIDC is off. Add to §14.6 a short list of the only events that reload or recreate the edge (edge config change, Caddy or module upgrade, admin-origin IP list) so everything else is provably reload-free.

## Tenant-isolation red team (attacker = one tenant's admin account, one tenant's end-user device, or a compromised Headscale container of tenant A)

**Verdict:** NOT READY TO APPROVE AS-IS: resolve the 8 high issues in the plan first. I found no guaranteed cross-tenant breach of the core model. One instance per tenant, per-instance keys, in-process fail-closed DERP verification and the default-deny edge allow-list all check out against Headscale v0.29.7 source (hscontrol/app.go createRouter, hscontrol/derp/server/derp_server.go, hscontrol/auth.go, hscontrol/debug.go). The isolation claims weaken at the shared and privileged seams, which the plan specifies least: (1) the naming scheme behind the dynamic edge upstream (slug versus an undefined short_id); (2) the root-equivalent Host Agent acting on tenant-writable state and on worker-supplied specs; (3) backup/restore cryptography and post-restore revocation; (4) web-auth that any Internet client can start, credited with a mitigation the plan itself says is impossible; (5) SSRF and IdP-administration paths that bypass the tenant boundary and the support-grant model. The tests for boundaries 3, 4, 10, 11 and 12 assert configuration or the happy path, and nothing probes from inside a tenant network. Nothing was executed: findings come from reading the plan and upstream source/docs, and the claim that the edge container inherits ip_forward=1 is inferred from kernel defaults, not confirmed. Probed without finding a defect: Host/SNI mismatch, path case/encoding/dot-segment/method tricks against the allow-list, h2c upgrade smuggling, cross-tenant auth_id or pre-auth key redemption, API key sent to the wrong instance. Sections to amend first: 14.5/14.6, 11.1/11.5, 17, 7.4, 6.1, 5.2/22.

**Strengths noted:**

- The edge allow-list is default-deny and matches the real v0.29.7 router (hscontrol/app.go createRouter). Every route outside the list (/api/v1/*, /swagger*, /verify, /health, /version, /apple*, /windows) falls to the 404. The main listener is not h2c-wrapped, so an Upgrade cannot tunnel past the path filter, and case, encoding or dot-segment tricks can only shrink what an allow-list admits.
- Relay isolation rests on a mechanism confirmed in source: the embedded DERP sets its verify URL to the in-process scheme headscale-derp-verify with SetVerifyClientURLFailOpen(false) and checks the node key against the instance's own node list. Blocking the public /verify oracle at the edge is correct.
- Per-instance API keys, AAD-bound secret references and Registry.ForTenant make misrouting fail closed (wrong instance returns 401), and api/worker are never attached to tenant networks.
- Cross-tenant enrollment confusion is excluded by construction. Pending auth lives in one instance's memory and upstream binds the follow-up to the originating machine key, so an auth_id or pre-auth key from tenant A is meaningless at tenant B. Host/SNI mismatch gains nothing because one wildcard certificate is used and all routing keys on Host.
- The deny-all policy and API key are set over the local Unix socket before the edge is attached, closing the allow-all window of a fresh instance. Composite tenant foreign keys, FORCE RLS, issuer-binding triggers and the explicit shared-kernel and no-Tailnet-Lock disclosures are the right baseline.

### ISO-01 — HIGH — 14.5 (alias row), 14.6 (public/admin/metrics listener rows), 10.2, 6.3 tenant_instances, 11.3 steps 3, 9, 10

**Problem.** The identifier that names every per-tenant runtime object is never defined, and the edge routing contradicts it. The public listener builds its upstream from the Host label, which is the tenant slug (`hs-<label>:8080`), but the only DNS alias the instance template creates is `hs-<short_id>`; 10.2 shows `hs-a` for slug `a`. `short_id` has no definition, no column in `tenant_instances` and no uniqueness constraint, yet it is the identity of the Compose project, Docker network, container, DNS alias and admin/metrics routing key. Consequences: (a) read literally, every tenant's public control path resolves a name that does not exist, so G1 item 3 fails unless short_id equals the slug; (b) if the builder derives short_id by truncating the instance UUID (the plan prefers UUIDv7), the leading 8 hex digits are identical for every ID generated within about 65 s, so back-to-back provisioning (P3-T14 runs 20 in a row) yields the same `mg-t-<short_id>`: step 9 ('inspect before create') adopts the other tenant's network, `docker compose -p mg-t-<short_id> up -d` recreates the other tenant's container with the new tenant's mounts, and compensation can then `compose down` the wrong tenant; (c) if both `hs-<slug>` and `hs-<short_id>` aliases are added to make routing work, a slug equal to another tenant's short_id gives the multi-homed edge two candidates for one name (Docker DNS answers from every attached network), so one tenant's public traffic, or another tenant's API key, reaches the wrong instance.

<details><summary>Evidence</summary>

14.6: 'Nhãn host được kiểm bằng regex slug rồi ghép thành upstream `hs-<label>:8080`'. 14.5: 'alias `hs-<short_id>` trên network tenant'. 10.2: '`a.<mesh_domain>` → edge → `hs-a:8080`'. 11.3 step 3: '`control_hostname = <slug>.<mesh_domain>`'; step 9 idempotency: 'inspect trước khi tạo'. 6.1: 'UUID (ưu tiên UUIDv7 …)'. 6.3 `tenant_instances` lists no short_id and no unique runtime name. UUIDv7 puts the 48-bit Unix-ms timestamp first, so the first 8 hex digits change only every 2^16 ms.

</details>

**Suggested fix.** Define the identifier in 6.3 and use it everywhere: `tenant_instances.runtime_id text NOT NULL UNIQUE`, generated from a CSPRNG (e.g. 16 lowercase base32 chars, first char a letter), immutable, never reused; or use the full instance UUID. Never use a UUID prefix. Use two disjoint alias namespaces so slug space and ID space cannot collide: `hsp-<slug>` for the public listener and `hsi-<runtime_id>` for the admin/metrics listeners (`X-MG-Instance: <runtime_id>`). The Agent derives project/network/container/alias names itself from the instance row and must FAIL, not adopt, when an object with that name carries a different `meshguard.instance_id` label. Slug rules: keep the regex, and also forbid `--`, the `xn--` prefix and the labels of `<mesh_domain>` itself. Tests: provision 50 tenants concurrently and assert 50 distinct projects/networks/aliases; `Host: <runtime_id>.<mesh_domain>` returns 404; a job whose names collide with a live instance aborts without touching it.

### ISO-02 — HIGH — 11.3 step 7, 14.2, 14.4 (agent row), 17.1, 11.4 Upgrade rollback, 5.2 IT-10/IT-11

**Problem.** The Host Agent (root, Docker socket, all tenants' directories mounted) reads and processes files in a directory the tenant's Headscale process can write, and the plan specifies no symlink, special-file or untrusted-database handling. A compromised container A (attacker model c) owns `data/` read-write and can: (1) replace `noise_private.key`, `derp_server_private.key` or `db.sqlite` with a symlink to another instance's file or to an Agent-local secret. The path layout is uniform and the only unknown is the other instance's UUID, which is not a secret (logs, metric labels, backup object names). The Agent's 'copy file into the same archive' or `sqlite3 … VACUUM INTO` follows the link, and the content returns to A's `data/` on the next restore, which A can provoke by corrupting its DB so the post-upgrade health gate fails and the automatic rollback restores the cold backup. (2) Hand the root Agent a crafted SQLite file; a parser bug there is root plus Docker socket, i.e. every tenant. (3) Plant a FIFO or a huge sparse file and stall the single per-host Agent or fill the shared backup volume for all tenants. In addition, the whole instance directory, including the `compose.yaml` the root Agent executes and `config/`, is owned by the tenant UID, so any host-side foothold as that UID escalates to root. IT-10/IT-11 test only host UID permissions and the overwrite direction, so they detect none of this.

<details><summary>Evidence</summary>

11.3 step 7: '`config/`, `data/`, `secrets/`, `meta/` thuộc `run_uid`, mode `0700`'. 14.2: '<instance_id>/ # owner = run_uid của instance, 0700' (contains compose.yaml). 14.4 agent: 'Image của ta + CLI docker/compose + `sqlite3` + `age` | Mount Docker socket và `/opt/meshguard/tenants` cùng đường dẫn trong/ngoài container'. 17.1: '`VACUUM INTO` do Host Agent thực hiện trên file của tenant' and 'Sao chép file vào cùng archive'. https://www.sqlite.org/security.html section 1.2: 'any database file which might have ever been writable by an agent in a different security domain should be treated as suspect.' IT-10 checks only 'tiến trình UID của B không đọc được file của A'.

</details>

**Suggested fix.** (a) Never touch tenant data from the Agent process. Run backup/restore file work in a throwaway helper container: `user: <run_uid>`, `network_mode: none`, `cap_drop: ALL`, read-only rootfs, pids/mem/cpu/time limits, bind-mounting ONLY that instance's `data/` (ro) and a size-limited per-instance staging dir (rw). The kernel then enforces the tenant boundary instead of path checks. (b) In the helper run `PRAGMA trusted_schema=OFF; PRAGMA cell_size_check=ON; PRAGMA mmap_size=0; PRAGMA quick_check;` before `VACUUM INTO`. Copy only regular files opened with O_NOFOLLOW / openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS); reject symlinks, FIFOs, devices and nlink>1; enforce per-file and total size caps. Any violation fails the backup closed and raises a security_event. (c) Ownership: `<instance_id>/`, `compose.yaml`, `config/`, `secrets/`, `meta/` root-owned (group run_gid, 0750/0440); only `data/` owned by run_uid. The Agent re-renders compose from the spec on every run and never executes an on-disk file it did not just write. (d) Restore: extract as run_uid in the helper, refuse members that are not regular files or directories, use lchown semantics. (e) New isolation test: plant a symlink to another instance, a FIFO, a 1 TB sparse file and a corrupt DB in A's data/; the backup must abort, B's bytes must never appear in A's archive, and the Agent must stay responsive.

### ISO-03 — HIGH — 7.6 (backup key row), 17.1, 17.2 step 2, 18.1 T-14/T-15, 6.1 Retention, 11.4 Deprovision/Upgrade, 14.3 (agent network_mode none)

**Problem.** The backup key model is self-contradictory, so T-15, AC-19 and T-14 cannot be implemented as written and the confidentiality and deletion claims do not hold. 7.6 defines ONE platform backup key (public key on host, private key offline, 'operator decrypts'). 17.1 and T-15 say archives use a 'tenant-bound key'. 17.2 has the Agent decrypt automatically inside an API-triggered job, and 11.4 uses the same restore for automatic upgrade rollback (RTO target 15 min). That is impossible with an offline private key; if the key moves onto the host, T-14's 'key not on host' is false and one host key opens every tenant's Noise key and node database. Further: (i) age-style recipient encryption gives no origin authentication, so the 'authenticated manifest' has no authenticator; anyone with the public key or write access to the offsite repository can mint an archive with any tenant_id/instance_id. (ii) 'Crypto-shredding by destroying the tenant DEK' does not shred backups, which are not encrypted under the DEK and sit in a versioned offsite store. (iii) The Agent has no network and the worker has no filesystem access, so no component can ship archives offsite.

<details><summary>Evidence</summary>

7.6: 'Khóa mã hóa backup | Public key trên host; private key offline | Agent (mã hóa) / người vận hành (giải mã)'. 17.1: 'Archive riêng từng tenant, khóa gắn tenant'; 'Mỗi archive có manifest được xác thực'. 17.2 step 2: 'Agent giải mã vào thư mục staging'. 18.1 T-14: 'backup mã hóa bằng khóa không nằm trên host'; T-15: 'mã hóa bằng khóa gắn tenant … test giải mã sai khóa'. 6.1: 'hủy DEK của tenant (crypto-shredding)'. 14.3: agent 'network_mode: none'.

</details>

**Suggested fix.** Specify one scheme and update 7.6, 17, T-14 and T-15. (1) Use a random data key per archive, wrapped twice: to a per-tenant backup key held in SecretStore under the tenant DEK (online path for automated restore/rollback) and to the offline platform DR recipient (disaster path, manual only). (2) Sign the manifest (tenant_id, instance_id, headscale_version, created_at, monotonically increasing sequence, sha256 of every member and of the ciphertext) with an Ed25519 key held only by the Agent; worker AND Agent verify signature and target match before extracting anything. (3) Deletion: destroying the tenant DEK kills the online path. State explicitly that DR copies remain until the offsite retention purge and add a purge job with verification, or use per-tenant DR recipients whose private keys are destroyed on deletion. (4) Define a `backup-shipper` container: egress only to the offsite endpoint, read-only mount of encrypted archives, no Docker socket, append-only repository credentials. (5) Make T-15's wrong-key test concrete: tenant B's wrapped key must fail to open tenant A's archive.

### ISO-04 — HIGH — 17.2 steps 3-4, 6.4 (authoritative data row 1), 11.4 API key rotation

**Problem.** Restore re-activates credentials and approvals revoked after the backup, and does so while the instance is already reachable. Step 3 starts the restored instance with the edge attached; only afterwards does step 4 re-apply policy, re-expire nodes from the audit trail and expire pre-auth keys. Not handled at all: Headscale API keys (a key rotated because it leaked is valid again until its original expiry, while the backend's current key may be absent from the restored database), route and exit-node approvals revoked after the backup, Headscale users of offboarded members, and tag changes. Between container start and the end of reconciliation, reconnecting clients receive netmaps computed from the stale policy and routes. Audit replay also assumes every revocation left an audit row detailed enough to map onto the restored node IDs.

<details><summary>Evidence</summary>

17.2 step 3: 'Dừng instance → đổi tên `data/` … → hoán đổi staging vào → khởi động → health gate'; step 4: '(a) apply lại policy … (b) duyệt audit … expire lại mọi node … (c) expire mọi pre-auth key … (d) chạy `inventory.sync`', with no mention of API keys, routes, users or tags. 6.4 lists 'pre-auth keys, API keys, Headscale users, policy đang hiệu lực' as authoritative in the tenant SQLite, so a restore rolls all of them back. Contrast 11.3 steps 12-14, where policy and key are set over the local socket before `edge.attach`.

</details>

**Suggested fix.** Mirror the provisioning order. (1) `docker network disconnect` the edge and stop the instance. (2) Swap data and start with NO edge attachment. (3) Over the local Unix socket via the Agent: `headscale policy set` with the currently applied version from PostgreSQL, expire EVERY API key in the restored database and bootstrap a fresh one into SecretStore, expire every unexpired pre-auth key. (4) Re-attach the edge. (5) The worker runs a state-based reconcile, not only audit replay: compare every node, user, route approval and tag in the restored instance with the last known desired state (device_inventory_cache, memberships, route approvals) and expire, delete or un-approve the difference. (6) Only then set status=running and report the diff. Add to AC-19: restore a backup taken before {API-key rotation, node revoke, route un-approve, member offboard, policy tightening} and assert the old API key gets 401 and none of the others is live when the hostname first answers. Add a periodic job: ListApiKeys per instance must equal {current, previous during rotation}; unknown prefixes are expired and raise a security_event.

### ISO-05 — HIGH — 7.4 flow A steps 4-8, 18.1 T-06, 23.1 R-22, 14.6 web-auth redirect

**Problem.** The default enrollment flow can be started by anyone on the Internet, and the plan's mitigations do not close it. The control endpoint is public and an unauthenticated registration request receives an AuthURL. An outsider runs `tailscale up --login-server https://<victim-slug>.<mesh_domain>` on his own machine and sends the genuine platform link `https://<victim-slug>.<mesh_domain>/register/<auth_id>` to a member of that tenant. The edge redirects to the Portal, the member signs in with real SSO+MFA and confirms, and the attacker's device joins the tenant as that user. Three specific defects: (1) T-06 lists a claim page showing hostname/OS as a mitigation, while 7.4 states the Portal cannot show hostname/OS before approval, so the threat model credits a control that cannot exist. (2) The claim is not bound to anything the victim started: step 4 creates an `enrollment_requests` row, but step 6 does not require a pending request from the same member and session. (3) The name check runs after `AuthRegister`; the attacker controls his own hostname and can tell the victim what to type, and the node holds the user's grants until the delete lands.

<details><summary>Evidence</summary>

7.4: 'Headscale API không liệt kê được pending registration (UNSUPPORTED) nên Portal không hiển thị được hostname/OS trước khi phê duyệt'. 18.1 T-06: 'trang claim web-auth hiển thị hostname/OS + xác nhận tường minh'. 7.4 step 6: 'user (đã đăng nhập) nhập tên thiết bị mong đợi và xác nhận; backend gọi `AuthRegister(user, auth_id)`'; step 8: 'lệch ⇒ xóa node ngay'. Upstream headscale v0.29.7 hscontrol/auth.go `handleRegisterInteractive`: creates the pending entry and returns `AuthURL: h.authProvider.RegisterURL(authID)` to any peer that completed the Noise handshake; no credential is involved. (Positive: `waitForFollowup` binds the verdict to the originating machine key, so a stolen auth_id cannot be redeemed by another machine.)

</details>

**Suggested fix.** (1) Remove the hostname/OS claim from T-06 and re-rate R-22. (2) Reverse the direction of the name check: when the member clicks 'Add device', the Portal issues a one-time enrollment code tied to the pending `enrollment_requests` row and prints the command with it, e.g. `tailscale up --login-server … --hostname mg-<code>`. Accept `web-auth:claim` only if that member has a pending web_auth request at most 10 minutes old, created in the same session; after `AuthRegister` the returned node name must equal the code (then rename to the label), otherwise DeleteNode plus security_event. An attacker who starts the flow himself cannot know a code that does not exist yet. (3) A claim link opened without a pending request shows a phishing warning and no confirm button, and is counted and alerted. (4) Let tenants disable web-auth claims entirely and use Portal-issued single-use pre-auth keys; use the same fallback on mobile clients where the hostname cannot be set. (5) The edge validates the auth_id against the upstream format (prefix `hskey-authreq-` plus 24 characters) and URL-encodes it before building the redirect. (6) Test: outsider-initiated auth_id plus a logged-in member without a pending request; the claim is refused and no node is created.

### ISO-06 — HIGH — 8.2 (IdP driver `external`, tenant-brought IdP, flow C), 8.6 tenant.idp:update, 15.2, 18 (no SSRF threat)

**Problem.** Tenant-supplied URLs are fetched server-side from inside the management network, and the plan never mentions SSRF. (1) Portal login: a Tenant Owner sets the tenant's issuer via `PUT /tenants/{t}/identity-provider`. The `external` driver 'checks discovery', and every login then fetches discovery and JWKS and POSTs the code and client secret to the tenant-controlled token endpoint. These calls come from api/worker containers that sit on mg-admin (edge admin listener), mg-data (PostgreSQL) and mg-edge (IdP, api internals), and on a cloud VM (Exposure Path C) next to the instance metadata service. (2) Flow C: the tenant-supplied issuer is rendered into Headscale's config and fetched by the tenant container at start-up, from a network that still has open egress (TD-12). Redirects and DNS rebinding make a one-time discovery check insufficient, and OIDC client libraries commonly embed the upstream response body in error strings.

<details><summary>Evidence</summary>

8.2: '`external` (chỉ ghi nhận issuer/client do tenant cung cấp, kiểm tra discovery)'; 'IdP do tenant mang tới … Hỗ trợ ngay từ MVP'. 8.6: '`tenant.idp:read` / `:update` | `GET` / `PUT /identity-provider`' allowed for Tenant Owner. 15.2: api/worker egress 'IdP (discovery, token, Admin API)'; 14.3 puts api and worker on mg-admin and mg-data. The string 'SSRF' does not occur in the plan and section 18 has no corresponding threat.

</details>

**Suggested fix.** Add an SSRF control to 8.2 and 13 and a threat T-19. Use one hardened outbound HTTP client for every tenant-influenced URL (issuer, jwks_uri, token and userinfo endpoints, later custom-domain checks): https only, port 443 only, no redirects (or re-validate every hop), resolve once and dial the validated IP to defeat rebinding, deny loopback, RFC1918, 169.254.0.0/16, 100.64.0.0/10, ULA, multicast and all Docker pools, cap response size and time, and never echo upstream bodies into Problem.detail. Route that client through a dedicated egress proxy or network so the code path cannot reach mg-admin or mg-data. Check that the discovery `issuer` equals the stored issuer and re-validate endpoints on every refresh. For flow C, validate the issuer in the worker with the same client before rendering, and allow egress from that tenant's bridge only to the resolved issuer address. Tests: issuer pointing at the edge admin IP, at 169.254.169.254, at a host that 302s to an internal address, and at a rebinding name must all be rejected.

### ISO-07 — HIGH — 11.1 (Agent rejection list), 11.3 step 8, 11.5 (InstanceSpec, WriteRuntimeFile), 24 ADR-05

**Problem.** The Agent's trust boundary is a four-item deny-list over a spec that may contain free-form files. This does not deliver ADR-05's goal that a compromised worker must not become host root or cross tenants. Step 8 has 'Worker → Agent' render `config.yaml` and `compose.yaml`; 11.5 says InstanceSpec carries the rendered config plus compose parameters including the network name; 11.1 lists the only rejections. Gaps: (1) if the worker supplies compose YAML, `privileged`, `cap_add`, host mounts, `pid: host`, `network_mode`, extra networks and aliases are all unchecked. (2) A network name that merely matches the pattern can be another tenant's `mg-t-<id>`, putting A's container on B's network with direct access to hs-B:8080/9090 without the edge; reconcile notices later but does not prevent it. (3) The worker-rendered `config.yaml` is not checked for the invariants isolation depends on (`derp.server.verify_clients: true`, `policy.mode: database`, `stun_listen_addr` port equal to the allocated port, empty `tls_*`, `grpc_allow_insecure: false`, `derp.urls: []`, listen addresses, `trusted_proxies`), while tenant-supplied settings (nameservers, search domains, OIDC issuer and allowed_*) flow into that file.

<details><summary>Evidence</summary>

11.1: 'Agent từ chối spec có: image digest ngoài allowlist, đường dẫn không suy ra từ `instance_id` dạng UUID, cổng ngoài dải được cấp, tên network/container sai mẫu'. 11.3 step 8: '`config.render` | Worker → Agent | render `config.yaml` …, `compose.yaml`, `extra-records.json`, `bootstrap-policy.hujson`'. 11.5: '`InstanceSpec` gồm: … config đã render, tham số compose (`run_uid`, …, `stun_port`, tên network, label …)' and `WriteRuntimeFile(ctx, id, kind, content []byte)`.

</details>

**Suggested fix.** Make the Agent API a closed, typed parameter set and move ALL rendering into the Agent: `EnsureInstance{instance_id, tenant_id, slug, runtime_id, image_digest, run_uid, stun_port, limits, HeadscaleParams{node_expiry, dns{validated types}, oidc{issuer, client_id, …}}}`. The Agent owns the compose and config templates (versioned in its image), derives every name, path and alias from the instance identifiers itself, marshals YAML from structs (no text templating of tenant strings), and exposes no RPC that accepts YAML, mounts, capabilities, network names or commands. `WriteRuntimeFile` takes typed DNS records, not bytes. `instance_config_versions` stores what the Agent rendered (hash returned to the worker). Add property tests: no input to the Agent API can produce a container with a mount outside `/opt/meshguard/tenants/<its id>`, a capability, a second network, or a config that violates the invariant list.

### ISO-08 — HIGH — 8.4 invariant 2, 8.5 platform.idp:manage, 8.7, 6.3 identity_providers/identities, 7.6 (IdP admin credential), 18.1 T-03

**Problem.** 'No implicit tenant access for platform roles' and the dual-controlled break-glass can be bypassed through identity administration, with no second person and no tenant-visible audit. (1) With the default platform-hosted Keycloak, whoever administers the IdP (a Super Admin at the console on the admin origin, or anything holding the worker's IdP admin credential) can impersonate a Tenant Owner or reset his password and OTP and log in as him. That yields Owner rights, which exceed anything a grant allows ('never Tenant Owner') and include enrolling devices. (2) Identities are keyed `(idp_id, subject)` and `identity_providers.issuer` is a mutable column that a Super Admin can PATCH via `/platform/identity-providers` without 2P. Pointing an existing tenant IdP row at an attacker-run issuer that asserts the Owner's `sub` inherits every membership. The automated invariant tests in 8.4 would pass while both paths exist; T-03's residual risk lists only two colluding Super Admins and host root.

<details><summary>Evidence</summary>

8.4 invariant 2: 'role platform không bao hàm quyền nội bộ tenant'. 8.6: grants 'không bao giờ Tenant Owner'. 8.5: '`platform.idp:read` / `:manage` | `GET` / `POST,PATCH /platform/identity-providers`' allowed for SA with no 2P marker. 6.3: identities '`UNIQUE(idp_id, subject)`'; identity_providers has `issuer` as an ordinary column. 7.6: 'Thông tin quản trị IdP (cho driver) | SecretStore | worker'. 15.1: 'Console quản trị IdP chỉ ở origin admin'. 18.1 T-03 residual: 'Hai SA thông đồng; root host bỏ qua mọi kiểm soát ứng dụng'.

</details>

**Suggested fix.** (1) Make issuer immutable per identity_providers row. Changing a tenant's IdP creates a new row, and the Tenant Owner re-links memberships with step-up. Any platform-initiated change to a tenant-scoped IdP row needs tenant approval or 2P break-glass and writes a tenant-visible audit event. (2) Keycloak realm template: disable impersonation; give the IdP driver a per-realm service account with minimum roles (create/disable users, send required actions) instead of a master-realm admin; forward Keycloak admin events (credential reset, user update, impersonation, client change) into the tenant's audit_events. (3) Put the Keycloak admin console behind the same 2P, step-up and IP restriction as break-glass, and alert on every admin login. (4) State in 8.7 and T-03 that with a platform-hosted IdP the platform can become any tenant user, and recommend a tenant-owned IdP for customers who need the separation. (5) Tests: PATCH of issuer on a tenant IdP is rejected; an admin reset of a tenant user's credential produces tenant-visible audit and a notification.

### ISO-09 — MEDIUM — 8.5 (2P cells), 13.2 (tenants, platform rows), 6.3

**Problem.** Dual control (2P) is a listed mitigation for tenant deletion, instance restore, Super Admin assignment and break-glass, but only the break-glass approval has a data model or API. 13.2 has no request/approve endpoints for `DELETE /tenants/{id}` or `:restore`, and 6.3 has no table holding the pending action, its parameters, requester, approver and expiry. Without parameter binding, an approver can be shown one action while another executes (for example a restore with a different backup_id).

<details><summary>Evidence</summary>

8.5: '`platform.tenant:delete` … 2P', '`platform.instance:restore` … 2P | 2P', 'SA role: 2P'. 13.2 lists `DELETE /tenants/{tenantId}` (202, dual control) and `:restore` with no approval endpoints. In 6.3 only `support_access_grants` has approval columns.

</details>

**Suggested fix.** Add `approval_requests(id, action, target_type, target_id, tenant_id NULL, params jsonb, params_sha256, requested_by, requested_at, approved_by, approved_at, expires_at, status, consumed_by_job_id)` with CHECK (approved_by <> requested_by), a trigger that both parties are active platform users holding the required permission, single-use consumption in the same transaction that enqueues the job, 30-minute expiry, and step-up on approve. Endpoints: `POST /platform/approvals`, `POST /platform/approvals/{id}:approve` and `:reject`; 2P operations take `approval_id` and re-hash their parameters before executing. Tests: self-approval, replay, parameter change after approval, expiry.

### ISO-10 — MEDIUM — 14.3 (closing paragraph), 14.6 internal listener rows, 14.1 Firewall row, 22.2 AC-02/AC-20

**Problem.** The claim that tenant containers cannot reach the edge's internal listeners rests on `bind` to a static IP, which is not an interface restriction, and the multi-homed edge is a router by default. Linux uses the weak host model: a listener bound to the mg-admin address accepts a connection arriving on a tenant-network interface if the destination is that address, and with default `arp_ignore=0` the edge answers ARP for it on the tenant bridge. A container network namespace normally inherits `net.ipv4.ip_forward=1` from the Docker host (not confirmed here; check on the target host), and the edge namespace has no filter rules, so the edge would also forward packets between tenant networks. Today this is unreachable only because the tenant container lacks NET_ADMIN/NET_RAW and Docker's host-side isolation chains drop inter-bridge traffic. The plan names neither control as load-bearing, and a single ACCEPT rule in the DOCKER-USER chain the plan intends to write would bypass the second. There is no test from inside a tenant network: AC-20 scans from outside, and AC-02 and reconcile only count network members. Related: the optional IP restriction on `admin.<domain>` and CrowdSec's default private-range whitelist would treat a tenant container (private source address on the edge's own interface) as trusted LAN.

<details><summary>Evidence</summary>

14.3: 'chúng `bind` vào IP tĩnh của `mg-admin`/`mg-obs` và yêu cầu thêm token nội bộ, để container của một tenant không gọi được chúng qua network tenant'. 14.1: 'Quy tắc trong chain `DOCKER-USER`/nftables'. AC-02: 'network mỗi tenant đúng 2 thành viên'; AC-20: 'Port scan từ ngoài'. Kernel behaviour: new network namespaces inherit IPv4 devconf, including forwarding, from the init namespace by default (https://sysctl-explorer.vstack.com/net/devconf_inherit_init_net.html). Check with `docker exec <edge> sysctl net.ipv4.ip_forward`.

</details>

**Suggested fix.** (1) Edge service: `sysctls: net.ipv4.ip_forward=0, net.ipv6.conf.all.forwarding=0, net.ipv4.conf.all.arp_ignore=1, net.ipv4.conf.all.arp_announce=2, net.ipv4.conf.all.rp_filter=1`. (2) In the admin and metrics sites add a `remote_ip` matcher for the mg-admin or mg-obs subnet and `abort` everything else, in addition to the token; give each internal listener its own port. (3) Rule for 14.1: DOCKER-USER contains only DROP/RETURN, never ACCEPT. Document the tenant pool CIDR and exclude it explicitly from the admin-origin allow-list and from CrowdSec whitelists. (4) Add an in-network probe test (IT-14 in ISO-18): a probe container on mg-t-A, once hardened like Headscale and once with NET_ADMIN+NET_RAW to simulate a capability regression, must fail to reach hs-B:8080/9090, the edge admin and metrics listeners, PostgreSQL, api and host services. Run it before G1 and after every edge or template change.

### ISO-11 — MEDIUM — 14.6 (admin and metrics listener rows), 24 ADR-08/ADR-10, 18.1 T-05

**Problem.** Internal credentials are handed to tenant instances, and every tenant's API key flows through the Internet-facing proxy. (1) Caddy forwards request headers unchanged by default. Unless explicitly removed, the admin listener's internal token and the metrics listener's token (typically a Prometheus bearer Authorization header) are delivered to `hs-<id>` on every call, so a compromised instance learns the shared second factor protecting both internal listeners for all tenants. (2) The all-powerful per-instance API key and the internal token are terminated by the same Caddy process that parses all Internet traffic and loads third-party modules (DNS provider, CrowdSec bouncer). A memory disclosure or RCE there yields each tenant's key as it passes. T-05's residual risk lists only api/worker.

<details><summary>Evidence</summary>

14.6: 'Admin nội bộ | … | Token nội bộ + API key của instance'; 'Metrics nội bộ | … | Token nội bộ'. Caddy reverse_proxy docs, Headers / Defaults (https://caddyserver.com/docs/caddyfile/directives/reverse_proxy): Caddy 'passes through incoming headers—including Host—to the backend without modifications', except X-Forwarded-*. 18.1 T-05 residual: 'api/worker bị chiếm lộ các key đang dùng trong bộ nhớ' (edge not listed).

</details>

**Suggested fix.** (1) Specify `header_up -X-MG-Token` and `header_up -X-MG-Instance` on the admin route and `header_up -Authorization` on the metrics route. Prefer mTLS or a Unix socket to a shared header, and use distinct credentials for admin and metrics. (2) Move the admin and metrics listeners out of the public edge into a second, unpublished gateway container (stock Caddy, no third-party modules, attached to tenant networks plus mg-admin/mg-obs). The public edge then has no route to `/api/v1` and never sees an API key. Tenant networks then have exactly three members {headscale, edge, gateway}; update ADR-08, the reconcile check and AC-02. (3) Test: capture requests arriving at a test instance and assert that neither the internal token nor the metrics Authorization header is present.

### ISO-12 — MEDIUM — 7.6 (KEK and API key rows), 5.2 boundary 10, 14.3 mg-admin, 24 ADR-17

**Problem.** Boundary 10 lists a per-tenant DEK as an isolation mechanism, but one KEK unwraps every tenant's DEK. That KEK is loaded into `api`, the process that parses all Portal traffic, alongside platform-scope database access and membership of mg-admin. A single RCE or file-read in api therefore yields every tenant's Headscale API key and the network path to use it; the per-tenant DEK only buys crypto-shredding. The plan applied this reasoning to the Docker socket (ADR-05) but not to the KEK.

<details><summary>Evidence</summary>

7.6: 'KEK | File trên host + bản sao offline | api, worker'; 'Headscale API key (mỗi instance) | SecretStore | api, worker'. 5.2 boundary 10: 'API key, DEK, thư mục/UID riêng'. 14.3: mg-admin members 'edge (IP tĩnh), api, worker'.

</details>

**Suggested fix.** Keep the KEK and the mg-admin attachment out of the public API tier. A small internal broker (or the worker) is the only process that reads the KEK and talks to Headscale. api calls it over a Unix socket or gRPC, passing the authenticated principal and tenantId, and the broker re-checks tenant scope before each call. api then holds no KEK, no API keys and no route to instances. If this is deferred, say so in ADR-17 and T-05, correct boundary 10 so the DEK is not presented as tenant isolation, and alert on SecretStore decrypt volume per principal.

### ISO-13 — MEDIUM — 6.1 (Row-Level Security, DB roles, Platform scope, Audit history rows), 6.3 audit_events/usage_records, 5.2 IT-03

**Problem.** Four RLS details would fail open or fail closed in production, and IT-03 as written detects none of them. (1) Platform scope is a session setting (`app.scope='platform'`) on the same database role and pool that serve tenant requests. Any path that can set a GUC (injection, a helper using SET instead of SET LOCAL, a leaked session value) sees all rows of every T+P table (tenant_instances, identity_providers, secrets, backups, support_access_grants). (2) After a connection has once run `SET LOCAL app.tenant_id`, later transactions on that pooled connection read `current_setting('app.tenant_id', true)` as an empty string, not NULL. The policy cast to uuid then raises errors in platform-scope transactions on reused connections. This is well-known PostgreSQL behaviour that I did not test here; cover it with a test. (3) `audit_events` and `usage_records` are partitioned. Policies on the parent are ignored when a partition is named directly, so RLS depends on the application role having no privileges on partitions, which `ALTER DEFAULT PRIVILEGES` in a migration or the monthly partition-creation job can easily break. (4) Support access is enforced only by the application setting `app.tenant_id`; the database does not check that an active grant exists.

<details><summary>Evidence</summary>

6.1: policy '`tenant_id = current_setting('app.tenant_id', true)::uuid`'; 'policy bổ sung `current_setting('app.scope', true) = 'platform'`'; 'nhân sự nền tảng muốn đọc phải có Support Access Grant và đặt đúng `app.tenant_id`'; '`audit_events` … partition theo tháng'. PostgreSQL docs, Inheritance (https://www.postgresql.org/docs/current/ddl-inherit.html): 'A child table's policies, if any, are applied only when it is the table explicitly named in the query; and in that case, any policies attached to its parent(s) are ignored.' IT-03 covers only: 'không đặt `app.tenant_id` ⇒ 0 hàng; chèn tham chiếu chéo tenant bị DB từ chối; đặt tenant A không đọc được hàng tenant B'.

</details>

**Suggested fix.** (1) Use two login roles and two pools: `mg_app_tenant`, with policies `TO mg_app_tenant USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)` and no platform branch; and `mg_app_platform`, used only by platform handlers and the worker, with its own policies. Tenant-request code then cannot obtain platform scope whatever GUC it sets. (2) Use `SELECT set_config('app.tenant_id', $1, true)`; have `WithTenantTx` also set `app.actor_id` and `app.actor_kind`; run `RESET ALL` when a connection returns to the pool. (3) Partitions: revoke all privileges on partitions from application roles; create partitions only through the migrator with RLS enabled and forced; add a CI query asserting every partition has zero application-role privileges. (4) For tenant-internal tables extend the tenant policy: actor is a tenant member, OR an approved, unexpired, unrevoked row exists in support_access_grants for (row tenant, `app.actor_id`). Add a trigger on support_access_grants: approval_kind 'tenant' requires the approver to be a member of that tenant holding tenant.support_grant:decide; 'breakglass' requires two distinct Super Admins. (5) Extend IT-03: reused connection, direct SELECT on a partition, tenant role calling `set_config('app.scope','platform',true)`, staff reading tenant tables with and without a live grant.

### ISO-14 — MEDIUM — 13.1 (Idempotency row), 6.3 idempotency_keys and enrollment_requests, 13.2 enrollment, 7.4 flow B

**Problem.** The idempotency design contradicts the show-once rule for enrollment credentials. `Idempotency-Key` is mandatory for enrollment creation and the stored response is replayed verbatim; the creation response is the only place the plaintext pre-auth key appears. As specified, the plaintext key is persisted in PostgreSQL (`idempotency_keys.response jsonb`, no RLS, no tenant column, included in nightly dumps) and can be fetched again by replaying the key, while 6.3 promises that no plaintext pre-auth key is stored. The primary key `(key, identity_id)` has no tenant or route, so a support identity acting in two tenants with the same key could be served tenant A's stored response on tenant B's path unless `request_hash` happens to cover the path.

<details><summary>Evidence</summary>

13.1: '`Idempotency-Key` bắt buộc cho `POST` tạo tài nguyên/job (tenant, enrollment, …); lưu ở `idempotency_keys`, lặp lại trả cùng kết quả'. 6.3: '`idempotency_keys` | `key, identity_id, request_hash, response jsonb, status, expires_at` | `PRIMARY KEY(key, identity_id)` | —'; enrollment_requests: 'Không lưu plaintext pre-auth key/Auth ID'. 13.2: 'Pre-auth key chỉ hiển thị một lần trong response tạo'.

</details>

**Suggested fix.** For operations marked `x-secret-response: true` in OpenAPI, store only `{status, resource_type, resource_id, response_sha256}`. A replay returns the EnrollmentRequest without `preauth_key` plus `secret_already_delivered: true`; a client that lost the key revokes it and creates a new one. Add `tenant_id` (nullable for platform routes) and `operation_id` to the primary key, define `request_hash = sha256(method, canonical path, body)`, apply RLS, and set TTL to at most 24 h. Extend IT-10's secret scan to database rows and backups (search for `hskey-` in a dump taken after the E2E run).

### ISO-15 — MEDIUM — 14.1 Firewall row, 14.3, 15.2 (Headscale tenant row), 23.2 TD-12, 20 P6-T07

**Problem.** Tenant Headscale containers keep unrestricted outbound access to the Internet, the host and the operator's LAN until Phase 6, i.e. through MVP acceptance. Tenant bridges cannot be `internal` because they publish the STUN port, so each has NAT egress and reaches host services on the bridge gateway. 15.2 states the instance needs no egress in default mode, yet blocking it is deferred as TD-12/P6-T07. For attacker model (c) this is the difference between a contained process and a foothold with a route to the LAN router, other LAN hosts, every service the host binds on 0.0.0.0, and an exfiltration or command channel. It is also the path that makes ISO-06 flow C exploitable.

<details><summary>Evidence</summary>

15.2: 'Headscale tenant | Không ở chế độ mặc định … chỉ cần tới issuer khi dùng OIDC gốc'. 23.2: 'TD-12 | Chưa chặn egress của pool tenant | Cần kiểm chứng quy tắc firewall | P6-T07'. 14.1: 'chặn kết nối mới từ pool tenant ra ngoài pool … đề xuất — không tự áp dụng'.

</details>

**Suggested fix.** Move the egress part of P6-T07 into Phase 1 and make it a G1 item. In DOCKER-USER (DROP/RETURN only), drop NEW connections from the tenant pool to anything outside the same bridge subnet; in INPUT, drop tenant-pool traffic to the host except what Docker needs; allow replies via conntrack. Make a per-instance exception only for a validated OIDC issuer address. Give tenant containers no usable resolver unless OIDC is enabled, because Docker's embedded DNS forwards to the host's resolvers and is otherwise an exfiltration channel. Isolation-suite test: from a probe container on mg-t-A, connections to an Internet host, a LAN host, the bridge gateway on 22/80/443 and another tenant's STUN port all fail, while STUN replies and edge-to-8080 still work.

### ISO-16 — MEDIUM — 14.3, 14.4 (closing sentence), 16.1, 16.5, 15.1 api row, 13.2 internal row

**Problem.** The monitoring design cannot be built without breaking two isolation statements, and the network table is inconsistent. (1) cAdvisor needs Docker metadata to expose the `meshguard.tenant_id` container label, and the log collector needs it to attach `tenant_id` from container labels. Both normally get it from the Docker socket, which the plan reserves for the Agent, so a builder will mount the socket into two more containers on mg-obs (reachable from Grafana, which is exposed on the admin origin). (2) Prometheus is only on mg-obs and api is only on mg-edge/mg-admin/mg-data, so the HTTP service-discovery call to `/internal/prometheus/sd` and the scrape of api/worker metrics have no path; that endpoint is also missing from 13.2. (3) api's `/internal/*` and `/metrics` listen on mg-edge, where web, idp and grafana can reach them. (4) The IdP shares mg-data with the platform PostgreSQL, and CrowdSec appears in no network row. (5) Nothing bounds what a compromised instance can return on `/metrics`: forged `tenant_id` labels and unbounded series.

<details><summary>Evidence</summary>

14.4: 'Không service nào ngoài agent được mount Docker socket'. 16.1: 'cAdvisor | … | Label container `meshguard.tenant_id`'; 'Prometheus HTTP SD đọc `GET /internal/prometheus/sd` của API'. 16.5: 'collector gắn `service`, `tenant_id` (từ label container)'. 15.1: 'api | … | Chỉ `mg-edge`, `mg-admin`, `mg-data`'. 14.3: mg-obs members do not include api or worker; mg-data lists '(idp ↔ DB của idp)'.

</details>

**Suggested fix.** (1) Decide and document a socket-free telemetry path in ADR-05/ADR-19. The collector tails `/var/lib/docker/containers/*/*-json.log` read-only, with the json-file `labels` log option so the label travels in the log line. For container metrics, either use a read-only Docker API proxy that allows only `GET /containers/json` and `/containers/{id}/json` on a network only cAdvisor can reach, or use no labels and join on a `meshguard_instance_info{container, tenant_id}` series exported by the API. (2) Fix 14.3: expose api/worker metrics and service discovery through the token-protected metrics listener (or a narrow dedicated network), bind `/internal/*` to that interface only, give the IdP its own database network and PostgreSQL instance, and place crowdsec on a two-member network with the edge. (3) Scrape config for instance targets: `honor_labels: false`, `metric_relabel_configs` dropping any scraped `tenant_id`/`instance_id`, `sample_limit`, `label_limit`, `body_size_limit`, a scrape timeout, and an alert when a target hits a limit. (4) Add a test: an instance serving metrics with another tenant's label and a million series affects neither tenant B's dashboard nor Prometheus health.

### ISO-17 — MEDIUM — 5.2 boundary 4 / IT-04, 14.6 ('giới hạn kết nối'), 18.1 T-11, 2.6 EG-11, 4.3 Edge row

**Problem.** Availability isolation between tenants at the shared choke points has no mechanism and no test. (1) T-11 and 14.6 rely on per-IP and per-hostname connection and rate limits at the edge, but EG-11 records that Caddy needs an unofficial plugin for rate limiting and the edge build contains only the DNS and CrowdSec modules. (2) T-11 counts Headscale's pending-auth ceiling as a mitigation, but it is the lever. Any Internet client that fetches `/key` and completes a Noise handshake can open interactive registrations without credentials. 1,024 of them make that tenant's instance refuse every new web-auth or OIDC enrollment for up to 15 minutes, repeatable indefinitely, and the edge cannot see inside the Noise stream. (3) Tenant `data/` directories share one filesystem with each other, with backups and possibly PostgreSQL, with no quota; a compromised or merely busy instance can fill the disk for everyone, and the only control is an 80 % alert. (4) IT-04 saturates one tenant's CPU only.

<details><summary>Evidence</summary>

18.1 T-11: 'Rate/connection limit theo IP và theo hostname tenant ở edge; … trần pending-auth của Headscale (HS-11)'. 2.6 EG-11: 'Rate limiting ở Caddy cần plugin không chính thức'. 4.3 Edge: 'xcaddy (module DNS provider + CrowdSec bouncer, pin version)'. Upstream headscale v0.29.7 hscontrol/state/state.go: `defaultRegisterCacheMaxEntries = 1024`, `registerCacheExpiration = time.Minute * 15`, `ErrAuthCacheFull` ('authentication capacity reached; retry later'), SetAuthCacheEntry 'admits a pending authentication without displacing existing'. hscontrol/auth.go `handleRegisterInteractive` calls `SetAuthCacheEntry` for any Noise peer, and `authAdmissionError` maps a full cache to HTTP 503.

</details>

**Suggested fix.** (1) State the real mechanism: nftables per-source limits on new TCP/443 connections and on concurrent connections (generous enough for an office NAT), plus either a vetted, pinned rate-limit module added to the xcaddy manifest or an explicit statement that per-hostname limiting does not exist at MVP. (2) Pending-auth exhaustion: alert on Headscale log lines for auth-admission failures, document Portal-issued pre-auth keys as the fallback (they do not use the cache), and consider raising `tuning.register_cache_max_entries` together with the per-IP limit. Correct T-11 so the ceiling is not listed as a mitigation. (3) Add a per-tenant disk quota for `/opt/meshguard/tenants/<id>` (XFS project quota or a size-limited volume per instance), a sized tmpfs and an I/O weight; put PostgreSQL and backups on separate filesystems. (4) Extend IT-04: hold thousands of idle upgraded streams on tenant A's hostname and measure B; fill A's pending-auth cache and enroll on B; fill A's data quota and verify that B and PostgreSQL keep writing.

### ISO-18 — MEDIUM — 5.2 (IT-01 to IT-13), 22.1, 22.2 (AC-02, AC-14, AC-19, AC-20)

**Problem.** Several of the twelve boundary tests assert configuration or the happy path and would stay green during the violations they are meant to catch. Boundary 3 (IT-03) never exercises platform scope, pooled-connection reuse or partitions. Boundary 4 (IT-04) covers CPU only. Boundary 10 (IT-10): 'A's key gets 401 on B' tests Headscale rather than the platform's routing, and the UID check does not cover the root Agent acting on tenant files. Boundary 11 (IT-11/AC-19) tests overwrite of B but not B's data ending up in A's archive, nor resurrected credentials. Boundary 12 (IT-12) checks API parameters but not forged labels at the source. The network claim behind boundaries 4, 9 and 10 is verified by counting members (`docker network inspect`) and an outside-in scan (AC-20); nothing probes from inside a tenant network, where attacker (c) stands. AC-14's 'Auth ID of A used with --login-server of B' is not an executable test, because auth IDs are minted by the server.

<details><summary>Evidence</summary>

5.2 IT-10: 'API key của A bị instance B trả `401`; tiến trình UID của B không đọc được file của A'. IT-11: 'restore A, checksum dữ liệu B không đổi; restore archive của A vào B bị từ chối'. AC-02: 'network mỗi tenant đúng 2 thành viên'. AC-20: 'Port scan từ ngoài'. AC-14: 'Pre-auth key và Auth ID của A dùng với `--login-server` của B'.

</details>

**Suggested fix.** Add to 5.2 and 22: IT-14 in-network reachability (probe container on mg-t-A, hardened and again with NET_ADMIN/NET_RAW: no path to hs-B:8080/9090, the edge admin/metrics listeners, PostgreSQL, api, host services or the Internet). IT-15 naming: concurrent provisioning yields unique project/network/alias, and a collision aborts. IT-16 hostile data directory: symlink, FIFO, sparse giant file and corrupt DB make the backup fail closed with no foreign bytes in A's archive. IT-17 restore: old API key, revoked node, un-approved route, offboarded user and old policy are not live after restore. IT-18 RLS: the tenant database role cannot obtain platform rows via a GUC, direct partition SELECT is denied, and reused connections behave. IT-19: saturating A at the shared edge, disk or auth cache leaves B healthy. IT-20: telemetry forgery at the instance. Rewrite IT-10 as fault injection (swap `internal_address` and secret references of A and B in the registry; every call must fail with 401 and serve no data). Rewrite AC-14 as: an auth_id minted by instance A, submitted to web-auth:claim of tenant B and to instance B's API, is rejected with no node created in either. Run IT-14 and the allow-list scan after every edge or template change, not only at gates.

### ISO-19 — MEDIUM — 11.4 (Suspend, Deprovision, Reconcile), 11.3 step 3, 6.3 tenant_instances constraints, 20 P1-T11

**Problem.** Lifecycle states leave gaps an attacker can use or that cross tenants. (1) Suspend lists 'reject pending auth', but the API cannot enumerate pending auth requests (7.4 says so) and AuthReject needs the ID, so the step is not implementable. In native-OIDC mode new nodes can still register during suspension because the public endpoints stay routed. (2) There is no containment state for a compromised instance: suspend keeps it running and reachable, and reconcile's automatic edge re-attach would undo a manual detach. (3) Deprovision does not mention revoking Portal sessions of the tenant's identities, removing scrape and probe targets, or disconnecting the edge before removing the network. (4) Allocation: there is no `UNIQUE(host_id, run_uid)`. 'Smallest free' reuses a STUN port and UID immediately, although a deleted tenant may still be restored from its final backup during the grace period, when its config points at a port that now belongs to another tenant. Nothing keeps tenant UIDs disjoint from UIDs used by core containers. (5) P1-T11 accepts 'or record an exception' if Headscale cannot run non-root, which silently removes the per-tenant UID mechanism of boundaries 4 and 10.

<details><summary>Evidence</summary>

11.4 Suspend: 'expire mọi pre-auth key còn hiệu lực, reject pending auth'; 7.4: 'Headscale API không liệt kê được pending registration (UNSUPPORTED)'. 11.4 Reconcile: 'tự sửa trường hợp an toàn (restart container đã thoát, attach lại edge)'. 11.3 step 3: 'cấp `stun_port` trống nhỏ nhất'. 6.3 tenant_instances: '`UNIQUE(host_id, stun_port)`' only. 11.4 Deprovision: 'Trước mốc hủy DEK: restore từ backup cuối'. 20 P1-T11: 'Instance healthy với UID riêng, hoặc ghi nhận ngoại lệ'. Upstream hscontrol/grpcv1.go: AuthReject requires the auth_id, and the v1 API has no list call for pending auth.

</details>

**Suggested fix.** (1) Replace 'reject pending auth' with 'restart the instance after applying the suspension policy' (pending auth lives in memory and is cleared on restart). State the OIDC-mode behaviour, or render the OIDC allow-list to an empty-match value for suspended tenants. (2) Add status `quarantined`: edge detached, STUN port unpublished, container stopped, data and logs preserved read-only; reconcile must not self-heal it and only a 2P action can release it. (3) Deprovision checklist: revoke sessions, remove service-discovery and probe targets, disconnect the edge and then remove the network, purge backups per ISO-03. (4) Add `UNIQUE(host_id, run_uid)` and a reserved UID/GID range checked against the host and core images; quarantine a freed port, UID and runtime_id until the tenant's DEK is destroyed. (5) Make V-04 a hard gate: if non-root fails, stop and revise the design (userns-remap or a VM tier) instead of recording an exception.

### ISO-20 — MEDIUM — 8.2 IdP table, row 'Keycloak Organizations trong một realm'; 2.6 ID-02; 6.3 identity_providers

**Problem.** The documented fallback for realm scaling (Keycloak Organizations in one shared realm, with isolation by claim and per-tenant client) is incompatible with the isolation invariants and would open a cross-tenant join through enrollment method C. Headscale cannot check custom claims and admits anyone the IdP authenticates for its client, so with a shared issuer any realm user who can authenticate to tenant A's client can register a node in A's tailnet unless Keycloak itself restricts the client. On the Portal side the schema cannot express the model: `identity_providers.issuer` is UNIQUE and issuer binding is defined per issuer.

<details><summary>Evidence</summary>

8.2: 'Phương án lùi khi số realm trở thành giới hạn; khi đó cách ly dựa vào claim + client theo tenant'. 2.6 ID-02: 'ai IdP xác thực cho client đó đều được nhận … không kiểm tra được claim tùy biến (ví dụ tenant id)'. 6.3: '`UNIQUE(issuer)`'.

</details>

**Suggested fix.** Either delete the fallback or specify it fully. Full specification means: the binding key becomes (issuer, organization-id claim) with a database trigger equivalent to today's issuer binding; Keycloak enforces per-client access (a client-scoped role required for login, or an organization-restricted client policy), and that enforcement gets its own isolation test; enrollment method C is forbidden for tenants on a shared issuer. Until then, state that realm-per-tenant or a tenant-owned IdP is the only supported model, and that V-15 failing means choosing a different IdP product, not Organizations.

### ISO-21 — LOW — 2.6 PL-15 (labelled VERIFIED), 2.6 RT-01, 14.1 daemon.json row

**Problem.** PL-15 misstates who can reach the Headscale debug endpoints, and the actual rule has a consequence the plan misses. At v0.29.7 the `/debug/<name>` handlers (policy, filter, ssh, routes, mapresponses, config, registration-cache, nodestore, ping) are registered through tsweb and guarded by `tsweb.Protected`: loopback and Tailscale ranges only (100.64.0.0/10, fd7a:115c:a1e0::/48), and any request carrying X-Forwarded-For is refused. Headscale's extra private-address allowance (`protectedDebugHandler`) wraps only `/debug/statsviz`; `/metrics` has no gate. So (a) containers on an RFC1918 tenant bridge can read /metrics and statsviz but not the policy or map-response dumps, the opposite of the plan's statement that every container on the Docker network can read them. (b) If the operator picks `default-address-pools` from CGNAT space to avoid LAN clashes (14.1 only says not to overlap the host LAN), every peer on the tenant network counts as a Tailscale IP and all debug endpoints open, including the unauthenticated node-ping action.

<details><summary>Evidence</summary>

Plan 2.6 PL-15: 'truy cập giới hạn theo địa chỉ nguồn loopback/Tailscale/private ⇒ mọi container cùng Docker network đều đọc được'. Upstream headscale v0.29.7 hscontrol/debug.go: `debug := tsweb.Debugger(debugMux)` followed by `debug.Handle('policy', …)` etc.; `protectedDebugHandler` is used only for `debugMux.Handle('/debug/statsviz/', …)` and `/debug/statsviz/ws`; `debugMux.Handle('/metrics', promhttp.Handler())` is unguarded. tailscale v1.104.7 tsweb/debug.go `handle()`: `d.mux.Handle(href, Protected(debugBrowserHeaderHandler(handler)))`. tsweb/tsweb.go AllowDebugAccess: returns false when X-Forwarded-For is set; allows `tsaddr.IsTailscaleIP(ip) || ip.IsLoopback() || ipStr == envknob.String('TS_ALLOW_DEBUG_IP')`. Headscale's go.mod pins tailscale.com v1.104.4; I read tsweb at the v1.104.7 tag.

</details>

**Suggested fix.** Correct PL-15 and RT-01. Add to 14.1: tenant and core address pools MUST NOT overlap 100.64.0.0/10 or fd7a:115c:a1e0::/48 (also needed because tenants use that range inside their tailnets), with a check in P1-T02. Keep `/debug/*` unproxied as planned. Add an assertion from inside the tenant network to edge.verify: `GET hs:9090/debug/policy` returns 403.

### ISO-22 — LOW — 14.6 (dynamic upstream bullets)

**Problem.** For any syntactically valid label that is not a live tenant, the edge asks Docker's embedded DNS for `hs-<label>`. On a miss, Docker forwards the query to the host's upstream resolvers, and containers inherit the host's search domains. Effects: every probed label is disclosed to the upstream resolver; resolution time differs between existing and non-existing tenants, weakening the 'uniform 404' claim; and if the LAN or corporate search domain has a wildcard record or a host named `hs-…`, the edge proxies the allow-listed paths to that host on port 8080.

<details><summary>Evidence</summary>

14.6: 'tên `hs-<short_id>` được phân giải bằng DNS của Docker' and 'Nhãn không khớp regex hoặc không phân giải được ⇒ `404` thống nhất'. Docker behaviour: the embedded DNS server forwards names it cannot resolve to the external DNS servers configured for the container, and containers inherit the host's search domains unless `dns_search` is set.

</details>

**Suggested fix.** On the edge service set `dns_search: .` so no search domain is appended, and pin the proxy's resolver to the embedded DNS with short negative caching. Treat a resolution failure as the same 404 with no retry. Test: an unknown label produces no query towards the host's upstream resolver (packet capture) and returns 404 in the same latency band as a blocked path on an existing tenant.

### ISO-23 — LOW — 13.1 ('Thao tác dài', 'Tenant context'), 13.2 jobs row, 13.3 Job schema, 8.6 tenant.job:read

**Problem.** Long-running operations return `Location: /api/v1/jobs/{jobId}`, a URL without `{tenantId}`. This contradicts the rule that tenant context is always a path parameter and bypasses the 'tenant from path' layers of 8.8, since the handler must authorize from the loaded object alone (the classic BOLA shape). Job `steps[].detail` and `error` are produced by the orchestrator and Agent; they can contain host paths, ports, other tenants' container names or internal addresses, and are returned to tenant roles including Tenant Viewer.

<details><summary>Evidence</summary>

13.1: 'Trả `202 Accepted` + `Location: /api/v1/jobs/{jobId}`' versus 'Tenant context | Luôn là path param `{tenantId}`'. 13.3: 'Job: {…, steps[{name,status,attempt,started_at,finished_at,detail}], error?…}'.

</details>

**Suggested fix.** Use `/api/v1/tenants/{tenantId}/jobs/{jobId}` for tenant-initiated work and `/api/v1/platform/jobs/{jobId}` for platform work, and remove the unscoped path from the spec. Define two projections of Job: platform (full) and tenant (step name, status, timestamps and a stable error code only; no `detail`, no raw error). Add the job endpoints and a seeded cross-tenant job to the IT-02 matrix.

### ISO-24 — LOW — 7.6, 14.2 (`secrets/` row), 14.4 (api/worker/edge rows), 14.5 mounts, 2.6 ST-05

**Problem.** Secret file permissions as specified cannot work with the specified container users, and the likely workaround weakens the boundary. All files under `/opt/meshguard/secrets/` are root-owned 0400, while api, worker and edge run non-root. Compose file secrets are bind mounts whose uid/gid/mode options are ignored (ST-05 notes this). The services cannot read their secrets, so a builder will make them world-readable or run the services as root. The same applies to the tenant `secrets/oidc_client_secret`, which is absent from the instance's mount list (14.5 mounts only `config/` and `data/`).

<details><summary>Evidence</summary>

14.2: 'secrets/ # root:root 0700 — KEK, mật khẩu DB, token DNS, khóa bouncer (mỗi secret một file 0400)'. 14.4: 'api, worker | Image của ta (distroless, non-root)'; edge 'non-root'. 2.6 ST-05: 'thuộc tính `uid/gid/mode` bị bỏ qua ⇒ phải đặt quyền ở phía host'.

</details>

**Suggested fix.** Specify per-service ownership in 14.2: one fixed UID per core service; each secret file owned by exactly the consuming UID with mode 0400 (KEK: broker/worker UID only, see ISO-12; DNS token: edge UID; database passwords: per role per service); parent directory root-owned 0711. Add a read-only mount of `secrets/oidc_client_secret` to the instance template, owned by run_uid 0400 under a root-owned parent. Extend the P1-T03 permission script to fail on any secret readable by more than one UID, and run it in reconcile.

### ISO-25 — LOW — 7.6 (Token DNS provider row), 15.4, 18.1 T-09

**Problem.** The edge, the most exposed process, holds a DNS provider token with write access to the zone containing `app.`, `admin.`, `auth.` and `*.mesh.`. 'Limited to one zone' still lets a compromised edge repoint any platform or tenant hostname and obtain certificates for it. That turns an edge compromise into a durable man-in-the-middle of every tenant's control channel and of the IdP.

<details><summary>Evidence</summary>

7.6: 'Token DNS provider (ACME DNS-01) | Docker secret | Chỉ edge | Theo lịch; giới hạn một zone'.

</details>

**Suggested fix.** Delegate only the ACME challenge: CNAME `_acme-challenge.mesh.<domain>` (and the three single names) to a dedicated throw-away zone or an acme-dns style endpoint, give the edge a token for that zone only, and set Caddy's DNS challenge override domain accordingly. Keep CAA records with the account URI pinned to the edge's ACME account. Monitor the production zone for record changes from an independent vantage point.

## Internal consistency and referential integrity (whole plan read end to end: <plan file>

**Verdict:** Referentially clean but not yet buildable as written. IDs, counts, section cross-references and the ten Mermaid diagrams all check out (verified mechanically), so the defects are not sloppy numbering; they are places where two normative tables prescribe incompatible things. Five are high severity: (1) the public edge route builds `hs-<slug>` while the container alias is `hs-<short_id>`, and `short_id` is never defined; (2) backup key custody is specified three incompatible ways, so the automated restore that G3/AC-19 require cannot run as written; (3) the worker sits only on `internal` networks but must perform public-path, STUN, DNS-provider and SMTP calls; (4) the permission matrix and the endpoint catalogue contradict the 'exactly one x-permission per operation' invariant in about ten places; (5) dual control (2P) is relied on for delete/restore/SA assignment but has no table, endpoint or state. Seventeen medium issues are section-versus-section disagreements (lifecycle flows, phases, task dependencies, migration order, module names and import cycles, monitoring network membership, secret file ownership, unscheduled features). I found no contradiction that by itself yields a cross-tenant breach or data loss, hence no 'critical'; each high item has a local fix that does not change the architecture. Recommend fixing C-01 to C-05 before G0 approval and C-06 to C-22 before the affected phase starts.

**Strengths noted:**

- ID hygiene is excellent (checked mechanically): 98 task IDs match the declared ranges exactly (6/14/16/14/14/12/12/10), no duplicates, and every referenced HS/PL/ID/DP/RT/CL/EG/ST/AC/T/R/TD/V/ADR ID is defined; each cited fact ID supports the claim it is attached to.
- Every section cross-reference (about 150) resolves to an existing section with the expected content, and all declared counts agree across sections: 12 requirement conflicts, 20 AC, 8 phases/gates, 8 user decisions, 19 provisioning steps, 18 discovery items, lint rules L1-L10, migrations 0001-0016 between §19 and §20.
- Numeric defaults are consistent everywhere they recur: node.expiry 90 days, pre-auth key ≤ 15 minutes, API key ≤ 90 days with rotation 14 days ahead, STUN range 3478-3577, support grant ≤ 8 hours, ports 8080/9090/50443.
- The recurring architectural statements do not drift: api/worker reach Headscale only through the edge admin listener, the Agent has no network, tenant networks have exactly two members, baseline policy content and bootstrap-policy file location, default enrollment method A, and /api, /swagger, /verify, metrics blocked at the public edge.
- All ten Mermaid diagrams parse against the current grammars and all Markdown tables have consistent column counts; spot checks against the pinned Headscale tag (routes in hscontrol/app.go, 29 RPCs, CLI flags for policy set and apikeys create, 90-day API key default) match what the plan states.

### C-01 — HIGH — §14.5 + §14.6 (also §5.1, §6.3 tenant_instances, §7.7, §11.1, §11.3 steps 9-10, §11.6)

**Problem.** The public edge listener derives the upstream from the request host label, which is the tenant slug (`hs-<label>:8080`), but the only DNS name the tenant container has on its network is the alias `hs-<short_id>`. `short_id` is used for the compose project, network, container, alias, the `X-MG-Instance` header and the metrics path, yet it is never defined: no derivation rule and no column in `tenant_instances`, while directories are keyed by `<instance_id>` and hostnames by `<slug>`. Either `short_id` equals the slug (never stated, and then the second term is redundant) or the public route of every tenant cannot resolve its upstream. This is the mechanism behind 'add a tenant without reloading Caddy' (G1 condition 3, V-03); the Agent name-pattern check and the reconcile job need the same rule.

<details><summary>Evidence</summary>

L1727: 'Nhãn host được kiểm bằng regex slug rồi ghép thành upstream `hs-<label>:8080` (dynamic theo request — EG-03)'. L1695: '`mg-t-<short_id>` / `mg-hs-<short_id>` / alias `hs-<short_id>` trên network tenant'. L1733: 'tên `hs-<short_id>` được phân giải bằng DNS của Docker'. L1730: 'Header `X-MG-Instance: <short_id>` (regex) ⇒ `hs-<short_id>:8080`'. L1706: server_url = 'https://<slug>.<mesh_domain>'. L775: the `tenant_instances` column list has no `short_id`. L1338: Agent rejects 'tên network/container sai mẫu' but the pattern is never given. `short_id` occurs at L633, 988, 1378, 1379, 1433, 1671, 1695, 1730, 1731, 1733 and nowhere is it defined.

</details>

**Suggested fix.** Define the key once (Quy ước or §5.1) and store it. Suggested text: '`short_id` = 12 lowercase hex characters taken from `instance_id`, immutable, stored in `tenant_instances.short_id` (UNIQUE, CHECK ^[0-9a-f]{12}$). It names the compose project `mg-t-<short_id>`, the tenant network and the container `mg-hs-<short_id>`. The container has two aliases on its tenant network: `hs-<short_id>` (used by the admin and metrics listeners) and `hs-<slug>` (used by the public wildcard listener, which computes hs-{label} from the Host header).' Add `short_id` to §6.3, to `InstanceSpec` (§11.5) and to the Agent name-pattern rule (§11.1); add to P1-T10 verification 'public route resolves through the slug alias, admin route through short_id'. Alternative: drop `short_id` and use the immutable slug in every name (replace all ten occurrences).

### C-02 — HIGH — §7.6 secrets table, §17.1, §17.2, §17.3, §18.1 T-14 and T-15, §5.2 row 11

**Problem.** Backup key custody is specified in three incompatible ways. §7.6 has ONE backup key pair: public key on the host, private key offline, decryption by a human operator. §5.2, §17.1 and T-15 say archives are encrypted with a per-tenant key and require a wrong-key negative test. §17.2 has the Agent decrypt the archive inside the automated `instance.restore` job, which G3/AC-19 must pass, which P6-T04 runs periodically, and for which §17.3 targets RTO ≤ 15 minutes. That is impossible if the private key is offline, and it contradicts T-14 if the key is on the host.

<details><summary>Evidence</summary>

L981: 'Khóa mã hóa backup | Public key trên host; private key offline | Agent (mã hóa) / người vận hành (giải mã)'. L1913: 'Archive riêng từng tenant, khóa gắn tenant'. L658: 'Archive + khóa theo tenant; manifest ràng buộc'. L1927: 'Agent giải mã vào thư mục staging của đúng instance'. L1917: 'KEK + khóa giải mã backup | Bản sao offline ở ≥ 2 nơi'. L2018 (T-14): 'backup mã hóa bằng khóa không nằm trên host'. L2019 (T-15): 'mã hóa bằng khóa gắn tenant … test giải mã sai khóa; diễn tập restore định kỳ'. L1939: RTO '≤ 15 phút'. L2114 (G3): 'restore tenant A không đổi checksum tenant B'.

</details>

**Suggested fix.** Adopt one two-path scheme and use it in all six places: 'Each archive is encrypted with a random data key. The data key is wrapped twice: (a) by the tenant DEK through SecretStore (`backups.key_ref`), used by the automated restore path: the Worker unwraps it and hands it to the Agent over the socket for that job only; (b) by the offline platform recovery public key (age recipient), used only by an operator for host-loss DR. Destroying the tenant DEK crypto-shreds path (a).' Then edit §7.6 (two rows: per-tenant backup data key in SecretStore; offline recovery key), §17.1 column 4, §17.2 step 2 ('Worker unwraps, Agent decrypts into staging'), T-14 (state honestly that a compromised host can decrypt backups reachable through path (a)), T-15 and IT-11, and say in §17.3 that RTO ≤ 15 minutes applies to path (a) only.

### C-03 — HIGH — §14.3 vs §11.3 (steps 4, 6, 17, 18), §15.2

**Problem.** The worker is attached only to `mg-data` and `mg-admin`, both declared `internal` with 'no way out'. Yet the worker executes steps that need reachability beyond those two subnets: step 4 (DNS driver / resolution check), step 6 (discovery of an external issuer), step 17 (probe `/derp/probe` and the tenant STUN port, which is published on the host and is on no network the worker joins), step 18 (checks 'through the public path' that `/key` answers and `/api/v1/*` is blocked), and §15.2 lists SMTP and the DNS provider as worker egress. An `internal` bridge provides no route beyond its own subnet. `edge.verify` is the control T-05 and AC-20 depend on.

<details><summary>Evidence</summary>

L1668: '`mg-data` (`internal`) | api, worker, postgres … | Không có đường ra ngoài'. L1669: '`mg-admin` (`internal`, subnet tĩnh) | edge (IP tĩnh), api, worker'. L1386: step 17 executor 'Worker … kiểm tra `/derp/probe` và cổng STUN phản hồi'. L1387: step 18 executor 'Worker | qua đường public: `GET /key` trả 200; `/api/v1/*`, `/swagger*`, `/verify` … không truy cập được'. L1373: step 4 'Worker … tạo qua DNS driver'. L1785: 'api / worker | PostgreSQL; edge listener admin; IdP (discovery, token, Admin API); (tùy chọn) SMTP, DNS provider'.

</details>

**Suggested fix.** Add an explicit egress network to the §14.3 table, e.g. '`mg-egress` | worker, api, alertmanager, probes | outbound only, nothing published; destinations allow-listed in DOCKER-USER', and state in §11.3 how steps 17 and 18 reach the public side: 'the Worker resolves `<slug>.<mesh_domain>` to the host public/LAN address and connects through `mg-egress` (hairpin), so the check crosses the same listener and DNAT as a real client; the STUN check sends a binding request to `<public_ip>:<stun_port>`'. If hairpin is not available on the host, move steps 17 and 18 to a small `probe` service on the host network and name it as the executor. Update the §15.1 api/worker row and §15.2 to match.

### C-04 — HIGH — §8.4 invariant 4, §8.5, §8.6, §8.7 vs §13.2

**Problem.** Invariant 4 demands exactly one `x-permission` per OpenAPI operation, and P2-T02 ('mọi operation có x-permission') and P2-T15 ('100% operation được phủ') are generated from it, but the matrix and the endpoint catalogue disagree: (a) one operation with several permissions: `PATCH /users/{id}` appears under `tenant.user:manage`, `tenant.membership:assign` and implicitly `tenant.membership:assign_admin`; `POST /enrollment/requests` needs `tenant.enrollment:request` or `tenant.enrollment:issue_privileged` depending on the body. (b) Permissions with no operation: `tenant.membership:assign_admin`, `tenant.enrollment:issue_privileged`, and `tenant.billing:read` = `GET /billing` (no billing endpoint exists in §13.2). (c) Operations with no permission: `GET /enrollment/instructions`, `GET /policies/current`, `GET /dns/records`, every `auth/*` and `internal/*` route. (d) `GET /tenants` and `GET /tenants/{tenantId}` carry `platform.tenant:read` (platform roles only), yet §13.2 says tenant users call them; no tenant permission covers reading one's own tenant. (e) §8.7 says a Super Admin may revoke a grant at any time, but there is no platform permission or endpoint to list or revoke grants; the tenant side can approve and revoke but not reject. (f) The Staff legend says Tenant Admin level is 'only via break-glass', yet two rows read 'G (Admin)' and one 'G (Admin, break-glass)'. (g) The tenant matrix says all paths are under `/tenants/{tenantId}` but its last row is `POST /tenants/{id}:request-deletion`; EU gets 'own resource' on the tenant-wide `GET /diagnostics/instance`.

<details><summary>Evidence</summary>

L1054: 'mỗi operation trong OpenAPI khai báo đúng một `x-permission`'. L1102-1104: `tenant.user:manage` = 'POST /users, PATCH, DELETE /users/{id}'; `tenant.membership:assign` = 'PATCH /users/{id} đổi role ≤ Tenant Operator'; `tenant.membership:assign_admin` = 'đổi role Admin/Owner, chuyển Owner' (no path). L1106 and L1108. L1122: '`tenant.billing:read` | `GET /billing`' vs L1535-1553 (no billing row). L1540: '`GET /enrollment/instructions`'. L1064 vs L1535: 'user tenant chỉ thấy tenant của mình'. L1135: 'tenant hoặc Super Admin thu hồi được bất cứ lúc nào' vs L1084-1085 and L1552 (only POST and :approve-breakglass). L1090 vs L1097, L1099, L1114. L1128, L1119. L2241, L2254.

</details>

**Suggested fix.** Make §13.2 the single source: add an 'x-permission' column there and regenerate §8.5/§8.6 from it. Concretely: split `PATCH /users/{id}` (profile/status, `tenant.user:manage`) from `PUT /users/{id}/role` (`tenant.membership:assign`), and either add `POST /users/{id}:transfer-ownership` or amend invariant 4 to allow one documented 'secondary permission' evaluated in the service layer (target role in {TA, TO} needs `assign_admin`); add `POST /enrollment/keys` for `issue_privileged`; add `GET /tenants/{tenantId}/billing`; map `/enrollment/instructions` to `tenant.enrollment:read`, `/policies/current` to `tenant.policy:read`, `GET /dns/records` to `tenant.dns:read`; define sentinel values `public` (auth/login, auth/callback), `authenticated` (auth/session, auth/logout, `GET /tenants` filtered by membership) and `internal` (never routed by the edge); add `tenant.tenant:read` for `GET /tenants/{tenantId}`; add `platform.support_grant:read` and `:revoke` with `GET /platform/support-grants` and `POST /platform/support-grants/{id}:revoke`, plus `POST /support-grants/{id}:reject` on the tenant side; use one notation for the staff ceiling and state in §8.7 whether a tenant may approve an Admin-level grant.

### C-05 — HIGH — §8.5 (2P cells), §11.4 Deprovision, §17.2 step 1, §13.2, §6.3

**Problem.** Dual control is asserted for tenant deletion, instance restore, Super Admin assignment and break-glass; it is a Phase 3 security control, a T-03 mitigation ('Test 2P') and an ADR-13 validation. Only break-glass has an approval operation. For the other three there is no table, state, endpoint, expiry or requester-is-not-approver rule: `DELETE /tenants/{tenantId}` is annotated '(202, dual control)' with nothing to hold the pending request, and for restore (2P for both SA and PO) it is not stated who may be the second person.

<details><summary>Evidence</summary>

L1060: '2P = cho phép nhưng cần người thứ hai phê duyệt (dual control)'. L1068 (tenant delete: SA 2P), L1072 (restore: SA 2P, PO 2P), L1079 ('SA role: 2P'). L1535: '`DELETE /tenants/{tenantId}` (202, dual control)'. L1398: 'xác nhận dual control → backup cuối'. L1926: 'Kiểm tra quyền (2P) → tạo job `instance.restore`'. L2106: 'dual control cho xóa/restore'. L2007: 'Test 2P'. L2543: 'test 2P'. The only approval endpoint in the plan is L1085: 'POST /platform/support-grants/{id}:approve-breakglass'. §6.3 has no approval table.

</details>

**Suggested fix.** Add a generic mechanism. Table `approval_requests(id, tenant_id NULL, action, target_type, target_id, payload_hash, requested_by_identity_id, approver_identity_id, status {pending, approved, rejected, expired, executed}, reason, expires_at, created_at, decided_at)` with CHECK (approver_identity_id <> requested_by_identity_id), RLS class P. Endpoints `GET /platform/approvals` and `POST /platform/approvals/{id}:approve` / `:reject` with permission `platform.approval:decide` (SA; for restore decide explicitly whether a second PO suffices). A 2P operation returns 202 + `Location: /api/v1/platform/approvals/{id}`; the job is enqueued only on approval, after re-checking the payload hash, with step-up for both parties. Put the table in the Phase 3 migrations (needed by P3-T09 and P3-T11), reuse it for break-glass, and add the work to P3-T09 or a new task.

### C-06 — MEDIUM — §11.4 Suspend and §17.2 Restore vs §7.4, §6.3 enrollment_requests, §11.3 steps 12 and 14

**Problem.** Three lifecycle statements contradict their own constraints. (a) Suspend includes 'reject pending auth', but §7.4 says the Headscale API cannot list pending registrations and `enrollment_requests` keeps only `auth_id_hash`, so the platform has no Auth ID to pass to `AuthReject`. (b) The note below the table says suspension works through deny-all policy 'kết hợp expire node', but the Suspend sequence never expires nodes, and resume only re-applies the saved policy, which would not bring expired nodes back. (c) Restore starts the restored database while the edge is still attached and only afterwards re-applies the current policy and re-expires revoked nodes; for that interval the restored policy, revoked nodes and old pre-auth keys are live, which is exactly what the step claims to prevent. Provisioning, by contrast, forbids any network path until the policy is in place.

<details><summary>Evidence</summary>

L1397: 'expire mọi pre-auth key còn hiệu lực, reject pending auth → `status=suspended`'. L947: 'Headscale API không liệt kê được pending registration (UNSUPPORTED)'. L786: 'Không lưu plaintext pre-auth key/Auth ID'. L1404: 'policy deny-all (được client thực thi qua packet filter) kết hợp expire node'. L1928-1929: 'hoán đổi staging vào → khởi động → health gate. 4. Hậu restore bắt buộc (không để restore hồi sinh quyền đã thu hồi)'. L1381: 'trước khi instance có bất kỳ đường mạng nào'. Upstream check: proto/headscale/v1/headscale.proto at v0.29.7 has AuthRegister, AuthApprove, AuthReject and no list RPC.

</details>

**Suggested fix.** (a) Replace with: 'pending web-auth cannot be enumerated; suspension blocks the Portal claim endpoint (`tenant_suspended`) and the 15-minute in-memory expiry does the rest (optionally restart the instance to flush the cache, ID-05)'. (b) Delete 'kết hợp expire node' from the note, or add an explicit optional 'hard suspend' variant and state that resume then requires every device to re-authenticate. (c) Reorder §17.2: '3. Stop instance → detach edge → swap data → start with no network path. 4. Run (a) policy re-apply, (b) re-expire and (c) pre-auth key expiry through the Agent CLI over the instance Unix socket (same path as `policy.bootstrap`), verify the policy sha256. 5. Re-attach edge → `edge.verify` → `inventory.sync`.' Add this ordering to the P3-T11 verification.

### C-07 — MEDIUM — §18.1 T-06 vs §7.4, ADR-14, R-22

**Problem.** The mitigation list for T-06 (unauthorized node enrollment) says the web-auth claim page shows hostname/OS. §7.4 and ADR-14 state the opposite for the default enrollment method: the Portal cannot show device details before approval and compensates with a name comparison after registration. The threat model therefore credits a control the design says cannot exist.

<details><summary>Evidence</summary>

L2010: 'trang claim web-auth hiển thị hostname/OS + xác nhận tường minh'. L947: 'Portal không hiển thị được hostname/OS trước khi phê duyệt — bù bằng bước đối chiếu sau đăng ký ở bước 8'. L2544 (ADR-14 trade-off): 'không xem được chi tiết thiết bị trước khi duyệt'. L2505 (R-22): 'Trang claim có cảnh báo + đối chiếu tên thiết bị'.

</details>

**Suggested fix.** Replace the phrase in T-06 with: 'trang claim yêu cầu user nhập tên thiết bị mong đợi và hiển thị cảnh báo chống phishing; sau `AuthRegister` backend đối chiếu tên node với tên đã nhập, lệch ⇒ xóa node + `security_event` (hostname/OS chỉ hiển thị được ở chế độ OIDC gốc — ID-07)'. Add a matching verification ('tên lệch ⇒ node bị xóa') and a residual risk ('kẻ tấn công đặt trùng tên thiết bị').

### C-08 — MEDIUM — §13.1 (long-running operations, tenant context), §13.2 jobs, §8.5, §8.6, §12.2

**Problem.** A job is addressed five different ways, and the top-level form breaks the rule that tenant context is always a path parameter (authorization layer 1 takes the tenant from the path, so a top-level job route has no tenant to authorize against). Platform jobs have a list route but no item route, although `POST /tenants` returns a job.

<details><summary>Evidence</summary>

L1525: 'Location: /api/v1/jobs/{jobId}'. L1518: 'Luôn là path param `{tenantId}` (UUID). Không nhận tenant từ body/header/query'. L1551: '`GET /tenants/{t}/jobs` · `GET /jobs/{jobId}`'. L1127: '`tenant.job:read` | `GET /jobs[/{id}]`' (under the `/tenants/{tenantId}` prefix). L1076: '`GET /platform/jobs`' (no item route). L1455: '`POST /tenants` → `GET /jobs/{id}`'. L1142: layer 1 checks the role 'trong tenant lấy từ path'.

</details>

**Suggested fix.** Define exactly two item routes and use them everywhere: `GET /api/v1/tenants/{tenantId}/jobs/{jobId}` (`tenant.job:read`) and `GET /api/v1/platform/jobs/{jobId}` (`platform.job:read`). Change §13.1 to: 'Location is the tenant-scoped URL for tenant-scoped operations and the platform URL for `POST /tenants` and `/platform/*` actions'. Fix L1455 and write the §8.5 row as `GET /platform/jobs[/{id}]`.

### C-09 — MEDIUM — §14.3 and §14.4 vs §16.1, §16.2, §15.1, §15.2, §7.7, §13.2

**Problem.** Monitoring containers are placed only on `mg-obs`, which is `internal` and whose only non-monitoring member is the edge. §16.1 nevertheless has Prometheus read `GET /internal/prometheus/sd` from the API and scrape API/Worker `/metrics` (neither is on `mg-obs`), a PostgreSQL exporter (postgres is only on `mg-data`), blackbox probes of public URLs and a STUN probe to host-published UDP ports (no route from an internal network), and optional alert webhooks. Further membership contradictions: §14.4 says monitoring is 'only mg-obs' while §14.3 puts grafana on `mg-edge`; crowdsec appears in no network although the bouncer needs its LAPI and its metrics are scraped; the §7.7 network list omits `mg-admin`; `/internal/prometheus/sd` is missing from the §13.2 internal group. Finally cAdvisor and the log collector are expected to label by the container label `meshguard.tenant_id`, while §14.4 forbids the Docker socket for every service except the Agent.

<details><summary>Evidence</summary>

L1670: '`mg-obs` (`internal`, subnet tĩnh) | edge (IP tĩnh), prometheus, alertmanager, grafana, log store, collector, exporters'. L1687: 'Chỉ `mg-obs`'. L1667: '`mg-edge` | edge, web, api, idp, grafana'. L1836: 'Prometheus HTTP SD đọc `GET /internal/prometheus/sd` của API'. L1840-1843 (API/Worker `/metrics`, PostgreSQL exporter, blackbox on `https://<slug>.<mesh_domain>/key`, STUN probe). L1553: internal group lists only edge/ask, healthz, readyz, metrics. L1772: 'CrowdSec LAPI … Chỉ edge ↔ crowdsec' (no such network in L1667-1672). L988 lists mg-edge, mg-data, mg-obs only. L1689: 'Không service nào ngoài agent được mount Docker socket' vs L1837 'Label container `meshguard.tenant_id`' and L1898.

</details>

**Suggested fix.** Replace the §14.3 table with a full service × network matrix, one row per service (edge, crowdsec, web, api, worker, agent, postgres, idp, prometheus, alertmanager, grafana, loki, alloy, cadvisor, node_exporter, blackbox, stun-probe, pg-exporter). Minimum edits: expose api/worker `/metrics` and the SD endpoint on `mg-obs` (or proxy them through the edge metrics listener like Headscale); put pg-exporter on `mg-data`; add a network for edge ↔ crowdsec; give blackbox, the STUN probe and alertmanager the egress network proposed in C-03; add `mg-admin` to §7.7; add `GET /internal/prometheus/sd` to §13.2. For labels, either write the exception into §14.4 ('cAdvisor and Alloy read container metadata through a read-only socket proxy limited to GET /containers; this is a filter, not a sandbox — ST-02') or avoid the Docker API (json-file `labels` log option plus file tailing; per-tenant cgroup parent) and say so.

### C-10 — MEDIUM — §7.6, §14.2, §14.4 vs ST-05 (§2.6); §8.1

**Problem.** Platform secrets are files owned root:root with mode 0400 in a 0700 directory, consumed as file secrets by containers that are explicitly non-root with all capabilities dropped (api, worker, edge). The plan's own fact ST-05 says Compose ignores uid/gid/mode for file secrets because they are bind mounts, so those processes cannot read the KEK, the DB passwords, the DNS token or the bouncer key. The secrets inventory also omits credentials the design depends on: the internal token(s) that protect the edge admin and metrics listeners, the offsite backup credential, SMTP and Grafana/IdP client secrets. §8.1 names SecretStore as the store for service identities while §7.6 puts the Agent token in a Docker secret.

<details><summary>Evidence</summary>

L970: 'KEK nạp từ file Docker secret (`/opt/meshguard/secrets/`, root `0400`)'. L1649: 'secrets/ # root:root 0700 — KEK, mật khẩu DB, token DNS, khóa bouncer (mỗi secret một file 0400)'. L1682: 'api, worker | Image của ta (distroless, non-root) | read-only, `cap_drop: ALL` … secret dạng file'. L1680: edge 'non-root; `cap_drop: ALL` + `NET_BIND_SERVICE`'. L295 (ST-05): 'thuộc tính `uid/gid/mode` bị bỏ qua ⇒ phải đặt quyền ở phía host'. L1674: listeners 'yêu cầu thêm token nội bộ' (no row in L972-982). L1001 vs L980.

</details>

**Suggested fix.** Add a table to §14.2: secret file → owner UID:GID → mode → consuming service. For example dedicated host groups: `mg-sec-app` (KEK, app DB password, edge admin token; files root:mg-sec-app 0440; api and worker run with that supplementary group), `mg-sec-edge` (DNS token, bouncer key, listener tokens), `mg-sec-obs` (metrics token); one subdirectory per group with mode 0750 so a service cannot list another group's files. Add the missing rows to §7.6 and correct the §8.1 storage column ('Docker secret file for bootstrap credentials; SecretStore for credentials issued at runtime'). Extend the P1-T03 permission script to assert that each container user can read exactly its own files.

### C-11 — MEDIUM — §7.4 flow A vs §8.4, §8.6, §6.3, X-3 (§2.9)

**Problem.** The permission model has `tenant.enrollment:approve` (`:approve` / `:reject`, held by TO/TA/TP; the Tenant Operator role is described as approving ordinary enrollments), `enrollment_requests` has `status` and `approver_membership_id`, End Users may request only 'if the tenant allows self-enroll', and X-3 presents Portal-brokered enrollment as the replacement for admin approval. But the ten-step flow A contains no approval step: the backend creates the request and, once the user claims the Auth ID, calls `AuthRegister` directly. It is undefined when approval is required, what is approved (the request before the client is started, or the claim) and how that fits the 15-minute in-memory lifetime of a pending registration.

<details><summary>Evidence</summary>

L938-941 (steps 3-6: permission check, create `enrollment_requests`, user runs the client, claim → 'backend gọi `AuthRegister(user, auth_id)`'). L1107: '`tenant.enrollment:approve` | `POST /enrollment/requests/{id}:approve`, `:reject`'. L1106: '✔ (nếu tenant cho phép self-enroll)'. L1045: 'duyệt enrollment thường'. L786: `status, approver_membership_id` with no value list. L370 (X-3). L211 (ID-05): 'cache bộ nhớ 15 phút'.

</details>

**Suggested fix.** Insert into flow A: '3a. Nếu tenant đặt `enrollment.approval = required` (hoặc requester là EU và self-enroll tắt), request ở trạng thái `pending_approval`; TP/TA/TO gọi `:approve` trước khi hướng dẫn và trang claim được mở. Phê duyệt gắn với request (thiết bị dự kiến, hạn 24 giờ), không gắn với Auth ID, nên không phụ thuộc cửa sổ 15 phút; bước claim chỉ được chấp nhận khi request ở trạng thái `approved` và chưa hết hạn.' Add the enum `enrollment_requests.status ∈ {pending_approval, approved, rejected, claimed, consumed, expired, revoked}` to §6.3 and state the same rule for pre-auth keys.

### C-12 — MEDIUM — §11.2 flowchart, §11.3 table and general rules, §11.5 InfrastructureDriver

**Problem.** (a) 'A failed job can be retried and continues from the failed step' contradicts the rule in the same paragraph that a non-retryable failure runs compensation for every completed step (network removed, compose down, storage deleted, tenant set to failed). (b) Step 16 `tenant.configure` ('DNS settings, OIDC', executor Worker, idempotency 'upsert') runs after start, but RT-04 and §11.4 say DNS settings and OIDC are config-file changes needing render + restart, and step 8 already rendered them. (c) Step 12 `policy.bootstrap`, the step that closes the allow-all window, and the compensation of step 14 (detach) have no method in `InfrastructureDriver`, although P3-T03 lists 'policy bootstrap qua CLI' as an Agent operation. (d) Step 8 says the Worker renders `compose.yaml`, while `InstanceSpec` carries only compose parameters and the Agent is supposed to refuse anything outside fixed patterns; who renders the compose file decides how much a compromised worker can make a root-equivalent Agent run. (e) The flowchart has 18 action nodes, omits `idp.ensure` and merges steps 13+14 and 15+16, so it does not match the 19-step table that P3-T05 implements.

<details><summary>Evidence</summary>

L1390: 'chạy compensation ngược thứ tự các step đã hoàn tất … job `failed` có thể `:retry` (tiếp tục từ step lỗi vì mọi step idempotent)'. L1385 vs L239 (RT-04: 'DNS settings, DERP, OIDC, prefixes, trusted_proxies cần restart') and L1396. L1381 and L2263 vs the 13 methods at L1410-1424. L1377: 'render `config.yaml` …, `compose.yaml`, `extra-records.json`, `bootstrap-policy.hujson`' vs L1427: 'config đã render, tham số compose (`run_uid`, giới hạn CPU/RAM/PID, `stun_port`, tên network, label …)'. L1344-1363 vs L1370-1388; L2265: '19 bước'.

</details>

**Suggested fix.** (a) Write: '`:retry` restarts from the earliest step whose effect was compensated (normally step 3); steps whose effect persisted are skipped by their idempotency check'. (b) Reword step 16: 'DB only: `identity_providers` row, tenant settings, Owner membership invitation — no Headscale or config call; DNS/OIDC values were rendered in step 8'. (c) Add `BootstrapPolicy(ctx, id uuid.UUID, hujson []byte) (sha256 string, err error)` and `DetachEdge(ctx, id uuid.UUID) error` to the interface. (d) State: 'compose.yaml is rendered by the Agent from a template shipped in the Agent image, using only typed parameters; the Worker never sends compose text. config.yaml is sent as content and checked by the Agent against a key allow-list (paths, `unix_socket`, `policy.mode`, listen addresses).' (e) Redraw §11.2 with 19 nodes named exactly as in the table.

### C-13 — MEDIUM — §8.2, §6.3 identity_providers, §14.5 `oidc` row, ID-02 (§2.6)

**Problem.** Identity isolation is argued from 'one issuer per tenant' (different issuer and signing keys) and enforced by `UNIQUE(issuer)`, yet the plan lists Google Workspace among tenant-brought IdPs supported from MVP. Google uses one issuer (https://accounts.google.com) and one key set for all customers, so (i) a second tenant using Google cannot be registered, (ii) the 'different issuer + different keys' argument does not hold there (only audience or the `hd` claim separates organisations), and (iii) for Headscale-native OIDC (method C) the plan's own fact ID-02 says the login filters are empty by default and anyone the IdP authenticates for that client is admitted, but neither §8.2 nor the §14.5 `oidc` row requires `allowed_domains` or `allowed_groups`.

<details><summary>Evidence</summary>

L1007: 'token của tenant này vô nghĩa ở tenant khác (khác issuer + khác khóa ký)'. L1014: 'IdP do tenant mang tới (Entra ID, Google Workspace, Okta, Keycloak riêng…) | Mạnh nhất (khác tổ chức) | … Hỗ trợ ngay từ MVP'. L777: '`UNIQUE(issuer)`'. L208 (ID-02): 'Bộ lọc đăng nhập `allowed_groups/domains/users` rỗng mặc định (ai IdP xác thực cho client đó đều được nhận)'. L1720: '`oidc` | chỉ khi tenant chọn phương thức C'. `allowed_domains` occurs only in the fact tables (L175, L208), never in the design.

</details>

**Suggested fix.** Change the constraint to `UNIQUE(issuer, client_id)` and define issuer binding on the `identity_providers` row (issuer + audience), not on the issuer string. Add a column `required_claims jsonb` (for example hd = example.com, or tid) that the backend RP checks at callback. In §8.2 add: 'IdP dùng issuer chung (Google, ứng dụng Entra multi-tenant) chỉ được chấp nhận khi có luật claim domain/tenant bắt buộc'. Change the §14.5 `oidc` row to: 'chỉ cho phương thức C; `allowed_domains` hoặc `allowed_groups` là bắt buộc — render từ chối bộ lọc rỗng; PKCE bật; `email_verified_required: true`'. Extend IT-01 with a same-issuer / different-client case.

### C-14 — MEDIUM — §19 'Database migrations' rows (Phases 2-6), §20 P2-T03 / P3-T06 / P4-T05, §6.3

**Problem.** (a) `0001` (identity and RBAC, which includes `identity_providers.tenant_id` and `tenant_memberships.tenant_id`) precedes `0002` (tenants), the table it must reference. (b) `system_settings` is in no migration although Phase 4 ships `platform/settings`. (c) `0006` is 'jobs/idempotency' and Phase 2 exposes a `jobs` API, but the only job tables in §6.3 are `provisioning_jobs` / `provisioning_job_steps`, created by `0007` in Phase 3 (the queue's own tables live in a separate schema). (d) `support_access_grants` is `0015` (Phase 4), but the Phase 2 authorizer, `auth/session` (which returns active grants), `audit_events.support_grant_id` (0004) and the positive half of AC-05, which Phase 2 and M2 claim, all need it.

<details><summary>Evidence</summary>

L2082: '`0001` identity & RBAC; `0002` tenants/hosts/instances/config versions; … `0006` jobs/idempotency'. L2104: '`0007` provisioning_jobs/steps'. L2126: '`0015` support_access_grants'. L2170. L777, L780 (tenant_id columns). L799 (`system_settings`). L790, L801. L2083: API changes include '`jobs`'. L2088: 'AC-04, AC-05, AC-06, AC-07, AC-12 ở mức API'. L2428 (AC-05): 'có grant thì thao tác được và audit ghi `actor_type=support`'. L1534: session returns 'grant đang hiệu lực'. L535: authz module covers 'support grant'.

</details>

**Suggested fix.** Renumber so every reference points backwards: `0001` tenants/hosts/instances/config versions/system_settings; `0002` identity, RBAC, sessions, support_access_grants; `0003` secrets/tenant_keys; `0004` audit/security events; `0005` device cache; `0006` user-visible jobs (say explicitly that it creates `provisioning_jobs`, `provisioning_job_steps`, `idempotency_keys`); Phase 3 then starts with relay, backups, plans, policy_versions (and the approvals table from C-05). Update P2-T03, P3-T06, P4-T05 ranges. If the current numbers are kept instead, add the sentence 'FK tới bảng tạo sau được thêm ở migration sau' and narrow Phase 2 / M2 to 'AC-05 phần không có grant; phần có grant ở Phase 4' (L2088, L2451).

### C-15 — MEDIUM — §20 dependency columns vs §21.2 critical-path graph; §19 Phase 2 dependencies

**Problem.** The task tables and the graph disagree, and one prerequisite cannot be reached by following dependencies, although §20 and §25.1 tell the agent to execute strictly in dependency order. (a) P3-T06 (migrations 0007-0011: provisioning_jobs, relay, backups, plans, policy_versions) has no dependents; P3-T05 (state machine that writes `provisioning_job_steps`), P3-T08 (policy `suspension`) and P3-T11 (`backups`) do not depend on it. (b) P1-T05 (wildcard certificate) has no dependents in §20, but §21.2 draws T05 → T10; P1-T12 (real clients, which need a trusted certificate) depends only on P1-T09 and P1-T10. (c) §21.2 draws P2-T06 → P2-T07, while §20 gives P2-T07 the dependencies P2-T02, P2-T03. (d) §21.2 shows G3 → P4-T06 and G3 → P4-T10, skipping P4-T05 and P4-T09 which §20 makes prerequisites and which form the longest chain in Phase 4. (e) §19 lists a running IdP with three realms as a dependency of Phase 2, though it is produced inside the phase by P2-T05.

<details><summary>Evidence</summary>

L2265: P3-T05 depends on 'P3-T03, P3-T04, P2-T12'. L2266: P3-T06 'Migration `0007–0011`' (no task lists it as a dependency). L2268, L2271. L2225 and L2230 (P1-T10 depends on 'P1-T08') vs L2372: 'T05 --> T10[P1-T10 edge config + PoC]'. L2246 vs L2375: 'B06[P2-T06 identity] --> B07[P2-T07 authz]'. L2285 and L2289 (P4-T10 depends on 'P4-T05, P4-T09') vs L2382-2383. L2079: 'G1; IdP hoạt động (realm platform + 2 realm tenant)' vs L2244. L2204: 'đúng thứ tự phụ thuộc'.

</details>

**Suggested fix.** In §20 add P3-T06 to the dependencies of P3-T05, P3-T08 and P3-T11; set P1-T10 to 'P1-T05, P1-T08'; either add P2-T06 to P2-T07 or delete that edge from §21.2. In §21.2 add `D05[P4-T05 migrations]` and `D09[P4-T09 groups/users]` with `G3 --> D05 --> D06`, `D05 --> D09 --> D10`, plus `T09 --> T12` and `C06[P3-T06 migrations] --> C05`. Reword L2079 to 'G1; quyết định D-3 về IdP đã có (IdP do P2-T05 triển khai)'. Add to P0-T04 a docs check that every edge in §21.2 exists in the §20 dependency column.

### C-16 — MEDIUM — §5.2, §5.5, §19 acceptance rows, §20, §22.1-22.4

**Problem.** (a) IT-07 (DNS isolation) and IT-08 (routing isolation) are defined in §5.2 and never referenced again: no task, phase or AC runs them, although §5.5 requires all of IT-01…IT-13 at the 2-tenant POC and §22.1 says the isolation suite runs on every PR. (b) IT-12 is scheduled for Phase 2 but covers usage and relay APIs that arrive in Phase 6 or are unscheduled; IT-06 (policy apply) is scheduled in Phase 2 while the policy pipeline is Phase 4. (c) AC-16 carries Phase '1 (qua Caddy), 5' in §22.2 but is absent from the Phase 1 acceptance list and from M1. (d) V-04 and V-05 are assigned to gate G1 in §22.4 but are not among the six G1 conditions, and V-05 has no task. (e) AC-12 is Phase 2 in §22.2 but Phase 4 lists it 'qua UI'; AC-02 and AC-03 are Phase 1 but Phase 3 re-claims AC-01…AC-03.

<details><summary>Evidence</summary>

L654-655 are the only occurrences of IT-07 and IT-08 in the file. L694: 'Toàn bộ IT-01…IT-13'. L2411: 'IT-01…IT-13 (§5.2) … Mỗi PR + trước mỗi gate'. L2254: 'Isolation suite v1 (IT-01, 02, 03, 06, 10, 12)'. L2303-2304: IT-05, IT-13, IT-09. L659 (IT-12: 'API audit/usage/relay'). L2439 vs L2066 and L2450. L2465-2466 (V-04, V-05 → G1) vs L2070. L2435 vs L2132. L2425-2426 vs L2110.

</details>

**Suggested fix.** Add IT-07 and IT-08 to a task (for example 'P4-T12 … Kiểm chứng: record hot-reload; settings ⇒ job restart; IT-07, IT-08', with the on-device half in P5-T05) and add to §22 a table 'Isolation test → task → gate' covering all thirteen. Split IT-12 into 12a (audit, Phase 2) and 12b (usage, relay; Phase 6) and state that IT-06 in Phase 2 is adapter-level. Add 'AC-16 (qua Caddy, functional)' to L2066 and L2450. Add to G1: '(7) V-04 đạt hoặc ngoại lệ được ghi nhận; (8) V-05: relay vẫn hoạt động khi `/verify` trả 404' and put V-05 into the P1-T12 verification. Align the Phase column of AC-02, AC-03 and AC-12 with §19.

### C-17 — MEDIUM — §11.4, §13.2, §13.5 vs §19 'API changes' / 'Files' rows and §20

**Problem.** Catalogued capabilities without an implementing task, and designed jobs missing from the job catalogue. (a) Upgrade: a flow in §11.4, job kind `instance.upgrade`, permission `platform.instance:upgrade`, but Phase 3 tasks cover only provision, suspend, deprovision, key rotation, backup, reconcile and reconfigure; P6-T10 merely drills it. (b) No phase lists `GET /tenants/{t}/relay`, `/platform/relay-regions`, `/platform/plans`, `/platform/identity-providers` (P4-T03 is UI only), `/platform/audit`, `PATCH /tenants/{id}`, `:request-deletion`, tenant `settings` / `identity-provider`, `dashboard`, or the tenant `users` write endpoints (P4-T09 builds them but the Phase 4 API list omits them). (c) `internal/usage` and `internal/monitoring` (§4.2) are in no phase's file list although quota checks are used from Phase 3 step 1. (d) §13.5 lacks the policy drift job (§7.3; P4-T10 'job drift'), the instance reconcile job (§11.4; P3-T12) and the 'running without OIDC' detector (§8.2). (e) The idempotency key `instance:<id>:cfg:<config_sha>` is shared by reconfigure, restart and upgrade, but restart and upgrade do not change the config hash, so a second restart would be deduplicated.

<details><summary>Evidence</summary>

L1399 (Upgrade flow), L1603, L1071 vs L2261-2274 (no upgrade task) and L2325. L1545, L1552 vs L2083, L2105, L2127, L2171. L545, L548 vs L2080, L2102, L2124. L920: 'Drift detection: job định kỳ'; L1402: 'Reconcile (định kỳ)'; L1019: 'job phát hiện instance đang chạy không có OIDC' vs L1600-1611. L2289, L2272. L1603: '`instance:<id>:cfg:<config_sha>`'.

</details>

**Suggested fix.** Add a Phase 3 task 'Job upgrade (preflight theo RT-10, cold backup, đổi digest, health + contract smoke, rollback bằng restore)' or widen P3-T13 and rename it. Add the missing endpoints to the 'API changes' rows (relay, relay-regions read, plans → Phase 3; identity-providers, platform/audit, tenant settings/idp, dashboard, users write, PATCH tenant, request-deletion → Phase 4). Add `internal/usage` (QuotaChecker only) to the Phase 3 file list and `internal/monitoring` to Phase 4. Add rows `policy.drift_check`, `instance.reconcile` and `instance.oidc_check` to §13.5, and use distinct keys: `instance:<id>:restart:<request-key>` and `instance:<id>:upgrade:<target_digest>`.

### C-18 — MEDIUM — §7.5, X-4 (§2.9) / §7.3 / TD-07, §8.2, §3.5 vs §19 and §20

**Problem.** Four features carry phase labels that contradict the roadmap. (a) §7.5 classifies time-bound access, JIT access and Tailscale SSH check mode as 'Phase 2'; roadmap Phase 2 is 'SaaS Backend', JIT/time-bound is P7-T07, and SSH check mode is in no phase. (b) The policy evaluator / shadow instance is 'Phase 5' in X-4 and §7.3 and 'Phase 5+' in TD-07, but is absent from the Phase 5 scope and from all twelve P5 tasks. (c) Periodic IdP reconciliation is 'Phase 6' in §8.2 but P7-T06 in §20; the same §8.2 says a tenant-brought IdP is supported from MVP while the Phase 7 scope and P7-T06 list onboarding of the tenant's IdP. (d) §3.5 gives 'Backup offsite' as the MVP handling of the single-host SPOF, but offsite backup is P6-T03/P6-T04, after the MVP gate G5.

<details><summary>Evidence</summary>

L961-963: 'Time-bound access | Phase 2', 'Just-in-time access | Phase 2', 'Tailscale SSH (check mode) | Phase 2 (opt-in)' vs L2072 and L2339 ('P7-T07 | Application ZTNA extensions: JIT/time-bound'). L371: 'evaluator là Phase 5'; L921: 'là hạng mục Phase 5'; L2517: '(Phase 5+)' vs L2143 and L2299-2310. L1021: 'là hạng mục Phase 6' vs L2338. L1014: 'Hỗ trợ ngay từ MVP' vs L2187: 'tích hợp danh tính nâng cao (IdP của tenant, SCIM)'. L505: column 'Xử lý ở MVP' = 'Backup offsite + runbook dựng lại (§17)' vs L2318-2319 and L2401.

</details>

**Suggested fix.** In §7.5 rename the class to 'Post-MVP (Phase 7, P7-T07)' and either add SSH check mode to P7-T07 or mark it 'chưa lên lịch'. For the evaluator choose one: add 'P5-T13 (tùy chọn) what-if evaluator / shadow instance' or change X-4, §7.3 and TD-07 to 'Phase 7 / chưa lên lịch'. Change L1021 to 'Phase 7 (P7-T06)' and reword L2187 and P7-T06 to 'wizard tự phục vụ cho IdP của tenant + SCIM' so it no longer contradicts 'external IdP supported from MVP through the `external` driver'. Change L505 to 'Backup cục bộ đã mã hóa + runbook dựng lại; offsite ở Phase 6 (trước G6)'.

### C-19 — MEDIUM — §3.4 diagram, §4.2, §4.4, §13.6, §19 file lists

**Problem.** Package names differ between the component diagram, the module table and the dependency-rule table that the architecture lint is meant to enforce: `tenant` / `device` / `policy` (§3.4, §13.6) vs `tenants` / `devices` / `policies` (§4.2, §4.4, §19); `billing` (§13.6; 'usage / billing' in §3.4) vs `usage` (§4.2); `configuration` (§13.6) vs `config` (§4.4, absent from §4.2). §13.6 contains an import cycle (`tenant` depends on `billing`; `billing` depends on `tenant`) and contradicts §3.4 (tenant → provisioning there, provisioning → tenant in §13.6); Go rejects import cycles at compile time. `authz`, `platform`, `store`, `jobs`, `httpapi` and `usage` have no dependency rule, and no module owns memberships/users, groups or the dashboard (P4-T09 has no output package).

<details><summary>Evidence</summary>

L473-486 (e.g. 'MW --> TN[tenant]', 'MW --> DV[device]', 'MW --> PL[policy]', 'MW --> US[usage / billing]', 'TN --> PV[provisioning …]'). L536-551 (`tenants`, `devices`, `policies`, `usage`). L592-594 (adds `config`). L1619: '`identity` | `audit`, `configuration`'. L1620: '`tenant` | `identity`, `audit`, `billing` (quota)'. L1624: '`relay`, `monitoring`, `billing` | `tenant`'. L1623: '`provisioning` | `tenant`, `headscale`, `secrets`, `relay`, agent client'. L1627: 'kiểm bằng lint kiến trúc trong CI'. L2288 (P4-T09 output '—').

</details>

**Suggested fix.** Use the §4.2 names everywhere (edit the §3.4 labels and §13.6). Break both cycles by inversion: '`tenants` khai báo interface `QuotaChecker` và `LifecycleRequester`; `usage` và `provisioning` hiện thực và được nối ở `apps/*`; `tenants` không import hai module đó'. Add rows for `authz` (→ `store`), `platform`, `store` (imports no internal package), `jobs`, `httpapi` (may import every service interface; nothing imports it) and `usage`. Assign ownership: `identity` or a new `members` module for memberships, invitations and groups (add to §4.2 and as the output of P4-T09); `monitoring` for dashboard and diagnostics.

### C-20 — MEDIUM — §4.3 Backup row, §17.1, ADR-18 (§24), §14.3, §14.4, §15.2, §13.5

**Problem.** (a) §17.1 allows the SQLite backup API (`.backup`) or `VACUUM INTO`; §4.3 and ADR-18 choose `VACUUM INTO` and list `.backup` as a considered-and-rejected alternative (ST-06 gives the reason), and §25.1 rule 3 says ADR decisions are fixed. (b) The stack names `restic` for offsite copies, but no component can run it: the Agent, the only component with the tenant filesystem, has `network_mode: none`, an image without restic, and no mount of `/opt/meshguard/backups`; api and worker have no tenant filesystem. The nightly PostgreSQL dump likewise has no executor and no job kind.

<details><summary>Evidence</summary>

L1913: 'Online backup qua SQLite backup API (`.backup`) hoặc `VACUUM INTO` do Host Agent thực hiện'. L578: '`VACUUM INTO` + `age` + `restic` … | `.backup`' (alternative column). L2548 (ADR-18): 'Alternatives đã xét: `.backup`; Litestream …'. L296 (ST-06). L1683: agent image 'CLI docker/compose + `sqlite3` + `age`', mounts 'Docker socket và `/opt/meshguard/tenants`', '`network_mode: none`'. L1786: 'agent | Không (không có network)'. L1657-1659 (backups directory). L1912: 'Mã hóa trước khi rời host … + offsite'. L1604: only `instance.backup` / `instance.restore`.

</details>

**Suggested fix.** §17.1: write '`VACUUM INTO` (duy nhất; `.backup` là phương án đã loại — ADR-18)'. Add a service row to §14.4: '`backup-shipper` | restic, pin digest | mount `/opt/meshguard/backups` read-only; chỉ network egress; không Docker socket; credential kho offsite là file secret riêng'. Add `/opt/meshguard/backups/tenants` to the Agent mounts in §11.1 and §14.4. Add job kinds `postgres.backup` (name the executor, e.g. a sidecar on `mg-data` writing to `backups/postgres`) and `backup.ship` to §13.5 and reference them from P3-T11, P6-T03 and P6-T04.

### C-21 — MEDIUM — §14.4 edge row, §14.6, §14.7, §13.1, §3.5, §18.1 T-10/T-11 vs EG-11 (§2.6) and §4.3

**Problem.** Rate and connection limiting at the edge is cited as a control in six places, but the plan's own fact EG-11 says Caddy needs an unofficial plugin for rate limiting, and the edge build manifest lists only the DNS-provider module and the CrowdSec bouncer (P1-T04 verifies exactly those with `caddy list-modules`). Separately, §14.7 wants CrowdSec acquisition from access logs 'split per site' for per-tenant traceability, but the design uses a single wildcard site with a request-time upstream precisely to avoid per-tenant site blocks, so there is only one log.

<details><summary>Evidence</summary>

L285 (EG-11): 'Rate limiting ở Caddy cần plugin không chính thức'. L574, L1680, L2224: 'xcaddy: module DNS provider + CrowdSec bouncer'. L1727: 'CrowdSec handler; giới hạn kết nối'. L1746. L2014: 'giới hạn kết nối ở edge'. L2015: 'Rate/connection limit theo IP và theo hostname tenant ở edge'. L1526: 'cộng thêm giới hạn ở edge'. L511: 'Giới hạn tốc độ'. L1743: 'Acquisition từ JSON access log của Caddy, tách file theo site' vs L1727 and L1733 (one wildcard site, no reload per tenant).

</details>

**Suggested fix.** Decide and write one of: (i) add a pinned rate-limit module to the xcaddy manifest (name it; add it to §4.3, §14.4, the P1-T04 `list-modules` check, and to R-16 as a second third-party module), or (ii) state 'MVP không có HTTP rate limit ở edge: chỉ dùng giới hạn/timeout gốc của Caddy, nftables connlimit theo IP nguồn cho 443 và dải STUN, và token bucket ở API' and reword §13.1, §14.6, T-10 and T-11 accordingly. Change L1743 to 'một access log JSON cho site wildcard; tách tenant theo trường `request.host` ở parser/collector'.

### C-22 — MEDIUM — §6.1, §6.3 vs §7.2, §8.3, §13.1, §13.3, §5.5, §14.5

**Problem.** Schema columns do not carry what other sections require. (a) §6.1 makes a `version bigint` column the optimistic-lock counter for 'policy draft', but in `policy_versions` the `version` column is the policy version number with `UNIQUE(tenant_id, version)`; a draft cannot both keep its number and bump its lock. (b) `provisioning_job_steps` has no timestamps although the API `Job.steps[]` exposes `started_at` / `finished_at`, §5.5 measures step durations from this table and the Phase 3 DoD requires them; `provisioning_jobs` has no `created_at` (API `Job.created_at`). (c) Step-up needs `auth_time` ≤ 15 minutes but `sessions` stores only `acr, amr`. (d) `tagOwners` is rendered from a 'tenant tag catalogue' that has no table and no endpoint. (e) `state` + `nonce` + PKCE verifier are 'stored server-side' with no table. (f) `tenant_instances` lacks `run_gid` (and `short_id`, see C-01) used by §14.5, and its `status` values are never listed (only `running` and `removed` appear).

<details><summary>Evidence</summary>

L724: 'Cột `version bigint` tăng mỗi lần cập nhật … (tenant, policy draft, group, resource, settings)' vs L787: '`id, tenant_id, version, kind …` | `UNIQUE(tenant_id, version)`'. L790: 'steps(id, job_id, seq, name, status, attempt, detail jsonb, compensation_status)' vs L1567, L705 ('Thời gian từng step trong `provisioning_job_steps`') and L2111. L1031 vs L782. L882: 'Danh mục tag của tenant'. L1026: '`state` + `nonce` lưu phía server'. L1697: '`<run_uid>:<run_gid>`' vs L775. L775 ('WHERE status <> removed') and L1388.

</details>

**Suggested fix.** `policy_versions`: add `revision bigint` as the ETag source and keep `version` as the number. `provisioning_job_steps`: add `started_at, finished_at`; `provisioning_jobs`: add `created_at`. `sessions`: add `auth_time timestamptz`, `scope`, `csrf_hash`. Add `tenant_tags(id, tenant_id, name, owners jsonb, description, version)` with `GET/POST/DELETE /tenants/{tenantId}/tags` under `tenant.policy:edit`, or state that tags live in `policy_versions.source`. Add `auth_login_states(state_hash, nonce, pkce_verifier, idp_id, tenant_id, expires_at)` or state 'cookie mã hóa có chữ ký, TTL 10 phút'. Add `run_gid` and the enum `tenant_instances.status ∈ {allocated, starting, running, stopped, failed, removed}`.

### C-23 — LOW — §2.5 HS-17 vs §10.1 and §11.3 step 8; §5.1, §5.5, R-20 citing '§2.6'; §1 and ADR-15 vs PL-02; §6.1 and ADR-06 vs §8.8

**Problem.** (a) §10.1 states, labelled VERIFIED against hscontrol/types/config.go, that none of the listed `derp.server.*` keys has a code default, and step 8 repeats it; HS-17 in the same document calls `verify_clients: true` the default. At the pinned tag three of the listed keys do have code defaults. The design decision (write every key explicitly) is unaffected, but one of two VERIFIED statements is wrong. (b) Three places cite '§2.6' for facts that §2.6 does not contain: 'API key is full-privilege, no scope' and 'every API call costs one bcrypt' (RT-12 only says the key is stored as prefix + bcrypt hash). Both facts are true upstream; they just have no ID or label. (c) §1 and ADR-15 say a policy lacking `grants` is allow-all; HS-07 and PL-02 say lacking both `acls` and `grants`. (d) RLS is 'the third layer of defence' in §6.1 and ADR-06 but layer 4 of 5 in §8.8.

<details><summary>Evidence</summary>

L1257: 'Các khóa này không có default trong code, chỉ có trong file ví dụ. VERIFIED `[HS:hscontrol/types/config.go]`'; L1377: 'không có default trong code'; L171: '`verify_clients: true` mặc định'. Upstream juanfont/headscale@v0.29.7 hscontrol/types/config.go L459-462: viper.SetDefault('derp.server.enabled', false), viper.SetDefault('derp.server.verify_clients', true), viper.SetDefault('derp.server.automatically_add_embedded_derp_region', true); no SetDefault for region_id/code/name, stun_listen_addr, private_key_path, ipv4/ipv6, auto_update_enabled. L636 ('không có scope (§2.6)'), L695 and L2503 ('§2.6') vs L247. Upstream pointers for the missing rows: proto/headscale/v1/apikey.proto message ApiKey has only id, prefix, expiration, created_at, last_seen; hscontrol/db/api_key.go L268 bcrypt.CompareHashAndPassword, called per request from hscontrol/app.go L448 and L494. L44 and L2545 vs L161 and L188. L721 and L2536 vs L1145.

</details>

**Suggested fix.** (a) Reword L1257 and L1377: '`enabled` (false), `verify_clients` (true) và `automatically_add_embedded_derp_region` (true) có default trong code; `region_id/code/name`, `stun_listen_addr`, `private_key_path`, `ipv4/ipv6`, `auto_update_enabled` thì không — tất cả vẫn được ghi tường minh'. (b) Add two rows to §2.6 with their own IDs and labels (for example RT-15 'API key không có trường scope — `[HS:proto/headscale/v1/apikey.proto]`' and RT-16 'mỗi request xác thực bằng một lần bcrypt compare — `[HS:hscontrol/db/api_key.go]`') and cite those IDs at L636, L695, L2503 and in ADR-22. (c) Write 'policy thiếu cả `acls` lẫn `grants`' at L44 and L2545. (d) Write 'lớp 4/5 (§8.8)' at L721 and L2536.

### C-24 — LOW — §11.1 vs §14.2; Appendix A.2 item 14 vs §14.6; §14.2 vs §14.5; Quy ước; §13.4 title and §5.2 row 6

**Problem.** (a) The Agent socket is `/run/meshguard/agent.sock` in §11.1 and `/opt/meshguard/run/agent.sock` in §14.2. (b) Discovery checklist item 14 probes `https://<host>/health`, a path the edge design answers with 404 on tenant hostnames (monitoring correctly uses `/key`). (c) `config/` is 'mounted read-only, except extra-records' in §14.2 but mounted whole as `/etc/headscale:ro` in §14.5; the `secrets/` directory holding `oidc_client_secret` is missing from the §14.5 mount list although `client_secret_path` points to it. (d) Tenant hostnames are written both `<slug>.<mesh_domain>` and `<slug>.mesh.<domain>`, and `base_domain` both `<slug>.<tailnet_suffix>` and `<slug>.tail.<domain>`; the placeholders `<domain>`, `<mesh_domain>`, `<tailnet_suffix>` are never defined. (e) The tenant path parameter is written `{tenantId}`, `{t}` and `{id}`. (f) §13.4 calls the adapter 'the only boundary to Headscale' and §5.2 row 6 says policy is written 'only via Registry.ForTenant', while the baseline policy and the first API key are written by the Agent through the CLI (acknowledged in §25.1 rule 7).

<details><summary>Evidence</summary>

L1338 vs L1660. L2664: '`curl -sI https://<host>/health`' vs L1727: 'mọi path khác ⇒ `404` (gồm `/api/*`, `/swagger*`, `/verify`, `/version`, `/health`)' and L1842. L1653: '(mount read-only, trừ extra-records)' vs L1698: 'mount `config/` → `/etc/headscale:ro`, `data/` → `/var/lib/headscale`'. L978. L1706 and L1715 vs L1820-1821. L1064, L1092, L1536. L1573 and L653 vs L1381-1382 and L2568.

</details>

**Suggested fix.** (a) Write 'thư mục host `/opt/meshguard/run/`, mount tại `/run/meshguard/` trong worker và agent'. (b) Replace item 14 with '`curl -sI https://<slug>.<mesh_domain>/key` (kỳ vọng 200) và `…/health` (kỳ vọng 404)'. (c) Write '`config/` → `/etc/headscale:ro` (Agent thay `extra-records.json` trên host bằng tmp + rename trong cùng thư mục); `secrets/` → `/run/secrets/headscale:ro`'. (d) Add to 'Quy ước': '`<domain>` = domain đã đăng ký; `<mesh_domain>` = `mesh.<domain>`; `<tailnet_suffix>` = `tail.<domain>`' and use only the placeholders. (e) Use `{tenantId}` only. (f) Retitle §13.4 'ranh giới duy nhất của api/worker tới Headscale (ngoại lệ: Agent CLI cho bootstrap và DR — §11.3 bước 12–13)' and adjust L653.

### C-25 — LOW — §9.3 Mermaid sequence diagram; §3.3 and §3.4 diagrams; Appendix B; §23.2 TD-09; references to the task brief

**Problem.** (a) §9.3: the message at L1203 contains `<slug>.<mesh_domain>`. Mermaid passes message text through its HTML sanitiser, which drops unknown tags, so the label renders as 'TLS tới .:443, GET /derp + Upgrade: DERP'. This is the only rendering defect found: all ten diagrams otherwise parse (no parentheses, quotes or pipes inside flowchart labels; no semicolon or hash in sequence messages; state and ER labels valid). `TB` (subgraph id, L442) and `RL` (node id, L479) are direction keywords; they parse only because the current grammar lexes directions solely in the state entered after `flowchart`. (b) Appendix B, which P0-T01 must follow without changing technical content and whose completeness is the Phase 0 acceptance criterion, maps no target file for §11 (orchestrator), §12 (portal), §16 (monitoring), §23 (risks), §25 (build rules) or Appendix C, and §17 lands only in 'rollback-plan.md'. (c) TD-09 refers to 'V-kiểm chứng' without a number; no V-xx exists for shared STUN. (d) 'Rule XIX.14/16/18/20', 'Rule 14' and 'Yêu cầu §2.1 đề bài' point into the task brief, which is not part of the plan or of Appendix C; inside this document §2.1 is Repository 1.

<details><summary>Evidence</summary>

L1203: 'A->>E: TLS tới <slug>.<mesh_domain>:443, GET /derp + Upgrade: DERP'. L442: 'subgraph TB[Compose project: mg-t-B]'; L479: 'MW --> RL[relay]'; checked against mermaid-js flow.jison (DIR tokens exist only in the `dir` lexer state; TEXT excludes ( ) [ ] { } | and double quote). L2674-2701 (no row for §11, §12, §16, §23, §25); L2044: 'Đủ file theo Appendix B'. L2519: 'Shared STUN nếu V-kiểm chứng đạt (P5-T11)'. L3, L501, L642, L710, L834, L1637, L2531.

</details>

**Suggested fix.** (a) Write `#lt;slug#gt;.#lt;mesh_domain#gt;:443` or drop the brackets (SLUG.MESH_DOMAIN:443); rename subgraphs `TA`/`TB` to `TEN_A`/`TEN_B` and node `RL` to `RELAY`. (b) Add rows to Appendix B: `docs/architecture/orchestrator-design.md` ← §11; `docs/architecture/portal-design.md` ← §12; `docs/operations/monitoring-design.md` ← §16; `docs/operations/backup-recovery-design.md` ← §17; `docs/planning/risk-register.md` ← §23; `docs/planning/build-mode-instructions.md` ← §25; `docs/architecture/research-sources.md` ← Appendix C. (c) Add 'V-16 | Shared STUN responder trên UDP 3478 | `tailscale netcheck` với ≥ 2 tenant | G5 (tùy chọn)' and cite it in TD-09 and P5-T11. (d) Add the brief to Appendix C under a symbol such as `[REQ:<mục>]` and write the references as `[REQ:Rule XIX.14]`, `[REQ:§2.1]`.

## Upstream fact-check: Tailscale client v1.104.7, derper, Caddy 2.11.x, Docker Engine 28/29, CrowdSec, SQLite, PostgreSQL, Let's Encrypt (plan sections 2.6 DP/CL/EG/ST, 2.7, 9, 10, 14.6, 15, 17)

**Verdict:** The fact tables are mostly accurate: I checked the DP, CL, EG and ST rows against the pinned Tailscale tag, Caddy source through v2.11.9, Docker docs and moby source, sqlite.org, postgresql.org and letsencrypt.org, and found few outright errors. The problems are in the design built on those facts. Three edge/Docker mechanics do not work as written: the host-label upstream does not match any alias the template creates; an unresolvable label gives 502 plus an external DNS lookup, not a clean 404; and worker and monitoring sit only on internal networks yet are assigned public-path, DNS and STUN work. Beyond that, several claims are over-stated or left open when upstream documents the answer (IPv6 publishing, independence from Tailscale Inc., rootless Docker), and the SQLite backup execution model and the 9.5 pass criteria need tightening. No critical finding; 3 high, 9 medium, 4 low. Nothing was executed; fixes that depend on runtime behaviour are marked for the Phase 1 PoC.

**Strengths noted:**

- EG-07 is exactly right at v1.104.7: control/controlhttp/client.go dials http://host:80/ts2021 first, starts 443 after 500 ms or immediately on any non-101 (RoundTrip, no redirect following), so a fast redirect on :80 is safe.
- DP-01..DP-08 match cmd/derper and derp/derpserver: fail-open defaults to true and applies only to transport errors (non-200 is rejected), 5 s timeout, single verification in accept(), FrameClosePeer gated on mesh key, -rate-config is one per-client value, DERPNode fields and the 900-999 range.
- The 9.5 strings and knobs are real: 'pong from ... via DERP(code)' / 'via ip:port', status 'direct' / 'relay', --until-direct=false, tailscaled_*_bytes_total{path=...}, and TS_DEBUG_ALWAYS_USE_DERP replaces the UDP socket with a block-forever conn (build tag !ios).
- The /register/<auth_id> redirect cannot disturb client polling: registration and follow-up are POST /machine/register with Followup over the Noise channel (controlclient/direct.go); the client only logs and hands the AuthURL to the browser.
- EG-02 (reload closes upgraded streams; the retain option stream_detached exists only on Caddy master, absent through v2.11.9), EG-06 (Let's Encrypt limits), ST-06 (VACUUM INTO / backup API semantics, Litestream adds _litestream_lock) and ST-07 (PostgreSQL 18 is latest production; 19 is at RC2) all check out.

### UF-01 — HIGH — 14.6 row 'Public :443 - *.<mesh_domain>' and bullet 1; 14.5 row 'Project / container / alias'; 11.3 step 3; 6 tenant_instances columns

**Problem.** The label-derived upstream cannot resolve as specified, and the alias namespace is not collision-safe. 14.6 proxies to hs-<label>:8080 where the label is the tenant slug (control_hostname = <slug>.<mesh_domain>). The only alias the template creates is hs-<short_id> (14.5), which the admin and metrics listeners also use. <short_id> is never defined: it is not a tenant_instances column, has no derivation rule, and nothing says it equals the slug. As written, no public request reaches an instance. The obvious patch (add an hs-<slug> alias) puts slugs and short ids in one hs- namespace. Docker's embedded DNS returns the first match across every network the querying container is attached to, and edge is attached to all tenant networks. A slug equal to another instance's short id (an 8-hex id starting a-f satisfies the slug regex), or any duplicated alias left by restore or relocation, would make edge send one tenant's control/DERP traffic, and on the admin listener that tenant's API key, to another tenant's Headscale. Docker does not enforce alias uniqueness across networks. Separately, {labels.N} is indexed from the right, so N depends on how many labels <mesh_domain> has (a .com.vn zone shifts it by one).

<details><summary>Evidence</summary>

Plan 14.6: 'Nhan host duoc kiem bang regex slug roi ghep thanh upstream hs-<label>:8080'. Plan 14.5: 'alias hs-<short_id> tren network tenant'. Plan 11.3 step 3: 'control_hostname = <slug>.<mesh_domain>'. moby daemon/libnetwork/sandbox.go, Sandbox.ResolveName/resolveName: loops 'for _, ep := range epList' and returns on the first network where the alias resolves. Caddy docs (patterns.md): labels are '0-indexed from the right (e.g. 0=com, 1=example-one, 2=www)'.

</details>

**Suggested fix.** Add to 14.5/14.6: (1) tenant_instances.short_id = 12 lowercase base32 chars of instance_id, UNIQUE, immutable. (2) Two aliases on the tenant network with disjoint reserved prefixes: ts-<slug> (public routing; slug is UNIQUE and immutable) and hi-<short_id> (admin and metrics listeners). (3) Caddy public upstream = ts-{labels.N}.:8080, with N computed at render time from the label count of <mesh_domain>. (4) Before edge.attach the Agent inspects every network edge is on and refuses if either alias already exists; reconcile asserts uniqueness; give the compose service a unique name too, since Compose adds the service name as an alias. (5) New isolation test: create a tenant whose slug equals another instance's short_id and prove both hostnames still reach their own /key (compare Noise key fingerprints).

### UF-02 — HIGH — 14.6 last bullet ('khong phan giai duoc => 404'); EG-03 (labelled VERIFIED); 14.6 protections 'gioi han ket noi'; T-11; V-03

**Problem.** Three things about the placeholder upstream are wrong or missing. (a) A resolution failure is a dial error, which Caddy maps to 502 (504 on timeout), not 404. (b) Docker's embedded DNS does not answer NXDOMAIN for unknown names; it forwards them to the host's resolvers, and Go then walks the search list inherited from the host (Docker's default is ndots:0). So every request for a non-existent label (attacker-chosen at will), and every request for a real tenant whose container is momentarily absent (restart, upgrade, restore swap, deprovision), emits external DNS queries. If any upstream resolver or search domain answers (wildcard zone, NXDOMAIN-hijacking resolver, split-horizon LAN DNS), edge proxies /key, /ts2021, /derp and /register for that hostname to an address outside the tenant network. This is the open-proxy case Caddy itself warns about. (c) Caddy treats a placeholder upstream as one upstream: max_requests, unhealthy_request_count and max_fails/fail_duration state is keyed by the unexpanded dial string and shared by all tenants. A per-tenant connection limit therefore cannot be built from these knobs, and enabling passive health checks lets one down tenant mark the shared upstream unhealthy for everyone.

<details><summary>Evidence</summary>

Caddy v2.11.9 reverseproxy.go statusError: 'statusCode := http.StatusBadGateway'. hosts.go Upstream.Dial comment: 'a single upstream that represents numerous (perhaps arbitrary) backends can be considered down if one or enough of the arbitrary backends is down. Also be aware of open proxy vulnerabilities.' Caddy docs: placeholders make the upstream 'dynamically static ... We recommend using a dynamic upstreams module instead'. Docker docs: 'The embedded DNS server forwards external DNS lookups to the DNS servers configured on the host.' moby resolver.go: unanswered queries go to forwardExtDNS except 'If the user sets ndots > 0 explicitly and the query is in the root domain don't forward it out'.

</details>

**Suggested fix.** Replace the bullet with: (1) every upstream name in the Caddyfile is rooted (ts-{labels.N}.:8080, api.:8080) so Go never appends search domains. (2) The edge service clears inherited search domains and sets dns_opt: ['ndots:1'], so Docker answers unknown single-label names locally instead of forwarding. Both are derived from source reading and must be confirmed in the PoC. (3) handle_errors 502 503 504 { respond 404 } on the wildcard site to keep the uniform 404. (4) Never enable max_fails, fail_duration, unhealthy_request_count or max_requests on this proxy; per-tenant limits need a keyed rate-limit module (pin it in the xcaddy manifest) or container-level limits. (5) Extend V-03 with assertions: a packet capture on the host shows zero outbound DNS for 1,000 random labels and for a stopped tenant; the response is 404; p99 latency is bounded. Relabel EG-03 as VERIFIED (mechanism) / REQUIRES VALIDATION (failure path).

### UF-03 — HIGH — 14.3 network table (mg-data, mg-admin, mg-obs all 'internal'); 14.4 monitoring row ('Chi mg-obs') and agent row; 11.3 steps 4, 17, 18; 15.2; 16.1; 4.3 Backup row

**Problem.** Worker and monitoring are placed only on internal networks but are assigned work that needs external DNS, public paths and published UDP ports. Docker internal networks have no default route, drop all traffic to and from other networks, and (since the CVE-2024-29018 fix) get no external DNS forwarding when a container is attached only to internal networks. As drawn: worker (mg-data + mg-admin only) cannot run dns.ensure (resolution check, DNS-provider API), relay.assign (probe /derp/probe and the STUN port), edge.verify over the public path, or SMTP; blackbox_exporter and the STUN/DERP probe cannot reach https://<slug>.<mesh_domain>/key or published STUN ports; Alertmanager cannot deliver webhooks. Provisioning halts at step 4, 17 or 18, and the relay-probe alert fires permanently. Offsite upload is the same gap: the Agent is network_mode: none and the worker has neither the backup filesystem nor egress, so no component can run restic.

<details><summary>Evidence</summary>

Docker CLI reference, network create --internal: 'no default route is configured and firewall rules are set up to drop all traffic to or from other networks'. Engine 25.0/26.0 release notes: 'Do not forward requests to external DNS servers for a container that is only connected to an internal network.' Plan 11.3 step 18: 'edge.verify | Worker | qua duong public: GET /key tra 200'. Plan 15.2 monitoring egress: '(tuy chon) webhook canh bao'.

</details>

**Suggested fix.** Add a non-internal network mg-egress to 14.3 with members worker, a small prober service (blackbox + STUN/DERP probe), alertmanager and a backup-uploader sidecar that sees only /opt/meshguard/backups read-only. Restrict it with DOCKER-USER rules to: the host public IP on 80/443 and the STUN range, the DNS-provider API, SMTP, webhook endpoints and the offsite store. Alternatively keep worker internal and have it call the prober over mg-admin for steps 4, 17 and 18. Name the component that performs offsite upload. Add a note under TD-12: do not block tenant egress by marking mg-t-* networks internal; an internal network provides no gateway endpoint, so the published STUN port would stop working. Use DOCKER-USER egress rules instead.

### UF-04 — MEDIUM — EG-10; 2.7 row 'Embedded DERP <-> Docker publish UDP (STUN)' ('IPv6 chua ro'); 10.1 STUN row and config row (explicit ipv6 key); R-06

**Problem.** IPv6 behaviour is not unknown: Docker documents it, and it breaks both STUN and the edge. With the default userland-proxy, IPv4-only bridges and a mapping without a host IP (P:P/udp, 443:443), host IPv6 addresses are proxied to the container's IPv4 address by docker-proxy, so the container sees the bridge gateway as the source. For STUN, Headscale's listener on 0.0.0.0:P is IPv4-only; a reply to an IPv6 probe then carries an IPv4 mapped address (gateway:ephemeral), and netcheck classifies by the mapped address family. The client either adopts that private address as GlobalV4 or flips MappingVariesByDestIP to true. On edge, every IPv6 client collapses into one private source IP for True-Client-IP, CrowdSec and rate limits: either unbannable (if a private-range whitelist is in place) or one ban blocks all IPv6 users of all tenants. Any real address in derp.server.ipv6, or an AAAA record, activates this path.

<details><summary>Evidence</summary>

Docker docs, port-publishing: 'Ports on the host's IPv6 addresses will map to the container's IPv4 address if no host IP is given in a port mapping, the bridge network is IPv4-only, and --userland-proxy=true (default).' Tailscale net/netcheck addNodeLatency: 'case ipp.Addr().Is4(): ... if !rs.gotEP4.IsValid() { rs.gotEP4 = ipp; ret.GlobalV4 = ipp } else { if rs.gotEP4 != ipp { ret.MappingVariesByDestIP.Set(true) }'. Headscale derp_server.go ServeSTUN: ListenPacket(..., 'udp', d.cfg.STUNAddr).

</details>

**Suggested fix.** State in 10.1 and 15 that the MVP is IPv4-only. Publish with an explicit host IP ('0.0.0.0:P:P/udp', '0.0.0.0:443:443', '0.0.0.0:80:80') or set 'userland-proxy': false in daemon.json. Publish no AAAA records for *.mesh, app, admin or auth. Render derp.server.ipv6 as empty. Add a G1 check: docker port and ss -lnu show no [::] binds, and the STUN Info line of tailscale debug derp shows the client's public IPv4. Replace 'IPv6 chua ro' in 2.7 with 'UNSUPPORTED in MVP (source address lost via userland proxy)'. Treat dual-stack as a separate validated change, with the default gateway pinned first (see UF-07).

### UF-05 — MEDIUM — 10.1 config row (explicit derp.server.ipv4/ipv6); 15.3 Path A ('derp.server.ipv4 = IP WAN; client trong LAN can hairpin NAT hoac split DNS'); 15.3 LAN environment; Path B

**Problem.** derp.server.ipv4 is not a hint; it replaces DNS for every client. Headscale copies it into DERPNode.IPv4, and the client then dials DERP over TCP to that literal and sends STUN to it. Consequences: (a) the split-DNS half of Path A does not work. With ipv4 set to the WAN IP, LAN clients still dial the WAN IP for DERP and STUN; control works via DNS, but relay and STUN silently fail without hairpin NAT. (b) The LAN development environment must put the LAN IP there or leave it empty. (c) With a dynamic WAN IP the value goes stale, and changing it requires an instance restart (RT-04). (d) Path B must put the VPS address. The plan requires the key to be written explicitly but gives no rule for its value.

<details><summary>Evidence</summary>

Headscale v0.29.7 GenerateRegion: 'IPv4: d.cfg.IPv4, IPv6: d.cfg.IPv6'. Tailscale derphttp dialNode: 'dst := cmp.Or(dstPrimary, n.HostName)' with startDial(n.IPv4, 'tcp4'). netcheck nodeAddrPort: 'if n.IPv4 != "" { ip, _ := netip.ParseAddr(n.IPv4) ... return netip.AddrPortFrom(ip, uint16(port)), true }'. tailcfg DERPNode.IPv4: 'optionally forces an IPv4 address to use, instead of using DNS'.

</details>

**Suggested fix.** Add a rule table to 10.1 and enforce it in the config validator. LAN-only: empty or the LAN IP. Public static IP where all clients are external or the router hairpins: the public IP. Mixed internal and external clients relying on split DNS, or a dynamic IP: leave empty and accept the DNS dependency. Path B: the VPS IP. ipv6: empty for the MVP. Add a G1 test that runs tailscale debug derp <code> from one LAN client and one external client and requires both the DERP connection and the STUN response.

### UF-06 — MEDIUM — 3.2 ('Khong phu thuoc ha tang Tailscale Inc. luc chay'); HS-22; 10.1 rows 'DERP map' and 'Captive portal'; ADR-11 security implications; 15.5

**Problem.** Three statements are over-stated for official clients at v1.104.7. (1) Logs: the client stops uploading to Tailscale's log service only after it receives a map carrying Debug.DisableLogTail, and it forgets that on every process restart. Each tailscaled start uploads until the first full map, and a device that never logs in uploads indefinitely. (2) Captive portal: the client probes a DERP node only if IPv4 is set and CanPort80 is true, using http://<IPv4 literal>/generate_204 with a challenge header. Headscale's generated region never sets CanPort80, so the edge /generate_204 is not used by clients (only tailscale debug derp fetches it). Instead the client always tries http://controlplane.tailscale.com/generate_204 and http://login.tailscale.com/generate_204 when STUN does not answer quickly, which is exactly the TCP-443-only networks of 15.5 and filtered non-3478 STUN ports of 10.2. (3) DNS fallback: when system DNS fails, the client asks Tailscale's DERP servers /bootstrap-dns?q=<tenant control hostname>; the fallback map always starts from the compiled-in Tailscale map. Also, tailscale netcheck without a map fetches Tailscale's default DERP map.

<details><summary>Evidence</summary>

control/controlclient/direct.go: 'if buildfeatures.HasLogTail && debug.DisableLogTail { logtail.Disable(); envknob.SetNoLogsNoSupport() }'. Headscale mapper.go: 'Clients forget the logtail instruction when their process restarts'. net/captivedetection/endpoints.go: 'if node.IPv4 == "" || !node.CanPort80 { continue }' and appendTailscaleEndpoint for both Tailscale URLs. net/dnsfallback GetDERPMap: 'dm := getStaticDERPMap()' then merges the cached map. cmd/tailscale/cli/netcheck.go: 'No DERP map from tailscaled; using default.'

</details>

**Suggested fix.** Reword 3.2 to 'no dependency on Tailscale Inc. relays or coordination; official clients may still contact Tailscale Inc. hosts (see CL-16)'. Reword HS-22 to 'the client stops log upload after its first full map of each run'. Add row CL-16 listing the four contact points with the source pointers above. In 15.5 and the tenant privacy notice, list the hosts and recommend TS_NO_LOGS_NO_SUPPORT=true (or tailscaled --no-logs-no-support) for customers who require no telemetry. In 10.1 change the captive-portal rationale to 'used by tailscale debug derp only'. If tenant-local captive detection is wanted later, serve a derp.paths map with ipv4 and canport80: true, and answer on a catch-all http:// site with header X-Tailscale-Response 'response {http.request.header.X-Tailscale-Challenge}' plus 204; a bare 204 fails the client's challenge check.

### UF-07 — MEDIUM — EG-10 ('can ghim default gateway'); 14.3 mg-edge row; 14.6 Bind column ('moi interface public') and bullet 1; 17.6 edge upgrade; 11.4 Reconcile

**Problem.** The edge multi-network lifecycle is under-specified in three places where documented Docker behaviour matters. (a) The pinning mechanism is never named. Docker picks the default gateway by highest gw-priority; on ties it prefers non-internal, then dual-stack over single-stack endpoints, then the lexicographically first network name. Today it works only by naming luck (mg-edge sorts before mg-t-*) and breaks the moment a tenant network is created dual-stack. Published 80/443 follow the gateway endpoint, and the proposed egress block on tenant pools would then cut edge's ACME and DNS-01 traffic. (b) Networks attached with docker network connect are not part of the Compose model. Any recreate of edge (the digest bump in 17.6, an env or volume change) should start a container with only the compose-declared networks, so every tenant fails until reconcile reattaches N networks, and reconcile is only periodic. Confirm this in the PoC. (c) 'moi interface public' is 0.0.0.0 inside the container, which includes every tenant network, mg-admin and mg-obs. Tenant containers can therefore reach the app, admin and auth origins from a private source address, sidestepping an IP allow-list or CrowdSec.

<details><summary>Evidence</summary>

Docker docs: 'The default gateway is selected by Docker, and may change whenever a container's network connections change.' Engine 28.0 notes: 'If multiple endpoints have the same priority, endpoints are sorted lexicographically by their network name, and the one that sorts first is picked.' moby Endpoint.Less comment: '(gw4 and gw6) < (gw4 or gw6) < (no gw)'. Compose reference: 'priority does not affect which network is selected as the default gateway. Use the gw_priority attribute instead.' (gw_priority needs Compose 2.33.1+).

</details>

**Suggested fix.** In 14.3 and 14.4: give edge 'mg-edge: { gw_priority: 100, ipv4_address: <static> }' and record the minimums (Engine 28.0, Compose 2.33.1) in the Phase 0 pin list. Attach tenant networks with explicit --gw-priority 0 and a fixed --ip. Reconcile asserts that the container's default route points at the mg-edge gateway. Make 'edge recreate' an Agent operation: recreate, reattach all active tenant networks from the registry, verify /key per tenant, then report healthy. Add the alert edge_attached_tenant_networks != running_instances and forbid manual compose up on mg-core in the runbook. Bind the public sites to the static mg-edge address (bind <ip>) instead of all interfaces.

### UF-08 — MEDIUM — 17.1 row 'SQLite cua tung tenant'; ST-06; ADR-18; 14.4 agent row; 14.2 ownership; V-12

**Problem.** VACUUM INTO is the right primitive, but the execution model has four documented traps that the plan does not address. The model is: a sqlite3 binary in the Agent container, under a different UID, against a live WAL database owned by a per-instance run_uid in a 0700 directory. (1) WAL readers need write access to the -shm file or the directory; a read-only mount fails, and immutable=1 would run but can copy an inconsistent image. (2) Ownership: if a root process without CAP_CHOWN, or any other UID, creates -shm or -wal (a backup racing an instance stop, start or restore), Headscale can no longer open its database. (3) A second connection from another process is the precondition for the WAL-reset corruption bug in SQLite 3.7.0-3.51.2, fixed in 3.51.3. Headscale 0.29.7 bundles 3.53.2, but a distro sqlite3 in the Agent image is likely older, and the bug needs the second connection to write or checkpoint. (4) The INTO target must not exist, and an interrupted run leaves a corrupt file.

<details><summary>Evidence</summary>

sqlite.org/wal.html: 'The opening process must have write privileges for "-shm" wal-index shared memory file ..., or else write access on the directory'. SQLite os_unix.c: 'If this process is running as root, make sure that the SHM file is owned by the same user that owns the original database. Otherwise, the original owner will not be able to connect.' wal.html section 11: 'two or more database connections open on the same file, in separate threads or processes, and when those two connections attempt to write or checkpoint at the same instant ... fixed in version 3.51.3'. lang_vacuum.html: 'The file named by the INTO clause must not previously exist, or else it must be an empty file'. modernc.org/sqlite v1.52.0 changelog: 'Upgrade to SQLite 3.53.2'.

</details>

**Suggested fix.** Specify in 17.1: the backup runs in a short-lived helper container started by the Agent with --network none --user <run_uid>:<run_gid>, mounting data/ read-write and a staging directory, using a sqlite3 image pinned by digest at version 3.51.3 or later. Command: sqlite3 -readonly db.sqlite with .timeout 10000 and VACUUM INTO a fresh unique path. Never run wal_checkpoint or any write on the source. Afterwards fsync the file and directory, run PRAGMA integrity_check and foreign_key_check on the copy, then encrypt. Take the per-tenant lifecycle lock so no backup overlaps stop, start, restore or upgrade. Extend V-12: after 1,000 backups under write load the owner and mode of db, -wal and -shm are unchanged, and Headscale restarts cleanly mid-backup.

### UF-09 — MEDIUM — T-10 ('rate-limit UDP STUN bang nftables'); 14.7 last row; EG-11; 14.1 Firewall row; TD-12; 15.3 Path B

**Problem.** Three firewall statements conflict with upstream or Docker documentation. (a) Rate-limiting STUN: upstream says not to. The client retransmits STUN at about 100 ms spacing, and all devices behind one office NAT share a source address, so a per-source limit turns into intermittent UDP:false and relay fallback that looks like a NAT fault. (b) DOCKER-USER is reached only from FORWARD. Traffic from a tenant container to the host itself (bridge gateway address: sshd, any host-network exporter, anything bound to 0.0.0.0) is INPUT and never passes it, so the rule blocking tenant-pool egress does not protect the host. Packets in DOCKER-USER are also already DNATed, so published ports must be matched with conntrack original-destination, not --dport. (c) Path B: Engine 28+ drops packets addressed to container IPs from other hosts in raw PREROUTING, before DOCKER-USER, so the VPS cannot DNAT straight to container addresses.

<details><summary>Evidence</summary>

tailscale cmd/derper/README.md: 'Don't rate-limit UDP STUN packets.' Docker docs port-publishing: containers 'can access host services listening on that bridge address (including services listening on "any" host address, 0.0.0.0 or ::)'. firewall-iptables: 'When packets arrive to the DOCKER-USER chain, they have already passed through a Destination Network Address Translation (DNAT) filter' and 'These packets are dropped by a rule in the raw table's PREROUTING chain ... they never reach the DOCKER-USER chain'.

</details>

**Suggested fix.** T-10 and 14.7: replace 'rate-limit UDP STUN' with 'no rate limit on STUN (upstream guidance); rely on near-1:1 response size, per-container CPU limits and a packets-per-second alert'. 14.1: add host input-chain rules that drop NEW traffic from tenant pool CIDRs to the host itself; state that DOCKER-USER covers forwarded traffic only; give the conntrack form (-m conntrack --ctorigdstport <port> --ctdir ORIGINAL). 15.3 Path B: 'the VPS DNATs to the Docker host's tunnel address, where the ports are published; alternatively set com.docker.network.bridge.trusted_host_interfaces=<tunnel interface> on the relevant networks'.

### UF-10 — MEDIUM — 11.3 steps 3, 8, 9; 14.5 row trusted_proxies ('subnet cua network tenant'); 14.1 daemon.json row; 6 tenant_instances

**Problem.** The tenant subnet is needed before it exists. trusted_proxies is rendered in step 8 (config.render), but the network is created in step 9, and neither placement.allocate nor tenant_instances carries a subnet. With Docker auto-allocation the value is unknown at render time. default-address-pools is a single daemon-wide list, not a pool reserved for tenant networks; it also feeds every other auto-allocated network. Edge's address inside a tenant network is likewise dynamic unless --ip is passed, and that requires a user-specified subnet. Trusting the whole subnet also trusts the bridge gateway (the host) to set True-Client-IP.

<details><summary>Evidence</summary>

Plan 11.3: step 8 'render config.yaml', step 9 'tao network mg-t-<short_id>'. Plan 14.1: 'default-address-pools rieng cho network tenant'. Docker docs: 'When no --subnet option is provided, Docker automatically selects a subnet from predefined default address pools. These pools can be configured in /etc/docker/daemon.json.'

</details>

**Suggested fix.** In step 3 allocate a per-tenant subnet from a platform-owned range (for example a /28 out of 10.200.0.0/16, 4,096 per host) under UNIQUE(host_id, net_cidr), and store it in tenant_instances. Step 9 creates the network with --subnet and --gateway. Headscale gets a fixed address; edge.attach uses --ip <fixed>. Render trusted_proxies as ['<edge ip>/32']. Keep default-address-pools only to move Docker's automatic pools off the LAN ranges.

### UF-11 — MEDIUM — 9.5 rows 1, 3, 5, 6; 10.4 row 'NAT detection'; V-02; AC-15; AC-16

**Problem.** Several pass criteria will misfire as written. (1) tailscale debug derp prints JSON with Info, Warnings and Errors and exits 0. With one region it always warns; on an IPv4-only host it always reports an IPv6 connection error; and it connects with a random key and never checks admission. 'kiem tra thanh cong' is therefore undefined, and the command cannot prove verify_clients. (2) tailscale status prints 'direct' or 'relay' only for peers active in the last two minutes; idle peers print '-' or 'idle'. (3) The path metrics exclude disco packets, so tailscale ping alone moves nothing, and the first data packets of a session legitimately go via DERP before the upgrade; 'path=derp khong tang' is too strict. (4) With a single STUN node the retransmits go to the same address, so netcheck sets MappingVariesByDestIP to false even behind a symmetric NAT. The 10.4 item can be closed as 'cannot detect' rather than left for validation. (5) If tailscaled has no map, netcheck silently uses Tailscale's production map, so 'UDP: true' alone proves nothing about the tenant's STUN.

<details><summary>Evidence</summary>

ipn/localapi/debugderp.go: 'Having only a single DERP region ... is a single point of failure'; 'Error connecting to node %q @ %q over IPv6'; 'fakePrivKey := key.NewNode()'; TODO 'try to DERP auth with new public key'. cmd/tailscale/cli/status.go: prints direct/relay only inside 'if !ps.Active {...} else {...}'. ipnstate: Active means activity 'in the past two minutes'. magicsock/derp.go: '} else if !wr.isDisco { c.metrics.outboundPacketsDERPTotal.Add(1)'. netcheck probeWouldHelp/addNodeLatency: 'else if ret.MappingVariesByDestIP == "" { ret.MappingVariesByDestIP.Set(false) }'.

</details>

**Suggested fix.** Rewrite 9.5. Direct: after 10 s of real TCP traffic, status --json shows CurAddr non-empty and PeerRelay empty; ping shows via ip:port; the direct_* byte delta is far larger than the derp delta during the window. Relay: every pong shows via DERP(<code>) with --until-direct=false; CurAddr is empty; the path=derp byte delta matches the transfer. debug derp: Info contains 'Successfully established a DERP connection' and 'returned IPv4 STUN response: <client public ip:port>'; Errors is empty except the IPv6 line when IPv6 is declared out of scope; admission is proven only by IT-09 (a foreign node key is rejected). netcheck: require 'IPv4: yes, <public ip>' and Nearest DERP equal to the tenant region name; do not use MappingVariesByDestIP to classify NAT.

### UF-12 — MEDIUM — 10.3 option (c); 19 Phase 1 Go/No-Go G1 ('That bai (2) => chuyen sang phuong an (c)'); DP-04; 15.5

**Problem.** The designated fallback for the Phase 1 gate is presented as cheaper than it is. Option (c), one derper per tenant using 'own IP or a DERPPort other than 443', means on a single-IP host N derpers sharing one address, which upstream advises against. DP-04 quotes that README for the proxy rule but omits this caveat. A non-443 DERPPort also voids the 15.5 promise that TCP-443-only networks still work via relay, and manual certificate mode means a derper restart at every renewal, about every 60 days per tenant, dropping relay sessions. If G1 item (2) fails, the plan has no fallback that keeps both the single IP and port 443.

<details><summary>Evidence</summary>

tailscale cmd/derper/README.md: 'A DERP server should not share an IP address with any other DERP server.'; 'The firewall on the derper should permit TCP ports 80 and 443 and UDP port 3478.'; 'Only LetsEncrypt certs are rotated automatically. Other cert updates require a restart.' Plan 15.5: 'Mang chi cho TCP 443 van hoat dong qua relay'.

</details>

**Suggested fix.** Add the three README sentences to DP-04. In 10.3(c) state the real cost: one public IP per derper to keep 443, or accept non-443 relay and amend 15.5. Add an intermediate fallback to evaluate before (c): layer-4 SNI passthrough on the shared 443 to a per-tenant TLS-terminating listener (already listed as DP-09), with the shared-IP caveat as an explicit validation item. Change G1 to 'if (2) fails: stop, run the DP-09 PoC, then decide between passthrough and (c) with an IP budget'.

### UF-13 — LOW — EG-04; 14.4 edge row ('admin API qua Unix socket hoac tat'); 15.1 'Caddy admin API | Unix socket / tat'; 14.6 fallback

**Problem.** 'hoac tat' contradicts the plan's own fallback. With admin off, caddy reload is impossible, so the fallback 'generate config and reload with stream_close_delay' becomes a full process restart that drops every tenant's control and DERP streams at once. stream_close_delay does not survive process exit.

<details><summary>Evidence</summary>

Caddy docs, global option admin: 'If set to off ... config changes will be impossible without stopping and starting the server, since the caddy reload command uses the admin API'.

</details>

**Suggested fix.** Decide now: admin unix//run/caddy/admin.sock (mode 0600, on a tmpfs directory mounted into no other container) plus persist_config off for the read-only root filesystem. Remove 'tat' from EG-04, 14.4 and 15.1.

### UF-14 — LOW — ST-10; 2.7 row 'Rootless Docker <-> STUN: UNSUPPORTED'; 4.3 Host row; 14.1 Docker row

**Problem.** The claim is over-stated. Current Docker docs say rootless port forwarding does not propagate source IPs by default, not that it cannot. The builtin port driver propagates them since RootlessKit 3.0 when userland-proxy is disabled, and the slirp4netns port driver and pasta also propagate. It is also not UDP-specific. Rootful remains a reasonable MVP choice, but the UNSUPPORTED label closes off a real mitigation for R-15/T-14 (the root-equivalent Agent).

<details><summary>Evidence</summary>

Docker docs rootless/troubleshoot.md: 'Port forwarding with docker run -p does not propagate source IP addresses by default.' The driver table marks builtin as propagating with footnote '(*) Applicable since RootlessKit v3.0. Also requires userland-proxy to be disabled.'

</details>

**Suggested fix.** Reword ST-10 to 'rootless does not propagate source IPs by default; possible with RootlessKit 3.0+ and userland-proxy=false, or the slirp4netns or pasta port drivers. REQUIRES VALIDATION'. Change the 2.7 cell from UNSUPPORTED to REQUIRES VALIDATION. List rootless as a Phase 6 hardening candidate.

### UF-15 — LOW — 15.1 row 'edge (Caddy) | UDP 443 (HTTP/3) | Tat o MVP'

**Problem.** Not publishing UDP 443 does not disable HTTP/3. Caddy's default protocol set includes h3, so it still advertises Alt-Svc for h3 and browsers attempt QUIC against a closed port before falling back.

<details><summary>Evidence</summary>

Caddy docs, servers option protocols: 'Default: h1 h2 h3'.

</details>

**Suggested fix.** Add to the edge global options: servers { protocols h1 h2 }. Alternatively publish 443/udp deliberately. Note it in 14.6.

### UF-16 — LOW — 6.1 row 'Row-Level Security'; ST-07 ('an toan voi pooling theo transaction')

**Problem.** The policy expression fails closed only on a session that has never set the variable. I believe that after any SET LOCAL app.tenant_id on a pooled connection the custom setting reverts to an empty string, not NULL, when the transaction ends; I did not find this stated in the PostgreSQL manual, so confirm it with a three-statement psql test. If so, a later statement outside WithTenantTx on that connection (a platform-scope query, health check or job) raises 'invalid input syntax for type uuid' instead of returning zero rows. On registry tables with the OR'ed platform branch, evaluation order is not guaranteed, so platform queries can fail intermittently. The manual does confirm that referential-integrity checks and TRUNCATE are not subject to RLS, which matters for mg_app's grants.

<details><summary>Evidence</summary>

Plan 6.1: 'policy tenant_id = current_setting('app.tenant_id', true)::uuid'. PostgreSQL docs, ddl-rowsecurity: 'Referential integrity checks, such as unique or primary key constraints and foreign key references, always bypass row security' and 'Operations that apply to the whole table, such as TRUNCATE and REFERENCES, are not subject to row security.'

</details>

**Suggested fix.** Define a helper app_tenant_id() returning NULLIF(current_setting('app.tenant_id', true), '')::uuid and use it in every policy, with the same pattern for app.scope. REVOKE TRUNCATE and REFERENCES from mg_app. Add an integration test that runs a tenant transaction and then a platform-scope query on the same pooled connection.

