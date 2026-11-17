# API Contracts

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §13. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 13. Backend API Design

Đây là **API SaaS do ta thiết kế**, không phải Headscale API. Headscale API chỉ được gọi từ `internal/headscale` (adapter) ở phía server.

### 13.1 Quy ước chung

| Chủ đề | Quy ước |
|---|---|
| Contract | **OpenAPI 3.1 contract-first**: `api/openapi.yaml` là nguồn sự thật; sinh server interface (Go) và client type-safe (TypeScript). CI fail nếu code lệch spec. Mỗi operation có `operationId`, đúng một `x-permission` (§8.5–8.6; giá trị đặc biệt: `public` cho `auth/login` và `auth/callback`, `authenticated` cho `auth/session`, `auth/sessions`, `auth/logout`, `GET /tenants`, và `internal` cho route không bao giờ đi qua edge; quyền phụ `x-permission-secondary` chỉ được dùng ở đúng một operation — §8.4 bất biến 4) và `x-audit-action`. **Quy tắc path:** không segment nào trộn `{param}` với chữ — hành động là segment con (`POST /…/{id}/suspend`); spec-lint kiểm quy tắc này (router chuẩn và generator không định tuyến được dạng `{id}:action`). Trường chứa secret hiển-thị-một-lần được đánh dấu `x-secret-once: true`. **Biểu diễn máy-đọc-được của ma trận quyền** (để sinh ma trận authz từ spec + seed): ô ○ của §8.6 = `role_permissions.scope = own` (mặc định `any`) và operation khai báo `x-own-resource: true` — role có scope `own` chỉ gọi được operation mang cờ này và service kiểm chủ sở hữu; ô 2P = operation khai báo `x-dual-control: true` (mọi role có quyền đều cần người thứ hai; thao tác chỉ 2P theo điều kiện được tách thành operation riêng); ô có điều kiện = grant kèm `role_permissions.condition`, operation tự kiểm điều kiện thì khai báo `x-conditions: [<điều kiện>]` (ví dụ `restore_only` trên duyệt/từ chối `platform/approvals` — P3-T04a), không khai báo ⇒ Authorizer từ chối grant đó; cột Staff = `role_permissions` của hai role `support_operator`/`support_admin`; ô phụ thuộc thiết lập của tenant (self-enroll, 4-eyes) do service kiểm và có ca thử riêng. Spec-lint: mọi `operationId` thuộc đúng một hàng của §8.5/§8.6 và mọi hàng ánh xạ tới ít nhất một `operationId`. |
| Versioning | Major version trên URI (`/api/v1`). Trong v1 chỉ thay đổi cộng thêm; bỏ trường/endpoint phải qua `Deprecation` + `Sunset` header ≥ 1 chu kỳ phát hành. |
| Tenant context | **Luôn** là path param `{tenantId}` (UUID). Không nhận tenant từ body/header/query. `slug` chỉ dùng để định tuyến đăng nhập. |
| Xác thực | Cookie session (BFF, §8.3). API token cho tự động hóa là hạng mục Phase 7. |
| Error model | RFC 9457 `application/problem+json`: `{type, title, status, detail, instance, code, request_id, errors[]}`. Mã `code` ổn định: `unauthenticated` (401), `reauth_required` (401), `forbidden` (403), `tenant_suspended` (403), `quota_exceeded` (403), `not_found` (404, dùng cả cho ID chéo tenant), `conflict` (409), `precondition_failed` (412), `precondition_required` (428, thiếu `If-Match`), `validation_failed` (422), `rate_limited` (429), `instance_unavailable` (503, Headscale của tenant không phản hồi), `upstream_rejected` (502, Headscale hoặc IdP từ chối — kèm lý do đã lọc), `not_implemented` (501, operation đã có trong hợp đồng nhưng chưa có handler — chỉ xuất hiện trong lúc xây dựng). Không trả stack trace, không trả thông điệp thô chứa secret. |
| Pagination | Cursor: `?limit=50&cursor=<opaque>` (tối đa 200); response `{items, next_cursor}`; thứ tự ổn định `(created_at, id)`. |
| Filtering/sorting | Tham số tường minh theo từng resource (`?online=true&owner=<id>&tag=tag:server&q=`); không nhận biểu thức truy vấn tự do. |
| Idempotency | `Idempotency-Key` bắt buộc cho `POST` tạo tài nguyên/job (tenant, enrollment, apply policy, action trên instance); lưu ở `idempotency_keys` theo `(tenant, identity, operation, key)`; `request_hash` phủ cả method và path. Lặp lại cùng key + cùng `request_hash` ⇒ trả lại kết quả đã lưu; cùng key khác body ⇒ `422 idempotency_key_reuse`; request trước chưa xong ⇒ `409` + `Retry-After`. **Response chứa secret** (pre-auth key): body lưu lại đã bỏ secret; secret được giữ tạm trong SecretStore dưới khóa tenant với TTL = min(TTL của credential, 15 phút) và tham chiếu qua `secret_ref` — replay trong TTL được trả lại secret, sau TTL trả `secret_no_longer_available` để UI đề nghị thu hồi và cấp lại; sweeper hủy secret khi hết hạn; có test bảo đảm không có mẫu `hskey-` trong bảng **và trong bản `pg_dump` lấy sau khi chạy E2E** (P4-T06). |
| Concurrency | `ETag` + `If-Match` (§6.1). |
| Thao tác dài | Trả `202 Accepted` + `Location: /api/v1/tenants/{tenantId}/jobs/{jobId}` (người gọi phạm vi tenant) hoặc `/api/v1/platform/jobs/{jobId}` (người gọi phạm vi platform) — không có path job nào thiếu phạm vi; client poll job (`status`, `steps[]`, `error`, `resource`). Thao tác 2P trả `Location` của yêu cầu phê duyệt (§8.6). |
| Rate limiting | Token bucket theo identity và theo IP tại API (header `RateLimit-*`, `Retry-After`), cộng thêm giới hạn ở edge (module rate-limit — có từ P6-T07; trước đó chỉ có giới hạn tại API). Hạn mức riêng, chặt hơn cho `auth/*`, `enrollment/*`, `devices/sync`; `enrollment/web-auth/claim` giới hạn thêm theo membership. |
| Truy vết | `X-Request-Id` (sinh nếu thiếu) đi xuyên log, audit, job. |
| Độ tươi dữ liệu | Response lấy từ cache kèm `synced_at`; `?fresh=true` (giới hạn tần suất) chạy một lần sync có giới hạn thời gian rồi trả **trang 1** từ sổ thiết bị; `fresh=true` kèm `cursor` ⇒ `422` (danh sách của Headscale không phân trang). |

### 13.2 Danh mục endpoint (tiền tố `/api/v1`)

Quy ước của bảng: `{t}` là viết tắt của `{tenantId}`; trong các nhóm phạm vi tenant, path không ghi tiền tố (ví dụ `GET /devices/{deviceId}`, `PUT /settings/security`) luôn nằm dưới `/tenants/{tenantId}`; ở `/platform/tenants/{id}`, `{id}` chính là `tenantId`.

| Nhóm | Endpoint | Ghi chú |
|---|---|---|
| **auth** | `GET /auth/login` · `GET /auth/callback/{idpId}` · `POST /auth/logout` · `GET /auth/session` · `GET /auth/sessions` · `DELETE /auth/sessions/{id}` (phiên của chính mình; `{id}` = `sessions.public_id`) | §8.3 (mỗi IdP một redirect URI); `session` trả principal, memberships, grant đang hiệu lực, CSRF token |
| **tenants** (phạm vi tenant) | `GET /tenants` (các tenant mà người gọi là thành viên) · `GET /tenants/{tenantId}` · `POST /tenants/{tenantId}/request-deletion` | Thao tác vòng đời do nền tảng thực hiện nằm ở `/platform/tenants` (hàng **platform**) |
| **invitations** | `GET/POST /tenants/{t}/invitations` · `DELETE /invitations/{id}` · `POST /invitations/{id}/resend` | Cách duy nhất để thêm người chưa từng đăng nhập (§6.3 `tenant_invitations`) |
| **dashboard** | `GET /tenants/{t}/dashboard` | Số liệu từ cache + health instance; mỗi số kèm `synced_at` |
| **devices** | `GET /tenants/{t}/devices` · `GET /devices/{deviceId}` · `PATCH /devices/{deviceId}` (rename) · `PUT /devices/{deviceId}/tags` (danh sách rỗng ⇒ `422`) · `POST /devices/{deviceId}/expire` · `DELETE /devices/{deviceId}` · `POST /devices/sync` | `deviceId` là UUID của ta, ánh xạ `(tenant, headscale_node_id)`; không nhận node id thô của Headscale; `PUT …/tags` yêu cầu `If-Match` = `tags_etag` (hash tập tag đọc **trực tiếp** từ Headscale ngay trước khi ghi; lệch ⇒ `412`) |
| **users** | `GET /tenants/{t}/users` · `GET/PATCH/DELETE /users/{membershipId}` · `PUT /users/{membershipId}/role` · `DELETE /users/{membershipId}/sessions` · `POST /tenants/{t}/ownership-transfer` | `PATCH` chỉ đổi trạng thái/hồ sơ; đổi role là operation riêng (`role` cho các role dưới Admin, `admin-role` cho Tenant Admin — mỗi operation đúng một quyền, §8.6). `DELETE` = offboard: khóa membership, thu hồi mọi session Portal của identity đó, expire/xóa toàn bộ node của Headscale user tương ứng (gồm cả node đã bị gắn tag sau khi đăng ký dưới tên user đó) và expire mọi pre-auth key của họ |
| **groups** | `GET/POST /tenants/{t}/groups` · `GET/PATCH/DELETE /groups/{groupId}` · `PUT /groups/{groupId}/members` | Đổi thành viên ⇒ một lần `policy.apply` mới (trigger `group_change`) trên version đang là desired — **không** tạo version mới; group `sensitive`: trả `202` + yêu cầu phê duyệt phạm vi tenant (§7.3, §8.6) |
| **tags** | `GET/POST /tenants/{t}/tags` · `PATCH/DELETE /tags/{tagId}` | Danh mục tag (nguồn render `tagOwners`); thay đổi ⇒ `policy.apply` (trigger `tag_change`); `PUT /devices/{id}/tags`, `requested_tags` của enrollment và policy chỉ nhận tag có trong danh mục; xóa tag còn được tham chiếu ⇒ `409` |
| **enrollment** | `POST /tenants/{t}/enrollment/requests` (thiết bị của mình) · `POST /enrollment/keys` (key đặc quyền) · `GET /enrollment/requests[/{id}]` · `POST /enrollment/requests/{id}/approve` · `/reject` · `/issue` · `/revoke` · `/start` · `POST /enrollment/web-auth/claim` · `GET /enrollment/instructions` | Pre-auth key chỉ hiển thị **một lần** (`x-secret-once`); `web-auth/claim` nhận Auth ID và chỉ thành công khi người gọi có yêu cầu đang chờ trong cùng phiên (§7.4); khi tenant bật `requires_approval`, mã enrollment/pre-auth key chỉ được phát ở `/start` sau khi yêu cầu được duyệt |
| **policies** | `GET /tenants/{t}/policies` · `GET /policies/current` · `POST /policies` (draft) · `GET/PATCH /policies/{versionId}` · `POST /policies/{versionId}/validate` · `/submit` · `/approve` · `/reject` · `/apply` (202) · `/rollback` (202) · `GET /policies/{versionId}/diff?against=` | Vòng đời ở §7.3 |
| **routes** | `GET /tenants/{t}/routes` · `POST /routes/approve` · `POST /routes/revoke` | Body `{device_id, prefixes[]}` + `If-Match` bắt buộc (ETag = `routes.etag` của thiết bị: hash tập route đã duyệt); server giữ `SELECT … FOR UPDATE` trên hàng thiết bị, đọc **trực tiếp** tập đã duyệt từ Headscale (không dùng cache), ETag lệch ⇒ `412`, rồi mới tính tập mới và gọi `SetApprovedRoutes` (thay thế toàn bộ — PL-10); prefix không đang được quảng bá ⇒ `422`; exit node = `0.0.0.0/0` + `::/0`; khi `routes.four_eyes` bật, `approve` trả `202` + yêu cầu phê duyệt phạm vi tenant và chỉ gọi Headscale sau khi người thứ hai duyệt |
| **dns** | `GET /tenants/{t}/dns` · `PUT /dns/settings` (202) · `GET/POST /dns/records` · `DELETE /dns/records/{id}` | `settings` ⇒ render lại config + restart có kiểm soát; `records` ⇒ ghi `extra-records.json` (không restart) |
| **resources** | `GET/POST /tenants/{t}/resources` · `GET/PATCH/DELETE /resources/{id}` | Network Resource Catalog |
| **relay** | `GET /tenants/{t}/relay` | Relay được gán, health, số đo relay nếu có |
| **usage** | `GET /tenants/{t}/usage?metric=&from=&to=` · `GET /tenants/{t}/billing` | Không có traffic P2P (§10.6); `billing` = gói, quota, kỳ thanh toán (chỉ Tenant Owner) |
| **audit** | `GET /tenants/{t}/audit?actor=&action=&from=&to=` | Chỉ sự kiện của tenant, gồm hành động của support |
| **notifications** | `GET /tenants/{t}/notifications` · `POST /notifications/{id}/read` | Thông báo trong Portal của **chính người gọi** (đọc từ `notification_outbox` theo `recipient_membership_id`); không trả thông báo của thành viên khác; nội dung không chứa secret |
| **settings / idp** | `GET/PATCH /tenants/{t}/settings` (thiết lập thường) · `PUT /settings/security` (khóa bảo mật; step-up; yêu cầu **tắt** 4-eyes trả `202` + `Location` tới approval) · `GET /approvals[/{id}]` · `POST /approvals/{id}/approve` · `/reject` · `PUT /tenants/{t}/settings/security` · `GET/PATCH /tenants/{t}/identity-provider` | `PATCH /identity-provider` chỉ sửa `claim_mapping`, `required_claims`, `allowed_email_domains` và client secret của IdP `active`; `issuer`/`client_id` bất biến — luồng đổi IdP chưa thuộc MVP (§8.2, P7-T06) |
| **support grants** | `GET /tenants/{t}/support-grants` · `POST /support-grants/{id}/approve` · `/reject` · `/revoke` | Phía tenant |
| **approvals** (phạm vi tenant) | `GET /tenants/{t}/approvals` · `GET /approvals/{id}` · `POST /approvals/{id}/approve` · `/reject` | Dual control trong tenant (tắt 4-eyes, duyệt route khi `routes.four_eyes` bật, đổi thành viên group `sensitive`); người duyệt xem được `payload`; chỉ thực thi từ yêu cầu đã duyệt có `payload_sha256` còn khớp (§8.6). Tenant chỉ có một người giữ quyền duyệt thì phải mời thêm Admin trước — không có đường tắt |
| **diagnostics** | `GET /tenants/{t}/diagnostics/instance` · `POST /diagnostics/connectivity` | Server chỉ trả trạng thái control plane + hướng dẫn lệnh chạy trên client; không tự đo được đường P2P |
| **jobs** | `GET /tenants/{t}/jobs` · `GET /tenants/{t}/jobs/{jobId}` | Chỉ job của tenant; `steps[]` là phép chiếu an toàn cho tenant (không có `detail` thô — §13.3) |
| **platform** | `GET /platform/health` · `GET/POST /platform/tenants` (POST ⇒ 202) · `GET/PATCH/DELETE /platform/tenants/{id}` (DELETE ⇒ 202, dual control) · `POST /platform/tenants/{id}/suspend` · `/resume` · `GET /platform/instances[/{id}]` · `POST /platform/instances/{id}/restart` · `/reconfigure` · `/upgrade` · `/backup` · `/restore` · `/quarantine` · `/release` (202; restore và release cần dual control) · `GET /platform/approvals[/{id}]` · `POST /platform/approvals/{id}/approve` · `/reject` · `GET/POST/PATCH /platform/hosts` · `GET/POST/PATCH/DELETE /platform/relay-regions` · `GET /platform/jobs[/{id}]` · `POST /platform/jobs/{id}/retry` · `/cancel` · `/rollback` · `GET/PUT /platform/settings/{key}` · `GET/POST/PATCH /platform/identity-providers` (issuer bất biến) · `GET/POST/PATCH/DELETE /platform/users` (POST nhận `sub` của IdP platform + role — §8.2) · `PUT /platform/users/{id}/super-admin-role` (gán/gỡ role SA; dual control) · `GET/POST/PATCH /platform/plans` · `GET /platform/usage` · `GET /platform/audit` · `GET /platform/security-events` · `GET/POST /platform/support-grants` · `POST /platform/support-grants/{id}/approve-breakglass` · `/revoke` · `GET /platform/backups` | Chỉ phục vụ trên origin `admin.<domain>` (listener LAN-direct) |
| **internal** (không public) | `GET /internal/edge/ask?domain=` · `GET /internal/prometheus/sd` · `GET /healthz` · `GET /readyz` · `GET /metrics` | Chỉ nghe trên mạng nội bộ (`mg-obs` cho `sd` và `metrics`); edge không route các path này ra ngoài |

**Truy vết endpoint → phase/task** — mỗi nhóm endpoint của bảng trên có phase đầu tiên có mặt và task xây; spec-lint (P2-T02) yêu cầu mọi operation mang `x-task` trỏ tới một ID có trong §20 và khớp bảng này.

| Nhóm endpoint | Phase | Task |
|---|---|---|
| auth | 2 | P2-T06 |
| tenants (đọc); jobs | 2 | P2-T11; P2-T12 |
| dashboard; `platform/health` | 2 | P2-T13a |
| devices (đọc, rename, expire, delete, sync) | 2 | P2-T13 |
| users (đọc) | 2 | P2-T11 |
| audit (`tenants/{t}/audit`, `platform/audit`) | 2 | P2-T08 |
| `platform/tenants` và `platform/instances` (đọc); `platform/jobs` (đọc) | 2 | P2-T11; P2-T12 |
| `platform/tenants` (tạo, suspend, resume, xóa); `platform/instances/{id}/<action>`; `platform/hosts`; `platform/jobs/{id}/retry`, `/cancel` | 3 | P3-T05, P3-T08, P3-T09; P3-T11, P3-T13, P3-T13a; P3-T04; P3-T05 |
| `platform/approvals`; approvals (phạm vi tenant) | 3 | P3-T04a |
| invitations | 3 | P3-T05a |
| notifications (đọc); `POST /notifications/{id}/read` | 3; 4 | P3-T05b; P4-T04 |
| relay; `platform/relay-regions` (đọc) | 3 | P3-T05c |
| enrollment (gồm `instructions`) | 4 | P4-T06 |
| policies | 4 | P4-T10 (lõi áp dụng: P3-T08a) |
| `devices/{id}/tags` | 4 | P4-T10 |
| tags (danh mục tag) | 4 | P4-T15 |
| users (ghi, `role`, `admin-role`, `ownership-transfer`); groups | 4 | P4-T09 |
| routes; dns; resources | 4 | P4-T12 |
| settings / idp; `request-deletion`; `PATCH /platform/tenants/{id}`; `platform/users`; `platform/settings`; `platform/identity-providers`; `platform/plans` | 4 | P4-T03a |
| support grants (phía tenant và `platform/support-grants`) | 4 | P4-T13 |
| diagnostics | 5 | P5-T08 |
| `platform/security-events` | 6 | P6-T02a |
| usage; billing; `platform/usage` | 6 | P6-T11 |
| `platform/backups` | 6 | P6-T04 |
| Gỡ ban CrowdSec (endpoint và quyền chốt trong task) | 6 | P6-T07a |
| internal: `healthz`, `readyz`, `metrics` | 2 | P2-T01 (kiểm tra readiness bổ sung dần theo P2-T04, P2-T09) |
| internal: `prometheus/sd` | 6 | P6-T01 |
| internal: `edge/ask`; `platform/relay-regions` (ghi) | 7 | P7-T05; P7-T04 |

### 13.3 Schema tiêu biểu (rút gọn; bản đầy đủ nằm trong `api/openapi.yaml`)

Các schema dưới đây là **đầu vào chuẩn** cho P2-T02, P3-T06a, P4-T06, P4-T10 và P6-T11: tên trường, enum và chuyển trạng thái phải khớp; `api/openapi.yaml` chỉ bổ sung chi tiết (mô tả, ví dụ, phân trang), không định nghĩa lại.

```yaml
Tenant:            {id, slug, name, status, deployment_region, plan, limits, control_url, created_at, updated_at, version}
TenantCreate:      {slug, name, plan_key, deployment_region?, owner_email,
                    # identity_provider.client_secret chỉ-ghi: API mã hóa qua SecretStore trước khi enqueue (SecretStore tạo DEK của tenant nếu chưa có);
                    # job, idempotency và audit chỉ mang secret reference
                    identity_provider{driver: keycloak|external, issuer?, client_id?, client_secret?, required_claims?,
                                      allowed_email_domains?}, settings?}        # -> 202 Job; identity_provider.client_secret là trường chỉ-ghi: vào SecretStore, không bao giờ được trả lại (§8.2)
Device:            {id, name, given_name, ip_addresses[], owner{membership_id,display_name}?, tags[], register_method,
                    online, last_seen, expiry, routes{advertised[],approved[],etag}, tags_etag,
                    revocation{state: none|pending|applied|failed, kind?, requested_at?, verified_at?}, synced_at}
EnrollmentRequest: {id, method: web_auth|preauth_key|oidc, status: pending_approval|approved|rejected|issued|consumed|expired|revoked, device_label, tags[], ephemeral, credential_expires_at,
                    preauth_key?  # chỉ có trong response tạo (hoặc response của /start khi tenant bật duyệt trước), một lần
                    login_server, instructions{linux,windows,macos,ios,android}}
PolicyVersion:     {id, version, revision, kind, state, content_sha256, source: PolicySource, validation_report{errors[],warnings[],tests[]},
                    created_by, submitted_by?, approved_by?, review_mode?: peer|self, rejected_reason?, rollback_of?}   # không chứa trạng thái áp dụng
PolicySource:      {grants[{src[Principal], dst[Principal], ip[], app?, via[]?}], ssh[], auto_approvers?}
                    # Principal = tham chiếu có kiểu {type: user|group|tag|resource|autogroup|cidr, ref} — ref của user là membership_id, của tag là tag_id (§7.2, bảng tenant_tags);
                    # `groups`, `hosts` và `tagOwners` được render từ bảng groups/network_resources/tenant_tags lúc áp dụng, không nằm trong source
PolicyApplication: {id, policy_version_id, trigger, state: pending|applied|failed|unknown, applied_sha256?,
                    headscale_updated_at?, error_code?, requested_by?, created_at, finished_at?}
TenantSettings:    {enrollment{identity_mode: portal|headscale_oidc, web_auth_enabled, self_enroll, requires_approval, preauth_key_ttl_max},
                    node_expiry, policy{four_eyes, sensitive_groups[]}, routes{four_eyes},
                    dns{magic_dns, nameservers[], search_domains[], split_dns{}}, notifications{new_device, policy_applied}}
                    # các khóa bảo mật (identity_mode, web_auth_enabled, self_enroll, requires_approval, four_eyes, node_expiry) chỉ đổi được qua PUT /settings/security (quyền tenant.settings:update_security) — PATCH /settings từ chối các khóa này; identity_mode bất biến sau khi tenant có Headscale user đầu tiên (ID-08)
                    # allow-list IP văn phòng cho CrowdSec (§14.7): tenant khai báo, nhân sự nền tảng áp dụng — chưa là khóa của TenantSettings ở MVP; mô hình dữ liệu chốt ở P6-T07a
PlanLimits:        {max_devices, max_users, max_tagged_devices, max_live_enrollment_credentials, backup_interval_minutes,
                    instance{cpus, memory_mb, pids}}
                    # bộ khóa hợp lệ của subscription_plans.limits và subscriptions.overrides (override chỉ ghi đè từng khóa); bốn khóa max_* là các khóa quota nêu ở §6.3 —
                    # QuotaChecker chỉ đọc các khóa này; backup_interval_minutes (lịch backup theo plan — §17.1) và instance{…} (giới hạn container theo plan — §14.5) là đề xuất;
                    # thêm khóa phải sửa mục này và §6.3 trước; trần số tenant toàn nền tảng nằm ở system_settings
UsageMetric:       devices_registered | devices_online_peak | users_active | enrollment_keys_issued | relay_bytes_approx
                    # giá trị hợp lệ của usage_records.metric (không có traffic P2P — §10.6)
TenantInstanceStatus: allocated -> starting -> running; running <-> stopped (upgrade và restore đi qua stopped; tiến trình của thao tác nằm ở job — §13.5);
                    mọi trạng thái -> failed; failed -> starting (retry); stopped | failed -> removed; allocated -> removed (compensation bước 3 — chưa từng start);
                    mọi trạng thái chưa removed -> quarantined; quarantined -> starting -> running chỉ sau /release có 2P (§11.4)
                    # allocated: bước 3; starting: bước 10–18; running: bước 19 (§11.3); removed: sau deprovision hoặc khi instance bị thay thế (§11.4)
EnrollmentStatus:  # enum của enrollment_requests.status: tập giá trị ở §6.3, thứ tự chuyển trạng thái theo từng phương thức ở §7.4 — nguồn duy nhất, không lặp lại ở đây
Job:               {id, kind, tenant_id?, status, current_step, resource{type,id}?, steps[{name,status,attempt,started_at,finished_at,message}], error?, created_at}
                    # steps[].detail thô chỉ có ở GET /platform/jobs/{id}; phía tenant chỉ nhận message đã lọc; resource = tài nguyên job tạo ra
                    # phía tenant (GET /tenants/{t}/jobs…): message chỉ sinh từ danh mục mẫu thông điệp theo mã (tham số, nếu có, chỉ là dữ liệu của chính tenant) — không chép
                    # chuỗi lỗi thô của orchestrator/Agent; error chỉ gồm mã lỗi ổn định {code}; không đường dẫn host, tên container, địa chỉ nội bộ hay định danh của tenant khác;
                    # error thô chỉ trả ở GET /platform/jobs/{id}
AuditEvent:        {id, occurred_at, actor{type,identity_id?,display_name?,support_grant_id?}, action, resource{type,id},
                    outcome, request_id, operation_id?, details}
Problem:           {type, title, status, detail, instance, code, request_id, errors[{field,code,message}]}
```

### 13.4 Headscale Adapter (ranh giới duy nhất tới Headscale)

```go
// internal/headscale — interface ổn định; implementation gắn với một dải version Headscale.
type Registry interface {
    ForTenant(ctx context.Context, tenantID uuid.UUID) (Instance, error) // cách DUY NHẤT lấy Instance
}
type Instance interface {
    Health(ctx) (Health, error); Version(ctx) (string, error)
    ListUsers(ctx, UserFilter) ([]User, error); CreateUser(ctx, CreateUser) (User, error)
    RenameUser(ctx, id uint64, name string) (User, error); DeleteUser(ctx, id uint64) error
    ListNodes(ctx, user string) ([]Node, error); GetNode(ctx, id uint64) (Node, error)
    RenameNode(ctx, id uint64, name string) (Node, error); SetTags(ctx, id uint64, tags []string) (Node, error)
    SetApprovedRoutes(ctx, id uint64, routes []netip.Prefix) (Node, error)
    ExpireNode(ctx, id uint64, at *time.Time) (Node, error); DeleteNode(ctx, id uint64) error
    CreatePreAuthKey(ctx, PreAuthKeyOpts) (PreAuthKey, error); ListPreAuthKeys(ctx) ([]PreAuthKey, error)
    ExpirePreAuthKey(ctx, id uint64) error; DeletePreAuthKey(ctx, id uint64) error
    AuthRegister(ctx, user, authID string) (Node, error); AuthApprove(ctx, authID string) error; AuthReject(ctx, authID string) error
    GetPolicy(ctx) (Policy, error); CheckPolicy(ctx, hujson string) error; SetPolicy(ctx, hujson string) (Policy, error)
    CreateAPIKey(ctx, expires time.Time) (string, error); ListAPIKeys(ctx) ([]APIKey, error); ExpireAPIKey(ctx, prefix string) error
}
```

Phạm vi: adapter là ranh giới duy nhất của **api/worker** tới Headscale. Ngoại lệ có chủ đích là CLI trong container do Host Agent chạy qua Unix socket cục bộ: `policy.bootstrap` và `apikey.bootstrap` (§11.3 bước 12–13), đặt policy trước khi start và `PostRestoreReconcile` khi restore (§17.2), lệnh khôi phục trong DR runbook (§6.5); ở Phase 1–2, trước khi có Agent, các lệnh này chạy bằng `docker exec` theo runbook đã duyệt (§25.1 quy tắc 7).

Quy tắc bắt buộc: (1) không hàm nào nhận URL/địa chỉ instance từ input request; (2) `ForTenant` nạp `tenant_instances` + secret, cache ngắn hạn, có circuit breaker và timeout theo instance; (3) ba lớp retry: **safe** (`GET`) — retry tự động; **ghi idempotent** (`SetPolicy` — thay thế toàn bộ, `ExpireNode` với thời điểm tường minh, `SetApprovedRoutes`, `SetTags`, `ExpirePreAuthKey`, `DeleteNode` — lần lặp trả `not_found` coi như đã xong) — retry có backoff; **không idempotent** (`CreateUser`, `CreatePreAuthKey`, `CreateAPIKey`, `AuthRegister`) — không retry, đối soát bằng đọc lại; (4) mỗi phiên bản Headscale được hỗ trợ có bộ **contract test** chạy với container Headscale thật (pin digest); (5) lỗi từ Headscale được ánh xạ sang `Problem.code`, thông điệp gốc chỉ ghi vào log nội bộ.

Hành vi upstream phải được mã hóa trong adapter và ghim bằng contract test (P2-T10):

| Chủ đề | Quy tắc của adapter |
|---|---|
| Tham số | `ExpireNode`, `RegisterNode`, `DeletePreAuthKey` gửi tham số ở **query string** (`ExpireNode` với `expiry` trong body bị bỏ qua và node hết hạn ngay — V-06); `AuthRegister` nhận **JSON body** `{user, authId}`, không nhận query (V-06, P2-T10); `CreatePreAuthKey`/`CreateAPIKey` luôn gửi `expiration` tường minh (bỏ trống ⇒ key được lưu với hạn bằng 0 và bị coi là đã hết hạn); `SetApprovedRoutes` thay thế toàn bộ tập route; `RenameUser`/`RenameNode` mang tên mới trong **path** (`…/rename/{new_name}`) ⇒ kiểm định dạng cục bộ (nhãn DNS cho node, quy tắc ID-08 cho user) và luôn `url.PathEscape` — không bao giờ ghép chuỗi thô vào URL |
| User | `CreateUser` chỉ gửi `name = mg-<membership_uuid>` và `display_name`; **không gửi email** (token `user@` trong policy khớp theo cả email ⇒ trùng email có thể làm policy thành không hợp lệ lúc khởi động); tên được kiểm ở phía nền tảng vì REST không áp quy tắc đặt tên; `DeleteUser` thất bại khi user còn node (phải expire/xóa node trước) và xóa luôn pre-auth key của user đó; user tạo qua OIDC không đổi tên được ⇒ adapter trả lỗi có kiểu, không retry. **Không dùng `headscale_user_id` đã cache cho thao tác ghi:** phân giải lại `ListUsers(name = mg-<membership_uuid>)` ngay trước mọi lời gọi ghi dùng ID số của user (ví dụ `CreatePreAuthKey`), lệch thì cập nhật cache — ID số có thể đổi chủ sau restore (§17.2) |
| Phân loại lỗi | REST gateway trả HTTP 500 cho phần lớn lỗi nghiệp vụ ⇒ phân loại theo body `{code, message}` + mẫu thông điệp theo từng operation (ví dụ lỗi `SetPolicy` ⇒ `upstream_rejected`; Auth ID không có trong cache ⇒ `validation_failed`; không tìm thấy ⇒ `not_found`; vi phạm unique ⇒ `conflict`); circuit breaker chỉ đếm lỗi truyền tải, timeout và 503/504 |
| Kiểm tra trước | Kiểm định dạng cục bộ trước khi gọi: Auth ID (`^hskey-authreq-[A-Za-z0-9_-]{24}$`), tên user, định dạng tag; luôn `CheckPolicy` trước `SetPolicy`; khi `SetPolicy` lỗi ⇒ đọc lại và khẳng định lại version đang áp dụng; `GetPolicy` "không có policy" ⇒ `ErrNoPolicy`, job drift coi là sự cố nghiêm trọng (instance đang allow-all) và xử lý như Post-start gate ở §11.4 (cảnh báo Critical, gỡ edge); API key còn hạn theo registry mà bị instance từ chối (sau khi nạp lại secret và thử lại một lần) ⇒ nghi DB của instance đã bị thay, vì DB mới không chứa key của nền tảng (ASSUMED — suy ra từ RT-12): cảnh báo Critical và **không** tự chạy lại `apikey.bootstrap` (kể cả trong luồng xoay key ở §11.4); việc gỡ edge tự động chỉ áp dụng ở Post-start gate, ngoài ra người vận hành xác minh rồi restore (§17.2) |
| Version | Headscale chỉ phục vụ phiên bản ở `GET /version` (ngoài `/api/v1`) ⇒ listener admin của edge cho phép **đúng** path này (khớp chính xác, cùng token nội bộ; phía public vẫn 404); luồng upgrade khẳng định version báo về bằng version mong đợi trước khi chạy contract smoke |
| Kẹp hạn node | Sau mỗi lần đăng ký và ở mỗi `inventory.sync`: node thuộc user có `expiry` rỗng hoặc vượt `registered_at + node_expiry` của tenant ⇒ gọi `ExpireNode` với hạn đúng và ghi `security_event(kind=expiry_overridden)` (HS-19). Kẹp hạn **chỉ rút ngắn**: đọc lại node ngay trước khi ghi, không kéo dài hạn, không chạm node đã hết hạn, không áp dụng cho thiết bị đang thu hồi (`pending`) hay đã thu hồi; snapshot cũ hơn lần chốt (settle) của một thu hồi không ghi đè `expiry` đã xác minh và không sinh lệnh kẹp; thu hồi bắt đầu trong lúc lệnh kẹp đang gửi ⇒ áp lại hạn của thu hồi (T-17) |
| Đọc node | VERIFIED trên 0.29.7 (V-28, P2-T10): `GetNode` trả `subnet_routes = []` và `user = null` với tagged node, trong khi `ListNodes` có route primary/exit và `user = "tagged-devices"` ⇒ mọi cập nhật sổ thiết bị đi qua **một** hàm chuẩn hóa lấy route và owner từ `ListNodes`; read-back bằng `GetNode` chỉ để xác minh trường vừa ghi, không bao giờ ghi đè `subnet_routes`/`owner_membership_id` |
| Tag rỗng | Gỡ hết tag không đưa tagged node trở lại personal (phải re-auth — HS-10) và `SetTags` từ chối danh sách rỗng (400, code 3 — VERIFIED, V-28/P2-T10) ⇒ `PUT /devices/{id}/tags` với `[]` trả `422 validation_failed` tại nền tảng, không gọi Headscale |

### 13.5 Background job interface

| Job kind | Kích hoạt | Khóa chống trùng (`dedupe_key`, chỉ áp dụng khi job đang chờ/đang chạy) | Ghi chú |
|---|---|---|---|
| `tenant.provision` / `tenant.suspend` / `tenant.resume` / `tenant.deprovision` | API | `tenant:<id>:lifecycle` | State machine §11; một lifecycle job tại một thời điểm cho mỗi tenant |
| `instance.reconfigure` / `instance.restart` / `instance.upgrade` | API / lịch | `instance:<id>:<kind>` | Có health gate + rollback; hai yêu cầu restart nối tiếp tạo hai lần restart |
| `instance.quarantine` / `instance.release` | API | `instance:<id>:quarantine` | §11.4; `release` chỉ chạy sau phê duyệt 2P |
| `instance.backup` | Lịch | `instance:<id>:backup:<slot>` | §17.1 |
| `instance.restore` | API (sau phê duyệt 2P) | `instance:<id>:restore` | §17.2; khóa không chứa `<slot>` của backup; chờ job backup đang chạy của cùng instance kết thúc rồi mới bắt đầu |
| `apikey.rotate` | Lịch (trước hạn ≥ 14 ngày) | `instance:<id>:apikey:<period>` | Tạo key mới → kiểm tra → expire key cũ |
| `backup.purge` (từ P6-T04) | Lịch (tenant đã xóa, hết retention) | `instance:<id>:purge` | Bản offsite của tenant đã xóa được xóa bằng lifecycle rule của kho (ưu tiên) hoặc do người vận hành xóa bằng credential riêng giữ **ngoài host** — `backup-shipper` chỉ có quyền append; job này **xác minh** bằng cách liệt kê kho (credential chỉ liệt kê): không còn object/snapshot nào của `instance_id`, rồi cập nhật `backups`, ghi audit, và cảnh báo nếu quá hạn mà dữ liệu vẫn còn |
| `inventory.sync` | Lịch (jitter) / sau thao tác ghi | `instance:<id>:sync:<slot>` | Upsert `device_inventory_cache` |
| `device.revoke` | API / offboard / restore | `device:<id>:revoke` | `ExpireNode`/`DeleteNode` + read-back; instance không phản hồi ⇒ giữ `revocation_state=pending` và retry có backoff, hết lượt ⇒ `failed` + cảnh báo; cập nhật `revocation_*` |
| `policy.apply` | API / thay đổi group-resource-tag / suspend-resume / restore / drift | `tenant:<id>:policy.apply` | **Level-triggered**: tham số chỉ có `tenant_id`; handler đọc trạng thái mong muốn lúc chạy, ghi một hàng `policy_applications` cho mỗi lần chạy (§7.3) |
| `policy.drift_check` | Lịch | `tenant:<id>:policy.drift:<slot>` | So sha256 của `GetPolicy` với `applied_sha256` mới nhất; lệch ⇒ `security_event` + cảnh báo và enqueue `policy.apply` (trigger `drift_repair`) để áp lại trạng thái mong muốn; `ErrNoPolicy` ⇒ Critical (§7.3, §13.4; P4-T10) |
| `instance.reconcile` | Lịch (mỗi 10 phút, lệch theo hash của `instance_id`) | `instance:<id>:reconcile:<slot>` | So trạng thái mong muốn với thực tế qua Agent (`GetInstanceStatus`) và Headscale (`ListAPIKeys`); chỉ báo cáo drift — báo cáo là output của job, drift an ninh ⇒ `security_events`; restart container đã thoát là bước sau (§11.4; P3-T12) |
| `host.reconcile` | Lịch (mỗi 10 phút) | `host.reconcile:<slot>` | Đối chiếu inventory của host (`ListInstances` của Agent) với registry: tài nguyên mang label MeshGuard không có hàng registry (và ngược lại), alias `hs-<slug>` trùng trên các network của edge; chỉ báo cáo (§11.4; P3-T12) |
| `instance.oidc_check` | Lịch (chỉ tenant dùng phương thức C) | `instance:<id>:oidc:<slot>` | Phát hiện instance đang chạy không có OIDC ⇒ cảnh báo + `instance.restart` có kiểm soát (§8.2). **Không xây ở MVP**: đi cùng phương thức C (TD-14; kiểm chứng tùy chọn ở P5-T10) |
| `partition.maintain` | Lịch (hằng ngày, DSN riêng) | theo ngày | Tạo partition 3 tháng tới; export + drop partition quá hạn |
| `notification.send` | Outbox | theo hàng outbox | Email / in-portal; retry có backoff |
| `idp.audit_sync` (P3-T15) | Lịch | `idp:<id>:audit:<slot>` | Chỉ với IdP do nền tảng host: đọc admin event của realm bằng service account của chính realm đó và ghi vào `audit_events` của tenant (§8.2) |
| `enrollment.reconcile` | Lịch | `tenant:<id>:enroll:<slot>` | Đối chiếu key đã dùng/hết hạn; chuyển request quá hạn (chờ duyệt hoặc chờ `issue` 24 giờ; mã 10 phút) sang `expired` |
| `usage.collect` | Lịch (hằng ngày) | `tenant:<id>:usage:<date>` | Ghi `usage_records` |
| `health.probe` | Lịch | `instance:<id>:health:<slot>` | Cập nhật `tenant_instances.last_health` |
| `job.reaper` | Lịch (mỗi phút) | theo slot | Job `running` đã quá `timeout_at`, hoặc job mà queue đã loại bỏ ⇒ job nhóm lifecycle: `failed_resumable` (vẫn giữ khóa chạy tới khi `/retry` hoặc `/rollback`), job khác: `failed`; phát cảnh báo |
| `grant.expire` / `session.gc` / `retention.sweep` | Lịch | theo slot | Dọn dẹp theo giá trị retention ở §6.4 |

Bốn khái niệm tách biệt: (a) **chống lặp request của API** — `request_key` = `Idempotency-Key` của client, `UNIQUE (requested_by, kind, request_key)`; (b) **chống trùng job đang chạy** — `dedupe_key` (có chứa kind) chỉ unique trong các trạng thái chưa kết thúc `queued/running/compensating/failed_resumable`, nên job đã kết thúc không bao giờ chặn job mới cùng nội dung (ví dụ resume áp lại đúng policy cũ, restart lần hai); không dựa vào cơ chế unique mặc định của thư viện queue cho mục đích này; (c) **job hội tụ** (`policy.apply`, `inventory.sync`, reconcile) là level-triggered, chỉ mang ID và đọc trạng thái mong muốn khi chạy; (d) **loại trừ khi chạy** — job nhóm lifecycle (`tenant.*`, `instance.reconfigure`/`restart`/`upgrade`/`restore`) mang thêm `lock_key = tenant:<id>:lifecycle`; partial unique index trên `lock_key` ở các trạng thái `running/compensating/failed_resumable` bảo đảm mỗi tenant chỉ có **một** job nhóm này đang chạy. Handler chiếm khóa bằng chính lệnh chuyển `queued → running` trong một transaction ngắn; đụng unique thì job tự hoãn (snooze) rồi thử lại — không advisory lock, không giữ transaction qua lời gọi Agent/Headscale. `instance.backup` cũng mang `lock_key` này (không backup khi instance đang bị dừng hoặc đang đổi dữ liệu) nhưng khi lỗi thì kết thúc ở `failed` và nhả khóa ngay. Job lifecycle ở `failed_resumable` vẫn giữ khóa tới khi `/retry` xong hoặc `/rollback` (trong lúc đó backup theo lịch của tenant cũng chờ — cảnh báo quá hạn backup ở §16.3 buộc người vận hành xử lý).

Job được enqueue **trong cùng transaction** với thay đổi nghiệp vụ; handler phải idempotent; retry với exponential backoff + jitter; có `timeout_at`; job thất bại hết lượt chuyển `failed` (job nhóm lifecycle: `failed_resumable` — §11.3) và sinh cảnh báo. Hai việc định kỳ **không** phải job của worker: dump PostgreSQL (service `pg-backup`) và đẩy archive ra kho offsite (service `backup-shipper`) là hai service có lịch riêng (§14.4), vì worker không có công cụ dump lẫn mount thư mục backup; tuổi bản backup gần nhất được giám sát và cảnh báo theo §16.3.

**Giãn tải khi khởi động lại (reboot host, restart worker):** trong thao tác hàng loạt do Agent điều khiển (upgrade theo đợt, reconfigure hàng loạt, khôi phục sau sự cố) Agent start tối đa K instance đồng thời (K cấu hình được); khi host boot, Docker tự start container theo restart policy — hành vi này được đo ở P1-T21. Sau khi worker khởi động, job định kỳ chạy theo `RunOnStart` được trễ ngẫu nhiên 0–10 phút, và job theo instance (`instance.backup`, `inventory.sync`, `health.probe`) được rải theo hash của `instance_id` trong chu kỳ của chúng — tránh việc mọi instance vừa lên cùng nhận backup, sync và probe một lúc (mỗi lời gọi API tốn một lần bcrypt — RT-15).

### 13.6 Phụ thuộc giữa module

| Module | Phụ thuộc vào | Không được phụ thuộc |
|---|---|---|
| `identity` | `audit`, `config`, `idp` (chỉ interface) | `headscale`, `provisioning` |
| `tenants` | `identity`, `audit`, `jobs` (enqueue job vòng đời; handler thuộc `provisioning`, đăng ký ở `apps/worker`); **khai báo** interface `QuotaChecker` ở phía mình — `usage` hiện thực, nối ở `apps/*` | `usage`, `provisioning`, `headscale`, `members`, driver hạ tầng |
| `members` | `tenants`, `identity`, `headscale`, `idp`, `audit`, `notifications` | `policies`, `devices`, `provisioning` (đổi thành viên group ⇒ enqueue `policy.apply` qua `jobs`; khi offboard gọi thẳng adapter để expire node và pre-auth key) |
| `headscale` (adapter) | `tenants` (registry), `secrets` | HTTP handler, DB nghiệp vụ khác |
| `devices`, `policies`, `network`, `enrollment` | `headscale`, `tenants`, `audit`, `usage` (quota — P3-T06a) | lẫn nhau qua DB (chỉ gọi qua service interface) |
| `provisioning` | `tenants`, `headscale`, `secrets`, `relay`, `idp`, `platform` (placement — bước 3), `policies` (baseline — bước 15), agent client | HTTP handler |
| `relay`, `monitoring`, `usage` | `tenants` | `policies`, `devices` (chỉ đọc qua interface) |
| `notifications` | `audit`, `store`, `jobs` (enqueue `notification.send` trong transaction của sự kiện — P3-T05b) | module nghiệp vụ (chỉ nhận sự kiện qua outbox) |
| `audit` | — | mọi module nghiệp vụ |
| `httpapi` | Service interface của mọi module nghiệp vụ; `authz`, `identity` | `headscale` trực tiếp; truy vấn DB trực tiếp |
| `authz` | — (chỉ module nền; `approvals` của P3-T04a dùng `audit`) | `headscale`, `provisioning`, module nghiệp vụ |
| `platform` | `tenants` (registry), `relay` | `headscale` trực tiếp, module nghiệp vụ của tenant |
| `idp` | `secrets` | module nghiệp vụ |
| `secrets` | — (chỉ module nền) | mọi module nghiệp vụ |
| `jobs` | — (handler do từng module tự đăng ký) | import module nghiệp vụ |
| `config` | `store` (chỉ để đọc/ghi `system_settings`) | mọi module khác |
| `store` | — | mọi module khác |

Tên module theo đúng §4.2. Đồ thị phụ thuộc **không được có chu trình** (Go từ chối import cycle): khi module A cần gọi module B mà B đã phụ thuộc A, A khai báo interface ở phía mình và hiện thực được nối ở `apps/*` — đã áp dụng cho `tenants` ↔ `usage`; `tenants` không import `provisioning` mà chỉ enqueue job. Bảng phủ mọi module của §4.2. Module nền (`store`, `config`, `audit`, `jobs`, `notifications`) được mọi module khác dùng mà không cần liệt kê ở cột giữa. Hàng của các module hạ tầng (`httpapi`, `authz`, `platform`, `idp`, `secrets`, `jobs`, `config`, `store`) là quy tắc khởi đầu: P2-T01 rà lại rồi chuyển nguyên bảng thành cấu hình lint — muốn đổi quy tắc phải sửa bảng này trước. Quy tắc phụ thuộc được kiểm bằng lint kiến trúc trong CI. Lint kiến trúc còn kiểm ADR-05 (P3-T01): ngoài `apps/agent` và compose driver `internal/provisioning/driver/compose` (chỉ `apps/agent` được import), không mã nào của `apps/` và `internal/` được import thư viện Docker client hay nhắc tới `docker.sock` — api và worker không bao giờ link Docker client.
