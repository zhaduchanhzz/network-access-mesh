# G2 — rà soát bảo mật nội bộ (authn/authz)

> **File viết tay — không sinh từ master.** Bằng chứng phụ của gate G2 (§19 Phase 2: "rà soát bảo mật nội bộ cho authn/authz không còn lỗi mức Cao"). Quy ước: [README](README.md). File này ghi từng vòng rà soát và trạng thái sửa của từng phát hiện. Người rà soát G2 (con người) **chưa chỉ định** — vòng 1 dưới đây là vòng tự rà của agent, không thay thế người rà soát.

## Vòng 1 — tự rà trước G2 (2026-11-17)

| Mục | Giá trị |
|---|---|
| Phạm vi | Commit `2d3797a` (= `main` lúc rà). Chỉ đọc code, không chạy. 7 vùng: authn/session (`internal/identity`, `internal/idp`), authz (`internal/authz`, `internal/httpapi/**`, `authzhook`, `x-permission`), data layer (`internal/store`, migration, role/grant), secrets (`internal/secrets`, keyring, `kek-drill`), adapter Headscale + locator, audit/logging, lệnh admin của `apps/api` |
| Người thực hiện | Agent rà soát (Claude Opus 5.5), giao bởi người điều phối |
| Môi trường | Không môi trường chạy — đọc mã nguồn |
| Loại trừ | Race `inventory.sync` sau `SettleDeviceRevocation` (đang sửa riêng — "Sửa sau" của [P2-T13](P2-T13.md)); phần nối api/worker (P2-T16, đang làm — xem "Điểm dễ nối sai") |
| Nhãn | **VERIFIED** = đã lần theo đường code từ đầu đến cuối. **PLAUSIBLE** = cần chạy để khẳng định |

### Kết luận vòng 1

**Không thấy lỗi mức Critical/High** ở cả 7 vùng. Có 3 lỗi Medium và 1 lỗi Low. Không lỗi nào chặn G2 theo tiêu chí §19, nhưng cả 4 lỗi được lên lịch sửa trước khi nộp báo cáo G2. **Cập nhật 2026-11-17:** cả 4 lỗi đã sửa ở commit `f20f9ef` — xem [Sửa sau vòng 1](#sửa-sau-vòng-1).

### Phát hiện

| ID | Mức | Vị trí | Lỗi | Kịch bản thất bại | Hướng sửa | Nhãn | Trạng thái |
|---|---|---|---|---|---|---|---|
| F1 | Medium | `internal/identity/login.go:70-137`, `middleware.go:90-91`, `callback.go:244-248` | Login CSRF: `GET /auth/login` không kiểm Fetch-Metadata. Callback thu hồi session hiện tại ngay cả khi identity mới khác identity cũ | Tenant Owner xấu (cùng actor T-20) có IdP `external` tự cấp code cho `sub` của mình. Một trang ngoài điều hướng nạn nhân tới `/api/v1/auth/login?scope=tenant&tenant=<evil>`: session thật của nạn nhân bị thu hồi, nạn nhân âm thầm thành session của tenant kẻ tấn công. Từ Phase 4, thiết bị nạn nhân enroll sẽ vào tailnet có policy do kẻ tấn công kiểm soát | Từ chối `authLogin` khi `Sec-Fetch-Site` ∉ {`same-origin`, `none`}. Không thu hồi session của một identity khác mà không có bước xác nhận | Đường code VERIFIED; khai thác PLAUSIBLE (cần một IdP `external` đã đăng ký) | Đã sửa (commit `f20f9ef`) — `TestLoginStartFetchMetadata`: 6 dạng `Sec-Fetch-Site` lạ ⇒ 403, 0 hàng `auth_requests`; `TestCallbackKeepsSessionOfAnotherIdentity`: identity khác trên session đang mở ⇒ 403, session cũ giữ nguyên |
| F2 | Medium (nặng hơn mức P2-T08 §4 ghi nhận) | `internal/identity/middleware.go:90-97`, `login.go:58-61`, `callback.go:52-56`, `auditapi/identity.go:30-37`, `httpapi/ratelimit.go:47-50` | Request ẩn danh bị từ chối vẫn ghi hàng append-only vào `audit_events` (`RecordDetached`). Rate limit theo IP không đủ chặn | `POST` với `Origin` lạ ở hạn mức mặc định (50/s, burst 300 mỗi IP hoặc /64) cho khoảng 4,3 triệu hàng/ngày/IP, không xóa được trước khi hết retention (≥ 400 ngày). Nhiều IP hoặc dải IPv6 làm đầy đĩa PostgreSQL dùng chung (T-11). `auditapi` đã bỏ 401 ẩn danh vì đúng lý do này, nhưng module identity thì không | Từ chối trước khi có identity: gộp theo (IP/64, lý do, cửa sổ thời gian) thành một hàng kèm bộ đếm, hoặc chuyển sang metric + `security_events` có dedupe. Giữ audit từng hàng khi đã có identity | Đường code VERIFIED; độ lớn PLAUSIBLE | Đã sửa (commit `f20f9ef`) — `TestAnonymousRejectionsAreBounded`: 5 loại × 1 000 request ẩn danh bị từ chối ⇒ ≤ 4 hàng mỗi loại (đếm chạy tới 1 000); có identity vẫn 1 hàng/denial |
| F3 | Medium | `internal/identity/config.go:37-42`, `callback.go:153-161`, `database/migrations/0002_identity_rbac.sql:65`, `internal/idp/external/external.go:130-142, 168-180` | `client_secret_ref` của IdP không bị ràng buộc với chủ của IdP. DB chỉ CHECK định dạng; driver `external` Get/Destroy ref do caller đưa vào | Nếu ref của IdP tenant A bị ghi thành `mgsec://<B>/headscale-api-key#1` (lỗi SQL ở pool platform, API `PATCH /identity-provider` sau này, hoặc vận hành sai): callback giải mã API key Headscale của B và gửi nó làm `client_secret` tới IdP do A kiểm soát. `RemoveIssuer(purge)` còn hủy secret của B | Kiểm `ref.Tenant == IdP.TenantID` (hoặc platform với scope platform) và tên ref đúng của IdP đó, trong callback và driver `external`. Thêm DB CHECK owner-segment theo `tenant_id`. Adapter `ClientSecrets` của P2-T16 cũng kiểm | PLAUSIBLE (cần quyền ghi cột) — test đỏ trên code cũ xác nhận: key Headscale của B bị giải mã, gửi tới token endpoint của A, và bị `RemoveIssuer(purge)` hủy | Đã sửa (commit `f20f9ef`, migration `0007`) — `TestForeignClientSecretRefRefused`: ref trỏ sang key của B ⇒ callback 500, 0 lần đọc SecretStore, 0 token call, 1 `security_event`; driver từ chối Get/Destroy |
| L1 | Low | `internal/headscale/registry.go:139-147`, `locator/locator.go:126-138` | `CachingRegistry` cache Target 60 s. Trạng thái tenant/instance chỉ được kiểm lúc Locate | Tenant bị suspend hoặc instance bị quarantine thì job/sync vẫn gọi Headscale tối đa 60 s | `Invalidate` ở mọi chuyển trạng thái vòng đời, hoặc kiểm trạng thái rẻ ở mỗi `ForTenant` | VERIFIED (tác động Phase 2 thấp: chưa có API suspend) | Đã sửa (commit `f20f9ef`) — `TestLifecycleChangeSeenWithinTTL`: TTL 1 h, suspend tenant / quarantine instance bằng SQL ⇒ `ForTenant` kế tiếp trả `ErrNoInstance`, 0 request tới edge |

### Điểm dễ nối sai (giao cho P2-T16 làm yêu cầu bắt buộc)

Nếu nối sai các điểm dưới đây thì lớp bảo vệ tương ứng âm thầm không có hiệu lực. Agent P2-T16 nhận danh sách này ngày 2026-11-17 và phải ghi trong evidence của P2-T16 chỗ mỗi điểm được thỏa và test chứng minh.

1. `httpapi.New` chỉ từ chối khi thiếu `Hooks.Authz`; thiếu hook `Audit` thì mọi denial lớp 1/2 không vào audit (§8.8).
2. `identity.Config` phải đặt `ClientIP`, `RequestID`, `ProblemWriter`, `Auditor` của `authzhook`/`auditapi`. Mặc định của chúng không an toàn: IP lấy từ RemoteAddr (= IP của edge), `X-Request-Id` thô chưa kiểm, Auditor chỉ ghi log.
3. HTTP client của IdP = `idp.NewIssuerClient(hardened, route)` với `Deny` = `MG_EGRESS_DENY_CIDRS` và `DenyDomains` = domain nền tảng. Biến này phải bắt buộc ngoài dev.
4. Adapter `ClientSecrets` kiểm chủ của ref (F3).
5. `MG_TRUSTED_PROXIES` chỉ gồm đúng địa chỉ của edge, không phải cả dải `mg-edge`. Edge phải giữ `Host`, đặt XFF, bỏ header `X-MG-*` từ ngoài vào, và giới hạn IP cho `admin.` trong đúng site block.
6. Role DB đúng theo tiến trình: api dùng `mg_api_*`; worker dùng `mg_worker_*` (`session.gc`, xoay khóa); pool audit dùng `mg_audit_writer`; kek-ops chỉ ở worker.
7. Lệnh admin `adopt-instance`, `register-platform-idp`, `set-idp-client-secret` phải dùng Auditor ghi vào `audit_events`, không dùng `provisioning.LogAuditor` (chỉ ghi log).
8. 4 handler job lấy tenant từ path. `GetPlatformJob` chỉ ở route platform.
9. Giữ mặc định `monitoring.Config.StaleAfter`. `locator.New` dùng `DefaultTenantStatuses`. File token edge để 0440.
10. `ErrIntegrity` của SecretStore phải sinh `security_events`.

### Trạng thái checklist theo vùng

| Vùng | Trạng thái | Đã kiểm, thấy ổn |
|---|---|---|
| AuthN/session | Không lỗi Cao; Medium F1, F2, F3 | Issuer chọn từ DB; state/nonce/PKCE; iss/aud/azp/exp/iat/auth_time; RFC 9207; mix-up; hash session; cookie `__Host-`; idle/absolute; CSRF HMAC + Origin; `return_to`; step-up; client chống SSRF và đường hẹp tới IdP nền tảng |
| AuthZ | Không lỗi Cao | Tenant chỉ lấy từ path; 404 cho tenant khác; own-resource cho End User; chặn ghi khi tenant suspended; deny-by-default theo `x-permission`; role platform không ngầm có quyền tenant. Lattice và last-Owner mới có code, chưa có endpoint. Support grant thuộc P4-T13 |
| Data layer | Không lỗi Cao (phần DB của F3) | ENABLE + FORCE RLS đủ; `current_setting(…, true)`; FK ghép theo tenant; `set_config(…, true)` trong transaction; không có `SECURITY DEFINER`; `search_path` ghim; grant đúng; audit append-only |
| Secrets | Không lỗi Cao | Nonce GCM ngẫu nhiên; AAD ràng buộc ref/scope/version; kiểm quyền file KEK; rewrap chỉ ở worker; lỗi không chứa giá trị secret |
| Adapter Headscale + locator | Không lỗi Cao (L1) | `ForTenant` là đường duy nhất; ref phải đúng tenant; chỉ retry GET; replay 401/403 an toàn; Problem không chứa text upstream |
| Audit/logging | Không lỗi Cao (F2) | Denial ghi dưới tenant của actor; cặp sự kiện; redaction `hskey-`, Bearer, JWT, cookie; request id được kiểm định dạng |
| Lệnh admin | Không lỗi Cao (điểm nối sai 7) | Credential chỉ qua stdin là pipe; idempotent; ngưỡng 2 SA có khóa advisory |

**Chưa kiểm được nếu không chạy** (cần ở vòng có môi trường chạy hoặc ở người rà soát):
- Hành vi trình duyệt thật (Fetch-Metadata, SameSite) của F1.
- Lượng hàng audit và dung lượng thực của F2.
- Nội bộ go-oidc v3.21 (lọc alg, JWKS) — vòng 1 đánh giá theo hiểu biết về thư viện.
- RLS và grant trên PostgreSQL thật, gồm grant schema `river` sau khi River migrate.
- Cấu hình Caddy: giữ Host, XFF, bỏ `X-MG-*`, giới hạn IP cho `admin.`.
- Tính đồng thời của `GuardMembershipChange` (chưa có endpoint gọi).

## Sửa sau vòng 1

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-17 |
| Commit | `f20f9ef` (code + test) trên nhánh `fix-g2-findings` tách từ `main` @ `e043bc4`; file này và 2 câu ở master (§6.3, §8.3) ở commit kế tiếp |
| Người thực hiện | Agent (Claude Opus 5.5), giao bởi người điều phối |
| Môi trường | dev/CI — VM build 110 (`mg-ci-runner-2`): PostgreSQL 18 và Go 1.27.4 trong image pin digest như CI |
| Cách làm | Mỗi lỗi: tự kiểm lại đường code, viết test **đỏ trên code cũ** (9 test, cả 9 đỏ), sửa, test xanh. Đột biến: bỏ từng chốt chặn mới ⇒ **26/26 đột biến bị test bắt** |

**F1 — login CSRF.** Nguyên nhân: `beginLogin` (`login.go`) không đọc Fetch Metadata, và callback (`callback.go:244-248` cũ) thu hồi session đang mở rồi tạo session cho identity vừa đăng nhập, bất kể identity khác. Sửa hai lớp:
1. Middleware ghi `Sec-Fetch-Site` vào `RequestInfo.FetchSite` (rỗng hoặc lặp ⇒ `invalid`); `BeginLogin` từ chối `403 forbidden` (reason `sec_fetch_site_cross_origin`, sự kiện `auth.login_start` denied) khi header có mặt và khác `same-origin`/`none` — trước mọi truy vấn DB nên không có hàng `auth_requests`, không cookie, không redirect. `same-site` cũng bị từ chối: subdomain khác của nền tảng (origin quản trị, trang của tenant) không phải trang của Portal. **Thiếu header thì cho qua**: client không phải trình duyệt (test, harness, curl) và trình duyệt chưa có Fetch Metadata không gửi nó, mọi trình duyệt chính hiện hành đều gửi; lỗ còn lại do lớp 2 đóng, lớp này không phụ thuộc header.
2. Callback: nếu origin đang có session của **identity khác** thì từ chối `403` (reason `session_identity_mismatch`), **giữ nguyên session cũ** và rollback (identity mới không được tạo); audit ghi dưới identity, tenant và session được giữ, không ghi vào tenant của IdP kia. Muốn đổi identity thì đăng xuất trước — đó là bước tường minh. Chọn "giữ và từ chối" thay vì "thêm bước xác nhận" vì an toàn nhất (không có trạng thái chờ xác nhận nào để kẻ tấn công lợi dụng), không cần API/UI mới, và giữ nguyên hành vi của các test đăng nhập hiện có: cùng identity vẫn xoay session (`TestStepUp`).

Test: `TestLoginStartFetchMetadata`, `TestCallbackKeepsSessionOfAnotherIdentity` (đỏ trước: 302 và session bị thay). `tests/security/oidclogin`, `tests/e2e/harness` (không đăng nhập qua API) và fixture P2-T15a (`sessionfixture`, `authzmatrix`, `bootstrapseed`, `it01`) không dựa vào hành vi cũ của F1. Một số fixture phải đổi vì F3 (xem dưới).

**F2 — audit ẩn danh không giới hạn.** Nguyên nhân: middleware identity (`middleware.go:90-97, 109-112`), `BeginLogin`, `CompleteLogin` ghi một `AuditEvent` cho mỗi lần từ chối, và `auditapi.IdentityAuditor` (`identity.go:30-37` cũ) đưa mọi sự kiện không thành công vào `RecordDetached`: mỗi request một hàng append-only, kể cả khi chưa có identity. Sửa theo hướng "gộp theo (IP/64, lý do, cửa sổ) thành bản ghi có bộ đếm":
- `audit.Logger.RecordAnonymousDenial`: khóa gộp = (IPv4 /32 hoặc IPv6 /64, tenant, action, reason), cửa sổ `AnonymousWindow` (mặc định 10 phút) tính từ lần đầu. Chỉ lần thứ 1, 10, 100, 1 000… được ghi (đường detached), kèm `details.count`, `client_prefix`, `window_seconds`: tối đa ⌊log10 n⌋+1 hàng mỗi khóa và cửa sổ — 4 hàng cho 1 000 request, 5 hàng cho 30 300 request mà rate limit theo IP cho qua trong 10 phút (trước đây: 30 300 hàng). Tối đa `AnonymousKeys` (256) khóa cùng lúc; nguồn mới vượt ngưỡng dùng chung khóa `*`. Metric `meshguard_audit_anonymous_denials_total{action,reason}` đếm mọi lần.
- `IdentityAuditor`: thành công ⇒ `RecordCommitted`; có identity ⇒ `RecordDetached`, **một hàng mỗi denial như cũ** (§8.8, ví dụ CSRF sai của user đã đăng nhập); không có identity ⇒ `RecordAnonymousDenial`. Nhất quán với `auditapi.Middleware` (401 ẩn danh chỉ ở access log), nhưng giữ một vết có giới hạn để tenant vẫn thấy đăng nhập thất bại vào IdP của mình. Không chọn hướng "metric + `security_events`": phần lớn từ chối ẩn danh là lành tính (hết hạn, người dùng hủy ở IdP) nên làm nhiễu bảng nhân sự nền tảng phải xem, và tenant mất dấu vết đăng nhập thất bại.

Test: `TestAnonymousRejectionsAreBounded` (đỏ trước: 4 000 hàng cho 4 loại có audit), `TestAnonymousDenialRows`, `TestAnonymousAggregation`, `TestIdentityAuditor`.

**F3 — `client_secret_ref` không ràng buộc chủ.** Nguyên nhân: `0002_identity_rbac.sql:65` chỉ CHECK định dạng; callback (`callback.go:153-161` cũ) đưa ref đã lưu cho `ClientSecrets`; driver `external` (`external.go:130-142, 168-180` cũ) và driver `keycloak` (`client.go` EnsureClient, `remove.go` purge — cùng mẫu, sửa luôn) parse ref rồi Get/Destroy. Test đỏ trên code cũ xác nhận đường khai thác: key Headscale của tenant B bị giải mã, gửi làm `client_secret` tới token endpoint của IdP tenant A, và bị `RemoveIssuer(purge)` hủy. Sửa:
- `idp.Registration.OwnClientSecretRef`: chỉ nhận ref có owner = tenant của IdP (`platform` với IdP platform) và tên `idp.<idp id>.client` (driver ghi) hoặc `idp-client-secret.<idp id>` (`meshguard admin set-idp-client-secret` ghi); sai ⇒ lỗi riêng `secret_ref_not_owned` (reason `malformed`/`owner`/`name`).
- Callback kiểm **trước** SecretStore và token endpoint: `500 internal_error` (fail closed), `security_event` `idp.client_secret_ref_not_owned` mức `high`, phạm vi platform, dedupe 1 sự kiện mỗi IdP mỗi giờ (qua field mới `identity.AuditEvent.Security`). Driver `external`/`keycloak` kiểm trước Get (EnsureClient) và Destroy (RemoveIssuer purge) — `keycloak` kiểm trước cả lời gọi Keycloak — và nâng cùng `security_event` qua `Config.Security` (tùy chọn).
- Migration **`0007_idp_secret_ref_owner.sql`** (expand-only, forward-only): `CHECK` owner segment của `client_secret_ref` = `tenant_id` (`platform` khi `tenant_id` NULL); phần tên chỉ do code kiểm. DB đang có ref sai chủ sẽ không migrate được (goose dừng ở 0006) cho tới khi sửa hàng đó. **Số `0007` trùng chỗ bản đồ migration §6.3 dành cho P3-T06: có thể phải đánh số lại khi gộp.**

Test: `TestForeignClientSecretRefRefused` (superuser bỏ CHECK rồi trỏ ref sang key của B, key Headscale của chính A, secret platform ⇒ callback 500, 0 lần đọc SecretStore, 0 token call, 1 `security_event`; driver từ chối Get/Destroy, key của B còn nguyên), `TestMigration0007ClientSecretRefOwner` (up trên DB có dữ liệu; DB có ref sai chủ không lên 0007, version giữ 6; sau 0007 superuser và `mg_api_platform` ghi sai chủ ⇒ 23514), `TestOwnClientSecretRef`, `TestClientSecretRefMustBeTheIdPsOwn` (external, keycloak). Fixture test từng dùng tên secret không thuộc IdP (`idp-client#1`, `idp-a#1`, `idp-platform#1`…) — tức dựa vào hành vi chưa ràng buộc — được đổi sang tên của chính IdP: `internal/identity` (env, keycloak), `internal/httpapi` (auditapi, authzhook, tenantsapi), `tests/isolation/it01`, `tests/security/{oidclogin,bootstrapseed,authzmatrix}`.

**L1 — cache Target che thay đổi vòng đời.** Nguyên nhân: `CachingRegistry.ForTenant` (`registry.go:139-147` cũ) trả entry trong TTL mà không kiểm trạng thái; locator chỉ kiểm ở `Locate` (`locator.go:126-138` cũ). Chọn **kiểm trạng thái rẻ ở mỗi `ForTenant`** thay vì hook `Invalidate`: hook phải được gọi ở mọi tiến trình api và worker (mỗi tiến trình một cache — cần tín hiệu liên tiến trình), dễ quên (fail open), và bỏ sót thay đổi không đi qua code vòng đời (vận hành sửa bằng SQL); phép kiểm chỉ là một lần đọc registry (2 truy vấn trong scope tenant, không đọc secret, không đọc file token, không probe version). Interface tùy chọn `headscale.StatusChecker` (do `locator.Locator` cài): tenant/instance không còn gọi được ⇒ bỏ entry, trả `instance_unavailable` bọc `ErrNoInstance`; instance bị thay ⇒ `ErrTargetStale` ⇒ locate lại; không kiểm được ⇒ từ chối (fail closed). `Instance` đã lấy trước khi suspend vẫn dùng được tới lần `ForTenant` kế tiếp (caller lấy `Instance` theo từng thao tác).

Test: `TestLifecycleChangeSeenWithinTTL` (unit với fake locator và DB thật với locator thật), `TestReplacedInstanceLocatedAgain`.

**Ảnh hưởng tới phần nối của P2-T16:** `identity.Config` không đổi; `auditapi.IdentityAuditor`/`Middleware` giữ chữ ký, nhưng `IdentityRecorder` có thêm `RecordAnonymousDenial` và `RecordSecurityEvent` (`*audit.Logger` đã cài cả hai). Khi dựng driver IdP, đặt `external.Config.Security`/`keycloak.Config.Security` = `audit.Logger`. Điểm nối 4 ("adapter `ClientSecrets` kiểm chủ của ref"): callback nay tự kiểm, adapter kiểm thêm chỉ còn là phòng thủ chiều sâu.
