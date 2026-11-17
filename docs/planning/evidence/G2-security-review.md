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

## Vòng 2 — rà soát độc lập theo OWASP ASVS 5.0.0 (L2)

> Người rà soát độc lập của G2 do chủ dự án chọn (giao qua người điều phối): một agent **không viết** bất kỳ phần code nào của Phase 2. Vòng 1 ở trên chỉ được dùng làm đầu vào; mọi điều vòng 2 dựa vào đều được kiểm lại bằng code, test hoặc thăm dò chạy thật. Vòng 2 **không sửa code** — chỉ báo cáo; mọi phát hiện dưới đây đang **mở**.

### Metadata

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-17; chạy thử 10:10–11:26 UTC (gồm dọn dẹp; mọi tài nguyên `asvs*` trên VM đã gỡ — kiểm lại: 0 container, 0 network, 0 volume, 0 image, 0 thư mục) |
| Người rà soát | Agent rà soát độc lập (Claude Opus 5.5), giao bởi người điều phối theo lựa chọn của chủ dự án; không là tác giả của phần code nào được rà |
| Đối tượng | `main` @ `03509d3` (code cuối Phase 2), worktree chỉ đọc, nhánh `g2-asvs`. Cây chạy thử = `git archive` của đúng commit này |
| Chuẩn | OWASP ASVS **5.0.0**, **Level 2**: mọi yêu cầu L1 + L2 của V6 (35), V7 (18), V8 (7), V9 (7), V10 (29) — **96 yêu cầu**. V9/V10 áp cho BFF ở vai trò relying party tiêu thụ ID token (BFF không cấp token nào cho trình duyệt); các yêu cầu của authorization server / OpenID Provider thuộc Keycloak (Delegated) |
| Nguồn ASVS | `https://github.com/OWASP/ASVS`, tag `v5.0.0_release` (repo không có tag tên đúng `v5.0.0`; đây là tag phát hành 5.0.0) = commit `5cf9b032440be53ce345ab3c130fda46ba1ce7a2` ("Publish ASVS v5.0.0", 2025-05-30), file `5.0/en/0x15-V6-Authentication.md` … `0x19-V10-OAuth-and-OIDC.md`. Chỉ tải xuống (sparse clone); không gửi dữ liệu dự án đi đâu |
| Phương pháp | (1) Đọc code theo từng yêu cầu: `internal/identity`, `internal/idp/**`, `internal/authz`, `internal/httpapi/**`, `internal/store` + `database/migrations`, `internal/devices`, `apps/internal/runner`, `apps/api` (lệnh admin), `infrastructure/caddy/Caddyfile.tmpl` + `tools/render_edge.py`, `infrastructure/idp/realms/*.tmpl` + `tools/render_idp.py`; mã nguồn go-oidc v3.21.0 lấy từ module cache. (2) Chạy toàn bộ test Go. (3) 3 **probe test Go** ngoài repo (chép tạm vào cây thử — mục "Probe"). (4) 12 **thăm dò hộp đen** (P1–P12) qua edge trên stack dev/CI (`tests/e2e/harness`: Caddy render từ `Caddyfile.tmpl`, Keycloak 26.8.2 với realm render từ template, api/worker build từ cây) |
| Môi trường | **dev/CI** (nhãn §22.1: functional) — VM build 105 (`mg-ci-runner`, 12 vCPU). Go 1.27.4 và PostgreSQL 18 trong image pin digest như CI; stack e2e tiền tố `asvse2e` trên dải mạng thử riêng. Không đụng staging, VPS, DNS, VM của chuỗi kiểm của người điều phối |
| Kết quả nền | `go test -race -count=1 -v ./...`: 39 package ok, 441 test cấp cao nhất + 191 subtest PASS, **0 FAIL**, 10 SKIP (chỉ test cần Keycloak/Headscale/adopt thật). `go test -race -count=1 -v -tags mgtestfixture ./tests/...`: 8 package ok, 13 + 14 PASS, **0 FAIL**, 5 SKIP. `e2e.py up` + `e2e.py test` trên stack thử: **25/25 PASS** (functional) trước khi thăm dò |
| Nhãn | **VERIFIED** = chứng minh bằng test/probe chạy thật hoặc lần theo code từ đầu đến cuối; **PLAUSIBLE** = suy luận, chưa chạy (đưa vào danh sách kiểm trên staging) |

### Kết luận vòng 2

- 96 yêu cầu: **36 Pass**, **25 Delegated (Keycloak, đạt)**, **16 Fail**, **19 N/A**.
- 9 phát hiện: **0 Critical, 0 High**, 3 Medium (A-1 phiên SSO của IdP sống sau khi đăng xuất Portal, A-2 không có đường chấm dứt session khi khóa tài khoản, A-3 không có danh sách chặn mật khẩu), 6 Low (A-4 … A-9); thêm 7 ghi chú Info (I-1 … I-7). Cả 3 Medium đều VERIFIED bằng thăm dò chạy thật.
- Không có lỗi mức Cao ở xác thực, phiên hay kiểm soát truy cập: chống IdP mix-up, ràng buộc state/nonce/PKCE với trình duyệt, kiểm ID token, cách ly tenant (tenant từ path → authz → RLS → FK ghép) và deny-by-default theo `x-permission` đều đứng vững khi kiểm lại độc lập.

| Chương | Số yêu cầu | Pass | Delegated (đạt) | Fail | N/A |
|---|---|---|---|---|---|
| V6 Authentication | 35 | 6 | 13 | 9 | 7 |
| V7 Session Management | 18 | 9 | 1 | 7 | 1 |
| V8 Authorization | 7 | 7 | 0 | 0 | 0 |
| V9 Self-contained Tokens | 7 | 6 | 1 | 0 | 0 |
| V10 OAuth and OIDC | 29 | 8 | 10 | 0 | 11 |
| **Tổng** | **96** | **36** | **25** | **16** | **19** |

**Delegated** = yêu cầu do Keycloak thực thi. Cách giữ: template `infrastructure/idp/realms/*.json.tmpl` → `tools/render_idp.py` `check_realm()` (`render_idp.py:174-265`, từ chối render khi vi phạm; chạy trong CI qua `tools/test_render_idp.py`) → import một lần (`IGNORE_EXISTING`) → realm đang chạy được driver sửa drift (`keycloak.EnsureIssuer`: mọi khóa cấp realm của template, flow MFA, required actions, client — P2-T05a). Cột bằng chứng ghi rõ khóa nào `check_realm` **không** kiểm (chỉ template + `EnsureIssuer` giữ). Số dòng của template dẫn theo `platform.json.tmpl`; hai template tenant giống từng khóa trừ tên, id, redirect URI và thời hạn SSO.

### Bảng yêu cầu — V6 Authentication

| ID | Yêu cầu (tóm tắt) | Kết luận | Bằng chứng |
|---|---|---|---|
| 6.1.1 | Tài liệu rate limit / anti-automation chống credential stuffing, brute force; chống khóa tài khoản ác ý | Pass | P2-T05 Q10 (brute force Keycloak: khóa **tạm** từ lần sai thứ 5, 60 s tăng tới 15 phút, không khóa vĩnh viễn để tránh DoS khóa Tenant Owner); §13.1 + `internal/httpapi/ratelimit.go:45-64` (class `auth` 2/s burst 30 theo IP, 1/s theo identity) |
| 6.1.2 | Tài liệu danh sách từ theo ngữ cảnh cấm dùng làm mật khẩu | **Fail — A-3** | Không có danh sách nào trong master, P2-T05 hay RUNBOOK |
| 6.1.3 | Mọi đường xác thực được tài liệu hóa cùng kiểm soát và độ mạnh | Pass | §8.1 (bốn mặt phẳng danh tính), §8.2 (console/break-glass Keycloak sau 2P + giới hạn IP), RUNBOOK (lệnh host-only `bootstrap-super-admin`, `seed-membership`). Chỗ tài liệu lệch thực tế mạng: A-8, I-2 |
| 6.2.1 | Mật khẩu ≥ 8 ký tự | Delegated (đạt) | `passwordPolicy` `length(12) and maxLength(128) and notUsername and notEmail and passwordHistory(5)` (`platform.json.tmpl:33`); `check_realm` kiểm `length(>=12)` (`render_idp.py:200-201`). P8a: 11 ký tự ⇒ 400, 12 ⇒ chấp nhận — VERIFIED |
| 6.2.2 | Người dùng đổi được mật khẩu | Delegated (đạt) | Account console `/realms/<realm>/account` công khai qua edge (`@idp_public`, `Caddyfile.tmpl:206-209`); `UPDATE_PASSWORD` bật (`platform.json.tmpl:86`; `check_realm` bắt đủ bộ required actions `:221-223`). P6b: đổi được — VERIFIED |
| 6.2.3 | Đổi mật khẩu đòi mật khẩu hiện tại + mới | **Fail — A-4** | P6/P6b: form `kc_action=UPDATE_PASSWORD` chỉ có `password-new`, `password-confirm`; POST ⇒ `kc_action_status=success` — VERIFIED |
| 6.2.4 | Kiểm với ≥ 3000 mật khẩu phổ biến | **Fail — A-3** | Không có `passwordBlacklist`; P4: `password1234`, `qwertyuiop123`, `Password1234!` được chấp nhận — VERIFIED |
| 6.2.5 | Không có luật thành phần ký tự | Delegated (đạt) | Policy không có `upperCase`/`digits`/`specialChars`; P4 chấp nhận mật khẩu chỉ chữ thường + số |
| 6.2.6 | Ô mật khẩu `type=password` | Delegated (đạt) | P8b: `type=['password']`, có nút hiện mật khẩu (theme mặc định) — VERIFIED |
| 6.2.7 | Cho dán, cho trình quản lý mật khẩu | Delegated (đạt) | P8b: không có `onpaste`, `autocomplete="current-password"` — VERIFIED |
| 6.2.8 | Kiểm đúng mật khẩu nhận được (không cắt, không đổi hoa/thường) | Delegated (đạt) | `maxLength(128)` từ chối lúc đặt (P8a: 129 ⇒ 400) nên không cắt ngầm; Keycloak băm cả chuỗi; P8a: chuỗi có dấu cách + Unicode được chấp nhận |
| 6.2.9 | Cho phép ≥ 64 ký tự | Delegated (đạt) | `maxLength(128)`; P8a: 64 và 128 ký tự ⇒ chấp nhận — VERIFIED. `check_realm` **không** kiểm `maxLength` |
| 6.2.10 | Không bắt đổi mật khẩu định kỳ | Delegated (đạt) | Policy không có `forceExpiredPasswordChange` (`platform.json.tmpl:33`) |
| 6.2.11 | Dùng danh sách từ ngữ cảnh để chặn mật khẩu dễ đoán | **Fail — A-3** | P4: `meshguard2026`, `tenant-a12345` được chấp nhận — VERIFIED |
| 6.2.12 | Kiểm với tập mật khẩu đã lộ | **Fail — A-3** | Không có kiểm breached password nào |
| 6.3.1 | Chống credential stuffing / brute force theo tài liệu | Delegated (đạt) | `bruteForceProtected` true, `permanentLockout` false, `failureFactor` 5, `MULTIPLE` (`platform.json.tmpl:23-32`); `check_realm` kiểm (`render_idp.py:198-199`); P2-T05 `tests/idp/login_test.py`: lần sai thứ 5 khóa tạm. API: `TestRateLimitClasses`, `TestRateLimitBehindEdge` PASS |
| 6.3.2 | Không có tài khoản mặc định (root/admin/sa) | Pass | Realm platform/tenant: chỉ service account của `mg-idp-driver`, `admin-cli` tắt (`platform.json.tmpl:163-178`; `check_realm` `:255-260`). Realm master: chỉ admin break-glass `mg-bootstrap-admin` (tên riêng, mật khẩu 40 ký tự ngẫu nhiên — `infrastructure/idp/secrets.sh:27-28, 48-49`); điểm yếu của nó: A-8 |
| 6.3.3 | Bắt buộc MFA | Delegated (đạt) | Browser flow `mg-browser` = cookie SSO hoặc [mật khẩu REQUIRED → OTP REQUIRED] (`platform.json.tmpl:56-80`), `CONFIGURE_TOTP` là default action; `check_realm` kiểm đúng cấu trúc (`render_idp.py:212-225`); E2E-22/24 và P1: bước `['password', 'configure_totp']`. IdP `external`: MFA do IdP của tenant (§8.2, có lý do). Lưu ý: RP không tự kiểm độ mạnh (A-6); admin break-glass chỉ có mật khẩu (A-8) |
| 6.3.4 | Không có đường xác thực ngoài tài liệu; độ mạnh nhất quán | **Fail — A-8** | Mọi thành viên `mg-edge` tới thẳng `idp:8080` và lấy token realm master bằng password grant (`admin-cli` bật, brute force tắt — P10), trong khi `Caddyfile.tmpl:194-197` mô tả realm master "CHỈ từ worker" — VERIFIED |
| 6.4.1 | Mật khẩu ban đầu do hệ thống sinh: hết hạn, không thành mật khẩu lâu dài | **Fail — A-9** | `infrastructure/idp/create-user.sh:51` đặt `"temporary":false`. Lời mời của driver (P4) dùng action token 12 giờ (`platform.json.tmpl:47`) — đạt |
| 6.4.2 | Không gợi ý mật khẩu / câu hỏi bí mật | Pass | Keycloak không có; template không bật gì tương tự |
| 6.4.3 | Quy trình quên mật khẩu an toàn, không vượt MFA | N/A | `resetPasswordAllowed: false` (`platform.json.tmpl:14`): Phase 2 không có luồng quên mật khẩu tự phục vụ. Cảnh báo cho P4: I-6 |
| 6.4.4 | Mất yếu tố MFA ⇒ xác minh danh tính ngang mức lúc đăng ký | **Fail — A-7** | Không tài liệu nào mô tả quy trình khi mất thiết bị TOTP |
| 6.5.1 | TOTP / OOB / lookup chỉ dùng được một lần | Delegated (đạt) | `otpPolicyCodeReusable: false`, `check_realm` kiểm (`render_idp.py:202`); P8c: dùng lại mã vừa dùng ⇒ Keycloak từ chối — VERIFIED |
| 6.5.2 | Lookup secret < 112 bit phải băm có salt | N/A | Flow không có authenticator recovery code (chỉ mật khẩu + OTP): lookup secret không dùng được để đăng nhập |
| 6.5.3 | Seed TOTP sinh bằng CSPRNG | Delegated (đạt) | Keycloak sinh secret TOTP phía server (trường `totpSecret` của form `CONFIGURE_TOTP`) |
| 6.5.4 | Lookup / OOB ≥ 20 bit | N/A | Không có lookup secret / OOB |
| 6.5.5 | Thời hạn OOB ≤ 10 phút, TOTP ≤ 30 s | Delegated (đạt) | `otpPolicyPeriod 30`; `otpPolicyLookAheadWindow 1` cho lệch ±1 bước (RFC 6238 §5.2). `check_realm` **không** kiểm period / look-ahead |
| 6.6.1 | OTP qua PSTN/SMS | N/A | Không có |
| 6.6.2 | OOB gắn với yêu cầu gốc | N/A | Không có OOB |
| 6.6.3 | OOB chống brute force | N/A | Không có OOB |
| 6.8.1 | Nhiều IdP: không giả danh qua IdP khác | Pass | `identities UNIQUE (idp_id, subject)` + FK ghép (`0002_identity_rbac.sql:97-101`); `UpsertLoginIdentity` theo `(idp_id, sub)` (`database/queries/sessions.sql:39`), không bao giờ theo email; `TestTenantIssuerIsolation`, `TestIT01IdentityIsolation`, `TestDBRejectsIdentityOutsideItsIdP` PASS |
| 6.8.2 | Luôn kiểm chữ ký assertion | Pass | `internal/identity/callback.go:202-205` (go-oidc `Verify`); go-oidc `verify.go:313` (`jose.ParseSigned` với allowlist) rồi `VerifySignature` trước khi đọc claim; `TestIDTokenValidation` (khóa lạ, `alg none`, HS256 bằng client secret ⇒ 401) PASS |
| 6.8.3 | SAML dùng một lần | N/A | Không có SAML |
| 6.8.4 | Kiểm độ mạnh / thời điểm xác thực từ IdP (`acr`, `amr`, `auth_time`) hoặc fallback có tài liệu | **Fail — A-6** | `auth_time` có kiểm (`callback.go:220-227`, step-up `session.go:151-160`, `TestStepUp`), nhưng `acr`/`amr` chỉ được lưu (`claims.go:159-167`); probe `TestProbeSingleFactorPlatformLoginAccepted`: ID token platform `amr=["pwd"]`, `acr="0"` ⇒ session admin — VERIFIED |

### Bảng yêu cầu — V7 Session Management

| ID | Yêu cầu (tóm tắt) | Kết luận | Bằng chứng |
|---|---|---|---|
| 7.1.1 | Tài liệu idle / absolute timeout, lý do lệch NIST SP 800-63B | Pass | §8.3 bước 6: tenant 30 phút / 12 giờ (đúng mức AAL2), nhân sự nền tảng 15 phút / 8 giờ (chặt hơn); phiên SSO Keycloak cùng giá trị (P2-T05 Q11, `check_realm` `:203-204`) |
| 7.1.2 | Tài liệu số phiên song song cho một tài khoản | **Fail — A-7** | Không giới hạn và không tài liệu (`GET /auth/sessions` chỉ liệt kê) |
| 7.1.3 | Tài liệu hệ thống SSO/federation và cách phối hợp vòng đời, kết thúc phiên | **Fail — A-1** | Thời hạn có phối hợp (Q11), **kết thúc** thì không: đăng xuất BFF không kết thúc phiên Keycloak, khóa user ở Keycloak không kết thúc phiên BFF — chỉ ghi "phase sau" ở [P2-T06](P2-T06.md) mục 6 ý 4 và mục 8 |
| 7.2.1 | Kiểm session token ở backend tin cậy | Pass | `internal/identity/session.go:91-146`: tra hash trong `sessions`, kiểm thu hồi, hạn, origin, scope, trạng thái identity và IdP ở mỗi request |
| 7.2.2 | Token động, không phải secret tĩnh | Pass | Session id sinh mới mỗi lần đăng nhập (`callback.go:237`) |
| 7.2.3 | Reference token ≥ 128 bit, CSPRNG, duy nhất | Pass | 256 bit `crypto/rand` (`tokens.go:17, 28-32`); DB chỉ lưu SHA-256 làm khóa chính (`tokens.go:51-54`, `0002:145`); giải mã chặt (`tokens.go:38-47`, `TestDecodeSecretIsStrict`) |
| 7.2.4 | Token mới khi xác thực (kể cả xác thực lại), chấm dứt token cũ | Pass | `callback.go:262-276`: thu hồi session đang mở của cùng identity rồi tạo session mới; `TestStepUp`; P1: cookie mới khác cookie cũ |
| 7.3.1 | Idle timeout | Pass | `session.go:112`, gia hạn ≤ absolute `:125-131`; `TestSessionTimeouts` |
| 7.3.2 | Absolute timeout | Pass | `session.go:110`; `config.go:32-35`; `TestSessionTimeouts` |
| 7.4.1 | Kết thúc phiên ⇒ backend vô hiệu | Pass (phiên BFF) | `session.go:330-347` (`revoked_at`), kiểm ở `:108`; `TestSessionsListAndRevoke`; P1: sau logout `GET /auth/session` ⇒ 401. Phiên ở IdP: A-1 |
| 7.4.2 | Khóa / xóa tài khoản ⇒ chấm dứt mọi phiên | **Fail — A-2** | `identities.status='disabled'` có hiệu lực ngay (`session.go:120`, `TestDisabledIdentityAndIdP`) nhưng Phase 2 không có đường nào đặt trạng thái đó ngoài SQL; khóa user ở Keycloak không ảnh hưởng phiên BFF (P5) — VERIFIED |
| 7.4.3 | Tùy chọn chấm dứt các phiên khác sau khi đổi / gỡ yếu tố xác thực | **Fail — A-2** | Đổi mật khẩu / OTP xảy ra ở Keycloak; BFF không biết, phiên BFF giữ nguyên |
| 7.4.4 | Trang cần xác thực có nút đăng xuất | N/A | Phase 2 chưa có web UI (Portal ở Phase 4); `POST /auth/logout` có sẵn |
| 7.4.5 | Quản trị viên chấm dứt phiên của một người / mọi người | **Fail — A-2** | `RevokeIdentitySessions` (`session.go:379-390`) không có caller ngoài test; không API, không lệnh admin (`apps/api/admin.go:80-95`); chỉ SQL (`docs/operations/backup-restore.md` mục 6.3 bước 5 — thu hồi tất cả, trong ngữ cảnh restore) |
| 7.5.1 | Xác thực lại đầy đủ trước khi sửa thuộc tính ảnh hưởng xác thực | Delegated (đạt) | Mọi sửa đổi mật khẩu / MFA nằm ở Keycloak; AIA đòi đăng nhập lại khi lần xác thực cũ hơn `max_auth_age` mặc định 300 s; `UPDATE_EMAIL` tắt (`platform.json.tmpl:88`) và email không dùng để khôi phục tài khoản (`resetPasswordAllowed: false`). Siết thành luôn xác thực lại: A-4 |
| 7.5.2 | Xem và (sau khi xác thực lại) chấm dứt phiên | **Fail — A-5** | Xem / chấm dứt có (`internal/httpapi/identityapi/handlers.go:140-199`, `TestSessionsListAndRevoke`) nhưng không đòi xác thực lại; probe `TestProbeRevokeOtherSessionWithoutReauth` — VERIFIED |
| 7.6.1 | Vòng đời RP–IdP đúng tài liệu, đòi xác thực lại khi cần | **Fail — A-1** | P1 (realm `tenant-a` và `platform`): sau `POST /auth/logout`, `GET /auth/login` ⇒ Keycloak trả code ngay (không form mật khẩu / OTP) ⇒ session mới — VERIFIED |
| 7.6.2 | Tạo phiên cần hành động / đồng ý của người dùng | Pass | Phiên chỉ tạo ở callback ràng buộc cookie `__Host-mg_authreq` do `GET /auth/login` đặt (`callback.go:122-125`); login do trang khác khởi xướng bị từ chối (`login.go:91-95`, `TestLoginStartFetchMetadata`); không dùng `prompt=none` |

### Bảng yêu cầu — V8 Authorization

| ID | Yêu cầu (tóm tắt) | Kết luận | Bằng chứng |
|---|---|---|---|
| 8.1.1 | Tài liệu quy tắc function-level và data-specific | Pass | §8.4 (bất biến 1–6), §8.5/§8.6 (ma trận), §8.8 (5 lớp); `x-permission`, `x-own-resource` trong `api/openapi.yaml`; `internal/authz/operations_gen.go` sinh từ spec, CI so khớp |
| 8.1.2 | Tài liệu field-level (đọc / ghi) | Pass | Mỗi operation một schema; body ghi khai báo `additionalProperties: false` (ví dụ `DeviceRename` chỉ có `given_name`); §13.3 phân biệt bản job "safe projection" (tenant) và bản đầy đủ (platform). Phase 2 không có operation nào mà các role được gọi lại thấy trường khác nhau — Phase 4 (users, End User) phải ghi quy tắc trường tường minh |
| 8.2.1 | Function-level chỉ cho người có quyền tường minh | Pass | `internal/httpapi/authzhook/authzhook.go:67-88` chạy trước mọi handler; `internal/authz/authz.go:265-286` deny-by-default (`unknown_permission` `:285`, `unknown_operation` `:290-294`); `internal/httpapi/server.go:89-98` từ chối mount handler khi thiếu hook Authz/Session/Audit; `TestAuthzMatrix` (100% operation — `TestEveryOperationHasAnExpectation`), `TestRequireOperation`, `TestNoHandlersWithoutAuthz` PASS |
| 8.2.2 | Data-specific (chống IDOR / BOLA) | Pass | Tenant chỉ lấy từ path (`authzhook.go:74-80`); membership nạp trong `WithTenantTx` + RLS (`authz.go:407-427`, `database/queries/authz.sql:6-16`); tài nguyên tenant khác ⇒ 404; End User chỉ thiết bị của mình, không tag (`internal/devices/device.go:77-83`, `service.go:200-212, 226-236`, `devices.sql:107-125`); job chỉ với decision cùng tenant, không own-only (`jobsapi/handlers.go:142-155`); `TestDevicesThroughTheComposedAPI`, `TestIT01IdentityIsolation`, E2E-22 (thiết bị của B ⇒ 404) PASS |
| 8.2.3 | Field-level (chống BOPLA) | Pass | Body ghi duy nhất của Phase 2 là `DeviceRename` (chỉ `given_name`, kiểm lại cục bộ `devices/service.go:219-221`); struct sinh từ schema nên không có mass assignment |
| 8.3.1 | Quyết định ở tầng dịch vụ tin cậy | Pass | Lớp 1–3 ở api, lớp 4 PostgreSQL, lớp 5 adapter; session chỉ mang danh tính, quyền nạp lại mỗi request (`TestAuthorizerLoadsEveryRequest`) |
| 8.4.1 | Kiểm soát chéo tenant | Pass | RLS ENABLE + FORCE (`0002:184-207`), FK ghép `(tenant_id, identity_id)` (`0002:137`); nhân sự nền tảng không vào route tenant khi chưa có Support Access Grant (`authz.go:318-321`); `TestIT03TenantPoolSeesOnlyItsTenant`, `TestIT03TenantForeignKeysAreComposite`, `TestIT12aAuditIsolation`, `TestAuthzMatrix` (không có tác dụng phụ ở tenant bị dò) PASS; P9: SNI một origin + Host origin khác ⇒ 421 |

### Bảng yêu cầu — V9 Self-contained Tokens (ID token mà BFF nhận)

| ID | Yêu cầu (tóm tắt) | Kết luận | Bằng chứng |
|---|---|---|---|
| 9.1.1 | Kiểm chữ ký trước khi dùng nội dung | Pass | go-oidc `verify.go:313` → `VerifySignature` trước khi giải claim; module chỉ đọc claim sau `Verify` (`callback.go:202-209`); `TestIDTokenValidation` |
| 9.1.2 | Allowlist thuật toán, không `none` | Pass | go-oidc `oidc.go:180-191, 338-342`: thuật toán của discovery giao với {RS*, ES*, PS*, EdDSA}, mặc định RS256 — `none` và HS* không bao giờ vào allowlist; `TestIDTokenValidation` ("alg none", "alg HS256 keyed with the client secret" ⇒ 401) |
| 9.1.3 | Khóa từ nguồn cấu hình sẵn; không tin `jku`/`x5u`/`jwk` | Pass | Khóa chỉ từ `jwks_uri` trong discovery của issuer lưu ở DB (`provider.go:131-156`), qua client hardening / đường hẹp (`apps/internal/runner/api.go:63`); go-oidc chỉ dùng `RemoteKeySet`, không đọc header khóa của JWS |
| 9.2.1 | Kiểm `exp` / `nbf` | Pass | go-oidc `verify.go:262-283` (`exp` không leeway; `nbf` leeway cố định 5 phút — I-5); `TestIDTokenValidation` ("expired"), probe `TestProbeNbf` (`nbf` +10 phút ⇒ 401) |
| 9.2.2 | Đúng loại token cho đúng mục đích | Pass | BFF chỉ nhận ID token trực tiếp từ token endpoint của issuer đã lưu qua TLS (`callback.go:183-205`); không nhận token nào từ client; access token bị bỏ (không lưu, không dùng để phân quyền) |
| 9.2.3 | Kiểm `aud` | Pass | go-oidc với `ClientID` (`callback.go:202`); `azp` khi nhiều audience (`callback.go:213-215`); `TestIDTokenValidation` |
| 9.2.4 | Issuer dùng chung khóa cho nhiều audience phải ràng buộc audience | Delegated (đạt) | Mỗi realm một khóa ký (E2E-02: 3 issuer, 3 khóa riêng); ID token của Keycloak mang `aud` = client |

### Bảng yêu cầu — V10 OAuth and OIDC

| ID | Yêu cầu (tóm tắt) | Kết luận | Bằng chứng |
|---|---|---|---|
| 10.1.1 | Token chỉ tới thành phần cần nó (BFF giữ token) | Pass | Trình duyệt chỉ có cookie opaque; bảng `sessions` không có cột token (`0002:144-160`); ID / access token không được lưu (`callback.go:183-231`); `use.refresh.tokens=false` (P11: không có refresh token) |
| 10.1.2 | Chỉ nhận code / ID token của giao dịch do cùng user agent khởi tạo; state/nonce/PKCE không đoán được, gắn với trình duyệt | Pass | state, nonce, verifier, binding 256 bit (`login.go:129`); state chỉ lưu hash, dùng một lần (`sessions.sql:32` `ConsumeAuthRequest`); verifier mã hóa bằng khóa dẫn xuất từ state + cookie binding (`tokens.go:77-121`); `TestCallbackSingleUseStateAndBinding`, `TestSealedVerifier` PASS |
| 10.2.1 | Chống CSRF của code flow (PKCE hoặc state) | Pass | Cả hai: S256 (`login.go:149`) và state ràng buộc cookie (`callback.go:122-125`) |
| 10.2.2 | Chống mix-up khi có nhiều AS | Pass | Mỗi IdP một redirect URI `/auth/callback/{idpId}`; `auth_requests.idp_id` phải bằng `{idpId}` trước token call (`callback.go:117-118`); RFC 9207 `iss` (`:142-151`); issuer của discovery khớp chính xác; `TestIdPMixUpRejectedBeforeTokenCall` PASS |
| 10.3.1 | RS kiểm audience của access token | N/A | BFF không là resource server: API không nhận access token, phân quyền theo session BFF |
| 10.3.2 | RS quyết định theo claim ủy quyền | N/A | Như 10.3.1 |
| 10.3.3 | RS định danh user bằng claim không tái gán (`iss` + `sub`) | N/A | Như 10.3.1 (vai trò RP: 10.5.2) |
| 10.3.4 | RS kiểm độ mạnh / thời điểm xác thực của access token | N/A | Như 10.3.1 (vai trò RP: 6.8.4) |
| 10.4.1 | AS so khớp redirect URI chính xác | Delegated (đạt) | Đúng một redirect URI, không wildcard (`check_realm` `:233-241`); P7: thêm hậu tố / thêm query / origin khác ⇒ "Invalid parameter: redirect_uri" — VERIFIED |
| 10.4.2 | Code dùng một lần | Delegated (đạt) | P11: đổi lần 2 cùng code ⇒ 400 `invalid_grant` — VERIFIED |
| 10.4.3 | Code ngắn hạn (≤ 10 phút) | Delegated (đạt) | `accessCodeLifespan 60` (`platform.json.tmpl:44`; `check_realm` **không** kiểm khóa này, chỉ `accessCodeLifespanLogin` ≤ 600); P11: code đổi sau 65 s ⇒ `invalid_grant` — VERIFIED |
| 10.4.4 | Chỉ grant cần thiết; không implicit / password | Delegated (đạt) | `mg-portal` chỉ code, `mg-idp-driver` chỉ client credentials; implicit / direct grant tắt mọi client (`check_realm` `:229-238`); P7: `response_type=token` ⇒ `unauthorized_client` — VERIFIED |
| 10.4.5 | Chống replay refresh token của public client | N/A | Không có public client, không cấp refresh token |
| 10.4.6 | PKCE bắt buộc, không `plain` | Delegated (đạt) | `pkce.code.challenge.method=S256` (`check_realm` `:246`); P7: thiếu PKCE ⇒ `invalid_request`, `plain` ⇒ `invalid_request` — VERIFIED |
| 10.4.7 | Đăng ký client động ẩn danh được kiểm soát | Delegated (đạt) | P3: `POST /realms/{tenant-a,platform}/clients-registrations/openid-connect` qua edge ⇒ 403 (policy "Trusted Hosts" mặc định) — VERIFIED. `check_realm` **không** kiểm policy này (component mặc định của Keycloak) |
| 10.4.8 | Refresh token có hạn tuyệt đối | N/A | Không cấp refresh token (`check_realm` `:247`; P11) |
| 10.4.9 | Thu hồi refresh / reference token qua UI của AS | N/A | Không có refresh / reference token |
| 10.4.10 | Client bí mật xác thực ở back-channel | Delegated (đạt) | `mg-portal` `publicClient: false` (`check_realm` `:242-244`); BFF gửi secret (`provider.go:160-170`); P7: token endpoint không secret ⇒ 401 — VERIFIED |
| 10.4.11 | Chỉ gán scope cần thiết | Delegated (đạt) | `fullScopeAllowed: false`, default scope `basic, acr, profile, email`, không optional scope (`platform.json.tmpl:111, 132-133`; `check_realm` `:242-249`) |
| 10.5.1 | Chống replay ID token (nonce) | Pass | `callback.go:210-212` (so sánh hằng thời gian với nonce của auth request); `TestCallbackSingleUseStateAndBinding` (`nonce_mismatch`) PASS |
| 10.5.2 | Định danh user bằng `sub` không tái gán (theo IdP) | Pass | `(idp_id, sub)` (`0002:97`), không theo email (§8.2); `claims.go:137-140` |
| 10.5.3 | Từ chối metadata có issuer khác issuer cấu hình | Pass | go-oidc `NewProvider` (`oidc.go:328-336`, `IssuerMismatchError`); module không dùng `InsecureIssuerURLContext` (`provider.go:140`) |
| 10.5.4 | `aud` = `client_id` | Pass | `callback.go:202, 213-215`; `TestIDTokenValidation` |
| 10.5.5 | Back-channel logout: `logout+jwt`, `events`, không `nonce` | N/A | Không triển khai back-channel logout. Nếu A-2 được sửa bằng back-channel logout thì phải đạt yêu cầu này |
| 10.6.1 | OP chỉ cho response type code / id_token / id_token code | Delegated (đạt) | P7: `token`, `id_token token` ⇒ `unauthorized_client` — VERIFIED |
| 10.6.2 | OP chống ép đăng xuất | Delegated (đạt) | Keycloak 26 đòi xác nhận khi logout không có `id_token_hint` (mặc định) — PLAUSIBLE, kiểm ở staging (S-6) |
| 10.7.1 | AS đảm bảo người dùng đồng ý | N/A | Chỉ có client first-party bí mật với redirect URI cố định (danh tính client được bảo đảm); `consentRequired: false` có chủ đích |
| 10.7.2 | Nội dung màn hình đồng ý | N/A | Không có màn hình đồng ý |
| 10.7.3 | Xem / sửa / thu hồi đồng ý | N/A | Không có đồng ý nào được cấp |

### Phát hiện vòng 2

Mức: Critical / High / Medium / Low; Info không tính vào gate. Trạng thái của mọi mục: **mở**.

| ID | Mức | Vị trí | Kịch bản thất bại | Hướng sửa | Test chứng minh khi sửa | Nhãn |
|---|---|---|---|---|---|---|
| A-1 | Medium | `internal/httpapi/identityapi/handlers.go:106-120`, `internal/identity/session.go:330-347` (logout chỉ thu hồi phiên BFF); `internal/identity/login.go:147-154` (lần đăng nhập sau logout không có `prompt`, `max_age` = absolute 12 h / 8 h); realm: `frontchannelLogout: false`, không có backchannel logout URL (`platform.json.tmpl:113, 129`). ASVS 7.6.1, 7.1.3 | Nhân sự nền tảng dùng máy chung trong mạng quản trị, bấm Đăng xuất (BFF trả 204, phiên BFF chết). Người kế tiếp mở `admin.<domain>`, bấm đăng nhập: Keycloak còn phiên SSO (idle 15 phút, mỗi lần dùng lại được gia hạn, tối đa 8 giờ) ⇒ trả code ngay, không hỏi mật khẩu, không hỏi OTP ⇒ có session platform của người trước. Tenant Portal (công khai qua VPS) tương tự với phiên SSO 30 phút / 12 giờ. Cả mật khẩu lẫn MFA bị bỏ qua | Logout = OIDC RP-Initiated Logout: `POST /auth/logout` trả URL `end_session_endpoint` của issuer (`id_token_hint` hoặc `client_id`, `post_logout_redirect_uri` đã đăng ký, `state`) thay vì chỉ 204; giữ `sid` / ID token hint phía server (mã hóa) để gửi; đăng ký post-logout redirect URI trong template + `check_realm`. Phòng thủ thêm: lần login đầu tiên sau logout trên cùng trình duyệt luôn gửi `prompt=login`. Ghi vào §8.3 cách phối hợp kết thúc phiên RP–IdP (7.1.3) | Unit: `AuthLogout` trả redirect tới `end_session_endpoint` với `id_token_hint`/`client_id` và `post_logout_redirect_uri` đúng; e2e: lặp lại P1 — sau logout, `GET /auth/login` ⇒ Keycloak hiện form mật khẩu, không 302 về callback | VERIFIED (P1, realm `tenant-a` và `platform`). Đã được ghi nhận ở [P2-T06](P2-T06.md) mục 6 ý 4 / mục 8 ("phase sau") nhưng chưa có task, chưa vào §23 |
| A-2 | Medium | `internal/identity/session.go:379-390` (`RevokeIdentitySessions` không có caller ngoài test); `apps/api/admin.go:80-95` (không có lệnh thu hồi phiên); `internal/idp/keycloak/users.go` `DisableUser` (chỉ đăng xuất phiên Keycloak, chưa có caller); không có back-channel logout. ASVS 7.4.2, 7.4.3, 7.4.5 | Cookie phiên của một Tenant Owner hoặc nhân sự nền tảng bị lấy (máy nhiễm mã độc). Người vận hành khóa user ở Keycloak (`enabled=false` + đăng xuất mọi phiên SSO), chủ tài khoản đổi mật khẩu / OTP ⇒ kẻ tấn công vẫn dùng phiên BFF tới hết absolute (12 h / 8 h), chỉ cần giữ hoạt động trong idle. Phase 2 không có API hay lệnh admin để giết phiên của một identity; đường duy nhất là SQL bằng superuser trên host (`UPDATE identities SET status='disabled' …`), không có trong RUNBOOK cho trường hợp một người | (1) Ngay ở Phase 2/3: lệnh host-only `meshguard admin revoke-sessions --idp <id> --subject <sub>` (và `--all`), tùy chọn `--disable` đặt `identities.status='disabled'`, gọi `RevokeIdentitySessions`, ghi audit `actor_type=system`; thêm vào RUNBOOK mục thu hồi khẩn cấp. (2) P4-T09: khóa / offboard / đổi role thu hồi phiên trong cùng transaction (§8.3 bước 8) + `DELETE /users/{id}/sessions`. (3) Đồng bộ với IdP: back-channel logout của Keycloak tới một endpoint của BFF (đạt 10.5.5) hoặc `idp.audit_sync` (P3-T15) thu hồi phiên khi thấy sự kiện khóa user / đổi credential | Test lệnh admin: X có 2 phiên sống, Y có 1 ⇒ chạy lệnh cho X ⇒ X 401, Y 200, 1 sự kiện audit; e2e: lặp lại P5 — sau khi khóa ở Keycloak (có back-channel) `GET /auth/session` ⇒ 401 | VERIFIED (P5; tìm caller bằng grep) |
| A-3 | Medium | `infrastructure/idp/realms/*.json.tmpl:33` (`passwordPolicy` không có `passwordBlacklist`); `tools/render_idp.py:200-201` (chỉ kiểm length). ASVS 6.2.4 (L1), 6.2.11, 6.2.12, 6.1.2 | Password spraying qua form Keycloak công khai (`auth.<domain>` trên listener tunnel-facing): `Password1234!`, `meshguard2026`… hợp lệ với policy hiện tại (P4). Brute force detection đếm theo từng user nên thử 1–4 mật khẩu phổ biến trên nhiều user không bị khóa. TOTP bắt buộc chặn bước sau, nhưng tài khoản chưa đăng ký TOTP (vừa tạo, chờ đăng nhập lần đầu — `CONFIGURE_TOTP` là required action) bị kẻ đoán đúng mật khẩu chiếm và đăng ký TOTP của chúng | Thêm `passwordBlacklist(<file>)`: danh sách mật khẩu phổ biến / đã lộ (ví dụ top 100 000 đã lọc ≥ 12 ký tự) cộng danh sách từ ngữ cảnh có tài liệu (meshguard, tên sản phẩm, slug tenant, domain, tên realm); file đóng trong image IdP (`infrastructure/docker/idp`) với checksum ghi lại; `check_realm` bắt buộc có `passwordBlacklist`; tài liệu danh sách ở P2-T05 / RUNBOOK (6.1.2). Keycloak không kiểm HIBP sẵn: blacklist file là cách đạt 6.2.12 | `tools/test_render_idp.py` ca âm (thiếu `passwordBlacklist` ⇒ render thất bại); e2e: lặp lại P4 ⇒ 5 mật khẩu bị từ chối (400), mật khẩu ngẫu nhiên vẫn đặt được | VERIFIED (P4) |
| A-4 | Low | Required action `UPDATE_PASSWORD` có `config: {}` (`platform.json.tmpl:86`; tenant như nhau) ⇒ `max_auth_age` mặc định 300 s; tương tự `CONFIGURE_TOTP`, `delete_credential`, `webauthn-register*`. ASVS 6.2.3 (siết 7.5.1) | Trong 5 phút sau khi người dùng đăng nhập (hoặc trên trình duyệt có phiên SSO vừa xác thực), ai cầm trình duyệt đó vào account console đổi mật khẩu mà không cần mật khẩu cũ (P6b: `kc_action_status=success`, mật khẩu cũ không còn dùng được) rồi khóa chủ tài khoản ra ngoài; tương tự gỡ / thêm OTP | Đặt `max_auth_age` = `0` trong config của các required action trên (Keycloak 26.8.2 có tùy chọn này cho từng required action, mặc định 300 — P12) ⇒ luôn xác thực lại; `check_realm` kiểm; mở rộng `reconcileRequiredActions` của driver để sửa drift của config (hiện chỉ kiểm enabled / default action) | `test_render_idp.py` ca âm; e2e: lặp lại P6 ⇒ `kc_action=UPDATE_PASSWORD` ngay sau đăng nhập phải qua bước xác thực lại trước form mật khẩu mới | VERIFIED (P6, P6b; P12: config đang rỗng ⇒ 300 s) |
| A-5 | Low | `internal/identity/session.go:351-375`, `internal/httpapi/identityapi/handlers.go:184-199` (không gọi `RequireRecentAuth`). ASVS 7.5.2 | Kẻ cầm phiên bị đánh cắp (auth_time đã cũ hơn 15 phút) liệt kê và chấm dứt các phiên khác của nạn nhân bằng `DELETE /auth/sessions/{id}`, đá chủ tài khoản ra trong khi giữ phiên của mình, không phải xác thực lại | Với `sessionId` khác phiên hiện tại: gọi `RequireRecentAuth` (401 `reauth_required`, Portal chuyển `reauth=true`); tự kết thúc phiên hiện tại vẫn qua `POST /auth/logout` | Đảo ngược probe `TestProbeRevokeOtherSessionWithoutReauth`: auth_time 16 phút ⇒ 401 `reauth_required`, phiên kia còn sống; sau `reauth` ⇒ 204 | VERIFIED |
| A-6 | Low | `internal/identity/claims.go:159-167` (lưu `acr`/`amr`, không kiểm), `callback.go:228-231`. ASVS 6.8.4 (liên quan 6.3.3) | Realm `platform` bị sửa sai qua break-glass (OTP chuyển `CONDITIONAL`/`DISABLED` — đúng loại drift P2-T05a liệt kê) và trước lần `EnsureIssuer` kế tiếp: nhân sự nền tảng đăng nhập chỉ bằng mật khẩu, BFF vẫn cấp session admin (probe: `amr=["pwd"]`, `acr="0"` ⇒ 200). Với IdP `external` của tenant, không tài liệu nào nói BFF giả định mức tối thiểu (một yếu tố) | Platform scope: đòi bằng chứng MFA trong ID token — LoA/ACR của Keycloak (`acr_values` / claim `acr` essential, ánh xạ LoA vào flow) hoặc mapper `amr`, từ chối khi thiếu; tenant `external`: ghi fallback "coi như một yếu tố" và cờ tùy chọn `required_acr` trên `identity_providers`. Ghi vào §8.2 | Đảo ngược probe `TestProbeSingleFactorPlatformLoginAccepted` ⇒ từ chối (`mfa_required`); ID token có bằng chứng OTP ⇒ đạt; e2e Keycloak: đăng nhập platform có OTP ⇒ claim có mặt | VERIFIED |
| A-7 | Low | Master §8.3; `infrastructure/host/RUNBOOK.md`. ASVS 7.1.2, 6.4.4 | Không có chính sách số phiên đồng thời (credential bị lộ mở bao nhiêu phiên cũng không có tín hiệu); khi nhân sự mất thiết bị TOTP không có quy trình xác minh danh tính trước khi gỡ OTP ⇒ người vận hành có thể bị lừa gỡ OTP cho kẻ giả danh | §8.3: chính sách phiên đồng thời (không giới hạn + hiển thị ở `GET /auth/sessions` + cảnh báo khi > N, hoặc giới hạn N). RUNBOOK: quy trình mất yếu tố MFA — xác minh ngang mức lúc cấp tài khoản (kênh đã biết; hai người với nhân sự nền tảng), xóa credential OTP + thu hồi phiên (A-2), ghi audit | Rà tài liệu ở vòng rà G2 kế tiếp | VERIFIED (không có tài liệu) |
| A-8 | Low | Realm `master` (cấu hình mặc định của Keycloak); `infrastructure/caddy/Caddyfile.tmpl:194-197` (mô tả "CHỈ từ worker"); idp là thành viên `mg-edge`. ASVS 6.3.4 (ghi chú cho 6.3.2, 6.3.3) | Edge chỉ lọc ở tầng HTTP của chính nó. Mọi thành viên `mg-edge` (api, worker, edge, host qua gateway) tới thẳng `idp:8080` bằng HTTP: realm master có `bruteForceProtected=false`, `sslRequired=external`, browser flow mặc định (không OTP), `admin-cli` bật direct grant, admin duy nhất là temporary admin chỉ có mật khẩu (P10). Một tiến trình api bị chiếm có thể đoán mật khẩu admin master không giới hạn tốc độ (thực tế bất khả với 40 ký tự ngẫu nhiên ⇒ Low); console `/admin/` tới được từ trong mạng dù tài liệu nói "không bao giờ" | (Hướng đã có ở P3-T15) thay temporary admin bằng admin cố định có OTP; bật brute force + `sslRequired=all` cho master; tắt direct grant của `admin-cli` master (break-glass qua client riêng có secret); và / hoặc chỉ cho edge + worker tới `idp:8080`; sửa mô tả trong Caddyfile / §8.2 cho đúng thực tế mạng | Test nối mạng: container api ⇒ `idp:8080` bị từ chối (hoặc password grant master ⇒ `unauthorized_client`); Admin API đọc master ⇒ `bruteForceProtected=true`, OTP bắt buộc | VERIFIED (P10; đường `KeycloakAdmin` của harness e2e dùng chính lối này) |
| A-9 | Low | `infrastructure/idp/create-user.sh:9-12, 51` (`"temporary":false`). ASVS 6.4.1 | Người vận hành dùng script tạo tài khoản cho người khác (TO/TA tenant thử, nhân sự khác) và trao mật khẩu qua kênh riêng: mật khẩu do người vận hành sinh trở thành mật khẩu lâu dài mà người vận hành vẫn biết; cộng với `CONFIGURE_TOTP` chờ ở lần đăng nhập đầu, ai dùng mật khẩu trước chủ tài khoản thì đăng ký TOTP của mình | Mặc định `temporary: true` (bắt đổi ở lần đầu — như cách tay ở RUNBOOK dòng 249); chỉ cho `temporary:false` với cờ tường minh `--self` (tài khoản của chính người chạy); hoặc dùng `execute-actions-email` (`UPDATE_PASSWORD` + `CONFIGURE_TOTP`) khi có SMTP | Chạy script trên stack thử ⇒ user mới mang required action `UPDATE_PASSWORD`; đăng nhập lần đầu phải đổi mật khẩu | VERIFIED (đọc script) |

**Info (không tính vào gate):**

| ID | Vị trí | Ghi chú |
|---|---|---|
| I-1 | `infrastructure/caddy/Caddyfile.tmpl:76, 198-221` | Edge không tự chặn `;` trong path của `auth.`: `/realms/master;x=1/…` không khớp `not path /realms/master/*` và được chuyển tới Keycloak; realm master không lộ chỉ vì Keycloak trả `400 invalidCharacter` (P2, P2b). Nên thêm `;` vào `@unsafe_path` của `platform_site` như đã làm với `\` (client của chính dự án đã từ chối `;` — `internal/idp/platform.go` `allowedPath`) |
| I-2 | `infrastructure/host/RUNBOOK.md:249` | Ghi Admin Console tại `https://auth.<domain>/admin/master/console/` "chỉ từ mạng quản trị", nhưng edge không bao giờ định tuyến `/admin/` (E2E-19 ⇒ 404). Sửa RUNBOOK theo đường thật (kcadm trong container / tunnel SSH) |
| I-3 | `internal/devices/service.go:132-136`, §13.1 | `GET …/devices?fresh=true` cho mọi role có `tenant.device:read` (kể cả TV, EU own-only) kích hoạt sync toàn tenant (gọi Headscale, có thể kẹp hạn node với actor system) — là GET có tác dụng phụ, cookie `SameSite=Lax` đi kèm khi điều hướng cấp cao từ site khác. Có giới hạn tần suất class `sync`, không lộ dữ liệu. Cân nhắc đòi `tenant.device:sync` cho `fresh=true` |
| I-4 | `internal/identity/claims.go:144-148` | `email_verified` luôn đọc từ claim `email_verified` kể cả khi `claim_mapping` đổi `email` sang claim khác ⇒ `allowed_email_domains` có thể tin một claim chưa xác minh. Phase 2 không có API sửa `claim_mapping`; nên từ chối map lại `email` khi có ràng buộc domain, hoặc map cả cờ verified |
| I-5 | go-oidc `verify.go:278` | `nbf` có leeway cố định 5 phút (rộng hơn `ClockSkew` 2 phút của module) — `TestProbeNbf`: `nbf` +4 phút ⇒ đăng nhập được. Ảnh hưởng không đáng kể |
| I-6 | `internal/idp/keycloak/users.go` `InviteUser` (`DefaultInviteActions`) | Gọi cho user **đã tồn tại** và đang bật sẽ gửi link action token `UPDATE_PASSWORD` + `CONFIGURE_TOTP`: ai giữ hộp thư đặt lại được cả hai yếu tố (vượt MFA — 6.4.3). Chưa có caller ở Phase 2; P4-T09 không được dùng nó làm đường "đặt lại" khi chưa xác minh danh tính |
| I-7 | `apps/internal/runner/deps.go:286-289` | Adapter `clientSecrets` chỉ nhận tên `idp-client-secret.<id>` (lệnh `set-idp-client-secret`), còn driver `keycloak`/`external` lưu `idp.<id>.client` (`internal/idp/secretref.go:16`, `keycloak/client.go:351, 391`, `external/external.go:151`) và callback chấp nhận cả hai ⇒ IdP do driver tạo (P3 `idp.ensure`) sẽ đăng nhập thất bại kín (`client_secret_unavailable`). Lỗi chức năng, fail closed — không phải lỗ bảo mật |

### Probe

Mọi probe nằm **ngoài repo** (thư mục scratch của phiên rà soát), chạy trên VM build 105; không secret nào được in (mật khẩu, cookie, token, client secret chỉ ở trong tiến trình và tập che của harness). Domain của stack thử viết là `<ci-domain>`.

**Probe test Go** — `asvs_probe_test.go`, chép tạm vào `internal/identity/` của một bản giải nén riêng của cây (`go test -count=1 -v -run TestProbe ./internal/identity/`, PostgreSQL thật):

```go
// ASVS 9.2.1 — nbf: go-oidc v3.21 rejects an ID token whose nbf is beyond its fixed 5-minute leeway.
func TestProbeNbf(t *testing.T) {
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	now := e.clock.Now
	fake.Mutate(func(c map[string]any) { c["nbf"] = now().Add(10 * time.Minute).Unix() })
	b := e.browser()
	wantDenied(t, e, b, appHost, b.login(appHost, "scope=tenant&tenant="+ten.Slug), http.StatusUnauthorized,
		"unauthenticated", "id_token_invalid")
	fake.Mutate(func(c map[string]any) { c["nbf"] = now().Add(4 * time.Minute).Unix() })
	b2 := e.browser()
	rec := b2.login(appHost, "scope=tenant&tenant="+ten.Slug)
	t.Logf("nbf = now+4m (inside go-oidc's 5-minute leeway) ⇒ HTTP %d", rec.Code)
}

// ASVS 7.5.2 — terminating another session of one's own identity needs no re-authentication.
func TestProbeRevokeOtherSessionWithoutReauth(t *testing.T) {
	e := newEnv(t)
	fake := e.fakeIdP()
	ten := e.newTenant(fake)
	q := "scope=tenant&tenant=" + ten.Slug
	b1, b2 := e.browser(), e.browser()
	b1.mustLogin(appHost, q)
	b2.mustLogin(appHost, q)
	e.clock.Advance(8 * time.Minute)
	b1.session(appHost) // touch (idle 30 min)
	e.clock.Advance(8 * time.Minute)
	r1, s1 := b1.session(appHost)
	if r1.Code != http.StatusOK {
		t.Fatalf("b1 session: %d", r1.Code)
	}
	if err := e.svc.RequireRecentAuth(authenticate(t, e, b1, appHost, identity.OriginApp)); err == nil {
		t.Fatal("step-up window not exceeded")
	}
	var l gen.SessionList
	if err := json.Unmarshal(b1.get("https://"+appHost+"/api/v1/auth/sessions").Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	other := uuid.Nil
	for _, it := range l.Items {
		if !it.Current {
			other = it.Id
		}
	}
	del := b1.do(http.MethodDelete, "https://"+appHost+"/api/v1/auth/sessions/"+other.String(), unsafeHeaders(appHost, b1.csrf(appHost)))
	after, _ := b2.session(appHost)
	t.Logf("auth_time %s ago (> step-up 15m): RequireRecentAuth ⇒ reauth_required, yet DELETE /auth/sessions/{other} ⇒ "+
		"HTTP %d; other browser GET /auth/session ⇒ HTTP %d", e.clock.Now().Sub(s1.AuthTime).Round(time.Second), del.Code, after.Code)
	if del.Code != http.StatusNoContent || after.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected: delete %d, after %d", del.Code, after.Code)
	}
}

// ASVS 6.8.4 / 6.3.3 — a staff login whose ID token reports single-factor still yields a session on admin.
func TestProbeSingleFactorPlatformLoginAccepted(t *testing.T) {
	e := newEnv(t)
	fake := e.fakeIdP()
	e.newPlatform(fake)
	fake.Mutate(func(c map[string]any) { c["amr"] = []any{"pwd"}; c["acr"] = "0" })
	b := e.browser()
	b.mustLogin(adminHost, "scope=platform")
	r, s := b.session(adminHost)
	t.Logf("platform login with amr=[pwd], acr=0 ⇒ session HTTP %d, scope %s, origin %s", r.Code, s.Principal.Scope, s.Origin)
	if r.Code != http.StatusOK {
		t.Fatalf("session: %d", r.Code)
	}
}
```

```text
=== RUN   TestProbeNbf
    asvs_probe_test.go:30: nbf = now+10m ⇒ 401 id_token_invalid
    asvs_probe_test.go:34: nbf = now+4m (inside go-oidc's 5-minute leeway) ⇒ HTTP 302
--- PASS: TestProbeNbf (0.84s)
=== RUN   TestProbeRevokeOtherSessionWithoutReauth
    asvs_probe_test.go:69: auth_time 16m0s ago (> step-up 15m): RequireRecentAuth ⇒ reauth_required, yet DELETE /auth/sessions/{other} ⇒ HTTP 204; other browser GET /auth/session ⇒ HTTP 401
--- PASS: TestProbeRevokeOtherSessionWithoutReauth (0.10s)
=== RUN   TestProbeSingleFactorPlatformLoginAccepted
    asvs_probe_test.go:86: platform login with amr=[pwd], acr=0 ⇒ session HTTP 200, scope platform, origin admin
--- PASS: TestProbeSingleFactorPlatformLoginAccepted (0.06s)
ok  	github.com/zhaduchanhzz/network-access-mesh/internal/identity	1.071s
```

**Thăm dò hộp đen** — script Python (thư viện chuẩn) dùng `Browser`, `keycloak_login`, `portal_login`, `KeycloakAdmin` của `tests/e2e/harness/backend.py`: mọi request đi qua edge của stack (Caddy thật, TLS của CA nội bộ của lượt chạy, cookie theo host, không tự theo redirect); tài khoản thử tạo mới ở Keycloak cho từng ca (mật khẩu ngẫu nhiên, TOTP thật). Phần lõi của P1 và P5:

```python
# P1 — đăng xuất Portal rồi đăng nhập lại trên cùng trình duyệt (cookie của auth. còn nguyên), không reauth
sess, steps1 = portal_login(st, b, host, query, u)                      # mật khẩu + đăng ký TOTP
lo = b.request("POST", f"https://{host}/api/v1/auth/logout", b"", {"Origin": f"https://{host}", "X-CSRF-Token": sess["csrf_token"]})
r = b.get(f"https://{host}/api/v1/auth/login?{query}")                  # 302 tới authorization endpoint
k = b.get(r.header("Location"))                                         # Keycloak, với cookie SSO
silent = k.status in (302, 303) and urlsplit(k.header("Location")).hostname == host   # thẳng về callback, không form
# P5 — khóa user ở Keycloak + đăng xuất mọi phiên SSO của user, rồi dùng lại cookie BFF cũ
user = kc._call("GET", f"/admin/realms/tenant-a/users/{sub}"); user["enabled"] = False
kc._call("PUT", f"/admin/realms/tenant-a/users/{sub}", body=user)
kc._call("POST", f"/admin/realms/tenant-a/users/{sub}/logout")
after = b.get(f"{api}/auth/session")                                    # 200 = phiên BFF vẫn sống
```

Kết quả nguyên văn (trích; `<ci-domain>` thay cho domain của stack thử):

```text
PROBE P1-tenant-a FAIL(silent-relogin) — login1 steps ['password', 'configure_totp']; logout 204; session sau logout 401; login lại: prompt=- max_age=43200; Keycloak trả 302 thẳng về callback (không form); callback 302; session mới 200 identity 01a1e905…=01a1e905…; cookie mới khác cũ True
PROBE P1-platform FAIL(silent-relogin) — login1 steps ['password', 'configure_totp']; logout 204; session sau logout 401; login lại: prompt=- max_age=28800; Keycloak trả 302 thẳng về callback (không form); callback 302; session mới 200 identity 01a1e905…=01a1e905…; cookie mới khác cũ True
PROBE P2 FAIL(master-realm-reachable) — /realms/master/.well-known/openid-configuration ⇒ 404; /realms/master;x=1/.well-known/openid-configuration ⇒ 400; /realms/master;/.well-known/openid-configuration ⇒ 400; /realms/MASTER/.well-known/openid-configuration ⇒ 404; /realms/master%3Bx/.well-known/openid-configuration ⇒ 404; /realms/tenant-a;x=1/.well-known/openid-configuration ⇒ 400; /realms/master;x=1/protocol/openid-connect/auth ⇒ 400; /admin;x=1/realms/master ⇒ 404; /admin/master/console;x=1/ ⇒ 404; POST /realms/master;x=1/…/token (admin-cli, password sai) ⇒ 400 invalidCharacter
PROBE P2b INFO — /realms/master;x=1/.well-known/openid-configuration ⇒ 400 ct='application/json; charset=UTF-8' server='' body='{"error":"invalidCharacter","error_description":"Request path contains invalid character \';\'"}' | /realms/tenant-a;x=1/.well-known/openid-configuration ⇒ 400 […cùng thân lỗi invalidCharacter…] | /resources;x=1/master/login/keycloak.v2/css/styles.css ⇒ 404 ct='' server='' body=''
PROBE P3 PASS — tenant-a ⇒ 403 insufficient_scope Policy 'Trusted Hosts' rejected request to client-registration service. Details:; platform ⇒ 403 insufficient_scope Policy 'Trusted Hosts' rejected request to client-registration service. Details:
PROBE P4 FAIL(no-blocklist) — password1234 ⇒ chấp nhận; qwertyuiop123 ⇒ chấp nhận; Password1234! ⇒ chấp nhận; meshguard2026 ⇒ chấp nhận; tenant-a12345 ⇒ chấp nhận
PROBE P5 FAIL(session-survives-idp-disable) — session trước 200; Keycloak: user enabled=false + logout mọi phiên SSO; GET /auth/session sau đó ⇒ 200; GET /auth/sessions ⇒ 200 (1 session sống)
PROBE P6 FAIL(no-current-password) — kc_action=UPDATE_PASSWORD ngay sau đăng nhập: hops [302, 200], trường của form ['password-confirm', 'password-new']; hỏi mật khẩu hiện tại False; POST ⇒ 302; đăng nhập bằng mật khẩu mới: bước [] (lỗi StackError)
PROBE P6b FAIL(no-current-password) — đăng nhập 1: callback 302 bước ['password', 'configure_totp']; form kc_action=UPDATE_PASSWORD: trường ['password-confirm', 'password-new']; POST ⇒ 302 /realms/tenant-a/account/ kc_action_status=success; mật khẩu cũ: bị từ chối (StackError); mật khẩu mới: lỗi StackError: too many Keycloak steps: ['password', 'password', 'password', […]
PROBE P7 INFO — đối chứng (hợp lệ) ⇒ 200 trang đăng nhập; redirect_uri thêm hậu tố ⇒ 400 Invalid parameter: redirect_uri; redirect_uri thêm query ⇒ 400 Invalid parameter: redirect_uri; redirect_uri origin khác ⇒ 400 Invalid parameter: redirect_uri; response_type=token (implicit) ⇒ 302 → app.<ci-domain> error=unauthorized_client (Client is not allowed to initiate browser login with given r); response_type=id_token token ⇒ 302 → app.<ci-domain> error=unauthorized_client (Client is not allowed to initiate browser login with given r); PKCE plain ⇒ 302 → app.<ci-domain> error=invalid_request (Invalid parameter: code challenge method is not matching the); không PKCE ⇒ 302 → app.<ci-domain> error=invalid_request (Missing parameter: code_challenge_method); token endpoint không client secret ⇒ 401 unauthorized_client; grant password (không secret) ⇒ 401 unauthorized_client
PROBE P8a INFO — 11 ký tự ⇒ từ chối (400); 12 ký tự ⇒ chấp nhận; 64 ký tự ⇒ chấp nhận; 128 ký tự ⇒ chấp nhận; 129 ký tự ⇒ từ chối (400); có dấu cách + unicode, 20 ký tự ⇒ chấp nhận
PROBE P8b INFO — input password: type=['password'] autocomplete=['current-password']; onpaste trong trang: False; nút hiện mật khẩu: True
PROBE P8c PASS — đăng nhập 1 bước ['password', 'configure_totp'] callback 302; dùng lại mã của counter vừa dùng (28s sau đầu cửa sổ) ⇒ 200 Keycloak từ chối, form OTP hiện lại
PROBE P9 PASS — SNI app + Host admin ⇒ 421; SNI auth + Host admin ⇒ 421; SNI app + Host auth ⇒ 421; SNI admin + Host app ⇒ 421
PROBE P10 INFO — master: bruteForceProtected=False sslRequired=external browserFlow=browser passwordPolicy=None; users=[{'username': 'mg-bootstrap-admin', 'temporary_admin': ['true'], 'requiredActions': [], 'totp': False}] credentials=[['password']]; admin-cli enabled=True directAccessGrants=True (lấy token master bằng password grant thẳng tới idp:8080 trên network edge — đường của harness — thành công)
PROBE P11 PASS — đổi code lần 1 ⇒ 200 ['access_token', 'id_token'] (không refresh_token: True); dùng lại cùng code ⇒ 400 invalid_grant; code mới đổi sau 65 s ⇒ 400 invalid_grant
PROBE P12 INFO — UPDATE_PASSWORD: tùy chọn [('max_auth_age', 300)]; config hiện tại {'config': {}}; CONFIGURE_TOTP: tùy chọn [('max_auth_age', 300), ('add-recovery-codes', False)]; config hiện tại {'config': {}}; delete_credential: tùy chọn [('max_auth_age', 300)]; config hiện tại {'config': {}}
```

Ghi chú đọc kết quả: P2 in nhãn `FAIL` do điều kiện của script quá rộng (coi mọi mã khác 404 là lộ); P2b cho thấy 400 đến từ chính Keycloak (`invalidCharacter`), không có nội dung realm master nào lộ ⇒ kết luận: không lộ, chỉ còn ghi chú I-1. Ở P6, bước đăng nhập lại của script dùng một đối tượng TOTP mới không có khóa đã đăng ký nên không qua được bước OTP (lỗi của script — làm lại ở P6b). Ở P6b, bước "đăng nhập bằng mật khẩu mới" thất bại vì lần thử mật khẩu cũ ngay trước đó (script gửi lại form nhiều lần) đã làm brute force detection khóa tạm user; lần gửi mật khẩu cũ đầu tiên đã bị từ chối khi user chưa có lần sai nào. `kc_action_status=success` cộng mật khẩu cũ bị từ chối là đủ chứng minh mật khẩu đã đổi mà không cần mật khẩu cũ.

### Kết luận cho gate G2

**Số mục High / Critical còn mở: 0.** Theo vòng rà độc lập này (ASVS 5.0.0 L2: V6, V7, V8 và phần relying party của V9/V10, trên `03509d3`), tiêu chí G2 "0 mục Cao còn mở" **đạt**.

Điều kiện kèm, nói thẳng:

1. Có **3 Medium thật, VERIFIED** (A-1, A-2, A-3) và 6 Low. Chúng không chặn G2 theo chữ của tiêu chí, nhưng chủ dự án cần quyết định rõ cho từng mục: sửa trước khi Portal có người dùng thật (khuyến nghị: A-2 lệnh thu hồi khẩn cấp ngay ở Phase 3; A-1 và A-3 trước P4 / trước go-live), hoặc chấp nhận tạm và ghi vào §23.
2. Kết luận dựa trên stack dev/CI (nhãn functional) cùng code và template; các mục ở "Kiểm cần staging" dưới đây **chưa chạy**. Nếu kiểm trên staging phát hiện lỗi mức Cao, kết luận này phải sửa lại trước khi chủ dự án ký G2.

### Kiểm cần staging (hộp đen qua edge LAN — chờ người điều phối báo đã triển khai)

| ID | Kiểm | Kỳ vọng | Liên quan |
|---|---|---|---|
| S-1 | SNI một origin + Host origin khác giữa `app.`/`admin.`/`auth.` trên listener LAN-direct, và qua điểm vào công khai (VPS) | 421 hoặc đóng kết nối; không request nào tới api với origin `admin` | P9, 8.4.1 |
| S-2 | `admin.<domain>` từ nguồn ngoài `admin_allow` (LAN khác, qua VPS) và từ nguồn được phép | Đóng kết nối / không có bản ghi DNS công khai; nguồn được phép ⇒ 401 problem+json | 8.2.1 |
| S-3 | `auth.<domain>` qua LAN và qua VPS: realm master, `/admin/…`, biến thể `;`, `%2e%2e`, `\`, chữ hoa; `/metrics`, `/health` | 404 / 400 (`invalidCharacter`), không nội dung realm master | I-1, A-8 |
| S-4 | Cấu hình realm **đang chạy** (đọc qua Admin API từ worker hoặc kcadm trong container): `passwordPolicy`, brute force, OTP policy, flow `mg-browser`, SSO, `accessCodeLifespan`, config của required action, client registration policy, realm master | Khớp template; xác nhận A-3, A-4, A-8 trên bản thật | A-3, A-4, A-8 |
| S-5 | Đăng nhập thật app./admin. bằng tài khoản thử: Fetch-Metadata cross-site của `GET /auth/login` bằng trình duyệt thật ⇒ 403; cookie `__Host-` (Secure, HttpOnly, SameSite=Lax, không Domain); đăng xuất ⇒ 401; **đăng nhập lại sau đăng xuất** | A-1 tái hiện trên staging (Keycloak trả code không hỏi credential) | A-1, 7.4.1, 7.6.2 |
| S-6 | Keycloak `end_session_endpoint` không `id_token_hint` | Trang xác nhận, không đăng xuất ngầm | 10.6.2 |
| S-7 | Khóa user thử ở Keycloak khi đang có phiên BFF | A-2 tái hiện (phiên BFF còn 200) | A-2 |
| S-8 | P7 + P11 trên realm thật: redirect URI chính xác, implicit, PKCE plain / thiếu, token endpoint không secret, code dùng lại, code quá 60 s | Như P7 / P11 | 10.4.x |
| S-9 | DCR ẩn danh `POST /realms/<r>/clients-registrations/openid-connect` qua LAN và VPS | 403 | 10.4.7 |
| S-10 | `X-Forwarded-For` giả từ client qua edge; `GET /auth/sessions` của phiên vừa tạo | Trường `ip` = IP thật của client (theo edge), không phải giá trị giả | 7.5.2, F2 vòng 1 |
| S-11 | Giới hạn tần suất class `auth` qua edge (vượt burst) | 429 + `Retry-After` | 6.3.1 |
| S-12 | Header của `app.`/`admin.`/`auth.`: HSTS, CSP, `X-Content-Type-Options`, không `Server`; `Cache-Control: no-store` trên `/api/v1/auth/*` | Có đủ | 7.x (phòng thủ chiều sâu) |
| S-13 | Account console `/realms/<r>/account` qua VPS: đổi mật khẩu ngay sau đăng nhập | A-4 tái hiện (không hỏi mật khẩu cũ) | A-4, 6.2.2 |

### Ghi chú môi trường của người rà soát (để chạy lại)

- VM build 105, tài nguyên tiền tố `asvs`: container `asvs-pg` (PostgreSQL pin digest), network `asvs-net`, volume `asvs-gomod`, `asvs-gocache`, stack e2e `asvse2e-*`, thư mục `~/asvs`, `~/asvs-secrets` (mật khẩu superuser dùng một lần). Kịch bản trong thư mục scratch của phiên rà soát: `asvs-vm-setup.sh` (bản sao `mainv-vm-setup.sh`, đổi tiền tố), `asvs-go.sh suite|probe|src` (mẫu `gorun` của `mainv-verify.sh`), `asvs-e2e.sh up|test|probe`, probe `asvs-probe/identity/asvs_probe_test.go`, `asvs-probe-e2e.py` (P1–P6), `asvs-probe-e2e2.py` (P2b, P6b, P7), `asvs-probe-e2e3.py` (P8), `asvs-probe-e2e4.py` (P9), `asvs-probe-e2e5.py` (P10), `asvs-probe-e2e6.py` (P11), `asvs-probe-e2e7.py` (P12), dọn bằng `asvs-cleanup.sh`.
- Probe P1, P3–P9, P11 dùng lại được cho staging bằng cách thay `Stack()` (địa chỉ edge, CA) bằng địa chỉ edge LAN và CA công khai; P5, P10, P11 cần quyền Admin API (chỉ chạy trên stack thử, hoặc trên staging với tài khoản thử và đường worker).
