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

**Không thấy lỗi mức Critical/High** ở cả 7 vùng. Có 3 lỗi Medium và 1 lỗi Low. Không lỗi nào chặn G2 theo tiêu chí §19, nhưng cả 4 lỗi được lên lịch sửa trước khi nộp báo cáo G2.

### Phát hiện

| ID | Mức | Vị trí | Lỗi | Kịch bản thất bại | Hướng sửa | Nhãn | Trạng thái |
|---|---|---|---|---|---|---|---|
| F1 | Medium | `internal/identity/login.go:70-137`, `middleware.go:90-91`, `callback.go:244-248` | Login CSRF: `GET /auth/login` không kiểm Fetch-Metadata. Callback thu hồi session hiện tại ngay cả khi identity mới khác identity cũ | Tenant Owner xấu (cùng actor T-20) có IdP `external` tự cấp code cho `sub` của mình. Một trang ngoài điều hướng nạn nhân tới `/api/v1/auth/login?scope=tenant&tenant=<evil>`: session thật của nạn nhân bị thu hồi, nạn nhân âm thầm thành session của tenant kẻ tấn công. Từ Phase 4, thiết bị nạn nhân enroll sẽ vào tailnet có policy do kẻ tấn công kiểm soát | Từ chối `authLogin` khi `Sec-Fetch-Site` ∉ {`same-origin`, `none`}. Không thu hồi session của một identity khác mà không có bước xác nhận | Đường code VERIFIED; khai thác PLAUSIBLE (cần một IdP `external` đã đăng ký) | Chưa sửa — lên lịch |
| F2 | Medium (nặng hơn mức P2-T08 §4 ghi nhận) | `internal/identity/middleware.go:90-97`, `login.go:58-61`, `callback.go:52-56`, `auditapi/identity.go:30-37`, `httpapi/ratelimit.go:47-50` | Request ẩn danh bị từ chối vẫn ghi hàng append-only vào `audit_events` (`RecordDetached`). Rate limit theo IP không đủ chặn | `POST` với `Origin` lạ ở hạn mức mặc định (50/s, burst 300 mỗi IP hoặc /64) cho khoảng 4,3 triệu hàng/ngày/IP, không xóa được trước khi hết retention (≥ 400 ngày). Nhiều IP hoặc dải IPv6 làm đầy đĩa PostgreSQL dùng chung (T-11). `auditapi` đã bỏ 401 ẩn danh vì đúng lý do này, nhưng module identity thì không | Từ chối trước khi có identity: gộp theo (IP/64, lý do, cửa sổ thời gian) thành một hàng kèm bộ đếm, hoặc chuyển sang metric + `security_events` có dedupe. Giữ audit từng hàng khi đã có identity | Đường code VERIFIED; độ lớn PLAUSIBLE | Chưa sửa — lên lịch |
| F3 | Medium | `internal/identity/config.go:37-42`, `callback.go:153-161`, `database/migrations/0002_identity_rbac.sql:65`, `internal/idp/external/external.go:130-142, 168-180` | `client_secret_ref` của IdP không bị ràng buộc với chủ của IdP. DB chỉ CHECK định dạng; driver `external` Get/Destroy ref do caller đưa vào | Nếu ref của IdP tenant A bị ghi thành `mgsec://<B>/headscale-api-key#1` (lỗi SQL ở pool platform, API `PATCH /identity-provider` sau này, hoặc vận hành sai): callback giải mã API key Headscale của B và gửi nó làm `client_secret` tới IdP do A kiểm soát. `RemoveIssuer(purge)` còn hủy secret của B | Kiểm `ref.Tenant == IdP.TenantID` (hoặc platform với scope platform) và tên ref đúng của IdP đó, trong callback và driver `external`. Thêm DB CHECK owner-segment theo `tenant_id`. Adapter `ClientSecrets` của P2-T16 cũng kiểm | PLAUSIBLE (cần quyền ghi cột) | Chưa sửa — phần adapter giao P2-T16, phần còn lại lên lịch |
| L1 | Low | `internal/headscale/registry.go:139-147`, `locator/locator.go:126-138` | `CachingRegistry` cache Target 60 s. Trạng thái tenant/instance chỉ được kiểm lúc Locate | Tenant bị suspend hoặc instance bị quarantine thì job/sync vẫn gọi Headscale tối đa 60 s | `Invalidate` ở mọi chuyển trạng thái vòng đời, hoặc kiểm trạng thái rẻ ở mỗi `ForTenant` | VERIFIED (tác động Phase 2 thấp: chưa có API suspend) | Chưa sửa — lên lịch |

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
