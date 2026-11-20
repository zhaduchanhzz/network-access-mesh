# Portal Design (Super Admin / Tenant Admin)

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §12. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 12. Super Admin / Tenant Admin Design

### 12.1 Một Web Management Platform, hai phạm vi

Một bản build SPA, phục vụ trên hai origin: **Platform Console** `admin.<domain>` (có thể giới hạn IP/VPN ở edge) và **Tenant Portal** `app.<domain>`. Điều hướng theo role (role-aware navigation) và mọi view tenant đều gắn `tenantId` (tenant-aware views). Tất cả đi qua **một** SaaS Backend; browser không bao giờ gọi Headscale và không giữ Headscale API key. Ẩn/hiện menu ở frontend chỉ là UX — quyền được quyết định ở server (§8.8).

### 12.2 Platform Super Admin — chức năng → màn hình → API

| Chức năng | Màn hình | API chính | Kiểm soát |
|---|---|---|---|
| Quản lý tất cả tenant; tạo/sửa/xóa | Tenants (danh sách, chi tiết, wizard tạo) | `GET/POST/PATCH/DELETE /platform/tenants` | Xóa: dual control + step-up |
| Provision Headscale instance | Tenant wizard → Job timeline | `POST /platform/tenants` → `GET /platform/jobs/{id}` | Hiển thị từng step; retry/cancel/rollback |
| Theo dõi health | Platform Health; Instance detail | `GET /platform/health`, `/platform/instances` | Số liệu thật, có `checked_at` |
| Cluster/host placement | Hosts (capacity, instance theo host) | `/platform/hosts` | — |
| Relay regions | Relay Regions | `/platform/relay-regions` | Ở MVP chỉ đọc (embedded theo tenant) |
| Billing & usage | Usage, Plans | `/platform/usage`, `/platform/plans` | Không có số liệu traffic P2P |
| System configuration | Settings | `/platform/settings/{key}` | SA; audit + ETag |
| Quota | Plan + override theo tenant | `PATCH /platform/tenants/{id}`, `/platform/plans` | — |
| Identity providers | Identity Providers | `/platform/identity-providers` | SA; step-up; IdP của tenant: tenant duyệt hoặc 2P (§8.2) |
| Platform roles | Platform Users | `/platform/users` | Gán SA: 2P |
| Security events | Security Events | `/platform/security-events` | — |
| Thao tác hỗ trợ tenant có audit | Support Access (yêu cầu, break-glass) | `/platform/support-grants` | §8.7 — không có "vào thẳng tenant" |
| Vận hành instance | Instance actions (restart, reconfigure, upgrade, backup, restore, quarantine/release) | `/platform/instances/{id}/<action>` | Restore, release: 2P |

Super Admin **không** mặc định xem được thiết bị/policy/audit nội bộ của tenant và **không** có khả năng giải mã payload WireGuard (§8.7).

### 12.3 Tenant Admin — chức năng → màn hình → API

| Chức năng | Màn hình | API chính | Ghi chú thực tế |
|---|---|---|---|
| Tenant Dashboard | Tổng quan | `/dashboard` | Mọi số có `synced_at`; không có số giả |
| Device Management | Devices (lọc, chi tiết, rename, tag, expire, delete) | `/devices…` | Không có OS/phiên bản client/endpoint từ Headscale API (HS-14) — cột này **không hiển thị** thay vì hiển thị giá trị giả |
| User & Group Management | Users, Groups | `/users…`, `/groups…` | Group được biên dịch vào policy |
| Device Enrollment | Add device (hướng dẫn theo OS, claim web-auth) | `/enrollment/requests`, `/enrollment/web-auth/claim`, `/enrollment/instructions` | §7.4 |
| Enrollment Key Management | Enrollment keys (pre-auth: tạo, hạn, thu hồi) | `/enrollment/keys`, `/enrollment/requests…` | Key hiển thị một lần |
| Access Policies | Policies (editor, lint, diff, lịch sử, duyệt, apply, rollback), Danh mục tag | `/policies…`, `/tags` | §7.3; editor form trên `PolicySource` + chế độ HuJSON qua bộ dịch phía server (`/policies/import`, `/export` — P4-T11); template least-privilege (`/policies/templates` — P5-T01) và các ca `tests` sinh tự động trong báo cáo kiểm tra |
| DNS/MagicDNS | DNS settings, Records | `/dns…` | Đổi settings ⇒ restart instance có kiểm soát (thông báo trước) |
| Subnet Routes / Exit Nodes | Routes (quảng bá vs đã duyệt, cảnh báo chồng lấn) | `/routes…` | Double opt-in (PL-10) |
| Network Resource Catalog | Resources | `/resources…` | Sinh alias `hosts` |
| Connectivity Diagnostics | Diagnostics | `/diagnostics…` | Trạng thái control plane + checklist lệnh chạy trên client (§9.5) |
| Usage Monitoring | Usage | `/usage` | **Sau MVP** — Phase 6 (P6-T11); trước đó màn hình hiển thị "không khả dụng" (§12.4). Thiết bị, user, key, relay (xấp xỉ) |
| Audit Logs | Audit | `/audit` | Gồm cả hành động của support |
| Tenant Settings | Settings, Identity Provider, Support Access, Approvals (hàng chờ phê duyệt) | `/settings`, `/settings/security`, `/approvals`, `/identity-provider`, `/support-grants`, `/approvals` | — |

End User chỉ thấy: thiết bị của mình, thêm/xóa thiết bị của mình, hướng dẫn kết nối.

**Truy vết màn hình → task** (màn hình của §12.2–§12.3; API tương ứng xem bảng truy vết ở §13.2). Màn hình ghi "Sau MVP" hiển thị trạng thái "không khả dụng" cho tới khi task hoàn tất (§12.4).

| Màn hình | Task UI | Phạm vi |
|---|---|---|
| Tenants (danh sách, chi tiết, wizard), Job timeline, hàng chờ phê duyệt 2P | P4-T02 | MVP |
| Platform Health, Instances + Instance actions, Hosts, Jobs, Settings, Platform Users, Identity Providers, Relay Regions (chỉ đọc), Plans | P4-T03 | MVP |
| Support Access (platform và tenant), Audit, Tenant Settings / Identity Provider, hàng chờ phê duyệt trong tenant | P4-T13 | MVP |
| Tổng quan (dashboard), Devices, mục Relay, hộp thông báo | P4-T04 | MVP |
| Add device (wizard theo OS, trang claim), Enrollment keys | P4-T08 | MVP |
| Users, Groups, Invitations | P4-T09a | MVP |
| Policies | P4-T11 | MVP |
| Routes, DNS, Resources | P4-T12 | MVP |
| Diagnostics | P5-T08 | MVP |
| Security Events | P6-T02a | Sau MVP (Phase 6) |
| Usage (tenant và platform), Billing | P6-T11 | Sau MVP (Phase 6) |
| Backups | P6-T04 | Sau MVP (Phase 6) |
| Gỡ ban CrowdSec | P6-T07a | Sau MVP (Phase 6) |

### 12.4 Kiến trúc WebUI

| Chủ đề | Quyết định |
|---|---|
| Framework | React + TypeScript (strict) + Vite; React Router; TanStack Query — **mọi query key bắt đầu bằng `tenantId`** để không lẫn cache giữa tenant |
| Type-safe API | Client sinh từ `api/openapi.yaml` (`openapi-typescript` + `openapi-fetch`); CI fail nếu lệch |
| Responsive | Bố cục desktop-first, dùng được trên tablet/mobile cho thao tác thu hồi khẩn cấp |
| Theme | Dark/Light theo design token; tôn trọng `prefers-color-scheme` |
| i18n | Vietnamese + English; không hardcode chuỗi; định dạng ngày/số theo locale; lưu ý quy tắc số nhiều tiếng Việt (ST-03) |
| Accessibility | Component có sẵn ARIA (Radix/React Aria); điều hướng bàn phím; mục tiêu WCAG 2.1 AA; kiểm bằng axe trong E2E |
| Bảo mật trình duyệt | Chỉ cookie session HttpOnly; không token trong `localStorage`; CSP chặt (không inline script, không CDN bên thứ ba); `frame-ancestors 'none'` |
| Trạng thái dữ liệu | Hiển thị `synced_at`, trạng thái job, "pending/applied/failed" cho thu hồi và policy; **không dùng mock metrics** — tính năng không có nguồn dữ liệu hiển thị trạng thái "không khả dụng" kèm lý do |
| Realtime | MVP: polling qua TanStack Query; WebSocket/SSE là Phase 4+ |

### 12.5 Tái sử dụng từ Repository 2 (theo ADR-16, MIT, có ghi công)

Được phép tham khảo/port sau khi review từng file: quy trình draft → validate → acknowledge (allow-all/deny-all) → drift banner; lịch sử version và diff; `VisualEditor` cho rule (mở rộng sang grants); primitives UI; bố cục trang Connect. **Không** tái dùng: evaluator ACL, access matrix N², raw editor dạng textarea, mọi contract backend.
