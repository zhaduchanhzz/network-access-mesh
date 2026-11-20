# G4b — báo cáo gate (Phase 4, P4-T14)

> **Trạng thái:** **Go** theo quy tắc chủ dự án ký ngày 2026-11-20 ("Ký G4a ngay, G4b tự động": G4b là Go khi báo cáo
> xanh và không có phát hiện mức Cao/Nghiêm trọng). Báo cáo này xanh, 0 phát hiện Cao/Nghiêm trọng. Vòng khám phá trên
> staging (mục 5) làm sau đợt nâng staging 3 và ghi bổ sung; nếu vòng đó tìm ra phát hiện Cao ⇒ trạng thái quay về "chờ
> chủ dự án".

## Tiêu chí G4b (master §19, Go/No-Go G4)

"**G4b:** toàn bộ E2E xanh (hai vai trò, hai ngôn ngữ, axe); rà soát UX bảo mật theo checklist: key hiển thị một lần;
lời nhắc step-up; cách diễn đạt trạng thái hai pha; không secret trong DOM/storage; xác nhận thao tác phá hủy."

| Tiêu chí | Kết quả | Bằng chứng |
|---|---|---|
| Toàn bộ E2E xanh — hai vai trò, hai ngôn ngữ, axe | **Đạt** — Playwright 220 test (4 setup + 108 × 2 project `vi` sáng / `en` tối; Platform Super Admin, Tenant Owner, Tenant Admin, End User, khách), **hai lượt liên tiếp 220/220, 0 fail, 0 flaky, 0 skip**; axe WCAG 2.1 AA 0 vi phạm ở mọi mức; PW-S (artifact không secret) PASS | [P4-T14](P4-T14.md) mục 2, 4 |
| E2E chức năng của backend | **Đạt** — `e2e.py all` 90/90 (gồm enrollment E2E-99…101, 117…120, C4) trong chuỗi kiểm chứng main | `current.md` (lượt `91b118b`) |
| (a) Key/credential hiển thị một lần | **Đạt** — pre-auth key, mã enrollment, Auth ID, lệnh sau `/start`, client secret IdP | P4-T14 mục 3 (a) |
| (b) Lời nhắc step-up đúng chỗ, thao tác tiếp tục sau step-up | **Đạt** — đổi role chạm Admin/Owner, xin + duyệt Support Access Grant, xóa tenant (2P) | P4-T14 mục 3 (b) |
| (c) Diễn đạt trạng thái hai pha | **Đạt** — xóa/thu hồi thiết bị, offboard, policy "đã áp dụng lên Headscale" ≠ "client đã hội tụ", thu hồi key | P4-T14 mục 3 (c) |
| (d) Không secret trong DOM/storage/URL/console | **Đạt** — `checkNoSecrets` sau mọi luồng nhạy cảm, `checkBrowserStorage` sau mọi lần đăng nhập, PW-S | P4-T14 mục 3 (d) |
| (e) Xác nhận thao tác phá hủy | **Đạt** — 12 loại thao tác: hộp `alertdialog` nêu đối tượng + hậu quả, focus vào Hủy, Esc/Hủy không thực hiện, thao tác có gõ lại tên/lý do | P4-T14 mục 3 (e) |
| C4 — nhân viên có Support Access Grant duyệt enrollment | **Đạt** | P4-T14 mục 3 (hàng C4) |

## Phát hiện

| # | Phát hiện | Mức | Xử lý |
|---|---|---|---|
| 1 | Hộp thoại modal để lọt nhãn "Dismiss" (tiếng Anh) của React Aria trên giao diện tiếng Việt | Thấp | Đã sửa |
| 2 | Bấm ra ngoài hộp pre-auth key đóng hộp ⇒ mất key một lần | Thấp | Đã sửa |
| 3 | 2 nút có tên truy cập không chứa nhãn hiển thị (WCAG 2.5.3) | Thấp | Đã sửa |
| 4 | 403 của nhân viên hỗ trợ (grant hết hạn) không nêu lý do | Thấp | Đã sửa |
| F-G4a-1 | Rate limit enrollment chung GET + POST claim ⇒ 429 khi thao tác nhanh | Thấp | Trang claim tự gửi lại một lần sau `Retry-After`; tách bucket ở P6-T07 |

**0 phát hiện Cao/Nghiêm trọng.**

## Phần chỉ là functional / giới hạn

- Playwright chạy trên stack dev/CI một host (Chromium của image Playwright pin digest, client Tailscale chính thức
  trong container) — **functional** (§22.1).
- Không chạy trong Playwright (cùng cơ chế UI đã chứng minh, có Vitest): apply policy khi tenant bật 4-eyes, đổi IdP,
  thiết lập bảo mật, duyệt yêu cầu dual control, break-glass (P4-T14 mục 7).
- Trên staging với trình duyệt thật: luồng Owner (đăng nhập + TOTP, Devices, Policies, Audit, Add device → trang claim)
  đã chạy ở G4a mục 2.6.

## 5. Vòng khám phá trên staging (agent-browser)

_Chờ đợt nâng staging 3 (web có các bản sửa của mục Phát hiện)._ Phạm vi: đi qua các màn hình chính của `app.` và
`admin.` (nay public) bằng trình duyệt thật, chụp ảnh, ghi lỗi UX/i18n/a11y; lỗi tìm được ⇒ spec Playwright.

## Chủ dự án duyệt

| Vai trò | Quyết định | Ngày |
|---|---|---|
| Chủ dự án | **Go** theo quy tắc ký trước ngày 2026-11-20 ("Ký G4a ngay, G4b tự động" — xanh, 0 phát hiện Cao) | 2026-11-20 |
