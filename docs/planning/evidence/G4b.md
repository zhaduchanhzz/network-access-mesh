# G4b — báo cáo gate (Phase 4, P4-T14)

> **Trạng thái: CHỜ CHỦ DỰ ÁN.** Vòng khám phá trên staging (mục 5, 2026-11-20) tìm ra **1 phát hiện mức Cao —
> G4b-E1**: trên tenant mới provision, mời thành viên (IdP do nền tảng host) không hoàn tất — realm Keycloak của tenant
> mới không có SMTP nên thư thiết lập tài khoản không gửi được (`idp_email_failed`), và lời mời Owner ở bước 16 không tạo
> tài khoản IdP ⇒ người được mời không đăng nhập được nếu người vận hành không can thiệp trên host. Theo quy tắc "Ký G4a
> ngay, G4b tự động" (Go chỉ khi xanh và 0 phát hiện Cao/Nghiêm trọng), G4b quay về chờ chủ dự án quyết định. Phần
> Playwright + checklist UX bảo mật bên dưới vẫn xanh (0 phát hiện Cao).

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

**0 phát hiện Cao/Nghiêm trọng** trong phần Playwright/checklist. Vòng khám phá trên staging (mục 5): **1 Cao (G4b-E1)**,
3 Trung bình, 14 Thấp.

## Phần chỉ là functional / giới hạn

- Playwright chạy trên stack dev/CI một host (Chromium của image Playwright pin digest, client Tailscale chính thức
  trong container) — **functional** (§22.1).
- Không chạy trong Playwright (cùng cơ chế UI đã chứng minh, có Vitest): apply policy khi tenant bật 4-eyes, đổi IdP,
  thiết lập bảo mật, duyệt yêu cầu dual control, break-glass (P4-T14 mục 7).
- Trên staging với trình duyệt thật: luồng Owner (đăng nhập + TOTP, Devices, Policies, Audit, Add device → trang claim)
  đã chạy ở G4a mục 2.6.

## 5. Vòng khám phá trên staging (agent-browser)

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-20, 03:30–03:58 UTC |
| Môi trường | **staging** sau đợt nâng 3 (web/api/worker `91b118b`, pin ở `versions.lock` @ `9697f39`); `app.<domain>` và `admin.<domain>` qua DNS công khai → VPS → tunnel → edge |
| Trình duyệt | Chrome 157 headless (agent-browser 0.42.0, phiên riêng `g4b-explore`, `allowedDomains` = `*.<domain>`) trên máy vận hành |
| Tenant thử | `g4bx-a2f1` — provision 03:32:41 (SA1), deprovision 2P 03:57:19 (SA1 yêu cầu, SA1 tự duyệt ⇒ 403, SA2 duyệt ⇒ job 15 bước, `deleted`) |
| Tài khoản | SA thử `g3-sa1`/`g3-sa2`; Owner `g4bx-owner` và End User `g4bx-enduser` (tạo bằng `create-user.sh`, e-mail `<tên>@<slug>.example.invalid`); mật khẩu/TOTP chỉ trong tiến trình + file 0600 ở máy vận hành (đã xóa); điền form Keycloak qua CLI agent-browser từ script, không in ra |
| Thiết bị | VM 105 (`tailscaled` hệ thống, Tailscale chính thức) — web-auth: lệnh do trang Thêm thiết bị tạo ⇒ link ⇒ mở trong cùng trình duyệt ⇒ trang claim xác nhận **bằng bàn phím** ⇒ `verified`, Online |
| Ảnh chụp | ~120 ảnh (toàn trang) + văn bản trang, ở scratchpad của phiên — **không commit** (chứa domain/IP thật) |

### 5.1 Phạm vi đã đi

| Origin / vai trò | Màn hình | Ngôn ngữ × theme × kích thước |
|---|---|---|
| `app.` — Tenant Owner | 22 route của menu (Tổng quan, Thông báo, Thiết bị, Thêm thiết bị, Enrollment key, Policy, Tag, Relay, Routes, DNS, Tài nguyên mạng, Chẩn đoán, Người dùng, Nhóm, Lời mời, Audit, Chờ phê duyệt, Support Access, Thiết lập, Identity Provider, Mức sử dụng, Gói) + 3 trang 404 (route lạ trong tenant, route lạ ngoài tenant, tenant id lạ) — **trạng thái rỗng** | en × sáng (theo hệ thống) × 1440 px; vi × tối × 390 px |
| | 16 trang **có dữ liệu** (gồm chi tiết thiết bị, chi tiết policy version, chi tiết group) | en × tối × 390 px |
| | Luồng thao tác thật: mời thành viên, Thêm thiết bị + trang claim, khai báo tag, tạo group + thêm thành viên, DNS record (giá trị sai ⇒ thông báo lỗi, rồi giá trị đúng), tài nguyên mạng, policy draft → kiểm tra → duyệt → áp dụng; validate ô nhập (nhãn thiết bị, tên tag); hộp thoại: mời, tạo group, thêm tài nguyên (Esc), duyệt, áp dụng, xóa thiết bị (chỉ mở — Tab/Shift-Tab trong hộp, Esc) | vi × sáng × 1440 px |
| `app.` — End User | 9 route (Thông báo, Thêm thiết bị + thử tạo lệnh, và 7 route quản trị gõ thẳng URL) | vi × sáng × 1440 px |
| `app.` — khách | trang đăng nhập; slug không tồn tại, slug tenant đã xóa, slug viết hoa + khoảng trắng; Đăng xuất ⇒ đăng nhập lại (phiên IdP đã kết thúc?) | vi/en × sáng × 1440 px |
| `admin.` — Super Admin | 17 route (Platform Health, Tenant, chi tiết tenant, Relay Region, Nhân sự, IdP, Chờ phê duyệt, Thiết lập, Support Access, Audit, Security events, Job, Instance, Host, Plan, Usage, Backup) + 404 + route tenant của Portal trên `admin.` | en × sáng × 1440 px |
| | 14 route + wizard Tạo tenant (bước 1) + bộ chọn tenant của Support Access | vi × tối × 390 px |

Không chạy lại phần Playwright đã phủ (P4-T14: hộp xác nhận phá hủy, step-up, key một lần, C4…); không thực hiện thao tác
phá hủy ngoài tenant thử; tenant-a/b chỉ thấy trong danh sách của Console (không mở, không đổi).

### 5.2 Phát hiện

| # | Màn hình / bước tái hiện | Phát hiện | Mức | Xử lý đề xuất |
|---|---|---|---|---|
| **G4b-E1** | Tenant mới provision ⇒ Owner: Người dùng ⇒ Mời thành viên (End User) ⇒ Gửi lời mời ⇒ trang Lời mời | Banner "Đã gửi lời mời", cột IdP **"Thất bại `idp_email_failed`"** (không lời giải thích). Worker: job `member.idp_invite` failed; Keycloak `KC-SERVICES0088 Failed to send execute actions email` — *Invalid sender address 'null'*: realm do `idp.ensure` tạo từ `internal/idp/keycloak/realm.json.tmpl` **không có `smtpServer`** (chỉ realm render tĩnh `platform`/`tenant-a`/`tenant-b` có, qua `render_idp.py` + `realm-update.sh`). User được tạo kèm required actions nhưng không có mật khẩu; realm tắt registration và reset password ⇒ **người được mời không đăng nhập được**. "Gửi lại" gặp cùng lỗi. Thêm: lời mời Owner ở bước 16 (`orchestrator/dbstore.go` `Configure`) chỉ enqueue thư nền tảng, **không** `member.idp_invite` (cột IdP "chưa có job") ⇒ Owner của tenant mới không có tài khoản IdP trừ khi người vận hành chạy `create-user.sh` trên host (G4a và lượt này đều làm vậy). Đây là `member.idp_invite` đầu tiên trên staging trong 72 h (log worker) ⇒ chưa từng được chạy trên staging | **Cao** — chặn luồng chính (onboarding Owner/thành viên với IdP do nền tảng host) ở **mọi** tenant mới | (1) `idp.ensure` đặt `smtpServer` cho realm mới như `render_idp.py` (`mailrelay:587`, STARTTLS, CA nội bộ) + bước sửa cho realm tenant đã có; (2) lời mời Owner của bước 16 đi qua `IdPInviteNotifier` (tạo user + thư thiết lập); (3) UI dịch `idp_email_failed` thành câu hướng dẫn (thư thiết lập chưa gửi được — liên hệ quản trị nền tảng); (4) ca harness/E2E: mời thành viên trên tenant **vừa provision** tới khi người được mời đăng nhập được |
| G4b-E2 | `app.` /login ⇒ nhập slug không tồn tại (hoặc slug tenant đã xóa) ⇒ Tiếp tục | Trình duyệt rời SPA tới `/api/v1/auth/login` và hiện **JSON problem thô** (`404 not_found`, tiếng Anh), không nút quay lại — lỗi gõ nhầm slug là lỗi thường gặp | Trung bình | API redirect về `/login?error=tenant_not_found` (không tiết lộ tồn tại/không — cùng thông điệp cho mọi trường hợp) hoặc SPA gọi kiểm tra trước; thông báo i18n "Không tìm thấy tenant hoặc tenant không cho đăng nhập" |
| G4b-E3 | End User (tenant mặc định: tắt "Cho phép người dùng tự đăng ký thiết bị") ⇒ Thêm thiết bị ⇒ chọn OS ⇒ Tạo lệnh đăng ký | Menu và toàn bộ wizard vẫn hiện; chỉ khi bấm mới nhận 403: "Bạn không có quyền thực hiện thao tác này." + detail **tiếng Anh** của server "This tenant does not let members add devices themselves." trên giao diện vi | Trung bình (luồng gây nhầm lẫn + i18n) | Khi `self_enroll` tắt: wizard thay bằng thông báo (đã dịch) "Tenant chưa cho phép tự thêm thiết bị — liên hệ quản trị viên"; ánh xạ mã lỗi ⇒ chuỗi i18n thay vì in `detail` của server |
| G4b-E4 | Owner ⇒ Policy ⇒ Soạn version mới ⇒ Thêm luật ⇒ Đích: kiểu "tài nguyên" | Báo "Danh mục tài nguyên mạng chưa có API đọc (P4-T12): chỉ tài nguyên đã được tham chiếu mới chọn được; dùng chế độ HuJSON…" dù trang Tài nguyên mạng (P4-T12, đã có `GET /resources`) vừa có `web-1` ⇒ không chọn được tài nguyên vừa tạo bằng Biểu mẫu | Trung bình | Nạp danh mục từ `GET /tenants/{id}/resources` cho bộ chọn; bỏ chuỗi `policies…noResources` lỗi thời |
| G4b-E5 | 390 px ⇒ Audit log (Portal và Console) | Trang **cuộn ngang** 104–169 px: `span.sr-only` "Chi tiết/Details" (absolute) ở tiêu đề cột thoát khỏi vùng `overflow-x-auto` của bảng vì wrapper không `position: relative` | Thấp | Thêm `relative` cho wrapper bảng dùng chung (`data-table`) |
| G4b-E6 | 390 px ⇒ Console ⇒ Support Access | Ô Tìm tenant, Tenant (select có option dài), Mã ticket, Lý do tràn khỏi card ~8 px | Thấp | `min-w-0`/`w-full max-w-full` cho ô của form |
| G4b-E7 | Console ⇒ Support Access ⇒ ô Tenant (chưa gõ tìm) | Chỉ có tenant-a, tenant-b — tenant active mới (`g4bx-…`, và một tenant active khác) không có trong danh sách (giả thuyết: chỉ lọc trang đầu của danh sách tenant — staging có 52 tenant, 48 đã xóa — chưa đọc mã); chỉ hiện khi gõ "Tìm tenant", không có gợi ý | Thấp | Lọc `status=active,suspended` ở server; hoặc ghi rõ "gõ để tìm" |
| G4b-E8 | Lưu group / duyệt policy / khai báo tag; Platform Health | Thời gian tương đối **sai chiều** cho mốc vừa qua: "Cập nhật … (sau 17 giây nữa)", "Checked at … (in 1 second)". `ui/time.tsx`: `useNow()` chỉ cập nhật mỗi 30 s nên `now` cũ hơn timestamp vừa trả về (đồng hồ máy và server khớp — đã đo) | Thấp | `formatRelative` dùng `max(now, Date.now())` hoặc kẹp \|diff\| < 60 s ⇒ "vừa xong" |
| G4b-E9 | Thiết bị (End User chưa có thiết bị; tenant mới), Platform Health (edge/idp) | "Đồng bộ từ Headscale lúc chưa từng" / "Synced from Headscale at never" / "Checked at never" — ghép `ui.never` sau "lúc/at"; với End User chưa có thiết bị luôn "chưa từng" dù tenant đã đồng bộ (bấm "Làm mới" ⇒ `GET …&fresh=true` 200, vẫn vậy) | Thấp | Chuỗi riêng "Chưa đồng bộ lần nào"; `synced_at` của tenant thay vì của các hàng trả về |
| G4b-E10 | Hộp Mời thành viên; hộp đổi role | Dịch sai vi: `roleHint` "Chỉ hiện role **bạn được mời**" (= role mà bạn được mời) và `description` "role **bạn được gán**" — en là "roles you may invite / may give" | Thấp (i18n) | "Chỉ hiện role bạn được phép mời…", "…role bạn được phép gán…" (`vi.json`, không sửa ở lượt này) |
| G4b-E11 | Nhiều màn hình (Tổng quan, Thiết bị, chi tiết thiết bị, Policy, Usage, Chẩn đoán, Relay, wizard Tạo tenant…) | Tham chiếu nội bộ lộ ra UI khách hàng: HS-14, HS-19, PL-04, PL-09, §7.4, ADR-23, T-18, L1–L13, "quy tắc 3a", "bước 16", task P4-T03/P4-T10/P4-T12/P5-T08/P6-T02a/P6-T04/P6-T11, mã thô `(no_source)`, `(not_served)`, `(unsupported)`, `verify_clients`, tên job `policy.apply`/`member.idp_invite` | Thấp | Rút mã nội bộ khỏi chuỗi hiển thị (đưa vào tooltip/tài liệu), mã thô ⇒ câu đã dịch |
| G4b-E12 | Console: Instance, Job, Relay Region, IdP, chi tiết tenant, danh sách Tenant | Cột định danh hiện **UUID** thay vì slug/tên (Tenant, Host, Owning tenant); danh sách Tenant: cột **Gói trống** ở mọi hàng (chi tiết có `standard`); chi tiết tenant: "Figures without a source" dùng **khóa thô** `traffic_bytes`, `auth_failures`… (trang Relay Region dịch đủ) | Thấp | Trả kèm slug/tên ở API list hoặc tra ở client; dùng chung component số đo của trang Relay |
| G4b-E13 | Portal ⇒ Audit log; Thông báo | Actor của `auth.login` hiện UUID danh tính, của `invitation.accept` hiện e-mail; actor hệ thống tên tiếng Anh ("Keycloak administrator (master realm)", "IdP provisioning identity (platform)") cả ở giao diện vi | Thấp | Hiển thị tên/e-mail nhất quán; dịch tên actor hệ thống ở client theo mã |
| G4b-E14 | Đăng nhập Portal/Console khi giao diện là vi | Trang Keycloak luôn tiếng Anh (không truyền `ui_locales`, theme không có bản vi) | Thấp (i18n) | Gửi `ui_locales` theo ngôn ngữ đã chọn + bật i18n của realm/theme (vi, en) |
| G4b-E15 | Policy ⇒ version đã duyệt (chế độ Biểu mẫu) | Vẫn hiện nút sửa (Thêm luật, Gỡ luật, Thêm luật SSH) — chỉ "Lưu bản nháp" bị khóa; "Dựa trên" hiện tiền tố UUID (`01a1f703`) thay vì "Version 1"; Diff văn bản của bản nháp chưa đổi gì vẫn hiện 6 dòng đổi do thứ tự khóa (`grants`/`ssh`/`tagOwners`) | Thấp | Biểu mẫu chỉ-đọc khi không phải draft; hiện số version; chuẩn hóa thứ tự khóa trước khi diff |
| G4b-E16 | Lời mời của Owner (tạo khi provision) | "Người mời —", IdP "chưa có job" — khó hiểu (gắn với G4b-E1) | Thấp | "Tạo khi provision (nền tảng)"; IdP theo trạng thái thật sau khi sửa E1 |
| G4b-E17 | Gửi hộp Mời thành viên (⇒ chuyển sang /invitations), Tạo group (⇒ trang group) | Sau khi hộp đóng và route đổi, focus rơi về `<body>`, không thông báo trang mới (hộp đóng bằng Esc/Hủy thì trả focus đúng nút mở) | Thấp (a11y) | Khi đổi route: focus vào `h1` (tabIndex −1) hoặc vùng thông báo |
| G4b-E18 | Console | Header lặp "Platform Console" (badge + tên); phân trang khác nhãn Portal "Trang sau" ↔ Console "Tiếp" | Thấp | Bỏ tên lặp; thống nhất chuỗi |

Ghi nhận (không tính là phát hiện): ô ngày giờ của bộ lọc Audit hiển thị `mm/dd/yyyy` theo locale của trình duyệt (input
gốc) dù giao diện vi; Chẩn đoán và mẫu policy (P5-T08, P5-T01) chưa có trên staging (`91b118b`) — hiện "Sắp có", đúng
phiên bản; tên hiển thị "G3 <slug>" của tenant thử do script G3/G4a đặt.

**Đạt (không phát hiện):** 404 (vi/en, cả `app.` và `admin.`, route Portal trên `admin.`); trang "Không có quyền" cho End
User, "Về trang chủ" đưa tới Thiết bị (không vòng lặp); hộp thoại: focus đầu vào ô nhập/Hủy, Tab/Shift-Tab không thoát
hộp, Esc đóng và trả focus nút mở; trang claim dùng hoàn toàn bằng bàn phím, cảnh báo phishing, nút khóa tới khi tick;
Đăng xuất kết thúc phiên IdP (đăng nhập lại phải nhập mật khẩu); slug viết hoa/khoảng trắng được chuẩn hóa; gợi ý lỗi ô
nhập gắn `aria-describedby` (nhãn thiết bị, tên tag); lỗi DNS record rõ ràng; ở 1440 px không tràn bố cục ở mọi trang;
ở 390 px menu thành thanh cuộn ngang, bảng cuộn trong khung — chỉ E5, E6 tràn; tối/sáng không thấy chữ khó đọc.

### 5.3 Kết luận

1 Cao (**G4b-E1** — onboarding thành viên/Owner trên tenant mới provision với IdP do nền tảng host), 3 Trung bình (E2–E4),
14 Thấp (E5–E18). E1 không thuộc lớp UI (UI hiển thị đúng trạng thái `failed`) mà là khoảng trống cấu hình realm +
luồng lời mời Owner — Playwright và harness không thấy vì realm của stack thử được render tĩnh có SMTP (Mailpit) và tài
khoản được tạo sẵn. **G4b chuyển về chờ chủ dự án** (quy tắc ký trước: có phát hiện Cao ⇒ dừng hỏi lại). Các phát hiện
Trung bình/Thấp đề xuất gom vào một task UX/i18n (kèm spec Playwright: 390 px không cuộn ngang trang, slug sai ⇒ trang
lỗi của SPA, End User khi `self_enroll` tắt, chọn tài nguyên trong Biểu mẫu policy, thời gian tương đối không ở tương
lai). Lượt này không sửa code.

### 5.4 Dọn

Đã dọn: tenant `g4bx-a2f1` deprovision 2P ⇒ `deleted` (host: 0 container, 0 network, 0 volume, edge không còn network của
slug; realm bị vô hiệu ở `idp.disable`, slug giữ chỗ, backup cuối + DEK tự hủy sau grace như G4a); VM 105 `tailscale
logout` ⇒ `NeedsLogin`, không profile, `tailscale0` không IPv4; file credential/state/bộ đếm TOTP tạm `~/.meshguard/g4bx-*`
đã xóa; phiên trình duyệt `g4b-explore` đã đóng. Không đổi DNS, cổng, OPNsense, VPS, Proxmox, Tailscale của máy vận hành,
`staging.env`, image/compose, edge, migration; tenant-a/b không bị thay đổi. Dấu vết còn lại: audit/security event của
tenant thử và của các lần đăng nhập `kcadm` (`create-user.sh` ×2 ⇒ `idp.console_login`), 1 job `member.idp_invite` failed.

## Chủ dự án duyệt

| Vai trò | Quyết định | Ngày |
|---|---|---|
| Chủ dự án | **Go** theo quy tắc ký trước ngày 2026-11-20 ("Ký G4a ngay, G4b tự động" — xanh, 0 phát hiện Cao) | 2026-11-20 |
| Chủ dự án | **Chờ quyết định** — vòng khám phá trên staging (mục 5) có phát hiện Cao G4b-E1 ⇒ quy tắc tự động không còn áp dụng | — |
