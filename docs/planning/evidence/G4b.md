# G4b — báo cáo gate (Phase 4, P4-T14)

> **Trạng thái: Go (2026-11-20)** — theo quyết định của chủ dự án "Go sau khi sửa xong", kiểm tự động theo lựa chọn
> "Chỉ kiểm tự động". Điều kiện đã đạt: bản sửa G4b-E1…E18 (mục 6) chạy trên staging từ đợt nâng 4 (api/worker/web
> `a703ce8`), và phép kiểm trên staging (mục 7, tenant thử `g4bv-d54e`) xanh ở cả bốn mục bắt buộc — realm mới có SMTP
> (`mailrelay:587`, STARTTLS) + i18n vi/en; lời mời Owner qua IdP `succeeded`, thư qua relay; Owner đăng nhập và mời End
> User ⇒ job IdP `succeeded`; trang Keycloak theo `ui_locales` (`lang="vi"`/`"en"`) — cùng E3/E12; **0 phát hiện Cao mới**.
>
> Lịch sử: vòng khám phá trên staging (mục 5) từng tìm ra **1 phát hiện mức Cao — G4b-E1** (realm Keycloak của tenant mới
> không có SMTP ⇒ `idp_email_failed`; lời mời Owner ở bước 16 không tạo tài khoản IdP) ⇒ G4b chuyển về chờ chủ dự án
> theo quy tắc "Ký G4a ngay, G4b tự động". Phần Playwright + checklist UX bảo mật bên dưới vẫn xanh (0 phát hiện Cao).

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

## 6. Sửa sau vòng khám phá

Nhánh `g4b-fix` (từ `3a84b44`), commit `aad868a` (mã, test, mã sinh, E2E-124); tài liệu ở commit kế tiếp `[skip ci]`. Lên
staging ở đợt nâng 4 (2026-11-20, mục 6.3) và kiểm lại ở mục 7. Không migration, không đổi image idp/edge, `staging.env`.
**Lô 2** (chủ dự án yêu cầu sửa nốt các mục còn dở — E3 menu, E9, E11–E15): nhánh `g4b-fix2` (từ `83c16d1`), kiểm chứng
ở mục 6.5; cũng không migration, không đổi image idp/edge, `staging.env`. Bảng 6.1 ghi trạng thái sau cả hai lô.

### 6.1 Từng phát hiện

| # | Xử lý | Test |
|---|---|---|
| **G4b-E1** (a) realm mới thiếu SMTP | **Đã sửa.** `keycloak.Config.SMTP` (`internal/idp/keycloak/smtp.go`): worker suy ra từ relay thư của chính nó (`MG_SMTP_ADDR`/`MG_SMTP_TLS`/`MG_SMTP_FROM` — staging `mailrelay:587`, STARTTLS, người gửi mặc định; relay có AUTH ⇒ không SMTP cho realm, cảnh báo log — realm không bao giờ giữ mật khẩu) ⇒ `smtpServer` giống hệt `smtp_relay` của `render_idp.py`. `EnsureIssuer` đặt nó khi **tạo** realm và đặt lại khi realm lệch (so sánh chuẩn hóa như `smtp_norm` của `realm-update.sh`; driver không có relay ⇒ không đụng `smtpServer` sẵn có). Realm đã tồn tại: `meshguard-worker admin idp-realm-smtp [--dry-run]` (`apps/worker/realmsmtp.go`) — mọi IdP keycloak có `driver_ref` JSON (realm do driver tạo), bỏ qua realm render tĩnh (`platform`/`tenant-a`/`tenant-b` — của `realm-update.sh`) và IdP `disabled`; idempotent (`EnsureSMTP`: chỉ PUT khi khác, kiểm `meshguard.idp_id` của realm) | `TestSMTPFromConfig`, `TestRealmRepCarriesSMTP`, `TestEnsureSMTP` (Keycloak giả: lần 1 PUT đúng một lần, lần 2 không ghi; realm render tĩnh ⇒ `unsupported`; realm của IdP khác ⇒ `conflict`; không relay ⇒ từ chối), `TestIdpRealmSMTP` (lọc realm, `--dry-run`, lỗi ⇒ exit 1, thiếu relay ⇒ exit 2); E2E-124 |
| G4b-E1 (b) lời mời Owner không qua IdP | **Đã sửa.** `DBStore.WithOwnerInvite` (`orchestrator/dbstore.go`): bước 16 gọi `members.IdPInviteNotifier` trong **cùng transaction** với lời mời ⇒ job `member.idp_invite` (`invitation:<id>:idp_invite`, chống trùng; chạy lại bước 16 thấy lời mời cũ thì không tạo thêm) — cùng đường với lời mời gửi từ Portal; IdP do tenant quản lý ⇒ job "không áp dụng". Worker nối ở `runner/provision.go` | `TestProvisionEndToEndDB` (PostgreSQL thật): đúng một job `member.idp_invite` cho lời mời Owner; E2E-124 |
| G4b-E1 (c) UI mã thô, banner khẳng định | **Đã sửa.** Trang Lời mời: mã của `member.idp_invite` (`idp_email_failed`, `idp_user_disabled`, `idp_invite_failed`, `not_configured`, `invalid_input`, mã lạ) ⇒ câu hướng dẫn vi/en (mã thô chỉ ở tooltip); banner sau Mời/Gửi lại nói đúng hai pha ("Đã tạo lời mời" + tài khoản IdP đang xử lý/đã xong), job IdP thất bại ⇒ cảnh báo `role=alert` | Vitest `people.test.tsx` |
| G4b-E1 (d) test hồi quy | **E2E-124** (`tests/e2e/harness/provisioned.py`) — mục 6.2 | `e2e.py all` |
| **G4b-E2** slug sai ⇒ JSON thô | **Đã sửa.** Server: `GET /auth/login` là điều hướng của trình duyệt (`Sec-Fetch-Mode: navigate`, `RequestInfo.FetchMode`) với tenant không đăng nhập được (mọi lý do `not_found`) ⇒ `302 /login?error=tenant_not_found&tenant=<slug>[&return_to=…]` (một mã, không lộ tồn tại; client khác vẫn `404`); OpenAPI mô tả. SPA: `LoginPage` đọc `?error=` ⇒ thông báo vi/en trong vùng alert sẵn có, điền lại slug, focus ô nhập; mã lạ ⇒ câu chung | `TestLoginFailureForANavigation`; Vitest `LoginPage.test.tsx` (+ axe); Playwright `auth.spec.ts` (ca mới) |
| **G4b-E3** End User khi tắt tự đăng ký | **Đã sửa.** Lô 1: `EnrollmentInstructions` thêm `self_enroll` (giá trị `enrollment.self_enroll` — End User đọc được) ⇒ trang Thêm thiết bị của End User hiện ngay "Tenant chưa cho phép tự thêm thiết bị — liên hệ quản trị viên", ẩn wizard/nút tạo lệnh/ô dán link (đường lùi: 403 ⇒ cùng thông báo); `ProblemAlert` không hiện `detail` tiếng Anh của 403 trên giao diện không phải en. **Lô 2 (menu):** vỏ tenant (`TenantScope.useTenantNav`) của End User đọc cùng query `GET /enrollment/instructions` (linux) ⇒ `self_enroll=false` ⇒ ẩn mục "Thêm thiết bị"; gõ thẳng URL vẫn tới trang giải thích; chưa biết cờ (đang tải, lỗi, chưa có instance) ⇒ giữ mục | DB test `ListAndInstructions`; Vitest `enrollment.test.tsx`; lô 2: `enrollment-a11y.test.tsx` (vi/en + axe: tắt ⇒ menu không có mục, trang giải thích; bật ⇒ có mục) |
| **G4b-E4** policy không chọn được tài nguyên | **Đã sửa.** Danh mục tên của Biểu mẫu policy đọc `GET /resources` (theo trang); bộ chọn hiện "tên (địa chỉ)" + tài nguyên đã tham chiếu; bỏ chuỗi "chưa có API đọc (P4-T12)"; không đọc được ⇒ câu riêng; trang Tài nguyên mạng làm mới danh mục sau khi đổi | Vitest `policies.test.tsx` |
| G4b-E5 cuộn ngang Audit 390 px | **Đã sửa** — `relative` cho mọi wrapper `overflow-x-auto` của `data-table` (28 chỗ) + test quét mã giữ quy ước | `ui.test.tsx` |
| G4b-E6 tràn form Support Access | **Đã sửa** — `min-w-0`, select `w-full max-w-full` | — |
| G4b-E7 bộ chọn tenant chỉ trang đầu | **Đã sửa** — gọi `status=active` và `status=suspended`, gộp; gợi ý "gõ để tìm", báo khi còn trang sau | `support.test.tsx` |
| G4b-E8 thời gian sai chiều | **Đã sửa** — `freshNow = max(now, Date.now())`, lệch < 10 s ⇒ "bây giờ" | `ui.test.tsx` |
| G4b-E9 "lúc chưa từng" | **Đã sửa.** Lô 1: câu riêng "Chưa đồng bộ/kiểm tra/đọc lần nào". **Lô 2:** API `DeviceList.synced_at` (cộng thêm, tùy chọn): lần sync gần nhất đã áp của instance live của tenant, đọc trong cùng transaction với trang (`devices.Page.SyncedAt`, dùng chung `lastSync` với dashboard) — có cả khi trang rỗng (End User chưa có thiết bị); UI "Đồng bộ từ Headscale lúc …" theo mốc của tenant, `null` ⇒ "Chưa đồng bộ từ Headscale lần nào."; server cũ không trả ⇒ như lô 1 | Go `TestSyncNormalisesFromListNodes` (PostgreSQL thật: `synced_at` của trang = lần sync; trang rỗng của End User vẫn có; tenant chưa sync ⇒ `nil`); Vitest `portal-a11y.test.tsx` (vi/en + axe: rỗng + có mốc, rỗng + `null`) |
| G4b-E10 dịch sai "role bạn được mời" | **Đã sửa** — "role bạn được phép mời/gán" | — |
| G4b-E11 mã nội bộ trên UI | **Đã sửa.** Lô 1: ~20 chuỗi × 2 ngôn ngữ bỏ HS-/PL-/T-/ADR-/§/P#-T#, "quy tắc 3a", "bước 16", tên job ở phần giới thiệu; mã lý do thô vào tooltip. **Lô 2:** báo cáo policy — câu chính là mô tả đã dịch, mã luật + mã phát hiện chỉ ở dòng "Chi tiết kỹ thuật: L4 · …" nhỏ (`FindingList`); 30 thông điệp phát hiện × 2 ngôn ngữ bỏ "(Lx)"/"cần xác nhận Lx"; hộp xác nhận luật dùng tên đã dịch ("Xác nhận: đích * hoặc route mặc định", "Lý do xác nhận (…)"), mã luật ở tooltip; giới thiệu/hint/nhãn accept/autoApprovers/ownerOnly không còn L-code; "Job policy.apply" ⇒ "Job áp dụng policy"; `verify_clients` ⇒ "DERP nhúng kiểm client"; mã lỗi job ở Portal (áp dụng policy, đồng bộ, DNS/route, offboard) ⇒ "Mã lỗi: …" nhỏ thay `<code>`/"(code)" thô; Console: lý do health của instance/relay ở chi tiết tenant dịch theo mã (mã ở tooltip). Giữ nguyên (định danh dữ liệu, không phải tham chiếu nội bộ): mã region (`mg-<slug>`), kind/step của job ở trang Job của Console | Vitest `policies.test.tsx` (nhãn xác nhận theo tên, mã ở tooltip, không "L4" trong chữ; dòng chi tiết kỹ thuật), `policies-a11y.test.tsx` (khóa `policies.ack.name.*` vi/en), quét i18n: không còn `L\d`/`policy.apply`/`verify_clients` trong chuỗi hiển thị (trừ hai khóa chi tiết kỹ thuật) |
| G4b-E12 UUID/khóa thô ở Console | **Đã sửa.** Lô 1: "Figures without a source" dùng nhãn đã dịch của trang Relay. **Lô 2:** API (cộng thêm) — `Instance.tenant_slug`/`tenant_name`/`host_name`, `Job`/`PlatformJob.tenant_slug`/`tenant_name`, `PlatformRelayRegion.tenant_slug`/`tenant_name`/`host_name`, `IdentityProvider.tenant_slug`/`tenant_name` (chỉ ở view của Console), `Tenant.plan` có ở danh sách `GET /platform/tenants` (trước rỗng); tra theo lô một lần mỗi trang (`platform.Service.Labels`: query `ListTenantLabels` — slug, tên, gói của subscription còn hiệu lực; `ListHostNames`), tra lỗi ⇒ bỏ nhãn (không làm hỏng trang). UI (`platform/Refs.tsx`): tên tenant (slug nhỏ) / tên host, UUID ở tooltip + đích link; thiếu nhãn ⇒ UUID như cũ — Instance (danh sách, chi tiết), Job (danh sách, chi tiết), Relay Region, IdP (danh sách, chi tiết), host của instance ở chi tiết tenant | Ma trận authz + isolation (`-tags mgtestfixture`, handler jobs/relay có nhãn trong world test); Vitest `platform/refs.test.tsx` (vi/en + axe: tên thay UUID, tooltip, thiếu nhãn ⇒ UUID, cột Gói) |
| G4b-E13 actor không nhất quán | **Đã sửa.** API (cộng thêm) `AuditActor.kind` (`user`, `support`, `idp_driver`, `idp_provisioner`, `idp_admin`, `realm_user`, `job`, `admin_command`, `system` — suy từ `details.idp_actor_kind`, mô tả mà `auditsync` ghi, kind job, lệnh `meshguard …`) và `AuditActor.email`; `display_name` của danh tính = tên hiện tại khi phạm vi của list đọc được (`ListAuditActorIdentities`: tenant ⇒ danh tính của tenant đó; platform ⇒ nhân sự nền tảng; support trong audit của tenant ⇒ giữ ảnh chụp), nếu không thì ảnh chụp lúc ghi. Thông báo `idp.admin_change` mang thêm `actor_kind`. UI: người ⇒ tên + e-mail nhỏ, ID danh tính ở tooltip, không tên ⇒ "Người dùng (chưa rõ tên)" (không UUID trần); hệ thống ⇒ nhãn đã dịch theo mã, mô tả thô ở tooltip; thông báo cũ không có `actor_kind` ⇒ suy từ mô tả tiếng Anh đã biết | Go `TestReaderActorIdentities` (PostgreSQL thật: phạm vi tenant/platform, support và danh tính tenant khác không lộ), `TestActorKindNameAndEmail`; Vitest `audit/actor.test.tsx` (vi/en + axe), `notificationText.test.ts` |
| G4b-E14 trang Keycloak luôn tiếng Anh | **Đã sửa.** `GET /auth/login` nhận `ui_locales` (`vi`/`en`, cộng thêm; giá trị khác ⇒ `422` trước khi ghi `auth_requests`) ⇒ tham số OIDC `ui_locales` của authorization request; SPA gửi ngôn ngữ đang chọn ở mọi lần bắt đầu đăng nhập/step-up. Template realm (3 template tĩnh + bản sao của driver): `internationalizationEnabled: true`, `supportedLocales: [vi, en]`, `defaultLocale: vi` (= mặc định của SPA; thư thiết lập/mời đi theo ngôn ngữ này khi user chưa chọn) — `check_realm` của `render_idp.py` bắt buộc; realm render tĩnh: `realm-update.sh` thêm nhóm `i18n` (so khớp locales như tập, idempotent); realm do `idp.ensure` tạo: có ngay từ template, `EnsureIssuer` sửa lệch; realm do driver tạo trước đó: `meshguard-worker admin idp-realm-i18n [--dry-run]` (`EnsureI18n`, cùng lọc/quy tắc với `idp-realm-smtp` — chung khung `realmRepair`). **Kiểm chứng bản dịch:** theme của image Keycloak 26.8.2 (digest pin) có `messages_vi.properties` cho login (498/525 khóa), email (68/73), account, keycloak.v2/login (khóa thiếu ⇒ tiếng Anh) — **không đổi image idp**; trang login có `<html lang="…">` theo locale. Harness: link chuyển ngôn ngữ (`kc_locale=`) không bị nhầm là link "proceed" | Go `TestLoginPassesUILocales` (PostgreSQL thật), `TestTemplateI18n`, `TestEnsureI18n` (Keycloak giả: một PUT, lần 2/locales khác thứ tự không ghi, realm tĩnh/IdP khác bị từ chối), `TestIdpRealmI18n`; `tools/test_render_idp.py` (3 ca âm i18n); Vitest `session.test.ts`, `LoginPage.test.tsx`/`app.test.tsx` (URL có `ui_locales`); E2E-124 (realm do driver tạo: i18n bật; trang thiết lập từ link thư `lang=vi`; đăng nhập Owner `ui_locales=en` ⇒ `lang=en`, End User `vi` ⇒ `lang=vi`); E2E `realm-update.sh` trên realm mới: 0 thay đổi |
| G4b-E15 version đã duyệt vẫn sửa được | **Đã sửa (phần Biểu mẫu).** Lô 1: "Dựa trên"/"Rollback từ" hiện "Version N". **Lô 2:** Biểu mẫu chỉ sửa được version chưa duyệt (draft, validated, pending_approval); version đã duyệt / đang mong muốn (đã áp dụng) / đã thay thế / bị từ chối hiện chỉ đọc (không Thêm/Gỡ luật, Mẫu, Lưu, Kiểm tra) kèm khung "Version này ở trạng thái … nên chỉ đọc" + nút "Tạo bản nháp từ version này" (`POST /policies` với nội dung của nó — API sẵn có); Áp dụng/Rollback giữ nguyên. Hợp đồng server **không đổi** (PATCH version approved vẫn đưa về draft). Chưa sửa: diff do thứ tự khóa (phía server — ghi nhận, không thuộc yêu cầu lô này) | Vitest `model.test.ts` (`isEditable`), `policies.test.tsx` (approved ⇒ chỉ đọc, tạo bản nháp ⇒ POST + điều hướng, không PATCH), `policies-a11y.test.tsx` (vi/en + axe) |
| G4b-E16 nhãn lời mời Owner | **Đã sửa** — "Tạo khi provision (nền tảng)"; cột IdP theo job thật (E1 b) | `people.test.tsx` |
| G4b-E17 focus sau điều hướng | **Đã sửa** — `Page` focus `h1` (tabIndex −1) khi điều hướng mang cờ; Mời ⇒ Lời mời, Tạo group ⇒ trang group | `people.test.tsx` |
| G4b-E18 header lặp, nhãn phân trang | **Đã sửa** — Console không lặp "Platform Console"; `Pager` chung "Trang trước"/"Trang sau" | `app.test.tsx` |

### 6.2 E2E-124 — mời thành viên trên tenant vừa provision qua orchestrator

`tests/e2e/harness/provisioned.py`, chạy **cuối** `e2e.py all` (sau E2E-70/71: cần IdP platform, Super Admin của E2E-24 và
Keycloak — bản dump giữ chúng; worker có orchestrator trước E2E-71 sẽ provision luôn tenant mà E2E-71 tạo trong khoảng
mất). Realm của stack thử render tĩnh, user tạo sẵn ⇒ trước đây không ca nào chạm realm do driver tạo — đúng lý do G4b-E1
lọt.

| Bước | Kết quả (VM 111, `g4bfixe2e`, 05:38–05:39 UTC) |
|---|---|
| Orchestrator | Host Agent build từ cây (55 s), chạy như compose `mg-agent` (network none, rootfs chỉ đọc, cap tối thiểu), pool `10.250.216.0/24` (`E2E_AGENT_POOL`, kiểm không chồng), UID 39500–39599, hàng `hosts` vùng riêng; worker tạo lại với `MG_AGENT_*`/`MG_PROVISION_*`/`MG_PROBER_URL` (override compose) ⇒ log "tenant orchestrator configured" |
| Provision | Super Admin `POST /platform/tenants` (driver keycloak, `deployment_region` = vùng của host thử) ⇒ `tenant.provision` **succeeded** (19 bước, ~14 s) |
| Realm | realm do driver tạo (`meshguard.idp_id` = IdP của tenant): `smtpServer` = `mailrelay:587`, `starttls=true`, không AUTH |
| Owner | job `member.idp_invite` của lời mời bước 16 **succeeded** ⇒ thư Keycloak tới Worker giả qua `mailrelay` (From `MeshGuard <no-reply@meshguard-ci.test>`) ⇒ theo link: `proceed → configure_totp → update_password → profile → done` ⇒ đăng nhập `app.` (mật khẩu + OTP) ⇒ membership **`tenant_owner`** của tenant mới (lời mời gắn ở lần đăng nhập đầu) |
| End User | Owner mời qua API (`end_user`) ⇒ job **succeeded** ⇒ cùng đường thư/link ⇒ đăng nhập ⇒ **`end_user`** |
| Dọn | realm xóa; container `mg-hs-<prefix>-*`, network `mg-t-<prefix>-*`, agent, thư mục gốc, image agent gỡ; worker tạo lại không orchestrator (hàng DB đi cùng stack); `Stack.teardown` gỡ thêm các đối tượng này nếu ca dừng giữa chừng |

Worker giả (`infrastructure/mail/cf-worker/test/devserver.mjs`) có thêm `DEVSERVER_BODIES` (chỉ compose của stack thử):
thân thư thô `0600` trong thư mục work của lượt chạy để ca theo link như người được mời; link/khóa action token vào bộ che
secret (E2E-16 PASS). Không có bản sửa ⇒ ca FAIL ở hai chỗ: `smtpServer` rỗng (job `idp_email_failed`, không thư) và
lời mời Owner không có job `member.idp_invite`.

### 6.3 Áp lên staging (người điều phối)

[deploy-backend mục q](../../operations/deploy-backend.md): api/worker/web của commit sửa (không migration) ⇒ log worker
không có cảnh báo "realms the driver creates get no SMTP" ⇒ `docker compose -p mg-app exec -T worker
/usr/local/bin/meshguard admin idp-realm-smtp --dry-run`, rồi chạy thật, rồi chạy lại (`updated 0`) — staging hiện chỉ có
realm render tĩnh (bỏ qua) và realm của tenant provision trước bản sửa còn hoạt động (nếu có — `updated`); lời mời có cột
IdP thất bại ⇒ "Gửi lại". Kiểm lại: provision tenant thử ⇒ Owner nhận thư thiết lập, đăng nhập; Owner mời End User ⇒ End
User đăng nhập; dọn tenant thử bằng xóa 2P.

**Lô 2 (thêm, mục q "Bổ sung"):** sau api/worker/web của lô 2 — render lại realm tĩnh bằng `render_idp.py` mới rồi
`realm-update.sh --check` ⇒ áp ⇒ `--check` 0 thay đổi (nhóm `i18n` của `platform`/`tenant-a`/`tenant-b`); `meshguard admin
idp-realm-i18n --dry-run` ⇒ chạy thật ⇒ chạy lại `updated 0` (realm do driver tạo). Kiểm lại: đăng nhập Portal/Console với
giao diện vi ⇒ trang Keycloak tiếng Việt, en ⇒ tiếng Anh; End User của tenant tắt tự đăng ký không thấy "Thêm thiết bị";
Console hiện tên tenant/host; Audit hiện tên người dùng (e-mail nhỏ), actor hệ thống có nhãn đã dịch.

### 6.4 Kiểm chứng (VM 111, tiền tố `g4bfix`)

Cây trên VM = `git archive 3a84b44` (md5 kiểm) + file đổi/mới đẩy bằng tar (md5 kiểm), mọi bước trong container pin
digest (Go `golang@sha256:f18c3d73…`, PostgreSQL `postgres@sha256:2ea8630d…` 18.7, Node `node@sha256:e6bedef2…`).

| Bước | Kết quả |
|---|---|
| Mã sinh | `go generate ./internal/httpapi/gen` (đổi `api.gen.go` theo `self_enroll`), `npm run gen:api` (`schema.d.ts`) — chạy lại không đổi; `gen:rbac` không đổi; `sqlc diff` (v1.31.1) khớp |
| gofmt, go vet | `gofmt -l` 0 file (lượt đầu bắt 2 file — đã sửa), `go vet ./...`, `-tags dockerintegration,mgtestfixture ./...`, `-tags "linux dockerintegration" ./tests/integration/...` đạt |
| `go test -race -count=1 ./...` | PostgreSQL thật, `MG_TEST_PG_REQUIRED=1`: 82 package ok, 1 FAIL (`TestEnsureSMTP` — tên host TLS của test, đã sửa) ⇒ chạy lại các package đụng tới (`internal/idp/...`, `enrollment`, `httpapi/...`, `identity`, `apps/...`, `orchestrator`, `members`): **mọi package ok** |
| `-tags mgtestfixture ./tests/security/... ./tests/isolation/...` | **ok** (ma trận authz, isolation, ...) — hai lượt (trước/sau đổi OpenAPI lần 2) |
| golangci-lint v2.15.0 (sha256 kiểm) | **0 issues** |
| Web | `lint` 0, `typecheck` 0, Vitest **37 file / 488 test** đạt (15 skip có sẵn), `build` + check-dist, `npm audit --omit=dev` 0 |
| `python tools/split_plan.py`, `docs_check.py` | OK |
| `e2e.py all` (`test_stack.py` PASS trước) | **92/92 PASS** (gồm E2E-124, E2E-16), 1 846 s; dọn: 0 container, 0 network mang tiền tố (còn 2 volume cache Go — gỡ sau) |
| Playwright (stack mới `g4bfixpw`, toàn bộ bộ, 1 lượt) | **PW-1 PASS** — 224 pass / 0 fail / 0 flaky / 0 skip (4 setup + 110 × `vi`/`en`, gồm ca mới `auth.spec.ts` slug không tồn tại ⇒ `/login?error=tenant_not_found`; lời mời, đăng nhập, enrollment), axe 0 vi phạm, 1 232 s; **PW-S PASS** |

### 6.5 Lô 2 — kiểm chứng (VM 111, tiền tố `g4bfix2`)

Commit `8a7920b` (mã, test, mã sinh). Cây trên VM = `git archive 83c16d1` (md5 kiểm) + file đổi/mới đẩy bằng tar (md5 kiểm); mọi bước trong container pin
digest (Go `golang@sha256:f18c3d73…`, PostgreSQL `postgres@sha256:2ea8630d…`, Node `node@sha256:e6bedef2…`). Bản dịch `vi`
của Keycloak kiểm trực tiếp trên image `quay.io/keycloak/keycloak@sha256:7e66a96e…` (26.8.2, digest của `versions.lock`):
`org.keycloak.keycloak-themes-26.8.2.jar` có `messages_vi.properties` của theme `base/login` (498/525 khóa của `en`),
`base/email` (68/73), `base/account`, `keycloak.v2/login`; `theme.properties` của login/email/account liệt kê `vi`;
`template.ftl` của login đặt `<html lang="${lang}">` ⇒ không cần theme riêng, không đổi image idp.

| Bước | Kết quả |
|---|---|
| Mã sinh | `sqlc generate` (v1.31.1 — `ListTenantLabels`, `ListHostNames`, `ListAuditActorIdentities`), `go generate ./internal/httpapi/gen`, `npm run gen:api` + `gen:rbac` (rbac không đổi); chạy lại không đổi; `sqlc diff` khớp; `openapi_lint.py` 158 operation, 0 vấn đề |
| gofmt, go vet | `gofmt -l` 0 file; `go vet ./...`, `-tags dockerintegration,mgtestfixture ./...`, `-tags "linux dockerintegration" ./tests/integration/...` đạt |
| `go test -race -count=1 ./...` | PostgreSQL thật, `MG_TEST_PG_REQUIRED=1`: **83 package ok, 0 FAIL** (gồm `internal/devices`, `internal/audit`, `internal/identity`, `internal/idp/...`, `internal/platform`, `internal/httpapi/...`, `apps/worker`) |
| `-tags mgtestfixture ./tests/security/... ./tests/isolation/...` | **ok** (ma trận authz 293 s — handler jobs/relay có nhãn, isolation, adminauthz, membersauthz…) |
| golangci-lint v2.15.0 (sha256 kiểm) | **0 issues** |
| Web | `lint` 0, `typecheck` 0, Vitest **40 file / 509 test** đạt (15 skip có sẵn — live), `build` + check-dist, `npm audit --omit=dev` 0 |
| `tools/test_render_idp.py` | 139 PASS (gồm 3 ca âm i18n mới) |
| `python tools/split_plan.py`, `docs_check.py` | OK |
| `e2e.py all` (`test_stack.py` PASS trước) | **92/92 PASS** (stack mới `g4bfix2e2e`, 1 808 s). E2E-124 mở rộng (G4b-E14): realm do `idp.ensure` tạo có `i18n=(True, [en, vi], vi)`; trang thiết lập từ link thư `lang=vi` (mặc định của realm — link không mang `ui_locales`), Owner đăng nhập với `ui_locales=en` ⇒ `lang=en` (mật khẩu + OTP), End User `ui_locales=vi` ⇒ `lang=vi`; roles `tenant_owner`/`end_user`. E2E-31: `realm-update.sh` trên realm mới (template có i18n) 0 thay đổi, chạy lại 0, `--check` sạch, `check_realm` trên bản export của Keycloak đạt. E2E-16 (không secret trong artifact) PASS |
| Playwright (stack mới `g4bfix2pw`, toàn bộ bộ, 1 lượt) | **PW-1 PASS** — 224 pass / 0 fail / 0 flaky / 0 skip (4 setup + 110 × `vi`/`en`), axe 0 vi phạm, 1 139 s; đăng nhập thật qua Keycloak giờ mang `ui_locales` (trang Keycloak theo ngôn ngữ của project — selector theo `name`/`id`, không theo chữ); **PW-S PASS**. (Dòng "FAIL E2E-24" trong log chuẩn bị của `playwrightui.py` là `check_platform` dùng để tạo SA1 với `Results` riêng không tính — không có job `inventory.sync` của E2E-23 trong lượt này) |
| Live UI (`platformui.py`, `policyui.py` — Vitest trên stack thật `g4bfix2ui`; `src/live/*` cập nhật theo nhãn mới) | **5/5** (E2E-89, 90, 108–110) và **3/3** (E2E-114–116) PASS, 0 secret trong log vitest |
| Dọn | VM 111: 0 container, 0 network, 0 volume mang tiền tố `g4bfix2*` (gỡ cả 8 volume cache Go), image base Keycloak kéo để kiểm bản dịch đã gỡ, `~/g4bfix2` và `/tmp/g4bfix2*` đã xóa |

## 7. Kiểm trên staging sau đợt 4 (2026-11-20)

Staging đã nâng đợt 4 lúc 08:28–08:38 UTC ([deploy-backend mục q](../../operations/deploy-backend.md)): api/worker/web
của `a703ce8` (`api@sha256:cf0ac84c…`, `worker@sha256:90e2030b…`, `web@sha256:1a4e6ba0…` — kiểm bằng `docker inspect` lúc
08:41), `meshguard admin idp-realm-smtp` + `idp-realm-i18n` đã chạy, `realm-update.sh` bật i18n cho
`platform`/`tenant-a`/`tenant-b`; log worker từ lúc khởi động: 0 dòng "realms the driver creates get no SMTP",
"tenant orchestrator configured". Phép kiểm theo lựa chọn **"Chỉ kiểm tự động"** của chủ dự án: mọi e-mail là
`owner@<slug>.example.invalid` / `user@<slug>.example.invalid` — relay nhận và chuyển tới Worker Cloudflare, thư không tới
hộp thư nào; phần "theo link thư ⇒ đặt mật khẩu ⇒ đăng nhập" đã chứng minh bằng E2E-124 (mục 6.2, 6.5). Tenant thử
**`g4bv-d54e`**, 08:45–08:48 UTC, script [G4b/g4bv.py](G4b/g4bv.py) (dùng lại harness `tests/g3` — `Platform`, 2P,
step-up — và `backend.portal_login`; Keycloak admin API bằng `kcadm` trong container idp với admin khởi tạo đọc từ secret
đã mount, như `infrastructure/idp/user-id.sh`/`create-user.sh`).

| # | Mục | Kết quả | Bằng chứng |
|---|---|---|---|
| 1 | SA provision tenant thử qua API Console (IdP do nền tảng host) | **Đạt** | SA1 `POST /platform/tenants` (`identity_provider.driver = keycloak`, Owner `owner@<slug>.example.invalid`) ⇒ 202; `tenant.provision` **succeeded** 9,5 s, 19/19 bước; `mg-hs-g4bv-d54e` healthy |
| 1a | Realm mới có SMTP | **Đạt** | `kcadm get realms/g4bv-d54e`: `smtpServer` = host `mailrelay`, port `587`, `starttls=true`, `ssl=false`, `auth=false` (không trường mật khẩu), from `no-reply@<domain>`, tên hiển thị `MeshGuard` — có ngay khi `idp.ensure` tạo realm (log worker "keycloak: realm created") |
| 1b | Realm mới có i18n | **Đạt** | `internationalizationEnabled=true`, `supportedLocales` = {vi, en}, `defaultLocale=vi` |
| 2 | Lời mời Owner (bước 16) qua IdP | **Đạt** | 1 lời mời (`pending`, không người mời = do provision tạo); job `member.idp_invite` (resource = lời mời Owner) **succeeded** 1,73 s, output `{"idp":"invited","created":true,"email_sent":true}` |
| 2a | User Owner trong realm | **Đạt** | username = e-mail, `enabled=true`, `emailVerified=false`, required actions `VERIFY_EMAIL`, `UPDATE_PASSWORD`, `CONFIGURE_TOTP` |
| 2b | Log Keycloak | **Đạt** | từ 08:45 tới cuối lượt: 0 `KC-SERVICES0088`, 0 dòng `Failed to send`/`EmailException`/`MessagingException`, 0 `ERROR`, 0 `WARN` nhắc tới realm thử |
| 2c | Log mail-bridge | **Đạt** | ngay sau provision 3 dòng "mailrelay: message relayed" `result=delivered code=sent status=200 rcpt=1 sent=1 failed=0` (1,2–1,7 s): thư thiết lập của Keycloak (execute-actions) + 2 thư nền tảng (`tenant.invitation`, `tenant.activated`); cả lượt: **11/11 delivered**, 0 WARN/ERROR — 2 thư Keycloak (~4,5 KB) + 9 thư `notification_outbox` (đều `sent`, người nhận đều thuộc `*.example.invalid`). Không in địa chỉ (relay chỉ log `from` đã che) hay nội dung |
| 3 | Owner đăng nhập được | **Đạt** | Mật khẩu đặt cho **chính user Owner do lời mời tạo** qua admin API (không qua thư): `kcadm update users/<id>/reset-password` (32 ký tự sinh tại chỗ, `temporary=false`, chỉ qua stdin ssh → `docker exec` → pipe), rồi `kcadm update users/<id>` đặt tên + `emailVerified=true` + `requiredActions=[CONFIGURE_TOTP]` (bỏ `VERIFY_EMAIL`/`UPDATE_PASSWORD` — hai bước mà link thư sẽ làm). Owner đăng nhập `app.` (`password` ⇒ `configure_totp`) ⇒ membership **`tenant_owner`**, lời mời Owner `accepted` |
| 3a | Owner mời End User qua API Portal | **Đạt** | `POST /tenants/{id}/invitations` `{user@<slug>.example.invalid, end_user}` ⇒ 201 `pending`; job `member.idp_invite` **succeeded** 1,14 s (`email_sent=true`); user mới trong realm (cùng required actions); mail-bridge thêm 2 thư delivered, Keycloak 0 lỗi |
| 3b | Cột IdP của lời mời | **Đạt** | `GET /invitations` + `GET /jobs?kind=member.idp_invite` ghép theo `resource.id` (đúng cách `InvitationsPage`): (end_user, `pending`, job **succeeded**), (tenant_owner, `accepted`, job **succeeded**) — 0 mã lỗi ⇒ UI hiện trạng thái thành công, không cảnh báo |
| 4 | Trang đăng nhập Keycloak theo ngôn ngữ | **Đạt** | `GET https://app.<domain>/api/v1/auth/login?scope=tenant&tenant=g4bv-d54e&ui_locales=vi` ⇒ authorization request mang `ui_locales=vi` ⇒ trang Keycloak HTTP 200 `<html lang="vi">`; `ui_locales=en` ⇒ `<html lang="en">`; không tham số ⇒ `lang="vi"` (mặc định realm) |
| 5 | E3 — End User khi tắt tự đăng ký | **Đạt** | End User (mật khẩu đặt như mục 3) đăng nhập ⇒ `end_user` (lời mời gắn); `GET /enrollment/instructions?os=linux` ⇒ 200 `self_enroll=false` (vỏ tenant ẩn "Thêm thiết bị"); `POST /enrollment/requests` ⇒ 403 `forbidden` |
| 5a | E12 — Console | **Đạt** | `GET /platform/tenants`: tenant thử có `name` + `plan=standard` (cũng `cuonghq`; `tenant-a`/`tenant-b` không có subscription — seed tĩnh — nên `plan` rỗng, đúng dữ liệu); `GET /platform/instances`: `tenant_slug`/`tenant_name`/`host_name` có; job `tenant.provision` có `tenant_slug` |
| 6 | Dọn | **Đạt** | Deprovision 2P: SA1 `DELETE` ⇒ 202, SA1 tự duyệt ⇒ **403** (`approval.self_decision` medium), SA2 duyệt ⇒ 200; `tenant.deprovision` succeeded 15 bước; tenant **`deleted`**; host: 0 container, 0 network, 0 volume mang slug, 0 thư mục instance, 0 secret; network của edge chỉ còn của nền tảng + `mg-t-cuonghq`/`mg-t-tenant-a`/`mg-t-tenant-b`; `mg-hs-*` còn 3; realm `g4bv-d54e` `enabled=false` (`idp.disable`) |

Tổng: 23 kiểm PASS (results.json của lượt). Lượt đầu của bước đọc realm báo 2 FAIL giả do script (stderr "Logging into …" của `kcadm` dính sau
JSON; `--fields smtpServer` không lấy trường con) — sửa script (`smtpServer(*)`, `raw_decode`) và đọc lại ⇒ PASS; không
liên quan sản phẩm. Log trong cả lượt: api/worker/mail-bridge 0 `ERROR`; WARN chỉ là security event mong đợi (dưới đây).

**Phát hiện mới: không có** (0 Cao, 0 Trung bình). Ghi nhận (không phải lỗi): mỗi lần `kcadm` đăng nhập realm master ⇒
security event `idp.console_login` (High, 6 lần) và mỗi `reset-password` ⇒ `idp.credential_reset` (High, 2 lần, realm
thử) — đúng thiết kế auditsync; các thay đổi admin của user ⇒ 4 thông báo `idp.admin_change` gửi tới Owner (`.invalid`).

**Dấu vết còn trên staging:** tenant `g4bv-d54e` `deleted` (slug giữ chỗ; backup cuối + DEK tự hủy sau grace như G4a);
realm `g4bv-d54e` bị vô hiệu cùng 2 user thử (mật khẩu/TOTP không còn ở đâu); audit, security event nêu trên, 9 hàng
`notification_outbox` `sent`, 2 job `member.idp_invite` succeeded. Máy vận hành: `~/.meshguard/g4bv-*` (state, credential,
bộ đếm TOTP, log đã che) **đã xóa**; SA thử `g3-sa1/g3-sa2` giữ nguyên. Không đổi DNS, cổng, OPNsense, VPS, Proxmox,
Tailscale của máy vận hành, `staging.env`, image/compose, edge (không reload), migration; `tenant-a`/`tenant-b`/`cuonghq`
chỉ đọc (danh sách tenant).

```bash
for s in provision invite owner locale e3e12 cleanup; do python -B docs/planning/evidence/G4b/g4bv.py $s; done
```

## Chủ dự án duyệt

| Vai trò | Quyết định | Ngày |
|---|---|---|
| Chủ dự án | **Go** theo quy tắc ký trước ngày 2026-11-20 ("Ký G4a ngay, G4b tự động" — xanh, 0 phát hiện Cao) | 2026-11-20 |
| Chủ dự án | **Chờ quyết định** — vòng khám phá trên staging (mục 5) có phát hiện Cao G4b-E1 ⇒ quy tắc tự động không còn áp dụng | — |
| Chủ dự án | **"Go sau khi sửa xong"**, kiểm "Chỉ kiểm tự động" ⇒ điều kiện đạt (bản sửa mục 6 trên staging từ đợt 4; mục 7 xanh, 0 phát hiện Cao mới) ⇒ **Go** | 2026-11-20 |
