# Demo tham khảo headscale-admin (R2) trên staging — ngoại lệ §25.1 quy tắc 6

> **File viết tay — không sinh từ master.** Ghi nhận ngoại lệ do chủ dự án duyệt và kết quả dựng bản demo của repo tham khảo R2 (§2.2, ADR-16 của [bản master](../implementation-master-plan.md)). Quy ước: [README](README.md). Cấu hình: [infrastructure/demo/headscale-admin/](../../../infrastructure/demo/headscale-admin/).

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-16, 18:45–19:20 UTC |
| Người thực hiện | Agent (Claude Code) |
| Chấp thuận | Hỏi: "đã thử mô phỏng lại các repo sau đó cải tiến thêm thay vì làm lại từ đầu chưa?". Agent đề xuất dựng headscale-admin trong sandbox để xem UI tham khảo (cần đổi quy tắc §25.1(6)). Chủ dự án: **"Thực hiện luôn không cần sandbox"** |
| Phạm vi | Chỉ R2 (headscale-admin). R1 đã được dựng lại thực chất ở dạng đã hardening (spike [P1-T05a](P1-T05a.md) và staging). R3 không có gì để chạy: dự án build `stund` thẳng từ tag Tailscale. R4 (`h.tar`) **vẫn cấm** — yêu cầu gốc của chủ dự án; repo không có mã nguồn |
| Không đổi | ADR-16 (Portal viết mới, port có chọn lọc theo MIT); `h.tar` cấm; bản demo không phải POC kiến trúc |

## Soát trước khi chạy (mã nguồn tại commit `0a4ca5e`, bản 1.3.0, 2026-11-09)

| Hạng mục | Kết quả |
|---|---|
| Image | `Dockerfile` của repo: 3 stage, `npm ci` theo lockfile, typecheck + build, runtime **non-root** (`node`), healthcheck nội bộ; tài liệu khuyến nghị read-only + `cap_drop: ALL` |
| Lời gọi ra ngoài lúc chạy | Chỉ tới `HS_URL`. InfluxDB và "AI" (endpoint `/chat/completions` tương thích OpenAI) chỉ gọi khi được cấu hình — demo không cấu hình |
| Tài khoản ban đầu | `admin`, mật khẩu ngẫu nhiên 20 ký tự in **một lần** vào log container, `must_change_pwd = 1` ⇒ bắt đổi ở lần đăng nhập đầu |
| Cookie | `Secure` chỉ khi `PANEL_PUBLIC_URL` là https; `PANEL_PUBLIC_URL` chỉ dùng cho cờ này (không kiểm `Origin`) |
| Gói có install script | `esbuild` (2 bản) và `fsevents` (chỉ macOS) |
| Endpoint Headscale | Toàn bộ dưới `/api/v1/*` (kể cả health) ⇒ đi được qua listener admin của edge (§14.6) |

## Đã dựng

| Bước | Chi tiết | Số đo |
|---|---|---|
| Build | VM 105 (máy build, không giữ dữ liệu tenant): `docker build` với `NODE_IMAGE=node@sha256:1314fb30…` (node 22.23.5, pin theo digest) | 92 s; image `sha256:bce5811f…`, 483 MB |
| Chuyển image | VM 105 phục vụ tarball tạm trong LAN; staging tải và kiểm sha256 rồi `docker load` (đi vòng qua máy vận hành quá chậm — đã hủy) | < 1 s, 88 MB nén; ID image khớp |
| Tenant demo `tenant-c` | `render_instance.py` + `tenant-deploy.sh` + `reattach-edge.sh` (runbook P1-T19): 10.250.0.16/29, UID 30003, deny-all rồi fixture `test-allow-intra`, user `lab-c` | 5,7 s; `/key` 200 qua LAN và qua VPS cho cả A, B, C |
| Proxy `mg-demo-proxy` | Image edge của dự án, non-root 10001, chỉ `NET_BIND_SERVICE`, read-only; `mg-demo-int` (10.249.250.2) + `mg-admin`; chỉ nghe trên IP `mg-demo-int`; gắn `X-MG-Token` (file) và ghim `X-MG-Instance: tenant-c` | — |
| Panel `mg-demo-panel` | Chỉ ở `mg-demo-int` (internal, 10.249.250.3); read-only, tmpfs, `cap_drop: ALL`, `no-new-privileges`, giới hạn 512 MB / 1 CPU / 256 PID; `HS_URL` = proxy; secret từ `panel.env` (root 0600, sinh trên host) | healthy sau vài giây |
| Thiết bị thật | VM 105 cài Tailscale 1.104.7, đăng ký vào `tenant-c` bằng pre-auth key dùng một lần hạn 1 giờ (đi qua pipe) | `lab-c1` 100.64.0.1 online |
| Truy cập UI | **Không** publish cổng, **không** sửa firewall host (rule `iifname eth0 ct state new drop` giữ nguyên): SSH tunnel `127.0.0.1:9080 → 10.249.250.3:3000` từ máy có SSH key của dự án | UI 200, `/api/system/health` = `{"ok":true,"db":true,…}` |

## Kiểm chứng cách ly của bản demo

| Phép thử | Kết quả |
|---|---|
| Panel → Internet (`https://1.1.1.1`) | `ENETUNREACH` |
| Panel → listener admin của edge `10.249.2.2:8081` (đi thẳng) | `ENETUNREACH` |
| Panel → Headscale tenant A `10.250.0.2:8080` | `ENETUNREACH` |
| Panel → proxy, path ngoài `/api/v1/*` (`/swagger`) | 404 |
| Panel → proxy với header tự đặt `X-MG-Instance: tenant-a` | 200 nhưng danh sách user **rỗng** (của tenant-c) — proxy ghi đè header, không lộ `lab-a` |
| Container khác trên `mg-admin` → proxy `10.249.2.129:9000` | bị từ chối (proxy chỉ nghe trên IP `mg-demo-int`) |
| Log nội bộ của edge từ lúc panel chạy | 12 × `GET /api/v1/node` (quét mỗi 15 s) + 1 × `GET /api/v1/user`, đều 200, đều `X-MG-Instance: tenant-c`; header token đã bị xóa khỏi log |

## Độ lệch so với chuẩn của dự án (chấp nhận cho bản demo)

- Secret của panel nằm trong biến môi trường, vì panel chỉ hỗ trợ cách này. Chỉ root trên host đọc được qua `docker inspect`. Chuẩn của dự án là secret dạng file.
- API key của `tenant-c` là toàn quyền (Headscale không có scope). Hạn 168 giờ; `down.sh` expire nó.
- Phụ thuộc npm lấy theo lockfile của repo, không review từng gói. Rủi ro được khoanh trong container không có đường ra mạng.
- UI chỉ có tiếng Trung giản thể (không i18n — §2.2); dùng tính năng dịch của trình duyệt.
- UI đi qua HTTP bên trong SSH tunnel: đường truyền được SSH mã hóa, không qua LAN dạng rõ.

## Đánh giá ban đầu (đầu vào cho P4-T01, ADR-16)

- **Dùng được như một panel cho một tenant** (phương án A ở §2.2): đặt sau proxy ghim tenant thì panel chạy được với Headscale của dự án mà không phải sửa mã. Mỗi tenant cần một panel, một tài khoản cục bộ và một API key toàn quyền.
- **Không dùng được làm Portal đa tenant** nếu không viết lại backend. Những điểm khiến R2 không làm được Portal đa tenant đều thấy trực tiếp trên bản demo:
  - một panel chỉ nối một Headscale;
  - quyền theo role toàn cục;
  - đăng nhập bằng tài khoản cục bộ, không có SSO;
  - trình soạn policy chỉ xử lý `acls`, còn policy của dự án dùng `grants`;
  - không có Super Admin.
- **Nên port ở Phase 4** (đúng ADR-16): trình soạn rule trực quan, lịch sử phiên bản và diff policy, luồng nháp → kiểm → xác nhận → cảnh báo drift, trang hướng dẫn kết nối. Chủ dự án xem UI trên bản demo để chọn ưu tiên.
- **Cần kiểm thêm khi dùng UI:** nếu lưu policy từ trình soạn của panel, panel có thể ghi đè fixture `grants` của `tenant-c` bằng `acls`. Không ảnh hưởng A/B. Khôi phục bằng `tenant-policy.sh tenant-c …`.

## Gỡ

`sudo bash infrastructure/demo/headscale-admin/down.sh` (thêm `--with-tenant` để xóa cả `tenant-c`); trên VM 105: `sudo tailscale logout`. API key của panel tự hết hạn sau 168 giờ nếu không gỡ.
