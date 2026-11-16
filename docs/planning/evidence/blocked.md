# Task bị chặn

> **File viết tay — không sinh từ master.** Theo §25.1 quy tắc 15 của [bản master](../implementation-master-plan.md): task bị chặn bởi phụ thuộc ngoài thì dừng và ghi vào đây; chỉ chuyển sang task không phụ thuộc vào nó; không thay phép thử thật bằng mô phỏng. Cập nhật khi tình trạng đổi.

| Task / gate | Bị chặn bởi | Cần gì để gỡ | Từ ngày |
|---|---|---|---|
| P0-T02 (phần còn lại) | Chủ dự án | Tên người chịu trách nhiệm cho từng rủi ro ở §23.1 | 2026-11-16 |
| P1-T05 (và P1-T05a, P1-T06 phần chứng chỉ) | Chủ dự án | API token Cloudflare chỉ có quyền sửa DNS của zone `gta5web.online`, chủ dự án tự đặt thành file secret trên host staging; email cho ACME account (A.1 #9) | 2026-11-16 |
| P1-T15…P1-T18 (VPS) | Pipeline deploy của dự án cũ | Tắt pipeline deploy của 3 dự án cũ hoặc gỡ key deploy của chúng khỏi root ([nhật ký](infrastructure-bootstrap.md) §6) | 2026-11-16 |
| V-35 bước "thử từ ngoài" | Thiết bị | Một mạng ngoài có IPv6 công khai (ví dụ điện thoại 4G) để thử kết nối tới host staging | 2026-11-16 |

**Đã gỡ chặn (2026-11-16):** G0 đạt 8/8 ([G0.md](G0.md)) ⇒ Phase 1 bắt đầu. D-10 — chủ dự án không đổi mật khẩu root (chấp nhận rủi ro). P0-T05, P0-T07 (CI trên runner của GitHub + GHCR, workflow xanh), P0-T03 phần upstream, P0-T04.

**Không bị chặn:** P0-T08 phần 2 (đọc lại nguyên văn các dữ kiện then chốt); P1-T03, P1-T04, P1-T07 và các task Phase 1 không cần chứng chỉ.
