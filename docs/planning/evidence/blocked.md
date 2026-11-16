# Task bị chặn

> **File viết tay — không sinh từ master.** Theo §25.1 quy tắc 15 của [bản master](../implementation-master-plan.md): task bị chặn bởi phụ thuộc ngoài thì dừng và ghi vào đây; chỉ chuyển sang task không phụ thuộc vào nó; không thay phép thử thật bằng mô phỏng. Cập nhật khi tình trạng đổi.

| Task / gate | Bị chặn bởi | Cần gì để gỡ | Từ ngày |
|---|---|---|---|
| P0-T07 | — | Repo giữ public theo quyết định của chủ dự án ⇒ CI trên runner của GitHub. Chờ kết quả `runner-smoke` sau khi push | 2026-11-16 |
| P0-T03 (phần image tự build) | P0-T07 | Registry đã thử được. Phần upstream đã xong 2026-11-16 (`versions.lock`) | 2026-11-16 |
| P0-T02 (phần còn lại) | Chủ dự án | Tên người chịu trách nhiệm cho từng rủi ro ở §23.1 | 2026-11-16 |
| G0 | G0(5) | P0-T07. Xem [G0.md](G0.md) | 2026-11-16 |
| Mọi task Phase 1 | G0 | Chủ dự án đã cho Go có điều kiện: Phase 1 bắt đầu ngay khi G0(5) đạt ([G0.md](G0.md)) | 2026-11-16 |
| P1-T15…P1-T18 (VPS) | G0; pipeline deploy của dự án cũ | Tắt pipeline deploy của 3 dự án cũ hoặc gỡ key deploy của chúng khỏi root ([nhật ký](infrastructure-bootstrap.md) §6) | 2026-11-16 |
| P1-T05 | Chủ dự án | API token Cloudflare chỉ có quyền sửa DNS của zone `gta5web.online`, chủ dự án tự đặt thành file secret trên host staging; email cho ACME account (A.1 #9) | 2026-11-16 |

**Đã gỡ chặn:** D-10 — 2026-11-16: chủ dự án quyết định không đổi mật khẩu root đã lộ (chấp nhận rủi ro); bản sao trên máy vận hành đã xóa. P0-T05 — xong 2026-11-16: mọi mục A.1 có giá trị hoặc "chưa biết — người chịu trách nhiệm" (Appendix A.4 của master); yêu cầu tư vấn pháp lý R-01 do chủ dự án mở (D-6).

**Không bị chặn:** P0-T06 (xong); P0-T08 phần 1 (xong: [nhật ký bằng chứng nghiên cứu](../../architecture/research-evidence.md)); P0-T08 phần 2 — đọc lại nguyên văn các dữ kiện then chốt. Đã xong 2026-11-16: phần upstream của P0-T03, phần không có CI của P0-T04.
