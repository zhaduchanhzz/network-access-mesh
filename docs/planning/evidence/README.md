# Evidence — quy ước lưu bằng chứng

> **File viết tay — không sinh từ master** (Appendix B). Đầu ra của task **P0-T06**. Áp dụng cho mọi bằng chứng của task và gate từ Phase 0 trở đi (§19, §22.1, §25.1 của [bản master](../implementation-master-plan.md)).

## Thư mục này chứa gì

| File / thư mục | Nội dung |
|---|---|
| `architecture-approval.md` | Biên bản phê duyệt kiến trúc (P0-T02) |
| `blocked.md` | Task đang bị chặn bởi phụ thuộc ngoài (§25.1 quy tắc 15) |
| `validation-register.md` | Sổ đăng ký kiểm chứng V-01…V-36: task, gate, kết quả, đường dẫn bằng chứng |
| `infrastructure-bootstrap.md` + `infrastructure-bootstrap/` | Nhật ký khởi tạo hạ tầng trước G0 theo chỉ đạo của chủ dự án (2026-11-16): thay đổi, lệnh hoàn tác, script đã chạy |
| `G<n>.md` | Báo cáo gate (G0…G7, G4a/G4b); kết thúc bằng dòng xác nhận của chủ dự án |
| `G<n>-<chủ-đề>.md` | Bằng chứng phụ của gate, ví dụ `G2-security-review.md` |
| `<task-id>/` | Output nguyên văn, ảnh chụp, file đo của một task, ví dụ `P1-T12/` |

## Mỗi bằng chứng phải ghi

1. Ngày giờ (múi giờ), task hoặc gate, người/agent thực hiện.
2. Môi trường: **dev/CI**, **staging** (host LAN + VPS gateway) hoặc **production**.
3. Phiên bản: Headscale, image digest, Caddy, client Tailscale **trên từng thiết bị** (client di động tự cập nhật nên phải ghi phiên bản thực tế).
4. Với phép thử mạng: sơ đồ mạng (thiết bị nào ở mạng nào, NAT ra sao), lệnh đã chạy và output nguyên văn.
5. Tiêu chí đạt/không đạt lấy từ task hoặc AC tương ứng, và kết luận.

## Nhãn kết quả (§22.1)

- **functional** — chạy bằng container cùng host, mô phỏng, hoặc stack dev/CI.
- **network E2E verified** — chỉ khi chạy trên **thiết bị thật** ở mạng phù hợp; bắt buộc kèm sơ đồ mạng và phiên bản client. Ở chế độ "MVP LAN-only" ghi **network E2E verified (LAN NAT)**.
- Mọi con số độ trễ là **giá trị đo**, không phải cam kết.

## Che dữ liệu nhạy cảm trước khi lưu hoặc commit (§25.1 quy tắc 14)

| Loại | Cách xử lý |
|---|---|
| Mật khẩu, private key, file state của `tailscaled`, KEK | **Không bao giờ** lưu — kể cả đã che |
| Pre-auth key, API key Headscale (`hskey-…`), token, cookie, header `Authorization` | Thay bằng `<redacted>`; nếu cần đối chiếu, chỉ giữ prefix của API key |
| Email người dùng thật | Thay bằng `<user-a>`, `<user-b>`… |
| IP công khai của thiết bị người dùng | Che octet cuối (ví dụ `203.0.113.x`) |

Secret scan chạy trên mọi file của thư mục này như phần còn lại của repo (rule cho `hskey-` — P0-T04).

## Gate và xác nhận

Báo cáo gate liệt kê từng điều kiện của gate (§19) với bằng chứng tương ứng. Gate chỉ được coi là đạt khi chủ dự án ghi xác nhận ở cuối báo cáo: `Xác nhận của chủ dự án: <ngày> — Go` (hoặc `No-Go` kèm lý do).
