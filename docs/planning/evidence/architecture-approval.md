# Biên bản phê duyệt kiến trúc

> **File viết tay — không sinh từ master.** Đầu ra của task **P0-T02** (phần ghi nhận phê duyệt). Quy ước: [README](README.md).

| Mục | Nội dung |
|---|---|
| Ngày | 2026-11-16 |
| Người phê duyệt | Chủ dự án — xác nhận trong phiên làm việc: "Tôi đã duyệt plan và bắt đầu thực hiện được rồi" |
| Đối tượng | Implementation Master Plan **Rev 3** — `docs/planning/implementation-master-plan.md`, sha256 `ffe4746c38f6c4d882473e9ab30a46174693347d76b809bc2e90803775bfe734` (bản tại thời điểm phê duyệt, trước khi ghi trạng thái phê duyệt vào file): 25 mục, Appendix A–D, 25 ADR, 149 task |
| Cơ sở | Nghiên cứu chỉ-đọc (16 research agent — [nhật ký bằng chứng](../../architecture/research-evidence.md)); phản biện tự động của 8 agent AI và vòng kiểm chứng lại ([Appendix D](../review-log.md)). Phản biện tự động **không** thay cho thẩm định của chuyên gia; plan có rà soát bảo mật độc lập ở G2 và pen test bên ngoài ở Phase 6 |

## Kết quả

**Kiến trúc:** 25 ADR (§24) chuyển từ *Proposed* sang **Accepted**. Từ nay, thay đổi một ADR cần một ADR thay thế được chủ dự án duyệt (§25.1 quy tắc 3).

**Quyết định ghi nhận là chấp nhận theo khuyến nghị của plan khi phê duyệt** (chủ dự án báo nếu muốn đổi):

| # | Nội dung đã chấp nhận |
|---|---|
| D-2 | Đường public đi qua VPS Public Gateway (đã quyết trước đó, 2026-11-16) |
| D-4 | `node.expiry` mặc định 90 ngày |
| D-5 | Chấp nhận rủi ro một host cho dev/staging; không dùng cho production |
| D-7 | Tài liệu bằng tiếng Việt kèm thuật ngữ tiếng Anh |
| D-8 | Tắt chia sẻ tín hiệu với CrowdSec Central API |
| D-9 | VPS chỉ làm gateway tầng 4; không giữ khóa TLS hay dữ liệu tenant |

**Quyết định còn mở — cần thông tin của chủ dự án:** D-1 (domain + DNS provider), D-3 (IdP), D-6 (tư vấn pháp lý R-01), D-10 (đổi mật khẩu root VPS + SSH key), D-11 (số người vận hành), D-12 (Git hosting đã có: GitHub; còn CI runner và container registry), D-13 (cơ chế nâng quyền không dùng mật khẩu), D-14 (host production — chốt trước G6).

## Không bao gồm

Phê duyệt kiến trúc **không** có nghĩa là G0 đã đạt. G0 cần thêm 8 đầu vào (§19) — tiến độ theo dõi ở [G0.md](G0.md). Các quyết định chốt sau thời điểm phê duyệt (D-3 sơ bộ, D-11, D-12) được ghi ở §25.4 của master và ở G0.md.

Phần còn lại của P0-T02 — gán tên người chịu trách nhiệm cho từng rủi ro ở §23.1 — chờ chủ dự án (ghi ở [blocked.md](blocked.md)).
