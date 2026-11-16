# Tenant Isolation

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §5.2, §5.3. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

### 5.2 Mười hai ranh giới cách ly — cơ chế và phép thử

| # | Ranh giới | Cơ chế thiết kế | Phép thử chấp nhận (Isolation Test) |
|---|---|---|---|
| 1 | Identity | Issuer riêng theo tenant (hoặc `required_claims` khi issuer dùng chung); issuer binding (§8.4); callback theo từng IdP; cookie `__Host-` theo origin | IT-01: identity của IdP tenant A không tạo được session/membership ở tenant B; token của issuer A bị từ chối ở luồng đăng nhập tenant B. IT-01b: IdP do tenant kiểm soát không lái được code của IdP khác vào callback của mình (mix-up, T-20). IT-01c: user thuộc tổ chức khác trên cùng issuer dùng chung bị từ chối |
| 2 | API Authorization | 5 lớp (§8.8); tenant từ path; `404` cho ID lạ | IT-02: ma trận sinh từ OpenAPI — mọi operation tenant-scoped × (tenant khác, object của tenant khác) ⇒ `404`, không side effect |
| 3 | Database | RLS + FK ghép `(tenant_id, id)`; SQLite riêng từng instance | IT-03: không đặt `app.tenant_id` ⇒ 0 hàng; chèn tham chiếu chéo tenant bị DB từ chối; đặt tenant A không đọc được hàng tenant B, kể cả `identities` thuộc IdP của tenant B |
| 4 | Control Plane | Tiến trình/container/config/Noise key/UID/giới hạn tài nguyên riêng | IT-04 (AC-18): restart/kill instance A, client của B không gián đoạn và state của B không đổi (phương pháp ở AC-18); làm bão hòa CPU của A, đo độ trễ control của B |
| 5 | Network Peer | Netmap riêng theo instance | IT-05 (AC-13): `tailscale status --json` trên client A có peer cùng tenant và không chứa node key nào của B, và ngược lại (tiền điều kiện ở §22.1) |
| 6 | Network Policy | Policy theo instance; api/worker chỉ ghi qua `Registry.ForTenant` (ngoại lệ: baseline và policy đặt trước khi start lúc restore do Agent ghi bằng CLI cục bộ — §11.3 bước 12, §17.2) | IT-06: apply policy cho A ⇒ sha256 `GetPolicy` của B không đổi |
| 7 | DNS | `base_domain` duy nhất/tenant; file extra-records riêng | IT-07: tên MagicDNS/extra record của B không phân giải được từ client A |
| 8 | Routing | Duyệt route theo instance; subnet router chỉ thuộc một tailnet | IT-08: route duyệt ở A không xuất hiện trong netmap của B; exit node của A không chọn được từ B |
| 9 | Relay Access | Embedded DERP + `verify_clients` (fail-closed, in-process) | IT-09: node key thuộc B (hoặc key chưa đăng ký) kết nối `/derp` của A bị từ chối |
| 10 | Secret | API key và thư mục/UID riêng theo instance; `Registry.ForTenant` từ chối secret reference không thuộc đúng tenant; DEK theo tenant (phục vụ crypto-shredding — **không** là ranh giới cách ly khi api/worker bị chiếm, vì dùng chung KEK); không `.env` chung; API không bao giờ trả secret | IT-10: API key của A bị instance B trả `401`; tiến trình UID của B không đọc được file của A; quét response API không có mẫu secret |
| 11 | Backup/Restore | Archive + data key theo tenant; manifest ký ràng buộc `tenant_id`/`instance_id`; đường dẫn từ `instance_id` | IT-11 (AC-19): restore A, dữ liệu B không đổi theo phương pháp của AC-19; restore archive của A vào B bị từ chối trước khi giải mã |
| 12 | Audit/Telemetry | RLS trên `audit_events`; nhãn tenant ép ở server cho truy vấn metrics; không cấp log thô | IT-12a: API audit của A không trả sự kiện của B. IT-12b: dashboard/relay metrics của A không chứa số liệu của B; thử chèn nhãn tenant khác vào tham số bị bỏ qua. IT-12c: API usage của A không trả số liệu của B |

Bổ sung cho enrollment: IT-13 (AC-14) — pre-auth key của A bị Headscale của B từ chối; Auth ID sinh ở instance A gửi tới endpoint claim của tenant B bị từ chối, không node nào được tạo ở cả hai.

Bổ sung cho giả định "container Headscale của một tenant bị chiếm": IT-14 — từ bên trong network của một tenant (probe chạy hai lần: hardening như Headscale, và có `NET_ADMIN` + `NET_RAW` để mô phỏng lỗi capability) không gọi được listener admin/metrics hay site public nào của edge, không tới được instance của tenant khác (8080/9090), PostgreSQL, api, dịch vụ trên host và trong LAN, và không ra được Internet (kể cả qua DNS).

Bổ sung cho ranh giới 11 (thư mục dữ liệu thù địch): IT-15 — đặt trong `data/` của A một symlink trỏ sang file của instance khác, một FIFO, một file thưa rất lớn và một DB hỏng ⇒ backup và start guard thất bại (fail-closed) kèm `security_event`, archive của A không chứa byte nào của tenant khác, và Agent vẫn phản hồi cho các instance khác.

Bổ sung cho ranh giới 11 (không hồi sinh quyền sau restore): IT-16 — bản backup lấy trước khi xoay API key, thu hồi một node, gỡ duyệt một route, offboard một thành viên và siết policy ⇒ sau restore, tại thời điểm hostname trả lời lần đầu, API key cũ nhận `401`, node đã thu hồi vẫn hết hạn, route vẫn chưa được duyệt, user đã offboard không còn node hiệu lực và `GetPolicy` khớp bản đang áp dụng (ca bổ sung của AC-19).

Bổ sung cho ranh giới 3 (RLS): IT-17 — kết nối pool tái sử dụng (GUC rỗng) ⇒ 0 hàng, không lỗi; role ứng dụng `SELECT` thẳng một partition bị từ chối; pool tenant gọi `set_config('app.scope','platform',true)` vẫn không thấy hàng tenant khác hay bảng **P**; staff không có grant đang hiệu lực không mở được `WithTenantTx`.

Bổ sung cho ranh giới 12 (giả mạo telemetry tại nguồn): IT-18 — instance trả `/metrics` mang nhãn `tenant_id` của tenant khác và số series vượt trần ⇒ số liệu của B không đổi, target bị cắt theo `sample_limit`, Prometheus vẫn khỏe.

Bổ sung cho ranh giới 4 (điểm nghẽn dùng chung): IT-19 — giữ hàng nghìn stream nâng cấp nhàn rỗi trên hostname của A, làm đầy cache pending-auth của A và làm đầy quota `data/` của A ⇒ B vẫn enroll được, control của B không gián đoạn, PostgreSQL vẫn ghi.

Bổ sung cho ranh giới 10 (tiêm lỗi registry): IT-20 — hoán đổi riêng `internal_address`, riêng `api_key_secret_ref`, rồi cả hai giữa A và B trong registry của môi trường test ⇒ mọi lời gọi qua `ForTenant` thất bại (`401`, hoặc secret reference khác tenant bị từ chối), không dữ liệu nào của tenant kia được trả.

**Truy vết phép thử cách ly** (mỗi IT có task thực hiện, mức tự động và gate đầu tiên phải đạt):

| IT | Task thực hiện | Mức tự động | Gate đầu tiên |
|---|---|---|---|
| IT-01, 01b, 01c | P2-T06, P2-T15 | Tự động, mỗi PR | G2 |
| IT-02 | P2-T15 | Tự động (ma trận sinh từ OpenAPI), mỗi PR | G2 |
| IT-03 | P2-T03, P2-T15 | Tự động, mỗi PR | G2 |
| IT-17 | P2-T03, P2-T15; ca support grant: P4-T13 | Tự động, mỗi PR | G2; G4b (ca support grant) |
| IT-04 | P1-T13 (restart); P6-T09 (bão hòa CPU) | Thủ công có kịch bản | G1; G6 |
| IT-19 | P6-T09 | Thủ công có kịch bản | G6 |
| IT-05 | P1-T12; P5-T05 | Functional hằng đêm (client container); network-verified ở gate | G1; G5 |
| IT-06 | P2-T15 (mức adapter: `SetPolicy` qua `Registry.ForTenant`); chạy lại qua pipeline policy ở P4-T10 | Tự động, mỗi PR | G2 |
| IT-07, IT-08 | P5-T05a | Functional hằng đêm sau P4-T12; network-verified ở gate | G5 |
| IT-09 | P1-T12b; P5-T06 | Công cụ `derpprobe` | G1; G5 |
| IT-10 | P1-T09 (quyền file/UID); P2-T15 (API key, quét response) | Script + tự động | G1; G2 |
| IT-20 | P2-T15 | Tự động, mỗi PR | G2 |
| IT-11 | P3-T11 | Tự động (integration) | G3 |
| IT-15, IT-16 | P3-T11 | Tự động (integration trên Docker thật; thu hồi/gỡ duyệt/offboard của IT-16 dựng bằng adapter + fixture) | G3 |
| IT-12a | P2-T15 | Tự động, mỗi PR | G2 |
| IT-12b | P2-T13a (dashboard từ cache/health); phần relay metrics: P3-T05c, chạy lại với Prometheus ở P6-T01 | Tự động | G2 (dashboard); G3 (relay) |
| IT-12c | P6-T11 | Tự động | G6 |
| IT-18 | P6-T01 | Tự động | G6 |
| IT-13 | P1-T12 (pre-auth key); P5-T05 (Auth ID) | Thủ công → functional hằng đêm | G1; G5 |
| IT-14 | P1-T12c | Script; functional hằng đêm trên stack P2-T01a và sau mỗi thay đổi edge/template | G1 |

Tenant A không thể **xem, sửa, thu hồi hay đăng ký** thiết bị của tenant B vì: (a) không có đường API (IT-02), (b) không có credential (IT-10, IT-13), (c) không có đường mạng tới instance B ngoài các endpoint client công khai (network 2 thành viên), (d) frontend routing không tham gia vào quyết định nào.

### 5.3 Thành phần dùng chung và rủi ro tồn dư

| Thành phần dùng chung | Lý do chấp nhận ở MVP | Rủi ro tồn dư |
|---|---|---|
| Host, kernel, Docker daemon | Single-host MVP | Root/kernel bị chiếm ⇒ mọi tenant (T-14) |
| Edge (Caddy + CrowdSec), địa chỉ IP công khai | Cổng 80/443 là độc quyền trên một IP | SPOF; ban/giới hạn sai có phạm vi toàn nền tảng; lỗi cấu hình định tuyến hostname |
| VPS Public Gateway + STUN dùng chung | Host LAN không có IP công khai; STUN vốn không mang danh tính tenant | Gateway thấy metadata (IP client, hostname tenant qua SNI, dung lượng); gateway bị chiếm có thể gây gián đoạn hoặc giả mạo IP nguồn trong PROXY header (T-19) |
| PostgreSQL | Dữ liệu quản trị nhỏ; cách ly logic | Lỗi authz/RLS; lộ credential DB |
| IdP nền tảng (nếu tenant không mang IdP riêng) | Giảm chi phí vận hành | Lỗi cấu hình realm/issuer |
| Monitoring/log store | Vận hành tập trung | Lộ metadata chéo tenant cho nhân sự nền tảng (đúng thiết kế) |
| Kho backup | Một đích lưu trữ | Lộ nếu khóa backup bị lộ |
| Chứng chỉ wildcard, tài khoản ACME, zone DNS | Một chứng chỉ cho mọi hostname tenant (trần cấp phát của CA — EG-06) | Hết hạn/thu hồi/mất quyền DNS ảnh hưởng mọi tenant cùng lúc; khóa riêng của chứng chỉ nằm trên edge |
| KEK, Worker, Host Agent, hàng đợi job | Một Management Plane | KEK lộ ⇒ lộ secret của mọi tenant; Agent ≈ root trên host (R-15); job nặng của tenant này có thể làm chậm job của tenant khác |
