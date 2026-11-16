# Test Strategy

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §22 (phần mở đầu), §22.1, §22.4. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 22. Milestone Acceptance Criteria & Test Strategy

### 22.1 Test strategy

| Lớp | Phạm vi | Công cụ | Chạy khi |
|---|---|---|---|
| Unit | Logic thuần: lattice role, lint policy, render, state machine, SecretStore, ánh xạ lỗi | `go test`, Vitest | Mỗi commit |
| Integration | PostgreSQL thật (RLS, migration), Headscale thật (contract test adapter, pipeline policy), Docker thật (driver/agent) | testcontainers | Mỗi PR |
| **Isolation** | IT-01…IT-14 (§5.2) | Bộ test riêng `tests/isolation` | IT-01/02/03/06/10/11/12a: mỗi PR; IT-05/07/08/09/13/14 ở mức functional bằng client container (stack P2-T01a): hằng đêm; mức network-verified: G1 và G5; các phép thử bổ sung IT-15…IT-18 chạy theo bảng truy vết ở §5.2 |
| Security | Ma trận authz sinh từ OpenAPI; edge conformance (P1-T10a) trên mọi hostname tenant; secret scan repo/log/image; canary secret; các ca SSRF và IdP mix-up (T-20, T-21) | `tests/security`, scanner | Mỗi PR / hằng đêm |
| E2E (UI) | Luồng hai vai trò, hai ngôn ngữ, a11y | Playwright + axe | Hằng đêm + trước gate |
| E2E functional | Enrollment, policy, suspend/resume với client container trong stack dev/CI | `tests/e2e/harness` (P2-T01a, P3-T14a) | Mỗi PR có thay đổi liên quan; kết quả chỉ ghi "functional" |
| **Network E2E** | NAT, P2P trực tiếp, DERP relay, thu hồi, policy — với **official client trên thiết bị thật ở mạng khác nhau** | Quy trình có kịch bản + script thu bằng chứng | Gate G1 (một phần), G5 |
| Load / chaos | Mật độ tenant, polling, noisy neighbour, kill thành phần | `tests/load` | Phase 6 |
| DR | Restore tenant, restore PostgreSQL, upgrade/rollback, mất host | Runbook có kịch bản | Phase 3 (cơ bản), Phase 6 |

Quy tắc ghi nhận: kết quả từ container cùng host hoặc từ mô phỏng được ghi là **"functional"**; chỉ kết quả từ thiết bị thật trên mạng phù hợp mới được ghi **"network E2E verified"** (kèm sơ đồ mạng, phiên bản client, output lệnh). Mọi con số độ trễ là **giá trị đo**, không phải cam kết; các ngưỡng trong AC-17 là ngưỡng nghiệm thu nội bộ, không phải SLA.

**Tiền điều kiện chung cho mọi phép thử có client** (AC-08…AC-18, IT-05/07/08): tenant đang áp một policy cho phép đã biết (fixture `test-allow-intra` hoặc policy của bài thử), mỗi tenant có ≥ 2 node online và mỗi client thấy ≥ 1 peer cùng tenant. Dưới baseline deny-all, node **không có peer nào** nên mọi phép thử "không thấy node của tenant khác" sẽ đạt một cách vô nghĩa — nếu danh sách peer rỗng thì phép thử **không hợp lệ**.

### 22.4 Danh sách kiểm chứng bắt buộc cho các mục REQUIRES VALIDATION trọng yếu

Đây là sổ đăng ký kiểm chứng (khởi tạo ở P0-T06) và phải **đầy đủ**: mọi nhãn REQUIRES VALIDATION ở §3–§18 mang mã V (hoặc mã AC) ngay tại dòng đó và có hàng ở đây; nhãn trên dữ kiện của §2 được ánh xạ ở ghi chú cuối mục. Mỗi mã V có task thực hiện và gate chốt. Mã có gate đầu tiên ≤ G5 là **thuộc MVP** (điều kiện của Definition of Done Phase 5); mã chỉ có gate G6 hoặc muộn hơn (V-13, V-14, V-15, V-25, V-31) là sau MVP; V-29 là tùy chọn và V-34 chỉ mở khi dùng phương án dự phòng; kết quả đo được ghi vào `docs/planning/evidence/` và nhãn trong tài liệu được cập nhật trong cùng thay đổi.

| # | Điều cần kiểm chứng | Phép thử | Task | Gate |
|---|---|---|---|---|
| V-01 | DERP + control upgrade qua Caddy | Ép relay giữa hai client thật qua hostname tenant | P1-T05a, P1-T12 | G1 |
| V-02 | STUN dùng chung (`stund` tại điểm vào công khai) trả đúng IP/port công khai và được client của mọi tenant dùng | `tailscale netcheck` từ mạng ngoài; `tailscale debug derp-map` thấy STUN port 3478 và IP của điểm vào; `tailscale debug derp <region_code>` từ **một client trong LAN và một client ngoài LAN**: cả hai có kết nối DERP và phản hồi STUN (`derp.server.ipv4` thay thế DNS — §10.1) | P1-T18, P5-T02a | G1 |
| V-03 | Upstream động theo nhãn + attach network lúc chạy | Thêm tenant khi client tenant khác đang kết nối; không rớt stream; bắt gói DNS trên host khi gửi 1.000 nhãn ngẫu nhiên khớp regex slug và khi gọi một tenant đang dừng ⇒ **0** truy vấn đi ra resolver ngoài, mọi phản hồi là `404` trong cùng dải độ trễ với một path bị chặn trên tenant đang chạy (§14.6) | P1-T12d, P1-T10a | G1 |
| V-04 | Headscale chạy non-root, read-only | Instance healthy với UID riêng | P1-T11 | G1 |
| V-05 | Chặn `/verify` không ảnh hưởng embedded DERP | Relay vẫn hoạt động khi `/verify` trả 404 ở edge | P1-T05a | G1 |
| V-06 | Key tạo không kèm `expiration`; policy rỗng; mã lỗi HTTP của `SetPolicy`; `/key` cần `?v=`; decoder policy với khóa khác kiểu chữ, khóa `#`, giá trị `null` | Contract test | P2-T10 | G2 |
| V-07 | Chuyển hướng `/register/<auth_id>` về Portal | Đăng ký hoàn tất trên từng OS | P4-T07 | G4a |
| V-08 | Client 1.104.x trên 5 hệ điều hành | Ma trận tương thích | P1-T12e (sơ bộ), P5-T03 | G5 |
| V-09 | Độ trễ thu hồi và lan truyền policy; hành vi peer offline | Đo theo AC-17 | P5-T04, P5-T07 | G5 |
| V-10 | Tunnel direct khi control plane của tenant ngừng | Đo theo AC-18 | P1-T13 | G1/G5 |
| V-11 | Hành vi client khi Noise key đổi / restore bản cũ | Thử trên tenant test | P3-T11 | G3/G6 |
| V-12 | `VACUUM INTO` trên DB đang hoạt động + restore | Restore bản backup lấy lúc có client hoạt động; sau 100 lần backup online khi client liên tục kết nối/ngắt: Headscale restart sạch trong `stop_grace_period` và mọi file trong `data/` vẫn thuộc `run_uid`; xác nhận `VACUUM INTO` chạy được với mount `data/` chỉ-đọc (§11.5); lặp ≥ 1.000 lần backup online dưới tải ghi: owner/mode của `db.sqlite`, `-wal`, `-shm` không đổi và `VACUUM INTO` chạy được với mount `data/` chỉ-đọc; restart Headscale giữa lúc backup ⇒ instance lên sạch và backup hoặc hoàn tất hoặc thất bại rõ ràng (không có archive hỏng); backup lúc instance đã dừng đi đúng nhánh cold copy | P3-T11, P6-T04 | G3/G6 |
| V-13 | Tài nguyên/instance, mật độ/host, chi phí polling (bcrypt) | Load test | P6-T08 | G6 |
| V-14 | CrowdSec không khóa nhầm NAT của tenant | Replay lưu lượng nhiều client sau một IP | P6-T07b | G6 |
| V-15 | Quy mô số realm của IdP | Load test IdP | P6-T08 | Trước mốc 100 tenant |
| V-16 | Control upgrade + DERP qua chuỗi VPS `l4proxy` (TCP, PROXY v2) → tunnel → Caddy | Đăng ký và ép relay giữa hai client thật qua Internet | P1-T18 | G1 |
| V-17 | Edge nhận đúng IP client qua PROXY protocol và chỉ chấp nhận PROXY header từ peer tunnel | So IP trong log edge với IP thật; thử kết nối tới listener tunnel-facing không có header / từ nguồn khác | P1-T17, P1-T18 | G1 |
| V-18 | Stream dài (control long-poll, DERP) không bị `l4proxy`/tunnel cắt khi nhàn rỗi | Để client yên ≥ 30 phút, theo dõi số lần reconnect | P1-T18 | G1 |
| V-19 | CAA giới hạn cấp chứng chỉ về `dns-01` + đúng tài khoản ACME | `dig CAA`; thử xin chứng chỉ HTTP-01 bằng tài khoản khác ở CA staging ⇒ bị từ chối | P1-T18 | G1 / G6 |
| V-20 | Thông lượng và độ trễ của đường relay qua VPS + uplink của LAN | Đo truyền dữ liệu khi ép relay; so với đường trực tiếp | P5-T06 | G5 / G6 |
| V-21 | `node.expiry` chỉ là mặc định (hạn do client yêu cầu được ưu tiên) ⇒ kiểm cả việc client thật thực thi hạn lẫn việc nền tảng kẹp hạn | (i) Đặt expiry ngắn trên tenant thử; quan sát client về trạng thái cần đăng nhập lại và peer loại bỏ nó. (ii) Ca âm: client thử dựng từ thư viện Tailscale đã pin (cùng cách với `derpprobe`) gửi `RegisterRequest.Expiry` xa hơn hạn của tenant ⇒ sau `inventory.sync`, node có `expiry` ≤ `registered_at + node_expiry` và có `security_event(kind=expiry_overridden)` | P2-T10, P2-T13 (ii); P5-T07a (i) | G2 (ii); G5 (i) |
| V-22 | Nhận diện NAT với một STUN endpoint duy nhất (§10.4) | `tailscale netcheck` từ nhiều loại NAT; so `MappingVariesByDestIP` với thực tế (kỳ vọng theo source: luôn `false` khi chỉ có một STUN endpoint — §10.4) | P5-T06 | G5 |
| V-23 | Offboarding phía IdP: user bị vô hiệu ở IdP không đăng nhập lại được Portal và node bị expire | Offboard một user thử rồi thử đăng nhập và kết nối lại | P4-T09 | G4b |
| V-24 | `tests` của policy có khẳng định được quyền chỉ đến từ `via`/`autogroup:self` hay không | `CheckPolicy` với policy mẫu có `via` và `autogroup:self` | P5-T01 | G5 |
| V-25 | Đếm được số stream nâng cấp đang mở theo hostname tại edge (§10.6) | So số liệu metrics/log của Caddy với số client đang kết nối | P6-T01 | G6 |
| V-26 | `AuthRegister` với Auth ID không đến từ luồng `/register/` (phiên SSH-check) không làm Headscale lỗi nghiêm trọng; `AuthApprove` trên Auth ID đăng ký (§7.4); trạng thái policy khi `SetPolicy` trả lỗi sau khi đã hoán đổi trong bộ nhớ (§7.3) | Contract test trên Headscale thật | P2-T10 | G2 |
| V-29 | Peer relays với client stable hiện hành (CL-13, §10.5) | `tailscale status` in `peer-relay` giữa hai client của cùng tenant | P5-T11 (tùy chọn) | Không chặn gate (chỉ khi người dùng yêu cầu) |
| V-34 | STUN publish trực tiếp theo tenant qua Docker, gồm IPv6 (EG-10, §2.7) — **chỉ** khi dùng phương án dự phòng (a) ở §10.3 | `tailscale netcheck` IPv4/IPv6 thấy đúng IP/port công khai | Chỉ mở khi V-02 không đạt (P1-T18) | G1 |
| V-32 | Edge trả tĩnh `/bootstrap-dns` không ảnh hưởng client (§14.6) | Client thật đăng ký và kết nối relay bình thường khi edge trả JSON tĩnh; ghi nhận client có gọi endpoint này hay không | P1-T12 | G1 |
| V-33 | Edge gắn ~100–300 network tenant lúc chạy (thời gian attach, restart/recreate, phân giải tên upstream) và nền tảng tự phục hồi sau reboot host / restart `dockerd` | Network giả + tenant A/B thật, đo theo P1-T20/P1-T21; lặp lại khi orchestrator đang chạy; quy mô đầy đủ trong load test | P1-T20, P1-T21, P3-T14, P6-T08 | G1 (sơ bộ) / G3 / G6 |
| V-27 | Official client liên lạc những host nào của Tailscale Inc. khi dùng Headscale (CL-16), và `TS_NO_LOGS_NO_SUPPORT` có chặn được việc gửi log hay không | Bắt gói DNS + SNI trên client ở bốn tình huống: trước khi đăng nhập; sau map đầy đủ đầu tiên; khi STUN bị chặn (chỉ còn TCP 443); khi DNS hệ thống lỗi — rồi lặp lại với `TS_NO_LOGS_NO_SUPPORT=true`. Danh sách host quan sát được đưa vào thông báo quyền riêng tư (§15.5) | P1-T12e (sơ bộ, Linux), P5-T03 | G5 |
| V-31 | cAdvisor không có Docker socket vẫn ghép được nhãn tenant: nhãn `id` chứa container ID và join được với `meshguard_instance_info` (§16.1) | So nhãn `id` do cAdvisor xuất với `container_id` do Agent báo; dashboard theo tenant cho đúng số liệu của hai tenant thử | P6-T01 | G6 |
| V-30 | Site public của edge chỉ `bind` IP trên `mg-edge` mà mọi cổng publish (LAN-direct, tunnel-facing) vẫn hoạt động; từ network tenant không tới được site hay listener nào của edge (§14.3) | P1-T10: gọi từng cổng publish sau khi đặt `bind`; IT-14 (cả hai biến thể probe) không mở được kết nối tới cổng public và cổng admin/metrics qua IP của edge trên network tenant | P1-T10, P1-T12c | G1 |
| V-28 | Hành vi adapter nêu theo đọc source của reviewer, chưa chạy thử: `GetNode` so với `ListNodes` (`subnet_routes`, user của tagged node); `SetTags` với danh sách rỗng; `AuthRegister` trên machine key đã có node — của chính user (re-auth, không tạo node mới) và của user khác (§7.4, §13.4) | Contract test trên Headscale thật | P2-T10 | G2 |

**Ánh xạ nhãn REQUIRES VALIDATION của §2 vào sổ:** PL-06 → V-06; PL-12 → V-09; ID-04 → V-23; DP-09 (nửa sau: chặn `/verify`) → V-05; RT-06 → V-11; RT-09 và hàng client `1.104.7` của §2.7 → V-08; CL-11 → V-10; CL-13 và hàng peer relays của §2.7 → V-29; EG-01 và hàng Caddy của §2.7 → V-01; EG-10 và hàng embedded STUN của §2.7 → V-34; ST-04 → V-15; GW-03, GW-05 → V-16, V-18. Nhãn trên dữ kiện mà thiết kế **không dùng** không cần phép thử: CL-03 (private CA), RT-07 (list qua biến môi trường), ST-10 (rootless Docker), nửa đầu DP-09 (derper sau L4 passthrough — chỉ xét ở P7-T04), HS-22 (`nodeAttrs` bị lint L3 từ chối), OIDC provider tích hợp của R2 và các tuyên bố của R4 (tenant isolation, database consistency — §2.4, §2.8); nếu thiết kế bắt đầu dựa vào chúng thì phải thêm mã V trước. CL-15 không phải phép thử kỹ thuật: do tư vấn pháp lý kết luận (R-01, D-6).
