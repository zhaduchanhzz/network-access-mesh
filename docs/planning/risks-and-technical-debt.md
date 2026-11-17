# Risks & Technical Debt

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §23. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 23. Risks & Technical Debt

### 23.1 Risk register

| ID | Rủi ro | Căn cứ | Mức | Giảm thiểu / kế hoạch | Chủ sở hữu quyết định |
|---|---|---|---|---|---|
| R-01 | **Pháp lý/giấy phép khi dùng official Tailscale Client cho dịch vụ thương mại** (ToS giới hạn mục đích dùng "Client Software"; GUI Windows/macOS/iOS mã đóng; chưa thấy chính sách thương hiệu) | CL-15 | Cao (kinh doanh) | Ý kiến pháp lý sơ bộ bằng văn bản **trước G2** — **chủ dự án xác nhận 2026-11-16: "R-01 thông qua và đã được đồng ý"** (`docs/planning/evidence/R-01.md`); đầy đủ **trước G6**; không dùng tên/logo Tailscale trong tiếp thị; phương án lùi cần đánh giá: khách tự cài client, hoặc build từ mã nguồn mở BSD-3 (tailscaled/CLI/Android) dưới tên khác | Người dùng |
| R-02 | Mô hình triển khai nằm ngoài phạm vi hỗ trợ của upstream (Docker, reverse proxy; "not enterprise software") | HS-03, RT-03, HS-23 | Cao | Bộ integration + network E2E riêng; tái hiện lỗi không qua proxy trước khi báo upstream; pin version | Tech lead |
| R-03 | API Headscale thay đổi phá vỡ (0.30 thay REST v1, bỏ gRPC); mỗi minor đều có breaking change | RT-11 | Cao | Adapter có lớp version + contract test; pin theo instance; không tự nâng minor | Tech lead |
| R-04 | Giới hạn quy mô một tailnet ("100s of devices" nếu ít biến động); `autogroup:self` tốn tài nguyên | HS-23, HS-08 | Trung bình–Cao | Quota thiết bị theo plan; đo ở Phase 6; tier host riêng cho tenant lớn | Product |
| R-05 | DERP qua Caddy chưa được upstream kiểm chứng — spike P1-T05a **đạt** ở LAN NAT (2026-11-16); đường qua VPS gateway cũng **đạt** (P1-T18: ép relay 20 MiB, stream 36 phút không rớt); còn thử từ client ở mạng ngoài; xét hạ mức ở báo cáo G1 (P1-T14) | §10.1, V-01, V-16 | Cao (chặn G1) | PoC sớm nhất có thể; phương án lùi: PoC (e) trước, (c) là cuối cùng (§10.3) | Tech lead |
| R-06 | STUN dùng chung là thành phần chung của mọi tenant; chỉ có một STUN endpoint/IP nên khả năng nhận diện hard NAT bị hạn chế | V-02, §10.4 | Trung bình | Test `netcheck`; `stund` stateless nên dễ khởi động lại/nhân bản; thêm STUN ở IP thứ hai khi multi-host | Tech lead |
| R-07 | Single host: SPOF và cách ly dùng chung kernel | T-14, §3.5 | Cao (đã công bố) | Backup offsite, runbook; lộ trình multi-host; tier riêng | Người dùng (chấp nhận rủi ro) |
| R-08 | Reload edge đóng stream của mọi tenant | EG-02 | Trung bình | Định tuyến không cần reload; `stream_close_delay`; cửa sổ bảo trì | SRE |
| R-09 | Không có metrics relay và không đo được traffic P2P | §10.6 | Trung bình | Số đo xấp xỉ; billing không theo traffic; nói rõ với khách | Product |
| R-10 | Thu hồi/lan truyền policy không có cam kết thời gian; peer offline giữ netmap cũ | CL-12, T-17, T-18 | Trung bình–Cao | Trạng thái hai pha, đo thực tế, `node.expiry` ngắn | Security |
| R-11 | Không có Tailnet Lock ⇒ tenant phải tin control plane của nhà vận hành | CL-14, T-03 | Trung bình | Dual control, audit minh bạch, thông báo node mới; công bố cho khách | Security |
| R-12 | Upstream không có kênh advisory/chính sách hỗ trợ; bản vá chỉ ở minor mới nhất | RT-12 | Trung bình | Theo dõi release feed; quy trình vá nhanh theo đợt | SRE |
| R-13 | IdP: footprint RAM và quy mô số realm | ST-04, V-15 | Trung bình | Gating theo phần cứng; IdP của tenant; phương án Organizations chỉ khi đạt điều kiện ở §8.2 | Tech lead |
| R-14 | River còn pre-1.0; periodic job bản OSS không bền | ST-01 | Thấp–Trung bình | `RunOnStart`; handler idempotent; có phương án outbox | Tech lead |
| R-15 | Host Agent tương đương root | T-14 | Cao (đã kiểm soát) | Spec khai báo + allowlist; không network; review code bắt buộc; đánh giá rootless ở Phase 6 (ST-10, P6-T07) | Security |
| R-16 | CrowdSec khóa nhầm IP NAT của tenant; bouncer và module rate-limit là hai module bên thứ ba chạy trong edge | EG-08, EG-09, EG-11 | Trung bình | Allowlist, thời hạn ban ngắn, nút gỡ ban; pin commit + review mã nguồn từng module (P0-T03, P1-T04) | SRE |
| R-17 | Thiếu thông tin môi trường (domain + DNS provider, phần cứng host LAN và VPS, quota băng thông VPS) | Appendix A | Cao (chặn Phase 1) | G0 yêu cầu trả lời; thiết kế đã có nhánh cho từng trường hợp | Người dùng |
| R-23 | **VPS Public Gateway**: mật khẩu root đã bị lộ trong hội thoại; thêm hai SPOF nối tiếp (VPS, tunnel/đường truyền LAN); toàn bộ control + relay đi qua băng thông VPS và uplink của LAN | §14.9, T-19 | Cao | SSH key đã có (2026-11-16); chủ dự án **không đổi** mật khẩu root đã lộ (chấp nhận rủi ro, 2026-11-16) ⇒ đăng nhập SSH bằng mật khẩu **đã tắt** ở P1-T15 (2026-11-16); VPS stateless, không khóa TLS; CAA giới hạn (P1-T18, V-19 đạt); diễn tập dựng lại gateway 14,1 s; đo thông lượng (V-20); lộ trình Path C khi cần | Người dùng + SRE |
| R-18 | Grants/tests trong Headscale còn mới (0.29, 06/2026), tests gắn nhãn beta | PL-01, PL-04 | Trung bình | Lint phía nền tảng độc lập với tests; contract test theo version | Tech lead |
| R-19 | Đổi DNS/OIDC/DERP phải restart instance ⇒ rớt phiên relay của tenant | RT-04 | Thấp–Trung bình | Gom thay đổi; thông báo; dùng extra-records cho thay đổi thường xuyên | SRE |
| R-20 | Mỗi lời gọi API tới Headscale tốn một lần bcrypt ⇒ chi phí polling | RT-15 | Trung bình | Polling thưa + sync theo sự kiện ghi; đo ở Phase 6 | Tech lead |
| R-21 | Khác biệt nền tảng client (Windows không có GUI nhập server; iOS cần MDM cho policy) | CL-04 | Trung bình | Hướng dẫn theo OS; hỗ trợ `LoginURL` cho triển khai hàng loạt | Product |
| R-22 | Phishing kiểu device-code ở luồng web-auth | T-06 | Trung bình | Claim chỉ khi có yêu cầu đang chờ trong cùng phiên + mã enrollment trong hostname + kiểm node sau đăng ký; link claim lạ hiển thị cảnh báo phishing; thông báo + thu hồi nhanh (§7.4) | Security |
| R-24 | Thiếu thiết bị thử, mạng thứ hai ngoài LAN hoặc VPS chưa sẵn sàng ⇒ không đạt được mức "network E2E verified" | §22.1, G1(4), Phase 5 | Cao (chặn G5) | G0 yêu cầu danh sách client; G1(4) phải đóng trước các task lab của Phase 5, hoặc có quyết định "MVP LAN-only" bằng văn bản | Người dùng |
| R-25 | Chỉ có một người vận hành trong khi thiết kế yêu cầu dual control (2P) | §8.5, ADR-13 | Trung bình | Chốt D-11 ở G0: ≥ 2 người, hoặc chế độ thay thế "trì hoãn thực thi có thông báo" được ghi vào ADR-13 | Người dùng |
| R-26 | Phạm vi UI của Phase 4 phình to làm chậm việc kiểm chứng trên mạng thật | §12, Phase 4 | Trung bình | Tách G4a/G4b: UI tối thiểu cho enrollment/policy/devices trước, phần còn lại sau | Product |
| R-27 | Phiên bản đã pin lỗi thời trong lúc xây (bản vá bảo mật của Headscale/client; client di động tự cập nhật) | RT-12, HS-05 | Trung bình | Rà phiên bản ở mỗi gate; contract test + smoke client trước khi nâng pin | Tech lead |
| R-28 | CI runner tự host (D-12): job CI chạy code của repo và cần Docker trên máy runner; nếu runner nằm trên host LAN staging hoặc dùng Docker socket của host đó thì một workflow lỗi hoặc bị chiếm có quyền tương đương root trên nơi giữ dữ liệu tenant và KEK (trái ADR-05); repo public cho phép PR từ fork kích hoạt workflow | D-12, T-13, ADR-05 | Cao | Runner trên máy hoặc VM riêng, không phải host LAN staging, không mount `/opt/meshguard` hay Docker socket của host đó; **hiện không dùng self-hosted runner**: repo public theo quyết định của chủ dự án (2026-11-16), CI chạy trên runner của GitHub; nếu sau này dùng self-hosted runner thì chỉ cho repo private, mỗi job một runner hoặc job chạy trong container; chỉ nhận job của repo này, workflow từ fork phải được duyệt; token GHCR chỉ đủ quyền đẩy image của repo; action pin theo commit SHA (§25.1 quy tắc 8); không đặt secret nào khác vào CI | Chủ dự án + Security |
| R-29 | **Repo công khai** (chủ dự án quyết định ngày 2026-11-16): tài liệu và evidence công khai sơ đồ hạ tầng, IP LAN và VPS, domain, tư thế bảo mật — mật khẩu root đã lộ mà không đổi (D-10); VPS từng cho đăng nhập SSH bằng mật khẩu (đã tắt ở P1-T15, 2026-11-16) | D-10, D-12, T-19 | Trung bình–Cao | Không bao giờ commit secret (gitleaks ở pre-commit và CI); đăng nhập SSH bằng mật khẩu trên VPS đã tắt (P1-T15); không gắn self-hosted runner vào repo public; trước go-live cân nhắc chuyển evidence chi tiết sang kho riêng | Chủ dự án |

Cột "Chủ sở hữu quyết định" ghi **vai trò**; tên người chịu trách nhiệm cho từng rủi ro được chốt ở P0-T02. Toàn bộ sổ rủi ro được rà lại tại mỗi gate (§19).

### 23.2 Technical debt được chấp nhận có chủ đích

| ID | Nợ kỹ thuật | Lý do chấp nhận ở MVP | Điều kiện trả nợ |
|---|---|---|---|
| TD-01 | Inventory bằng polling + cache | Headscale không có webhook/stream | Khi upstream có event API hoặc khi chi phí polling vượt ngưỡng đo |
| TD-02 | Relay không có metrics chính xác | Embedded DERP không xuất metrics | Chuyển sang derper độc lập nếu P7-T04 kết luận Go |
| TD-03 | Envelope encryption trong PostgreSQL thay cho KMS; api cũng giữ `kek-app` (KEK bọc DEK của mọi tenant) vì chưa có "secret broker" (ADR-17) | Không thêm dịch vụ phải vận hành | OpenBao khi multi-host (backlog sau P7-T01, chưa có task) |
| TD-04 | Một edge duy nhất | Một IP/host | Multi-host |
| TD-05 | Dump hằng đêm trước khi có PITR | Đơn giản cho MVP (dump do P2-T03a đảm nhiệm); cửa sổ mất dữ liệu tới 24 giờ được chấp nhận và xử lý bằng đối soát sau restore (§17.2, P3-T17) | P6-T03 |
| TD-06 | Client REST tự viết gắn với API v1 của 0.29 | 0.30 thay API | P7-T09 |
| TD-07 | Chưa có what-if policy | Không có API upstream | Evaluator/shadow instance — backlog sau MVP (chưa có task) |
| TD-08 | Portal cập nhật bằng polling | Giảm phạm vi | WebSocket/SSE khi cần |
| TD-09 | Một STUN endpoint duy nhất (một IP) và mọi lưu lượng public đi qua một VPS gateway | Chỉ có một IP công khai | Thêm gateway/STUN thứ hai hoặc chuyển sang Path C (Phase 7) |
| TD-10 | DR thủ công theo runbook | Một host | Tự động hóa sau P7-T02 (backlog, chưa có task) |
| TD-11 | Audit chưa có hash-chain/đẩy ra ngoài | Phạm vi MVP | P6-T02 |
| TD-12 | Chưa allow-list đích đi ra của `mg-egress` bằng `DOCKER-USER` (network tenant đã là `internal` từ Phase 1; rule chặn pool tenant → host và IT-14 thuộc G1; rule theo pool tenant ở Phase 6 chỉ là lớp bổ sung) | Cần kiểm chứng quy tắc firewall trên host thật | P6-T07 |
| TD-13 | Role lấy từ backend, chưa ánh xạ từ claim IdP | Tránh leo thang qua IdP | P7-T06 (opt-in) |
| TD-14 | Không xây ở MVP: phương thức enrollment C (OIDC gốc của Headscale — chỉ kiểm chứng tùy chọn ở P5-T10), billing, DNS driver tạo bản ghi theo tenant (dùng wildcard) | Giảm phạm vi; chưa có yêu cầu cụ thể | Khi có khách cần (Phase 7) |
| TD-15 | Listener admin/metrics nằm trong edge public: API key của mọi tenant đi qua tiến trình nhận toàn bộ lưu lượng Internet (T-05) | Giữ network tenant đúng hai thành viên (ADR-08) và không thêm gateway thứ hai ở MVP; token nội bộ đã không còn tới được instance (§14.6) | Quyết định tách sang gateway nội bộ không publish (Caddy gốc, không module ngoài) ở review go-live G6 (P6-T12); muộn nhất khi multi-host (P7-T01) |
| TD-16 | Chưa có luồng đổi IdP của tenant (hàng `pending` → liên kết lại qua `identity_links` → cắt chuyển — §8.2) | Không thuộc tiêu chí nghiệm thu MVP; `issuer`/`client_id` bất biến nên không có thao tác nào khóa tenant ra ngoài | P7-T06 |
| TD-17 | Bản vá Headscale do dự án duy trì (ADR-02 sửa đổi 2026-11-17; bản đầu `mg.1` sửa V-26 — P2-T10): image `mg-headscale` tự build, khác image chính thức ở hai bản vá, Go 1.27.4 + `-trimpath`, base distroless mới hơn, user mặc định 65532 | 0.29.7 chính thức làm sập control plane của tenant khi `AuthRegister` nhận Auth ID của phiên SSH-check; upstream chưa có bản sửa; chủ dự án chọn vá và **không báo upstream** | Mỗi lần nâng Headscale: rebase bản vá (`git apply --check` trong Dockerfile dừng build khi lệch), cập nhật `[sources.headscale]`, chạy lại contract test kèm đối chứng âm; gỡ từng bản vá khi upstream sửa đúng lỗi đó và contract test xanh trên bản upstream không cần bản vá — khi đó quay lại image chính thức |
