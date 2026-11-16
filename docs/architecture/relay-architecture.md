# Relay Architecture (DERP/STUN)

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §10. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 10. DERP/STUN Architecture

### 10.1 Quyết định cho MVP (ADR-11): embedded DERP riêng cho từng tenant + STUN dùng chung tại điểm vào công khai

| Khía cạnh | Thiết kế | Căn cứ |
|---|---|---|
| Relay | Bật embedded DERP trong **mỗi** Headscale instance; `verify_clients: true` | Xác minh in-process, **fail-closed**, chỉ nhận node key có trong node list của chính instance đó ⇒ node của tenant khác bị từ chối (upstream có integration test cho key lạ). VERIFIED `[HS:hscontrol/derp/server/derp_server.go]`, `[HS:integration/embedded_derp_test.go]` |
| DERP map | `derp.urls: []`, `derp.paths: []` ⇒ client của tenant chỉ thấy relay của tenant | Không phụ thuộc/không lộ metadata **relay** cho DERP của Tailscale Inc. (ngoại lệ phía client: DNS fallback và `netcheck` khi chưa có map vẫn hỏi DERP của Tailscale — CL-16); tránh việc Headscale **không khởi động** khi fetch URL thất bại. Đánh đổi: một relay = SPOF, không có đa vùng (HS-17) |
| Cấu hình | Ghi **tường minh mọi khóa** `derp.server.*` (`enabled, region_id, region_code, region_name, verify_clients, stun_listen_addr, private_key_path, automatically_add_embedded_derp_region, ipv4, ipv6`) và `auto_update_enabled` | Trong code chỉ có default cho `enabled` (false), `verify_clients` (true), `automatically_add_embedded_derp_region` (true) và `derp.update_frequency` (3h); **không** có default cho `region_id`, `region_code`, `region_name`, `stun_listen_addr`, `private_key_path`, `ipv4`, `ipv6`, `auto_update_enabled` (chỉ có trong file ví dụ). Vẫn ghi tường minh mọi khóa để hành vi không phụ thuộc default nào. VERIFIED `[HS:hscontrol/types/config.go]` (đối chiếu lại ở Rev 3) |
| Đường DERP (TCP) | Client → `https://<slug>.<mesh_domain>:443/derp` (TLS tại edge) → `Upgrade: DERP` → Headscale `:8080` trong network của tenant | Region tự sinh lấy host/port từ `server_url` (RT-14). Client luôn dial TLS và yêu cầu `101` (không có WebSocket fallback trên client native). **REQUIRES VALIDATION** (V-01): upstream không test DERP sau HTTP reverse proxy ⇒ đây là **Go/No-Go gate của Phase 1** |
| STUN (UDP) | **Một STUN responder dùng chung** — `stund`, tự build từ `tailscale.com/cmd/stund` tại tag đã pin — lắng nghe UDP 3478 ở điểm vào công khai (VPS khi Internet-facing; host LAN khi Local Development), chạy host network. Mọi tenant đặt `stun_listen_addr: 0.0.0.0:3478` (bind trong container, **không publish**) và `derp.server.ipv4` = IP của điểm vào (`ipv6` để trống — MVP chỉ IPv4, không tạo bản ghi AAAA: §15.4) ⇒ region tự sinh quảng bá DERP `<hostname tenant>:443` + STUN `:3478`. **Hệ quả phải ghi nhận:** khi `ipv4` được đặt, client dùng nguyên văn IP này cho cả STUN lẫn kết nối TCP tới DERP và **không tra DNS** (DP-05; theo phản biện đối chiếu `[TS:tailcfg/derpmap.go]`) ⇒ split DNS không đổi được đích, và đổi IP của điểm vào (chuyển từ Local Development sang VPS, thay VPS/gateway) phải render lại config + restart **mọi** instance — chỉ đổi DNS là chưa đủ. **Giá trị `ipv4` thay thế DNS ở client:** cả kết nối TCP tới DERP lẫn STUN đều đi tới đúng địa chỉ này và client không tra DNS, kể cả client trong LAN (theo phản biện — reviewer đọc `GenerateRegion` của Headscale, `derphttp`/`netcheck` của client và chú thích của `tailcfg.DERPNode.IPv4`) ⇒ split DNS không đổi được đích; đổi điểm vào (Local Development → VPS, thay gateway) phải render lại config + restart có kiểm soát **mọi** instance (RT-04) — chỉ đổi DNS là chưa đủ. Giá trị do Agent suy ra từ `hosts.public_entry`, không nhận từ tenant | Cổng quảng bá lấy từ `stun_listen_addr` (RT-14); client gửi STUN tới IPv4/IPv6 của node trên đúng `STUNPort` (VERIFIED `[TS:net/netcheck/netcheck.go]`); `stund` có sẵn trong source Tailscale (GW-01). STUN stateless, không xác thực, không mang danh tính tenant; chỉ **một** tiến trình bind UDP 3478 trên IP công khai nên không có xung đột cổng. **REQUIRES VALIDATION** (V-02): `tailscale netcheck` từ mạng ngoài báo đúng IP/port công khai |
| Tên region | `region_code` riêng theo tenant (ví dụ `mg-<slug>`) để `tailscale status`/`ping` chỉ rõ relay của tenant nào | CL-08 |
| Region | `region_id` trong dải 900–999 (dành cho DERP tự vận hành; phạm vi ID chỉ trong map của một control server nên các tenant dùng lại cùng số được) | VERIFIED `[TS:tailcfg/derpmap.go]` / ASSUMED (dùng lại ID giữa các tenant — kiểm ở P1-T12: A và B dùng cùng `region_id`, `tailscale debug derp-map` của mỗi client chỉ có region của tenant mình) |
| Captive portal | `http://<host>/generate_204` trả `204` tại edge (embedded DERP không hỗ trợ endpoint này) | HS-15, HS-17. Thực tế chỉ `tailscale debug derp` gọi endpoint này: client không dùng nó để dò captive portal vì region embedded không đặt `CanPort80`, và client vẫn thử URL trên host của Tailscale Inc. (CL-16). Dò captive portal theo tenant (map tùy biến qua `derp.paths` với `ipv4` + `canport80: true`, site `http://` bắt mọi Host trả `204` kèm header `X-Tailscale-Response` đáp lại challenge) là backlog sau MVP, chưa có task |
| `/verify` | **Chặn** ở edge public (là membership oracle cho node key — DP-08); embedded DERP không cần endpoint HTTP này vì xác minh in-process | VERIFIED (cơ chế) / REQUIRES VALIDATION (V-05: chặn `/verify` không ảnh hưởng embedded DERP) |

### 10.2 Ánh xạ host/network/port thực tế trên một host

Không giả định nhiều container cùng bind một cổng trên một IP.

| Tài nguyên | Tenant A | Tenant B | Thành phần bind cổng trên host |
|---|---|---|---|
| Control + DERP (TCP 443) | `a.<mesh_domain>` → edge → `hs-a:8080` | `b.<mesh_domain>` → edge → `hs-b:8080` | **Chỉ Caddy** (edge trên host LAN) terminate TLS và định tuyến theo hostname; ở Internet-facing, `l4proxy` trên VPS bind TCP 443 và chuyển tiếp nguyên luồng |
| HTTP (TCP 80) | redirect + `/generate_204` | như A | Caddy trên host LAN; `l4proxy` trên VPS bind TCP 80 và chuyển tiếp |
| STUN (UDP 3478) | dùng chung | dùng chung | **Chỉ `stund`** bind UDP 3478 tại điểm vào công khai; container Headscale bind `:3478` trong network namespace riêng và **không publish** |
| Metrics/debug `:9090` | chỉ trong network tenant A | chỉ trong network tenant B | Không publish; Prometheus đọc qua listener metrics nội bộ của edge (chỉ path `/metrics`) |
| gRPC `:50443` | không khởi động (RT-01) | như A | — |
| Unix socket | tmpfs trong container | như A | Không chia sẻ ra ngoài container |

Không container tenant nào publish cổng ra host ⇒ network của tenant là `internal` (không có đường ra ngoài) và không cần cấp phát/forward dải cổng UDP theo tenant. Phương án dự phòng "mỗi tenant một cổng UDP STUN publish trực tiếp" (cột `stun_port`) chỉ dùng khi instance chạy trên host có IP công khai trực tiếp **và** phép thử V-02 với STUN dùng chung không đạt.

### 10.3 So sánh các phương án relay trên một host có N tenant

| Phương án | Ưu điểm | Nhược điểm / rủi ro | Trạng thái |
|---|---|---|---|
| (a) Embedded DERP mỗi tenant + cổng STUN riêng publish trực tiếp | Chỉ dùng cơ chế gốc của Headscale; không thêm thành phần | Nhiều cổng UDP; **không đi qua được VPS gateway** nếu không DNAT giữ IP nguồn + định tuyến chính sách qua tunnel (dễ vỡ); phụ thuộc Docker publish giữ IP nguồn | Dự phòng — chỉ cho host có IP công khai trực tiếp |
| **(b) Embedded DERP mỗi tenant + một STUN responder dùng chung (`stund`) trên UDP 3478** | Cách ly relay theo tenant sẵn có (verify in-process); một cổng UDP chuẩn; container tenant không publish cổng; khớp với VPS gateway; với client, region vẫn ở dạng chuẩn `host:443` + `host:3478` | Thêm một image phải tự build; STUN là thành phần dùng chung (bị quá tải thì mọi tenant giảm khả năng kết nối trực tiếp, vẫn còn relay); DERP đi qua Caddy (chưa được upstream test); không rate limit/metrics relay; restart Headscale làm rớt phiên relay của tenant | **Chọn cho MVP** — phụ thuộc V-01 và V-02 |
| (c) derper độc lập cho từng tenant | Có metrics (`bytes_sent/received`, kết nối), accept limiter, `-rate-config` | Upstream cấm đặt sau HTTP proxy/LB (DP-04) và khuyến cáo không dùng chung IP giữa các DERP server ⇒ muốn giữ cổng 443 cần **một IP công khai cho mỗi derper** (VPS hiện có một IPv4; `l4proxy` chỉ chuyển tiếp 80/443); dùng `DERPPort` khác 443 thì mạng chỉ cho TCP 443 **không** relay được (phải sửa §15.5) và phải mở thêm cổng ở VPS; chứng chỉ manual ⇒ restart derper mỗi kỳ gia hạn, rớt phiên relay; derper không nhận PROXY protocol; phải tự build image; `fail-open` mặc định phải tắt | Dự phòng **cuối** — chỉ sau khi PoC (e) không đạt — nếu gate "DERP qua Caddy" thất bại; nền cho relay vùng |
| (d) Một derper dùng chung + verify aggregator | Ít tài nguyên; relay theo vùng | derper **không có khái niệm tenant** (DP-01): mọi client đã được nhận gửi được frame tới mọi key; cần aggregator tự viết; không quota theo tenant; node bị thu hồi vẫn giữ kết nối (DP-03) | **Chỉ là research proposal** (§10.5) — không bật ở production |
| (e) SNI passthrough tầng 4 trên cổng 443 dùng chung tới derper riêng của từng tenant (derper tự terminate TLS trên hostname DERP riêng; DERP map của tenant cấp qua `derp.paths`; verify qua `/verify` nội bộ, fail-closed) | Giữ một IP và cổng 443; không có HTTP proxy trước DERP; `l4proxy` vốn đã là tầng 4 | Chưa kiểm chứng (DP-09); vẫn vướng khuyến cáo không dùng chung IP giữa các DERP server (DP-04); derper không thấy IP nguồn thật (không có PROXY protocol); thêm khóa/chứng chỉ và một container cho mỗi tenant; ở Local Development cần thêm bộ định tuyến SNI trước Caddy | **Phương án lùi trung gian** — REQUIRES VALIDATION bằng PoC (DP-09) trước khi xét (c) |

### 10.4 Giới hạn cần công bố của DERP

| Chủ đề | Giới hạn |
|---|---|
| Bandwidth | Relay qua TCP/HTTPS, chậm hơn đường trực tiếp; embedded DERP "no speed or throughput optimisations" (HS-17); toàn bộ lưu lượng relay của mọi tenant đi qua Caddy và NIC của một host |
| Authentication | Chỉ kiểm tra **lúc kết nối**, chỉ dựa trên việc node key có được đăng ký hay không (không xét expiry/policy). Node bị thu hồi giữ kết nối DERP đang mở tới khi rớt; peer đã nhận netmap mới sẽ không còn gửi cho nó |
| Routing | Định tuyến thuần theo public key đích; không hiểu tailnet/tenant |
| Metadata | Nhà vận hành relay thấy: node public key, IP:port nguồn, thời điểm, key đích, số lượng/kích thước gói; **không** thấy payload (DP-07) |
| Vận hành | Không có API quản lý DERP; đổi cấu hình DERP = restart instance = rớt phiên relay của tenant đó |
| NAT detection | Với **một** STUN endpoint, client gửi lại probe tới cùng địa chỉ nên `MappingVariesByDestIP` luôn là `false`, kể cả sau NAT đối xứng (theo phản biện — reviewer đọc `[TS:net/netcheck/netcheck.go]`) ⇒ **không** dùng trường này để phân loại NAT; V-22 chỉ xác nhận lại hành vi này; muốn nhận diện hard NAT cần STUN ở IP thứ hai (TD-09) |

### 10.5 Research proposal: Shared/Regional DERP (Phase 7 — chưa được phép dùng ở production)

| Hạng mục | Đề xuất nghiên cứu | Điều kiện Go/No-Go |
|---|---|---|
| Regional DERP pools | derper tự build từ **tag upstream đã pin** (không dùng image cộng đồng — §2.3), mỗi vùng ≥ 1 node, IP/cổng riêng, TLS do derper tự terminate | Image có provenance; không đặt sau HTTP proxy |
| Multi-tenant authentication | **Verify aggregator** trong backend: một endpoint nhận `{NodePublic, Source}`, trả `200 {Allow}` trong < 5 s; nguồn dữ liệu là chỉ mục node key trung tâm (từ inventory) hoặc fan-out tới `/verify` của từng tenant qua mạng nội bộ | Test: node chưa đăng ký ở tenant nào bị từ chối; độ trễ đăng ký node mới → được nhận |
| Fail-closed | `--verify-client-url-fail-open=false`; aggregator phải HA (5xx từ proxy cũng là từ chối) | Diễn tập aggregator ngừng: relay từ chối client mới, không mở toang |
| Per-tenant quotas | derper không hỗ trợ; chỉ có `-rate-config` toàn cục theo kết nối; kế toán theo tenant bằng cách scrape `/debug/clients` rồi join node key ↔ tenant | Load test đường relay ép buộc; noisy-neighbour test |
| Capacity & geographic assignment | Backend sinh DERP map theo tenant (file `derp.paths`), region ID 900–999, gán vùng theo `deployment_region` | Giám sát dung lượng theo vùng |
| Multi-region fallback | ≥ 2 region trong map của tenant | Test mất một region |
| Thu hồi tức thời | Công cụ dùng mesh key gửi `FrameClosePeer`; mesh key là secret cấp cao nhất | Chỉ khi có yêu cầu nghiệp vụ |
| Lựa chọn thay thế | **Peer relays** (Headscale 0.29 liệt kê là có hỗ trợ — HS-06): relay UDP do chính node của tenant đảm nhiệm, cấp quyền bằng grant | REQUIRES VALIDATION với client hiện hành (V-29) |

Rủi ro tồn dư của mọi relay dùng chung: node của tenant này có thể gửi gói rác tới node key đã biết của tenant khác (WireGuard sẽ loại bỏ nhưng tốn hàng đợi/băng thông), và có thể dò một key có đang kết nối hay không — **ASSUMED/VERIFIED từ source derper** (§2.6 DP-01).

### 10.6 Relay monitoring và giới hạn của traffic accounting

| Dữ liệu yêu cầu | Embedded DERP (MVP) | derper độc lập (tương lai) |
|---|---|---|
| Relay ingress/egress bytes | Headscale **không** xuất metrics của relay (UNSUPPORTED). Ước lượng bằng bộ đếm network theo container và số byte của request `/derp` theo hostname trong access log của edge — là **xấp xỉ**, gộp cả lưu lượng control | `bytes_received`, `bytes_sent` |
| Concurrent connections | Số stream nâng cấp đang mở theo hostname tại edge — REQUIRES VALIDATION khả năng đo (V-25) | `gauge_current_connections` |
| Relay health | Probe tổng hợp: `GET https://<host>/derp/probe`, probe UDP STUN, `tailscale debug derp <region>` từ canary client | Như bên + `/debug/check` |
| Authentication failures | Metric dựng từ log của Headscale (định dạng dòng log cần xác nhận) | Log/counter của derper |
| Throughput | Suy ra từ bộ đếm byte | Như bên |
| Network latency | `tailscale netcheck --format=json` từ canary client ngoài host (tùy chọn) | Như bên |
| Regional availability | Không áp dụng (một region) | Probe theo region |

**Không suy ra tổng lưu lượng VPN từ số đo relay.** Lưu lượng direct P2P không đi qua nền tảng nên **không đo được** ở phía server; Headscale API không có bộ đếm byte (HS-14) và network flow logs không được hỗ trợ (HS-06). Usage/billing vì vậy dựa trên số thiết bị, user, tính năng — không dựa trên dung lượng truyền.
