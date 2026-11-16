# Network Port Matrix & Connectivity Requirements

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §15 (phần mở đầu), §15.1, §15.2, §15.5. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 15. Network Requirements

### 15.1 Network Port Matrix

| Service | Cổng / giao thức | Hướng | Phơi ra | Mục đích | Ghi chú |
|---|---|---|---|---|---|
| **VPS `l4proxy`** | TCP 443, TCP 80 | Vào | **Public** (IP của VPS) | Điểm vào từ Internet; chuyển tiếp tầng 4 về listener tunnel-facing của edge, kèm PROXY protocol v2 | Không terminate TLS; không có chứng chỉ trên VPS |
| **VPS `stund`** | UDP 3478 | Vào | **Public** (IP của VPS; trên host LAN ở chế độ dev) | STUN dùng chung cho mọi tenant | Host network; HTTP debug chỉ bind loopback |
| **Tunnel WireGuard** | UDP (một cổng trên VPS) | Vào VPS, từ host LAN | Chỉ peer có khóa; giới hạn IP nguồn nếu host LAN có IP ra cố định | Liên kết riêng VPS ↔ host LAN | Host LAN chủ động kết nối — không cần port forwarding ở LAN |
| edge (Caddy) — tunnel-facing | TCP 8443, 8080 trên IP tunnel của host LAN | Vào, từ VPS | **Chỉ peer tunnel** | Nhận lưu lượng public đã chuyển tiếp: Portal, SaaS API, IdP, control plane mọi tenant (`/ts2021`), DERP (`/derp`) | PROXY protocol bắt buộc; nơi **duy nhất** terminate TLS |
| edge (Caddy) — LAN-direct | TCP 443, TCP 80 trên IP LAN | Vào | Chỉ LAN | Local Development; Platform Console (`admin.<domain>`); redirect, `/generate_204`, lần thử upgrade đầu của client (EG-07) | `admin.<domain>` **không** phục vụ trên listener tunnel-facing |
| edge (Caddy) | UDP 443 (HTTP/3) | Vào | Tắt ở MVP | — | Tắt **tường minh** bằng global option `servers { protocols h1 h2 }`: mặc định của Caddy là `h1 h2 h3` (tài liệu Caddy, theo phản biện) nên chỉ không publish UDP 443 thì edge vẫn quảng bá `Alt-Svc` cho h3 và trình duyệt thử QUIC vào cổng đóng trước khi lùi. Control/DERP dùng HTTP/1.1 upgrade; bật lại (kèm publish 443/udp) nếu cần cho Portal |
| Headscale tenant *n* | TCP 8080 | Nội bộ | Chỉ network tenant (`internal`) | Control + REST API | Public chỉ qua allow-list của edge; container **không publish cổng nào** |
| Headscale tenant *n* | TCP 9090 | Nội bộ | Chỉ network tenant | Metrics + debug (không xác thực) | Chỉ `/metrics` được edge chuyển tiếp nội bộ |
| Headscale tenant *n* | TCP 50443 | — | Không khởi động | gRPC | RT-01 |
| edge listener admin | TCP 9443 (đề xuất) | Nội bộ | Chỉ `mg-admin` | api/worker → Headscale API | Bind IP tĩnh + matcher `remote_ip` + token riêng (§14.3, §14.6) |
| edge listener metrics | TCP 9444 (đề xuất) | Nội bộ | Chỉ `mg-obs` | Prometheus → `/metrics` instance | Bind IP tĩnh + matcher `remote_ip` + token riêng (§14.3, §14.6) |
| api | TCP 8000 (đề xuất) | Nội bộ | `mg-edge`, `mg-admin`, `mg-data`, `mg-obs` (chỉ `/metrics`, `/internal/prometheus/sd`) | REST `/api/v1`, `/internal/*`, `/metrics` | `/internal/*` và `/metrics` không được edge route ra ngoài; đi ra qua `mg-egress` |
| postgres | TCP 5432 | Nội bộ | Chỉ `mg-data` | DB | **Không** publish |
| idp | TCP 8080 (đề xuất: cổng HTTP mặc định của image) | Nội bộ | Qua edge (`auth.<domain>`) | OIDC | Console quản trị IdP chỉ ở origin admin |
| Prometheus / Alertmanager / Loki | TCP 9090 / 9093 / 3100 (đề xuất: cổng mặc định của image) | Nội bộ | Chỉ `mg-obs` | Monitoring | **Không** publish |
| Grafana | TCP 3000 (đề xuất: cổng mặc định của image) | Nội bộ | Qua edge (origin admin, SSO) | Dashboard platform | — |
| CrowdSec LAPI | TCP 8080 (đề xuất: cổng mặc định của image) | Nội bộ | Chỉ edge ↔ crowdsec (network `mg-sec`) | Quyết định ban | Cổng metrics của engine nằm trên `mg-obs` |
| prober | TCP 9115 (`/metrics`) và TCP 9116 (RPC) — đề xuất | Nội bộ | `mg-admin` (RPC từ worker), `mg-obs` (scrape) | Probe STUN/DERP/allow-list; kiểm tra bước 17–18 của provisioning | Không có secret; đi ra qua `mg-egress` tới điểm vào công khai |
| backup-shipper | Không lắng nghe | Ra | Không | Đẩy archive đã mã hóa lên kho offsite | Chỉ trên `mg-egress`; credential append-only; mount chỉ-đọc |
| pg-backup | Không lắng nghe | Nội bộ | Không | Dump PostgreSQL qua `mg-data` (service có lịch riêng) | Mount ghi chỉ `backups/postgres`; không có đường ra ngoài |
| Đường ra `mg-egress` | TCP 443, SMTP tới đích trong allow-list | Ra | Không publish cổng | worker, api, idp, alertmanager, prober, backup-shipper đi tới issuer OIDC, API DNS provider, SMTP, webhook, kho offsite; prometheus chỉ tới `/metrics` của VPS trên IP tunnel (Phase 6) | Allow-list bằng `DOCKER-USER` (P6-T07) |
| Caddy admin API | Unix socket (không TCP, không tắt) | — | Không | Quản trị edge | EG-04 |
| SSH | TCP 22 | Vào | Chỉ mạng quản trị | Vận hành | Chỉ key |
| Client ↔ client | UDP (nguồn mặc định 41641) | Giữa các client | Không liên quan host | WireGuard P2P | Không đi qua nền tảng |

**Đối chiếu AC-20:** PostgreSQL, Headscale admin API (`/api/v1`, Swagger), metrics/debug, gRPC và Platform Console đều **không** có đường public; từ VPS chỉ tới được đúng hai cổng listener tunnel-facing của edge.

**Các endpoint cần public (đi qua VPS):** `https://<slug>.<mesh_domain>` (control + DERP), `http://…:80` (redirect, `/generate_204`), STUN UDP 3478, `app.<domain>` (Tenant Portal + SaaS API), `auth.<domain>` (IdP). **Không public:** `admin.<domain>`, Grafana, Headscale API/Swagger/metrics, PostgreSQL, Prometheus/log store, CrowdSec LAPI, Agent.

### 15.2 Connectivity requirements theo dịch vụ

| Dịch vụ | Cần đi ra (egress) | Cần đi vào (ingress) |
|---|---|---|
| edge | ACME directory; API của DNS provider (DNS-01); resolver công khai (UDP/TCP 53) cho bước kiểm tra propagation của DNS-01; (tùy chọn) không gì khác | 80/443 từ client và browser |
| Headscale tenant | **Không** ở chế độ mặc định (`derp.urls: []`, tắt check update, tắt logtail; network `internal`); chỉ cần tới issuer khi dùng OIDC gốc — qua đường ra riêng của tenant, không qua `mg-egress` (§14.3) | 8080 từ edge |
| VPS gateway (`l4proxy`, `stund`) | Tunnel tới host LAN | TCP 80/443 và UDP 3478 từ Internet; UDP tunnel từ host LAN |
| api / worker | PostgreSQL; edge listener admin; Prober (worker); qua `mg-egress`: issuer OIDC (discovery, JWKS, token — HTTP client đã hardening, T-21), Admin API của IdP, API của DNS provider (nếu dùng DNS driver), SMTP (**bắt buộc** cho thông báo và thư mời) | api: từ edge; worker: không có ingress ngoài scrape `/metrics` |
| agent | Không (không có network) | Unix socket từ worker |
| idp | DB của nó; qua `mg-egress`: IdP thượng nguồn khi brokering, SMTP (**bắt buộc** cho thư mời/đặt lại mật khẩu khi IdP do nền tảng host) | Từ edge |
| monitoring | Các đích scrape nội bộ; Alertmanager đi ra qua `mg-egress` tới kênh cảnh báo; Prometheus đi qua `mg-egress` tới `node_exporter` của VPS trên IP tunnel (Phase 6); Prometheus đi qua `mg-egress` tới node_exporter/`l4proxy` của VPS trên IP tunnel (Phase 6) | Grafana từ edge |
| prober | Qua `mg-egress`: điểm vào công khai của chính nền tảng (TCP 443/80, UDP 3478) | RPC từ worker; scrape từ Prometheus |
| backup-shipper | Kho backup offsite qua `mg-egress` | Không |
| crowdsec | Không ở mặc định (`DISABLE_ONLINE_API=true`); nếu bật Central API (D-8): TCP 443 qua `mg-egress` | LAPI từ edge trên `mg-sec`; đọc access log của edge qua volume chung chỉ-đọc |
| postgres | Không | TCP 5432 từ api, worker, postgres-exporter trên `mg-data` |
| web | Không | Từ edge |
| Host và CI lúc build/cập nhật | Registry image (pull theo digest), module proxy Go/npm (chỉ trên CI), kho gói Ubuntu, NTP | — |
| pg-backup | PostgreSQL trên `mg-data`; không đi ra ngoài (việc đẩy offsite thuộc backup-shipper) | Không |
| Official client | TCP 443 tới `<slug>.<mesh_domain>`; UDP 3478 tới điểm vào công khai (STUN); UDP tới peer; ngoài ra client có thể tự liên lạc host của Tailscale Inc. (CL-16) — không cần cho hoạt động của tenant | Thường không cần inbound |

### 15.5 Yêu cầu phía mạng của khách hàng (đưa vào tài liệu onboarding)

Cho phép đi ra: TCP 443 tới `<slug>.mesh.<domain>`; UDP 3478 tới cùng địa chỉ đó (STUN); UDP tùy ý giữa các thiết bị để có đường trực tiếp. Mạng chỉ cho TCP 443 vẫn hoạt động qua relay với thông lượng thấp hơn (§10.4). Subnet router/exit node là thiết bị của khách, do khách quản trị; nền tảng chỉ duyệt route.

**Công bố cho khách (đưa vào thông báo quyền riêng tư và tài liệu onboarding):** dù control server và relay là của nền tảng, official client có thể tự liên lạc một số host của Tailscale Inc. — gửi log chẩn đoán từ lúc `tailscaled` khởi động tới map đầy đủ đầu tiên, dò captive portal khi STUN không trả lời nhanh (mạng chỉ cho TCP 443), DNS fallback khi DNS hệ thống lỗi (lộ hostname control của tenant), và `tailscale netcheck` khi chưa có map (CL-16). Khách yêu cầu không gửi telemetry đặt `TS_NO_LOGS_NO_SUPPORT=true` (hoặc `tailscaled --no-logs-no-support`) trên thiết bị và có thể chặn các host đó ở firewall của mình; danh sách host cụ thể lấy từ kết quả V-27.
