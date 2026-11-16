# MeshGuard — trạng thái hiện tại và quy trình thực hiện

> **File viết tay, cập nhật liên tục.** Ghi **những gì đang chạy**, **đã được dựng như thế nào** và **làm sao mở rộng hay luân chuyển** mà không phải đọc lại toàn bộ lịch sử. Mỗi lần thay đổi hạ tầng: sửa mục 2–5 nếu cần, thêm một dòng vào mục 8.
> Nguồn sự thật về thiết kế vẫn là [bản master](docs/planning/implementation-master-plan.md); tiến độ ở [ROADMAP.md](ROADMAP.md); bằng chứng ở [docs/planning/evidence/](docs/planning/evidence/).
> **Cập nhật:** 2026-11-16 (UTC) — **G1 đạt** (chủ dự án ký Go); đang ở Phase 2.

## 1. Tham số môi trường — một file cho mỗi môi trường

Mọi giá trị phụ thuộc môi trường nằm trong **một** file, **không có secret**:

| Môi trường | File |
|---|---|
| staging | [infrastructure/environments/staging/staging.env](infrastructure/environments/staging/staging.env) |
| mẫu cho môi trường mới | [.env.example](.env.example) |

| Biến | Dùng ở đâu |
|---|---|
| `MG_BASE_DOMAIN`, `MG_DNS_ZONE` | hostname mọi tenant (`<slug>.mesh.<domain>`), `server_url` và `dns.base_domain` của Headscale, site wildcard của edge, bản ghi DNS + CAA, lệnh client |
| `MG_PUBLIC_IPV4` | bản ghi `*.mesh` A, `derp.server.ipv4` của **mọi** tenant, `/bootstrap-dns` của edge, bind của `l4proxy` trên VPS, endpoint tunnel của host |
| `MG_LAN_IPV4`, `MG_LAN_CIDR` | cổng 80/443 edge publish trên host; set `@lan4` của firewall host |
| `MG_TUNNEL_HOST_IPV4`, `MG_TUNNEL_VPS_IPV4`, `MG_TUNNEL_PORT`, `MG_TUNNEL_HTTP_PORT`, `MG_TUNNEL_HTTPS_PORT` | tunnel WireGuard, listener tunnel-facing của edge, đích của `l4proxy`, firewall host |
| `MG_ACME`, `MG_ACME_ACCOUNT_URI` | CA của edge; `accounturi` trong CAA |
| `MG_DNS_RESOLVERS`, `MG_TENANT_NAMESERVERS` | kiểm tra DNS-01 của edge; nameserver tenant phát cho client |
| `MG_IDP_ID_PLATFORM`, `MG_IDP_ID_TENANT_A`, `MG_IDP_ID_TENANT_B` | id của 3 IdP (Keycloak realm) trong redirect URI `/api/v1/auth/callback/<id>` và trong bảng `identity_providers` (P2-T05, P2-T11) |

**Cơ chế:**

- **File tham số** (`edge.json`, `gateway.json`, `dns-public.json`, `tenants/*.json`) và **template** (`infrastructure/host/mg-staging-firewall.nft`) chỉ chứa placeholder `${MG_*}`. [tools/mgenv.py](tools/mgenv.py) điền giá trị.
- **Tool tự đọc env file:** `render_edge.py`, `render_instance.py`, `render_gateway.py`, `cf_dns.py` tìm thấy file env của môi trường mà không cần truyền gì thêm.
- **Lệnh shell** nạp biến bằng `eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)"`.
- **Thiếu biến là lỗi**, không có giá trị mặc định ngầm.
- **Có test:** [tools/test_mgenv.py](tools/test_mgenv.py) chạy trong CI; nó kiểm cả việc không còn giá trị môi trường nào bị ghi cứng trong file tham số.
- **Không có trong env file:**
  - **Secret** (token Cloudflare, token nội bộ, khóa…): file trên host, xem §14.2 của master.
  - **Digest image:** nằm ở `versions.lock`.
  - **Dải mạng nền tảng** (`10.249.0.0/16`, `10.250.0.0/16`): là hằng số thiết kế, không phải tham số môi trường.

## 2. Đang chạy (staging)

| Máy | Vai trò | Đang chạy |
|---|---|---|
| VM 104 `mg-staging` (`MG_LAN_IPV4`), Ubuntu 24.04, kernel 6.8.0-149, Docker 29.9.3 | Host staging | **Edge** (Caddy tự build, Caddyfile template **v4**), CrowdSec (chỉ quan sát), PostgreSQL (chưa dùng), Headscale 0.29.7 cho **tenant-a**, **tenant-b**, **tenant-c** (demo); demo headscale-admin (`mg-demo-panel`, `mg-demo-proxy`); firewall `inet mg_host` + `bridge mg_bridge`; tunnel `mg-wg0` |
| VPS (`MG_PUBLIC_IPV4`), Ubuntu 24.04, kernel 6.8.0-149, Docker 29.1.3 | Điểm vào công khai (tầng 4) | `mg-gateway`: `l4proxy` (HAProxy 3.4.7, 80/443 → tunnel, PROXY v2) + `stund` (UDP 3478); firewall `inet mg_vps`; tunnel `mg-wg0`; dịch vụ thư của chủ dự án (25/587). SSH chỉ bằng khóa |
| VM 105 `mg-ci-runner` | Máy build (Go, image) | Tailscale 1.104.7 — node `lab-c1` của tenant-c; trang thử `http://100.64.0.1:8000` (systemd `mg-lab-web`, tự tắt) |
| VM 106/107 (`a1`, `b1`, LAN) và VM 108/109 (`a2`, `b2`, sau NAT của OPNsense) | Client lab | Tailscale 1.104.7; a1/b1 dùng DNS công khai (đi qua VPS); a2/b2 dùng `/etc/hosts` cho control (LAN-direct) và ép relay |
| Điện thoại của chủ dự án | Client Android | Tailscale 1.104.6, node `redmi-note-13` của tenant-c |

| Tenant | Network | UID | Policy | Node |
|---|---|---|---|---|
| tenant-a | `10.250.0.0/29` | 30001 | fixture `test-allow-intra` (TCP 8000 + ICMP) | `lab-a1`, `lab-a2` |
| tenant-b | `10.250.0.8/29` | 30002 | fixture | `lab-b1`, `lab-b2` |
| tenant-c (demo) | `10.250.0.16/29` | 30003 | fixture | `lab-c1`, `redmi-note-13` |

**Đường đi:**

- **Client → control/DERP:** client mở `https://<slug>.mesh.<domain>`. DNS công khai trỏ tới `MG_PUBLIC_IPV4` (VPS). `l4proxy` gắn PROXY v2 rồi chuyển qua tunnel (`MG_TUNNEL_VPS_IPV4` → `MG_TUNNEL_HOST_IPV4`) tới edge `:8443`, edge chuyển tới `hs-<slug>:8080` trên network riêng của tenant.
- **Trong LAN** đi tắt: `MG_LAN_IPV4:443` → edge.
- **STUN:** `stund` trên VPS.
- **Dữ liệu ứng dụng:** P2P giữa client, không qua nền tảng.

**Chỉ có từ Internet:** cổng 22, 80, 443, 587. Không publish PostgreSQL, Headscale API hay metrics (AC-20).

## 3. Quy trình đã thực hiện (dựng lại từ đầu theo đúng thứ tự)

Trên host, repo nằm ở `~/mg`. Mọi lệnh render tự đọc `staging.env`. Mỗi bước có script, kèm lệnh hoàn tác trong chính script và trong bằng chứng.

| # | Bước | Lệnh / file | Bằng chứng |
|---|---|---|---|
| 1 | Chuẩn bị host: Docker, `daemon.json` | [infrastructure/host/](infrastructure/host/) | [P1-T02](docs/planning/evidence/P1-T02.md) |
| 2 | Bố cục `/opt/meshguard` + secret dạng file | `sudo bash infrastructure/host/layout.sh` | [P1-T03](docs/planning/evidence/P1-T03.md) |
| 3 | Network nền tảng (IP tĩnh của edge) | `sudo bash infrastructure/host/networks.sh` | [P1-T06](docs/planning/evidence/P1-T06.md) |
| 4 | Firewall host (tự hoàn tác sau 180 s nếu không xác nhận) | `python3 tools/mgenv.py render infrastructure/host/mg-staging-firewall.nft infrastructure/environments/staging/staging.env \| bash infrastructure/host/apply-firewall.sh` | [P1-T02](docs/planning/evidence/P1-T02.md), [P1-T12c](docs/planning/evidence/P1-T12c.md) |
| 5 | Core (CrowdSec, PostgreSQL) | `docker compose -f compose.core.yaml up -d` (`stund` chỉ với `--profile local-dev`) | [P1-T06](docs/planning/evidence/P1-T06.md) |
| 6 | Edge | `python3 tools/render_edge.py infrastructure/environments/staging/edge.json /tmp/edge` → cài Caddyfile + compose → `up -d` | [P1-T10](docs/planning/evidence/P1-T10.md), [P1-T18](docs/planning/evidence/P1-T18.md) |
| 7 | Tenant (mỗi tenant) | `render_instance.py` → `tenant-deploy.sh` → `reattach-edge.sh` → `tenant-policy.sh` ([RUNBOOK](infrastructure/host/RUNBOOK.md)) | [P1-T08](docs/planning/evidence/P1-T08.md), [P1-T19](docs/planning/evidence/P1-T19.md) |
| 8 | VPS: SSH chỉ bằng khóa, firewall, vá | `infrastructure/gateway/vps-firewall.nft` + `apply-vps-firewall.sh` | [P1-T15](docs/planning/evidence/P1-T15.md) |
| 9 | Tunnel | `wg-setup.sh key` trên mỗi máy, rồi `wg-setup.sh vps "$MG_TUNNEL_VPS_IPV4/32" "$MG_TUNNEL_HOST_IPV4/32" <pub host>` trên VPS và `wg-setup.sh host "$MG_TUNNEL_HOST_IPV4/32" "$MG_TUNNEL_VPS_IPV4/32" <pub vps> "$MG_PUBLIC_IPV4:$MG_TUNNEL_PORT"` trên host; drop-in `systemd/docker-after-wg.conf` | [P1-T16](docs/planning/evidence/P1-T16.md) |
| 10 | Gateway VPS | `python3 tools/render_gateway.py infrastructure/environments/staging/gateway.json /tmp/gw` → `/opt/meshguard/gateway/` → `docker compose up -d` | [P1-T17](docs/planning/evidence/P1-T17.md) |
| 11 | DNS public + CAA (cần chấp thuận riêng) | `sudo python3 infrastructure/gateway/cf_dns.py apply infrastructure/environments/staging/dns-public.json` (hoàn tác: `delete`) | [P1-T18](docs/planning/evidence/P1-T18.md) |
| 12 | Kiểm sau mỗi thay đổi | conformance `tests/security/edge/run_staging.sh`, IT-14 `tests/isolation/it14_probe.sh` (truyền `-e MG_TUNNEL_HOST_IPV4 -e MG_TUNNEL_VPS_IPV4`), từ Internet `tests/security/edge/external.py`, `tools/health_probe.py` | [P1-T18](docs/planning/evidence/P1-T18.md) |

## 4. Mở rộng

| Việc | Cách làm |
|---|---|
| **Thêm tenant** | Sao chép `tenants/tenant-b.json` → đổi `tenant_id`, `instance_id` (UUID mới), `slug`, `net_cidr` (/29 trống trong `10.250.0.0/16`), `run_uid` (30000–39999) → bước 7 của mục 3. Hostname, DNS và chứng chỉ có sẵn nhờ wildcard; edge không reload. Đã làm với tenant-c trong 5,7 s |
| **Gỡ tenant** | `sudo bash infrastructure/host/tenant-remove.sh <slug> --i-understand-this-deletes-data` |
| **Đổi cấu hình tenant** (ví dụ `derp_ipv4`) | render → `tenant-reconfigure.sh` (configtest nháp, giữ bản cũ, restart ~2,5 s, kiểm policy) |
| **Đổi cấu hình edge** | render → reload (compose không đổi) hoặc recreate + `reattach-edge.sh` (compose đổi) → chạy lại conformance + IT-14 + external ([RUNBOOK](infrastructure/host/RUNBOOK.md)) |
| **Thêm môi trường** (ví dụ production) | `infrastructure/environments/<env>/<env>.env` từ `.env.example` + bộ file tham số JSON cùng placeholder → quy trình mục 3 |
| **Thêm host / vùng** | Phase 7 (multi-host, Agent qua mTLS) — chưa làm |
| Backend, Portal, orchestrator | Phase 2–4: sẽ thay các bước tay ở mục 3 bằng API + Host Agent |

## 5. Luân chuyển (đổi VPS, domain, IP LAN)

Chỉ sửa `staging.env`, rồi thực hiện:

| Đổi | Việc phải làm | Ảnh hưởng tới client |
|---|---|---|
| **IP công khai** (VPS mới) | 1. Dựng VPS mới theo mục 3, bước 8–10.<br>2. `cf_dns.py apply dns-public.json` (bản ghi A).<br>3. Render lại mọi tenant → `tenant-reconfigure.sh` (`derp.server.ipv4`).<br>4. Render edge → reload (`/bootstrap-dns`).<br>5. `wg-setup.sh host … "$MG_PUBLIC_IPV4:$MG_TUNNEL_PORT"` (endpoint tunnel).<br>6. Chạy `external.py` | Client tự nối lại: restart tenant ~2,5 s; DNS TTL 300 s. Không phải đăng ký lại |
| **Domain** | Chứng chỉ wildcard mới qua DNS-01 (edge tự xin khi domain trong Caddyfile đổi); `cf_dns.py apply` cho zone mới (A + CAA); render lại edge + mọi tenant (`server_url`, `dns.base_domain`) → reload/restart | **Client phải đăng nhập lại**, vì profile của Tailscale gắn với URL control (CL-01). Lên lịch và thông báo trước |
| **IP LAN của host** | Render edge (cổng publish) → recreate + `reattach-edge.sh`; render firewall → `apply-firewall.sh` | Chỉ ảnh hưởng client đi LAN-direct |
| **Tài khoản ACME** | Đổi `MG_ACME_ACCOUNT_URI` → `cf_dns.py apply` (CAA) **trước** khi edge dùng tài khoản mới | Không |

## 6. Số đo chính (Phase 1)

| Hạng mục | Kết quả |
|---|---|
| Thêm tenant (dựng + gắn edge) | 5,7–7,1 s, 0 stream của tenant khác bị đóng |
| Restart một tenant | Control phục hồi ~2,5–2,7 s; tenant khác không bị ảnh hưởng |
| Edge: restart / recreate + gắn lại, 100 network | 11,0 s / 15,9 s |
| Reboot host staging (tunnel + 3 tenant) | Gián đoạn ~23,6 s (LAN), ~28 s (qua VPS) |
| Reboot VPS | Đường qua VPS gián đoạn ~30,6 s; LAN-direct 0 lỗi |
| Dựng lại gateway VPS từ repo | 14,1 s |
| Relay 20 MiB qua VPS | 5,5–6,6 s (~3,2–3,8 MB/s) |
| Stream dài qua VPS | 36 phút, 0 lần nối lại |

## 7. Việc tiếp theo

1. ~~Ký G1~~ — **Go** 2026-11-16.
2. Phase 2 (không đụng host, chạy song song): P2-T02 (OpenAPI v1), P2-T03 (migration + RLS), P2-T04 (SecretStore), …. Triển khai backend lên host sau G1 (P2-T16).
3. Việc của chủ dự án:
   - ~~Ý kiến pháp lý sơ bộ R-01~~ — xong 2026-11-16 (thông qua).
   - Token Cloudflare hẹp.
   - Thử Windows/iOS khi tiện.
4. Gỡ demo headscale-admin khi không cần: `infrastructure/demo/headscale-admin/down.sh`.

## 8. Nhật ký thay đổi (thêm dòng mới ở cuối)

| Ngày (UTC) | Thay đổi | Bằng chứng |
|---|---|---|
| 2026-11-16 | Phase 1 dựng staging: edge, tenant A/B, firewall, conformance, IT-09/IT-14, restart/rebuild, 100–300 network | [ROADMAP](ROADMAP.md) mục 2 |
| 2026-11-16 | VPS gateway + tunnel + DNS/CAA; staging Internet-facing; sửa lỗ listener tunnel-facing (template v4) | [P1-T15…T18](docs/planning/evidence/P1-T18.md) |
| 2026-11-16 | Tenant demo `tenant-c` + demo headscale-admin (ngoại lệ §25.1(6)) | [ref-headscale-admin-demo](docs/planning/evidence/ref-headscale-admin-demo.md) |
| 2026-11-16 | Điện thoại Android trên 4G vào tenant-c (relay qua VPS, trực tiếp IPv6) | [P1-T12e](docs/planning/evidence/P1-T12e.md) |
| 2026-11-16 | Reboot host staging (có tunnel) và reboot VPS (kernel 6.8.0-149) | [G1](docs/planning/evidence/G1.md) |
| 2026-11-16 | Gom tham số môi trường vào `staging.env` + `tools/mgenv.py`; output render trùng từng byte với cấu hình đang chạy | mục 1 |
| 2026-11-16 | **G1 đạt** (chủ dự án ký Go) — bắt đầu Phase 2 | [G1](docs/planning/evidence/G1.md) |
| 2026-11-16 | R-01 (pháp lý) được chủ dự án xác nhận thông qua — điều kiện trước G2 đạt | [R-01](docs/planning/evidence/R-01.md) |
| 2026-11-16 | P2-T02: hợp đồng OpenAPI v1 (28 operation) + spec-lint + sinh code Go/TS — chưa triển khai lên host | [P2-T02](docs/planning/evidence/P2-T02.md) |
| 2026-11-16 | P2-T03: schema PostgreSQL (migration 0001–0006, RLS, role, partition audit) + `internal/store` — chưa triển khai lên host | [P2-T03](docs/planning/evidence/P2-T03.md) |
| 2026-11-16 | P2-T05: Keycloak 26.8.2 + 3 realm (MFA bắt buộc) dựng và thử trên VM build — chưa lên host; thêm `MG_IDP_ID_*` vào env file | [P2-T05](docs/planning/evidence/P2-T05.md) |
