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
| VM 104 `mg-staging` (`MG_LAN_IPV4`), Ubuntu 24.04, kernel 6.8.0-149, Docker 29.9.3 | Host staging | **Edge** (Caddy tự build, Caddyfile template **v7** — site `app.`/`admin.`/`auth.` từ 2026-11-17; network `mg-idp` riêng với idp), CrowdSec (chỉ quan sát), PostgreSQL (`meshguard`, schema 8), **backend `mg-app`** (`api` + `worker`, image `129b202` — P2-T16 + sửa G2 vòng 2), **`mg-backup`** (postgres/idp/edge, giữ 14 ngày), Headscale 0.29.7 **+ bản vá V-26 mg.1** (`mg-headscale` `sha256:d95ff9df…`, từ 2026-11-17) cho **tenant-a**, **tenant-b**, **tenant-c** (demo); **IdP `mg-idp`** (Keycloak 26.8.2 image `129b202` có danh sách cấm mật khẩu, realm `platform`/`tenant-a`/`tenant-b` template `idp-realm-v2`, `idp-db`, SMTP mẫu `mailsink`; chỉ trên network `mg-idp`/`mg-idp-data`/`mg-egress`/`mail`); firewall `inet mg_host` + `bridge mg_bridge`; tunnel `mg-wg0` |
| VPS (`MG_PUBLIC_IPV4`), Ubuntu 24.04, kernel 6.8.0-149, Docker 29.1.3 | Điểm vào công khai (tầng 4) | `mg-gateway`: `l4proxy` (HAProxy 3.4.7, 80/443 → tunnel, PROXY v2) + `stund` (UDP 3478); firewall `inet mg_vps`; tunnel `mg-wg0`; dịch vụ thư của chủ dự án (25/587). SSH chỉ bằng khóa |
| VM 105 `mg-ci-runner`, 12 vCPU / 24 GB (từ 2026-11-17) | Máy build (Go, image) | Tailscale 1.104.7 — node `lab-c1` của tenant-c; trang thử `http://100.64.0.1:8000` (systemd `mg-lab-web`, tự tắt) |
| VM 110 `mg-ci-runner-2` (192.168.1.23), 12 vCPU / 24 GB / 200 GB, Docker 29.9.3 | Máy build thứ hai (từ 2026-11-17) | Chỉ Docker; agent chạy test song song với VM 105 |
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
2. ~~Phase 2~~ — **xong, G2 đạt 2026-11-17** ([G2](docs/planning/evidence/G2.md)). **Phase 3 (Tenant Orchestrator) bắt đầu**: P3-T01 (Host Agent + `agent.proto`), P3-T02 (compose driver), P3-T04 (placement), P3-T06 (migration từ `0009`) … theo §20; mọi thay đổi trên host staging vẫn duyệt theo từng loại thao tác.
3. Việc của chủ dự án:
   - ~~Ý kiến pháp lý sơ bộ R-01~~ — xong 2026-11-16 (thông qua).
   - Token Cloudflare hẹp.
   - Thử Windows/iOS khi tiện.
4. ~~Gỡ demo headscale-admin~~ — xong 2026-11-17 (`down.sh`, giữ tenant-c; API key của panel đã expire).

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
| 2026-11-17 | Image `idp`: gỡ root emSign Root CA - G1 khỏi kho CA của JVM (CVE-2026-91403), ngoại lệ grype chỉ cho image này, hết hạn **2027-02-16** (quá hạn ⇒ CI chặn); image `idp` vào workflow `images` — chưa lên host | [P2-T05](docs/planning/evidence/P2-T05.md) mục 7 |
| 2026-11-17 | Pin image `idp` trong `versions.lock` (GHCR `sha256:a0191d54…`) — `render_idp.py` dùng mặc định, không cần `--image` | `versions.lock` `[images.mg-idp]` |
| 2026-11-17 | Hợp nhất P2-T04/T06/T07/T12/T14 vào main (SecretStore, đăng nhập/session, phân quyền, khung job, middleware) + lắp đăng nhập/phân quyền vào API; CI thêm kiểm `go mod tidy -diff` — chưa triển khai lên host | [P2-T04](docs/planning/evidence/P2-T04.md), [P2-T06](docs/planning/evidence/P2-T06.md), [P2-T07](docs/planning/evidence/P2-T07.md), [P2-T12](docs/planning/evidence/P2-T12.md), [P2-T14](docs/planning/evidence/P2-T14.md) |
| 2026-11-17 | P2-T09/T10: adapter Headscale (`internal/headscale`) + contract test với Headscale 0.29.7 thật (26/26; workflow CI `headscale-contract`); V-06/V-28 đạt, V-21 phần adapter đạt, V-26 phát hiện Headscale panic với Auth ID của phiên SSH-check — vẫn chặn rule SSH `check` — chưa triển khai lên host | [P2-T09](docs/planning/evidence/P2-T09.md), [P2-T10](docs/planning/evidence/P2-T10.md) |
| 2026-11-17 | Chủ dự án quyết: **vá Headscale** cho V-26 (sửa ADR-02/§25.1 mục 7 ở P2-T10a) và **chưa báo upstream** | P2-T10a (đang làm) |
| 2026-11-17 | P2-T05a: driver IdP (`internal/idp`) + client chống SSRF + đường hẹp cho Keycloak của nền tảng; §8.2 thêm câu về đường hẹp này — chưa triển khai lên host | [P2-T05a](docs/planning/evidence/P2-T05a.md) |
| 2026-11-17 | P2-T15a: fixture phiên kiểm thử (tag `mgtestfixture`) + đăng nhập Keycloak thật có TOTP qua API; response lỗi của identity đi qua `httpapi` (nosniff + log); CI chạy thêm test có tag | [P2-T15a](docs/planning/evidence/P2-T15a.md) |
| 2026-11-17 | Repo GitHub chuyển **private** (chủ dự án); CI đọc bằng credential Git sẵn có, chỉ đọc; D-12/R-29 cập nhật | ROADMAP mục 1 |
| 2026-11-17 | Đợt gộp 3: P2-T08 (audit), P2-T11 (registry + `adopt-instance`), P2-T10a (Headscale vá V-26 — image `mg-headscale` build trong CI, staging **chưa** đổi image), P2-T01a (stack dev/CI), bộ công cụ nghi thức khóa P2-T04a, sửa test job chập chờn — chưa triển khai lên host | [P2-T08](docs/planning/evidence/P2-T08.md), [P2-T11](docs/planning/evidence/P2-T11.md), [P2-T10a](docs/planning/evidence/P2-T10a.md), [P2-T01a](docs/planning/evidence/P2-T01a.md), [P2-T04a](docs/planning/evidence/P2-T04a.md) |
| 2026-11-17 | Staging: tenant-c → b → a chuyển sang **Headscale vá V-26** (`mg-headscale` `sha256:d95ff9df…`, commit `f9cc62be…`) bằng `tenant-upgrade.sh` — chủ dự án duyệt; mỗi tenant healthy sau ~4,8 s, policy/node/user không đổi, probe public `/key` 200 + `/derp` 200 + STUN đạt; cold backup tại `meta/backup-20261117T0642…–0643…Z/`; hoàn tác: `headscale_build = official` + chạy lại script | [P2-T10a](docs/planning/evidence/P2-T10a.md) mục 9 |
| 2026-11-17 | **Nghi thức khóa P2-T04a** trên host staging: `kek-app` (`staging-app-20261117-0623`, KCV `66c83426`), `kek-ops` (`staging-ops-20261117-0623`, KCV `aabd042a`), khóa ký manifest; `MG_BACKUP_RECOVERY_RECIPIENT` + `MG_BACKUP_MANIFEST_PUBKEY` vào `staging.env`; kiểm 2 bản + drill PASS, tmpfs đã shred. Bản offline = bản số chủ dự án chọn giữ trong `config/secrets/staging/` (git bỏ qua, OneDrive) — chưa có bản giấy | [P2-T04a](docs/planning/evidence/P2-T04a.md) |
| 2026-11-17 | Proxmox: thêm **VM 110 `mg-ci-runner-2`** (12 vCPU / 24 GB / 200 GB, 192.168.1.23) làm máy build thứ hai — chủ dự án duyệt; Docker trùng từng phiên bản với VM 105. Nâng VM 105 lên 12 vCPU / 24 GB làm sau (cần khởi động lại VM 105, chờ agent đang chạy xong). Hoàn tác: `qm stop 110 && qm destroy 110 --purge` | [infrastructure-bootstrap.md](docs/planning/evidence/infrastructure-bootstrap.md) bước 11 |
| 2026-11-17 | Proxmox: **VM 105** nâng lên 12 vCPU / 24 GB (`qm set` + `qm reboot`, dừng ~15 s) — chủ dự án duyệt; hoàn tác `qm set 105 --cores 6 --memory 16384 && qm reboot 105` | [infrastructure-bootstrap.md](docs/planning/evidence/infrastructure-bootstrap.md) bước 11 |
| 2026-11-17 | Main: sửa lỗi bảo mật T-17 trong đồng bộ thiết bị (snapshot cũ không ghi đè hạn đã thu hồi; kẹp hạn chỉ rút ngắn), contract thử đúng image Headscale pin; chuẩn bị IdP lên staging (SMTP mẫu Mailpit, `create-user.sh`); rà soát bảo mật G2 vòng 1 (0 Critical/High; F1–F3 Medium + L1 đang sửa); **P2-T16 phần code** (api/worker, project `mg-app`, edge v5, runbook a→j) — chưa triển khai lên host | [P2-T13](docs/planning/evidence/P2-T13.md) mục 8, [G2-security-review](docs/planning/evidence/G2-security-review.md), [P2-T16](docs/planning/evidence/P2-T16.md) |
| 2026-11-17 | Staging: **gỡ demo headscale-admin** (`infrastructure/demo/headscale-admin/down.sh` — panel, proxy, network `mg-demo-int`, volume, `/opt/meshguard/demo/r2`; API key duy nhất của tenant-c expire), giữ tenant-c; dừng tunnel demo trên máy vận hành — chủ dự án duyệt. Hoàn tác: `up.sh` của cùng thư mục | [ref-headscale-admin-demo](docs/planning/evidence/ref-headscale-admin-demo.md) |
| 2026-11-17 | Staging: **IdP `mg-idp`** lên (P2-T16 bước c, chủ dự án duyệt): `secrets.sh` (5 secret, `check-secrets` PASS), render `12f2336` → `/opt/meshguard/core/compose.idp.yaml` + `idp/{realms,initdb}`, `idp` + `idp-db` + `mailsink` healthy sau 43 s; issuer `https://auth.<domain>/realms/{platform,tenant-a,tenant-b}`; network `mg-idp_mail` internal (chỉ idp + mailsink); thư thử Keycloak → Mailpit đạt. Chưa có route `auth.` ở edge (bước h). Hoàn tác: `docker compose -p mg-idp … down` (`-v` xóa DB) | [RUNBOOK](infrastructure/host/RUNBOOK.md) mục IdP |
| 2026-11-17 | Keycloak staging: 6 **tài khoản mẫu** (`create-user.sh`, mật khẩu không tạm trong `config/secrets/staging/idp-accounts/` của chủ dự án — git bỏ qua, chưa từng in ra; TOTP đăng ký lần đầu). `sub`: platform `op-1` `62765603-11b3-4161-82e0-e6089d034629`, `op-2` `39f7bf30-db74-4bf7-86fe-8953ac5cdf7d`; tenant-a `a-owner` `1280e61a-f411-42b4-9e93-fcc7db87c2b4`, `a-admin` `9e91f8d1-3f98-4c95-87ff-2db6b4a93d84`; tenant-b `b-owner` `382d882e-d19b-4c3d-9228-b10d5f45c6f7`, `b-admin` `ff761517-2e9d-4141-915c-78fb076e86bc` | [deploy-backend](docs/operations/deploy-backend.md) f |
| 2026-11-17 | Main: gộp sửa G2 vòng 1 (F1 login CSRF, F2 audit ẩn danh, F3 `client_secret_ref` + migration `0007`, L1); master §6.3 dời bản đồ migration Phase 3–6 (+1), §14.2–§14.4 theo `mg-app`; chuỗi tương đương CI trên `03509d3` xanh (go-ci, contract 34/34, isolation, e2e 26/26) + GitHub CI 6/6; pin `[images.mg-api]`/`[images.mg-worker]`/`[images.mg-backup]` (`03509d3`, run 44063142251) | [G2-security-review](docs/planning/evidence/G2-security-review.md), [P2-T16](docs/planning/evidence/P2-T16.md) |
| 2026-11-17 | Staging: **P2-T16 triển khai** (chủ dự án duyệt a–h): `layout.sh` + `app-secrets.sh` (`check-secrets` 26/26 PASS); `db-bootstrap`; `mg-backup` (check ×3) → backup `postgres-20261117T102719Z-pre-migration` → migrate schema 7; `api`/`worker` healthy (KCV `66c83426`/`aabd042a`); `register-platform-idp`, adopt tenant-a/b (mỗi instance còn đúng 1 API key, hạn 2027-02-15), client secret `mg-portal` ×3; Super Admin `op-1`, `op-2`; TO/TA A/B; `mg-backup` theo lịch + bộ `postgres-20261117T103025Z-manual`; edge template **v5 → v6** (reload 10:31:09Z và 11:18:45Z — v6 sửa 200 rỗng cho host không có site trên listener tunnel-facing), conformance **PASS**, probe A/B/C qua VPS 200; `idp-bootstrap` (`mg-provisioner`, break-glass đã hủy). Hoàn tác: `docs/operations/deploy-backend.md` từng bước | [P2-T16](docs/planning/evidence/P2-T16.md) mục 12 |
| 2026-11-17 | Chủ dự án đăng nhập thử thành công (`op-1`, Super Admin, TOTP lần đầu, 12:43:52 UTC). **DNS công khai** (bước i, chủ dự án duyệt): A `app.`/`auth.` → IP VPS (DNS-only), CAA Let's Encrypt/DNS-01/accounturi cho `app.`/`auth.`/`admin.`; không A cho `admin.`; kiểm qua VPS + `external.py` AC-20 PASS 127/127, cổng mở 22/80/443/587. Hoàn tác: `cf_dns.py delete dns-platform.json` | [P2-T16](docs/planning/evidence/P2-T16.md) mục 12 |
| 2026-11-17 | Staging: **cập nhật sau G2 vòng 2** (deploy-backend mục k, chủ dự án chọn "sửa rồi triển khai lại, kiểm lại"): pin `api`/`worker`/`idp` `129b202` (`7935635`); k2 network `mg-idp` (10.249.7.0/24 internal) + edge gắn `10.249.7.2` (không restart) + Caddyfile **v7** (reload 13:56:45Z); k3 idp image mới, rời `mg-edge` (healthy 18 s; từ container trên `mg-edge` không còn tới `idp:8080`); k4 `realm-update.sh` 40 thay đổi (blocklist mật khẩu, mapper `amr`, `max_auth_age` 0, post-logout URI, gia cố realm master), `check_realm` đạt, `--check` 0 thay đổi (log `/root/realm-update.20261117T135904Z.log`); k5 backup `postgres-20261117T140404Z-pre-migration` → schema 8; k6 api/worker mới healthy 4 s. Kiểm: conformance PASS, probe A/B/C 200, 0 `id_token_hint` trong access log, `admin.` có `prompt=login`. Hoàn tác: deploy-backend mục k từng bước | [G2-security-review](docs/planning/evidence/G2-security-review.md) "Sửa sau vòng 2" |
| 2026-11-17 | **G2 đạt — chủ dự án ký "G2 go" lúc 14:31 UTC**; Phase 2 đóng (25/25 task), Phase 3 bắt đầu | [G2](docs/planning/evidence/G2.md) |
