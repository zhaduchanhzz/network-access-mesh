# Deployment Plan

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §14 (trừ §14.3, §14.6). Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 14. Ubuntu Deployment Architecture

Mục tiêu ban đầu: **một** Ubuntu host (IP private trong LAN, thư mục `/opt/meshguard`, Docker Engine + Docker Compose) chạy toàn bộ nền tảng, cách ly tenant ở mức logic, dùng cho Development/Staging trước production; cộng thêm **một VPS có IP công khai** làm Public Gateway cho các endpoint cần public (§14.9). Thông số phần cứng/mạng của cả hai máy hiện **chưa biết** (Appendix A). Chưa có thao tác nào dưới đây được thực hiện trên máy chủ.

### 14.1 Chuẩn bị host (Phase 1 — chỉ thực hiện sau khi được phê duyệt)

| Hạng mục | Thiết kế | Căn cứ |
|---|---|---|
| Truy cập | User triển khai không phải root + SSH key; nếu mật khẩu root từng được chia sẻ ⇒ đổi trước khi triển khai; không lưu credential ở bất kỳ đâu trong repo/log | Yêu cầu §2.1 đề bài |
| Hệ điều hành | Ubuntu LTS còn hỗ trợ; đồng bộ thời gian bật | TLS/OIDC/key expiry phụ thuộc đồng hồ |
| Docker | Docker Engine **rootful** + Compose v5 | ST-10: rootless mặc định không giữ IP nguồn ở cổng publish; đánh giá lại ở Phase 6 (P6-T07) |
| `daemon.json` (đề xuất) | `default-address-pools` chỉ để dời pool tự động của Docker khỏi dải LAN (đây là **một** danh sách chung của daemon, không dành riêng được cho tenant) và dải `hosts.tenant_net_pool` cho network tenant (subnet `/29` tường minh — §11.3 bước 3): cả hai **không chồng** dải LAN của host, **không chồng** `100.64.0.0/10` và `fd7a:115c:a1e0::/48` (PL-15); xoay log container; `live-restore`. **Đã áp dụng** trên host staging và runner CI (2026-11-16): pool tự động `172.24.0.0/13` chia /24; `"ip": "127.0.0.1"` ⇒ cổng publish không ghi IP chỉ nghe loopback (không có `[::]`), compose phải ghi tường minh IP LAN cho cổng cần mở (V-35, AC-20); log json-file 10 MB × 5 | EG-10: pool mặc định chỉ 31 subnet và có dải `192.168.0.0/16` |
| Firewall | Quy tắc trong chain `DOCKER-USER`/nftables (không dựa vào ufw cho cổng publish). Chain `DOCKER-USER` chỉ chứa `DROP`/`RETURN`, **không bao giờ** `ACCEPT` (theo cách Docker sắp chain, một rule `ACCEPT` ở đây kết thúc việc xét duyệt trước các chain cách ly giữa các bridge). Host LAN: cho vào TCP 80/443 từ LAN (Local Development, Platform Console); hai cổng listener tunnel-facing của edge **chỉ** từ peer tunnel (`DOCKER-USER` chỉ thấy lưu lượng **FORWARD** và gói tới đó đã qua DNAT ⇒ so khớp cổng publish bằng `-m conntrack --ctorigdstport <cổng> --ctdir ORIGINAL`, không dùng `--dport` — tài liệu Docker, theo phản biện); SSH từ mạng quản trị; mặc định chặn phần còn lại. Lưu lượng từ container tới **chính host** (địa chỉ gateway của bridge; với network `internal` đường này được coi là vẫn mở cho tới khi IT-14 chứng minh ngược lại) đi qua chain `INPUT` chứ không qua `DOCKER-USER`: mọi gói đi vào host từ bridge của network tenant (nguồn thuộc pool tenant) bị `DROP`, và không có rule chấp nhận chung cho bridge Docker — áp ở Phase 1 (P1-T02) sau khi người dùng duyệt, là tiền điều kiện của IT-14 (phương án thay thế nếu Engine hỗ trợ: tạo network tenant ở gateway mode `isolated`, chỉ dùng sau khi IT-14 xác nhận). **IPv6:** LAN có IPv6 công khai qua SLAAC (Appendix A.4) ⇒ mọi rule trên áp dụng cho cả IPv6 (ip6tables hoặc nftables họ `inet`), và trên host LAN cổng publish chỉ `bind` vào địa chỉ IPv4 LAN cho tới khi V-35 đạt. VPS: xem §14.9 | EG-10; đề xuất — không tự áp dụng |
| Không join tailnet | Host **không** cài Tailscale client join tenant nào | HS-24 |

### 14.2 Bố cục thư mục trên host

```text
/opt/meshguard/
├── core/                       # compose project mg-core và project riêng mg-edge, mg-agent (file compose của từng project, Caddyfile, cấu hình crowdsec/monitoring; agent/allowlist — image Headscale được phép, sinh từ versions.lock bằng tools/render_agent.py, root 0644) — không có secret
├── secrets/                    # root:root 0700 — keyring KEK (kek-app/, kek-ops/: mỗi KEK một file <kek_id> + file ACTIVE), mật khẩu DB, token DNS, khóa bouncer (mỗi secret một file 0400 thuộc UID:GID cố định của service dùng nó, trong secrets/<service>/ — không phải root 0400)
│                               #   ST-05: Compose bỏ qua uid/gid/mode của secret dạng file nên file root:root 0400 KHÔNG đọc được từ edge/api/worker (non-root — §14.4).
│                               #   UID:GID số của từng service core ghim trong compose (user:) và versions.lock; thư mục cha vẫn root 0700 (file được bind mount riêng lẻ).
│                               #   Secret mà hai UID cùng cần (khóa bouncer: crowdsec + edge; mật khẩu DB: postgres + api/worker/migrate) lưu mỗi consumer một bản, xoay cùng lúc.
│                               #   Không dùng 0444, không chạy service bằng root; service không đọc được secret ⇒ dừng ngay và chỉ log đường dẫn, không log giá trị.
├── tenants/
│   ├── .<instance_id>.creating/ .<instance_id>.removing/  # tạm của Agent (tên ẩn, không phải UUID — guard bỏ qua): instance mới dựng xong rồi rename vào chỗ; gỡ thì rename đi rồi xóa
│   └── <instance_id>/          # root:run_gid 0750 — tiến trình tenant KHÔNG ghi được vào đây
│       ├── compose.yaml        # do Agent render lại ở mỗi lần chạy (không secret); root:root 0440
│       ├── config/             # root:run_gid 0750; config.yaml, bootstrap-policy.hujson root:run_gid 0440 (mount read-only)
│       ├── records/            # root:run_gid 0750; extra-records.json root:run_gid 0440 (không có bản ghi = "[]", không để file rỗng; EnsureInstance chỉ ghi "[]" khi chưa có — sau đó WriteDnsRecords) — Agent ghi atomically; mount read-only cả thư mục (Headscale theo dõi file)
│       ├── secrets/            # oidc_client_secret (nếu dùng), root 0440 group run_gid
│       ├── data/               # run_uid:run_gid 0700 — đường dẫn DUY NHẤT thuộc tenant: db.sqlite(+wal/shm), noise_private.key, derp_server_private.key; chỉ tạo cùng instance, không bao giờ tạo lại cho instance đã có meta/activated
│       ├── config.next/        # tạm của ValidateConfig (root:run_gid 0750): config ứng viên cho configtest, luôn bị xóa sau lần chạy (P3-T03)
│       └── meta/               # root:root 0700: instance.json root:root 0400 (tenant_id, instance_id, slug, run_uid, net_cidr — ghi cùng thư mục ở bước 7; template_version, config_sha256, image — bước 8, cùng khóa và định dạng với render_instance.py; noise_key_fingerprint = khóa công khai X25519 dạng hex của data/noise_private.key, ghi ở lần EnsureEdgeAttachment đầu; edge_attach — P3-T03), activated (root:root 0400, JSON {job_id, activated_at} của job kích hoạt — compensation bước 14 chỉ xóa khi đúng job đó)
├── backups/                    # root 0700; filesystem riêng (khác tenants/) hoặc có quota + cảnh báo dung lượng — retention không được làm đầy đĩa dữ liệu; nếu là mount riêng thì thêm vào RequiresMountsFor
│   ├── postgres/               # 10007:mg-sec-backup 0750 — chỉ pg-backup ghi (project mg-backup, P2-T03a)
│   ├── idp/                    # 10007:mg-sec-backup 0750 — chỉ idp-backup ghi (P2-T05b)
│   ├── edge/                   # 10001:mg-sec-backup 0750 — bản sao volume ACME của edge (đã mã hóa), chỉ edge-backup ghi
│   └── tenants/<instance_id>/  # root 0700 — archive đã mã hóa + manifest (agent)
└── run/agent.sock              # Unix socket worker ↔ agent, 0660 nhóm mg-sec-worker; run/ = root:mg-sec-worker 0750 (layout.sh, từ P3-T02; thư mục chỉ mount vào hai container này — §11.1)
```

**Quyền đọc secret file.** Compose gắn secret dạng file bằng bind mount và **bỏ qua** `uid/gid/mode` khai báo trong compose (ST-05), nên quyền phải đặt ở host cho đúng UID/GID mà tiến trình trong container dùng. Thư mục `secrets/` giữ `root:root 0700` (chỉ Docker daemon cần đi qua, vì từng file được mount riêng vào container khai báo nó); mỗi file thuộc `root:<nhóm>` với mode `0440`, và service non-root nhận GID của nhóm qua `group_add` (ASSUMED theo tài liệu Compose — script kiểm quyền của P1-T03 là phép thử). File `root:root 0400` chỉ dành cho service chạy root. Một service chỉ khai báo đúng các secret nó dùng. Bảng khởi đầu (danh sách file chốt ở P1-T03, bổ sung khi service tương ứng được triển khai):

| Nhóm trên host | File (`root:<nhóm>`, `0440`) | Service nhận GID |
|---|---|---|
| `mg-sec-app` | keyring `kek-app`; mật khẩu role `mg_audit_writer`; token listener admin của edge | api, worker |
| `mg-sec-api` | mật khẩu role `mg_api_tenant`, `mg_api_platform` | api |
| `mg-sec-worker` | mật khẩu role `mg_worker_tenant`, `mg_worker_platform`, `mg_partition_maint`; keyring `kek-ops`; token Agent (agent chạy root đọc cùng file với tư cách owner); credential SMTP | worker |
| `mg-sec-migrate` | mật khẩu role `mg_migrator`; **bản** mật khẩu của 6 role đăng nhập (`secrets/migrate/` — job migrate đặt chúng; `mg_migrator` vốn có ADMIN trên các role này nên bản sao không mở rộng quyền, P2-T16) | job `migrate` (project `mg-app`) |
| `mg-sec-edge` | token DNS provider; khóa bouncer CrowdSec; token listener admin và token listener metrics (để đối chiếu) | edge |
| `mg-sec-obs` | token listener metrics; mật khẩu DB của postgres-exporter; secret SSO của Grafana (nếu Grafana tự làm OIDC client); URL webhook cảnh báo | prometheus, postgres-exporter, grafana, alertmanager |
| `mg-sec-backup` (GID 20007) | mật khẩu role `mg_backup` (`secrets/backup/pg_backup_password`); mật khẩu role chỉ-đọc `idp_backup` của idp-db (`secrets/backup/idp_backup_password` — bản của consumer, idp-db đọc bản `secrets/idp/backup_db_password`) | pg-backup, idp-backup (UID 10007 — `versions.lock [ids] backup_uid` — nhóm chính `mg-sec-backup`; project `mg-backup`); edge-backup chạy UID của edge (10001) với nhóm chính `mg-sec-backup`, không có secret |
| `mg-sec-ship` | credential kho offsite (append-only) | backup-shipper |
| `mg-sec-mail` (GID 20009, P3-T05b-mail) | khóa HMAC chung với Worker Cloudflare (`secrets/mail/relay_hmac_key`); khóa TLS của `mailrelay` (`secrets/mail/tls_key`) — chứng chỉ và CA nội bộ cùng thư mục là dữ liệu công khai (0444) | `mail-bridge` (cầu `mailrelay`, project `mg-app`; worker **không** có nhóm này) |
| theo UID/GID mà image chính thức dùng | mật khẩu khởi tạo của PostgreSQL; mật khẩu DB và credential quản trị khởi tạo của IdP; cấu hình bouncer phía CrowdSec | postgres, idp, crowdsec |
| `root:root`, `0400` | khóa ký manifest backup (Ed25519) | agent (chạy root) |

### 14.4 Compose project `mg-core` — dịch vụ và hardening

| Service | Image | Hardening / ghi chú |
|---|---|---|
| edge (**compose project riêng `mg-edge`**, để việc deploy `mg-core` không bao giờ recreate edge) | Caddy tự build (xcaddy: module DNS provider + CrowdSec bouncer + module rate-limit đã pin và review), pin digest | Publish với **IPv4 tường minh**: `<IP LAN>:80`/`:443` và (khi có tunnel) `<IP tunnel>:8080`/`:8443` — không dùng dạng `80:80` vì dạng đó bind cả `0.0.0.0` lẫn `[::]` (§15.4); non-root; `cap_drop: ALL` + `NET_BIND_SERVICE`; read-only + volume dữ liệu ACME; admin API **chỉ** qua Unix socket (`admin unix//run/caddy/admin.sock`, chỉ user chạy Caddy truy cập được, nằm trên tmpfs không mount vào container nào khác) + `persist_config off` (rootfs chỉ-đọc); **không** tắt admin vì `caddy reload` của phương án lùi ở §14.6 cần admin API (EG-04); `dns_search: ["."]` (cú pháp của Docker để **xóa** search domain kế thừa; danh sách rỗng nghĩa là kế thừa của host — xác nhận ở V-03) + `dns_opt: ["ndots:1"]` để tên upstream không bị chuyển tiếp ra resolver ngoài; `sysctls`: `net.ipv4.ip_forward=0`, `net.ipv6.conf.all.forwarding=0`, `net.ipv4.conf.all.arp_ignore=1`, `net.ipv4.conf.all.arp_announce=2`, `net.ipv4.conf.all.rp_filter=1` — edge không được làm router giữa các network tenant (kiểm bằng IT-14) |
| prober | Image của ta: blackbox_exporter (thêm ở P3-T16) + `meshguard-probe` (`apps/probe`, image `infrastructure/docker/probe` — P3-T03a: probe STUN/DERP, HTTPS GET tới IP với SNI/Host chỉ định, kiểm tra allow-list của edge); nhận RPC từ Worker cho bước 17–18 (`POST /v1/{stun,https,edge,relay}`) | Không có secret; non-root, rootfs chỉ-đọc, không publish cổng; chỉ phục vụ caller trong `MG_PROBE_ALLOW_CALLERS` (subnet `mg-admin`) và chỉ probe IP trong `MG_PROBE_ALLOW_TARGETS` (edge, điểm vào công khai — không tra DNS); trên `mg-edge`, `mg-admin`, `mg-obs`, `mg-egress`; service compose nằm trong project monitoring của P3-T16 |
| backup-shipper | Image của ta (restic/rclone đã pin) | Mount **chỉ-đọc** `/opt/meshguard/backups` (chỉ thấy archive đã mã hóa); chỉ trên `mg-egress`; credential kho offsite kiểu append-only; không Docker socket |
| pg-backup (**compose project riêng `mg-backup`** cùng idp-backup, edge-backup — render bằng `tools/render_backup.py`, để nâng cấp image backup không recreate postgres/idp/edge; P2-T03a) | Image của ta `backup` (`meshguard-backup` + `pg_dump`/`pg_dumpall`/`pg_restore` 18.7 chép từ image postgres pin + `age` build tái lập, trên distroless `base-debian13`; pin digest `[images.mg-backup]`) | Chỉ trên `mg-data`; role DB `mg_backup` (chỉ đọc + `BYPASSRLS`, vì `pg_dump` phải đọc hết các bảng `FORCE ROW LEVEL SECURITY` — §6.1); `user: 10007:20007`; mount ghi **chỉ** `/opt/meshguard/backups/postgres`; lịch riêng trong dịch vụ (hằng đêm, UTC) và một lần trước mỗi migration — bước migrate chạy `docker compose -p mg-backup … run --rm pg-backup once --label pre-migration` và dừng nếu lỗi (khác project nên không dùng `depends_on`); dump được mã hóa tới recovery recipient **trước khi ghi** vào thư mục này, nên `backup-shipper` chỉ thấy bản đã mã hóa; non-root, rootfs chỉ-đọc, `cap_drop: ALL`, `no-new-privileges`, không Docker socket, không secret trong biến môi trường |
| idp-backup (project `mg-backup`, P2-T05b) | Image `backup` | Chỉ trên `mg-idp-data`; role chỉ-đọc `idp_backup` của idp-db (`pg_read_all_data`, mặc định read-only — `infrastructure/idp/initdb/20-idp-backup-role.sql`); `user: 10007:20007`; mount ghi **chỉ** `backups/idp`; hardening như pg-backup |
| edge-backup (project `mg-backup`, P2-T05b) | Image `backup` | `network_mode: none`; volume ACME của project `mg-edge` mount **chỉ-đọc** (external); `user: 10001:20007` (UID của edge — đọc được khóa 0600 mà không cần capability); mount ghi **chỉ** `backups/edge`; hardening như pg-backup |
| crowdsec | Chính thức, pin digest | Persist `/etc/crowdsec` + data; `DISABLE_ONLINE_API=true` mặc định (EG-09) |
| api, worker (**compose project riêng `mg-app`** cùng job `migrate` và `db-bootstrap` — render bằng `tools/render_app.py`, để deploy backend không bao giờ recreate postgres/crowdsec; P2-T16) | Image của ta (distroless, non-root) | read-only, `cap_drop: ALL`, `no-new-privileges`, giới hạn CPU/RAM/PID; secret dạng file; api chỉ phục vụ request từ IP của edge; `migrate` chạy sau backup pre-migration (`infrastructure/host/migrate.sh`) |
| agent | Image của ta + CLI docker/compose + `sqlite3` (≥ 3.51.3 — §17.1) + `age` | Mount Docker socket, `/opt/meshguard/tenants` và `/opt/meshguard/backups/tenants` (nơi ghi archive đã mã hóa + manifest ký) **cùng đường dẫn** trong/ngoài container; `network_mode: none`; allowlist image digest (file cấu hình sinh từ `versions.lock`, Worker không ghi được). Chạy root với `cap_drop: ALL` + `cap_add: [CHOWN, FOWNER, DAC_OVERRIDE]` (phải chown sang `run_uid` và đi qua thư mục `0700` của tenant — tập capability tối thiểu là ASSUMED, chốt bằng test ở P3-T02); `read_only: true`, tmpfs cho `DOCKER_CONFIG`, `no-new-privileges`, giới hạn PID/RAM. Socket: xóa socket cũ khi khởi động, tạo `0660` với group = GID của worker, kiểm `SO_PEERCRED` (uid = UID của worker) **cùng** token Agent. Chữ ký/provenance của image được kiểm ở CI và khi người vận hành cập nhật allowlist — Agent không có network nên chỉ cưỡng chế digest |
| web | Tĩnh, do edge phục vụ hoặc container tĩnh | read-only |
| postgres | Chính thức, pin digest | Chỉ `mg-data`; volume riêng; không publish cổng |
| idp | Keycloak (hoặc theo §8.2), pin digest | Chỉ qua edge; DB trên instance PostgreSQL riêng (`idp-db`, chỉ trên `mg-idp-data` — §14.3), không dùng chung PostgreSQL của nền tảng |
| stund (chỉ ở Local Development) | Image của ta build từ tag Tailscale đã pin | Host network, UDP 3478; khi đã dùng VPS thì `stund` chạy trên VPS và bản trên host LAN tắt |
| monitoring | Prometheus, Alertmanager, Grafana, Loki, Alloy, cAdvisor, node_exporter (blackbox_exporter và probe STUN/DERP nằm trong service `prober`) | Chỉ `mg-obs` (Alertmanager thêm `mg-egress`; Prometheus thêm `mg-egress` **chỉ** để scrape node_exporter/`l4proxy` của VPS qua IP tunnel từ Phase 6 — network `internal` không có route tới tunnel, đích bị khóa bằng allow-list ở P6-T07; phương án thay thế giữ Prometheus hoàn toàn nội bộ: `prober` chuyển tiếp chỉ-đọc `/metrics` của VPS); Grafana sau SSO ở origin admin. Ngoại lệ so với "chỉ `mg-obs`", theo bảng §14.3: Grafana thêm `mg-edge`, postgres-exporter thêm `mg-data`; node_exporter cần `pid: host` và mount chỉ-đọc `/proc`, `/sys`, `/` — cách Prometheus tới được nó chốt ở P3-T16 |

Không service nào ngoài agent được mount Docker socket. Không dùng `env_file` chứa secret; không biến môi trường chứa secret. Ánh xạ container → tenant cho log và metrics **không** dùng Docker API: container tenant khai báo log option `labels=meshguard.tenant_id,meshguard.instance_id` và collector đọc file log qua mount host chỉ-đọc; cAdvisor (không có Docker socket nên không biết tên hay label container) được ghép nhãn tenant bằng join theo container ID với chuỗi `meshguard_instance_info` do API xuất (§16.1, V-31).

### 14.5 Template instance của tenant (thiết kế — file thực được tạo ở Phase 1/3)

| Thuộc tính compose | Giá trị |
|---|---|
| Định danh runtime | **Slug** của tenant là định danh duy nhất cho mọi object runtime (duy nhất, bất biến; regex `^[a-z][a-z0-9-]{1,30}[a-z0-9]$`, cấm `--`, tiền tố `xn--`, và các tên dành riêng như `app`, `admin`, `auth`, `api`, `www`, `stun` cùng các nhãn của `<mesh_domain>`). Thư mục dữ liệu dùng `instance_id` (UUID đầy đủ — không bao giờ dùng tiền tố UUID làm tên) |
| Project / network / container / service / alias | `mg-t-<slug>` / `mg-t-<slug>` / `mg-hs-<slug>` / service `hs-<slug>` / alias `hs-<slug>` trên network tenant (Compose tự thêm tên service làm alias nên tên service cũng phải duy nhất). Agent từ chối nếu object trùng tên mang `meshguard.instance_id` khác, và kiểm tra alias chưa tồn tại trên mọi network mà edge đang gắn trước khi attach |
| Bind mount | Cú pháp dài với `bind: { create_host_path: false }` cho `config/`, `records/`, `data/` (và `secrets/` khi dùng phương thức C) — thiếu thư mục thì container **không** khởi động thay vì tạo thư mục rỗng |
| Network | `mg-t-<slug>` khai báo `external: true` — Agent tạo ở bước 9 với `--internal`, `--subnet <net_cidr>` và label `meshguard.instance_id`, `meshguard.role=tenant`; compose không tạo và không xóa network |
| Image | `mg-headscale@sha256:<digest>` — Headscale 0.29.7 + bản vá V-26 do dự án build (`infrastructure/docker/headscale`, `versions.lock` `[images.mg-headscale]`; ADR-02 sửa đổi, P2-T10a); bố cục như image chính thức (`/ko-app/headscale`, `headscale` trong `PATH`, user mặc định 65532), lệnh `serve`. Tham số `headscale_build` của instance chọn `patched` (mặc định khi đã pin) hoặc `official` (`headscale/headscale@sha256:<digest của 0.29.7>` — rollback; DB dùng chung hai chiều); đổi image của instance đang chạy bằng `tenant-upgrade.sh` (luồng Upgrade §11.4) |
| User | `<run_uid>:<run_gid>` riêng từng instance (`run_gid` = `run_uid`, không cấp phát riêng — §6.3) (image mặc định chạy root — RT-08) — **REQUIRES VALIDATION** (V-04) image chạy được non-root với volume đã chown |
| Filesystem | `read_only: true`; `tmpfs: /var/run/headscale` (thuộc `run_uid`); mount `config/` → `/etc/headscale:ro`, `records/` → `/etc/headscale-records:ro`, `secrets/` → `/etc/headscale-secrets:ro` (chỉ khi tenant dùng phương thức C, cho `oidc.client_secret_path`), `data/` → `/var/lib/headscale`; khi dùng phương thức C thêm `secrets/` → `/etc/headscale-secrets:ro` (`oidc.client_secret_path` trỏ vào đây) |
| Ports | **Không publish cổng nào** (STUN dùng chung nằm ở điểm vào công khai; `stun_listen_addr: 0.0.0.0:3478` chỉ bind trong container) |
| Bảo mật | `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `pids_limit`, `mem_limit`, `cpus` theo plan; compose tenant không khai báo biến môi trường `TS_*` nào (đặc biệt `TS_ALLOW_DEBUG_IP`, `TS_DEBUG_TRUSTED_CIDRS`, `TS_DEBUG_KEY_PATH` — chúng mở endpoint debug, PL-15) — Agent kiểm như một bất biến |
| Dung lượng | Quota đĩa theo instance cho `data/` (XFS project quota hoặc volume có trần — chọn theo filesystem ghi nhận ở P1-T01); host chưa hỗ trợ ⇒ cảnh báo dung lượng `data/` theo instance (đo trong container trợ giúp — §11.5) và áp quota muộn nhất ở P6-T07. `tmpfs` khai báo `size`. Khuyến nghị đặt `/opt/meshguard/backups` và volume PostgreSQL trên filesystem khác `tenants/` (hiện trạng ghi ở P1-T01) để một instance ghi đầy đĩa không chặn PostgreSQL và backup của tenant khác |
| Healthcheck | `test: ["CMD", "headscale", "health"]`; `start_period: 60s` với `start_interval: 2s` (cần Docker Engine ≥ 25) để instance vừa start được nhận `healthy` trong vài giây thay vì chờ probe đầu tiên sau 30 s của mặc định Docker; trạng thái ổn định `interval: 30s`, `timeout: 5s`, `retries: 3` (ghi tường minh; không hạ `interval` vì mỗi probe là một lần exec CLI trên từng instance — chi phí đo ở P1-T20/P6-T08) |
| Restart / log | `unless-stopped`; `stop_grace_period: 60s` (theo phản biện, Headscale chạy `VACUUM` khi đóng DB ở chế độ WAL — mặc định 10 s của Docker có thể SIGKILL giữa chừng; giá trị chốt theo số đo ở V-12); xoay log; label `meshguard.tenant_id`, `meshguard.instance_id` |

| Khóa `config.yaml` | Giá trị render |
|---|---|
| `server_url` | `https://<slug>.<mesh_domain>` |
| `listen_addr` / `metrics_listen_addr` | `0.0.0.0:8080` / `0.0.0.0:9090` (chỉ tới được trong network tenant) |
| `grpc_listen_addr`, `grpc_allow_insecure` | mặc định / `false` (gRPC không khởi động — RT-01) |
| `trusted_proxies` | `net_cidr` của network tenant — cấp ở bước 3 của §11.3 nên biết trước khi network tồn tại (bước 8 render trước bước 9). Tin cả subnet là có chủ đích: ngoài Headscale, trong subnet chỉ có edge và địa chỉ gateway của bridge (chính host — vốn đã thuộc ranh giới tin cậy, T-14); thu hẹp về `<IP của edge>/32` cần cấp IP cố định cho edge — hardening tùy chọn, không làm ở MVP |
| `tls_*` | rỗng (TLS tại edge) |
| `noise.private_key_path`, `database.sqlite.path`, `derp.server.private_key_path` | dưới `/var/lib/headscale/` |
| `prefixes` | `100.64.0.0/10`, `fd7a:115c:a1e0::/48` (mặc định; các tenant độc lập nên dùng lại được) |
| `derp.*` | theo §10.1 (tường minh mọi khóa; `urls: []`) |
| `policy.mode` | `database` |
| `dns.*` | `magic_dns: true`; `base_domain: <slug>.<tailnet_suffix>` (không trùng/không là cha của host trong `server_url` — RT-07); nameserver theo tenant settings; `extra_records_path` |
| `node.expiry` | theo tenant settings (mặc định đề xuất 90 ngày) |
| `node.ephemeral.inactivity_timeout`, `taildrop.enabled` | ghi tường minh (`30m`, `true`) để hành vi không phụ thuộc default: default trong code của `inactivity_timeout` là `120s`, khác `30m` của file ví dụ (HS-19) |
| `log` | `format: json`, `level: info` |
| `disable_check_updates` | `true` (RT-08) |
| `logtail.enabled` | `false` |
| `oidc` | chỉ khi tenant chọn phương thức C |
| `unix_socket` | `/var/run/headscale/headscale.sock` (tmpfs, không chia sẻ) |

### 14.7 CrowdSec dùng chung (thay vì lặp lại theo tenant)

| Quyết định | Lý do |
|---|---|
| Một engine + một bouncer tại edge | Mọi HTTP đi qua edge; lặp theo tenant không khả thi trên một IP |
| Acquisition từ JSON access log của Caddy, một file cho site wildcard; tách tenant theo trường `request.host` ở parser/collector | Truy vết theo tenant; lưu ý log stream dài chỉ có khi đóng (EG-08) |
| Thời hạn ban ngắn hơn mặc định cho hostname tenant; allowlist IP văn phòng do tenant khai báo; nút gỡ ban trong Platform Console (Phase 6 — P6-T07a; trước đó gỡ ban bằng `cscli` theo runbook) | Một IP NAT bị ban sẽ khóa mọi thiết bị của tenant sau NAT đó khỏi control **và** relay (EG-09) |
| Tắt chia sẻ Central API ở mặc định | Không gửi IP khách hàng cho bên thứ ba khi chưa có quyết định về quyền riêng tư |
| Không kỳ vọng CrowdSec bảo vệ kênh Noise hay STUN | Ngoài tầm quan sát (EG-09) ⇒ dùng giới hạn kết nối ở edge cho TCP (module rate-limit — có từ P6-T07); với STUN **không rate-limit** gói hợp lệ (khuyến cáo của upstream — EG-11, T-10), chỉ giám sát gói/giây và chặn nguồn lạm dụng rõ ràng bằng nftables tại điểm vào công khai |

### 14.8 Quy trình triển khai và rollback

Trình tự chi tiết nằm ở Phase 1 (§19) và task P1-* (§20). Nguyên tắc: mỗi bước có kiểm tra sau bước; mọi thay đổi host (cài Docker, `daemon.json`, firewall) có bản sao cấu hình cũ và lệnh hoàn tác; không mở cổng public trước khi qua kiểm tra nội bộ; `mg-core`, `mg-edge` và từng project tenant có thể `down` độc lập mà không xóa dữ liệu.

### 14.9 VPS Public Gateway (project `mg-gateway` trên VPS)

Mục đích: cung cấp địa chỉ IP công khai cho các endpoint **cần public** trong khi toàn bộ state, khóa TLS và Management Plane vẫn nằm trên host LAN. VPS được thiết kế là **đường truyền không tin cậy hoàn toàn**: không có gì trên VPS đủ để giải mã lưu lượng hay mạo danh nền tảng.

| Thành phần trên VPS | Vai trò | Cấu hình cốt lõi | Ghi chú bảo mật |
|---|---|---|---|
| Tunnel WireGuard site-to-site (kernel, do systemd quản lý) | Liên kết riêng VPS ↔ host LAN | VPS lắng nghe một cổng UDP; **host LAN chủ động kết nối** (keepalive) nên không cần port forwarding ở LAN; mỗi đầu một địa chỉ /32, `AllowedIPs` chỉ là địa chỉ của đầu kia | Khóa sinh tại từng máy, chỉ trao đổi public key. Đây là WireGuard thuần — host **không** join tailnet của tenant nào (HS-24) |
| `l4proxy` (HAProxy chế độ TCP, image chính thức pin digest) | Chuyển tiếp TCP 443 → listener `:8443` và TCP 80 → listener `:8080` của edge qua tunnel, kèm `send-proxy-v2` (GW-03) | Không terminate TLS, không có chứng chỉ; timeout đủ dài cho stream control/DERP (đo ở V-18); chỉ bind/publish trên IPv4 công khai của VPS, không bind `[::]` (§15.4) | Chỉ thấy ciphertext TLS + metadata (IP, SNI) |
| `stund` (tự build từ tag Tailscale đã pin — GW-01) | STUN responder dùng chung, UDP 3478 | Host network; HTTP debug bind `127.0.0.1` | Stateless; không có secret |
| Firewall của VPS (nftables + security group của nhà cung cấp nếu có) | Chỉ mở: TCP 80/443, UDP 3478, UDP cổng tunnel, SSH (key-only, giới hạn IP nguồn); từ P6-T07: giới hạn số kết nối TCP mới và đồng thời theo IP nguồn tới 80/443, ngưỡng đủ rộng cho NAT văn phòng (T-11) | Mặc định chặn | — |
| node_exporter (Phase 6) | Giám sát VPS | Chỉ bind IP tunnel | Scrape từ Prometheus trên host LAN |

**Không đặt trên VPS:** khóa riêng TLS, token DNS provider, dữ liệu/khóa của tenant, PostgreSQL, API key của Headscale, Docker socket của Agent, Platform Console.

**Luồng lưu lượng Internet-facing:** client → `<slug>.<mesh_domain>` (DNS trỏ về IP của VPS) → `l4proxy` TCP 443 → tunnel → edge `:8443` trên host LAN (đọc PROXY header, terminate TLS, áp allow-list path, CrowdSec) → Headscale của tenant. STUN: client → VPS UDP 3478 → `stund` trả lời tại chỗ.

**Kiểm soát bắt buộc trước khi dùng VPS:** (1) user triển khai + SSH key (đã có từ 2026-11-16) và tắt đăng nhập SSH bằng mật khẩu — biện pháp bù bắt buộc vì chủ dự án quyết định không đổi mật khẩu root đã bị lộ (D-10); vẫn cần chủ dự án chấp thuận khi làm P1-T15; (2) firewall như bảng trên; (3) bản ghi **CAA** của domain giới hạn CA, phương thức `dns-01` và `accounturi` của tài khoản ACME đang dùng (GW-04) — để người kiểm soát IP của VPS **không** tự xin được chứng chỉ qua HTTP-01/TLS-ALPN-01; (4) firewall host LAN chỉ cho peer tunnel tới hai cổng listener của edge; (5) image trên VPS pin digest, cấu hình nằm trong repo để dựng lại gateway trong vài phút.

**Giới hạn đã biết:** thêm một chặng mạng (độ trễ) và hai SPOF nối tiếp (VPS; tunnel/đường truyền của LAN); toàn bộ lưu lượng control **và relay** đi qua băng thông/quota của VPS và uplink của LAN; gateway bị chiếm có thể gây gián đoạn, quan sát metadata và giả mạo IP nguồn trong PROXY header (T-19). Khi cần hiệu năng/độ sẵn sàng cao hơn: chuyển tenant runtime lên host có IP công khai (Path C, Phase 7).
