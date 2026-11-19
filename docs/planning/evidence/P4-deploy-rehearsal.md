# Diễn tập nâng staging Phase 3 → lô Phase 4 (`8840590` → `9736636`)

> **File viết tay — không sinh từ master.** Bằng chứng diễn tập triển khai trước đợt Phase 4 đầu tiên lên staging. Quy
> ước: [README](README.md). Runbook đã sửa theo diễn tập: [deploy-backend.md](../../operations/deploy-backend.md) mục m, o;
> [RUNBOOK](../../../infrastructure/host/RUNBOOK.md) mục "Template v8 → v9". Script đã chạy (không secret):
> [P4-deploy-rehearsal/](P4-deploy-rehearsal/).

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-19, 09:44–11:40 UTC |
| Người thực hiện | Agent (Claude Code), theo brief của người điều phối |
| Môi trường | **dev/CI — VM 110** `mg-ci-runner-2` (192.168.1.23), tài nguyên tiền tố `dep4`. **Không** chạm staging (VM 104), VPS, OPNsense, Tailscale, Proxmox, DNS công khai, Cloudflare |
| Từ | `~/mg` = `8840590` (đúng commit của staging — `current.md` đợt 12; mã = image api/worker/agent `d8a4223`) |
| Lên | `9736636` (main cục bộ: P4-T01, T01a, T02, T03, T03a, T04, T05, T06, T07, T09, T09a, T10, T11, T12, T13, T15, T14 phần chuẩn bị, fu-g3, fu-flake) |
| Image | build từ cây trong host lồng như workflow `images` (`APP`/`VERSION`/`COMMIT`): api, worker, agent (cả hai commit), web (mới), probe, backup, node-exporter (cũ — không đổi ở lô này). Image pin còn lại từ cache của VM theo digest `versions.lock`: edge `9ec3b439…`, idp `ce83f361…` (`129b202`), mg-headscale `d95ff9df…`, stund, postgres 18.7, prometheus, alertmanager; golang/node đúng digest của brief |
| Nhãn kết quả | **functional** (§22.1) — client Tailscale chính thức 1.104.7 là container trên cùng VM; mạng là bridge của Docker |

## 1. Kết luận

**Nâng cấp đã được chứng minh; có 5 lỗi runbook/script (F-1…F-5), đã sửa hoặc ghi vào runbook.**

- Nâng `8840590` → `9736636` trên bản sao staging dựng bằng **chính** script của host (`layout.sh`, `networks.sh`,
  firewall, `ceremony.sh`, `app-secrets.sh`, `migrate.sh`, `tenant-deploy.sh`, `adopt-instance`, `backfill-instance`,
  `realm-update.sh`, …): migration 19 → 26 **4 s** (lần hai 8 s), api/worker/web **5,1 s** recreate, Agent **3,3 s**, reload
  edge v8 → v9 → v10 **0,2 s** mỗi lần. Gián đoạn đo mỗi 0,5 s: **`app.` API 502 ~2 s** (lúc recreate api), **`/key` của
  tenant qua LAN và qua "VPS": 0 lỗi / 943 lượt**, 1 request bị đóng đúng lúc reload edge; long-poll của 4 client đóng
  đúng 5 phút sau reload (`stream_close_delay`) và tự nối lại.
- Sau nâng: conformance edge **PASS** (v10, cây mới), 34/34 kiểm API (route Phase 4 200, chéo tenant 404), G3 tenant C
  **12/12** (provision 19 bước → 2 client → suspend/resume → deprovision 2P), `realm-update.sh --check` **0 thay đổi**,
  policy/node/API key của A/B **không đổi**, bản ghi DNS P4-T12 tới tận client (MagicDNS).
- Hoàn tác **A** (không đụng DB: image cũ trên schema 26): `app.` 502 1,5 s, `/key` 0 lỗi, 34/34 + G3 12/12 + conformance
  PASS. Hoàn tác **B** (restore bộ pre-migration + đối soát): API không phục vụ **21,5 s**, `post-restore-reconcile`
  `completed`, 0 mục chưa xong, 0 mục cần rà; G3 12/12. Nâng lại sau B: đạt như lần đầu.
- **Edge v10 chưa nên lên staging**: `9736636` chưa có trang `/enroll/claim` (P4-T08) — đã thấy link `/register/<auth_id>`
  chuyển tới SPA và SPA không có route đó. Đề xuất đợt staging: lên tới **v9**, v10 cùng đợt có P4-T08 (mục 7).

## 2. Môi trường diễn tập — giống staging tới đâu

**"VM con" `dep4-host`:** container privileged trên VM 110 mang **userland Ubuntu 24.04 của chính VM** (`/usr` chỉ đọc —
cùng Docker **29.9.3**, containerd snapshotter, `daemon.json` y hệt staging) với `/etc`, `/opt`, `/root`, `/var` riêng
dưới `~/dep4/root`: `/opt/meshguard`, nhóm `mg-sec-*` (GID cố định), `~/mg` (= `/root/mg`) và dockerd lồng đều tách khỏi
VM và khỏi agent `fup4b`. Mọi script của host chạy **nguyên văn** với đường dẫn thật `/opt/meshguard`. Hostname
`mg-staging`; `eth0` = "LAN", `mg-wg0` = "tunnel" (network Docker đổi tên interface để firewall áp đúng như staging).

| Thành phần staging | Trong diễn tập | Ghi chú |
|---|---|---|
| Host VM 104, `staging.env` | `dep4-host`, `infrastructure/environments/dep4/dep4.env` (chỉ tồn tại trong host lồng, không commit): `dep4.test`, LAN `10.77.4.0/24`, tunnel `10.77.5.0/24`, "IP công khai" `192.88.99.10` (dải 6to4 relay anycast đã bỏ — RFC 7526: Python xếp *global* nên `render_gateway.py` nhận; TEST-NET bị từ chối) | `edge.json`, `gateway.json`, `tenants/tenant-{a,b}.json` chép nguyên của staging |
| Firewall `inet mg_host` + `bridge mg_bridge` | template của repo render bằng `mgenv.py`, `nft -c` rồi `nft -f` | không có systemd ⇒ không qua `apply-firewall.sh` (và lệnh đó hỏng — F-1) |
| Nghi thức khóa P2-T04a | `ceremony.sh preflight` + `generate` thật (`MGKC_ENV_FILE`, age build bằng `build-age.sh`, sha256 khớp `versions.lock`) | identity khôi phục giữ trên tmpfs của host lồng cho bước restore (staging: bản giấy của chủ dự án) |
| Edge Caddy, chứng chỉ ACME DNS-01 | Caddyfile render thật, **chỉ** khối `tls` đổi sang chứng chỉ CA thử bằng chính `stack.ci_tls()` của harness (override compose thêm 2 secret file) | ACME/Cloudflare: chỉ kiểm được trên staging |
| VPS `l4proxy` (HAProxy gateway **v2**, F-G3-1) + `stund` | `render_gateway.py` của cây mới (v2), HAProxy + stund pin digest, PROXY v2 qua "tunnel" | không WireGuard (network Docker) |
| A/B dựng tay Phase 1 → adopt → backfill | đúng chuỗi đó: `render_instance` → `tenant-deploy.sh` → `reattach-edge.sh` → fixture → `adopt-instance` → `backfill-instance` → `policy-apply` | cùng `tenant_id`/`instance_id`/`run_uid`/`/29` như staging |
| IdP 3 realm + relay thư | `mg-idp` image pin, `mail-secrets.sh`, `mail-bridge`; `MG_MAILRELAY_URL=https://mailrelay.invalid/v1/send` | **không gửi thư thật**: thư vào outbox, cầu báo 451, job thử lại |
| Tài khoản người | `create-user.sh` (mật khẩu sinh tại chỗ, 0600, đã xóa), 2 SA (`bootstrap-super-admin`), TO/TA A/B (`seed-membership`), TOTP đăng ký ở lần đăng nhập đầu | đăng nhập thật qua edge bằng harness (`backend.portal_login`) |
| mg-backup, mg-obs, Host Agent, `host-set` | đúng runbook; `obs-targets.sh` một lượt (không timer systemd) | |
| Client lab a1/b1 (qua VPS), a2/b2 (LAN-direct, sau NAT) | container Tailscale chính thức; a2/b2 thêm đường ra "Internet" (DERP/STUN tới IP công khai như sau OPNsense) | |
| DNS công khai `*.mesh` (bước 4 `dns.ensure`) | resolver giả trên `mg-egress` + `MG_PROVISION_DNS_SERVER` (override compose) | `MG_PROVISION_DNS_CHECK=skip` bị chặn ngoài dev/ci — đúng |
| api/worker/prober tin chứng chỉ công khai | override compose: `SSL_CERT_FILE` = CA thử (api, worker), `MG_PROBE_CA_FILE` (prober); conformance chạy với `SSL_CERT_FILE` | staging không có các file override này |

Dữ liệu mẫu trước nâng: tenant A (3 node, 2 online), B (2 node), policy fixture qua lõi (`desired_policy_version_id`),
1 lời mời `pending` (A), suspend → resume B qua API (thông báo outbox), 4 tenant thử G3 đã `deleted` (1 `failed`
rolled_back), lịch backup instance, `audit_events` 189 hàng, schema 19.

## 3. Khác biệt triển khai `8840590` → `9736636`

| Loại | Thay đổi | Việc trên staging |
|---|---|---|
| Migration | `0020` enrollment_requests (+ **FK** `device_inventory_cache.enrollment_request_id`), `0021` groups/group_members/tenant_tags, `0022` network_resources/dns_records, `0023` support_access_grants/identity_links, `0024` **CHECK** `tenant_memberships.status ∈ {active, locked, offboarded}`, `0025` **CHECK** `platform_users.status ∈ {active, disabled}`, `0026` `support_access_grants.grantee_display`; seed RBAC chỉ đổi mô tả route. Mọi file: forward-only, expand-only | `migrate.sh` **sau khi** cài compose mới (F-3). Preflight 3 truy vấn chặn migration (deploy-backend o bước 2). api/worker **cũ** chạy được trên schema 26 (đã kiểm) |
| Image | **api, worker** (mọi task backend Phase 4), **web** mới (SPA), **agent** (P4-T12 `WriteDnsRecords`); `mail-bridge` dùng image worker ⇒ recreate cùng worker. **Không đổi**: edge, idp, headscale, stund, backup, node-exporter; probe chỉ đổi test | Pin **cùng tag** `[images.mg-api]`, `[images.mg-worker]`, `[images.mg-web]` **và** `[images.mg-agent]` (`versions.lock` ở `9736636`: `[images.mg-web]` chưa pin — `render_app.py` từ chối) |
| `compose.app.yaml` | template **3 → 4**: service `web` (chỉ `mg-edge`, không secret/volume, 65532, rootfs chỉ đọc); đổi image api/worker/migrate/db-bootstrap/mail-bridge (diff 39 dòng) | render + cài |
| `compose.agent.yaml` | chỉ image + `MG_AGENT_HELPER_IMAGE` (6 dòng); `agent/allowlist` không đổi | render + cài + `up -d` |
| Edge | Caddyfile **v8 → v9** (71 dòng: SPA sau `app.`/`admin.`, `@dot_segment` 404, trang 503, COOP/CORP/Permissions-Policy) **→ v10** (36 dòng: `/register/<auth_id>` ⇒ 302 claim). `compose.edge.yaml` chỉ khác dòng chú thích ⇒ **reload**, không recreate | v9 render bằng cây `f7ceb5d` (F-2); v10 chờ P4-T08 |
| Biến môi trường | mới: `MG_IDP_CONSOLE_LOGIN_NOTIFY_WINDOW` (worker, tùy chọn, mặc định 10m — F-G3-2); không render vào compose | không cần sửa `staging.env` |
| Secret file / network / firewall / layout | không đổi: `app-secrets.sh`, `check-secrets.sh`, `networks.sh`, `layout.sh`, template firewall giống hệt (`web` không có secret; baseline `check-secrets.sh` 29 PASS) | — |
| IdP | `infrastructure/idp`, `render_idp.py` không đổi ⇒ `realm-update.sh --check` 0 thay đổi trước và sau | chỉ kiểm |
| Job / lịch worker | lịch mới: `policy.drift` (`policy.drift_check` mỗi 15 phút/instance — lệch ⇒ security_event High + `policy.apply` `drift_repair`), `enrollment.reconcile`; định kỳ nền tảng `grant.expire`; kind mới `dns.records_write` (qua Agent), `member.offboard`, `member.idp_invite`, `policy.apply` hợp nhất; thông báo mới `idp.config_changed`, `tenant.security_settings_changed`, `tenant.deletion_requested`, `platform.tenant_deletion_requested` | preflight sha policy A/B (deploy-backend o bước 2) |
| VPS | gateway template v2 đã lên từ F-G3-1 — lô này không đổi | — |
| Test-only | image Playwright `[images.playwright]`, `make e2e-playwright` — không triển khai | — |
| Script kiểm | `tests/security/edge/conformance.py`/`run_staging.sh` đổi theo v9/v10 (nhóm `platform` cần `mg-app-web-1`; nhóm `public` đòi chuyển hướng v10) | chạy bản của **cùng cây** với Caddyfile đang chạy (F-2) |

**Thứ tự bắt buộc** (đã kiểm từng ràng buộc): pin → compose mới → `migrate.sh` → Agent → api/worker/web/mail-bridge →
edge v9 (web trước — v9 không có web ⇒ 503) → v10 chỉ sau P4-T06 (có ở `9736636`) **và** P4-T08 (chưa có).

## 4. Trình tự đã chạy và số đo (lần nâng 1)

Đầu dò `probe.py` trên VM 110 (ngoài host lồng — như một máy LAN và một máy Internet), mỗi 0,5 s, kết nối TLS mới mỗi
lượt; mốc từ `steps.log` của host lồng.

| UTC | Bước | Thời gian | Ảnh hưởng đo được |
|---|---|---|---|
| 10:49:52 | `sync`: `~/mg` = `9736636` (bản cũ `mg.bak-…`), sao lưu compose/Caddyfile đang chạy | < 1 s | 0 |
| 10:49:53 | preflight: `test_render_app/edge/agent/backup/monitoring/idp` exit 0; membership `active=4`, platform_users `active=2`, device có `enrollment_request_id` 0, job dở 0 | 2 s | 0 |
| 10:49:55 | render + diff (mục 3) | 18 s | 0 |
| 10:50:13 | **F-3**: `migrate.sh` khi compose cũ còn cài ⇒ backup + migrate của image cũ ⇒ `schema 19`, `current:true`, `OK` — không có migration nào | 30 s | 0 (no-op âm thầm) |
| 10:50:44 | cài `compose.app.yaml` mới → `migrate.sh`: backup `postgres-20261119T105045Z-pre-migration` → schema **26** `current:true`, 0 vi phạm quyền partition | **~4 s** | 0; api/worker cũ healthy, 34/34 kiểm API trên schema 26 |
| 10:51:00 | `$APP up -d --wait api worker web mail-bridge` | **5,1 s** | `app.` API **502 2,0 s**; `/key` 0 |
| 10:51:29 | **F-4**: bản ghi DNS (P4-T12) với **Agent cũ** ⇒ `dns.records_write` `failed agent_refused` | — | bản ghi có trong DB, không tới Headscale |
| 10:51:48 | Agent mới `up -d --wait` | **3,3 s** | 0; supervisor gắn lại; ghi DNS kế tiếp ⇒ `succeeded`, file chứa **cả hai** bản ghi (level-triggered) |
| 10:52:05 | edge **v8 → v9** (render cây `f7ceb5d`, validate, reload) | **0,2 s** | 0; `app./` 404 → 200 (SPA) |
| 10:53:20 | edge **v9 → v10** | **0,2 s** | 1 request `RemoteDisconnected` (`/key` B qua VPS) đúng lúc reload |
| 10:57:06 | `stream_close_delay`: long-poll của a1/a2/b1/b2 `PollNetMap: unexpected EOF` (5 phút + 1 s sau reload v9) | — | 4/4 client nối lại; ping trực tiếp giữa a1↔a2, b1↔b2 đạt |

Tổng (không tính hai lần demo F-3/F-4): migrate → v10 ≈ **1 phút 15 s**; gián đoạn API `app.` ≈ **2 s**; control plane
của tenant **0 s** (mỗi reload chỉ đóng stream cũ sau 5 phút). `api-lan` thêm 3 mã 429 lúc 10:56–10:57: đầu dò gọi
`/api/v1/auth/session` 2 lần/s từ cùng IP với các lượt đăng nhập kiểm — giới hạn tần suất của `/auth/*` theo IP, không
phải lỗi (đầu dò sau đó chuyển sang `/api/v1/tenants`). Trên staging, DB lớn hơn (audit 30 ngày, ~20 tenant thử đã xóa) ⇒
backup + migrate có thể dài hơn vài giây — vẫn không gián đoạn vì api/worker cũ chạy tiếp trên schema mới.

## 5. Kiểm sau nâng

| Kiểm | Kết quả |
|---|---|
| Health | api/worker/mail-bridge `/readyz` 200, web healthprobe 200, Agent healthy (`agent_started`, `edge_supervisor_started`); worker `worker wired`, `job worker and schedules started`, orchestrator/reconfigure/restart-upgrade/relay thư configured |
| Conformance edge (`run_staging.sh`, nhóm public/admin/metrics/unreachable/tunnel-reject/platform/real-api/stopped) | v9 + cây `f7ceb5d`: **PASS**; v9 + cây `9736636`: **FAIL** 30+ ca `/register/<auth_id>` (đòi v10 — F-2); v10 + cây `9736636`: **PASS** |
| Site nền tảng (LAN và qua VPS) | `app./`, deep link `/tenants/x/devices`, `/healthz` ⇒ 200 `text/html` SPA + CSP; `/api/v1/auth/session` ⇒ 401 `problem+json`; `/.env` ⇒ 404; `admin./` ⇒ SPA (LAN), console Keycloak ⇒ 401 không phiên; `admin.` qua VPS ⇒ đóng kết nối; `/register/<auth_id>` ⇒ **302** `https://app.dep4.test/enroll/claim?tenant=tenant-a&auth_id=…`, `?via=portal` ⇒ trang Headscale; đích `/enroll/claim` ⇒ `index.html` của SPA **không có route** này (P4-T08) |
| API thật (đăng nhập Keycloak + TOTP qua edge) | **34/34**: SA `GET /platform/tenants|health|instances|users|plans|support-grants` 200; TO-A `GET /tenants/A/{devices, policies, tags, users, groups, dns, routes, resources, enrollment/requests, support-grants, settings, dashboard, audit}` 200; TO-B tới cùng route của A ⇒ 404 |
| G3 `tenant-c` (cây mới, client chính thức qua "VPS") | **12/12**: provision 14,4 s (19 bước, gồm `relay.assign` thật qua prober + stund), `/key` 200 + 22/22 path cấm 404, 2 client join bằng pre-auth key một lần, TCP thông, suspend ⇒ chặn, resume ⇒ thông, deprovision 2P (tự duyệt 403), 0 mồ côi |
| A/B không bị đụng | `mg-hs-tenant-a/b` StartedAt như trước (không restart); policy sha `46206234…` cả A và B (như trước), `desired_policy_version_id` giữ bản của backfill; node/node key giữ nguyên; mỗi tenant đúng 1 API key còn hạn |
| Job mới | `policy.drift_check` succeeded (không lệch), `grant.expire` succeeded, `dns.records_write` succeeded (sau Agent mới); worker ERROR duy nhất = job F-4; api 0 ERROR |
| P4-T12 tới client | `extra-records.json` (root:30001 0440) có bản ghi; `tailscale dns query svc.dep4-lab.test` trên a2 ⇒ `A 100.64.0.3` |
| IdP | `realm-update.sh --check` exit 0 (platform/tenant-a/tenant-b 0 thay đổi, master đã gia cố, mg-provisioner đọc được event) |

## 6. Hoàn tác

| | A — giữ DB (11:30:26) | B — restore bộ pre-migration (11:33:34) |
|---|---|---|
| Cách làm | Caddyfile v8 + compose edge đã sao lưu → validate → reload (0,3 s); compose agent cũ → `up --wait` (3,9 s); compose app cũ → `up --wait --remove-orphans api worker mail-bridge` (4,9 s, gỡ `web`); `~/mg` = bản `mg.bak-…` | backup-restore.md 6.3 + 6.5: bảo trì on (api 503) → chờ worker dừng job (11 s) → dừng api/worker (1,2 s) → đổi tên DB → globals → `pg_restore --create` qua `age --decrypt` (2,1 s) → `migrate status` image cũ: schema 19 `current:true` → cờ bảo trì trong DB mới → `up --wait` (3,9 s) → `post-restore-reconcile` dry-run + thật → bảo trì off → backup `manual` |
| Gián đoạn đo | `app.` API **502 1,5 s**; `/key` 0 lỗi; 1 request đóng lúc reload | API **21,5 s** (503 bảo trì rồi 502 lúc dừng); `/key` 0 lỗi (Headscale phục vụ suốt — §17.4) |
| Kết quả | api/worker/agent cũ trên **schema 26**: 34/34 kiểm API, G3 tenant-C **12/12**, conformance (cây `8840590`, v8) **PASS**, 4/4 client | `post-restore-reconcile` exit 0 `completed`: session thu hồi 19 (+ 21 auth request), lời mời `pending` ⇒ `revoked` 1, 0 mồ côi, 0 mất, API key A/B `ok` (giữ nguyên), policy A/B `match` (`46206234…`), 0 job mở, `incomplete` [], `review_required` []; DB cũ giữ ở `meshguard_before_restore_202611191133`; 34/34 + G3 **12/12** |
| Còn lại (F-5) | `records/extra-records.json` của A vẫn chứa 2 bản ghi tạo sau khi nâng — Headscale vẫn phát | như A, và DB vừa restore không còn bản ghi nào ⇒ ghi `[]` hoặc để lần ghi DNS đầu tiên sau khi nâng lại dọn (đã kiểm: file chỉ còn bản ghi mới) |

**Nâng lại sau B** (11:36:03–11:36:47): `migrate.sh` 19 → 26 **8 s**, Agent 4,1 s, app 7,6 s (`app.` 502 **4,5 s**), hai
reload 0,3 s; 34/34 (route Phase 4), conformance v10 PASS, `/key` 0 lỗi / 138 lượt. Bộ pre-migration của mỗi lần
(`…105045Z`, `…113614Z`) và `manual` sau restore đều có manifest ký, sha256 khớp.

## 7. Trình tự triển khai staging đề xuất

Lệnh đầy đủ (kiểm sau từng bước, hoàn tác A/B): **[deploy-backend.md mục o](../../operations/deploy-backend.md)**. Tóm tắt:

| # | Bước | Kiểm | Hoàn tác |
|---|---|---|---|
| 0 | Máy vận hành: workflow `images` xanh trên commit D ⇒ một commit pin api/worker/web/**agent** cùng tag; báo trước giờ reload edge | `python3 tools/test_render_app.py` không còn dòng INFO "chưa có [images.mg-web]" | revert commit pin |
| 1 | `~/mg` = `git archive` D; sao lưu `~/mg.bak-$TS`, `/root/compose.{app,agent,edge}.yaml.$TS`, `/root/Caddyfile.v8.$TS` | — | chép lại |
| 2 | Preflight chỉ đọc: 3 test render; 4 truy vấn (status membership/platform_users, FK 0020, job dở); sha policy đang chạy A/B = `applied_sha256` hiện hành | đúng như chú thích từng dòng | — |
| 3 | Render `compose.app.yaml`, `compose.agent.yaml` + diff | template 3→4 + web; agent chỉ image | — |
| 4 | **Cài compose app mới** → `migrate.sh` | `schema_version` 26, `current:true`, `OK`; ghi id bộ pre-migration | B |
| 5 | Agent mới `up -d --wait` | healthy, socket `660 0:20003`, supervisor gắn A/B | compose agent cũ + `up` |
| 6 | `$APP up -d --wait api worker web mail-bridge` | 3 healthcheck 200, web 200, log `worker wired` | A |
| 7 | Caddyfile v9 (render bằng tools của `f7ceb5d`), validate, reload; conformance bằng `tests/` của `f7ceb5d` | PASS; SPA trên `app.`/`admin.`; `/key` A/B qua VPS + LAN 200 | Caddyfile v8 + reload |
| 8 | **Chỉ khi P4-T08 đã lên**: v10 + conformance cây mới + V-07 client thật | PASS; link đăng ký ⇒ trang claim ⇒ `Running` | Caddyfile v9 + reload |
| 9 | Kiểm sau nâng (mục 5 ở trên, trên dữ liệu thật) + `current.md` | | |

Ước lượng cửa sổ trên staging: **10–15 phút** thao tác (gồm preflight, kiểm), gián đoạn API Portal **vài giây** lúc
recreate api, control plane tenant **không gián đoạn**; stream long-poll đóng **5 phút** sau reload, client tự nối lại.

## 8. Lỗi runbook/script phát hiện

| # | Lỗi | Ảnh hưởng | Sửa |
|---|---|---|---|
| F-1 | Dòng chú thích 1 của `infrastructure/host/mg-staging-firewall.nft` chứa chuỗi placeholder (`$` + `{MG_*}`), `mgenv.py render` giữ nguyên, `apply-firewall.sh` từ chối mọi bản render còn `${MG_` ⇒ lệnh của `current.md` §3 bước 4 **luôn** dừng "còn placeholder" (từ `9c38a77`, 2026-11-17) | dựng lại host / đổi firewall theo runbook bị chặn | chú thích viết lại; `tools/test_mgenv.py` render template bằng `staging.env` và kiểm đúng điều kiện của `apply-firewall.sh` (đỏ trên template cũ, xanh trên bản sửa) |
| F-2 | Cây từ `3498e00` chỉ render được Caddyfile **v10**, nhưng mục m/RUNBOOK v8→v9 bảo render từ cây đang triển khai; v10 đòi P4-T08 chưa có. Conformance của cây mới đòi v10 ⇒ FAIL trên edge v9 | không dừng được ở v9 theo runbook; hoặc lên v10 thiếu trang claim | deploy-backend m3/m4 + mục o bước 7, RUNBOOK v8→v9: render v9 và chạy conformance bằng cây `f7ceb5d`; v10 chỉ khi có P4-T08 |
| F-3 | deploy-backend m2 và RUNBOOK "Template v8 → v9" bước 0: "`migrate.sh` **trước**" rồi mới render compose. `migrate.sh` chạy job `migrate` của compose **đang cài** ⇒ migration của image cũ: báo `OK`, `current:true`, schema không đổi. api mới không tự kiểm schema khi khởi động ⇒ lỗi chỉ lộ khi route Phase 4 chạm bảng mới | triển khai "thành công" mà DB thiếu 0020–0026 | sửa thứ tự trong deploy-backend m2, RUNBOOK (cài compose → migrate → up), mục o bước 4 ghi kết quả mong đợi `schema_version` 26 |
| F-4 | Mục m/n không nói tới **Host Agent**: P4-T12 thêm `WriteDnsRecords` vào Agent; Agent cũ ⇒ `dns.records_write` `failed agent_refused` (bản ghi ở DB, không tới Headscale) | tính năng DNS của Portal hỏng âm thầm tới khi nâng Agent | mục o: pin `[images.mg-agent]` cùng lượt, bước 5 nâng Agent trước api/worker; RUNBOOK bước 0 |
| F-5 | Hoàn tác (A hoặc B) không xóa `records/extra-records.json` mà P4-T12 đã ghi; image cũ không biết file này | Headscale tiếp tục phát bản ghi DNS mà DB (sau B) không còn | mục o "Hoàn tác": ghi `[]` hoặc để lần ghi DNS đầu tiên sau khi nâng lại dọn (đã kiểm) |

Ghi nhận nhỏ (không sửa): `apply-firewall.sh`, timer `mg-obs-targets` cần systemd (host thật có); biến của tiến trình ghi đè
env file (`mgenv`) ⇒ sau khi sửa `staging.env` trong cùng shell phải `eval` lại `mgenv.py export` (đã gặp khi điền
recipient sau nghi thức khóa).

## 9. Chỉ kiểm được trên staging

- Chứng chỉ ACME DNS-01 thật (edge không đổi tên site ⇒ không xin chứng chỉ mới), DNS công khai `*.mesh`/`app.`/`auth.`,
  `external.py` từ Internet thật.
- VPS thật + WireGuard: diễn tập dùng HAProxy gateway v2 thật nhưng tunnel là network Docker.
- Thư thật qua Worker Cloudflare (diễn tập chặn bằng `.invalid`): thông báo mới của Phase 4 sẽ gửi thư thật tới địa chỉ
  đã xác minh khi sự kiện xảy ra.
- Dữ liệu thật của staging: kích thước DB (thời gian backup/migrate/restore), các tenant thử G3 đã xóa, SA thử
  `g3-sa1/g3-sa2`, `op-1/op-2` từng `disabled` tạm (hợp lệ với CHECK 0025) — preflight mục o bước 2 xác nhận.
- `policy.drift_check` trên A/B thật (adopt tay → backfill → restore AC-19): preflight so sha trước khi nâng.
- Client thật qua OPNsense NAT, điện thoại; V-07 (claim web-auth bằng client thật từng OS) — sau P4-T08.
- systemd trên host (`mg-host-firewall.service`, `mg-obs-targets.timer`), cgroup driver `systemd` (diễn tập: `cgroupfs`).

## 10. Chủ dự án cần duyệt

- [ ] Đợt Phase 4 lên staging theo deploy-backend mục o (migration `0020`–`0026` có backup trước; api/worker/web/agent
      mới) — **thông báo trước** giờ reload edge (stream đóng sau 5 phút, client tự nối lại).
- [ ] Dừng ở edge **v9** đợt này; v10 cùng đợt có P4-T08 (hoặc chấp nhận v10 ngay, với hệ quả: `tailscale up` không key ⇒
      link mở trang "không tìm thấy" của SPA; đăng ký bằng pre-auth key không ảnh hưởng).
- [ ] Hoàn tác được chọn khi có sự cố: A (giữ DB, vài giây) trước; B (restore, ~30 s API bảo trì) chỉ khi dữ liệu hỏng.
- Không cần: mở cổng, đổi DNS, đổi OPNsense, đổi VPS, sửa `staging.env`, secret mới.

## 11. Tài nguyên đã dọn (VM 110)

Container `dep4-host` (cả dockerd lồng và mọi container bên trong), `dep4-vps`, `dep4-stund`, `dep4-a1/a2/b1/b2`; network
`dep4-lan`, `dep4-tun`, `dep4-inet`; image `dep4-host:skel` và `haproxy` (do diễn tập kéo về); thư mục `~/dep4` (15 GB:
`/var/lib/docker` lồng, `/opt/meshguard` thử, CA thử, mật khẩu/TOTP thử, identity khôi phục thử). Kiểm sau dọn: 0
container/network/volume/image mang `dep4`. Không đụng tài nguyên `fup4b`, `mainm`, `mainv`; không prune.

## Phụ lục — script

[P4-deploy-rehearsal/](P4-deploy-rehearsal/) (chạy theo thứ tự): `host-up.sh` (VM con) → `images.sh` (nạp image pin) →
`build.sh` (build từ cây) → `p3.sh env base keys edge tenants idp app registry people idpboot realm agent obs backfill`
(dựng Phase 3) → `extra.sh fakedns override` → `outer.sh vps clients` → `api.py login|p3data` → G3 `tenant-c` (cây mới,
`--hostside-bin`) → `up.sh snap:pre sync preflight render migrate app agent edge9 edge10` (+ `probe.py run`) →
`api.py check p4|dns` → `rb.sh fast full` → `up.sh …` (nâng lại) → `down.sh`. `lib.sh` chứa biến chung (override CA thử
của diễn tập nằm ở `APP`/`OBS`/`EDGE`).
