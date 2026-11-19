# Triển khai backend (api, worker) lên host staging — P2-T16

> **File viết tay.** Runbook cho người điều phối: các bước **theo thứ tự** trên host staging (`mg-staging`), mỗi bước có lệnh kiểm và cách hoàn tác. Phần code và phép thử trên stack dev/CI: [bằng chứng P2-T16](../planning/evidence/P2-T16.md). Thiết kế: §14.2–§14.4, §16.2, §7.6, §8.2–§8.3 của [bản master](../planning/implementation-master-plan.md).
>
> **Duyệt:** bước có nhãn **[CHỦ DỰ ÁN DUYỆT]** chỉ chạy sau khi chủ dự án đồng ý rõ ràng cho đúng bước đó. Không bước nào in, ghi log hay đưa lên dòng lệnh một giá trị secret: secret sinh trên host (`app-secrets.sh`), đi vào lệnh **chỉ qua pipe** (stdin), credential của tài khoản mẫu chỉ nằm trong `config/secrets/staging/` trên máy vận hành.

## 0. Tổng quan và thứ tự

| # | Bước | Duyệt | Ảnh hưởng tới đang chạy |
|---|---|---|---|
| a | Chuẩn bị host: image pin, render `compose.app.yaml`, secret file | **[CHỦ DỰ ÁN DUYỆT]** (bắt đầu triển khai) | Không |
| b | DB: bootstrap (`mg_migrator`, `mg_backup`) → `mg-backup` sẵn sàng → backup pre-migration → migrate | **[CHỦ DỰ ÁN DUYỆT]** | PostgreSQL của nền tảng (chưa ai dùng) |
| c | IdP `mg-idp` — **đã chạy trên staging** (người điều phối, mục IdP của RUNBOOK): ở đây chỉ dùng nó | — | — |
| d | `api`, `worker` lên (project `mg-app`) | **[CHỦ DỰ ÁN DUYỆT]** | Không (chưa có route ở edge) |
| e | `register-platform-idp`, client secret `mg-portal`, adopt tenant A/B | **[CHỦ DỰ ÁN DUYỆT]** (expire key Phase 1 của A/B) | API key của A/B đổi; client Tailscale không ảnh hưởng |
| f | Tài khoản mẫu, `bootstrap-super-admin`, `seed-membership` | **[CHỦ DỰ ÁN DUYỆT]** (người nào là SA/TO/TA) | Không |
| g | `mg-backup` chạy theo lịch | — (đã duyệt cùng P2-T03a/T05b) | Không |
| h | Edge: template v5 (site `app.`/`admin.`/`auth.`) — **reload có lịch**; rồi IdP driver bootstrap + đăng nhập thử | **[CHỦ DỰ ÁN DUYỆT]** + thông báo trước | **Reload đóng mọi stream upgrade sau `stream_close_delay` (5 phút)** — client tự nối lại |
| i | DNS công khai `app.`/`auth.` + CAA, mở qua VPS | **[CHỦ DỰ ÁN DUYỆT] riêng** | `app.`/`auth.` public |
| j | Thu thập bằng chứng G2 | — | Không |
| k | Cập nhật sau G2 vòng 2 (OWASP ASVS): network `mg-idp`, image idp mới, `realm-update.sh`, migration `0008`, api/worker mới | **[CHỦ DỰ ÁN DUYỆT]** từng bước | Xem bảng của mục k |
| l | P3-T15 — kiểm soát quản trị IdP: api/worker mới (job `idp.audit_sync`, cổng console), `realm-update.sh` (`frontendUrl` của master, `view-events` của danh tính provisioning), Caddyfile **v8** | Ủy quyền Phase 3 (người điều phối) + **thông báo trước reload edge** | Xem bảng của mục l |
| m | P4-T01a — SPA sau edge: service `web` trong `mg-app`, Caddyfile **v9** (`app.`/`admin.` ngoài `/api/*` ⇒ `web:8080`) | **[CHỦ DỰ ÁN/NGƯỜI ĐIỀU PHỐI DUYỆT]** + **thông báo trước reload edge** | Xem mục m |
| n | P4-T07 — Caddyfile **v10**: `/register/<auth_id>` không `via=portal` ⇒ 302 tới trang claim của Portal; chỉ sau khi API claim (P4-T06) và trang `/enroll/claim` (P4-T08) đã chạy | **[CHỦ DỰ ÁN DUYỆT]** + **thông báo trước reload edge** | Xem mục n |
| o | Lô Phase 4 đầu tiên lên staging (`8840590` → `9736636`): migration `0020`–`0026`, api/worker/web/**agent** mới, Caddyfile v9 (v10 khi có P4-T08) — trình tự đã diễn tập trên VM 110 | **[CHỦ DỰ ÁN DUYỆT]** + **thông báo trước reload edge** | Xem mục o |

Lệch thứ tự so với danh sách của brief: **idp-bootstrap và đăng nhập thử nằm sau (h)** — worker chỉ tới được Admin API của Keycloak qua site `auth.` mới của edge, đăng nhập cần site `app.`/`admin.`. Adopt, client secret, bootstrap SA/seed (e, f) không cần edge mới.

Biến dùng xuyên suốt (đứng trong bản sao repo `~/mg`, đã đồng bộ commit cần triển khai bằng `git archive`):

```bash
cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)" && sudo -v
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
BK="sudo docker compose -p mg-backup -f /opt/meshguard/core/compose.backup.yaml"
```

## a. Chuẩn bị host

1. **Image** (máy người điều phối, trước khi lên host): workflow `images` xanh trên `main` cho commit cần triển khai ⇒ commit riêng ghi **cùng commit** vào `versions.lock`: `[images.mg-api]` (mới) và `[images.mg-worker]` (thay bản của nghi thức khóa), mỗi mục `image`, `tag` (SHA), `index` (digest GHCR), `user = "65532:65532"`; `[images.mg-backup]` nếu chưa pin (P2-T03a). `tools/render_app.py` từ chối khi hai mục khác `tag`.
2. **Render + kiểm**:

   ```bash
   python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app
   sudo install -o root -g root -m 0644 /tmp/mg-app/compose.app.yaml /opt/meshguard/core/compose.app.yaml
   $APP config -q && echo compose-ok
   grep -E 'MG_TRUSTED_PROXIES|ipv4_address|MG_EGRESS_DENY_CIDRS|image:' /opt/meshguard/core/compose.app.yaml
   ```

   Mong đợi: `MG_TRUSTED_PROXIES: 10.249.0.2`, worker `ipv4_address: 10.249.0.4`, dải bị chặn gồm `172.24.0.0/13,10.249.0.0/16,10.250.0.0/16,$MG_LAN_CIDR,$MG_TUNNEL_HOST_IPV4,$MG_TUNNEL_VPS_IPV4,$MG_PUBLIC_IPV4`, hai image theo digest.
3. **Secret file** (sinh trên host, không in): `sudo bash infrastructure/host/app-secrets.sh` — tạo `secrets/api/*` (`root:mg-sec-api 0440`), `secrets/worker/*` (`root:mg-sec-worker`), `secrets/app/db_audit_writer_password` (`root:mg-sec-app`), thư mục `secrets/migrate/` (`root:mg-sec-migrate 0750`: `mg_migrator` + **bản** mật khẩu 6 role đăng nhập — mỗi consumer một bản). Token listener admin (`secrets/app/edge_admin_token`), `secrets/backup/pg_backup_password`, keyring `secrets/kek-app` (`root:mg-sec-app 0750`), `secrets/kek-ops` (`root:mg-sec-worker 0750`) đã có (P1-T03, P2-T03a, P2-T04a).
4. **Kiểm quyền**: `sudo bash infrastructure/host/check-secrets.sh` — mọi dòng `PASS` (consumer đọc được, nhóm khác không). Keyring: `sudo stat -c '%a %U:%G %n' /opt/meshguard/secrets/kek-{app,ops} /opt/meshguard/secrets/kek-{app,ops}/*` ⇒ `750`/`440`, nhóm 20001/20003.
5. **Pull**: `$APP pull api worker` (theo digest).

Hoàn tác: `sudo rm /opt/meshguard/core/compose.app.yaml`; secret (chỉ trước bước b): `sudo rm -rf /opt/meshguard/secrets/{api,worker,migrate} /opt/meshguard/secrets/app/db_audit_writer_password`.

## b. Database: bootstrap, backup trước migration, migrate

1. **Bootstrap một lần** (superuser — `database/bootstrap/superuser.sql`, mật khẩu `mg_migrator` + `mg_backup` từ file, verifier SCRAM tính phía client):

   ```bash
   $APP --profile bootstrap run --rm -T db-bootstrap
   ```

   Mong đợi một dòng JSON `{"mode":"bootstrap",…,"passwords_set":["mg_migrator","mg_backup"],…}`, exit 0. Chạy lại vô hại (cũng là cách xoay hai mật khẩu đó).
2. **`mg-backup` sẵn sàng** cho trigger trước migration: [backup-restore.md](backup-restore.md) mục 4 bước 1, 2, 4, 5 (`render_backup.py`, `check` ba dịch vụ). Bước 3 của mục đó (mật khẩu `mg_backup`) chính là bước b1 ở trên. Chưa cần `up -d` (bước g).
3. **Migrate** (mỗi lần nâng cấp đều qua script này):

   ```bash
   sudo bash infrastructure/host/migrate.sh
   ```

   Script chạy `pg-backup once --label pre-migration` của `mg-backup` **trước**, dừng nếu exit ≠ 0 (không migrate), rồi `--profile migrate run --rm -T migrate` (`mg_migrator`: goose + seed RBAC + River, đặt mật khẩu 6 role đăng nhập từ `secrets/migrate/`, kiểm). Mong đợi `{"mode":"up",…,"state":{"schema_version":6,"latest_migration":6,…,"partition_grant_violations":[]},…,"current":true}` và `OK: backup pre-migration + migrate xong`. Ghi id bộ backup pre-migration (`sudo ls /opt/meshguard/backups/postgres`) vào bằng chứng.
4. **Kiểm lại bất cứ lúc nào**: `$APP --profile migrate run --rm -T migrate migrate status` (chỉ đọc; exit 0 = đúng bản này).

Hoàn tác: migration chỉ tiến; lần đầu (DB rỗng) — `sudo docker exec -i mg-core-postgres-1 psql -U postgres -c 'DROP DATABASE meshguard' -c 'CREATE DATABASE meshguard'` rồi làm lại b1; lần sau — restore bộ pre-migration ([backup-restore.md](backup-restore.md) mục 6.3) + image trước.

## c. IdP (`mg-idp`) — tiền điều kiện

`mg-idp` (Keycloak 26.8.2, realm `platform`, `tenant-a`, `tenant-b`) **đã chạy trên staging** do người điều phối dựng — xem mục IdP của [RUNBOOK](../../infrastructure/host/RUNBOOK.md). Backend chỉ cần: (1) container `idp` với alias `idp` trên network edge dùng để tới nó (edge → `idp:8080`; từ G2 vòng 2 là `mg-idp`, chỉ edge + idp — mục k), (2) client `mg-portal` của mỗi realm (secret đưa vào SecretStore ở bước e), (3) admin khởi tạo của realm `master` cho **một** lần idp-bootstrap (bước h), (4) site `auth.` của edge (bước h). Kiểm: `sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml ps` ⇒ `idp` healthy.

## d. api và worker

```bash
$APP up -d --wait --wait-timeout 180 api worker
$APP ps                                                                   # healthy cả hai
sudo docker exec mg-app-api-1 /usr/local/bin/meshguard healthcheck        # HTTP 200 {"failing":[],"ready":true}
sudo docker exec mg-app-worker-1 /usr/local/bin/meshguard healthcheck
$APP logs api worker | grep -E '"keyring loaded"|"api wired"|"worker wired"'
```

Mong đợi: `keyring loaded` với `kcv` **66c83426** (kek-app, cả hai) và **aabd042a** (kek-ops, chỉ worker) — đúng KCV của nghi thức P2-T04a; `worker wired` báo `idp_drivers:["external","keycloak"]`, `keycloak_provisioner_bootstrapped:false` (bình thường tới bước h). `/readyz` gồm `postgres`, `secretstore` (giải mã thử một DEK mỗi phạm vi/KEK), `edge_admin` (listener admin của edge trả 404 khi token đúng). api chỉ phục vụ request đến từ đúng IP của edge (`10.249.0.2`) — container khác gọi thẳng ⇒ 403.

Hoàn tác: `$APP stop api worker` (giữ trạng thái) hoặc `$APP down` (không xóa gì của PostgreSQL).

## e. IdP của nền tảng, client secret, adopt tenant A/B

Theo mục "Đưa tenant A/B vào registry — `meshguard admin adopt-instance`" của [RUNBOOK](../../infrastructure/host/RUNBOOK.md), **thay** `CORE=…` bằng `CORE="$APP"` (service `api` của project `mg-app`; lệnh admin đọc thêm `MG_DB_AUDIT_WRITER_PASSWORD_FILE` từ service — sự kiện audit của adopt/IdP nay **vào `audit_events`**, `actor_type=system`, không còn ra stderr). Tóm tắt:

```bash
CORE="$APP"
$CORE run --rm --no-deps -T -e "MG_IDP_ID_PLATFORM=$MG_IDP_ID_PLATFORM" api admin register-platform-idp
# adopt: S=tenant-a rồi tenant-b — đúng khối lệnh của RUNBOOK (API key mới đi thẳng từ `headscale apikeys create` qua pipe)
# client secret mg-portal của từng realm, chỉ qua pipe (script từ chối stdout là terminal hoặc file):
sudo bash infrastructure/host/idp-client-secret.sh platform | $CORE run --rm --no-deps -T api admin set-idp-client-secret "$MG_IDP_ID_PLATFORM"
sudo bash infrastructure/host/idp-client-secret.sh tenant-a | $CORE run --rm --no-deps -T api admin set-idp-client-secret "$MG_IDP_ID_TENANT_A"
sudo bash infrastructure/host/idp-client-secret.sh tenant-b | $CORE run --rm --no-deps -T api admin set-idp-client-secret "$MG_IDP_ID_TENANT_B"
```

Kiểm: như mục "Kiểm" của RUNBOOK; thêm `sudo docker exec mg-core-postgres-1 psql -U postgres -d meshguard -c "SELECT action, actor_type, count(*) FROM audit_events GROUP BY 1,2 ORDER BY 1"` ⇒ `platform.instance.adopt.requested/succeeded` = 2/2, `platform.idp.register`, `platform.idp.client_secret.update` = 3, tất cả `system`. Hoàn tác: mục "Hoàn tác" của RUNBOOK (chỉ trước go-live).

## f. Tài khoản mẫu, Super Admin, TO/TA

1. Tài khoản trong realm: [infrastructure/idp/create-user.sh](../../infrastructure/idp/create-user.sh) (mục IdP của RUNBOOK). Mật khẩu (không tạm — chủ dự án giữ trong kho secret của họ) sinh **trên máy vận hành** vào `config/secrets/staging/idp-accounts/<realm>-<username>.txt` (git bỏ qua) và đi tới script qua stdin của `ssh` — không in, không nằm trên dòng lệnh. TOTP do chính người dùng đăng ký ở lần đăng nhập đầu (CONFIGURE_TOTP) — file không chứa seed TOTP.
2. `sub` của từng người: `sudo bash infrastructure/idp/user-id.sh <realm> <username>`.
3. Super Admin (D-11: hai người) và TO/TA của A/B: mục "Super Admin đầu tiên và TO/TA…" của [RUNBOOK](../../infrastructure/host/RUNBOOK.md) với `CORE="$APP"`. Ghi `sub`, id, request id (không secret) vào `current.md`.

Hoàn tác: mục "Hoàn tác" tương ứng của RUNBOOK; user mẫu xóa ở realm.

## g. `mg-backup` theo lịch

`$BK up -d` rồi [backup-restore.md](backup-restore.md) mục 4 bước 6 (`status.json` của `postgres`, `idp`, `edge`: `last_attempt.ok = true`). Postgres **không** chạy bù vì bộ pre-migration của bước b đã tạo `status.json`, mà bộ đó chụp DB lúc còn rỗng. Vì vậy chạy ngay một bộ sau khi registry có dữ liệu: `$BK run --rm -T pg-backup once --label manual` (lần đầu trên staging 2026-11-17: `postgres-20261117T103025Z-manual`). Hoàn tác: `$BK down`.

## h. Edge với site `app.`/`admin.`/`auth.` (template v5) — reload có lịch

1. **Thông báo trước** giờ reload: mọi stream upgrade (control `/ts2021`, DERP) đóng sau `stream_close_delay 5m`; client tự nối lại.
2. Render + so sánh (compose của edge không đổi ⇒ chỉ reload, không recreate):

   ```bash
   python3 tools/render_edge.py infrastructure/environments/staging/edge.json /tmp/edge
   diff <(sudo cat /opt/meshguard/core/compose.edge.yaml) /tmp/edge/compose.edge.yaml | grep -v '^[<>] #' || true   # chỉ khác dòng chú thích
   sudo cp -a /opt/meshguard/core/caddy/Caddyfile /root/Caddyfile.v4.$(date -u +%Y%m%dT%H%M%SZ)
   sudo install -o root -g root -m 0644 /tmp/edge/caddy/Caddyfile /opt/meshguard/core/caddy/Caddyfile
   sudo docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
   sudo docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
   ```

   Edge xin 3 chứng chỉ mới (`app.`, `admin.`, `auth.`) qua DNS-01 — theo dõi `sudo docker logs mg-edge 2>&1 | grep -i certificate`.
3. **Kiểm ngay** (đúng như mục "Đổi cấu hình edge" của RUNBOOK) — `/key?v=113` qua VPS và LAN-direct 200; `sudo bash tests/security/edge/run_staging.sh "mesh.$MG_BASE_DOMAIN" "$MG_PUBLIC_IPV4" tenant-a tenant-b` (nay gồm nhóm `platform`: `app.` chỉ `/api/*`, header bảo mật, Admin API/realm master/console của `auth.` ⇒ 404 từ nguồn không phải worker, `admin.` bị đóng với nguồn ngoài `MG_LAN_CIDR`; `tunnel-reject` với SNI `admin.`); IT-14 hai chế độ; `tests/security/edge/external.py` từ máy ngoài.
4. **IdP driver bootstrap** (danh tính provisioning `mg-provisioner` ở realm master; mật khẩu break-glass đi thẳng từ file của host qua pipe vào **container worker đang chạy** — chỉ IP tĩnh của worker tới được `/admin/realms` qua edge):

   ```bash
   U=$(sudo sed -n 's/^bootstrap-admin-username=//p' /opt/meshguard/secrets/idp/keycloak.conf)
   sudo sed -n 's/^bootstrap-admin-password=//p' /opt/meshguard/secrets/idp/keycloak.conf \
     | $APP exec -T worker /usr/local/bin/meshguard admin idp-bootstrap --admin-username "$U" \
         --adopt-realm tenant-a --adopt-realm tenant-b
   $APP restart worker && $APP logs --since 2m worker | grep '"keycloak_provisioner_bootstrapped":true'
   ```

   Mong đợi `secret: mgsec://platform/idp.keycloak.provisioner#1 (platform_ops — worker only)` và `OK`. Bản mật khẩu break-glass lưu tạm trong SecretStore bị hủy ngay sau lệnh (thành công hay không). Chạy lại = sửa/xoay.
5. **Đăng nhập thử từ LAN** (trước DNS công khai: máy vận hành trỏ `app.`/`admin.`/`auth.$MG_BASE_DOMAIN` về `$MG_LAN_IPV4` bằng DNS nội bộ hoặc file hosts): TO của A tại `https://app.$MG_BASE_DOMAIN/api/v1/auth/login?scope=tenant&tenant=tenant-a`, SA tại `https://admin.$MG_BASE_DOMAIN/api/v1/auth/login?scope=platform`; sau đó `GET /api/v1/auth/session`, `/api/v1/tenants`, `/api/v1/platform/health` (mục "Kiểm" của P2-T11a).

Hoàn tác: cài lại `/root/Caddyfile.v4.*` rồi reload (site nền tảng biến mất; tenant không ảnh hưởng ngoài lần reload).

## i. DNS công khai `app.`/`auth.` **[CHỦ DỰ ÁN DUYỆT] riêng**

VPS (`l4proxy`) đã chuyển mọi TCP 443/80 qua tunnel tới listener tunnel-facing của edge: không đổi gì ở VPS. Chỉ thêm bản ghi:

```bash
sudo python3 infrastructure/gateway/cf_dns.py apply infrastructure/environments/staging/dns-platform.json
```

(`A app.` và `A auth.` → `MG_PUBLIC_IPV4`; CAA `issue` Let's Encrypt + `validationmethods=dns-01` + `accounturi` cho `app.`, `auth.`, `admin.`; **không** có bản ghi công khai cho `admin.` — §15.4.) Kiểm từ máy ngoài: `https://app.$MG_BASE_DOMAIN/api/v1/auth/session` ⇒ 401, `https://auth.$MG_BASE_DOMAIN/realms/tenant-a/.well-known/openid-configuration` ⇒ 200, `/admin/` ⇒ 404; `admin.` không phân giải. Hoàn tác: `sudo python3 infrastructure/gateway/cf_dns.py delete infrastructure/environments/staging/dns-platform.json`.

## j. Bằng chứng G2

Ghi vào `docs/planning/evidence/P2-T16.md` (mục "Triển khai lên host") và `current.md`: digest đã pin; output JSON của `db-bootstrap`/`migrate` + id bộ pre-migration; `check-secrets.sh`; `/readyz` + KCV trong log; output adopt/register/client secret (chỉ reference, prefix); id SA/membership (sub, request id); `run_staging.sh` (gồm `platform`), IT-14, `external.py`; kết quả đăng nhập thử; `status.json` của `mg-backup`; truy vấn `audit_events`. Rà soát G2 (người không viết code, OWASP ASVS — §19) dùng bảng "Wiring hazards G2" của bằng chứng P2-T16 làm danh mục kiểm.

## k. Cập nhật sau G2 vòng 2

Áp các bản sửa của rà soát G2 vòng 2 (OWASP ASVS — [bằng chứng G2](../planning/evidence/G2-security-review.md), mục "Sửa sau vòng 2") lên staging đang chạy. **Thứ tự là bắt buộc**: image idp mới phải chạy trước `realm-update.sh` (realm mới tham chiếu file danh sách mật khẩu chỉ image mới có), realm phải có mapper `amr` trước api mới (api mới từ chối đăng nhập platform không có bằng chứng MFA), migration `0008` trước api mới (api mới đọc/ghi cột `sessions.id_token_hint_enc`; api cũ chạy được trên schema mới — expand-only).

| # | Bước | Duyệt | Ảnh hưởng tới đang chạy |
|---|---|---|---|
| k1 | Pin image, đồng bộ `~/mg` | — | Không |
| k2 | Network `mg-idp`; edge gắn vào (không restart) + Caddyfile v7 (reload) | **[CHỦ DỰ ÁN DUYỆT]** + thông báo trước | Reload: stream upgrade đóng sau 5 phút, client tự nối lại |
| k3 | idp: image mới, chỉ trên `mg-idp` (recreate) | **[CHỦ DỰ ÁN DUYỆT]** | `auth.` không phục vụ ~1–2 phút; phiên SSO Keycloak còn (DB giữ nguyên) |
| k4 | `realm-update.sh` (realm platform/tenant-a/tenant-b + gia cố master) | **[CHỦ DỰ ÁN DUYỆT]** | Mật khẩu đặt mới phải qua danh sách cấm; đổi credential ở account console phải xác thực lại |
| k5 | Migration `0008` qua `migrate.sh` (backup pre-migration trước) | **[CHỦ DỰ ÁN DUYỆT]** | Không (expand-only) |
| k6 | api, worker image mới | **[CHỦ DỰ ÁN DUYỆT]** | Đăng xuất chuyển tới Keycloak; đăng nhập platform luôn hỏi mật khẩu + OTP |
| k7 | Kiểm (+ chạy lại các kiểm S-4…S-7, S-13 của vòng 2) | — | Không |

**k1. Pin + đồng bộ** (máy người điều phối): workflow `images` xanh trên `main` cho commit gộp ⇒ commit riêng ghi vào `versions.lock`: `[images.mg-idp]` (image mới — có `/opt/keycloak/mg/password-blacklists/mg-passwords-v1.txt`), `[images.mg-api]`, `[images.mg-worker]` (**cùng commit**), `[images.mg-backup]` nếu workflow build lại. `[images.mg-edge]` không đổi (chỉ Caddyfile đổi). Trên host: `~/mg` = `git archive` của commit đó; `cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)" && sudo -v`; `IDP="sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml"`, `APP` như mục 0. Kiểm: `python3 tools/test_render_idp.py && python3 tools/test_render_edge.py` ⇒ exit 0.

**k2. Network `mg-idp` + edge** (trước k3: sau k3 edge chỉ tới được idp qua `mg-idp`):

```bash
sudo bash infrastructure/host/networks.sh                                   # "tạo mg-idp 10.249.7.0/24 (internal)"
sudo docker network connect --ip 10.249.7.2 mg-idp mg-edge                  # gắn khi đang chạy — không restart
python3 tools/render_edge.py infrastructure/environments/staging/edge.json /tmp/edge
sudo cp -a /opt/meshguard/core/compose.edge.yaml /root/compose.edge.yaml.v6.$(date -u +%Y%m%dT%H%M%SZ)
sudo cp -a /opt/meshguard/core/caddy/Caddyfile /root/Caddyfile.v6.$(date -u +%Y%m%dT%H%M%SZ)
sudo install -o root -g root -m 0644 /tmp/edge/compose.edge.yaml /opt/meshguard/core/compose.edge.yaml   # cho lần recreate sau
sudo install -o root -g root -m 0644 /tmp/edge/caddy/Caddyfile /opt/meshguard/core/caddy/Caddyfile
sudo docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
```

Kiểm: `sudo docker inspect -f '{{json .NetworkSettings.Networks}}' mg-edge | python3 -m json.tool | grep -A3 '"mg-idp"'` ⇒ `10.249.7.2`; diff Caddyfile cũ/mới chỉ gồm `template_version 7`, chú thích và khối `format filter … delete id_token_hint` của `(access_log)`; `/key?v=113` qua VPS và LAN-direct 200 như mục "Đổi cấu hình edge" của RUNBOOK. Hoàn tác: cài lại `/root/Caddyfile.v6.*` + reload; `sudo docker network disconnect mg-idp mg-edge` (chỉ sau khi k3 đã hoàn tác).

**k3. idp: image mới, chỉ trên `mg-idp`** (realm trong `idp-db` giữ nguyên; `--import-realm` bỏ qua realm đã có):

```bash
python3 tools/render_idp.py infrastructure/environments/staging/staging.env /tmp/mg-idp     # image = [images.mg-idp] mới
sudo cp -a /opt/meshguard/core/compose.idp.yaml /root/compose.idp.yaml.v1.$(date -u +%Y%m%dT%H%M%SZ)
sudo tar -C /opt/meshguard/core/idp -czf /root/idp-realms.v1.$(date -u +%Y%m%dT%H%M%SZ).tgz realms
sudo install -o root -g root -m 0644 /tmp/mg-idp/compose.idp.yaml /opt/meshguard/core/compose.idp.yaml
sudo install -o root -g root -m 0644 /tmp/mg-idp/idp/realms/*.json /opt/meshguard/core/idp/realms/
$IDP config --quiet && $IDP pull idp && $IDP up -d --wait --wait-timeout 300 idp
```

Kiểm: `$IDP ps` ⇒ `idp` healthy; `sudo docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' mg-idp` ⇒ đúng `mg-edge` và `mg-idp-idp-1`; `idp` không còn trên `mg-edge`; `KC_PROXY_TRUSTED_ADDRESSES=10.249.7.2` trong `sudo docker inspect mg-idp-idp-1`; `https://auth.$MG_BASE_DOMAIN/realms/tenant-a/.well-known/openid-configuration` (LAN) ⇒ 200, `issuer` đúng; từ container khác trên `mg-edge`: `sudo docker run --rm --network mg-edge <image alpine của versions.lock> wget -q -T 5 -O- http://idp:8080/realms/master` ⇒ thất bại (A-8). Hoàn tác: cài lại `/root/compose.idp.yaml.v1.*` (image cũ `c983f678`, trên `mg-edge`) + `$IDP up -d idp` — **chỉ sau khi đã gỡ `passwordBlacklist` khỏi policy các realm** (k4 hoàn tác), nếu không Keycloak cũ không tìm thấy file danh sách khi đặt mật khẩu.

**k4. Realm đang chạy + realm master:**

```bash
sudo bash infrastructure/idp/realm-update.sh --check     # in diff trước → sau, exit 3 = có thay đổi chờ áp, không ghi gì
sudo bash infrastructure/idp/realm-update.sh 2>&1 | sudo tee /root/realm-update.$(date -u +%Y%m%dT%H%M%SZ).log
sudo bash infrastructure/idp/realm-update.sh --check     # exit 0: "0 thay đổi" mọi realm
```

Mong đợi lần áp: mỗi realm `passwordPolicy` (+ `passwordBlacklist(mg-passwords-v1.txt)`), `attributes.meshguard.template` (`idp-realm-v2`), `mg-portal.post.logout.redirect.uris` (`+` → `https://app.`/`admin.$MG_BASE_DOMAIN/`), `mg-portal.protocolMappers` (+ `amr`), hai `authenticatorConfig` (`mg-amr-pwd`, `mg-amr-otp`), 5 `requiredAction.*.config` (`max_auth_age` `0`); realm `master` 7 khóa (brute force bật, event bật, policy); rồi `check_realm trên bản export của Keycloak — đạt` cho 3 realm và `OK`. Log không chứa secret (chỉ các khóa trên). Mật khẩu hiện có **không** bị kiểm lại: 6 tài khoản mẫu (24 ký tự ngẫu nhiên) không bị ảnh hưởng; danh sách chỉ áp khi đặt/đổi mật khẩu. Hoàn tác (giá trị cũ nằm trong log đã lưu): với từng realm, kcadm **trong** container như `user-id.sh` — ví dụ policy:

```bash
sudo docker exec -i mg-idp-idp-1 bash -s -- tenant-a <<'IN'
set -euo pipefail; cfg=$(mktemp /tmp/kcadm.XXXXXX); trap 'rm -f "$cfg"' EXIT; conf=/run/secrets/keycloak.conf
KC_CLI_PASSWORD=$(sed -n 's/^bootstrap-admin-password=//p' "$conf") /opt/keycloak/bin/kcadm.sh config credentials \
  --config "$cfg" --server http://localhost:8080 --realm master --user "$(sed -n 's/^bootstrap-admin-username=//p' "$conf")" >/dev/null
/opt/keycloak/bin/kcadm.sh update "realms/$1" --config "$cfg" \
  -s 'passwordPolicy=length(12) and maxLength(128) and notUsername and notEmail and passwordHistory(5)'
IN
```

(mapper `amr`, `authenticatorConfig`, `max_auth_age`, khóa của master: để nguyên khi hoàn tác api — chúng không làm hỏng api cũ; gỡ mapper `amr` của realm `platform` sẽ làm api **mới** từ chối mọi đăng nhập platform.)

**k5. Migration `0008`** (mục b bước 3 — luôn qua `migrate.sh`, image migrate = `[images.mg-api]` mới):

```bash
sudo bash infrastructure/host/migrate.sh
```

Mong đợi `"schema_version":8,"latest_migration":8`, `OK: backup pre-migration + migrate xong`; ghi id bộ pre-migration vào bằng chứng. `0008` chỉ thêm cột NULL `sessions.id_token_hint_enc` (không ghi lại hàng). Hoàn tác: forward-only — api/worker cũ chạy được trên schema 8; về schema 7 chỉ bằng restore bộ pre-migration ([backup-restore.md](backup-restore.md) mục 6.3) — không cần cho hoàn tác thường.

**k6. api, worker:** `python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app` → cài như mục a bước 2 → `$APP up -d --wait --wait-timeout 180 api worker` → kiểm như mục d. Hoàn tác: pin lại digest `03509d3` của `[images.mg-api]`/`[images.mg-worker]`, render, `$APP up -d api worker`.

**k7. Kiểm sau triển khai** (tài khoản thử, không dùng tài khoản thật của người khác):

1. **A-1** — đăng nhập TO của A trên `app.` (mật khẩu + OTP), `POST /api/v1/auth/logout` (CSRF) ⇒ `200 {"redirect_to": "https://auth.…/realms/tenant-a/protocol/openid-connect/logout?client_id=mg-portal&id_token_hint=…&post_logout_redirect_uri=https%3A%2F%2Fapp.…%2F"}`; trình duyệt tới đó ⇒ Keycloak 302 về `https://app.$MG_BASE_DOMAIN/`; `GET /api/v1/auth/login?scope=tenant&tenant=tenant-a` ⇒ Keycloak **hiện form mật khẩu** (S-5 lặp lại phải đổi kết quả). Trên `admin.`: URL tới Keycloak luôn có `prompt=login`. `sudo grep -c id_token_hint= /opt/meshguard/logs/edge/access.log` ⇒ 0.
2. **A-6** — `psql … -c "SELECT origin, acr, amr FROM sessions WHERE revoked_at IS NULL ORDER BY created_at DESC LIMIT 5"` ⇒ phiên `admin` có `amr` `{pwd,otp}`.
3. **A-3** — đặt mật khẩu `password1234` cho tài khoản thử (Admin API/console) ⇒ bị từ chối (`invalidPasswordBlacklistedMessage`).
4. **A-4** — account console `https://auth.$MG_BASE_DOMAIN/realms/tenant-a/account` → đổi mật khẩu ⇒ hỏi lại mật khẩu + OTP trước form mật khẩu mới (S-13 lặp lại phải đổi kết quả).
5. **A-2** — tài khoản thử đăng nhập, khóa ở Keycloak, `revoke-sessions` theo mục "Một người rời đi…" của RUNBOOK ⇒ cookie cũ `GET /api/v1/auth/session` ⇒ 401; `enable-identity` để trả lại.
6. **A-8** — `sudo bash infrastructure/idp/realm-update.sh --check` ⇒ exit 0; `master`: `bruteForceProtected=true` (dòng `realm master: 0 thay đổi (đã gia cố)`).

Ghi kết quả vào bằng chứng G2 (mục "Sửa sau vòng 2" — phần staging) và `current.md` (image đã pin, network `mg-idp`, id bộ pre-migration, log `realm-update`).

## l. P3-T15 — kiểm soát quản trị IdP (console Keycloak sau 2P, `idp.audit_sync`)

Không migration (bảng/quyền của 0001/0002/0004/0009 đủ), không đổi image idp hay edge (chỉ Caddyfile). **Thứ tự bắt buộc**: api mới (có cổng `GET /internal/edge/idp-console`) trước Caddyfile v8 (v8 gửi mọi request console tới cổng đó — api cũ trả 404 ⇒ console đóng, đúng chiều an toàn nhưng không dùng được); `realm-update.sh` trước khi dùng console (console của realm master chỉ chạy được ở `admin.` khi `frontendUrl` = `https://admin.<domain>`). Bằng chứng: [P3-T15](../planning/evidence/P3-T15.md).

| # | Bước | Ảnh hưởng tới đang chạy |
|---|---|---|
| l1 | Pin `[images.mg-api]`/`[images.mg-worker]` của commit gộp (workflow `images` xanh), đồng bộ `~/mg` | Không |
| l2 | api, worker image mới | Không (worker chạy thêm job `idp.audit_sync` mỗi phút; lần đầu đọc 30 ngày event của Keycloak) |
| l3 | `realm-update.sh` (`--check` trước): realm `master` `attributes.frontendUrl`, `view-events` của `mg-provisioner` trên `master-realm` + `platform-realm` | Token master phát trước đó bị Admin API từ chối một lần (driver tự lấy token mới); console chỉ còn hợp lệ ở `admin.` |
| l4 | Caddyfile **v7 → v8** (`caddy validate` rồi reload) | **Reload** — báo trước: stream upgrade đóng sau `stream_close_delay` (5 phút), client tự nối lại |
| l5 | Kiểm | Không — lưu ý: mọi đăng nhập realm master (kể cả kcadm của `realm-update.sh`) sinh `security_event` + email cảnh báo, đúng thiết kế |

**l1–l2.** Như mục k6: `python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app` → cài `compose.app.yaml` (lưu bản cũ vào `/root/compose.app.yaml.<ts>`) → `$APP up -d --wait --wait-timeout 180 api worker`. Kiểm: `$APP logs --since 5m worker | grep -c '"job":"idp.audit_sync"'` > 0 sau tối đa 11 phút (lần chạy đầu trễ ngẫu nhiên ≤ 10 phút, sau đó mỗi phút); chạy một lượt ngay: `$APP exec -T worker /usr/local/bin/meshguard admin idp-audit-sync` ⇒ `realms <1 + số IdP keycloak>, imported N` + `OK` (exit 0; exit 3 + dòng `NOT READ` trước l3 là bình thường cho `master`/`platform` — chưa có `view-events`). Hoàn tác: pin lại digest trước đó, render, `$APP up -d api worker` (job cũ không có; con trỏ `idp.audit_sync.*` trong `system_settings` vô hại).

**l3.**

```bash
sudo bash infrastructure/idp/realm-update.sh --check     # mong đợi: realm platform/tenant-* 0 thay đổi; master 1 (attributes.frontendUrl);
                                                         # danh tính provisioning mg-provisioner: 2 thay đổi (master-realm, platform-realm)
sudo bash infrastructure/idp/realm-update.sh 2>&1 | sudo tee /root/realm-update.$(date -u +%Y%m%dT%H%M%SZ).log
sudo bash infrastructure/idp/realm-update.sh --check     # exit 0
$APP exec -T worker /usr/local/bin/meshguard admin idp-audit-sync   # exit 0: mọi realm đọc được
```

Không cần chạy lại `idp-bootstrap` (Bootstrap mới giữ đúng các role này nếu chạy lại; với `--audit-realm platform` thì tự cấp). Hoàn tác (giá trị cũ trong log): kcadm **trong** container như mục k4 — `update realms/master -s 'attributes.frontendUrl='` và `remove-roles -r master --uusername service-account-mg-provisioner --cclientid master-realm --rolename view-events` (tương tự `platform-realm`); để nguyên cũng không hại gì khi hoàn tác api/worker.

**l4.** Như mục k2 (không đổi network):

```bash
python3 tools/render_edge.py infrastructure/environments/staging/edge.json /tmp/edge
sudo cp -a /opt/meshguard/core/caddy/Caddyfile /root/Caddyfile.v7.$(date -u +%Y%m%dT%H%M%SZ)
sudo cp -a /opt/meshguard/core/compose.edge.yaml /root/compose.edge.yaml.v7.$(date -u +%Y%m%dT%H%M%SZ)
diff /opt/meshguard/core/caddy/Caddyfile /tmp/edge/caddy/Caddyfile   # chỉ: template_version 8, chú thích, (portal_headers) có đối số,
                                                                    # app.: import portal_headers *, admin.: @portal/@idp_console/
                                                                    # @idp_impersonation + route @idp_console {forward_auth…}, auth.: @idp_impersonation
sudo install -o root -g root -m 0644 /tmp/edge/compose.edge.yaml /opt/meshguard/core/compose.edge.yaml
sudo install -o root -g root -m 0644 /tmp/edge/caddy/Caddyfile /opt/meshguard/core/caddy/Caddyfile
sudo docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
```

Hoàn tác: cài lại `/root/Caddyfile.v7.*` (+ compose) rồi `validate` + `reload` — console trở về trạng thái "không phục vụ ở đâu" của v7.

**l5. Kiểm** (từ máy trong `admin_allow`, không dùng tài khoản thật của người khác):

1. Không phiên: `curl -s -o /dev/null -w '%{http_code}' --resolve admin.$MG_BASE_DOMAIN:443:$MG_LAN_IPV4 https://admin.$MG_BASE_DOMAIN/admin/master/console/` ⇒ `401`; cùng lệnh với `auth.` ⇒ `404`; `https://auth.$MG_BASE_DOMAIN/realms/master/.well-known/openid-configuration` ⇒ `404`.
2. Super Admin có phiên Platform Console nhưng chưa có phiên console ⇒ `403`; `psql … -c "SELECT details->>'reason', count(*) FROM audit_events WHERE action='idp.console.access' GROUP BY 1"`.
3. (Tùy chủ dự án — cần hai Super Admin và tài khoản break-glass của master) quy trình "Console quản trị Keycloak" của RUNBOOK; mong đợi console tải được, `security_event` `idp.console_login` + email.
4. `/key?v=113` của A/B/C qua VPS và LAN-direct ⇒ 200 (edge không đổi gì phía tenant); conformance của P1-T17 (admin. không có qua VPS) ⇒ PASS.
5. `psql … -c "SELECT action, count(*) FROM audit_events WHERE action LIKE 'idp.%' GROUP BY 1 ORDER BY 1"` — các sự kiện quản trị IdP từ lúc dựng (tạo user mẫu, đặt mật khẩu, client secret…) đã vào audit của tenant A/B và của nền tảng; Owner A/B nhận email `idp.admin_change` tương ứng (đúng: mọi thao tác quản trị trực tiếp trước đây giờ hiện cho tenant).

Ghi vào `current.md` (digest api/worker, log `realm-update`, giờ reload edge v8) và bằng chứng P3-T15 (mục staging).

## m. P4-T01a — SPA sau edge (service `web`, Caddyfile v9)

Không migration của riêng task này, không đổi image edge hay compose của edge (chỉ Caddyfile ⇒ **reload**, §14.6 (a)). **Thứ tự bắt buộc**: `web` chạy trước Caddyfile v9 (v9 không có `web` ⇒ `app.`/`admin.` trả 503 tĩnh của edge — đúng chiều an toàn nhưng Portal không dùng được). Bằng chứng và thiết kế: [P4-T01a](../planning/evidence/P4-T01a.md); lệnh chi tiết: RUNBOOK mục "Template v8 → v9".

| # | Bước | Ảnh hưởng tới đang chạy |
|---|---|---|
| m1 | Pin `[images.mg-api]`, `[images.mg-worker]`, `[images.mg-web]` của **cùng** commit gộp (workflow `images` xanh — job `web` gồm khối kiểm image), đồng bộ `~/mg` | Không |
| m2 | Render **và cài** `compose.app.yaml` (template 4) **trước**, rồi có migration mới thì `migrate.sh` (mục b — job `migrate` dùng image api của file **đang cài**: chạy trước khi cài là chạy migration của image cũ, báo `OK`/`current:true` mà schema không đổi — diễn tập P4, F-3), rồi `$APP up -d --wait api worker web` | api/worker recreate nếu đổi image (như k6/l2; đo được ~2 s 502 trên `app.`); `web` mới — chưa có route |
| m3 | Caddyfile **v8 → v9**: render, `diff` compose (chỉ dòng `template_version`), sao lưu, cài, `caddy validate`, reload. Cây từ `3498e00` (P4-T07) trở đi chỉ render được **v10**: muốn dừng ở v9 thì render bằng `tools/render_edge.py` của `git archive f7ceb5d` (mục o bước 6) | **Reload** — báo trước: stream upgrade đóng sau `stream_close_delay` (5 phút), client tự nối lại |
| m4 | Kiểm: `app.`/`admin.` trả SPA (`/`, deep link), một CSP, `/api/v1/auth/session` 401, `/healthz`/`/metrics`/`/internal/*` là `index.html`, dot segment ⇒ 404; console Keycloak trên `admin.` vẫn 401 khi không có phiên; `/key?v=113` A/B/C 200; `run_staging.sh` (nhóm `platform`) PASS — chạy bằng `tests/security/edge/` của **cùng cây đã render Caddyfile đang chạy** (bản của cây ≥ `3498e00` đòi chuyển hướng v10 ⇒ FAIL nhóm `public` trên edge v9); `external.py` từ ngoài | Không |

Hoàn tác: cài lại Caddyfile v8 đã sao lưu + `validate` + reload (Portal về 404 như trước); `web` để chạy vô hại hoặc `$APP stop web`.

Ghi vào `current.md` (digest api/worker/web, giờ reload edge v9) và bằng chứng P4-T01a (mục staging).

## n. P4-T07 — chuyển hướng web-auth (Caddyfile v10)

Chỉ Caddyfile ⇒ **reload** (§14.6 (a)); không migration, không image mới của edge. **Thứ tự bắt buộc**: api/worker có `POST /tenants/{tenantId}/enrollment/web-auth/claim` (P4-T06) và `web` có trang `/enroll/claim` (P4-T08) **trước** v10 — v10 đưa mọi link `/register/<auth_id>` (không `via=portal`) tới trang đó. Bằng chứng và thiết kế: [P4-T07](../planning/evidence/P4-T07.md); lệnh chi tiết: RUNBOOK mục "Template v9 → v10".

| # | Bước | Ảnh hưởng tới đang chạy |
|---|---|---|
| n1 | Xác nhận api/worker/web đang chạy là bản có P4-T06 + P4-T08 (digest trong `current.md`) | Không |
| n2 | Caddyfile **v9 → v10**: render, `diff` compose (chỉ dòng `template_version`), sao lưu, cài, `caddy validate`, reload | **Reload** — báo trước: stream upgrade đóng sau `stream_close_delay` (5 phút), client tự nối lại |
| n3 | Kiểm: `run_staging.sh` (nhóm `public`: chuyển hướng, Auth ID sai ⇒ 404, `via=portal`) PASS; `/key?v=113` A/B/C 200; **V-07**: client thật từng OS hoàn tất đăng ký sau claim (link in ra ⇒ `app.<domain>/enroll/claim` ⇒ claim ⇒ `Running`) | Không |

Hoàn tác: cài lại Caddyfile v9 đã sao lưu + `validate` + reload. Ghi vào `current.md` (giờ reload edge v10) và bằng chứng P4-T07 (mục staging — V-07).

## o. Lô Phase 4 đầu tiên lên staging (`8840590` → `9736636`) — trình tự đã diễn tập

Áp mục m (web + v9) và — khi có P4-T08 — mục n trong **một** đợt, cùng migration `0020`–`0026`, api/worker/web mới và
**Host Agent mới** (P4-T12 `WriteDnsRecords`: Agent cũ trả UNIMPLEMENTED ⇒ job `dns.records_write` `failed
agent_refused`). Diễn tập đầy đủ (nâng, kiểm, hoàn tác A và B, nâng lại) trên VM 110 với chính các script của host:
[P4-deploy-rehearsal](../planning/evidence/P4-deploy-rehearsal.md) — số đo, lỗi runbook đã sửa (F-1…F-5), mục chỉ kiểm
được trên staging. **Thứ tự bắt buộc:** compose mới **cài trước** `migrate.sh` (F-3) → migrate → Agent → api/worker/web
→ edge v9 (web phải chạy trước) → v10 **chỉ khi** SPA có `/enroll/claim` (P4-T08 — chưa có ở `9736636`: link
`/register/<auth_id>` sẽ mở trang "không tìm thấy" của SPA). Không đổi: IdP/realm (`realm-update.sh --check` exit 0),
image idp/edge/headscale/backup/probe/node-exporter, `compose.edge.yaml` (chỉ dòng chú thích), firewall, network,
secret file, `staging.env`, VPS (gateway v2 đã lên từ F-G3-1). Biến mới tùy chọn: `MG_IDP_CONSOLE_LOGIN_NOTIFY_WINDOW`
(worker, mặc định 10m — không render vào compose).

```bash
# 0. máy vận hành: workflow `images` xanh cho commit D (≥ 9736636) ⇒ MỘT commit pin [images.mg-api], [images.mg-worker],
#    [images.mg-web], [images.mg-agent] cùng tag D (render_app từ chối khi thiếu/khác tag). Báo trước giờ reload edge.
# 1. đồng bộ + sao lưu cấu hình đang chạy
TS=$(date -u +%Y%m%dT%H%M%SZ)
cp -a ~/mg ~/mg.bak-$TS                                     # rồi ~/mg = git archive của commit pin
for f in app agent edge; do sudo cp -a /opt/meshguard/core/compose.$f.yaml /root/compose.$f.yaml.$TS; done
sudo cp -a /opt/meshguard/core/caddy/Caddyfile /root/Caddyfile.v8.$TS
cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)" && sudo -v
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
PSQL="sudo docker exec -i mg-core-postgres-1 psql -X -U postgres -d meshguard -tA"
# 2. preflight (chỉ đọc) — mọi dòng phải như chú thích
for t in test_render_app test_render_edge test_render_agent; do python3 tools/$t.py >/dev/null && echo "$t ok"; done
$PSQL -c "SELECT status, count(*) FROM tenant_memberships GROUP BY 1"   # chỉ active|locked|offboarded (CHECK của 0024)
$PSQL -c "SELECT status, count(*) FROM platform_users GROUP BY 1"       # chỉ active|disabled (CHECK của 0025)
$PSQL -c "SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id IS NOT NULL"   # 0 (FK của 0020)
$PSQL -c "SELECT count(*) FROM provisioning_jobs WHERE status IN ('queued','running')"          # 0 (không job dở)
for S in tenant-a tenant-b; do echo "$S $(sudo docker exec mg-hs-$S headscale policy get | head -c -1 | sha256sum | cut -c1-64)"; done
$PSQL -c "SELECT t.slug, a.applied_sha256 FROM policy_applications a JOIN tenants t ON t.id = a.tenant_id
          WHERE a.state = 'applied' AND a.superseded_at IS NULL ORDER BY 1"
#    hai sha phải trùng nhau từng tenant: lệch ⇒ trong ≤ 15 phút sau triển khai, policy.drift_check (P4-T10) ghi
#    security_event High và áp lại version mong muốn (drift_repair); instance không có policy ⇒ gỡ edge khỏi instance
# 3. render + diff (không đổi gì đang chạy)
python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app
diff /opt/meshguard/core/compose.app.yaml /tmp/mg-app/compose.app.yaml   # template 3→4: + service web, image api/worker
python3 tools/render_agent.py infrastructure/environments/staging/staging.env /tmp/agent
diff /opt/meshguard/core/compose.agent.yaml /tmp/agent/compose.agent.yaml # chỉ image + MG_AGENT_HELPER_IMAGE
diff /opt/meshguard/core/agent/allowlist /tmp/agent/agent/allowlist       # không đổi
# 4. compose mới TRƯỚC, rồi backup pre-migration + migrate 0020–0026 (api/worker cũ vẫn chạy được trên schema 26)
sudo install -m 0644 /tmp/mg-app/compose.app.yaml /opt/meshguard/core/compose.app.yaml
sudo bash infrastructure/host/migrate.sh        # mong đợi "schema_version":26,"latest_migration":26 … "current":true + OK
sudo ls /opt/meshguard/backups/postgres | grep pre-migration | tail -1   # ghi id bộ — điểm hoàn tác B
# 5. Host Agent mới (recreate ~4 s; tenant không bị đụng)
sudo install -m 0644 /tmp/agent/compose.agent.yaml /opt/meshguard/core/compose.agent.yaml
sudo docker compose -f /opt/meshguard/core/compose.agent.yaml up -d --wait --wait-timeout 120
# 6. api/worker/web/mail-bridge (recreate ~5–8 s; app. 502 ~2–5 s dưới Caddyfile v8)
$APP up -d --wait --wait-timeout 240 api worker web mail-bridge
for c in api worker mail-bridge; do sudo docker exec mg-app-$c-1 /usr/local/bin/meshguard healthcheck; done
sudo docker exec mg-app-web-1 /usr/bin/healthprobe http://127.0.0.1:8080/ 200 && echo web-ok
# 7. edge v8 → v9 (reload 0,2–0,3 s): cây ≥ 3498e00 chỉ render được v10 ⇒ render v9 bằng tools/ của f7ceb5d
#    (máy vận hành: git archive f7ceb5d tools infrastructure/caddy infrastructure/compose tests/security/edge versions.lock
#    → giải nén vào ~/mg-v9 trên host; file tham số + env vẫn của ~/mg)
(cd ~/mg-v9 && python3 tools/render_edge.py ~/mg/infrastructure/environments/staging/edge.json /tmp/edge9)
diff /opt/meshguard/core/compose.edge.yaml /tmp/edge9/compose.edge.yaml   # chỉ dòng chú thích template_version
sudo install -m 0644 /tmp/edge9/compose.edge.yaml /opt/meshguard/core/compose.edge.yaml
sudo install -m 0644 /tmp/edge9/caddy/Caddyfile /opt/meshguard/core/caddy/Caddyfile
sudo docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
sudo bash ~/mg-v9/tests/security/edge/run_staging.sh "mesh.$MG_BASE_DOMAIN" "$MG_PUBLIC_IPV4" tenant-a tenant-b   # PASS
# 8. (chỉ khi P4-T08 đã lên — mục n) edge v9 → v10: như bước 7 với tools/ của ~/mg, conformance bằng ~/mg/tests/…
# 9. kiểm sau nâng: mục m4; `sudo bash infrastructure/idp/realm-update.sh --check` ⇒ exit 0; Super Admin + TO đăng nhập,
#    GET /tenants/{A}/devices|policies|tags|users|groups|dns ⇒ 200, cùng route của A bằng TO-B ⇒ 404; một tenant thử
#    (G3 `tenant-c`: provision → 2 client → suspend/resume → deprovision 2P); policy A/B (sha ở bước 2) không đổi sau
#    ≥ 15 phút; `$APP logs --since 20m worker | grep '"level":"ERROR"'` chỉ còn lỗi đã biết (thư khi relay lỗi)
```

**Hoàn tác** (đo trên VM 110 — `P4-deploy-rehearsal` mục 6):

- **A — nhanh, giữ DB** (schema 26 expand-only; api/worker/agent cũ đã kiểm 34/34 + tenant C 12/12 trên schema mới):
  cài lại `/root/Caddyfile.v8.$TS` + `/root/compose.edge.yaml.$TS` → `validate` → reload; cài lại
  `/root/compose.agent.yaml.$TS` → `up -d --wait`; cài lại `/root/compose.app.yaml.$TS` →
  `$APP up -d --wait --remove-orphans api worker mail-bridge` (gỡ `web`); `~/mg` = `~/mg.bak-$TS`. Gián đoạn `app.`
  ~1,5 s, `/key` của tenant 0 lỗi. Bản ghi DNS (P4-T12) tạo trong cửa sổ vẫn nằm ở `records/extra-records.json` của
  instance và Headscale vẫn phát chúng (Agent/worker cũ không đọc) — F-5.
- **B — restore bộ pre-migration của bước 4** ([backup-restore.md](backup-restore.md) 6.3 + 6.5, sau A): bảo trì →
  dừng api/worker → đổi tên DB → globals → `pg_restore --create` → `migrate status` (image cũ: schema 19, exit 0) → cờ bảo
  trì trong DB mới → `up` → `post-restore-reconcile` (dry-run rồi thật) → tắt bảo trì → backup `manual`. API không phục
  vụ ~22 s (gồm 11 s chờ worker dừng job). Sau B: instance có `records/extra-records.json` không rỗng trong khi DB vừa
  restore không có bản ghi DNS nào ⇒ ghi lại file `[]` hoặc để lần ghi DNS đầu tiên sau khi nâng lại ghi lại toàn bộ file
  từ DB (job level-triggered — đã kiểm) — F-5.
