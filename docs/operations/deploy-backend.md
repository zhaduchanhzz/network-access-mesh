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

`mg-idp` (Keycloak 26.8.2, realm `platform`, `tenant-a`, `tenant-b`) **đã chạy trên staging** do người điều phối dựng — xem mục IdP của [RUNBOOK](../../infrastructure/host/RUNBOOK.md). Backend chỉ cần: (1) container `idp` trên `mg-edge` với alias `idp` (edge → `idp:8080`), (2) client `mg-portal` của mỗi realm (secret đưa vào SecretStore ở bước e), (3) admin khởi tạo của realm `master` cho **một** lần idp-bootstrap (bước h), (4) site `auth.` của edge (bước h). Kiểm: `sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml ps` ⇒ `idp` healthy.

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
$CORE run --rm --no-deps -T -e MG_IDP_ID_PLATFORM api admin register-platform-idp
# adopt: S=tenant-a rồi tenant-b — đúng khối lệnh của RUNBOOK (API key mới đi thẳng từ `headscale apikeys create` qua pipe)
# client secret mg-portal của từng realm, chỉ qua pipe (script từ chối stdout là terminal hoặc file):
sudo bash infrastructure/host/idp-client-secret.sh platform | $CORE run --rm --no-deps -T api admin set-idp-client-secret "$MG_IDP_ID_PLATFORM"
sudo bash infrastructure/host/idp-client-secret.sh tenant-a | $CORE run --rm --no-deps -T api admin set-idp-client-secret "$MG_IDP_ID_TENANT_A"
sudo bash infrastructure/host/idp-client-secret.sh tenant-b | $CORE run --rm --no-deps -T api admin set-idp-client-secret "$MG_IDP_ID_TENANT_B"
```

Kiểm: như mục "Kiểm" của RUNBOOK; thêm `sudo docker exec mg-core-postgres-1 psql -U postgres -d meshguard -c "SELECT action, actor_type, count(*) FROM audit_events GROUP BY 1,2 ORDER BY 1"` ⇒ `platform.instance.adopt.requested/succeeded` = 2/2, `platform.idp.register`, `platform.idp.client_secret.update` = 3, tất cả `system`. Hoàn tác: mục "Hoàn tác" của RUNBOOK (chỉ trước go-live).

## f. Tài khoản mẫu, Super Admin, TO/TA

1. Tài khoản trong realm: dùng script tạo user của mục IdP (người điều phối). Mật khẩu tạm sinh **trên máy vận hành** vào `config/secrets/staging/<realm>-<username>.txt` (git bỏ qua) và đi tới script qua stdin của `ssh` — không in, không nằm trên dòng lệnh. TOTP do chính người dùng đăng ký ở lần đăng nhập đầu.
2. `sub` của từng người: `sudo bash infrastructure/idp/user-id.sh <realm> <username>`.
3. Super Admin (D-11: hai người) và TO/TA của A/B: mục "Super Admin đầu tiên và TO/TA…" của [RUNBOOK](../../infrastructure/host/RUNBOOK.md) với `CORE="$APP"`. Ghi `sub`, id, request id (không secret) vào `current.md`.

Hoàn tác: mục "Hoàn tác" tương ứng của RUNBOOK; user mẫu xóa ở realm.

## g. `mg-backup` theo lịch

`$BK up -d` rồi [backup-restore.md](backup-restore.md) mục 4 bước 6 (`status.json` của `postgres`, `idp`, `edge`: `last_attempt.ok = true`). Hoàn tác: `$BK down`.

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
