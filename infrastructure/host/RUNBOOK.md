# Runbook Phase 1 — dựng lại tenant thử, edge và gateway VPS của staging

> **File viết tay.** Quy trình dựng (lại) Headscale của các tenant thử A/B theo đúng thứ tự §11.3 của [bản master](../../docs/planning/implementation-master-plan.md), chỉ bằng script trong repo — dùng cho P1-T08/P1-T09 và diễn tập P1-T19; thêm đổi cấu hình tenant/edge, đưa A/B vào registry của nền tảng (`meshguard admin adopt-instance` — P2-T11, chạy ở P2-T16) và dựng lại gateway VPS (P1-T18). Từ Phase 3, Orchestrator thay thế phần tenant của runbook này.

## Điều kiện

- Host đã qua `layout.sh`, `networks.sh`, firewall (`apply-firewall.sh`), stack `mg-core` và `mg-edge` đang chạy, edge healthy.
- Bản sao repo trên host (ví dụ `~/mg`) gồm `tools/`, `infrastructure/`.
- Tham số môi trường (domain, IP công khai, IP LAN, tunnel…) chỉ nằm trong `infrastructure/environments/staging/staging.env`; tool render tự đọc. Lệnh shell cần giá trị thì nạp trước: `eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)"`.
- Tham số tenant (không bí mật) ở `infrastructure/environments/staging/tenants/<slug>.json`.

## Các bước (mỗi tenant)

```bash
cd ~/mg
S=tenant-a                                   # slug
# 1. render (tất định — cùng tham số cho cùng file, cùng instance_id)
python3 tools/render_instance.py infrastructure/environments/staging/tenants/$S.json /tmp/render/$S
# 2. gỡ bản cũ (XÓA dữ liệu và khóa của tenant — chỉ với tenant thử)
sudo bash infrastructure/host/tenant-remove.sh $S --i-understand-this-deletes-data
# 3. thư mục → network internal /29 → start → healthy → policy deny-all (đọc lại khớp) → dấu policy-bootstrap.ok
sudo bash infrastructure/host/tenant-deploy.sh /tmp/render/$S
# 4. gắn edge (chỉ instance đã có dấu policy) + kiểm network đúng 2 thành viên
sudo bash infrastructure/host/reattach-edge.sh $S
# 5. (lab) fixture cho phép thử có client — trả về baseline trước P1-T14
sudo bash infrastructure/host/tenant-policy.sh $S infrastructure/headscale/templates/test-allow-intra.hujson
# 6. kiểm
python3 tools/health_probe.py "$MG_PUBLIC_IPV4" "mesh.$MG_BASE_DOMAIN" $S     # qua VPS; "$MG_LAN_IPV4" để thử LAN-direct
```

## Đăng ký lại client (lab)

Khóa Noise và DB mới ⇒ client cũ phải đăng ký lại. Mỗi client: `headscale users create lab-<x>` (một lần mỗi tenant), một pre-auth key **dùng một lần, hạn ngắn** (`headscale preauthkeys create --user <id> --expiration 1h -o json`), chuyển thẳng tới client qua pipe — không in, không lưu:

```bash
tailscale up --login-server=https://<slug>.mesh.$MG_BASE_DOMAIN --auth-key=file:/dev/stdin --hostname=<tên> \
  --accept-dns=false --force-reauth
```

## Nghi thức khóa (P2-T04a)

Sinh KEK `kek-app`/`kek-ops`, khóa khôi phục backup và khóa ký manifest ngay trên host, với chủ dự án giữ 2 bản giấy: [docs/operations/key-ceremony.md](../../docs/operations/key-ceremony.md), bộ công cụ ở [key-ceremony/](key-ceremony/ceremony.sh). Hai bước có vật liệu khóa (`show-offline`, `verify-offline`) chỉ chạy trong terminal của chủ dự án (`ssh -t`); mọi bước khác chạy được qua SSH không TTY và không in bí mật.

## Backup và restore (P2-T03a, P2-T05b)

Project compose `mg-backup` (`pg-backup`, `idp-backup`, `edge-backup` — lịch riêng, mã hóa tới recipient khôi phục trước khi ghi, file trạng thái cho cảnh báo quá hạn), trigger bắt buộc trước migration, restore PostgreSQL/IdP/volume ACME và **thu hồi toàn bộ session sau khi restore vào môi trường đang dùng**: [docs/operations/backup-restore.md](../../docs/operations/backup-restore.md). Kích hoạt trên host ở P2-T16, sau nghi thức khóa.

## Sau khi recreate edge

Network tenant được gắn lúc chạy nên mất khi container edge bị recreate: chạy lại `sudo bash infrastructure/host/reattach-edge.sh` (mọi instance) — đo được ~16 s cho 100 network ([P1-T20](../../docs/planning/evidence/P1-T20.md)).

## Đổi cấu hình của tenant đang chạy

Ví dụ đổi `derp_ipv4` khi chuyển điểm vào ([P1-T18](../../docs/planning/evidence/P1-T18.md)). Render lại như bước 1, rồi `sudo bash infrastructure/host/tenant-reconfigure.sh /tmp/render/$S`. Script thực hiện:

1. `configtest` với dữ liệu nháp.
2. Giữ bản cũ ở `meta/config.yaml.bak-<ts>`.
3. Restart có kiểm soát (~2,5 s; client mất control vài giây rồi tự nối lại).
4. Chờ healthy.
5. Kiểm policy giữ nguyên.

## Đổi image Headscale của tenant đang chạy (bản vá V-26 ⇄ image chính thức)

Bối cảnh: [P2-T10a](../../docs/planning/evidence/P2-T10a.md) — ADR-02 sửa đổi ngày 2026-11-17. Tham số `headscale_build` trong `infrastructure/environments/staging/tenants/<slug>.json` chọn image: `"patched"` (`versions.lock` `[images.mg-headscale]`, phải đã pin) hoặc `"official"` (`[images.headscale]` — đường rollback). Chỉ đổi image, không đổi config cùng lúc. **Chỉ chạy khi chủ dự án đã duyệt rollout.**

```bash
cd ~/mg
S=tenant-a
# 1. trong tenants/$S.json: "headscale_build": "patched"; render (config.yaml phải giống hệt bản đang chạy)
python3 tools/render_instance.py infrastructure/environments/staging/tenants/$S.json /tmp/render/$S
# 2. pull → ghi policy/node/user → dừng → cold backup data/ (meta/backup-<ts>/) → configtest image đích trên bản sao
#    dữ liệu, không network → cài compose.yaml/meta mới (giữ bản cũ) → compose up -d → healthy → kiểm image, policy,
#    số node, số user không đổi
sudo bash infrastructure/host/tenant-upgrade.sh /tmp/render/$S
# 3. kiểm thêm: headscale version (commit của bản vá), /key qua VPS, edge còn gắn network của tenant
docker exec mg-hs-$S headscale version
python3 tools/health_probe.py "$MG_PUBLIC_IPV4" "mesh.$MG_BASE_DOMAIN" $S
```

Hoàn tác (về digest chính thức): đặt lại `"headscale_build": "official"`, render như bước 1, rồi `sudo bash infrastructure/host/tenant-upgrade.sh /tmp/render/$S`. Cả hai bản đều là v0.29.7 và dùng chung DB hai chiều (contract test P2-T10a). Nếu instance không lên được: `docker compose -f /opt/meshguard/tenants/<instance_id>/compose.yaml down`, thay `data/` bằng `meta/backup-<ts>/data` (giữ owner `run_uid`), cài lại `meta/compose.yaml.bak-<ts>` và `meta/instance.json.bak-<ts>`, rồi `up -d`.

## Đổi cấu hình edge (Caddyfile)

1. Chạy `python3 tools/render_edge.py infrastructure/environments/staging/edge.json /tmp/edge` (tham số lấy từ `staging.env`).
2. Nếu `compose.edge.yaml` chỉ khác ở dòng chú thích: **reload**. Sao lưu `/opt/meshguard/core/caddy/Caddyfile` ra ngoài thư mục mount, cài bản mới, rồi chạy `docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock`.
3. Nếu compose đổi thật (cổng publish): **recreate** rồi làm mục trên.
4. Với `stream_close_delay 5m`, stream cũ đóng đồng loạt khoảng 5 phút sau reload; client tự nối lại.
5. Kiểm lại ngay:
   - `/key?v=113` qua VPS và qua LAN-direct đều trả 200;
   - `tests/security/edge/run_staging.sh` (conformance, kể cả `tunnel-reject`);
   - `tests/isolation/it14_probe.sh` ở hai chế độ ([P1-T12c](../../docs/planning/evidence/P1-T12c.md));
   - `tests/security/edge/external.py` từ một máy ngoài.
6. Hoàn tác: cài lại bản sao lưu rồi reload.

## IdP — Keycloak `mg-idp` (P2-T05, triển khai lên staging ở P2-T16)

Project `mg-idp`: `idp` (Keycloak 26.8.2, 3 realm `platform`/`tenant-a`/`tenant-b` nhập lúc khởi động đầu), `idp-db` (PostgreSQL riêng, chỉ trên `mg-idp-data`) và — khi `MG_IDP_MAIL_SINK=mailpit` (staging) — `mailsink` (Mailpit, network `mail` internal: thư không ra ngoài host). Không publish cổng nào; `auth.<domain>` qua edge là bước riêng của P2-T16 (template edge mới + reload có lịch). Thiết kế: [P2-T05](../../docs/planning/evidence/P2-T05.md), [P2-T05b](../../docs/planning/evidence/P2-T05b.md).

Điều kiện: network nền tảng đã có (`networks.sh` — có `mg-edge`, `mg-idp-data`, `mg-egress`), edge chạy ở `10.249.0.2` (proxy tin cậy duy nhất của Keycloak), `~/mg` là bản đồng bộ **chỉ file tracked** của repo (không bao giờ có `config/secrets/`).

```bash
cd ~/mg
IDP="sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml"
# 1. Secret dạng file, sinh trên host, không in ra (chạy lại an toàn — file đã có thì giữ); kiểm quyền mọi secret
sudo bash infrastructure/idp/secrets.sh
sudo bash infrastructure/host/check-secrets.sh
# 2. Render (không secret) rồi cài: compose + realm + script khởi tạo DB
python3 tools/render_idp.py infrastructure/environments/staging/staging.env /tmp/mg-idp
sudo install -d -o root -g root -m 0755 /opt/meshguard/core/idp/realms /opt/meshguard/core/idp/initdb
sudo install -o root -g root -m 0644 /tmp/mg-idp/compose.idp.yaml /opt/meshguard/core/compose.idp.yaml
sudo install -o root -g root -m 0644 /tmp/mg-idp/idp/realms/*.json /opt/meshguard/core/idp/realms/
sudo install -o root -g root -m 0644 /tmp/mg-idp/idp/initdb/*.sql /opt/meshguard/core/idp/initdb/
rm -rf /tmp/mg-idp
$IDP config --quiet
# 3. Kéo image theo digest, chạy, chờ healthy (Keycloak: start_period 180 s)
$IDP pull && $IDP up -d
$IDP ps
```

Kiểm:

- `$IDP ps`: `idp`, `idp-db` (và `mailsink`) đều `healthy`.
- Realm đã nhập và admin khởi tạo dùng được: `sudo bash infrastructure/idp/user-id.sh tenant-a service-account-mg-idp-driver` in đúng một user.
- Discovery của 3 realm (từ host, thẳng tới `idp:8080` trên `mg-edge`): `issuer` = `https://auth.<domain>/realms/<realm>`.
- `mail` là network internal, chỉ có `idp` và `mailsink`: `sudo docker network inspect mg-idp_mail`.
- Thư đi được Keycloak → Mailpit: gửi `execute-actions-email` cho một tài khoản mẫu, đếm thư qua API của Mailpit (`http://<IP mailsink>:8025/api/v1/messages` từ host). Đọc thư bằng trình duyệt: `ssh -L 8025:<IP mailsink>:8025 mgdeploy@<host>` rồi mở `http://localhost:8025`.

Tài khoản mẫu (owner 2026-11-17: 2 người vận hành trong `platform`, TO/TA của A và B): tạo bằng [infrastructure/idp/create-user.sh](../idp/create-user.sh) — mật khẩu do máy của người vận hành sinh, ghi vào kho secret của chủ dự án (`config/secrets/staging/`, ngoài git) và đi qua stdin của ssh, không nằm trên dòng lệnh, không in ra; TOTP đăng ký ở lần đăng nhập đầu. Sau đó dùng `user-id.sh` lấy `sub` cho mục "Super Admin đầu tiên" bên dưới.

Hoàn tác:

```bash
$IDP down                         # dừng, GIỮ DB của IdP (volume mg-idp_idp-db-data)
$IDP down -v                      # chỉ trước khi dùng thật: xóa luôn DB (realm, user) — lần up sau nhập lại realm
sudo rm -rf /opt/meshguard/core/idp /opt/meshguard/core/compose.idp.yaml
sudo rm -rf /opt/meshguard/secrets/idp /opt/meshguard/secrets/backup/idp_backup_password   # chỉ sau down -v
```

## Đưa tenant A/B vào registry — `meshguard admin adopt-instance` (P2-T11, chạy ở P2-T16)

Chuyển quyền quản lý hai instance dựng tay ở Phase 1 sang nền tảng: đăng ký tenant, host, instance (từ `meta/instance.json`) và IdP của tenant; giao cho nền tảng một API key **mới**; expire **mọi** key khác của instance (gồm key hạn ngắn của Phase 1). Chỉ adopt đúng instance được chỉ định — **không** adopt `tenant-c` (tenant demo; `staging.env` không có `MG_IDP_ID_TENANT_C` nên lệnh cũng tự từ chối). Thiết kế và phép thử: [P2-T11](../../docs/planning/evidence/P2-T11.md).

**Ngoại lệ có chủ đích (§25.1 quy tắc 7, Phase 1–2):** key mới được tạo bằng CLI trong container (`docker exec … headscale apikeys create`) vì chưa có Agent (`apikey.bootstrap` — P3). Key đi **thẳng** từ stdout của `docker exec` qua pipe vào stdin của lệnh: không gõ, không dán, không nằm trong file, tham số dòng lệnh, biến môi trường, lịch sử shell hay log. Lệnh từ chối stdin là terminal hoặc file thường, và từ chối mọi tham số trông như key.

### Điều kiện

- Core compose của P2-T16 đã có service `api` (image của `apps/api`; lệnh chạy bằng `docker compose run` nên dùng **nguyên** cấu hình của service: network `mg-data` + `mg-admin`, user 65532, rootfs chỉ đọc, secret dạng file) và migration đã chạy. Biến môi trường mà lệnh đọc từ service (đặt ở P2-T16, không có giá trị secret nào):
  - `MG_ENV`, `MG_BASE_DOMAIN`, `MG_LOG_LEVEL`;
  - `MG_DB_URL` (không user/mật khẩu), `MG_DB_TENANT_USER=mg_api_tenant`, `MG_DB_PLATFORM_USER=mg_api_platform`, `MG_DB_TENANT_PASSWORD_FILE`, `MG_DB_PLATFORM_PASSWORD_FILE`;
  - `MG_KEK_APP_DIR` (keyring `kek-app` — P2-T04a);
  - `MG_EDGE_ADMIN_URL=http://<edge_admin_ip>:<admin_port>` (giá trị của listener admin trong `tools/render_edge.py`: `EDGE_IPS`, `INTERNAL`) và `MG_EDGE_ADMIN_TOKEN_FILE` trỏ tới bản mount của `/opt/meshguard/secrets/app/edge_admin_token` (`root:mg-sec-app 0440`; service thêm `group_add` nhóm `mg-sec-app`).
- Edge đã gắn vào network của tenant (`reattach-edge.sh`), instance healthy.
- Đứng trong bản sao repo trên host, nạp tham số: `cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)"` (cho `MG_IDP_ID_*`); `sudo -v` một lần trước để `sudo` không hỏi mật khẩu giữa pipe.

### Các bước

```bash
cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)" && sudo -v
CORE="sudo docker compose -p mg-core -f /opt/meshguard/core/compose.core.yaml"   # tên file/service theo P2-T16
RANGE=$(python3 -c 'import tomllib; print(tomllib.load(open("versions.lock","rb"))["ids"]["tenant_run_uid_range"])')
POOL=$(python3 -c 'import tomllib; print(tomllib.load(open("versions.lock","rb"))["ids"]["tenant_net_pool"])')

# 0. IdP của nền tảng (một lần; chạy lại vô hại)
$CORE run --rm --no-deps -T -e "MG_IDP_ID_PLATFORM=$MG_IDP_ID_PLATFORM" api admin register-platform-idp

# 1. mỗi tenant: S=tenant-a, rồi S=tenant-b (lần đầu kèm vùng/dải của host; lần sau chỉ --host)
S=tenant-a; NAME="Tenant A"
IID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instance_id"])' infrastructure/environments/staging/tenants/$S.json)
sudo docker exec mg-hs-$S headscale apikeys list            # ghi lại các prefix hiện có (prefix không phải secret)
T=$(sudo mktemp -d)                                         # meta không chứa secret; bản 0444 cho uid 65532 của api
sudo install -m 0444 /opt/meshguard/tenants/$IID/meta/instance.json "$T/instance.json"
sudo docker exec mg-hs-$S headscale apikeys create -e 2160h -o json \
  | $CORE run --rm --no-deps -T -e "MG_IDP_ID_TENANT_A=$MG_IDP_ID_TENANT_A" -e "MG_IDP_ID_TENANT_B=$MG_IDP_ID_TENANT_B" \
      -v "$T/instance.json:/run/mg-adopt/instance.json:ro" \
      api admin adopt-instance --host mg-staging --host-region lab --run-uid-range "$RANGE" --tenant-net-pool "$POOL" \
      --name "$NAME" /run/mg-adopt/instance.json
sudo rm -rf "$T"
```

Lệnh kiểm theo thứ tự, và **không ghi gì** nếu một bước kiểm trước khi ghi thất bại:

1. `meta/instance.json` đúng định dạng của `render_instance.py`; host đã đăng ký thì vùng/dải phải khớp; `run_uid`/`net_cidr` nằm trong dải của host; registry không mâu thuẫn — slug của tenant khác, tenant đã có instance **khác** (instance thứ hai bị từ chối), instance của tenant khác, IdP mang issuer/client khác, tenant `suspended`/`deleted`.
2. **Pre-flight qua listener admin của edge** bằng chính key mới: `GET /version` trong dải hỗ trợ, `ListAPIKeys` thành công (key thuộc đúng `hs-<slug>`), hạn còn ≥ 14 ngày.
3. Ghi registry (tenant `provisioning`, instance `starting`, IdP `active` với id `MG_IDP_ID_<SLUG>`, issuer `https://auth.<domain>/realms/<slug>`, client `mg-portal`), ghi key vào SecretStore (`mgsec://<tenant_id>/headscale-api-key#<n>`), trỏ instance tới reference đó.
4. **Kiểm qua `Registry.ForTenant`** (registry + SecretStore + edge — đúng đường của api); lỗi ⇒ trả reference cũ, hủy phiên bản vừa ghi, không expire gì.
5. Expire mọi key **khác** còn hạn của instance, liệt kê lại: chỉ còn key mới; kích hoạt (tenant `active`, instance `running`); hủy phiên bản secret cũ.

Kết quả mong đợi (không có secret — chỉ reference và prefix công khai):

```text
  registry: host created, tenant created, instance created, identity provider created
  secret: mgsec://<tenant_id>/headscale-api-key#1 (previous: none)
  verified: ListAPIKeys through Registry.ForTenant (registry + SecretStore + edge)
  expired: <n> other API key(s) (<prefix>, …); valid keys now: 1
  activated: tenant provisioning→active, instance starting→running
OK
```

Mã thoát: `0` đạt; `1` lỗi (thông báo nói rõ bước; `refused`/`API key check failed` ⇒ chưa ghi gì); `2` sai cú pháp. Sự kiện audit (`platform.instance.adopt.requested` → `.succeeded`/`.failed`, `actor_type=system`) ra stderr dạng JSON cho tới khi P2-T16 nối `internal/audit` (P2-T08) — lưu kèm hồ sơ thay đổi.

### Kiểm

```bash
sudo docker exec mg-hs-$S headscale apikeys list    # đúng MỘT key còn hạn = prefix lệnh in ra; key Phase 1 đã hết hạn
$CORE exec postgres psql -U postgres -d meshguard -c \
  "SELECT t.slug, t.status, i.status, i.api_key_prefix, i.api_key_expires_at, p.issuer
     FROM tenants t JOIN tenant_instances i ON i.tenant_id = t.id JOIN identity_providers p ON p.tenant_id = t.id"
```

Chạy lại lệnh (với một key mới khác) là idempotent: registry giữ nguyên, secret lên phiên bản kế tiếp, key nền tảng cũ bị expire — cũng là cách xoay key thủ công tới khi có job `apikey.rotate` (P3).

### Client secret của `mg-portal` (sau adopt, trước khi mở đăng nhập)

Keycloak sinh secret của client lúc import realm (P2-T05). Đưa secret vào SecretStore cũng chỉ qua pipe (cách đọc secret từ Admin API của Keycloak bằng admin khởi tạo chốt ở P2-T16/P2-T05a; không đặt mật khẩu admin trên dòng lệnh):

```bash
<lệnh in ra client secret của mg-portal trong realm $S> \
  | $CORE run --rm --no-deps -T api admin set-idp-client-secret "$MG_IDP_ID_TENANT_A"    # và _TENANT_B, _PLATFORM
```

### Hoàn tác (chỉ trước go-live)

Key Phase 1 đã expire không khôi phục được (không cần: CLI trong container — `docker exec mg-hs-<slug> headscale …` — luôn dùng được qua Unix socket). Gỡ đăng ký một tenant khi chưa có ai đăng nhập (FK từ chối nếu đã có `identities`/membership — khi đó dùng luồng deprovision, không xóa tay):

```bash
sudo docker exec mg-hs-$S headscale apikeys expire --prefix <prefix nền tảng>   # key nền tảng không còn ai giữ
TID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tenant_id"])' infrastructure/environments/staging/tenants/$S.json)
$CORE exec -T postgres psql -U postgres -d meshguard -v ON_ERROR_STOP=1 -v tid="$TID" <<'SQL'
BEGIN;
DELETE FROM secrets WHERE tenant_id = :'tid';
DELETE FROM tenant_keys WHERE tenant_id = :'tid';
DELETE FROM tenant_instances WHERE tenant_id = :'tid';
DELETE FROM identity_providers WHERE tenant_id = :'tid';
DELETE FROM tenants WHERE id = :'tid';
DELETE FROM hosts h WHERE h.name = 'mg-staging' AND NOT EXISTS (SELECT 1 FROM tenant_instances i WHERE i.host_id = h.id);
COMMIT;
SQL
```

Sự kiện audit đã ghi được giữ nguyên (append-only).

## Super Admin đầu tiên và TO/TA của tenant A/B — `bootstrap-super-admin`, `seed-membership` (P2-T11a, chạy ở P2-T16)

Tạo **hai** Super Admin đầu tiên (D-11: từ 2 người vận hành trở lên) theo `(IdP platform, sub)`, rồi gán Tenant Owner / Tenant Admin của `tenant-a` và `tenant-b` theo `(IdP của chính tenant, sub)` — không qua lời mời. Lần đăng nhập đầu của mỗi người khớp đúng hàng đã tạo theo `(idp_id, sub)`; **không bao giờ theo email** (§8.2). Từ Super Admin thứ ba trở đi chỉ qua API + 2P (`PUT /platform/users/{id}/super-admin-role`, P4-T03a): lệnh bootstrap tự từ chối khi đã có 2 SA đang hoạt động. Thiết kế và phép thử: [P2-T11a](../../docs/planning/evidence/P2-T11a.md).

### Điều kiện

- Đã xong mục "Đưa tenant A/B vào registry" ở trên: service `api` của core compose, `register-platform-idp` đã chạy, tenant A/B đã adopt (IdP `active` của từng tenant), client secret của `mg-portal` đã nạp.
- Mỗi người có tài khoản trong **đúng realm**: người vận hành nền tảng trong realm `platform`; TO/TA của A trong realm `tenant-a`, của B trong `tenant-b`. Tạo user (nếu chưa có) ở Admin Console của Keycloak (`https://auth.<domain>/admin/master/console/`, chỉ từ mạng quản trị): realm → Users → Add user (username, email, *Email verified*), Required actions `Update Password` + `Configure OTP`; tab Credentials → mật khẩu **tạm** (Temporary: On), trao cho người đó qua kênh riêng — người đó đổi mật khẩu và đăng ký TOTP ở lần đăng nhập đầu. Không gửi mật khẩu qua chat/ticket, không ghi vào repo hay `current.md`.
- Nạp tham số như mục adopt: `cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)" && sudo -v` (cho `MG_IDP_ID_PLATFORM`).

### 1. Tìm `sub` của từng người

Với Keycloak, `sub` = **id của user** (UUID chữ thường, ví dụ `0f8fad5b-d9cb-469f-a165-70867728950e`) — không phải username, không phải email; lệnh từ chối mọi giá trị không phải UUID cho IdP driver `keycloak`.

- **Cách 1 (khuyến nghị) — script chỉ đọc qua Admin REST:** `sudo bash infrastructure/idp/user-id.sh <realm> <username|email>` in mảng JSON `[{ "id": …, "username": …, "email": …, "enabled": … }]` của user khớp chính xác; `id` là `sub`. Script chạy `kcadm.sh get users` **bên trong** container `idp` bằng admin khởi tạo của realm `master`: mật khẩu được đọc trong container từ secret đã mount, chỉ nằm trong biến môi trường của tiến trình `kcadm` — không in ra, không có trong dòng lệnh (`ps`), không qua terminal, không ghi đĩa; token tạm của `kcadm` ở tmpfs của container, xóa khi thoát. `[]` = không có user đó trong realm (kiểm lại realm/username).
- **Cách 2 — Admin Console:** realm → Users → chọn user → trường **ID** ở đầu trang chi tiết (người vận hành tự đăng nhập console; không chép mật khẩu admin ra terminal).
- Đối chiếu với chính người đó (username/email họ dùng để đăng nhập) trước khi chạy lệnh — `sub` sai chỉ tạo một danh tính không ai đăng nhập vào được, nhưng `sub` của **người khác** sẽ trao quyền cho người khác.

```bash
uid() {  # uid <realm> <username|email> → sub (lỗi nếu không đúng 1 user)
  sudo bash infrastructure/idp/user-id.sh "$1" "$2" \
    | python3 -c 'import json,sys; u=json.load(sys.stdin); assert len(u) == 1, f"{len(u)} user"; print(u[0]["id"])'
}
SA1=$(uid platform <username người vận hành 1>); SA2=$(uid platform <username người vận hành 2>)
TOA=$(uid tenant-a <username TO của A>); TAA=$(uid tenant-a <username TA của A>)
TOB=$(uid tenant-b <username TO của B>); TAB=$(uid tenant-b <username TA của B>)
echo "$SA1 $SA2 $TOA $TAA $TOB $TAB"    # sub không phải secret — ghi vào hồ sơ thay đổi
```

### 2. Hai Super Admin

```bash
CORE="sudo docker compose -p mg-core -f /opt/meshguard/core/compose.core.yaml"   # như mục adopt (tên theo P2-T16)
$CORE run --rm --no-deps -T -e "MG_IDP_ID_PLATFORM=$MG_IDP_ID_PLATFORM" api admin bootstrap-super-admin --subject "$SA1" --display-name "<tên 1>"
$CORE run --rm --no-deps -T -e "MG_IDP_ID_PLATFORM=$MG_IDP_ID_PLATFORM" api admin bootstrap-super-admin --subject "$SA2" --display-name "<tên 2>"
```

Kết quả mong đợi (lần 1 có cảnh báo vì mới 1 SA; lần 2 `active Super Admins: 2`, không cảnh báo):

```text
bootstrap-super-admin: platform identity provider <MG_IDP_ID_PLATFORM> (issuer https://auth.<domain>/realms/platform)
  identity: <identity_id> (subject <sub>) — created
  platform user: <platform_user_id> — super_admin, active — created
  audit: platform.super_admin.bootstrap (actor_type system, request admin-<uuid>)
  active Super Admins: 1 (this command refuses from 2 on)
  WARNING: fewer than 2 active Super Admins — dual-control (2P) operations cannot be approved until the next one is bootstrapped
OK
```

Chạy lại cùng `sub` ⇒ `already an active Super Admin: nothing changed` (mã 0, không ghi, không audit). Người thứ ba ⇒ mã 1 `bootstrap closed: 2 active Super Admins already …` — **không** ghi gì. Lệnh cũng từ chối: `sub` không phải UUID (`not a username or an e-mail`), `MG_IDP_ID_PLATFORM` thiếu hoặc là id IdP của một tenant, identity đã bị khóa, người đã là platform user với role/trạng thái khác (đổi role đi qua API). Hai lệnh chạy đồng thời cũng không vượt ngưỡng (khóa advisory trong cùng transaction với phép đếm).

### 3. TO/TA của A và B

```bash
$CORE run --rm --no-deps -T api admin seed-membership --tenant tenant-a --role tenant_owner --subject "$TOA"
$CORE run --rm --no-deps -T api admin seed-membership --tenant tenant-a --role tenant_admin --subject "$TAA"
$CORE run --rm --no-deps -T api admin seed-membership --tenant tenant-b --role tenant_owner --subject "$TOB"
$CORE run --rm --no-deps -T api admin seed-membership --tenant tenant-b --role tenant_admin --subject "$TAB"
```

```text
seed-membership: tenant tenant-a (<tenant_id>), identity provider <MG_IDP_ID_TENANT_A> (issuer https://auth.<domain>/realms/tenant-a)
  identity: <identity_id> (subject <sub>) — created
  membership: <membership_id> — tenant_owner, active — created
  audit: platform.identity.seed + tenant.membership.seed (actor_type system, request admin-<uuid>)
OK
```

IdP luôn là IdP `active` của chính tenant trong registry (không chọn được IdP khác); `--tenant` nhận slug hoặc id. Chỉ nhận `tenant_owner`/`tenant_admin` (mã 2 với role khác — role platform chỉ qua `bootstrap-super-admin`/API). Chạy lại ⇒ `nothing changed`; membership đã có với role/trạng thái khác ⇒ mã 1, không đổi gì. Hai bước ghi (identity trên pool platform, membership trên pool tenant — không role nào ghi được cả hai bảng): nếu bước 2 lỗi, lệnh in `identity … created …; the membership was NOT created` — chạy lại lệnh để hoàn tất (identity không có membership không có quyền gì).

### 4. Kiểm

```bash
$CORE exec -T postgres psql -U postgres -d meshguard <<'SQL'
SELECT 'platform' AS scope, r.key AS role, pu.status, i.subject, i.display_name
  FROM platform_users pu JOIN identities i ON i.id = pu.identity_id JOIN roles r ON r.id = pu.role_id
UNION ALL
SELECT t.slug, r.key, m.status, i.subject, i.display_name
  FROM tenant_memberships m JOIN tenants t ON t.id = m.tenant_id JOIN identities i ON i.id = m.identity_id
  JOIN roles r ON r.id = m.role_id
ORDER BY 1, 2;
SELECT occurred_at, action, tenant_id, resource_type, resource_id, actor_type, request_id
  FROM audit_events WHERE action IN ('platform.super_admin.bootstrap', 'platform.identity.seed', 'tenant.membership.seed')
  ORDER BY occurred_at;
SQL
```

Mong đợi: đúng 2 dòng `platform | super_admin | active`, mỗi tenant 1 `tenant_owner` + 1 `tenant_admin`; mỗi lệnh đã ghi có sự kiện `actor_type = system` (sự kiện membership mang `tenant_id` của tenant — tenant thấy trong `GET /tenants/{t}/audit`). Đăng nhập thử: Super Admin tại `https://admin.<domain>` (`GET /api/v1/auth/session` ⇒ `platform_role: super_admin`, `GET /api/v1/platform/tenants` liệt kê A và B, route `/tenants/{A}/…` ⇒ 403 khi chưa có Support Access Grant); TO của A tại `https://app.<domain>` (`/auth/login?scope=tenant&tenant=tenant-a`) thấy A, mọi đường dẫn của B ⇒ 404. Ghi kết quả (sub, id, request id — không secret) vào `current.md` ở P2-T16.

### Hoàn tác (chỉ trước go-live)

Sau go-live **không** xóa tay: khóa/offboard qua API (P4). Trước go-live, gỡ đúng các danh tính vừa tạo (mỗi `sub` một lần; session của identity bị xóa dây chuyền; audit giữ nguyên — append-only). Gỡ Super Admin làm số SA hoạt động < 2 ⇒ lệnh bootstrap dùng lại được — đúng chủ đích (chỉ trước go-live).

```bash
IDP=$MG_IDP_ID_PLATFORM; SUB=$SA2      # SA; với TO/TA: IDP=$MG_IDP_ID_TENANT_A (hoặc _B), SUB=$TOA …
$CORE exec -T postgres psql -U postgres -d meshguard -v ON_ERROR_STOP=1 -v idp="$IDP" -v sub="$SUB" <<'SQL'
BEGIN;
DELETE FROM tenant_memberships WHERE identity_id IN (SELECT id FROM identities WHERE idp_id = :'idp' AND subject = :'sub');
DELETE FROM platform_users     WHERE identity_id IN (SELECT id FROM identities WHERE idp_id = :'idp' AND subject = :'sub');
DELETE FROM identities WHERE idp_id = :'idp' AND subject = :'sub';
COMMIT;
SQL
```

## VPS gateway `mg-gateway` — dựng lại từ repo (ADR-25, T-19)

VPS không giữ khóa TLS hay dữ liệu tenant, nên dựng lại chỉ cần render từ repo. Lần diễn tập đo được 14,1 s từ `down` tới khi `/key` qua VPS trả 200 ([P1-T18](../../docs/planning/evidence/P1-T18.md)).

```bash
# trên máy có repo: render rồi chuyển hai file sang VPS (không có secret)
python3 tools/render_gateway.py infrastructure/environments/staging/gateway.json /tmp/gw
# trên VPS
cd /opt/meshguard/gateway && sudo docker compose -f compose.gateway.yaml down
sudo install -m 0644 ~/gw/haproxy.cfg ~/gw/compose.gateway.yaml /opt/meshguard/gateway/
cd /opt/meshguard/gateway && sudo docker compose -f compose.gateway.yaml up -d
# kiểm: /key?v=113 qua DNS công khai = 200; tools/stun_probe.py "$MG_PUBLIC_IPV4"; client ép relay vẫn "via DERP(<region>)"
```

Tunnel `mg-wg0` (`infrastructure/gateway/wg-setup.sh`) và firewall VPS (`apply-vps-firewall.sh`) không bị ảnh hưởng. Khóa WireGuard được sinh tại từng máy. Nếu phải dựng lại tunnel thì chỉ trao đổi public key.

## Backend `mg-app` (api, worker, migrate) — P2-T16

Triển khai backend lên host (project compose `mg-app` render bằng `tools/render_app.py`, secret bằng `app-secrets.sh`, bootstrap DB một lần, bước migrate luôn qua `migrate.sh` — backup pre-migration của `mg-backup` trước, dừng nếu lỗi —, `api`/`worker` lên, adopt/IdP/SA, edge template v5 với site `app.`/`admin.`/`auth.`, DNS công khai): **[docs/operations/deploy-backend.md](../../docs/operations/deploy-backend.md)** — các bước theo thứ tự, lệnh kiểm, hoàn tác và nhãn duyệt của chủ dự án. Hai mục adopt và Super Admin/TO/TA ở trên dùng nguyên văn với `CORE="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"` (service `api` của project `mg-app`; sự kiện audit của các lệnh admin nay vào `audit_events`).

```bash
sudo bash infrastructure/host/app-secrets.sh && sudo bash infrastructure/host/check-secrets.sh   # secret file (không in)
python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app          # → /opt/meshguard/core/
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
$APP --profile bootstrap run --rm -T db-bootstrap                 # MỘT lần (superuser): mg_migrator, mg_backup
sudo bash infrastructure/host/migrate.sh                          # mỗi lần nâng cấp: backup pre-migration → migrate
$APP up -d --wait api worker                                      # /readyz: postgres, secretstore, edge_admin
```
