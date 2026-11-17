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
$CORE run --rm --no-deps -T -e MG_IDP_ID_PLATFORM api admin register-platform-idp

# 1. mỗi tenant: S=tenant-a, rồi S=tenant-b (lần đầu kèm vùng/dải của host; lần sau chỉ --host)
S=tenant-a; NAME="Tenant A"
IID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instance_id"])' infrastructure/environments/staging/tenants/$S.json)
sudo docker exec mg-hs-$S headscale apikeys list            # ghi lại các prefix hiện có (prefix không phải secret)
T=$(sudo mktemp -d)                                         # meta không chứa secret; bản 0444 cho uid 65532 của api
sudo install -m 0444 /opt/meshguard/tenants/$IID/meta/instance.json "$T/instance.json"
sudo docker exec mg-hs-$S headscale apikeys create -e 2160h -o json \
  | $CORE run --rm --no-deps -T -e MG_IDP_ID_TENANT_A -e MG_IDP_ID_TENANT_B \
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
